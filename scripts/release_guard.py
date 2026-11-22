#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Guards of the release workflows, kept here so unit tests can plant each defect.

    release_guard.py tag REF_TYPE REF_NAME SHA
        Print the `version=` and `prerelease=` output lines of the release
        build. A tag must be vX.Y.Z or vX.Y.Z-rc.N; a manual run (no tag)
        gets version run-<12 hex> and no prerelease line.
    release_guard.py publish VERSION TAG PRERELEASE
        Refuse to publish when the release build named another version than
        the tag, or classified the tag otherwise than the tag's own shape.
    release_guard.py published EXPECTED ACTUAL
        Refuse a published release whose isPrerelease is not EXPECTED.
    release_guard.py checksums SUMS
        Check every file SUMS lists against its SHA-256, like
        `sha256sum --check`, relative to the directory of SUMS.
    release_guard.py verify SUMS BUNDLE --workflow-of REPOSITORY REF
        Verify the keyless cosign signature BUNDLE of SUMS: it must come from
        release-build.yml of REPOSITORY at REF, issued by GitHub Actions.
        Then check the files SUMS lists. --test-key PUBLIC_KEY verifies
        against a local key instead, without any transparency log; only the
        tests use it.

Exit status: 0 on success, 1 when a guard refuses, 2 when the tool cannot
run (missing file, cosign not installed).
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess  # nosec B404 - allow-listed cosign argv, no shell, bounded timeout.
import sys
from pathlib import Path

if __package__:
    from . import admit_series
else:
    import admit_series

CANDIDATE = admit_series.CANDIDATE
FINAL = admit_series.FINAL
GuardError = admit_series.GuardError
NUMBER = admit_series.NUMBER
OIDC_ISSUER = admit_series.OIDC_ISSUER
Refused = admit_series.Refused
SUMS_LINE = admit_series.SUMS_LINE
read_sums = admit_series.read_sums
signer_identity = admit_series.signer_identity


def classify(tag: str) -> str:
    """Return "false" for vX.Y.Z and "true" for vX.Y.Z-rc.N; refuse any other tag."""
    if FINAL.fullmatch(tag):
        return "false"
    if CANDIDATE.fullmatch(tag):
        return "true"
    raise Refused(f"tag {tag} is neither vX.Y.Z nor vX.Y.Z-rc.N")


def tag_outputs(ref_type: str, ref_name: str, sha: str) -> list[str]:
    """The release build's output lines for this ref."""
    if ref_type != "tag":
        # A manual run builds, attests and signs, but publish never runs.
        return [f"version=run-{sha[:12]}"]
    return [f"version={ref_name}", f"prerelease={classify(ref_name)}"]


def check_publish(version: str, tag: str, prerelease: str) -> None:
    """Refuse a release build that does not match the tag it publishes."""
    if version != tag:
        raise Refused(f"release build named {version}, the tag is {tag}")
    # An empty value is a bug in the release build, not "final".
    if prerelease not in ("true", "false"):
        raise Refused(f"release build did not classify {tag}: prerelease={prerelease!r}")
    if prerelease != classify(tag):
        raise Refused(f"release build classified {tag} as prerelease={prerelease}")


def check_published(expected: str, actual: str) -> None:
    if actual != expected:
        raise Refused(f"the release has isPrerelease={actual}, expected {expected}")


def check_sums(sums: Path) -> list[str]:
    """Check every listed file; return one `name: OK` line per file."""
    lines = []
    for digest, name in read_sums(sums):
        try:
            actual = hashlib.sha256((sums.parent / name).read_bytes()).hexdigest()
        except OSError as exc:
            raise Refused(f"{name}: {exc.strerror}") from exc
        if actual != digest:
            raise Refused(f"{name}: checksum does not match {sums.name}")
        lines.append(f"{name}: OK")
    return lines


def cosign_arguments(args: argparse.Namespace) -> list[str]:
    """The cosign verify-blob argv for ARGS: test key offline, else the keyless
    release-build identity.
    """
    command = ["cosign", "verify-blob", "--bundle", str(args.bundle)]
    if args.test_key:
        command += ["--key", str(args.test_key)]
        command += ["--insecure-ignore-tlog=true"]
    else:
        repository, ref = args.workflow_of
        command += ["--certificate-identity", signer_identity(repository, ref)]
        command += ["--certificate-oidc-issuer", OIDC_ISSUER]
    return [*command, str(args.sums)]


def verify(args: argparse.Namespace) -> list[str]:
    """Verify the signature of SUMS, then the files it lists."""
    try:
        result = subprocess.run(  # nosec B603 - cosign argv is allow-listed by cosign_arguments.
            cosign_arguments(args), check=False, timeout=300
        )
    except FileNotFoundError as exc:
        raise GuardError("cosign is not installed") from exc
    if result.returncode != 0:
        raise Refused(f"cosign verify-blob refused the signature of {args.sums}")
    return check_sums(args.sums)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    tag = commands.add_parser("tag", help="print the release build's output lines")
    tag.add_argument("ref_type")
    tag.add_argument("ref_name")
    tag.add_argument("sha")
    publish = commands.add_parser("publish", help="match the release build to the tag")
    publish.add_argument("version")
    publish.add_argument("tag")
    publish.add_argument("prerelease")
    published = commands.add_parser("published", help="check the release's isPrerelease")
    published.add_argument("expected")
    published.add_argument("actual")
    checksums = commands.add_parser("checksums", help="check the files SUMS lists")
    checksums.add_argument("sums", type=Path)
    signed = commands.add_parser("verify", help="verify the signature, then the checksums")
    signed.add_argument("sums", type=Path)
    signed.add_argument("bundle", type=Path)
    signer = signed.add_mutually_exclusive_group(required=True)
    signer.add_argument("--workflow-of", nargs=2, metavar=("REPOSITORY", "REF"))
    signer.add_argument("--test-key", type=Path, metavar="PUBLIC_KEY")
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> list[str]:
    if args.command == "tag":
        return tag_outputs(args.ref_type, args.ref_name, args.sha)
    if args.command == "publish":
        check_publish(args.version, args.tag, args.prerelease)
        return []
    if args.command == "published":
        check_published(args.expected, args.actual)
        return []
    if args.command == "checksums":
        return check_sums(args.sums)
    return verify(args)


def main(argv: list[str]) -> int:
    """Exit 0 on success, 1 when a guard refuses, 2 when the tool cannot run."""
    args = parse_args(argv)
    try:
        lines = run(args)
    except Refused as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    except (GuardError, subprocess.TimeoutExpired) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
