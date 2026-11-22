#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Fetch release assets and admit a signed ffmpeg-patches series tarball for consumers."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import http.client
import json
import re
import subprocess  # nosec B404 - allow-listed cosign argv, no shell, bounded timeout.
import sys
import tarfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

NUMBER = r"(0|[1-9][0-9]*)"
FINAL = re.compile(rf"^v{NUMBER}\.{NUMBER}\.{NUMBER}$")
CANDIDATE = re.compile(rf"^v{NUMBER}\.{NUMBER}\.{NUMBER}-rc\.[1-9][0-9]*$")
SUMS_LINE = re.compile(r"([0-9a-f]{64}) [ *](.+)")
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
CALLER_WORKFLOW = ".github/workflows/release.yml"
DIST_FILES = (
    "base.env",
    "series.txt",
    "patches",
    "scripts/series.py",
    "upstream-contributions.json",
    "LICENSE",
    "LICENSES",
    "README.md",
    "REUSE.toml",
)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
PATCH_NAME = re.compile(r"^[0-9]{4}-[a-zA-Z0-9._-]+\.patch$")
MAX_TAR_MEMBERS = 4096
MAX_ASSET_BYTES = 256 * 1024 * 1024
MAX_HASH_BYTES = MAX_ASSET_BYTES
FETCH_CHUNK = 1024 * 1024
FETCH_TIMEOUT = 60
COSIGN_TIMEOUT = 300
MAX_DIAG_REPR = 200
ENV_KEY = re.compile(r"^[A-Z_][A-Z0-9_]*$")

STATEMENT_TYPES = frozenset({"https://in-toto.io/Statement/v1"})
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


class GuardError(Exception):
    """The helper cannot run; main() exits 2."""


class Refused(Exception):
    """Admission refused; main() exits 1."""


@dataclass(frozen=True)
class SignerBinding:
    """Keyless cosign bindings for a series release."""

    repository: str
    tag: str
    commit: str


def signer_identity(repository: str, ref: str) -> str:
    """Return the certificate identity of release-build.yml in REPOSITORY at REF."""
    return f"https://github.com/{repository}/.github/workflows/release-build.yml@{ref}"


def read_sums(sums: Path) -> list[tuple[str, str]]:
    """Read checksum entries or report an unreadable listing with its path."""
    try:
        text = sums.read_text(encoding="utf-8")
    except OSError as exc:
        raise GuardError(f"{sums}: {exc.strerror}") from exc
    except UnicodeDecodeError as exc:
        raise GuardError(f"{sums}: {exc}") from exc
    entries = []
    for number, line in enumerate(text.splitlines(), 1):
        match = SUMS_LINE.fullmatch(line)
        if not match:
            raise Refused(f"{sums}:{number}: not a SHA-256 checksum line")
        entries.append((match.group(1), match.group(2)))
    if not entries:
        raise Refused(f"{sums}: lists no file")
    return entries


def tarball_name(tag: str) -> str:
    """Return the release tarball filename for TAG."""
    return f"ffmpeg-patches-{tag}.tar.gz"


def sbom_name(tag: str) -> str:
    """Return the release SBOM filename for TAG."""
    return f"ffmpeg-patches-{tag}.spdx.json"


def provenance_name(tag: str) -> str:
    """Return the provenance bundle filename for TAG."""
    return f"ffmpeg-patches-{tag}.provenance.sigstore.json"


def fetch_asset_names(tag: str) -> tuple[str, ...]:
    """Return the five release asset filenames for TAG in download order."""
    return (
        tarball_name(tag),
        sbom_name(tag),
        provenance_name(tag),
        "SHA256SUMS",
        "SHA256SUMS.sigstore.json",
    )


def keyless_cosign_flags(repository: str, tag: str, commit: str) -> list[str]:
    """Return shared keyless cosign certificate flags for REPOSITORY, TAG and COMMIT."""
    ref = f"refs/tags/{tag}"
    return [
        "--certificate-identity",
        signer_identity(repository, ref),
        "--certificate-oidc-issuer",
        OIDC_ISSUER,
        "--certificate-github-workflow-ref",
        ref,
        "--certificate-github-workflow-sha",
        commit,
    ]


def sums_verify_argv(
    sums: Path,
    bundle: Path,
    binding: SignerBinding,
    test_key: Path | None,
) -> list[str]:
    """Return the cosign verify-blob argv for SUMS without running cosign."""
    command = ["cosign", "verify-blob", "--bundle", str(bundle)]
    if test_key is not None:
        command += ["--key", str(test_key), "--insecure-ignore-tlog=true"]
    else:
        command += keyless_cosign_flags(binding.repository, binding.tag, binding.commit)
    return [*command, str(sums)]


def attestation_verify_argv(
    tarball: Path,
    bundle: Path,
    binding: SignerBinding,
    test_key: Path | None,
) -> list[str]:
    """Return the cosign verify-blob-attestation argv without running cosign."""
    command = [
        "cosign",
        "verify-blob-attestation",
        "--bundle",
        str(bundle),
        "--type",
        "slsaprovenance1",
    ]
    if test_key is not None:
        command += ["--key", str(test_key), "--insecure-ignore-tlog=true"]
    else:
        command += keyless_cosign_flags(binding.repository, binding.tag, binding.commit)
    return [*command, str(tarball)]


def run_cosign(argv: list[str]) -> None:
    """Run cosign with a bounded timeout or refuse when cosign is missing."""
    try:
        result = subprocess.run(  # nosec B603 - cosign argv is constructed above, no shell.
            argv, check=False, timeout=COSIGN_TIMEOUT
        )
    except OSError as exc:
        raise GuardError(f"cosign is not installed: {exc}") from exc
    if result.returncode != 0:
        raise Refused(f"cosign refused: {' '.join(argv[:3])}")


def refuse_error(message: str) -> NoReturn:
    """Raise Refused with MESSAGE formatted for GitHub Actions."""
    raise Refused(message)


def diag_text(value: object) -> str:
    """Return a bounded repr of VALUE for refusal diagnostics."""
    rendered = repr(value)
    if len(rendered) <= MAX_DIAG_REPR:
        return rendered
    return f"{rendered[:MAX_DIAG_REPR]}... (length {len(rendered)})"


def require_stmt_object(value: object, path: str) -> dict:
    """Refuse when VALUE is not a mapping at provenance PATH."""
    if not isinstance(value, dict):
        refuse_error(f"provenance shape: {path} is not an object")
    return value


def require_stmt_object_list(value: object, path: str, *, min_items: int = 0) -> list:
    """Refuse when VALUE is not a non-empty list of objects at PATH."""
    if not isinstance(value, list):
        refuse_error(f"provenance shape: {path} is not a list")
    if len(value) < min_items:
        refuse_error(f"provenance shape: {path} is empty")
    for index, item in enumerate(value):
        require_stmt_object(item, f"{path}[{index}]")
    return value


def check_provenance_field_shapes(statement: dict) -> None:
    """Refuse when statement fields are not objects and lists of objects."""
    subjects = require_stmt_object_list(statement.get("subject"), "subject", min_items=1)
    for index, entry in enumerate(subjects):
        require_stmt_object(entry.get("digest"), f"subject[{index}].digest")
    predicate = require_stmt_object(statement.get("predicate"), "predicate")
    build_def = require_stmt_object(predicate.get("buildDefinition"), "predicate.buildDefinition")
    deps = build_def.get("resolvedDependencies")
    if not isinstance(deps, list):
        refuse_error(
            "provenance shape: predicate.buildDefinition.resolvedDependencies is not a list"
        )
    for index, dep in enumerate(deps):
        require_stmt_object(dep, f"predicate.buildDefinition.resolvedDependencies[{index}]")
    if deps:
        require_stmt_object(
            deps[0].get("digest"), "predicate.buildDefinition.resolvedDependencies[0].digest"
        )
    external = require_stmt_object(
        build_def.get("externalParameters"), "predicate.buildDefinition.externalParameters"
    )
    require_stmt_object(
        external.get("workflow"),
        "predicate.buildDefinition.externalParameters.workflow",
    )
    internal = require_stmt_object(
        build_def.get("internalParameters"), "predicate.buildDefinition.internalParameters"
    )
    require_stmt_object(
        internal.get("github"),
        "predicate.buildDefinition.internalParameters.github",
    )
    run_details = require_stmt_object(predicate.get("runDetails"), "predicate.runDetails")
    require_stmt_object(run_details.get("builder"), "predicate.runDetails.builder")


def check_pin_shapes(tag: str, series_commit: str, tarball_sha256: str, signer_repo: str) -> None:
    """Refuse malformed tag, commit, sha256 or signer repository shapes."""
    if not (FINAL.fullmatch(tag) or CANDIDATE.fullmatch(tag)):
        refuse_error(f"pin shape tag: expected vX.Y.Z or vX.Y.Z-rc.N, got {tag!r}")
    if not COMMIT_RE.fullmatch(series_commit):
        refuse_error(f"pin shape commit: expected 40 lowercase hex, got {series_commit!r}")
    if not SHA256_RE.fullmatch(tarball_sha256):
        refuse_error(f"pin shape sha256: expected 64 lowercase hex, got {tarball_sha256!r}")
    if not REPO_RE.fullmatch(signer_repo):
        refuse_error(f"pin shape signer repository: expected OWNER/NAME, got {signer_repo!r}")


def file_sha256(path: Path, cap: int | None = None) -> str:
    """Return the SHA-256 hex digest of PATH within CAP bytes."""
    limit = MAX_HASH_BYTES if cap is None else cap
    try:
        handle = path.open("rb")
    except OSError as exc:
        raise GuardError(f"{path}: {exc.strerror}") from exc
    loops = limit // FETCH_CHUNK + 2
    with handle:
        digest = hashlib.sha256()
        total = 0
        for _ in range(loops):
            chunk = handle.read(FETCH_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                refuse_error(f"file hash cap: {path.name}: exceeds {limit} bytes")
            digest.update(chunk)
        return digest.hexdigest()


def check_tarball_digest(tarball: Path, expected: str) -> None:
    """Refuse when the tarball digest does not match EXPECTED."""
    actual = file_sha256(tarball)
    if actual != expected:
        refuse_error(f"tarball sha256: pin {expected} does not match file {actual}")


def verify_sums_signature(
    assets: Path,
    tag: str,
    commit: str,
    signer_repo: str,
    test_key: Path | None,
) -> None:
    """Refuse when cosign verify-blob does not accept SHA256SUMS."""
    sums = assets / "SHA256SUMS"
    bundle = assets / "SHA256SUMS.sigstore.json"
    binding = SignerBinding(signer_repo, tag, commit)
    argv = sums_verify_argv(sums, bundle, binding, test_key)
    run_cosign(argv)


def check_sums_strict(assets: Path, tag: str, tarball_sha256: str) -> None:
    """Refuse when SHA256SUMS does not list exactly the tarball and SBOM."""
    sums = assets / "SHA256SUMS"
    tname = tarball_name(tag)
    sname = sbom_name(tag)
    entries = read_sums(sums)
    names = [name for _, name in entries]
    if len(entries) != 2:
        refuse_error(f"SHA256SUMS listing: expected 2 names, got {diag_text(names)}")
    if len(set(names)) != 2:
        refuse_error(f"SHA256SUMS listing: duplicate name in {diag_text(names)}")
    expected = {tname, sname}
    if set(names) != expected:
        refuse_error(
            f"SHA256SUMS listing: expected {diag_text(sorted(expected))}, got {diag_text(names)}"
        )
    by_name = {name: digest for digest, name in entries}
    if by_name[tname] != tarball_sha256:
        refuse_error(
            f"SHA256SUMS tarball line: pin {tarball_sha256} does not match {by_name[tname]}"
        )
    for digest, name in entries:
        path = assets / name
        if not path.is_file():
            refuse_error(f"SHA256SUMS strict: missing file {name}")
        actual = file_sha256(path)
        if actual != digest:
            refuse_error(f"SHA256SUMS strict: {name} digest {digest} does not match {actual}")


def read_asset_bytes(path: Path) -> bytes:
    """Return asset bytes or raise GuardError when PATH cannot be read."""
    try:
        return path.read_bytes()
    except OSError as exc:
        raise GuardError(f"{path}: {exc.strerror}") from exc


def verify_tarball_attestation(
    assets: Path,
    tag: str,
    commit: str,
    signer_repo: str,
    test_key: Path | None,
) -> bytes:
    """Refuse when cosign verify-blob-attestation fails; return provenance bundle bytes."""
    tarball = assets / tarball_name(tag)
    bundle_path = assets / provenance_name(tag)
    bundle_bytes = read_asset_bytes(bundle_path)
    binding = SignerBinding(signer_repo, tag, commit)
    argv = attestation_verify_argv(tarball, bundle_path, binding, test_key)
    run_cosign(argv)
    return bundle_bytes


def decode_statement(bundle_bytes: bytes) -> dict:
    """Decode the in-toto statement JSON from a sigstore bundle."""
    try:
        text = bundle_bytes.decode("utf-8")
    except UnicodeDecodeError:
        refuse_error("provenance bundle: not JSON")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        refuse_error("provenance bundle: not JSON")
    if not isinstance(payload, dict):
        refuse_error("provenance bundle: not an object")
    envelope = payload.get("dsseEnvelope")
    if not isinstance(envelope, dict):
        refuse_error("provenance bundle: without dsseEnvelope or payload")
    encoded = envelope.get("payload")
    if not isinstance(encoded, str):
        refuse_error("provenance bundle: without dsseEnvelope or payload")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        refuse_error("provenance bundle: payload not base64")
    try:
        statement = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        refuse_error("provenance bundle: payload not JSON")
    if not isinstance(statement, dict):
        refuse_error("provenance bundle: payload not JSON")
    return statement


def check_provenance_subject(statement: dict, tag: str, tarball_sha256: str) -> None:
    """Refuse when the statement subject does not match the tarball pin."""
    tname = tarball_name(tag)
    subjects = statement["subject"]
    tarball_subj = next((s for s in subjects if s.get("name") == tname), None)
    if tarball_subj is None:
        refuse_error(f"provenance subject: expected name {diag_text(tname)}, missing")
    subj_sha = tarball_subj.get("digest", {}).get("sha256", "")
    if subj_sha != tarball_sha256:
        refuse_error(f"provenance subject digest: pin {tarball_sha256} does not match {subj_sha}")


def check_provenance_commit_and_workflow(
    predicate: dict, tag: str, commit: str, signer_repo: str
) -> None:
    """Refuse when provenance commit, workflow, runner or builder disagree."""
    build_def = predicate["buildDefinition"]
    deps = build_def["resolvedDependencies"]
    if not deps:
        refuse_error("provenance commit: resolvedDependencies is empty")
    dep = deps[0]
    dep_commit = dep.get("digest", {}).get("gitCommit", "")
    if dep_commit != commit:
        refuse_error(f"provenance commit: pin {commit} does not match {dep_commit}")
    tag_ref = f"refs/tags/{tag}"
    expected_uri = f"git+https://github.com/{signer_repo}@{tag_ref}"
    dep_uri = dep.get("uri", "")
    if dep_uri != expected_uri:
        refuse_error(
            "provenance dependency uri: expected "
            f"{diag_text(expected_uri)}, got {diag_text(dep_uri)}"
        )
    workflow = build_def["externalParameters"]["workflow"]
    workflow_ref = workflow.get("ref")
    if workflow_ref != tag_ref:
        refuse_error(
            f"provenance workflow ref: expected {diag_text(tag_ref)}, got {diag_text(workflow_ref)}"
        )
    expected_repo = f"https://github.com/{signer_repo}"
    workflow_repo = workflow.get("repository")
    if workflow_repo != expected_repo:
        refuse_error(
            f"provenance workflow repository: expected {diag_text(expected_repo)}, "
            f"got {diag_text(workflow_repo)}"
        )
    workflow_path = workflow.get("path")
    if workflow_path != CALLER_WORKFLOW:
        refuse_error(
            f"provenance workflow path: expected {diag_text(CALLER_WORKFLOW)}, "
            f"got {diag_text(workflow_path)}"
        )
    runner = build_def["internalParameters"]["github"].get("runner_environment", "")
    if runner != "github-hosted":
        refuse_error(f"provenance runner: expected github-hosted, got {diag_text(runner)}")
    builder_id = predicate["runDetails"]["builder"].get("id", "")
    expected_builder = signer_identity(signer_repo, tag_ref)
    if builder_id != expected_builder:
        refuse_error(
            f"provenance builder id: expected {diag_text(expected_builder)}, "
            f"got {diag_text(builder_id)}"
        )


def check_provenance_statement(
    statement: dict,
    tag: str,
    commit: str,
    tarball_sha256: str,
    signer_repo: str,
) -> None:
    """Refuse when the provenance statement does not match the admitted pins."""
    if statement.get("_type") not in STATEMENT_TYPES:
        refuse_error(
            "provenance _type: expected an in-toto Statement, got "
            f"{diag_text(statement.get('_type'))}"
        )
    if statement.get("predicateType") != PREDICATE_TYPE:
        refuse_error(
            f"provenance predicateType: expected {diag_text(PREDICATE_TYPE)}, "
            f"got {diag_text(statement.get('predicateType'))}"
        )
    check_provenance_field_shapes(statement)
    check_provenance_subject(statement, tag, tarball_sha256)
    check_provenance_commit_and_workflow(statement["predicate"], tag, commit, signer_repo)


def dist_path_allowed(rel: str) -> bool:
    """Return whether REL path inside the tarball prefix is allowed by DIST_FILES."""
    for entry in DIST_FILES:
        if entry in ("patches", "LICENSES"):
            if rel == entry or rel.startswith(f"{entry}/"):
                return True
        elif rel == entry:
            return True
    return False


def dist_directory_allowed(rel: str) -> bool:
    """Return whether REL directory path is allowed under the series prefix."""
    rel = rel.rstrip("/")
    if rel in ("patches", "LICENSES"):
        return True
    return any("/" in entry and entry.split("/", 1)[0] == rel for entry in DIST_FILES)


def tarball_root_names(tag: str) -> frozenset[str]:
    """Return tarball member names that denote the series root directory."""
    root = f"ffmpeg-patches-{tag}"
    return frozenset({root, f"{root}/"})


def member_tail(name: str, prefix: str) -> str:
    """Return the member path below PREFIX or refuse an unsafe tarball name."""
    if not name.startswith(prefix):
        refuse_error(
            f"tarball prefix: member {diag_text(name)} does not start with {diag_text(prefix)}"
        )
    if name.startswith("/") or "\\" in name or "\x00" in name:
        refuse_error(f"tarball path: unsafe name {diag_text(name)}")
    tail = name[len(prefix) :]
    if not tail:
        refuse_error(f"tarball path: empty name after prefix in {diag_text(name)}")
    parts = tail.split("/")
    for part in parts:
        if not part:
            refuse_error(f"tarball path: empty path part in {diag_text(name)}")
        if part in (".", ".."):
            refuse_error(f"tarball path: {diag_text(part)} in {diag_text(name)}")
    return tail


def read_member_payload(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    """Return member file bytes or refuse a disallowed member type."""
    if member.isdir():
        return b""
    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
        refuse_error(
            f"tarball member type: {diag_text(member.name)} is not a regular file or directory"
        )
    if not member.isreg():
        refuse_error(
            f"tarball member type: {diag_text(member.name)} is not a regular file or directory"
        )
    payload = archive.extractfile(member)
    if payload is None:
        return b""
    return payload.read()


def open_tarball_gzip(tarball: Path) -> tarfile.TarFile:
    """Open TARBALL as gzip tar or refuse with a tarball archive error."""
    try:
        return tarfile.open(tarball, mode="r:gz")
    except tarfile.ReadError as exc:
        refuse_error(f"tarball archive: not a gzip tar archive ({exc})")


def scan_tar_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    *,
    prefix: str,
    roots: frozenset[str],
) -> tuple[bytes, bytes]:
    """Validate one TAR member and return base.env or series.txt payload updates."""
    base_bytes = b""
    series_bytes = b""
    if member.isdir():
        if member.name in roots:
            return base_bytes, series_bytes
        if not member.name.startswith(prefix):
            refuse_error(
                "tarball prefix: member "
                f"{diag_text(member.name)} does not start with {diag_text(prefix)}"
            )
        dir_tail = member.name[len(prefix) :].rstrip("/")
        if not dist_directory_allowed(dir_tail):
            refuse_error(f"tarball dist: directory {diag_text(dir_tail)} not in DIST_FILES")
        return base_bytes, series_bytes
    tail = member_tail(member.name, prefix)
    if not dist_path_allowed(tail):
        refuse_error(f"tarball dist: file {diag_text(tail)} not under DIST_FILES")
    payload = read_member_payload(archive, member)
    if tail == "base.env":
        base_bytes = payload
    if tail == "series.txt":
        series_bytes = payload
    return base_bytes, series_bytes


def check_tarball_members(tarball: Path, tag: str) -> dict[str, bytes]:
    """Refuse unsafe tarball members; return base.env and series.txt bytes."""
    prefix = f"ffmpeg-patches-{tag}/"
    roots = tarball_root_names(tag)
    base_bytes = b""
    series_bytes = b""
    count = 0
    with open_tarball_gzip(tarball) as archive:
        for member in archive.getmembers():
            count += 1
            if count > MAX_TAR_MEMBERS:
                refuse_error(f"tarball members: count {count} exceeds {MAX_TAR_MEMBERS}")
            part_base, part_series = scan_tar_member(archive, member, prefix=prefix, roots=roots)
            if part_base:
                base_bytes = part_base
            if part_series:
                series_bytes = part_series
    if not base_bytes:
        refuse_error("tarball dist: base.env missing")
    if not series_bytes:
        refuse_error("tarball dist: series.txt missing")
    return {"base.env": base_bytes, "series.txt": series_bytes}


def parse_base_env(text: str) -> dict[str, str]:
    """Parse base.env text into a key map or refuse invalid lines."""
    values: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "`" in line or "$(" in line:
            refuse_error(f"base.env:{number}: shell substitution is not allowed")
        if "=" not in line:
            refuse_error(f"base.env:{number}: not a KEY=VALUE line")
        key, value = line.split("=", 1)
        if not ENV_KEY.fullmatch(key):
            refuse_error(f"base.env:{number}: invalid key {key!r}")
        if key in values:
            refuse_error(f"base.env:{number}: duplicate key {key!r}")
        values[key] = value
    return values


def check_base_env_pins(
    base_text: str,
    ffmpeg_remote: str,
    ffmpeg_tag: str,
    ffmpeg_commit: str,
) -> None:
    """Refuse when base.env pins differ from the consumer FFmpeg pins."""
    values = parse_base_env(base_text)
    for key, expected in (
        ("FFMPEG_REMOTE", ffmpeg_remote),
        ("FFMPEG_TAG", ffmpeg_tag),
        ("FFMPEG_COMMIT", ffmpeg_commit),
    ):
        actual = values.get(key)
        if actual is None:
            refuse_error(f"base.env: missing key {key}")
        if actual != expected:
            refuse_error(f"base.env {key}: pin {expected!r} does not match {actual!r}")


def list_tarball_patches(tarball: Path, tag: str) -> set[str]:
    """Return patch basenames under patches/ in the tarball."""
    prefix = f"ffmpeg-patches-{tag}/patches/"
    names: set[str] = set()
    with open_tarball_gzip(tarball) as archive:
        for member in archive.getmembers():
            if member.name.startswith(prefix) and member.name.endswith(".patch"):
                names.add(member.name[len(prefix) :])
    return names


def check_series_txt(series_text: str, tarball: Path, tag: str) -> None:
    """Refuse when series.txt and patches/ disagree."""
    listed: list[str] = []
    for number, line in enumerate(series_text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not PATCH_NAME.fullmatch(stripped):
            refuse_error(f"series.txt:{number}: invalid patch name {stripped!r}")
        if stripped in listed:
            refuse_error(f"series.txt:{number}: duplicate patch {stripped!r}")
        listed.append(stripped)
    patches = list_tarball_patches(tarball, tag)
    for name in listed:
        if name not in patches:
            refuse_error(f"series.txt: patch {diag_text(name)} missing under patches/")
    for name in sorted(patches - set(listed)):
        refuse_error(f"series.txt: patch member {diag_text(name)} not listed")


def require_empty_destination(path: Path, label: str) -> None:
    """Refuse when PATH exists and is not an empty directory."""
    if not path.exists():
        return
    if path.is_dir() and not any(path.iterdir()):
        return
    refuse_error(f"{label}: destination {path} exists and is not empty")


def extract_tarball(tarball: Path, tag: str, dest: Path) -> None:
    """Extract TARBALL into DEST using the tar data filter."""
    require_empty_destination(dest, "extract")
    dest.mkdir(parents=True, exist_ok=True)
    with open_tarball_gzip(tarball) as archive:
        archive.extractall(dest, filter="data")


def remove_part_file(part: Path) -> None:
    """Remove PART when it exists."""
    if part.exists():
        part.unlink()


class HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when the target URL stays on HTTPS."""

    def redirect_request(  # noqa: PLR0913, PLR0917
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        """Refuse redirect targets that are not https:// URLs."""
        if not newurl.startswith("https://"):
            refuse_error(f"fetch redirect: non-https target {diag_text(newurl)}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def refuse_fetch_read(part: Path, url: str, exc: BaseException) -> NoReturn:
    """Remove PART and refuse a bounded fetch read error for URL."""
    remove_part_file(part)
    detail = f"{type(exc).__name__}: {exc}"
    refuse_error(f"fetch read: {diag_text(url)}: {detail}")


def stream_url_to_part(part: Path, url: str, response: object) -> None:
    """Read RESPONSE in bounded chunks into PART for URL."""
    total = 0
    loops = MAX_ASSET_BYTES // FETCH_CHUNK + 2
    with part.open("wb") as handle:
        for _ in range(loops):
            try:
                chunk = response.read(FETCH_CHUNK)  # type: ignore[attr-defined]
            except TimeoutError as exc:
                refuse_fetch_read(part, url, exc)
            except http.client.HTTPException as exc:
                refuse_fetch_read(part, url, exc)
            except OSError as exc:
                if isinstance(exc, TimeoutError):
                    raise
                refuse_fetch_read(part, url, exc)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ASSET_BYTES:
                remove_part_file(part)
                refuse_error(f"fetch size: asset exceeds {MAX_ASSET_BYTES} bytes")
            try:
                handle.write(chunk)
            except OSError as exc:
                if isinstance(exc, TimeoutError):
                    raise
                refuse_fetch_read(part, url, exc)


def download_asset(url: str, dest: Path) -> None:
    """Download URL into DEST with a size cap and HTTPS-only enforcement."""
    if not url.startswith("https://"):
        refuse_error(f"fetch url: expected https, got {diag_text(url)}")
    part = dest.parent / f"{dest.name}.part"
    remove_part_file(part)
    request = urllib.request.Request(url, method="GET")
    opener = urllib.request.build_opener(HttpsOnlyRedirectHandler)
    try:
        with opener.open(request, timeout=FETCH_TIMEOUT) as response:  # nosec B310
            stream_url_to_part(part, url, response)
    except urllib.error.URLError as exc:
        refuse_fetch_read(part, url, exc)
    part.replace(dest)


def run_fetch(args: argparse.Namespace) -> None:
    """Download the five release assets for TAG into DEST."""
    tag = args.tag
    if not (FINAL.fullmatch(tag) or CANDIDATE.fullmatch(tag)):
        refuse_error(f"fetch pin shape tag: expected vX.Y.Z or vX.Y.Z-rc.N, got {tag!r}")
    if not REPO_RE.fullmatch(args.repository):
        refuse_error(f"fetch pin shape repository: expected OWNER/NAME, got {args.repository!r}")
    dest = Path(args.dest)
    require_empty_destination(dest, "fetch")
    dest.mkdir(parents=True, exist_ok=True)
    base = f"https://github.com/{args.repository}/releases/download/{tag}"
    for name in fetch_asset_names(tag):
        download_asset(f"{base}/{name}", dest / name)


def decode_member_text(inner: dict[str, bytes], key: str) -> str:
    """Decode INNER[KEY] as UTF-8 or refuse at check h or i."""
    try:
        return inner[key].decode("utf-8")
    except UnicodeDecodeError:
        refuse_error(f"{key}: not UTF-8")


def run_admit(args: argparse.Namespace) -> tuple[str, str, str, str]:
    """Run admission checks a through j and return success output fields."""
    assets = Path(args.assets)
    tag = args.tag
    commit = args.commit
    sha256 = args.sha256
    signer_repo = args.signer_repository
    test_key = Path(args.test_key) if args.test_key else None
    check_pin_shapes(tag, commit, sha256, signer_repo)
    tarball = assets / tarball_name(tag)
    check_tarball_digest(tarball, sha256)
    verify_sums_signature(assets, tag, commit, signer_repo, test_key)
    check_sums_strict(assets, tag, sha256)
    bundle_bytes = verify_tarball_attestation(assets, tag, commit, signer_repo, test_key)
    statement = decode_statement(bundle_bytes)
    check_provenance_statement(statement, tag, commit, sha256, signer_repo)
    inner = check_tarball_members(tarball, tag)
    base_text = decode_member_text(inner, "base.env")
    series_text = decode_member_text(inner, "series.txt")
    check_base_env_pins(base_text, args.ffmpeg_remote, args.ffmpeg_tag, args.ffmpeg_commit)
    check_series_txt(series_text, tarball, tag)
    if args.extract:
        extract_tarball(tarball, tag, Path(args.extract))
    return tag, commit, sha256, signer_repo


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments for fetch and admit."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("fetch", help="download the five release assets")
    fetch.add_argument("--repository", required=True)
    fetch.add_argument("--tag", required=True)
    fetch.add_argument("--dest", required=True)
    admit = commands.add_parser("admit", help="verify and admit release assets")
    admit.add_argument("--assets", required=True)
    admit.add_argument("--tag", required=True)
    admit.add_argument("--commit", required=True)
    admit.add_argument("--sha256", required=True)
    admit.add_argument("--signer-repository", required=True)
    admit.add_argument("--ffmpeg-remote", required=True)
    admit.add_argument("--ffmpeg-tag", required=True)
    admit.add_argument("--ffmpeg-commit", required=True)
    admit.add_argument("--extract", default="")
    admit.add_argument("--test-key", default="")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    """Exit 0 admitted, 1 refused, 2 when the helper cannot run."""
    if sys.version_info < (3, 12):
        print("error: Python 3.12 or newer is required", file=sys.stderr)
        return 2
    args = parse_args(argv)
    try:
        if args.command == "fetch":
            run_fetch(args)
            return 0
        admitted = run_admit(args)
        tag, commit, digest, _repo = admitted
        print(f"admitted {tag} {commit} {digest}")
        return 0
    except Refused as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    except (GuardError, subprocess.TimeoutExpired) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
