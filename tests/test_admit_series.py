# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Tests for scripts/admit_series.py."""

from __future__ import annotations

import base64
import hashlib
import http.client
import io
import json
import os
import shutil
import subprocess  # nosec B404 - cosign path and arguments are test fixtures.
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import admit_series  # noqa: E402

from tests.helpers import capture_main  # noqa: E402

COSIGN = shutil.which("cosign")
TAG = "v1.0.0"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
SIGNER = "vidiko/ffmpeg-patches"
V070_SIGNER_REPOSITORY = "VMAFx/ffmpeg-patches"
FFMPEG_REMOTE = "https://github.com/FFmpeg/FFmpeg.git"
FFMPEG_TAG = "n9.0.2"
FFMPEG_COMMIT = "946fcce07b6dcd0331c8cc609192aeff5e1924f8"
PREDICATE_TEMPLATE = ROOT / "tests" / "fixtures" / "admission" / "predicate-v070.json"
SIGNING_CONFIG = ROOT / "tests" / "fixtures" / "admission" / "signing-config-offline.json"
_ADMIT_STDERR_LOG: list[str] = []


class _DecodeUpgradeState:
    """Toggle cosign offline Statement v0.1 label normalization in tests."""

    enabled = True


_ORIGINAL_DECODE_STATEMENT = admit_series.decode_statement


def decode_statement_for_tests(bundle_bytes: bytes) -> dict:
    """Decode bundles; map cosign 3.1.3 offline Statement v0.1 labels to v1."""
    statement = _ORIGINAL_DECODE_STATEMENT(bundle_bytes)
    if (
        _DecodeUpgradeState.enabled
        and statement.get("_type") == "https://in-toto.io/Statement/v0.1"
        and statement.get("predicateType") == admit_series.PREDICATE_TYPE
    ):
        return {**statement, "_type": "https://in-toto.io/Statement/v1"}
    return statement


admit_series.decode_statement = decode_statement_for_tests


def admit(*argv: str) -> tuple[int, str, str]:
    """Run admit_series.main and return the exit status, stdout and stderr."""
    status, out, err = capture_main(admit_series.main, *argv)
    _ADMIT_STDERR_LOG.append(err)
    return status, out, err


def argv_with_flag_value(argv: list[str], flag: str, value: str) -> list[str]:
    """Return a copy of ARGV with the value after FLAG replaced by VALUE."""
    indices = [idx for idx, token in enumerate(argv) if token == flag]
    if not indices:
        raise ValueError(f"flag {flag!r} is absent from argv")
    if len(indices) > 1:
        raise ValueError(f"flag {flag!r} appears more than once in argv")
    pos = indices[0]
    if pos + 1 >= len(argv):
        raise ValueError(f"flag {flag!r} is the last element in argv")
    out = list(argv)
    out[pos + 1] = value
    return out


def default_member_map(tag: str, base: str, series: str) -> dict[str, bytes]:
    """Return default tarball member bytes for TAG."""
    prefix = f"ffmpeg-patches-{tag}/"
    return {
        f"{prefix}base.env": base.encode(),
        f"{prefix}series.txt": series.encode(),
        f"{prefix}patches/0001-alpha.patch": b"patch1\n",
        f"{prefix}patches/0002-beta.patch": b"patch2\n",
        f"{prefix}patches/series.toml": b"# meta\n",
        f"{prefix}scripts/series.py": b"# stub\n",
        f"{prefix}upstream-contributions.json": b"{}\n",
        f"{prefix}LICENSE": b"license\n",
        f"{prefix}LICENSES/EUPL-1.2.txt": b"eupl\n",
        f"{prefix}README.md": b"readme\n",
        f"{prefix}REUSE.toml": b"version = 1\n",
    }


def add_tar_dir(archive: tarfile.TarFile, name: str, mode: int) -> None:
    """Add a directory entry NAME with MODE to ARCHIVE."""
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE
    info.mode = mode
    archive.addfile(info)


def write_fixture_tarball(  # noqa: PLR0913
    path: Path,
    tag: str,
    members: dict[str, bytes],
    *,
    git_archive_dirs: bool = False,
    extra_dirs: tuple[str, ...] = (),
    include_symlink: bool = False,
) -> None:
    """Write a gzip tarball for series TAG with MEMBERS."""
    prefix = f"ffmpeg-patches-{tag}/"
    with tarfile.open(path, "w:gz") as archive:
        if git_archive_dirs:
            root = prefix.rstrip("/")
            add_tar_dir(archive, root, 0o755)
            add_tar_dir(archive, f"{prefix}LICENSES", 0o755)
            add_tar_dir(archive, f"{prefix}patches", 0o755)
            add_tar_dir(archive, f"{prefix}scripts", 0o775)
        for dirname in extra_dirs:
            add_tar_dir(archive, dirname, 0o755)
        for name, data in sorted(members.items()):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            if name.endswith("scripts/series.py") and git_archive_dirs:
                info.mode = 0o775
            archive.addfile(info, io.BytesIO(data))
        if include_symlink:
            link = tarfile.TarInfo(name=f"{prefix}patches/link.patch")
            link.type = tarfile.SYMTYPE
            link.linkname = "0001-alpha.patch"
            archive.addfile(link)


def generate_signer_keypair(scratch: Path) -> None:
    """Write signer.key and signer.pub under SCRATCH."""
    env = {**os.environ, "COSIGN_PASSWORD": ""}
    subprocess.run(  # nosec B603 - cosign path and arguments are test fixtures.
        [COSIGN or "cosign", "generate-key-pair", "--output-key-prefix", "signer"],
        cwd=scratch,
        env=env,
        check=True,
        capture_output=True,
        timeout=120,
    )


def sign_sums_bundle(scratch: Path, sums: Path, bundle: Path) -> None:
    """Sign SUMS into BUNDLE with the scratch signer key."""
    subprocess.run(  # nosec B603 - cosign path and arguments are test fixtures.
        [
            COSIGN or "cosign",
            "sign-blob",
            "--yes",
            "--key",
            "signer.key",
            "--bundle",
            str(bundle),
            "--use-signing-config=false",
            "--tlog-upload=false",
            str(sums),
        ],
        cwd=scratch,
        env={**os.environ, "COSIGN_PASSWORD": ""},
        check=True,
        capture_output=True,
        timeout=120,
    )


def provenance_statement_bytes(
    fixture: SeriesFixture,
    predicate: dict | None,
) -> tuple[dict, bytes]:
    """Return the aligned statement object and predicate-only JSON bytes."""
    statement = json.loads(PREDICATE_TEMPLATE.read_text(encoding="utf-8"))
    if predicate is not None:
        statement = json.loads(json.dumps(predicate))
    tag_ref = f"refs/tags/{fixture.tag}"
    statement["subject"][0]["name"] = admit_series.tarball_name(fixture.tag)
    statement["subject"][0]["digest"]["sha256"] = fixture.tarball_sha256
    statement["subject"][1]["name"] = admit_series.sbom_name(fixture.tag)
    statement["subject"][1]["digest"]["sha256"] = hashlib.sha256(
        (fixture.assets / admit_series.sbom_name(fixture.tag)).read_bytes()
    ).hexdigest()
    pred = statement["predicate"]
    if predicate is None:
        pred["buildDefinition"]["externalParameters"]["workflow"]["ref"] = tag_ref
        pred["buildDefinition"]["externalParameters"]["workflow"]["repository"] = (
            f"https://github.com/{SIGNER}"
        )
        pred["buildDefinition"]["resolvedDependencies"][0]["uri"] = (
            f"git+https://github.com/{SIGNER}@{tag_ref}"
        )
        pred["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = fixture.commit
        pred["runDetails"]["builder"]["id"] = admit_series.signer_identity(SIGNER, tag_ref)
    return statement, json.dumps(statement["predicate"]).encode()


def sign_provenance_bundle(
    scratch: Path,
    fixture: SeriesFixture,
    predicate: dict | None,
) -> None:
    """Attest the tarball and write the provenance sigstore bundle."""
    _, predicate_bytes = provenance_statement_bytes(fixture, predicate)
    predicate_path = scratch / "predicate.json"
    predicate_path.write_bytes(predicate_bytes)
    config_path = scratch / "signing-config.json"
    config_path.write_text(SIGNING_CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
    prov_bundle = fixture.assets / admit_series.provenance_name(fixture.tag)
    tarball = fixture.assets / admit_series.tarball_name(fixture.tag)
    subprocess.run(  # nosec B603 - cosign path and arguments are test fixtures.
        [
            COSIGN or "cosign",
            "attest-blob",
            "--yes",
            "--key",
            "signer.key",
            "--predicate",
            str(predicate_path),
            "--type",
            "slsaprovenance1",
            "--bundle",
            str(prov_bundle),
            "--signing-config",
            str(config_path),
            str(tarball),
        ],
        cwd=scratch,
        env={**os.environ, "COSIGN_PASSWORD": ""},
        check=True,
        capture_output=True,
        timeout=120,
    )


def bundle_bytes_from_statement(statement: dict) -> bytes:
    """Encode a full in-toto statement as a sigstore bundle for test patching."""
    return json.dumps(
        {
            "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
            "dsseEnvelope": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(
                    json.dumps(statement, separators=(",", ":")).encode()
                ).decode(),
                "signatures": [{"sig": "e30="}],
            },
        }
    ).encode()


def provenance_shape_mutations() -> list[tuple[str, object]]:
    """Return provenance shape subTest paths and mutators for check f."""
    return [
        ("subject", lambda s: s.__setitem__("subject", "not-a-list")),
        ("subject[0]", lambda s: s.__setitem__("subject", ["bad"])),
        ("subject[0].digest", lambda s: s["subject"][0].__setitem__("digest", "bad")),
        ("predicate", lambda s: s.__setitem__("predicate", "bad")),
        (
            "predicate.buildDefinition",
            lambda s: s["predicate"].__setitem__("buildDefinition", "bad"),
        ),
        (
            "predicate.buildDefinition.externalParameters",
            lambda s: s["predicate"]["buildDefinition"].__setitem__("externalParameters", 1),
        ),
        (
            "predicate.buildDefinition.externalParameters.workflow",
            lambda s: s["predicate"]["buildDefinition"]["externalParameters"].__setitem__(
                "workflow", []
            ),
        ),
        (
            "predicate.buildDefinition.internalParameters",
            lambda s: s["predicate"]["buildDefinition"].__setitem__("internalParameters", []),
        ),
        (
            "predicate.buildDefinition.internalParameters.github",
            lambda s: s["predicate"]["buildDefinition"]["internalParameters"].__setitem__(
                "github", "bad"
            ),
        ),
        ("predicate.runDetails", lambda s: s["predicate"].__setitem__("runDetails", "bad")),
        (
            "predicate.runDetails.builder",
            lambda s: s["predicate"]["runDetails"].__setitem__("builder", []),
        ),
        (
            "predicate.buildDefinition.resolvedDependencies",
            lambda s: s["predicate"]["buildDefinition"].__setitem__("resolvedDependencies", {}),
        ),
        (
            "predicate.buildDefinition.resolvedDependencies[0].digest",
            lambda s: s["predicate"]["buildDefinition"]["resolvedDependencies"][0].__setitem__(
                "digest", "bad"
            ),
        ),
    ]


def aligned_predicate(template: dict, *, tag: str, commit: str) -> dict:
    """Return a copy of TEMPLATE with workflow pins aligned to TAG and COMMIT."""
    data = json.loads(json.dumps(template))
    tag_ref = f"refs/tags/{tag}"
    predicate = data["predicate"]
    predicate["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = commit
    predicate["buildDefinition"]["resolvedDependencies"][0]["uri"] = (
        f"git+https://github.com/{SIGNER}@{tag_ref}"
    )
    workflow = predicate["buildDefinition"]["externalParameters"]["workflow"]
    workflow["ref"] = tag_ref
    workflow["repository"] = f"https://github.com/{SIGNER}"
    predicate["runDetails"]["builder"]["id"] = admit_series.signer_identity(SIGNER, tag_ref)
    return data


def makefile_dist_files() -> tuple[str, ...]:
    """Return DIST_FILES words parsed from the Makefile."""
    words: list[str] = []
    capturing = False
    for line in (ROOT / "Makefile").read_text(encoding="utf-8").splitlines():
        if line.startswith("DIST_FILES ="):
            capturing = True
            fragment = line.split("=", 1)[1].strip()
        elif capturing:
            fragment = line.strip()
        else:
            continue
        continued = fragment.endswith("\\")
        if continued:
            fragment = fragment[:-1].strip()
        words.extend(fragment.split())
        if capturing and not continued:
            break
    return tuple(words)


class SeriesFixture:
    """Signed release assets for admission tests."""

    assets: Path
    tarball_sha256: str
    tag: str
    commit: str

    @classmethod
    def build(  # noqa: PLR0913
        cls,
        scratch: Path,
        *,
        tag: str = TAG,
        commit: str = COMMIT,
        base_env: str | None = None,
        series_text: str | None = None,
        predicate: dict | None = None,
        extra_members: list[tuple[str, bytes]] | None = None,
        tarball_override: bytes | None = None,
        include_symlink: bool = False,
        git_archive_dirs: bool = False,
        extra_dirs: tuple[str, ...] = (),
    ) -> SeriesFixture:
        """Create assets under SCRATCH and return the fixture metadata."""
        self = object.__new__(cls)
        self.tag = tag
        self.commit = commit
        self.assets = scratch / "assets"
        self.assets.mkdir()
        base = base_env or (
            f"FFMPEG_REMOTE={FFMPEG_REMOTE}\n"
            f"FFMPEG_TAG={FFMPEG_TAG}\n"
            f"FFMPEG_COMMIT={FFMPEG_COMMIT}\n"
        )
        series = series_text or "0001-alpha.patch\n0002-beta.patch\n"
        members = default_member_map(tag, base, series)
        if extra_members:
            for name, data in extra_members:
                members[name] = data
        tarball_path = self.assets / admit_series.tarball_name(tag)
        if tarball_override is not None:
            tarball_path.write_bytes(tarball_override)
        else:
            write_fixture_tarball(
                tarball_path,
                tag,
                members,
                git_archive_dirs=git_archive_dirs,
                extra_dirs=extra_dirs,
                include_symlink=include_symlink,
            )
        self.tarball_sha256 = hashlib.sha256(tarball_path.read_bytes()).hexdigest()
        sbom_path = self.assets / admit_series.sbom_name(tag)
        sbom_path.write_bytes(b"{}\n")
        self._write_sums(tag, sbom_path)
        cls._sign_assets(scratch, self, predicate)
        return self

    def _write_sums(self, tag: str, sbom_path: Path) -> None:
        """Write SHA256SUMS listing the tarball and SBOM digests."""
        lines = [
            f"{self.tarball_sha256}  {admit_series.tarball_name(tag)}\n",
            (
                f"{hashlib.sha256(sbom_path.read_bytes()).hexdigest()}  "
                f"{admit_series.sbom_name(tag)}\n"
            ),
        ]
        (self.assets / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")

    @staticmethod
    def _sign_assets(scratch: Path, fixture: SeriesFixture, predicate: dict | None) -> None:
        """Sign SHA256SUMS and the provenance bundle with a throwaway key."""
        generate_signer_keypair(scratch)
        sign_sums_bundle(
            scratch,
            fixture.assets / "SHA256SUMS",
            fixture.assets / "SHA256SUMS.sigstore.json",
        )
        sign_provenance_bundle(scratch, fixture, predicate)

    def admit_argv(self, *, extract: str = "", sha256: str | None = None) -> list[str]:
        """Return a default admit subcommand argv for this fixture."""
        digest = sha256 or self.tarball_sha256
        argv = [
            "admit",
            "--assets",
            str(self.assets),
            "--tag",
            self.tag,
            "--commit",
            self.commit,
            "--sha256",
            digest,
            "--signer-repository",
            SIGNER,
            "--ffmpeg-remote",
            FFMPEG_REMOTE,
            "--ffmpeg-tag",
            FFMPEG_TAG,
            "--ffmpeg-commit",
            FFMPEG_COMMIT,
            "--test-key",
            str(self.assets.parent / "signer.pub"),
        ]
        if extract:
            argv += ["--extract", extract]
        return argv


@unittest.skipIf(
    COSIGN is None and not os.environ.get("CI"),
    "cosign is not installed; CI installs it and runs these tests",
)
class AdmitCosignTest(unittest.TestCase):
    """Admission tests that need offline cosign signing."""

    fixture: SeriesFixture

    def setUp(self) -> None:
        """Build an isolated signed asset set for each test."""
        self._scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self._scratch.cleanup)
        self.fixture = SeriesFixture.build(Path(self._scratch.name))

    def test_g1_good_fixture_admits_and_extracts(self) -> None:
        """G1: a valid signed fixture exits 0 and optional extract writes the tree."""
        extract = Path(self._scratch.name) / "tree"
        status, out, err = admit(*self.fixture.admit_argv(extract=str(extract)))
        self.assertEqual(status, 0, err)
        self.assertIn(f"admitted {TAG} {COMMIT} {self.fixture.tarball_sha256}", out)
        self.assertTrue((extract / f"ffmpeg-patches-{TAG}" / "base.env").is_file())

    def test_r1_wrong_sha256_pin(self) -> None:
        """R1: a wrong --sha256 pin is refused at check b."""
        status, _, err = admit(*self.fixture.admit_argv(sha256="0" * 64))
        self.assertEqual(status, 1)
        self.assertIn("tarball sha256:", err)

    def test_r2_tarball_changed_sums_pin(self) -> None:
        """R2: a changed tarball breaks the SHA256SUMS line at check d."""
        tarball = self.fixture.assets / admit_series.tarball_name(TAG)
        tarball.write_bytes(b"tampered\n")
        new_sha = hashlib.sha256(tarball.read_bytes()).hexdigest()
        status, _, err = admit(*self.fixture.admit_argv(sha256=new_sha))
        self.assertEqual(status, 1)
        self.assertIn("SHA256SUMS tarball line:", err)

    def test_r3_sha256sums_changed(self) -> None:
        """R3: a tampered SHA256SUMS is refused at check c."""
        sums = self.fixture.assets / "SHA256SUMS"
        lines = sums.read_text(encoding="utf-8").splitlines()
        lines[0] = f"{'f' * 64}  {admit_series.tarball_name(TAG)}"
        sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
        status, _, err = admit(*self.fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("cosign refused:", err)

    def test_r4_sbom_changed(self) -> None:
        """R4: a changed SBOM is refused at check d."""
        sbom = self.fixture.assets / admit_series.sbom_name(TAG)
        sbom.write_bytes(b"{ }\n")
        status, _, err = admit(*self.fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("SHA256SUMS strict:", err)

    def _resign_sums(self, fixture: SeriesFixture) -> None:
        """Re-sign SHA256SUMS after a test edits it."""
        sums = fixture.assets / "SHA256SUMS"
        bundle = fixture.assets / "SHA256SUMS.sigstore.json"
        scratch = fixture.assets.parent
        subprocess.run(  # nosec B603 - cosign path and arguments are test fixtures.
            [
                COSIGN or "cosign",
                "sign-blob",
                "--yes",
                "--key",
                "signer.key",
                "--bundle",
                str(bundle),
                "--use-signing-config=false",
                "--tlog-upload=false",
                str(sums),
            ],
            cwd=scratch,
            env={**os.environ, "COSIGN_PASSWORD": ""},
            check=True,
            capture_output=True,
            timeout=120,
        )

    def test_r5_sums_lists_extra_name(self) -> None:
        """R5: an extra SHA256SUMS name is refused at check d."""
        sums = self.fixture.assets / "SHA256SUMS"
        sums.write_text(
            sums.read_text(encoding="utf-8") + f"{'a' * 64}  extra.json\n",
            encoding="utf-8",
        )
        self._resign_sums(self.fixture)
        status, _, err = admit(*self.fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("SHA256SUMS listing:", err)

    def test_r5_sums_repeats_tarball_line(self) -> None:
        """R5: a repeated tarball line violates the listing entry count."""
        sums = self.fixture.assets / "SHA256SUMS"
        tarball_line, sbom_line = sums.read_text(encoding="utf-8").splitlines()
        sums.write_text(f"{tarball_line}\n{tarball_line}\n{sbom_line}\n", encoding="utf-8")
        self._resign_sums(self.fixture)
        status, _, err = admit(*self.fixture.admit_argv())
        self.assertEqual(status, 1, err)
        self.assertIn("expected 2 names", err)

    def test_r5_sums_lists_tarball_name_twice(self) -> None:
        """R5: two tarball entries trigger the duplicate-name refusal."""
        sums = self.fixture.assets / "SHA256SUMS"
        tarball_line, _ = sums.read_text(encoding="utf-8").splitlines()
        sums.write_text(f"{tarball_line}\n{tarball_line}\n", encoding="utf-8")
        self._resign_sums(self.fixture)
        status, _, err = admit(*self.fixture.admit_argv())
        self.assertEqual(status, 1, err)
        self.assertIn("duplicate name", err)

    def test_r5_sums_substitutes_sbom_name(self) -> None:
        """R5: an existing substitute for the SBOM violates the listing name set."""
        sums = self.fixture.assets / "SHA256SUMS"
        tarball_line, _ = sums.read_text(encoding="utf-8").splitlines()
        substitute = self.fixture.assets / "substitute.json"
        substitute.write_bytes(b"{}\n")
        digest = hashlib.sha256(substitute.read_bytes()).hexdigest()
        sums.write_text(f"{tarball_line}\n{digest}  {substitute.name}\n", encoding="utf-8")
        self._resign_sums(self.fixture)
        status, _, err = admit(*self.fixture.admit_argv())
        self.assertEqual(status, 1, err)
        self.assertIn("SHA256SUMS listing: expected", err)

    def test_r6_wrong_series_commit_in_predicate(self) -> None:
        """R6: a wrong series commit in the predicate is refused at check f."""
        template = json.loads(PREDICATE_TEMPLATE.read_text(encoding="utf-8"))
        wrong = aligned_predicate(template, tag=TAG, commit=COMMIT)
        wrong["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = (
            "ffffffffffffffffffffffffffffffffffffffff"
        )
        scratch = Path(self._scratch.name) / "r6"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, predicate=wrong)
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("provenance commit:", err)

    def test_r7_predicate_workflow_ref_of_another_tag(self) -> None:
        """R7: a wrong workflow ref is refused at check f."""
        template = json.loads(PREDICATE_TEMPLATE.read_text(encoding="utf-8"))
        wrong = aligned_predicate(template, tag=TAG, commit=COMMIT)
        wrong["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["ref"] = (
            "refs/tags/v9.9.9"
        )
        scratch = Path(self._scratch.name) / "r7"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, predicate=wrong)
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("provenance workflow ref:", err)

    def test_r8_runner_environment_self_hosted(self) -> None:
        """R8: a self-hosted runner is refused at check f."""
        template = json.loads(PREDICATE_TEMPLATE.read_text(encoding="utf-8"))
        wrong = aligned_predicate(template, tag=TAG, commit=COMMIT)
        wrong["predicate"]["buildDefinition"]["internalParameters"]["github"][
            "runner_environment"
        ] = "self-hosted"
        scratch = Path(self._scratch.name) / "r8"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, predicate=wrong)
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("provenance runner:", err)

    def test_r9_builder_or_repository_of_another_repository(self) -> None:
        """R9: a wrong workflow repository is refused at check f."""
        template = json.loads(PREDICATE_TEMPLATE.read_text(encoding="utf-8"))
        wrong = aligned_predicate(template, tag=TAG, commit=COMMIT)
        wrong["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["repository"] = (
            "https://github.com/other/ffmpeg-patches"
        )
        scratch = Path(self._scratch.name) / "r9"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, predicate=wrong)
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("provenance workflow repository:", err)

    def test_r9b_predicate_builder_id_differs(self) -> None:
        """R9b: a wrong builder id is refused at check f."""
        template = json.loads(PREDICATE_TEMPLATE.read_text(encoding="utf-8"))
        wrong = aligned_predicate(template, tag=TAG, commit=COMMIT)
        wrong["predicate"]["runDetails"]["builder"]["id"] = (
            "https://github.com/other/ffmpeg-patches/.github/workflows/release-build.yml"
            "@refs/tags/v1.0.0"
        )
        scratch = Path(self._scratch.name) / "r9b"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, predicate=wrong)
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("provenance builder id:", err)

    def test_r10f_provenance_subject_digest_at_statement(self) -> None:
        """R10f: check_provenance_statement refuses a wrong subject digest."""
        prov = self.fixture.assets / admit_series.provenance_name(TAG)
        statement = admit_series.decode_statement(prov.read_bytes())
        statement["subject"][0]["digest"]["sha256"] = "f" * 64
        with self.assertRaises(admit_series.Refused) as caught:
            admit_series.check_provenance_statement(
                statement, TAG, COMMIT, self.fixture.tarball_sha256, SIGNER
            )
        self.assertIn("provenance subject digest:", str(caught.exception))

    def test_r10_subject_digest_differs(self) -> None:
        """R10: a tampered bundle subject digest is refused at check e."""
        fixture = self.fixture
        bundle_path = fixture.assets / admit_series.provenance_name(TAG)
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
        statement["subject"][0]["digest"]["sha256"] = "f" * 64
        bundle["dsseEnvelope"]["payload"] = base64.b64encode(
            json.dumps(statement).encode()
        ).decode()
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("cosign refused:", err)

    def test_r11_member_outside_prefix(self) -> None:
        """R11: a tarball member outside the prefix is refused at check g."""
        scratch = Path(self._scratch.name) / "r11"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(
            scratch,
            extra_members=[("rogue.txt", b"x")],
        )
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("tarball prefix:", err)

    def test_r12_symlink_member(self) -> None:
        """R12: a symlink member is refused at check g."""
        scratch = Path(self._scratch.name) / "r12"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, include_symlink=True)
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("tarball member type:", err)

    def test_r13_dotdot_member(self) -> None:
        """R13: a .. path is refused at check g."""
        scratch = Path(self._scratch.name) / "r13"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(
            scratch,
            extra_members=[(f"ffmpeg-patches-{TAG}/patches/../evil.patch", b"x")],
        )
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("tarball path:", err)

    def test_r14_member_not_under_dist_files(self) -> None:
        """R14: a path outside DIST_FILES is refused at check g."""
        scratch = Path(self._scratch.name) / "r14"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(
            scratch,
            extra_members=[(f"ffmpeg-patches-{TAG}/extra.bin", b"x")],
        )
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("tarball dist:", err)

    def test_r15_base_env_ffmpeg_commit_differs(self) -> None:
        """R15: a wrong FFMPEG_COMMIT in base.env is refused at check h."""
        base = (
            f"FFMPEG_REMOTE={FFMPEG_REMOTE}\n"
            f"FFMPEG_TAG={FFMPEG_TAG}\n"
            "FFMPEG_COMMIT=ffffffffffffffffffffffffffffffffffffffff\n"
        )
        scratch = Path(self._scratch.name) / "r15"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, base_env=base)
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("base.env FFMPEG_COMMIT:", err)

    def test_r16_base_env_remote_differs(self) -> None:
        """R16: a wrong FFMPEG_REMOTE in base.env is refused at check h."""
        base = (
            "FFMPEG_REMOTE=https://example.invalid/ffmpeg.git\n"
            f"FFMPEG_TAG={FFMPEG_TAG}\n"
            f"FFMPEG_COMMIT={FFMPEG_COMMIT}\n"
        )
        scratch = Path(self._scratch.name) / "r16"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, base_env=base)
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("base.env FFMPEG_REMOTE:", err)

    def test_r17_base_env_command_substitution_or_duplicate_key(self) -> None:
        """R17: shell substitution or duplicate keys in base.env are refused at check h."""
        for index, base in enumerate(
            (
                (
                    f"FFMPEG_REMOTE=$(echo x)\nFFMPEG_TAG={FFMPEG_TAG}\n"
                    f"FFMPEG_COMMIT={FFMPEG_COMMIT}\n"
                ),
                (
                    f"FFMPEG_REMOTE={FFMPEG_REMOTE}\nFFMPEG_TAG={FFMPEG_TAG}\n"
                    f"FFMPEG_COMMIT={FFMPEG_COMMIT}\nFFMPEG_TAG=duplicate\n"
                ),
            )
        ):
            with self.subTest(base=base[:20]):
                scratch = Path(self._scratch.name) / f"r17-{index}"
                scratch.mkdir(exist_ok=True)
                fixture = SeriesFixture.build(scratch, base_env=base)
                status, _, err = admit(*fixture.admit_argv())
                self.assertEqual(status, 1)
                self.assertIn("base.env:", err)

    def test_r18_series_txt_names_missing_patch(self) -> None:
        """R18: a series.txt entry with no patch file is refused at check i."""
        scratch = Path(self._scratch.name) / "r18"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, series_text="0001-alpha.patch\n9999-missing.patch\n")
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("series.txt: patch", err)

    def test_r19_patch_member_not_listed_in_series_txt(self) -> None:
        """R19: an unlisted patch member is refused at check i."""
        scratch = Path(self._scratch.name) / "r19"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, series_text="0001-alpha.patch\n")
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("series.txt: patch member", err)

    def test_g2_git_archive_directory_layout(self) -> None:
        """G2: directory members matching the v0.7.0 git-archive layout admit."""
        scratch = Path(self._scratch.name) / "g2"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, git_archive_dirs=True)
        extract = scratch / "tree"
        status, out, err = admit(*fixture.admit_argv(extract=str(extract)))
        self.assertEqual(status, 0, err)
        self.assertIn("admitted", out)
        self.assertTrue((extract / f"ffmpeg-patches-{TAG}" / "scripts" / "series.py").is_file())

    def test_g3_existing_empty_extract_destination(self) -> None:
        """G3: --extract accepts an existing empty destination directory."""
        extract = Path(self._scratch.name) / "empty"
        extract.mkdir()
        status, _, err = admit(*self.fixture.admit_argv(extract=str(extract)))
        self.assertEqual(status, 0, err)

    def test_r22_disallowed_directory_member(self) -> None:
        """R22: a docs/ directory member is refused at check g."""
        scratch = Path(self._scratch.name) / "r22"
        scratch.mkdir(exist_ok=True)
        prefix = f"ffmpeg-patches-{TAG}/"
        fixture = SeriesFixture.build(
            scratch,
            git_archive_dirs=True,
            extra_dirs=(f"{prefix}docs",),
        )
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("docs", err)

    def test_r30_statement_shapes(self) -> None:
        """R30: wrong provenance field types refuse at check f with a shape path."""
        prov = self.fixture.assets / admit_series.provenance_name(TAG)
        good = admit_series.decode_statement(prov.read_bytes())
        for path, mutate in provenance_shape_mutations():
            with self.subTest(path=path):
                statement = json.loads(json.dumps(good))
                mutate(statement)
                raw = bundle_bytes_from_statement(statement)
                with unittest.mock.patch.object(
                    admit_series, "verify_tarball_attestation", return_value=raw
                ):
                    status, _, err = admit(*self.fixture.admit_argv())
                self.assertEqual(status, 1)
                self.assertIn(f"provenance shape: {path}", err)
                self.assertNotIn("Traceback", err)

    def test_r31_bounded_provenance_text(self) -> None:
        """R31: a megabyte workflow ref yields a short refusal line with length."""
        template = json.loads(PREDICATE_TEMPLATE.read_text(encoding="utf-8"))
        wrong = aligned_predicate(template, tag=TAG, commit=COMMIT)
        huge = "x" * (1024 * 1024)
        wrong["predicate"]["buildDefinition"]["externalParameters"]["workflow"]["ref"] = huge
        scratch = Path(self._scratch.name) / "r31"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, predicate=wrong)
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("provenance workflow ref:", err)
        self.assertLess(len(err), 400)
        self.assertIn("(length ", err)

    def test_r23_statement_type_v01(self) -> None:
        """R23: in-toto Statement v0.1 is refused at check f."""
        statement = json.loads(PREDICATE_TEMPLATE.read_text(encoding="utf-8"))
        statement["subject"][0]["name"] = admit_series.tarball_name(TAG)
        statement["subject"][0]["digest"]["sha256"] = self.fixture.tarball_sha256
        statement["subject"][1]["name"] = admit_series.sbom_name(TAG)
        statement["subject"][1]["digest"]["sha256"] = hashlib.sha256(
            (self.fixture.assets / admit_series.sbom_name(TAG)).read_bytes()
        ).hexdigest()
        statement["_type"] = "https://in-toto.io/Statement/v0.1"
        bundle_bytes = json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
                "dsseEnvelope": {
                    "payloadType": "application/vnd.in-toto+json",
                    "payload": base64.b64encode(
                        json.dumps(statement, separators=(",", ":")).encode()
                    ).decode(),
                    "signatures": [{"sig": "e30="}],
                },
            }
        ).encode()
        prior = _DecodeUpgradeState.enabled
        _DecodeUpgradeState.enabled = False
        self.addCleanup(setattr, _DecodeUpgradeState, "enabled", prior)
        with unittest.mock.patch.object(
            admit_series, "verify_tarball_attestation", return_value=bundle_bytes
        ):
            status, _, err = admit(*self.fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("provenance _type:", err)

    def test_r24_malformed_provenance_bundle(self) -> None:
        """R24: malformed provenance bundles exit 1 at check f without a traceback."""
        cases: list[tuple[bytes, str]] = [
            (b"not json", "provenance bundle: not JSON"),
            (b"[]", "provenance bundle: not an object"),
            (b'{"dsseEnvelope":{}}', "provenance bundle: without dsseEnvelope or payload"),
            (
                b'{"dsseEnvelope":{"payload":"%%%"}}',
                "provenance bundle: payload not base64",
            ),
            (
                b'{"dsseEnvelope":{"payload":"YQ=="}}',
                "provenance bundle: payload not JSON",
            ),
        ]
        for raw, needle in cases:
            with self.subTest(needle=needle):
                with unittest.mock.patch.object(
                    admit_series, "verify_tarball_attestation", return_value=raw
                ):
                    status, _, err = admit(*self.fixture.admit_argv())
                self.assertEqual(status, 1)
                self.assertIn(needle, err)
                self.assertNotIn("Traceback", err)

    def test_r25_tarball_not_gzip_tar(self) -> None:
        """R25: a non-tarball file is refused at check g."""
        override = b"plain text, not a gzip tarball"
        scratch = Path(self._scratch.name) / "r25"
        scratch.mkdir(exist_ok=True)
        fixture = SeriesFixture.build(scratch, tarball_override=override)
        status, _, err = admit(*fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("tarball archive:", err)

    def test_r26_member_text_not_utf8(self) -> None:
        """R26: non-UTF-8 base.env or series.txt bytes are refused at h or i."""
        prefix = f"ffmpeg-patches-{TAG}/"
        for key, needle in (
            ("base.env", "base.env: not UTF-8"),
            ("series.txt", "series.txt: not UTF-8"),
        ):
            with self.subTest(key=key):
                scratch = Path(self._scratch.name) / f"r26-{key}"
                scratch.mkdir(exist_ok=True)
                fixture = SeriesFixture.build(
                    scratch,
                    extra_members=[(f"{prefix}{key}", b"\xff")],
                )
                status, _, err = admit(*fixture.admit_argv())
                self.assertEqual(status, 1)
                self.assertIn(needle, err)

    def test_r27_bad_member_path_parts(self) -> None:
        """R27: double slashes or a dot path part are refused at check g."""
        prefix = f"ffmpeg-patches-{TAG}/"
        for name in (f"{prefix}patches//evil.patch", f"{prefix}patches/./evil.patch"):
            with self.subTest(name=name):
                scratch = Path(self._scratch.name) / f"r27-{len(name)}"
                scratch.mkdir(exist_ok=True)
                fixture = SeriesFixture.build(scratch, extra_members=[(name, b"x")])
                status, _, err = admit(*fixture.admit_argv())
                self.assertEqual(status, 1)
                self.assertIn("tarball path:", err)

    def test_r29_file_over_hash_cap(self) -> None:
        """R29: a file larger than the hash cap is refused with its name."""
        with unittest.mock.patch.object(admit_series, "MAX_HASH_BYTES", 8):
            status, _, err = admit(*self.fixture.admit_argv())
        self.assertEqual(status, 1)
        self.assertIn("file hash cap:", err)


class CosignNotExecutableTest(unittest.TestCase):
    def test_r28_cosign_not_executable(self) -> None:
        """R28: cosign present but not runnable exits 2 naming cosign is not installed."""
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        assets = Path(scratch.name) / "assets"
        assets.mkdir()
        blob = b"fixture\n"
        tarball = assets / admit_series.tarball_name(TAG)
        tarball.write_bytes(blob)
        digest = hashlib.sha256(blob).hexdigest()
        argv = [
            "admit",
            "--assets",
            str(assets),
            "--tag",
            TAG,
            "--commit",
            COMMIT,
            "--sha256",
            digest,
            "--signer-repository",
            SIGNER,
            "--ffmpeg-remote",
            FFMPEG_REMOTE,
            "--ffmpeg-tag",
            FFMPEG_TAG,
            "--ffmpeg-commit",
            FFMPEG_COMMIT,
        ]
        fake_bin = Path(scratch.name) / "bin"
        fake_bin.mkdir()
        (fake_bin / "cosign").write_text("not executable\n", encoding="utf-8")
        (fake_bin / "cosign").chmod(0o644)
        with unittest.mock.patch.dict(os.environ, {"PATH": str(fake_bin)}):
            status, _, err = admit(*argv)
        self.assertEqual(status, 2)
        self.assertIn("cosign is not installed", err)


def base_pin_argv(assets: Path) -> list[str]:
    """Return a default admit argv with well-formed pin shapes except as overridden."""
    return [
        "admit",
        "--assets",
        str(assets),
        "--tag",
        TAG,
        "--commit",
        COMMIT,
        "--sha256",
        "b" * 64,
        "--signer-repository",
        SIGNER,
        "--ffmpeg-remote",
        FFMPEG_REMOTE,
        "--ffmpeg-tag",
        FFMPEG_TAG,
        "--ffmpeg-commit",
        FFMPEG_COMMIT,
    ]


class PinShapeTest(unittest.TestCase):
    def _assert_pin_refused(self, root: Path, edits: dict[int, str], needle: str) -> None:
        """Run admit with ARGV slots EDITS replaced and assert refusal NEEDLE."""
        argv = base_pin_argv(root)
        for index, value in edits.items():
            argv[index] = value
        status, _, err = admit(*argv)
        self.assertEqual(status, 1)
        self.assertIn(needle, err)

    def test_r21_malformed_pins(self) -> None:
        """R21: malformed pins are refused at check a before cosign."""
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        self._assert_pin_refused(root, {4: "not-a-tag"}, "pin shape tag:")
        self._assert_pin_refused(root, {6: "SHORT"}, "pin shape commit:")
        self._assert_pin_refused(root, {8: "F" * 64}, "pin shape sha256:")
        self._assert_pin_refused(root, {10: "bad signer name"}, "pin shape signer repository:")


class CosignMissingTest(unittest.TestCase):
    def test_r20_cosign_missing_exits_2(self) -> None:
        """R20: missing cosign exits 2 with a clear message."""
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        assets = Path(scratch.name) / "assets"
        assets.mkdir()
        blob = b"cosign-missing-fixture\n"
        tarball = assets / admit_series.tarball_name(TAG)
        tarball.write_bytes(blob)
        digest = hashlib.sha256(blob).hexdigest()
        base_argv = [
            "admit",
            "--assets",
            str(assets),
            "--tag",
            TAG,
            "--commit",
            COMMIT,
            "--sha256",
            digest,
            "--signer-repository",
            SIGNER,
            "--ffmpeg-remote",
            FFMPEG_REMOTE,
            "--ffmpeg-tag",
            FFMPEG_TAG,
            "--ffmpeg-commit",
            FFMPEG_COMMIT,
        ]
        empty_bin = Path(scratch.name) / "empty-path-bin"
        empty_bin.mkdir(parents=True, exist_ok=True)
        with unittest.mock.patch.dict(os.environ, {"PATH": str(empty_bin)}):
            status, _, err = admit(*base_argv)
        self.assertEqual(status, 2)
        self.assertIn("cosign is not installed", err)


class ArgvTest(unittest.TestCase):
    def test_a1_keyless_argv_for_v070(self) -> None:
        """A1: keyless cosign argv lists match the v0.7.0 VMAFx release pins."""
        tag = "v0.7.0"
        commit = "c84de852dad9a25d8415939b823c3ebc319b70b1"
        repo = V070_SIGNER_REPOSITORY
        sums = Path("SHA256SUMS")
        sums_bundle = Path("SHA256SUMS.sigstore.json")
        tarball = Path(admit_series.tarball_name(tag))
        prov = Path(admit_series.provenance_name(tag))
        identity = (
            f"https://github.com/{V070_SIGNER_REPOSITORY}/.github/workflows/"
            "release-build.yml@refs/tags/v0.7.0"
        )
        shared = [
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            admit_series.OIDC_ISSUER,
            "--certificate-github-workflow-ref",
            "refs/tags/v0.7.0",
            "--certificate-github-workflow-sha",
            commit,
        ]
        binding = admit_series.SignerBinding(repo, tag, commit)
        self.assertEqual(
            admit_series.sums_verify_argv(sums, sums_bundle, binding, None),
            ["cosign", "verify-blob", "--bundle", str(sums_bundle), *shared, str(sums)],
        )
        self.assertEqual(
            admit_series.attestation_verify_argv(tarball, prov, binding, None),
            [
                "cosign",
                "verify-blob-attestation",
                "--bundle",
                str(prov),
                "--type",
                "slsaprovenance1",
                *shared,
                str(tarball),
            ],
        )


class FakeUrlResponse:
    """Return bounded bytes from a mocked HTTPS body."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        """Return the next SIZE bytes from the mocked response body."""
        if size < 0:
            size = len(self._data) - self._offset
        chunk = self._data[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def __enter__(self) -> FakeUrlResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class FetchTest(unittest.TestCase):
    def setUp(self) -> None:
        """Create a scratch directory for fetch tests."""
        self._scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self._scratch.cleanup)
        self.root = Path(self._scratch.name)

    def _patch_fetch_opener(self, side_effect: object):
        """Patch urllib opener construction to run SIDE_EFFECT on each download."""
        opener = unittest.mock.MagicMock()
        opener.open.side_effect = side_effect
        return unittest.mock.patch("urllib.request.build_opener", return_value=opener)

    def _assert_fetch_repository_refused(self, urls: list[str]) -> None:
        """Assert malformed repository pins are refused before any download."""
        status, _, err = admit(
            "fetch", "--repository", "bad repo", "--tag", TAG, "--dest", str(self.root / "d1")
        )
        self.assertEqual(status, 1)
        self.assertIn("fetch pin shape repository:", err)
        self.assertEqual(urls, [])

    def _assert_non_empty_dest_refused(self) -> None:
        """Assert fetch refuses a destination that already holds files."""
        blocked = self.root / "blocked"
        blocked.mkdir()
        (blocked / "occupied").write_text("x", encoding="utf-8")
        status, _, err = admit(
            "fetch", "--repository", SIGNER, "--tag", TAG, "--dest", str(blocked)
        )
        self.assertEqual(status, 1)
        self.assertIn("fetch: destination", err)

    def _assert_oversize_asset_refused(self) -> None:
        """Assert fetch refuses a single asset larger than the size cap."""
        huge_dest = self.root / "huge"
        over = b"x" * (admit_series.FETCH_CHUNK + 1)

        def huge_urlopen(request, timeout=0):  # noqa: ANN001
            return FakeUrlResponse(over * (admit_series.MAX_ASSET_BYTES // len(over) + 2))

        with self._patch_fetch_opener(huge_urlopen):
            status, _, err = admit(
                "fetch", "--repository", SIGNER, "--tag", TAG, "--dest", str(huge_dest)
            )
            self.assertEqual(status, 1)
            self.assertIn("fetch size:", err)

    def _assert_successful_fetch_order(self, urls: list[str]) -> None:
        """Assert fetch downloads the five assets in release order."""
        ok_dest = self.root / "ok"

        def fake_urlopen(request, timeout=0):  # noqa: ANN001
            urls.append(request.full_url)
            self.assertEqual(timeout, 60)
            return FakeUrlResponse(b"x" * 512)

        with self._patch_fetch_opener(fake_urlopen):
            status, _, _ = admit(
                "fetch", "--repository", SIGNER, "--tag", TAG, "--dest", str(ok_dest)
            )
            self.assertEqual(status, 0)
            expected = [
                f"https://github.com/{SIGNER}/releases/download/{TAG}/{name}"
                for name in admit_series.fetch_asset_names(TAG)
            ]
            self.assertEqual(urls, expected)

    def test_f1_fetch_urls_order_size_and_validation(self) -> None:
        """F1: fetch validates pins, refuses a non-empty DEST and caps asset size."""
        urls: list[str] = []
        self._assert_fetch_repository_refused(urls)
        self._assert_non_empty_dest_refused()
        self._assert_oversize_asset_refused()
        urls.clear()
        self._assert_successful_fetch_order(urls)

    def test_g3_existing_empty_fetch_destination(self) -> None:
        """G3: fetch accepts an existing empty destination directory."""
        empty = self.root / "empty-fetch"
        empty.mkdir()

        def fake_urlopen(request, timeout=0):  # noqa: ANN001
            return FakeUrlResponse(b"y" * 128)

        with self._patch_fetch_opener(fake_urlopen):
            status, _, err = admit(
                "fetch", "--repository", SIGNER, "--tag", TAG, "--dest", str(empty)
            )
        self.assertEqual(status, 0, err)

    def test_f3_fetch_read_timeout(self) -> None:
        """F3: a socket read timeout refuses fetch read and removes the partial file."""
        dest = self.root / "timeout"
        names = admit_series.fetch_asset_names(TAG)
        calls = {"n": 0}

        def stepped_urlopen(request, timeout=0):  # noqa: ANN001
            calls["n"] += 1
            if calls["n"] == 1:
                return FakeUrlResponse(b"a" * 64)
            if calls["n"] == 2:

                class TimeoutOnRead:
                    def read(self, size: int = -1) -> bytes:
                        raise TimeoutError("timed out")

                    def __enter__(self) -> TimeoutOnRead:
                        return self

                    def __exit__(self, *args: object) -> None:
                        return None

                return TimeoutOnRead()
            return FakeUrlResponse(b"b" * 64)

        with self._patch_fetch_opener(stepped_urlopen):
            status, _, err = admit(
                "fetch", "--repository", SIGNER, "--tag", TAG, "--dest", str(dest)
            )
        self.assertEqual(status, 1)
        self.assertIn("fetch read:", err)
        self.assertTrue((dest / names[0]).is_file())
        self.assertFalse(any(path.name.endswith(".part") for path in dest.iterdir()))

    def test_f4_fetch_incomplete_read(self) -> None:
        """F4: IncompleteRead during fetch refuses and removes the partial file."""
        dest = self.root / "incomplete"

        def bad_urlopen(request, timeout=0):  # noqa: ANN001
            class IncompleteResponse:
                def read(self, size: int = -1) -> bytes:
                    raise http.client.IncompleteRead(b"partial")

                def __enter__(self) -> IncompleteResponse:
                    return self

                def __exit__(self, *args: object) -> None:
                    return None

            return IncompleteResponse()

        with self._patch_fetch_opener(bad_urlopen):
            status, _, err = admit(
                "fetch", "--repository", SIGNER, "--tag", TAG, "--dest", str(dest)
            )
        self.assertEqual(status, 1)
        self.assertIn("fetch read:", err)
        self.assertFalse(any(path.name.endswith(".part") for path in dest.iterdir()))

    def test_f5_fetch_write_oserror(self) -> None:
        """F5: ENOSPC while writing the partial file refuses fetch and cleans up."""
        dest = self.root / "enospc"
        real_open = Path.open

        def open_fail_part(self, mode="r", *args, **kwargs):  # noqa: ANN001
            if self.name.endswith(".part") and "b" in mode:

                class BadWriter:
                    def write(self, data: bytes) -> int:
                        raise OSError(28, "No space left on device")

                    def __enter__(self) -> BadWriter:
                        return self

                    def __exit__(self, *args: object) -> None:
                        return None

                return BadWriter()
            return real_open(self, mode, *args, **kwargs)

        def fake_urlopen(request, timeout=0):  # noqa: ANN001
            return FakeUrlResponse(b"z" * 4096)

        with (
            unittest.mock.patch.object(Path, "open", open_fail_part),
            self._patch_fetch_opener(fake_urlopen),
        ):
            status, _, err = admit(
                "fetch", "--repository", SIGNER, "--tag", TAG, "--dest", str(dest)
            )
        self.assertEqual(status, 1)
        self.assertIn("fetch read:", err)
        self.assertFalse(any(path.name.endswith(".part") for path in dest.iterdir()))

    def test_f6_fetch_connection_reset(self) -> None:
        """F6: ConnectionResetError on read refuses fetch read."""
        dest = self.root / "reset"

        def reset_urlopen(request, timeout=0):  # noqa: ANN001
            class ResetResponse:
                def read(self, size: int = -1) -> bytes:
                    raise ConnectionResetError("connection reset")

                def __enter__(self) -> ResetResponse:
                    return self

                def __exit__(self, *args: object) -> None:
                    return None

            return ResetResponse()

        with self._patch_fetch_opener(reset_urlopen):
            status, _, err = admit(
                "fetch", "--repository", SIGNER, "--tag", TAG, "--dest", str(dest)
            )
        self.assertEqual(status, 1)
        self.assertIn("fetch read:", err)

    def test_f7_redirect_downgrade(self) -> None:
        """F7: redirects to non-https targets refuse; https targets are allowed."""
        handler = admit_series.HttpsOnlyRedirectHandler()
        request = urllib.request.Request("https://example.com/start")
        with self.assertRaises(admit_series.Refused) as caught:
            handler.redirect_request(request, None, 302, "Found", {}, "http://downgrade.example/x")
        self.assertIn("fetch redirect:", str(caught.exception))
        allowed = handler.redirect_request(
            request, None, 302, "Found", {}, "https://example.com/ok"
        )
        self.assertIsNotNone(allowed)
        dest = self.root / "handler-opener"
        handlers: list[object] = []
        mock_opener = unittest.mock.MagicMock()
        mock_opener.open.side_effect = lambda req, timeout=0: FakeUrlResponse(b"x" * 8)

        def record_build_opener(*args: object) -> unittest.mock.MagicMock:
            if args:
                handlers.append(args[0])
            return mock_opener

        with unittest.mock.patch("urllib.request.build_opener", side_effect=record_build_opener):
            admit("fetch", "--repository", SIGNER, "--tag", TAG, "--dest", str(dest))
        self.assertEqual(len(handlers), len(admit_series.fetch_asset_names(TAG)))
        self.assertTrue(
            all(handler is admit_series.HttpsOnlyRedirectHandler for handler in handlers)
        )

    def test_f2_fetch_keeps_completed_assets_without_part_files(self) -> None:
        """F2: a late size refusal keeps earlier assets and removes partial downloads."""
        dest = self.root / "partial"
        names = admit_series.fetch_asset_names(TAG)
        calls = {"n": 0}

        def stepped_urlopen(request, timeout=0):  # noqa: ANN001
            calls["n"] += 1
            if calls["n"] <= 2:
                return FakeUrlResponse(b"z" * 256)
            over = b"x" * (admit_series.MAX_ASSET_BYTES + 1)
            return FakeUrlResponse(over)

        with self._patch_fetch_opener(stepped_urlopen):
            status, _, err = admit(
                "fetch", "--repository", SIGNER, "--tag", TAG, "--dest", str(dest)
            )
        self.assertEqual(status, 1)
        self.assertIn("fetch size:", err)
        self.assertTrue((dest / names[0]).is_file())
        self.assertTrue((dest / names[1]).is_file())
        self.assertFalse(any(path.name.endswith(".part") for path in dest.iterdir()))


class DistFilesTest(unittest.TestCase):
    def test_d1_dist_files_matches_makefile(self) -> None:
        """D1: DIST_FILES equals the Makefile word list."""
        self.assertEqual(admit_series.DIST_FILES, makefile_dist_files())


@unittest.skipUnless(os.environ.get("ADMIT_SERIES_LIVE_ASSETS"), "host live assets directory")
class LiveAdmitTest(unittest.TestCase):
    def test_l1_live_v070_pins(self) -> None:
        """L1: opt-in live v0.7.0 assets admit with the real pins."""
        assets = Path(os.environ["ADMIT_SERIES_LIVE_ASSETS"])
        tag = "v0.7.0"
        good_commit = "c84de852dad9a25d8415939b823c3ebc319b70b1"
        sha = "b880f99128a94bf36a54416a026dcc064e7765d43c9ec96971ddf85580f86d8a"
        argv = [
            "admit",
            "--assets",
            str(assets),
            "--tag",
            tag,
            "--commit",
            good_commit,
            "--sha256",
            sha,
            "--signer-repository",
            V070_SIGNER_REPOSITORY,
            "--ffmpeg-remote",
            FFMPEG_REMOTE,
            "--ffmpeg-tag",
            FFMPEG_TAG,
            "--ffmpeg-commit",
            FFMPEG_COMMIT,
        ]
        status, out, err = admit(*argv)
        self.assertEqual(status, 0, err)
        self.assertIn(f"admitted {tag} {good_commit} {sha}", out)
        wrong_commit = "7641804bdd5e73040e4b84f63440a88f4cc20576"
        status, _, err = admit(*argv_with_flag_value(argv, "--commit", wrong_commit))
        self.assertEqual(status, 1)
        self.assertIn("::error::cosign refused", err)
        status, _, err = admit(*argv_with_flag_value(argv, "--signer-repository", SIGNER))
        self.assertEqual(status, 1)
        self.assertIn("::error::cosign refused", err)


class ArgvFlagEditTest(unittest.TestCase):
    def test_replaces_value_after_flag_and_leaves_input_unchanged(self) -> None:
        """argv_with_flag_value replaces the value after the flag and leaves argv intact."""
        argv = ["admit", "--commit", "aaa", "--sha256", "bbb"]
        out = argv_with_flag_value(argv, "--commit", "ccc")
        self.assertEqual(out, ["admit", "--commit", "ccc", "--sha256", "bbb"])
        self.assertEqual(argv, ["admit", "--commit", "aaa", "--sha256", "bbb"])

    def test_absent_flag_fails_with_flag_named(self) -> None:
        """argv_with_flag_value raises when the flag is absent from argv."""
        with self.assertRaises(ValueError) as caught:
            argv_with_flag_value(["admit"], "--missing", "x")
        self.assertIn("--missing", str(caught.exception))

    def test_duplicate_flag_fails_with_flag_named(self) -> None:
        """argv_with_flag_value raises when the flag appears more than once."""
        argv = ["admit", "--commit", "a", "--commit", "b"]
        with self.assertRaises(ValueError) as caught:
            argv_with_flag_value(argv, "--commit", "c")
        self.assertIn("--commit", str(caught.exception))

    def test_flag_last_element_fails_with_flag_named(self) -> None:
        """argv_with_flag_value raises when the flag is the last argv element."""
        with self.assertRaises(ValueError) as caught:
            argv_with_flag_value(["admit", "--commit"], "--commit", "c")
        self.assertIn("--commit", str(caught.exception))


class ReadSumsMessageTest(unittest.TestCase):
    def test_m1_read_sums_messages_carry_listing_path(self) -> None:
        """M1: read_sums errors name the SHA256SUMS path that was given."""
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        sums = Path(scratch.name) / "SHA256SUMS"
        sums.write_text("", encoding="utf-8")
        with self.assertRaises(admit_series.Refused) as caught:
            admit_series.read_sums(sums)
        self.assertIn(f"{sums}: lists no file", str(caught.exception))
        sums.write_text("not-a-line\n", encoding="utf-8")
        with self.assertRaises(admit_series.Refused) as caught:
            admit_series.read_sums(sums)
        self.assertIn(f"{sums}:1: not a SHA-256 checksum line", str(caught.exception))


class TracebackSweepTest(unittest.TestCase):
    def test_t1_no_traceback_in_collected_stderr(self) -> None:
        """T1: no admit main() run in this module printed a Python traceback."""
        joined = "\n".join(_ADMIT_STDERR_LOG)
        self.assertNotIn("Traceback", joined)


def tearDownModule() -> None:
    """Fail the module when any admit() call left a traceback on stderr."""
    joined = "\n".join(_ADMIT_STDERR_LOG)
    if "Traceback" in joined:
        raise AssertionError("Traceback found in admit stderr collected during module tests")


if __name__ == "__main__":
    unittest.main()
