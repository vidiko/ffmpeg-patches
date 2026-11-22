# Consumer series admission

Downstream repositories that build against a released ffmpeg-patches series
should download the signed release assets and run the shared admission helper
before they trust a tarball. The helper lives in
[`scripts/admit_series.py`](../scripts/admit_series.py); behaviour is locked by
[`tests/test_admit_series.py`](../tests/test_admit_series.py).

## Newcomer path

### Pins you record

Alongside the series tag and tarball SHA-256, record the **series commit**, the
**signer repository** (`OWNER/NAME` at release time), and the FFmpeg base pins
from `base.env`. The v0.7.0 values verified on the host are:

| Pin | v0.7.0 value |
| :--- | :--- |
| Series tag | `v0.7.0` |
| Series commit | `c84de852dad9a25d8415939b823c3ebc319b70b1` |
| Tarball SHA-256 | `b880f99128a94bf36a54416a026dcc064e7765d43c9ec96971ddf85580f86d8a` |
| Signer repository | `VMAFx/ffmpeg-patches` |
| `FFMPEG_REMOTE` | `https://github.com/FFmpeg/FFmpeg.git` |
| `FFMPEG_TAG` | `n9.0.2` |
| `FFMPEG_COMMIT` | `946fcce07b6dcd0331c8cc609192aeff5e1924f8` |

The signer repository is its own pin: v0.7.0 certificates name the
repository as it was named before the move to `vidiko` (the pin in the table
above), not the current slug. Admission with `vidiko/ffmpeg-patches` as the
signer refuses (see live check `L1` in
[`tests/test_admit_series.py`](../tests/test_admit_series.py)).

Consumer pin migration for vmafx is tracked in
[vmafx#3313](https://github.com/vidiko/vmafx/issues/3313).

### Release assets

Each GitHub release publishes five files (built by
[`.github/workflows/release-build.yml`](../.github/workflows/release-build.yml)):

1. `ffmpeg-patches-<tag>.tar.gz`
2. `ffmpeg-patches-<tag>.spdx.json`
3. `ffmpeg-patches-<tag>.provenance.sigstore.json`
4. `SHA256SUMS`
5. `SHA256SUMS.sigstore.json`

### Commands

Download assets into an empty directory (HTTPS only, 60 s timeout per file,
HTTPS-only redirects, no partial `.part` left on read errors):

```bash
python3 admit_series.py fetch \
  --repository vidiko/ffmpeg-patches \
  --tag v0.7.0 \
  --dest ./assets
```

Admit with your recorded pins (optional `--extract` after all checks pass):

```bash
python3 admit_series.py admit \
  --assets ./assets \
  --tag v0.7.0 \
  --commit c84de852dad9a25d8415939b823c3ebc319b70b1 \
  --sha256 b880f99128a94bf36a54416a026dcc064e7765d43c9ec96971ddf85580f86d8a \
  --signer-repository VMAFx/ffmpeg-patches \
  --ffmpeg-remote https://github.com/FFmpeg/FFmpeg.git \
  --ffmpeg-tag n9.0.2 \
  --ffmpeg-commit 946fcce07b6dcd0331c8cc609192aeff5e1924f8 \
  --extract ./series-tree
```

Exit status: **0** prints `admitted <tag> <commit> <sha256>`; **1** prints one
`::error::` line naming the failed check; **2** prints one `::error::` line when
Python &lt; 3.12 (plain `error:`) or the helper cannot read an asset or run
`cosign` (the helper never skips cosign).

### Vendor the helper

Copy [`scripts/admit_series.py`](../scripts/admit_series.py) from a **known git
commit** of this repository and pin both that commit and the file SHA-256 in your
own supply-chain metadata. A helper taken from the same release tarball it
verifies proves nothing.

## Reference

### Checks (in order)

The `admit` subcommand runs checks **a** through **j** in
[`scripts/admit_series.py`](../scripts/admit_series.py); the first failure
decides the exit status and message:

| Step | What it verifies |
| :--- | :--- |
| a | Tag, commits and SHA-256 pin shapes |
| b | Tarball file digest equals `--sha256` |
| c | `cosign verify-blob` on `SHA256SUMS` (keyless identity bound to signer repo, tag ref, series commit) |
| d | `SHA256SUMS` lists exactly the tarball and SBOM, strict `sha256sum --check` |
| e | `cosign verify-blob-attestation` on the tarball (`slsaprovenance1`) with the same keyless bindings |
| f | Decoded provenance statement: typed SLSA object graph, subject digest, git commit, workflow, runner, builder (refusal text bounded) |
| g | Tarball members: prefix, types, `DIST_FILES` allow-list (see [`Makefile`](../Makefile)) |
| h | `base.env` text pins for FFmpeg remote, tag and commit |
| i | `series.txt` matches `patches/*.patch` |
| j | Optional `--extract` with tar `filter="data"` |

Refusal cases **R1–R31** and fetch cases **F1–F7** in
[`tests/test_admit_series.py`](../tests/test_admit_series.py) map one-to-one to
these checks.

### Mapping from vmafx and pelorus

| Concern | vmafx today | pelorus today | Shared helper |
| :--- | :--- | :--- | :--- |
| Tarball SHA-256 pin | yes | yes | check **b** |
| `SHA256SUMS` + cosign | optional (`auto`) | yes | checks **c**, **d** |
| Provenance / series commit | no | via `gh attestation` | checks **e**, **f** |
| Member allow-list | partial | yes | check **g** |
| `base.env` pins | tag + commit | remote + tag + commit | check **h** |
| `series.txt` | no | yes | check **i** |

vmafx gains provenance verification, a series commit pin and mandatory cosign.
pelorus can drop its `gh` dependency because cosign validates the provenance
bundle directly.

### Requirements

- Python **3.12+** (stdlib only inside `admit_series.py`)
- **cosign** on `PATH` (flags verified with **cosign v3.1.3**; see
  `A1` in [`tests/test_admit_series.py`](../tests/test_admit_series.py))

### Shared definitions with release guard

[`scripts/release_guard.py`](../scripts/release_guard.py) imports checksum and
signer definitions from `admit_series` so CI release jobs and consumers share
one implementation. Release-side guards remain covered by
[`tests/test_release_guard.py`](../tests/test_release_guard.py).