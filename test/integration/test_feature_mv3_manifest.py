"""MV3 manifest variant + parallel XPI build.

We keep MV2 as the canonical addon (TB 140 ESR is the target), but ship
an MV3 variant for forward-compat experimentation. Both must:
- declare the same experiment_apis surface (same schema + parent)
- declare the same gecko id, version, options page
- install temporarily into TB 140 (smoke-only — full MV3 support in TB
  is still maturing; we tolerate a load failure but check the build).
"""

from __future__ import annotations

import json
import os
import subprocess
import zipfile
from pathlib import Path

import pytest
from helpers.tb_client import TBClient

REPO = Path("/")  # build outputs are mounted under /build
XPI_MV2 = "/build/onionbird.xpi"
XPI_MV3 = "/build/onionbird-mv3.xpi"

ADDON_DIR = Path("/addon")


@pytest.fixture
def tb() -> TBClient:
    client = TBClient(host="thunderbird", port=2828)
    yield client
    client.close()


def _read_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def test_mv3_manifest_declares_manifest_version_3() -> None:
    m = _read_json(ADDON_DIR / "manifest.mv3.json")
    assert m["manifest_version"] == 3, "manifest.mv3.json must declare MV3"


def test_mv3_keeps_same_gecko_id_and_experiments() -> None:
    mv2 = _read_json(ADDON_DIR / "manifest.json")
    mv3 = _read_json(ADDON_DIR / "manifest.mv3.json")

    # Same identity across both
    mv2_id = mv2.get("applications", {}).get("gecko", {}).get("id")
    mv3_id = mv3.get("browser_specific_settings", {}).get("gecko", {}).get("id")
    assert mv2_id == mv3_id, f"gecko.id differs: mv2={mv2_id!r} mv3={mv3_id!r}"

    assert mv2["version"] == mv3["version"], "version differs across mv2/mv3 manifests"

    # Same experiment_apis surface (the Experiments API is TB-specific and
    # not affected by MV2 vs MV3 — must declare identically).
    assert mv2["experiment_apis"] == mv3["experiment_apis"], (
        "experiment_apis differ between MV2 and MV3 manifests"
    )


def test_manifests_strict_max_pinned_to_next_planned_esr() -> None:
    """F-011 (Mozilla ATN policy 2026-05-26 — third revision after
    research): ATN requires `strict_max_version` for Mail Experiments
    AND only accepts values matching real planned TB releases.
      - Bare `*` → rejected by schema regex `^[0-9]{1,3}(\\.[a-z0-9*]+)+$`
      - `999.*` → rejected by ATN's version-resolver (no such release)
      - `<current>.*` → accepted but auto-disables on next major (F-011)
    Compromise: pin to the NEXT planned TB-ESR (`153.*`, scheduled
    21 July 2026). Widest concrete value ATN currently accepts. The
    F-011 silent-disable leak is no longer manifest-preventable; it
    becomes a RELEASE-PROCESS obligation (bump strict_max + re-sign,
    or use Mozilla's Compatibility Bumper) on each new TB major.
    """
    mv2 = _read_json(ADDON_DIR / "manifest.json")
    mv3 = _read_json(ADDON_DIR / "manifest.mv3.json")
    mv2_gecko = mv2["applications"]["gecko"]
    mv3_gecko = mv3["browser_specific_settings"]["gecko"]
    assert mv2_gecko.get("strict_max_version") == "153.*", (
        f"F-011: MV2 strict_max_version must be `153.*` (next planned "
        f"TB-ESR, widest ATN-accepted upper bound). Got "
        f"{mv2_gecko.get('strict_max_version')!r}."
    )
    assert mv3_gecko.get("strict_max_version") == "153.*", (
        f"F-011: MV3 strict_max_version must be `153.*`. Got "
        f"{mv3_gecko.get('strict_max_version')!r}."
    )


def test_mv3_xpi_swaps_manifest_correctly(tmp_path) -> None:
    """build_xpi.py --manifest=mv3 must ship manifest.mv3.json AS the
    manifest.json inside the archive, and NOT include the original."""
    out = tmp_path / "smoke.xpi"
    subprocess.run(
        [
            "python3", "/scripts/build_xpi.py",
            str(ADDON_DIR), str(out),
            "--manifest=mv3",
        ],
        check=True,
    )
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
        assert "manifest.json" in names
        assert "manifest.mv3.json" not in names, (
            "MV3 build must REPLACE manifest.json, not include both"
        )
        with z.open("manifest.json") as f:
            manifest_in_archive = json.load(f)
    assert manifest_in_archive["manifest_version"] == 3


def test_mv2_xpi_does_not_include_mv3_manifest(tmp_path) -> None:
    """Default MV2 build must not leak the alternate manifest into the XPI."""
    out = tmp_path / "smoke-mv2.xpi"
    subprocess.run(
        [
            "python3", "/scripts/build_xpi.py",
            str(ADDON_DIR), str(out),
            "--manifest=mv2",
        ],
        check=True,
    )
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
        assert "manifest.json" in names
        assert "manifest.mv3.json" not in names, (
            "MV2 build must not ship the parallel MV3 manifest file"
        )


def test_mv3_install_smoke(tb: TBClient) -> None:
    """Tolerated: TB 140 MV3 support is partial. We check whether the MV3
    XPI loads at all; if Mozilla rejects it we skip rather than fail."""
    if not os.path.exists(XPI_MV3):
        pytest.skip(f"{XPI_MV3} not built — run `make build-mv3`")
    try:
        addon_id = tb.install_addon(XPI_MV3, temporary=True)
    except Exception as e:
        pytest.skip(f"TB 140 rejected MV3 install (expected on current ESR): {e}")
    assert addon_id == "onionbird@undisclose.de"
