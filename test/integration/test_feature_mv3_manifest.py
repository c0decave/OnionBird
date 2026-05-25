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


def test_manifests_do_not_strict_max_disable_future_tb() -> None:
    mv2 = _read_json(ADDON_DIR / "manifest.json")
    mv3 = _read_json(ADDON_DIR / "manifest.mv3.json")
    mv2_gecko = mv2["applications"]["gecko"]
    mv3_gecko = mv3["browser_specific_settings"]["gecko"]
    assert "strict_max_version" not in mv2_gecko
    assert "strict_max_version" not in mv3_gecko


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
