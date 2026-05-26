"""Top-level test/ conftest.

Purpose
-------
The integration and external suites import ``marionette_driver`` and
``socks`` (PySocks) at module load time — those modules ship with the
docker-based test harness, not pip, so they're not available on a bare
developer host. Without intervention pytest's collection phase raises
``ModuleNotFoundError`` for ~25 files before any test gets to run, and
the substrate's ``tests-pass`` and ``no-prior-regression`` hard gates
fail before they have a chance to assert anything substantive.

Resolution
----------
We probe for ``marionette_driver`` and ``socks`` once at collection
time. When either is missing, every test path that transitively
imports them is added to ``collect_ignore_glob`` so pytest skips it
without surfacing the import error. The harness path
(``test/integration/`` + ``test/external/``) is still collected and
executed normally inside the docker runner — only the host-side run
sidesteps it.

Why a top-level conftest.py
---------------------------
``test/integration/conftest.py`` itself imports ``marionette_driver``
transitively (via ``test/helpers/tb_client.py``), so the per-directory
conftest cannot decide to skip its own siblings — pytest would already
have crashed loading that conftest. The collection-ignore decision
has to live at a higher scope.

Scope
-----
Unit tests (``test/unit/``) remain collected unconditionally — they
are pure-Python and have no Marionette dependency.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


_MARIONETTE_AVAILABLE = _module_available("marionette_driver")
_PYSOCKS_AVAILABLE = _module_available("socks")

_TEST_DIR = Path(__file__).parent
_INTEGRATION_DIR = _TEST_DIR / "integration"
_EXTERNAL_DIR = _TEST_DIR / "external"


def pytest_ignore_collect(collection_path, config):  # noqa: ARG001
    """Stop pytest from descending into test/integration/ or test/external/.

    The `pytest_ignore_collect` hook fires BEFORE pytest tries to load a
    directory's conftest.py — `collect_ignore_glob` alone is not enough
    because the integration/external conftests themselves import
    `marionette_driver` and crash during conftest load, which short-
    circuits collection before the parent's glob list is consulted.
    """
    path = Path(collection_path)
    try:
        is_in_integration = path == _INTEGRATION_DIR or _INTEGRATION_DIR in path.parents
        is_in_external = path == _EXTERNAL_DIR or _EXTERNAL_DIR in path.parents
    except (ValueError, OSError):
        return None
    if is_in_integration and not _MARIONETTE_AVAILABLE:
        return True
    if is_in_external and (not _MARIONETTE_AVAILABLE or not _PYSOCKS_AVAILABLE):
        return True
    return None


# helpers/ is pure-helper code, not a test directory; pytest won't try
# to collect tests from it (no `test_*.py` pattern there) and the
# integration/external tests that import from helpers/ are already
# excluded by the pytest_ignore_collect hook above on hosts that lack
# marionette_driver.


def pytest_report_header(config) -> list[str]:  # noqa: ARG001
    bits = []
    if not _MARIONETTE_AVAILABLE:
        bits.append(
            "test/conftest.py: marionette_driver not importable — "
            "skipping test/integration/ + test/external/ collection"
        )
    if not _PYSOCKS_AVAILABLE:
        bits.append(
            "test/conftest.py: PySocks (socks) not importable — "
            "skipping test/external/ collection"
        )
    return bits or [
        "test/conftest.py: all marionette/PySocks deps present; "
        "full suite collected"
    ]
