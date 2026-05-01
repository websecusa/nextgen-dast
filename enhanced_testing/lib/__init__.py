# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
Thin re-export of the toolkit/lib primitives so probes here can do a
single import line. The validation toolkit (toolkit/lib) and the
enhanced-testing toolkit share the same SafeClient / Probe / Verdict
plumbing — there's no need to duplicate the code, only to expose it
under a stable import path so probes don't have to know which lib
directory they live alongside.

Example probe import:
    from lib import Probe, Verdict, SafeClient
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _find_toolkit_lib() -> Path | None:
    """Return the directory holding the toolkit's probe / http / safety
    modules. Image runtime first, then walk up from this file to find a
    sibling toolkit/."""
    img = Path("/app/toolkit/lib")
    if img.is_dir():
        return img
    here = Path(__file__).resolve()
    for parent in (here.parents[1], here.parents[2], here.parents[3]):
        cand = parent / "toolkit" / "lib"
        if cand.is_dir():
            return cand
    return None


def _load(modname: str, path: Path):
    """Load a Python file as a module under a custom name without
    touching sys.path or sys.modules globally — so we don't shadow the
    stdlib `http` package."""
    spec = importlib.util.spec_from_file_location(modname, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sys.modules[modname] = mod
    return mod


_lib = _find_toolkit_lib()
if not _lib:
    raise ImportError(
        "enhanced_testing/lib could not locate toolkit/lib. Expected at "
        "/app/toolkit/lib (image) or <repo>/toolkit/lib (source tree)."
    )

# Each toolkit lib module imports its siblings via relative imports
# (`from .safety import ...`). For relative imports to resolve we need
# the modules registered as submodules of a real package. Easiest path:
# register `nextgen_dast_toolkit_lib` as a synthetic package whose
# __path__ points at the toolkit's lib dir, then load each module under
# that name. The toolkit's own `from .safety import ...` then resolves.
_PKG = "nextgen_dast_toolkit_lib"
if _PKG not in sys.modules:
    _spec = importlib.util.spec_from_file_location(
        _PKG, str(_lib / "__init__.py"),
        submodule_search_locations=[str(_lib)])
    _pkg = importlib.util.module_from_spec(_spec)
    sys.modules[_PKG] = _pkg
    _spec.loader.exec_module(_pkg)

_safety = importlib.import_module(f"{_PKG}.safety")
_http   = importlib.import_module(f"{_PKG}.http")
_probe  = importlib.import_module(f"{_PKG}.probe")

Probe           = _probe.Probe
Verdict         = _probe.Verdict
SafeClient      = _http.SafeClient
Response        = _http.Response
AuditLog        = _safety.AuditLog
Budget          = _safety.Budget
SafetyViolation = _safety.SafetyViolation

__all__ = ["Probe", "Verdict", "SafeClient", "Response",
           "AuditLog", "Budget", "SafetyViolation"]  # noqa: E305
