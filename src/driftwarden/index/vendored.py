"""The one vendored-path predicate (L-030). Deterministic, no I/O.

Third-party code checked into the repository (``vendor/``, ``third_party/``,
``node_modules/``, ``external/`` ...) is not this repository's code: what it
imports or declares is neither a choice the team made nor a breach of one.

Both consumers use this predicate, so they cannot disagree again:

* ``undocumented.detect`` never reports a technology seen only there;
* ``judge.evidence`` never collects it as evidence (no ``forbidden``,
  ``alternative``, boundary or keyword candidate comes from a vendored file, and
  an import edge whose source *or* target is vendored is not a boundary
  crossing); the ignored occurrences are listed in the evidence notes instead.

Matching is on whole path segments *above* the file, exact case: ``vendor/x.js``
and ``src/third_party/lib/a.py`` are vendored, ``vendor.py``, ``vendors.md`` at the
root and ``src/vendoring/a.py`` are not. Case is exact on purpose: ``Pods/`` is
CocoaPods, while ``pods/`` is often a Kubernetes manifest directory.

Known trade-off (precision over recall): a project directory that happens to be
named ``external/`` or ``vendor/`` (integration code for external services, a
"vendor" domain module) is treated as third-party, so a violation there is not
seen. ``Config.exclude`` globs are a separate mechanism: excluded files never
enter the snapshot at all.
"""

from __future__ import annotations

VENDORED_DIRS = frozenset(
    {"node_modules", "vendor", "vendors", "third_party", "third-party", "thirdparty",
     "external", "bower_components", "jspm_packages", "site-packages", ".venv", "venv",
     "Pods"}
)  # fmt: skip


def is_vendored(path: str) -> bool:
    """True when ``path`` (repo-relative POSIX) lies inside a vendored / third-party
    directory at any depth. A directory path counts when one of its *parent*
    segments is vendored (``vendor/lib`` is inside ``vendor/``; ``vendor`` itself
    is not)."""
    return any(seg in VENDORED_DIRS for seg in path.split("/")[:-1])
