"""Repository indexer: files, languages and the import graph (pipeline stage 4)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from driftwarden.config import Config
from driftwarden.index.files import FileEntry, FileIndex, detect_language, index_files
from driftwarden.index.imports import ImportEdge, ImportGraph, build_import_graph

__all__ = [
    "FileEntry",
    "FileIndex",
    "ImportEdge",
    "ImportGraph",
    "RepoIndex",
    "build_import_graph",
    "build_index",
    "detect_language",
    "index_files",
]


@dataclass
class RepoIndex:
    files: FileIndex
    imports: ImportGraph


def build_index(root: str | Path, config: Config | None = None) -> RepoIndex:
    """Index the files at ``root`` (honouring git ignore rules and ``config.exclude``)
    and build their import graph."""
    cfg = config or Config()
    files = index_files(root, cfg.exclude)
    return RepoIndex(files=files, imports=build_import_graph(files))
