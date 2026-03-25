from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from rimscan.models import SourceMetadata


@contextmanager
def prepare_source(
    *,
    local_path: str | None,
    repo_url: str | None,
    sbom_path: str | None,
    git_ref: str | None = None,
) -> Iterator[tuple[Path, SourceMetadata]]:
    if local_path:
        resolved = Path(local_path).expanduser().resolve(strict=True)
        yield resolved, SourceMetadata(
            source_type="path",
            target=local_path,
            resolved_path=str(resolved),
        )
        return

    if sbom_path:
        resolved = Path(sbom_path).expanduser().resolve(strict=True)
        yield resolved, SourceMetadata(
            source_type="sbom",
            target=sbom_path,
            resolved_path=str(resolved),
        )
        return

    if not repo_url:
        raise ValueError("one of local_path, repo_url, or sbom_path is required")
    if shutil.which("git") is None:
        raise RuntimeError("git is required to scan a repository URL")

    with tempfile.TemporaryDirectory(prefix="rimscan-clone-") as temp_dir:
        clone_root = Path(temp_dir) / "repo"
        command = ["git", "clone", "--depth", "1", repo_url, str(clone_root)]
        if git_ref:
            command = [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                git_ref,
                repo_url,
                str(clone_root),
            ]
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            output = (completed.stdout or "").strip() or "git clone failed"
            raise RuntimeError(output)
        yield clone_root, SourceMetadata(
            source_type="repo_url",
            target=repo_url,
            resolved_path=str(clone_root),
            repo_url=repo_url,
        )
