from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional, Union

PathLike = Union[str, os.PathLike[str]]

def resolve_github_path(raw_path: Optional[PathLike], *, description: str | None = None) -> Path | None:
    label = description or "path"
    if not raw_path:
        print(f"::warning::Skipping {label}: no path provided.", file=sys.stderr)
        return None

    candidate = Path(raw_path)
    workspace = os.getenv("GITHUB_WORKSPACE")
    if not candidate.is_absolute() and workspace:
        candidate = Path(workspace) / candidate

    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        print(f"::warning::Unable to resolve {label}: {exc}", file=sys.stderr)
        return None

    if workspace:
        try:
            workspace_path = Path(workspace).resolve(strict=False)
            resolved.relative_to(workspace_path)
        except Exception:
            print(
                f"::warning::Skipping {label}: {resolved} is outside of GITHUB_WORKSPACE.",
                file=sys.stderr,
            )
            return None

    if not resolved.exists():
        print(f"::warning::Skipping {label}: {resolved} does not exist.", file=sys.stderr)
        return None

    return resolved
