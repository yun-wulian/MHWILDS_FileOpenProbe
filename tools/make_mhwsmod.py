from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def resolve_packer_exe(project_root: Path) -> Path | None:
    env_override = os.environ.get("MHWILDS_PAK_PACKER_EXE")
    if env_override:
        candidate = Path(env_override)
        if candidate.is_file():
            return candidate

    candidates = [
        project_root / "build_nodrop" / "Release" / "mhwilds_pak_packer.exe",
        project_root / "build_nodrop" / "RelWithDebInfo" / "mhwilds_pak_packer.exe",
        project_root / "build_nodrop" / "Debug" / "mhwilds_pak_packer.exe",
        project_root / "build" / "Release" / "mhwilds_pak_packer.exe",
        project_root / "build" / "RelWithDebInfo" / "mhwilds_pak_packer.exe",
        project_root / "build" / "Debug" / "mhwilds_pak_packer.exe",
    ]

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    return None


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            "Usage: py tools/make_mhwsmod.py <game_exe_path> <input_pak_path> <output_mhwsmod_path>",
            file=sys.stderr,
        )
        return 1

    project_root = Path(__file__).resolve().parents[1]
    packer_exe = resolve_packer_exe(project_root)
    if packer_exe is None:
        print(
            "mhwilds_pak_packer.exe not found. Build the project first, or set MHWILDS_PAK_PACKER_EXE.",
            file=sys.stderr,
        )
        return 2

    result = subprocess.run(
        [str(packer_exe), argv[1], argv[2], argv[3]],
        check=False,
    )
    return int(result.returncode)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
