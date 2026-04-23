from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parent.parent


def repo_root() -> Path:
    return _REPO_ROOT


def config_path(filename: str) -> Path:
    return _REPO_ROOT / "config" / filename


def var_path(filename: str) -> Path:
    return _REPO_ROOT / "var" / filename
