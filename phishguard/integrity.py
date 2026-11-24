# Copyright (c) 2026 Shubhan Punde · MIT licence
"""Load the bundled model only if it matches its pinned SHA-256.

joblib files are pickles, and unpickling a tampered file can run arbitrary code. Every load in this
project goes through `load_verified`, which refuses a model whose hash does not match the value
written next to it at training time (`models/phishguard.joblib.sha256`).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import joblib


class ModelIntegrityError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pin_file(path: Path) -> Path:
    return path.with_name(path.name + ".sha256")


def pin(path: Path) -> str:
    """Record the model's hash; called by training right after the model is written."""
    digest = sha256(path)
    pin_file(path).write_text(f"{digest}  {path.name}\n")
    return digest


def load_verified(path: Path):
    path = Path(path)
    pf = pin_file(path)
    if not pf.exists():
        raise ModelIntegrityError(f"no pinned hash for {path.name}; retrain with `python -m phishguard.train`")
    expected = pf.read_text().split()[0]
    actual = sha256(path)
    if actual != expected:
        raise ModelIntegrityError(f"{path.name} does not match its pinned SHA-256 (expected {expected[:12]}…, "
                                  f"got {actual[:12]}…); refusing to load it")
    return joblib.load(path)
