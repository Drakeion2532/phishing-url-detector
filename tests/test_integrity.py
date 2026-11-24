# Copyright (c) 2026 Shubhan Punde · MIT licence
"""The model is only loaded when its SHA-256 matches the pinned value."""
import shutil
from pathlib import Path

import pytest

from phishguard.integrity import ModelIntegrityError, load_verified, pin, sha256

MODEL = Path(__file__).resolve().parents[1] / "models" / "phishguard.joblib"


def test_bundled_model_matches_its_pin():
    pinned = (MODEL.parent / "phishguard.joblib.sha256").read_text().split()[0]
    assert sha256(MODEL) == pinned
    bundle = load_verified(MODEL)
    assert hasattr(bundle, "predict_proba") or isinstance(bundle, dict)


def test_tampered_model_is_refused(tmp_path):
    bad = tmp_path / "phishguard.joblib"
    shutil.copy(MODEL, bad)
    pin(bad)
    with open(bad, "r+b") as f:            # flip one byte after pinning
        f.seek(100)
        b = f.read(1)
        f.seek(100)
        f.write(bytes([b[0] ^ 0xFF]))
    with pytest.raises(ModelIntegrityError):
        load_verified(bad)


def test_model_without_pin_is_refused(tmp_path):
    lone = tmp_path / "phishguard.joblib"
    shutil.copy(MODEL, lone)
    with pytest.raises(ModelIntegrityError):
        load_verified(lone)
