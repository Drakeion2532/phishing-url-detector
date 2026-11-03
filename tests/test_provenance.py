# Copyright (c) 2026 Shubhan Punde · https://github.com/Drakeion2532/phishing-url-detector · MIT licence · sp2532-fc172ce9ff51
"""Keeps the authorship metadata intact (see LICENSE)."""
import phishguard


def test_authorship_metadata():
    assert phishguard.__author__ == "Shubhan Punde"
    assert phishguard.__provenance__ == "sp2532-fc172ce9ff51"
