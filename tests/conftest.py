"""Shared fixtures. Every test that touches files runs inside an eval sandbox."""

import pytest

from hardenctl import evaluate


@pytest.fixture
def sandbox():
    with evaluate.sandbox() as root:
        yield root
