from __future__ import annotations

import pytest

import fsverity_hash


@pytest.mark.parametrize('algorithm', ['', 'spam'])
def test_invalid_algorithm(algorithm):
    with pytest.raises(ValueError):
        fsverity_hash.FSVerityBlock(algorithm=algorithm)
