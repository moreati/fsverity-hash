from __future__ import annotations

import pytest

import fsverity_hash


@pytest.mark.parametrize(
    'name,expected', [
        ('sha256', fsverity_hash.FSVerityAlgorithm.sha256),
        ('sha512', fsverity_hash.FSVerityAlgorithm.sha512),
    ],
)
def test_from_name(name, expected):
    assert fsverity_hash.FSVerityAlgorithm.from_name(name) is expected


@pytest.mark.parametrize('name', ['', 'spam'])
def test_from_name_invalid(name):
    with pytest.raises(ValueError):
        fsverity_hash.FSVerityAlgorithm.from_name(name)


def test_digest_size():
    assert fsverity_hash.FSVerityAlgorithm.sha256.digest_size == 32
    assert fsverity_hash.FSVerityAlgorithm.sha512.digest_size == 64
