from __future__ import annotations

import pytest

import fsverity_hash


@pytest.mark.parametrize('algorithm', ['', 'spam'])
def test_algorithm_invalid(algorithm):
    with pytest.raises(ValueError):
        fsverity_hash.FSVerityHash(algorithm=algorithm)


@pytest.mark.parametrize('block_size', [-1, 0, 1, 2, 32, 33, 100, 1023])
def test_block_size_invalid_sha256(block_size):
    with pytest.raises(ValueError):
        fsverity_hash.FSVerityHash(block_size=block_size)


@pytest.mark.parametrize('block_size', [-1, 0, 1, 2, 32, 33, 64, 100, 1023])
def test_block_size_invalid_sha512(block_size):
    with pytest.raises(ValueError):
        fsverity_hash.FSVerityHash(algorithm='sha512', block_size=block_size)


def test_defaults():
    fsvhash = fsverity_hash.FSVerityHash()
    assert fsvhash.algorithm.name == fsverity_hash.DEFAULT_ALGORITHM == 'sha256'
    assert fsvhash.block_size == fsverity_hash.DEFAULT_BLOCK_SIZE == 4096
    assert fsvhash.name == 'fsverity'
    assert fsvhash.version == 1
    assert fsvhash.salt == b''
    assert fsvhash.data_size == 0
    assert fsvhash.digest_size == 32
    assert fsvhash.digests_per_block == 128


@pytest.mark.parametrize(
    'algorithm,expected', [
        ('sha256', fsverity_hash.FSVerityAlgorithm.sha256),
        ('sha512', fsverity_hash.FSVerityAlgorithm.sha512),
    ],
)
def test_algorithm(algorithm, expected):
    fsvhash = fsverity_hash.FSVerityHash(algorithm=algorithm)
    assert fsvhash.algorithm is expected
    assert fsvhash.digest_size == expected.digest_size


@pytest.mark.parametrize('block_size', [64, 128, 256, 512, 1024, 2048, 2**20])
def test_block_size_sha256(block_size):
    fsvhash = fsverity_hash.FSVerityHash(algorithm='sha256', block_size=block_size)
    assert fsvhash.block_size == block_size


@pytest.mark.parametrize('block_size', [128, 256, 512, 1024, 2048, 2**20])
def test_block_size_sha512(block_size):
    fsvhash = fsverity_hash.FSVerityHash(algorithm='sha512', block_size=block_size)
    assert fsvhash.block_size == block_size


@pytest.mark.parametrize(
    'expected,algorithm,data_size', [
        ('0000000000000000000000000000000000000000000000000000000000000000', 'sha256', 0),
        ('00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'sha512', 0),  # noqa: E501
    ],
)
def test_merkle_root_digest_sha256(expected, algorithm, data_size):
    data = b'A' * data_size
    fsvhash = fsverity_hash.FSVerityHash(data, algorithm=algorithm)
    assert fsvhash._merkle_root_digest().hex() == expected
