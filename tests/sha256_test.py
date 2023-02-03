from __future__ import annotations

import pytest

import fsverity_hash


@pytest.mark.parametrize(
    'expected,data_size', [
        ('3d248ca542a24fc62d1c43b916eae5016878e2533c88238480b26128a1f1af95', 0),
        ('9845e616f7d2f7a1cd6742f0546a36d2e74d4eb8ae7d9bdc0b0df982c27861b7', 1),
        ('e40425eaca55b3aca9994575b03b1585ff756c4684395fa144ee2642aeaf1d49', 100),
        ('d67826aecb67a64705ac70f82cd0878394be2c1e19bdced9b0aad653fa2e73ae', 1000),
        ('aab040052277ce2baa6de148f1b3c8798de72f760d019427f44ce7caac6a69ef', 4095),
        ('3fd7a78101899a79cd337b1b4e5414be8bcb376b133370156ef6e65026d930ed', 4096),
        ('7319937c445f61df1a8f310eb4d6da157618d80713972a78d70a7528fc1a6f32', 4097),
        ('1998a5f553ea5cb29aec221561290c29eca2f30d7ed2be832745ec7ddc73c5a8', 8191),
        ('8bddf40a09fef722e6f2b141d69ab2cc23010aa824a78186d38abb05cb8b47f5', 8192),
        ('d45adc8817b342124448dcd0a06184aa2df5a919eec7ab900bca0c14bccd129c', 8193),
        ('5c00a54bd1d8341d7bbad060ff1b8e88ed2646d7bb38db6e752cd1cff66c0a78', 524_287),
        ('f5c2b9ded1595acfe8a996795264d488dd6140531f6a01f8f8086a83fd835935', 524_288),
        ('a7abb76568871169a79104d00679fae6521dfdb2a2648e380c02b10e96e217ff', 524_289),
        ('04b74498f0fafcd91622f0b218f3f1a024221e7ccb1732ea180cd4833808edd6', 1_234_567),
        ('91634eb57e4b47f077b18c596cdae9ebf60bbded408f19423ccd5703028e95a4', 67_108_863),
        ('2dbb93b12267f696804876449e4874e543ad7fbf5715dbf6ff5a277553d9edfe', 67_108_864),
        ('d0d2d7311c25c6d121011a569274bec0929afe1ca56543cb1235d5056efc4f7b', 67_108_865),
    ],
)
def test_sha256_oneshot(expected, data_size):
    data = b'A' * data_size
    assert fsverity_hash.FSVerityHash(data).hexdigest() == expected
