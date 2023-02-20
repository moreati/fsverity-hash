from __future__ import annotations

import pytest

import fsverity_hash


@pytest.mark.parametrize(
    'expected,data_size', [
        ('ccf9e5aea1c2a64efa2f2354a6024b90dffde6bbc017825045dce374474e13d10adb9dadcc6ca8e17a3c075fbd31336e8f266ae6fa93a6c3bed66f9e784e5abf', 0),  # noqa: E501
        ('4e6098d82f38c94e02769bd917acd308e09f0d336c3bc8e49b6f65e3a1bfe2bc4d219cd038535faa58e612d55e7429b96fbaf8360954bf1b1b50904fe0d2c829', 1),  # noqa: E501
        ('cd303be40b2b7c017750f995bd4003d19a0231a425e36878ca037e4f1db04fd3ba244fd4f7c8200beeea17638367f3b8c9c030857b3224df1361a4c6efcf610c', 100),  # noqa: E501
        ('5a4d9751e8e43713af0a8740c0009f4845e0bb85e9c4ca8acdfe7604842be6200cabd4921dad07ee953b34ae903bdd3908140ce0cf4894d1c958195fd5180598', 1000),  # noqa: E501
        ('30e95fc9bd69ff282c816e86842651e4f9484fb5eff1d23744e59864a2a856e4b71cdec451c4529c086aacf280904168f0ee7f78f9ae6edc1c1d0f3e0b48d17a', 4095),  # noqa: E501
        ('ce7dbc6b1765f5a893a33cd28e169eb8cf42109a0c9e61fff61525f7dc4b0112fbdc9f119e2d944a2e3e44a74ac3a19cc52fc4d269232d9147d763b5614540d6', 4096),  # noqa: E501
        ('6e635c539643f51051de01115da81bb9867ffa2ce96e706d80819cd6d4a151b60870f3c88646bdda25dbbb8a6a57194d6247962da3b932133b9fa45aa11a7f13', 4097),  # noqa: E501
        ('3a18978972b9326e3862a717e5860d06bcf45b09f36cc1831b42606587725f19575029f61c88afd1166d1b9ce61222746a94e2b062cf934c4bb44d6c949b1e1b', 8191),  # noqa: E501
        ('96b1990ef1989e9b15754208590846398156c7708396fef9c584bc099331ba6b510aacf3c755580be49d5e105c6c8c0acd49c2b5aad036f656bdf4c35fde264c', 8192),  # noqa: E501
        ('7dc74748e8a95404efd3cbef2e2e7d01b0bee4acec4ec74281a5b40af667f1dd60de2d05d255110cb49b54fe52c2bb4ae5b1c35f1eb063e9b363ade8dfa819e8', 8193),  # noqa: E501
        ('07530574e2e89fae5856cace0dca4cc114bb76e16fe51502857d0e85bb9939f4f387607b00b017d569c027257657be44c69794ba10a7adf42668aa7fb70551ec', 524_287),  # noqa: E501
        ('7ef6fb0ddfdb3b3dfb41dca12cbc0b2cf17a95c20b6d960b00f2beebef287c4631e25dbe118f20680e628daae5481c08e432017359fa4ac9fa1cc2a1641e2f8e', 524_288),  # noqa: E501
        ('e957e494d3c66366a8a13f50a5a2cbb8e457eb88337ea6da3c750b9c06e20cff073e3f60bb152c4f314c9b093506c666ec09ccf320f2c8723685a477de02ea38', 524_289),  # noqa: E501
        ('eb8abdd48c108253367d85c441ea828ea8c67bee24d76a1b16f6d1e014a21eb8e7a542719dce9753bfba00deb0b407ecd51650ca8544718fa811ac6024ca5cf5', 1_234_567),  # noqa: E501
        ('bd0c21bc4baaa1f3146fc4f825240c3126e7983acf6234c9b1595326887e757320e959f2af9a2e3327e5b6796fa823ac085d0c2a1fd7a1a34f022b336efe286b', 67_108_863),  # noqa: E501
        ('7b2950b63f5bbe90651ad4ec5ff022361966180d520a4887bfc4fd81a197916de0eb7d941db9a43ca1ad5e45808099a91e12664fe7d47ca845d567d9f7bf17f3', 67_108_864),  # noqa: E501
        ('76280da9ee955ce5f3623d99cf378078c7210bcefa24faf6dfbe50a731df3e25b8b8498c7b916d94b47fe484b471ee856dc378b1e157a4fdfc10a0d1d0864e1a', 67_108_865),  # noqa: E501
    ],
)
def test_sha256_oneshot(expected, data_size):
    data = b'A' * data_size
    assert fsverity_hash.FSVerityHash(data, algorithm='sha512').hexdigest() == expected
