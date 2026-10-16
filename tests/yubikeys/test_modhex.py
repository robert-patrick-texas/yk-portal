import pytest

from yk_portal.yubikeys import modhex


def test_alphabet_maps_to_hex_digits():
    assert modhex.decode("cbdefghijklnrtuv") == bytes.fromhex("0123456789abcdef")
    assert modhex.encode(bytes.fromhex("0123456789abcdef")) == "cbdefghijklnrtuv"


def test_round_trip():
    data = bytes(range(256))
    assert modhex.decode(modhex.encode(data)) == data


@pytest.mark.parametrize("text", ["", "cb", "vvccccbbcdef"])
def test_is_modhex(text):
    assert modhex.is_modhex(text)


@pytest.mark.parametrize("text", ["c", "cbd", "ab", "CB", "cb ", "0123", "vvcccc bbcdef"])
def test_not_modhex(text):
    assert not modhex.is_modhex(text)
    with pytest.raises(ValueError, match="not ModHex"):
        modhex.decode(text)
