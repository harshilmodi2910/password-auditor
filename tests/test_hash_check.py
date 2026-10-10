import hashlib

import pytest

from auditor.hash_check import detect_hash

SALT22 = "a" * 22


def keys(text):
    return [a.key for a in detect_hash(text)]


@pytest.mark.parametrize(
    "algo, expected",
    [
        ("md5", "md5"),
        ("sha1", "sha1"),
        ("sha256", "sha256"),
        ("sha384", "sha384"),
        ("sha512", "sha512"),
    ],
)
def test_hex_hashes_detected_by_length(algo, expected):
    digest = hashlib.new(algo, b"password").hexdigest()
    assert expected in keys(digest)
    assert expected in keys(digest.upper())


def test_32_hex_is_ambiguous():
    assert keys("5f4dcc3b5aa765d61d8327deb882cf99") == ["md5", "ntlm", "lm"]


def test_prefixed_formats():
    samples = {
        "bcrypt": "$2b$12$" + "a" * 53,
        "argon2": "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub",
        "scrypt": "$scrypt$ln=16,r=8,p=1$c29tZXNhbHQ$abcdefgh",
        "md5crypt": "$1$saltsalt$" + SALT22,
        "sha256crypt": "$5$saltsalt$" + "a" * 43,
        "sha512crypt": "$6$rounds=5000$saltsalt$" + "a" * 86,
    }
    for expected, text in samples.items():
        assert keys(text) == [expected], expected


def test_unrecognised_formats_give_an_empty_list():
    for text in ["not a hash", "abcd", "g" * 32, "$9$whatever"]:
        assert detect_hash(text) == []


def test_surrounding_whitespace_is_ignored():
    digest = hashlib.sha1(b"x").hexdigest()
    assert keys("  " + digest + "\n") == ["sha1"]
