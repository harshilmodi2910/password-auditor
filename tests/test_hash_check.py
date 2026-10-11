import hashlib

import pytest

from auditor.hash_check import (
    ACCEPTABLE,
    BROKEN,
    UNKNOWN,
    UNSUITED,
    check_hash,
    detect_hash,
    resolve_algorithm,
)

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


def test_32_hex_is_ambiguous_and_flagged_as_a_guess():
    digest = "5f4dcc3b5aa765d61d8327deb882cf99"
    assert keys(digest) == ["md5", "ntlm", "lm"]
    notes = check_hash(digest).notes
    assert any("guess" in n for n in notes)
    assert any("worst" in n for n in notes)
    assert check_hash("$2b$12$" + "a" * 53).notes == []


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


def test_ratings_by_tier():
    assert check_hash(hashlib.md5(b"x").hexdigest()).tier == BROKEN
    assert check_hash(hashlib.sha1(b"x").hexdigest()).tier == BROKEN
    assert check_hash(hashlib.sha256(b"x").hexdigest()).tier == UNSUITED
    assert check_hash("$2b$12$" + "a" * 53).tier == ACCEPTABLE
    assert check_hash("$1$saltsalt$" + SALT22).tier == BROKEN


def test_bcrypt_with_low_cost_is_downgraded():
    r = check_hash("$2b$04$" + "a" * 53)
    assert r.tier == UNSUITED
    assert "Cost factor is 4" in r.candidates[0].reason


def test_pbkdf2_iteration_count_decides_rating():
    low = check_hash("$pbkdf2-sha256$29000$abc$def")
    high = check_hash("pbkdf2_sha256$600000$salt$hash")
    assert low.tier == UNSUITED
    assert high.tier == ACCEPTABLE
    assert high.candidates[0].name == "PBKDF2-SHA256"


def test_unrecognised_and_empty_hashes():
    for text in ["not a hash", "abcd", "g" * 32, "$9$whatever"]:
        r = check_hash(text)
        assert r.tier == UNKNOWN
        assert r.candidates == []
    with pytest.raises(ValueError):
        check_hash("")
    with pytest.raises(ValueError):
        check_hash("   ")


def test_resolve_algorithm_names():
    assert resolve_algorithm("SHA-256") == "sha256"
    assert resolve_algorithm("sha_1") == "sha1"
    assert resolve_algorithm("Argon2id") == "argon2"
    with pytest.raises(ValueError):
        resolve_algorithm("rot13")


def test_algorithm_override_and_format_mismatch():
    digest = hashlib.sha1(b"x").hexdigest()
    assert keys("  " + digest + "\n") == ["sha1"]  # whitespace is ignored

    good = check_hash(hashlib.md5(b"x").hexdigest(), algorithm="md5")
    assert good.format_matches is True
    assert good.tier == BROKEN

    bad = check_hash("abcd", algorithm="sha256")
    assert bad.format_matches is False
    assert bad.tier == UNSUITED
    assert any("does not look like" in n for n in bad.notes)


