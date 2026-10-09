import pytest

from auditor.strength import (
    character_classes,
    check_password,
    find_repeats,
    find_sequences,
    load_wordlist,
)


@pytest.fixture(scope="module")
def common():
    return load_wordlist()


def test_empty_password(common):
    r = check_password("", common)
    assert r.score == 0
    assert r.label == "Very Weak"
    assert r.classes == []
    assert r.issues == ["password is empty"]


@pytest.mark.parametrize("pw", ["password", "PassWord"])
def test_common_password_is_capped(common, pw):
    r = check_password(pw, common)
    assert r.in_common_list
    assert r.score <= 10
    assert r.label == "Very Weak"


def test_short_password_is_capped_even_with_every_class(common):
    r = check_password("Ab1!", common)
    assert r.score <= 24
    assert r.label == "Very Weak"
    assert "shorter than 8 characters" in r.issues


def test_strong_password(common):
    r = check_password("T7#kq9!Lm2$vR8zP", common)
    assert r.label == "Strong"
    assert r.issues == []
    assert not r.in_common_list


def test_find_sequences():
    assert find_sequences("abc") == ["abc"]
    assert find_sequences("CBA") == ["cba"]
    assert find_sequences("xx12345yy") == ["12345"]
    assert find_sequences("a1b2c3") == []
    assert find_sequences("ab") == []


def test_find_repeats():
    assert find_repeats("aaabbb") == ["aaa", "bbb"]
    assert find_repeats("aabb") == []
    assert find_repeats("") == []


def test_patterns_show_up_as_issues(common):
    with_repeat = check_password("Kq9#Zm2$Xv7!aaa", common)
    with_sequence = check_password("Kq9#Zm2$Xv7!abc", common)
    clean = check_password("Kq9#Zm2$Xv7!", common)
    assert any("repeated" in i for i in with_repeat.issues)
    assert any("sequence" in i for i in with_sequence.issues)
    assert clean.issues == []


def test_character_classes_including_unicode_and_space():
    assert character_classes("aA1! é") == ["lower", "upper", "digit", "symbol", "other"]
    assert character_classes("1234") == ["digit"]


def test_wordlists(tmp_path, common):
    assert len(common) > 9_000
    assert "password" in common

    f = tmp_path / "words.txt"
    f.write_text("hunter2\n\n  Spaced Out  \n", encoding="utf-8")
    words = load_wordlist(f)
    assert words == {"hunter2", "spaced out"}
    assert check_password("HUNTER2", words).in_common_list
    assert not check_password("hunter2", common).in_common_list
