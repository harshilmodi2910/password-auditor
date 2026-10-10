import math

import pytest

from auditor.strength import (
    SECONDS_PER_YEAR,
    character_classes,
    check_password,
    estimate_times,
    find_repeats,
    find_sequences,
    format_duration,
    load_wordlist,
)


@pytest.fixture(scope="module")
def common():
    return load_wordlist()


def test_empty_password(common):
    r = check_password("", common)
    assert r.score == 0
    assert r.label == "Very Weak"
    assert r.estimates == []
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


def test_estimates(common):
    # four digits is 10 ** 4 combinations, half on average, so 5000 guesses
    est = {e.key: e.human for e in estimate_times(4, 10)}
    assert est["online_throttled"] == "about 2 days"
    assert est["online_unthrottled"] == "about 5 seconds"
    assert est["offline_slow_hash"] == "under a second"
    assert est["offline_fast_hash"] == "under a second"

    # a higher assumed rate should never give a longer time
    times = [e.log10_seconds for e in check_password("Kq9#Zm2$Xv7!", common).estimates]
    assert len(times) == 4
    assert times == sorted(times, reverse=True)


def test_format_duration():
    assert format_duration(-1) == "under a second"
    assert format_duration(math.log10(5 * 3600)) == "about 5 hours"
    assert format_duration(math.log10(3 * SECONDS_PER_YEAR)) == "about 3 years"
    assert format_duration(math.log10(2e9 * SECONDS_PER_YEAR)) == "about 2 billion years"
    assert format_duration(400) == "over a trillion years"


def test_extremely_long_password_does_not_overflow():
    pw = "aB3$" * 25_000
    r = check_password(pw, set())
    assert r.length == 100_000
    assert all(e.human == "over a trillion years" for e in r.estimates)


def test_wordlists(tmp_path, common):
    assert len(common) > 9_000
    assert "password" in common

    f = tmp_path / "words.txt"
    f.write_text("hunter2\n\n  Spaced Out  \n", encoding="utf-8")
    words = load_wordlist(f)
    assert words == {"hunter2", "spaced out"}
    assert check_password("HUNTER2", words).in_common_list
    assert not check_password("hunter2", common).in_common_list
