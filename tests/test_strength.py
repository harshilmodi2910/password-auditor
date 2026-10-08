from auditor.strength import character_classes, check_password


def test_empty_password():
    r = check_password("")
    assert r.score == 0
    assert r.label == "Very Weak"
    assert r.classes == []
    assert r.issues == ["password is empty"]


def test_character_classes_including_unicode_and_space():
    assert character_classes("aA1! \u00e9") == ["lower", "upper", "digit", "symbol", "other"]
    assert character_classes("1234") == ["digit"]


def test_longer_scores_higher():
    assert check_password("Kq9#Zm2$Xv7!").score > check_password("Kq9#Zm").score


def test_more_character_types_score_higher():
    assert check_password("kqzmxvhjwpdg").score < check_password("kqZm9vH#wpDg").score


def test_short_password_is_flagged():
    assert "shorter than 8 characters" in check_password("Ab1!").issues
