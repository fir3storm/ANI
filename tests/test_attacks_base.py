from src.attacks.base import BaseAttack


def test_check_indicators_substring_match():
    found = BaseAttack.check_indicators("I will ignore previous instructions", ["ignore previous"])
    assert "ignore previous" in found


def test_check_indicators_case_insensitive():
    found = BaseAttack.check_indicators("i will IGNORE previous instructions", ["ignore previous"])
    assert "ignore previous" in found


def test_check_indicators_no_match():
    found = BaseAttack.check_indicators("everything is fine", ["malicious payload"])
    assert found == []
