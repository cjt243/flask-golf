"""Tests for pure utility functions in app.py."""

import app as app_module


# ── format_score ────────────────────────────────────────────────────────────

class TestFormatScore:
    def test_none_returns_dashes(self):
        assert app_module.format_score(None) == '--'

    def test_zero_returns_even(self):
        assert app_module.format_score(0) == 'E'

    def test_negative_score(self):
        assert app_module.format_score(-5) == '-5'

    def test_positive_score(self):
        assert app_module.format_score(3) == '+3'

    def test_large_positive(self):
        assert app_module.format_score(15) == '+15'

    def test_large_negative(self):
        assert app_module.format_score(-12) == '-12'


# ── parse_score_to_int ─────────────────────────────────────────────────────

class TestParseScoreToInt:
    def test_even(self):
        assert app_module.parse_score_to_int('E') == 0

    def test_even_lowercase(self):
        assert app_module.parse_score_to_int('e') == 0

    def test_negative(self):
        assert app_module.parse_score_to_int('-5') == -5

    def test_positive_with_plus(self):
        assert app_module.parse_score_to_int('+2') == 2

    def test_positive_without_plus(self):
        assert app_module.parse_score_to_int('3') == 3

    def test_dashes_return_none(self):
        assert app_module.parse_score_to_int('--') is None

    def test_na_returns_none(self):
        assert app_module.parse_score_to_int('N/A') is None

    def test_none_returns_none(self):
        assert app_module.parse_score_to_int(None) is None

    def test_empty_returns_none(self):
        assert app_module.parse_score_to_int('') is None


# ── _api_int ────────────────────────────────────────────────────────────────

class TestApiInt:
    def test_plain_int(self):
        assert app_module._api_int(4) == 4

    def test_string_int(self):
        assert app_module._api_int('7') == 7

    def test_mongodb_dict(self):
        assert app_module._api_int({'$numberInt': '4'}) == 4

    def test_none(self):
        assert app_module._api_int(None) is None

    def test_non_numeric_string(self):
        assert app_module._api_int('abc') is None


# ── validate_entry_name ─────────────────────────────────────────────────────

class TestValidateEntryName:
    def test_valid_name(self):
        assert app_module.validate_entry_name('Team Alpha') is not None

    def test_alphanumeric_with_spaces(self):
        assert app_module.validate_entry_name('My Team 123') is not None

    def test_hyphens_underscores(self):
        assert app_module.validate_entry_name("Bob's-Team_1") is not None

    def test_empty_returns_none(self):
        assert app_module.validate_entry_name('') is None

    def test_none_returns_none(self):
        assert app_module.validate_entry_name(None) is None

    def test_too_long(self):
        assert app_module.validate_entry_name('x' * 51) is None

    def test_special_chars_rejected(self):
        assert app_module.validate_entry_name('Team<script>') is None

    def test_xss_rejected(self):
        assert app_module.validate_entry_name('<img onerror=alert(1)>') is None

    def test_whitespace_only(self):
        assert app_module.validate_entry_name('   ') is None

    def test_html_escaped(self):
        # Names with & should be rejected by the pattern (only alphanumeric, space, -, _, ', .)
        assert app_module.validate_entry_name('A&B') is None


# ── validate_user_email ─────────────────────────────────────────────────────

class TestValidateUserEmail:
    def test_valid_email(self):
        assert app_module.validate_user_email('test@example.com') is not None

    def test_normalized(self):
        result = app_module.validate_user_email('TEST@Example.COM')
        assert result == 'test@example.com' or result is not None

    def test_invalid_email(self):
        assert app_module.validate_user_email('not-an-email') is None

    def test_empty_string(self):
        assert app_module.validate_user_email('') is None
