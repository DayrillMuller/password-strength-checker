"""Comprehensive pytest unit tests for the Password Strength Checker."""

from __future__ import annotations

import hashlib
import io
import json
import urllib.error
from typing import Any
from unittest.mock import MagicMock

import pytest
from rich.console import Console

import checker
from checker import (
    MAX_LENGTH,
    MIN_LENGTH,
    SPECIAL_CHARACTERS,
    PasswordReport,
    calculate_entropy,
    check_password_breach,
    evaluate_password,
    has_edge_whitespace,
    has_keyboard_walk,
    has_repeated_chars,
    has_sequential_run,
    is_common_password,
    is_passphrase,
    normalize_leetspeak,
    validate_password_input,
)
from main import format_json_report, main, parse_args, render_report, run_interactive


class TestTypedReportModel:
    def test_evaluate_returns_password_report_dataclass(self) -> None:
        report = evaluate_password("K9m2p7x!qWzR#8Lv")
        assert isinstance(report, PasswordReport)
        assert isinstance(report.score, int)
        assert report.rating in {"Weak", "Fair", "Strong", "Very Strong"}
        assert isinstance(report.entropy_bits, float)
        assert report.is_breached is None
        assert isinstance(report.suggestions, list)

    def test_report_to_dict_is_json_serializable(self) -> None:
        report = evaluate_password("Correct Horse Battery 99!")
        payload = report.to_dict()
        dumped = json.dumps(payload)
        parsed = json.loads(dumped)
        assert parsed["score"] == 100
        assert parsed["rating"] == "Very Strong"
        assert parsed["entropy_bits"] == report.entropy_bits
        assert parsed["is_breached"] is None
        assert parsed["is_passphrase"] is True


class TestCommonAndLeetSpeakPasswords:
    @pytest.mark.parametrize(
        "weak_pwd",
        [
            "password",
            "PASSWORD",
            "Password",
            "123456",
            "qwerty",
            "QwErTy",
            "admin",
            "ADMIN",
            "letmein",
            "LetMeIn",
        ],
    )
    def test_common_passwords_heavily_penalized(self, weak_pwd: str) -> None:
        report = evaluate_password(weak_pwd)
        assert is_common_password(weak_pwd) is True
        assert report.rating == "Weak"
        assert report.score <= 15
        assert report.checks["not_common"] is False
        assert any("common" in s.lower() for s in report.suggestions)

    @pytest.mark.parametrize(
        "leet_pwd",
        [
            "P@ssw0rd!",
            "P@ssw0rd123",
            "P@$$w0rd!23",
            "p4$$w0rd",
            "L3tm3!n",
            "1etme1n",
            "@dm1n",
            "Adm1n!23",
            "$unsh1ne!",
            "Dr@g0n99!",
            "W3lc0m3!",
        ],
    )
    def test_leetspeak_common_password_variants_caught(self, leet_pwd: str) -> None:
        assert is_common_password(leet_pwd) is True
        report = evaluate_password(leet_pwd)
        assert report.rating == "Weak"
        assert report.score <= 15
        assert report.checks["not_common"] is False

    def test_normalize_leetspeak_generates_expected_forms(self) -> None:
        forms = normalize_leetspeak("P@ssw0rd123")
        assert "password" in forms
        assert "letmein" in normalize_leetspeak("1etme1n")
        assert "admin" in normalize_leetspeak("@dm1n")

    def test_short_simple_password_is_weak(self) -> None:
        report = evaluate_password("cat")
        assert report.rating == "Weak"
        assert report.score <= 35
        assert report.checks["min_length"] is False


class TestEntropyAndPassphrases:
    def test_entropy_scales_with_length_and_diversity(self) -> None:
        low = calculate_entropy("kxmptqwr")
        mid = calculate_entropy("K9m2p7x!")
        high = calculate_entropy("K9m2p7x!qWzR#8Lv")
        assert 0 < low < mid < high

    def test_entropy_discounts_repeated_characters(self) -> None:
        repeated = calculate_entropy("aaaaaaaa")
        varied = calculate_entropy("kxmptqwr")
        assert repeated < varied

    def test_long_lowercase_passphrase_scored_fairly_without_special_penalty(self) -> None:
        pwd = "correct horse battery staple"
        assert is_passphrase(pwd) is True
        report = evaluate_password(pwd)
        assert report.is_passphrase is True
        assert report.rating in {"Strong", "Very Strong"}
        assert report.score >= 80
        assert report.entropy_bits >= 100.0
        assert not any("special character" in s.lower() for s in report.suggestions)

    def test_hyphenated_passphrase_recognized(self) -> None:
        pwd = "maple-river-falcon-sunset"
        assert is_passphrase(pwd) is True
        report = evaluate_password(pwd)
        assert report.is_passphrase is True
        assert report.rating == "Very Strong"
        assert report.score == 100

    def test_repeated_word_string_is_not_valid_passphrase(self) -> None:
        assert is_passphrase("maple maple maple maple") is False

    def test_very_strong_passphrase_with_all_classes(self) -> None:
        report = evaluate_password("Correct Horse Battery 99!")
        assert report.score == 100
        assert report.rating == "Very Strong"
        assert report.is_passphrase is True
        assert report.suggestions == []
        assert all(report.checks.values())

    def test_fair_password(self) -> None:
        report = evaluate_password("k9m2p7x4")
        assert report.score == 50
        assert report.rating == "Fair"


class TestBoundaryLengths:
    def test_length_7_fails_minimum(self) -> None:
        pwd = "A1!k9mZ"
        assert len(pwd) == 7
        report = evaluate_password(pwd)
        assert report.checks["min_length"] is False
        assert report.rating == "Weak"
        assert report.score <= 35
        assert any(str(MIN_LENGTH) in s for s in report.suggestions)

    def test_length_8_meets_minimum(self) -> None:
        pwd = "A1!k9mZx"
        assert len(pwd) == 8
        report = evaluate_password(pwd)
        assert report.checks["min_length"] is True
        assert report.checks["recommended_length"] is False
        assert report.score == 80
        assert report.rating == "Strong"

    def test_length_12_earns_bonus(self) -> None:
        res_11 = evaluate_password("A1!k9mZxQ2w")
        res_12 = evaluate_password("A1!k9mZxQ2wR")
        assert res_12.score > res_11.score
        assert res_12.checks["recommended_length"] is True

    def test_length_16_earns_top_bonus(self) -> None:
        res_15 = evaluate_password("A1!k9mZxQ2wR7pL")
        res_16 = evaluate_password("A1!k9mZxQ2wR7pL#")
        assert res_16.score > res_15.score
        assert res_16.score == 100
        assert res_16.checks["strong_length"] is True

    def test_length_128_is_accepted(self) -> None:
        block = "A1!k9mZxQ2wR7pL#"
        pwd = block * (MAX_LENGTH // len(block))
        assert len(pwd) == 128
        assert validate_password_input(pwd) is None
        report = evaluate_password(pwd)
        assert report.checks["valid_input"] is True
        assert report.checks["within_max_length"] is True
        assert report.score == 100
        assert report.rating == "Very Strong"

    def test_length_129_is_rejected(self) -> None:
        pwd = "A1!k" * 32 + "x"
        assert len(pwd) == 129
        assert validate_password_input(pwd) is not None
        report = evaluate_password(pwd)
        assert report.score == 0
        assert report.rating == "Weak"
        assert report.entropy_bits == 0.0
        assert report.checks["valid_input"] is False
        assert report.checks["within_max_length"] is False
        assert any("128" in s for s in report.suggestions)


class TestCharacterDiversity:
    def test_missing_lowercase(self) -> None:
        report = evaluate_password("K9M2P7X!QWZR#8LV")
        assert report.checks["has_lowercase"] is False
        assert any("lowercase" in s.lower() for s in report.suggestions)

    def test_missing_uppercase(self) -> None:
        report = evaluate_password("k9m2p7x!qwzr#8lv")
        assert report.checks["has_uppercase"] is False
        assert any("uppercase" in s.lower() for s in report.suggestions)

    def test_missing_digit(self) -> None:
        report = evaluate_password("KmPx!qWzR#LvTnBg")
        assert report.checks["has_digit"] is False
        assert any("digit" in s.lower() for s in report.suggestions)

    def test_missing_special(self) -> None:
        report = evaluate_password("K9m2p7x4qWzR8LvT")
        assert report.checks["has_special"] is False
        assert any("special" in s.lower() for s in report.suggestions)

    @pytest.mark.parametrize("char", list(SPECIAL_CHARACTERS))
    def test_all_listed_special_characters_recognized(self, char: str) -> None:
        report = evaluate_password(f"K9m2p7x{char}qWzR8LvT")
        assert report.checks["has_special"] is True


class TestPatternAndKeyboardWalkPenalties:
    @pytest.mark.parametrize("pwd", ["K9m2aaa!qWzR8LvT", "K9m21111!qWzR8Lv", "K9m2p7x!!!qWzR8L"])
    def test_repeated_characters_penalized(self, pwd: str) -> None:
        assert has_repeated_chars(pwd) is True
        report = evaluate_password(pwd)
        assert report.checks["no_repeated_chars"] is False
        assert report.score < 100
        assert any("repeat" in s.lower() for s in report.suggestions)

    def test_two_repeated_characters_not_penalized(self) -> None:
        pwd = "K9m2aa!qWzR8LvT#"
        assert has_repeated_chars(pwd) is False
        report = evaluate_password(pwd)
        assert report.checks["no_repeated_chars"] is True
        assert report.score == 100

    @pytest.mark.parametrize(
        "pwd",
        [
            "K9m21234!qWzR8Lv",
            "K9m29876!qWzR8Lv",
            "K9m2abcd!qWzR8Lv",
            "K9m2ZYXW!qWzR8Lv",
        ],
    )
    def test_sequential_runs_penalized(self, pwd: str) -> None:
        assert has_sequential_run(pwd) is True
        report = evaluate_password(pwd)
        assert report.checks["no_sequential_runs"] is False
        assert report.score < 100
        assert any("sequential" in s.lower() for s in report.suggestions)

    @pytest.mark.parametrize(
        "pwd",
        [
            # Forward horizontal
            "K9m2qwerty!qWzR8",
            "K9m2asdfgh!qWzR8",
            "K9m2zxcvbn!qWzR8",
            # Reverse horizontal
            "K9m2ytrewq!qWzR8",
            "K9m2hgfdsa!qWzR8",
            "K9m2nbvcxz!qWzR8",
            # Forward diagonal
            "K9m21qaz2wsx!qWz",
            "K9m23edc!qWzR8Lv",
            "K9m24esz!qWzR8Lv",
            # Reverse diagonal
            "K9m2xsw2zaq1!qWz",
            "K9m2mju7!qWzR8Lv",
            "K9m2zse4!qWzR8Lv",
        ],
    )
    def test_keyboard_walks_forward_and_reverse_penalized(self, pwd: str) -> None:
        assert has_keyboard_walk(pwd) is True
        report = evaluate_password(pwd)
        assert report.checks["no_keyboard_walks"] is False
        assert report.score < 100
        assert any("keyboard walk" in s.lower() for s in report.suggestions)

    def test_normal_words_not_flagged_as_patterns(self) -> None:
        pwd = "First Power Tree 99!"
        assert has_sequential_run(pwd) is False
        assert has_keyboard_walk(pwd) is False
        report = evaluate_password(pwd)
        assert report.score == 100


class TestHIBPBreachCheck:
    def _mock_urlopen_response(self, body: str) -> MagicMock:
        cm = MagicMock()
        cm.__enter__.return_value.read.return_value = body.encode("utf-8")
        cm.__exit__.return_value = False
        return cm

    def test_hibp_breached_password_uses_k_anonymity_and_caps_score(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pwd = "K9m2p7x!qWzR#8Lv"
        sha1_hex = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1_hex[:5], sha1_hex[5:]

        captured_urls: list[str] = []

        def fake_urlopen(req: Any, timeout: float = 3.0) -> MagicMock:
            captured_urls.append(req.full_url)
            assert timeout == 3.0
            body = f"00000000000000000000000000000000000:2\n{suffix}:4219\n"
            return self._mock_urlopen_response(body)

        monkeypatch.setattr(checker.urllib.request, "urlopen", fake_urlopen)

        report = evaluate_password(pwd, check_breach=True)
        assert len(captured_urls) == 1
        assert captured_urls[0].endswith(f"/range/{prefix}")
        assert suffix not in captured_urls[0]
        assert report.is_breached is True
        assert report.breach_count == 4219
        assert report.rating == "Weak"
        assert report.score <= 10
        assert report.checks["not_breached"] is False
        assert any("breach" in s.lower() for s in report.suggestions)

    def test_hibp_safe_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pwd = "K9m2p7x!qWzR#8Lv"
        body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:12\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:3\n"
        monkeypatch.setattr(
            checker.urllib.request,
            "urlopen",
            lambda _req, timeout=3.0: self._mock_urlopen_response(body),
        )

        report = evaluate_password(pwd, check_breach=True)
        assert report.is_breached is False
        assert report.breach_count == 0
        assert report.score == 100
        assert report.checks["not_breached"] is True

    def test_hibp_padded_zero_count_treated_as_safe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pwd = "K9m2p7x!qWzR#8Lv"
        suffix = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()[5:]
        body = f"{suffix}:0\n"
        monkeypatch.setattr(
            checker.urllib.request,
            "urlopen",
            lambda _req, timeout=3.0: self._mock_urlopen_response(body),
        )

        breached, count = check_password_breach(pwd)
        assert breached is False
        assert count == 0

    @pytest.mark.parametrize(
        "error",
        [
            TimeoutError("timed out"),
            urllib.error.URLError("offline"),
            OSError("network unreachable"),
        ],
    )
    def test_hibp_network_failure_falls_back_gracefully(
        self, monkeypatch: pytest.MonkeyPatch, error: BaseException
    ) -> None:
        def fail_urlopen(_req: Any, timeout: float = 3.0) -> Any:
            raise error

        monkeypatch.setattr(checker.urllib.request, "urlopen", fail_urlopen)

        report = evaluate_password("K9m2p7x!qWzR#8Lv", check_breach=True)
        assert report.is_breached is None
        assert report.breach_count is None
        assert report.score == 100
        assert report.rating == "Very Strong"


class TestWhitespaceUnicodeAndInvalidInputs:
    def test_empty_password(self) -> None:
        assert validate_password_input("") is not None
        report = evaluate_password("")
        assert report.score == 0
        assert report.rating == "Weak"
        assert report.checks["valid_input"] is False

    @pytest.mark.parametrize("ws", [" ", "     ", "\t\n  "])
    def test_whitespace_only_password(self, ws: str) -> None:
        assert validate_password_input(ws) is not None
        report = evaluate_password(ws)
        assert report.score == 0
        assert report.rating == "Weak"
        assert report.checks["valid_input"] is False
        assert any("whitespace" in s.lower() for s in report.suggestions)

    @pytest.mark.parametrize(
        "pwd",
        [" K9m2p7x!qWzR8Lv#", "K9m2p7x!qWzR8Lv# ", " K9m2p7x!qWzR8Lv# "],
    )
    def test_leading_or_trailing_spaces_flagged(self, pwd: str) -> None:
        assert has_edge_whitespace(pwd) is True
        report = evaluate_password(pwd)
        assert report.checks["no_edge_whitespace"] is False
        assert report.score == 90
        assert any("leading or trailing" in s.lower() for s in report.suggestions)

    @pytest.mark.parametrize(
        "pwd",
        [
            "Café-Münch3n!2026",
            "Пароль9!Крепкий#2",
            "🔒K9m2p7x!qWzR8Lv",
            "日本語Pass9!Word#88",
        ],
    )
    def test_unicode_and_emoji_passwords_supported(self, pwd: str) -> None:
        report = evaluate_password(pwd)
        assert report.checks["valid_input"] is True
        assert report.score >= 80
        assert report.rating in {"Strong", "Very Strong"}
        assert report.entropy_bits > 0

    @pytest.mark.parametrize("bad_input", [None, 12345, ["password"], {"pwd": "abc"}])
    def test_non_string_raises_type_error(self, bad_input: object) -> None:
        with pytest.raises(TypeError):
            evaluate_password(bad_input)  # type: ignore[arg-type]


class TestCLIAndPiping:
    def test_parse_args_flags(self) -> None:
        default_args = parse_args([])
        assert default_args.visible is False
        assert default_args.breach_check is False
        assert default_args.json_output is False

        all_args = parse_args(["--visible", "--breach-check", "--json"])
        assert all_args.visible is True
        assert all_args.breach_check is True
        assert all_args.json_output is True

    def test_format_json_report(self) -> None:
        report = evaluate_password("Correct Horse Battery 99!")
        raw_json = format_json_report(report)
        data = json.loads(raw_json)
        assert data["score"] == 100
        assert data["rating"] == "Very Strong"
        assert data["entropy_bits"] == report.entropy_bits
        assert data["is_breached"] is None

    def test_stdin_piping_json_output(self) -> None:
        fake_stdin = io.StringIO("Correct Horse Battery 99!\n")
        fake_stdout = io.StringIO()

        exit_code = main(["--json"], stdin=fake_stdin, output_stream=fake_stdout)
        assert exit_code == 0

        data = json.loads(fake_stdout.getvalue())
        assert data["score"] == 100
        assert data["rating"] == "Very Strong"
        assert data["is_passphrase"] is True

    def test_stdin_piping_empty_and_oversized_json_no_crash(self) -> None:
        for raw in ("", "   \n", ("A1!k" * 32 + "x") + "\n", "🔒Café-Münch3n!2026\n"):
            fake_stdin = io.StringIO(raw)
            fake_stdout = io.StringIO()
            exit_code = main(["--json"], stdin=fake_stdin, output_stream=fake_stdout)
            assert exit_code == 0
            data = json.loads(fake_stdout.getvalue())
            assert "score" in data
            assert "rating" in data
            assert "entropy_bits" in data

    def test_stdin_piping_rich_output(self) -> None:
        fake_stdin = io.StringIO("K9m2p7x!qWzR#8Lv\n")
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=False, width=100)

        exit_code = main([], stdin=fake_stdin, output_stream=buf, console=console)
        assert exit_code == 0
        rendered = buf.getvalue()
        assert "Very Strong" in rendered
        assert "100/100" in rendered
        assert "Security Breakdown" in rendered

    def test_render_report_displays_breach_states(self) -> None:
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=False, width=100)
        breached_report = PasswordReport(
            score=10,
            rating="Weak",
            entropy_bits=42.0,
            is_breached=True,
            breach_count=1500,
            suggestions=["Breached password."],
            checks={"min_length": True},
        )
        render_report(breached_report, console, breach_check_enabled=True)
        out = buf.getvalue()
        assert "BREACHED (1,500 exposures)" in out
        assert "Improvement Suggestions" in out

    def test_interactive_loop_handles_invalid_valid_and_exit(self) -> None:
        inputs = iter(["", "   ", "x" * 129, "K9m2p7x!qWzR#8Lv", "exit"])
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=False, width=100)

        exit_code = run_interactive(
            visible=True,
            input_func=lambda _prompt: next(inputs),
            console=console,
            output_stream=buf,
        )

        rendered = buf.getvalue()
        assert exit_code == 0
        assert "Password cannot be empty." in rendered
        assert "Password cannot contain only whitespace." in rendered
        assert "Password must not exceed 128 characters." in rendered
        assert "Very Strong" in rendered
        assert "Goodbye!" in rendered

    @pytest.mark.parametrize("exc", [KeyboardInterrupt, EOFError])
    def test_interactive_handles_interrupt_and_eof(self, exc: type[BaseException]) -> None:
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=False, width=100)

        def raise_exc(_prompt: str) -> str:
            raise exc()

        exit_code = run_interactive(
            visible=True,
            input_func=raise_exc,
            console=console,
            output_stream=buf,
        )

        assert exit_code == 0
        assert "Goodbye!" in buf.getvalue()
