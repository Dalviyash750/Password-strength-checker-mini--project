import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from password_checker import check_password, format_crack_time, generate_password  # noqa: E402


class TestCheckPassword(unittest.TestCase):
    def test_empty_password(self):
        result = check_password("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.label, "Very Weak")

    def test_common_password_is_very_weak(self):
        for pwd in ("password", "123456", "qwerty", "iloveyou", "Password"):
            with self.subTest(pwd=pwd):
                result = check_password(pwd)
                self.assertTrue(result.is_common)
                self.assertEqual(result.label, "Very Weak")
                self.assertEqual(result.crack_time, "instantly")

    def test_leet_speak_does_not_fool_checker(self):
        result = check_password("P@ssw0rd")
        self.assertTrue(result.is_common)
        self.assertEqual(result.label, "Very Weak")

    def test_short_password_is_very_weak(self):
        result = check_password("aB3$x")
        self.assertEqual(result.label, "Very Weak")
        self.assertTrue(any("short" in issue.lower() for issue in result.issues))

    def test_repeated_characters_detected(self):
        result = check_password("aaaaaaaaaaaa")
        self.assertTrue(any("repeated" in i.lower() for i in result.issues))
        self.assertIn(result.label, ("Very Weak", "Weak"))

    def test_sequence_detected(self):
        result = check_password("abcd1234efgh")
        self.assertTrue(any("sequence" in i.lower() for i in result.issues))

    def test_keyboard_pattern_detected(self):
        result = check_password("zxcvbnmQ1")
        self.assertTrue(any("keyboard" in i.lower() for i in result.issues))

    def test_character_flags(self):
        result = check_password("Abc123!x")
        self.assertTrue(result.has_lower)
        self.assertTrue(result.has_upper)
        self.assertTrue(result.has_digit)
        self.assertTrue(result.has_symbol)

    def test_missing_types_produce_suggestions(self):
        result = check_password("onlylowercaseletters")
        joined = " ".join(result.suggestions).lower()
        self.assertIn("uppercase", joined)
        self.assertIn("numbers", joined)
        self.assertIn("symbols", joined)

    def test_strong_random_password(self):
        result = check_password("t7#Qm!vZ9r$Lw2@Xk8")
        self.assertIn(result.label, ("Strong", "Very Strong"))
        self.assertGreaterEqual(result.score, 70)

    def test_longer_is_stronger(self):
        short = check_password("Tr9#kLp2")
        long = check_password("Tr9#kLp2Vb6&nMq4")
        self.assertGreater(long.entropy_bits, short.entropy_bits)
        self.assertGreaterEqual(long.score, short.score)

    def test_score_is_in_range(self):
        for pwd in ("a", "password", "Tr9#kLp2Vb6&nMq4" * 5, "🔒🔑🔒🔑🔒🔑🔒🔑"):
            with self.subTest(pwd=pwd):
                self.assertTrue(0 <= check_password(pwd).score <= 100)


class TestFormatCrackTime(unittest.TestCase):
    def test_instant(self):
        self.assertEqual(format_crack_time(0), "instantly")

    def test_seconds_minutes_hours(self):
        self.assertIn("second", format_crack_time(5))
        self.assertIn("minute", format_crack_time(120))
        self.assertIn("hour", format_crack_time(7200))

    def test_years_and_centuries(self):
        self.assertIn("year", format_crack_time(3 * 365 * 24 * 3600))
        self.assertIn("centur", format_crack_time(1e15))


class TestGenerator(unittest.TestCase):
    def test_length_and_character_types(self):
        for _ in range(50):
            pwd = generate_password(16)
            self.assertEqual(len(pwd), 16)
            self.assertTrue(any(c.islower() for c in pwd))
            self.assertTrue(any(c.isupper() for c in pwd))
            self.assertTrue(any(c.isdigit() for c in pwd))
            self.assertTrue(any(not c.isalnum() for c in pwd))

    def test_no_symbols_option(self):
        for _ in range(20):
            self.assertTrue(generate_password(20, use_symbols=False).isalnum())

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            generate_password(4)

    def test_passwords_differ(self):
        self.assertNotEqual(generate_password(24), generate_password(24))


if __name__ == "__main__":
    unittest.main()
