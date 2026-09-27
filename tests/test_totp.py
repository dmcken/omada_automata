'''Tests for TOTP code generation. Uses the RFC 6238 published test
vector (secret "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", SHA1) rather than
any real account's secret - the code at a given Unix time is a fixed,
publicly documented value, so this needs no mocking.'''
from omada_automata.totp import generate_totp_code, generate_totp_codes_with_drift_tolerance

_RFC6238_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'


class TestGenerateTotpCode:
    def test_matches_rfc6238_test_vector(self):
        # RFC 6238 Appendix B: T=59 -> "94287082" (8-digit, SHA1) -
        # pyotp's default 6-digit truncation keeps the last 6 digits.
        assert generate_totp_code(_RFC6238_SECRET, at_time=59) == '287082'

    def test_different_time_gives_different_code(self):
        assert generate_totp_code(_RFC6238_SECRET, at_time=59) != generate_totp_code(
            _RFC6238_SECRET, at_time=1111111109
        )

    def test_defaults_to_current_time(self):
        code = generate_totp_code(_RFC6238_SECRET)
        assert len(code) == 6
        assert code.isdigit()


class TestGenerateTotpCodesWithDriftTolerance:
    def test_includes_the_current_code(self):
        codes = generate_totp_codes_with_drift_tolerance(_RFC6238_SECRET, steps=1, period=30)
        assert generate_totp_code(_RFC6238_SECRET) in codes

    def test_one_step_returns_three_distinct_codes(self):
        codes = generate_totp_codes_with_drift_tolerance(_RFC6238_SECRET, steps=1, period=30)
        assert len(codes) == 3
        assert len(set(codes)) == 3

    def test_zero_steps_returns_just_the_current_code(self):
        codes = generate_totp_codes_with_drift_tolerance(_RFC6238_SECRET, steps=0, period=30)
        assert codes == [generate_totp_code(_RFC6238_SECRET)]
