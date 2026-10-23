import unittest

from depshield.models import Advisory
from depshield.osv.matcher import is_vulnerable


class TestMatcher(unittest.TestCase):
    def setUp(self):
        self.adv = Advisory(
            id="TEST-1",
            summary="demo",
            ranges=[{"introduced": "0"}, {"fixed": "2.31.0"}],
        )

    def test_below_fix_is_vulnerable(self):
        self.assertTrue(is_vulnerable("2.19.1", self.adv, "PyPI"))

    def test_at_fix_is_safe(self):
        self.assertFalse(is_vulnerable("2.31.0", self.adv, "PyPI"))

    def test_above_fix_is_safe(self):
        self.assertFalse(is_vulnerable("2.32.0", self.adv, "PyPI"))


if __name__ == "__main__":
    unittest.main()
