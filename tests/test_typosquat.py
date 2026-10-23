import unittest

from depshield.models import Dependency
from depshield.typosquat import STARTER_POPULAR, _levenshtein, check_dependency


class TestTyposquat(unittest.TestCase):
    def test_levenshtein(self):
        self.assertEqual(_levenshtein("colorama", "colourama"), 1)
        self.assertEqual(_levenshtein("requests", "requests"), 0)

    def test_colourama_flagged(self):
        dep = Dependency(name="colourama", ecosystem="PyPI", version="0.4.6")
        hit = check_dependency(dep, STARTER_POPULAR["PyPI"])
        self.assertIsNotNone(hit)
        self.assertEqual(hit.suggestion, "colorama")

    def test_real_package_not_flagged(self):
        dep = Dependency(name="requests", ecosystem="PyPI", version="2.31.0")
        self.assertIsNone(check_dependency(dep, STARTER_POPULAR["PyPI"]))


if __name__ == "__main__":
    unittest.main()
