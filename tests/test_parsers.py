import os
import tempfile
import unittest

from depshield.parsers import parse_manifest


class TestRequirementsParser(unittest.TestCase):
    def test_pins_ranges_and_unpinned(self):
        content = "requests==2.31.0\nflask>=2.0\nnumpy\n# comment\n"
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, dir=tempfile.gettempdir()
        ) as f:
            f.write(content)
            path = f.name
        try:
            deps = parse_manifest(path)
        finally:
            os.unlink(path)
        by_name = {d.name: d for d in deps}
        self.assertEqual(by_name["requests"].version, "2.31.0")
        self.assertIsNone(by_name["flask"].version)
        self.assertIsNone(by_name["numpy"].version)
        self.assertEqual(by_name["requests"].ecosystem, "PyPI")


if __name__ == "__main__":
    unittest.main()
