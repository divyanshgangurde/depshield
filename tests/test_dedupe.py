import unittest

from depshield.models import Advisory
from depshield.osv.dedupe import dedupe_advisories


def _adv(id, summary, ranges, severity=None):
    return Advisory(id=id, summary=summary, ranges=ranges, severity=severity)


class TestDedupe(unittest.TestCase):
    def test_same_id_folds_and_merges_ranges(self):
        a1 = _adv("GHSA-x", "Nova leak", [{"introduced": "0"}, {"fixed": "1.0"}])
        a2 = _adv("GHSA-x", "Nova leak", [{"introduced": "2.0"}, {"fixed": "3.0"}])
        out = dedupe_advisories([a1, a2])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].id, "GHSA-x")
        # Union of both ranges, duplicate events collapsed.
        self.assertEqual(len(out[0].ranges), 4)

    def test_ghsa_pysec_same_summary_merges(self):
        ghsa = _adv(
            "GHSA-r562-m862-63w3",
            "APM Java Agent Local Privilege Escalation",
            [{"introduced": "0"}, {"fixed": "1.0"}],
        )
        pysec = _adv(
            "PYSEC-2026-634",
            "APM Java Agent Local Privilege Escalation",
            [{"introduced": "0"}, {"fixed": "1.0"}],
        )
        out = dedupe_advisories([pysec, ghsa])  # input order shouldn't matter
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].id, "GHSA-r562-m862-63w3")
        self.assertEqual(out[0].aliases, ["PYSEC-2026-634"])

    def test_distinct_summaries_stay_separate(self):
        out = dedupe_advisories(
            [
                _adv("GHSA-a", "XSS in admin", [{"introduced": "0"}]),
                _adv("GHSA-b", "SSRF in API", [{"introduced": "0"}]),
            ]
        )
        self.assertEqual(len(out), 2)

    def test_empty_summary_never_merges(self):
        out = dedupe_advisories(
            [
                _adv("PYSEC-1", "", [{"introduced": "0"}]),
                _adv("PYSEC-2", "", [{"introduced": "0"}]),
            ]
        )
        self.assertEqual(len(out), 2)

    def test_summary_match_is_case_and_whitespace_insensitive(self):
        out = dedupe_advisories(
            [
                _adv("GHSA-a", "SQL  injection  in  login", []),
                _adv("PYSEC-9", "sql injection in login", []),
            ]
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].id, "GHSA-a")

    def test_severity_survives_merge(self):
        out = dedupe_advisories(
            [
                _adv("PYSEC-9", "Bug", [], severity=None),
                _adv("GHSA-a", "Bug", [], severity="HIGH"),
            ]
        )
        self.assertEqual(out[0].severity, "HIGH")


if __name__ == "__main__":
    unittest.main()
