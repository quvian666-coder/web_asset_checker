from __future__ import annotations

import unittest

from webapp.findings import FindingReviewUpdate, ReviewStatus, finding_fingerprint, normalize_endpoint


class FindingIdentityTests(unittest.TestCase):
    def test_normalization_collapses_equivalent_default_ports(self) -> None:
        self.assertEqual(
            normalize_endpoint("HTTPS://Example.COM:443/admin/"),
            "https://example.com/admin",
        )
        self.assertEqual(
            finding_fingerprint("https://example.com:443/admin/", "admin"),
            finding_fingerprint("https://EXAMPLE.com/admin", "ADMIN"),
        )

    def test_protocol_port_path_and_category_change_identity(self) -> None:
        base = finding_fingerprint("https://example.com/admin", "ADMIN")
        variants = {
            finding_fingerprint("http://example.com/admin", "ADMIN"),
            finding_fingerprint("https://example.com:8443/admin", "ADMIN"),
            finding_fingerprint("https://example.com/login", "ADMIN"),
            finding_fingerprint("https://example.com/admin", "LOGIN"),
        }
        self.assertNotIn(base, variants)
        self.assertEqual(len(variants), 4)


class FindingReviewTests(unittest.TestCase):
    def test_normalizes_tags_and_fields(self) -> None:
        update = FindingReviewUpdate.create(
            status="CONFIRMED",
            assignee=" analyst ",
            notes=" checked ",
            tags=["web", " web ", "auth"],
            evidence_summary=" 401 response ",
            mark_retested=True,
        )
        self.assertEqual(update.status, ReviewStatus.CONFIRMED)
        self.assertEqual(update.assignee, "analyst")
        self.assertEqual(update.tags, ("web", "auth"))

    def test_accepted_risk_requires_notes(self) -> None:
        with self.assertRaisesRegex(ValueError, "备注"):
            FindingReviewUpdate.create(
                status="ACCEPTED_RISK",
                assignee="",
                notes="",
                tags=[],
                evidence_summary="",
                mark_retested=False,
            )


if __name__ == "__main__":
    unittest.main()
