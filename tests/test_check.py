from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("action_check", ROOT / "scripts/check.py")
assert SPEC and SPEC.loader
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class CheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary.name)
        self.environment = mock.patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        os.environ["GITHUB_WORKSPACE"] = str(self.workspace)

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def write(self, relative: str, content: bytes) -> Path:
        target = self.workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def test_saved_html_is_workspace_confined_and_carries_explicit_scope(self) -> None:
        self.write("dist/checkout.html", b'<script src="/pay.js"></script>')
        os.environ.update(
            {
                "INPUT_HTML_FILE": "dist/checkout.html",
                "INPUT_PAGE_ORIGIN": "https://shop.example/checkout",
                "INPUT_ALLOWED_DOMAINS": "shop.example, js.stripe.com",
                "INPUT_PAYMENT_PAGE_SCOPE": "direct",
            }
        )

        body = CHECK.build_request_body()

        self.assertEqual(body["url"], "https://shop.example/checkout")
        self.assertIn("/pay.js", body["html"])
        self.assertEqual(body["allowed_domains"], ["shop.example", "js.stripe.com"])
        self.assertEqual(body["payment_page_scope"], "direct")

    def test_absolute_outside_and_symlink_html_paths_are_refused(self) -> None:
        outside = Path(self.temporary.name).parent / "outside.html"
        outside.write_text("<html></html>", encoding="utf-8")
        self.addCleanup(outside.unlink, missing_ok=True)
        self.write("inside.html", b"<html></html>")
        (self.workspace / "linked.html").symlink_to(self.workspace / "inside.html")

        for supplied in (str(outside), "../outside.html", "linked.html"):
            with self.subTest(supplied=supplied):
                os.environ["INPUT_HTML_FILE"] = supplied
                with self.assertRaises(SystemExit):
                    CHECK.build_request_body()

    def test_saved_html_must_be_bounded_utf8_without_nul(self) -> None:
        for name, content in (
            ("invalid.html", b"\xff"),
            ("nul.html", b"<html>\x00</html>"),
            ("large.html", b"x" * (CHECK.MAX_HTML_BYTES + 1)),
        ):
            with self.subTest(name=name):
                self.write(name, content)
                os.environ["INPUT_HTML_FILE"] = name
                with self.assertRaises(SystemExit):
                    CHECK.build_request_body()

    def test_url_and_scope_inputs_fail_closed(self) -> None:
        for url in (
            "http://shop.example/checkout",
            "https://user:secret@shop.example/checkout",
            "https://shop.example:8443/checkout",
        ):
            with self.subTest(url=url):
                os.environ.clear()
                os.environ.update({"GITHUB_WORKSPACE": str(self.workspace), "INPUT_URL": url})
                with self.assertRaises(SystemExit):
                    CHECK.build_request_body()

        os.environ.clear()
        os.environ.update(
            {
                "GITHUB_WORKSPACE": str(self.workspace),
                "INPUT_URL": "https://shop.example/checkout",
                "INPUT_PAYMENT_PAGE_SCOPE": "guessed",
            }
        )
        with self.assertRaises(SystemExit):
            CHECK.build_request_body()

    def test_medium_threshold_uses_complete_observed_findings(self) -> None:
        os.environ.update(
            {
                "INPUT_URL": "https://shop.example/checkout",
                "INPUT_FAIL_ON": "medium",
            }
        )
        result = {
            "headline": "Review one observation.",
            "proven_gaps": [],
            "observed_findings": [
                {
                    "code": "INLINE_SCRIPT",
                    "severity": "medium",
                    "message": "An inline block needs a justification.",
                    "evidence": "inline script block 1",
                }
            ],
            "total_findings": 1,
        }

        with mock.patch.object(CHECK, "call_service", return_value=result):
            self.assertEqual(CHECK.main(), 1)

    def test_never_threshold_reports_findings_without_failing(self) -> None:
        os.environ.update(
            {
                "INPUT_URL": "https://shop.example/checkout",
                "INPUT_FAIL_ON": "never",
            }
        )
        result = {
            "headline": "Review one observation.",
            "observed_findings": [
                {"severity": "high", "message": "Observed gap", "evidence": "host"}
            ],
            "total_findings": 1,
        }

        with mock.patch.object(CHECK, "call_service", return_value=result):
            self.assertEqual(CHECK.main(), 0)

    def test_invalid_finding_count_fails_closed(self) -> None:
        os.environ["INPUT_URL"] = "https://shop.example/checkout"

        for invalid in (True, -1, 1.5, None, "many", [], {}):
            with self.subTest(invalid=invalid):
                result = {
                    "headline": "Check complete.",
                    "observed_findings": [],
                    "total_findings": invalid,
                }
                with mock.patch.object(CHECK, "call_service", return_value=result):
                    with self.assertRaises(SystemExit):
                        CHECK.main()

    def test_unknown_severity_and_inconsistent_complete_count_fail_closed(self) -> None:
        os.environ["INPUT_URL"] = "https://shop.example/checkout"

        for result in (
            {
                "observed_findings": [{"severity": "urgent", "message": "gap"}],
                "total_findings": 1,
            },
            {
                "observed_findings": [{"severity": "info", "message": "note"}],
                "total_findings": 2,
            },
        ):
            with self.subTest(result=result):
                with mock.patch.object(CHECK, "call_service", return_value=result):
                    with self.assertRaises(SystemExit):
                        CHECK.main()

    def test_medium_and_low_thresholds_require_the_complete_findings_contract(self) -> None:
        os.environ["INPUT_URL"] = "https://shop.example/checkout"
        legacy = {
            "headline": "Legacy result",
            "proven_gaps": [],
            "total_findings": 1,
        }

        for threshold in ("medium", "low"):
            with self.subTest(threshold=threshold):
                os.environ["INPUT_FAIL_ON"] = threshold
                with mock.patch.object(CHECK, "call_service", return_value=legacy):
                    with self.assertRaises(SystemExit):
                        CHECK.main()

    def test_info_findings_are_reported_but_do_not_block_high_threshold(self) -> None:
        os.environ["INPUT_URL"] = "https://shop.example/checkout"
        result = {
            "headline": "One bounded note.",
            "observed_findings": [{"severity": "info", "message": "Review scope."}],
            "total_findings": 1,
        }

        with mock.patch.object(CHECK, "call_service", return_value=result):
            self.assertEqual(CHECK.main(), 0)

    def test_summary_escapes_untrusted_markdown_and_html(self) -> None:
        summary = self.workspace / "summary.md"
        os.environ.update(
            {
                "INPUT_URL": "https://shop.example/checkout",
                "INPUT_FAIL_ON": "never",
                "GITHUB_STEP_SUMMARY": str(summary),
            }
        )
        result = {
            "headline": "<img src=x onerror=alert(1)>",
            "observed_findings": [
                {
                    "severity": "low",
                    "message": "[click](https://evil.example)|row",
                    "evidence": "ignored",
                }
            ],
            "total_findings": 1,
        }

        with mock.patch.object(CHECK, "call_service", return_value=result):
            self.assertEqual(CHECK.main(), 0)
        rendered = summary.read_text(encoding="utf-8")
        self.assertNotIn("<img", rendered)
        self.assertNotIn("[click]", rendered)
        self.assertIn("&lt;img", rendered)
        self.assertIn("&#124;row", rendered)

    def test_direct_result_exposes_only_validated_server_next_steps(self) -> None:
        summary = self.workspace / "summary.md"
        os.environ.update(
            {
                "INPUT_URL": "https://shop.example/checkout",
                "INPUT_PAYMENT_PAGE_SCOPE": "direct",
                "INPUT_FAIL_ON": "never",
                "GITHUB_STEP_SUMMARY": str(summary),
            }
        )
        result = {
            "headline": "One bounded observation.",
            "observed_findings": [],
            "total_findings": 0,
            "sample_url": "/samples/pci-dss-6-4-3-remediation-pack",
            "buy_url": "/checkout/pci",
            "ongoing_monitoring": {
                "sample_url": "/samples/pci-dss-11-6-1-evidence-ledger",
                "buy_url": "/checkout/pci_ledger",
            },
        }

        with mock.patch.object(CHECK, "call_service", return_value=result):
            self.assertEqual(CHECK.main(), 0)

        rendered = summary.read_text(encoding="utf-8")
        self.assertIn("pci-dss-6-4-3-script-inventory-template", rendered)
        self.assertIn("https://qi.toledotechnologies.com/checkout/pci)", rendered)
        self.assertIn("https://qi.toledotechnologies.com/checkout/pci_ledger)", rendered)
        self.assertIn("Preview the 6.4.3 deliverable", rendered)
        self.assertIn("Preview the 11.6.1 evidence ledger", rendered)

    def test_non_direct_scope_never_advertises_a_returned_checkout(self) -> None:
        summary = self.workspace / "summary.md"
        os.environ.update(
            {
                "INPUT_URL": "https://shop.example/cart",
                "INPUT_PAYMENT_PAGE_SCOPE": "outsourced",
                "INPUT_FAIL_ON": "never",
                "GITHUB_STEP_SUMMARY": str(summary),
            }
        )
        inconsistent = {
            "headline": "Bounded inventory complete.",
            "observed_findings": [],
            "total_findings": 0,
            "sample_url": "/samples/pci-dss-6-4-3-remediation-pack",
            "buy_url": "/checkout/pci",
            "ongoing_monitoring": {"buy_url": "/checkout/pci_ledger"},
        }

        with mock.patch.object(CHECK, "call_service", return_value=inconsistent):
            self.assertEqual(CHECK.main(), 0)

        rendered = summary.read_text(encoding="utf-8")
        self.assertIn("saq-a-script-security-confirmation", rendered)
        self.assertNotIn("/checkout/", rendered)
        self.assertNotIn("Preview the 6.4.3 deliverable", rendered)

    def test_unspecified_scope_is_omitted_and_never_advertises_checkout(self) -> None:
        summary = self.workspace / "summary.md"
        os.environ.update(
            {
                "INPUT_URL": "https://shop.example/checkout",
                "INPUT_ALLOWED_DOMAINS": "shop.example, js.stripe.com",
                "INPUT_FAIL_ON": "never",
                "GITHUB_STEP_SUMMARY": str(summary),
            }
        )

        body = CHECK.build_request_body()

        self.assertNotIn("payment_page_scope", body)
        self.assertEqual(body["allowed_domains"], ["shop.example", "js.stripe.com"])

        inconsistent = {
            "headline": "Bounded inventory complete.",
            "observed_findings": [],
            "total_findings": 0,
            "sample_url": "/samples/pci-dss-6-4-3-remediation-pack",
            "buy_url": "/checkout/pci",
            "ongoing_monitoring": {
                "sample_url": "/samples/pci-dss-11-6-1-evidence-ledger",
                "buy_url": "/checkout/pci_ledger",
            },
        }

        with mock.patch.object(CHECK, "call_service", return_value=inconsistent):
            self.assertEqual(CHECK.main(), 0)

        rendered = summary.read_text(encoding="utf-8")
        self.assertIn("bounded PCI payment-page workflow", rendered)
        self.assertNotIn("/checkout/", rendered)
        self.assertNotIn("Preview the 6.4.3 deliverable", rendered)
        self.assertNotIn("Preview the 11.6.1 evidence ledger", rendered)

    def test_initial_readme_recipes_are_scope_neutral_before_classification(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        initial_usage = readme.split(
            "### After the first inventory, choose the confirmed payment flow", 1
        )[0]

        self.assertNotIn("payment-page-scope:", initial_usage)
        self.assertIn(
            "The first run intentionally leaves `payment-page-scope` unspecified.",
            initial_usage,
        )
        self.assertIn("cannot show paid next steps", initial_usage)
        self.assertIn("payment-page-scope: direct", readme)
        self.assertIn("payment-page-scope: embedded", readme)
        self.assertIn("payment-page-scope: outsourced", readme)

    def test_saved_html_never_advertises_a_returned_monitor(self) -> None:
        summary = self.workspace / "summary.md"
        self.write("checkout.html", b"<script></script>")
        os.environ.update(
            {
                "INPUT_HTML_FILE": "checkout.html",
                "INPUT_PAGE_ORIGIN": "https://shop.example/checkout",
                "INPUT_PAYMENT_PAGE_SCOPE": "direct",
                "INPUT_FAIL_ON": "never",
                "GITHUB_STEP_SUMMARY": str(summary),
            }
        )
        result = {
            "headline": "Bounded inventory complete.",
            "observed_findings": [],
            "total_findings": 0,
            "buy_url": "/checkout/pci",
            "ongoing_monitoring": {"buy_url": "/checkout/pci_ledger"},
        }

        with mock.patch.object(CHECK, "call_service", return_value=result):
            self.assertEqual(CHECK.main(), 0)

        rendered = summary.read_text(encoding="utf-8")
        self.assertIn("/checkout/pci)", rendered)
        self.assertNotIn("/checkout/pci_ledger", rendered)

    def test_untrusted_next_step_origins_and_paths_fail_closed(self) -> None:
        for value in (
            "https://evil.example/checkout/pci",
            "//evil.example/checkout/pci",
            "/checkout/pci?coupon=unknown",
            "/checkout/not-a-product",
            7,
        ):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                CHECK._safe_product_url(value, base="https://qi.toledotechnologies.com")

    def test_a_result_without_server_offer_fields_never_synthesizes_checkout(self) -> None:
        summary = self.workspace / "summary.md"
        os.environ.update(
            {
                "INPUT_URL": "https://shop.example/checkout",
                "INPUT_PAYMENT_PAGE_SCOPE": "direct",
                "INPUT_FAIL_ON": "never",
                "GITHUB_STEP_SUMMARY": str(summary),
            }
        )
        result = {
            "headline": "Bounded inventory complete.",
            "observed_findings": [],
            "total_findings": 0,
        }

        with mock.patch.object(CHECK, "call_service", return_value=result):
            self.assertEqual(CHECK.main(), 0)

        self.assertNotIn("/checkout/", summary.read_text(encoding="utf-8"))

    def test_multiline_output_uses_a_non_static_delimiter(self) -> None:
        output = self.workspace / "output.txt"
        os.environ["GITHUB_OUTPUT"] = str(output)

        CHECK._out("report", "one\n__EOF__\ntwo")

        rendered = output.read_text(encoding="utf-8")
        first = rendered.splitlines()[0]
        self.assertTrue(first.startswith("report<<CSI_"))
        self.assertNotEqual(first, "report<<__EOF__")
        delimiter = first.split("<<", 1)[1]
        self.assertEqual(rendered.splitlines()[-1], delimiter)

    def test_summary_and_log_cells_are_bounded(self) -> None:
        summary = self.workspace / "summary.md"
        os.environ["GITHUB_STEP_SUMMARY"] = str(summary)

        CHECK._summary("[" * (CHECK.MAX_SUMMARY_BYTES + 100))

        rendered = summary.read_bytes()
        self.assertLessEqual(len(rendered), CHECK.MAX_SUMMARY_BYTES + 1)
        self.assertIn(b"Result truncated", rendered)
        self.assertLessEqual(len(CHECK._one_line("x" * 10_000)), CHECK.MAX_LOG_CHARS)
        self.assertLessEqual(len(CHECK._cell("[" * 10_000)), CHECK.MAX_CELL_CHARS * 5)

    def test_error_annotations_cannot_inject_a_second_workflow_command(self) -> None:
        stream = StringIO()
        with redirect_stdout(stream), self.assertRaises(SystemExit):
            CHECK._fail("bad\n::warning::injected%")

        rendered = stream.getvalue()
        self.assertEqual(rendered.count("\n"), 1)
        self.assertNotIn("\n::warning", rendered)
        self.assertIn("%25", rendered)


if __name__ == "__main__":
    unittest.main()
