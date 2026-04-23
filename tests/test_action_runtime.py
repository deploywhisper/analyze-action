from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import action_runtime


class BuildPrCommentTests(unittest.TestCase):
    def _share_summary_payload(self) -> dict:
        return {
            "severity": "high",
            "recommendation": "no-go",
            "headline": "NO-GO: Security group exposure could widen database ingress.",
            "json_payload": {
                "verdict_banner": "DeployWhisper HIGH · NO-GO",
                "headline": "NO-GO: Security group exposure could widen database ingress.",
                "top_findings": [
                    {
                        "title": "Database security group widens ingress to 0.0.0.0/0",
                        "severity": "critical",
                        "evidence_count": 2,
                        "confidence": 0.98,
                    },
                    {
                        "title": "Application load balancer now targets the database subnet",
                        "severity": "high",
                        "evidence_count": 1,
                        "confidence": 0.82,
                    },
                    {
                        "title": "Rollback depends on a manual security group replacement",
                        "severity": "medium",
                        "evidence_count": 1,
                        "confidence": 0.72,
                    },
                ],
                "evidence_count": 6,
                "blast_radius_summary": "2 direct / 4 transitive (Primary DB, Worker Queue, Checkout API)",
                "rollback_summary": "4/5 HIGH · First step: restore the previous security group rule set",
                "context_completeness": {
                    "score": 0.61,
                    "label": "LIMITED CONTEXT",
                    "summary": "LIMITED CONTEXT (0.61) - one or more artifacts failed to parse cleanly.",
                },
                "report_link": "https://deploywhisper.example.com/history?report_id=42",
                "rollback_link": "https://deploywhisper.example.com/history?report_id=42",
                "advisory_summary": "This result requires additional human review before release.",
            },
        }

    def test_build_pr_comment_includes_story_fields_and_collapsible_details(self) -> None:
        comment = action_runtime.build_pr_comment(self._share_summary_payload())

        self.assertIn("DeployWhisper HIGH · NO-GO", comment)
        self.assertIn("6 evidence items", comment)
        self.assertIn("Blast radius", comment)
        self.assertIn("[View rollback plan]", comment)
        self.assertIn("[Open full report]", comment)
        self.assertIn("LIMITED CONTEXT", comment)
        self.assertIn("<details>", comment)
        self.assertIn("</details>", comment)
        self.assertLessEqual(len(comment), 2000)

    def test_build_pr_comment_trims_content_to_two_thousand_characters(self) -> None:
        share_summary = self._share_summary_payload()
        share_summary["json_payload"]["blast_radius_summary"] = "Primary DB, " * 80
        share_summary["json_payload"]["rollback_summary"] = "Manual rollback, " * 80
        share_summary["json_payload"]["context_completeness"]["summary"] = (
            "LIMITED CONTEXT " * 80
        )
        share_summary["json_payload"]["top_findings"][0]["title"] = (
            "Critical finding " * 80
        )

        comment = action_runtime.build_pr_comment(share_summary)

        self.assertLessEqual(len(comment), 2000)
        self.assertTrue(comment.rstrip().endswith("</details>"))
        self.assertIn("- CRITICAL:", comment)
        self.assertIn("- HIGH:", comment)
        self.assertIn("- MEDIUM:", comment)


class UpsertPrCommentTests(unittest.TestCase):
    def _context(self) -> dict[str, object]:
        return {
            "repository": "deploywhisper/example-repo",
            "pull_request_number": 17,
        }

    def _response(self, payload: dict) -> object:
        class Response:
            def __init__(self, body: dict) -> None:
                self._body = json.dumps(body).encode("utf-8")

            def read(self) -> bytes:
                return self._body

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

        return Response(payload)

    def test_upsert_pr_comment_updates_existing_marker_comment(self) -> None:
        requests: list[tuple[str, str]] = []

        def fake_urlopen(request_obj, timeout=120):
            requests.append((request_obj.get_method(), request_obj.full_url))
            if request_obj.get_method() == "GET":
                return self._response(
                    [
                        {
                            "id": 99,
                            "body": "<!-- deploywhisper:pr-comment -->\nexisting",
                            "html_url": "https://github.com/deploywhisper/example-repo/issues/17#issuecomment-99",
                        }
                    ]
                )
            return self._response(
                {
                    "id": 99,
                    "html_url": "https://github.com/deploywhisper/example-repo/issues/17#issuecomment-99",
                }
            )

        with patch("action_runtime.request.urlopen", side_effect=fake_urlopen):
            result = action_runtime.upsert_pr_comment(
                self._context(),
                "<!-- deploywhisper:pr-comment -->\nnew body",
                github_token="ghs_test",
            )

        self.assertEqual(result["id"], 99)
        self.assertEqual(requests[0][0], "GET")
        self.assertEqual(requests[1][0], "PATCH")
        self.assertTrue(requests[1][1].endswith("/issues/comments/99"))

    def test_upsert_pr_comment_creates_comment_when_marker_missing(self) -> None:
        requests: list[tuple[str, str]] = []

        def fake_urlopen(request_obj, timeout=120):
            requests.append((request_obj.get_method(), request_obj.full_url))
            if request_obj.get_method() == "GET":
                return self._response([])
            return self._response(
                {
                    "id": 101,
                    "html_url": "https://github.com/deploywhisper/example-repo/issues/17#issuecomment-101",
                }
            )

        with patch("action_runtime.request.urlopen", side_effect=fake_urlopen):
            result = action_runtime.upsert_pr_comment(
                self._context(),
                "<!-- deploywhisper:pr-comment -->\nnew body",
                github_token="ghs_test",
            )

        self.assertEqual(result["id"], 101)
        self.assertEqual(requests[0][0], "GET")
        self.assertEqual(requests[1][0], "POST")
        self.assertTrue(requests[1][1].endswith("/issues/17/comments"))

    def test_upsert_pr_comment_scans_multiple_pages_before_creating_duplicate(self) -> None:
        requests: list[tuple[str, str]] = []

        def fake_urlopen(request_obj, timeout=120):
            requests.append((request_obj.get_method(), request_obj.full_url))
            if request_obj.get_method() == "GET":
                if "page=1" in request_obj.full_url:
                    return self._response(
                        [
                            {
                                "id": index,
                                "body": f"unrelated comment {index}",
                                "html_url": f"https://github.com/example/issues/17#issuecomment-{index}",
                            }
                            for index in range(1, 101)
                        ]
                    )
                return self._response(
                    [
                        {
                            "id": 222,
                            "body": "<!-- deploywhisper:pr-comment -->\nexisting",
                            "html_url": "https://github.com/deploywhisper/example-repo/issues/17#issuecomment-222",
                        }
                    ]
                )
            return self._response(
                {
                    "id": 222,
                    "html_url": "https://github.com/deploywhisper/example-repo/issues/17#issuecomment-222",
                }
            )

        with patch("action_runtime.request.urlopen", side_effect=fake_urlopen):
            result = action_runtime.upsert_pr_comment(
                self._context(),
                "<!-- deploywhisper:pr-comment -->\nnew body",
                github_token="ghs_test",
            )

        self.assertEqual(result["id"], 222)
        get_urls = [url for method, url in requests if method == "GET"]
        self.assertTrue(any("page=1" in url for url in get_urls))
        self.assertTrue(any("page=2" in url for url in get_urls))
        self.assertEqual(requests[-1][0], "PATCH")


class RunActionCommentTests(unittest.TestCase):
    def test_run_action_writes_comment_outputs_when_pull_request_comment_is_posted(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            output_path = repo_root / "github-output.txt"
            summary_path = repo_root / "step-summary.md"
            args = argparse.Namespace(
                api_url="https://deploywhisper.example.com",
                api_token="",
                changed_files="plan.tf",
                working_directory=str(repo_root),
            )
            analysis_payload = {
                "meta": {"accepted_artifact_count": 1},
                "data": {
                    "persisted_report": {"id": 42},
                    "share_summary": {
                        "severity": "high",
                        "recommendation": "no-go",
                        "markdown": "### DeployWhisper HIGH · NO-GO",
                        "json_payload": {
                            "verdict_banner": "DeployWhisper HIGH · NO-GO",
                            "headline": "NO-GO: widened ingress.",
                            "top_findings": [
                                {
                                    "title": "Security group widened ingress",
                                    "severity": "high",
                                    "evidence_count": 1,
                                    "confidence": 0.92,
                                }
                            ],
                            "evidence_count": 1,
                            "blast_radius_summary": "1 direct / 1 transitive",
                            "rollback_summary": "3/5 MEDIUM · First step: revert the security group rule",
                            "context_completeness": {
                                "score": 0.88,
                                "label": "STRONG CONTEXT",
                                "summary": "STRONG CONTEXT (0.88) - supporting topology and parser coverage look healthy.",
                            },
                            "report_link": "https://deploywhisper.example.com/history?report_id=42",
                            "rollback_link": "https://deploywhisper.example.com/history?report_id=42",
                            "advisory_summary": "This result requires additional human review before release.",
                        },
                    },
                },
            }
            environ = {
                "GITHUB_OUTPUT": str(output_path),
                "GITHUB_STEP_SUMMARY": str(summary_path),
                "GITHUB_TOKEN": "ghs_test",
            }
            context = {
                "event_name": "pull_request",
                "repository": "deploywhisper/example-repo",
                "pull_request_number": 17,
                "head_sha": "abcdef1234567890",
            }

            with (
                patch(
                    "action_runtime.select_artifacts_for_upload",
                    return_value=([("plan.tf", b"resource")], []),
                ),
                patch(
                    "action_runtime.submit_analysis",
                    return_value=analysis_payload,
                ),
                patch(
                    "action_runtime.load_github_context",
                    return_value=context,
                ),
                patch(
                    "action_runtime.upsert_pr_comment",
                    return_value={
                        "id": 777,
                        "html_url": "https://github.com/deploywhisper/example-repo/issues/17#issuecomment-777",
                        "updated": False,
                    },
                ),
            ):
                exit_code = action_runtime.run_action(args, environ=environ)

            self.assertEqual(exit_code, 0)
            output = output_path.read_text(encoding="utf-8")
            self.assertIn("comment-id=777", output)
            self.assertIn("comment-updated=false", output)
            self.assertIn(
                "comment-url=https://github.com/deploywhisper/example-repo/issues/17#issuecomment-777",
                output,
            )

    def test_run_action_keeps_report_successful_when_comment_publish_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_root = Path(tmpdir)
            output_path = repo_root / "github-output.txt"
            summary_path = repo_root / "step-summary.md"
            args = argparse.Namespace(
                api_url="https://deploywhisper.example.com",
                api_token="",
                changed_files="plan.tf",
                working_directory=str(repo_root),
            )
            analysis_payload = {
                "meta": {"accepted_artifact_count": 1},
                "data": {
                    "persisted_report": {"id": 42},
                    "share_summary": {
                        "severity": "high",
                        "recommendation": "no-go",
                        "markdown": "### DeployWhisper HIGH · NO-GO",
                        "json_payload": {
                            "verdict_banner": "DeployWhisper HIGH · NO-GO",
                            "headline": "NO-GO: widened ingress.",
                            "top_findings": [],
                            "evidence_count": 1,
                            "blast_radius_summary": "1 direct / 1 transitive",
                            "rollback_summary": "3/5 MEDIUM · First step: revert the security group rule",
                            "context_completeness": {
                                "score": 0.88,
                                "label": "STRONG CONTEXT",
                                "summary": "STRONG CONTEXT (0.88) - supporting topology and parser coverage look healthy.",
                            },
                            "report_link": "https://deploywhisper.example.com/history?report_id=42",
                            "rollback_link": "https://deploywhisper.example.com/history?report_id=42",
                            "advisory_summary": "This result requires additional human review before release.",
                        },
                    },
                },
            }
            context = {
                "event_name": "pull_request",
                "repository": "deploywhisper/example-repo",
                "pull_request_number": 17,
                "head_sha": "abcdef1234567890",
            }
            environ = {
                "GITHUB_OUTPUT": str(output_path),
                "GITHUB_STEP_SUMMARY": str(summary_path),
                "GITHUB_TOKEN": "ghs_test",
            }

            with (
                patch(
                    "action_runtime.select_artifacts_for_upload",
                    return_value=([("plan.tf", b"resource")], []),
                ),
                patch(
                    "action_runtime.submit_analysis",
                    return_value=analysis_payload,
                ),
                patch(
                    "action_runtime.load_github_context",
                    return_value=context,
                ),
                patch(
                    "action_runtime.upsert_pr_comment",
                    side_effect=action_runtime.ActionRuntimeError("permission denied"),
                ),
            ):
                exit_code = action_runtime.run_action(args, environ=environ)

            self.assertEqual(exit_code, 0)
            output = output_path.read_text(encoding="utf-8")
            self.assertIn("created=true", output)
            self.assertNotIn("comment-id=", output)
            summary = summary_path.read_text(encoding="utf-8")
            self.assertIn("PR comment not published", summary)
            self.assertIn("permission denied", summary)


if __name__ == "__main__":
    unittest.main()
