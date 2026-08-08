import json
import pathlib
import tempfile
import unittest
import urllib.parse

import oidf_vc_runner
from oidf_api import OIDFClient


class OIDFVCRunnerTest(unittest.TestCase):
    def test_create_plan_uses_suite_api_shape(self) -> None:
        client = OIDFClient("https://suite.example", "token")
        captured: dict[str, object] = {}

        def request(method: str, path: str, body: object = None) -> object:
            captured.update(method=method, path=path, body=body)
            return {"id": "plan-1"}

        client.request = request  # type: ignore[method-assign]
        plan_id = client.create_plan(
            "oid4vci-1_0-issuer-test-plan",
            "protocolsoup",
            {"client_auth_type": "private_key_jwt", "fapi_profile": "vci"},
            {"vci": {"credential_issuer_url": "https://issuer.example"}},
            "ProtocolSoup issuer",
        )

        self.assertEqual("plan-1", plan_id)
        self.assertEqual("POST", captured["method"])
        parsed = urllib.parse.urlparse(str(captured["path"]))
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(["oid4vci-1_0-issuer-test-plan"], query["planName"])
        self.assertEqual(
            {"client_auth_type": "private_key_jwt", "fapi_profile": "vci"},
            json.loads(query["variant"][0]),
        )
        self.assertEqual(
            {
                "vci": {"credential_issuer_url": "https://issuer.example"},
                "alias": "protocolsoup",
                "description": "ProtocolSoup issuer",
            },
            captured["body"],
        )

    def test_manifest_requires_pinned_suite_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.json"
            path.write_text(
                json.dumps(
                    {
                        "suite_release": oidf_vc_runner.SUITE_RELEASE,
                        "suite_commit": "0" * 40,
                        "plans": [
                            {
                                "plan_name": "oid4vp-1final-verifier-test-plan",
                                "alias": "protocolsoup",
                                "variant": {},
                                "config": {},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "suite_commit"):
                oidf_vc_runner.load_manifest(path)

    def test_manifest_rejects_unpinned_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.json"
            path.write_text(
                json.dumps(
                    {
                        "suite_release": oidf_vc_runner.SUITE_RELEASE,
                        "suite_commit": oidf_vc_runner.SUITE_COMMIT,
                        "plans": [
                            {
                                "plan_name": "future-plan",
                                "alias": "protocolsoup",
                                "variant": {},
                                "config": {},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unpinned plan"):
                oidf_vc_runner.load_manifest(path)

    def test_redact_removes_nested_private_material(self) -> None:
        redacted = oidf_vc_runner.redact(
            {
                "client": {
                    "client_secret": "secret",
                    "jwks": {"keys": [{"kty": "EC", "d": "private", "x": "public"}]},
                }
            }
        )
        self.assertEqual(redacted["client"]["client_secret"], "[REDACTED]")
        self.assertEqual(
            redacted["client"]["jwks"]["keys"][0]["d"],
            "[REDACTED]",
        )
        self.assertEqual(redacted["client"]["jwks"]["keys"][0]["x"], "public")

    def test_parse_deployment_urls_requires_unique_role_url_pairs(self) -> None:
        self.assertEqual(
            oidf_vc_runner.parse_deployment_urls(
                [
                    "issuer=https://protocolsoup.com",
                    "wallet=https://wallet.protocolsoup.com",
                ]
            ),
            {
                "issuer": "https://protocolsoup.com",
                "wallet": "https://wallet.protocolsoup.com",
            },
        )
        with self.assertRaisesRegex(ValueError, "role=https://host"):
            oidf_vc_runner.parse_deployment_urls(["https://protocolsoup.com"])
        with self.assertRaisesRegex(ValueError, "repeated"):
            oidf_vc_runner.parse_deployment_urls(
                ["issuer=https://one.example", "issuer=https://two.example"]
            )

    def test_condition_failures_extracts_failed_conditions(self) -> None:
        failed = oidf_vc_runner.condition_failures(
            [
                {"type": "CONDITION", "result": True, "message": "passed"},
                {"type": "CONDITION", "result": False, "message": "failed"},
                {"status": "FAILURE", "message": "module failed"},
            ]
        )
        self.assertEqual(len(failed), 2)

    def test_parse_target_commit_requires_full_sha(self) -> None:
        self.assertEqual(
            oidf_vc_runner.parse_target_commit("A" * 40),
            "a" * 40,
        )
        with self.assertRaisesRegex(ValueError, "40-character"):
            oidf_vc_runner.parse_target_commit("abc123")

    def test_wait_for_modules_requires_passing_terminal_result(self) -> None:
        class Client:
            def __init__(self, result: str) -> None:
                self.result = result

            def module_info(self, module_id: str) -> dict[str, str]:
                return {
                    "id": module_id,
                    "status": "FINISHED",
                    "result": self.result,
                }

        completed = oidf_vc_runner.wait_for_modules(Client("PASSED"), ["one"], 1, 1)
        self.assertEqual(completed["one"]["result"], "PASSED")
        with self.assertRaisesRegex(RuntimeError, "did not all pass"):
            oidf_vc_runner.wait_for_modules(Client("FAILED"), ["one"], 1, 1)


if __name__ == "__main__":
    unittest.main()
