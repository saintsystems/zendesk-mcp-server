import unittest
from unittest.mock import call, patch

from zendesk_mcp_server.zendesk_client import ZendeskClient


class FakeResponse:
    def __init__(self, status_code=200, headers=None, content=b""):
        self.status_code = status_code
        self.headers = headers or {}
        self._content = content

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size):
        yield self._content


class AttachmentSecurityTests(unittest.TestCase):
    def setUp(self):
        self.client = object.__new__(ZendeskClient)
        self.client.subdomain = "saintsystems"
        self.client.auth_header = "Basic secret"

    @patch("zendesk_mcp_server.zendesk_client._requests.get")
    def test_rejects_arbitrary_initial_host_without_sending_credentials(self, get):
        with self.assertRaisesRegex(ValueError, "configured Zendesk host"):
            self.client.get_ticket_attachment("https://attacker.example/steal")
        get.assert_not_called()

    @patch("zendesk_mcp_server.zendesk_client._requests.get")
    def test_rejects_non_https_url(self, get):
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            self.client.get_ticket_attachment(
                "http://saintsystems.zendesk.com/api/v2/attachments/1"
            )
        get.assert_not_called()

    @patch("zendesk_mcp_server.zendesk_client._requests.get")
    def test_rejects_redirect_to_untrusted_host(self, get):
        get.return_value = FakeResponse(
            status_code=302,
            headers={"Location": "https://attacker.example/steal"},
        )
        with self.assertRaisesRegex(ValueError, "not a trusted Zendesk host"):
            self.client.get_ticket_attachment(
                "https://saintsystems.zendesk.com/api/v2/attachments/1"
            )
        self.assertEqual(get.call_count, 1)

    @patch("zendesk_mcp_server.zendesk_client._requests.get")
    def test_authenticates_tenant_but_not_zendesk_cdn(self, get):
        png = b"\x89PNG\r\n\x1a\ncontent"
        get.side_effect = [
            FakeResponse(
                status_code=302,
                headers={"Location": "https://files.zdusercontent.com/attachment/1"},
            ),
            FakeResponse(
                headers={"Content-Type": "image/png"},
                content=png,
            ),
        ]

        result = self.client.get_ticket_attachment(
            "https://saintsystems.zendesk.com/api/v2/attachments/1"
        )

        self.assertEqual(result["content_type"], "image/png")
        self.assertEqual(
            get.call_args_list,
            [
                call(
                    "https://saintsystems.zendesk.com/api/v2/attachments/1",
                    headers={"Authorization": "Basic secret"},
                    timeout=30,
                    stream=True,
                    allow_redirects=False,
                ),
                call(
                    "https://files.zdusercontent.com/attachment/1",
                    headers={},
                    timeout=30,
                    stream=True,
                    allow_redirects=False,
                ),
            ],
        )


if __name__ == "__main__":
    unittest.main()