"""Conformance tests for all built-in and third-party ActionAdapter implementations."""

from typing import Any, Dict, Set

from tempus_ddb import (
    GitHubActionAdapter,
    HttpActionAdapter,
    PaymentActionAdapter,
    SlackActionAdapter,
)
from tempus_ddb.executor_runtime import ExecutionResult
from tempus_ddb.testing import AdapterConformanceHarness


class MockGitHubTransport:
    def request(self, method, url, headers, payload):
        return {
            "id": 1234,
            "number": 99,
            "html_url": "https://github.com/acme/repo/issues/99",
        }


class MockHttpTransport:
    def request(self, method, url, headers, payload):
        return {"status": "ok", "delivered": True}


class MockSlackTransport:
    def request(self, endpoint, token, payload):
        return {
            "ok": True,
            "ts": "1234567890.000100",
            "message": {"text": payload.get("text")},
        }


class CustomDatabaseAdapter:
    """Example third-party adapter showing how to build secure DB executors in < 30 lines."""

    SUPPORTED_ACTIONS: Set[str] = {"db:insert_user", "db:update_status"}

    @property
    def supported_actions(self) -> Set[str]:
        return self.SUPPORTED_ACTIONS

    def execute_action(self, intent: Dict[str, Any]) -> ExecutionResult:
        # Mock database query execution
        query_input = intent.get("input", {})
        return ExecutionResult(
            status="SUCCEEDED",
            payload={"rows_affected": 1, "query_echo": query_input},
        )


def test_github_adapter_conformance():
    harness = AdapterConformanceHarness(
        adapter_factory=lambda: GitHubActionAdapter(
            token="ghp_mock_token_12345",
            transport=MockGitHubTransport(),
        ),
        valid_action_type="github.create_issue",
        valid_resource="acme/widget-repo",
        valid_input={"title": "Test Conformance Issue", "body": "Testing"},
    )
    harness.run_all_checks()


def test_http_adapter_conformance():
    harness = AdapterConformanceHarness(
        adapter_factory=lambda: HttpActionAdapter(
            auth_header="Bearer secret_token",
            allowed_domains={"api.example.com"},
            transport=MockHttpTransport(),
        ),
        valid_action_type="http.post",
        valid_resource="https://api.example.com/webhook",
        valid_input={"event": "user.signup", "id": 42},
    )
    harness.run_all_checks()


def test_slack_adapter_conformance():
    harness = AdapterConformanceHarness(
        adapter_factory=lambda: SlackActionAdapter(
            token="xoxb-mock-token",
            transport=MockSlackTransport(),
        ),
        valid_action_type="slack.post_message",
        valid_resource="#security-alerts",
        valid_input={"text": "System operational"},
    )
    harness.run_all_checks()


def test_payment_adapter_conformance():
    harness = AdapterConformanceHarness(
        adapter_factory=lambda: PaymentActionAdapter(
            secret_key="sk_live_isolated_secret",
        ),
        valid_action_type="finance.disburse",
        valid_resource="res://treasury/main",
        valid_input={"invoice_id": "inv_9981"},
        valid_money={"amount": "10000", "asset": "USD", "beneficiary": "vendor_corp"},
    )
    harness.run_all_checks()


def test_custom_database_adapter_conformance():
    harness = AdapterConformanceHarness(
        adapter_factory=lambda: CustomDatabaseAdapter(),
        valid_action_type="db:insert_user",
        valid_resource="db://users_table",
        valid_input={"username": "alice", "role": "admin"},
    )
    harness.run_all_checks()
