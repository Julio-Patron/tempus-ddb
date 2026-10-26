import json
import time

import pytest
from tempus_ddb import (
    GitHubExecutorAdapter,
    TempusDDB,
    TempusExecutor,
    UnknownExecutionError,
    gen_keys,
)
from tempus_ddb.github_executor import GitHubExecutorError


class FakeGitHubTransport:
    def __init__(self, response=None, failure=None):
        self.response = response or {
            "id": 991,
            "number": 42,
            "html_url": "https://github.test/acme/widget/issues/42",
            "state": "open",
        }
        self.failure = failure
        self.calls = []

    def request(self, method, url, headers, payload):
        self.calls.append((method, url, headers, payload))
        if self.failure:
            raise self.failure
        if headers.get("Authorization") != "Bearer executor-only-token":
            raise PermissionError("downstream credential missing")
        return self.response


@pytest.fixture
def execution_environment(tmp_path):
    gate_keyfile = tmp_path / "gate.keys.json"
    agent_keyfile = tmp_path / "agent.keys.json"
    executor_keyfile = tmp_path / "executor.keys.json"
    for keyfile in (gate_keyfile, agent_keyfile, executor_keyfile):
        gen_keys(str(keyfile))

    gate = TempusDDB(str(tmp_path / "gate.db"), str(gate_keyfile))
    gate_id = json.loads(gate_keyfile.read_text())["public_key"]
    agent_id = json.loads(agent_keyfile.read_text())["public_key"]
    executor_id = json.loads(executor_keyfile.read_text())["public_key"]
    gate.register_agent(gate_id, "tempus-gate", '{"can_delegate":true}')
    gate.install_allow_all_dev_policy()  # explicit dev opt-in (default is deny-all)
    gate.register_agent(agent_id, "coding-agent", "{}")
    gate.register_agent(executor_id, "github-executor", "{}")

    return {
        "tmp_path": tmp_path,
        "gate": gate,
        "gate_id": gate_id,
        "agent_id": agent_id,
        "agent_keyfile": agent_keyfile,
        "executor_keyfile": executor_keyfile,
    }


def issue_permit(
    environment, idempotency_key, action_type, action_input, resource="acme/widget"
):
    intent = json.dumps(
        {
            "schema_version": "tempus.action-intent.v1",
            "tenant_id": "github-test",
            "agent_id": environment["agent_id"],
            "idempotency_key": idempotency_key,
            "action_type": action_type,
            "resource": resource,
            "requested_at": time.time_ns() // 1_000,
            "input": action_input,
        }
    )
    return json.loads(
        environment["gate"].request_action(
            intent,
            str(environment["agent_keyfile"]),
            60,
        )
    )


def build_adapter(environment, transport):
    return GitHubExecutorAdapter(
        str(environment["tmp_path"] / "executor.db"),
        str(environment["executor_keyfile"]),
        environment["gate_id"],
        "github-test",
        token="executor-only-token",
        api_url="https://api.github.test",
        transport=transport,
        executor_pool_size=2,
    )


@pytest.mark.parametrize(
    "api_url",
    [
        "http://api.github.test",
        "https://executor:token@api.github.test",
        "https://api.github.test?redirect=https://attacker.test",
    ],
    ids=["plaintext", "embedded-credentials", "query-string"],
)
def test_github_executor_rejects_unsafe_api_urls(execution_environment, api_url):
    with pytest.raises(GitHubExecutorError, match="absolute HTTPS endpoint"):
        GitHubExecutorAdapter(
            str(execution_environment["tmp_path"] / "unsafe-executor.db"),
            str(execution_environment["executor_keyfile"]),
            execution_environment["gate_id"],
            "github-test",
            token="executor-only-token",
            api_url=api_url,
        )


def test_executor_pool_size_must_be_positive(execution_environment):
    with pytest.raises(RuntimeError, match="pool size must be greater than zero"):
        TempusExecutor(
            str(execution_environment["tmp_path"] / "invalid-pool.db"),
            str(execution_environment["executor_keyfile"]),
            execution_environment["gate_id"],
            "github-test",
            0,
        )


def test_github_issue_executes_exact_signed_arguments_and_replay_is_blocked(
    execution_environment,
):
    permit = issue_permit(
        execution_environment,
        "issue-001",
        "github.create_issue",
        {"title": "Guarded issue", "body": "Created by an agent", "labels": ["ai"]},
    )
    transport = FakeGitHubTransport()
    adapter = build_adapter(execution_environment, transport)

    outcome = json.loads(adapter.execute(json.dumps(permit)))
    assert outcome["status"] == "SUCCEEDED"
    assert outcome["output"]["number"] == 42
    assert len(transport.calls) == 1
    method, url, headers, payload = transport.calls[0]
    assert method == "POST"
    assert url == "https://api.github.test/repos/acme/widget/issues"
    assert headers["Authorization"] == "Bearer executor-only-token"
    assert payload == {
        "title": "Guarded issue",
        "body": "Created by an agent",
        "labels": ["ai"],
    }

    authorization = permit["authorization"]
    state = json.loads(adapter.get_execution_state(authorization["authorization_id"]))
    assert state["status"] == "SUCCEEDED"
    assert state["observation"]["status"] == "SUCCEEDED"
    assert state["observation"]["executor_signature"]

    receipt = json.loads(
        execution_environment["gate"].commit_outcome_signed(
            authorization["authorization_id"],
            json.dumps(outcome),
        )
    )
    verification = json.loads(
        execution_environment["gate"].verify_trace(authorization["action_id"])
    )
    assert receipt["receipt"]["status"] == "SUCCEEDED"
    assert verification["status"] == "VERIFIED"

    with pytest.raises(PermissionError, match="already consumed"):
        adapter.execute(json.dumps(permit))
    assert len(transport.calls) == 1


def test_unsupported_or_extra_arguments_fail_before_github(execution_environment):
    permit = issue_permit(
        execution_environment,
        "merge-001",
        "github.merge_pull_request",
        {"pull_number": 7},
    )
    transport = FakeGitHubTransport()
    adapter = build_adapter(execution_environment, transport)

    outcome = json.loads(adapter.execute(json.dumps(permit)))
    assert outcome["status"] == "FAILED"
    assert outcome["output"]["error_code"] == "TEMPUS_GITHUB_BINDING_REJECTED"
    assert transport.calls == []

    state = json.loads(
        adapter.get_execution_state(permit["authorization"]["authorization_id"])
    )
    assert state["status"] == "FAILED"
    assert state["observation"]["status"] == "FAILED"

    extra_field_permit = issue_permit(
        execution_environment,
        "issue-extra-001",
        "github.create_issue",
        {"title": "Unsafe", "authorization": "smuggled-secret"},
    )
    extra_outcome = json.loads(adapter.execute(json.dumps(extra_field_permit)))
    assert extra_outcome["status"] == "FAILED"
    assert transport.calls == []


def test_ambiguous_transport_failure_becomes_unknown_and_never_replays(
    execution_environment,
):
    permit = issue_permit(
        execution_environment,
        "issue-timeout-001",
        "github.create_issue",
        {"title": "May have been created"},
    )
    transport = FakeGitHubTransport(failure=TimeoutError("socket timed out"))
    adapter = build_adapter(execution_environment, transport)

    with pytest.raises(UnknownExecutionError) as error_info:
        adapter.execute(json.dumps(permit))
    observation = json.loads(error_info.value.observation)
    assert observation["status"] == "UNKNOWN"
    assert observation["executor_signature"]

    authorization_id = permit["authorization"]["authorization_id"]
    state = json.loads(adapter.get_execution_state(authorization_id))
    assert state["status"] == "UNKNOWN"
    with pytest.raises(PermissionError, match="already consumed"):
        adapter.execute(json.dumps(permit))
    assert len(transport.calls) == 1


def test_crash_recovery_marks_started_execution_unknown_without_effect(
    execution_environment,
):
    permit = issue_permit(
        execution_environment,
        "issue-recovery-001",
        "github.create_issue",
        {"title": "Recover me"},
    )
    executor_db = execution_environment["tmp_path"] / "recovery-executor.db"
    executor = TempusExecutor(
        str(executor_db),
        str(execution_environment["executor_keyfile"]),
        execution_environment["gate_id"],
        "github-test",
    )
    executor.verify_and_consume_permit(json.dumps(permit))
    authorization_id = permit["authorization"]["authorization_id"]
    started = json.loads(executor.get_execution_state(authorization_id))
    assert started["status"] == "STARTED"
    assert started["observation"]["status"] == "STARTED"

    restarted = TempusExecutor(
        str(executor_db),
        str(execution_environment["executor_keyfile"]),
        execution_environment["gate_id"],
        "github-test",
    )
    recovered = json.loads(restarted.recover_incomplete(0))
    assert len(recovered) == 1
    assert recovered[0]["status"] == "UNKNOWN"
    assert recovered[0]["details"]["reason"] == "EXECUTOR_RECOVERY_TIMEOUT"
    assert recovered[0]["executor_signature"]

    unknown = json.loads(restarted.get_execution_state(authorization_id))
    assert unknown["status"] == "UNKNOWN"
    with pytest.raises(PermissionError, match="already consumed"):
        restarted.verify_and_consume_permit(json.dumps(permit))
