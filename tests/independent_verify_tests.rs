//! Independent verification: the verifier pins the gate public key out of band
//! and never trusts the root of trust stored in the database being verified.

use _tempus_ddb::{generate_keypair, verify_checkpoint, verify_receipt, SqliteStorage};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn public_key(path: &Path) -> String {
    let value: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    value["public_key"].as_str().unwrap().to_string()
}

fn parse(value: &str) -> Value {
    serde_json::from_str(value).unwrap()
}

struct World {
    _temp: tempfile::TempDir,
    storage: SqliteStorage,
    gate_id: String,
    executor_id: String,
    action_id: String,
    permit: Value,
    outcome: Value,
    trace: Value,
}

fn keyfile(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    generate_keypair(path.to_str().unwrap()).unwrap();
    path
}

/// A complete gate: its own gate/agent/executor keys, a permissive dev policy,
/// one purchase of `amount` USD, authorized and executed.
fn world(amount: &str) -> World {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let gate_key = keyfile(dir, "gate.keys.json");
    let agent_key = keyfile(dir, "agent.keys.json");
    let executor_key = keyfile(dir, "executor.keys.json");
    let (gate_id, agent_id, executor_id) = (
        public_key(&gate_key),
        public_key(&agent_key),
        public_key(&executor_key),
    );
    let storage = SqliteStorage::new(
        dir.join("tempus.db").to_str().unwrap().to_string(),
        gate_key.to_str().unwrap().to_string(),
    )
    .unwrap();
    storage
        .register_agent(&gate_id, "gate", r#"{"can_delegate":true}"#)
        .unwrap();
    storage.install_allow_all_dev_policy().unwrap();
    storage.register_agent(&agent_id, "agent", "{}").unwrap();
    storage
        .register_agent(&executor_id, "executor", "{}")
        .unwrap();
    let requested_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let intent = json!({
        "schema_version": "tempus.action-intent.v1",
        "tenant_id": "acme",
        "agent_id": agent_id,
        "idempotency_key": "pay-1",
        "action_type": "purchase",
        "resource": "vendor-api/credits",
        "requested_at": requested_at,
        "input": {"sku": "compute-credits"},
        "money": {"amount": amount, "asset": "USD", "beneficiary": "vendor-42"}
    });
    let permit = parse(
        &storage
            .request_action(&intent.to_string(), agent_key.to_str().unwrap(), 60)
            .unwrap(),
    );
    assert_eq!(permit["authorization"]["decision"], "ALLOWED");
    let authorization_id = permit["authorization"]["authorization_id"]
        .as_str()
        .unwrap()
        .to_string();
    let action_id = permit["authorization"]["action_id"]
        .as_str()
        .unwrap()
        .to_string();
    let outcome = parse(
        &storage
            .commit_outcome(
                &authorization_id,
                &json!({
                    "schema_version": "tempus.action-outcome.v1",
                    "authorization_id": authorization_id,
                    "action_id": action_id,
                    "status": "SUCCEEDED",
                    "external_reference": "vendor-tx-1",
                })
                .to_string(),
                executor_key.to_str().unwrap(),
            )
            .unwrap(),
    );
    let trace = parse(&storage.get_trace(&action_id).unwrap());
    World {
        _temp: temp,
        storage,
        gate_id,
        executor_id,
        action_id,
        permit,
        outcome,
        trace,
    }
}

fn check(receipt: &Value, gate: &str, executors: &[String]) -> Value {
    parse(&verify_receipt(&receipt.to_string(), gate, executors).unwrap())
}

fn has_error(result: &Value, code: &str) -> bool {
    result["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error == code)
}

#[test]
fn valid_receipts_verify_with_the_pinned_gate_key_and_no_database() {
    let w = world("25.00");
    for (receipt, kind) in [
        (&w.trace, "trace"),
        (&w.permit, "authorization"),
        (&w.outcome, "execution"),
    ] {
        let result = check(receipt, &w.gate_id, &[]);
        assert_eq!(result["status"], "VERIFIED", "{kind}: {result}");
        assert_eq!(result["kind"], kind);
        assert_eq!(result["trust"]["mode"], "PINNED_GATE_KEY");
        assert_eq!(result["trust"]["independent"], true);
    }
    // Pinning the executor as well still verifies.
    let result = check(&w.trace, &w.gate_id, std::slice::from_ref(&w.executor_id));
    assert_eq!(result["status"], "VERIFIED", "{result}");
    assert_eq!(result["trust"]["executor_keys_pinned"], 1);
    // Upper-case hex of the pinned key is accepted.
    let result = check(&w.trace, &w.gate_id.to_uppercase(), &[]);
    assert_eq!(result["status"], "VERIFIED", "{result}");
    // The standalone outcome says what it could not link.
    let outcome = check(&w.outcome, &w.gate_id, &[]);
    let not_checked = outcome["trust"]["not_checked"].to_string();
    assert!(not_checked.contains("PERMIT_LINKAGE"), "{not_checked}");
}

#[test]
fn pinned_database_trace_verification_matches_the_standalone_verifier() {
    let w = world("25.00");
    let result = parse(
        &w.storage
            .verify_trace_pinned(&w.action_id, &w.gate_id, &[])
            .unwrap(),
    );
    assert_eq!(result["status"], "VERIFIED", "{result}");
    assert_eq!(result["trust"]["independent"], true);
}

#[test]
fn legacy_database_verification_is_marked_not_independent() {
    let w = world("25.00");
    let result = parse(&w.storage.verify_trace(&w.action_id).unwrap());
    assert_eq!(result["status"], "VERIFIED");
    assert_eq!(result["trust"]["independent"], false);
    assert_eq!(result["trust"]["mode"], "DATABASE_SELF_ATTESTED");
}

#[test]
fn fully_forged_database_verifies_against_itself_but_not_against_the_real_gate_key() {
    let real = world("25.00");
    // The attacker builds a complete, internally consistent gate with its own
    // keys and a fake $9,999 payment.
    let forged = world("9999.00");
    assert_ne!(real.gate_id, forged.gate_id);

    // Old behaviour: the forged DB is VERIFIED because it vouches for itself.
    let self_attested = parse(&forged.storage.verify_trace(&forged.action_id).unwrap());
    assert_eq!(self_attested["status"], "VERIFIED");
    assert_eq!(self_attested["trust"]["independent"], false);

    // With the real gate key pinned, the same forged evidence is INVALID.
    let pinned_db = parse(
        &forged
            .storage
            .verify_trace_pinned(&forged.action_id, &real.gate_id, &[])
            .unwrap(),
    );
    assert_eq!(pinned_db["status"], "INVALID", "{pinned_db}");
    assert!(has_error(&pinned_db, "GATE_KEY_NOT_PINNED"));
    let pinned_doc = check(&forged.trace, &real.gate_id, &[]);
    assert_eq!(pinned_doc["status"], "INVALID", "{pinned_doc}");
    assert!(has_error(&pinned_doc, "GATE_KEY_NOT_PINNED"));
    assert!(has_error(&pinned_doc, "EXECUTION_GATE_KEY_NOT_PINNED"));
}

#[test]
fn forger_cannot_relabel_a_forged_receipt_with_the_real_gate_id() {
    let real = world("25.00");
    let forged = world("9999.00");
    let text = forged
        .trace
        .to_string()
        .replace(&forged.gate_id, &real.gate_id);
    let result = parse(&verify_receipt(&text, &real.gate_id, &[]).unwrap());
    assert_eq!(result["status"], "INVALID", "{result}");
}

#[test]
fn wrong_gate_public_key_is_invalid() {
    let w = world("25.00");
    let other = world("1.00");
    for receipt in [&w.trace, &w.permit, &w.outcome] {
        let result = check(receipt, &other.gate_id, &[]);
        assert_eq!(result["status"], "INVALID", "{result}");
    }
    assert!(verify_receipt(&w.trace.to_string(), "not-hex", &[]).is_err());
    assert!(verify_receipt(&w.trace.to_string(), "abcd", &[]).is_err());
}

#[test]
fn wrong_executor_public_key_is_invalid() {
    let w = world("25.00");
    let other = world("1.00");
    let result = check(
        &w.trace,
        &w.gate_id,
        std::slice::from_ref(&other.executor_id),
    );
    assert_eq!(result["status"], "INVALID", "{result}");
    assert!(has_error(&result, "EXECUTOR_KEY_NOT_PINNED"));
}

#[test]
fn tampered_receipts_are_invalid() {
    let w = world("25.00");
    for path in [
        "/authorization/intent/money/amount",
        "/authorization/authorization/decision",
        "/authorization/authorization/expires_at",
        "/execution/outcome/status",
        "/execution/outcome/external_reference",
        "/execution/receipt/status",
        "/execution/receipt/gate_signature",
    ] {
        assert!(
            w.trace.pointer(path).is_some(),
            "trace shape changed: {path}"
        );
    }
    let mutations: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        (
            "amount in the signed intent",
            Box::new(|v| v["authorization"]["intent"]["money"]["amount"] = json!("9999.00")),
        ),
        (
            "decision flipped",
            Box::new(|v| v["authorization"]["authorization"]["decision"] = json!("BLOCKED")),
        ),
        (
            "permit expiry extended",
            Box::new(|v| v["authorization"]["authorization"]["expires_at"] = json!(u64::MAX / 4)),
        ),
        (
            "outcome status",
            Box::new(|v| v["execution"]["outcome"]["status"] = json!("FAILED")),
        ),
        (
            "outcome reference",
            Box::new(|v| v["execution"]["outcome"]["external_reference"] = json!("tx-forged")),
        ),
        (
            "receipt status",
            Box::new(|v| v["execution"]["receipt"]["status"] = json!("FAILED")),
        ),
        (
            "gate signature",
            Box::new(|v| {
                let sig = v["execution"]["receipt"]["gate_signature"]
                    .as_str()
                    .unwrap()
                    .to_string();
                let flipped = if sig.starts_with('0') { "1" } else { "0" };
                v["execution"]["receipt"]["gate_signature"] =
                    json!(format!("{flipped}{}", &sig[1..]));
            }),
        ),
    ];
    for (label, mutate) in mutations {
        let mut trace = w.trace.clone();
        mutate(&mut trace);
        let result = check(&trace, &w.gate_id, &[]);
        assert_eq!(result["status"], "INVALID", "{label}: {result}");
    }
    // Same for the standalone documents.
    let mut permit = w.permit.clone();
    permit["intent"]["money"]["amount"] = json!("9999.00");
    assert_eq!(check(&permit, &w.gate_id, &[])["status"], "INVALID");
    let mut outcome = w.outcome.clone();
    outcome["outcome"]["external_reference"] = json!("tx-forged");
    assert_eq!(check(&outcome, &w.gate_id, &[])["status"], "INVALID");
}

#[test]
fn unknown_or_malformed_receipts_are_errors_not_verified() {
    let w = world("25.00");
    assert!(verify_receipt("{}", &w.gate_id, &[])
        .unwrap_err()
        .contains("TEMPUS_RECEIPT_SCHEMA_UNKNOWN"));
    assert!(verify_receipt("not json", &w.gate_id, &[]).is_err());
    let mut stripped = w.trace.clone();
    stripped["authorization"] = Value::Null;
    assert_eq!(check(&stripped, &w.gate_id, &[])["status"], "INVALID");
}

#[test]
fn checkpoint_verification_requires_the_pinned_public_key() {
    let w = world("25.00");
    let other = world("1.00");
    let checkpoint = w.storage.create_checkpoint("acme").unwrap();
    let stream = w.storage.export_event_stream("acme", 1, 1000).unwrap();
    let ok = parse(&verify_checkpoint(&checkpoint, &stream, &w.gate_id).unwrap());
    assert_eq!(ok["status"], "VERIFIED", "{ok}");
    let wrong = parse(&verify_checkpoint(&checkpoint, &stream, &other.gate_id).unwrap());
    assert_eq!(wrong["status"], "INVALID", "{wrong}");
    assert!(verify_checkpoint(&checkpoint, &stream, "zz").is_err());
}
