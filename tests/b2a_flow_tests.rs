use _tempus_ddb::{generate_keypair, SqliteStorage};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn public_key(path: &Path) -> String {
    let value: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    value["public_key"].as_str().unwrap().to_string()
}

fn parse(value: &str) -> Value {
    serde_json::from_str(value).unwrap()
}

fn intent(agent_id: &str, idempotency_key: &str, resource: &str) -> String {
    let requested_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    json!({
        "schema_version": "tempus.action-intent.v1",
        "tenant_id": "acme",
        "agent_id": agent_id,
        "idempotency_key": idempotency_key,
        "action_type": "purchase",
        "resource": resource,
        "requested_at": requested_at,
        "input": {"sku": "compute-credits"},
        "money": {"amount": "25.00", "asset": "USD", "beneficiary": "vendor-42"}
    })
    .to_string()
}

#[test]
fn b2a_authorize_execute_verify_and_replay_guards() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("tempus.db");
    let gate_keyfile = temp.path().join("gate.keys.json");
    let agent_keyfile = temp.path().join("agent.keys.json");
    let executor_keyfile = temp.path().join("executor.keys.json");
    let other_keyfile = temp.path().join("other.keys.json");
    generate_keypair(gate_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(agent_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(executor_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(other_keyfile.to_str().unwrap()).unwrap();

    let gate_id = public_key(&gate_keyfile);
    let agent_id = public_key(&agent_keyfile);
    let executor_id = public_key(&executor_keyfile);
    let other_id = public_key(&other_keyfile);
    let storage = SqliteStorage::new(
        db_path.to_str().unwrap().to_string(),
        gate_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();

    let root = parse(
        &storage
            .register_agent(&gate_id, "tempus-gate", r#"{"can_delegate":true}"#)
            .unwrap(),
    );
    assert_eq!(root["registration"]["registered_by"], gate_id);
    storage.install_allow_all_dev_policy().unwrap(); // explicit dev opt-in
    assert!(storage.verify_agent(&gate_id).unwrap());
    storage
        .register_agent(&agent_id, "buyer-agent", "{}")
        .unwrap();
    storage
        .register_agent(&executor_id, "purchase-executor", "{}")
        .unwrap();
    assert!(storage.verify_agent(&agent_id).unwrap());
    assert!(storage
        .register_agent(&agent_id, "renamed-agent", "{}")
        .unwrap_err()
        .contains("TEMPUS_AGENT_ALREADY_REGISTERED"));

    let request = intent(&agent_id, "purchase-001", "vendor-api/credits");
    let authorization_json = storage
        .request_action(&request, agent_keyfile.to_str().unwrap(), 60)
        .unwrap();
    let authorization = parse(&authorization_json);
    assert_eq!(
        authorization["schema_version"],
        "tempus.authorization-result.v1"
    );
    assert_eq!(authorization["authorization"]["decision"], "ALLOWED");
    let authorization_id = authorization["authorization"]["authorization_id"]
        .as_str()
        .unwrap();
    let action_id = authorization["authorization"]["action_id"]
        .as_str()
        .unwrap();

    let duplicate = storage
        .request_action(&request, agent_keyfile.to_str().unwrap(), 60)
        .unwrap();
    assert_eq!(
        parse(&duplicate)["authorization"]["authorization_id"],
        authorization_id
    );
    let conflict = intent(&agent_id, "purchase-001", "different-resource");
    assert!(storage
        .request_action(&conflict, agent_keyfile.to_str().unwrap(), 60)
        .unwrap_err()
        .contains("TEMPUS_IDEMPOTENCY_CONFLICT"));

    let outcome = json!({
        "schema_version": "tempus.action-outcome.v1",
        "authorization_id": authorization_id,
        "action_id": action_id,
        "status": "SUCCEEDED",
        "external_reference": "vendor-tx-9182",
        "output": {"credits_added": 1000}
    })
    .to_string();
    let execution_json = storage
        .commit_outcome(
            authorization_id,
            &outcome,
            executor_keyfile.to_str().unwrap(),
        )
        .unwrap();
    let execution = parse(&execution_json);
    assert_eq!(execution["receipt"]["status"], "SUCCEEDED");

    let duplicate_execution = storage
        .commit_outcome(
            authorization_id,
            &outcome,
            executor_keyfile.to_str().unwrap(),
        )
        .unwrap();
    assert_eq!(
        parse(&duplicate_execution)["receipt"]["receipt_id"],
        execution["receipt"]["receipt_id"]
    );
    let conflicting_outcome = json!({
        "schema_version": "tempus.action-outcome.v1",
        "authorization_id": authorization_id,
        "action_id": action_id,
        "status": "FAILED",
        "error": "late conflicting result"
    })
    .to_string();
    assert!(storage
        .commit_outcome(
            authorization_id,
            &conflicting_outcome,
            executor_keyfile.to_str().unwrap(),
        )
        .unwrap_err()
        .contains("TEMPUS_PERMIT_ALREADY_CONSUMED"));

    let verification = parse(&storage.verify_trace(action_id).unwrap());
    assert_eq!(verification["status"], "VERIFIED");
    assert_eq!(verification["phase"], "COMPLETED");
    let trace = parse(&storage.get_trace(action_id).unwrap());
    assert_eq!(trace["execution"]["receipt"]["executor_id"], executor_id);

    let unregistered_intent = intent(&other_id, "unregistered-001", "email/send");
    let blocked = parse(
        &storage
            .request_action(&unregistered_intent, other_keyfile.to_str().unwrap(), 60)
            .unwrap(),
    );
    assert_eq!(blocked["authorization"]["decision"], "BLOCKED");
    let blocked_action = blocked["authorization"]["action_id"].as_str().unwrap();
    let blocked_verification = parse(&storage.verify_trace(blocked_action).unwrap());
    assert_eq!(blocked_verification["status"], "VERIFIED");
    assert_eq!(blocked_verification["phase"], "BLOCKED");

    let stale_intent = json!({
        "schema_version": "tempus.action-intent.v1",
        "tenant_id": "acme",
        "agent_id": agent_id,
        "idempotency_key": "stale-001",
        "action_type": "send_email",
        "resource": "mail/outbox",
        "requested_at": 1,
        "input": {}
    })
    .to_string();
    let stale = parse(
        &storage
            .request_action(&stale_intent, agent_keyfile.to_str().unwrap(), 60)
            .unwrap(),
    );
    assert_eq!(stale["authorization"]["decision"], "BLOCKED");
    assert_eq!(stale["authorization"]["reason_codes"][0], "REQUEST_STALE");

    let invalid_signature_intent = intent(&agent_id, "invalid-signature-001", "mail/outbox");
    let invalid_signature = parse(
        &storage
            .request_action_signed(&invalid_signature_intent, &agent_id, &"00".repeat(64), 60)
            .unwrap(),
    );
    assert_eq!(invalid_signature["authorization"]["decision"], "BLOCKED");
    let invalid_signature_action = invalid_signature["authorization"]["action_id"]
        .as_str()
        .unwrap();
    assert_eq!(
        parse(&storage.verify_trace(invalid_signature_action).unwrap())["status"],
        "VERIFIED"
    );

    let agent_storage = SqliteStorage::new(
        db_path.to_str().unwrap().to_string(),
        agent_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();
    assert!(agent_storage
        .register_agent(&other_id, "unauthorized-delegation", "{}")
        .unwrap_err()
        .contains("TEMPUS_REGISTRAR_NOT_AUTHORIZED"));
}

#[test]
fn trace_verification_detects_receipt_tampering() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("tempus.db");
    let gate_keyfile = temp.path().join("gate.keys.json");
    let agent_keyfile = temp.path().join("agent.keys.json");
    generate_keypair(gate_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(agent_keyfile.to_str().unwrap()).unwrap();
    let gate_id = public_key(&gate_keyfile);
    let agent_id = public_key(&agent_keyfile);
    let storage = SqliteStorage::new(
        db_path.to_str().unwrap().to_string(),
        gate_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();
    storage.register_agent(&gate_id, "gate", "{}").unwrap();
    storage.install_allow_all_dev_policy().unwrap(); // explicit dev opt-in
    storage.register_agent(&agent_id, "agent", "{}").unwrap();
    let authorization = parse(
        &storage
            .request_action(
                &intent(&agent_id, "tamper-001", "calendar/create"),
                agent_keyfile.to_str().unwrap(),
                60,
            )
            .unwrap(),
    );
    let action_id = authorization["authorization"]["action_id"]
        .as_str()
        .unwrap();

    let connection = Connection::open(&db_path).unwrap();
    connection
        .execute(
            "UPDATE action_authorizations
             SET authorization_json = replace(authorization_json, 'POLICY_ALLOWED', 'POLICY_BYPASSED')
             WHERE action_id = ?1",
            [action_id],
        )
        .unwrap();
    let verification = parse(&storage.verify_trace(action_id).unwrap());
    assert_eq!(verification["status"], "INVALID");
    assert!(verification["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|error| error == "AUTHORIZATION_ID_MISMATCH"));
}

#[test]
fn phase2_receipts_remain_historically_verifiable_but_not_consumable() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("migration.db");
    let gate_keyfile = temp.path().join("gate.keys.json");
    let agent_keyfile = temp.path().join("agent.keys.json");
    let executor_keyfile = temp.path().join("executor.keys.json");
    generate_keypair(gate_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(agent_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(executor_keyfile.to_str().unwrap()).unwrap();
    let gate_id = public_key(&gate_keyfile);
    let agent_id = public_key(&agent_keyfile);
    let executor_id = public_key(&executor_keyfile);
    let storage = SqliteStorage::new(
        db_path.to_str().unwrap().to_string(),
        gate_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();
    storage.register_agent(&gate_id, "gate", "{}").unwrap();
    storage.install_allow_all_dev_policy().unwrap(); // explicit dev opt-in
    storage.register_agent(&agent_id, "agent", "{}").unwrap();
    storage
        .register_agent(&executor_id, "executor", "{}")
        .unwrap();
    let mut result = parse(
        &storage
            .request_action(
                &intent(&agent_id, "phase2-history", "legacy/resource"),
                agent_keyfile.to_str().unwrap(),
                60,
            )
            .unwrap(),
    );
    let action_id = result["authorization"]["action_id"]
        .as_str()
        .unwrap()
        .to_string();
    let old_authorization_id = result["authorization"]["authorization_id"]
        .as_str()
        .unwrap()
        .to_string();
    result.as_object_mut().unwrap().remove("policy_bundle");
    let authorization = result["authorization"].as_object_mut().unwrap();
    authorization.remove("authorization_id");
    authorization.remove("gate_signature");
    authorization.remove("policy_digest");
    authorization.remove("evidence_digest");
    authorization.remove("executor_constraints");
    authorization.remove("gate_signer");
    authorization.insert(
        "policy_version".to_string(),
        json!("tempus.identity-gate.v1"),
    );
    let authorization_body = serde_json::to_string(&result["authorization"]).unwrap();
    let authorization_id = hex::encode(Sha256::digest(authorization_body.as_bytes()));
    let key_value: Value =
        serde_json::from_str(&std::fs::read_to_string(&gate_keyfile).unwrap()).unwrap();
    let private_bytes: [u8; 32] = hex::decode(key_value["private_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let gate_key = SigningKey::from_bytes(&private_bytes);
    let signature = gate_key.sign(&hex::decode(&authorization_id).unwrap());
    result["authorization"]["authorization_id"] = json!(authorization_id);
    result["authorization"]["gate_signature"] = json!(hex::encode(signature.to_bytes()));
    let legacy_json = serde_json::to_string(&result).unwrap();
    let connection = Connection::open(&db_path).unwrap();
    connection
        .execute(
            "UPDATE action_authorizations
             SET authorization_id = ?1, authorization_json = ?2
             WHERE authorization_id = ?3",
            rusqlite::params![authorization_id, legacy_json, old_authorization_id],
        )
        .unwrap();

    let verification = parse(&storage.verify_trace(&action_id).unwrap());
    assert_eq!(verification["status"], "VERIFIED");
    let outcome = json!({
        "schema_version": "tempus.action-outcome.v1",
        "authorization_id": authorization_id,
        "action_id": action_id,
        "status": "SUCCEEDED",
        "output": {}
    })
    .to_string();
    assert!(storage
        .commit_outcome(
            &authorization_id,
            &outcome,
            executor_keyfile.to_str().unwrap()
        )
        .unwrap_err()
        .contains("TEMPUS_POLICY_BUNDLE_MISSING"));
}

#[test]
fn phase3_policy_rotation_and_emergency_revocation_are_enforced() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("phase3.db");
    let gate_keyfile = temp.path().join("gate.keys.json");
    let agent_v1_keyfile = temp.path().join("agent-v1.keys.json");
    let agent_v2_keyfile = temp.path().join("agent-v2.keys.json");
    let executor_keyfile = temp.path().join("executor.keys.json");
    let denied_executor_keyfile = temp.path().join("denied-executor.keys.json");
    for keyfile in [
        &gate_keyfile,
        &agent_v1_keyfile,
        &agent_v2_keyfile,
        &executor_keyfile,
        &denied_executor_keyfile,
    ] {
        generate_keypair(keyfile.to_str().unwrap()).unwrap();
    }
    let gate_id = public_key(&gate_keyfile);
    let agent_v1 = public_key(&agent_v1_keyfile);
    let agent_v2 = public_key(&agent_v2_keyfile);
    let executor_id = public_key(&executor_keyfile);
    let denied_executor_id = public_key(&denied_executor_keyfile);
    let storage = SqliteStorage::new(
        db_path.to_str().unwrap().to_string(),
        gate_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();
    storage
        .register_agent(&gate_id, "gate", r#"{"can_delegate":true}"#)
        .unwrap();
    storage
        .register_agent(&agent_v1, "agent", r#"{"tenant_id":"acme"}"#)
        .unwrap();
    storage
        .register_agent(&executor_id, "executor", r#"{"tenant_id":"acme"}"#)
        .unwrap();
    storage
        .register_agent(
            &denied_executor_id,
            "denied-executor",
            r#"{"tenant_id":"acme"}"#,
        )
        .unwrap();

    let policy = json!({
        "schema_version": "tempus.policy-bundle.v1",
        "policy_version": "acme-github-v1",
        "tenant_id": "acme",
        "constraints": {
            "allowed_action_types": ["purchase"],
            "allowed_resources": ["vendor-api/*"],
            "allowed_executors": [executor_id],
            "max_ttl_seconds": 30,
            "max_input_bytes": 1024,
            "allowed_currencies": ["USD"],
            "max_money_amount_minor": 3000
        }
    });
    let installed = parse(&storage.install_policy(&policy.to_string()).unwrap());
    assert_eq!(installed["policy_version"], "acme-github-v1");
    assert_eq!(installed["signer"]["algorithm"], "Ed25519");

    let ttl_denied = parse(
        &storage
            .request_action(
                &intent(&agent_v1, "phase3-ttl-denied", "vendor-api/credits"),
                agent_v1_keyfile.to_str().unwrap(),
                60,
            )
            .unwrap(),
    );
    assert_eq!(ttl_denied["authorization"]["decision"], "BLOCKED");
    assert_eq!(
        ttl_denied["authorization"]["reason_codes"][0],
        "POLICY_TTL_DENIED"
    );

    let mut money_denied_intent = parse(&intent(
        &agent_v1,
        "phase3-money-denied",
        "vendor-api/credits",
    ));
    money_denied_intent["money"]["amount"] = json!("40.00");
    let money_denied = parse(
        &storage
            .request_action(
                &money_denied_intent.to_string(),
                agent_v1_keyfile.to_str().unwrap(),
                30,
            )
            .unwrap(),
    );
    assert_eq!(money_denied["authorization"]["decision"], "BLOCKED");
    assert_eq!(
        money_denied["authorization"]["reason_codes"][0],
        "POLICY_MONEY_DENIED"
    );

    let mut nondeterministic_intent = parse(&intent(
        &agent_v1,
        "phase3-float-denied",
        "vendor-api/credits",
    ));
    nondeterministic_intent["input"]["ratio"] = json!(1.5);
    // A float in the input can be spelled several ways for one f64, so it is refused when
    // the intent arrives instead of being signed (it no longer yields a signed denial).
    let nondeterministic = storage
        .request_action(
            &nondeterministic_intent.to_string(),
            agent_v1_keyfile.to_str().unwrap(),
            30,
        )
        .unwrap_err();
    assert!(
        nondeterministic.starts_with("NON_EXACT_NUMBER"),
        "{nondeterministic}"
    );

    let mut cross_tenant_intent = parse(&intent(
        &agent_v1,
        "phase3-cross-tenant",
        "vendor-api/credits",
    ));
    cross_tenant_intent["tenant_id"] = json!("other-tenant");
    let cross_tenant = parse(
        &storage
            .request_action(
                &cross_tenant_intent.to_string(),
                agent_v1_keyfile.to_str().unwrap(),
                30,
            )
            .unwrap(),
    );
    assert_eq!(cross_tenant["authorization"]["decision"], "BLOCKED");
    assert_eq!(
        cross_tenant["authorization"]["reason_codes"][0],
        "AGENT_TENANT_SCOPE_DENIED"
    );

    let permit = parse(
        &storage
            .request_action(
                &intent(&agent_v1, "phase3-rotate", "vendor-api/credits"),
                agent_v1_keyfile.to_str().unwrap(),
                30,
            )
            .unwrap(),
    );
    assert_eq!(permit["authorization"]["decision"], "ALLOWED");
    assert_eq!(
        permit["policy_bundle"]["policy_digest"],
        permit["authorization"]["policy_digest"]
    );
    assert_eq!(
        permit["authorization"]["evidence_digest"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    let authorization_id = permit["authorization"]["authorization_id"]
        .as_str()
        .unwrap();
    let action_id = permit["authorization"]["action_id"].as_str().unwrap();

    let rotation = parse(&storage.rotate_agent(&agent_v1, &agent_v2).unwrap());
    assert_eq!(rotation["event"]["event_type"], "ROTATE");
    assert!(!storage.verify_agent(&agent_v1).unwrap());
    assert!(storage.verify_agent(&agent_v2).unwrap());
    assert_eq!(
        parse(&storage.verify_trace(action_id).unwrap())["status"],
        "VERIFIED"
    );

    let outcome = json!({
        "schema_version": "tempus.action-outcome.v1",
        "authorization_id": authorization_id,
        "action_id": action_id,
        "status": "SUCCEEDED",
        "output": {"ok": true}
    })
    .to_string();
    assert!(storage
        .commit_outcome(
            authorization_id,
            &outcome,
            denied_executor_keyfile.to_str().unwrap()
        )
        .unwrap_err()
        .contains("TEMPUS_EXECUTOR_POLICY_DENIED"));
    storage
        .commit_outcome(
            authorization_id,
            &outcome,
            executor_keyfile.to_str().unwrap(),
        )
        .unwrap();
    assert_eq!(
        parse(&storage.verify_trace(action_id).unwrap())["status"],
        "VERIFIED"
    );

    let open_permit = parse(
        &storage
            .request_action(
                &intent(&agent_v2, "phase3-revoke", "vendor-api/credits"),
                agent_v2_keyfile.to_str().unwrap(),
                30,
            )
            .unwrap(),
    );
    let open_authorization = open_permit["authorization"]["authorization_id"]
        .as_str()
        .unwrap();
    let open_action = open_permit["authorization"]["action_id"].as_str().unwrap();
    let revocation = parse(
        &storage
            .revoke_agent(&agent_v2, "operator emergency revocation")
            .unwrap(),
    );
    assert_eq!(revocation["event"]["event_type"], "REVOKE");
    assert_eq!(revocation["revoked_unconsumed_permits"], 1);
    assert!(!storage.verify_agent(&agent_v2).unwrap());
    let blocked_outcome = json!({
        "schema_version": "tempus.action-outcome.v1",
        "authorization_id": open_authorization,
        "action_id": open_action,
        "status": "SUCCEEDED",
        "output": {"should_not_run": true}
    })
    .to_string();
    assert!(storage
        .commit_outcome(
            open_authorization,
            &blocked_outcome,
            executor_keyfile.to_str().unwrap()
        )
        .unwrap_err()
        .contains("TEMPUS_PERMIT_REVOKED"));
    assert_eq!(
        parse(&storage.verify_trace(open_action).unwrap())["status"],
        "VERIFIED"
    );
    assert_eq!(
        parse(&storage.list_identity_events().unwrap())
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn test_segregation_of_duties_proposer_cannot_execute() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("gate.db");
    let gate_keyfile = temp.path().join("gate.keys.json");
    let agent_keyfile = temp.path().join("agent.keys.json");
    generate_keypair(gate_keyfile.to_str().unwrap()).unwrap();
    generate_keypair(agent_keyfile.to_str().unwrap()).unwrap();

    let gate_id = public_key(&gate_keyfile);
    let agent_id = public_key(&agent_keyfile);
    let storage = SqliteStorage::new(
        db_path.to_str().unwrap().to_string(),
        gate_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();

    storage
        .register_agent(&gate_id, "gate", r#"{"can_delegate":true}"#)
        .unwrap();
    storage.install_allow_all_dev_policy().unwrap(); // explicit dev opt-in
    storage
        .register_agent(&agent_id, "agent-both", "{}")
        .unwrap();

    let req = intent(&agent_id, "action-self", "transfer");
    let auth_json = storage
        .request_action(&req, agent_keyfile.to_str().unwrap(), 60)
        .unwrap();
    let auth = parse(&auth_json);
    let auth_id = auth["authorization"]["authorization_id"].as_str().unwrap();
    let act_id = auth["authorization"]["action_id"].as_str().unwrap();

    let outcome = json!({
        "schema_version": "tempus.action-outcome.v1",
        "authorization_id": auth_id,
        "action_id": act_id,
        "status": "SUCCEEDED",
        "output": {}
    })
    .to_string();

    let err = storage
        .commit_outcome(auth_id, &outcome, agent_keyfile.to_str().unwrap())
        .unwrap_err();
    assert!(
        err.contains("TEMPUS_EXECUTOR_INVALID"),
        "Expected TEMPUS_EXECUTOR_INVALID error, got: {err}"
    );
}

struct Gate {
    _temp: tempfile::TempDir,
    db_path: std::path::PathBuf,
    gate_keyfile: std::path::PathBuf,
    agent_keyfile: std::path::PathBuf,
    agent_id: String,
}

impl Gate {
    /// Fresh gate with a registered root and agent, and NO policy installed.
    fn new() -> (Self, SqliteStorage) {
        let temp = tempfile::tempdir().unwrap();
        let gate_keyfile = temp.path().join("gate.keys.json");
        let agent_keyfile = temp.path().join("agent.keys.json");
        generate_keypair(gate_keyfile.to_str().unwrap()).unwrap();
        generate_keypair(agent_keyfile.to_str().unwrap()).unwrap();
        let gate = Gate {
            db_path: temp.path().join("tempus.db"),
            agent_id: public_key(&agent_keyfile),
            gate_keyfile,
            agent_keyfile,
            _temp: temp,
        };
        let storage = gate.open();
        storage
            .register_agent(&public_key(&gate.gate_keyfile), "gate", "{}")
            .unwrap();
        storage
            .register_agent(&gate.agent_id, "agent", "{}")
            .unwrap();
        (gate, storage)
    }

    fn open(&self) -> SqliteStorage {
        SqliteStorage::new(
            self.db_path.to_str().unwrap().to_string(),
            self.gate_keyfile.to_str().unwrap().to_string(),
        )
        .unwrap()
    }

    fn request(&self, storage: &SqliteStorage, key: &str, tenant: &str) -> Value {
        let mut request = parse(&intent(&self.agent_id, key, "github.com/evil/x"));
        request["tenant_id"] = json!(tenant);
        request["action_type"] = json!("github.delete_repo");
        parse(
            &storage
                .request_action(
                    &request.to_string(),
                    self.agent_keyfile.to_str().unwrap(),
                    60,
                )
                .unwrap(),
        )
    }
}

fn assert_not_installed(result: &Value) {
    assert_eq!(result["authorization"]["decision"], "BLOCKED");
    assert_eq!(
        result["authorization"]["reason_codes"],
        json!(["POLICY_NOT_INSTALLED"])
    );
    assert!(result.get("policy_bundle").is_none());
}

#[test]
fn default_deny_without_installed_policy_is_blocked_and_verifiable() {
    let (gate, storage) = Gate::new();
    // Registering the root and the first agent must not seed any policy.
    assert_eq!(parse(&storage.list_policies().unwrap()), json!([]));
    let result = gate.request(&storage, "dd-1", "acme");
    assert_not_installed(&result);
    let action_id = result["authorization"]["action_id"].as_str().unwrap();
    let verification = parse(&storage.verify_trace(action_id).unwrap());
    assert_eq!(verification["status"], "VERIFIED", "{verification}");
}

#[test]
fn default_deny_receipt_cannot_be_flipped_to_allowed() {
    let (gate, storage) = Gate::new();
    let result = gate.request(&storage, "dd-forge", "acme");
    let action_id = result["authorization"]["action_id"].as_str().unwrap();
    let connection = Connection::open(&gate.db_path).unwrap();
    connection
        .execute(
            "UPDATE action_authorizations
             SET authorization_json = replace(replace(authorization_json,
                 'POLICY_NOT_INSTALLED', 'POLICY_ALLOWED'), 'BLOCKED', 'ALLOWED')
             WHERE action_id = ?1",
            [action_id],
        )
        .unwrap();
    let verification = parse(&storage.verify_trace(action_id).unwrap());
    assert_eq!(verification["status"], "INVALID");
}

#[test]
fn tenant_without_its_own_policy_is_blocked() {
    let (gate, storage) = Gate::new();
    let spec = json!({
        "schema_version": "tempus.policy-bundle.v1",
        "policy_version": "acme-only-v1",
        "tenant_id": "acme",
        "constraints": {
            "allowed_action_types": ["github.delete_repo"],
            "allowed_resources": ["*"],
            "allowed_executors": ["*"],
            "max_ttl_seconds": 60,
            "max_input_bytes": 1024
        }
    });
    storage.install_policy(&spec.to_string()).unwrap();
    let acme = gate.request(&storage, "t-acme", "acme");
    assert_eq!(acme["authorization"]["decision"], "ALLOWED");
    let other = gate.request(&storage, "t-other", "other-tenant");
    assert_not_installed(&other);
}

#[test]
fn deleting_policies_from_the_database_and_reopening_stays_blocked() {
    let (gate, storage) = Gate::new();
    storage.install_allow_all_dev_policy().unwrap();
    assert_eq!(
        gate.request(&storage, "del-1", "acme")["authorization"]["decision"],
        "ALLOWED"
    );
    drop(storage);
    let connection = Connection::open(&gate.db_path).unwrap();
    connection
        .execute_batch("DELETE FROM active_policy_attestations; DELETE FROM policy_bundles;")
        .unwrap();
    drop(connection);
    let reopened = gate.open();
    assert_not_installed(&gate.request(&reopened, "del-2", "acme"));
    let reopened_again = gate.open();
    assert_not_installed(&gate.request(&reopened_again, "del-3", "acme"));
}

#[test]
fn legacy_seeded_baseline_in_an_old_database_is_ignored() {
    let (gate, storage) = Gate::new();
    storage.install_allow_all_dev_policy().unwrap();
    let connection = Connection::open(&gate.db_path).unwrap();
    // Simulate a database seeded by a gate older than default-deny.
    connection
        .execute_batch(
            "UPDATE policy_bundles SET policy_version = 'tempus.baseline.v1';
             UPDATE active_policy_attestations SET policy_version = 'tempus.baseline.v1';",
        )
        .unwrap();
    drop(connection);
    assert_not_installed(&gate.request(&gate.open(), "legacy-1", "acme"));
}

#[test]
fn allow_all_dev_policy_is_explicit_idempotent_and_replaceable_by_a_real_policy() {
    let (gate, storage) = Gate::new();
    let first = parse(&storage.install_allow_all_dev_policy().unwrap());
    let second = parse(&storage.install_allow_all_dev_policy().unwrap());
    assert_eq!(first["policy_digest"], second["policy_digest"]);
    assert!(first["policy_version"]
        .as_str()
        .unwrap()
        .starts_with("tempus.dev-allow-all.v1"));
    let allowed = gate.request(&storage, "dev-1", "acme");
    assert_eq!(allowed["authorization"]["decision"], "ALLOWED");
    assert_eq!(
        parse(
            &storage
                .verify_trace(allowed["authorization"]["action_id"].as_str().unwrap())
                .unwrap()
        )["phase"],
        "AUTHORIZED"
    );
    // A real wildcard policy is never silently replaced by the dev opt-in.
    let spec = json!({
        "schema_version": "tempus.policy-bundle.v1",
        "policy_version": "real-wildcard-v1",
        "tenant_id": "*",
        "constraints": {
            "allowed_action_types": ["purchase"],
            "allowed_resources": ["vendor/*"],
            "allowed_executors": ["*"],
            "max_ttl_seconds": 60,
            "max_input_bytes": 1024
        }
    });
    storage.install_policy(&spec.to_string()).unwrap();
    assert!(storage
        .install_allow_all_dev_policy()
        .unwrap_err()
        .contains("TEMPUS_DEV_ALLOW_ALL_REFUSED"));
}

fn canonical_json(value: &Value) -> String {
    fn write(value: &Value, output: &mut String) {
        match value {
            Value::Null => output.push_str("null"),
            Value::Bool(flag) => output.push_str(if *flag { "true" } else { "false" }),
            Value::Number(number) => output.push_str(&number.to_string()),
            Value::String(text) => output.push_str(&serde_json::to_string(text).unwrap()),
            Value::Array(items) => {
                output.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    write(item, output);
                }
                output.push(']');
            }
            Value::Object(map) => {
                output.push('{');
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for (index, key) in keys.iter().enumerate() {
                    if index > 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(key).unwrap());
                    output.push(':');
                    write(&map[*key], output);
                }
                output.push('}');
            }
        }
    }
    let mut output = String::new();
    write(value, &mut output);
    output
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sign_digest_bytes(keyfile: &Path, digest_hex: &str) -> String {
    let value: Value = serde_json::from_str(&std::fs::read_to_string(keyfile).unwrap()).unwrap();
    let seed = hex::decode(value["private_key"].as_str().unwrap()).unwrap();
    let seed: [u8; 32] = seed.try_into().unwrap();
    let key = SigningKey::from_bytes(&seed);
    hex::encode(key.sign(&hex::decode(digest_hex).unwrap()).to_bytes())
}

/// Rewrite the active dev policy so it is signed like a bundle whose currency list is a wildcard.
fn store_signed_dev_policy_with_currency_wildcard(gate: &Gate) -> String {
    let connection = Connection::open(&gate.db_path).unwrap();
    let (version, bundle_json, issued_at): (String, String, i64) = connection
        .query_row(
            "SELECT policy_version, bundle_json, issued_at FROM policy_bundles
             WHERE tenant_id = '*' AND retired_at IS NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let mut bundle: Value = serde_json::from_str(&bundle_json).unwrap();
    bundle
        .get_mut("constraints")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("allowed_currencies".to_string(), json!(["*"]));
    let mut body = bundle.clone();
    let object = body.as_object_mut().unwrap();
    object.remove("policy_digest");
    object.remove("signature");
    object.remove("status");
    object.remove("retired_at");
    let digest = sha256_hex(canonical_json(&body).as_bytes());
    let signature = sign_digest_bytes(&gate.gate_keyfile, &digest);
    bundle["policy_digest"] = json!(digest.clone());
    bundle["signature"] = json!(signature);
    let attestation = json!({
        "schema_version": "tempus.active-policy-attestation.v1",
        "activated_at": issued_at,
        "policy_digest": digest.clone(),
        "policy_version": version.clone(),
        "signer": bundle["signer"].clone(),
        "tenant_id": "*",
    });
    let attestation_json = canonical_json(&attestation);
    let attestation_sig =
        sign_digest_bytes(&gate.gate_keyfile, &sha256_hex(attestation_json.as_bytes()));
    connection
        .execute(
            "UPDATE policy_bundles SET policy_digest = ?1, bundle_json = ?2 WHERE policy_version = ?3",
            rusqlite::params![digest.clone(), canonical_json(&bundle), version.clone()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE active_policy_attestations
             SET policy_digest = ?1, signature = ?2, attestation_json = ?3
             WHERE policy_version = ?4",
            rusqlite::params![digest.clone(), attestation_sig, attestation_json, version],
        )
        .unwrap();
    digest
}

fn corrupt_active_bundle_signature(gate: &Gate) {
    let connection = Connection::open(&gate.db_path).unwrap();
    let (version, bundle_json): (String, String) = connection
        .query_row(
            "SELECT policy_version, bundle_json FROM policy_bundles
             WHERE tenant_id = '*' AND retired_at IS NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let mut bundle: Value = serde_json::from_str(&bundle_json).unwrap();
    let signature = bundle["signature"].as_str().unwrap().to_string();
    let mut chars: Vec<char> = signature.chars().collect();
    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
    let flipped: String = chars.into_iter().collect();
    bundle["signature"] = json!(flipped);
    connection
        .execute(
            "UPDATE policy_bundles SET bundle_json = ?1 WHERE policy_version = ?2",
            rusqlite::params![canonical_json(&bundle), version],
        )
        .unwrap();
}

fn active_currency_list(storage: &SqliteStorage) -> Value {
    let policies = parse(&storage.list_policies().unwrap());
    for policy in policies.as_array().unwrap() {
        if policy["status"] == "ACTIVE" && policy["tenant_id"] == "*" {
            return policy["constraints"]
                .get("allowed_currencies")
                .cloned()
                .unwrap_or(Value::Null);
        }
    }
    panic!("no active wildcard policy: {policies}");
}

fn policy_store_snapshot(gate: &Gate) -> String {
    let connection = Connection::open(&gate.db_path).unwrap();
    let mut snapshot = String::new();
    for (label, sql) in [
        (
            "bundles",
            "SELECT policy_version, tenant_id, policy_digest, CAST(issued_at AS TEXT),
                    CAST(ifnull(retired_at, -1) AS TEXT), bundle_json
             FROM policy_bundles ORDER BY policy_version",
        ),
        (
            "attestations",
            "SELECT tenant_id, policy_version, policy_digest, CAST(activated_at AS TEXT),
                    signer_public_key, signature, attestation_json
             FROM active_policy_attestations ORDER BY tenant_id, policy_version",
        ),
        (
            "events",
            "SELECT tenant_id, CAST(sequence_number AS TEXT), event_type, event_digest, event_json
             FROM event_stream ORDER BY tenant_id, sequence_number",
        ),
        (
            "authorizations",
            "SELECT action_id, intent_hash, authorization_json
             FROM action_authorizations ORDER BY action_id",
        ),
    ] {
        snapshot.push_str(label);
        snapshot.push('\n');
        let mut statement = connection.prepare(sql).unwrap();
        let column_count = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                let mut line = String::new();
                for index in 0..column_count {
                    if index > 0 {
                        line.push('|');
                    }
                    line.push_str(&row.get::<_, String>(index)?);
                }
                Ok(line)
            })
            .unwrap();
        for row in rows {
            snapshot.push_str(&row.unwrap());
            snapshot.push('\n');
        }
    }
    snapshot
}

fn dev_request_error(gate: &Gate, storage: &SqliteStorage, key: &str) -> String {
    let mut request = parse(&intent(&gate.agent_id, key, "github.com/evil/x"));
    request["tenant_id"] = json!("acme");
    request["action_type"] = json!("github.delete_repo");
    storage
        .request_action(
            &request.to_string(),
            gate.agent_keyfile.to_str().unwrap(),
            60,
        )
        .unwrap_err()
}

fn assert_stale_dev_currency_error(error: &str) {
    assert!(error.contains("TEMPUS_POLICY_INVALID"), "{error}");
    assert!(error.contains("install-policy --allow-all-dev"), "{error}");
    assert!(
        error.contains("TempusDDB.install_allow_all_dev_policy"),
        "{error}"
    );
    assert!(error.contains("not allowed"), "{error}");
}

#[test]
fn stale_dev_allow_all_with_a_currency_wildcard_fails_closed() {
    let (gate, storage) = Gate::new();
    let original = parse(&storage.install_allow_all_dev_policy().unwrap());
    drop(storage);
    let stale_digest = store_signed_dev_policy_with_currency_wildcard(&gate);
    assert_ne!(original["policy_digest"].as_str().unwrap(), stale_digest);
    let before = policy_store_snapshot(&gate);
    let storage = gate.open();
    assert_eq!(active_currency_list(&storage), json!(["*"]));

    // Loading the signed policy does not rewrite it and does not allow the action.
    let error = dev_request_error(&gate, &storage, "stale-load");
    assert_stale_dev_currency_error(&error);
    drop(storage);
    assert_eq!(policy_store_snapshot(&gate), before);
    let storage = gate.open();
    assert_eq!(active_currency_list(&storage), json!(["*"]));
    let error_again = dev_request_error(&gate, &storage, "stale-load-2");
    assert_stale_dev_currency_error(&error_again);
    drop(storage);
    assert_eq!(policy_store_snapshot(&gate), before);

    // The operator command is what replaces the stored policy.
    let storage = gate.open();
    let replaced = parse(&storage.install_allow_all_dev_policy().unwrap());
    let again = parse(&storage.install_allow_all_dev_policy().unwrap());
    assert_eq!(replaced["policy_digest"], again["policy_digest"]);
    assert_ne!(replaced["policy_digest"].as_str().unwrap(), stale_digest);
    assert!(replaced["constraints"].get("allowed_currencies").is_none());
    assert!(replaced["policy_version"]
        .as_str()
        .unwrap()
        .starts_with("tempus.dev-allow-all.v1"));
    let allowed = gate.request(&storage, "stale-repaired", "acme");
    assert_eq!(allowed["authorization"]["decision"], "ALLOWED");
    assert!(allowed["policy_bundle"]["constraints"]
        .get("allowed_currencies")
        .is_none());
    assert_eq!(
        allowed["policy_bundle"]["policy_digest"],
        replaced["policy_digest"]
    );

    // A stored wildcard whose signature does not verify is also left unchanged.
    let (gate_bad, storage_bad) = Gate::new();
    storage_bad.install_allow_all_dev_policy().unwrap();
    drop(storage_bad);
    store_signed_dev_policy_with_currency_wildcard(&gate_bad);
    corrupt_active_bundle_signature(&gate_bad);
    let before_bad = policy_store_snapshot(&gate_bad);
    let storage_bad = gate_bad.open();
    let error = dev_request_error(&gate_bad, &storage_bad, "stale-bad");
    assert_stale_dev_currency_error(&error);
    drop(storage_bad);
    assert_eq!(policy_store_snapshot(&gate_bad), before_bad);

    // A non-dev policy with a currency wildcard is rejected and nothing is allowed by default.
    let (gate_real, storage_real) = Gate::new();
    let spec = json!({
        "schema_version": "tempus.policy-bundle.v1",
        "policy_version": "real-wildcard-currency",
        "tenant_id": "*",
        "constraints": {
            "allowed_action_types": ["*"],
            "allowed_resources": ["*"],
            "allowed_executors": ["*"],
            "max_ttl_seconds": 60,
            "max_input_bytes": 1024,
            "allowed_currencies": ["*"]
        }
    });
    let rejected = storage_real.install_policy(&spec.to_string()).unwrap_err();
    assert!(rejected.contains("TEMPUS_POLICY_INVALID"), "{rejected}");
    assert!(rejected.contains("exact currency codes"), "{rejected}");
    assert_not_installed(&gate_real.request(&storage_real, "wild-real", "acme"));
}

#[test]
fn test_copy_pyd_binary() {
    let candidates = [
        "target/debug/deps/_tempus_ddb.dll",
        "target/debug/_tempus_ddb.dll",
        "target/release/deps/_tempus_ddb.dll",
        "target/release/_tempus_ddb.dll",
    ];
    let pyd_path = std::path::Path::new("python/tempus_ddb/_tempus_ddb.pyd");
    for cand in candidates {
        let dll_path = std::path::Path::new(cand);
        if dll_path.exists() {
            let _ = std::fs::copy(dll_path, pyd_path);
            break;
        }
    }
}

#[test]
fn numbers_that_overflow_f64_are_non_exact_numbers_not_syntax_errors() {
    let temp = tempfile::tempdir().unwrap();
    let gate_keyfile = temp.path().join("gate.keys.json");
    generate_keypair(gate_keyfile.to_str().unwrap()).unwrap();
    let gate_id = public_key(&gate_keyfile);
    let storage = SqliteStorage::new(
        temp.path().join("tempus.db").to_str().unwrap().to_string(),
        gate_keyfile.to_str().unwrap().to_string(),
    )
    .unwrap();

    for raw in [r#"{"a":1e400}"#, r#"{"a":-1e400}"#, r#"{"a":[1e999]}"#] {
        let policy = storage.install_policy(raw).unwrap_err();
        assert!(policy.starts_with("NON_EXACT_NUMBER"), "{raw}: {policy}");
        let metadata = storage
            .register_agent(&gate_id, "tempus-gate", raw)
            .unwrap_err();
        assert!(
            metadata.starts_with("NON_EXACT_NUMBER"),
            "{raw}: {metadata}"
        );
    }
    // Real syntax errors keep their message.
    let syntax = storage.install_policy("{not json").unwrap_err();
    assert!(syntax.contains("must be valid JSON"), "{syntax}");
}
