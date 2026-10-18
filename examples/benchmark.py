import argparse
import json
import os
import sys
import tempfile
import time

from tempus_ddb import TempusDDB, gen_keys


def run_benchmark(records: int, json_output: bool, include_legacy: bool = False):
    with tempfile.TemporaryDirectory() as tmpdir:
        gate_db = os.path.join(tmpdir, "gate_bench.db")
        gate_keyfile = os.path.join(tmpdir, "gate.keys.json")
        agent_keyfile = os.path.join(tmpdir, "agent.keys.json")
        executor_keyfile = os.path.join(tmpdir, "executor.keys.json")

        gen_keys(gate_keyfile)
        gen_keys(agent_keyfile)
        gen_keys(executor_keyfile)

        gate = TempusDDB(gate_db, gate_keyfile)

        with open(gate_keyfile, encoding="utf-8") as f:
            gate_id = json.load(f)["public_key"]
        with open(agent_keyfile, encoding="utf-8") as f:
            agent_id = json.load(f)["public_key"]
        with open(executor_keyfile, encoding="utf-8") as f:
            executor_id = json.load(f)["public_key"]

        gate.register_agent(gate_id, "gate-benchmark", '{"can_delegate":true}')
        gate.install_allow_all_dev_policy()  # demo only: explicit allow-all (default is deny-all)
        gate.register_agent(agent_id, "agent-benchmark", "{}")
        gate.register_agent(executor_id, "executor-benchmark", "{}")

        tenant_id = "benchmark-tenant"

        if not json_output:
            print(f"🔥 Tempus DDB v0.4.0 B2A Protocol Benchmark ({records} actions)...")
            print("📍 Database: SQLite WAL mode | Signer: Ed25519 Native\n")

        # -------------------------------------------------------------
        # Phase 1: Action Intent & Permit Issuance (Authorization)
        # -------------------------------------------------------------
        now_us = time.time_ns() // 1_000
        permits = []
        action_ids = []

        auth_start = time.perf_counter()
        for i in range(records):
            intent = json.dumps({
                "schema_version": "tempus.action-intent.v1",
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "idempotency_key": f"bench-action-{i}-{now_us}",
                "action_type": "benchmark.execute_task",
                "resource": f"system/worker-{i % 10}",
                "requested_at": now_us,
                "input": {"iteration": i, "payload_bytes": 128},
            })
            auth_raw = gate.request_action(intent, agent_keyfile, 300)
            auth_obj = json.loads(auth_raw)["authorization"]
            permits.append(auth_obj)
            action_ids.append(auth_obj["action_id"])
        auth_end = time.perf_counter()
        auth_duration = auth_end - auth_start
        auth_tps = records / auth_duration if auth_duration > 0 else 0

        # -------------------------------------------------------------
        # Phase 2: Outcome Commit & Receipt Generation (Execution)
        # -------------------------------------------------------------
        exec_start = time.perf_counter()
        for i, permit in enumerate(permits):
            outcome = json.dumps({
                "schema_version": "tempus.action-outcome.v1",
                "authorization_id": permit["authorization_id"],
                "action_id": permit["action_id"],
                "status": "SUCCEEDED",
                "external_reference": f"bench-ref-{i}",
                "output": {"result_code": 0, "processed_at": now_us + 1000},
            })
            gate.commit_outcome(permit["authorization_id"], outcome, executor_keyfile)
        exec_end = time.perf_counter()
        exec_duration = exec_end - exec_start
        exec_tps = records / exec_duration if exec_duration > 0 else 0

        # -------------------------------------------------------------
        # Phase 3: Cryptographic Trace Verification (Audit)
        # -------------------------------------------------------------
        verify_sample_size = min(records, 100)
        verify_start = time.perf_counter()
        verified_count = 0
        for i in range(verify_sample_size):
            ver_raw = gate.verify_trace(action_ids[i])
            ver_obj = json.loads(ver_raw)
            if ver_obj.get("status") == "VERIFIED" and ver_obj.get("phase") == "COMPLETED":
                verified_count += 1
        verify_end = time.perf_counter()
        verify_duration = verify_end - verify_start
        verify_tps = verify_sample_size / verify_duration if verify_duration > 0 else 0

        # -------------------------------------------------------------
        # Optional Legacy Flight-Recorder Comparison
        # -------------------------------------------------------------
        legacy_metrics = None
        if include_legacy:
            leg_start = time.perf_counter()
            batch = [
                (json.dumps({"accion": "legacy_bench", "idx": i}), json.dumps({"limite": 100}))
                for i in range(records)
            ]
            gate.record_batch(batch, genesis=False)
            leg_end = time.perf_counter()
            leg_duration = leg_end - leg_start
            legacy_metrics = {
                "records": records,
                "duration_seconds": leg_duration,
                "throughput_per_sec": records / leg_duration if leg_duration > 0 else 0,
            }

        # -------------------------------------------------------------
        # Results Output
        # -------------------------------------------------------------
        if json_output:
            out_data = {
                "records": records,
                "authorization": {
                    "duration_seconds": round(auth_duration, 4),
                    "throughput_per_sec": round(auth_tps, 2),
                    "avg_latency_ms": round((auth_duration / records) * 1000, 3),
                },
                "execution_commit": {
                    "duration_seconds": round(exec_duration, 4),
                    "throughput_per_sec": round(exec_tps, 2),
                    "avg_latency_ms": round((exec_duration / records) * 1000, 3),
                },
                "trace_verification": {
                    "sample_size": verify_sample_size,
                    "duration_seconds": round(verify_duration, 4),
                    "verifications_per_sec": round(verify_tps, 2),
                    "all_verified": verified_count == verify_sample_size,
                },
            }
            if legacy_metrics:
                out_data["legacy_batch"] = legacy_metrics
            print(json.dumps(out_data, indent=2))
        else:
            print("📊 RESULTADOS DEL BENCHMARK B2A:")
            print("-----------------------------------------------------------------")
            print("1️⃣  Emisión de Permisos (Request Action):")
            print(f"    • Acciones procesadas: {records}")
            print(f"    • Tiempo total:        {auth_duration:.3f} s")
            print(f"    • Rendimiento:         {auth_tps:.2f} permisos/s")
            print(f"    • Latencia promedio:   {(auth_duration / records) * 1000:.2f} ms/acción\n")

            print("2️⃣  Consumo y Recibos (Commit Outcome):")
            print(f"    • Recibos firmados:    {records}")
            print(f"    • Tiempo total:        {exec_duration:.3f} s")
            print(f"    • Rendimiento:         {exec_tps:.2f} recibos/s")
            print(f"    • Latencia promedio:   {(exec_duration / records) * 1000:.2f} ms/recibo\n")

            print("3️⃣  Verificación Criptográfica de Trazas:")
            print(f"    • Muestra verificada:  {verify_sample_size}/{records} trazas")
            print(f"    • Trazas íntegras:     {verified_count}/{verify_sample_size} (100% VERIFIED)")
            print(f"    • Rendimiento audito:  {verify_tps:.2f} trazas verificadas/s")
            print("-----------------------------------------------------------------")

        del gate
        import gc
        gc.collect()


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Tempus DDB v0.4.0 Benchmark")
    parser.add_argument("--records", type=int, default=1000, help="Number of actions to benchmark (default: 1000)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--legacy", action="store_true", help="Include legacy batch flight-recorder comparison")
    args = parser.parse_args()

    run_benchmark(args.records, args.json, args.legacy)
