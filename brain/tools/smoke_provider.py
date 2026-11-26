"""Check one model provider end to end, by hand, with your own key, on built-in demo data.

    docker compose run --rm --no-deps \\
      -v "$PWD/secrets/momus_analyst_api_key:/run/secrets/momus_analyst_api_key:ro" \\
      -e MOMUS_ANALYST_API_KEY_FILE=/run/secrets/momus_analyst_api_key \\
      --entrypoint python3 brain -B -m tools.smoke_provider
    (MOMUS_ANALYST_PROVIDER and MOMUS_ANALYST_MODEL come from .env, with MOMUS_ANALYST_API_KEY left empty there; the key
    file is written with an editor, so the key never appears on a command line. Bedrock: also MOMUS_ANALYST_REGION, and
    the key is optional. See docs/analyst.md.)

It reads the same MOMUS_ANALYST_* settings as the brain, and nothing else. It builds a small demo snapshot in a temporary
folder (two hosts, three findings; no data of yours), checks the model (models.retrieve, models.get or Bedrock's
get_foundation_model / get_inference_profile), then runs one real brief through the same loop, tools, schemas, limits
and redaction the brain uses, and prints the outcome, each step, the token use and the brief. The demo data and the
prompts go to the provider: that is the point of the test. Nothing is written outside the temporary folder, and the
key is never printed. Exit code 0 when the brief finished, 1 otherwise."""
import dataclasses
import hashlib
import json
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import config, db as dbm, snapshot  # noqa: E402
from app.analyst import consent, runner  # noqa: E402
from app.llm import base, factory  # noqa: E402

DEMO_FINDINGS = [
    ("1a2b3c4d5e6f70819203", "www.demo.example", "nuclei", "generic-env", 443, "Environment file exposed", "high", "High", 82, "new",
     "The file /.env is served and contains configuration values.", "Remove the file from the web root."),
    ("2b3c4d5e6f7081920314", "www.demo.example", "nuclei", "git-config", 443, "Git configuration exposed", "medium", "Medium", 61, "persistent",
     "The file /.git/config is served.", "Block access to /.git/ on the web server."),
    ("3c4d5e6f708192031425", "mail.demo.example", "sslscan", "weak-cipher", 443, "Weak TLS cipher suites", "low", "Low", 22, "persistent",
     "TLS 1.0 and CBC suites are offered.", "Disable TLS 1.0 and 1.1."),
]


def demo_snapshot(path):
    """A database with the tables and columns the brain reads (snapshot.REQUIRED), all plain tables."""
    c = sqlite3.connect(path)
    for table, cols in snapshot.REQUIRED.items():
        c.execute(f"CREATE TABLE {table} ({', '.join(sorted(cols | ({'kind'} if table == 'runs' else set())))})")
    c.execute("INSERT INTO runs(seq, run_id, started, finished, kind) VALUES(1, 'demo-full-1', '2030-01-01T00:00:00Z', '2030-01-01T01:00:00Z', 'full')")
    c.execute("INSERT INTO runs(seq, run_id, started, finished, kind) VALUES(2, 'demo-full-2', '2030-01-08T00:00:00Z', '2030-01-08T01:00:00Z', 'full')")
    for key, host, src, check, port, title, sev, band, score, state, desc, fix in DEMO_FINDINGS:
        c.execute("INSERT INTO findings(finding_key, hostname, apex, source, check_id, port, title, severity, status, cve_ids, first_seen_run, "
                  "last_seen_run, fixed_run) VALUES(?,?, 'demo.example', ?,?,?,?,?, 'open', '', ?, 'demo-full-2', NULL)",
                  (key, host, src, check, port, title, sev, "demo-full-2" if state == "new" else "demo-full-1"))
        c.execute("INSERT INTO finding_observations(run_id, finding_key, asset_class, matched, description, remediation, reference, tags, cvss, "
                  "epss, kev, impact, likelihood, score, band, sla_days, state, raw_json, verdict, verification, exposure) VALUES"
                  "('demo-full-2', ?, 'owned', ?, ?, ?, '[]', '[]', NULL, NULL, 0, 3, 3, ?, ?, 30, ?, '{}', 'confirmed', '', '')",
                  (key, f"https://{host}/", desc, fix, score, band, state))
    for host, title in (("www.demo.example", "Demo shop"), ("mail.demo.example", "Webmail")):
        c.execute("INSERT INTO asset_observations(run_id, hostname, apex, class, reason, ips, cnames, tech, waf, status_code, title, server, urls, "
                  "cert_expiry) VALUES('demo-full-2', ?, 'demo.example', 'owned', 'demo', '[\"192.0.2.10\"]', '[]', '[\"nginx\"]', '', 200, ?, "
                  "'nginx', '[]', '2031-01-01')", (host, title))
    c.execute("INSERT INTO run_summary(run_id, json) VALUES('demo-full-2', ?)",
              (json.dumps({"bands": {"Critical": 0, "High": 1, "Medium": 1, "Low": 1}, "new": 1, "reopened": 0, "fixed": 0, "total": 3}),))
    c.commit()
    c.close()


def main():
    from app.llm import envguard
    envguard.scrub_at_start()          # as run.py does: before any SDK is imported
    s = config.from_env()
    if s.analyst_provider in ("none", "mock", "susceptible", "invalid"):
        print("Set MOMUS_ANALYST_PROVIDER to anthropic, openai, gemini or bedrock (and MOMUS_ANALYST_MODEL, and the key or region).")
        return 1
    tmp = tempfile.mkdtemp(prefix="momus-smoke-")
    pub = os.path.join(tmp, "published")
    os.makedirs(os.path.join(pub, "snapshots"))
    snap = os.path.join(pub, "snapshots", "demo-full-2.sqlite")
    demo_snapshot(snap)
    digest = hashlib.sha256(open(snap, "rb").read()).hexdigest()
    with open(os.path.join(pub, "snapshots", "latest.json"), "w") as fh:
        json.dump({"schema": "momus-snapshot-v1", "run_id": "demo-full-2", "job_id": "demo-full-2", "file": "demo-full-2.sqlite",
                   "sha256": digest, "created_at": "2030-01-08T01:00:00Z"}, fh)
    s = dataclasses.replace(s, data_dir=os.path.join(tmp, "data"), published_dir=pub, jobs_dir=os.path.join(tmp, "jobs"), lab=False,
                            scheduler_enabled=False, analyst_auto_brief=False, analyst_debug=False)
    os.makedirs(s.jobs_dir)
    dbm.migrate(s.db_path)
    print(f"provider: {factory.label(s)}; model: {s.analyst_model}; key: {'set' if s.analyst_key else 'not set'}")
    try:
        provider = factory.build(s)
        print("model check:", provider.check_model())
    except base.LLMError as e:
        print("model check failed:", e)
        return 1
    db = dbm.connect(s.db_path)
    consent.confirm(db, s, "smoke-test", None)        # in the temporary database only
    try:
        rid = runner.start(s, db, "brief", "smoke-test", "smoke-test", provider=provider, wait=True)
    except runner.RunRefused as e:
        print("refused:", e)
        return 1
    r = dict(db.execute("SELECT * FROM agent_runs WHERE id=?", (rid,)).fetchone())
    print(f"outcome: {r['outcome']} ({runner.OUTCOMES.get(r['outcome'])}); steps {r['steps']}; tokens in {r['tokens_in']}, out {r['tokens_out']}")
    for st in db.execute("SELECT step, kind, tool, arguments, result_bytes, tokens_in, tokens_out, error FROM agent_steps WHERE agent_run_id=?", (rid,)):
        print(f"  step {st['step']}: {st['kind']} {st['tool'] or ''} {st['arguments'] or ''} result {st['result_bytes']} bytes; "
              f"tokens {st['tokens_in']}/{st['tokens_out']}{'; ' + st['error'] if st['error'] else ''}")
    if r["result_json"]:
        print("brief (the model's text):")
        print(json.dumps(json.loads(r["result_json"]), indent=1, ensure_ascii=False))
    if r["dropped_json"] and json.loads(r["dropped_json"]):
        print("dropped by the validator:", r["dropped_json"])
    print("proposals:", [dict(x) for x in db.execute("SELECT kind, finding_key, reason FROM proposals WHERE agent_run_id=?", (rid,))])
    return 0 if r["outcome"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
