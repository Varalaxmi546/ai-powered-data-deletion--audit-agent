#!/usr/bin/env python3
"""GhostTrace AI: deterministic deletion audit pipeline.

Uses only participant-facing files under dataset/. It parses structured evidence,
resolves identity history, applies deletion rules, and emits the required CSV.
Evidence parsing is intentionally conservative: extend parsers when a new evidence
format is encountered, and never treat an operation's reported result as proof.
"""
from __future__ import annotations
import argparse, csv, json, re, hashlib, sqlite3, subprocess, sys
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"

def read_csv(path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None

def norm(value):
    return re.sub(r"\s+", " ", str(value or "").strip().lower())

def log_turn(message):
    log = ROOT / "log.txt"
    stamp = datetime.now(timezone.utc).isoformat()
    with log.open("a", encoding="utf-8") as f:
        f.write(f"[{stamp}] {message.replace(chr(10), ' ')}\n")

class Auditor:
    def __init__(self):
        self.requests = read_csv(DATA / "deletion_requests.csv")
        self.identities = read_csv(DATA / "user_identities.csv")
        self.audit = read_csv(DATA / "user_audit_log.csv")
        self.activities = read_csv(DATA / "system_activity.csv")
        self.rules = read_csv(DATA / "deletion_rules.csv")
        self.manifest = read_csv(DATA / "evidence_files.csv")
        self.rule_by_category = {norm(r.get("data_category")): r for r in self.rules}
        self.evidence_text = {}
        self.manifest_by_path = {m.get("file_path", ""): m for m in self.manifest}
        self._load_evidence()

    def _load_evidence(self):
        evroot = DATA / "evidence"
        for m in self.manifest:
            rel = (m.get("file_path") or "").replace("\\", "/")
            path = DATA / rel
            if not path.exists():
                # Manifest paths may be relative to evidence/
                path = evroot / Path(rel).name
            if not path.exists() or not path.is_file():
                continue
            ext = path.suffix.lower()
            try:
                if ext in (".txt", ".log", ".json", ".sql"):
                    content = path.read_text(encoding="utf-8", errors="replace")
                    self.evidence_text[rel] = content
                elif ext == ".pdf":
                    # Optional PDF text extraction when pypdf is installed.
                    try:
                        from pypdf import PdfReader
                        self.evidence_text[rel] = "\n".join(p.extract_text() or "" for p in PdfReader(str(path)).pages)
                    except Exception:
                        self.evidence_text[rel] = ""
                elif ext == ".png":
                    # OCR is optional; avoid adding heavy dependencies to the baseline.
                    try:
                        import pytesseract
                        from PIL import Image
                        self.evidence_text[rel] = pytesseract.image_to_string(Image.open(path))
                    except Exception:
                        self.evidence_text[rel] = ""
            except Exception:
                continue

    def _identifiers(self, request):
        email = norm(request.get("email"))
        users = [u for u in self.identities if norm(u.get("email")) == email]
        ids = {u.get("user_id") for u in users if u.get("user_id")}
        aliases = {email}
        names, phones, hashes = set(), set(), set()
        for u in users:
            for field, target in (("name", names), ("phone", phones), ("email_hash", hashes)):
                if u.get(field): target.add(norm(u[field]))
        # Historical changes can connect a current identity to previous email/phone/name.
        changed = True
        while changed:
            changed = False
            for a in self.audit:
                if a.get("user_id") in ids:
                    for field, target in (("old_value", aliases), ("new_value", aliases)):
                        value = norm(a.get(field))
                        if value and value not in target:
                            target.add(value); changed = True
        for a in self.audit:
            if a.get("user_id") in ids:
                for field in ("old_value", "new_value"):
                    val = norm(a.get(field))
                    if val and ("@" in val): aliases.add(val)
        # Hash email variants only if they exactly correspond to a recorded email hash.
        for u in users:
            if u.get("email_hash"): hashes.add(norm(u["email_hash"]))
        return ids, aliases, names, phones, hashes

    def _case_evidence(self, request, ids, aliases, names, phones, hashes):
        audit_at = parse_time(request.get("audit_at"))
        # A request only authorizes deletion when request text actually asks for it.
        text = norm(request.get("request_text"))
        authorized = bool(re.search(r"\b(delete|deletion|erase|erasure|remove|right to be forgotten)\b", text))
        # Evidence file matching: exact identifiers and linked user IDs, only in files
        # captured no later than audit_at. File ids are used as evidence citations.
        matching = []
        for m in self.manifest:
            captured = parse_time(m.get("captured_at"))
            if audit_at and captured and captured > audit_at:
                continue
            rel = (m.get("file_path") or "").replace("\\", "/")
            content = self.evidence_text.get(rel, "")
            if not content:
                continue
            ncontent = norm(content)
            hit = any(v and v in ncontent for v in ids | aliases | names | phones | hashes)
            if hit:
                matching.append((m, content))
        # Activity log evidence is time-scoped and identity/resource scoped where possible.
        activity_hits = []
        for a in self.activities:
            t = parse_time(a.get("event_time"))
            if audit_at and t and t > audit_at:
                continue
            hay = norm(" ".join(str(a.get(k, "")) for k in a.keys()))
            if any(v and v in hay for v in ids | aliases | names | phones | hashes):
                activity_hits.append(a)
        return authorized, matching, activity_hits

    def _build_case(self, request):
        ids, aliases, names, phones, hashes = self._identifiers(request)
        authorized, evidence, activities = self._case_evidence(request, ids, aliases, names, phones, hashes)
        if not authorized:
            return "NOT_APPLICABLE", []
        findings, remediations, verifications = [], [], []
        # Evidence parsers can report structured records when lines identify resource,
        # system, category, state, and direct identifiers. Treat explicit present
        # records as findings; operation success alone is not proof.
        for m, content in evidence:
            file_id = m.get("file_id", "")
            for line in content.splitlines():
                low = norm(line)
                if not any(v and v in low for v in ids | aliases | names | phones | hashes):
                    continue
                # A matching line must contain a recognizable resource identifier.
                rm = re.search(r"\b(account|support|search|analytics|telemetry|export|marketing|cache|backup|restore|email|security|legal|tombstone|profile)[_-][a-z0-9_-]+\b", line, re.I)
                if not rm: continue
                resource = rm.group(0)
                system = "unknown_system"
                for s in ("account_service","support_platform","search_service","analytics_platform","security_service","marketing_platform","email_service","profile_service","cache_service","backup_service"):
                    if s in low: system = s; break
                category = "USER_PROFILE" if resource.startswith("account_") else ""
                if "support" in resource: category = "SUPPORT_MESSAGE"
                elif "search" in resource: category = "SEARCH_INDEX_ENTRY"
                elif "analytics" in resource: category = "ANALYTICS_PROFILE"
                elif "telemetry" in resource: category = "PRODUCT_TELEMETRY"
                elif "export" in resource: category = "USER_EXPORT"
                elif "marketing" in resource: category = "MARKETING_PROFILE"
                elif "cache" in resource: category = "CACHE_ENTRY"
                elif "tombstone" in resource: category = "ACCOUNT_TOMBSTONE"
                elif "backup" in resource or "restore" in resource: category = "BACKUP_ARCHIVE"
                elif "email" in resource: category = "EMAIL_DELIVERY_LOG"
                elif "security" in resource: category = "SECURITY_AUDIT_LOG"
                rule = self.rule_by_category.get(norm(category), {})
                action = (rule.get("required_action") or "").upper()
                if action == "RETAIN":
                    op, state = "VERIFY_RECORD_PRESENT", "PRESENT"
                    verifications.append(dict(phase="VERIFICATION", system_id=system, resource_id=resource, operation=op, state=state, evidence_id=file_id))
                elif action == "REDACT":
                    findings.append(dict(phase="FINDING", system_id=system, resource_id=resource, operation="REPORT_EXPOSED_PII", state="PRESENT", evidence_id=file_id))
                    remediations.append(dict(phase="REMEDIATION", system_id=system, resource_id=resource, operation="REDACT_RECORD", state="REDACTED", evidence_id=""))
                    verifications.append(dict(phase="VERIFICATION", system_id=system, resource_id=resource, operation="VERIFY_RECORD_REDACTED", state="REDACTED", evidence_id=""))
                elif action == "ANONYMIZE":
                    findings.append(dict(phase="FINDING", system_id=system, resource_id=resource, operation="REPORT_EXPOSED_PII", state="PRESENT", evidence_id=file_id))
                    remediations.append(dict(phase="REMEDIATION", system_id=system, resource_id=resource, operation="ANONYMIZE_RECORD", state="ANONYMIZED", evidence_id=""))
                    verifications.append(dict(phase="VERIFICATION", system_id=system, resource_id=resource, operation="VERIFY_RECORD_ANONYMIZED", state="ANONYMIZED", evidence_id=""))
                elif action == "DELETE":
                    findings.append(dict(phase="FINDING", system_id=system, resource_id=resource, operation="REPORT_REMAINING_RECORD", state="PRESENT", evidence_id=file_id))
                    remediations.append(dict(phase="REMEDIATION", system_id=system, resource_id=resource, operation="DELETE_RECORD", state="ABSENT", evidence_id=""))
                    verifications.append(dict(phase="VERIFICATION", system_id=system, resource_id=resource, operation="VERIFY_RECORD_ABSENT", state="ABSENT", evidence_id=""))
        # Find active flows and restore paths from activity details. Reported results
        # are treated as claims; only active flow-like descriptions are candidate risks.
        for a in activities:
            typ = norm(a.get("event_type"))
            details = norm(a.get("details"))
            resource = a.get("resource_id") or "unknown_resource"
            system = a.get("target_system") or a.get("source_system") or "unknown_system"
            if any(w in typ + " " + details for w in ("sync", "import", "restore")):
                if "restore" in typ + " " + details:
                    findings.append(dict(phase="FINDING", system_id=system, resource_id=resource, operation="REPORT_RESTORE_RISK", state="ACTIVE", evidence_id=a.get("activity_id","")))
                    remediations.append(dict(phase="REMEDIATION", system_id=system, resource_id=resource, operation="BLOCK_RESTORE", state="BLOCKED", evidence_id=""))
                    verifications.append(dict(phase="VERIFICATION", system_id=system, resource_id=resource, operation="VERIFY_RESTORE_BLOCKED", state="BLOCKED", evidence_id=""))
                elif "active" in details or "enabled" in details or "scheduled" in details:
                    findings.append(dict(phase="FINDING", system_id=system, resource_id=resource, operation="REPORT_ACTIVE_DATA_FLOW", state="ACTIVE", evidence_id=a.get("activity_id","")))
                    remediations.append(dict(phase="REMEDIATION", system_id=system, resource_id=resource, operation="DISABLE_DATA_FLOW", state="DISABLED", evidence_id=""))
                    verifications.append(dict(phase="VERIFICATION", system_id=system, resource_id=resource, operation="VERIFY_DATA_FLOW_DISABLED", state="DISABLED", evidence_id=""))
        # Deduplicate by all semantic fields.
        def unique(rows):
            seen, out = set(), []
            for x in rows:
                key = tuple(x.get(k, "") for k in ("phase","system_id","resource_id","operation","state","evidence_id"))
                if key not in seen: seen.add(key); out.append(x)
            return out
        findings, remediations, verifications = map(unique, (findings, remediations, verifications))
        # Sort by required operation order, then system and resource.
        order = {
            "REPORT_REMAINING_RECORD": 1, "REPORT_EXPOSED_PII": 2,
            "REPORT_ACTIVE_DATA_FLOW": 3, "REPORT_RESTORE_RISK": 4,
            "DISABLE_DATA_FLOW": 1, "BLOCK_RESTORE": 2, "DELETE_RECORD": 3,
            "REDACT_RECORD": 4, "ANONYMIZE_RECORD": 5,
            "VERIFY_RECORD_ABSENT": 1, "VERIFY_RECORD_PRESENT": 2,
            "VERIFY_RECORD_REDACTED": 3, "VERIFY_RECORD_ANONYMIZED": 4,
            "VERIFY_DATA_FLOW_DISABLED": 5, "VERIFY_RESTORE_BLOCKED": 6
        }
        for rows in (findings, remediations, verifications):
            rows.sort(key=lambda x: (order.get(x["operation"],99), x["system_id"], x["resource_id"]))
        # Only verification steps for complete cases. Conservative baseline: if any
        # evidence of required treatment is incomplete, return remediation plan.
        incomplete = bool(findings or remediations)
        if incomplete:
            steps = findings + remediations + verifications
            status = "INCOMPLETE"
        else:
            # If no evidence can prove all relevant records/flows are clear, don't
            # claim complete; use verification only when actual evidence exists.
            status = "COMPLETE" if verifications else "INCOMPLETE"
            steps = verifications if status == "COMPLETE" else []
        for i, step in enumerate(steps, 1):
            step["step_no"] = i
            # ensure exact schema keys and order is not semantically relevant
            step.setdefault("evidence_id", "")
        keys = ("step_no","phase","system_id","resource_id","operation","state","evidence_id")
        return status, [{k: s.get(k, "") for k in keys} for s in steps]

    def run(self):
        rows = []
        for request in self.requests:
            status, steps = self._build_case(request)
            rows.append({"case_id": request.get("case_id",""), "deletion_status": status,
                         "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",",":"))})
        rows.sort(key=lambda r: r["case_id"])
        with OUTPUT.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["case_id","deletion_status","steps_json"], lineterminator="\n")
            writer.writeheader(); writer.writerows(rows)
        return rows

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate", action="store_true", help="validate output schema and row count")
    args = parser.parse_args()
    log_turn("SESSION START / RUN: GhostTrace deterministic audit pipeline")
    auditor = Auditor()
    rows = auditor.run()
    if args.validate:
        errors=[]
        if len(rows) != 518: errors.append(f"expected 518 rows, got {len(rows)}")
        if len({r["case_id"] for r in rows}) != len(rows): errors.append("duplicate case_id")
        for i,r in enumerate(rows,2):
            try: steps=json.loads(r["steps_json"])
            except Exception: errors.append(f"invalid JSON at CSV row {i}"); continue
            if r["deletion_status"] not in {"COMPLETE","INCOMPLETE","NOT_APPLICABLE"}: errors.append(f"invalid status at row {i}")
            if r["deletion_status"]=="NOT_APPLICABLE" and steps: errors.append(f"NOT_APPLICABLE has steps at row {i}")
            for j,s in enumerate(steps,1):
                if s.get("step_no") != j: errors.append(f"nonconsecutive step_no at row {i}")
        report=ROOT/"evaluation"/"evaluation_report.md"
        report.parent.mkdir(exist_ok=True)
        report.write_text("# Evaluation Report\n\n## Full dataset checks\n\n- Rows: %d\n- Unique case IDs: %d\n- Schema/JSON errors: %d\n\n## Additional team-created evaluation cases\n\n1. No deletion request: expected `NOT_APPLICABLE` and `[]`.\n2. Remaining profile record: expected `INCOMPLETE` with finding, delete remediation, and absence verification.\n3. Retained security record: expected retention verification while preserving the record.\n\n## Failures and improvements\n\n- Initial baseline does not yet fully parse every multimodal evidence schema; add format-specific parsers and test against all 32 supplied sample answers before submission.\n- Do not treat reported activity results alone as proof; prefer current evidence and audit timestamps.\n" % (len(rows), len({r["case_id"] for r in rows}), len(errors)), encoding="utf-8")
        usage=ROOT/"evaluation"/"usage_report.md"
        usage.write_text("# Token Usage and Cost Report\n\nThis run uses a deterministic local Python pipeline and makes no model/API calls.\n\n- Model provider/name: None (no LLM invoked)\n- Model calls: 0\n- Input tokens: 0\n- Output tokens: 0\n- Total tokens: 0\n- Average tokens per request: 0\n- Estimated total cost: $0.00\n- Estimated cost per request: $0.00\n\nThese figures describe the local pipeline run only. If an LLM is added, update this report with measured provider usage.\n", encoding="utf-8")
        if errors:
            print("VALIDATION FAILED")
            print("\n".join(errors[:30]))
            sys.exit(1)
        print(f"Validation passed: {len(rows)} rows; reports written.")
    else:
        print(f"Wrote {len(rows)} rows to {OUTPUT}")

if __name__ == "__main__":
    main()
