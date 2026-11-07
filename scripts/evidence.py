#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Evidence ledger: content-addressed Evidence records, Residual Unknowns, bundles, claim checks.

The ledger lives at <workdir>/evidence.json and is always written canonically
(sorted, byte-stable), so the file itself is the exportable bundle.

Commands (all print JSON):
  record     Add one Evidence record (idempotent; conflicting content under the same ID is rejected)
               --from FILE|-            JSON produced by run_provider.py / js_bundle.py / diff_versions.py
               or: --target PATH --provider ID [--provider-version V] --operation OP
                   [--params JSON] --result JSON [--raw-file PATH] [--authority A] [--confidence C]
                   [--limitation TEXT]... [--location LOC]... [--link EVID]...
             Inference shortcut:
               --infer "statement" --link EVID [--link EVID]...   (authority = analyst-inference)
  show ID    Summary of one record. --full for everything, --field PATH --page N --page-size M to page a list.
  list       One line per record. Filters: --operation, --target-sha, --authority.
  unknown add     --question Q --severity low|medium|high --domain D [--target PATH] [--supporting EVID]... [--contradicting EVID]...
  unknown update  ID --expected-revision N [--status open|investigating|resolved|wont-resolve]
                  [--resolution TEXT] [--add-supporting EVID]... [--add-contradicting EVID]... [--severity S]
  unknown list    [--status S]
  export PATH [--overwrite]    Write the canonical bundle elsewhere (byte-identical to the ledger).
  import PATH                  Validate the whole bundle, then merge atomically (all or nothing).
  validate [PATH]              Recompute every ID, check links and canonical bytes.
  verify CLAIMS.json           Evaluate claims against the ledger -> pass | fail | unknown per claim.

Global: --workdir DIR (default ./re-work or $RE_WORKDIR)

Authorities: shipped-artifact | controlled-replay | historical-reference | external-service | analyst-inference
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (atomic_write_text, canonical_json, emit, fail, sha256_bytes,  # noqa: E402
                     sha256_file, subject_for, workdir_path)

AUTHORITIES = ["shipped-artifact", "controlled-replay", "historical-reference", "external-service",
               "analyst-inference"]
CONFIDENCE = ["high", "medium", "low"]
UNKNOWN_STATUS = ["open", "investigating", "resolved", "wont-resolve"]
SEVERITY = ["low", "medium", "high"]
BUNDLE_VERSION = 1


# --------------------------------------------------------------------------- ids + serialization

def evidence_id_for(rec: dict) -> str:
    identity = {
        "subject_sha256": (rec.get("subject") or {}).get("sha256"),
        "provider": {"id": rec["provider"]["id"], "version": rec["provider"].get("version")},
        "operation": rec["operation"],
        "parameters": rec.get("parameters") or {},
        "normalized_result": rec.get("normalized_result"),
    }
    return "ev-" + sha256_bytes(canonical_json(identity).encode())[:20]


def unknown_id_for(question: str, subject_sha: str | None) -> str:
    return "unk-" + sha256_bytes(canonical_json({"q": question.strip(), "s": subject_sha}).encode())[:16]


def serialize(bundle: dict) -> str:
    b = {
        "bundle_version": BUNDLE_VERSION,
        "records": sorted(bundle["records"], key=lambda r: r["evidence_id"]),
        "unknowns": sorted(bundle["unknowns"], key=lambda u: u["unknown_id"]),
    }
    subjects = {}
    providers = {}
    for r in b["records"]:
        s = r.get("subject") or {}
        if s.get("sha256"):
            subjects[s["sha256"]] = {k: s.get(k) for k in ("sha256", "format", "arch", "size", "digest_kind")}
        p = r["provider"]
        providers[f'{p["id"]}@{p.get("version")}'] = {"id": p["id"], "version": p.get("version")}
    b["subjects"] = [subjects[k] for k in sorted(subjects)]
    b["providers"] = [providers[k] for k in sorted(providers)]
    return json.dumps(b, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def empty_bundle() -> dict:
    return {"records": [], "unknowns": []}


@contextlib.contextmanager
def ledger(workdir, write=False):
    w = workdir_path(workdir)
    path = w / "evidence.json"
    lock = open(w / ".ledger.lock", "w")
    fcntl.flock(lock, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
    try:
        bundle = json.loads(path.read_text()) if path.exists() else empty_bundle()
        state = {"bundle": bundle, "path": path, "dirty": False}
        try:
            yield state
        except SystemExit as e:  # emit() exits inside the block: persist successful writes first
            if write and state["dirty"] and not e.code:
                atomic_write_text(path, serialize(state["bundle"]))
            raise
        if write and state["dirty"]:
            atomic_write_text(path, serialize(state["bundle"]))
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


def index(bundle):
    return {r["evidence_id"]: r for r in bundle["records"]}, {u["unknown_id"]: u for u in bundle["unknowns"]}


# --------------------------------------------------------------------------- record

def build_record(d: dict) -> dict:
    for k in ("provider", "operation"):
        if k not in d:
            fail(f"record is missing '{k}'")
    if isinstance(d["provider"], str):
        d["provider"] = {"id": d["provider"], "version": None}
    authority = d.get("authority", "shipped-artifact")
    if authority not in AUTHORITIES:
        fail(f"authority must be one of {AUTHORITIES}")
    confidence = d.get("confidence", "high")
    if confidence not in CONFIDENCE:
        fail(f"confidence must be one of {CONFIDENCE}")
    rec = {
        "subject": d.get("subject"),
        "provider": {"id": d["provider"]["id"], "version": d["provider"].get("version")},
        "operation": d["operation"],
        "parameters": d.get("parameters") or {},
        "normalized_result": d.get("normalized_result"),
        "raw_result": d.get("raw_result"),
        "authority": authority,
        "confidence": confidence,
        "limitations": sorted(set(d.get("limitations") or [])),
        "locations": sorted(set(d.get("locations") or [])),
        "evidence_links": sorted(set(d.get("evidence_links") or [])),
        "environment": d.get("environment") or {"host": os.uname().sysname, "isolation": "none"},
    }
    rec["evidence_id"] = evidence_id_for(rec)
    return rec


def add_record(workdir, d: dict) -> dict:
    """Library entry point used by run_provider/js_bundle/diff_versions --record. Does not exit."""
    rec = build_record(dict(d))
    with ledger(workdir, write=True) as st:
        recs, _ = index(st["bundle"])
        missing = [l for l in rec["evidence_links"] if l not in recs]
        if missing:
            return {"evidence_id": None, "status": "rejected", "error": f"linked evidence missing: {missing}"}
        old = recs.get(rec["evidence_id"])
        if old is not None:
            same = canonical_json(old) == canonical_json(rec)
            return {"evidence_id": rec["evidence_id"], "status": "existing" if same else "conflict"}
        st["bundle"]["records"].append(rec)
        st["dirty"] = True
    return {"evidence_id": rec["evidence_id"], "status": "recorded"}


def finish(payload: dict, workdir, record: bool, summary: dict) -> None:
    """Print a provider result summary-first; optionally record it as Evidence."""
    out = {"ok": True, "summary": summary}
    if record:
        out["recorded"] = add_record(workdir, payload)
    else:
        out["evidence"] = payload
        out["hint"] = "re-run with --record (or pipe to evidence.py record --from -) to add this to the ledger"
    if payload.get("raw_result"):
        out["raw_result"] = payload["raw_result"]
    if payload.get("limitations"):
        out["limitations"] = payload["limitations"]
    emit(out)


def cmd_record(a):
    if a.infer:
        if not a.link:
            fail("an inference must link the evidence it is based on (--link EVID)")
        d = {"provider": {"id": "analyst", "version": None}, "operation": "analyst-inference",
             "parameters": {"statement": a.infer}, "normalized_result": {"statement": a.infer, "based_on": sorted(a.link)},
             "authority": "analyst-inference", "confidence": a.confidence or "medium",
             "evidence_links": a.link, "limitations": a.limitation or []}
    elif a.from_file:
        raw = sys.stdin.read() if a.from_file == "-" else open(a.from_file).read()
        d = json.loads(raw)
        d = d.get("evidence", d)  # run_provider wraps its payload under "evidence"
        if a.authority:
            d["authority"] = a.authority
        if a.confidence:
            d["confidence"] = a.confidence
        d["limitations"] = (d.get("limitations") or []) + (a.limitation or [])
        d["evidence_links"] = (d.get("evidence_links") or []) + (a.link or [])
    else:
        if not (a.provider and a.operation and a.result is not None):
            fail("need --from, --infer, or --provider/--operation/--result")
        raw_result = None
        if a.raw_file:
            raw_result = {"path": os.path.abspath(a.raw_file), "sha256": sha256_file(a.raw_file),
                          "bytes": os.path.getsize(a.raw_file)}
        d = {"subject": subject_for(a.target) if a.target else None,
             "provider": {"id": a.provider, "version": a.provider_version}, "operation": a.operation,
             "parameters": json.loads(a.params) if a.params else {}, "normalized_result": json.loads(a.result),
             "raw_result": raw_result, "authority": a.authority or "shipped-artifact",
             "confidence": a.confidence or "high", "limitations": a.limitation or [],
             "locations": a.location or [], "evidence_links": a.link or []}
    rec = build_record(d)
    with ledger(a.workdir, write=True) as st:
        recs, _ = index(st["bundle"])
        missing = [l for l in rec["evidence_links"] if l not in recs]
        if missing:
            fail("linked evidence not in ledger", missing=missing)
        old = recs.get(rec["evidence_id"])
        if old is not None:
            if canonical_json(old) == canonical_json(rec):
                emit({"ok": True, "evidence_id": rec["evidence_id"], "status": "existing"})
            fail("conflicting record: same identity, different authority/limitations/links",
                 evidence_id=rec["evidence_id"], code=3)
        st["bundle"]["records"].append(rec)
        st["dirty"] = True
    emit({"ok": True, "evidence_id": rec["evidence_id"], "status": "recorded", "operation": rec["operation"],
          "authority": rec["authority"]})


# --------------------------------------------------------------------------- show / list

def get_path(obj, path: str):
    cur = obj
    for part in [p for p in path.split(".") if p]:
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(part)
    return cur


def summarize(value, depth=0):
    if isinstance(value, list):
        return {"type": "list", "length": len(value), "first": [summarize(v, depth + 1) for v in value[:3]]} if depth < 2 else f"list[{len(value)}]"
    if isinstance(value, dict):
        return {k: summarize(v, depth + 1) for k, v in list(value.items())[:25]} if depth < 2 else f"dict[{len(value)}]"
    if isinstance(value, str) and len(value) > 300:
        return value[:300] + f"... ({len(value)} chars)"
    return value


def cmd_show(a):
    with ledger(a.workdir) as st:
        recs, _ = index(st["bundle"])
    rec = recs.get(a.id)
    if not rec:
        fail(f"no such evidence: {a.id}")
    if a.field:
        try:
            v = get_path(rec, a.field)
        except (KeyError, IndexError, ValueError):
            fail(f"field not found: {a.field}")
        if isinstance(v, list):
            start = a.page * a.page_size
            emit({"ok": True, "evidence_id": a.id, "field": a.field, "total": len(v), "page": a.page,
                  "page_size": a.page_size, "items": v[start:start + a.page_size]})
        emit({"ok": True, "evidence_id": a.id, "field": a.field, "value": v})
    if a.full:
        emit({"ok": True, "record": rec})
    out = dict(rec)
    out["normalized_result"] = summarize(rec.get("normalized_result"))
    emit({"ok": True, "record": out, "hint": "use --field normalized_result.<key> --page N to read lists; --full for everything"})


def cmd_list(a):
    with ledger(a.workdir) as st:
        b = st["bundle"]
    rows = []
    for r in sorted(b["records"], key=lambda r: r["evidence_id"]):
        s = r.get("subject") or {}
        if a.operation and r["operation"] != a.operation:
            continue
        if a.target_sha and s.get("sha256") != a.target_sha:
            continue
        if a.authority and r["authority"] != a.authority:
            continue
        rows.append({"evidence_id": r["evidence_id"], "operation": r["operation"], "provider": r["provider"]["id"],
                     "authority": r["authority"], "confidence": r["confidence"],
                     "subject": (s.get("path") or "")[-60:], "limitations": len(r["limitations"])})
    emit({"ok": True, "count": len(rows), "records": rows,
          "unknowns_open": sum(1 for u in b["unknowns"] if u["status"] in ("open", "investigating"))})


# --------------------------------------------------------------------------- unknowns

def cmd_unknown(a):
    with ledger(a.workdir, write=a.ucmd in ("add", "update")) as st:
        recs, unks = index(st["bundle"])
        if a.ucmd == "list":
            rows = [u for u in st["bundle"]["unknowns"] if not a.status or u["status"] == a.status]
            emit({"ok": True, "count": len(rows), "unknowns": sorted(rows, key=lambda u: u["unknown_id"])})
        if a.ucmd == "add":
            refs = (a.supporting or []) + (a.contradicting or [])
            missing = [r for r in refs if r not in recs]
            if missing:
                fail("referenced evidence not in ledger", missing=missing)
            sha = subject_for(a.target)["sha256"] if a.target else None
            uid = unknown_id_for(a.question, sha)
            if uid in unks:
                emit({"ok": True, "unknown_id": uid, "status": "existing", "revision": unks[uid]["revision"]})
            u = {"unknown_id": uid, "question": a.question, "severity": a.severity, "domain": a.domain,
                 "subject_sha256": sha, "status": "open", "revision": 1, "resolution": None,
                 "supporting_evidence_ids": sorted(set(a.supporting or [])),
                 "contradicting_evidence_ids": sorted(set(a.contradicting or [])),
                 "history": [{"revision": 1, "status": "open", "at": time.strftime("%Y-%m-%dT%H:%M:%S")}]}
            st["bundle"]["unknowns"].append(u)
            st["dirty"] = True
            emit({"ok": True, "unknown_id": uid, "revision": 1, "status": "open"})
        # update
        u = unks.get(a.id)
        if not u:
            fail(f"no such unknown: {a.id}")
        if a.expected_revision != u["revision"]:
            fail("revision mismatch: someone else updated this unknown; re-read it first",
                 expected=a.expected_revision, actual=u["revision"], code=3)
        refs = (a.add_supporting or []) + (a.add_contradicting or [])
        missing = [r for r in refs if r not in recs]
        if missing:
            fail("referenced evidence not in ledger", missing=missing)
        u["supporting_evidence_ids"] = sorted(set(u["supporting_evidence_ids"]) | set(a.add_supporting or []))
        u["contradicting_evidence_ids"] = sorted(set(u["contradicting_evidence_ids"]) | set(a.add_contradicting or []))
        if a.severity:
            u["severity"] = a.severity
        if a.resolution:
            u["resolution"] = a.resolution
        if a.status:
            if a.status == "resolved" and not (u["resolution"] and u["supporting_evidence_ids"]):
                fail("resolving needs --resolution text and at least one supporting evidence ID")
            u["status"] = a.status
        u["revision"] += 1
        u["history"].append({"revision": u["revision"], "status": u["status"], "at": time.strftime("%Y-%m-%dT%H:%M:%S")})
        st["dirty"] = True
        emit({"ok": True, "unknown_id": u["unknown_id"], "revision": u["revision"], "status": u["status"]})


# --------------------------------------------------------------------------- validate / export / import

def validate_bundle(b: dict, raw_text: str | None = None) -> list[str]:
    problems = []
    if not isinstance(b, dict) or "records" not in b or "unknowns" not in b:
        return ["not an evidence bundle (needs records + unknowns)"]
    seen = set()
    for r in b["records"]:
        try:
            expect = evidence_id_for(r)
        except (KeyError, TypeError) as e:
            problems.append(f"malformed record: {e}")
            continue
        if r.get("evidence_id") != expect:
            problems.append(f"{r.get('evidence_id')}: id does not match content (expected {expect})")
        if r["evidence_id"] in seen:
            problems.append(f"{r['evidence_id']}: duplicate")
        seen.add(r["evidence_id"])
        if r.get("authority") not in AUTHORITIES:
            problems.append(f"{r['evidence_id']}: bad authority")
    for r in b["records"]:
        for l in r.get("evidence_links") or []:
            if l not in seen:
                problems.append(f"{r['evidence_id']}: links missing {l}")
    for u in b["unknowns"]:
        for l in (u.get("supporting_evidence_ids") or []) + (u.get("contradicting_evidence_ids") or []):
            if l not in seen:
                problems.append(f"{u['unknown_id']}: references missing {l}")
        if u.get("status") not in UNKNOWN_STATUS:
            problems.append(f"{u['unknown_id']}: bad status")
    if raw_text is not None and not problems and serialize(b) != raw_text:
        problems.append("file is not in canonical form (re-export it with evidence.py export)")
    return problems


def cmd_validate(a):
    path = a.path or str(workdir_path(a.workdir) / "evidence.json")
    text = open(path).read()
    probs = validate_bundle(json.loads(text), text)
    emit({"ok": not probs, "path": path, "problems": probs}, 0 if not probs else 1)


def cmd_export(a):
    if os.path.exists(a.path) and not a.overwrite:
        fail(f"{a.path} exists; pass --overwrite")
    with ledger(a.workdir) as st:
        text = serialize(st["bundle"])
        b = st["bundle"]
    atomic_write_text(a.path, text)
    emit({"ok": True, "path": os.path.abspath(a.path), "bytes": len(text.encode()), "sha256": sha256_bytes(text.encode()),
          "records": len(b["records"]), "unknowns": len(b["unknowns"])})


def cmd_import(a):
    text = open(a.path).read()
    incoming = json.loads(text)
    probs = validate_bundle(incoming)
    if probs:
        fail("bundle rejected; nothing imported", problems=probs)
    with ledger(a.workdir, write=True) as st:
        recs, unks = index(st["bundle"])
        conflicts = [r["evidence_id"] for r in incoming["records"]
                     if r["evidence_id"] in recs and canonical_json(recs[r["evidence_id"]]) != canonical_json(r)]
        conflicts += [u["unknown_id"] for u in incoming["unknowns"]
                      if u["unknown_id"] in unks and unks[u["unknown_id"]]["revision"] > u["revision"]]
        if conflicts:
            fail("bundle conflicts with ledger; nothing imported", conflicts=conflicts, code=3)
        added = [r for r in incoming["records"] if r["evidence_id"] not in recs]
        st["bundle"]["records"].extend(added)
        newer = {u["unknown_id"]: u for u in incoming["unknowns"]
                 if u["unknown_id"] not in unks or unks[u["unknown_id"]]["revision"] < u["revision"]}
        st["bundle"]["unknowns"] = [u for u in st["bundle"]["unknowns"] if u["unknown_id"] not in newer] + list(newer.values())
        st["dirty"] = bool(added or newer)
        total = len(st["bundle"]["records"])
    emit({"ok": True, "imported": len(added), "unknowns_added_or_updated": len(newer), "total": total})


# --------------------------------------------------------------------------- verify

def check_expect(rec, e):
    try:
        v = get_path(rec, e["path"])
    except (KeyError, IndexError, ValueError):
        return False, f"{e['path']} not present"
    if "equals" in e:
        return v == e["equals"], f"{e['path']} == {e['equals']!r} -> {v!r}"[:200]
    if "contains" in e:
        needle = e["contains"]
        if isinstance(v, str):
            ok = needle in v
        elif isinstance(v, list):
            ok = any(needle == x or (isinstance(x, str) and needle in x) or
                     (isinstance(x, dict) and needle in canonical_json(x)) for x in v)
        elif isinstance(v, dict):
            ok = needle in v or needle in canonical_json(v)
        else:
            ok = False
        return ok, f"{e['path']} contains {needle!r}: {ok}"
    if "min" in e:
        n = len(v) if isinstance(v, (list, dict, str)) else v
        return n >= e["min"], f"{e['path']} >= {e['min']} -> {n}"
    return False, "expect needs equals | contains | min"


def cmd_verify(a):
    spec = json.load(open(a.claims))
    claims = spec["claims"] if isinstance(spec, dict) else spec
    with ledger(a.workdir) as st:
        recs, unks = index(st["bundle"])
    open_unks = [u for u in unks.values() if u["status"] in ("open", "investigating")]
    results = []
    for c in claims:
        cid, ev = c.get("id"), c.get("evidence_ids") or []
        reasons, probes, status = [], [], "pass"
        missing = [e for e in ev if e not in recs]
        cited = [recs[e] for e in ev if e in recs]
        if missing:
            status = "fail"
            reasons.append(f"cites evidence not in ledger: {missing}")
        if not ev:
            status = "unknown"
            reasons.append("no evidence cited")
            probes.append("run the operation that would observe this directly, then cite its evidence ID")
        if cited and c.get("kind", "observation") == "observation" and all(r["authority"] == "analyst-inference" for r in cited):
            status = "fail"
            reasons.append("labelled as observation but only analyst inference supports it")
        if c.get("runtime") and not any(r["authority"] == "controlled-replay" for r in cited):
            status = "fail"
            reasons.append("claims runtime behaviour but no controlled-replay (runtime) evidence is cited; static analysis does not observe execution")
            probes.append("observe it at runtime (lldb/frida/strace) with user approval, or restate the claim as a static inference")
        req = c.get("requires_authority")
        if req and cited and not any(r["authority"] in req for r in cited):
            status = "fail"
            reasons.append(f"needs authority in {req}")
        for e in c.get("expect") or []:
            rec = recs.get(e.get("evidence_id"))
            if not rec:
                status = "fail"
                reasons.append(f"expect references missing evidence {e.get('evidence_id')}")
                continue
            ok, why = check_expect(rec, e)
            reasons.append(why)
            if not ok:
                status = "fail"
        # Open Unknowns only weaken a claim when they actually bear on it:
        #  - the Unknown lists cited evidence as *contradicting* (the evidence is disputed), or
        #  - the claim explicitly declares it depends on that Unknown.
        # An Unknown that merely cites the same evidence as context (a follow-up question
        # raised by it) does not make an otherwise supported claim unknown.
        depends = set(c.get("depends_on_unknowns") or [])
        missing_unks = sorted(depends - set(unks))
        if missing_unks:
            status = "fail"
            reasons.append(f"depends_on_unknowns references unknowns not in ledger: {missing_unks}")
        for u in open_unks:
            disputed = set(ev) & set(u["contradicting_evidence_ids"])
            if disputed or u["unknown_id"] in depends:
                if status == "pass":
                    status = "unknown"
                why = f"evidence {sorted(disputed)} is contradicted by" if disputed else "declared dependency on"
                reasons.append(f"{why} unresolved {u['unknown_id']}: {u['question']}")
                probes.append(f"resolve {u['unknown_id']} first")
            elif set(ev) & set(u["supporting_evidence_ids"]):
                reasons.append(f"note: open follow-up {u['unknown_id']} cites the same evidence ({u['question']}); "
                               f"add it to depends_on_unknowns if this claim actually relies on it")
        for uid in depends:
            u = unks.get(uid)
            if u and u["status"] == "wont-resolve" and status == "pass":
                status = "unknown"
                reasons.append(f"declared dependency {uid} was closed as wont-resolve")
        for r in cited:
            for lim in r["limitations"]:
                reasons.append(f"limitation ({r['evidence_id']}): {lim}")
        results.append({"id": cid, "statement": c.get("statement"), "kind": c.get("kind", "observation"),
                        "status": status, "evidence_ids": ev, "reasons": reasons, "probes": probes})
    overall = "fail" if any(r["status"] == "fail" for r in results) else (
        "unknown" if any(r["status"] == "unknown" for r in results) else "pass")
    emit({"ok": True, "overall": overall,
          "summary": {s: sum(1 for r in results if r["status"] == s) for s in ("pass", "fail", "unknown")},
          "claims": results, "open_unknowns": [u["unknown_id"] for u in open_unks]})


# --------------------------------------------------------------------------- cli

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workdir")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("record")
    r.add_argument("--from", dest="from_file")
    r.add_argument("--infer")
    r.add_argument("--target")
    r.add_argument("--provider")
    r.add_argument("--provider-version")
    r.add_argument("--operation")
    r.add_argument("--params")
    r.add_argument("--result")
    r.add_argument("--raw-file")
    r.add_argument("--authority", choices=AUTHORITIES)
    r.add_argument("--confidence", choices=CONFIDENCE)
    r.add_argument("--limitation", action="append")
    r.add_argument("--location", action="append")
    r.add_argument("--link", action="append")
    r.set_defaults(fn=cmd_record)

    s = sub.add_parser("show")
    s.add_argument("id")
    s.add_argument("--full", action="store_true")
    s.add_argument("--field")
    s.add_argument("--page", type=int, default=0)
    s.add_argument("--page-size", type=int, default=50)
    s.set_defaults(fn=cmd_show)

    l = sub.add_parser("list")
    l.add_argument("--operation")
    l.add_argument("--target-sha")
    l.add_argument("--authority")
    l.set_defaults(fn=cmd_list)

    u = sub.add_parser("unknown")
    us = u.add_subparsers(dest="ucmd", required=True)
    ua = us.add_parser("add")
    ua.add_argument("--question", required=True)
    ua.add_argument("--severity", choices=SEVERITY, default="medium")
    ua.add_argument("--domain", default="general")
    ua.add_argument("--target")
    ua.add_argument("--supporting", action="append")
    ua.add_argument("--contradicting", action="append")
    uu = us.add_parser("update")
    uu.add_argument("id")
    uu.add_argument("--expected-revision", type=int, required=True)
    uu.add_argument("--status", choices=UNKNOWN_STATUS)
    uu.add_argument("--resolution")
    uu.add_argument("--severity", choices=SEVERITY)
    uu.add_argument("--add-supporting", action="append")
    uu.add_argument("--add-contradicting", action="append")
    ul = us.add_parser("list")
    ul.add_argument("--status", choices=UNKNOWN_STATUS)
    u.set_defaults(fn=cmd_unknown)

    e = sub.add_parser("export")
    e.add_argument("path")
    e.add_argument("--overwrite", action="store_true")
    e.set_defaults(fn=cmd_export)

    i = sub.add_parser("import")
    i.add_argument("path")
    i.set_defaults(fn=cmd_import)

    v = sub.add_parser("validate")
    v.add_argument("path", nargs="?")
    v.set_defaults(fn=cmd_validate)

    vf = sub.add_parser("verify")
    vf.add_argument("claims")
    vf.set_defaults(fn=cmd_verify)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
