#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""One record of the proof clock, from one run of deploy/gcp/deploy.sh.

    record.py --core DIR --deploy-out FILE --rc N --platform sev-snp|tdx --tag TAG
              --started ISO8601 --out-root DIR [--scrub NAME=VALUE]... [--raw-copy DIR]
              [--core-commit SHA]

deploy.sh — the one-button deployment of vault-genome/vaultgenome-core —
left its record under DIR/deploy/gcp/records/<stamp>/ and its transcript
in FILE, and exited with N. This script decides the status of the run and
writes what a stranger may see under OUT/<date>/<stamp>-<platform>/:

    record.json      the facts, parsed (schema vault-genome/proof-clock-record/v1)
    deploy.txt       the transcript of deploy.sh (the PROVEN block is in it)
    deployment.txt   instance, zone, machine, platform, release, sealer, started
    verify/          the release verified on the runner: cosign, checksums, slsa, tag, tools
    guest.tgz        the guest's record, byte for byte as the guest printed it on the serial console
    guest/           the files of that record a reader wants at hand
    failure.txt      the guest's failure block, when the guest failed

The status is "proven" only when deploy.sh exited 0, the job in the guest's
own record succeeded with the gate at EXACT, and the guest's replay of its
audit log was ok. deploy.sh itself asserts none of that (it reports what the
guest says); the clock does. Other statuses: not-exact, refused (the vault's
verifier did not admit the worker), no-capacity (no zone had the machine),
failed (anything else; the reason is kept).

Each --scrub NAME=VALUE replaces VALUE by <NAME> in every text written on
the runner's side (the transcript, verify/, failure.txt): the account the
run acted as, the project's number. The guest's files are published as the
guest wrote them. The serial console is not published (--raw-copy writes a
scrubbed copy of everything, serial console included, for a workflow
artifact).

Prints status=…, record=…, headline=… for the workflow. Exit 0 when a
record was written, whatever its status; 3 when none could be.
"""
import argparse
import base64
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile

SCHEMA = "vault-genome/proof-clock-record/v1"
GUEST_FILES = [
    "chip.txt", "steps.txt", "timeline.txt", "metadata.txt", "versions.txt", "kernel.txt", "tsm.txt",
    "runtime.txt", "provision.json", "job-submit.json", "job.json", "audit-verify.json", "audit-events.jsonl",
    "audit-public-key.pem", "sagvd-identity.json", "acp-compute-identity.json", "checksums-check.txt",
    "inputs.sha256", "sealed-files.txt", "status.txt", "finetune.json", "seal.json", "sha256sums.txt",
]
VERIFY_FILES = ["assets.sha256", "checksums.txt", "cosign.txt", "slsa.txt", "tag.txt", "tools.txt"]
BLOB_RE = re.compile(
    r"===VG-DEPLOY-BEGIN=== (\S+) size=(\d+) sha256=([0-9a-f]{64}) lines=(\d+) copy=\d+\n(.*?)===VG-DEPLOY-END===", re.S)
FAIL_RE = re.compile(r"===VG-DEPLOY-FAILED=== (\S+) ([^\n]*)\n(.*?)===VG-DEPLOY-FAILED-END===", re.S)
# what the vault's verifier says when it does not admit a worker (internal/orchestration trust reasons)
REFUSAL_RE = re.compile(
    r"trust\.(peer_unknown|measurement_revoked|peer_missing|policy_profile_not_served|stop_list_unavailable|operator_stop)"
    r"|below the floor|refus|not admitted|denied", re.I)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path):
    if not path or not os.path.isfile(path):
        return ""
    with open(path, errors="replace") as f:
        return f.read()


def kv(path):
    """key=value lines (the first value of a key wins); '== heading' lines skipped — as deploy.sh reads them."""
    d = {}
    for line in read_text(path).splitlines():
        if "=" in line and not line.startswith("=="):
            k, v = line.split("=", 1)
            d.setdefault(k, v)
    return d


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def parse_time(s):
    """2026-10-28T18:31:58.447919916Z -> aware datetime (microseconds kept, the rest dropped)."""
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1]
    if "." in s:
        head, frac = s.split(".", 1)
        s = head + "." + frac[:6]
    return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)


def stamp_time(stamp):
    return dt.datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)


def iso(t):
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def seconds_between(a, b):
    try:
        return round((parse_time(b) - parse_time(a)).total_seconds(), 1)
    except (ValueError, TypeError, AttributeError):
        return None


class Scrubber:
    def __init__(self, pairs):
        # longest value first, so that an e-mail is replaced before the project id inside it
        self.pairs = sorted([(n, v) for n, v in pairs if v], key=lambda p: -len(p[1]))

    def text(self, s):
        for name, value in self.pairs:
            s = s.replace(value, "<%s>" % name)
        return s


def clean_transcript(text):
    """deploy.sh rewrites a progress line in place with carriage returns: keep the last state of each line."""
    text = text.replace("\x1b[K", "")
    out = []
    for line in text.split("\n"):
        if "\r" in line:
            segments = [s for s in line.split("\r")]
            kept = segments[-1] if segments[-1].strip() else (segments[-2] if len(segments) > 1 else "")
            line = kept
        out.append(line.rstrip())
    return "\n".join(out).strip("\n") + "\n"


def guest_blob(serial_text):
    """The guest's record as printed on the serial console: the intact copy, checked as deploy.sh checks it."""
    for m in BLOB_RE.finditer(serial_text):
        stamp, size, digest, nlines = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
        lines = {}
        for line in m.group(5).splitlines():
            mm = re.match(r".*?@@(\d{4}) (\S+)$", line)
            if mm:
                lines[int(mm.group(1))] = mm.group(2)
        if len(lines) != nlines:
            continue
        b64 = "".join(lines[i] for i in range(nlines))
        if len(b64) != size or sha256_bytes(b64.encode()) != digest:
            continue
        return {"stamp": stamp, "b64_sha256": digest, "tgz": base64.b64decode(b64)}
    return None


def failure_block(text):
    m = FAIL_RE.search(text)
    if not m:
        return None, None
    reason = m.group(2).strip()
    lines = [re.sub(r"^.*?startup-script: ", "", l) for l in m.group(3).splitlines()]
    return reason, "\n".join(lines).strip("\n") + "\n"


def newest_record_dir(core):
    root = os.path.join(core, "deploy", "gcp", "records")
    if not os.path.isdir(root):
        return None
    dirs = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)))
    return os.path.join(root, dirs[-1]) if dirs else None


def classify(rc, transcript, rec, serial_text):
    g = os.path.join(rec, "guest") if rec else None
    job = load_json(os.path.join(g, "job.json")) if g else None
    if rc == 0 and job is not None:
        gate = job.get("gate") or {}
        audit = load_json(os.path.join(g, "audit-verify.json")) or {}
        steps_gate = (kv(os.path.join(g, "steps.txt")).get("gate_level") or "").split(" ")[0]
        if job.get("status") == "succeeded" and gate.get("level") == "EXACT" and steps_gate == "EXACT" and audit.get("ok") is True:
            return "proven", ""
        if gate.get("level") and gate.get("level") != "EXACT":
            return "not-exact", "the gate's level is %s, not EXACT (job %s)" % (gate.get("level"), job.get("status"))
        return "failed", "deploy.sh exited 0 but job=%s gate=%s audit ok=%s" % (job.get("status"), gate.get("level"), audit.get("ok"))
    if rc == 0:
        return "failed", "deploy.sh exited 0 without a guest record"
    m = re.search(r"no zone of .* had capacity[^\n]*", transcript)
    if m:
        return "no-capacity", m.group(0).strip()
    reason, block = failure_block(serial_text or "")
    if reason is None:
        reason, block = failure_block(transcript)
    if reason is not None:
        if REFUSAL_RE.search(reason) or REFUSAL_RE.search(block or ""):
            return "refused", reason
        return "failed", reason
    errors = re.findall(r"^ERROR: (.*)$", transcript, re.M)
    if errors:
        return "failed", errors[-1].strip()
    if not transcript.strip():
        return "failed", "deploy.sh did not run (exit %s before it: credentials, clone or runner)" % rc
    return "failed", "deploy.sh exit %s" % rc


def chip_info(platform, g):
    if platform == "sev-snp":
        for line in read_text(os.path.join(g, "audit-events.jsonl")).splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("kind") != "TRUST_EVALUATED":
                continue
            s = ((e.get("payload") or {}).get("peer_detail") or {}).get("sev_snp") or {}
            if not s:
                continue
            return {
                "vendor": "AMD", "product": s.get("product"), "variant": s.get("variant"), "cpuid": s.get("cpuid"),
                "chip_id_hex": s.get("chip_id_hex"),
                "tcb_reported": (s.get("tcb") or {}).get("reported"), "tcb_committed": (s.get("tcb") or {}).get("committed"),
                "firmware": (s.get("firmware") or {}).get("current"),
                "alias_check_complete": (s.get("platform_info") or {}).get("alias_check_complete"),
                "mitigation_vector_hex": (s.get("mitigation_vector") or {}).get("current_hex"),
                "guest_policy_hex": (s.get("guest_policy") or {}).get("raw_hex"),
                "platform_info_hex": (s.get("platform_info") or {}).get("raw_hex"),
                "floor": s.get("floor"), "floor_source": s.get("floor_source"),
            }
        return None
    ident = load_json(os.path.join(g, "acp-compute-identity.json")) or {}
    t = ident.get("tdx") or {}
    chip = read_text(os.path.join(g, "chip.txt"))
    fmspc = re.search(r"fmspc=(\S+)", chip)
    return {
        "vendor": "Intel", "product": "TDX", "mrtd_hex": t.get("mrtd_hex"), "rtmr_hex": t.get("rtmr_hex"),
        "fmspc": fmspc.group(1) if fmspc else None,
        "pcs_documents": sorted(f[len("pcs-"):] for f in os.listdir(g) if f.startswith("pcs-")),
    }


def chip_label(platform, chip):
    if not chip:
        return "AMD SEV-SNP" if platform == "sev-snp" else "Intel TDX"
    if platform == "sev-snp":
        return "AMD %s" % (chip.get("product") or "SEV-SNP")
    return "Intel TDX" + (" (FMSPC %s)" % chip["fmspc"] if chip.get("fmspc") else "")


def copy_text(src, dst, scrub):
    with open(dst, "w") as f:
        f.write(scrub.text(read_text(src).rstrip("\n")) + "\n")


def raw_copy(src_root, dst_root, scrub):
    """Everything, serial console included, scrubbed: text files line by line, other files as they are."""
    for base, _dirs, files in os.walk(src_root):
        for name in files:
            s = os.path.join(base, name)
            d = os.path.join(dst_root, os.path.relpath(s, src_root))
            os.makedirs(os.path.dirname(d), exist_ok=True)
            with open(s, "rb") as f:
                data = f.read()
            try:
                text = data.decode("utf-8")
                with open(d, "w") as f:
                    f.write(scrub.text(text))
            except UnicodeDecodeError:
                shutil.copyfile(s, d)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--core", required=True, help="the vaultgenome-core checkout deploy.sh ran from")
    ap.add_argument("--deploy-out", required=True, help="the transcript of deploy.sh")
    ap.add_argument("--rc", required=True, type=int, help="the exit status of deploy.sh")
    ap.add_argument("--platform", required=True, choices=["sev-snp", "tdx"])
    ap.add_argument("--tag", required=True, help="the release tag deploy.sh was asked to prove")
    ap.add_argument("--started", required=True, help="when the run started (ISO 8601, UTC)")
    ap.add_argument("--out-root", required=True, help="the records directory")
    ap.add_argument("--scrub", action="append", default=[], metavar="NAME=VALUE", help="replace VALUE by <NAME> in every text")
    ap.add_argument("--raw-copy", default=None, help="write a scrubbed copy of the whole raw record here (for an artifact)")
    ap.add_argument("--core-commit", default=None, help="the commit of vaultgenome-core deploy.sh ran from")
    a = ap.parse_args()

    scrub = Scrubber([s.split("=", 1) for s in a.scrub if "=" in s])
    rec = newest_record_dir(a.core)
    transcript = scrub.text(clean_transcript(read_text(a.deploy_out)))
    serial_text = read_text(os.path.join(rec, "serial-console.txt")) if rec else ""
    status, reason = classify(a.rc, transcript, rec, serial_text)
    reason = scrub.text(reason)

    dep = kv(os.path.join(rec, "deployment.txt")) if rec else {}
    stamp = dep.get("started") or dep.get("attached")
    started = parse_time(a.started)
    if not stamp:
        stamp = started.strftime("%Y%m%dT%H%M%SZ")
    if dep.get("platform") and dep["platform"] != a.platform:
        print("record.py: deployment.txt says platform=%s, the run says %s" % (dep["platform"], a.platform), file=sys.stderr)
        return 3
    date = "%s-%s-%s" % (stamp[0:4], stamp[4:6], stamp[6:8])
    out = os.path.join(a.out_root, date, "%s-%s" % (stamp, a.platform))
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)

    with open(os.path.join(out, "deploy.txt"), "w") as f:
        f.write(transcript)

    g = os.path.join(rec, "guest") if rec else None
    have_guest = bool(g and os.path.isfile(os.path.join(g, "steps.txt")))
    blob = None
    if rec:
        if os.path.isfile(os.path.join(rec, "deployment.txt")):
            copy_text(os.path.join(rec, "deployment.txt"), os.path.join(out, "deployment.txt"), scrub)
        v = os.path.join(rec, "verify")
        if os.path.isdir(v):
            os.makedirs(os.path.join(out, "verify"))
            for name in VERIFY_FILES:
                if os.path.isfile(os.path.join(v, name)):
                    copy_text(os.path.join(v, name), os.path.join(out, "verify", name), scrub)
        fail_reason, fail_text = failure_block(serial_text)
        if fail_text:
            with open(os.path.join(out, "failure.txt"), "w") as f:
                f.write(scrub.text(fail_text))
        blob = guest_blob(serial_text)
        if blob:
            with open(os.path.join(out, "guest.tgz"), "wb") as f:
                f.write(blob["tgz"])
        if have_guest:
            os.makedirs(os.path.join(out, "guest"))
            names = [n for n in GUEST_FILES if os.path.isfile(os.path.join(g, n))]
            names += sorted(n for n in os.listdir(g) if n.startswith("pcs-") and os.path.isfile(os.path.join(g, n)))
            for n in names:
                shutil.copyfile(os.path.join(g, n), os.path.join(out, "guest", n))

    # the facts
    steps = kv(os.path.join(g, "steps.txt")) if have_guest else {}
    tl = kv(os.path.join(g, "timeline.txt")) if have_guest else {}
    prov = (load_json(os.path.join(g, "provision.json")) if have_guest else None) or {}
    job = (load_json(os.path.join(g, "job.json")) if have_guest else None) or {}
    audit = (load_json(os.path.join(g, "audit-verify.json")) if have_guest else None) or {}
    gate = job.get("gate") or {}
    sv = gate.get("signed_verdict") or {}
    verdict = sv.get("verdict") or {}
    chip = chip_info(a.platform, g) if have_guest else None
    versions = read_text(os.path.join(g, "versions.txt")) if have_guest else ""
    mc = re.search(r"\(commit ([0-9a-f]{40})\)", versions)
    assets = read_text(os.path.join(rec, "verify", "assets.sha256")) if rec else ""
    ml = re.search(r"^([0-9a-f]{64})  checksums-%s\.txt$" % re.escape(a.tag), assets, re.M)
    tag_txt = read_text(os.path.join(rec, "verify", "tag.txt")) if rec else ""
    good = [l for l in tag_txt.splitlines() if "Good" in l]
    cosign_txt = read_text(os.path.join(rec, "verify", "cosign.txt")) if rec else ""
    slsa_txt = read_text(os.path.join(rec, "verify", "slsa.txt")) if rec else ""
    checks_txt = read_text(os.path.join(rec, "verify", "checksums.txt")) if rec else ""
    tools = {}
    if rec:  # "cosign: v2.6.5 (/path)" lines: the version only
        for line in read_text(os.path.join(rec, "verify", "tools.txt")).splitlines():
            m = re.match(r"^(cosign|slsa-verifier|gcloud): (.*)$", line)
            if m:
                tools[m.group(1)] = re.sub(r" \(.*\)$", "", m.group(2)).strip()
    guest_hashes_ok = None
    if have_guest:
        guest_hashes_ok = True
        for line in read_text(os.path.join(g, "sha256sums.txt")).splitlines():
            m = re.match(r"^([0-9a-f]{64})  (.+)$", line)
            if not m:
                continue
            p = os.path.join(g, m.group(2))
            if not os.path.isfile(p) or sha256_file(p) != m.group(1):
                guest_hashes_ok = False
    finished_guest = tl.get("finished")
    seconds = None
    if finished_guest and stamp:
        try:
            seconds = round((parse_time(finished_guest) - stamp_time(stamp)).total_seconds(), 1)
        except ValueError:
            seconds = None
    measurement = (prov.get("vault") or {}).get("measurement_hex")
    worker_measurement = (prov.get("worker") or {}).get("measurement_hex")

    env = os.environ
    run_url = None
    if env.get("GITHUB_SERVER_URL") and env.get("GITHUB_REPOSITORY") and env.get("GITHUB_RUN_ID"):
        run_url = "%s/%s/actions/runs/%s" % (env["GITHUB_SERVER_URL"], env["GITHUB_REPOSITORY"], env["GITHUB_RUN_ID"])
        if env.get("GITHUB_RUN_ATTEMPT") and env["GITHUB_RUN_ATTEMPT"] != "1":
            run_url += "/attempts/%s" % env["GITHUB_RUN_ATTEMPT"]

    record = {
        "schema": SCHEMA,
        "date": date,
        "stamp": stamp,
        "platform": a.platform,
        "status": status,
        "reason": reason,
        "proven_at": iso(parse_time(finished_guest)) if status == "proven" and finished_guest else None,
        "release": {
            "tag": a.tag,
            "commit": mc.group(1) if mc else None,
            "checksums_list_sha256": ml.group(1) if ml else None,
            "cosign": scrub.text(cosign_txt.strip().splitlines()[-1]) if cosign_txt.strip() else None,
            "checksums_ok": sum(1 for l in checks_txt.splitlines() if l.rstrip().endswith(": OK")) if checks_txt else None,
            "slsa_passed": slsa_txt.count("PASSED: SLSA verification passed") if slsa_txt else None,
            "tag_signature": good[0].strip() if good else None,
            "guest_checksums_ok": (steps.get("checksums_ok") or "").split(" ")[0] or None,
        },
        "cloud": {
            "provider": "gcp",
            "zone": dep.get("zone"),
            "region": dep["zone"].rsplit("-", 1)[0] if dep.get("zone") else None,
            "machine": dep.get("machine"),
            "instance": dep.get("instance"),
        },
        "chip": chip,
        "measurement": measurement,
        "measurements_equal": (measurement == worker_measurement) if measurement and worker_measurement else None,
        "sealer": {"vault": (prov.get("vault") or {}).get("sealer"), "worker": (prov.get("worker") or {}).get("sealer"),
                   "requested": dep.get("sealer")},
        "sealed_files": {k: len(v) for k, v in (prov.get("sealed") or {}).items()} or None,
        "settled_boot": ("reboot" in tl) if tl else None,
        "gate": {
            "level": gate.get("level"), "door": gate.get("door"), "rung": gate.get("rung"), "kind": gate.get("kind"),
            "fixtures": gate.get("fixtures"), "n_exact": verdict.get("n_exact"), "n_equivalent": verdict.get("n_equivalent"),
            "n_mismatch": verdict.get("n_mismatch"), "max_abs_err": verdict.get("max_abs_err"),
            "fixtures_hash": verdict.get("fixtures_hash"), "genome_id": verdict.get("genome_id"),
            "signer_key_id": gate.get("signer_key_id"), "signer_pub": sv.get("signer_pub"), "signature": sv.get("signature"),
            "job_id": job.get("job_id"), "job_status": job.get("status"),
        } if job else None,
        "audit": {
            "ok": audit.get("ok"), "events": audit.get("event_count"), "tip": audit.get("tip"),
            "kid": (prov.get("vault") or {}).get("audit_kid"),
            "public_key_pem": (prov.get("vault") or {}).get("audit_public_key_pem"),
        } if audit else None,
        "timing": {
            "deploy_started_at": iso(stamp_time(stamp)) if stamp else None,
            "guest_boot_at": iso(parse_time(tl["boot"])) if tl.get("boot") else None,
            "guest_finished_at": iso(parse_time(finished_guest)) if finished_guest else None,
            "button_to_record_s": seconds,
            "boot_to_verdict_s": seconds_between(tl.get("boot"), tl.get("job_done")) if tl else None,
            "guest_elapsed_s": float(steps["elapsed_seconds"]) if steps.get("elapsed_seconds") else None,
            "provision_s": seconds_between(tl.get("provision_start"), tl.get("provision_end")) if tl else None,
            "job_s": seconds_between(tl.get("job_submit"), tl.get("job_done")) if tl else None,
            "sagvd_ready_after": steps.get("sagvd_ready_after"),
            "session_opened_after": steps.get("session_opened_after"),
        },
        "guest_blob": {
            "stamp": blob["stamp"], "b64_sha256": blob["b64_sha256"], "tgz_sha256": sha256_bytes(blob["tgz"]),
            "tgz_bytes": len(blob["tgz"]), "unpacked_hashes_ok": guest_hashes_ok,
        } if blob else None,
        "run": {
            "repository": env.get("GITHUB_REPOSITORY"), "id": env.get("GITHUB_RUN_ID"), "attempt": env.get("GITHUB_RUN_ATTEMPT"),
            "url": run_url, "event": env.get("GITHUB_EVENT_NAME"), "runner_image": env.get("ImageOS"),
            "runner_image_version": env.get("ImageVersion"), "started_at": iso(started), "finished_at": iso(dt.datetime.now(dt.timezone.utc)),
            "core_commit": a.core_commit, "deploy_rc": a.rc,
            "tools": tools or None,
        },
        "files": {},
    }
    for base, _dirs, files in os.walk(out):
        for name in files:
            p = os.path.join(base, name)
            record["files"][os.path.relpath(p, out).replace(os.sep, "/")] = sha256_file(p)

    label = chip_label(a.platform, chip)
    if status == "proven":
        headline = "%s %s: proven %s on %s, EXACT %s/%s, %s s" % (
            date, a.platform, a.tag, label, gate.get("fixtures"), gate.get("fixtures"), int(seconds) if seconds else "?")
    else:
        headline = "%s %s: %s %s — %s" % (date, a.platform, status, a.tag, reason[:80] if reason else "no reason recorded")
    record["headline"] = headline
    with open(os.path.join(out, "record.json"), "w") as f:
        json.dump(record, f, indent=2, sort_keys=False)
        f.write("\n")

    if a.raw_copy:
        os.makedirs(a.raw_copy, exist_ok=True)
        with open(os.path.join(a.raw_copy, "deploy.out"), "w") as f:
            f.write(scrub.text(read_text(a.deploy_out)))
        if rec:
            raw_copy(rec, os.path.join(a.raw_copy, os.path.basename(rec)), scrub)

    print("status=%s" % status)
    print("record=%s" % out)
    print("headline=%s" % headline)
    return 0


if __name__ == "__main__":
    sys.exit(main())
