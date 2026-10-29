#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A stranger's check of one record of the proof clock.

    check-record.py RECORD_DIR [--kds] [--release]

Offline, from the record alone:
  1. guest.tgz is the record the guest printed: its sha256 is the one in
     record.json, and unpacked, every file matches the guest's own sha256sums.txt;
  2. the files under guest/ are those files, byte for byte;
  3. every published file has the sha256 record.json lists for it;
  4. the gate's verdict carries the authority's Ed25519 signature over its
     canonical bytes (compact JSON, as the daemon signs it), the signer is
     the authority key of the vault's identity, and the level is EXACT;
  5. the launch measurement is one value everywhere it appears: the vault's
     pin of the worker, the worker's pin of the vault, the vault's own
     identity, the admission event in the audit log;
  6. the guest's replay of its audit log says ok and counted as many events
     as the log lists.
With a request to the Internet:
  --kds      SEV-SNP only: AMD's key server answers for this chip at the
             TCB the verifier saw (one request to kdsintf.amd.com);
  --release  the release's signed checksums list, the five files on it and
             their SLSA provenance verify again from GitHub Releases, and
             the files downloaded now are the files the runner saw
             (needs cosign and slsa-verifier on PATH; downloads ~100 MB).
Exit 0 when every check passed, 1 otherwise. Needs python3, openssl, tar.
"""
import argparse
import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ISSUER = "https://token.actions.githubusercontent.com"
REPO = "vault-genome/vaultgenome-core"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
FAILED = []


def ok(msg):
    print("  ok    " + msg)


def fail(msg):
    FAILED.append(msg)
    print("  FAIL  " + msg)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(p):
    with open(p) as f:
        return json.load(f)


def pem_raw_key(pem):
    body = "".join(l for l in pem.strip().splitlines() if not l.startswith("-----"))
    der = base64.b64decode(body)
    return der[-32:] if len(der) == 44 and der[:12] == ED25519_SPKI_PREFIX else None


def verify_ed25519(pub_raw, msg, sig):
    with tempfile.TemporaryDirectory() as d:
        for name, data in (("pub.der", ED25519_SPKI_PREFIX + pub_raw), ("msg", msg), ("sig", sig)):
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", os.path.join(d, "pub.der"), "-keyform", "DER",
                            "-rawin", "-in", os.path.join(d, "msg"), "-sigfile", os.path.join(d, "sig")], capture_output=True, text=True)
    return r.returncode == 0 and "Verified Successfully" in r.stdout


def check_offline(rec_dir, rec):
    print("== the guest's record (guest.tgz)")
    blob = rec.get("guest_blob")
    tgz = os.path.join(rec_dir, "guest.tgz")
    members = {}
    if not blob or not os.path.isfile(tgz):
        fail("no guest.tgz in this record (status %s)" % rec.get("status"))
    else:
        digest = sha256_file(tgz)
        (ok if digest == blob["tgz_sha256"] else fail)("sha256 of guest.tgz %s record.json (%s…)" % ("is in" if digest == blob["tgz_sha256"] else "differs from", digest[:16]))
        with tarfile.open(tgz, "r:gz") as tar:
            for m in tar.getmembers():
                if m.isfile():
                    members[m.name.split("/", 1)[1]] = tar.extractfile(m).read()
        sums = members.get("sha256sums.txt", b"").decode(errors="replace")
        listed = re.findall(r"^([0-9a-f]{64})  (.+)$", sums, re.M)
        bad = [n for h, n in listed if sha256_bytes(members.get(n, b"\0missing")) != h]
        (ok if listed and not bad else fail)("%d of %d files in guest.tgz match the guest's own sha256sums.txt%s" % (
            len(listed) - len(bad), len(listed), "" if not bad else ": " + ", ".join(bad)))
    print("== the published copies")
    gdir = os.path.join(rec_dir, "guest")
    if os.path.isdir(gdir) and members:
        names = sorted(os.listdir(gdir))
        bad = [n for n in names if n not in members or sha256_file(os.path.join(gdir, n)) != sha256_bytes(members[n])]
        (ok if not bad else fail)("%d of %d files under guest/ are the guest's bytes%s" % (len(names) - len(bad), len(names), "" if not bad else ": " + ", ".join(bad)))
    files = rec.get("files") or {}
    bad = [p for p, h in files.items() if not os.path.isfile(os.path.join(rec_dir, p)) or sha256_file(os.path.join(rec_dir, p)) != h]
    extra = []
    for base, _d, ns in os.walk(rec_dir):
        for n in ns:
            rel = os.path.relpath(os.path.join(base, n), rec_dir).replace(os.sep, "/")
            if rel != "record.json" and rel not in files:
                extra.append(rel)
    (ok if not bad and not extra else fail)("%d files have the sha256 record.json lists%s%s" % (
        len(files) - len(bad), "" if not bad else "; differ: " + ", ".join(bad), "" if not extra else "; unlisted: " + ", ".join(extra)))

    print("== the gate's verdict")
    job_path = os.path.join(gdir, "job.json")
    gate = rec.get("gate") or {}
    if not os.path.isfile(job_path):
        fail("no guest/job.json")
    else:
        job = load(job_path)
        sv = (job.get("gate") or {}).get("signed_verdict") or {}
        verdict = sv.get("verdict") or {}
        msg = json.dumps(verdict, separators=(",", ":"), ensure_ascii=False).encode()
        try:
            sig, pub = base64.b64decode(sv.get("signature", "")), base64.b64decode(sv.get("signer_pub", ""))
        except ValueError:
            sig, pub = b"", b""
        good = len(pub) == 32 and len(sig) == 64 and verify_ed25519(pub, msg, sig)
        (ok if good else fail)("Ed25519 signature over the verdict's canonical bytes (%d bytes) verifies with signer_pub" % len(msg))
        ident = load(os.path.join(gdir, "sagvd-identity.json")) if os.path.isfile(os.path.join(gdir, "sagvd-identity.json")) else {}
        auth_raw = pem_raw_key(ident.get("authority_public_key_pem", ""))
        (ok if auth_raw and auth_raw == pub else fail)("signer_pub is the authority key of the vault's identity (%s)" % ident.get("authority_kid"))
        (ok if (job.get("gate") or {}).get("signer_key_id") == ident.get("authority_kid") else fail)("signer_key_id %s = authority_kid %s" % ((job.get("gate") or {}).get("signer_key_id"), ident.get("authority_kid")))
        level = verdict.get("level")
        (ok if level == "EXACT" and (job.get("gate") or {}).get("level") == "EXACT" else fail)(
            "level %s: %s of %s fixtures exact, max_abs_err %s" % (level, verdict.get("n_exact"), (job.get("gate") or {}).get("fixtures"), verdict.get("max_abs_err")))
        (ok if gate.get("signature") == sv.get("signature") and gate.get("level") == level else fail)("record.json quotes this verdict")

    print("== the launch measurement")
    prov = load(os.path.join(gdir, "provision.json")) if os.path.isfile(os.path.join(gdir, "provision.json")) else {}
    seen = {
        "vault's pin of the worker": (prov.get("worker") or {}).get("measurement_hex"),
        "worker's pin of the vault": (prov.get("vault") or {}).get("measurement_hex"),
        "the vault's identity": (load(os.path.join(gdir, "sagvd-identity.json")) if os.path.isfile(os.path.join(gdir, "sagvd-identity.json")) else {}).get("tee_measurement_hex"),
        "record.json": rec.get("measurement"),
    }
    ev_path = os.path.join(gdir, "audit-events.jsonl")
    if os.path.isfile(ev_path):
        for line in open(ev_path):
            e = json.loads(line)
            if e.get("kind") == "TRUST_EVALUATED":
                seen["the admission event (TRUST_EVALUATED)"] = (e.get("payload") or {}).get("peer_measurement_hex")
                break
    values = {v for v in seen.values()}
    (ok if len(values) == 1 and None not in values else fail)("one value in %d places: %s" % (len(seen), ", ".join(k for k in seen) if len(values) == 1 else json.dumps(seen, indent=1)))

    print("== the audit log")
    av = load(os.path.join(gdir, "audit-verify.json")) if os.path.isfile(os.path.join(gdir, "audit-verify.json")) else {}
    n = sum(1 for l in open(ev_path) if l.strip()) if os.path.isfile(ev_path) else 0
    (ok if av.get("ok") is True and av.get("event_count") == n else fail)("the guest's replay: ok=%s, %s events verified, %d events listed" % (av.get("ok"), av.get("event_count"), n))
    print("  note  the chain's hashes and signatures were replayed on the guest (acpctl audit verify); replaying them here needs the audit database, which the record does not carry")


def check_kds(rec):
    print("== AMD's key server (KDS)")
    c = rec.get("chip") or {}
    if rec.get("platform") != "sev-snp" or not c.get("chip_id_hex"):
        print("  skip  not a SEV-SNP record")
        return
    t = c.get("tcb_reported") or {}
    url = "https://kdsintf.amd.com/vcek/v1/%s/%s?blSPL=%s&teeSPL=%s&snpSPL=%s&ucodeSPL=%s" % (
        c["product"], c["chip_id_hex"], t.get("bootloader"), t.get("tee"), t.get("snp"), t.get("microcode"))
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            der = r.read()
    except Exception as e:  # noqa: BLE001 - any failure is the same answer to the reader
        fail("no VCEK from KDS for this chip at this TCB: %s" % e)
        return
    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f:
        f.write(der)
        path = f.name
    r = subprocess.run(["openssl", "x509", "-inform", "der", "-in", path, "-noout", "-subject", "-issuer"], capture_output=True, text=True)
    os.unlink(path)
    good = r.returncode == 0 and "CN=SEV-VCEK" in r.stdout and ("CN=SEV-%s" % c["product"]) in r.stdout
    (ok if good else fail)("KDS answers with a VCEK for this chip at TCB snp=%s microcode=%s (issuer SEV-%s)" % (t.get("snp"), t.get("microcode"), c["product"]))


def check_release(rec_dir, rec):
    print("== the release, from GitHub Releases now")
    tag = (rec.get("release") or {}).get("tag")
    for tool in ("cosign", "slsa-verifier"):
        if not shutil.which(tool):
            fail("%s is needed on PATH for --release" % tool)
            return
    assets_txt = os.path.join(rec_dir, "verify", "assets.sha256")
    if not os.path.isfile(assets_txt):
        fail("no verify/assets.sha256 in this record")
        return
    runner_saw = dict((n, h) for h, n in re.findall(r"^([0-9a-f]{64})  (.+)$", open(assets_txt).read(), re.M))
    lst = "checksums-%s.txt" % tag
    names = [lst, lst + ".sig", lst + ".cert", "multiple.intoto.jsonl", "sagvd", "acp-compute", "acpctl", "acp-keygen", "genome-worker-%s.tar.gz" % tag]
    d = tempfile.mkdtemp(prefix="proof-clock-release-")
    try:
        same = 0
        for n in names:
            url = "https://github.com/%s/releases/download/%s/%s" % (REPO, tag, n)
            with urllib.request.urlopen(url, timeout=300) as r, open(os.path.join(d, n), "wb") as f:
                shutil.copyfileobj(r, f)
            if sha256_file(os.path.join(d, n)) == runner_saw.get(n):
                same += 1
        (ok if same == len(names) else fail)("%d of %d files downloaded now are the bytes the runner verified (verify/assets.sha256)" % (same, len(names)))
        identity = "https://github.com/%s/.github/workflows/release.yml@refs/tags/%s" % (REPO, tag)
        r = subprocess.run(["cosign", "verify-blob", "--signature", lst + ".sig", "--certificate", lst + ".cert",
                            "--certificate-identity", identity, "--certificate-oidc-issuer", ISSUER, lst], cwd=d, capture_output=True, text=True)
        (ok if r.returncode == 0 else fail)("cosign: %s signed by %s" % (lst, identity))
        listed = dict((n, h) for h, n in re.findall(r"^([0-9a-f]{64})  (.+)$", open(os.path.join(d, lst)).read(), re.M))
        five = ["sagvd", "acp-compute", "acpctl", "acp-keygen", "genome-worker-%s.tar.gz" % tag]
        on_list = sum(1 for n in five if listed.get(n) == sha256_file(os.path.join(d, n)))
        (ok if on_list == 5 else fail)("%d of 5 files are on the signed list" % on_list)
        passed = 0
        for n in five:
            r = subprocess.run(["slsa-verifier", "verify-artifact", n, "--provenance-path", "multiple.intoto.jsonl",
                                "--source-uri", "github.com/" + REPO, "--source-tag", tag], cwd=d, capture_output=True, text=True)
            passed += 1 if r.returncode == 0 and "PASSED: SLSA verification passed" in (r.stdout + r.stderr) else 0
        (ok if passed == 5 else fail)("slsa-verifier: %d of 5 provenances pass against github.com/%s@%s" % (passed, REPO, tag))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("record_dir")
    ap.add_argument("--kds", action="store_true")
    ap.add_argument("--release", action="store_true")
    a = ap.parse_args()
    rec = load(os.path.join(a.record_dir, "record.json"))
    print("record %s: %s %s, status %s" % (rec.get("stamp"), rec.get("platform"), (rec.get("release") or {}).get("tag"), rec.get("status")))
    check_offline(a.record_dir, rec)
    if a.kds:
        check_kds(rec)
    if a.release:
        check_release(a.record_dir, rec)
    print("== %s" % ("every check passed" if not FAILED else "%d check(s) failed" % len(FAILED)))
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
