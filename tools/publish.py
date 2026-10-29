#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Commit files to a branch through GitHub's API, as this workflow run.

    publish.py --repo OWNER/NAME --branch main --headline TEXT [--body TEXT] PATH...

createCommitOnBranch makes the commit on GitHub's side from the run's own
token: no git identity and no key on the runner, and GitHub signs the
commit, so a reader sees "Verified" and the run it came from in the
message. PATHs are files or directories, relative to the repository root.
Needs gh on PATH with GH_TOKEN set.
"""
import argparse
import base64
import json
import os
import subprocess
import sys

MUTATION = """mutation($input: CreateCommitOnBranchInput!) {
  createCommitOnBranch(input: $input) { commit { oid url } }
}"""


def gh(args, stdin=None):
    r = subprocess.run(["gh", "api"] + args, input=stdin, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("gh api %s: %s" % (" ".join(args[:1]), (r.stderr or r.stdout).strip()))
    return r.stdout


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--branch", default="main")
    ap.add_argument("--headline", required=True)
    ap.add_argument("--body", default="")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args()

    files = []
    for p in a.paths:
        if os.path.isdir(p):
            for base, _dirs, names in os.walk(p):
                files += [os.path.join(base, n) for n in names]
        elif os.path.isfile(p):
            files.append(p)
        else:
            sys.exit("publish.py: no such file: %s" % p)
    additions = []
    for f in sorted(set(files)):
        with open(f, "rb") as fh:
            additions.append({"path": os.path.normpath(f).replace(os.sep, "/"), "contents": base64.b64encode(fh.read()).decode()})
    head = gh(["repos/%s/git/ref/heads/%s" % (a.repo, a.branch), "--jq", ".object.sha"]).strip()
    body = {"query": MUTATION, "variables": {"input": {
        "branch": {"repositoryNameWithOwner": a.repo, "branchName": a.branch},
        "message": {"headline": a.headline, "body": a.body},
        "expectedHeadOid": head,
        "fileChanges": {"additions": additions},
    }}}
    out = json.loads(gh(["graphql", "--input", "-"], stdin=json.dumps(body)))
    if out.get("errors"):
        sys.exit("createCommitOnBranch: %s" % json.dumps(out["errors"]))
    commit = out["data"]["createCommitOnBranch"]["commit"]
    print("commit=%s" % commit["oid"])
    print("url=%s" % commit["url"])
    print("files=%d" % len(additions))
    return 0


if __name__ == "__main__":
    sys.exit(main())
