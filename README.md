# Vault Genome proof clock

Twice a day this repository does what a stranger does with the one-button
deployment of [Vault Genome](https://github.com/vault-genome/vaultgenome-core):
it clones the repository, runs `deploy/gcp/deploy.sh` against the latest
release on a real Confidential VM in Google Cloud — AMD SEV-SNP at 06:00 UTC,
Intel TDX at 18:00 UTC — waits for the guest's record, decides the status
itself, removes the VM, and commits the record here.

A release proven once is a claim. A release proven again every day, on a
chip the clock did not choose, with the record published and checkable by
anyone, is a track record. `latest.json` is the counter; `records/` holds
every record; `index.json` lists them.

![proof clock](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/vault-genome/proof-clock/main/badge.json)

## What one run does

1. **The release is verified on the runner before anything runs anywhere** —
   deploy.sh does this: the signed checksums list against the release
   workflow's identity for this very tag (cosign), the five files against the
   list, their SLSA provenance against the source tag (slsa-verifier), the
   tag's signature against the keys pinned on `main`.
2. **One Confidential VM is created** — an `n2d-standard-4` on AMD Milan with
   SEV-SNP, or a `c3-standard-4` Trust Domain on Intel TDX — with the guest
   script and the verified list in its metadata. The guest fetches the release
   itself and runs only what is on the list.
3. **The guest provisions the deployment**, seals the key files to the chip
   (SEV-SNP: the chip's derived key; TDX: the vTPM on a settled boot after one
   reboot), starts both daemons, gates a first genome over the Return Path,
   pauses the services and replays its audit log, and prints its record on
   the serial console.
4. **The clock decides.** deploy.sh reports what the guest says and asserts
   nothing; the clock reads the guest's own record and calls the run
   **proven** only when the job succeeded with the gate at **EXACT** and the
   audit log replayed **ok**. Anything else is named: `not-exact`, `refused`
   (the vault's verifier did not admit the worker), `no-capacity` (no zone had
   the machine), `failed` (with the reason).
5. **The VM is removed**, in every case; a janitor also removes any `clock-*`
   VM older than 90 minutes that a dead run may have left.
6. **The record is committed** to this repository by GitHub itself for this
   run (a "Verified" commit, the run's URL in its message), the counter is
   recomputed, and a run that did not prove opens an issue. The job is red
   unless the status is `proven`.

Google Cloud trusts the run's own OIDC token through Workload Identity
Federation; there is no key anywhere, in GitHub or on the runner.

## The counter: `latest.json`

| field | meaning |
|---|---|
| `last_proven` | the newest proven record: when, which platform, which chip, the release, the seconds from the button to the record |
| `last_run` | the newest record of any status |
| `streak_days` | consecutive UTC days, counted back from today (or yesterday, when today has no proven run yet), with at least one proven run |
| `days_proven` | UTC days with at least one proven run |
| `runs` | runs by status: `total`, `proven`, `not-exact`, `refused`, `no-capacity`, `failed` |
| `by_platform` | per platform: runs, proven, `last_proven_at`, `chips_seen` (distinct chip ids; SEV-SNP only — TDX reports no chip identity), `measurements_seen` (distinct launch measurements), `firmware_seen`, `releases_proven` |
| `releases_proven` | every release tag proven at least once |
| `badge` | the shields.io badge (`badge.json` is the same, at the root, for the endpoint) |

`index.json` is one line per record, newest first, with the path of the record.

## A record

`records/<date>/<stamp>-<platform>/`:

| file | what it is |
|---|---|
| `record.json` | the facts, parsed: status and reason, release (tag, commit, the sha256 of the signed list, what cosign, the checksums and slsa-verifier said, the tag's signature), cloud (zone, machine), chip (SEV-SNP: product, CPUID, chip id, reported and committed TCB, firmware, platform info, the floors the verifier held it to; TDX: MRTD, RTMR0–3, FMSPC), the launch measurement, the sealer, the gate (level, fixtures, the signed verdict), the audit replay, timings, the run, and the sha256 of every other file here |
| `deploy.txt` | the transcript of deploy.sh, the PROVEN block included |
| `deployment.txt` | instance, zone, machine, platform, release, sealer, when |
| `verify/` | the release verification on the runner: `cosign.txt`, `checksums.txt`, `slsa.txt`, `tag.txt`, `assets.sha256` (the sha256 of every downloaded asset), `tools.txt` |
| `guest.tgz` | the guest's record, byte for byte as the guest printed it on the serial console (its base64's sha256 is the one the guest announced, `guest_blob.b64_sha256`) |
| `guest/` | the files of that record a reader wants at hand: `chip.txt`, `steps.txt`, `timeline.txt`, `provision.json`, `job.json` (the signed verdict), `audit-verify.json`, `audit-events.jsonl`, the identities, the Intel PCS documents on TDX, … |
| `failure.txt` | the guest's failure block, when the guest failed |

The transcript, `verify/` and `failure.txt` are written on the runner's side
and have the account the run acted as and the project's number replaced by
`<account>` and `<project-number>`. The guest's files are published as the
guest wrote them: the instance's host name in `kernel.txt` carries the
project's name, which also stands in the public evidence of the core
repository. The serial console is not published; a scrubbed copy of the whole
raw record is the run's artifact for 14 days.

## Checking a record yourself

```
python3 tools/check-record.py records/<date>/<stamp>-<platform> [--kds] [--release]
```

Offline, from the record alone, it checks that `guest.tgz` is the record the
guest printed (its sha256 is the one in `record.json`; unpacked, every file
matches the guest's own `sha256sums.txt`), that the files under `guest/` are
those files byte for byte, that every published file has the sha256
`record.json` lists, that the gate's verdict carries the authority's Ed25519
signature over its canonical bytes (compact JSON, verified with openssl) and
the signer is the authority key of the vault's identity, that the launch
measurement is one value in the five places it appears (both daemons' pins,
the vault's identity, the admission event in the audit log, `record.json`),
and that the guest's replay of the audit log says ok and counted the events
the log lists.

`--kds` (SEV-SNP) asks AMD's key server for the VCEK of this chip at the TCB
the verifier saw — one request to kdsintf.amd.com; an answer means AMD knows
this chip at this TCB. `--release` downloads the release's assets from GitHub
Releases now, verifies them again with cosign and slsa-verifier, and checks
they are the bytes the runner verified (`verify/assets.sha256`). Needs
python3, openssl and tar; `--release` needs cosign and slsa-verifier.

## What the clock does not prove

- The record carries the verifier's reading of the hardware — TCB, chip id,
  launch measurement, the signed verdict — not the attestation report or the
  quote itself. A reader cannot re-verify AMD's or Intel's signature from the
  record; `--kds` shows that AMD knows the chip at that TCB, no more.
- The audit chain's hashes and signatures were replayed on the guest
  (`acpctl audit verify`); the audit database is not in the record, so the
  replay cannot be repeated here. The events, the verifier's output and the
  audit public key are.
- A proven run proves that this release deploys, attests, seals and gates
  EXACT on that day's chip and firmware, in the operator's own project. It is
  not an audit of the code.
- A day without a proven run — no capacity, a refused host, a failure — ends
  the streak. The record says why; nothing is retried quietly.

## Run your own clock

Fork this repository. In a Google Cloud project of yours, once:

```
tools/gcp-setup.sh --project <id> --repo <owner>/proof-clock --owner-id <numeric owner id>
```

It creates a service account that may create and delete Compute Engine VMs,
a Workload Identity pool and provider that trust GitHub's OIDC issuer for
exactly that repository's `main` branch, and prints three names. Set them as
repository variables (`gh variable set NAME --repo <owner>/proof-clock --body VALUE`):
`GCP_PROJECT`, `GCP_SERVICE_ACCOUNT`, `GCP_WIF_PROVIDER`. Then run the
workflow once by hand (`gh workflow run clock.yml -f platform=sev-snp`); the
schedule takes over. The project needs quota for 4 N2D vCPUs and 4 C3 vCPUs
in `us-central1`; a run costs a few cents.

## License

The tools are AGPL-3.0-or-later (`LICENSE`), as the core repository. The
records are facts about public releases: copy and quote them, with a link to
the record.
