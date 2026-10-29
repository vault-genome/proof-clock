#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The Google Cloud side of the proof clock, once: a service account that may
# create and delete Compute Engine VMs in the project, trusted — through
# Workload Identity Federation — by GitHub's OIDC issuer for exactly one
# repository's main branch. No key is created anywhere; GitHub stores
# nothing but the three names printed at the end (repository variables,
# not secrets). Runs again without harm: what exists is kept.
#
# Usage: gcp-setup.sh --project ID --repo OWNER/NAME --owner-id N
#                     [--pool github] [--provider proof-clock] [--sa proof-clock]
#   --owner-id  the numeric id of the repository's owner (gh api orgs/OWNER --jq .id):
#               the condition is on the id, which a rename does not change
set -euo pipefail
PROJECT=""; REPO=""; OWNER_ID=""; POOL="github"; PROVIDER="proof-clock"; SA="proof-clock"
while [ $# -gt 0 ]; do
  case "$1" in
    --project) PROJECT="${2:?}"; shift 2;;
    --repo) REPO="${2:?}"; shift 2;;
    --owner-id) OWNER_ID="${2:?}"; shift 2;;
    --pool) POOL="${2:?}"; shift 2;;
    --provider) PROVIDER="${2:?}"; shift 2;;
    --sa) SA="${2:?}"; shift 2;;
    -h|--help) sed -n '5,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown argument: $1 (see --help)" >&2; exit 2;;
  esac
done
[ -n "$PROJECT" ] && [ -n "$REPO" ] && [ -n "$OWNER_ID" ] || { echo "--project, --repo and --owner-id are needed (see --help)" >&2; exit 2; }
case "$REPO" in */*) ;; *) echo "--repo must be OWNER/NAME" >&2; exit 2;; esac

say() { printf '%s\n' "$*"; }
say "== APIs"
gcloud services enable iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com compute.googleapis.com --project "$PROJECT"
NUM="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
SA_EMAIL="$SA@$PROJECT.iam.gserviceaccount.com"

say "== the service account $SA_EMAIL"
gcloud iam service-accounts describe "$SA_EMAIL" --project "$PROJECT" >/dev/null 2>&1 \
  || gcloud iam service-accounts create "$SA" --project "$PROJECT" --display-name "Proof clock: GitHub Actions of $REPO"
# compute.instanceAdmin.v1: create, delete, read the serial console of VMs;
# serviceUsageConsumer: see that the Compute Engine API is enabled (deploy.sh
# checks); serviceAccountUser on the default compute service account: the VM
# runs as it (deploy.sh passes no --service-account).
for role in roles/compute.instanceAdmin.v1 roles/serviceusage.serviceUsageConsumer; do
  gcloud projects add-iam-policy-binding "$PROJECT" --member "serviceAccount:$SA_EMAIL" --role "$role" --condition=None >/dev/null
  say "  $role"
done
gcloud iam service-accounts add-iam-policy-binding "$NUM-compute@developer.gserviceaccount.com" --project "$PROJECT" \
  --member "serviceAccount:$SA_EMAIL" --role roles/iam.serviceAccountUser >/dev/null
say "  roles/iam.serviceAccountUser on the default compute service account"

say "== the pool $POOL and its provider $PROVIDER (issuer: GitHub Actions)"
gcloud iam workload-identity-pools describe "$POOL" --location global --project "$PROJECT" >/dev/null 2>&1 \
  || gcloud iam workload-identity-pools create "$POOL" --location global --project "$PROJECT" --display-name "GitHub Actions"
gcloud iam workload-identity-pools providers describe "$PROVIDER" --workload-identity-pool "$POOL" --location global --project "$PROJECT" >/dev/null 2>&1 \
  || gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" --workload-identity-pool "$POOL" --location global --project "$PROJECT" \
       --display-name "$REPO" --issuer-uri https://token.actions.githubusercontent.com \
       --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_owner_id=assertion.repository_owner_id,attribute.ref=assertion.ref" \
       --attribute-condition "assertion.repository_owner_id == '$OWNER_ID' && assertion.repository == '$REPO' && assertion.ref == 'refs/heads/main'"
# the runs of that repository's main branch — and nothing else — may act as the service account
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" --project "$PROJECT" --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/$NUM/locations/global/workloadIdentityPools/$POOL/attribute.repository/$REPO" >/dev/null

say "== done. The repository variables (gh variable set NAME --repo $REPO --body VALUE):"
say "GCP_PROJECT=$PROJECT"
say "GCP_SERVICE_ACCOUNT=$SA_EMAIL"
say "GCP_WIF_PROVIDER=projects/$NUM/locations/global/workloadIdentityPools/$POOL/providers/$PROVIDER"
