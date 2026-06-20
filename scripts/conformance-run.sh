#!/usr/bin/env bash
#
# Drive the OpenID Connect OP test plans through the OIDF conformance suite.
#
# The suite is expected to be already running (see
# docker/docker-compose.conformance.yml). This script renders the suite config
# from scripts/conformance/config.template.json using environment values, then
# runs each targeted OP plan and variant through scripts/conformance/runner.py.
#
# Conformance is driven entirely through standard OP endpoints. There is no
# suite-specific branch in the OP; the target is the real deployment.
#
# Required environment:
#   OIDC_TARGET_BASE_URL     Public issuer base, default https://protocolsoup.com
#   OIDC_CLIENT_SECRET       Secret for the confidential conformance client
#   OIDC_PASSWORD            Password for the conformance end user (alice)
# Optional:
#   CONFORMANCE_SUITE_URL    Default https://localhost.emobix.co.uk:8443
#   OIDC_CLIENT_ID           Default conformance-client (confidential)
#   OIDC_CLIENT2_ID          Default conformance-client-2 (second confidential
#                            client; the suite uses it to verify codes are bound
#                            to the client they were issued to)
#   OIDC_CLIENT2_SECRET      Default: reuses OIDC_CLIENT_SECRET
#   OIDC_USERNAME            Default alice@example.com
#   CONFORMANCE_RESULTS_DIR  Default .artifacts/conformance
#   CONFORMANCE_STRICT       "1" to fail on WARNING
#   CONFORMANCE_EXPECTED_FAILURES  Path to suite-side known-issue JSON
#
# The two clients MUST be registered on the target OP with the suite callback
# (https://<suite-host>/test/a/<alias>/callback) for every alias below. On the
# deployment this is driven by OIDC_CONFORMANCE_REDIRECT_URIS (see fly.toml).
#
# Exit code is non-zero if any targeted plan has a real failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_DIR="${SCRIPT_DIR}/conformance"

export OIDC_TARGET_BASE_URL="${OIDC_TARGET_BASE_URL:-https://protocolsoup.com}"
export CONFORMANCE_SUITE_URL="${CONFORMANCE_SUITE_URL:-https://localhost.emobix.co.uk:8443}"
export OIDC_DISCOVERY_URL="${OIDC_DISCOVERY_URL:-${OIDC_TARGET_BASE_URL}/.well-known/openid-configuration}"
export OIDC_AUTHORIZE_URL="${OIDC_AUTHORIZE_URL:-${OIDC_TARGET_BASE_URL}/oidc/authorize}"
export OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-conformance-client}"
export OIDC_CLIENT_SECRET="${OIDC_CLIENT_SECRET:-}"
export OIDC_CLIENT2_ID="${OIDC_CLIENT2_ID:-conformance-client-2}"
# The second confidential client reuses the first secret unless a distinct one
# is provided, matching the OP default in registerConformanceClients.
export OIDC_CLIENT2_SECRET="${OIDC_CLIENT2_SECRET:-${OIDC_CLIENT_SECRET}}"
export OIDC_USERNAME="${OIDC_USERNAME:-alice@example.com}"
export OIDC_PASSWORD="${OIDC_PASSWORD:-}"
export CONFORMANCE_RESULTS_DIR="${CONFORMANCE_RESULTS_DIR:-.artifacts/conformance}"
export CONFORMANCE_EXPECTED_FAILURES="${CONFORMANCE_EXPECTED_FAILURES:-${CONF_DIR}/expected_failures.json}"

if [[ -z "${OIDC_CLIENT_SECRET}" ]]; then
  echo "ERROR: OIDC_CLIENT_SECRET is required (confidential client secret)." >&2
  exit 2
fi
if [[ -z "${OIDC_PASSWORD}" ]]; then
  echo "ERROR: OIDC_PASSWORD is required (conformance end-user password)." >&2
  exit 2
fi

STRICT_FLAG=()
if [[ "${CONFORMANCE_STRICT:-0}" == "1" ]]; then
  STRICT_FLAG=(--strict-warnings)
fi

mkdir -p "${CONFORMANCE_RESULTS_DIR}"

render_config() {
  local out="$1"
  # envsubst only substitutes the named variables; nothing else is touched.
  envsubst '${OIDC_ALIAS} ${OIDC_DISCOVERY_URL} ${OIDC_CLIENT_ID} ${OIDC_CLIENT_SECRET} ${OIDC_CLIENT2_ID} ${OIDC_CLIENT2_SECRET} ${OIDC_AUTHORIZE_URL} ${OIDC_USERNAME} ${OIDC_PASSWORD}' \
    < "${CONF_DIR}/config.template.json" > "${out}"
}

# Targeted OP plans. One OpenID Connect certification fee covers every profile
# the deployment passes, so we run the full set the implementation supports.
# Variant axes are confirmed against the suite version pinned in
# docker-compose.conformance.yml: server metadata via discovery, static client.
#
# The config plan (Config OP) validates only the discovery/configuration
# document and JWKS; it takes no variant axes and performs no authorization
# flow, so it needs no redirect URI or end-user login.
#
# The basic plan is run twice to cover both token-endpoint client
# authentication methods the OP advertises (client_secret_basic and
# client_secret_post); the OP enforces the same code path for both, so each must
# be exercised. Implicit and hybrid plans use the same discovery+static axes.
VARIANT_DISCOVERY_STATIC='{"server_metadata":"discovery","client_registration":"static_client"}'
VARIANT_BASIC_POST='{"server_metadata":"discovery","client_registration":"static_client","client_auth_type":"client_secret_post"}'

declare -a PLANS=(
  "oidcc-config-certification-test-plan||config"
  "oidcc-basic-certification-test-plan|${VARIANT_DISCOVERY_STATIC}|basic"
  "oidcc-basic-certification-test-plan|${VARIANT_BASIC_POST}|basic-post"
  "oidcc-implicit-certification-test-plan|${VARIANT_DISCOVERY_STATIC}|implicit"
  "oidcc-hybrid-certification-test-plan|${VARIANT_DISCOVERY_STATIC}|hybrid"
)

overall=0
for entry in "${PLANS[@]}"; do
  IFS='|' read -r plan variant label <<< "${entry}"
  export OIDC_ALIAS="protocolsoup-${label}"
  config_file="${CONFORMANCE_RESULTS_DIR}/config.${label}.json"
  render_config "${config_file}"

  echo "=== Running ${plan} (${label}) ==="
  if ! python3 "${CONF_DIR}/runner.py" \
      --plan "${plan}" \
      --variant "${variant}" \
      --config "${config_file}" \
      --results-dir "${CONFORMANCE_RESULTS_DIR}/${label}" \
      "${STRICT_FLAG[@]}"; then
    echo "Plan ${plan} (${label}) reported real failures." >&2
    overall=1
  fi
done

exit "${overall}"
