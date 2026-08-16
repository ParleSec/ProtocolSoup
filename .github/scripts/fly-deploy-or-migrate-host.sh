#!/usr/bin/env bash
# Deploy a Fly Launch app. If Fly cannot place or update a volume-pinned
# Machine because the current host is out of CPUs, converge the app to one
# runnable Machine on a different host (preserving volume data), then retry.
#
# This is idempotent across runs. It handles a first packed-host failure, a
# leftover clone from a partial recovery, orphan volumes, a packed Machine
# that no longer exists, and a new host that is also packed.
#
# Reads use the Machines API (flyctl machine status has no --json). Mutations
# still go through flyctl.
set -euo pipefail

APP=""
CONFIG=""
MIGRATE_ONLY=0
DEPLOY_ARGS=()
FLY_API_HOSTNAME="${FLY_API_HOSTNAME:-https://api.machines.dev}"
MAX_RECOVERIES=2

usage() {
  cat <<'EOF'
Usage:
  fly-deploy-or-migrate-host.sh --app NAME [--config FILE] -- [flyctl deploy args...]
  fly-deploy-or-migrate-host.sh --app NAME --migrate-only

EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app)
      APP="${2:-}"
      shift 2
      ;;
    --config)
      CONFIG="${2:-}"
      shift 2
      ;;
    --migrate-only)
      MIGRATE_ONLY=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --)
      shift
      DEPLOY_ARGS+=("$@")
      break
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$APP" ]]; then
  echo "--app is required" >&2
  usage >&2
  exit 2
fi

if ! command -v flyctl >/dev/null 2>&1; then
  echo "flyctl is not on PATH" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is not on PATH" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is not on PATH" >&2
  exit 1
fi
if [[ -z "${FLY_API_TOKEN:-}" ]]; then
  echo "FLY_API_TOKEN is not set" >&2
  exit 1
fi

fly() {
  flyctl "$@" --app "$APP"
}

fly_api_get() {
  local path="$1"
  local raw http_code body
  raw="$(curl -sS -w '\n%{http_code}' \
    -H "Authorization: Bearer ${FLY_API_TOKEN}" \
    -H "Content-Type: application/json" \
    "${FLY_API_HOSTNAME}${path}")"
  http_code="$(printf '%s\n' "$raw" | tail -n1)"
  body="$(printf '%s\n' "$raw" | sed '$d')"
  if [[ ! "$http_code" =~ ^2 ]]; then
    echo "Machines API GET ${path} failed (HTTP ${http_code})" >&2
    printf '%s\n' "$body" >&2
    return 1
  fi
  if ! printf '%s\n' "$body" | jq -e . >/dev/null; then
    echo "Machines API GET ${path} returned non-JSON" >&2
    printf '%s\n' "$body" >&2
    return 1
  fi
  printf '%s\n' "$body"
}

list_volumes_json() {
  fly_api_get "/v1/apps/${APP}/volumes"
}

list_machines_json() {
  fly_api_get "/v1/apps/${APP}/machines"
}

machine_json() {
  fly_api_get "/v1/apps/${APP}/machines/${1}"
}

machine_exists() {
  local raw http_code
  raw="$(curl -sS -w '\n%{http_code}' \
    -H "Authorization: Bearer ${FLY_API_TOKEN}" \
    -H "Content-Type: application/json" \
    "${FLY_API_HOSTNAME}/v1/apps/${APP}/machines/${1}")"
  http_code="$(printf '%s\n' "$raw" | tail -n1)"
  [[ "$http_code" =~ ^2 ]]
}

volume_attached_machine() {
  local vol_id="$1"
  list_volumes_json | jq -r --arg id "$vol_id" '
    .[] | select(.id == $id) |
    (.attached_machine_id // empty)
  ' | awk 'NF && $0 != "null" { print; exit }'
}

guest_field() {
  local machine_id="$1" field="$2" default="$3"
  machine_json "$machine_id" | jq -r --arg f "$field" --arg d "$default" '
    .config.guest[$f] // $d
  '
}

mount_path_for() {
  local machine_id="$1"
  machine_json "$machine_id" | jq -r '.config.mounts[0].path // "/data"'
}

volume_id_for_machine() {
  local machine_id="$1"
  local from_machine from_list
  from_machine="$(machine_json "$machine_id" | jq -r '.config.mounts[0].volume // empty')"
  if [[ -n "$from_machine" && "$from_machine" != "null" ]]; then
    printf '%s\n' "$from_machine"
    return 0
  fi
  from_list="$(list_volumes_json | jq -r --arg mid "$machine_id" '
    .[] | select((.attached_machine_id // "") == $mid) | .id
  ' | awk 'NF { print; exit }')"
  if [[ -z "$from_list" ]]; then
    echo "no volume attached to machine ${machine_id}" >&2
    return 1
  fi
  printf '%s\n' "$from_list"
}

volume_region() {
  local vol_id="$1"
  list_volumes_json | jq -r --arg id "$vol_id" '
    .[] | select(.id == $id) | (.region // empty)
  '
}

machine_state() {
  local machine_id="$1"
  machine_json "$machine_id" | jq -r '.state // empty'
}

live_machine_ids() {
  list_machines_json | jq -r '.[].id'
}

volume_backed_machine_ids() {
  list_machines_json | jq -r '
    .[] | select((.config.mounts // []) | length > 0) | .id
  '
}

wait_for_attach() {
  local vol_id="$1" timeout_s="$2"
  local start now attached
  start="$(date +%s)"
  while true; do
    attached="$(volume_attached_machine "$vol_id")"
    if [[ -n "$attached" ]]; then
      printf '%s\n' "$attached"
      return 0
    fi
    now="$(date +%s)"
    if (( now - start >= timeout_s )); then
      echo "timed out waiting for volume ${vol_id} to attach to a machine" >&2
      return 1
    fi
    sleep 5
  done
}

wait_for_started() {
  local machine_id="$1" timeout_s="$2"
  local start now state
  start="$(date +%s)"
  while true; do
    state="$(machine_state "$machine_id")"
    case "$state" in
      started)
        return 0
        ;;
      stopped|suspended)
        echo "Starting ${machine_id} (state=${state})..." >&2
        fly machine start "$machine_id" || true
        ;;
    esac
    now="$(date +%s)"
    if (( now - start >= timeout_s )); then
      echo "timed out waiting for machine ${machine_id} to start (last state: ${state:-unknown})" >&2
      return 1
    fi
    sleep 5
  done
}

wait_for_detach() {
  local vol_id="$1" timeout_s="$2"
  local start now attached
  start="$(date +%s)"
  while true; do
    attached="$(volume_attached_machine "$vol_id")"
    if [[ -z "$attached" ]]; then
      return 0
    fi
    now="$(date +%s)"
    if (( now - start >= timeout_s )); then
      echo "timed out waiting for volume ${vol_id} to detach (still on ${attached})" >&2
      return 1
    fi
    sleep 5
  done
}

is_packed_host_error() {
  grep -Eqi \
    'insufficient CPUs available to fulfill request on the current host|insufficient resources to create new machine with existing volume|could not reserve resource for machine: insufficient CPUs' \
    "$1"
}

packed_ids_from_log() {
  grep -Eo 'failed to update (VM|machine) [a-zA-Z0-9]+' "$1" \
    | awk '{ print $NF }' \
    | sort -u
}

in_list() {
  local needle="$1"
  local item
  shift
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

fork_volume() {
  local vol_id="$1" region="$2" cpu_kind="$3" cpus="$4" memory_mb="$5"
  local out id
  out="$(fly volumes fork "$vol_id" \
    --region "$region" \
    --require-unique-zone \
    --vm-cpu-kind "$cpu_kind" \
    --vm-cpus "$cpus" \
    --vm-memory "$memory_mb")"
  id="$(printf '%s\n' "$out" | awk '/^[[:space:]]*ID:/ { print $2; exit }')"
  if [[ -z "$id" ]]; then
    echo "could not parse forked volume id from fly volumes fork output:" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  printf '%s\n' "$id"
}

verify_mount() {
  local machine_id="$1" mount_path="$2"
  echo "Checking ${mount_path} on ${machine_id}..." >&2
  fly ssh console --quiet --machine "$machine_id" --command "ls -la ${mount_path}" >&2
}

clone_onto_fork() {
  local source_machine="$1"
  local source_volume region mount_path cpu_kind cpus memory_mb
  local new_volume new_machine

  source_volume="$(volume_id_for_machine "$source_machine")"
  region="$(volume_region "$source_volume")"
  mount_path="$(mount_path_for "$source_machine")"
  cpu_kind="$(guest_field "$source_machine" "cpu_kind" "shared")"
  cpus="$(guest_field "$source_machine" "cpus" "1")"
  memory_mb="$(guest_field "$source_machine" "memory_mb" "256")"
  cpu_kind="${cpu_kind:-shared}"
  cpus="${cpus:-1}"
  memory_mb="${memory_mb:-256}"
  if [[ -z "$region" ]]; then
    echo "could not determine region for volume ${source_volume}" >&2
    return 1
  fi

  echo "Forking ${source_volume} from ${source_machine} (${cpu_kind} cpus=${cpus} memory_mb=${memory_mb} region=${region})..." >&2
  new_volume="$(fork_volume "$source_volume" "$region" "$cpu_kind" "$cpus" "$memory_mb")"
  echo "  forked volume=${new_volume}" >&2

  echo "Cloning ${source_machine} onto ${new_volume}..." >&2
  if ! fly machine clone "$source_machine" \
    --region "$region" \
    --attach-volume "${new_volume}:${mount_path}" \
    --vm-cpu-kind "$cpu_kind" \
    --vm-cpus "$cpus" \
    --vm-memory "$memory_mb"; then
    echo "clone failed; destroying unused fork ${new_volume}" >&2
    fly volumes destroy "$new_volume" -y || true
    return 1
  fi

  new_machine="$(wait_for_attach "$new_volume" 180)"
  echo "  new machine=${new_machine}" >&2
  wait_for_started "$new_machine" 180
  verify_mount "$new_machine" "$mount_path"
  printf '%s\n' "$new_machine"
}

pick_keeper() {
  local id
  local packed=("$@")
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    if ((${#packed[@]})) && in_list "$id" "${packed[@]}"; then
      continue
    fi
    printf '%s\n' "$id"
    return 0
  done < <(volume_backed_machine_ids)
  return 1
}

pick_source() {
  local id
  local packed=("$@")
  for id in "${packed[@]}"; do
    if machine_exists "$id"; then
      printf '%s\n' "$id"
      return 0
    fi
  done
  id="$(volume_backed_machine_ids | awk 'NF { print; exit }')"
  if [[ -n "$id" ]]; then
    printf '%s\n' "$id"
    return 0
  fi
  return 1
}

destroy_machine() {
  local machine_id="$1"
  if ! machine_exists "$machine_id"; then
    echo "Machine ${machine_id} already gone"
    return 0
  fi
  echo "Destroying machine ${machine_id}..."
  fly machine destroy "$machine_id" --force
}

destroy_volume() {
  local vol_id="$1"
  if [[ -z "$vol_id" ]]; then
    return 0
  fi
  if ! list_volumes_json | jq -e --arg id "$vol_id" '.[] | select(.id == $id)' >/dev/null; then
    echo "Volume ${vol_id} already gone"
    return 0
  fi
  wait_for_detach "$vol_id" 120 || true
  echo "Destroying volume ${vol_id}..."
  fly volumes destroy "$vol_id" -y
}

destroy_all_except_keeper() {
  local keeper="$1"
  local keeper_volume=""
  local id vol_id

  keeper_volume="$(volume_id_for_machine "$keeper")"
  echo "Keeper ${keeper} volume ${keeper_volume}"

  while IFS= read -r id; do
    [[ -z "$id" || "$id" == "$keeper" ]] && continue
    destroy_machine "$id"
  done < <(live_machine_ids)

  while IFS= read -r vol_id; do
    [[ -z "$vol_id" || "$vol_id" == "$keeper_volume" ]] && continue
    destroy_volume "$vol_id"
  done < <(list_volumes_json | jq -r '.[].id')
}

place_volume_on_new_host() {
  local source_vol newest region
  source_vol="$(list_volumes_json | jq -r 'sort_by(.created_at) | first | .id // empty')"
  if [[ -z "$source_vol" ]]; then
    echo "no volumes on ${APP} to migrate" >&2
    return 1
  fi
  region="$(volume_region "$source_vol")"
  echo "No Machines left; forking oldest volume ${source_vol} onto a new host..."
  newest="$(fork_volume "$source_vol" "$region" "shared" "1" "256")"
  echo "  forked volume=${newest}"
  while IFS= read -r vol_id; do
    [[ -z "$vol_id" || "$vol_id" == "$newest" ]] && continue
    destroy_volume "$vol_id"
  done < <(list_volumes_json | jq -r '.[].id')
}

# Converge to one volume-backed Machine that Fly did not just refuse to place,
# with /data verified, and no leftover Machines or volumes.
converge_to_runnable_host() {
  local keeper="" source="" mount_path="/data"
  local packed=()
  local id

  if [[ $# -gt 0 ]]; then
    packed=("$@")
  fi

  echo "Converging ${APP} off packed hosts (${#packed[@]} packed id(s): ${packed[*]:-none})"

  if keeper="$(pick_keeper "${packed[@]+"${packed[@]}"}")"; then
    echo "Reusing existing Machine ${keeper} that is not in the packed set"
    wait_for_started "$keeper" 180
    mount_path="$(mount_path_for "$keeper")"
    verify_mount "$keeper" "$mount_path"
    destroy_all_except_keeper "$keeper"
    echo "Host migration complete: machine ${keeper}"
    return 0
  fi

  if source="$(pick_source "${packed[@]+"${packed[@]}"}")"; then
    keeper="$(clone_onto_fork "$source")"
    destroy_all_except_keeper "$keeper"
    echo "Host migration complete: machine ${keeper}"
    return 0
  fi

  place_volume_on_new_host
  echo "Host migration complete: volume moved; next deploy will create the Machine"
}

run_deploy() {
  local args=(deploy --app "$APP")
  if [[ -n "$CONFIG" ]]; then
    args+=(--config "$CONFIG")
  fi
  args+=("${DEPLOY_ARGS[@]}")
  flyctl "${args[@]}"
}

ids_from_log_or_live() {
  local log_file="$1"
  local ids
  ids="$(packed_ids_from_log "$log_file" || true)"
  if [[ -n "$ids" ]]; then
    printf '%s\n' "$ids"
    return 0
  fi
  volume_backed_machine_ids
}

if [[ "$MIGRATE_ONLY" -eq 1 ]]; then
  mapfile -t packed < <(volume_backed_machine_ids)
  if ((${#packed[@]} == 1)); then
    converge_to_runnable_host "${packed[0]}"
  else
    # Multiple Machines: converge to one. Without a deploy log, keep a
    # volume-backed Machine and retire the rest (no extra fork).
    converge_to_runnable_host
  fi
  exit 0
fi

log_file="$(mktemp)"
cleanup() { rm -f "$log_file"; }
trap cleanup EXIT

recoveries=0
while true; do
  set +e
  run_deploy 2>&1 | tee "$log_file"
  status="${PIPESTATUS[0]}"
  set -e

  if [[ "$status" -eq 0 ]]; then
    exit 0
  fi
  if ! is_packed_host_error "$log_file"; then
    exit "$status"
  fi
  if (( recoveries >= MAX_RECOVERIES )); then
    echo "Still cannot place the Machine after ${recoveries} host migrations" >&2
    exit "$status"
  fi

  recoveries=$((recoveries + 1))
  echo "Fly refused an in-place update because a volume's current host is out of CPUs (recovery ${recoveries}/${MAX_RECOVERIES})."
  mapfile -t packed < <(ids_from_log_or_live "$log_file")
  converge_to_runnable_host "${packed[@]+"${packed[@]}"}"
  echo "Retrying deploy..."
done
