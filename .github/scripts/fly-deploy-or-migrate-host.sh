#!/usr/bin/env bash
# Deploy a Fly Launch app. If Fly refuses to update a volume-pinned Machine
# because the current physical host is out of CPUs, fork the volume onto a
# different host, clone the Machine onto that copy, retire the packed-host
# Machine, then retry the deploy.
set -euo pipefail

APP=""
CONFIG=""
MIGRATE_ONLY=0
DEPLOY_ARGS=()

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

fly() {
  flyctl "$@" --app "$APP"
}

list_volumes_json() {
  fly volumes list --json
}

volume_attached_machine() {
  local vol_id="$1"
  list_volumes_json | jq -r --arg id "$vol_id" '
    .[] | select(.id == $id) |
    (.attached_machine_id // .attachedMachineId // empty)
  ' | awk 'NF && $0 != "null" { print; exit }'
}

machine_status_json() {
  fly machine status "$1" --json
}

guest_field() {
  local machine_id="$1" field="$2" default="$3"
  machine_status_json "$machine_id" | jq -r --arg f "$field" --arg d "$default" '
    (.config.guest[$f] // .Machine.config.guest[$f] // $d)
  '
}

mount_path_for() {
  local machine_id="$1"
  machine_status_json "$machine_id" | jq -r '
    (.config.mounts[0].path // .Machine.config.mounts[0].path // "/data")
  '
}

volume_id_for_machine() {
  local machine_id="$1"
  local from_status from_list
  from_status="$(machine_status_json "$machine_id" | jq -r '
    .config.mounts[0].volume // .Machine.config.mounts[0].volume // empty
  ')"
  if [[ -n "$from_status" && "$from_status" != "null" ]]; then
    printf '%s\n' "$from_status"
    return 0
  fi
  from_list="$(list_volumes_json | jq -r --arg mid "$machine_id" '
    .[] | select((.attached_machine_id // .attachedMachineId // "") == $mid) | .id
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
  machine_status_json "$machine_id" | jq -r '
    .state // .State // .Machine.state // empty
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
    if [[ "$state" == "started" ]]; then
      return 0
    fi
    now="$(date +%s)"
    if (( now - start >= timeout_s )); then
      echo "timed out waiting for machine ${machine_id} to start (last state: ${state:-unknown})" >&2
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

machine_id_from_log() {
  grep -Eo 'failed to update (VM|machine) [a-zA-Z0-9]+' "$1" \
    | awk '{ print $NF }' \
    | tail -n1
}

only_volume_machine() {
  list_volumes_json | jq -r '
    [.[] | (.attached_machine_id // .attachedMachineId // empty) | select(. != "" and . != "null")] | unique | .[]
  '
}

resolve_machine_id() {
  local from_log="${1:-}"
  if [[ -n "$from_log" ]]; then
    printf '%s\n' "$from_log"
    return 0
  fi
  local ids
  ids="$(only_volume_machine)"
  if [[ -z "$ids" ]]; then
    echo "no volume-attached machine found on ${APP}" >&2
    return 1
  fi
  if [[ "$(printf '%s\n' "$ids" | awk 'NF' | wc -l | tr -d ' ')" != "1" ]]; then
    echo "multiple volume-attached machines on ${APP}; pass a failed-update machine id" >&2
    printf '%s\n' "$ids" >&2
    return 1
  fi
  printf '%s\n' "$ids"
}

fork_volume() {
  local vol_id="$1" region="$2" cpu_kind="$3" cpus="$4" memory_mb="$5"
  local out id
  out="$(fly volumes fork "$vol_id" \
    --region "$region" \
    --require-unique-zone \
    --vm-cpu-kind "$cpu_kind" \
    --vm-cpus "$cpus" \
    --vm-memory "$memory_mb" \
    --json)"
  id="$(printf '%s\n' "$out" | jq -r '.id // .ID // empty' 2>/dev/null || true)"
  if [[ -z "$id" || "$id" == "null" ]]; then
    id="$(printf '%s\n' "$out" | awk '/^[[:space:]]*ID:/ { print $2; exit }')"
  fi
  if [[ -z "$id" || "$id" == "null" ]]; then
    echo "could not parse forked volume id from fly volumes fork output:" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  printf '%s\n' "$id"
}

destroy_unattached_extras() {
  local keep_csv="$1"
  local vol_id attached
  while IFS= read -r vol_id; do
    [[ -z "$vol_id" ]] && continue
    case ",${keep_csv}," in
      *",${vol_id},"*) continue ;;
    esac
    attached="$(volume_attached_machine "$vol_id")"
    if [[ -z "$attached" ]]; then
      echo "destroying extra unattached volume ${vol_id}"
      fly volumes destroy "$vol_id" -y
    fi
  done < <(list_volumes_json | jq -r '.[].id')
}

migrate_off_packed_host() {
  local hint_machine="${1:-}"
  local old_machine old_volume region mount_path cpu_kind cpus memory_mb
  local new_volume new_machine

  old_machine="$(resolve_machine_id "$hint_machine")"
  old_volume="$(volume_id_for_machine "$old_machine")"
  region="$(volume_region "$old_volume")"
  mount_path="$(mount_path_for "$old_machine")"
  cpu_kind="$(guest_field "$old_machine" "cpu_kind" "shared")"
  cpus="$(guest_field "$old_machine" "cpus" "1")"
  memory_mb="$(guest_field "$old_machine" "memory_mb" "256")"
  cpu_kind="${cpu_kind:-shared}"
  cpus="${cpus:-1}"
  memory_mb="${memory_mb:-256}"

  if [[ -z "$region" ]]; then
    echo "could not determine region for volume ${old_volume}" >&2
    return 1
  fi

  echo "Packed-host recovery for ${APP}:"
  echo "  machine=${old_machine}"
  echo "  volume=${old_volume}"
  echo "  region=${region}"
  echo "  mount=${mount_path}"
  echo "  guest=${cpu_kind} cpus=${cpus} memory_mb=${memory_mb}"

  echo "Forking ${old_volume} onto a different host..."
  new_volume="$(fork_volume "$old_volume" "$region" "$cpu_kind" "$cpus" "$memory_mb")"
  echo "  forked volume=${new_volume}"

  echo "Cloning ${old_machine} onto ${new_volume}..."
  if ! fly machine clone "$old_machine" \
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
  echo "  new machine=${new_machine}"
  wait_for_started "$new_machine" 180

  echo "Checking ${mount_path} on ${new_machine}..."
  fly ssh console --quiet --machine "$new_machine" --command "ls -la ${mount_path}"

  destroy_unattached_extras "${old_volume},${new_volume}"

  echo "Destroying packed-host machine ${old_machine}..."
  fly machines destroy "$old_machine" --force -y

  echo "Destroying packed-host volume ${old_volume}..."
  fly volumes destroy "$old_volume" -y

  echo "Host migration complete: machine ${new_machine} volume ${new_volume}"
}

run_deploy() {
  local args=(deploy --app "$APP")
  if [[ -n "$CONFIG" ]]; then
    args+=(--config "$CONFIG")
  fi
  args+=("${DEPLOY_ARGS[@]}")
  flyctl "${args[@]}"
}

if [[ "$MIGRATE_ONLY" -eq 1 ]]; then
  migrate_off_packed_host ""
  exit 0
fi

log_file="$(mktemp)"
cleanup() { rm -f "$log_file"; }
trap cleanup EXIT

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

echo "Fly refused the in-place update because the volume's current host is out of CPUs."
migrate_off_packed_host "$(machine_id_from_log "$log_file")"
echo "Retrying deploy on the new host..."
run_deploy
