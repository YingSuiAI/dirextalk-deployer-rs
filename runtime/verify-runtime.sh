#!/usr/bin/env bash
set -euo pipefail

out=/var/dirextalk-message-server/split
read_pair() {
  local file=$1 key=$2
  awk -F= -v key="$key" '$1 == key { count++; value=substr($0, length(key) + 2) } END { if (count == 1 && value != "") print value; else exit 1 }' "$file"
}
stack=$(read_pair "$out/.manifest" stack_name)
[[ "$stack" =~ ^d-[a-z2-7]{26}$ ]]
[[ "$(read_pair "$out/.env" DIREXTALK_SPLIT_STACK_NAME)" == "$stack" ]]
compose=(docker compose --project-name "$stack" --env-file "$out/.env" \
  -f /var/dirextalk-message-server/deploy/split-agent/compose.yaml \
  -f /var/dirextalk-message-server/deploy/split-agent/compose.production.yaml)
for service in postgres coturn message-server agent extension-runner core-runner; do
  container=$("${compose[@]}" ps --quiet "$service")
  [[ "$container" =~ ^[0-9a-f]{64}$ ]]
  [[ "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}|{{ .State.Status }}|{{ .State.Health.Status }}' "$container")" == "$stack|$service|running|healthy" ]]
done
edge=$stack-edge
caddy=$(docker ps --no-trunc --quiet \
  --filter "label=com.docker.compose.project=$edge" \
  --filter 'label=com.docker.compose.service=caddy')
[[ "$caddy" =~ ^[0-9a-f]{64}$ ]]
[[ "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}|{{ .State.Status }}|{{ .State.Health.Status }}' "$caddy")" == "$edge|caddy|running|healthy" ]]

systemctl is-active --quiet dirextalk-updater.service
token_file=/etc/dirextalk-updater/control-token
socket=/run/dirextalk-updater/http.sock
[[ -f "$token_file" && ! -L "$token_file" ]]
[[ "$(stat -c '%u:%g:%a' "$token_file")" == 0:0:600 ]]
[[ -S "$socket" ]]
token=$(<"$token_file")
[[ "$token" =~ ^[0-9a-f]{64}$ ]]
status_json=$(printf 'header = "X-Dirextalk-Control-Token: %s"\n' "$token" \
  | curl --fail --silent --show-error --max-time 10 --max-filesize 65536 \
      --config - --unix-socket "$socket" --header 'Content-Type: application/json' \
      --data '{}' http://localhost/_dirextalk/updater/v1/control/status)
jq -e '.available == true and .updater_ready == true and .desired_state == "running" and (.active_job == null)' \
  <<<"$status_json" >/dev/null

agent_version=$(read_pair "$out/.env" DIREXTALK_AGENT_VERSION)
message_version=$(read_pair "$out/.env" DIREXTALK_MESSAGE_SERVER_VERSION)
expect_current_version_negative() {
  local status
  if "$@" >/dev/null 2>&1; then
    return 1
  else
    status=$?
    [[ "$status" -eq 3 ]]
  fi
}
expect_current_version_negative \
  /var/dirextalk-message-server/deploy/split-agent/scripts/update-agent-local.sh \
  "$out" "$agent_version" "$message_version"
expect_current_version_negative \
  /var/dirextalk-message-server/deploy/split-agent/scripts/update-message-server-local.sh \
  "$out" "$message_version"
