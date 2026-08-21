#!/usr/bin/env bash
set -euo pipefail

out=/var/dirextalk-message-server/split
env_file=$out/.env
manifest=$out/.manifest
read_pair() {
  local file=$1 key=$2
  awk -F= -v key="$key" '$1 == key { count++; value=substr($0, length(key) + 2) } END { if (count == 1 && value != "") print value; else exit 1 }' "$file"
}
stack=$(read_pair "$manifest" stack_name)
[[ "$stack" =~ ^d-[a-z2-7]{26}$ ]]
[[ "$(read_pair "$env_file" DIREXTALK_SPLIT_STACK_NAME)" == "$stack" ]]
container=$(docker compose --project-name "$stack" --env-file "$env_file" \
  -f /var/dirextalk-message-server/deploy/split-agent/compose.yaml \
  -f /var/dirextalk-message-server/deploy/split-agent/compose.production.yaml \
  ps --quiet message-server)
[[ "$container" =~ ^[0-9a-f]{64}$ ]]
[[ "$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}|{{ index .Config.Labels "com.docker.compose.service" }}|{{ .State.Health.Status }}' "$container")" == "$stack|message-server|healthy" ]]
docker exec "$container" /bin/cat /var/dirextalk-message-server/p2p/bootstrap.json
