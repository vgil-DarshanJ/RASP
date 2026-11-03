#!/usr/bin/env bash
# RASP Shield on the office server (192.168.2.208): backend API, customer
# portal and visitor site as three background processes, with logs.
#
#   scripts/office-server.sh deploy            git pull both repos, install, migrate, build, restart
#   scripts/office-server.sh start|stop|restart [all|be|portal|visitor]
#   scripts/office-server.sh status            running? + HTTP check of each
#   scripts/office-server.sh logs be|portal|visitor
#
#   backend  http://192.168.2.208:4444   (PORT in the backend .env)
#   portal   http://192.168.2.208:5050   (npm run start:portal)
#   visitor  http://192.168.2.208:6050   (npm run start:visitor)
#
# Repositories side by side, e.g. ~/Darshan/RASP_Backend and
# ~/Darshan/RASP_Dashboard. Override with FE_DIR=/path/to/dashboard.
# Logs and pids: <backend repo>/.office-server/ (ignored by git).
set -u

BE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -z "${FE_DIR:-}" ]; then
  for candidate in "$BE_DIR/../RASP_Dashboard" "$BE_DIR/../FE"; do
    if [ -f "$candidate/package.json" ]; then FE_DIR="$(cd "$candidate" && pwd)"; break; fi
  done
fi
FE_DIR="${FE_DIR:-$BE_DIR/../RASP_Dashboard}"
STATE_DIR="$BE_DIR/.office-server"
LOG_DIR="$STATE_DIR/logs"
mkdir -p "$LOG_DIR"

BE_PORT="$(grep -E '^PORT=' "$BE_DIR/.env" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '"' )"
BE_PORT="${BE_PORT:-4444}"
PORTAL_PORT=5050
VISITOR_PORT=6050

port_of() {
  case "$1" in be) echo "$BE_PORT" ;; portal) echo "$PORTAL_PORT" ;; visitor) echo "$VISITOR_PORT" ;; esac
}
dir_of() {
  case "$1" in be) echo "$BE_DIR" ;; *) echo "$FE_DIR" ;; esac
}
cmd_of() {
  case "$1" in be) echo "node dist/index.js" ;; portal) echo "npm run start:portal" ;; visitor) echo "npm run start:visitor" ;; esac
}
url_of() {
  case "$1" in be) echo "http://127.0.0.1:$BE_PORT/healthz" ;; *) echo "http://127.0.0.1:$(port_of "$1")/" ;; esac
}

# PID of whatever listens on a port, if any.
port_pid() {
  ss -ltnpH "sport = :$1" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | head -1
}

start_one() {
  local name="$1" port dir cmd pid
  port="$(port_of "$name")"; dir="$(dir_of "$name")"; cmd="$(cmd_of "$name")"
  if pid="$(port_pid "$port")" && [ -n "$pid" ]; then
    echo "$name already running (pid $pid, port $port)."
    return 0
  fi
  if [ "$name" = "be" ] && [ ! -f "$BE_DIR/dist/index.js" ]; then
    echo "be: not built yet. Run: $0 deploy   (or: cd $BE_DIR && npm run build)"; return 1
  fi
  if [ "$name" != "be" ] && [ ! -d "$FE_DIR/.next" ]; then
    echo "$name: dashboard not built yet. Run: $0 deploy   (or: cd $FE_DIR && npm run build)"; return 1
  fi
  echo "Starting $name on port $port..."
  (
    cd "$dir" || exit 1
    echo "===== $(date '+%F %T') start: $cmd" >> "$LOG_DIR/$name.log"
    nohup bash -c "$cmd" >> "$LOG_DIR/$name.log" 2>&1 &
    echo $! > "$STATE_DIR/$name.pid"
  )
  for _ in $(seq 1 30); do
    if pid="$(port_pid "$port")" && [ -n "$pid" ]; then
      echo "$name started (pid $pid). Log: $LOG_DIR/$name.log"
      return 0
    fi
    sleep 1
  done
  echo "$name did not open port $port within 30 s. Last log lines:"
  tail -n 20 "$LOG_DIR/$name.log"
  return 1
}

stop_one() {
  local name="$1" port pid
  port="$(port_of "$name")"
  if pid="$(port_pid "$port")" && [ -n "$pid" ]; then
    echo "Stopping $name (pid $pid)..."
    # Stops the listening process (node / next-server); its npm wrapper then exits.
    kill "$pid" 2>/dev/null
    for _ in $(seq 1 10); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
    echo "$name stopped."
  else
    echo "$name not running."
  fi
  rm -f "$STATE_DIR/$name.pid"
}

status_one() {
  local name="$1" port pid code
  port="$(port_of "$name")"
  if pid="$(port_pid "$port")" && [ -n "$pid" ]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$(url_of "$name")")"
    echo "$name: RUNNING  pid $pid  port $port  -> HTTP $code"
  else
    echo "$name: STOPPED  (port $port free)"
  fi
}

targets() {
  case "${1:-all}" in
    all) echo "be portal visitor" ;;
    be|portal|visitor) echo "$1" ;;
    *) echo "Unknown target '$1' (all|be|portal|visitor)" >&2; exit 2 ;;
  esac
}

# `docker compose` (v2 plugin) or `docker-compose` (v1). Postgres and Redis
# may also run outside Docker: then this only warns.
start_databases() {
  if docker compose version >/dev/null 2>&1; then
    docker compose up -d postgres redis && return 0
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose up -d postgres redis && return 0
  fi
  echo "warning: could not start postgres/redis with Docker Compose; continuing (they must already be running)."
}

deploy() {
  set -e
  echo "== Backend: $BE_DIR"
  cd "$BE_DIR"
  git pull --ff-only
  npm ci
  start_databases
  npx prisma generate
  npx prisma migrate deploy
  npm run build
  echo "== Dashboard: $FE_DIR"
  cd "$FE_DIR"
  git pull --ff-only
  npm ci
  npm run build
  set +e
  for t in be portal visitor; do stop_one "$t"; done
  for t in be portal visitor; do start_one "$t"; done
  echo
  status
}

status() {
  for t in be portal visitor; do status_one "$t"; done
  echo "Status page: http://192.168.2.208:$PORTAL_PORT/status"
}

case "${1:-}" in
  deploy) deploy ;;
  start) for t in $(targets "${2:-all}"); do start_one "$t"; done ;;
  stop) for t in $(targets "${2:-all}"); do stop_one "$t"; done ;;
  restart) for t in $(targets "${2:-all}"); do stop_one "$t"; start_one "$t"; done ;;
  status) status ;;
  logs) tail -n 80 -f "$LOG_DIR/${2:-be}.log" ;;
  *)
    sed -n '2,17p' "$0"
    exit 1
    ;;
esac
