#!/usr/bin/env bash
# scripts/security_check.sh — перевірка безпеки перед здачею/деплоєм. Exit 1 = є FAIL.
export MSYS_NO_PATHCONV=1  # Git Bash на Windows: не перетворювати /шляхи
set -u
cd "$(dirname "$0")/.."
IMAGE="${IMAGE:-information-security-practice-api}"
FAIL=0; WARN=0
ok()   { echo "  [OK]   $1"; }
warn() { echo "  [WARN] $1"; WARN=$((WARN+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
mkdir -p reports

echo "== 1. Секрети =="
grep -qxE '\.env' .gitignore 2>/dev/null && ok ".env у .gitignore" || fail ".env відсутній у .gitignore"
git ls-files --error-unmatch .env >/dev/null 2>&1 && fail ".env відстежується Git!" || ok ".env не в Git"
if git log --all -p 2>/dev/null | grep -E '^\+.*(ENCRYPTION_KEY|BLIND_INDEX_KEY|JWT_SECRET_KEY)=[A-Za-z0-9_=-]{20,}' \
     | grep -qvE 'replace-me|change-me|your-|<'; then
  fail "секрет в історії Git — ротуйте ключі!"
else ok "секретів в історії Git не знайдено"; fi
if grep -rnE 'getenv\("[A-Z_]*(SECRET|KEY|PASSWORD)[A-Z_]*", *"[^"]{8,}"' app/ --include='*.py'; then
  fail "fallback-секрет у getenv (див. вище)"
else ok "fallback-секретів у коді немає"; fi
grep -q ':-dev' docker-compose.yml && fail "docker-compose.yml: dev-значення секрету за замовчуванням" \
  || ok "docker-compose.yml без dev-секретів"

echo "== 2. Docker =="
grep -qE '^USER\s+\S+' Dockerfile && ok "Dockerfile: USER (non-root)" || fail "Dockerfile без USER"
grep -q '^HEALTHCHECK' Dockerfile && ok "Dockerfile: HEALTHCHECK" || warn "немає HEALTHCHECK"
grep -qE '^CMD.*--reload' Dockerfile && warn "Dockerfile: --reload (лише для розробки)" || ok "без --reload"
grep -q 'read_only: true' docker-compose.yml && ok "compose: read_only" || warn "compose: немає read_only"
grep -q 'no-new-privileges' docker-compose.yml && ok "compose: no-new-privileges" || warn "compose: немає no-new-privileges"
CID=$(docker compose ps -q api 2>/dev/null)
if [ -n "$CID" ]; then
  WHO=$(docker compose exec -T api whoami 2>/dev/null | tr -d '\r')
  [ -n "$WHO" ] && [ "$WHO" != "root" ] && ok "процес працює від '$WHO'" || fail "контейнер працює від root"
  H=$(docker inspect --format='{{.State.Health.Status}}' "$CID")
  [ "$H" = "healthy" ] && ok "healthcheck: healthy" || warn "healthcheck: $H"
else warn "api не запущено — runtime-перевірки пропущено"; fi

echo "== 3. HTTPS і заголовки =="
HDR=$(curl -sk -D - -o /dev/null https://localhost/health 2>/dev/null)
if [ -n "$HDR" ]; then
  for h in Strict-Transport-Security Content-Security-Policy X-Frame-Options X-Content-Type-Options; do
    echo "$HDR" | grep -qi "^$h:" && ok "заголовок $h" || fail "немає заголовка $h"
  done
  echo "$HDR" | grep -qi '^server: nginx/' && warn "Nginx розкриває версію" || ok "версія сервера прихована"
  CODE=$(curl -s -o /dev/null -w '%{http_code}' http://localhost/)
  [ "$CODE" = "301" ] && ok "HTTP -> HTTPS (301)" || warn "HTTP повертає $CODE"
else warn "https://localhost недоступний"; fi

echo "== 4. Залежності, код, образ =="
if docker info >/dev/null 2>&1; then
  docker run --rm -v "$(pwd -W 2>/dev/null || pwd)":/src -w /src python:3.11-slim sh -c \
    "pip install -q pip-audit >/dev/null 2>&1 && pip-audit -r requirements.txt" > reports/pip-audit.txt 2>&1 \
    && ok "pip-audit: вразливостей не знайдено" || warn "pip-audit: є знахідки (reports/pip-audit.txt)"
  docker run --rm -v "$(pwd -W 2>/dev/null || pwd)":/src -w /src python:3.11-slim sh -c \
    "pip install -q bandit >/dev/null 2>&1 && bandit -r app -lll -q" > reports/bandit-high.txt 2>&1 \
    && ok "Bandit: HIGH-проблем немає" || fail "Bandit: є HIGH (reports/bandit-high.txt)"
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.56.2 image -q \
      --severity CRITICAL --ignore-unfixed --exit-code 1 "$IMAGE" > reports/trivy-critical.txt 2>&1 \
      && ok "Trivy: CRITICAL з виправленням немає" || warn "Trivy: є CRITICAL (reports/trivy-critical.txt)"
  else warn "образ $IMAGE не знайдено (docker compose build)"; fi
else warn "Docker daemon недоступний — сканери пропущено"; fi

echo "=================================="
echo "FAIL: $FAIL  WARN: $WARN"
[ "$FAIL" -eq 0 ] && echo "SECURITY CHECK PASSED" || echo "SECURITY CHECK FAILED"
exit $(( FAIL > 0 ))
