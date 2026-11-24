#!/usr/bin/env bash
# Test de integración en contenedor: aplica el playbook sobre un servidor mal
# configurado, comprueba idempotencia y que la auditoría final no tenga FAIL.
#
# Uso: tests/container/run.sh [imagen_base]   (por defecto ubuntu:24.04)
# Requiere: docker y ansible-playbook con la colección community.docker.
set -euo pipefail

BASE_IMAGE=${1:-ubuntu:24.04}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE="lsh-test-base:$(echo "$BASE_IMAGE" | tr ':/' '--')"
NAME="lsh-test"
RUN_LOG=$(mktemp)

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -f "$RUN_LOG"
}
trap cleanup EXIT

echo "==> Construyendo imagen $IMAGE (base $BASE_IMAGE)"
docker build -q --build-arg "BASE_IMAGE=$BASE_IMAGE" -t "$IMAGE" "$ROOT/tests/container" >/dev/null

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --cap-add NET_ADMIN --name "$NAME" "$IMAGE" >/dev/null

cd "$ROOT"
export ANSIBLE_CONFIG="$ROOT/ansible.cfg"
mkdir -p reports

echo "==> Protección anti-bloqueo: sin claves SSH debe abortar"
if ansible-playbook -i tests/container/inventory.yml site.yml --tags ssh -e ssh_skip_lockout_check=false >"$RUN_LOG" 2>&1; then
  echo "FALLO: el rol ssh no abortó sin authorized_keys" >&2
  exit 1
fi
grep -q 'dejaría el servidor inaccesible' "$RUN_LOG" || { echo "FALLO: mensaje anti-bloqueo no encontrado" >&2; exit 1; }

echo "==> Primera pasada (aplica el bastionado)"
ansible-playbook -i tests/container/inventory.yml site.yml
mkdir -p reports/primera-pasada
cp reports/lsh-test-before.* reports/lsh-test-after.* reports/primera-pasada/

echo "==> Segunda pasada (debe ser idempotente: changed=0)"
ansible-playbook -i tests/container/inventory.yml site.yml | tee "$RUN_LOG"
if ! grep -Eq 'ok=[0-9]+ +changed=0 +unreachable=0 +failed=0' "$RUN_LOG"; then
  echo "FALLO: la segunda pasada no es idempotente" >&2
  exit 1
fi

echo "==> Comprobando que la auditoría final no tiene FAIL"
if ! grep -q 'FAIL=0 ' "$ROOT/reports/lsh-test-after.txt"; then
  echo "FALLO: la auditoría DESPUÉS tiene fallos:" >&2
  grep '^\[FAIL\]' "$ROOT/reports/lsh-test-after.txt" >&2 || true
  exit 1
fi
echo "OK: bastionado aplicado, idempotente y auditoría sin FAIL"
