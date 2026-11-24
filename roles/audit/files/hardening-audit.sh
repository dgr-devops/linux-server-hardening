#!/usr/bin/env bash
# hardening-audit.sh - auditoría de bastionado para Debian/Ubuntu.
#
# Comprueba la configuración del servidor (SSH, cuentas, sysctl, cortafuegos,
# actualizaciones, auditd, fail2ban, permisos) y muestra PASS/FAIL/SKIP por
# comprobación más un resumen con puntuación. Solo lee: no modifica nada.
#
# Códigos de salida (estilo Nagios, igual que bash-sysadmin-toolkit):
#   0 sin FAIL | 1 solo FAIL de severidad media/baja | 2 algún FAIL alto
#   3 no se pudo auditar (no es root, sistema no soportado) | 64 uso incorrecto
# Las funciones auxiliares se invocan de forma indirecta mediante rc().
# shellcheck disable=SC2329,SC2317
set -u

readonly EX_OK=0 EX_WARNING=1 EX_CRITICAL=2 EX_UNKNOWN=3 EX_USAGE=64
readonly SSH_MAX_AUTH_TRIES=4 SSH_MAX_GRACE_TIME=60 SSH_MAX_ALIVE_COUNT=3
readonly PASS_MAX_DAYS_LIMIT=365

JSON=0
LABEL=""
PASS=0 FAIL=0 SKIP=0 HIGH_FAIL=0
RESULTS=()

usage() {
  cat <<'EOF'
Uso: hardening-audit.sh [--json] [--label ETIQUETA]

  --json            salida en JSON en vez de texto
  --label ETIQUETA  texto que aparece en la cabecera (p. ej. ANTES / DESPUÉS)
  -h, --help        esta ayuda

Códigos de salida: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN, 64 uso incorrecto.
EOF
}

die_usage() {
  echo "hardening-audit.sh: $1" >&2
  usage >&2
  exit "$EX_USAGE"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=1 ;;
    --label)
      [ $# -ge 2 ] || die_usage "--label necesita un valor"
      LABEL=$2
      shift
      ;;
    -h | --help)
      usage
      exit "$EX_OK"
      ;;
    *) die_usage "opción desconocida: $1" ;;
  esac
  shift
done

# --- registro de resultados ---------------------------------------------------

record() { # estado id severidad descripción detalle
  RESULTS+=("$1|$2|$3|$4|$5")
  case "$1" in
    PASS) PASS=$((PASS + 1)) ;;
    SKIP) SKIP=$((SKIP + 1)) ;;
    FAIL)
      FAIL=$((FAIL + 1))
      [ "$3" = "high" ] && HIGH_FAIL=$((HIGH_FAIL + 1))
      ;;
  esac
  return 0
}

# evaluate ID SEV DESC RC DETALLE: RC 0 = cumple
evaluate() {
  if [ "$4" -eq 0 ]; then
    record PASS "$1" "$2" "$3" "$5"
  else
    record FAIL "$1" "$2" "$3" "$5"
  fi
}

skip() { record SKIP "$1" "$2" "$3" "$4"; }

# rc CONDICIÓN...: imprime 0 si el comando se cumple, 1 si no.
rc() { if "$@"; then echo 0; else echo 1; fi; }

# --- utilidades ---------------------------------------------------------------

pkg_installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}

systemd_running() { [ -d /run/systemd/system ]; }

file_mode() { stat -c '%a' "$1" 2>/dev/null; }

# Modo octal <= máximo permitido (ningún bit extra respecto al máximo).
mode_within() { # modo máximo
  [ -n "$1" ] && [ $((8#$1 & ~8#$2)) -eq 0 ]
}

is_eq() { [ "$1" = "$2" ]; }
is_le() { [ -n "$1" ] && [ "$1" -le "$2" ] 2>/dev/null; }

sysctl_files() {
  local -A seen=()
  local dir f
  for dir in /etc/sysctl.d /run/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d; do
    for f in "$dir"/*.conf; do
      [ -e "$f" ] || continue
      [ -n "${seen[${f##*/}]:-}" ] && continue
      seen[${f##*/}]=$f
    done
  done
  for f in "${seen[@]}"; do echo "$f"; done | awk -F/ '{print $NF"\t"$0}' | sort | cut -f2-
  [ -r /etc/sysctl.conf ] && echo /etc/sysctl.conf
  return 0
}

# Valor configurado (el último que gana) de una clave sysctl en los ficheros.
sysctl_value() {
  local key=$1 value="" f line
  while IFS= read -r f; do
    line=$(grep -E "^[[:space:]]*${key//./\\.}[[:space:]]*=" "$f" 2>/dev/null | tail -n 1)
    [ -n "$line" ] && value=$(echo "${line#*=}" | tr -d '[:space:]')
  done < <(sysctl_files)
  echo "$value"
}

# grep silencioso recursivo sobre rutas que pueden no existir.
has_line() { # regex ruta...
  local re=$1
  shift
  grep -rEqs "$re" "$@"
}

# --- comprobaciones -----------------------------------------------------------

check_ssh() {
  local out
  if ! command -v sshd >/dev/null 2>&1; then
    skip SSH-00 high "Servidor OpenSSH instalado" "sshd no está instalado"
    return
  fi
  mkdir -p /run/sshd 2>/dev/null
  if ! out=$(sshd -T 2>/dev/null) || [ -z "$out" ]; then
    skip SSH-00 high "Configuración efectiva de sshd legible" "sshd -T falló (¿sin claves de host?)"
    return
  fi
  ssh_get() { awk -v k="$1" '$1 == k { print $2; exit }' <<<"$out"; }
  local v interval count

  v=$(ssh_get permitrootlogin)
  evaluate SSH-01 high "Login de root por SSH desactivado" "$(rc is_eq "$v" no)" "permitrootlogin=$v (esperado: no)"
  v=$(ssh_get passwordauthentication)
  evaluate SSH-02 high "Autenticación por contraseña desactivada" "$(rc is_eq "$v" no)" "passwordauthentication=$v (esperado: no)"
  v=$(ssh_get permitemptypasswords)
  evaluate SSH-03 high "Contraseñas vacías prohibidas" "$(rc is_eq "$v" no)" "permitemptypasswords=$v (esperado: no)"
  v=$(ssh_get x11forwarding)
  evaluate SSH-04 medium "Reenvío X11 desactivado" "$(rc is_eq "$v" no)" "x11forwarding=$v (esperado: no)"
  v=$(ssh_get maxauthtries)
  evaluate SSH-05 medium "MaxAuthTries <= $SSH_MAX_AUTH_TRIES" "$(rc is_le "$v" "$SSH_MAX_AUTH_TRIES")" "maxauthtries=$v (esperado: <= $SSH_MAX_AUTH_TRIES)"
  v=$(ssh_get logingracetime)
  evaluate SSH-06 medium "LoginGraceTime <= ${SSH_MAX_GRACE_TIME}s" "$(rc is_le "$v" "$SSH_MAX_GRACE_TIME")" "logingracetime=$v (esperado: <= $SSH_MAX_GRACE_TIME)"
  interval=$(ssh_get clientaliveinterval)
  count=$(ssh_get clientalivecountmax)
  evaluate SSH-07 medium "Sesiones inactivas se cierran (ClientAlive)" \
    "$([ "${interval:-0}" -gt 0 ] && rc is_le "$count" "$SSH_MAX_ALIVE_COUNT" || echo 1)" \
    "clientaliveinterval=$interval clientalivecountmax=$count"
  v=$(ssh_get allowagentforwarding)
  evaluate SSH-08 low "Reenvío del agente SSH desactivado" "$(rc is_eq "$v" no)" "allowagentforwarding=$v (esperado: no)"
  v=$(ssh_get hostbasedauthentication)
  evaluate SSH-09 medium "Autenticación basada en host desactivada" "$(rc is_eq "$v" no)" "hostbasedauthentication=$v (esperado: no)"
}

check_accounts() {
  local extra empty nopasswd max_days umask_val
  extra=$(awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd | paste -sd, -)
  evaluate ACC-01 high "Solo root tiene UID 0" "$(rc test -z "$extra")" "otras cuentas UID 0: ${extra:-ninguna}"
  empty=$(awk -F: '$2 == "" { print $1 }' /etc/shadow 2>/dev/null | paste -sd, -)
  evaluate ACC-02 high "Ninguna cuenta con contraseña vacía" "$(rc test -z "$empty")" "cuentas sin contraseña: ${empty:-ninguna}"

  nopasswd=$(grep -rEsl '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | paste -sd, -)
  evaluate ACC-03 medium "sudo siempre pide contraseña (sin NOPASSWD)" "$(rc test -z "$nopasswd")" "NOPASSWD en: ${nopasswd:-ningún fichero}"
  evaluate ACC-04 low "sudo usa pty (use_pty)" \
    "$(rc has_line '^[[:space:]]*Defaults[[:space:]]+([^#]*,[[:space:]]*)?use_pty' /etc/sudoers /etc/sudoers.d)" "Defaults use_pty en sudoers"
  evaluate ACC-05 low "sudo registra en fichero propio (logfile)" \
    "$(rc has_line '^[[:space:]]*Defaults[[:space:]]+([^#]*,[[:space:]]*)?logfile' /etc/sudoers /etc/sudoers.d)" "Defaults logfile en sudoers"

  max_days=$(awk '$1 == "PASS_MAX_DAYS" { print $2 }' /etc/login.defs 2>/dev/null | tail -n 1)
  evaluate ACC-06 medium "PASS_MAX_DAYS <= $PASS_MAX_DAYS_LIMIT en login.defs" \
    "$(rc is_le "$max_days" "$PASS_MAX_DAYS_LIMIT")" "PASS_MAX_DAYS=${max_days:-sin definir}"
  umask_val=$(awk '$1 == "UMASK" { print $2 }' /etc/login.defs 2>/dev/null | tail -n 1)
  evaluate ACC-07 medium "UMASK por defecto 027 o más estricta" \
    "$([[ "$umask_val" =~ ^0?(27|37|77)$ ]] && echo 0 || echo 1)" "UMASK=${umask_val:-sin definir}"
  evaluate ACC-08 medium "su restringido al grupo sudo (pam_wheel)" \
    "$(rc has_line '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\.so' /etc/pam.d/su)" "pam_wheel en /etc/pam.d/su"
}

check_sysctl() {
  local spec id sev key want got
  local -a specs=(
    "SYS-01|high|net.ipv4.tcp_syncookies|1"
    "SYS-02|medium|net.ipv4.conf.all.rp_filter|1"
    "SYS-03|medium|net.ipv4.conf.all.accept_redirects|0"
    "SYS-04|medium|net.ipv4.conf.all.send_redirects|0"
    "SYS-05|medium|net.ipv4.conf.all.accept_source_route|0"
    "SYS-06|low|net.ipv4.conf.all.log_martians|1"
    "SYS-07|low|net.ipv4.icmp_echo_ignore_broadcasts|1"
    "SYS-08|medium|net.ipv6.conf.all.accept_redirects|0"
    "SYS-09|medium|kernel.randomize_va_space|2"
    "SYS-10|medium|kernel.kptr_restrict|2"
    "SYS-11|low|kernel.dmesg_restrict|1"
    "SYS-12|medium|fs.protected_hardlinks|1"
    "SYS-13|medium|fs.protected_symlinks|1"
    "SYS-14|medium|fs.suid_dumpable|0"
  )
  for spec in "${specs[@]}"; do
    IFS='|' read -r id sev key want <<<"$spec"
    got=$(sysctl_value "$key")
    evaluate "$id" "$sev" "sysctl $key = $want" "$(rc is_eq "$got" "$want")" "configurado=${got:-sin definir} (esperado: $want)"
  done
}

check_firewall() {
  local rules="" policy
  if ! pkg_installed nftables; then
    evaluate FW-01 high "Cortafuegos nftables instalado" 1 "paquete nftables no instalado"
    evaluate FW-02 high "Política por defecto de entrada: drop" 1 "sin /etc/nftables.conf gestionado"
    evaluate FW-03 medium "SSH permitido explícitamente en el cortafuegos" 1 "sin /etc/nftables.conf gestionado"
    return
  fi
  evaluate FW-01 high "Cortafuegos nftables instalado" 0 "paquete nftables presente"
  [ -r /etc/nftables.conf ] && rules=$(tr '\n' ' ' </etc/nftables.conf)
  policy=$(grep -Eo 'hook input[^}]*policy (drop|accept)' <<<"$rules" | grep -Eo '(drop|accept)$' | head -n 1)
  evaluate FW-02 high "Política por defecto de entrada: drop" "$(rc is_eq "$policy" drop)" "policy input=${policy:-sin definir}"
  evaluate FW-03 medium "SSH permitido explícitamente en el cortafuegos" \
    "$(grep -Eq 'tcp dport[^;]*22[^;]*accept' <<<"$rules" && echo 0 || echo 1)" "regla tcp dport 22 accept"
  if systemd_running; then
    evaluate FW-04 medium "nftables.service habilitado al arranque" "$(rc systemctl is-enabled nftables)" "systemctl is-enabled nftables"
  else
    skip FW-04 medium "nftables.service habilitado al arranque" "systemd no está en ejecución (contenedor)"
  fi
}

check_updates() {
  local conf
  if ! pkg_installed unattended-upgrades; then
    evaluate UPD-01 medium "unattended-upgrades instalado" 1 "paquete no instalado"
    evaluate UPD-02 medium "Actualizaciones automáticas activadas (Unattended-Upgrade 1)" 1 "paquete no instalado"
    evaluate UPD-03 low "Lista de paquetes se refresca a diario" 1 "paquete no instalado"
    return
  fi
  evaluate UPD-01 medium "unattended-upgrades instalado" 0 "paquete presente"
  conf=$(apt-config dump 2>/dev/null)
  evaluate UPD-02 medium "Actualizaciones automáticas activadas (Unattended-Upgrade 1)" \
    "$(grep -Eq '^APT::Periodic::Unattended-Upgrade "1"' <<<"$conf" && echo 0 || echo 1)" "APT::Periodic::Unattended-Upgrade"
  evaluate UPD-03 low "Lista de paquetes se refresca a diario" \
    "$(grep -Eq '^APT::Periodic::Update-Package-Lists "1"' <<<"$conf" && echo 0 || echo 1)" "APT::Periodic::Update-Package-Lists"
}

check_auditd() {
  if ! pkg_installed auditd; then
    evaluate AUD-01 medium "auditd instalado" 1 "paquete no instalado"
    evaluate AUD-02 medium "Reglas de auditoría sobre identidad (/etc/passwd, /etc/shadow)" 1 "paquete no instalado"
    evaluate AUD-03 medium "Reglas de auditoría sobre sudoers y SSH" 1 "paquete no instalado"
    return
  fi
  evaluate AUD-01 medium "auditd instalado" 0 "paquete presente"
  evaluate AUD-02 medium "Reglas de auditoría sobre identidad (/etc/passwd, /etc/shadow)" \
    "$(rc has_line '^-w /etc/(passwd|shadow)' /etc/audit/rules.d)" "reglas -w en /etc/audit/rules.d"
  evaluate AUD-03 medium "Reglas de auditoría sobre sudoers y SSH" \
    "$(rc has_line '^-w /etc/(sudoers|ssh/sshd_config)' /etc/audit/rules.d)" "reglas -w sudoers/sshd_config"
  if systemd_running; then
    evaluate AUD-04 medium "auditd.service activo" "$(rc systemctl is-active auditd)" "systemctl is-active auditd"
  else
    skip AUD-04 medium "auditd.service activo" "systemd no está en ejecución (contenedor)"
  fi
}

check_fail2ban() {
  if ! pkg_installed fail2ban; then
    evaluate F2B-01 medium "fail2ban instalado" 1 "paquete no instalado"
    evaluate F2B-02 medium "Jail sshd de fail2ban activa" 1 "paquete no instalado"
    return
  fi
  evaluate F2B-01 medium "fail2ban instalado" 0 "paquete presente"
  evaluate F2B-02 medium "Jail sshd de fail2ban activa" \
    "$(fail2ban-client -d 2>/dev/null | grep -q "'add', 'sshd'" && echo 0 || echo 1)" "fail2ban-client -d"
  if systemd_running; then
    evaluate F2B-03 medium "fail2ban.service activo" "$(rc systemctl is-active fail2ban)" "systemctl is-active fail2ban"
  else
    skip F2B-03 medium "fail2ban.service activo" "systemd no está en ejecución (contenedor)"
  fi
}

check_files() {
  local mode ww
  mode=$(file_mode /etc/shadow)
  evaluate FS-01 high "/etc/shadow con modo <= 640" "$(rc mode_within "$mode" 640)" "modo=$mode"
  mode=$(file_mode /etc/gshadow)
  evaluate FS-02 high "/etc/gshadow con modo <= 640" "$(rc mode_within "$mode" 640)" "modo=$mode"
  mode=$(file_mode /etc/passwd)
  evaluate FS-03 medium "/etc/passwd con modo <= 644" "$(rc mode_within "$mode" 644)" "modo=$mode"
  mode=$(file_mode /etc/ssh/sshd_config)
  evaluate FS-04 medium "/etc/ssh/sshd_config con modo <= 600" "$(rc mode_within "$mode" 600)" "modo=${mode:-no existe}"
  mode=$(file_mode /etc/crontab)
  evaluate FS-05 medium "/etc/crontab con modo <= 600" "$(rc mode_within "$mode" 600)" "modo=${mode:-no existe}"

  ww=$(find /etc -xdev -type f -perm -0002 2>/dev/null | head -n 5 | paste -sd, -)
  evaluate FS-06 high "Sin ficheros escribibles por todos en /etc" "$(rc test -z "$ww")" "encontrados: ${ww:-ninguno}"
  mode=$(file_mode /tmp)
  evaluate FS-07 medium "/tmp con sticky bit" "$([ -n "$mode" ] && [ $((8#$mode & 8#1000)) -ne 0 ] && echo 0 || echo 1)" "modo=$mode"
  evaluate FS-08 low "Volcados de memoria (core dumps) desactivados en limits" \
    "$(rc has_line '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf /etc/security/limits.d)" "* hard core 0"
  evaluate FS-09 low "Módulos de sistemas de ficheros raros bloqueados (cramfs, udf)" \
    "$(rc has_line '^install (cramfs|udf) /bin/(true|false)' /etc/modprobe.d)" "install cramfs /bin/true"
}

# --- salida -------------------------------------------------------------------

json_escape() { sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' <<<"$1"; }

score() {
  local total=$((PASS + FAIL))
  if [ "$total" -eq 0 ]; then echo 0; else echo $((PASS * 100 / total)); fi
}

os_name() {
  # shellcheck disable=SC1091
  (. /etc/os-release && echo "$PRETTY_NAME")
}

print_text() {
  local r status id sev desc detail
  echo "== Auditoría de bastionado${LABEL:+ - $LABEL} =="
  echo "sistema: $(os_name)"
  echo
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r status id sev desc detail <<<"$r"
    printf '[%s] %-7s (%-6s) %s' "$status" "$id" "$sev" "$desc"
    if [ "$status" != PASS ]; then printf '  -> %s' "$detail"; fi
    printf '\n'
  done
  echo
  echo "RESUMEN: $((PASS + FAIL + SKIP)) comprobaciones | PASS=$PASS FAIL=$FAIL (altas: $HIGH_FAIL) SKIP=$SKIP | puntuación: $(score)%"
}

print_json() {
  local r status id sev desc detail first=1
  printf '{"label":"%s","pass":%d,"fail":%d,"fail_high":%d,"skip":%d,"score":%d,"checks":[' \
    "$(json_escape "$LABEL")" "$PASS" "$FAIL" "$HIGH_FAIL" "$SKIP" "$(score)"
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r status id sev desc detail <<<"$r"
    [ "$first" -eq 1 ] || printf ','
    first=0
    printf '{"id":"%s","status":"%s","severity":"%s","description":"%s","detail":"%s"}' \
      "$id" "$status" "$sev" "$(json_escape "$desc")" "$(json_escape "$detail")"
  done
  printf ']}\n'
}

main() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "UNKNOWN: se necesita root para leer /etc/shadow y la configuración efectiva de sshd" >&2
    exit "$EX_UNKNOWN"
  fi
  if ! command -v dpkg-query >/dev/null 2>&1; then
    echo "UNKNOWN: solo se soportan sistemas Debian/Ubuntu (falta dpkg-query)" >&2
    exit "$EX_UNKNOWN"
  fi

  check_ssh
  check_accounts
  check_sysctl
  check_firewall
  check_updates
  check_auditd
  check_fail2ban
  check_files

  if [ "$JSON" -eq 1 ]; then print_json; else print_text; fi

  if [ "$HIGH_FAIL" -gt 0 ]; then exit "$EX_CRITICAL"; fi
  if [ "$FAIL" -gt 0 ]; then exit "$EX_WARNING"; fi
  exit "$EX_OK"
}

main
