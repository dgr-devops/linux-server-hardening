# linux-server-hardening

Bastionado base de servidores **Debian/Ubuntu** con Ansible, más una **auditoría medible**: el mismo script
se ejecuta *antes* y *después* del playbook y se compara la puntuación. Todo es idempotente, está etiquetado
(`--tags`) y se prueba en un contenedor.

## Qué endurece y por qué

| Rol (tag) | Qué hace | Por qué |
|---|---|---|
| `ssh` | Drop-in `sshd_config.d`: sin root, sin contraseñas, `MaxAuthTries 3`, cifrados modernos, sin X11/agente/forwarding | SSH es la puerta de entrada; la fuerza bruta y las contraseñas débiles son el vector más común |
| `accounts` | sudo con `use_pty` y log propio, caducidad de contraseñas, `UMASK 027`, `su` solo para el grupo `sudo` | Limita el movimiento lateral y deja rastro de quién usó privilegios |
| `sysctl` | `rp_filter`, sin redirects ni source routing, syncookies, `kptr_restrict`, `dmesg_restrict`, protecciones de links | Reduce spoofing, MITM de red y fugas de información del kernel |
| `firewall` | nftables en tabla propia: entrada `drop`, SSH y puertos que indiques | Superficie mínima: solo lo que se abre expresamente |
| `updates` | `unattended-upgrades` diario, sin reinicio automático | Los parches de seguridad llegan sin intervención |
| `auditing` | `auditd` con vigilancia de passwd/shadow/sudoers/sshd | Trazabilidad de cambios en cuentas y privilegios |
| `fail2ban` | Jail `sshd` con `banaction = nftables` | Corta la fuerza bruta que consigue pasar el cortafuegos |
| `filesystem` | Permisos de `/etc/shadow` y otros, quita `o+w` en `/etc`, sin core dumps, módulos de FS raros bloqueados | Evita lecturas/escrituras indebidas y funciones de kernel sin uso |
| `audit` | Copia y ejecuta `hardening-audit.sh` y guarda `reports/<host>-before/after.{txt,json}` | Medir antes y después |

Decisiones y alternativas descartadas: [docs/decisiones.md](docs/decisiones.md).

## Uso

Requisitos: Ansible ≥ 2.15 en la máquina de control, SSH al servidor y `sudo`.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp inventory/hosts.ini.example inventory/hosts.ini   # edita tus hosts
```

```bash
ansible-playbook -i inventory/hosts.ini audit.yml              # solo auditar (no cambia nada)
ansible-playbook -i inventory/hosts.ini site.yml --check --diff # simulación
ansible-playbook -i inventory/hosts.ini site.yml                # audita, endurece, audita
ansible-playbook -i inventory/hosts.ini site.yml --tags ssh,firewall  # solo algunos roles
```

Antes de lanzarlo en un servidor real:

- Instala tu clave pública: el rol `ssh` **aborta** si desactivas contraseñas y no hay ningún `authorized_keys`.
- Revisa `firewall_extra_tcp_ports` y, en hosts con Docker, `firewall_forward_policy: accept`.
- Pon tu IP de administración en `fail2ban_ignoreip`.
- Todas las variables están en `roles/*/defaults/main.yml`.

El script de auditoría también funciona solo (como root): `hardening-audit.sh [--json] [--label TEXTO]`.
Códigos de salida estilo Nagios: `0` OK, `1` FAIL medio/bajo, `2` FAIL alto, `3` no auditable, `64` uso incorrecto.

## Resultado real: antes y después

Capturado ejecutando `tests/container/run.sh` (Ubuntu 24.04 en contenedor, configurado mal a propósito).
Informes completos: [antes](docs/ejemplos/auditoria-antes.txt) y [después](docs/ejemplos/auditoria-despues.txt).

**ANTES**

```text
[FAIL] SSH-01  (high  ) Login de root por SSH desactivado  -> permitrootlogin=yes (esperado: no)
[FAIL] SSH-02  (high  ) Autenticación por contraseña desactivada  -> passwordauthentication=yes (esperado: no)
[FAIL] FW-01   (high  ) Cortafuegos nftables instalado  -> paquete nftables no instalado
[FAIL] FS-01   (high  ) /etc/shadow con modo <= 640  -> modo=664
[FAIL] FS-06   (high  ) Sin ficheros escribibles por todos en /etc  -> encontrados: /etc/insecure-lab.conf
[FAIL] ACC-03  (medium) sudo siempre pide contraseña (sin NOPASSWD)  -> NOPASSWD en: /etc/sudoers.d/90-sysop
...
RESUMEN: 51 comprobaciones | PASS=10 FAIL=41 (altas: 7) SKIP=0 | puntuación: 19%
```

**DESPUÉS**

```text
[PASS] SSH-01  (high  ) Login de root por SSH desactivado
[PASS] SSH-02  (high  ) Autenticación por contraseña desactivada
[PASS] FW-02   (high  ) Política por defecto de entrada: drop
[PASS] FS-01   (high  ) /etc/shadow con modo <= 640
...
[SKIP] FW-04   (medium) nftables.service habilitado al arranque  -> systemd no está en ejecución (contenedor)
RESUMEN: 54 comprobaciones | PASS=51 FAIL=0 (altas: 0) SKIP=3 | puntuación: 100%
```

El playbook imprime además la comparación: `Puntuación 19% -> 100% | FAIL 41 -> 0 | PASS 10 -> 51`.
(El ANTES tiene 51 comprobaciones y el DESPUÉS 54 porque varias comprobaciones de auditd, fail2ban y
actualizaciones solo existen si el paquete está instalado.)

## Tests

```bash
tests/container/run.sh                # Ubuntu 24.04
tests/container/run.sh debian:12-slim # Debian 12
```

El script construye un contenedor mal configurado, comprueba que el rol `ssh` aborta sin claves (anti-bloqueo),
aplica el playbook, lo repite y exige `changed=0` (idempotencia) y `FAIL=0` en la auditoría final.
Lint: `yamllint .`, `ansible-lint` (perfil `production`) y `shellcheck`. CI en `.github/workflows/ci.yml`.

## Qué NO está verificado

- **Sin systemd:** en el contenedor no se arrancan ni habilitan servicios, no se recarga sshd ni se aplica
  `sysctl --system`, ni se cargan reglas de auditd. Las comprobaciones de servicio salen como `SKIP`.
- **sshd real:** se valida la configuración con `sshd -t` y `sshd -T`, pero no se ha probado una conexión SSH
  real con las nuevas opciones (cifrados/KEX restrictivos pueden fallar con clientes muy antiguos).
- **nftables:** las reglas se validan (`nft -c`) y se cargan en el netns del contenedor; no se ha probado
  tráfico real ni la interacción con Docker/Kubernetes.
- **fail2ban y auditd:** solo se comprueba la configuración, no que bloqueen o registren eventos.
- **Máquina virtual o servidor real:** no se ha ejecutado en un servidor físico ni en la nube.
- **Alcance:** es un bastionado base, no una certificación (CIS, STIG). La puntuación mide *estas* comprobaciones.
