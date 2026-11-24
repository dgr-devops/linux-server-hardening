# Decisiones de diseño

Notas breves sobre por qué el repositorio está hecho como está, con la alternativa descartada.

## 1. Auditoría propia en bash en vez de Lynis/OpenSCAP
El script `roles/audit/files/hardening-audit.sh` hace ~54 comprobaciones con PASS/FAIL/SKIP, severidad y
puntuación. Es legible en un minuto, no necesita instalar nada y sirve de documentación de lo que el playbook
corrige. *Descartado:* Lynis y OpenSCAP son más completos, pero su informe es largo y menos fácil de
enseñar en un README; el alcance aquí es deliberadamente acotado.

## 2. Códigos de salida estilo Nagios
`0` OK, `1` solo FAIL medios/bajos, `2` algún FAIL alto, `3` no se pudo auditar, `64` uso incorrecto; igual que
`bash-sysadmin-toolkit` y `python-devops-cli`. El script puede colgarse de cron o de un monitor.

## 3. Auditar la configuración, no solo el estado en ejecución
SSH se comprueba con `sshd -T` (configuración efectiva). Sysctl se lee de los ficheros (`/etc/sysctl.d`, con el
orden real de systemd), no de `/proc/sys`: así el mismo informe funciona en un contenedor, donde el kernel es
el del anfitrión. Coste: no detecta un valor cambiado a mano en caliente.
Los servicios se comprueban solo si hay systemd; si no, salen como `SKIP`, nunca como `PASS` falso.

## 4. SSH en un drop-in que se carga el primero
`/etc/ssh/sshd_config.d/10-hardening.conf` en vez de editar `sshd_config`: sshd usa el primer valor de cada
directiva, así que el drop-in gana a lo que haya después (incluidos los de cloud-init). El rol asegura que
`Include` está al principio y valida con `sshd -t` antes de escribir.

## 5. Protección anti-bloqueo
Si se desactiva `PasswordAuthentication`, el rol aborta salvo que exista algún `authorized_keys` con contenido
(`ssh_skip_lockout_check` la desactiva, solo para pruebas). Lo comprueba el test del contenedor.

## 6. NOPASSWD no se quita por defecto
Muchas imágenes cloud dependen de `NOPASSWD` para el usuario administrador; quitarlo a ciegas deja sin root.
`accounts_nopasswd_files` es una lista explícita (vacía por defecto); la auditoría lo marca como FAIL hasta
que se decida.

## 7. nftables en tabla propia, sin `flush ruleset`
Una tabla `inet hardening` evita borrar reglas de Docker o fail2ban. La política `forward` es `drop` por
defecto (servidor normal); en hosts con Docker o que enrutan hay que poner `firewall_forward_policy: accept`.
`nft -c` valida antes de desplegar. *Descartado:* ufw (una capa más sobre nftables, menos transparente).

## 8. Sin reinicios automáticos ni bloqueo del kernel
`Automatic-Reboot` y `-e 2` de auditd (reglas inmutables) vienen desactivados: ambos exigen una ventana de
mantenimiento acordada.

## 9. Test en contenedor, no Molecule
`tests/container/run.sh` construye un Ubuntu/Debian deliberadamente mal configurado, aplica el playbook dos veces
(la segunda debe dar `changed=0`) y exige `FAIL=0` en la auditoría final. Es Docker + Ansible, sin dependencias
extra. Limitación: sin systemd, así que servicios y sysctl en caliente no se ejercitan (variables
`hardening_manage_services` y `hardening_apply_runtime`).

## 10. Los informes son salida, no cambios
El rol `audit` guarda los informes en `reports/` de la máquina de control y no cuenta como `changed`. Una
segunda ejecución sobrescribe `*-before.*`: guarda una copia si quieres conservar el estado original.
