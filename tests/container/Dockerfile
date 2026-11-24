# Servidor de pruebas "mal configurado": Ubuntu 24.04 con SSH y valores laxos a
# propósito, para que la auditoría ANTES tenga fallos reales que corregir.
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

# Sin systemd en el contenedor: impide que los paquetes intenten arrancar servicios.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod +x /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 sudo openssh-server cron iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Configuración laxa típica de una imagen sin revisar.
RUN mkdir -p /run/sshd \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?X11Forwarding.*/X11Forwarding yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 10/' /etc/ssh/sshd_config \
    && chmod 644 /etc/ssh/sshd_config /etc/crontab \
    && chmod 664 /etc/shadow \
    && useradd -m -s /bin/bash sysop \
    && printf 'sysop ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/90-sysop \
    && chmod 440 /etc/sudoers.d/90-sysop \
    && printf 'net.ipv4.conf.all.accept_redirects = 1\n' > /etc/sysctl.d/10-lab.conf \
    && printf 'debug = true\n' > /etc/insecure-lab.conf \
    && chmod 666 /etc/insecure-lab.conf

CMD ["sleep", "infinity"]
