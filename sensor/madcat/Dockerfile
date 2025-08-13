FROM ubuntu:22.04

# === Essentials installieren ===
# locales-all ist sehr groß, ggf. nur en_US.UTF-8 installieren
RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends \
    locales iproute2 file libc-bin enca iptables openssh-server dnsutils git build-essential cmake libssl-dev lsof nano \
    libpcap0.8 libpcap-dev liblua5.1-0 liblua5.1-0-dev \
    python3-dev python3-apt conntrack auditd audispd-plugins net-tools \
    python3-pip curl wget ca-certificates && \
    # install specific locales instead of all
    echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && \
    locale-gen && \
    pip3 install --no-cache-dir psutil redis chardet luaparser==3.2.1 && \
    update-locale LANG=en_US.UTF-8 && \
    update-alternatives --install /usr/sbin/iptables iptables /usr/sbin/iptables-legacy 100 && \
    update-alternatives --set iptables /usr/sbin/iptables-legacy && \
    update-alternatives --install /usr/sbin/ip6tables ip6tables /usr/sbin/ip6tables-legacy 100 && \
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8
# === MADCAT Repository klonen ===
RUN git clone https://github.com/BSI-Bund/MADCAT_v2.git /opt/madcat

RUN useradd -m -s /bin/bash madcat
RUN chown -R madcat:madcat /opt/madcat

# === Build
WORKDIR /opt/madcat/build
RUN cmake .. && make

# === Skripte & Binaries korrekt kopieren
WORKDIR /opt/madcat
RUN for bin in udp_ip_port_mon icmp_mon raw_mon tcp_ip_port_mon; do \
      found=$(find . -type f -name "$bin" -executable | head -n 1); \
      if [ -n "$found" ]; then \
        echo " Gefunden: $found → /opt/madcat/$bin" && install -m 755 "$found" "/opt/madcat/$bin"; \
      else \
        echo " $bin nicht gefunden!" && exit 1; \
      fi; \
    done && \
    for script in enrichment_processor.py tcp_ip_port_mon_postprocessor.py; do \
      found=$(find . -type f -name "$script" | head -n 1); \
      if [ -n "$found" ]; then \
        echo " Gefunden: $found → /opt/madcat/$script" && install -m 755 "$found" "/opt/madcat/$script"; \
      else \
        echo " $script nicht gefunden!" && exit 1; \
      fi; \
    done

# === Konfiguration zuerst kopieren
#COPY dist/madcat_config.lua /opt/madcat/config/config.lua
COPY dist/madcat_config.lua /etc/madcat/config.lua
# === Jetzt den Symlink setzen
#RUN mkdir -p /etc/madcat && \
#    ln -sf /opt/madcat/config/config.lua /etc/madcat/config.lua

COPY dist/monitoring_config.py /etc/madcat/monitoring_config.py
COPY dist/redirector.py /opt/madcat/redirector.py


# === Entrypoint & Logs vorbereiten ===
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /opt/madcat/scripts/run_madcat.sh \
    &&mkdir -p /data/{ipm,upm,tpm,log} /var/log/madcat \
    && chown -R madcat:madcat /data /var/log/madcat

VOLUME /data
VOLUME /var/log/madcat
ENTRYPOINT ["/entrypoint.sh"]

