#!/bin/bash
set -e

# SSH-Port auf 22222 umstellen
sudo sed -i 's/^#\?Port .*/Port 22222/' /etc/ssh/sshd_config
sudo systemctl restart sshd 