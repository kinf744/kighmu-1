#!/bin/bash
# xray_installe.sh  Installation complète Xray + Trojan Go + UFW, avec users.json pour menu

RED='\u001B[0;31m'
GREEN='\u001B[0;32m'
NC='\u001B[0m'

read -rp "Entrez votre nom de domaine (ex: monsite.com) : " DOMAIN
if [[ -z "$DOMAIN" ]]; then
  echo -e "${RED}Erreur : nom de domaine non valide.${NC}"
  exit 1
fi

echo "$DOMAIN" > /tmp/.xray_domain

EMAIL="adrienkiaje@gmail.com"

apt update
apt install -y iptables iptables-persistent curl socat xz-utils wget apt-transport-https \
  gnupg gnupg2 gnupg1 dnsutils lsb-release cron bash-completion ntpdate chrony unzip jq ca-certificates libcap2-bin

# Suppression des mentions UFW et gestion via iptables uniquement
# Suppression des règles UFW si elles existent (aucun effet si UFW non utilisé)
if command -v ufw >/dev/null 2>&1; then
  ufw --help >/dev/null 2>&1 || true
  # Ne pas désactiver UFW si il est actif; on retire toute dépendance UFW en fin de script
fi

# Configuration iptables initiale
# Autoriser SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
# Autoriser HTTP et WS TLS/NTLS via Xray
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p udp --dport 443 -j ACCEPT

# Autoriser correspondances sortantes si nécessaire (optionnel)
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# S'assurer que les règles sont persistées
netfilter-persistent flush
netfilter-persistent save

echo "netfilter-persistent a appliqué les règles initiales."

echo "Démarrage et état des règles iptables sauvegardées dans netfilter-persistent."
# Vérification rapide
iptables -S

# Téléchargement et extraction de la dernière version stable Xray
latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep tag_name | cut -d '"' -f4 | sed 's/v//')
xraycore_link="https://github.com/XTLS/Xray-core/releases/download/v${latest_version}/xray-linux-64.zip"

mkdir -p /tmp/xray_install && cd /tmp/xray_install
curl -L -o xray.zip "$xraycore_link"
unzip -o xray.zip
if [[ ! -f ./xray ]]; then
  echo -e "${RED}Erreur: le binaire Xray est introuvable après extraction.${NC}" >&2
  exit 1
fi
mv -f xray /usr/local/bin/xray
chmod +x /usr/local/bin/xray
setcap 'cap_net_bind_service=+ep' /usr/local/bin/xray || true

mkdir -p /var/log/xray /etc/xray
touch /var/log/xray/access.log /var/log/xray/error.log
chown -R root:root /var/log/xray
chmod 644 /var/log/xray/access.log /var/log/xray/error.log

cd /root/
wget -q https://raw.githubusercontent.com/NevermoreSSH/hop/main/acme.sh
bash acme.sh --install
rm acme.sh
cd ~/.acme.sh || exit
bash acme.sh --register-account -m "$EMAIL"
bash acme.sh --issue --standalone -d "$DOMAIN" --force
bash acme.sh --installcert -d "$DOMAIN" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key

if [[ ! -f "/etc/xray/xray.crt" || ! -f "/etc/xray/xray.key" ]]; then
  echo -e "${RED}Erreur : certificats TLS non trouvés.${NC}"
  exit 1
fi

uuid=$(cat /proc/sys/kernel/random/uuid)

cat > /etc/xray/users.json << EOF
{
  "vless_tls": [
    {"uuid": "uuid", "limit": 5}
  ],
}
EOF

cat > /etc/xray/config.json << EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "$uuid"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{
            "certificateFile": "/etc/xray/xray.crt",
            "keyFile": "/etc/xray/xray.key"
          }],
          "minVersion": "1.2",
          "maxVersion": "1.3",
          "cipherSuites": "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
        },
        "wsSettings": {
          "path": "/vless-tls",
          "host": "$DOMAIN"
        }
      }
    },
  ],
  "outbounds": [
    {"protocol": "freedom", "settings": {}},
    {"protocol": "blackhole", "settings": {}, "tag": "blocked"}
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      }
    ]
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  },
  "stats": {},
  "api": {
    "services": ["StatsService"],
    "tag": "api"
  }
}
EOF

cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service Mod By NevermoreSSH
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xray
systemctl restart xray

if systemctl is-active --quiet xray; then
  echo -e "${GREEN}Xray démarré avec succès.${NC}"
else
  echo -e "${RED}Erreur : Xray ne démarre pas.${NC}"
  journalctl -u xray -n 20 --no-pager
  exit 1
fi

echo "Installation complète terminée."
echo "Domaine : $DOMAIN"
echo "UUID VLESS TLS : $uuid3"
echo "Mot de passe Trojan (WS TLS 8443) : $uuid5"
