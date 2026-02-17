FROM alpine:latest

# Installer dépendances
RUN apk add --no-cache curl unzip

# Télécharger Xray
RUN curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -o xray.zip \
    && unzip xray.zip \
    && mv xray /usr/local/bin/xray \
    && chmod +x /usr/local/bin/xray \
    && rm -f xray.zip

# Créer dossier config
RUN mkdir -p /etc/xray

# Copier config
COPY config.json /etc/xray/config.json

# Cloud Run fournit PORT (généralement 8080)
ENV PORT=8080

EXPOSE 8080

CMD ["xray", "-config", "/etc/xray/config.json"]