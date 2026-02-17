# ⚡ VLESS via WebSocket (WS) sur Google Cloud Run + CDN

Ce projet vous permet de déployer un serveur **proxy VLESS** via **WebSocket** en utilisant **Xray-core**, entièrement conteneurisé avec Docker et déployé sur **Google Cloud Run**, avec **Google Cloud CDN** en frontal.

---

## 🌟 Fonctionnalités

- ✔️ VLESS via WebSocket (WS)
- ✔️ Déployé sur Google Cloud Run (serverless + autoscaling)
- ✔️ Compatible avec Google Cloud Load Balancer + CDN
- ✔️ Dockerisé et facile à déployer
- ✔️ Conçu pour le domain fronting, le contournement, FreeNet

---

## ⚠️ Avis Important

- ❌ Les adresses IP Google Cloud commençant par `34.*` et `35.*` **ne fonctionnent PAS** de manière fiable avec V2Ray/VLESS.
- ✅ Utilisez un **domaine personnalisé avec HTTPS** via **Google Load Balancer + CDN** pour un bon fonctionnement.

---

## 🔧 Aperçu de la Configuration

### `config.json`

```json
{
  "inbounds": [
    {
      "port": 8080,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "00000400-0000-0300-0200-000000000001",
            "level": 0
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/kighmu"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
```

> 🔐 Remplacez l’UUID par le vôtre pour des raisons de sécurité.

---

## 🐳 Déploiement Docker

### Étape 1 : Construire l’image Docker

```bash
docker build -t gcr.io/YOUR_PROJECT_ID/vless-ws .
```

### Étape 2 : Envoyer vers Container Registry

```bash
docker push gcr.io/YOUR_PROJECT_ID/vless-ws
```

### Étape 3 : Déployer sur Google Cloud Run

```bash
gcloud run deploy vless-ws \
  --image gcr.io/YOUR_PROJECT_ID/vless-ws \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8080
```

> ☑️ Assurez-vous d’autoriser l’accès **non authentifié**.

---

## 🌐 Configuration Google CDN + Load Balancer

1. Allez dans **Google Cloud Console > Services réseau > Équilibrage de charge**
2. Créez un nouveau **Load Balancer HTTP(S)**
3. Ajoutez votre **service Cloud Run** comme backend
4. **Activez le CDN** sur le backend
5. Associez un **domaine personnalisé** et un **certificat SSL**

> 🔒 HTTPS est géré par Google ; il n’est pas nécessaire de configurer TLS dans Xray.

---

## 📲 Configuration Client (V2Ray, Xray)

Utilisez les paramètres suivants dans votre application client :

| Paramètre  | Valeur                                  |
|------------|------------------------------------------|
| Protocole  | VLESS                                   |
| Adresse    | `your.domain.com`                        |
| Port       | `443` (HTTPS)                            |
| UUID       | `a3b7de87-b46f-4dcf-b6ed-5bf5ebe83167`     |
| Chiffrement| none                                     |
| Transport  | WebSocket (WS)                           |
| Chemin WS  | `/kighmu`                                |
| TLS        | Oui (via Google CDN)                     |

---

## 🧪 Clients Testés

* ✅ **Windows** : V2RayN  
* ✅ **Android** : http injector / V2RayNG  
* ✅ **iOS** : Shadowrocket / V2Box  
* ✅ **macOS/Linux** : Xray CLI  

---

## 🛡 Conseils pour une meilleure discrétion

* Utilisez des UUID et des chemins WS aléatoires
* Combinez avec DNS Cloudflare et proxy
* Changez de domaine si nécessaire
* Activez les logs uniquement en environnement debug

---

## 📄 Licence

Ce projet est sous licence **MIT**.

---

## 👤 Auteur

Réalisé avec ❤️ par [Kighmu](https://t.me/kighmu)