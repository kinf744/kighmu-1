# KIGHMU AI

Interface de chat IA en terminal — style Claude Code.

## Installation rapide

```bash
# Cloner ou extraire le projet
cd kighmu-ai/

# Installer les dépendances
npm install

# Installer globalement (permet de lancer "kighmu-ai" depuis n'importe où)
npm install -g .
```

## Lancer

```bash
kighmu-ai
```

Au premier lancement, le wizard configure :
1. Les autorisations système (accès réseau, fichiers, shell)
2. Tes clés API (Mistral, Groq, OpenRouter)
3. Le provider et modèle par défaut

## Commandes rapides

```
/model          Changer de modèle
/provider       Changer de provider
/file <path>    Charger un fichier
/project <dir>  Charger un projet entier
/run <cmd>      Exécuter une commande shell
/resume         Reprendre un projet après SSH coupée
/task new       Créer une tâche autonome (daemon)
/help           Aide complète
```

## Daemon (agents autonomes)

```bash
# Lancer en arrière-plan
nohup node daemon.js > ~/.voanh/daemon.log 2>&1 &

# Voir les logs
tail -f ~/.voanh/daemon.log

# Arrêter
/task daemon stop
```

## Providers supportés

| Provider    | Modèles notables                        |
|-------------|-----------------------------------------|
| Mistral AI  | Codestral, Devstral, Mistral Large      |
| Groq        | Llama 3.3 70B, DeepSeek R1, Qwen QwQ   |
| OpenRouter  | Claude, GPT-4o, Gemini 2.5, DeepSeek   |

## Reconfigurer

```bash
kighmu-ai --setup
```

## Données

Tout est stocké dans `~/.voanh/` :
- `config.json` — clés API, préférences
- `history/` — sessions de chat
- `memory.json` — mémoire globale
- `projects.json` — snapshots de projets
- `tasks/` — tâches agents autonomes
- `daemon.log` — logs du daemon
