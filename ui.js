#!/usr/bin/env node
// ═══════════════════════════════════════════════════════
//  KIGHMU AI — Interface TUI style Claude Code
//  Usage : kighmu-ai  (après npm install -g .)
//  Features : Chat streamé, titre animé, modèle affiché,
//             setup API key au premier lancement,
//             permissions système demandées proprement
// ═══════════════════════════════════════════════════════

import readline from 'readline';
import fs       from 'fs';
import path     from 'path';
import os       from 'os';
import crypto   from 'crypto';
import { execSync } from 'child_process';

import { PROVIDERS } from './providers.js';
import {
  loadConfig, saveConfig,
  loadMemory, addMemory, getRelevantMemories,
  listSessions, loadSession, saveSession,
  readFileForContext, readDirForContext, formatFilesForContext,
  ensureConfigDir, CONFIG_DIR,
} from './config.js';

// ══════════════════════════════════════════════════════
// COULEURS & STYLES ANSI
// ══════════════════════════════════════════════════════
const A = {
  reset:     '\x1b[0m',
  bold:      '\x1b[1m',
  dim:       '\x1b[2m',
  italic:    '\x1b[3m',
  underline: '\x1b[4m',

  // Couleurs texte
  black:     '\x1b[30m',
  red:       '\x1b[31m',
  green:     '\x1b[32m',
  yellow:    '\x1b[33m',
  blue:      '\x1b[34m',
  magenta:   '\x1b[35m',
  cyan:      '\x1b[36m',
  white:     '\x1b[37m',
  gray:      '\x1b[90m',
  brightRed: '\x1b[91m',
  brightGreen: '\x1b[92m',
  brightYellow: '\x1b[93m',
  brightBlue: '\x1b[94m',
  brightMagenta: '\x1b[95m',
  brightCyan: '\x1b[96m',
  brightWhite: '\x1b[97m',

  // Fonds
  bgBlack:   '\x1b[40m',
  bgBlue:    '\x1b[44m',
  bgCyan:    '\x1b[46m',

  // Curseur & écran
  clearScreen: '\x1b[2J\x1b[H',
  clearLine:   '\x1b[2K\r',
  saveCursor:  '\x1b[s',
  restoreCursor: '\x1b[u',
  hideCursor:  '\x1b[?25l',
  showCursor:  '\x1b[?25h',
  moveUp:      (n) => `\x1b[${n}A`,
  moveDown:    (n) => `\x1b[${n}B`,
  moveCol:     (n) => `\x1b[${n}G`,
};

const W = () => process.stdout.columns || 80;

const c = {
  title:    (s) => `${A.bold}${A.brightCyan}${s}${A.reset}`,
  subtitle: (s) => `${A.dim}${A.cyan}${s}${A.reset}`,
  model:    (s) => `${A.bold}${A.brightMagenta}${s}${A.reset}`,
  provider: (s) => `${A.dim}${A.magenta}${s}${A.reset}`,
  user:     (s) => `${A.bold}${A.brightGreen}${s}${A.reset}`,
  ai:       (s) => `${A.brightCyan}${s}${A.reset}`,
  aiLabel:  (s) => `${A.bold}${A.cyan}${s}${A.reset}`,
  dim:      (s) => `${A.dim}${s}${A.reset}`,
  error:    (s) => `${A.bold}${A.brightRed}${s}${A.reset}`,
  success:  (s) => `${A.bold}${A.brightGreen}${s}${A.reset}`,
  warn:     (s) => `${A.bold}${A.brightYellow}${s}${A.reset}`,
  info:     (s) => `${A.dim}${A.brightCyan}${s}${A.reset}`,
  prompt:   (s) => `${A.bold}${A.brightGreen}${s}${A.reset}`,
  code:     (s) => `${A.dim}${A.brightWhite}${s}${A.reset}`,
  border:   (s) => `${A.dim}${A.cyan}${s}${A.reset}`,
  key:      (s) => `${A.bold}${A.bgBlack}${A.brightYellow} ${s} ${A.reset}`,
};

// ══════════════════════════════════════════════════════
// BANNIÈRE KIGHMU
// ══════════════════════════════════════════════════════
function printHeader(provider, model) {
  const w = W();
  const line = c.border('─'.repeat(w));

  // ASCII art KIGHMU — compact et stylé
  const art = [
    ' ██╗  ██╗ ██╗ ██████╗ ██╗  ██╗███╗   ███╗██╗   ██╗',
    ' ██║ ██╔╝ ██║██╔════╝ ██║  ██║████╗ ████║██║   ██║',
    ' █████╔╝  ██║██║  ███╗███████║██╔████╔██║██║   ██║',
    ' ██╔═██╗  ██║██║   ██║██╔══██║██║╚██╔╝██║██║   ██║',
    ' ██║  ██╗ ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║╚██████╔╝',
    ' ╚═╝  ╚═╝ ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ',
  ];

  process.stdout.write('\n');
  for (const line2 of art) {
    // Centrer
    const pad = Math.max(0, Math.floor((w - line2.length) / 2));
    process.stdout.write(' '.repeat(pad) + c.title(line2) + '\n');
  }

  // Sous-titre
  const sub = '  AI Terminal  ·  Multi-Provider  ·  Streaming  ';
  const padSub = Math.max(0, Math.floor((w - sub.length) / 2));
  process.stdout.write(' '.repeat(padSub) + c.subtitle(sub) + '\n');

  process.stdout.write('\n' + line + '\n');

  // Provider + Modèle affiché sous le titre
  const providerMap = {
    mistral:    `${A.bold}${A.yellow}◆ Mistral AI${A.reset}`,
    groq:       `${A.bold}${A.brightGreen}◆ Groq${A.reset}`,
    openrouter: `${A.bold}${A.brightMagenta}◆ OpenRouter${A.reset}`,
  };
  const pBadge = providerMap[provider] || c.provider(`◆ ${provider}`);
  const mLabel = c.model(`  ${model}`);
  const mLine  = `  ${pBadge}${mLabel}`;

  process.stdout.write(mLine + '\n');
  process.stdout.write(line + '\n\n');
}

function printShortHeader(provider, model) {
  const w = W();
  const providerMap = {
    mistral:    `${A.bold}${A.yellow}◆ Mistral${A.reset}`,
    groq:       `${A.bold}${A.brightGreen}◆ Groq${A.reset}`,
    openrouter: `${A.bold}${A.brightMagenta}◆ OpenRouter${A.reset}`,
  };
  const badge = providerMap[provider] || c.provider(`◆ ${provider}`);
  const modelShort = model.split('/').pop();
  process.stdout.write(
    `${A.dim}${'─'.repeat(w)}${A.reset}\n` +
    `  ${badge}  ${c.model(modelShort)}  ` +
    c.dim(`  /help pour l'aide  ·  Ctrl+C pour quitter`) +
    '\n' +
    `${A.dim}${'─'.repeat(w)}${A.reset}\n\n`
  );
}

// ══════════════════════════════════════════════════════
// WIZARD PERMISSIONS & API KEY
// ══════════════════════════════════════════════════════
async function runSetupWizard(rl) {
  const ask       = makeBoxedAsk(rl);
  const askHidden = (q) => makeBoxedAsk(rl)(q, { secret: true });
  const confirm   = makeBoxedConfirm(rl);

  process.stdout.write(A.clearScreen);
  printHeader('mistral', 'setup');

  process.stdout.write(`  ${c.title('CONFIGURATION INITIALE')}\n\n`);
  process.stdout.write(
    `  Bienvenue dans ${c.title('KIGHMU AI')} !\n` +
    `  Ce wizard va configurer tes clés API et les autorisations.\n\n`
  );

  // ── Autorisations système ──────────────────────────────
  process.stdout.write(`  ${c.warn('AUTORISATIONS REQUISES')}\n\n`);

  const perms = [
    { name: 'Accès réseau (API calls)',       info: 'Nécessaire pour contacter Mistral, Groq, OpenRouter' },
    { name: 'Lecture/écriture ~/.voanh/',     info: 'Config, sessions, mémoire, tâches autonomes' },
    { name: 'Exécution de commandes shell',   info: 'Pour /run, /shell, agents autonomes' },
    { name: 'Lecture des fichiers projet',    info: 'Pour /file, /project — uniquement ce que tu charges' },
  ];

  for (const p of perms) {
    process.stdout.write(`  ${c.success('✓')} ${A.bold}${p.name}${A.reset}  ${c.dim(p.info)}\n`);
  }
  process.stdout.write('\n');

  const accepted = await confirm('Accepter ces autorisations ?');
  if (!accepted) {
    process.stdout.write(`\n  ${c.error('Autorisations refusées. KIGHMU AI ne peut pas fonctionner.')}\n`);
    process.exit(1);
  }
  process.stdout.write(`\n  ${c.success('✓ Autorisations acceptées.')}\n\n`);

  // ── Clés API ──────────────────────────────────────────
  process.stdout.write(`  ${c.warn('CLÉS API')}\n\n`);
  process.stdout.write(`  ${c.dim('Appuie sur Entrée pour passer (au moins 1 clé requise).')}\n\n`);

  const providers = [
    { id: 'mistral',    label: 'Mistral AI',   url: 'console.mistral.ai/api-keys',  required: false },
    { id: 'groq',       label: 'Groq',         url: 'console.groq.com/keys',        required: false },
    { id: 'openrouter', label: 'OpenRouter',   url: 'openrouter.ai/keys',           required: false },
  ];

  const cfg = loadConfig();
  if (!cfg.keys) cfg.keys = {};

  for (const p of providers) {
    const existing = cfg.keys[p.id];
    if (existing) {
      const masked = existing.slice(0, 6) + '••••••••' + existing.slice(-4);
      process.stdout.write(
        `  ${c.success('✓')} ${A.bold}${p.label}${A.reset}  ${c.dim('déjà configurée: ' + masked)}\n`
      );
      continue;
    }
    process.stdout.write(
      `  ${c.dim('→ Obtenir une clé :')} ${A.underline}${A.dim}${p.url}${A.reset}\n`
    );
    const key = await askHidden(`Clé API ${p.label} :`);
    if (key.trim()) {
      cfg.keys[p.id] = key.trim();
      process.stdout.write(`  ${c.success('✓')} Clé ${p.label} enregistrée.\n`);
    } else {
      process.stdout.write(`  ${c.dim('⊘ Ignoré.')}\n`);
    }
    process.stdout.write('\n');
  }

  // Vérifier qu'au moins une clé est présente
  const hasKey = Object.keys(PROVIDERS).some(p => cfg.keys[p]);
  if (!hasKey) {
    process.stdout.write(`\n  ${c.error('⚠ Aucune clé API saisie. Configure au moins une clé.')}\n`);
    process.stdout.write(`  ${c.dim('Lance kighmu-ai --setup pour recommencer.')}\n\n`);
    process.exit(1);
  }

  // Provider + modèle par défaut
  process.stdout.write(`\n  ${c.warn('PROVIDER & MODÈLE PAR DÉFAUT')}\n\n`);
  const availableProviders = Object.keys(PROVIDERS).filter(p => cfg.keys[p]);
  process.stdout.write(`  Providers disponibles : ${availableProviders.map(p => c.model(p)).join('  ')}\n`);

  const defProvider = await ask(`Provider par défaut [${availableProviders[0]}] :`);
  cfg.defaultProvider = defProvider.trim() || availableProviders[0];

  const pModels = PROVIDERS[cfg.defaultProvider]?.models || [];
  if (pModels.length) {
    process.stdout.write(`  Modèles ${cfg.defaultProvider} :\n`);
    pModels.slice(0, 6).forEach((m, i) => {
      process.stdout.write(`    ${c.dim(String(i+1)+'.')} ${A.bold}${m.id.split('/').pop()}${A.reset}  ${c.dim(m.name)}\n`);
    });
    const defModel = await ask(`Modèle par défaut [${pModels[0].id}] :`);
    cfg.defaultModel = defModel.trim() || pModels[0].id;
  } else {
    cfg.defaultModel = 'codestral-2508';
  }

  // Sauvegarder
  saveConfig(cfg);
  ensureConfigDir();

  process.stdout.write(`\n  ${c.success('✓ Configuration sauvegardée dans ~/.voanh/config.json')}\n`);
  process.stdout.write(`  ${c.info('Lance kighmu-ai pour démarrer.')}\n\n`);

  // Marquer le setup comme fait
  cfg._setupDone = true;
  saveConfig(cfg);

  await makeBoxedAsk(rl)('Appuie sur Entrée pour démarrer le chat', { hint: '' });

  return cfg;
}

// ══════════════════════════════════════════════════════
// RENDU MARKDOWN SIMPLIFIÉ (pour le terminal)
// ══════════════════════════════════════════════════════
function renderMarkdownTUI(text) {
  const lines = text.split('\n');
  const out = [];
  let inCode = false;
  let codeLang = '';

  for (const line of lines) {
    // Bloc de code
    if (line.startsWith('```')) {
      if (!inCode) {
        inCode = true;
        codeLang = line.slice(3).trim() || 'code';
        const w = Math.min(W() - 4, 76);
        out.push(
          `  ${A.dim}${A.bgBlack}╭${'─'.repeat(w)}╮${A.reset}\n` +
          `  ${A.dim}${A.bgBlack}│ ${A.bold}${A.brightYellow}${codeLang.padEnd(w-2)}${A.dim} │${A.reset}`
        );
      } else {
        inCode = false;
        const w = Math.min(W() - 4, 76);
        out.push(`  ${A.dim}${A.bgBlack}╰${'─'.repeat(w)}╯${A.reset}`);
      }
      continue;
    }

    if (inCode) {
      out.push(`  ${A.dim}${A.bgBlack}│${A.reset} ${A.brightWhite}${line}${A.reset}`);
      continue;
    }

    // Titres
    if (line.startsWith('### ')) {
      out.push(`  ${A.bold}${A.brightCyan}▸ ${line.slice(4)}${A.reset}`);
    } else if (line.startsWith('## ')) {
      out.push(`  ${A.bold}${A.cyan}══ ${line.slice(3)} ══${A.reset}`);
    } else if (line.startsWith('# ')) {
      out.push(`  ${A.bold}${A.brightCyan}${line.slice(2)}${A.reset}`);
    }
    // Listes
    else if (line.match(/^[\-\*] /)) {
      const content = line.slice(2)
        .replace(/\*\*(.+?)\*\*/g, `${A.bold}$1${A.reset}`)
        .replace(/`(.+?)`/g, `${A.dim}${A.brightYellow}$1${A.reset}`);
      out.push(`  ${A.cyan}•${A.reset} ${content}`);
    }
    // Listes numérotées
    else if (line.match(/^\d+\. /)) {
      const [num, ...rest] = line.split('. ');
      const content = rest.join('. ')
        .replace(/\*\*(.+?)\*\*/g, `${A.bold}$1${A.reset}`)
        .replace(/`(.+?)`/g, `${A.dim}${A.brightYellow}$1${A.reset}`);
      out.push(`  ${A.dim}${num}.${A.reset} ${content}`);
    }
    // Texte normal
    else {
      const content = line
        .replace(/\*\*(.+?)\*\*/g, `${A.bold}$1${A.reset}`)
        .replace(/\*(.+?)\*/g,   `${A.italic}$1${A.reset}`)
        .replace(/`(.+?)`/g,     `${A.dim}${A.brightYellow}$1${A.reset}`)
        .replace(/~~(.+?)~~/g,   `${A.dim}$1${A.reset}`);
      out.push(`  ${content}`);
    }
  }
  return out.join('\n');
}

// ══════════════════════════════════════════════════════
// SPINNER
// ══════════════════════════════════════════════════════
class TUISpinner {
  constructor(label = '') {
    this.label   = label;
    this.frames  = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];
    this.i       = 0;
    this.timer   = null;
    this.active  = false;
  }
  start() {
    this.active = true;
    process.stdout.write('\n');
    this.timer = setInterval(() => {
      const frame = this.frames[this.i++ % this.frames.length];
      process.stdout.write(
        `${A.clearLine}  ${A.dim}${A.cyan}${frame}${A.reset}  ${A.dim}${this.label}${A.reset}`
      );
    }, 80);
  }
  stop(msg = '') {
    this.active = false;
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    process.stdout.write(`${A.clearLine}`);
    if (msg) process.stdout.write(`  ${msg}\n`);
  }
}

// ══════════════════════════════════════════════════════
// AFFICHAGE MESSAGES
// ══════════════════════════════════════════════════════
function printUserMessage(text) {
  const w = W();
  process.stdout.write('\n');
  process.stdout.write(`  ${c.user('╭─ Vous')}\n`);
  const lines = text.split('\n');
  for (const line of lines) {
    process.stdout.write(`  ${A.dim}${A.green}│${A.reset}  ${A.bold}${line}${A.reset}\n`);
  }
  process.stdout.write(`  ${A.dim}${A.green}╰${'─'.repeat(Math.min(w-4, 60))}${A.reset}\n`);
}

function printAIHeader(provider, model) {
  const modelShort = model.split('/').pop();
  const provMap = { mistral:'Mistral', groq:'Groq', openrouter:'OpenRouter' };
  const pName = provMap[provider] || provider;
  process.stdout.write(
    `\n  ${c.aiLabel(`╭─ KIGHMU`)}  ${c.provider(pName)}  ${c.model(modelShort)}\n` +
    `  ${A.dim}${A.cyan}│${A.reset}\n`
  );
}

function printAILine(text) {
  // Afficher le texte streamed en direct
  process.stdout.write(text);
}

function printAIFooter(elapsed, tokens) {
  const w = W();
  const info = elapsed ? `  ${c.dim(`${elapsed}s · ~${tokens} tokens`)}` : '';
  process.stdout.write(
    `\n  ${A.dim}${A.cyan}│${A.reset}\n` +
    `  ${A.dim}${A.cyan}╰${'─'.repeat(Math.min(w-4, 60))}${A.reset}` +
    info + '\n'
  );
}

// ══════════════════════════════════════════════════════
// AIDE RAPIDE
// ══════════════════════════════════════════════════════
function printHelp() {
  const w = W();
  process.stdout.write('\n');
  process.stdout.write(c.dim('─'.repeat(w)) + '\n');
  process.stdout.write(`  ${c.title('COMMANDES KIGHMU AI')}\n\n`);

  const cmds = [
    ['/model [id]',    'Changer de modèle IA'],
    ['/provider [p]',  'Changer de provider (mistral|groq|openrouter)'],
    ['/cle-api',       'Ajouter / modifier une clé API + choisir le modèle'],
    ['/file <path>',   'Charger un fichier dans le contexte'],
    ['/project <dir>', 'Charger tout un répertoire projet'],
    ['/unfile',        'Retirer les fichiers du contexte'],
    ['/run <cmd>',     'Exécuter une commande shell'],
    ['/new',           'Nouvelle conversation'],
    ['/sessions',      'Lister les sessions sauvegardées'],
    ['/load <id>',     'Reprendre une session'],
    ['/mem',           'Voir la mémoire globale'],
    ['/mem add <txt>', 'Mémoriser une info'],
    ['/resume',        'Reprendre un projet après déconnexion'],
    ['/task',          'Tâches agents autonomes'],
    ['/stream',        'Activer/désactiver le streaming'],
    ['/clear',         'Effacer l\'écran'],
    ['/status',        'Statut complet'],
    ['/help',          'Cette aide'],
    ['/exit',          'Quitter'],
  ];

  for (const [cmd, desc] of cmds) {
    if (cmd.startsWith('─')) {
      process.stdout.write(`  ${c.dim(cmd)}\n`);
    } else {
      process.stdout.write(
        `  ${A.bold}${A.brightCyan}${cmd.padEnd(22)}${A.reset}` +
        `  ${A.dim}${desc}${A.reset}\n`
      );
    }
  }

  process.stdout.write('\n  ' + c.dim('Raccourci : ↑↓ historique | Ctrl+C pour quitter') + '\n');
  process.stdout.write(c.dim('─'.repeat(w)) + '\n\n');
}

// ══════════════════════════════════════════════════════
// PROMPT CHAT — DEUX LIGNES HORIZONTALES
// ══════════════════════════════════════════════════════
function getPrompt(cfg, provider, model, loadedFiles, sessionId) {
  const w   = Math.min(W() - 4, 76);
  const bar = `${A.dim}${A.cyan}${'━'.repeat(w)}${A.reset}`;
  const tag = loadedFiles.length ? `  ${A.dim}[${loadedFiles.length} fichier(s)]${A.reset}` : '';
  return `\n  ${bar}${tag}\n  `;
}

function closeInputBox() {
  const w   = Math.min(W() - 4, 76);
  const bar = `${A.dim}${A.cyan}${'━'.repeat(w)}${A.reset}`;
  process.stdout.write(`\n  ${bar}\n`);
}

// ══════════════════════════════════════════════════════
// CHAMP DE SAISIE — DEUX LIGNES HORIZONTALES
// ══════════════════════════════════════════════════════

function makeBoxedAsk(rl) {
  return function boxedAsk(label, { secret = false, hint = '' } = {}) {
    return new Promise(resolve => {
      const w   = Math.min(W() - 4, 76);
      const bar = `${A.dim}${A.cyan}${'━'.repeat(w)}${A.reset}`;
      const lbl = label ? `  ${A.bold}${A.brightCyan}${label}${A.reset}\n` : '';

      process.stdout.write(`\n${lbl}  ${bar}\n  `);
      if (hint) process.stdout.write(`${A.dim}${hint}  ${A.reset}`);

      rl.question('', answer => {
        process.stdout.write(`  ${bar}\n`);
        resolve(answer);
      });
    });
  };
}

function makeBoxedConfirm(rl) {
  return function boxedConfirm(label) {
    return new Promise(resolve => {
      const w   = Math.min(W() - 4, 76);
      const bar = `${A.dim}${A.cyan}${'━'.repeat(w)}${A.reset}`;
      const lbl = label ? `  ${A.bold}${A.brightYellow}${label}${A.reset}  ${A.dim}(y/n)${A.reset}\n` : '';

      process.stdout.write(`\n${lbl}  ${bar}\n  `);

      rl.question('', ans => {
        const yes = ans.trim().toLowerCase() === 'y' || ans.trim().toLowerCase() === 'yes';
        process.stdout.write(`  ${bar}\n`);
        resolve(yes);
      });
    });
  };
}

// ══════════════════════════════════════════════════════
// ÉTAT GLOBAL
// ══════════════════════════════════════════════════════
let cfg          = {};
let messages     = [];
let sessionId    = null;
let loadedFiles  = [];
let projectDir   = null;
let streamOn     = true;
let activeProvider = 'mistral';
let activeModel    = 'codestral-2508';

// ══════════════════════════════════════════════════════
// ENVOI MESSAGE + STREAMING
// ══════════════════════════════════════════════════════
async function sendMessage(userText, rl) {
  const apiKey = cfg.keys?.[activeProvider];
  if (!apiKey) {
    process.stdout.write(`\n  ${c.error('⚠ Aucune clé API pour ' + activeProvider + '. Lance /provider ou kighmu-ai --setup.')}\n`);
    return;
  }

  printUserMessage(userText);
  messages.push({ role: 'user', content: userText });

  // Construire contexte
  const mems = getRelevantMemories(userText, 4);
  const filesCtx = loadedFiles.length
    ? '\n\n' + formatFilesForContext(loadedFiles)
    : '';

  // Détecter si un token GitHub a été fourni dans cette session
  const ghTokenMsg = messages.find(m =>
    m.role === 'user' && /ghp_[a-zA-Z0-9]+|github_pat_[a-zA-Z0-9_]+/.test(m.content)
  );
  const ghTokenHint = ghTokenMsg
    ? `\n\nToken GitHub détecté dans la conversation : utilise-le directement avec curl ou git pour cloner, lire ou modifier des dépôts. Exemple : curl -H "Authorization: token TOKEN" https://api.github.com/repos/USER/REPO/contents/`
    : '';

  const vpsInfo = (() => {
    try {
      const hostname = os.hostname();
      const platform = os.platform();
      const arch     = os.arch();
      const release  = os.release();
      const totalMem = Math.round(os.totalmem() / 1024 / 1024 / 1024);
      const cwd      = process.cwd();
      const nodeVer  = process.version;
      return `\n\nENVIRONNEMENT SERVEUR (VPS):\n- Hôte: ${hostname} | OS: ${platform} ${release} ${arch}\n- RAM: ${totalMem} Go | CWD: ${cwd}\n- Node.js: ${nodeVer}\n- Tu as accès shell complet via /run et execSync. Tu PEUX exécuter des commandes, cloner des dépôts, lire des fichiers, installer des packages.`;
    } catch { return ''; }
  })();

  const sysPrompt = `Tu es KIGHMU AI, un assistant expert en développement logiciel (Android, VPN, Node.js, Linux, DevOps).
Tu fonctionnes sur un VPS Linux avec un environnement de travail complet adapté au coding.
Tu as accès shell complet : tu PEUX et DOIS utiliser /run pour exécuter des commandes, analyser des fichiers, utiliser git, curl, npm, etc.
Ne dis JAMAIS que tu ne peux pas exécuter des commandes ou accéder à des fichiers — utilise /run.
Génère du code COMPLET. Ne tronque jamais. Commente le code important.
Réponds dans la langue de l'utilisateur.${vpsInfo}${ghTokenHint}` + filesCtx;

  const contextMessages = [
    { role: 'system', content: sysPrompt },
    ...(mems.length ? [
      { role: 'user', content: `[Mémoire]\n${mems.join('\n')}` },
      { role: 'assistant', content: 'Contexte mémorisé.' },
    ] : []),
    ...messages.slice(-30),
  ];

  const provider = PROVIDERS[activeProvider];
  const opts = { temperature: 0.4, maxTokens: 32768 };

  // ── Streaming ────────────────────────────────────────
  if (streamOn && provider.stream) {
    printAIHeader(activeProvider, activeModel);
    // Ouvrir la première ligne de contenu
    process.stdout.write('  ' + A.dim + A.cyan + '│' + A.reset + '  ');

    let fullReply = '';
    const startTime = Date.now();

    try {
      for await (const delta of provider.stream(apiKey, activeModel, contextMessages, opts)) {
        fullReply += delta;
        // Afficher le delta brut — le rendu final se fait après
        const parts = delta.split('\n');
        for (let i = 0; i < parts.length; i++) {
          if (i > 0) {
            process.stdout.write('\n  ' + A.dim + A.cyan + '│' + A.reset + '  ');
          }
          process.stdout.write(A.brightWhite + parts[i] + A.reset);
        }
      }
      // Fermer le bloc proprement après réception complète
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      const tokens  = Math.round(fullReply.length / 4);
      printAIFooter(elapsed, tokens);
      messages.push({ role: 'assistant', content: fullReply });
      autoSave();

    } catch (err) {
      process.stdout.write('\n');
      process.stdout.write(`\n  ${c.error('✗ Erreur: ' + err.message)}\n`);
      messages.pop();
    }

  // ── Non-streaming ────────────────────────────────────
  } else {
    const spinner = new TUISpinner(`${activeProvider} / ${activeModel.split('/').pop()} — génération…`);
    spinner.start();

    try {
      const result = await provider.send(apiKey, activeModel, contextMessages, opts);
      spinner.stop();
      printAIHeader(activeProvider, activeModel);
      process.stdout.write(renderMarkdownTUI(result.content) + '\n');
      printAIFooter(null, result.usage?.total_tokens || '?');
      messages.push({ role: 'assistant', content: result.content });
      autoSave();

    } catch (err) {
      spinner.stop();
      process.stdout.write(`\n  ${c.error('✗ Erreur: ' + err.message)}\n`);
      messages.pop();
    }
  }
}

function autoSave() {
  if (!sessionId) sessionId = crypto.randomUUID();
  const first = messages.find(m => m.role === 'user');
  saveSession(sessionId, {
    id:       sessionId,
    title:    first?.content?.slice(0, 60) || 'Session KIGHMU',
    provider: activeProvider,
    model:    activeModel,
    messages,
    updated:  Date.now(),
  });
}

// ══════════════════════════════════════════════════════
// COMMANDES
// ══════════════════════════════════════════════════════
async function handleCommand(input, rl) {
  const [cmd, ...args] = input.trim().split(/\s+/);
  const w = W();

  switch (cmd) {
    case '/help': case '/h': printHelp(); break;

    case '/clear': case '/cls':
      process.stdout.write(A.clearScreen);
      printHeader(activeProvider, activeModel);
      break;

    case '/status': case '/s': {
      process.stdout.write('\n' + c.dim('─'.repeat(w)) + '\n');
      process.stdout.write(`  ${c.title('STATUS')}\n\n`);
      const rows = [
        ['Provider',  activeProvider],
        ['Modèle',    activeModel],
        ['Streaming', streamOn ? 'ON' : 'OFF'],
        ['Session',   sessionId ? sessionId.slice(0,8) : '—'],
        ['Messages',  String(messages.length)],
        ['Fichiers',  String(loadedFiles.length)],
        ['Projet',    projectDir || '—'],
        ['Config',    CONFIG_DIR],
      ];
      for (const [k, v] of rows) {
        process.stdout.write(
          `  ${A.dim}${k.padEnd(12)}${A.reset}  ${A.bold}${v}${A.reset}\n`
        );
      }
      process.stdout.write('\n' + c.dim('─'.repeat(w)) + '\n\n');
      break;
    }

    case '/new': case '/n':
      messages = []; sessionId = null; loadedFiles = []; projectDir = null;
      process.stdout.write(`\n  ${c.success('✓ Nouvelle conversation.')}\n`);
      break;

    case '/provider': case '/p': {
      const name = args[0]?.toLowerCase();
      if (!name) {
        process.stdout.write('\n  Providers : ');
        Object.keys(PROVIDERS).forEach(p => {
          const hasKey = cfg.keys?.[p] ? c.success('✓') : c.error('✗');
          const active = p === activeProvider ? c.model(' ← actif') : '';
          process.stdout.write(`${A.bold}${p}${A.reset}${hasKey}${active}  `);
        });
        process.stdout.write('\n');
        break;
      }
      if (!PROVIDERS[name]) {
        process.stdout.write(`\n  ${c.error('Provider inconnu: ' + name)}\n`); break;
      }
      activeProvider = name;
      activeModel = cfg.providerDefaults?.[name] || PROVIDERS[name].models[0].id;
      process.stdout.write(`\n  ${c.success(`✓ Provider → ${name} | Modèle → ${activeModel}`)}\n`);

      // Redessiner le header court
      process.stdout.write('\n');
      printShortHeader(activeProvider, activeModel);
      break;
    }

    case '/model': case '/m': {
      const modelArg = args.join(' ');
      const models = PROVIDERS[activeProvider].models;
      if (!modelArg) {
        process.stdout.write('\n');
        models.slice(0, 10).forEach((m, i) => {
          const active = m.id === activeModel ? c.model(' ← actif') : '';
          process.stdout.write(
            `  ${A.dim}${String(i+1).padStart(2)}.${A.reset}  ` +
            `${A.bold}${m.id.split('/').pop().padEnd(40)}${A.reset}  ` +
            `${A.dim}${m.name}${A.reset}${active}\n`
          );
        });
        process.stdout.write(`\n  ${c.dim('Usage : /model <id ou numéro>')}\n`);
        break;
      }
      const byNum = parseInt(modelArg);
      if (!isNaN(byNum) && byNum >= 1 && byNum <= models.length) {
        activeModel = models[byNum-1].id;
      } else {
        const found = models.find(m => m.id === modelArg || m.id.includes(modelArg));
        if (!found) { process.stdout.write(`\n  ${c.error('Modèle non trouvé.')}\n`); break; }
        activeModel = found.id;
      }
      process.stdout.write(`\n  ${c.success(`✓ Modèle → ${activeModel}`)}\n`);
      process.stdout.write('\n');
      printShortHeader(activeProvider, activeModel);
      break;
    }

    case '/stream':
      streamOn = !streamOn;
      process.stdout.write(`\n  ${c.success('Streaming ' + (streamOn ? 'ACTIVÉ' : 'DÉSACTIVÉ'))}\n`);
      break;

    case '/file': case '/f': {
      const fp = args.join(' ');
      if (!fp) { process.stdout.write(`\n  ${c.info('Usage : /file <chemin>')}\n`); break; }
      const file = readFileForContext(fp);
      if (!file) { process.stdout.write(`\n  ${c.error('Fichier introuvable : ' + fp)}\n`); break; }
      const idx = loadedFiles.findIndex(f => f.path === file.path);
      if (idx !== -1) loadedFiles[idx] = file; else loadedFiles.push(file);
      const sizeStr = (file.size / 1024).toFixed(1);
      process.stdout.write(`\n  ${c.success(`✓ ${file.path} (${sizeStr} Ko)${file.truncated?' [tronqué]':''}`)}\n`);
      break;
    }

    case '/unfile':
      loadedFiles = []; projectDir = null;
      process.stdout.write(`\n  ${c.success('✓ Fichiers retirés du contexte.')}\n`);
      break;

    case '/project': case '/proj': {
      const dir = args.join(' ') || '.';
      if (!fs.existsSync(path.resolve(dir))) {
        process.stdout.write(`\n  ${c.error('Répertoire introuvable : ' + dir)}\n`); break;
      }
      const spinner = new TUISpinner(`Chargement de ${dir}…`);
      spinner.start();
      const files = readDirForContext(path.resolve(dir), 4);
      spinner.stop();
      loadedFiles = files;
      projectDir = path.resolve(dir);
      const totalKo = (files.reduce((s, f) => s + f.size, 0) / 1024).toFixed(0);
      process.stdout.write(`\n  ${c.success(`✓ ${files.length} fichiers chargés (${totalKo} Ko) — ${dir}`)}\n`);
      break;
    }

    case '/run': case '/exec': {
      const command = args.join(' ');
      if (!command) { process.stdout.write(`\n  ${c.info('Usage : /run <commande>')}\n`); break; }
      process.stdout.write(`\n  ${c.dim('$ ' + command)}\n`);
      process.stdout.write(`  ${A.dim}${'─'.repeat(Math.min(w-4,60))}${A.reset}\n`);
      try {
        const out = execSync(command, { encoding: 'utf8', timeout: 60000, maxBuffer: 512*1024, cwd: projectDir || process.cwd() });
        out.split('\n').slice(0,50).forEach(l => process.stdout.write(`  ${A.dim}${l}${A.reset}\n`));
        process.stdout.write(`  ${A.dim}${'─'.repeat(Math.min(w-4,60))}${A.reset}\n`);
        const inj = `[CMD: ${command}]\n\`\`\`\n${out.slice(0,6000)}\n\`\`\``;
        messages.push({ role:'user', content: inj });
        messages.push({ role:'assistant', content:'Résultat reçu.' });
        process.stdout.write(`\n  ${c.info('Résultat injecté dans le contexte.')}\n`);
      } catch (err) {
        const combined = (err.stdout||'') + '\n' + (err.stderr||err.message);
        combined.split('\n').slice(0,30).forEach(l => process.stdout.write(`  ${A.dim}${A.red}${l}${A.reset}\n`));
        process.stdout.write(`  ${A.dim}${'─'.repeat(Math.min(w-4,60))}${A.reset}\n`);
        const inj = `[ERR: ${command}]\n\`\`\`\n${combined.slice(0,6000)}\n\`\`\``;
        messages.push({ role:'user', content: inj });
        messages.push({ role:'assistant', content:'Erreur injectée.' });
      }
      break;
    }

    case '/sessions': case '/ls': {
      const sessions = listSessions();
      if (!sessions.length) { process.stdout.write(`\n  ${c.info('Aucune session.')}\n`); break; }
      process.stdout.write('\n' + c.dim('─'.repeat(w)) + '\n');
      sessions.slice(0, 15).forEach((s, i) => {
        const date = new Date(s.updated||0).toLocaleString('fr-FR');
        const msgs = (s.messages||[]).filter(m => m.role !== 'system').length;
        process.stdout.write(
          `  ${A.dim}${String(i+1).padStart(2)}.${A.reset}  ` +
          `${A.bold}${A.cyan}${s.id.slice(0,8)}${A.reset}  ` +
          `${A.dim}${(s.title||'?').slice(0,42).padEnd(42)}${A.reset}  ` +
          `${A.dim}${msgs}msgs  ${date}${A.reset}\n`
        );
      });
      process.stdout.write(c.dim('─'.repeat(w)) + '\n\n');
      break;
    }

    case '/load': {
      const arg = args[0];
      if (!arg) { process.stdout.write(`\n  ${c.info('Usage : /load <id ou numéro>')}\n`); break; }
      const sessions = listSessions();
      const byNum = parseInt(arg);
      let sess = null;
      if (!isNaN(byNum) && byNum >= 1 && byNum <= sessions.length) sess = sessions[byNum-1];
      else sess = sessions.find(s => s.id.startsWith(arg));
      if (!sess) { process.stdout.write(`\n  ${c.error('Session introuvable.')}\n`); break; }
      messages = sess.messages || [];
      sessionId = sess.id;
      activeProvider = sess.provider || activeProvider;
      activeModel    = sess.model    || activeModel;
      process.stdout.write(`\n  ${c.success(`✓ Session "${sess.title}" chargée (${messages.filter(m=>m.role!=='system').length} messages)`)}\n`);
      printShortHeader(activeProvider, activeModel);
      break;
    }

    case '/mem': {
      const sub = args[0];
      if (sub === 'add') {
        const content = args.slice(1).join(' ');
        if (!content) { process.stdout.write(`\n  ${c.info('Usage : /mem add <texte>')}\n`); break; }
        addMemory(content);
        process.stdout.write(`\n  ${c.success('✓ Mémorisé : "' + content.slice(0,60) + '"')}\n`);
        break;
      }
      const memories = loadMemory();
      if (!memories.length) { process.stdout.write(`\n  ${c.info('Mémoire vide. /mem add <texte>')}\n`); break; }
      process.stdout.write('\n' + c.dim('─'.repeat(w)) + '\n');
      process.stdout.write(`  ${c.title(`MÉMOIRE (${memories.length})`)}\n\n`);
      memories.slice(-10).reverse().forEach((m, i) => {
        const date = new Date(m.created).toLocaleDateString('fr-FR');
        process.stdout.write(`  ${A.dim}${String(i+1).padStart(2)}.${A.reset}  ${A.dim}${m.content.slice(0,75)}  ${date}${A.reset}\n`);
      });
      process.stdout.write(c.dim('─'.repeat(w)) + '\n\n');
      break;
    }

    // ── Gestion des clés API ────────────────────────────
    case '/cle-api': case '/key': case '/apikey': case '/keys': {
      const w2 = W();
      const ask       = makeBoxedAsk(rl);
      const askSecret = (q) => makeBoxedAsk(rl)(q, { secret: true });
      const confirm   = makeBoxedConfirm(rl);

      process.stdout.write('\n' + c.dim('─'.repeat(w2)) + '\n');
      process.stdout.write(`  ${c.title('GESTION DES CLÉS API & MODÈLES')}\n\n`);

      // ── Afficher l'état actuel ──────────────────────
      process.stdout.write(`  ${c.warn('ÉTAT ACTUEL')}\n\n`);
      const providerLabels = {
        mistral:    `${A.bold}${A.yellow}Mistral AI${A.reset}`,
        groq:       `${A.bold}${A.brightGreen}Groq${A.reset}`,
        openrouter: `${A.bold}${A.brightMagenta}OpenRouter${A.reset}`,
      };
      const providerUrls = {
        mistral:    'console.mistral.ai/api-keys',
        groq:       'console.groq.com/keys',
        openrouter: 'openrouter.ai/keys',
      };
      Object.keys(PROVIDERS).forEach((p, i) => {
        const existing = cfg.keys?.[p];
        const masked   = existing
          ? c.success('✓ ') + existing.slice(0, 6) + '••••••••' + existing.slice(-4)
          : c.error('✗ non configurée');
        const isActive = p === activeProvider ? c.model('  ← actif') : '';
        process.stdout.write(
          `  ${A.dim}${String(i+1)}.${A.reset}  ${(providerLabels[p] || p).padEnd?.(30) || providerLabels[p] || p}  ${masked}${isActive}\n`
        );
      });

      process.stdout.write('\n');
      const provList = Object.keys(PROVIDERS);

      // ── Choisir le provider ─────────────────────────
      const pChoice = await ask(`Provider à configurer (${provList.map((p,i)=>`${i+1}=${p}`).join(' | ')}) [Entrée pour annuler] :`);
      if (!pChoice.trim()) {
        process.stdout.write(`\n  ${c.dim('Annulé.')}\n`);
        break;
      }
      const pIdx = parseInt(pChoice.trim()) - 1;
      const chosenProvider = (!isNaN(pIdx) && pIdx >= 0 && pIdx < provList.length)
        ? provList[pIdx]
        : provList.find(p => p.toLowerCase().startsWith(pChoice.trim().toLowerCase()));

      if (!chosenProvider) {
        process.stdout.write(`\n  ${c.error('Provider invalide.')}\n`);
        break;
      }

      process.stdout.write(`\n  ${c.dim('→ Obtenir une clé : ')}${A.underline}${A.dim}${providerUrls[chosenProvider] || ''}${A.reset}\n`);
      const existingKey = cfg.keys?.[chosenProvider];
      if (existingKey) {
        const masked = existingKey.slice(0,6) + '••••••••' + existingKey.slice(-4);
        process.stdout.write(`  ${c.dim('Clé actuelle : ')}${masked}\n`);
      }

      const newKey = await askSecret(`Nouvelle clé API ${chosenProvider} [Entrée pour garder l'existante]`);
      if (newKey.trim()) {
        if (!cfg.keys) cfg.keys = {};
        cfg.keys[chosenProvider] = newKey.trim();
        saveConfig(cfg);
        process.stdout.write(`\n  ${c.success(`✓ Clé ${chosenProvider} mise à jour.`)}\n`);
      } else {
        process.stdout.write(`\n  ${c.dim('Clé inchangée.')}\n`);
      }

      // ── Choisir le modèle par défaut pour ce provider ──
      const pModels = PROVIDERS[chosenProvider]?.models || [];
      if (pModels.length) {
        process.stdout.write(`\n  ${c.warn(`MODÈLES DISPONIBLES — ${chosenProvider.toUpperCase()}`)}\n\n`);
        pModels.forEach((m, i) => {
          const isCurrent = m.id === (chosenProvider === activeProvider ? activeModel : cfg.providerDefaults?.[chosenProvider]);
          const tag = isCurrent ? c.model('  ← actif') : '';
          process.stdout.write(
            `  ${A.dim}${String(i+1).padStart(2)}.${A.reset}  ` +
            `${A.bold}${m.id.split('/').pop().padEnd(42)}${A.reset}` +
            `${A.dim}${m.name}${A.reset}${tag}\n`
          );
        });

        const mChoice = await ask(`Modèle par défaut (numéro ou id) [Entrée pour garder l'actuel] :`);
        if (mChoice.trim()) {
          const mIdx = parseInt(mChoice.trim()) - 1;
          let chosen = null;
          if (!isNaN(mIdx) && mIdx >= 0 && mIdx < pModels.length) {
            chosen = pModels[mIdx].id;
          } else {
            const found = pModels.find(m => m.id === mChoice.trim() || m.id.includes(mChoice.trim()));
            if (found) chosen = found.id;
          }
          if (chosen) {
            if (!cfg.providerDefaults) cfg.providerDefaults = {};
            cfg.providerDefaults[chosenProvider] = chosen;
            saveConfig(cfg);
            // Appliquer immédiatement si c'est le provider actif
            if (chosenProvider === activeProvider) {
              activeModel = chosen;
              process.stdout.write(`\n  ${c.success(`✓ Modèle → ${chosen} (actif immédiatement)`)}\n`);
              printShortHeader(activeProvider, activeModel);
            } else {
              process.stdout.write(`\n  ${c.success(`✓ Modèle par défaut ${chosenProvider} → ${chosen}`)}\n`);
            }
          } else {
            process.stdout.write(`\n  ${c.error('Modèle non trouvé.')}\n`);
          }
        } else {
          process.stdout.write(`\n  ${c.dim('Modèle inchangé.')}\n`);
        }
      }

      // ── Définir comme provider par défaut ? ────────
      if (chosenProvider !== activeProvider && cfg.keys?.[chosenProvider]) {
        const setDefault = await confirm(`Définir ${chosenProvider} comme provider actif ?`);
        if (setDefault.trim().toLowerCase() === 'y') {
          activeProvider = chosenProvider;
          activeModel    = cfg.providerDefaults?.[chosenProvider] || PROVIDERS[chosenProvider].models[0].id;
          cfg.defaultProvider = activeProvider;
          cfg.defaultModel    = activeModel;
          saveConfig(cfg);
          process.stdout.write(`\n  ${c.success(`✓ Provider actif → ${activeProvider} | Modèle → ${activeModel}`)}\n`);
          printShortHeader(activeProvider, activeModel);
        }
      }

      process.stdout.write('\n' + c.dim('─'.repeat(w2)) + '\n\n');
      break;
    }

    case '/exit': case '/quit': case '/q':
      process.stdout.write(`\n  ${c.dim('Au revoir. Données dans ~/.voanh/')}\n\n`);
      process.stdout.write(A.showCursor);
      rl.close();
      process.exit(0);

    default:
      process.stdout.write(`\n  ${c.error('Commande inconnue : ' + cmd)}  ${c.dim('/help pour l\'aide')}\n`);
  }
}

// ══════════════════════════════════════════════════════
// MAIN
// ══════════════════════════════════════════════════════
async function main() {
  const argv = process.argv.slice(2);

  // Interface readline
  const rl = readline.createInterface({
    input:       process.stdin,
    output:      process.stdout,
    terminal:    true,
    historySize: 500,
    prompt:      '',
  });

  // Charger config
  cfg = loadConfig();

  // Premier lancement ou --setup forcé
  const needsSetup = !cfg._setupDone || argv.includes('--setup') ||
    !Object.keys(PROVIDERS).some(p => cfg.keys?.[p]);

  if (needsSetup) {
    cfg = await runSetupWizard(rl);
  }

  // État initial
  activeProvider = cfg.defaultProvider || 'mistral';
  activeModel    = cfg.defaultModel    || 'codestral-2508';
  streamOn       = cfg.streamingDefault !== false;

  // Charger session depuis args
  const sessIdx = argv.indexOf('--session');
  if (sessIdx !== -1 && argv[sessIdx+1]) {
    const s = loadSession(argv[sessIdx+1]);
    if (s) { messages = s.messages||[]; sessionId = s.id; }
  }

  // Fichier/projet depuis args
  const fileIdx = argv.indexOf('--file');
  if (fileIdx !== -1 && argv[fileIdx+1]) {
    const f = readFileForContext(argv[fileIdx+1]);
    if (f) loadedFiles.push(f);
  }
  const projIdx = argv.indexOf('--project');
  if (projIdx !== -1 && argv[projIdx+1]) {
    const files = readDirForContext(argv[projIdx+1], 4);
    if (files.length) { loadedFiles = files; projectDir = path.resolve(argv[projIdx+1]); }
  }

  // ── Affichage bannière ─────────────────────────────
  process.stdout.write(A.clearScreen);
  process.stdout.write(A.hideCursor);
  printHeader(activeProvider, activeModel);

  // Tips
  process.stdout.write(
    c.dim('  Tape un message pour commencer  ·  /help pour les commandes  ·  Ctrl+C pour quitter') + '\n\n'
  );

  // Restaurer le curseur avant le prompt
  process.stdout.write(A.showCursor);

  // ── Boucle readline ───────────────────────────────
  let inMultiline = false;
  let mlBuffer    = [];

  rl.on('line', async (input) => {
    const line = input;

    // Mode multi-ligne actif
    if (inMultiline) {
      if (line.trim() === '\\\\end' || line.trim() === '\\end' || line.trim() === '\\\\' ) {
        inMultiline = false;
        const full = mlBuffer.join('\n');
        mlBuffer = [];
        closeInputBox();
        if (full.trim()) await sendMessage(full, rl);
      } else {
        mlBuffer.push(line);
        // Continuer dans le cadre ouvert
        const w  = Math.min(W() - 4, 76);
        process.stdout.write(`  ${A.dim}${A.green}│${A.reset}  `);
        return;
      }
      process.stdout.write(getPrompt(cfg, activeProvider, activeModel, loadedFiles, sessionId));
      return;
    }

    // Entrée en mode multi-ligne si la ligne se termine par "\"
    if (line.endsWith('\\') && !line.endsWith('\\\\')) {
      inMultiline = true;
      mlBuffer = [line.slice(0, -1)];
      // Le cadre est déjà ouvert (getPrompt l'a ouvert), on continue dedans
      process.stdout.write(`  ${A.dim}${A.green}│${A.reset}  `);
      return;
    }

    // Activation explicite multi-ligne avec \\ seul
    if (line.trim() === '\\\\' || line.trim() === '\\') {
      inMultiline = true; mlBuffer = [];
      process.stdout.write(`  ${A.dim}${A.green}│${A.reset}  `);
      return;
    }

    if (!line.trim()) {
      process.stdout.write(getPrompt(cfg, activeProvider, activeModel, loadedFiles, sessionId));
      return;
    }

    // Fermer le cadre de saisie AVANT de traiter
    closeInputBox();

    if (line.trim().startsWith('/')) {
      await handleCommand(line.trim(), rl);
    } else {
      await sendMessage(line, rl);
    }

    process.stdout.write(getPrompt(cfg, activeProvider, activeModel, loadedFiles, sessionId));
  });

  rl.on('close', () => {
    process.stdout.write('\n' + c.dim('  Bye.\n'));
    process.stdout.write(A.showCursor);
    process.exit(0);
  });

  // Afficher le premier prompt
  process.stdout.write(getPrompt(cfg, activeProvider, activeModel, loadedFiles, sessionId));
}

main().catch(err => {
  process.stdout.write(A.showCursor);
  process.stderr.write(`\x1b[31mFATAL: ${err.message}\x1b[0m\n`);
  process.stderr.write(err.stack + '\n');
  process.exit(1);
});
