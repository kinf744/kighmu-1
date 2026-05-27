#!/usr/bin/env node
// ═══════════════════════════════════════════════════════
//  VOANH CLI v2 — Multi-Provider AI Terminal
//  Mistral · Groq · OpenRouter
//  Features : Streaming · Files · Shell · Diff · Multi-files
//  Usage : node index.js [--setup] [--session <id>] [--no-stream]
// ═══════════════════════════════════════════════════════

import readline   from 'readline';
import fs         from 'fs';
import path       from 'path';
import os         from 'os';
import { execSync, spawnSync } from 'child_process';
import { createPatch }        from 'diff';

import { PROVIDERS, MISTRAL_MODELS, GROQ_MODELS, OPENROUTER_MODELS } from './providers.js';
import {
  loadConfig, saveConfig, loadAgents, saveAgents,
  loadMemory, saveMemory, addMemory, getRelevantMemories,
  listSessions, loadSession, saveSession, deleteSession, CONFIG_DIR,
  readFileForContext, readDirForContext, formatFilesForContext,
  saveProjectSnapshot, loadProjectSnapshot, listProjectSnapshots,
  listTasks, saveTask, loadTask, deleteTask, TASKS_DIR,
} from './config.js';
import {
  C, printBanner, printUserMsg, printAssistantMsg,
  printStreamHeader, printStreamFooter,
  printError, printSuccess, printInfo, printSection,
  printTable, Spinner, hr, hrCyan, termWidth,
  modelLabel, providerBadge, renderMarkdown, renderDiff,
  StreamRenderer,
} from './render.js';

// ══════════════════════════════════════════════════════
// STATE
// ══════════════════════════════════════════════════════
let cfg      = loadConfig();
let agents   = loadAgents();
let messages = [];
let sessionId    = null;
let activeAgent  = null;
let multilineBuffer = [];
let inMultiline     = false;

// Fichiers chargés dans le contexte courant
let loadedFiles = [];      // [{ path, content, size, ext }]
let projectDir  = null;    // si un répertoire entier est chargé

// Streaming activé par défaut (désactivable avec --no-stream)
let streamingEnabled = !process.argv.includes('--no-stream');

// Sélection active
let activeProvider = cfg.defaultProvider || 'mistral';
let activeModel    = cfg.defaultModel    || 'codestral-2508';

// ══════════════════════════════════════════════════════
// READLINE
// ══════════════════════════════════════════════════════
const rl = readline.createInterface({
  input:  process.stdin,
  output: process.stdout,
  terminal: true,
  historySize: 200,
});

function prompt() {
  const agentTag   = activeAgent  ? C.violet(`[${activeAgent.name}] `) : '';
  const provTag    = providerBadge(activeProvider) + ' ';
  const modelTag   = C.dim(activeModel.split('/').pop() ?? activeModel) + ' ';
  const streamTag  = streamingEnabled ? C.neon('~') : C.dim('•');
  const filesTag   = loadedFiles.length ? C.gold(` [${loadedFiles.length}f]`) : '';
  const projectTag = projectDir ? C.violet(` [proj]`) : '';
  process.stdout.write(`\n${agentTag}${provTag}${modelTag}${streamTag}${filesTag}${projectTag} ${C.cyan('▶')} `);
}

// ══════════════════════════════════════════════════════
// SYSTEM PROMPT
// ══════════════════════════════════════════════════════
function buildSystemPrompt(userMessage = '') {
  let sys = '';

  if (activeAgent) {
    sys += `[AGENT : ${activeAgent.name}]\n`;
    sys += `Rôle : ${activeAgent.desc || ''}\n`;
    if (activeAgent.instructions) sys += `\nInstructions : ${activeAgent.instructions}\n`;
    if (activeAgent.style) {
      const styleMap = {
        concis:       'Réponds de manière concise et directe.',
        detaille:     'Réponds de façon exhaustive et détaillée.',
        formel:       'Maintiens un ton formel et professionnel.',
        creatif:      'Sois créatif et innovant dans tes réponses.',
        pedagogique:  'Adopte une approche pédagogique et claire.',
        dev: `Tu es expert en développement logiciel (mobile iOS/Android/Flutter, web, backend, DevOps).
Génère du code COMPLET, FONCTIONNEL, PRODUCTION-READY sans jamais tronquer ni abréger.
Ne dis JAMAIS "le reste du code reste inchangé" ou "... voir code précédent" — donne TOUJOURS tout le fichier.
Commente le code de façon pertinente. Gère les erreurs. Respecte les best practices du langage.`,
      };
      if (styleMap[activeAgent.style]) sys += `\nStyle : ${styleMap[activeAgent.style]}\n`;
    }
    if (activeAgent.forbidden) sys += `\nINTERDIT : ${activeAgent.forbidden}\n`;
  } else {
    sys = `Tu es VOANH, un assistant IA expert en développement logiciel et architecture technique.
Tu fonctionnes sur un serveur VPS root sans limites de tokens.

RÈGLES ABSOLUES :
1. Génère du code COMPLET et FONCTIONNEL — jamais tronqué, jamais abrégé.
2. Ne dis JAMAIS "le reste est inchangé", "voir code précédent", "..." pour remplacer du code.
3. Donne TOUJOURS le fichier entier quand tu modifies du code existant.
4. Commente le code important. Gère les cas d'erreur. Respecte les conventions.
5. Pour le mobile : génère du code compatible iOS (Swift/SwiftUI) ET Android (Kotlin/Compose) ET Flutter (Dart) selon le contexte.
6. Réponds dans la langue de l'utilisateur (français par défaut).
7. Sois précis, structuré et professionnel.`;
  }

  // Mémoire globale pertinente
  if (userMessage) {
    const mems = getRelevantMemories(userMessage, 6);
    if (mems.length) {
      sys += `\n\n[MÉMOIRE GLOBALE]\n${mems.join('\n')}`;
    }
  }

  return sys;
}

// ══════════════════════════════════════════════════════
// CONTEXTE FICHIERS
// ══════════════════════════════════════════════════════
function buildFilesContext() {
  if (!loadedFiles.length) return '';
  return '\n\n' + formatFilesForContext(loadedFiles);
}

// ══════════════════════════════════════════════════════
// ENVOI API (avec ou sans streaming)
// ══════════════════════════════════════════════════════
async function sendMessage(userText) {
  const apiKey = cfg.keys?.[activeProvider];
  if (!apiKey) {
    printError(`Aucune clé API pour ${activeProvider}. Lance /setup ou /key ${activeProvider} <cle>`);
    return;
  }

  // Ajouter le message utilisateur
  messages.push({ role: 'user', content: userText });
  printUserMsg(userText);

  // Construire le contexte
  const sysPrompt = buildSystemPrompt(userText) + buildFilesContext();
  const relevantMems = getRelevantMemories(userText, 4);

  const contextMessages = [
    { role: 'system', content: sysPrompt },
  ];

  if (relevantMems.length) {
    contextMessages.push({
      role: 'user',
      content: `[Contexte mémoire globale]\n${relevantMems.join('\n')}`,
    });
    contextMessages.push({
      role: 'assistant',
      content: 'Contexte mémorisé. Je prends en compte ces informations.',
    });
  }

  // Fenêtre de contexte : derniers 40 messages
  const histSlice = messages.slice(-40);
  contextMessages.push(...histSlice);

  const provider = PROVIDERS[activeProvider];
  const modelInfo = provider.models.find(m => m.id === activeModel);

  const opts = {
    temperature: activeAgent?.temperature ?? cfg.overrideTemp ?? modelInfo?.temp ?? 0.5,
    maxTokens:   activeAgent?.maxTokens   ?? cfg.overrideMaxTokens ?? 32768,
  };

  // ── MODE STREAMING ──────────────────────────────────
  if (streamingEnabled && provider.stream) {
    printStreamHeader(activeProvider, activeModel);
    const renderer = new StreamRenderer();
    let fullReply = '';
    let startTime = Date.now();

    try {
      for await (const delta of provider.stream(apiKey, activeModel, contextMessages, opts)) {
        renderer.push(delta);
        fullReply += delta;
      }
      renderer.flush();

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      const tokenEstimate = Math.round(fullReply.length / 4);
      printStreamFooter({ total_tokens: tokenEstimate, elapsed });

      messages.push({ role: 'assistant', content: fullReply });
      autoSaveSession();

      if (activeAgent?.autoMemory) autoExtractMemory(fullReply);

    } catch (err) {
      printError(err.message);
      messages.pop();
    }

  // ── MODE NON-STREAMING ───────────────────────────────
  } else {
    const spinner = new Spinner(`${activeProvider} / ${activeModel}…`);
    spinner.start();

    try {
      const result = await provider.send(apiKey, activeModel, contextMessages, opts);
      spinner.stop();

      const reply = result.content;
      messages.push({ role: 'assistant', content: reply });

      autoSaveSession();
      printAssistantMsg(reply, activeProvider, activeModel, result.usage);

      if (activeAgent?.autoMemory) autoExtractMemory(reply);

    } catch (err) {
      spinner.fail();
      printError(err.message);
      messages.pop();
    }
  }
}

// ══════════════════════════════════════════════════════
// SESSION AUTO-SAVE
// ══════════════════════════════════════════════════════
function autoSaveSession() {
  if (!sessionId) sessionId = crypto.randomUUID();
  const firstUserMsg = messages.find(m => m.role === 'user');
  saveSession(sessionId, {
    id: sessionId,
    title: firstUserMsg?.content?.slice(0, 60) || 'Nouvelle conversation',
    provider: activeProvider,
    model: activeModel,
    agentId: activeAgent?.id ?? null,
    messages,
    updated: Date.now(),
  });
}

// ══════════════════════════════════════════════════════
// AUTO-MÉMOIRE
// ══════════════════════════════════════════════════════
function autoExtractMemory(text) {
  const match = text.match(/(?:MÉMO|RETIENS|REMEMBER)[:\s]+(.+?)(?:\n|$)/i);
  if (match) {
    addMemory(match[1].trim(), ['auto']);
    printInfo(`Mémorisé automatiquement : "${match[1].trim().slice(0, 60)}"`);
  }
}

// ══════════════════════════════════════════════════════
// COMMANDES /slash
// ══════════════════════════════════════════════════════
async function handleCommand(input) {
  const [cmd, ...args] = input.trim().split(/\s+/);

  switch (cmd) {

    // ── AIDE ──────────────────────────────────────────

    // ── RESUME PROJET (reprendre après SSH coupée) ────────
    case '/resume':
    case '/r': {
      const arg = args.join(' ');

      if (!arg) {
        const snaps = listProjectSnapshots();
        if (!snaps.length) {
          printInfo('Aucun snapshot de projet. Utilise /project <dir> puis /resume save.');
          break;
        }
        printSection('PROJETS MÉMORISÉS');
        snaps.slice(0, 10).forEach((s, i) => {
          const date = new Date(s.savedAt).toLocaleString('fr-FR');
          const files = s.fileCount || 0;
          const sess  = s.sessionId ? C.dim(s.sessionId.slice(0,8)) : C.dim('—');
          console.log(
            `  ${C.dim(String(i+1).padStart(2))}  ` +
            `${C.cyan(s.dir.split('/').pop().padEnd(25))}  ` +
            `${C.dim(String(files) + ' fichiers')}  ` +
            `${C.dim(date)}  sess:${sess}`
          );
          console.log(`  ${C.dim('    ' + s.dir)}`);
        });
        console.log();
        printInfo('Usage : /resume <numéro>  ou  /resume save  ou  /resume <dir>');
        break;
      }

      // Sauvegarder le snapshot du projet courant
      if (arg === 'save') {
        if (!projectDir) {
          printError('Aucun projet chargé. Utilise /project <dir> d'abord.');
          break;
        }
        saveProjectSnapshot(projectDir, {
          sessionId,
          provider: activeProvider,
          model: activeModel,
          agentId: activeAgent?.id ?? null,
          fileCount: loadedFiles.length,
          filePaths: loadedFiles.map(f => f.path),
          messageCount: messages.length,
          lastMessages: messages.slice(-6),
          notes: `Sauvegardé le ${new Date().toLocaleString('fr-FR')}`,
        });
        printSuccess(`Snapshot sauvegardé pour : ${projectDir}`);
        printInfo('Lors de ta prochaine session : /resume <numéro> pour reprendre.');
        break;
      }

      // Charger un snapshot
      const snaps = listProjectSnapshots();
      const byNum = parseInt(arg);
      let snap = null;
      if (!isNaN(byNum) && byNum >= 1 && byNum <= snaps.length) {
        snap = snaps[byNum - 1];
      } else {
        snap = snaps.find(s => s.dir.includes(arg));
      }

      if (!snap) { printError(`Snapshot introuvable : ${arg}`); break; }

      const spinner = new Spinner(`Rechargement du projet ${snap.dir}…`);
      spinner.start();

      // Recharger les fichiers
      const files = readDirForContext(snap.dir, 4);
      spinner.stop();

      loadedFiles = files;
      projectDir  = snap.dir;
      activeProvider = snap.provider || activeProvider;
      activeModel    = snap.model    || activeModel;

      if (snap.agentId) {
        const agents2 = loadAgents();
        activeAgent = agents2.find(a => a.id === snap.agentId) ?? null;
      }

      // Restaurer les derniers messages du contexte
      if (snap.lastMessages?.length) {
        messages = snap.lastMessages;
        sessionId = snap.sessionId || null;
      }

      printSuccess(`Projet repris : ${snap.dir}`);
      printInfo(`${files.length} fichiers rechargés | ${snap.messageCount} messages d'historique restaurés`);
      if (activeAgent) printInfo(`Agent actif : ${activeAgent.name}`);
      console.log();
      printInfo('Contexte prêt — tu peux continuer où tu t'es arrêté.');
      break;
    }

    // ── TÂCHES AGENTS AUTONOMES ───────────────────────────
    case '/task':
    case '/t': {
      const sub = args[0];

      if (!sub || sub === 'list' || sub === 'ls') {
        const tasks = listTasks();
        if (!tasks.length) {
          printInfo('Aucune tâche. Utilise /task new pour créer une tâche autonome.');
          printInfo('Lance le daemon :  nohup node daemon.js > /dev/null 2>&1 &');
          break;
        }
        printSection(`TÂCHES (${tasks.length})`);
        const statusColor = {
          pending:  C.gold,
          running:  C.neon,
          done:     (s) => `\x1b[32m${s}\x1b[0m`,
          error:    C.danger,
          cancelled: C.dim,
        };
        tasks.slice(0, 20).forEach((t, i) => {
          const col = statusColor[t.status] || C.muted;
          const repeat = t.repeat ? C.violet(' 🔁') : '';
          const date = t.lastRunAt ? new Date(t.lastRunAt).toLocaleString('fr-FR') : 'jamais';
          console.log(
            `  ${C.dim(String(i+1).padStart(2))}  ` +
            `${col(t.status.padEnd(9))}  ` +
            `${C.cyan(t.id.slice(0,8))}  ` +
            `${C.muted((t.title||'').slice(0,45).padEnd(45))}  ` +
            `${C.dim('dernier:'+date)}${repeat}`
          );
        });
        console.log();
        const pidFile = os.homedir() + '/.voanh/daemon.pid';
        const daemonRunning = fs.existsSync(pidFile);
        if (daemonRunning) {
          const pid = fs.readFileSync(pidFile,'utf8').trim();
          printInfo(`Daemon actif (PID ${pid}) | Logs : ~/.voanh/daemon.log`);
        } else {
          printInfo('Daemon non actif. Pour le lancer :');
          printInfo('  nohup node daemon.js > ~/.voanh/daemon.log 2>&1 &');
        }
        break;
      }

      if (sub === 'new') {
        await createTaskWizard();
        break;
      }

      if (sub === 'result' || sub === 'show') {
        const arg2 = args[1];
        if (!arg2) { printInfo('Usage : /task result <id>'); break; }
        const tasks = listTasks();
        const byNum = parseInt(arg2);
        let task = null;
        if (!isNaN(byNum) && byNum >= 1 && byNum <= tasks.length) task = tasks[byNum-1];
        else task = tasks.find(t => t.id.startsWith(arg2));
        if (!task) { printError(`Tâche introuvable : ${arg2}`); break; }

        if (!task.lastResult || !fs.existsSync(task.lastResult)) {
          printInfo(`Tâche "${task.title}" — pas encore de résultat (statut: ${task.status})`);
          if (task.lastError) printError(`Dernière erreur : ${task.lastError}`);
          break;
        }
        const result = fs.readFileSync(task.lastResult, 'utf8');
        printSection(`RÉSULTAT — ${task.title}`);
        console.log(renderMarkdown(result));

        // Injecter dans le contexte si souhaité
        messages.push({ role: 'user', content: `[Résultat tâche autonome: ${task.title}]
${result}` });
        messages.push({ role: 'assistant', content: 'Résultat de la tâche autonome reçu dans le contexte.' });
        printInfo('Résultat injecté dans le contexte courant.');
        break;
      }

      if (sub === 'cancel') {
        const arg2 = args[1];
        if (!arg2) { printInfo('Usage : /task cancel <id>'); break; }
        const tasks = listTasks();
        const byNum = parseInt(arg2);
        let task = null;
        if (!isNaN(byNum) && byNum >= 1 && byNum <= tasks.length) task = tasks[byNum-1];
        else task = tasks.find(t => t.id.startsWith(arg2));
        if (!task) { printError(`Tâche introuvable`); break; }
        task.status = 'cancelled';
        saveTask(task);
        printSuccess(`Tâche annulée : ${task.title}`);
        break;
      }

      if (sub === 'delete' || sub === 'del') {
        const arg2 = args[1];
        if (!arg2) { printInfo('Usage : /task delete <id>'); break; }
        const tasks = listTasks();
        const byNum = parseInt(arg2);
        let task = null;
        if (!isNaN(byNum) && byNum >= 1 && byNum <= tasks.length) task = tasks[byNum-1];
        else task = tasks.find(t => t.id.startsWith(arg2));
        if (!task) { printError(`Tâche introuvable`); break; }
        deleteTask(task.id);
        printSuccess(`Tâche supprimée : ${task.title}`);
        break;
      }

      if (sub === 'daemon') {
        const action = args[1];
        const pidFile = os.homedir() + '/.voanh/daemon.pid';
        if (action === 'stop') {
          if (!fs.existsSync(pidFile)) { printInfo('Daemon non actif.'); break; }
          const pid = fs.readFileSync(pidFile,'utf8').trim();
          try {
            process.kill(parseInt(pid), 'SIGTERM');
            printSuccess(`Daemon (PID ${pid}) arrêté.`);
          } catch { printError('Impossible d'arrêter le daemon (déjà mort?).'); }
          break;
        }
        // start
        printInfo('Pour lancer le daemon en arrière-plan :');
        console.log(C.cyan('  nohup node daemon.js > ~/.voanh/daemon.log 2>&1 &'));
        printInfo('Pour voir les logs :');
        console.log(C.cyan('  tail -f ~/.voanh/daemon.log'));
        printInfo('Pour arrêter :');
        console.log(C.cyan('  /task daemon stop'));
        break;
      }

      printInfo('Usage : /task [list|new|result <id>|cancel <id>|delete <id>|daemon]');
      break;
    }

    case '/help':
    case '/h': {
      printSection('COMMANDES DISPONIBLES');
      const cmds = [
        ['/help',              'Afficher cette aide'],
        ['─── IA & PROVIDERS ───────────────────────────────────', ''],
        ['/provider <name>',   'Changer de provider (mistral|groq|openrouter)'],
        ['/model [id]',        'Lister ou changer de modèle'],
        ['/key <p> <k>',       'Définir une clé API'],
        ['/keys',              'Voir les clés configurées (masquées)'],
        ['/agent [name|new]',  'Lister / activer / créer un agent'],
        ['/noagent',           'Désactiver l\'agent actif'],
        ['/stream',            'Activer/désactiver le streaming (actuel: ' + (streamingEnabled ? 'ON' : 'OFF') + ')'],
        ['─── FICHIERS & PROJET ────────────────────────────────', ''],
        ['/file <path>',       'Charger un fichier dans le contexte'],
        ['/files',             'Voir les fichiers chargés'],
        ['/unfile [path]',     'Retirer un fichier (ou tous si vide)'],
        ['/project <dir>',     'Charger tout un répertoire projet'],
        ['/tree [dir]',        'Afficher l\'arborescence d\'un dossier'],
        ['/write <path>',      'Écrire la dernière réponse dans un fichier'],
        ['/diff <path>',       'Diff entre la dernière réponse code et un fichier'],
        ['/patch <path>',      'Appliquer le code de la dernière réponse sur un fichier'],
        ['─── SHELL ────────────────────────────────────────────', ''],
        ['/run <cmd>',         'Exécuter une commande shell et injecter le résultat'],
        ['/shell',             'Lancer un shell interactif temporaire'],
        ['─── CONVERSATION ─────────────────────────────────────', ''],
        ['/new',               'Nouvelle conversation (reset messages)'],
        ['/sessions',          'Lister les sessions sauvegardées'],
        ['/load <id>',         'Charger une session'],
        ['/delete <id>',       'Supprimer une session'],
        ['/context',           'Voir le contexte actuel'],
        ['/export',            'Exporter la conversation (.md)'],
        ['─── MÉMOIRE & CONFIG ─────────────────────────────────', ''],
        ['/mem [add|clear]',   'Gérer la mémoire globale'],
        ['/temp <0.0-2.0>',    'Changer la température'],
        ['/tokens <n>',        'Changer max_tokens'],
        ['/status',            'Statut complet'],
        ['/setup',             'Wizard de configuration'],
        ['/clear',             'Effacer l\'écran'],
        ['\\\\',               'Mode multi-ligne (terminer avec \\\\end)'],
        ['/exit ou /quit',     'Quitter'],
        ['─── PROJET & REPRISE ─────────────────────────────────', ''],
        ['/resume [n|save]',   'Reprendre un projet après SSH coupée'],
        ['─── AGENTS AUTONOMES ─────────────────────────────────', ''],
        ['/task [list|new]',   'Gérer les tâches autonomes (avec daemon)'],
        ['/task result <id>',  'Voir le résultat d\'une tâche'],
        ['/task daemon',       'Infos pour lancer/arrêter le daemon'],
      ];
      printTable(['Commande', 'Description'], cmds);
      break;
    }

    // ── PROVIDER ──────────────────────────────────────
    case '/provider':
    case '/p': {
      const name = args[0]?.toLowerCase();
      if (!name) {
        printSection('PROVIDERS DISPONIBLES');
        Object.entries(PROVIDERS).forEach(([id, p]) => {
          const active = id === activeProvider ? C.neon(' ← actif') : '';
          const hasKey = cfg.keys?.[id] ? C.neon(' ✓') : C.danger(' ✗ pas de clé');
          const streamSupport = p.stream ? C.neon(' ~stream') : C.dim(' no-stream');
          console.log(`  ${providerBadge(id)} ${C.bright(p.name)}${hasKey}${streamSupport}${active}`);
        });
        console.log();
        printInfo('Usage : /provider mistral | groq | openrouter');
        break;
      }
      if (!PROVIDERS[name]) {
        printError(`Provider inconnu : ${name}. Disponibles : ${Object.keys(PROVIDERS).join(', ')}`);
        break;
      }
      activeProvider = name;
      const defaultModel = PROVIDERS[name].models[0];
      activeModel = cfg.providerDefaults?.[name] || defaultModel.id;
      printSuccess(`Provider → ${name.toUpperCase()} | Modèle → ${activeModel}`);
      break;
    }

    // ── MODEL ─────────────────────────────────────────
    case '/model':
    case '/m': {
      const modelArg = args.join(' ');
      if (!modelArg) {
        printSection(`MODÈLES — ${activeProvider.toUpperCase()}`);
        const models = PROVIDERS[activeProvider].models;
        models.forEach((m, i) => {
          const active = m.id === activeModel ? C.neon(' ←') : '';
          const idx = String(i + 1).padStart(2, ' ');
          const ctx = C.dim(`${(m.ctx / 1000).toFixed(0)}k`);
          console.log(`  ${C.dim(idx)}  ${C.cyan(m.id.padEnd(48))} ${C.dim(m.name.padEnd(35))} ${ctx}${active}`);
        });
        console.log();
        printInfo('Usage : /model <id>   ou   /model <numéro>');
        break;
      }
      const models = PROVIDERS[activeProvider].models;
      const byNum = parseInt(modelArg);
      if (!isNaN(byNum) && byNum >= 1 && byNum <= models.length) {
        activeModel = models[byNum - 1].id;
        printSuccess(`Modèle → ${activeModel}`);
        break;
      }
      const found = models.find(m => m.id === modelArg || m.id.includes(modelArg));
      if (found) {
        activeModel = found.id;
        printSuccess(`Modèle → ${activeModel}`);
      } else {
        printError(`Modèle introuvable : ${modelArg}`);
      }
      break;
    }

    // ── STREAMING ─────────────────────────────────────
    case '/stream': {
      streamingEnabled = !streamingEnabled;
      printSuccess(`Streaming ${streamingEnabled ? 'ACTIVÉ' : 'DÉSACTIVÉ'}`);
      break;
    }

    // ── CLÉS API ──────────────────────────────────────
    case '/key': {
      const provider = args[0]?.toLowerCase();
      const key      = args[1];
      if (!provider || !key) {
        printInfo('Usage : /key <provider> <cle_api>');
        printInfo('Ex :    /key mistral abc123...');
        break;
      }
      if (!PROVIDERS[provider]) {
        printError(`Provider inconnu : ${provider}`);
        break;
      }
      if (!cfg.keys) cfg.keys = {};
      cfg.keys[provider] = key;
      saveConfig(cfg);
      printSuccess(`Clé API ${provider} enregistrée dans ~/.voanh/config.json`);
      break;
    }

    case '/keys': {
      printSection('CLÉS API CONFIGURÉES');
      Object.keys(PROVIDERS).forEach(p => {
        const k = cfg.keys?.[p];
        if (k) {
          const masked = k.slice(0, 6) + '••••••••••' + k.slice(-4);
          console.log(`  ${providerBadge(p)} ${C.neon('✓')} ${C.dim(masked)}`);
        } else {
          console.log(`  ${providerBadge(p)} ${C.danger('✗')} ${C.dim('non configurée')}`);
        }
      });
      console.log();
      break;
    }

    // ══════════════════════════════════════════════════
    // FICHIERS
    // ══════════════════════════════════════════════════
    case '/file':
    case '/f': {
      const filePath = args.join(' ');
      if (!filePath) {
        printInfo('Usage : /file <chemin>  Ex: /file ./src/App.tsx');
        break;
      }
      const file = readFileForContext(filePath);
      if (!file) {
        printError(`Fichier introuvable ou illisible : ${filePath}`);
        break;
      }
      // Éviter les doublons
      const existing = loadedFiles.findIndex(f => f.path === file.path);
      if (existing !== -1) {
        loadedFiles[existing] = file;
        printSuccess(`Fichier rechargé : ${file.path} (${(file.size / 1024).toFixed(1)} Ko)`);
      } else {
        loadedFiles.push(file);
        printSuccess(`Fichier chargé : ${file.path} (${(file.size / 1024).toFixed(1)} Ko)`);
      }
      if (file.truncated) {
        printInfo('⚠ Fichier tronqué (>500 Ko) — seules les 200 premières lignes sont chargées.');
      }
      break;
    }

    case '/files': {
      if (!loadedFiles.length) {
        printInfo('Aucun fichier chargé. Utilise /file <path> ou /project <dir>.');
        break;
      }
      printSection(`FICHIERS CHARGÉS (${loadedFiles.length})`);
      loadedFiles.forEach((f, i) => {
        const sizeStr = (f.size / 1024).toFixed(1) + ' Ko';
        const truncTag = f.truncated ? C.danger(' [tronqué]') : '';
        console.log(`  ${C.dim(String(i + 1).padStart(2))}  ${C.cyan(f.path)}  ${C.dim(sizeStr)}${truncTag}`);
      });
      const totalSize = loadedFiles.reduce((s, f) => s + f.size, 0);
      console.log();
      console.log(C.dim(`  Total : ${(totalSize / 1024).toFixed(1)} Ko`));
      if (projectDir) console.log(C.dim(`  Projet : ${projectDir}`));
      console.log();
      break;
    }

    case '/unfile': {
      const filePath = args.join(' ');
      if (!filePath) {
        loadedFiles = [];
        projectDir = null;
        printSuccess('Tous les fichiers ont été retirés du contexte.');
        break;
      }
      const abs = path.resolve(filePath);
      const before = loadedFiles.length;
      loadedFiles = loadedFiles.filter(f => f.path !== abs);
      if (loadedFiles.length < before) {
        printSuccess(`Fichier retiré : ${abs}`);
      } else {
        printError(`Fichier non trouvé dans le contexte : ${filePath}`);
      }
      break;
    }

    // ── PROJET (répertoire complet) ───────────────────
    case '/project':
    case '/proj': {
      const dirPath = args.join(' ') || '.';
      const abs = path.resolve(dirPath);
      if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) {
        printError(`Répertoire introuvable : ${dirPath}`);
        break;
      }
      const spinner = new Spinner(`Chargement du projet ${abs}…`);
      spinner.start();
      const files = readDirForContext(abs, 4);
      spinner.stop();
      if (!files.length) {
        printError(`Aucun fichier texte/code trouvé dans ${abs}`);
        break;
      }
      loadedFiles = files;
      projectDir = abs;
      const totalSize = files.reduce((s, f) => s + f.size, 0);
      printSuccess(`Projet chargé : ${files.length} fichiers, ${(totalSize / 1024).toFixed(1)} Ko`);
      printInfo(`Répertoires exclus : node_modules, .git, dist, build, .dart_tool, Pods, .gradle`);

      // Résumé de l'arborescence
      const byExt = {};
      files.forEach(f => {
        const e = f.ext || 'autre';
        byExt[e] = (byExt[e] || 0) + 1;
      });
      const extSummary = Object.entries(byExt)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([e, n]) => `${e}:${n}`)
        .join('  ');
      printInfo(`Types : ${extSummary}`);
      break;
    }

    // ── TREE ──────────────────────────────────────────
    case '/tree': {
      const dirPath = args.join(' ') || '.';
      const abs = path.resolve(dirPath);
      if (!fs.existsSync(abs)) {
        printError(`Répertoire introuvable : ${dirPath}`);
        break;
      }

      function printTree(dir, prefix = '', depth = 0) {
        if (depth > 3) return;
        let entries;
        try { entries = fs.readdirSync(dir); } catch { return; }
        const filtered = entries.filter(e =>
          !['node_modules','.git','dist','build','.dart_tool','Pods','.gradle','.idea','__pycache__'].includes(e) &&
          !e.startsWith('.')
        );
        filtered.forEach((entry, i) => {
          const isLast = i === filtered.length - 1;
          const fullPath = path.join(dir, entry);
          const isDir = fs.statSync(fullPath).isDirectory();
          const connector = isLast ? '└── ' : '├── ';
          console.log(C.dim(prefix) + C.dim(connector) + (isDir ? C.cyan(entry + '/') : C.muted(entry)));
          if (isDir) {
            const newPrefix = prefix + (isLast ? '    ' : '│   ');
            printTree(fullPath, newPrefix, depth + 1);
          }
        });
      }

      console.log(C.cyan(abs + '/'));
      printTree(abs);
      console.log();
      break;
    }

    // ── WRITE (écrire la dernière réponse dans un fichier) ──
    case '/write':
    case '/w': {
      const filePath = args.join(' ');
      if (!filePath) {
        printInfo('Usage : /write <chemin>  Ex: /write ./src/App.tsx');
        break;
      }
      const lastAI = [...messages].reverse().find(m => m.role === 'assistant');
      if (!lastAI) {
        printError('Aucune réponse AI disponible.');
        break;
      }

      // Extraire le premier bloc de code s'il existe, sinon toute la réponse
      const codeMatch = lastAI.content.match(/```[\w]*\n([\s\S]*?)```/);
      const content = codeMatch ? codeMatch[1] : lastAI.content;

      const abs = path.resolve(filePath);
      const dir = path.dirname(abs);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      // Backup si le fichier existe déjà
      if (fs.existsSync(abs)) {
        const backup = abs + '.bak';
        fs.copyFileSync(abs, backup);
        printInfo(`Backup créé : ${backup}`);
      }

      fs.writeFileSync(abs, content, 'utf8');
      printSuccess(`Fichier écrit : ${abs} (${(content.length / 1024).toFixed(1)} Ko)`);

      // Recharger dans le contexte
      const file = readFileForContext(abs);
      if (file) {
        const existing = loadedFiles.findIndex(f => f.path === file.path);
        if (existing !== -1) loadedFiles[existing] = file;
        else loadedFiles.push(file);
        printInfo('Fichier rechargé dans le contexte.');
      }
      break;
    }

    // ── DIFF ──────────────────────────────────────────
    case '/diff': {
      const filePath = args.join(' ');
      if (!filePath) {
        printInfo('Usage : /diff <chemin>  Ex: /diff ./src/main.py');
        break;
      }
      const lastAI = [...messages].reverse().find(m => m.role === 'assistant');
      if (!lastAI) {
        printError('Aucune réponse AI disponible.');
        break;
      }

      const abs = path.resolve(filePath);
      if (!fs.existsSync(abs)) {
        printError(`Fichier introuvable : ${filePath}`);
        break;
      }

      const original = fs.readFileSync(abs, 'utf8');
      const codeMatch = lastAI.content.match(/```[\w]*\n([\s\S]*?)```/);
      const proposed = codeMatch ? codeMatch[1] : lastAI.content;

      const diff = createPatch(path.basename(abs), original, proposed, 'original', 'proposé');

      if (diff.split('\n').slice(4).every(l => l.startsWith(' ') || l === '')) {
        printInfo('Aucune différence entre la réponse et le fichier.');
      } else {
        printSection(`DIFF — ${abs}`);
        console.log(renderDiff(diff));
      }
      break;
    }

    // ── PATCH (appliquer le code proposé) ─────────────
    case '/patch': {
      const filePath = args.join(' ');
      if (!filePath) {
        printInfo('Usage : /patch <chemin>  Ex: /patch ./src/main.py');
        printInfo('Applique le PREMIER bloc de code de la dernière réponse AI sur le fichier.');
        break;
      }
      const lastAI = [...messages].reverse().find(m => m.role === 'assistant');
      if (!lastAI) {
        printError('Aucune réponse AI disponible.');
        break;
      }
      const abs = path.resolve(filePath);
      const codeMatch = lastAI.content.match(/```[\w]*\n([\s\S]*?)```/);
      if (!codeMatch) {
        printError('Aucun bloc de code trouvé dans la dernière réponse.');
        break;
      }
      const newContent = codeMatch[1];

      // Backup obligatoire
      if (fs.existsSync(abs)) {
        fs.copyFileSync(abs, abs + '.bak');
        printInfo(`Backup : ${abs}.bak`);
      }

      const dir = path.dirname(abs);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(abs, newContent, 'utf8');
      printSuccess(`Patch appliqué : ${abs}`);

      // Recharger dans le contexte
      const file = readFileForContext(abs);
      if (file) {
        const existing = loadedFiles.findIndex(f => f.path === file.path);
        if (existing !== -1) loadedFiles[existing] = file;
        else loadedFiles.push(file);
        printInfo('Fichier rechargé dans le contexte.');
      }
      break;
    }

    // ══════════════════════════════════════════════════
    // SHELL
    // ══════════════════════════════════════════════════
    case '/run':
    case '/exec':
    case '/!': {
      const command = args.join(' ');
      if (!command) {
        printInfo('Usage : /run <commande>  Ex: /run flutter analyze');
        printInfo('Le résultat sera injecté dans le prochain message à l\'IA.');
        break;
      }

      printInfo(`Exécution : ${command}`);
      try {
        const result = execSync(command, {
          encoding: 'utf8',
          timeout: 60000,
          maxBuffer: 512 * 1024,
          stdio: ['inherit', 'pipe', 'pipe'],
          cwd: projectDir || process.cwd(),
        });
        const output = result || '(aucune sortie)';
        console.log(C.dim('┌─ OUTPUT ──────────────────────'));
        output.split('\n').slice(0, 100).forEach(l => console.log(C.muted('│ ') + l));
        console.log(C.dim('└───────────────────────────────'));

        // Injecter dans le prochain message
        const injection = `[RÉSULTAT DE LA COMMANDE: ${command}]\n\`\`\`\n${output.slice(0, 8000)}\n\`\`\``;
        messages.push({ role: 'user', content: injection });
        messages.push({ role: 'assistant', content: 'Résultat de commande reçu. Prêt à analyser.' });
        printInfo('Résultat injecté dans le contexte. Pose ta question à l\'IA.');

      } catch (err) {
        const stderr = err.stderr || err.message || 'Erreur inconnue';
        const stdout = err.stdout || '';
        console.log(C.danger('┌─ ERREUR ──────────────────────'));
        stderr.split('\n').slice(0, 50).forEach(l => console.log(C.danger('│ ') + C.muted(l)));
        if (stdout) stdout.split('\n').slice(0, 20).forEach(l => console.log(C.muted('│ ') + l));
        console.log(C.danger('└───────────────────────────────'));

        // Injecter l'erreur aussi (utile pour debug)
        const combined = (stdout + '\n' + stderr).trim();
        const injection = `[ERREUR DE LA COMMANDE: ${command}]\n\`\`\`\n${combined.slice(0, 8000)}\n\`\`\``;
        messages.push({ role: 'user', content: injection });
        messages.push({ role: 'assistant', content: 'Erreur de commande reçue. Prêt à analyser.' });
        printInfo('Erreur injectée dans le contexte. Pose ta question à l\'IA.');
      }
      break;
    }

    // ── SHELL INTERACTIF (sous-process) ───────────────
    case '/shell': {
      printInfo('Lancement du shell interactif. Tape "exit" pour revenir à VOANH.');
      const shell = process.env.SHELL || '/bin/bash';
      // Mettre readline en pause
      rl.pause();
      process.stdin.setRawMode?.(false);
      const result = spawnSync(shell, [], {
        stdio: 'inherit',
        cwd: projectDir || process.cwd(),
        env: { ...process.env, VOANH_SHELL: '1' },
      });
      process.stdin.setRawMode?.(true);
      rl.resume();
      printSuccess('Retour dans VOANH CLI.');
      break;
    }

    // ── AGENTS ────────────────────────────────────────
    case '/agent':
    case '/a': {
      const sub = args[0];

      if (!sub) {
        if (!agents.length) {
          printInfo('Aucun agent créé. Utilise /agent new pour en créer un.');
          break;
        }
        printSection('AGENTS DISPONIBLES');
        agents.forEach((a, i) => {
          const active = activeAgent?.id === a.id ? C.neon(' ← actif') : '';
          console.log(`  ${C.dim(String(i + 1).padStart(2))}  ${C.cyan(a.name.padEnd(20))} ${C.dim((a.desc || '').slice(0, 55))}${active}`);
        });
        console.log();
        printInfo('Usage : /agent <nom>  ou  /agent <numéro>');
        break;
      }

      if (sub === 'new') {
        await createAgentWizard();
        break;
      }

      const byNum = parseInt(sub);
      if (!isNaN(byNum) && byNum >= 1 && byNum <= agents.length) {
        activeAgent = agents[byNum - 1];
        printSuccess(`Agent activé : ${activeAgent.name}`);
        break;
      }

      const found = agents.find(a =>
        a.name.toLowerCase() === sub.toLowerCase() ||
        a.name.toLowerCase().includes(sub.toLowerCase())
      );
      if (found) {
        activeAgent = found;
        printSuccess(`Agent activé : ${activeAgent.name}`);
      } else {
        printError(`Agent introuvable : ${sub}`);
      }
      break;
    }

    case '/noagent':
    case '/na': {
      activeAgent = null;
      printSuccess('Agent désactivé. Mode par défaut.');
      break;
    }

    // ── NOUVELLE CONV ─────────────────────────────────
    case '/new':
    case '/n': {
      messages = [];
      sessionId = null;
      printSuccess('Nouvelle conversation démarrée.');
      break;
    }

    // ── SESSIONS ──────────────────────────────────────
    case '/sessions':
    case '/ls': {
      const sessions = listSessions();
      if (!sessions.length) {
        printInfo('Aucune session sauvegardée.');
        break;
      }
      printSection('SESSIONS SAUVEGARDÉES');
      sessions.slice(0, 20).forEach((s, i) => {
        const date = s.updated ? new Date(s.updated).toLocaleString('fr-FR') : '?';
        const msgCount = (s.messages || []).filter(m => m.role !== 'system').length;
        console.log(
          `  ${C.dim(String(i + 1).padStart(2))}  ` +
          `${C.cyan(s.id.slice(0, 8))}  ` +
          `${C.muted((s.title || '?').slice(0, 45).padEnd(45))}  ` +
          `${C.dim(msgCount + ' msgs')}  ` +
          `${C.dim(date)}`
        );
      });
      console.log();
      printInfo('Usage : /load <id-court>  ou  /load <numéro>');
      break;
    }

    case '/load': {
      const sessions = listSessions();
      const arg = args[0];
      if (!arg) { printInfo('Usage : /load <id> ou /load <numéro>'); break; }

      const byNum = parseInt(arg);
      let session = null;
      if (!isNaN(byNum) && byNum >= 1 && byNum <= sessions.length) {
        session = sessions[byNum - 1];
      } else {
        session = sessions.find(s => s.id.startsWith(arg));
      }

      if (!session) { printError(`Session introuvable : ${arg}`); break; }

      messages   = session.messages || [];
      sessionId  = session.id;
      activeProvider = session.provider || activeProvider;
      activeModel    = session.model    || activeModel;
      if (session.agentId) {
        activeAgent = agents.find(a => a.id === session.agentId) ?? null;
      }
      printSuccess(`Session chargée : "${session.title}" (${messages.filter(m=>m.role!=='system').length} messages)`);
      break;
    }

    case '/delete': {
      const arg = args[0];
      if (!arg) { printInfo('Usage : /delete <id>'); break; }
      const sessions = listSessions();
      const byNum = parseInt(arg);
      let session = null;
      if (!isNaN(byNum) && byNum >= 1 && byNum <= sessions.length) {
        session = sessions[byNum - 1];
      } else {
        session = sessions.find(s => s.id.startsWith(arg));
      }
      if (!session) { printError(`Session introuvable : ${arg}`); break; }
      deleteSession(session.id);
      if (sessionId === session.id) { messages = []; sessionId = null; }
      printSuccess(`Session supprimée : ${session.title}`);
      break;
    }

    // ── MÉMOIRE ───────────────────────────────────────
    case '/mem': {
      const sub = args[0];

      if (sub === 'add') {
        const content = args.slice(1).join(' ');
        if (!content) { printInfo('Usage : /mem add <texte>'); break; }
        addMemory(content);
        printSuccess(`Mémorisé : "${content.slice(0, 60)}"`);
        break;
      }

      if (sub === 'clear') {
        saveMemory([]);
        printSuccess('Mémoire globale effacée.');
        break;
      }

      const memories = loadMemory();
      if (!memories.length) {
        printInfo('Mémoire globale vide. Utilise /mem add <texte>');
        break;
      }
      printSection(`MÉMOIRE GLOBALE (${memories.length} entrées)`);
      memories.slice(-20).reverse().forEach((m, i) => {
        const date = new Date(m.created).toLocaleDateString('fr-FR');
        const tags = m.tags?.length ? C.violet(` [${m.tags.join(',')}]`) : '';
        console.log(`  ${C.dim(String(i+1).padStart(2))}  ${C.muted(m.content.slice(0, 80))}${tags}  ${C.dim(date)}`);
      });
      console.log();
      break;
    }

    // ── CONTEXTE ──────────────────────────────────────
    case '/context':
    case '/ctx': {
      const visible = messages.filter(m => m.role !== 'system');
      if (!visible.length) { printInfo('Aucun message dans cette conversation.'); break; }
      printSection(`CONTEXTE — ${visible.length} messages`);
      visible.forEach((m, i) => {
        const role = m.role === 'user' ? C.cyan('USER') : C.neon('AI  ');
        const preview = m.content.slice(0, 100).replace(/\n/g, ' ');
        console.log(`  ${C.dim(String(i+1).padStart(2))}  ${role}  ${C.dim(preview)}${m.content.length > 100 ? C.dim('…') : ''}`);
      });
      console.log();
      break;
    }

    // ── EXPORT ────────────────────────────────────────
    case '/export': {
      const visible = messages.filter(m => m.role !== 'system');
      if (!visible.length) { printInfo('Aucun message à exporter.'); break; }
      const filename = `voanh-export-${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.md`;
      const filepath = path.join(projectDir || process.cwd(), filename);
      let md = `# VOANH Export — ${new Date().toLocaleString('fr-FR')}\n\n`;
      md += `**Provider:** ${activeProvider} | **Modèle:** ${activeModel}\n\n---\n\n`;
      visible.forEach(m => {
        md += `## ${m.role === 'user' ? '👤 Vous' : '🤖 AI'}\n\n${m.content}\n\n---\n\n`;
      });
      fs.writeFileSync(filepath, md);
      printSuccess(`Exporté : ${filepath}`);
      break;
    }

    // ── TEMPÉRATURE ───────────────────────────────────
    case '/temp': {
      const val = parseFloat(args[0]);
      if (isNaN(val) || val < 0 || val > 2) {
        printInfo('Usage : /temp <0.0-2.0>  Ex : /temp 0.3');
        break;
      }
      if (!activeAgent) {
        cfg.overrideTemp = val;
        saveConfig(cfg);
      } else {
        activeAgent.temperature = val;
      }
      printSuccess(`Température → ${val}`);
      break;
    }

    case '/tokens': {
      const val = parseInt(args[0]);
      if (isNaN(val) || val < 100) {
        printInfo('Usage : /tokens <n>  Ex : /tokens 16384');
        break;
      }
      if (!activeAgent) {
        cfg.overrideMaxTokens = val;
        saveConfig(cfg);
      } else {
        activeAgent.maxTokens = val;
      }
      printSuccess(`max_tokens → ${val}`);
      break;
    }

    // ── CLEAR ─────────────────────────────────────────
    case '/clear':
    case '/cls': {
      console.clear();
      printBanner();
      break;
    }

    // ── STATUS ────────────────────────────────────────
    case '/status':
    case '/s': {
      printSection('STATUS');
      console.log(`  Provider   : ${providerBadge(activeProvider)} ${C.bright(activeProvider)}`);
      console.log(`  Modèle     : ${C.cyan(activeModel)}`);
      console.log(`  Streaming  : ${streamingEnabled ? C.neon('ON') : C.dim('OFF')}`);
      console.log(`  Agent      : ${activeAgent ? C.violet(activeAgent.name) : C.dim('aucun')}`);
      console.log(`  Session    : ${sessionId ? C.dim(sessionId.slice(0,8)) : C.dim('non sauvegardée')}`);
      console.log(`  Messages   : ${C.muted(String(messages.filter(m=>m.role!=='system').length))}`);
      console.log(`  Mémoires   : ${C.muted(String(loadMemory().length))}`);
      console.log(`  Fichiers   : ${loadedFiles.length ? C.gold(String(loadedFiles.length)) : C.dim('0')}`);
      console.log(`  Projet     : ${projectDir ? C.violet(projectDir) : C.dim('aucun')}`);
      console.log(`  Config dir : ${C.dim(CONFIG_DIR)}`);
      const keyStatus = Object.keys(PROVIDERS).map(p =>
        `${p}: ${cfg.keys?.[p] ? C.neon('✓') : C.danger('✗')}`
      ).join('  ');
      console.log(`  Clés API   : ${keyStatus}`);
      console.log();
      break;
    }

    // ── SETUP WIZARD ──────────────────────────────────
    case '/setup': {
      await setupWizard();
      break;
    }

    // ── QUIT ──────────────────────────────────────────
    case '/exit':
    case '/quit':
    case '/q': {
      console.log();
      console.log(C.cyan('  Au revoir. Données sauvegardées dans ~/.voanh/'));
      console.log();
      rl.close();
      process.exit(0);
    }

    default: {
      printError(`Commande inconnue : ${cmd}. Tape /help pour l'aide.`);
    }
  }
}

// ══════════════════════════════════════════════════════
// WIZARD SETUP
// ══════════════════════════════════════════════════════
async function setupWizard() {
  const ask = (q) => new Promise(resolve => rl.question(C.cyan('  ? ') + C.bright(q) + ' ', resolve));

  console.clear();
  printBanner();
  printSection('WIZARD DE CONFIGURATION');
  console.log(C.muted('  Configure tes clés API. Appuie sur Entrée pour passer.\n'));

  const mistralKey = await ask('Clé API Mistral (console.mistral.ai) :');
  if (mistralKey.trim()) { if (!cfg.keys) cfg.keys = {}; cfg.keys.mistral = mistralKey.trim(); }

  const groqKey = await ask('Clé API Groq (console.groq.com) :');
  if (groqKey.trim()) { if (!cfg.keys) cfg.keys = {}; cfg.keys.groq = groqKey.trim(); }

  const orKey = await ask('Clé API OpenRouter (openrouter.ai/keys) :');
  if (orKey.trim()) { if (!cfg.keys) cfg.keys = {}; cfg.keys.openrouter = orKey.trim(); }

  const defProvider = await ask('Provider par défaut (mistral/groq/openrouter) [mistral] :');
  cfg.defaultProvider = defProvider.trim() || 'mistral';
  activeProvider = cfg.defaultProvider;

  const defModel = await ask('Modèle par défaut [codestral-2508] :');
  cfg.defaultModel = defModel.trim() || 'codestral-2508';
  activeModel = cfg.defaultModel;

  saveConfig(cfg);
  printSuccess('Configuration sauvegardée dans ~/.voanh/config.json');
  console.log();
}

// ══════════════════════════════════════════════════════
// WIZARD CRÉATION AGENT
// ══════════════════════════════════════════════════════
async function createAgentWizard() {
  const ask = (q, def = '') => new Promise(resolve => {
    const hint = def ? C.dim(` [${def}]`) : '';
    rl.question(C.cyan('  > ') + C.bright(q) + hint + ' ', ans => {
      resolve(ans.trim() || def);
    });
  });

  printSection('CRÉER UN AGENT');

  const name         = await ask('Nom de l\'agent :');
  if (!name) { printError('Nom requis.'); return; }

  const desc         = await ask('Description courte :');
  const instructions = await ask('Instructions système (optionnel) :');
  const style        = await ask('Style (dev/concis/detaille/formel/creatif/pedagogique) :', 'dev');
  const modelPref    = await ask(`Modèle préféré [${activeModel}] :`, activeModel);
  const tempStr      = await ask('Température (0.0-1.0) :', '0.3');
  const tokensStr    = await ask('Max tokens :', '32768');
  const forbidden    = await ask('Instructions interdites (optionnel) :');
  const autoMemory   = await ask('Auto-mémorisation (y/n) :', 'n');

  const agent = {
    id:          crypto.randomUUID(),
    name,
    desc,
    instructions,
    style,
    modelPref:   modelPref || activeModel,
    temperature: parseFloat(tempStr) || 0.3,
    maxTokens:   parseInt(tokensStr)  || 32768,
    forbidden,
    autoMemory:  autoMemory === 'y' || autoMemory === 'yes',
    created:     Date.now(),
  };

  agents.push(agent);
  saveAgents(agents);
  activeAgent = agent;

  printSuccess(`Agent "${name}" créé et activé !`);
}

// ══════════════════════════════════════════════════════
// MULTI-LIGNE (\\ ... \\end)
// ══════════════════════════════════════════════════════
function startMultiline() {
  inMultiline = true;
  multilineBuffer = [];
  printInfo('Mode multi-ligne activé. Tape \\\\end sur une ligne seule pour envoyer.');
}

async function finishMultiline() {
  inMultiline = false;
  const fullText = multilineBuffer.join('\n');
  multilineBuffer = [];
  if (fullText.trim()) {
    await sendMessage(fullText);
  }
}


// ══════════════════════════════════════════════════════
// WIZARD CRÉATION TÂCHE AUTONOME
// ══════════════════════════════════════════════════════
async function createTaskWizard() {
  const ask = (q, def = '') => new Promise(resolve => {
    const hint = def ? C.dim(` [${def}]`) : '';
    rl.question(C.cyan('  > ') + C.bright(q) + hint + ' ', ans => {
      resolve(ans.trim() || def);
    });
  });

  printSection('CRÉER UNE TÂCHE AUTONOME');
  printInfo('La tâche sera exécutée par le daemon même quand tu es déconnecté.');
  console.log();

  const title        = await ask('Titre de la tâche :');
  if (!title) { printError('Titre requis.'); return; }

  const prompt       = await ask('Prompt / instruction pour l\'IA :');
  if (!prompt) { printError('Prompt requis.'); return; }

  const instructions = await ask('Instructions système supplémentaires (optionnel) :');
  const shellCmd     = await ask('Commande shell à exécuter avant (optionnel) :');
  const writeToFile  = await ask('Écrire le résultat dans un fichier (optionnel) :');
  const repeatStr    = await ask('Tâche répétitive ? (y/n) :', 'n');
  let intervalMs     = 0;
  if (repeatStr === 'y' || repeatStr === 'yes') {
    const intervalStr = await ask('Intervalle (ex: 1h, 30m, 24h) :', '1h');
    const match = intervalStr.match(/(\d+)(h|m|s)/);
    if (match) {
      const val  = parseInt(match[1]);
      const unit = match[2];
      intervalMs = unit === 'h' ? val * 3600000
                 : unit === 'm' ? val * 60000
                 : val * 1000;
    }
  }
  const runAtStr = await ask('Planifier l\'exécution ? (ex: dans 2h, maintenant) :', 'maintenant');
  let runAt = Date.now();
  if (runAtStr !== 'maintenant') {
    const m = runAtStr.match(/(\d+)(h|m|s)/);
    if (m) {
      const val  = parseInt(m[1]);
      const unit = m[2];
      const delay = unit === 'h' ? val * 3600000 : unit === 'm' ? val * 60000 : val * 1000;
      runAt = Date.now() + delay;
    }
  }

  const providerStr = await ask(`Provider (mistral/groq/openrouter) :`, activeProvider);
  const modelStr    = await ask(`Modèle :`, activeModel);
  const autoMem     = await ask('Auto-mémorisation des résultats (y/n) :', 'n');

  const task = {
    id:           crypto.randomUUID(),
    title,
    prompt,
    instructions,
    shellCmd:     shellCmd || null,
    writeToFile:  writeToFile || null,
    provider:     providerStr || activeProvider,
    model:        modelStr    || activeModel,
    maxTokens:    8192,
    repeat:       repeatStr === 'y' || repeatStr === 'yes',
    intervalMs:   intervalMs || null,
    runAt,
    autoMemory:   autoMem === 'y',
    status:       'pending',
    createdAt:    Date.now(),
    lastRunAt:    null,
    lastResult:   null,
    lastError:    null,
    runCount:     0,
  };

  saveTask(task);

  const runAtDate = new Date(runAt).toLocaleString('fr-FR');
  printSuccess(`Tâche créée : "${title}" (ID: ${task.id.slice(0,8)})`);
  printInfo(`Planifiée pour : ${runAtDate}`);
  if (task.repeat) printInfo(`Répétition toutes les ${task.intervalMs/60000} min`);
  console.log();
  printInfo('Lance le daemon pour l\'exécuter automatiquement :');
  console.log(C.cyan('  nohup node daemon.js > ~/.voanh/daemon.log 2>&1 &'));
  printInfo('Ou exécute-la maintenant avec : /task result après avoir lancé le daemon.');
}

// ══════════════════════════════════════════════════════
// BOUCLE PRINCIPALE
// ══════════════════════════════════════════════════════
async function main() {
  const argv = process.argv.slice(2);

  if (argv.includes('--setup')) {
    await setupWizard();
    rl.close();
    process.exit(0);
  }

  const sessIdx = argv.indexOf('--session');
  if (sessIdx !== -1 && argv[sessIdx + 1]) {
    const s = loadSession(argv[sessIdx + 1]);
    if (s) {
      messages   = s.messages || [];
      sessionId  = s.id;
      activeProvider = s.provider || activeProvider;
      activeModel    = s.model    || activeModel;
    }
  }

  // Charger un fichier/projet depuis les args
  const fileIdx = argv.indexOf('--file');
  if (fileIdx !== -1 && argv[fileIdx + 1]) {
    const f = readFileForContext(argv[fileIdx + 1]);
    if (f) { loadedFiles.push(f); }
  }

  const projIdx = argv.indexOf('--project');
  if (projIdx !== -1 && argv[projIdx + 1]) {
    const files = readDirForContext(argv[projIdx + 1], 4);
    if (files.length) { loadedFiles = files; projectDir = path.resolve(argv[projIdx + 1]); }
  }

  cfg = loadConfig();
  agents = loadAgents();
  activeProvider = cfg.defaultProvider || 'mistral';
  activeModel    = cfg.defaultModel    || 'codestral-2508';

  const hasAnyKey = Object.keys(PROVIDERS).some(p => cfg.keys?.[p]);
  if (!hasAnyKey) {
    console.clear();
    printBanner();
    console.log(C.gold('  ⚠  Aucune clé API configurée. Lancement du wizard...\n'));
    await setupWizard();
    cfg = loadConfig();
  } else {
    console.clear();
    printBanner();
  }

  // Status initial
  const streamTag = streamingEnabled ? C.neon('~stream') : C.dim('no-stream');
  console.log(
    `  ${providerBadge(activeProvider)} ` +
    C.dim(activeModel) +
    `  ${streamTag}` +
    (activeAgent ? C.violet(`  [${activeAgent.name}]`) : '') +
    (loadedFiles.length ? C.gold(`  [${loadedFiles.length} fichiers]`) : '') +
    C.dim('  — /help pour l\'aide')
  );
  console.log();
  console.log(C.dim('  Astuce : tape \\\\ pour mode multi-ligne | /file <path> pour charger un fichier'));
  console.log(C.dim('  Nouveauté v2 : /project /run /diff /patch /write /shell /stream'));
  console.log(C.dim('  Ctrl+C ou /quit pour quitter.'));
  console.log();

  // Événements readline
  rl.on('line', async (input) => {
    const line = input;

    if (inMultiline) {
      if (line.trim() === '\\\\end' || line.trim() === '\\end') {
        await finishMultiline();
      } else {
        multilineBuffer.push(line);
        process.stdout.write(C.dim('... '));
      }
      return;
    }

    if (line.trim() === '\\\\' || line.trim() === '\\') {
      startMultiline();
      return;
    }

    if (!line.trim()) {
      prompt();
      return;
    }

    if (line.trim().startsWith('/')) {
      await handleCommand(line.trim());
      prompt();
      return;
    }

    await sendMessage(line);
    prompt();
  });

  rl.on('close', () => {
    console.log('\n' + C.cyan('  Bye.'));
    process.exit(0);
  });

  prompt();
}

main().catch(err => {
  console.error(C.danger('\n  FATAL: ') + err.message);
  console.error(err.stack);
  process.exit(1);
});
