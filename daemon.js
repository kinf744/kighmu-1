#!/usr/bin/env node
// ═══════════════════════════════════════════════════════
//  VOANH DAEMON — Agent autonome
//  Usage : node daemon.js
//  Lance les tâches planifiées même quand la session SSH
//  est fermée (utiliser avec : nohup node daemon.js &
//  ou via systemd/pm2)
// ═══════════════════════════════════════════════════════

import fs   from 'fs';
import path from 'path';
import os   from 'os';
import { execSync } from 'child_process';
import {
  loadConfig, loadAgents, loadTask, saveTask, listTasks, TASKS_DIR,
  addMemory, readFileForContext,
} from './config.js';
import { PROVIDERS } from './providers.js';

const LOG_FILE = path.join(os.homedir(), '.voanh', 'daemon.log');

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
  fs.appendFileSync(LOG_FILE, line + '\n');
}

async function callAI(provider, model, apiKey, messages, maxTokens = 8192) {
  const p = PROVIDERS[provider];
  if (!p) throw new Error(`Provider inconnu: ${provider}`);
  // mode non-streaming pour le daemon
  const result = await p.send(apiKey, model, messages, {
    temperature: 0.3,
    maxTokens,
  });
  return result.content;
}

function shouldRun(task) {
  if (task.status === 'running') return false;
  if (task.status === 'done' && !task.repeat) return false;
  if (task.status === 'cancelled') return false;

  const now = Date.now();

  // Tâche planifiée (runAt)
  if (task.runAt && now < task.runAt) return false;

  // Tâche répétitive (intervalMs)
  if (task.repeat && task.intervalMs) {
    const lastRun = task.lastRunAt || 0;
    if (now - lastRun < task.intervalMs) return false;
  }

  return true;
}

async function runTask(task) {
  const cfg = loadConfig();
  const provider = task.provider || cfg.defaultProvider || 'mistral';
  const model    = task.model    || cfg.defaultModel    || 'codestral-2508';
  const apiKey   = cfg.keys?.[provider];

  if (!apiKey) {
    task.status = 'error';
    task.lastError = `Aucune clé API pour ${provider}`;
    saveTask(task);
    log(`[TASK ${task.id.slice(0,8)}] ERREUR: ${task.lastError}`);
    return;
  }

  log(`[TASK ${task.id.slice(0,8)}] Démarrage: "${task.title}"`);
  task.status = 'running';
  task.lastRunAt = Date.now();
  saveTask(task);

  try {
    // Construction du contexte
    let contextContent = '';

    // Fichiers à analyser
    if (task.files?.length) {
      for (const fp of task.files) {
        const f = readFileForContext(fp);
        if (f) contextContent += `\n\n### ${f.path}\n\`\`\`\n${f.content}\n\`\`\``;
      }
    }

    // Commande shell à exécuter avant
    let shellOutput = '';
    if (task.shellCmd) {
      try {
        shellOutput = execSync(task.shellCmd, {
          encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024,
        });
        log(`[TASK ${task.id.slice(0,8)}] Shell OK: ${task.shellCmd}`);
      } catch (e) {
        shellOutput = `ERREUR: ${e.message}`;
      }
      contextContent += `\n\n### Résultat commande: ${task.shellCmd}\n\`\`\`\n${shellOutput.slice(0, 8000)}\n\`\`\``;
    }

    const messages = [
      {
        role: 'system',
        content: `Tu es VOANH Agent, un assistant autonome qui exécute des tâches de développement.
Réponds de façon concise, structurée. Donne du code complet si demandé.
Tâche assignée : ${task.title}
Instructions : ${task.instructions || 'Aucune instruction spéciale.'}`,
      },
      {
        role: 'user',
        content: task.prompt + (contextContent ? '\n\nContexte:\n' + contextContent : ''),
      },
    ];

    const reply = await callAI(provider, model, apiKey, messages, task.maxTokens || 8192);

    // Écriture du résultat
    const resultDir  = path.join(TASKS_DIR, 'results');
    if (!fs.existsSync(resultDir)) fs.mkdirSync(resultDir, { recursive: true });
    const resultFile = path.join(resultDir, `${task.id}.md`);
    const resultMd = `# Tâche: ${task.title}\n` +
      `**Date:** ${new Date().toLocaleString('fr-FR')}\n` +
      `**Provider:** ${provider} / ${model}\n\n---\n\n${reply}`;
    fs.writeFileSync(resultFile, resultMd, 'utf8');

    // Auto-mémorisation si activé
    if (task.autoMemory) {
      const match = reply.match(/(?:MÉMO|RETIENS|REMEMBER)[:\s]+(.+?)(?:\n|$)/i);
      if (match) addMemory(match[1].trim(), ['agent', task.id.slice(0,8)]);
    }

    // Écriture automatique dans un fichier cible
    if (task.writeToFile) {
      const codeMatch = reply.match(/```[\w]*\n([\s\S]*?)```/);
      if (codeMatch) {
        const targetDir = path.dirname(path.resolve(task.writeToFile));
        if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });
        if (fs.existsSync(task.writeToFile)) {
          fs.copyFileSync(task.writeToFile, task.writeToFile + '.bak');
        }
        fs.writeFileSync(task.writeToFile, codeMatch[1], 'utf8');
        log(`[TASK ${task.id.slice(0,8)}] Écrit dans: ${task.writeToFile}`);
      }
    }

    task.status = task.repeat ? 'pending' : 'done';
    task.lastResult = resultFile;
    task.lastRunAt  = Date.now();
    task.runCount   = (task.runCount || 0) + 1;
    task.lastError  = null;
    saveTask(task);

    log(`[TASK ${task.id.slice(0,8)}] Terminé → ${resultFile}`);

  } catch (err) {
    task.status = 'error';
    task.lastError = err.message;
    saveTask(task);
    log(`[TASK ${task.id.slice(0,8)}] ERREUR: ${err.message}`);
  }
}

async function daemonLoop() {
  log('=== VOANH DAEMON démarré ===');
  log(`PID: ${process.pid} | Tasks dir: ${TASKS_DIR}`);

  // Écrire le PID pour pouvoir arrêter le daemon
  const pidFile = path.join(os.homedir(), '.voanh', 'daemon.pid');
  fs.writeFileSync(pidFile, String(process.pid));

  process.on('SIGTERM', () => {
    log('SIGTERM reçu, arrêt propre.');
    if (fs.existsSync(pidFile)) fs.unlinkSync(pidFile);
    process.exit(0);
  });
  process.on('SIGINT', () => {
    log('SIGINT reçu, arrêt.');
    if (fs.existsSync(pidFile)) fs.unlinkSync(pidFile);
    process.exit(0);
  });

  // Boucle toutes les 60 secondes
  const INTERVAL = 60 * 1000;
  while (true) {
    const tasks = listTasks();
    const pending = tasks.filter(shouldRun);
    if (pending.length) {
      log(`${pending.length} tâche(s) à exécuter.`);
      // Exécution séquentielle pour éviter les conflits
      for (const task of pending) {
        await runTask(task);
      }
    }
    await new Promise(r => setTimeout(r, INTERVAL));
  }
}

daemonLoop().catch(err => {
  log(`FATAL: ${err.message}`);
  process.exit(1);
});
