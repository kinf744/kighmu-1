// ═══════════════════════════════════════════════════════
//  CONFIG v3 — Lecture/écriture ~/.voanh/
//  v3 : limite 50 Mo, troncature intelligente,
//       mémoire projets, tâches agents autonomes
// ═══════════════════════════════════════════════════════

import fs   from 'fs';
import path from 'path';
import os   from 'os';

export const CONFIG_DIR  = path.join(os.homedir(), '.voanh');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const AGENTS_FILE = path.join(CONFIG_DIR, 'agents.json');
const MEMORY_FILE = path.join(CONFIG_DIR, 'memory.json');
const HISTORY_DIR = path.join(CONFIG_DIR, 'history');
export const TASKS_DIR   = path.join(CONFIG_DIR, 'tasks');
export const PROJECT_MEM_FILE = path.join(CONFIG_DIR, 'projects.json');

// ── INIT ──────────────────────────────────────────────────
export function ensureConfigDir() {
  for (const d of [CONFIG_DIR, HISTORY_DIR, TASKS_DIR]) {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  }
}

// ── CONFIG ────────────────────────────────────────────────
export function loadConfig() {
  ensureConfigDir();
  if (!fs.existsSync(CONFIG_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); }
  catch { return {}; }
}
export function saveConfig(cfg) {
  ensureConfigDir();
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
}

// ── AGENTS ────────────────────────────────────────────────
export function loadAgents() {
  ensureConfigDir();
  if (!fs.existsSync(AGENTS_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(AGENTS_FILE, 'utf8')); }
  catch { return []; }
}
export function saveAgents(agents) {
  ensureConfigDir();
  fs.writeFileSync(AGENTS_FILE, JSON.stringify(agents, null, 2));
}

// ── MÉMOIRE GLOBALE ───────────────────────────────────────
export function loadMemory() {
  ensureConfigDir();
  if (!fs.existsSync(MEMORY_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(MEMORY_FILE, 'utf8')); }
  catch { return []; }
}
export function saveMemory(memories) {
  ensureConfigDir();
  fs.writeFileSync(MEMORY_FILE, JSON.stringify(memories, null, 2));
}
export function addMemory(content, tags = []) {
  const memories = loadMemory();
  const entry = {
    id: crypto.randomUUID(),
    content,
    tags: Array.isArray(tags) ? tags : [],
    created: Date.now(),
  };
  memories.push(entry);
  saveMemory(memories);
  return entry;
}
export function getRelevantMemories(query, limit = 5) {
  const memories = loadMemory();
  if (!memories.length) return [];
  const q = query.toLowerCase();
  return memories
    .map(m => ({
      ...m,
      score: (m.content.toLowerCase().includes(q) ? 2 : 0)
           + ((m.tags || []).some(t => q.includes(t.toLowerCase())) ? 1 : 0)
    }))
    .filter(m => m.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map(m => `[MEM${m.tags?.length ? ':' + m.tags.join(',') : ''}] ${m.content}`);
}

// ── MÉMOIRE PROJETS (reprendre après SSH coupée) ──────────
export function loadProjectMemory() {
  if (!fs.existsSync(PROJECT_MEM_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(PROJECT_MEM_FILE, 'utf8')); }
  catch { return {}; }
}
export function saveProjectMemory(projects) {
  ensureConfigDir();
  fs.writeFileSync(PROJECT_MEM_FILE, JSON.stringify(projects, null, 2));
}
export function saveProjectSnapshot(dirPath, data) {
  const projects = loadProjectMemory();
  const key = path.resolve(dirPath);
  projects[key] = {
    ...data,
    dir: key,
    savedAt: Date.now(),
  };
  saveProjectMemory(projects);
}
export function loadProjectSnapshot(dirPath) {
  const projects = loadProjectMemory();
  return projects[path.resolve(dirPath)] ?? null;
}
export function listProjectSnapshots() {
  const projects = loadProjectMemory();
  return Object.values(projects).sort((a, b) => (b.savedAt || 0) - (a.savedAt || 0));
}

// ── TÂCHES AGENTS AUTONOMES ───────────────────────────────
export function listTasks() {
  ensureConfigDir();
  try {
    return fs.readdirSync(TASKS_DIR)
      .filter(f => f.endsWith('.json'))
      .map(f => {
        try { return JSON.parse(fs.readFileSync(path.join(TASKS_DIR, f), 'utf8')); }
        catch { return null; }
      })
      .filter(Boolean)
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  } catch { return []; }
}
export function saveTask(task) {
  ensureConfigDir();
  fs.writeFileSync(
    path.join(TASKS_DIR, `${task.id}.json`),
    JSON.stringify(task, null, 2)
  );
}
export function loadTask(id) {
  const f = path.join(TASKS_DIR, `${id}.json`);
  if (!fs.existsSync(f)) return null;
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); }
  catch { return null; }
}
export function deleteTask(id) {
  const f = path.join(TASKS_DIR, `${id}.json`);
  if (fs.existsSync(f)) fs.unlinkSync(f);
}

// ── HISTORIQUE CONVERSATIONS ──────────────────────────────
export function listSessions() {
  ensureConfigDir();
  try {
    return fs.readdirSync(HISTORY_DIR)
      .filter(f => f.endsWith('.json'))
      .map(f => {
        const filePath = path.join(HISTORY_DIR, f);
        try {
          const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
          return { id: f.replace('.json', ''), ...data };
        } catch { return null; }
      })
      .filter(Boolean)
      .sort((a, b) => (b.updated || 0) - (a.updated || 0));
  } catch { return []; }
}
export function loadSession(id) {
  const filePath = path.join(HISTORY_DIR, `${id}.json`);
  if (!fs.existsSync(filePath)) return null;
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch { return null; }
}
export function saveSession(id, data) {
  ensureConfigDir();
  fs.writeFileSync(path.join(HISTORY_DIR, `${id}.json`), JSON.stringify(data, null, 2));
}
export function deleteSession(id) {
  const filePath = path.join(HISTORY_DIR, `${id}.json`);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
}

// ── EXTENSIONS TEXTE ──────────────────────────────────────
const TEXT_EXTENSIONS = new Set([
  '.js','.jsx','.ts','.tsx','.mjs','.cjs',
  '.py','.rb','.php','.java','.kt','.kts','.scala',
  '.swift','.m','.mm',
  '.dart',
  '.go','.rs','.c','.cpp','.h','.hpp','.cs',
  '.html','.css','.scss','.sass','.less',
  '.json','.yaml','.yml','.toml','.xml','.env','.ini','.cfg',
  '.sh','.bash','.zsh','.fish','.ps1',
  '.sql','.graphql','.gql',
  '.md','.mdx','.txt','.log','.csv',
  '.gradle','.kts','.podspec','.xcconfig',
  'Dockerfile','.dockerignore','.gitignore','.eslintrc',
  'Makefile','CMakeLists.txt','pubspec.yaml',
]);

// 50 Mo par fichier (au lieu de 500 Ko)
const MAX_FILE_SIZE   = 50  * 1024 * 1024;
// 10 Mo total contexte fichiers
const MAX_TOTAL_SIZE  = 10  * 1024 * 1024;

// Seuil à partir duquel on tronque intelligemment (1 Mo)
const SMART_TRUNC_THRESHOLD = 1 * 1024 * 1024;

/**
 * Troncature intelligente :
 * - Garde les N premières lignes (en-tête, imports, déclarations)
 * - Garde les N dernières lignes (code récent, fin de fichier)
 * - Garde un extrait du milieu
 * - Résume la structure (fonctions/classes détectées)
 */
function smartTruncate(content, filePath, originalSize) {
  const lines = content.split('\n');
  const total = lines.length;
  const ext = path.extname(filePath).toLowerCase();

  // Détection des symboles (fonctions/classes) pour le résumé
  const symbols = [];
  const symPatterns = [
    /^(?:export\s+)?(?:async\s+)?function\s+(\w+)/,         // JS/TS function
    /^(?:export\s+)?(?:default\s+)?class\s+(\w+)/,          // JS/TS class
    /^(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(/,     // JS arrow fn
    /^def\s+(\w+)/,                                           // Python
    /^class\s+(\w+)/,                                         // Python/Java
    /^(?:public|private|protected|static).*\s+(\w+)\s*\(/,  // Java/Kotlin
    /^fun\s+(\w+)/,                                           // Kotlin
    /^func\s+(\w+)/,                                          // Swift/Go
  ];
  lines.forEach((l, i) => {
    const trimmed = l.trim();
    for (const pat of symPatterns) {
      const m = trimmed.match(pat);
      if (m) { symbols.push(`  L${i+1}: ${trimmed.slice(0, 80)}`); break; }
    }
  });

  // Répartition : 300 lignes début, 200 lignes fin, 100 lignes milieu
  const HEAD_LINES = 300;
  const TAIL_LINES = 200;
  const MID_LINES  = 100;

  const head = lines.slice(0, HEAD_LINES);
  const tail = lines.slice(-TAIL_LINES);
  const midStart = Math.floor(total / 2) - Math.floor(MID_LINES / 2);
  const mid  = lines.slice(midStart, midStart + MID_LINES);

  const skippedHead = total - HEAD_LINES - TAIL_LINES;
  const skippedMid  = Math.floor(total / 2) - HEAD_LINES - Math.floor(MID_LINES / 2);

  const banner = (msg) => `\n${'─'.repeat(60)}\n${msg}\n${'─'.repeat(60)}\n`;

  let result = '';
  result += `[TRONCATURE INTELLIGENTE — ${(originalSize/1024/1024).toFixed(2)} Mo, ${total} lignes]\n`;

  if (symbols.length) {
    result += `[SYMBOLES DÉTECTÉS (${symbols.length})]\n${symbols.slice(0, 40).join('\n')}\n`;
    if (symbols.length > 40) result += `  … +${symbols.length - 40} autres\n`;
  }

  result += banner(`◀ DÉBUT (lignes 1–${HEAD_LINES})`);
  result += head.join('\n');

  if (skippedMid > 0) {
    result += banner(`⋯ MILIEU (lignes ${midStart+1}–${midStart+MID_LINES}, ${skippedMid} lignes omises avant)`);
    result += mid.join('\n');
  }

  result += banner(`▶ FIN (lignes ${total - TAIL_LINES + 1}–${total})`);
  result += tail.join('\n');

  return result;
}

/**
 * Lit un fichier texte et retourne son contenu avec métadonnées.
 * Limite 50 Mo, troncature intelligente au-delà de 1 Mo.
 */
export function readFileForContext(filePath) {
  try {
    const abs = path.resolve(filePath);
    if (!fs.existsSync(abs)) return null;
    const stat = fs.statSync(abs);
    if (!stat.isFile()) return null;

    // Refus au-delà de 50 Mo
    if (stat.size > MAX_FILE_SIZE) {
      return {
        path: abs,
        content: `[FICHIER TROP GRAND: ${(stat.size / 1024 / 1024).toFixed(1)} Mo — max 50 Mo]`,
        size: stat.size,
        ext: path.extname(abs) || path.basename(abs),
        truncated: true,
        tooLarge: true,
      };
    }

    const raw = fs.readFileSync(abs, 'utf8');

    // Troncature intelligente au-delà de 1 Mo
    if (stat.size > SMART_TRUNC_THRESHOLD) {
      return {
        path: abs,
        content: smartTruncate(raw, abs, stat.size),
        size: stat.size,
        ext: path.extname(abs) || path.basename(abs),
        truncated: true,
        tooLarge: false,
      };
    }

    return {
      path: abs,
      content: raw,
      size: stat.size,
      ext: path.extname(abs) || path.basename(abs),
      truncated: false,
    };
  } catch (err) {
    return null;
  }
}

/**
 * Charge tous les fichiers d'un répertoire (récursif, filtré).
 */
export function readDirForContext(dirPath, depth = 3) {
  const results = [];
  let totalSize = 0;

  function walk(dir, currentDepth) {
    if (currentDepth > depth) return;
    let entries;
    try { entries = fs.readdirSync(dir); } catch { return; }
    for (const entry of entries) {
      if (entry.startsWith('.') || entry === 'node_modules' || entry === '__pycache__' ||
          entry === '.git' || entry === 'dist' || entry === 'build' || entry === '.dart_tool' ||
          entry === 'ios/Pods' || entry === '.gradle' || entry === '.idea') continue;
      const fullPath = path.join(dir, entry);
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        walk(fullPath, currentDepth + 1);
      } else if (stat.isFile()) {
        const ext = path.extname(entry) || entry;
        if (TEXT_EXTENSIONS.has(ext) || TEXT_EXTENSIONS.has(entry)) {
          if (totalSize + stat.size > MAX_TOTAL_SIZE) continue;
          const file = readFileForContext(fullPath);
          if (file) {
            results.push(file);
            totalSize += file.size;
          }
        }
      }
    }
  }

  walk(path.resolve(dirPath), 0);
  return results;
}

/**
 * Formate les fichiers chargés en texte pour le contexte système.
 */
export function formatFilesForContext(files) {
  if (!files.length) return '';
  const lines = ['[FICHIERS DU PROJET]'];
  for (const f of files) {
    const ext = f.ext.replace('.', '') || 'txt';
    const tag = f.truncated ? (f.tooLarge ? ' ⛔ TROP GRAND' : ' ✂ tronqué') : '';
    lines.push(`\n### ${f.path}${tag}\n\`\`\`${ext}\n${f.content}\n\`\`\``);
  }
  return lines.join('\n');
}

export { CONFIG_FILE, AGENTS_FILE, MEMORY_FILE, HISTORY_DIR };
