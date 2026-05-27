// ═══════════════════════════════════════════════════════
//  RENDER v2 — Affichage terminal : markdown, code, couleurs
//  Nouveauté v2 : streaming display, diff coloré
// ═══════════════════════════════════════════════════════

import chalk from 'chalk';

// ── PALETTE CYBER ─────────────────────────────────────────
export const C = {
  cyan:     (s) => chalk.hex('#00e5ff')(s),
  neon:     (s) => chalk.hex('#00ff9d')(s),
  plasma:   (s) => chalk.hex('#ff6b35')(s),
  violet:   (s) => chalk.hex('#a78bfa')(s),
  gold:     (s) => chalk.hex('#f59e0b')(s),
  dim:      (s) => chalk.hex('#4a6b8a')(s),
  muted:    (s) => chalk.hex('#8badc4')(s),
  bright:   (s) => chalk.hex('#e8f4ff')(s),
  danger:   (s) => chalk.hex('#ff3366')(s),
  code:     (s) => chalk.hex('#00e5ff').bgHex('#091525')(s),
  bold:     (s) => chalk.bold(s),
  italic:   (s) => chalk.italic(s),
  // diff
  added:    (s) => chalk.hex('#00ff9d')(s),
  removed:  (s) => chalk.hex('#ff3366')(s),
  diffhdr:  (s) => chalk.hex('#f59e0b').bold(s),
};

// ── LARGEUR TERMINAL ──────────────────────────────────────
export const termWidth = () => Math.min(process.stdout.columns || 100, 120);

export const hr = (char = '─', color = C.dim) =>
  color(char.repeat(termWidth()));

export const hrCyan = () => C.cyan('═'.repeat(termWidth()));

// ── HEADER BANNER ─────────────────────────────────────────
export function printBanner() {
  console.log();
  console.log(hrCyan());
  console.log(C.cyan('  VOANH CLI v2 — Multi-Provider AI Terminal'));
  console.log(C.dim('  Mistral · Groq · OpenRouter  |  Streaming · Files · Shell · Diff · Multi-files'));
  console.log(hrCyan());
  console.log();
}

// ── LABEL BADGES ─────────────────────────────────────────
export function providerBadge(provider) {
  const map = {
    mistral:    chalk.bgHex('#ff7043').hex('#000')(' MISTRAL '),
    groq:       chalk.bgHex('#00ff9d').hex('#000')(' GROQ '),
    openrouter: chalk.bgHex('#a78bfa').hex('#000')(' OR '),
  };
  return map[provider] ?? chalk.bgGray(' ? ');
}

export function modelLabel(provider, model) {
  return `${providerBadge(provider)} ${C.muted(model)}`;
}

// ── STRIP ANSI (pour calcul longueur visible) ─────────────
export function stripAnsi(str) {
  return str.replace(/\u001b\[[0-9;]*m/g, '');
}

// ═══════════════════════════════════════════════════════
// STREAMING DISPLAY
// Affiche les tokens au fur et à mesure, avec rendu live
// des blocs de code détectés en fin de stream.
// ═══════════════════════════════════════════════════════

/**
 * StreamRenderer : collecte le texte streamé et affiche
 * les lignes complètes au fil de l'eau, avec coloration.
 */
export class StreamRenderer {
  constructor() {
    this.buffer = '';        // texte reçu mais pas encore affiché
    this.displayed = '';     // texte déjà rendu
    this.inCodeBlock = false;
    this.codeLang = '';
    this.codeLines = [];
    this.lineBuffer = '';
  }

  /**
   * Reçoit un delta de texte et affiche les lignes complètes.
   */
  push(delta) {
    this.buffer += delta;

    // Traiter toutes les lignes complètes dans le buffer
    const lines = this.buffer.split('\n');
    // Garder la dernière partie incomplète dans le buffer
    this.buffer = lines.pop();

    for (const line of lines) {
      this._renderLine(line + '\n');
    }
  }

  /**
   * Flush le buffer restant à la fin du stream.
   */
  flush() {
    if (this.buffer) {
      this._renderLine(this.buffer);
      this.buffer = '';
    }
    // Fermer un bloc de code non fermé
    if (this.inCodeBlock && this.codeLines.length) {
      const rendered = renderCodeBlock(this.codeLines, this.codeLang);
      process.stdout.write('\r' + rendered + '\n');
      this.codeLines = [];
      this.inCodeBlock = false;
    }
  }

  _renderLine(line) {
    const raw = line.endsWith('\n') ? line.slice(0, -1) : line;
    const hasNewline = line.endsWith('\n');

    // Détection ouverture/fermeture bloc de code
    const codeMatch = raw.match(/^```(\w*)/);
    if (codeMatch) {
      if (!this.inCodeBlock) {
        this.inCodeBlock = true;
        this.codeLang = codeMatch[1] || '';
        this.codeLines = [];
        // Afficher le header du bloc
        const w = termWidth();
        const langLabel = this.codeLang ? C.dim(` ${this.codeLang.toUpperCase()} `) : '';
        const header = chalk.hex('#1a3455')('┌' + '─'.repeat(w - 2) + '┐') + '\n' +
          chalk.hex('#1a3455')('│') + chalk.bgHex('#091525').hex('#4a6b8a')(` CODE ${langLabel}`.padEnd(w - 2)) + chalk.hex('#1a3455')('│');
        process.stdout.write(header + '\n');
        return;
      } else {
        // Fermeture du bloc
        this.inCodeBlock = false;
        const w = termWidth();
        const botBorder = chalk.hex('#1a3455')('└' + '─'.repeat(w - 2) + '┘');
        process.stdout.write(botBorder + '\n');
        this.codeLines = [];
        this.codeLang = '';
        return;
      }
    }

    if (this.inCodeBlock) {
      // Afficher les lignes de code avec highlighting
      this.codeLines.push(raw);
      const w = termWidth();
      const colored = highlightCode(raw, this.codeLang);
      const visibleLen = stripAnsi(colored).length;
      const pad = Math.max(0, w - 4 - visibleLen);
      const codeLine = chalk.hex('#1a3455')('│') +
        chalk.bgHex('#050d18')(' ' + colored + ' '.repeat(pad) + ' ') +
        chalk.hex('#1a3455')('│');
      process.stdout.write(codeLine + '\n');
      return;
    }

    // Ligne normale : rendu inline markdown
    const rendered = inlineMarkdown(renderHeadings(raw));
    process.stdout.write(rendered + (hasNewline ? '\n' : ''));
  }
}

// ═══════════════════════════════════════════════════════
// MARKDOWN RENDERER (batch — pour relecture sessions)
// ═══════════════════════════════════════════════════════
export function renderMarkdown(text) {
  const lines = text.split('\n');
  const out = [];
  let inCodeBlock = false;
  let codeLang = '';
  let codeLines = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.match(/^```(\w*)/)) {
      if (!inCodeBlock) {
        inCodeBlock = true;
        codeLang = line.match(/^```(\w*)/)[1] || '';
        codeLines = [];
      } else {
        inCodeBlock = false;
        out.push(renderCodeBlock(codeLines, codeLang));
        codeLines = [];
        codeLang = '';
      }
      continue;
    }

    if (inCodeBlock) {
      codeLines.push(line);
      continue;
    }

    out.push(renderLine(line));
  }

  if (inCodeBlock && codeLines.length) {
    out.push(renderCodeBlock(codeLines, codeLang));
  }

  return out.join('\n');
}

function renderLine(line) {
  if (line.trim() === '') return '';
  return inlineMarkdown(renderHeadings(line));
}

function renderHeadings(line) {
  if (line.match(/^### (.+)/)) return C.violet('  ' + line.replace(/^### /, '◆ '));
  if (line.match(/^## (.+)/))  return C.cyan(line.replace(/^## /, '◈ '));
  if (line.match(/^# (.+)/))   return C.bold(C.bright(line.replace(/^# /, '▶ ')));
  if (line.match(/^[−\-\*] (.+)/)) {
    const content = line.replace(/^[−\-\*] /, '');
    return C.dim('  · ') + inlineMarkdown(content);
  }
  if (line.match(/^\d+\. (.+)/)) {
    return '  ' + C.neon(line.match(/^(\d+)\./)[1] + '.') + ' ' + inlineMarkdown(line.replace(/^\d+\. /, ''));
  }
  if (line.match(/^[-*_]{3,}$/)) return hr('─', C.dim);
  return line;
}

function inlineMarkdown(text) {
  return text
    .replace(/\*\*(.+?)\*\*/g, (_, t) => C.bold(C.bright(t)))
    .replace(/\*(.+?)\*/g,     (_, t) => C.italic(C.muted(t)))
    .replace(/`([^`]+)`/g,     (_, t) => C.code(` ${t} `))
    .replace(/\[(.+?)\]\((.+?)\)/g, (_, label, url) => C.neon(label) + C.dim(` (${url})`));
}

// ── CODE BLOCK (rendu complet pour batch) ────────────────
function renderCodeBlock(lines, lang) {
  const w = termWidth();
  const langLabel = lang ? C.dim(` ${lang.toUpperCase()} `) : '';
  const topBorder  = chalk.hex('#1a3455')('┌' + '─'.repeat(w - 2) + '┐');
  const botBorder  = chalk.hex('#1a3455')('└' + '─'.repeat(w - 2) + '┘');
  const header     = chalk.hex('#1a3455')('│') + chalk.bgHex('#091525').hex('#4a6b8a')(` CODE ${langLabel}`.padEnd(w - 2)) + chalk.hex('#1a3455')('│');

  const coloredLines = lines.map(line => {
    const colored = highlightCode(line, lang);
    const visibleLen = stripAnsi(colored).length;
    const pad = Math.max(0, w - 4 - visibleLen);
    return chalk.hex('#1a3455')('│') + chalk.bgHex('#050d18')(' ' + colored + ' '.repeat(pad) + ' ') + chalk.hex('#1a3455')('│');
  });

  return [topBorder, header, ...coloredLines, botBorder].join('\n');
}

// ── SYNTAX HIGHLIGHTING ───────────────────────────────────
export function highlightCode(line, lang) {
  const l = (lang || '').toLowerCase();

  if (['js','javascript','ts','typescript','jsx','tsx','node','mjs'].includes(l)) {
    return line
      .replace(/\b(const|let|var|function|return|if|else|for|while|class|import|export|from|async|await|new|this|typeof|instanceof|throw|try|catch|finally|switch|case|break|continue|default|of|in|=>)\b/g,
        m => chalk.hex('#a78bfa')(m))
      .replace(/\b(true|false|null|undefined|NaN|Infinity)\b/g, m => chalk.hex('#ff6b35')(m))
      .replace(/\b(\d+\.?\d*)\b/g, m => chalk.hex('#f59e0b')(m))
      .replace(/(["`'])([^"`']*)\1/g, (_, q, s) => chalk.hex('#00ff9d')(q + s + q))
      .replace(/(\/\/.*)/g, m => chalk.hex('#4a6b8a').italic(m))
      .replace(/\b([A-Z][a-zA-Z0-9_]*)\b/g, m => chalk.hex('#00e5ff')(m));
  }

  if (['py','python'].includes(l)) {
    return line
      .replace(/\b(def|class|import|from|return|if|elif|else|for|while|in|not|and|or|with|as|try|except|finally|raise|pass|break|continue|lambda|yield|global|nonlocal|del|assert)\b/g,
        m => chalk.hex('#a78bfa')(m))
      .replace(/\b(True|False|None|self|cls)\b/g, m => chalk.hex('#ff6b35')(m))
      .replace(/\b(\d+\.?\d*)\b/g, m => chalk.hex('#f59e0b')(m))
      .replace(/(['"])([^'"]*)\1/g, (_, q, s) => chalk.hex('#00ff9d')(q + s + q))
      .replace(/(#.*)/g, m => chalk.hex('#4a6b8a').italic(m));
  }

  if (['bash','sh','shell','zsh','fish'].includes(l)) {
    return line
      .replace(/^(\$\s)/, m => chalk.hex('#00ff9d')(m))
      .replace(/\b(if|then|else|fi|for|do|done|while|case|esac|function|export|source|echo|cd|ls|mkdir|rm|cp|mv|cat|grep|awk|sed|chmod|chown|sudo|apt|npm|yarn|node|git|docker|flutter|pod|gradle|swift|kotlinc)\b/g,
        m => chalk.hex('#00e5ff')(m))
      .replace(/(#.*)/g, m => chalk.hex('#4a6b8a').italic(m))
      .replace(/(['"])([^'"]*)\1/g, (_, q, s) => chalk.hex('#00ff9d')(q + s + q))
      .replace(/(\$\w+)/g, m => chalk.hex('#f59e0b')(m));
  }

  if (['json'].includes(l)) {
    return line
      .replace(/"([^"]+)":/g, (_, k) => `"${chalk.hex('#00e5ff')(k)}":`)
      .replace(/: (".*?")/g, (_, v) => `: ${chalk.hex('#00ff9d')(v)}`)
      .replace(/: (\d+\.?\d*)/g, (_, v) => `: ${chalk.hex('#f59e0b')(v)}`)
      .replace(/: (true|false|null)/g, (_, v) => `: ${chalk.hex('#ff6b35')(v)}`);
  }

  if (['css','scss','sass'].includes(l)) {
    return line
      .replace(/([\w-]+)\s*\{/g, m => chalk.hex('#00e5ff')(m))
      .replace(/([\w-]+):/g, (_, p) => chalk.hex('#a78bfa')(p) + ':')
      .replace(/(\/\*.*?\*\/)/g, m => chalk.hex('#4a6b8a').italic(m));
  }

  if (['sql'].includes(l)) {
    return line
      .replace(/\b(SELECT|FROM|WHERE|JOIN|LEFT|RIGHT|INNER|OUTER|ON|AS|INSERT|INTO|VALUES|UPDATE|SET|DELETE|CREATE|TABLE|INDEX|DROP|ALTER|ADD|COLUMN|PRIMARY|KEY|FOREIGN|REFERENCES|GROUP|BY|ORDER|HAVING|LIMIT|OFFSET|DISTINCT|COUNT|SUM|AVG|MAX|MIN|AND|OR|NOT|IN|LIKE|IS|NULL|BETWEEN)\b/gi,
        m => chalk.hex('#a78bfa')(m.toUpperCase()))
      .replace(/(['"])([^'"]*)\1/g, (_, q, s) => chalk.hex('#00ff9d')(q + s + q))
      .replace(/\b(\d+)\b/g, m => chalk.hex('#f59e0b')(m))
      .replace(/(--.*)/g, m => chalk.hex('#4a6b8a').italic(m));
  }

  if (['yaml','yml','dockerfile','docker'].includes(l)) {
    return line
      .replace(/^(\s*)([\w-]+):/g, (_, sp, k) => sp + chalk.hex('#00e5ff')(k) + ':')
      .replace(/(#.*)/g, m => chalk.hex('#4a6b8a').italic(m))
      .replace(/: (.+)/g, (_, v) => ': ' + chalk.hex('#00ff9d')(v));
  }

  // Swift / Kotlin / Dart — mobile !
  if (['swift'].includes(l)) {
    return line
      .replace(/\b(func|class|struct|enum|protocol|extension|var|let|if|else|guard|return|import|for|while|switch|case|break|continue|init|self|super|override|public|private|internal|fileprivate|open|static|final|lazy|weak|unowned|nil|true|false|throws|throw|try|catch|async|await|actor)\b/g,
        m => chalk.hex('#a78bfa')(m))
      .replace(/\b(\d+\.?\d*)\b/g, m => chalk.hex('#f59e0b')(m))
      .replace(/(".*?")/g, m => chalk.hex('#00ff9d')(m))
      .replace(/(\/\/.*)/g, m => chalk.hex('#4a6b8a').italic(m))
      .replace(/\b([A-Z][a-zA-Z0-9_]*)\b/g, m => chalk.hex('#00e5ff')(m));
  }

  if (['kt','kotlin','kts'].includes(l)) {
    return line
      .replace(/\b(fun|class|object|interface|data|sealed|abstract|override|val|var|if|else|when|return|import|for|while|do|break|continue|init|this|super|public|private|protected|internal|companion|open|final|suspend|by|in|is|as|null|true|false|throw|try|catch|finally|coroutine|launch|async|await|flow)\b/g,
        m => chalk.hex('#a78bfa')(m))
      .replace(/\b(\d+\.?\d*)\b/g, m => chalk.hex('#f59e0b')(m))
      .replace(/(".*?")/g, m => chalk.hex('#00ff9d')(m))
      .replace(/(\/\/.*)/g, m => chalk.hex('#4a6b8a').italic(m))
      .replace(/\b([A-Z][a-zA-Z0-9_]*)\b/g, m => chalk.hex('#00e5ff')(m));
  }

  if (['dart'].includes(l)) {
    return line
      .replace(/\b(void|class|extends|implements|mixin|abstract|static|final|const|var|dynamic|if|else|for|while|do|return|import|export|library|part|show|hide|as|is|in|new|null|true|false|async|await|sync|yield|throw|try|catch|finally|on|rethrow|assert|enum|typedef|get|set|late|required|factory|super|this|with)\b/g,
        m => chalk.hex('#a78bfa')(m))
      .replace(/\b(\d+\.?\d*)\b/g, m => chalk.hex('#f59e0b')(m))
      .replace(/('.*?'|".*?")/g, m => chalk.hex('#00ff9d')(m))
      .replace(/(\/\/.*)/g, m => chalk.hex('#4a6b8a').italic(m))
      .replace(/\b([A-Z][a-zA-Z0-9_]*)\b/g, m => chalk.hex('#00e5ff')(m));
  }

  // Markdown
  if (['md','markdown'].includes(l)) {
    return line
      .replace(/^(#{1,6} .+)/, m => chalk.hex('#f59e0b')(m))
      .replace(/\*\*(.+?)\*\*/g, (_, t) => chalk.bold(t))
      .replace(/`([^`]+)`/g, (_, t) => chalk.hex('#00e5ff')(t));
  }

  return chalk.hex('#b8d4f0')(line);
}

// ═══════════════════════════════════════════════════════
// DIFF RENDERER — Affiche un diff unifié coloré
// ═══════════════════════════════════════════════════════
export function renderDiff(diffText) {
  const lines = diffText.split('\n');
  const out = [];
  for (const line of lines) {
    if (line.startsWith('+++') || line.startsWith('---')) {
      out.push(C.diffhdr(line));
    } else if (line.startsWith('@@')) {
      out.push(C.gold(line));
    } else if (line.startsWith('+')) {
      out.push(C.added(line));
    } else if (line.startsWith('-')) {
      out.push(C.removed(line));
    } else {
      out.push(C.dim(line));
    }
  }
  return out.join('\n');
}

// ── MESSAGE DISPLAY ───────────────────────────────────────
export function printUserMsg(content) {
  console.log();
  console.log(C.dim('  ▸ VOUS  ') + C.dim(new Date().toLocaleTimeString('fr-FR')));
  console.log(C.bright(content));
}

export function printStreamHeader(provider, model) {
  console.log();
  const label = `  ▸ AI  [${provider?.toUpperCase() ?? '?'}]  ${model ?? ''}  ${C.dim('(streaming…)')}`;
  console.log(C.cyan(label));
  console.log(hr('─', C.dim));
}

export function printStreamFooter(usage) {
  console.log();
  console.log(hr('─', C.dim));
  if (usage?.total_tokens) {
    console.log(C.dim(`  ${usage.total_tokens} tokens`));
  }
}

export function printAssistantMsg(content, provider, model, usage) {
  console.log();
  const label = `  ▸ AI  [${provider?.toUpperCase() ?? '?'}]  ${model ?? ''}`;
  const usageStr = usage?.total_tokens ? C.dim(`  ${usage.total_tokens} tokens`) : '';
  console.log(C.cyan(label) + usageStr);
  console.log(hr('─', C.dim));
  console.log(renderMarkdown(content));
  console.log(hr('─', C.dim));
}

export function printError(msg) {
  console.log();
  console.log(C.danger('  ⚠ ERREUR: ') + C.muted(msg));
}

export function printSuccess(msg) {
  console.log(C.neon('  ✓ ') + C.muted(msg));
}

export function printInfo(msg) {
  console.log(C.dim('  ◈ ') + C.muted(msg));
}

export function printSection(title) {
  console.log();
  console.log(C.cyan('  ═══ ' + title + ' ═══'));
  console.log();
}

// ── TABLE ─────────────────────────────────────────────────
export function printTable(headers, rows) {
  const colWidths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map(r => String(r[i] ?? '').length))
  );
  const rowStr = (cells, colors) =>
    '  ' + cells.map((c, i) => {
      const s = String(c ?? '').padEnd(colWidths[i]);
      return colors ? colors[i](s) : s;
    }).join('  ');

  console.log(rowStr(headers, headers.map(() => C.cyan)));
  console.log('  ' + colWidths.map(w => '─'.repeat(w)).join('  '));
  rows.forEach((r, idx) => {
    const alt = idx % 2 === 0;
    console.log(rowStr(r, r.map(() => alt ? C.muted : C.dim)));
  });
  console.log();
}

// ── SPINNER ───────────────────────────────────────────────
export class Spinner {
  constructor(text = 'Traitement…') {
    this.text = text;
    this.frames = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏'];
    this.i = 0;
    this.timer = null;
  }
  start() {
    process.stdout.write('\n');
    this.timer = setInterval(() => {
      process.stdout.write(`\r  ${C.cyan(this.frames[this.i++ % this.frames.length])} ${C.dim(this.text)}  `);
    }, 80);
    return this;
  }
  stop(msg) {
    clearInterval(this.timer);
    process.stdout.write('\r' + ' '.repeat(termWidth()) + '\r');
    if (msg) console.log(C.neon('  ✓ ') + C.muted(msg));
  }
  fail(msg) {
    clearInterval(this.timer);
    process.stdout.write('\r' + ' '.repeat(termWidth()) + '\r');
    if (msg) console.log(C.danger('  ✗ ') + C.muted(msg));
  }
}
