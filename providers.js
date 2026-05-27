// ═══════════════════════════════════════════════════════
//  PROVIDERS v2 — Mistral · Groq · OpenRouter
//  Chaque provider expose : { models, send(), stream() }
//  Nouveauté v2 : STREAMING natif sur les 3 providers
// ═══════════════════════════════════════════════════════

import fetch from 'node-fetch';

// ── MISTRAL ─────────────────────────────────────────────
export const MISTRAL_MODELS = [
  { id: 'mistral-large-2512',      name: 'Mistral Large (meilleur)',        ctx: 128000,  temp: 0.4 },
  { id: 'mistral-medium-2508',     name: 'Mistral Medium (ratio perf)',      ctx: 128000,  temp: 0.5 },
  { id: 'codestral-2508',          name: 'Codestral (code expert)',          ctx: 256000,  temp: 0.3 },
  { id: 'devstral-2512',           name: 'Devstral Full-Stack',              ctx: 128000,  temp: 0.4 },
  { id: 'devstral-medium-2507',    name: 'Devstral Medium (équilibré)',      ctx: 128000,  temp: 0.4 },
  { id: 'devstral-small-2507',     name: 'Devstral Small (rapide)',          ctx: 128000,  temp: 0.4 },
  { id: 'mistral-small-2506',      name: 'Mistral Small (flash)',            ctx: 128000,  temp: 0.4 },
  { id: 'ministral-8b-2512',       name: 'Ministral 8B (quotidien)',         ctx: 128000,  temp: 0.4 },
  { id: 'ministral-3b-2512',       name: 'Ministral 3B (ultra rapide)',      ctx: 128000,  temp: 0.4 },
  { id: 'magistral-medium-2509',   name: 'Magistral Medium (raisonnement)',  ctx: 128000,  temp: 0.5 },
  { id: 'magistral-small-2509',    name: 'Magistral Small (reason rapide)',  ctx: 128000,  temp: 0.5 },
  { id: 'open-mistral-nemo',       name: 'Mistral Nemo (open source)',       ctx: 128000,  temp: 0.4 },
  { id: 'pixtral-large-2411',      name: 'Pixtral Large (vision)',           ctx: 128000,  temp: 0.4 },
];

// ── GROQ ─────────────────────────────────────────────────
export const GROQ_MODELS = [
  { id: 'llama-3.3-70b-versatile',       name: 'Llama 3.3 70B Versatile',        ctx: 128000,  temp: 0.5 },
  { id: 'llama-3.1-8b-instant',          name: 'Llama 3.1 8B Instant',           ctx: 128000,  temp: 0.5 },
  { id: 'llama3-70b-8192',               name: 'Llama 3 70B',                     ctx: 8192,    temp: 0.5 },
  { id: 'llama3-8b-8192',                name: 'Llama 3 8B',                      ctx: 8192,    temp: 0.5 },
  { id: 'mixtral-8x7b-32768',            name: 'Mixtral 8x7B',                    ctx: 32768,   temp: 0.5 },
  { id: 'gemma2-9b-it',                  name: 'Gemma 2 9B',                      ctx: 8192,    temp: 0.5 },
  { id: 'deepseek-r1-distill-llama-70b', name: 'DeepSeek R1 Distill 70B',        ctx: 128000,  temp: 0.5 },
  { id: 'qwen-qwq-32b',                  name: 'Qwen QwQ 32B (raisonnement)',     ctx: 128000,  temp: 0.5 },
  { id: 'meta-llama/llama-4-scout-17b-16e-instruct', name: 'Llama 4 Scout 17B', ctx: 131072,  temp: 0.5 },
  { id: 'compound-beta',                 name: 'Compound Beta (agent)',           ctx: 128000,  temp: 0.5 },
];

// ── OPENROUTER — top models pour devs ────────────────────
export const OPENROUTER_MODELS = [
  { id: 'anthropic/claude-sonnet-4-5',          name: 'Claude Sonnet 4.5 (Anthropic)',       ctx: 200000, temp: 0.5 },
  { id: 'anthropic/claude-opus-4',              name: 'Claude Opus 4 (Anthropic top)',       ctx: 200000, temp: 0.5 },
  { id: 'openai/gpt-4o',                        name: 'GPT-4o (OpenAI)',                     ctx: 128000, temp: 0.5 },
  { id: 'openai/gpt-4.1',                       name: 'GPT-4.1 (OpenAI latest)',             ctx: 128000, temp: 0.5 },
  { id: 'openai/o3',                            name: 'o3 (OpenAI raisonnement)',            ctx: 200000, temp: 1.0 },
  { id: 'openai/o4-mini',                       name: 'o4-mini (OpenAI rapide)',             ctx: 200000, temp: 1.0 },
  { id: 'google/gemini-2.5-pro-preview',        name: 'Gemini 2.5 Pro (Google)',             ctx: 1048576, temp: 0.5 },
  { id: 'google/gemini-2.5-flash-preview',      name: 'Gemini 2.5 Flash (Google rapide)',    ctx: 1048576, temp: 0.5 },
  { id: 'deepseek/deepseek-r1',                 name: 'DeepSeek R1 (raisonnement libre)',    ctx: 164000, temp: 0.5 },
  { id: 'deepseek/deepseek-chat-v3-0324',       name: 'DeepSeek V3 Chat',                   ctx: 64000,  temp: 0.5 },
  { id: 'meta-llama/llama-4-maverick',          name: 'Llama 4 Maverick',                   ctx: 524288, temp: 0.5 },
  { id: 'qwen/qwen3-235b-a22b',                 name: 'Qwen3 235B (Alibaba top)',            ctx: 40960,  temp: 0.5 },
  { id: 'microsoft/mai-ds-r1',                  name: 'MAI DS R1 (Microsoft)',               ctx: 163840, temp: 0.5 },
  { id: 'mistralai/devstral',                   name: 'Devstral via OpenRouter',             ctx: 131072, temp: 0.4 },
  { id: 'moonshotai/kimi-k2',                   name: 'Kimi K2 (Moonshot)',                 ctx: 131072, temp: 0.5 },
  { id: 'x-ai/grok-3',                         name: 'Grok 3 (xAI)',                        ctx: 131072, temp: 0.5 },
  { id: 'tngtech/deepseek-r1t2-chimera:free',   name: 'DeepSeek Chimera (GRATUIT)',          ctx: 163840, temp: 0.5 },
  { id: 'google/gemma-3-27b-it:free',           name: 'Gemma 3 27B (GRATUIT)',              ctx: 96000,  temp: 0.5 },
];

// ═══════════════════════════════════════════════════════
// UTILITAIRE — Parser SSE (Server-Sent Events)
// Commun aux 3 providers (format OpenAI-compatible)
// ═══════════════════════════════════════════════════════
async function* parseSSE(response) {
  const decoder = new TextDecoder();
  let buffer = '';
  for await (const chunk of response.body) {
    buffer += decoder.decode(chunk, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop(); // garder la ligne incomplète
    for (const line of lines) {
      if (line.startsWith('data: ')) {
        const data = line.slice(6).trim();
        if (data === '[DONE]') return;
        if (data) {
          try {
            yield JSON.parse(data);
          } catch {
            // ignorer les lignes non-JSON (keepalive, commentaires)
          }
        }
      }
    }
  }
}

// ═══════════════════════════════════════════════════════
// MISTRAL — send (non-stream) + stream
// ═══════════════════════════════════════════════════════
export async function sendMistral(apiKey, modelId, messages, opts = {}) {
  const res = await fetch('https://api.mistral.ai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: modelId,
      messages,
      temperature: opts.temperature ?? 0.4,
      max_tokens: opts.maxTokens ?? 32768,
      top_p: 0.95,
      stream: false,
    }),
  });
  if (!res.ok) {
    const txt = await res.text();
    let msg = txt;
    try { msg = JSON.parse(txt)?.message || JSON.parse(txt)?.error?.message || txt; } catch {}
    throw new Error(`Mistral ${res.status}: ${msg}`);
  }
  const data = await res.json();
  return {
    content: data.choices?.[0]?.message?.content ?? '',
    usage: data.usage ?? {},
  };
}

export async function* streamMistral(apiKey, modelId, messages, opts = {}) {
  const res = await fetch('https://api.mistral.ai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: modelId,
      messages,
      temperature: opts.temperature ?? 0.4,
      max_tokens: opts.maxTokens ?? 32768,
      top_p: 0.95,
      stream: true,
    }),
  });
  if (!res.ok) {
    const txt = await res.text();
    let msg = txt;
    try { msg = JSON.parse(txt)?.message || JSON.parse(txt)?.error?.message || txt; } catch {}
    throw new Error(`Mistral ${res.status}: ${msg}`);
  }
  for await (const event of parseSSE(res)) {
    const delta = event?.choices?.[0]?.delta?.content;
    if (delta) yield delta;
  }
}

// ═══════════════════════════════════════════════════════
// GROQ — send (non-stream) + stream
// ═══════════════════════════════════════════════════════
export async function sendGroq(apiKey, modelId, messages, opts = {}) {
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: modelId,
      messages,
      temperature: opts.temperature ?? 0.5,
      max_tokens: opts.maxTokens ?? 32768,
      stream: false,
    }),
  });
  if (!res.ok) {
    const txt = await res.text();
    let msg = txt;
    try { msg = JSON.parse(txt)?.error?.message || txt; } catch {}
    throw new Error(`Groq ${res.status}: ${msg}`);
  }
  const data = await res.json();
  return {
    content: data.choices?.[0]?.message?.content ?? '',
    usage: data.usage ?? {},
  };
}

export async function* streamGroq(apiKey, modelId, messages, opts = {}) {
  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: modelId,
      messages,
      temperature: opts.temperature ?? 0.5,
      max_tokens: opts.maxTokens ?? 32768,
      stream: true,
    }),
  });
  if (!res.ok) {
    const txt = await res.text();
    let msg = txt;
    try { msg = JSON.parse(txt)?.error?.message || txt; } catch {}
    throw new Error(`Groq ${res.status}: ${msg}`);
  }
  for await (const event of parseSSE(res)) {
    const delta = event?.choices?.[0]?.delta?.content;
    if (delta) yield delta;
  }
}

// ═══════════════════════════════════════════════════════
// OPENROUTER — send (non-stream) + stream
// ═══════════════════════════════════════════════════════
export async function sendOpenRouter(apiKey, modelId, messages, opts = {}) {
  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': 'https://voanh-cli.local',
      'X-Title': 'VOANH CLI',
    },
    body: JSON.stringify({
      model: modelId,
      messages,
      temperature: opts.temperature ?? 0.5,
      max_tokens: opts.maxTokens ?? 32768,
      stream: false,
    }),
  });
  if (!res.ok) {
    const txt = await res.text();
    let msg = txt;
    try { msg = JSON.parse(txt)?.error?.message || txt; } catch {}
    throw new Error(`OpenRouter ${res.status}: ${msg}`);
  }
  const data = await res.json();
  return {
    content: data.choices?.[0]?.message?.content ?? '',
    usage: data.usage ?? {},
  };
}

export async function* streamOpenRouter(apiKey, modelId, messages, opts = {}) {
  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': 'https://voanh-cli.local',
      'X-Title': 'VOANH CLI',
    },
    body: JSON.stringify({
      model: modelId,
      messages,
      temperature: opts.temperature ?? 0.5,
      max_tokens: opts.maxTokens ?? 32768,
      stream: true,
    }),
  });
  if (!res.ok) {
    const txt = await res.text();
    let msg = txt;
    try { msg = JSON.parse(txt)?.error?.message || txt; } catch {}
    throw new Error(`OpenRouter ${res.status}: ${msg}`);
  }
  for await (const event of parseSSE(res)) {
    const delta = event?.choices?.[0]?.delta?.content;
    if (delta) yield delta;
  }
}

// ── PROVIDER MAP ──────────────────────────────────────────
export const PROVIDERS = {
  mistral:    { name: 'Mistral AI',   models: MISTRAL_MODELS,    send: sendMistral,    stream: streamMistral    },
  groq:       { name: 'Groq',         models: GROQ_MODELS,       send: sendGroq,       stream: streamGroq       },
  openrouter: { name: 'OpenRouter',   models: OPENROUTER_MODELS, send: sendOpenRouter, stream: streamOpenRouter },
};
