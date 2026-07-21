// ─────────────────────────────────────────────────────────────────────────
// /api/chat.js — Endpoint dedicado al chat con IA (Triskl).
// Separado de handler.js a propósito: lo usan tanto la página de asistente
// (chat de página completa) como el modal del transcriptor.
//
// TODA acción acá exige username + uuid + password en el body (sin
// excepciones — este endpoint no tiene acciones públicas/pre-login).
//
// Tablas requeridas en Supabase (crear antes de usar, si no vas a ver 500):
//   ai_chats(
//     id uuid primary key, user_id uuid, username text, materia text,
//     title text, last_message text,
//     created_at timestamptz, updated_at timestamptz, closed_at timestamptz
//   )
//   ai_chat_messages(
//     id uuid primary key, chat_id uuid references ai_chats(id) on delete cascade,
//     role text, content text, created_at timestamptz
//   )
// ─────────────────────────────────────────────────────────────────────────

const SUPABASE_URL          = process.env.LINKTR;
const SUPABASE_ANON         = process.env.ANONTR;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;

const AI_KEY   = process.env.ANTHROPIC_KEY || process.env.CLAUDE_KEY || "";
const AI_MODEL = process.env.AI_MODEL || "claude-sonnet-4-5";

// ─── Headers ────────────────────────────────────────────────────────────────
function authHeaders(jwt) {
  return {
    "Content-Type": "application/json",
    "apikey": SUPABASE_ANON,
    "Authorization": `Bearer ${jwt || SUPABASE_ANON}`,
    "Prefer": "return=representation",
  };
}

function serviceHeaders() {
  return {
    "Content-Type": "application/json",
    "apikey": SUPABASE_ANON,
    "Authorization": `Bearer ${SUPABASE_SERVICE_ROLE || SUPABASE_ANON}`,
    "Prefer": "return=representation",
  };
}

// ─── Supabase helpers ────────────────────────────────────────────────────────
async function sbGet(table, params = "", jwt = null) {
  const url = `${SUPABASE_URL}/rest/v1/${table}${params ? "?" + params : ""}`;
  const res = await fetch(url, { method: "GET", headers: authHeaders(jwt) });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`sbGet ${table}: ${err}`);
  }
  return res.json();
}

async function sbPost(table, data, jwt = null) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${table}`, {
    method: "POST",
    headers: authHeaders(jwt),
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`sbPost ${table}: ${err}`);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

async function sbPatch(table, filter, data, jwt = null) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${table}?${filter}`, {
    method: "PATCH",
    headers: authHeaders(jwt),
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`sbPatch ${table}: ${err}`);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

async function sbDelete(table, filter, jwt = null) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${table}?${filter}`, {
    method: "DELETE",
    headers: authHeaders(jwt),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`sbDelete ${table}: ${err}`);
  }
  return true;
}

async function sbAdminGet(table, params = "") {
  const url = `${SUPABASE_URL}/rest/v1/${table}${params ? "?" + params : ""}`;
  const res = await fetch(url, { method: "GET", headers: serviceHeaders() });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`sbAdminGet ${table}: ${err}`);
  }
  return res.json();
}

async function supabaseAuthPost(path, body) {
  const res = await fetch(`${SUPABASE_URL}/auth/v1${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "apikey": SUPABASE_ANON },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

// ─── Auto-refresh ────────────────────────────────────────────────────────────
async function withAutoRefresh(jwt, refreshToken, fn, relogin = null) {
  try {
    return await fn(jwt);
  } catch (e) {
    const msg = e.message || "";
    const isExpired =
      msg.includes("JWT expired") ||
      msg.includes("PGRST301") ||
      msg.includes("invalid JWT") ||
      msg.includes("401");

    if (isExpired) {
      if (refreshToken) {
        const { ok, data } = await supabaseAuthPost(
          "/token?grant_type=refresh_token",
          { refresh_token: refreshToken }
        );
        if (ok && data.access_token) {
          return await fn(data.access_token);
        }
      }
      if (relogin) {
        const freshJwt = await relogin();
        if (freshJwt) return await fn(freshJwt);
      }
    }
    throw e;
  }
}

// ─── AUTH por username + uuid + password (obligatorio, siempre) ────────────
const _sessCache = new Map(); // key: `${uuid}:${password}` -> { jwt, refreshToken, expiresAt, user }

async function loginByUuidPassword(uuid, password) {
  const rows = await sbAdminGet(
    "triskl_users",
    `id=eq.${uuid}&select=id,username,email,gen`
  ).catch(() => []);
  if (!rows || !rows.length || !rows[0].email) {
    throw new Error("Usuario no encontrado");
  }
  const email = rows[0].email;
  const { ok, data } = await supabaseAuthPost("/token?grant_type=password", { email, password });
  if (!ok || !data.access_token) {
    throw new Error("Credenciales incorrectas");
  }
  return {
    jwt: data.access_token,
    refreshToken: data.refresh_token || null,
    expiresAt: data.expires_at ? data.expires_at * 1000 : Date.now() + 3500 * 1000,
    user: { id: rows[0].id, username: rows[0].username, email, gen: rows[0].gen ?? null },
  };
}

function _mkAuthCtx(uuid, password, sess) {
  return {
    jwt: sess.jwt,
    refreshToken: sess.refreshToken,
    user: sess.user,
    relogin: async () => {
      const fresh = await loginByUuidPassword(uuid, password).catch(() => null);
      if (fresh) { _sessCache.set(`${uuid}:${password}`, fresh); return fresh.jwt; }
      return null;
    },
  };
}

// Exige username + uuid + password SIEMPRE (no hay acciones públicas acá).
async function resolveAuth(req) {
  const b = req.body || {};
  const uuid     = b.uuid || b.user_id || b.id || null;
  const password = b.password || null;
  const username  = (b.username || "").toString().trim().toLowerCase() || null;
  if (!uuid || !password || !username) return null;

  const key = `${uuid}:${password}`;
  const cached = _sessCache.get(key);
  if (cached && cached.expiresAt > Date.now() + 60_000) {
    if (!cached.user || cached.user.username.toLowerCase() !== username) return null;
    return _mkAuthCtx(uuid, password, cached);
  }
  const sess = await loginByUuidPassword(uuid, password);
  if (!sess.user || sess.user.username.toLowerCase() !== username) return null;
  _sessCache.set(key, sess);
  return _mkAuthCtx(uuid, password, sess);
}

// ─── LLM (Anthropic) ─────────────────────────────────────────────────────────
async function callLLM({ system, messages, maxTokens = 1200 }) {
  if (!AI_KEY) throw new Error("Falta ANTHROPIC_KEY en variables de entorno");
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": AI_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({ model: AI_MODEL, max_tokens: maxTokens, system, messages }),
  });
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`LLM ${res.status}: ${t.slice(0, 300)}`);
  }
  const data = await res.json();
  const text = (data.content || [])
    .filter(b => b.type === "text")
    .map(b => b.text)
    .join("\n")
    .trim();
  return text || "No obtuve respuesta.";
}

// Traduce errores típicos de "tabla no existe" a un mensaje entendible.
function friendlyDbError(err) {
  const msg = err && err.message || "";
  if (/relation .* does not exist/i.test(msg) || /42P01/.test(msg)) {
    return "Faltan las tablas ai_chats / ai_chat_messages en Supabase (ver comentario al inicio de chat.js con el SQL para crearlas).";
  }
  return msg || "Error inesperado";
}

// ─── Handler principal ───────────────────────────────────────────────────────
export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  if (req.method === "OPTIONS") return res.status(204).end();

  const action = req.query.action || (req.body && req.body.action) || "";

  const authCtx = await resolveAuth(req).catch(() => null);
  if (!authCtx || !authCtx.user) {
    return res.status(401).json({ error: "username, uuid y password son requeridos" });
  }

  const jwt          = authCtx.jwt;
  const refreshToken  = authCtx.refreshToken;
  const relogin       = authCtx.relogin;
  const username       = authCtx.user.username;
  const auto = (fn) => withAutoRefresh(jwt, refreshToken, fn, relogin);

  try {

    // Lista de conversaciones del usuario (inbox, estilo Instagram).
    if (action === "ai-chats-list") {
      const rows = await auto(j => sbGet("ai_chats",
        `username=eq.${username}&order=updated_at.desc&select=id,materia,title,last_message,created_at,updated_at,closed_at`, j
      ));
      return res.status(200).json(rows || []);
    }

    // Abre una conversación puntual (o la última abierta si no se pasa chat_id).
    if (action === "ai-chat-open") {
      let { chat_id, materia } = req.body;

      let chatRow = null;
      if (chat_id) {
        const rows = await auto(j => sbGet("ai_chats", `id=eq.${chat_id}&username=eq.${username}`, j));
        chatRow = rows && rows[0] ? rows[0] : null;
        if (!chatRow) return res.status(404).json({ error: "Conversación no encontrada" });
      } else {
        let params = `username=eq.${username}&closed_at=is.null&order=updated_at.desc&limit=1`;
        if (materia) params += `&materia=eq.${encodeURIComponent(materia)}`;
        const rows = await auto(j => sbGet("ai_chats", params, j));
        chatRow = rows && rows[0] ? rows[0] : null;
      }

      if (!chatRow) return res.status(200).json({ chat: null, messages: [] });

      const messages = await auto(j => sbGet("ai_chat_messages",
        `chat_id=eq.${chatRow.id}&order=created_at.asc&select=id,role,content,created_at`, j
      ));

      const { user_id, ...safeChat } = chatRow;
      return res.status(200).json({ chat: safeChat, messages: messages || [] });
    }

    // Finaliza (cierra) una conversación; queda visible en el historial.
    if (action === "ai-chat-finish") {
      const { chat_id } = req.body;
      if (!chat_id) return res.status(400).json({ error: "chat_id requerido" });
      await auto(j => sbPatch("ai_chats", `id=eq.${chat_id}&username=eq.${username}`,
        { closed_at: new Date().toISOString() }, j));
      return res.status(200).json({ ok: true });
    }

    // Borra una conversación entera del historial.
    if (action === "ai-chat-delete") {
      const { chat_id } = req.body;
      if (!chat_id) return res.status(400).json({ error: "chat_id requerido" });
      await auto(j => sbDelete("ai_chat_messages", `chat_id=eq.${chat_id}`, j)).catch(() => null);
      await auto(j => sbDelete("ai_chats", `id=eq.${chat_id}&username=eq.${username}`, j));
      return res.status(200).json({ ok: true });
    }

    // Envía un mensaje (crea la conversación si no existe todavía).
    if (action === "ai-chat") {
      const {
        chat_id,
        message,
        context,
        contextText,
        attachments,
        materia,
      } = req.body;

      if (!message) return res.status(400).json({ error: "Falta el mensaje" });

      // 1) Resolver o crear la conversación (siempre acotada al username dueño).
      let chat;
      if (chat_id) {
        const rows = await auto(j => sbGet("ai_chats", `id=eq.${chat_id}&username=eq.${username}`, j));
        chat = rows && rows[0];
        if (!chat) return res.status(404).json({ error: "Conversación no encontrada" });
      } else {
        const newChat = {
          id: crypto.randomUUID(), user_id: authCtx.user.id, username,
          materia: materia || null, title: materia || "Nueva conversación",
          created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
        };
        const created = await auto(j => sbPost("ai_chats", newChat, j));
        chat = Array.isArray(created) ? created[0] : created;
      }

      // 2) Historial real de la conversación.
      const priorMessages = await auto(j => sbGet("ai_chat_messages",
        `chat_id=eq.${chat.id}&order=created_at.asc&select=role,content`, j
      ));

      // 3) Material adjunto (texto)
      let materialText = "";
      if (typeof contextText === "string" && contextText.trim()) {
        materialText = contextText.trim();
      } else if (Array.isArray(context) && context.length) {
        materialText = context
          .map(c => `### ${(c.title || c.type || "Material")}\n${String(c.text || "").trim()}`)
          .join("\n\n");
      }

      // 4) System prompt de Triskl
      const system = [
        "Sos el asistente de estudio de Triskl, una plataforma para estudiantes de Uruguay.",
        "Ayudás a entender la clase: explicás, resumís, hacés esquemas, generás preguntas de repaso y aclarás dudas.",
        "Respondé en español rioplatense (voseo), claro y directo, sin relleno.",
        materia ? `Materia actual: ${materia}.` : "",
        materialText
          ? "Basá tus respuestas en el MATERIAL provisto (transcripciones, apuntes y archivos). Si algo no está en el material, aclaralo y ofrecé una explicación general marcándola como tal."
          : "Todavía no hay material adjunto; respondé de forma general y ofrecé ayuda para organizar la clase.",
      ].filter(Boolean).join("\n");

      // 5) Turno actual: material + adjuntos (pdf/imágenes) + pregunta
      const userBlocks = [];
      for (const a of (Array.isArray(attachments) ? attachments : [])) {
        if (!a || !a.data) continue;
        const mt = a.media_type || "application/octet-stream";
        if (mt.startsWith("image/")) {
          userBlocks.push({ type: "image", source: { type: "base64", media_type: mt, data: a.data } });
        } else if (mt === "application/pdf") {
          userBlocks.push({ type: "document", source: { type: "base64", media_type: mt, data: a.data } });
        }
      }
      const preface = materialText ? `MATERIAL DE LA CLASE:\n${materialText}\n\n---\n\n` : "";
      userBlocks.push({ type: "text", text: `${preface}PREGUNTA: ${message}` });

      // 6) Mensajes para el LLM (historial real + turno actual)
      const llmMessages = [
        ...(priorMessages || [])
          .filter(m => m && (m.role === "user" || m.role === "assistant") && m.content)
          .map(m => ({ role: m.role, content: String(m.content) })),
        { role: "user", content: userBlocks },
      ];

      const replyText = await callLLM({ system, messages: llmMessages });
      const nowIso = new Date().toISOString();

      await auto(j => sbPost("ai_chat_messages", {
        id: crypto.randomUUID(), chat_id: chat.id, role: "user", content: message, created_at: nowIso,
      }, j));
      await auto(j => sbPost("ai_chat_messages", {
        id: crypto.randomUUID(), chat_id: chat.id, role: "assistant", content: replyText, created_at: nowIso,
      }, j));
      await auto(j => sbPatch("ai_chats", `id=eq.${chat.id}`, {
        updated_at: nowIso, last_message: replyText.slice(0, 140),
      }, j)).catch(() => null);

      return res.status(200).json({ chat_id: chat.id, response: replyText, reply: replyText });
    }

    return res.status(404).json({ error: `Acción desconocida: ${action}` });

  } catch (err) {
    console.error("[chat.js ERROR]", err.message);
    return res.status(500).json({ error: friendlyDbError(err) });
  }
}
