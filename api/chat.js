// ─────────────────────────────────────────────────────────────────────────
// /api/chat.js — Endpoint que usa la IA de Servo SIN contexto fijo de SERVO.
// El historial enviado es solo el historial real de la conversación.
// Bloquea palabras prohibidas y reintenta si la respuesta contiene "servo".
// ─────────────────────────────────────────────────────────────────────────

const SUPABASE_URL          = process.env.LINKTR;
const SUPABASE_ANON         = process.env.ANONTR;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;

// ─── Configuración de la API de Servo ──────────────────────────────────────
const SERVO_API = 'https://servo.com.uy/api/support/chat';
const MAX_RETRIES = 20;

// ─── Palabras a bloquear (insensible a mayúsculas) ──────────────────────
const BLOCKED_WORDS = ['servo', 'plataforma', 'marketplace', 'marketplace de servicios'];
const blockedRegex = new RegExp(BLOCKED_WORDS.join('|'), 'i');

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

// ─── AUTH por username + uuid + password ──────────────────────────────────
const _sessCache = new Map();

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

// ─── LLM: llamada a Servo SIN contexto fijo ──────────────────────────────
async function callServo(userMessage, conversationHistory) {
  // conversationHistory: array de { role, content } (mensajes previos)
  // Se envía tal cual, sin añadir ningún prefijo.
  const payload = {
    message: userMessage,
    conversationHistory: conversationHistory || []
  };

  let retries = 0;
  let responseText = '';

  while (retries < MAX_RETRIES) {
    try {
      const response = await fetch(SERVO_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`API de Servo respondió con ${response.status}`);
      }

      const data = await response.json();
      responseText =
        data.reply ||
        data.message ||
        data.content ||
        data.response ||
        JSON.stringify(data);

      // Si NO contiene "servo" (insensible a mayúsculas) → salimos
      if (!/servo/i.test(responseText)) {
        break;
      }

      retries++;
      await new Promise(resolve => setTimeout(resolve, 500));
    } catch (err) {
      console.error('Error en llamada a Servo:', err);
      retries++;
      if (retries >= MAX_RETRIES) {
        responseText = '⚠️ No se pudo obtener una respuesta válida después de varios intentos.';
      }
    }
  }

  return responseText;
}

// ─── Traducción de errores de base de datos ──────────────────────────────
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

    // ─── Lista de conversaciones ──────────────────────────────────────────
    if (action === "ai-chats-list") {
      const rows = await auto(j => sbGet("ai_chats",
        `username=eq.${username}&order=updated_at.desc&select=id,materia,title,last_message,created_at,updated_at,closed_at`, j
      ));
      return res.status(200).json(rows || []);
    }

    // ─── Abrir conversación ──────────────────────────────────────────────
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

    // ─── Finalizar conversación ──────────────────────────────────────────
    if (action === "ai-chat-finish") {
      const { chat_id } = req.body;
      if (!chat_id) return res.status(400).json({ error: "chat_id requerido" });
      await auto(j => sbPatch("ai_chats", `id=eq.${chat_id}&username=eq.${username}`,
        { closed_at: new Date().toISOString() }, j));
      return res.status(200).json({ ok: true });
    }

    // ─── Borrar conversación ─────────────────────────────────────────────
    if (action === "ai-chat-delete") {
      const { chat_id } = req.body;
      if (!chat_id) return res.status(400).json({ error: "chat_id requerido" });
      await auto(j => sbDelete("ai_chat_messages", `chat_id=eq.${chat_id}`, j)).catch(() => null);
      await auto(j => sbDelete("ai_chats", `id=eq.${chat_id}&username=eq.${username}`, j));
      return res.status(200).json({ ok: true });
    }

    // ─── Enviar mensaje (principal) ──────────────────────────────────────
    if (action === "ai-chat") {
      const { chat_id, message } = req.body;

      if (!message) return res.status(400).json({ error: "Falta el mensaje" });

      // ── BLOQUEO en mensaje del usuario ──────────────────────────────────
      if (blockedRegex.test(message)) {
        return res.status(400).json({
          error: "No se permiten preguntas sobre esos temas (servo, plataforma, marketplace, marketplace de servicios)."
        });
      }

      // 1) Resolver o crear la conversación
      let chat;
      if (chat_id) {
        const rows = await auto(j => sbGet("ai_chats", `id=eq.${chat_id}&username=eq.${username}`, j));
        chat = rows && rows[0] ? rows[0] : null;
        if (!chat) return res.status(404).json({ error: "Conversación no encontrada" });
      } else {
        const newChat = {
          id: crypto.randomUUID(),
          user_id: authCtx.user.id,
          username,
          materia: null,
          title: "Nueva conversación",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        };
        const created = await auto(j => sbPost("ai_chats", newChat, j));
        chat = Array.isArray(created) ? created[0] : created;
      }

      // 2) Obtener historial real de la conversación (mensajes anteriores)
      const priorMessages = await auto(j => sbGet("ai_chat_messages",
        `chat_id=eq.${chat.id}&order=created_at.asc&select=role,content`, j
      ));

      // 3) Llamar a Servo con el mensaje y el historial (sin ningún prefijo)
      const replyText = await callServo(message, priorMessages);

      // ── BLOQUEO adicional en respuesta ──────────────────────────────────
      if (blockedRegex.test(replyText)) {
        const fallback = "Lo siento, no puedo responder a esa pregunta porque contiene términos no permitidos.";
        const nowIso = new Date().toISOString();
        // Guardamos el mensaje del usuario y la respuesta de fallback
        await auto(j => sbPost("ai_chat_messages", {
          id: crypto.randomUUID(), chat_id: chat.id, role: "user", content: message, created_at: nowIso,
        }, j));
        await auto(j => sbPost("ai_chat_messages", {
          id: crypto.randomUUID(), chat_id: chat.id, role: "assistant", content: fallback, created_at: nowIso,
        }, j));
        await auto(j => sbPatch("ai_chats", `id=eq.${chat.id}`, {
          updated_at: nowIso, last_message: fallback.slice(0, 140),
        }, j)).catch(() => null);
        return res.status(200).json({ chat_id: chat.id, response: fallback, reply: fallback });
      }

      // 4) Guardar mensaje y respuesta en Supabase
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
