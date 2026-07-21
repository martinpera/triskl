const SUPABASE_URL          = process.env.LINKTR;
const SUPABASE_ANON         = process.env.ANONTR;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;

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

async function sbAdminPost(table, data) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${table}`, {
    method: "POST",
    headers: serviceHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`sbAdminPost ${table}: ${err}`);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : null;
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
// Ahora acepta un `relogin()` opcional: si no hay refresh_token o falla, vuelve
// a loguearse con uuid+password (el nuevo motor de auth).
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

// ─── AUTH por uuid + password ────────────────────────────────────────────────
// Motor de auth: el cliente manda `uuid` (= id del usuario) y `password` en el
// body en CADA request. El server busca el email, hace login contra Supabase y
// usa ese JWT internamente (así siguen valiendo las RLS). Se cachea en memoria
// mientras la lambda esté caliente para no re-loguear en cada llamada.
const _sessCache = new Map(); // key: `${uuid}:${password}` -> { jwt, refreshToken, expiresAt, user }

async function loginByUuidPassword(uuid, password) {
  // Aún no tenemos JWT, así que buscamos el email con service role.
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
    // Se usa desde withAutoRefresh si el JWT cacheado ya venció.
    relogin: async () => {
      const fresh = await loginByUuidPassword(uuid, password).catch(() => null);
      if (fresh) { _sessCache.set(`${uuid}:${password}`, fresh); return fresh.jwt; }
      return null;
    },
  };
}

// Devuelve el contexto de auth, o null si no vinieron username+uuid+password,
// o si el username no coincide con el dueño real de ese uuid.
// TODA acción protegida exige los tres campos (ver PUBLIC_ACTIONS más abajo).
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

// ─── LLM (Anthropic por defecto) ─────────────────────────────────────────────
// Todo el proveedor de IA vive acá. Para cambiar a otro (OpenAI, Groq, etc.)
// tocás SOLO esta función.
const AI_KEY   = process.env.ANTHROPIC_KEY || process.env.CLAUDE_KEY || "";
const AI_MODEL = process.env.AI_MODEL || "claude-sonnet-4-5";

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

// ─── Lógica de negocio ───────────────────────────────────────────────────────
function calcLevel(xp) {
  if (xp < 100)  return 1;
  if (xp < 300)  return 2;
  if (xp < 600)  return 3;
  if (xp < 1000) return 4;
  if (xp < 1500) return 5;
  if (xp < 2100) return 6;
  if (xp < 2800) return 7;
  if (xp < 3600) return 8;
  if (xp < 4500) return 9;
  if (xp < 5500) return 10;
  return Math.max(1, Math.floor((1 + Math.sqrt(1 + 8 * xp / 50)) / 2));
}

function xpForPub(words) {
  return Math.max(5, Math.floor(words / 10));
}

async function grantXP(uid, amount, jwt) {
  const rows = await sbGet("triskl_users", `id=eq.${uid}&select=xp,level,total_words`, jwt).catch(() => []);
  if (!rows || !rows.length) return;
  const curXP    = rows[0].xp || 0;
  const newXP    = curXP + amount;
  const newLevel = calcLevel(newXP);
  await sbPatch("triskl_users", `id=eq.${uid}`, { xp: newXP, level: newLevel }, jwt).catch(() => null);
}

async function ensureUserProfile(uid, email, username, jwt, gen = null) {
  const existing = await sbGet("triskl_users", `id=eq.${uid}`, jwt).catch(() => []);
  if (!existing || existing.length === 0) {
    await sbPost("triskl_users", {
      id: uid,
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      xp: 0, level: 1, streak_days: 0, total_words: 0,
      last_active: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      bio: "", avatar_url: null, gen
    }, jwt);
  } else {
    await sbPatch("triskl_users", `id=eq.${uid}`, { last_active: new Date().toISOString() }, jwt);
    if (gen && existing[0].gen === null) {
      await sbPatch("triskl_users", `id=eq.${uid}`, { gen }, jwt);
    }
  }
}

// Acciones que se ejecutan ANTES de tener sesión (login/registro/health/etc).
// Todo lo demás exige username + uuid + password en el body, siempre.
const PUBLIC_ACTIONS = new Set([
  "login", "register", "verify-otp", "resend-otp", "refresh-token",
  "verify-session", "health", "branding", "sse",
  // "sse" queda público porque es un EventSource nativo del navegador y no
  // puede mandar body con auth; solo expone lo que el propio user_id ya podía ver.
]);

// ─── Handler principal ───────────────────────────────────────────────────────
export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,DELETE,PATCH");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Refresh-Token");
  if (req.method === "OPTIONS") return res.status(204).end();

  const action = req.query.action || (req.body && req.body.action) || "";

  // Motor de auth: username + uuid + password por POST, en TODAS las acciones
  // salvo las de PUBLIC_ACTIONS. Ya no hay fallback a JWT de header (legacy).
  const authCtx = await resolveAuth(req).catch(() => null);

  if (!PUBLIC_ACTIONS.has(action) && (!authCtx || !authCtx.user)) {
    return res.status(401).json({ error: "username, uuid y password son requeridos" });
  }

  const jwt          = authCtx?.jwt          || null;
  const refreshToken = authCtx?.refreshToken || null;
  const relogin      = authCtx?.relogin      || null;

  const auto = (fn) => withAutoRefresh(jwt, refreshToken, fn, relogin);

  try {

    // ========== SSE ==========
    if (action === "sse") {
      const userId = req.query.user_id;
      if (!userId) return res.status(400).json({ error: "user_id requerido" });

      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*"
      });

      let lastCheck = Date.now();
      const interval = setInterval(async () => {
        try {
          const notifs = await sbAdminGet(
            "notifications",
            `user_id=eq.${userId}&created_at=gt.${new Date(lastCheck).toISOString()}&order=created_at.desc&limit=10`
          );
          if (notifs && notifs.length) {
            for (const n of notifs) res.write(`data: ${JSON.stringify(n)}\n\n`);
            lastCheck = Date.now();
          }
        } catch(e) {}
      }, 3000);

      req.on("close", () => clearInterval(interval));
      return;
    }

    // ========== AUTH ==========
    if (action === "login") {
      const { email, password } = req.body;
      if (!email || !password) return res.status(400).json({ error: "email y password requeridos" });

      const { ok, data } = await supabaseAuthPost("/token?grant_type=password", {
        email: email.toLowerCase(), password
      });
      if (!ok) return res.status(401).json({ error: data.error_description || data.msg || "Credenciales incorrectas" });

      const user         = data.user || {};
      const userMetadata = user.user_metadata || {};
      const username     = userMetadata.username || email.split("@")[0];
      const accessJwt    = data.access_token;

      await ensureUserProfile(user.id, user.email, username, accessJwt);
      const userRow  = await sbGet("triskl_users", `id=eq.${user.id}&select=gen`, accessJwt).catch(() => []);
      const userGen  = (userRow && userRow[0]?.gen) || null;

      return res.status(200).json({
        id: user.id, username: username.toLowerCase(), email: user.email,
        jwt: accessJwt, refresh_token: data.refresh_token || "",
        expires_at: data.expires_at || 0, gen: userGen
      });
    }

    if (action === "register") {
      const { email, password, username, gen } = req.body;
      if (!email || !password || !username) return res.status(400).json({ error: "email, password y username requeridos" });

      const currentYear = new Date().getFullYear();
      let yearGen = null;
      if (gen) {
        const genNum = parseInt(gen);
        if (isNaN(genNum) || genNum < 2008 || genNum > currentYear)
          return res.status(400).json({ error: `El año debe estar entre 2008 y ${currentYear}` });
        yearGen = genNum;
      }

      const existingUser = await sbAdminGet("triskl_users", `username=eq.${username.toLowerCase()}`);
      if (existingUser && existingUser.length > 0) return res.status(400).json({ error: "Este nombre de usuario ya está en uso" });

      const signupRes = await supabaseAuthPost("/signup", {
        email: email.toLowerCase(), password,
        data: { username: username.toLowerCase(), gen: yearGen }
      });
      if (!signupRes.ok) return res.status(400).json({
        error: signupRes.data.msg || signupRes.data.error_description || "Error al registrarse",
        needsVerification: false
      });

      const signupUser    = signupRes.data.user || {};
      const emailConfirmed = signupUser.email_confirmed_at || signupUser.confirmed_at;

      if (!emailConfirmed) return res.status(200).json({
        needsVerification: true, email: email.toLowerCase(),
        message: "Se envió un código de verificación a tu email.",
        user_id: signupUser.id, gen: yearGen
      });

      await ensureUserProfile(signupUser.id, signupUser.email, username, null, yearGen);
      return res.status(200).json({
        id: signupUser.id, username: username.toLowerCase(), email: signupUser.email,
        jwt: signupRes.data.access_token, refresh_token: signupRes.data.refresh_token || "",
        expires_at: signupRes.data.expires_at || 0, needsVerification: false, gen: yearGen
      });
    }

    if (action === "verify-otp") {
      const { email, token } = req.body;
      if (!email || !token) return res.status(400).json({ error: "email y token requeridos" });

      const { ok, data } = await supabaseAuthPost("/verify", {
        email: email.toLowerCase(), token, type: "signup"
      });
      if (!ok) return res.status(400).json({ error: data.msg || data.error_description || "Código incorrecto" });

      const user         = data.user || {};
      const userMetadata = user.user_metadata || {};
      const username     = userMetadata.username || email.split("@")[0];
      const gen          = userMetadata.gen || null;
      const accessJwt    = data.access_token;

      await ensureUserProfile(user.id, user.email, username, accessJwt, gen);
      return res.status(200).json({
        id: user.id, username: username.toLowerCase(), email: user.email,
        jwt: accessJwt, refresh_token: data.refresh_token || "",
        expires_at: data.expires_at || 0, gen
      });
    }

    if (action === "resend-otp") {
      const { email } = req.body;
      if (!email) return res.status(400).json({ error: "email requerido" });
      const { ok, data } = await supabaseAuthPost("/otp", { email: email.toLowerCase() });
      if (!ok) return res.status(400).json({ error: data.msg || "Error al reenviar" });
      return res.status(200).json({ ok: true });
    }

    if (action === "verify-session") {
      const { email, password, jwt: existingJwt } = req.body;

      if (existingJwt) {
        const userRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
          headers: { "apikey": SUPABASE_ANON, "Authorization": `Bearer ${existingJwt}` }
        });
        if (userRes.ok) {
          const user         = await userRes.json();
          const userMetadata = user.user_metadata || {};
          const username     = userMetadata.username || user.email.split("@")[0];
          await sbPatch("triskl_users", `id=eq.${user.id}`, { last_active: new Date().toISOString() }, existingJwt);
          const userRow = await sbGet("triskl_users", `id=eq.${user.id}&select=gen`, existingJwt).catch(() => []);
          return res.status(200).json({
            id: user.id, username: username.toLowerCase(), email: user.email,
            jwt: existingJwt, gen: (userRow && userRow[0]?.gen) || null
          });
        }
      }

      if (email && password) {
        const { ok, data } = await supabaseAuthPost("/token?grant_type=password", {
          email: email.toLowerCase(), password
        });
        if (ok) {
          const user      = data.user || {};
          const username  = (user.user_metadata || {}).username || email.split("@")[0];
          const accessJwt = data.access_token;
          await ensureUserProfile(user.id, user.email, username, accessJwt);
          const userRow = await sbGet("triskl_users", `id=eq.${user.id}&select=gen`, accessJwt).catch(() => []);
          return res.status(200).json({
            id: user.id, username: username.toLowerCase(), email: user.email,
            jwt: accessJwt, refresh_token: data.refresh_token || "",
            expires_at: data.expires_at || 0, gen: (userRow && userRow[0]?.gen) || null
          });
        }
      }

      return res.status(401).json({ error: "No autenticado" });
    }

    if (action === "refresh-token") {
      const { refresh_token } = req.body;
      if (!refresh_token) return res.status(400).json({ error: "refresh_token requerido" });

      const { ok, data } = await supabaseAuthPost("/token?grant_type=refresh_token", { refresh_token });
      if (!ok) return res.status(401).json({ error: "No se pudo renovar" });

      return res.status(200).json({
        jwt: data.access_token,
        refresh_token: data.refresh_token || refresh_token,
        expires_at: data.expires_at || 0
      });
    }

    if (action === "change-password") {
      // authCtx ya validó username+uuid+password actuales (si no, 401 arriba).
      const { new_password } = req.body;
      if (!new_password || String(new_password).length < 6) {
        return res.status(400).json({ error: "La nueva contraseña debe tener al menos 6 caracteres" });
      }
      const updRes = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "apikey": SUPABASE_ANON,
          "Authorization": `Bearer ${authCtx.jwt}`,
        },
        body: JSON.stringify({ password: new_password }),
      });
      const updData = await updRes.json().catch(() => ({}));
      if (!updRes.ok) {
        return res.status(400).json({ error: updData.msg || updData.error_description || "No se pudo cambiar la contraseña" });
      }
      // La sesión cacheada con la password vieja queda inválida; se descarta.
      _sessCache.delete(`${req.body.uuid || req.body.user_id || req.body.id}:${req.body.password}`);
      return res.status(200).json({ ok: true });
    }

    // ========== PUSH SUBSCRIPTIONS ==========
    if (action === "check-push-subscription") {
      const user_id = req.query.user_id;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });
      const rows = await sbAdminGet("push_subscriptions", `user_id=eq.${user_id}&select=id&limit=1`).catch(() => []);
      return res.status(200).json({ has_subscription: !!(rows && rows.length) });
    }

    if (action === "save-push-subscription") {
      const { user_id, endpoint, p256dh, auth, device_name } = req.body;
      if (!user_id || !endpoint) return res.status(400).json({ error: "user_id y endpoint requeridos" });
      const existing = await sbAdminGet("push_subscriptions", `endpoint=eq.${encodeURIComponent(endpoint)}`).catch(() => []);
      if (existing?.length) {
        await fetch(`${SUPABASE_URL}/rest/v1/push_subscriptions?endpoint=eq.${encodeURIComponent(endpoint)}`, {
          method: "PATCH", headers: serviceHeaders(),
          body: JSON.stringify({ user_id, p256dh, auth, device_name: device_name || "Dispositivo", updated_at: new Date().toISOString() })
        });
      } else {
        await sbAdminPost("push_subscriptions", {
          user_id, endpoint, p256dh, auth,
          device_name: device_name || "Dispositivo",
          created_at: new Date().toISOString(), updated_at: new Date().toISOString()
        });
      }
      return res.status(200).json({ ok: true });
    }

    if (action === "remove-push-subscription") {
      const { user_id, endpoint } = req.body;
      if (!user_id || !endpoint) return res.status(400).json({ error: "user_id y endpoint requeridos" });
      await fetch(`${SUPABASE_URL}/rest/v1/push_subscriptions?user_id=eq.${user_id}&endpoint=eq.${encodeURIComponent(endpoint)}`,
        { method: "DELETE", headers: serviceHeaders() });
      return res.status(200).json({ ok: true });
    }

    if (action === "push-devices") {
      const { user_id } = req.query;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });
      const rows = await sbAdminGet(
        "push_subscriptions",
        `user_id=eq.${user_id}&select=id,endpoint,device_name,created_at,updated_at`
      ).catch(() => []);
      return res.status(200).json(rows || []);
    }

    if (action === "push-delete-device") {
      const { sub_id, user_id } = req.body;
      if (!sub_id || !user_id) return res.status(400).json({ error: "sub_id y user_id requeridos" });
      await fetch(
        `${SUPABASE_URL}/rest/v1/push_subscriptions?id=eq.${sub_id}&user_id=eq.${user_id}`,
        { method: "DELETE", headers: serviceHeaders() }
      );
      return res.status(200).json({ ok: true });
    }

    // ========== FEED PAGINADO (cursor por created_at) — para el HTML nuevo ==========
    if (action === "feed") {
      const scope  = req.query.scope || "gen";                 // gen | friends | mine
      const limit  = Math.min(parseInt(req.query.limit || "20", 10) || 20, 50);
      const before = req.query.before || null;

      // Identificar al viewer (mismo criterio que "publications")
      let viewerId = null, viewerGen = null;
      if (jwt) {
        const userInfo = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
          headers: { "apikey": SUPABASE_ANON, "Authorization": `Bearer ${jwt}` }
        }).then(r => r.json()).catch(() => ({}));
        if (userInfo.id) {
          viewerId = userInfo.id;
          const userRow = await auto(j => sbGet("triskl_users", `id=eq.${userInfo.id}&select=gen`, j)).catch(() => []);
          viewerGen = (userRow && userRow[0]?.gen) || null;
        }
      }
      if (!viewerId) return res.status(401).json({ error: "No autenticado" });
      const viewerKey = viewerGen === null ? 2009 : viewerGen;

      const EMBED = "user:user_id(id,username,avatar_url,xp,level,gen)";

      // Filtro base según el scope
      let filter;
      if (scope === "mine") {
        filter = `user_id=eq.${viewerId}&visibility=eq.private`;
      } else if (scope === "friends") {
        const [fo, fr] = await Promise.all([
          auto(j => sbGet("follows", `follower_id=eq.${viewerId}&select=followed_id`, j)).catch(() => []),
          auto(j => sbGet("follows", `followed_id=eq.${viewerId}&select=follower_id`,  j)).catch(() => []),
        ]);
        const following = new Set((fo || []).map(r => r.followed_id).filter(Boolean));
        const friends   = (fr || []).map(r => r.follower_id).filter(id => id && following.has(id));
        const ids = [...new Set([...friends, viewerId])];
        filter = `user_id=in.(${ids.join(",")})&or=(visibility.eq.todos,visibility.eq.friends)`;
      } else {
        filter = `visibility=eq.todos`;
      }

      // Paginación por cursor sobre created_at; filtro de gen en memoria (como publications)
      const RAW      = limit + 15;
      const items    = [];
      let   lastSeen = before;   // created_at de la ULTIMA fila mirada
      let   hasMore  = true;

      for (let i = 0; i < 8 && items.length < limit; i++) {
        let params = `${filter}&order=created_at.desc&limit=${RAW}&select=*,${EMBED}`;
        if (lastSeen) params += `&created_at=lt.${encodeURIComponent(lastSeen)}`;

        const rows = await auto(j => sbGet("publications", params, j));
        if (!rows || !rows.length) { hasMore = false; break; }
        const fullBatch = rows.length === RAW;

        for (const p of rows) {
          lastSeen = p.created_at;
          if (scope === "gen" && p.user_id !== viewerId) {
            const authorKey = (p.user?.gen === null || p.user?.gen === undefined) ? 2009 : p.user.gen;
            if (authorKey !== viewerKey) continue;
          }
          items.push(p);
          if (items.length >= limit) break;
        }

        if (items.length >= limit) break;
        if (!fullBatch) { hasMore = false; break; }
      }

      return res.status(200).json({ items, next_cursor: lastSeen, has_more: hasMore });
    }

    // Media (base64) de un lote de posts. El feed la pide aparte para pintar el texto ya.
    if (action === "feed-media") {
      const ids = String(req.query.ids || "").split(",").map(x => x.trim()).filter(Boolean);
      if (!ids.length) return res.status(200).json([]);
      const rows = await auto(j => sbGet("publications",
        `id=in.(${ids.join(",")})&select=id,media`, j)).catch(() => []);
      return res.status(200).json((rows || []).filter(r => r.media));
    }

    // ========== PUBLICACIONES ==========
    if (action === "publications") {
      const uid   = req.query.user_id;
      const vis   = req.query.visibility;
      const order = req.query.order || "created_at.desc";
      let params  = `order=${order}&select=*,user:user_id(id,username,avatar_url,xp,level,gen)`;

      if (uid) params += `&user_id=eq.${uid}`;

      if (vis && vis !== "undefined") {
        if (vis.includes(",")) {
          const orC = vis.split(",").map(v => `visibility.eq.${v}`).join(",");
          params += `&or=(${orC})`;
        } else {
          params += `&visibility=eq.${vis}`;
        }
      }
      else if (!uid) {
        params += `&visibility=eq.todos`;
      }
      else if (uid && (!vis || vis === "undefined")) {
        params += `&or=(visibility.eq.todos,visibility.eq.friends)`;
      }

      let rows = await auto(j => sbGet("publications", params, j));

      let viewerGen = null, viewerId = null;
      if (jwt) {
        const userInfo = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
          headers: { "apikey": SUPABASE_ANON, "Authorization": `Bearer ${jwt}` }
        }).then(r => r.json()).catch(() => ({}));
        if (userInfo.id) {
          viewerId = userInfo.id;
          const userRow = await auto(j => sbGet("triskl_users", `id=eq.${userInfo.id}&select=gen`, j)).catch(() => []);
          viewerGen = (userRow && userRow[0]?.gen) || null;
        }
      }

      const viewerKey = viewerGen === null ? 2009 : viewerGen;
      rows = (rows || []).filter(post => {
        if (post.user_id === viewerId) return true;
        const authorKey = (post.user?.gen === null || post.user?.gen === undefined) ? 2009 : post.user.gen;
        return authorKey === viewerKey;
      });

      return res.status(200).json(rows || []);
    }

    if (action === "publish") {
      const { session_id, title, content, visibility, post_type, username, user_id, materia, poll_options, poll_votes, poll_voters, poll_anonymous, media } = req.body;
      const payload = {
        user_id, username, title,
        materia: materia || title,
        content, visibility: visibility || "todos",
        post_type: post_type || "transcripcion",
        created_at: new Date().toISOString(),
      };
      if (session_id)            payload.session_id    = session_id;
      if (poll_options)          payload.poll_options  = poll_options;
      if (poll_votes)            payload.poll_votes    = poll_votes;
      if (poll_voters)           payload.poll_voters   = poll_voters;
      if (poll_anonymous !== undefined) payload.poll_anonymous = poll_anonymous;
      if (media)                 payload.media         = media;

      const result = await auto(j => sbPost("publications", payload, j));

      if (post_type === "transcripcion" && user_id && content && !content.startsWith("!!POST!!")) {
        const words = content.split(/\s+/).filter(Boolean).length;
        await auto(j => grantXP(user_id, xpForPub(words), j)).catch(() => null);
        const userRows = await auto(j => sbGet("triskl_users", `id=eq.${user_id}&select=total_words`, j)).catch(() => []);
        if (userRows && userRows.length) {
          const newTotal = (userRows[0].total_words || 0) + words;
          await auto(j => sbPatch("triskl_users", `id=eq.${user_id}`, { total_words: newTotal }, j)).catch(() => null);
        }
      }

      const pub = Array.isArray(result) ? result[0] : result;
      return res.status(200).json({ ok: true, id: pub?.id });
    }

    if (action === "delete-publication") {
      const { pub_id, user_id } = req.body;
      if (!pub_id) return res.status(400).json({ error: "pub_id requerido" });

      const pid = parseInt(pub_id, 10);
      if (isNaN(pid)) return res.status(400).json({ error: "pub_id inválido" });

      await auto(j => sbDelete("comments", `publication_id=eq.${pid}`, j)).catch(() => null);
      await auto(j => sbDelete("notifications", `pub_id=eq.${pid}`, j)).catch(() => null);
      await auto(j => sbDelete("publications", `id=eq.${pid}&user_id=eq.${user_id}`, j));

      return res.status(200).json({ ok: true });
    }

    if (action === "vote-poll") {
      const { pub_id, option, user_id } = req.body;
      if (!pub_id || !option || !user_id) return res.status(400).json({ error: "pub_id, option, user_id requeridos" });

      const rows = await auto(j => sbGet("publications", `id=eq.${pub_id}&select=poll_votes,poll_voters`, j));
      if (!rows || !rows.length) return res.status(404).json({ error: "Publicación no encontrada" });

      let votes = {}, voters = [];
      try { votes  = JSON.parse(rows[0].poll_votes  || "{}"); } catch(_) {}
      try { voters = JSON.parse(rows[0].poll_voters || "[]"); } catch(_) {}
      if (voters.includes(user_id)) return res.status(400).json({ error: "Ya votaste" });

      votes[option] = (votes[option] || 0) + 1;
      voters.push(user_id);
      await auto(j => sbPatch("publications", `id=eq.${pub_id}`, {
        poll_votes: JSON.stringify(votes), poll_voters: JSON.stringify(voters)
      }, j));
      return res.status(200).json({ ok: true });
    }

    // ========== COMENTARIOS ==========
    if (action === "comments") {
      const pub_id = req.query.publication_id;
      if (!pub_id) return res.status(400).json({ error: "publication_id requerido" });
      const rows = await auto(j => sbGet("comments", `publication_id=eq.${pub_id}&order=created_at.asc&select=*,user:user_id(id,username,avatar_url)`, j));
      return res.status(200).json(rows || []);
    }

    if (action === "add-comment") {
      const { publication_id, user_id, username, content } = req.body;
      if (!publication_id || !content) return res.status(400).json({ error: "publication_id y content requeridos" });

      await auto(j => sbPost("comments", { publication_id, user_id, username, content, created_at: new Date().toISOString() }, j));

      const pubRows = await auto(j => sbGet("publications", `id=eq.${publication_id}&select=comments_count,user_id,username`, j)).catch(() => []);
      if (pubRows && pubRows.length) {
        const newCount = (pubRows[0].comments_count || 0) + 1;
        await auto(j => sbPatch("publications", `id=eq.${publication_id}`, { comments_count: newCount }, j)).catch(() => null);
        if (pubRows[0].user_id !== user_id) {
          await auto(j => sbPost("notifications", {
            user_id: pubRows[0].user_id, from_uid: user_id, from_uname: username,
            type: "comment", pub_id: publication_id,
            content: `@${username} comentó en tu publicación`,
            read: false, created_at: new Date().toISOString()
          }, j)).catch(() => null);
        }
      }
      return res.status(200).json({ ok: true });
    }

    if (action === "delete-comment") {
      const { comment_id, user_id } = req.body;
      if (!comment_id) return res.status(400).json({ error: "comment_id requerido" });
      await auto(j => sbDelete("comments", `id=eq.${comment_id}&user_id=eq.${user_id}`, j));
      return res.status(200).json({ ok: true });
    }

    // ========== SEGUIDORES ==========
    if (action === "follows") {
      const follower_id = req.query.follower_id;
      const params = follower_id ? `follower_id=eq.${follower_id}` : "";
      const rows   = await auto(j => sbGet("follows", params, j));
      return res.status(200).json(rows || []);
    }

    if (action === "followers") {
      const user_id = req.query.user_id;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });
      const rows = await auto(j => sbGet("follows", `followed_id=eq.${user_id}&select=follower_id`, j));
      if (!rows || !rows.length) return res.status(200).json([]);
      const ids  = rows.map(r => r.follower_id).filter(Boolean);
      if (!ids.length) return res.status(200).json([]);
      const users = await auto(j => sbGet("triskl_users", `id=in.(${ids.join(",")})&select=id,username,bio,xp,level,avatar_url,total_words,streak_days,gen`, j));
      return res.status(200).json(users || []);
    }

    if (action === "following") {
      const user_id = req.query.user_id;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });
      const rows = await auto(j => sbGet("follows", `follower_id=eq.${user_id}&select=followed_id`, j));
      if (!rows || !rows.length) return res.status(200).json([]);
      const ids  = rows.map(r => r.followed_id).filter(Boolean);
      if (!ids.length) return res.status(200).json([]);
      const users = await auto(j => sbGet("triskl_users", `id=in.(${ids.join(",")})&select=id,username,bio,xp,level,avatar_url,total_words,streak_days,gen`, j));
      return res.status(200).json(users || []);
    }

    if (action === "follow") {
      const { follower_id, followed_id } = req.body;
      if (!follower_id || !followed_id) return res.status(400).json({ error: "follower_id y followed_id requeridos" });

      const existing = await auto(j => sbGet("follows", `follower_id=eq.${follower_id}&followed_id=eq.${followed_id}`, j)).catch(() => []);
      if (!existing || !existing.length) {
        await auto(j => sbPost("follows", { follower_id, followed_id, created_at: new Date().toISOString() }, j));
        const followerUser = await auto(j => sbGet("triskl_users", `id=eq.${follower_id}&select=username`, j)).catch(() => []);
        const followerName = (followerUser && followerUser[0]?.username) || follower_id;
        await auto(j => sbPost("notifications", {
          user_id: followed_id, from_uid: follower_id, from_uname: followerName,
          type: "follow", content: `@${followerName} te empezó a seguir`,
          read: false, created_at: new Date().toISOString()
        }, j)).catch(() => null);
      }
      return res.status(200).json({ ok: true });
    }

    if (action === "unfollow") {
      const { follower_id, followed_id } = req.body;
      await auto(j => sbDelete("follows", `follower_id=eq.${follower_id}&followed_id=eq.${followed_id}`, j));
      return res.status(200).json({ ok: true });
    }

    // ========== MENSAJES DIRECTOS ==========
    if (action === "dms") {
      const sender_id   = req.query.sender_id;
      const receiver_id = req.query.receiver_id;
      let params        = "order=created_at.asc";
      if (sender_id)   params += `&sender_id=eq.${sender_id}`;
      if (receiver_id) params += `&receiver_id=eq.${receiver_id}`;
      const rows = await auto(j => sbGet("direct_messages", params, j));
      return res.status(200).json(rows || []);
    }

    if (action === "send-dm") {
      const { sender_id, sender_uname, receiver_id, receiver_uname, content, attached_transcript, media, reply_to } = req.body;
      if (!sender_id || !receiver_id || !content) return res.status(400).json({ error: "sender_id, receiver_id y content requeridos" });

      const payload = { sender_id, sender_uname, receiver_id, receiver_uname, content, created_at: new Date().toISOString() };
      if (attached_transcript) payload.attached_transcript = attached_transcript;
      if (media)               payload.media               = media;
      if (reply_to)            payload.reply_to            = reply_to;

      await auto(j => sbPost("direct_messages", payload, j));

      // ── Notificación con contenido real del mensaje ──
      const notifBody = content.startsWith('📎')
        ? `@${sender_uname} te envió un archivo`
        : `@${sender_uname}: ${content.slice(0, 100)}`;

      await auto(j => sbPost("notifications", {
        user_id: receiver_id,
        from_uid: sender_id,
        from_uname: sender_uname,
        type: "dm",
        content: notifBody,
        read: false,
        created_at: new Date().toISOString()
      }, j)).catch(() => null);

      return res.status(200).json({ ok: true });
    }

    if (action === "delete-message") {
      const { message_id, type } = req.body;
      if (!message_id || !type) return res.status(400).json({ error: "message_id y type requeridos" });
      if (type === "dm") {
        await auto(j => sbPatch("direct_messages", `id=eq.${message_id}`, { deleted: true }, j));
      } else if (type === "group") {
        await auto(j => sbPatch("group_messages",  `id=eq.${message_id}`, { deleted: true }, j));
      } else {
        return res.status(400).json({ error: "type debe ser 'dm' o 'group'" });
      }
      return res.status(200).json({ ok: true });
    }

    if (action === "reply-to-message") {
      const { message_id, type, content, sender_id, sender_uname, receiver_id, group_id } = req.body;
      if (!message_id || !type || !content || !sender_id) return res.status(400).json({ error: "Faltan campos requeridos" });
      if (type === "dm") {
        if (!receiver_id) return res.status(400).json({ error: "receiver_id requerido" });
        await auto(j => sbPost("direct_messages", { sender_id, sender_uname, receiver_id, content, reply_to: message_id, created_at: new Date().toISOString() }, j));
      } else if (type === "group") {
        if (!group_id) return res.status(400).json({ error: "group_id requerido" });
        await auto(j => sbPost("group_messages", { group_id, sender_id, sender_uname, content, reply_to: message_id, created_at: new Date().toISOString() }, j));
      } else {
        return res.status(400).json({ error: "type debe ser 'dm' o 'group'" });
      }
      return res.status(200).json({ ok: true });
    }

    // ========== GRUPOS ==========
    if (action === "create-group") {
      const { name, creator_id, creator_uname, avatar_url } = req.body;
      if (!name || !creator_id) return res.status(400).json({ error: "name y creator_id requeridos" });

      const groupResult = await auto(j => sbPost("groups", { name, creator_id, avatar_url, created_at: new Date().toISOString() }, j));
      const group       = Array.isArray(groupResult) ? groupResult[0] : groupResult;
      if (!group?.id) return res.status(500).json({ error: "No se pudo crear el grupo" });

      await auto(j => sbPost("group_members", {
        group_id: group.id, user_id: creator_id,
        username: creator_uname || creator_id, joined_at: new Date().toISOString()
      }, j));
      return res.status(200).json({ ok: true, id: group.id });
    }

    if (action === "my-groups") {
      const user_id = req.query.user_id;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });

      const memberships = await auto(j => sbGet("group_members", `user_id=eq.${user_id}&select=group_id`, j)).catch(() => []);
      if (!memberships || !memberships.length) return res.status(200).json([]);
      const groupIds = memberships.map(m => m.group_id).filter(Boolean);
      if (!groupIds.length) return res.status(200).json([]);

      const groups = await auto(j => sbGet("groups", `id=in.(${groupIds.join(",")})&order=created_at.desc`, j));
      if (!groups || !groups.length) return res.status(200).json([]);

      const result = await Promise.all(groups.map(async g => {
        const mems = await auto(j => sbGet("group_members", `group_id=eq.${g.id}&select=user_id`, j)).catch(() => []);
        return { ...g, member_count: mems?.length || 0 };
      }));
      return res.status(200).json(result);
    }

    if (action === "group-members") {
      const group_id = req.query.group_id;
      if (!group_id) return res.status(400).json({ error: "group_id requerido" });
      const rows = await auto(j => sbGet("group_members", `group_id=eq.${group_id}&order=joined_at.asc`, j));
      return res.status(200).json(rows || []);
    }

    if (action === "add-group-member") {
      const { group_id, user_id, username } = req.body;
      if (!group_id || !user_id) return res.status(400).json({ error: "group_id y user_id requeridos" });

      const existing = await auto(j => sbGet("group_members", `group_id=eq.${group_id}&user_id=eq.${user_id}`, j)).catch(() => []);
      if (existing && existing.length) return res.status(400).json({ error: "Ya es miembro del grupo" });

      await auto(j => sbPost("group_members", { group_id, user_id, username: username || user_id, joined_at: new Date().toISOString() }, j));
      return res.status(200).json({ ok: true });
    }

    if (action === "remove-group-member") {
      const { group_id, user_id } = req.body;
      if (!group_id || !user_id) return res.status(400).json({ error: "group_id y user_id requeridos" });

      await auto(j => sbDelete("group_members", `group_id=eq.${group_id}&user_id=eq.${user_id}`, j));
      const remaining = await auto(j => sbGet("group_members", `group_id=eq.${group_id}&select=user_id`, j)).catch(() => []);
      if (!remaining || !remaining.length) {
        await auto(j => sbDelete("group_messages", `group_id=eq.${group_id}`, j)).catch(() => null);
        await auto(j => sbDelete("groups",         `id=eq.${group_id}`,       j)).catch(() => null);
      }
      return res.status(200).json({ ok: true });
    }

    if (action === "group-messages") {
      const group_id = req.query.group_id;
      if (!group_id) return res.status(400).json({ error: "group_id requerido" });
      const rows = await auto(j => sbGet("group_messages", `group_id=eq.${group_id}&order=created_at.asc`, j));
      return res.status(200).json(rows || []);
    }

    if (action === "send-group-message") {
      const { group_id, sender_id, sender_uname, content, attached_transcript, media, poll_data, reply_to } = req.body;
      if (!group_id || !sender_id || !content) return res.status(400).json({ error: "group_id, sender_id y content requeridos" });

      const membership = await auto(j => sbGet("group_members", `group_id=eq.${group_id}&user_id=eq.${sender_id}`, j)).catch(() => []);
      if (!membership || !membership.length) return res.status(403).json({ error: "No sos miembro de este grupo" });

      const payload = { group_id, sender_id, sender_uname: sender_uname || sender_id, content, created_at: new Date().toISOString() };
      if (attached_transcript) payload.attached_transcript = attached_transcript;
      if (media)               payload.media               = media;
      if (poll_data)           payload.poll_data           = poll_data;
      if (reply_to)            payload.reply_to            = reply_to;

      await auto(j => sbPost("group_messages", payload, j));
      return res.status(200).json({ ok: true });
    }

    if (action === "vote-chat-poll") {
      const { message_id, option, user_id } = req.body;
      if (!message_id || !option || !user_id) return res.status(400).json({ error: "message_id, option, user_id requeridos" });

      const rows = await auto(j => sbGet("group_messages", `id=eq.${message_id}&select=poll_data`, j));
      if (!rows || !rows.length) return res.status(404).json({ error: "Mensaje no encontrado" });

      let poll = null;
      try { poll = typeof rows[0].poll_data === "string" ? JSON.parse(rows[0].poll_data) : rows[0].poll_data; } catch(_) {}
      if (!poll?.question) return res.status(400).json({ error: "No es una encuesta" });

      if (!poll.votes)  poll.votes  = {};
      if (!poll.voters) poll.voters = [];
      if (poll.voters.includes(user_id)) return res.status(400).json({ error: "Ya votaste" });

      poll.votes[option] = (poll.votes[option] || 0) + 1;
      poll.voters.push(user_id);
      await auto(j => sbPatch("group_messages", `id=eq.${message_id}`, { poll_data: JSON.stringify(poll) }, j));
      return res.status(200).json({ ok: true });
    }

    if (action === "update-group-avatar") {
      const { group_id, avatar_url } = req.body;
      if (!group_id) return res.status(400).json({ error: "group_id requerido" });
      await auto(j => sbPatch("groups", `id=eq.${group_id}`, { avatar_url }, j));
      return res.status(200).json({ ok: true });
    }

    if (action === "group-detail") {
      const id = req.query.id;
      if (!id) return res.status(400).json({ error: "id requerido" });
      const rows = await auto(j => sbGet("groups", `id=eq.${id}`, j));
      return res.status(200).json(rows?.[0] || null);
    }

    // ========== NOTIFICACIONES ==========
    if (action === "notifications") {
      const user_id = req.query.user_id;
      const unread  = req.query.unread;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });

      let params = `user_id=eq.${user_id}&order=created_at.desc&limit=50`;
      if (unread === "1") params += `&read=eq.false`;

      const rows = await auto(j => sbGet("notifications", params, j));
      return res.status(200).json(rows || []);
    }

    if (action === "mark-notif-read") {
      const { notif_id } = req.body;
      if (!notif_id) return res.status(400).json({ error: "notif_id requerido" });
      await auto(j => sbPatch("notifications", `id=eq.${notif_id}`, { read: true }, j));
      return res.status(200).json({ ok: true });
    }

    if (action === "mark-all-notifs-read") {
      const { user_id } = req.body;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });
      const rows = await auto(j => sbGet("notifications", `user_id=eq.${user_id}&read=eq.false&select=id`, j)).catch(() => []);
      for (const n of (rows || [])) {
        await auto(j => sbPatch("notifications", `id=eq.${n.id}`, { read: true }, j)).catch(() => null);
      }
      return res.status(200).json({ ok: true });
    }

    if (action === "mark-dm-notifications-read") {
      const { user_id, partner_id } = req.body;
      if (!user_id || !partner_id) return res.status(400).json({ error: "user_id y partner_id requeridos" });
      await auto(j => sbPatch("notifications",
        `user_id=eq.${user_id}&from_uid=eq.${partner_id}&type=eq.dm&read=eq.false`,
        { read: true }, j)).catch(() => null);
      return res.status(200).json({ ok: true });
    }

    if (action === "mark-group-notifications-read") {
      const { user_id, group_id } = req.body;
      if (!user_id || !group_id) return res.status(400).json({ error: "user_id y group_id requeridos" });
      await auto(j => sbPatch("notifications",
        `user_id=eq.${user_id}&group_id=eq.${group_id}&type=eq.group_message&read=eq.false`,
        { read: true }, j)).catch(() => null);
      return res.status(200).json({ ok: true });
    }

    if (action === "unread-dms") {
      const user_id = req.query.user_id;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });
      const rows = await auto(j => sbGet("notifications",
        `user_id=eq.${user_id}&type=eq.dm&read=eq.false&select=from_uid`, j)).catch(() => []);
      const uniquePartners = [...new Set((rows || []).map(r => r.from_uid).filter(Boolean))];
      return res.status(200).json(uniquePartners);
    }

    if (action === "unread-group-messages") {
      const user_id = req.query.user_id;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });
      const rows = await auto(j => sbGet("notifications",
        `user_id=eq.${user_id}&type=eq.group_message&read=eq.false&select=group_id`, j)).catch(() => []);
      const uniqueGroups = [...new Set((rows || []).map(r => r.group_id).filter(Boolean))];
      return res.status(200).json(uniqueGroups);
    }

    // ========== EVENTOS ==========
    if (action === "events") {
      const user_id = req.query.user_id;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });
      const rows = await auto(j => sbGet("triskl_events", `user_id=eq.${user_id}&order=due_date.asc`, j));
      return res.status(200).json(rows || []);
    }

    if (action === "create-event") {
      const { user_id, username, type, materia, title, notes, due_date } = req.body;
      if (!user_id || !type || !materia || !title || !due_date) return res.status(400).json({ error: "Faltan campos requeridos" });
      const result = await auto(j => sbPost("triskl_events", {
        user_id, username: username || "", type, materia, title,
        notes: notes || "", due_date, done: false, snoozed: false,
        created_at: new Date().toISOString()
      }, j));

      const followers = await auto(j => sbGet("follows", `followed_id=eq.${user_id}&select=follower_id`, j)).catch(() => []);
      for (const f of (followers || [])) {
        await auto(j => sbPost("notifications", {
          user_id: f.follower_id, from_uid: user_id, from_uname: username,
          type: "event", content: `📅 ${title} - ${materia} (${due_date})`,
          read: false, created_at: new Date().toISOString()
        }, j)).catch(() => null);
      }

      return res.status(200).json({ ok: true, event: Array.isArray(result) ? result[0] : result });
    }

    if (action === "update-event") {
      const { event_id, user_id, ...fields } = req.body;
      if (!event_id || !user_id) return res.status(400).json({ error: "event_id y user_id requeridos" });
      await auto(j => sbPatch("triskl_events", `id=eq.${event_id}&user_id=eq.${user_id}`, fields, j));
      return res.status(200).json({ ok: true });
    }

    if (action === "delete-event") {
      const { event_id, user_id } = req.body;
      if (!event_id || !user_id) return res.status(400).json({ error: "event_id y user_id requeridos" });
      await auto(j => sbDelete("triskl_events", `id=eq.${event_id}&user_id=eq.${user_id}`, j));
      return res.status(200).json({ ok: true });
    }

    if (action === "upcoming-events") {
      const user_id = req.query.user_id || (req.body && req.body.user_id);
      const days    = parseInt(req.query.days || "7");
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });

      const today = new Date(); today.setHours(0,0,0,0);
      const limit = new Date(today); limit.setDate(limit.getDate() + days);
      const todayStr = today.toISOString().slice(0,10);
      const limitStr = limit.toISOString().slice(0,10);

      const rows = await auto(j => sbGet("triskl_events",
        `user_id=eq.${user_id}&done=eq.false&due_date=gte.${todayStr}&due_date=lte.${limitStr}&order=due_date.asc`, j));

      const active = (rows || []).filter(r => {
        if (r.done) return false;
        if (!r.snoozed || !r.snooze_until) return true;
        return r.snooze_until < todayStr;
      });
      return res.status(200).json(active);
    }

    // ========== PERFILES ==========
    if (action === "user-profile") {
      const user_id = req.query.user_id;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });
      const rows = await auto(j => sbGet("triskl_users", `id=eq.${user_id}`, j));
      return res.status(200).json(rows || []);
    }

    if (action === "update-user-stats") {
      const { user_id, total_words, xp, level, streak_days, bio, avatar_url } = req.body;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });

      const update = { updated_at: new Date().toISOString() };
      if (total_words  !== undefined) update.total_words  = total_words;
      if (xp           !== undefined) update.xp           = xp;
      if (level        !== undefined) update.level        = level;
      if (streak_days  !== undefined) update.streak_days  = streak_days;
      if (bio          !== undefined) update.bio          = bio;
      if (avatar_url   !== undefined) update.avatar_url   = avatar_url;

      await auto(j => sbPatch("triskl_users", `id=eq.${user_id}`, update, j));

      if (xp !== undefined) {
        const correctLevel = calcLevel(xp);
        if (correctLevel !== level) {
          await auto(j => sbPatch("triskl_users", `id=eq.${user_id}`, { level: correctLevel }, j));
        }
      }
      return res.status(200).json({ ok: true });
    }

    if (action === "update-bio") {
      const { user_id, bio, avatar_url } = req.body;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });

      const updateData = { updated_at: new Date().toISOString() };
      if (bio        !== undefined) updateData.bio        = bio;
      if (avatar_url !== undefined) updateData.avatar_url = avatar_url;
      if (Object.keys(updateData).length === 1) return res.status(400).json({ error: "No se proporcionaron campos para actualizar" });

      await auto(j => sbPatch("triskl_users", `id=eq.${user_id}`, updateData, j));
      return res.status(200).json({ ok: true });
    }

    if (action === "search-users") {
      const q = req.query.q || "";
      if (!q) return res.status(200).json([]);
      const rows = await auto(j => sbGet("triskl_users",
        `username=ilike.*${encodeURIComponent(q)}*&select=id,username,xp,level,bio,avatar_url,total_words,streak_days,gen`, j));
      return res.status(200).json(rows || []);
    }

    if (action === "leaderboard") {
      const rows = await auto(j => sbGet("triskl_users",
        "order=xp.desc&limit=20&select=id,username,xp,level,streak_days,total_words,avatar_url,gen", j));
      return res.status(200).json(rows || []);
    }

    if (action === "recalc-level") {
      const { user_id } = req.body;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });
      const rows = await auto(j => sbGet("triskl_users", `id=eq.${user_id}&select=xp,level`, j));
      if (!rows || !rows.length) return res.status(404).json({ error: "Usuario no encontrado" });

      const curXP        = rows[0].xp || 0;
      const correctLevel = calcLevel(curXP);
      const curLevel     = rows[0].level || 1;
      if (curLevel !== correctLevel) {
        await auto(j => sbPatch("triskl_users", `id=eq.${user_id}`, { level: correctLevel }, j));
        return res.status(200).json({ fixed: true, oldLevel: curLevel, newLevel: correctLevel });
      }
      return res.status(200).json({ fixed: false, level: curLevel });
    }

    // ========== SESIONES Y SEGMENTOS ==========
    if (action === "sessions") {
      const username = req.query.username || (req.body && req.body.username);
      if (!username) return res.status(400).json({ error: "username requerido" });
      const sessions = await auto(j => sbGet("sessions", `username=eq.${username}&order=started_at.desc`, j));
      return res.status(200).json(sessions || []);
    }

    if (action === "segments") {
      const session_id = req.query.session_id || (req.body && req.body.session_id);
      if (!session_id) return res.status(400).json({ error: "session_id requerido" });
      const segments = await auto(j => sbGet("segments", `session_id=eq.${session_id}&order=recorded_at.asc&select=id,text,recorded_at`, j));
      return res.status(200).json(segments || []);
    }

    if (action === "new-session") {
      const { session_id, materia, username, langs, file_path } = req.body;
      const payload = {
        id: session_id,
        materia: materia || "Sin materia",
        started_at: new Date().toISOString(),
        langs: langs || ["es"],
        file_path: file_path || ""
      };
      if (username) payload.username = username;
      const result = await auto(j => sbPost("sessions", payload, j));
      return res.status(200).json(result);
    }

    if (action === "resume-or-new-session") {
      const { materia, username, langs } = req.body;
      if (!username || !materia) return res.status(400).json({ error: "username y materia requeridos" });

      const open = await auto(j => sbGet("sessions",
        `username=eq.${username}&materia=eq.${encodeURIComponent(materia)}&ended_at=is.null&order=started_at.desc&limit=1`, j)).catch(() => []);

      if (open && open.length > 0) {
        const segs = await auto(j => sbGet("segments", `session_id=eq.${open[0].id}&order=recorded_at.asc&select=id,text,recorded_at`, j)).catch(() => []);
        return res.status(200).json({ session_id: open[0].id, resumed: true, segments: segs || [] });
      }

      const session_id = crypto.randomUUID();
      const payload    = { id: session_id, materia, started_at: new Date().toISOString(), langs: langs || ["es"], file_path: "", username };
      await auto(j => sbPost("sessions", payload, j));
      return res.status(200).json({ session_id, resumed: false, segments: [] });
    }

    if (action === "close-session") {
      const { session_id } = req.body;
      if (!session_id) return res.status(400).json({ error: "session_id requerido" });
      await auto(j => sbPatch("sessions", `id=eq.${session_id}`, { ended_at: new Date().toISOString() }, j));
      return res.status(200).json({ ok: true });
    }

    if (action === "push-segment") {
      const { segment_id, session_id, materia, text, username } = req.body;
      const payload = {
        id: segment_id, session_id,
        materia: materia || "Sin materia",
        text, recorded_at: new Date().toISOString(),
      };
      if (username) payload.username = username;

      const result = await auto(j => sbPost("segments", payload, j));

      if (username) {
        const userRows = await auto(j => sbGet("triskl_users", `username=eq.${username}&select=id,total_words`, j)).catch(() => []);
        if (userRows && userRows.length) {
          const words    = text.split(/\s+/).filter(Boolean).length;
          await auto(j => grantXP(userRows[0].id, xpForPub(words), j)).catch(() => null);
          const newTotal = (userRows[0].total_words || 0) + words;
          await auto(j => sbPatch("triskl_users", `id=eq.${userRows[0].id}`, { total_words: newTotal }, j)).catch(() => null);
        }
      }

      return res.status(200).json(result);
    }

    if (action === "delete-session") {
      const { session_id } = req.body;
      if (!session_id) return res.status(400).json({ error: "session_id requerido" });
      await auto(j => sbDelete("sessions", `id=eq.${session_id}`, j));
      return res.status(200).json({ ok: true });
    }

    if (action === "delete-session-segments") {
      const { session_id } = req.body;
      if (!session_id) return res.status(400).json({ error: "session_id requerido" });
      await auto(j => sbDelete("segments", `session_id=eq.${session_id}`, j));
      return res.status(200).json({ ok: true });
    }

    // ========== ANOTACIONES (notas / esquemas / respuestas IA) ==========
    if (action === "annotations") {
      const user_id = req.query.user_id;
      const materia = req.query.materia;
      if (!user_id || !materia) return res.status(400).json({ error: "user_id y materia requeridos" });
      const rows = await auto(j => sbGet("annotations",
        `user_id=eq.${user_id}&materia=eq.${encodeURIComponent(materia)}&order=created_at.desc`, j));
      return res.status(200).json(rows || []);
    }

    // Todos los apuntes del usuario, sin filtrar por materia (para el selector de contexto del chat).
    if (action === "all-annotations") {
      const user_id = req.query.user_id;
      if (!user_id) return res.status(400).json({ error: "user_id requerido" });
      const rows = await auto(j => sbGet("annotations",
        `user_id=eq.${user_id}&order=created_at.desc&select=id,materia,type,content,created_at`, j));
      return res.status(200).json(rows || []);
    }

    if (action === "create-annotation") {
      const { user_id, username, materia, type, content, drawing_data, ai_question, source_session_id } = req.body;
      if (!user_id || !materia || !type) return res.status(400).json({ error: "user_id, materia y type requeridos" });
      const payload = {
        user_id, username: username || null, materia,
        type, content: content || null, drawing_data: drawing_data || null,
        ai_question: ai_question || null, source_session_id: source_session_id || null,
        created_at: new Date().toISOString(), updated_at: new Date().toISOString()
      };
      const result = await auto(j => sbPost("annotations", payload, j));
      const row = Array.isArray(result) ? result[0] : result;
      return res.status(200).json({ ok: true, annotation: row });
    }

    if (action === "update-annotation") {
      const { id, user_id, content, drawing_data } = req.body;
      if (!id || !user_id) return res.status(400).json({ error: "id y user_id requeridos" });
      const update = { updated_at: new Date().toISOString() };
      if (content !== undefined)      update.content      = content;
      if (drawing_data !== undefined) update.drawing_data = drawing_data;
      await auto(j => sbPatch("annotations", `id=eq.${id}&user_id=eq.${user_id}`, update, j));
      return res.status(200).json({ ok: true });
    }

    if (action === "delete-annotation") {
      const { id, user_id } = req.body;
      if (!id || !user_id) return res.status(400).json({ error: "id y user_id requeridos" });
      await auto(j => sbDelete("annotations", `id=eq.${id}&user_id=eq.${user_id}`, j));
      return res.status(200).json({ ok: true });
    }


    // ========== BRANDING ==========
    if (action === "branding") {
      try {
        const r = await fetch("http://pera.com.uy/data/internal/triskl.txt", { headers: { "User-Agent": "triskl/web" } });
        if (!r.ok) return res.status(200).json({ raw: "" });
        const raw = await r.text();
        return res.status(200).json({ raw });
      } catch(_) { return res.status(200).json({ raw: "" }); }
    }

    // ========== HEALTH ==========
    if (action === "health") {
      return res.status(200).json({ status: "ok", timestamp: new Date().toISOString() });
    }

    return res.status(404).json({ error: `Acción desconocida: ${action}` });

  } catch (err) {
    console.error("[handler ERROR]", err.message);
    return res.status(500).json({ error: err.message });
  }
}
