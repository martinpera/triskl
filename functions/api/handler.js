// functions/api/handler.js  —  Cloudflare Pages Functions
// Ruta pública: /api/handler?action=...
//
// Variables de entorno (Pages → Settings → Environment variables):
//   LINKTR                 → https://xxxx.supabase.co
//   ANONTR                 → anon key
//   SUPABASE_SERVICE_ROLE  → service role key  (marcala como "Secret")

// ─── Respuestas ──────────────────────────────────────────────────────────────
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS,DELETE,PATCH",
  "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Refresh-Token",
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, "Content-Type": "application/json; charset=utf-8" },
  });

const bad = (msg, status = 400) => json({ error: msg }, status);
const enc = encodeURIComponent;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ─── Capa Supabase ───────────────────────────────────────────────────────────
function makeDB(env) {
  const URL_BASE = env.LINKTR;
  const ANON = env.ANONTR;
  const SERVICE = env.SUPABASE_SERVICE_ROLE || env.ANONTR;

  const authHeaders = (jwt) => ({
    "Content-Type": "application/json",
    apikey: ANON,
    Authorization: `Bearer ${jwt || ANON}`,
    Prefer: "return=representation",
  });

  const serviceHeaders = () => ({
    "Content-Type": "application/json",
    apikey: ANON,
    Authorization: `Bearer ${SERVICE}`,
    Prefer: "return=representation",
  });

  async function call(method, table, params, body, headers, tag) {
    const url = `${URL_BASE}/rest/v1/${table}${params ? "?" + params : ""}`;
    const res = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`${tag} ${table}: ${await res.text()}`);
    if (method === "DELETE") return true;
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  }

  return {
    URL_BASE,
    ANON,
    sbGet: (t, p = "", jwt = null) => call("GET", t, p, undefined, authHeaders(jwt), "sbGet"),
    sbPost: (t, d, jwt = null) => call("POST", t, "", d, authHeaders(jwt), "sbPost"),
    sbPatch: (t, f, d, jwt = null) => call("PATCH", t, f, d, authHeaders(jwt), "sbPatch"),
    sbDelete: (t, f, jwt = null) => call("DELETE", t, f, undefined, authHeaders(jwt), "sbDelete"),

    sbAdminGet: (t, p = "") => call("GET", t, p, undefined, serviceHeaders(), "sbAdminGet"),
    sbAdminPost: (t, d) => call("POST", t, "", d, serviceHeaders(), "sbAdminPost"),
    sbAdminPatch: (t, f, d) => call("PATCH", t, f, d, serviceHeaders(), "sbAdminPatch"),
    sbAdminDelete: (t, f) => call("DELETE", t, f, undefined, serviceHeaders(), "sbAdminDelete"),

    async supabaseAuthPost(path, body) {
      const res = await fetch(`${URL_BASE}/auth/v1${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", apikey: ANON },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      return { ok: res.ok, status: res.status, data };
    },

    async authUser(jwt) {
      if (!jwt) return null;
      const res = await fetch(`${URL_BASE}/auth/v1/user`, {
        headers: { apikey: ANON, Authorization: `Bearer ${jwt}` },
      });
      if (!res.ok) return null;
      return res.json().catch(() => null);
    },
  };
}

// ─── Auto-refresh del JWT ────────────────────────────────────────────────────
function makeAuto(db, jwt, refreshToken) {
  let current = jwt;
  return async function auto(fn) {
    try {
      return await fn(current);
    } catch (e) {
      const msg = e.message || "";
      const expired =
        msg.includes("JWT expired") || msg.includes("PGRST301") || msg.includes("invalid JWT");
      if (expired && refreshToken) {
        const { ok, data } = await db.supabaseAuthPost("/token?grant_type=refresh_token", {
          refresh_token: refreshToken,
        });
        if (ok && data.access_token) {
          current = data.access_token;
          return await fn(current);
        }
      }
      throw e;
    }
  };
}

// ─── Lógica de negocio ───────────────────────────────────────────────────────
function calcLevel(xp) {
  if (xp < 100) return 1;
  if (xp < 300) return 2;
  if (xp < 600) return 3;
  if (xp < 1000) return 4;
  if (xp < 1500) return 5;
  if (xp < 2100) return 6;
  if (xp < 2800) return 7;
  if (xp < 3600) return 8;
  if (xp < 4500) return 9;
  if (xp < 5500) return 10;
  return Math.max(1, Math.floor((1 + Math.sqrt(1 + (8 * xp) / 50)) / 2));
}

const xpForPub = (words) => Math.max(5, Math.floor(words / 10));

async function grantXP(db, uid, amount, jwt) {
  const rows = await db.sbGet("triskl_users", `id=eq.${uid}&select=xp,level,total_words`, jwt).catch(() => []);
  if (!rows?.length) return;
  const newXP = (rows[0].xp || 0) + amount;
  await db.sbPatch("triskl_users", `id=eq.${uid}`, { xp: newXP, level: calcLevel(newXP) }, jwt).catch(() => null);
}

async function ensureUserProfile(db, uid, email, username, jwt, gen = null) {
  const existing = await db.sbGet("triskl_users", `id=eq.${uid}`, jwt).catch(() => []);
  const now = new Date().toISOString();
  if (!existing || existing.length === 0) {
    await db.sbPost(
      "triskl_users",
      {
        id: uid,
        username: username.toLowerCase(),
        email: email.toLowerCase(),
        xp: 0,
        level: 1,
        streak_days: 0,
        total_words: 0,
        last_active: now,
        created_at: now,
        updated_at: now,
        bio: "",
        avatar_url: null,
        gen,
      },
      jwt
    );
  } else {
    await db.sbPatch("triskl_users", `id=eq.${uid}`, { last_active: now }, jwt);
    if (gen && existing[0].gen === null) {
      await db.sbPatch("triskl_users", `id=eq.${uid}`, { gen }, jwt);
    }
  }
}

// ─── Cursor keyset (created_at + id) ─────────────────────────────────────────
// Paginamos por (created_at desc, id desc). El cursor se manda opaco al cliente.
function encodeCursor(row) {
  if (!row) return null;
  try {
    return btoa(JSON.stringify({ t: row.created_at, i: row.id })).replace(/=+$/, "");
  } catch (_) {
    return null;
  }
}

function decodeCursor(str) {
  if (!str) return null;
  try {
    const pad = str + "===".slice((str.length + 3) % 4);
    const o = JSON.parse(atob(pad));
    return o?.t ? o : null;
  } catch (_) {
    return null;
  }
}

// Filtro PostgREST: "todo lo estrictamente anterior al cursor"
const keysetFilter = (c) =>
  `or=(created_at.lt."${c.t}",and(created_at.eq."${c.t}",id.lt.${c.i}))`;

// ─── Entry point ─────────────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env, waitUntil } = context;

  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

  const url = new URL(request.url);
  const q = url.searchParams;
  const db = makeDB(env);

  let body = {};
  if (request.method !== "GET" && request.method !== "HEAD") {
    body = await request.json().catch(() => ({}));
  }

  const action = q.get("action") || body.action || "";
  const jwt = (request.headers.get("authorization") || "").replace("Bearer ", "") || null;
  const refreshToken = request.headers.get("x-refresh-token") || null;
  const auto = makeAuto(db, jwt, refreshToken);

  try {
    // ========== SSE ==========
    // Ojo: en Workers el stream vive mientras el cliente lo mantenga abierto,
    // pero está sujeto a los límites de duración del plan. El EventSource del
    // cliente ya reconecta solo cada 5s, así que es tolerable.
    if (action === "sse") {
      const userId = q.get("user_id");
      if (!userId) return bad("user_id requerido");

      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();
      const te = new TextEncoder();
      let closed = false;

      const close = () => {
        closed = true;
        try { writer.close(); } catch (_) {}
      };
      request.signal?.addEventListener("abort", close);

      const pump = async () => {
        let lastCheck = Date.now();
        let ticks = 0;
        try {
          await writer.write(te.encode(": connected\n\n"));
          while (!closed) {
            await sleep(3000);
            if (closed) break;

            const since = new Date(lastCheck).toISOString();
            const notifs = await db
              .sbAdminGet(
                "notifications",
                `user_id=eq.${userId}&created_at=gt.${enc(since)}&order=created_at.desc&limit=10`
              )
              .catch(() => []);

            if (notifs?.length) {
              for (const n of notifs) await writer.write(te.encode(`data: ${JSON.stringify(n)}\n\n`));
              lastCheck = Date.now();
            } else if (++ticks % 10 === 0) {
              await writer.write(te.encode(": ping\n\n")); // keep-alive cada ~30s
            }
          }
        } catch (_) {
        } finally {
          close();
        }
      };

      waitUntil(pump());

      return new Response(readable, {
        headers: {
          ...CORS,
          "Content-Type": "text/event-stream; charset=utf-8",
          "Cache-Control": "no-cache, no-transform",
          Connection: "keep-alive",
          "X-Accel-Buffering": "no",
        },
      });
    }

    // ========== AUTH ==========
    if (action === "login") {
      const { email, password } = body;
      if (!email || !password) return bad("email y password requeridos");

      const { ok, data } = await db.supabaseAuthPost("/token?grant_type=password", {
        email: email.toLowerCase(),
        password,
      });
      if (!ok) return bad(data.error_description || data.msg || "Credenciales incorrectas", 401);

      const user = data.user || {};
      const username = (user.user_metadata || {}).username || email.split("@")[0];
      const accessJwt = data.access_token;

      await ensureUserProfile(db, user.id, user.email, username, accessJwt);
      const userRow = await db.sbGet("triskl_users", `id=eq.${user.id}&select=gen`, accessJwt).catch(() => []);

      return json({
        id: user.id,
        username: username.toLowerCase(),
        email: user.email,
        jwt: accessJwt,
        refresh_token: data.refresh_token || "",
        expires_at: data.expires_at || 0,
        gen: userRow?.[0]?.gen ?? null,
      });
    }

    if (action === "register") {
      const { email, password, username, gen } = body;
      if (!email || !password || !username) return bad("email, password y username requeridos");

      const currentYear = new Date().getFullYear();
      let yearGen = null;
      if (gen) {
        const genNum = parseInt(gen);
        if (isNaN(genNum) || genNum < 2008 || genNum > currentYear)
          return bad(`El año debe estar entre 2008 y ${currentYear}`);
        yearGen = genNum;
      }

      const existingUser = await db.sbAdminGet("triskl_users", `username=eq.${enc(username.toLowerCase())}`);
      if (existingUser?.length) return bad("Este nombre de usuario ya está en uso");

      const signupRes = await db.supabaseAuthPost("/signup", {
        email: email.toLowerCase(),
        password,
        data: { username: username.toLowerCase(), gen: yearGen },
      });
      if (!signupRes.ok)
        return json(
          {
            error: signupRes.data.msg || signupRes.data.error_description || "Error al registrarse",
            needsVerification: false,
          },
          400
        );

      const signupUser = signupRes.data.user || {};
      const confirmed = signupUser.email_confirmed_at || signupUser.confirmed_at;

      if (!confirmed)
        return json({
          needsVerification: true,
          email: email.toLowerCase(),
          message: "Se envió un código de verificación a tu email.",
          user_id: signupUser.id,
          gen: yearGen,
        });

      await ensureUserProfile(db, signupUser.id, signupUser.email, username, null, yearGen);
      return json({
        id: signupUser.id,
        username: username.toLowerCase(),
        email: signupUser.email,
        jwt: signupRes.data.access_token,
        refresh_token: signupRes.data.refresh_token || "",
        expires_at: signupRes.data.expires_at || 0,
        needsVerification: false,
        gen: yearGen,
      });
    }

    if (action === "verify-otp") {
      const { email, token } = body;
      if (!email || !token) return bad("email y token requeridos");

      const { ok, data } = await db.supabaseAuthPost("/verify", {
        email: email.toLowerCase(),
        token,
        type: "signup",
      });
      if (!ok) return bad(data.msg || data.error_description || "Código incorrecto");

      const user = data.user || {};
      const meta = user.user_metadata || {};
      const username = meta.username || email.split("@")[0];
      const gen = meta.gen || null;
      const accessJwt = data.access_token;

      await ensureUserProfile(db, user.id, user.email, username, accessJwt, gen);
      return json({
        id: user.id,
        username: username.toLowerCase(),
        email: user.email,
        jwt: accessJwt,
        refresh_token: data.refresh_token || "",
        expires_at: data.expires_at || 0,
        gen,
      });
    }

    if (action === "resend-otp") {
      const { email } = body;
      if (!email) return bad("email requerido");
      const { ok, data } = await db.supabaseAuthPost("/otp", { email: email.toLowerCase() });
      if (!ok) return bad(data.msg || "Error al reenviar");
      return json({ ok: true });
    }

    if (action === "verify-session") {
      const { email, password, jwt: existingJwt } = body;

      if (existingJwt) {
        const user = await db.authUser(existingJwt);
        if (user?.id) {
          const username = (user.user_metadata || {}).username || user.email.split("@")[0];
          await db
            .sbPatch("triskl_users", `id=eq.${user.id}`, { last_active: new Date().toISOString() }, existingJwt)
            .catch(() => null);
          const userRow = await db.sbGet("triskl_users", `id=eq.${user.id}&select=gen`, existingJwt).catch(() => []);
          return json({
            id: user.id,
            username: username.toLowerCase(),
            email: user.email,
            jwt: existingJwt,
            gen: userRow?.[0]?.gen ?? null,
          });
        }
      }

      if (email && password) {
        const { ok, data } = await db.supabaseAuthPost("/token?grant_type=password", {
          email: email.toLowerCase(),
          password,
        });
        if (ok) {
          const user = data.user || {};
          const username = (user.user_metadata || {}).username || email.split("@")[0];
          const accessJwt = data.access_token;
          await ensureUserProfile(db, user.id, user.email, username, accessJwt);
          const userRow = await db.sbGet("triskl_users", `id=eq.${user.id}&select=gen`, accessJwt).catch(() => []);
          return json({
            id: user.id,
            username: username.toLowerCase(),
            email: user.email,
            jwt: accessJwt,
            refresh_token: data.refresh_token || "",
            expires_at: data.expires_at || 0,
            gen: userRow?.[0]?.gen ?? null,
          });
        }
      }

      return bad("No autenticado", 401);
    }

    if (action === "refresh-token") {
      const { refresh_token } = body;
      if (!refresh_token) return bad("refresh_token requerido");
      const { ok, data } = await db.supabaseAuthPost("/token?grant_type=refresh_token", { refresh_token });
      if (!ok) return bad("No se pudo renovar", 401);
      return json({
        jwt: data.access_token,
        refresh_token: data.refresh_token || refresh_token,
        expires_at: data.expires_at || 0,
      });
    }

    // ========== PUSH SUBSCRIPTIONS ==========
    if (action === "check-push-subscription") {
      const user_id = q.get("user_id");
      if (!user_id) return bad("user_id requerido");
      const rows = await db.sbAdminGet("push_subscriptions", `user_id=eq.${user_id}&select=id&limit=1`).catch(() => []);
      return json({ has_subscription: !!rows?.length });
    }

    if (action === "save-push-subscription") {
      const { user_id, endpoint, p256dh, auth: authKey, device_name } = body;
      if (!user_id || !endpoint) return bad("user_id y endpoint requeridos");
      const filter = `endpoint=eq.${enc(endpoint)}`;
      const existing = await db.sbAdminGet("push_subscriptions", filter).catch(() => []);
      const now = new Date().toISOString();
      if (existing?.length) {
        await db.sbAdminPatch("push_subscriptions", filter, {
          user_id,
          p256dh,
          auth: authKey,
          device_name: device_name || "Dispositivo",
          updated_at: now,
        });
      } else {
        await db.sbAdminPost("push_subscriptions", {
          user_id,
          endpoint,
          p256dh,
          auth: authKey,
          device_name: device_name || "Dispositivo",
          created_at: now,
          updated_at: now,
        });
      }
      return json({ ok: true });
    }

    if (action === "remove-push-subscription") {
      const { user_id, endpoint } = body;
      if (!user_id || !endpoint) return bad("user_id y endpoint requeridos");
      await db.sbAdminDelete("push_subscriptions", `user_id=eq.${user_id}&endpoint=eq.${enc(endpoint)}`);
      return json({ ok: true });
    }

    if (action === "push-devices") {
      const user_id = q.get("user_id");
      if (!user_id) return bad("user_id requerido");
      const rows = await db
        .sbAdminGet("push_subscriptions", `user_id=eq.${user_id}&select=id,endpoint,device_name,created_at,updated_at`)
        .catch(() => []);
      return json(rows || []);
    }

    if (action === "push-delete-device") {
      const { sub_id, user_id } = body;
      if (!sub_id || !user_id) return bad("sub_id y user_id requeridos");
      await db.sbAdminDelete("push_subscriptions", `id=eq.${sub_id}&user_id=eq.${user_id}`);
      return json({ ok: true });
    }

    // ========== PUBLICACIONES (feed paginado) ==========
    // GET ?action=publications&limit=15&cursor=<opaco>&visibility=todos&user_id=...
    // Respuesta: { items: [...], next_cursor, has_more }
    // Compat: &flat=1 devuelve el array pelado (como antes).
    if (action === "publications") {
      const uid = q.get("user_id");
      const vis = q.get("visibility");
      const flat = q.get("flat") === "1";

      // Deep-link a un post puntual: acepta id=123 o id=eq.123
      const single = (q.get("id") || "").replace(/^eq\./, "");
      if (single) {
        const rows = await auto((j) =>
          db.sbGet(
            "publications",
            `id=eq.${enc(single)}&select=*,user:user_id(id,username,avatar_url,xp,level,gen)`,
            j
          )
        );
        return json(flat ? rows || [] : { items: rows || [], next_cursor: null, has_more: false });
      }

      const limit = Math.min(Math.max(parseInt(q.get("limit") || "15", 10) || 15, 1), 50);
      let cursor = decodeCursor(q.get("cursor"));

      // ── filtros base ──
      const base = ["select=*,user:user_id(id,username,avatar_url,xp,level,gen)", "order=created_at.desc,id.desc"];
      if (uid) base.push(`user_id=eq.${uid}`);

      if (vis && vis !== "undefined") {
        if (vis.includes(",")) {
          base.push(`or=(${vis.split(",").map((v) => `visibility.eq.${v.trim()}`).join(",")})`);
        } else {
          base.push(`visibility=eq.${vis}`);
        }
      } else if (!uid) {
        base.push("visibility=eq.todos");
      } else {
        base.push("or=(visibility.eq.todos,visibility.eq.friends)");
      }

      // ── quién mira (para el filtro por generación) ──
      let viewerId = null;
      let viewerGen = null;
      if (jwt) {
        const userInfo = await db.authUser(jwt);
        if (userInfo?.id) {
          viewerId = userInfo.id;
          const userRow = await auto((j) => db.sbGet("triskl_users", `id=eq.${userInfo.id}&select=gen`, j)).catch(
            () => []
          );
          viewerGen = userRow?.[0]?.gen ?? null;
        }
      }
      const viewerKey = viewerGen === null ? 2009 : viewerGen;
      const visible = (post) => {
        if (post.user_id === viewerId) return true;
        const authorKey = post.user?.gen == null ? 2009 : post.user.gen;
        return authorKey === viewerKey;
      };

      // ── el filtro por gen es post-query, así que sobre-pedimos hasta llenar
      //    el batch (o agotar la tabla). Máx 6 vueltas para no colgar el worker.
      const pageSize = Math.min(limit * 3, 100);
      const out = [];
      let exhausted = false;
      let guard = 0;

      while (out.length <= limit && !exhausted && guard++ < 6) {
        const params = [...base, `limit=${pageSize}`];
        if (cursor) params.push(keysetFilter(cursor));

        const rows = await auto((j) => db.sbGet("publications", params.join("&"), j));
        if (!rows?.length) {
          exhausted = true;
          break;
        }
        if (rows.length < pageSize) exhausted = true;

        cursor = { t: rows[rows.length - 1].created_at, i: rows[rows.length - 1].id };
        for (const r of rows) if (visible(r)) out.push(r);
      }

      const items = out.slice(0, limit);
      const has_more = out.length > limit || !exhausted;

      if (flat) return json(items);
      return json({
        items,
        next_cursor: items.length ? encodeCursor(items[items.length - 1]) : null,
        has_more,
      });
    }

    if (action === "publish") {
      const {
        session_id, title, content, visibility, post_type, username, user_id, materia,
        poll_options, poll_votes, poll_voters, poll_anonymous, media,
      } = body;

      const payload = {
        user_id,
        username,
        title,
        materia: materia || title,
        content,
        visibility: visibility || "todos",
        post_type: post_type || "transcripcion",
        created_at: new Date().toISOString(),
      };
      if (session_id) payload.session_id = session_id;
      if (poll_options) payload.poll_options = poll_options;
      if (poll_votes) payload.poll_votes = poll_votes;
      if (poll_voters) payload.poll_voters = poll_voters;
      if (poll_anonymous !== undefined) payload.poll_anonymous = poll_anonymous;
      if (media) payload.media = media;

      const result = await auto((j) => db.sbPost("publications", payload, j));

      if (post_type === "transcripcion" && user_id && content && !content.startsWith("!!POST!!")) {
        const words = content.split(/\s+/).filter(Boolean).length;
        await auto((j) => grantXP(db, user_id, xpForPub(words), j)).catch(() => null);
        const userRows = await auto((j) => db.sbGet("triskl_users", `id=eq.${user_id}&select=total_words`, j)).catch(
          () => []
        );
        if (userRows?.length) {
          await auto((j) =>
            db.sbPatch("triskl_users", `id=eq.${user_id}`, { total_words: (userRows[0].total_words || 0) + words }, j)
          ).catch(() => null);
        }
      }

      const pub = Array.isArray(result) ? result[0] : result;
      return json({ ok: true, id: pub?.id });
    }

    if (action === "delete-publication") {
      const { pub_id, user_id } = body;
      if (!pub_id) return bad("pub_id requerido");
      const pid = parseInt(pub_id, 10);
      if (isNaN(pid)) return bad("pub_id inválido");

      await auto((j) => db.sbDelete("comments", `publication_id=eq.${pid}`, j)).catch(() => null);
      await auto((j) => db.sbDelete("notifications", `pub_id=eq.${pid}`, j)).catch(() => null);
      await auto((j) => db.sbDelete("publications", `id=eq.${pid}&user_id=eq.${user_id}`, j));
      return json({ ok: true });
    }

    if (action === "vote-poll") {
      const { pub_id, option, user_id } = body;
      if (!pub_id || !option || !user_id) return bad("pub_id, option, user_id requeridos");

      const rows = await auto((j) => db.sbGet("publications", `id=eq.${pub_id}&select=poll_votes,poll_voters`, j));
      if (!rows?.length) return bad("Publicación no encontrada", 404);

      let votes = {}, voters = [];
      try { votes = JSON.parse(rows[0].poll_votes || "{}"); } catch (_) {}
      try { voters = JSON.parse(rows[0].poll_voters || "[]"); } catch (_) {}
      if (voters.includes(user_id)) return bad("Ya votaste");

      votes[option] = (votes[option] || 0) + 1;
      voters.push(user_id);
      await auto((j) =>
        db.sbPatch("publications", `id=eq.${pub_id}`, {
          poll_votes: JSON.stringify(votes),
          poll_voters: JSON.stringify(voters),
        }, j)
      );
      return json({ ok: true });
    }

    // ========== COMENTARIOS ==========
    if (action === "comments") {
      const pub_id = q.get("publication_id");
      if (!pub_id) return bad("publication_id requerido");
      const rows = await auto((j) =>
        db.sbGet(
          "comments",
          `publication_id=eq.${pub_id}&order=created_at.asc&select=*,user:user_id(id,username,avatar_url)`,
          j
        )
      );
      return json(rows || []);
    }

    if (action === "add-comment") {
      const { publication_id, user_id, username, content } = body;
      if (!publication_id || !content) return bad("publication_id y content requeridos");

      await auto((j) =>
        db.sbPost("comments", { publication_id, user_id, username, content, created_at: new Date().toISOString() }, j)
      );

      const pubRows = await auto((j) =>
        db.sbGet("publications", `id=eq.${publication_id}&select=comments_count,user_id,username`, j)
      ).catch(() => []);

      if (pubRows?.length) {
        await auto((j) =>
          db.sbPatch("publications", `id=eq.${publication_id}`, { comments_count: (pubRows[0].comments_count || 0) + 1 }, j)
        ).catch(() => null);
        if (pubRows[0].user_id !== user_id) {
          await auto((j) =>
            db.sbPost("notifications", {
              user_id: pubRows[0].user_id, from_uid: user_id, from_uname: username,
              type: "comment", pub_id: publication_id,
              content: `@${username} comentó en tu publicación`,
              read: false, created_at: new Date().toISOString(),
            }, j)
          ).catch(() => null);
        }
      }
      return json({ ok: true });
    }

    if (action === "delete-comment") {
      const { comment_id, user_id } = body;
      if (!comment_id) return bad("comment_id requerido");
      await auto((j) => db.sbDelete("comments", `id=eq.${comment_id}&user_id=eq.${user_id}`, j));
      return json({ ok: true });
    }

    // ========== SEGUIDORES ==========
    if (action === "follows") {
      const follower_id = q.get("follower_id");
      const rows = await auto((j) => db.sbGet("follows", follower_id ? `follower_id=eq.${follower_id}` : "", j));
      return json(rows || []);
    }

    if (action === "followers" || action === "following") {
      const user_id = q.get("user_id");
      if (!user_id) return bad("user_id requerido");
      const isFollowers = action === "followers";
      const filter = isFollowers ? `followed_id=eq.${user_id}&select=follower_id` : `follower_id=eq.${user_id}&select=followed_id`;
      const rows = await auto((j) => db.sbGet("follows", filter, j));
      if (!rows?.length) return json([]);
      const ids = rows.map((r) => (isFollowers ? r.follower_id : r.followed_id)).filter(Boolean);
      if (!ids.length) return json([]);
      const users = await auto((j) =>
        db.sbGet("triskl_users", `id=in.(${ids.join(",")})&select=id,username,bio,xp,level,avatar_url,total_words,streak_days,gen`, j)
      );
      return json(users || []);
    }

    if (action === "follow") {
      const { follower_id, followed_id } = body;
      if (!follower_id || !followed_id) return bad("follower_id y followed_id requeridos");

      const existing = await auto((j) =>
        db.sbGet("follows", `follower_id=eq.${follower_id}&followed_id=eq.${followed_id}`, j)
      ).catch(() => []);

      if (!existing?.length) {
        await auto((j) => db.sbPost("follows", { follower_id, followed_id, created_at: new Date().toISOString() }, j));
        const fu = await auto((j) => db.sbGet("triskl_users", `id=eq.${follower_id}&select=username`, j)).catch(() => []);
        const followerName = fu?.[0]?.username || follower_id;
        await auto((j) =>
          db.sbPost("notifications", {
            user_id: followed_id, from_uid: follower_id, from_uname: followerName,
            type: "follow", content: `@${followerName} te empezó a seguir`,
            read: false, created_at: new Date().toISOString(),
          }, j)
        ).catch(() => null);
      }
      return json({ ok: true });
    }

    if (action === "unfollow") {
      const { follower_id, followed_id } = body;
      await auto((j) => db.sbDelete("follows", `follower_id=eq.${follower_id}&followed_id=eq.${followed_id}`, j));
      return json({ ok: true });
    }

    // ========== MENSAJES DIRECTOS ==========
    if (action === "dms") {
      const sender_id = q.get("sender_id");
      const receiver_id = q.get("receiver_id");
      let params = "order=created_at.asc";
      if (sender_id) params += `&sender_id=eq.${sender_id}`;
      if (receiver_id) params += `&receiver_id=eq.${receiver_id}`;
      const rows = await auto((j) => db.sbGet("direct_messages", params, j));
      return json(rows || []);
    }

    if (action === "send-dm") {
      const { sender_id, sender_uname, receiver_id, receiver_uname, content, attached_transcript, media, reply_to } = body;
      if (!sender_id || !receiver_id || !content) return bad("sender_id, receiver_id y content requeridos");

      const payload = { sender_id, sender_uname, receiver_id, receiver_uname, content, created_at: new Date().toISOString() };
      if (attached_transcript) payload.attached_transcript = attached_transcript;
      if (media) payload.media = media;
      if (reply_to) payload.reply_to = reply_to;

      await auto((j) => db.sbPost("direct_messages", payload, j));

      const notifBody = content.startsWith("📎")
        ? `@${sender_uname} te envió un archivo`
        : `@${sender_uname}: ${content.slice(0, 100)}`;

      await auto((j) =>
        db.sbPost("notifications", {
          user_id: receiver_id, from_uid: sender_id, from_uname: sender_uname,
          type: "dm", content: notifBody, read: false, created_at: new Date().toISOString(),
        }, j)
      ).catch(() => null);

      return json({ ok: true });
    }

    if (action === "delete-message") {
      const { message_id, type } = body;
      if (!message_id || !type) return bad("message_id y type requeridos");
      const table = type === "dm" ? "direct_messages" : type === "group" ? "group_messages" : null;
      if (!table) return bad("type debe ser 'dm' o 'group'");
      await auto((j) => db.sbPatch(table, `id=eq.${message_id}`, { deleted: true }, j));
      return json({ ok: true });
    }

    if (action === "reply-to-message") {
      const { message_id, type, content, sender_id, sender_uname, receiver_id, group_id } = body;
      if (!message_id || !type || !content || !sender_id) return bad("Faltan campos requeridos");
      const now = new Date().toISOString();
      if (type === "dm") {
        if (!receiver_id) return bad("receiver_id requerido");
        await auto((j) =>
          db.sbPost("direct_messages", { sender_id, sender_uname, receiver_id, content, reply_to: message_id, created_at: now }, j)
        );
      } else if (type === "group") {
        if (!group_id) return bad("group_id requerido");
        await auto((j) =>
          db.sbPost("group_messages", { group_id, sender_id, sender_uname, content, reply_to: message_id, created_at: now }, j)
        );
      } else return bad("type debe ser 'dm' o 'group'");
      return json({ ok: true });
    }

    // ========== GRUPOS ==========
    if (action === "create-group") {
      const { name, creator_id, creator_uname, avatar_url } = body;
      if (!name || !creator_id) return bad("name y creator_id requeridos");

      const gr = await auto((j) =>
        db.sbPost("groups", { name, creator_id, avatar_url, created_at: new Date().toISOString() }, j)
      );
      const group = Array.isArray(gr) ? gr[0] : gr;
      if (!group?.id) return bad("No se pudo crear el grupo", 500);

      await auto((j) =>
        db.sbPost("group_members", {
          group_id: group.id, user_id: creator_id,
          username: creator_uname || creator_id, joined_at: new Date().toISOString(),
        }, j)
      );
      return json({ ok: true, id: group.id });
    }

    if (action === "my-groups") {
      const user_id = q.get("user_id");
      if (!user_id) return bad("user_id requerido");

      const memberships = await auto((j) => db.sbGet("group_members", `user_id=eq.${user_id}&select=group_id`, j)).catch(() => []);
      const groupIds = (memberships || []).map((m) => m.group_id).filter(Boolean);
      if (!groupIds.length) return json([]);

      const groups = await auto((j) => db.sbGet("groups", `id=in.(${groupIds.join(",")})&order=created_at.desc`, j));
      if (!groups?.length) return json([]);

      const counts = await auto((j) =>
        db.sbGet("group_members", `group_id=in.(${groupIds.join(",")})&select=group_id`, j)
      ).catch(() => []);
      const tally = {};
      for (const c of counts || []) tally[c.group_id] = (tally[c.group_id] || 0) + 1;

      return json(groups.map((g) => ({ ...g, member_count: tally[g.id] || 0 })));
    }

    if (action === "group-members") {
      const group_id = q.get("group_id");
      if (!group_id) return bad("group_id requerido");
      const rows = await auto((j) => db.sbGet("group_members", `group_id=eq.${group_id}&order=joined_at.asc`, j));
      return json(rows || []);
    }

    if (action === "add-group-member") {
      const { group_id, user_id, username } = body;
      if (!group_id || !user_id) return bad("group_id y user_id requeridos");
      const existing = await auto((j) => db.sbGet("group_members", `group_id=eq.${group_id}&user_id=eq.${user_id}`, j)).catch(() => []);
      if (existing?.length) return bad("Ya es miembro del grupo");
      await auto((j) =>
        db.sbPost("group_members", { group_id, user_id, username: username || user_id, joined_at: new Date().toISOString() }, j)
      );
      return json({ ok: true });
    }

    if (action === "remove-group-member") {
      const { group_id, user_id } = body;
      if (!group_id || !user_id) return bad("group_id y user_id requeridos");
      await auto((j) => db.sbDelete("group_members", `group_id=eq.${group_id}&user_id=eq.${user_id}`, j));
      const remaining = await auto((j) => db.sbGet("group_members", `group_id=eq.${group_id}&select=user_id`, j)).catch(() => []);
      if (!remaining?.length) {
        await auto((j) => db.sbDelete("group_messages", `group_id=eq.${group_id}`, j)).catch(() => null);
        await auto((j) => db.sbDelete("groups", `id=eq.${group_id}`, j)).catch(() => null);
      }
      return json({ ok: true });
    }

    if (action === "group-messages") {
      const group_id = q.get("group_id");
      if (!group_id) return bad("group_id requerido");
      const rows = await auto((j) => db.sbGet("group_messages", `group_id=eq.${group_id}&order=created_at.asc`, j));
      return json(rows || []);
    }

    if (action === "send-group-message") {
      const { group_id, sender_id, sender_uname, content, attached_transcript, media, poll_data, reply_to } = body;
      if (!group_id || !sender_id || !content) return bad("group_id, sender_id y content requeridos");

      const membership = await auto((j) => db.sbGet("group_members", `group_id=eq.${group_id}&user_id=eq.${sender_id}`, j)).catch(() => []);
      if (!membership?.length) return bad("No sos miembro de este grupo", 403);

      const payload = {
        group_id, sender_id, sender_uname: sender_uname || sender_id,
        content, created_at: new Date().toISOString(),
      };
      if (attached_transcript) payload.attached_transcript = attached_transcript;
      if (media) payload.media = media;
      if (poll_data) payload.poll_data = poll_data;
      if (reply_to) payload.reply_to = reply_to;

      await auto((j) => db.sbPost("group_messages", payload, j));
      return json({ ok: true });
    }

    if (action === "vote-chat-poll") {
      const { message_id, option, user_id } = body;
      if (!message_id || !option || !user_id) return bad("message_id, option, user_id requeridos");

      const rows = await auto((j) => db.sbGet("group_messages", `id=eq.${message_id}&select=poll_data`, j));
      if (!rows?.length) return bad("Mensaje no encontrado", 404);

      let poll = null;
      try {
        poll = typeof rows[0].poll_data === "string" ? JSON.parse(rows[0].poll_data) : rows[0].poll_data;
      } catch (_) {}
      if (!poll?.question) return bad("No es una encuesta");

      poll.votes ||= {};
      poll.voters ||= [];
      if (poll.voters.includes(user_id)) return bad("Ya votaste");

      poll.votes[option] = (poll.votes[option] || 0) + 1;
      poll.voters.push(user_id);
      await auto((j) => db.sbPatch("group_messages", `id=eq.${message_id}`, { poll_data: JSON.stringify(poll) }, j));
      return json({ ok: true });
    }

    if (action === "update-group-avatar") {
      const { group_id, avatar_url } = body;
      if (!group_id) return bad("group_id requerido");
      await auto((j) => db.sbPatch("groups", `id=eq.${group_id}`, { avatar_url }, j));
      return json({ ok: true });
    }

    if (action === "group-detail") {
      const id = q.get("id");
      if (!id) return bad("id requerido");
      const rows = await auto((j) => db.sbGet("groups", `id=eq.${id}`, j));
      return json(rows?.[0] || null);
    }

    // ========== NOTIFICACIONES ==========
    if (action === "notifications") {
      const user_id = q.get("user_id");
      if (!user_id) return bad("user_id requerido");
      let params = `user_id=eq.${user_id}&order=created_at.desc&limit=50`;
      if (q.get("unread") === "1") params += "&read=eq.false";
      const rows = await auto((j) => db.sbGet("notifications", params, j));
      return json(rows || []);
    }

    if (action === "mark-notif-read") {
      const { notif_id } = body;
      if (!notif_id) return bad("notif_id requerido");
      await auto((j) => db.sbPatch("notifications", `id=eq.${notif_id}`, { read: true }, j));
      return json({ ok: true });
    }

    if (action === "mark-all-notifs-read") {
      const { user_id } = body;
      if (!user_id) return bad("user_id requerido");
      // un solo PATCH masivo en vez del loop original
      await auto((j) => db.sbPatch("notifications", `user_id=eq.${user_id}&read=eq.false`, { read: true }, j)).catch(() => null);
      return json({ ok: true });
    }

    if (action === "mark-dm-notifications-read") {
      const { user_id, partner_id } = body;
      if (!user_id || !partner_id) return bad("user_id y partner_id requeridos");
      await auto((j) =>
        db.sbPatch("notifications", `user_id=eq.${user_id}&from_uid=eq.${partner_id}&type=eq.dm&read=eq.false`, { read: true }, j)
      ).catch(() => null);
      return json({ ok: true });
    }

    if (action === "mark-group-notifications-read") {
      const { user_id, group_id } = body;
      if (!user_id || !group_id) return bad("user_id y group_id requeridos");
      await auto((j) =>
        db.sbPatch("notifications", `user_id=eq.${user_id}&group_id=eq.${group_id}&type=eq.group_message&read=eq.false`, { read: true }, j)
      ).catch(() => null);
      return json({ ok: true });
    }

    if (action === "unread-dms") {
      const user_id = q.get("user_id");
      if (!user_id) return bad("user_id requerido");
      const rows = await auto((j) =>
        db.sbGet("notifications", `user_id=eq.${user_id}&type=eq.dm&read=eq.false&select=from_uid`, j)
      ).catch(() => []);
      return json([...new Set((rows || []).map((r) => r.from_uid).filter(Boolean))]);
    }

    if (action === "unread-group-messages") {
      const user_id = q.get("user_id");
      if (!user_id) return bad("user_id requerido");
      const rows = await auto((j) =>
        db.sbGet("notifications", `user_id=eq.${user_id}&type=eq.group_message&read=eq.false&select=group_id`, j)
      ).catch(() => []);
      return json([...new Set((rows || []).map((r) => r.group_id).filter(Boolean))]);
    }

    // ========== EVENTOS ==========
    if (action === "events") {
      const user_id = q.get("user_id");
      if (!user_id) return bad("user_id requerido");
      const rows = await auto((j) => db.sbGet("triskl_events", `user_id=eq.${user_id}&order=due_date.asc`, j));
      return json(rows || []);
    }

    if (action === "create-event") {
      const { user_id, username, type, materia, title, notes, due_date } = body;
      if (!user_id || !type || !materia || !title || !due_date) return bad("Faltan campos requeridos");

      const result = await auto((j) =>
        db.sbPost("triskl_events", {
          user_id, username: username || "", type, materia, title,
          notes: notes || "", due_date, done: false, snoozed: false,
          created_at: new Date().toISOString(),
        }, j)
      );

      const followers = await auto((j) => db.sbGet("follows", `followed_id=eq.${user_id}&select=follower_id`, j)).catch(() => []);
      if (followers?.length) {
        const now = new Date().toISOString();
        // un solo insert en batch
        await auto((j) =>
          db.sbPost("notifications", followers.map((f) => ({
            user_id: f.follower_id, from_uid: user_id, from_uname: username,
            type: "event", content: `📅 ${title} - ${materia} (${due_date})`,
            read: false, created_at: now,
          })), j)
        ).catch(() => null);
      }

      return json({ ok: true, event: Array.isArray(result) ? result[0] : result });
    }

    if (action === "update-event") {
      const { event_id, user_id, ...fields } = body;
      if (!event_id || !user_id) return bad("event_id y user_id requeridos");
      delete fields.action;
      await auto((j) => db.sbPatch("triskl_events", `id=eq.${event_id}&user_id=eq.${user_id}`, fields, j));
      return json({ ok: true });
    }

    if (action === "delete-event") {
      const { event_id, user_id } = body;
      if (!event_id || !user_id) return bad("event_id y user_id requeridos");
      await auto((j) => db.sbDelete("triskl_events", `id=eq.${event_id}&user_id=eq.${user_id}`, j));
      return json({ ok: true });
    }

    if (action === "upcoming-events") {
      const user_id = q.get("user_id") || body.user_id;
      const days = parseInt(q.get("days") || "7", 10);
      if (!user_id) return bad("user_id requerido");

      const today = new Date(); today.setHours(0, 0, 0, 0);
      const limitD = new Date(today); limitD.setDate(limitD.getDate() + days);
      const todayStr = today.toISOString().slice(0, 10);
      const limitStr = limitD.toISOString().slice(0, 10);

      const rows = await auto((j) =>
        db.sbGet("triskl_events", `user_id=eq.${user_id}&done=eq.false&due_date=gte.${todayStr}&due_date=lte.${limitStr}&order=due_date.asc`, j)
      );
      const active = (rows || []).filter((r) => {
        if (r.done) return false;
        if (!r.snoozed || !r.snooze_until) return true;
        return r.snooze_until < todayStr;
      });
      return json(active);
    }

    // ========== PERFILES ==========
    if (action === "user-profile") {
      const user_id = q.get("user_id");
      if (!user_id) return bad("user_id requerido");
      const rows = await auto((j) => db.sbGet("triskl_users", `id=eq.${user_id}`, j));
      return json(rows || []);
    }

    if (action === "update-user-stats") {
      const { user_id, total_words, xp, level, streak_days, bio, avatar_url } = body;
      if (!user_id) return bad("user_id requerido");

      const update = { updated_at: new Date().toISOString() };
      if (total_words !== undefined) update.total_words = total_words;
      if (xp !== undefined) { update.xp = xp; update.level = calcLevel(xp); }
      else if (level !== undefined) update.level = level;
      if (streak_days !== undefined) update.streak_days = streak_days;
      if (bio !== undefined) update.bio = bio;
      if (avatar_url !== undefined) update.avatar_url = avatar_url;

      await auto((j) => db.sbPatch("triskl_users", `id=eq.${user_id}`, update, j));
      return json({ ok: true });
    }

    if (action === "update-bio") {
      const { user_id, bio, avatar_url } = body;
      if (!user_id) return bad("user_id requerido");
      const updateData = { updated_at: new Date().toISOString() };
      if (bio !== undefined) updateData.bio = bio;
      if (avatar_url !== undefined) updateData.avatar_url = avatar_url;
      if (Object.keys(updateData).length === 1) return bad("No se proporcionaron campos para actualizar");
      await auto((j) => db.sbPatch("triskl_users", `id=eq.${user_id}`, updateData, j));
      return json({ ok: true });
    }

    if (action === "search-users") {
      const term = q.get("q") || "";
      if (!term) return json([]);
      const rows = await auto((j) =>
        db.sbGet("triskl_users", `username=ilike.*${enc(term)}*&select=id,username,xp,level,bio,avatar_url,total_words,streak_days,gen&limit=25`, j)
      );
      return json(rows || []);
    }

    if (action === "leaderboard") {
      const rows = await auto((j) =>
        db.sbGet("triskl_users", "order=xp.desc&limit=20&select=id,username,xp,level,streak_days,total_words,avatar_url,gen", j)
      );
      return json(rows || []);
    }

    if (action === "recalc-level") {
      const { user_id } = body;
      if (!user_id) return bad("user_id requerido");
      const rows = await auto((j) => db.sbGet("triskl_users", `id=eq.${user_id}&select=xp,level`, j));
      if (!rows?.length) return bad("Usuario no encontrado", 404);

      const correctLevel = calcLevel(rows[0].xp || 0);
      const curLevel = rows[0].level || 1;
      if (curLevel !== correctLevel) {
        await auto((j) => db.sbPatch("triskl_users", `id=eq.${user_id}`, { level: correctLevel }, j));
        return json({ fixed: true, oldLevel: curLevel, newLevel: correctLevel });
      }
      return json({ fixed: false, level: curLevel });
    }

    // ========== SESIONES Y SEGMENTOS ==========
    if (action === "sessions") {
      const username = q.get("username") || body.username;
      const sid = (q.get("id") || "").replace(/^eq\./, "");
      const select = q.get("select");

      if (sid) {
        const rows = await auto((j) =>
          db.sbGet("sessions", `id=eq.${enc(sid)}${select ? `&select=${enc(select)}` : ""}`, j)
        );
        return json(rows || []);
      }
      if (!username) return bad("username requerido");
      const sessions = await auto((j) => db.sbGet("sessions", `username=eq.${enc(username)}&order=started_at.desc`, j));
      return json(sessions || []);
    }

    if (action === "segments") {
      const session_id = q.get("session_id") || body.session_id;
      if (!session_id) return bad("session_id requerido");
      const segments = await auto((j) =>
        db.sbGet("segments", `session_id=eq.${session_id}&order=recorded_at.asc&select=id,text,recorded_at`, j)
      );
      return json(segments || []);
    }

    if (action === "new-session") {
      const { session_id, materia, username, langs, file_path } = body;
      const payload = {
        id: session_id,
        materia: materia || "Sin materia",
        started_at: new Date().toISOString(),
        langs: langs || ["es"],
        file_path: file_path || "",
      };
      if (username) payload.username = username;
      const result = await auto((j) => db.sbPost("sessions", payload, j));
      return json(result);
    }

    if (action === "resume-or-new-session") {
      const { materia, username, langs } = body;
      if (!username || !materia) return bad("username y materia requeridos");

      const open = await auto((j) =>
        db.sbGet("sessions", `username=eq.${enc(username)}&materia=eq.${enc(materia)}&ended_at=is.null&order=started_at.desc&limit=1`, j)
      ).catch(() => []);

      if (open?.length) {
        const segs = await auto((j) =>
          db.sbGet("segments", `session_id=eq.${open[0].id}&order=recorded_at.asc&select=id,text,recorded_at`, j)
        ).catch(() => []);
        return json({ session_id: open[0].id, resumed: true, segments: segs || [] });
      }

      const session_id = crypto.randomUUID();
      await auto((j) =>
        db.sbPost("sessions", { id: session_id, materia, started_at: new Date().toISOString(), langs: langs || ["es"], file_path: "", username }, j)
      );
      return json({ session_id, resumed: false, segments: [] });
    }

    if (action === "close-session") {
      const { session_id } = body;
      if (!session_id) return bad("session_id requerido");
      await auto((j) => db.sbPatch("sessions", `id=eq.${session_id}`, { ended_at: new Date().toISOString() }, j));
      return json({ ok: true });
    }

    if (action === "push-segment") {
      const { segment_id, session_id, materia, text, username } = body;
      const payload = {
        id: segment_id,
        session_id,
        materia: materia || "Sin materia",
        text,
        recorded_at: new Date().toISOString(),
      };
      if (username) payload.username = username;

      const result = await auto((j) => db.sbPost("segments", payload, j));

      if (username) {
        const userRows = await auto((j) => db.sbGet("triskl_users", `username=eq.${enc(username)}&select=id,total_words`, j)).catch(() => []);
        if (userRows?.length) {
          const words = (text || "").split(/\s+/).filter(Boolean).length;
          await auto((j) => grantXP(db, userRows[0].id, xpForPub(words), j)).catch(() => null);
          await auto((j) =>
            db.sbPatch("triskl_users", `id=eq.${userRows[0].id}`, { total_words: (userRows[0].total_words || 0) + words }, j)
          ).catch(() => null);
        }
      }
      return json(result);
    }

    if (action === "delete-session") {
      const { session_id } = body;
      if (!session_id) return bad("session_id requerido");
      await auto((j) => db.sbDelete("segments", `session_id=eq.${session_id}`, j)).catch(() => null);
      await auto((j) => db.sbDelete("sessions", `id=eq.${session_id}`, j));
      return json({ ok: true });
    }

    if (action === "delete-session-segments") {
      const { session_id } = body;
      if (!session_id) return bad("session_id requerido");
      await auto((j) => db.sbDelete("segments", `session_id=eq.${session_id}`, j));
      return json({ ok: true });
    }

    // ========== BRANDING ==========
    if (action === "branding") {
      try {
        const r = await fetch("http://pera.com.uy/data/internal/triskl.txt", {
          headers: { "User-Agent": "triskl/web" },
          cf: { cacheTtl: 300, cacheEverything: true },
        });
        if (!r.ok) return json({ raw: "" });
        return json({ raw: await r.text() });
      } catch (_) {
        return json({ raw: "" });
      }
    }

    // ========== HEALTH ==========
    if (action === "health") {
      return json({ status: "ok", runtime: "cloudflare-pages", timestamp: new Date().toISOString() });
    }

    return bad(`Acción desconocida: ${action}`, 404);
  } catch (err) {
    console.error("[handler ERROR]", err?.message);
    return json({ error: err?.message || "Error interno" }, 500);
  }
}
