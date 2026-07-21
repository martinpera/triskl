// /api/chat.js
// Usa el mismo sistema de autenticación que /api/handler: uuid + password
const SUPABASE_URL = process.env.LINKTR;
const SUPABASE_ANON = process.env.ANONTR;

// ─── Helpers (copiados de tu handler) ────────────────────────────────
function authHeaders(jwt) {
  return {
    "Content-Type": "application/json",
    "apikey": SUPABASE_ANON,
    "Authorization": `Bearer ${jwt || SUPABASE_ANON}`,
    "Prefer": "return=representation",
  };
}

async function sbGet(table, params = "", jwt = null) {
  const url = `${SUPABASE_URL}/rest/v1/${table}${params ? "?" + params : ""}`;
  const res = await fetch(url, { method: "GET", headers: authHeaders(jwt) });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`sbGet ${table}: ${err}`);
  }
  return res.json();
}

// ─── Handler principal ────────────────────────────────────────────────
export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Método no permitido" });
  }

  try {
    // 1. Autenticación con uuid + password (igual que en tu frontend)
    const { uuid, password, message, conversationHistory, context } = req.body;

    if (!uuid || !password) {
      return res.status(401).json({ error: "uuid y password requeridos" });
    }

    // Verificar que el usuario existe
    const users = await sbGet("triskl_users", `id=eq.${uuid}&password=eq.${password}`);
    if (!users || users.length === 0) {
      return res.status(401).json({ error: "Credenciales inválidas" });
    }

    // 2. Contexto fijo (asistente)
    const CONTEXT = [
      {
        role: "assistant",
        content:
          "¡Hola! Soy Servo, tu asistente virtual. ¿En qué puedo ayudarte hoy? Puedo responder preguntas sobre cómo usar la plataforma, registro, búsqueda de servicios, y más."
      }
    ];

    // 3. Construir historial completo
    let fullHistory = [
      ...CONTEXT,
      ...(Array.isArray(conversationHistory) ? conversationHistory : [])
    ];

    // Si hay contexto adicional (material adjunto)
    if (context && typeof context === "object" && context.text) {
      const sysMsg = {
        role: "system",
        content: `[CONTEXTO ADICIONAL] ${context.label || "Material adjunto"}:\n${context.text}`
      };
      fullHistory = [sysMsg, ...fullHistory];
    }

    // 4. Llamar a Servo con reintentos (igual que antes)
    const SERVO_API = "https://servo.com.uy/api/support/chat";
    const MAX_RETRIES = 20;
    let retries = 0;
    let responseText = "";

    while (retries < MAX_RETRIES) {
      try {
        const payload = {
          message: message.trim(),
          conversationHistory: fullHistory
        };

        const servoRes = await fetch(SERVO_API, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        if (!servoRes.ok) {
          throw new Error(`Servo respondió con ${servoRes.status}`);
        }

        const data = await servoRes.json();
        responseText =
          data.reply ||
          data.message ||
          data.content ||
          data.response ||
          JSON.stringify(data);

        // Si NO contiene "servo", salimos del bucle
        if (!/servo/i.test(responseText)) {
          break;
        }

        retries++;
        await new Promise(resolve => setTimeout(resolve, 500));
      } catch (err) {
        console.error("Error en llamada a SERVO:", err);
        retries++;
        if (retries >= MAX_RETRIES) {
          responseText = "⚠️ No se pudo obtener una respuesta válida después de varios intentos.";
        }
      }
    }

    // 5. Respuesta exitosa
    return res.status(200).json({ response: responseText });
  } catch (error) {
    console.error("[chat.js] Error:", error);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
}
