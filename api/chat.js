// ============================================================
// /api/chat.js
// Nuevo endpoint de chat, usando JWT para autenticación
// y llamando a la API de Servo con reintentos.
// ============================================================

import { createClient } from '@supabase/supabase-js';

// ─── Configuración ────────────────────────────────────────────────────────────
const SUPABASE_URL          = process.env.LINKTR;
const SUPABASE_ANON         = process.env.ANONTR;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;

// ─── Cliente Supabase (para verificar usuario) ──────────────────────────────
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON);

// ─── Contexto fijo del asistente (igual que el anterior) ────────────────────
const CONTEXT = [
  {
    role: 'assistant',
    content: '¡Hola! Soy Servo, tu asistente virtual. ¿En qué puedo ayudarte hoy? Puedo responder preguntas sobre cómo usar la plataforma, registro, búsqueda de servicios, y más.'
  }
];

const SERVO_API = 'https://servo.com.uy/api/support/chat';
const MAX_RETRIES = 20;

// ─── Handler principal ────────────────────────────────────────────────────────
export default async function handler(req, res) {
  // Solo permitir POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  try {
    // 1. Validar autenticación (JWT)
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Se requiere autenticación (Bearer token)' });
    }
    const jwt = authHeader.split(' ')[1];

    // 2. Verificar usuario con Supabase
    const { data: user, error: userError } = await supabase.auth.getUser(jwt);
    if (userError || !user?.user) {
      return res.status(401).json({ error: 'Token inválido o expirado' });
    }
    const userId = user.user.id;

    // 3. Extraer payload
    const { message, conversationHistory, context } = req.body;
    if (!message || typeof message !== 'string' || message.trim() === '') {
      return res.status(400).json({ error: 'Falta el mensaje' });
    }

    // 4. Construir historial completo
    let fullHistory = [
      ...CONTEXT,
      ...(Array.isArray(conversationHistory) ? conversationHistory : [])
    ];

    // Si hay contexto adicional (material adjunto), inyectar como sistema
    if (context && typeof context === 'object' && context.text) {
      const sysMsg = {
        role: 'system',
        content: `[CONTEXTO ADICIONAL] ${context.label || 'Material adjunto'}:\n${context.text}`
      };
      fullHistory = [sysMsg, ...fullHistory];
    }

    // 5. Llamar a Servo con reintentos
    let retries = 0;
    let responseText = '';

    while (retries < MAX_RETRIES) {
      try {
        const payload = {
          message: message.trim(),
          conversationHistory: fullHistory
        };

        const servoRes = await fetch(SERVO_API, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
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

        // Si NO contiene "servo" (insensible a mayúsculas), salimos
        if (!/servo/i.test(responseText)) {
          break;
        }

        retries++;
        await new Promise(resolve => setTimeout(resolve, 500));
      } catch (err) {
        console.error('Error en llamada a SERVO:', err);
        retries++;
        if (retries >= MAX_RETRIES) {
          responseText = '⚠️ No se pudo obtener una respuesta válida después de varios intentos.';
        }
      }
    }

    // 6. (Opcional) Guardar la conversación en la base de datos
    //    Descomentar si se dispone de una tabla "chat_messages"
    /*
    try {
      const { error: insertError } = await supabase
        .from('chat_messages')
        .insert([
          { user_id: userId, role: 'user', content: message, created_at: new Date().toISOString() },
          { user_id: userId, role: 'assistant', content: responseText, created_at: new Date().toISOString() }
        ]);
      if (insertError) console.warn('No se pudo guardar el mensaje:', insertError);
    } catch (_) {}
    */

    // 7. Respuesta exitosa
    return res.status(200).json({ response: responseText });

  } catch (error) {
    console.error('[chat.js] Error general:', error);
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
}
