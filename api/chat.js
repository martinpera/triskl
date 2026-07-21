// api/chat.js
// Contexto fijo que se añade al historial (está en el backend)
const CONTEXT = [
  {
    role: 'assistant',
    content: '¡Hola! Soy Servo, tu asistente virtual. ¿En qué puedo ayudarte hoy? Puedo responder preguntas sobre cómo usar la plataforma, registro, búsqueda de servicios, y más.'
  }
];

const SERVO_API = 'https://servo.com.uy/api/support/chat';
const MAX_RETRIES = 20; // hasta 20 reintentos

export default async function handler(req, res) {
  // Solo POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  try {
    const { message, conversationHistory } = req.body;

    if (!message) {
      return res.status(400).json({ error: 'Falta el mensaje' });
    }

    // Construir el historial completo: contexto + historial real
    const fullHistory = [...CONTEXT, ...(conversationHistory || [])];

    const payload = {
      message,
      conversationHistory: fullHistory
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
          throw new Error(`API respondió con ${response.status}`);
        }

        const data = await response.json();

        // Extraer la respuesta (igual que en el script Python)
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
        // Pequeña pausa entre reintentos (500ms)
        await new Promise(resolve => setTimeout(resolve, 500));
      } catch (err) {
        console.error('Error en llamada a SERVO:', err);
        retries++;
        if (retries >= MAX_RETRIES) {
          responseText = '⚠️ No se pudo obtener una respuesta válida después de varios intentos.';
        }
      }
    }

    // Devolver solo la respuesta (sin contar reintentos)
    return res.status(200).json({ response: responseText });

  } catch (error) {
    console.error('Error en la función:', error);
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
}
