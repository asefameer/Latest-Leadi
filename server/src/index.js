import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import { chatLimiter } from "./middleware.js";
import { addMessage, getMessageHistory, closeDb } from "./db.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.resolve(__dirname, "../public");

if (!N8N_WEBHOOK_URL) {
  console.warn("WARN: N8N_WEBHOOK_URL is not set; chatbot endpoint is temporarily disabled");
}

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(publicDir));

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Chat endpoint: POST /api/chat
// Body: { userId: string, text: string }
// Returns: { reply: string, messageId: number }
app.post("/api/chat", chatLimiter, async (req, res) => {
  const { userId, text } = req.body;

  if (!userId || !text) {
    return res.status(400).json({ error: "Missing userId or text" });
  }

  if (!N8N_WEBHOOK_URL) {
    return res.status(503).json({
      error: "Chatbot backend is temporarily unavailable",
    });
  }

  try {
    // Forward to n8n webhook with user context
    const n8nResponse = await fetch(N8N_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, userId }),
    });

    if (!n8nResponse.ok) {
      const errorText = await n8nResponse.text();
      console.error(`n8n error: ${n8nResponse.status} ${errorText}`);
      return res
        .status(502)
        .json({ error: "Failed to reach chatbot backend" });
    }

    let reply;
    try {
      const data = await n8nResponse.json();
      reply = data.reply || data.message || JSON.stringify(data);
    } catch (e) {
      reply = await n8nResponse.text();
    }

    // Persist message and reply
    const result = addMessage(userId, text, reply);

    res.json({ reply, messageId: result.lastID });
  } catch (err) {
    console.error("Error processing chat:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get chat history for a user
app.get("/api/chat/history/:userId", (req, res) => {
  const { userId } = req.params;
  const limit = parseInt(req.query.limit) || 50;

  try {
    const history = getMessageHistory(userId, limit);
    res.json({ history });
  } catch (err) {
    console.error("Error fetching history:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api") || req.path === "/health") {
    return next();
  }

  return res.sendFile(path.join(publicDir, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Chatbot backend running on http://localhost:${PORT}`);
  console.log(`Rate limit: 20 messages per minute per user`);
});

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("Shutting down...");
  closeDb();
  process.exit(0);
});
