import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import { chatLimiter } from "./middleware.js";
import {
  addMessage,
  getMessageHistory,
  closeDb,
  createUser,
  getUserByEmail,
  verifyUserPassword,
  createSession,
  getSessionWithUser,
  deleteSession,
  cleanupExpiredSessions,
  recordAuthEvent,
  listAuthEvents,
  validateBdPhone,
} from "./db.js";

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

const toSafeUser = (user) => ({
  id: String(user.id),
  email: user.email,
  phone: user.phone,
  role: user.role,
});

const getBearerToken = (req) => {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return null;
  }

  return authHeader.slice(7).trim();
};

const requireAuth = (req, res, next) => {
  cleanupExpiredSessions();
  const token = getBearerToken(req);

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const sessionUser = getSessionWithUser(token);
  if (!sessionUser) {
    return res.status(401).json({ error: "Session expired or invalid" });
  }

  req.authToken = token;
  req.user = {
    id: sessionUser.id,
    email: sessionUser.email,
    phone: sessionUser.phone,
    role: sessionUser.role,
  };

  return next();
};

const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }

  return next();
};

app.post("/api/auth/signup", (req, res) => {
  const { email, phone, password } = req.body;

  if (!email || !phone || !password) {
    return res.status(400).json({ error: "Email, phone, and password are required" });
  }

  if (!email.includes("@")) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  if (!validateBdPhone(phone)) {
    return res.status(400).json({
      error: "Invalid Bangladesh phone number. Use format: +8801XXXXXXXXX or 01XXXXXXXXX",
    });
  }

  if (getUserByEmail(email)) {
    return res.status(409).json({ error: "Email already registered" });
  }

  try {
    const user = createUser({
      email,
      phone,
      password,
      role: "viewer",
    });

    const token = createSession(user.id);

    recordAuthEvent({
      userId: user.id,
      email: user.email,
      eventType: "signup",
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"] || null,
    });

    return res.status(201).json({
      token,
      user: toSafeUser(user),
    });
  } catch (error) {
    console.error("Signup error:", error);
    return res.status(500).json({ error: "Failed to create account" });
  }
});

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = getUserByEmail(email);
  if (!user || !verifyUserPassword(user, password)) {
    recordAuthEvent({
      userId: user?.id || null,
      email,
      eventType: "login_failed",
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"] || null,
    });

    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = createSession(user.id);

  recordAuthEvent({
    userId: user.id,
    email: user.email,
    eventType: "login",
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"] || null,
  });

  return res.json({
    token,
    user: toSafeUser(user),
  });
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  return res.json({ user: toSafeUser(req.user) });
});

app.post("/api/auth/logout", requireAuth, (req, res) => {
  deleteSession(req.authToken);

  recordAuthEvent({
    userId: req.user.id,
    email: req.user.email,
    eventType: "logout",
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"] || null,
  });

  return res.json({ success: true });
});

app.get("/api/admin/auth-events", requireAuth, requireAdmin, (req, res) => {
  const limitRaw = Number.parseInt(req.query.limit, 10);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 1000) : 200;

  const events = listAuthEvents(limit);
  return res.json({ events });
});

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
    const reply = "Thanks for your message. Chatbot automation is temporarily disabled, but we received your request.";
    const result = addMessage(userId, text, reply);
    return res.json({
      reply,
      messageId: result.lastID,
      mocked: true,
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
