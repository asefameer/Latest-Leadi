import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import { chatLimiter } from "./middleware.js";

// Fallback to in-memory persistence when native sqlite binding fails to load.
let dbApi;
try {
  dbApi = await import("./db.js");
} catch (error) {
  console.error("Failed to load sqlite database, using in-memory fallback:", error);
  dbApi = await import("./db-memory.js");
}

const {
  addMessage,
  getMessageHistory,
  closeDb,
  createUser,
  getUserByEmail,
  verifyUserPassword,
  createSession,
  getSessionWithUser,
  deleteSession,
  hasAdminUser,
  cleanupExpiredSessions,
  recordAuthEvent,
  listAuthEvents,
  validateBdPhone,
  listContentSettings,
  setContentSettings,
  replaceLeaderboardRecords,
  listLeaderboardRecords,
  upsertSiteCopy,
  listSiteCopy,
  addMediaAsset,
  listMediaAssets,
} = dbApi;

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.resolve(__dirname, "../public");

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024,
  },
});

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
    const role = hasAdminUser() ? "viewer" : "admin";

    const user = createUser({
      email,
      phone,
      password,
      role,
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

app.get("/api/content/public", (_req, res) => {
  const settings = listContentSettings();
  const tsoData = listLeaderboardRecords();
  const siteCopy = listSiteCopy();

  return res.json({
    settings,
    tsoData,
    siteCopy,
  });
});

app.put("/api/admin/content/settings", requireAuth, requireAdmin, (req, res) => {
  const { settings } = req.body;

  if (!settings || typeof settings !== "object") {
    return res.status(400).json({ error: "settings object is required" });
  }

  setContentSettings(settings, req.user.id);
  return res.json({ success: true });
});

app.put("/api/admin/content/tso", requireAuth, requireAdmin, (req, res) => {
  const { tsoData } = req.body;

  if (!Array.isArray(tsoData)) {
    return res.status(400).json({ error: "tsoData array is required" });
  }

  replaceLeaderboardRecords(tsoData);
  return res.json({ success: true, count: tsoData.length });
});

app.get("/api/admin/content/assets", requireAuth, requireAdmin, (req, res) => {
  const limitRaw = Number.parseInt(req.query.limit, 10);
  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 1000) : 200;
  const assets = listMediaAssets(limit);
  return res.json({ assets });
});

app.post("/api/admin/content/upload", requireAuth, requireAdmin, upload.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  let assetType = "file";
  if (req.file.mimetype.startsWith("image/")) {
    assetType = "image";
  } else if (req.file.mimetype.startsWith("video/")) {
    assetType = "video";
  } else if (req.file.mimetype === "text/csv" || req.file.originalname.toLowerCase().endsWith(".csv")) {
    assetType = "csv";
  }

  let uploaded;
  try {
    const { uploadToBlob } = await import("./storage.js");
    uploaded = await uploadToBlob({
      buffer: req.file.buffer,
      originalName: req.file.originalname,
      mimeType: req.file.mimetype,
    });
  } catch (error) {
    console.error("Blob upload failed:", error);
    return res.status(500).json({ error: "Failed to upload file to Azure Blob Storage" });
  }

  const storageUrl = uploaded.url;

  const assetId = addMediaAsset({
    assetType,
    fileName: req.file.originalname,
    mimeType: req.file.mimetype,
    fileSize: req.file.size,
    storageUrl,
    uploadedBy: req.user.id,
  });

  return res.status(201).json({
    asset: {
      id: assetId,
      assetType,
      fileName: req.file.originalname,
      mimeType: req.file.mimetype,
      fileSize: req.file.size,
      storageUrl,
    },
  });
});

app.get("/api/content/site-copy", (_req, res) => {
  const siteCopy = listSiteCopy();
  return res.json({ siteCopy });
});

app.put("/api/admin/content/site-copy", requireAuth, requireAdmin, (req, res) => {
  const { siteCopy } = req.body;

  if (!siteCopy || typeof siteCopy !== "object") {
    return res.status(400).json({ error: "siteCopy object is required" });
  }

  upsertSiteCopy(siteCopy, req.user.id);
  return res.json({ success: true });
});

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Chat endpoint: POST /api/chat
// Body: { userId: string, text: string }
// Returns: { reply: string, messageId: number }
app.post("/api/chat", chatLimiter, (req, res) => {
  const { userId, text } = req.body;

  if (!userId || !text) {
    return res.status(400).json({ error: "Missing userId or text" });
  }

  const reply = "Thanks for your message! Our chatbot will be back soon.";
  const result = addMessage(userId, text, reply);
  return res.json({ reply, messageId: result.lastInsertRowid ?? result.lastID });
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
