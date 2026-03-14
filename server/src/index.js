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
  replaceTsoUsers,
  getTsoByUsername,
  verifyTsoPassword,
  listTsoUsers,
  replaceMgmtUsers,
  getMgmtByUserId,
  verifyMgmtPassword,
  upsertTsoImage,
  listTsoImages,
  clearTsoImages,
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

const toSafeUser = (user) => {
  const base = {
    id: String(user.id),
    role: user.role,
  };
  if (user.role === "admin" || user.role === "viewer") {
    base.email = user.email;
    base.phone = user.phone;
  }
  return base;
};

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

  const sessionData = getSessionWithUser(token);
  if (!sessionData) {
    return res.status(401).json({ error: "Session expired or invalid" });
  }

  req.authToken = token;
  // Build req.user for all session types
  const meta = sessionData.meta || {};
  if (sessionData.user_type === "tso") {
    req.user = {
      id: String(sessionData.user_id),
      role: "tso",
      username: meta.username,
      wing: meta.wing,
      division: meta.division,
      territory_code: meta.territory_code,
      territory: meta.territory,
    };
  } else if (sessionData.user_type === "management") {
    req.user = {
      id: String(sessionData.user_id),
      role: "management",
      display_name: meta.display_name,
      visibility: meta.visibility,
    };
  } else {
    req.user = {
      id: String(sessionData.id),
      email: sessionData.email,
      phone: sessionData.phone,
      role: sessionData.role,
    };
  }

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
  return res.json({ user: req.user });
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

// ─── TSO Login ───────────────────────────────────────────────────────────────

app.post("/api/auth/tso-login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  const tsoUser = getTsoByUsername(username);
  if (!tsoUser || !verifyTsoPassword(tsoUser, password)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const meta = {
    username: tsoUser.username,
    wing: tsoUser.wing,
    division: tsoUser.division,
    territory_code: tsoUser.territory_code,
    territory: tsoUser.territory,
  };
  const token = createSession(tsoUser.id, 24, "tso", meta);

  return res.json({
    token,
    user: {
      id: String(tsoUser.id),
      role: "tso",
      ...meta,
    },
  });
});

// ─── Management Login ────────────────────────────────────────────────────────

app.post("/api/auth/mgmt-login", (req, res) => {
  const { userId, password } = req.body;

  if (!userId || !password) {
    return res.status(400).json({ error: "User ID and password are required" });
  }

  const mgmtUser = getMgmtByUserId(userId);
  if (!mgmtUser || !verifyMgmtPassword(mgmtUser, password)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const meta = {
    display_name: mgmtUser.display_name,
    visibility: mgmtUser.visibility,
  };
  const token = createSession(mgmtUser.id, 24, "management", meta);

  return res.json({
    token,
    user: {
      id: String(mgmtUser.id),
      role: "management",
      ...meta,
    },
  });
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
  const tsoImages = listTsoImages();

  return res.json({
    settings,
    tsoData,
    siteCopy,
    tsoImages,
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

// ─── TSO Credentials CSV Upload ──────────────────────────────────────────────

app.post("/api/admin/upload/tso-credentials", requireAuth, requireAdmin, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const csvText = req.file.buffer.toString("utf8");
  const lines = csvText.trim().split(/\r?\n/);
  if (lines.length < 2) return res.status(400).json({ error: "CSV must have headers and at least one row" });

  const headers = lines[0].split(",").map((h) => h.trim());
  const required = ["Wing", "Division", "Territory_Code", "Territory", "Username", "Password"];
  for (const col of required) {
    if (!headers.includes(col)) return res.status(400).json({ error: `Missing column: ${col}` });
  }

  const records = [];
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    const vals = lines[i].split(",").map((v) => v.trim());
    const row = {};
    headers.forEach((h, idx) => { row[h] = vals[idx] || ""; });
    if (!row.Username || !row.Password) continue;
    records.push({
      wing: row.Wing,
      division: row.Division,
      territory_code: row.Territory_Code,
      territory: row.Territory,
      username: row.Username,
      password: row.Password,
    });
  }

  try {
    replaceTsoUsers(records);
    return res.json({ success: true, count: records.length });
  } catch (err) {
    console.error("TSO credentials upload error:", err);
    return res.status(500).json({ error: "Failed to store TSO credentials" });
  }
});

// ─── Management Credentials CSV Upload ──────────────────────────────────────

app.post("/api/admin/upload/mgmt-credentials", requireAuth, requireAdmin, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const csvText = req.file.buffer.toString("utf8");
  const lines = csvText.trim().split(/\r?\n/);
  if (lines.length < 2) return res.status(400).json({ error: "CSV must have headers and at least one row" });

  const headers = lines[0].split(",").map((h) => h.trim());
  const required = ["Display_Name", "User_ID", "Password", "Visibility"];
  for (const col of required) {
    if (!headers.includes(col)) return res.status(400).json({ error: `Missing column: ${col}` });
  }

  const records = [];
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    const vals = lines[i].split(",").map((v) => v.trim());
    const row = {};
    headers.forEach((h, idx) => { row[h] = vals[idx] || ""; });
    if (!row.User_ID || !row.Password) continue;
    records.push({
      display_name: row.Display_Name,
      user_id: row.User_ID,
      password: row.Password,
      visibility: row.Visibility || "all",
    });
  }

  try {
    replaceMgmtUsers(records);
    return res.json({ success: true, count: records.length });
  } catch (err) {
    console.error("Management credentials upload error:", err);
    return res.status(500).json({ error: "Failed to store management credentials" });
  }
});

// ─── TSO Images ZIP Upload ───────────────────────────────────────────────────

app.post("/api/admin/upload/tso-images", requireAuth, requireAdmin, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const ext = req.file.originalname.split(".").pop()?.toLowerCase();
  if (ext !== "zip") {
    return res.status(400).json({ error: "Only ZIP files are supported" });
  }

  let unzipper;
  try {
    unzipper = await import("unzipper");
  } catch {
    return res.status(500).json({ error: "ZIP processing not available" });
  }

  let uploadModule;
  try {
    uploadModule = await import("./storage.js");
  } catch (err) {
    console.error("Storage not available:", err);
    return res.status(500).json({ error: "Storage not available" });
  }
  const { uploadToBlob } = uploadModule;

  try {
    clearTsoImages();
    const directory = await unzipper.Open.buffer(req.file.buffer);
    const results = { uploaded: 0, skipped: 0 };
    const imageExts = ["png", "jpg", "jpeg", "gif", "webp", "svg"];

    for (const file of directory.files) {
      if (file.type !== "File") continue;
      const baseName = file.path.split("/").pop();
      if (!baseName) continue;
      const dotIdx = baseName.lastIndexOf(".");
      if (dotIdx === -1) { results.skipped++; continue; }
      const fileExt = baseName.slice(dotIdx + 1).toLowerCase();
      if (!imageExts.includes(fileExt)) { results.skipped++; continue; }
      const territoryCode = baseName.slice(0, dotIdx).toUpperCase();
      if (!territoryCode) { results.skipped++; continue; }

      const buffer = await file.buffer();
      const mimeMap = { png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", svg: "image/svg+xml" };

      const uploaded = await uploadToBlob({
        buffer,
        originalName: `tso-image-${territoryCode}.${fileExt}`,
        mimeType: mimeMap[fileExt] || "image/jpeg",
      });

      upsertTsoImage(territoryCode, uploaded.url, baseName);
      results.uploaded++;
    }

    return res.json({ success: true, ...results });
  } catch (err) {
    console.error("TSO images upload error:", err);
    return res.status(500).json({ error: "Failed to process ZIP file" });
  }
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
