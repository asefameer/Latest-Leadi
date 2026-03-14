import Database from "better-sqlite3";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { randomBytes, scryptSync, timingSafeEqual } from "crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Use the persistent /home volume on Azure App Service so data survives
// deployments. Fall back to a local path for non-Azure environments.
const dbDir = process.env.HOME
  ? path.join(process.env.HOME, "data")
  : path.join(__dirname, "..");
fs.mkdirSync(dbDir, { recursive: true });
const dbPath = process.env.DB_PATH || path.join(dbDir, "chatbot.db");

const db = new Database(dbPath);

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    message TEXT NOT NULL,
    reply TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_user_id ON chat_messages(user_id);

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  );

  CREATE TABLE IF NOT EXISTS auth_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    email TEXT,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  );

  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_auth_events_created_at ON auth_events(created_at);

  CREATE TABLE IF NOT EXISTS content_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_by INTEGER,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS media_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_type TEXT NOT NULL,
    file_name TEXT NOT NULL,
    mime_type TEXT,
    file_size INTEGER,
    storage_url TEXT NOT NULL,
    uploaded_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS site_copy (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_by INTEGER,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS leaderboard_records (
    id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_media_assets_created_at ON media_assets(created_at);
`);

const normalizePhone = (phone) => phone.replace(/\s/g, "");

const hashPassword = (password, salt) => {
  return scryptSync(password, salt, 64).toString("hex");
};

export function validateBdPhone(phone) {
  const bdPhoneRegex = /^(\+880|880|0)1[3-9]\d{8}$/;
  return bdPhoneRegex.test(normalizePhone(phone));
}

export function createUser({ email, phone, password, role = "viewer" }) {
  const passwordSalt = randomBytes(16).toString("hex");
  const passwordHash = hashPassword(password, passwordSalt);

  const stmt = db.prepare(
    "INSERT INTO users (email, phone, password_hash, password_salt, role) VALUES (?, ?, ?, ?, ?)"
  );

  const result = stmt.run(email.toLowerCase(), normalizePhone(phone), passwordHash, passwordSalt, role);
  return getUserById(result.lastInsertRowid);
}

export function getUserByEmail(email) {
  const stmt = db.prepare("SELECT id, email, phone, password_hash, password_salt, role, created_at FROM users WHERE email = ?");
  return stmt.get(email.toLowerCase());
}

export function hasAdminUser() {
  const stmt = db.prepare("SELECT COUNT(1) as count FROM users WHERE role = 'admin'");
  const row = stmt.get();
  return Number(row?.count || 0) > 0;
}

export function getUserById(userId) {
  const stmt = db.prepare("SELECT id, email, phone, role, created_at FROM users WHERE id = ?");
  return stmt.get(userId);
}

export function verifyUserPassword(user, plainPassword) {
  if (!user?.password_hash || !user?.password_salt) {
    return false;
  }

  const actualHash = Buffer.from(user.password_hash, "hex");
  const compareHash = Buffer.from(hashPassword(plainPassword, user.password_salt), "hex");

  if (actualHash.length !== compareHash.length) {
    return false;
  }

  return timingSafeEqual(actualHash, compareHash);
}

export function createSession(userId, ttlHours = 24) {
  const token = randomBytes(48).toString("hex");
  const stmt = db.prepare(
    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', ?))"
  );
  stmt.run(token, userId, `+${ttlHours} hours`);
  return token;
}

export function getSessionWithUser(token) {
  const stmt = db.prepare(`
    SELECT
      s.token,
      s.user_id,
      s.expires_at,
      u.id,
      u.email,
      u.phone,
      u.role
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = ?
      AND datetime(s.expires_at) > datetime('now')
    LIMIT 1
  `);

  return stmt.get(token);
}

export function deleteSession(token) {
  const stmt = db.prepare("DELETE FROM sessions WHERE token = ?");
  stmt.run(token);
}

export function cleanupExpiredSessions() {
  const stmt = db.prepare("DELETE FROM sessions WHERE datetime(expires_at) <= datetime('now')");
  stmt.run();
}

export function recordAuthEvent({ userId = null, email = null, eventType, ipAddress = null, userAgent = null }) {
  const stmt = db.prepare(
    "INSERT INTO auth_events (user_id, email, event_type, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)"
  );
  stmt.run(userId, email ? email.toLowerCase() : null, eventType, ipAddress, userAgent);
}

export function listAuthEvents(limit = 200) {
  const stmt = db.prepare(`
    SELECT
      ae.id,
      ae.user_id as userId,
      ae.email,
      ae.event_type as eventType,
      ae.ip_address as ipAddress,
      ae.user_agent as userAgent,
      ae.created_at as createdAt,
      u.role
    FROM auth_events ae
    LEFT JOIN users u ON u.id = ae.user_id
    ORDER BY ae.created_at DESC
    LIMIT ?
  `);
  return stmt.all(limit);
}

export function listContentSettings() {
  const stmt = db.prepare("SELECT key, value FROM content_settings");
  const rows = stmt.all();
  return rows.reduce((acc, row) => {
    acc[row.key] = row.value;
    return acc;
  }, {});
}

export function setContentSettings(settings = {}, updatedBy = null) {
  const upsertStmt = db.prepare(`
    INSERT INTO content_settings (key, value, updated_by, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET
      value = excluded.value,
      updated_by = excluded.updated_by,
      updated_at = datetime('now')
  `);

  const transaction = db.transaction((entries) => {
    for (const [key, value] of entries) {
      upsertStmt.run(key, String(value), updatedBy);
    }
  });

  transaction(Object.entries(settings));
}

export function replaceLeaderboardRecords(records = []) {
  const clearStmt = db.prepare("DELETE FROM leaderboard_records");
  const insertStmt = db.prepare(
    "INSERT INTO leaderboard_records (id, payload, updated_at) VALUES (?, ?, datetime('now'))"
  );

  const transaction = db.transaction((nextRecords) => {
    clearStmt.run();
    for (const item of nextRecords) {
      insertStmt.run(String(item.id), JSON.stringify(item));
    }
  });

  transaction(records);
}

export function listLeaderboardRecords() {
  const stmt = db.prepare("SELECT payload FROM leaderboard_records ORDER BY updated_at DESC");
  return stmt.all().map((row) => {
    try {
      return JSON.parse(row.payload);
    } catch {
      return null;
    }
  }).filter(Boolean);
}

export function upsertSiteCopy(entries = {}, updatedBy = null) {
  const stmt = db.prepare(`
    INSERT INTO site_copy (key, value, updated_by, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET
      value = excluded.value,
      updated_by = excluded.updated_by,
      updated_at = datetime('now')
  `);

  const transaction = db.transaction((items) => {
    for (const [key, value] of items) {
      stmt.run(key, String(value ?? ""), updatedBy);
    }
  });

  transaction(Object.entries(entries));
}

export function listSiteCopy() {
  const stmt = db.prepare("SELECT key, value FROM site_copy");
  const rows = stmt.all();
  return rows.reduce((acc, row) => {
    acc[row.key] = row.value;
    return acc;
  }, {});
}

export function addMediaAsset({ assetType, fileName, mimeType, fileSize, storageUrl, uploadedBy = null }) {
  const stmt = db.prepare(`
    INSERT INTO media_assets (asset_type, file_name, mime_type, file_size, storage_url, uploaded_by)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(assetType, fileName, mimeType || null, fileSize || 0, storageUrl, uploadedBy);
  return result.lastInsertRowid;
}

export function listMediaAssets(limit = 200) {
  const stmt = db.prepare(`
    SELECT
      id,
      asset_type as assetType,
      file_name as fileName,
      mime_type as mimeType,
      file_size as fileSize,
      storage_url as storageUrl,
      uploaded_by as uploadedBy,
      created_at as createdAt
    FROM media_assets
    ORDER BY created_at DESC
    LIMIT ?
  `);

  return stmt.all(limit);
}

function ensureDefaultAdmin() {
  const existingAdmin = getUserByEmail("admin@topperformers.com");
  if (!existingAdmin) {
    createUser({
      email: "admin@topperformers.com",
      phone: "+8801700000000",
      password: "admin123",
      role: "admin",
    });
  }
}

ensureDefaultAdmin();

export function addMessage(userId, message, reply) {
  const stmt = db.prepare(
    "INSERT INTO chat_messages (user_id, message, reply, created_at) VALUES (?, ?, ?, datetime('now'))"
  );
  return stmt.run(userId, message, reply);
}

export function getMessageHistory(userId, limit = 50) {
  const stmt = db.prepare(
    "SELECT * FROM chat_messages WHERE user_id = ? ORDER BY created_at DESC LIMIT ?"
  );
  return stmt.all(userId, limit).reverse();
}

export function closeDb() {
  db.close();
}
