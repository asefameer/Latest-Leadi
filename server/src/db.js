import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";
import { randomBytes, scryptSync, timingSafeEqual } from "crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(__dirname, "..", "chatbot.db");

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
