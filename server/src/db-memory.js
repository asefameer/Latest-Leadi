import { randomBytes, scryptSync, timingSafeEqual } from "crypto";

let userSeq = 1;
let authEventSeq = 1;
let mediaAssetSeq = 1;
let messageSeq = 1;

const users = [];
const sessions = new Map();
const authEvents = [];
const contentSettings = new Map();
const leaderboardRecords = new Map();
const siteCopy = new Map();
const mediaAssets = [];
const chatMessages = [];

const normalizePhone = (phone) => String(phone || "").replace(/\s/g, "");

const hashPassword = (password, salt) => {
  return scryptSync(password, salt, 64).toString("hex");
};

const nowIso = () => new Date().toISOString();

export function validateBdPhone(phone) {
  const bdPhoneRegex = /^(\+880|880|0)1[3-9]\d{8}$/;
  return bdPhoneRegex.test(normalizePhone(phone));
}

export function createUser({ email, phone, password, role = "viewer" }) {
  const normalizedEmail = String(email || "").toLowerCase();
  const normalizedPhone = normalizePhone(phone);

  if (users.some((u) => u.email === normalizedEmail)) {
    throw new Error("Email already exists");
  }

  if (users.some((u) => u.phone === normalizedPhone)) {
    throw new Error("Phone already exists");
  }

  const passwordSalt = randomBytes(16).toString("hex");
  const passwordHash = hashPassword(password, passwordSalt);
  const user = {
    id: userSeq++,
    email: normalizedEmail,
    phone: normalizedPhone,
    password_hash: passwordHash,
    password_salt: passwordSalt,
    role,
    created_at: nowIso(),
  };
  users.push(user);

  return getUserById(user.id);
}

export function getUserByEmail(email) {
  const normalizedEmail = String(email || "").toLowerCase();
  return users.find((u) => u.email === normalizedEmail) || null;
}

export function hasAdminUser() {
  return users.some((u) => u.role === "admin");
}

export function getUserById(userId) {
  const user = users.find((u) => u.id === Number(userId));
  if (!user) {
    return null;
  }

  return {
    id: user.id,
    email: user.email,
    phone: user.phone,
    role: user.role,
    created_at: user.created_at,
  };
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
  const expiresAt = Date.now() + ttlHours * 60 * 60 * 1000;
  sessions.set(token, { token, user_id: Number(userId), expiresAt, createdAt: nowIso() });
  return token;
}

export function getSessionWithUser(token) {
  const session = sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    if (session) {
      sessions.delete(token);
    }
    return null;
  }

  const user = users.find((u) => u.id === session.user_id);
  if (!user) {
    return null;
  }

  return {
    token: session.token,
    user_id: session.user_id,
    expires_at: new Date(session.expiresAt).toISOString(),
    id: user.id,
    email: user.email,
    phone: user.phone,
    role: user.role,
  };
}

export function deleteSession(token) {
  sessions.delete(token);
}

export function cleanupExpiredSessions() {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt <= now) {
      sessions.delete(token);
    }
  }
}

export function recordAuthEvent({ userId = null, email = null, eventType, ipAddress = null, userAgent = null }) {
  authEvents.push({
    id: authEventSeq++,
    userId,
    email: email ? String(email).toLowerCase() : null,
    eventType,
    ipAddress,
    userAgent,
    createdAt: nowIso(),
    role: users.find((u) => u.id === Number(userId))?.role || null,
  });
}

export function listAuthEvents(limit = 200) {
  return authEvents
    .slice()
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .slice(0, limit);
}

export function listContentSettings() {
  return Object.fromEntries(contentSettings.entries());
}

export function setContentSettings(settings = {}, _updatedBy = null) {
  for (const [key, value] of Object.entries(settings)) {
    contentSettings.set(key, String(value));
  }
}

export function replaceLeaderboardRecords(records = []) {
  leaderboardRecords.clear();
  for (const item of records) {
    leaderboardRecords.set(String(item.id), { payload: item, updatedAt: nowIso() });
  }
}

export function listLeaderboardRecords() {
  return Array.from(leaderboardRecords.values())
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
    .map((row) => row.payload);
}

export function upsertSiteCopy(entries = {}, _updatedBy = null) {
  for (const [key, value] of Object.entries(entries)) {
    siteCopy.set(key, String(value ?? ""));
  }
}

export function listSiteCopy() {
  return Object.fromEntries(siteCopy.entries());
}

export function addMediaAsset({ assetType, fileName, mimeType, fileSize, storageUrl, uploadedBy = null }) {
  const id = mediaAssetSeq++;
  mediaAssets.push({
    id,
    assetType,
    fileName,
    mimeType: mimeType || null,
    fileSize: fileSize || 0,
    storageUrl,
    uploadedBy,
    createdAt: nowIso(),
  });
  return id;
}

export function listMediaAssets(limit = 200) {
  return mediaAssets
    .slice()
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .slice(0, limit);
}

export function addMessage(userId, message, reply) {
  const id = messageSeq++;
  chatMessages.push({
    id,
    user_id: String(userId),
    message,
    reply,
    created_at: nowIso(),
  });

  return {
    lastInsertRowid: id,
    lastID: id,
  };
}

export function getMessageHistory(userId, limit = 50) {
  const key = String(userId);
  return chatMessages
    .filter((m) => m.user_id === key)
    .slice(-limit);
}

export function closeDb() {
  // no-op for in-memory fallback
}

if (!getUserByEmail("admin@topperformers.com")) {
  createUser({
    email: "admin@topperformers.com",
    phone: "+8801700000000",
    password: "admin123",
    role: "admin",
  });
}
