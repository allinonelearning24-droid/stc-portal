// ===== STC PORTAL - PRODUCTION BACKEND (Express + MongoDB) =====
// Save as: backend/server.js (recommended)
// Requires: npm i express cors dotenv jsonwebtoken bcryptjs cookie-parser helmet express-rate-limit multer xlsx mongoose
// Excel import endpoints:
//  - POST /api/admin/users/import/teachers (sheet: teachers)
//  - POST /api/admin/users/import/students (sheet: students)
//  - POST /api/admin/content/import (sheet: content)

const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const XLSX = require("xlsx");
const path = require("path");
const mongoose = require("mongoose");

dotenv.config();

const app = express();

// ===== ENV =====
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";

const MONGODB_URI = process.env.MONGODB_URI || "";
if (!MONGODB_URI) {
  console.error("❌ Missing MONGODB_URI in .env");
  process.exit(1);
}

const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "dev_refresh_change_me";
const ACCESS_TOKEN_EXPIRES = process.env.ACCESS_TOKEN_EXPIRES || "7d";
const REFRESH_TOKEN_DAYS = parseInt(process.env.REFRESH_TOKEN_DAYS || "365", 10);

const REFRESH_COOKIE_NAME = "stc_rt";
const REFRESH_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: NODE_ENV === "production",
  sameSite: NODE_ENV === "production" ? "none" : "lax",
  path: "/api/auth/refresh",
  maxAge: REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000,
};

// ===== SECURITY / MIDDLEWARE =====
app.use(
  helmet({
    // Your index.html uses CDN libs + inline onclick handlers; default CSP will block them.
    // Keep CSP disabled for now. Later: self-host libs + remove inline handlers -> enable CSP.
    contentSecurityPolicy: false,
  })
);

app.use(
  cors({
    origin: CORS_ORIGIN === "*" ? true : CORS_ORIGIN.split(",").map((x) => x.trim()),
    credentials: true,
  })
);

app.use(express.json({ limit: "5mb" }));
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const upload = multer({ storage: multer.memoryStorage() });

function sha256(str) {
  return crypto.createHash("sha256").update(String(str)).digest("hex");
}
function nowISO() {
  return new Date().toISOString();
}

// ===== MODELS =====
const SchoolSchema = new mongoose.Schema(
  {
    schoolId: { type: String, required: true, unique: true, index: true },
    name: { type: String, required: true },
    logoUrl: { type: String, default: "" },
    theme: { accent: { type: String, default: "#1d4ed8" } },
    deviceLimits: {
      student: { type: Number, default: 100 },
      teacher: { type: Number, default: 10 },
      admin: { type: Number, default: 10 },
    },
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true }
);

const UserSchema = new mongoose.Schema(
  {
    schoolId: { type: String, required: true, index: true },
    role: { type: String, enum: ["admin", "teacher", "student"], required: true, index: true },
    name: { type: String, default: "" },
    subject: { type: String, default: "" }, // teacher optional
    phone: { type: String, default: "" },
    email: { type: String, default: "" },
    roll: { type: String, default: "" }, // student
    className: { type: String, default: "" }, // student optional
    passwordHash: { type: String, required: true },
    firstLogin: { type: Boolean, default: true },
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true }
);
UserSchema.index({ schoolId: 1, email: 1 }, { unique: true, sparse: true });
UserSchema.index({ schoolId: 1, phone: 1 }, { unique: true, sparse: true });
UserSchema.index({ schoolId: 1, roll: 1 }, { unique: true, sparse: true });

const SessionSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true, ref: "User" },
    schoolId: { type: String, required: true, index: true },
    deviceId: { type: String, required: true },
    refreshHash: { type: String, required: true },
    createdAtISO: { type: String, required: true },
    lastSeenAtISO: { type: String, required: true },
    userAgent: { type: String, default: "" },
    ip: { type: String, default: "" },
  },
  { timestamps: true }
);
SessionSchema.index({ userId: 1, deviceId: 1 }, { unique: true });

const ContentItemSchema = new mongoose.Schema(
  {
    schoolId: { type: String, required: true, index: true }, // ALL or SCH001
    className: { type: String, default: "" },
    subject: { type: String, default: "" },
    chapter: { type: String, default: "" }, // for video/activity
    bookTitle: { type: String, default: "" }, // for worksheet/trm/answerkey/testpaper
    type: {
      type: String,
      enum: ["book", "video", "activity", "worksheet", "trm", "answerkey", "testpaper"],
      required: true,
      index: true,
    },
    title: { type: String, default: "" },
    url: { type: String, required: true },
    forRole: { type: String, default: "all" },
    sortOrder: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true }
);

const School = mongoose.model("School", SchoolSchema);
const User = mongoose.model("User", UserSchema);
const Session = mongoose.model("Session", SessionSchema);
const ContentItem = mongoose.model("ContentItem", ContentItemSchema);

// ===== AUTH HELPERS =====
function makeAccessToken(userDoc) {
  return jwt.sign(
    {
      uid: String(userDoc._id),
      sid: userDoc.schoolId,
      role: userDoc.role,
      subject: userDoc.subject || null,
      name: userDoc.name || "",
    },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRES }
  );
}

function makeRefreshToken(userDoc, sessionId) {
  return jwt.sign(
    { uid: String(userDoc._id), sid: userDoc.schoolId, role: userDoc.role, ses: sessionId },
    REFRESH_SECRET,
    { expiresIn: `${REFRESH_TOKEN_DAYS}d` }
  );
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, message: "Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (e) {
    return res.status(401).json({ ok: false, message: "Invalid/Expired token" });
  }
}

function optionalAuth(req, _res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) {
    req.user = { role: "guest" };
    return next();
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    req.user = { role: "guest" };
  }
  return next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ ok: false, message: "Forbidden" });
    }
    next();
  };
}

function isAllowedForRole(itemForRole, role) {
  const fr = String(itemForRole || "all").toLowerCase().trim();
  if (fr === "all") return true;
  if (fr === "student") return role === "student";
  if (fr === "teacher") return role === "teacher";
  if (fr === "admin") return role === "admin";
  if (fr === "teacher+admin") return role === "teacher" || role === "admin";
  return false;
}

async function getSchoolOrNull(schoolId) {
  return School.findOne({ schoolId, isActive: true }).lean();
}

async function getDeviceLimitForUser(userDoc) {
  const school = await getSchoolOrNull(userDoc.schoolId);
  const defaults = { student: 100, teacher: 10, admin: 10 };
  if (!school || !school.deviceLimits) return defaults[userDoc.role] || 10;
  return school.deviceLimits[userDoc.role] ?? (defaults[userDoc.role] || 10);
}

async function filterContentForUser(schoolId, role) {
  const items = await ContentItem.find({
    isActive: true,
    $or: [{ schoolId: "ALL" }, { schoolId }],
  })
    .lean()
    .sort({ sortOrder: 1, createdAt: 1 });

  const byRole = items.filter((x) => isAllowedForRole(x.forRole, role));

  // Students/guests: block teacher-only types
  if (role === "student" || role === "guest") {
    return byRole.filter((x) => {
      const t = String(x.type || "").toLowerCase();
      return t !== "trm" && t !== "answerkey" && t !== "testpaper";
    });
  }
  return byRole;
}

// ===== STATIC FRONTEND =====
app.use(express.static(path.join(__dirname, "../frontend")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

// ===== HEALTH =====
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "stc-portal-backend", time: nowISO() });
});

// ===== AUTH =====
app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const { schoolId, identifier, password, expectedRole, deviceId } = req.body || {};
    if (!schoolId || !identifier || !password) {
      return res.status(400).json({ ok: false, message: "schoolId, identifier, password required" });
    }
    if (!deviceId || String(deviceId).length < 6) {
      return res.status(400).json({ ok: false, message: "deviceId required" });
    }

    const user = await User.findOne({
      schoolId,
      isActive: true,
      $or: [{ phone: identifier }, { email: identifier }, { roll: identifier }],
    });

    if (!user) return res.status(401).json({ ok: false, message: "Invalid credentials" });
    if (expectedRole && user.role !== expectedRole) {
      return res.status(403).json({ ok: false, message: "Role mismatch" });
    }

    const ok = bcrypt.compareSync(password, user.passwordHash);
    if (!ok) return res.status(401).json({ ok: false, message: "Invalid credentials" });

    const limit = await getDeviceLimitForUser(user);

    const existingSessions = await Session.find({ userId: user._id }).lean();
    const alreadyOnThisDevice = existingSessions.find((s) => s.deviceId === String(deviceId));
    if (!alreadyOnThisDevice && existingSessions.length >= limit) {
      return res.status(429).json({
        ok: false,
        message: `Device limit reached (${existingSessions.length}/${limit}). Please logout from another device.`,
      });
    }

    const ua = req.headers["user-agent"] || "";
    const ip = req.ip || "";

    let session;
    if (alreadyOnThisDevice) {
      session = await Session.findOneAndUpdate(
        { userId: user._id, deviceId: String(deviceId) },
        { lastSeenAtISO: nowISO(), userAgent: ua, ip },
        { new: true }
      );
    } else {
      session = await Session.create({
        userId: user._id,
        schoolId: user.schoolId,
        deviceId: String(deviceId),
        refreshHash: "pending",
        createdAtISO: nowISO(),
        lastSeenAtISO: nowISO(),
        userAgent: ua,
        ip,
      });
    }

    const refreshToken = makeRefreshToken(user, String(session._id));
    await Session.updateOne({ _id: session._id }, { refreshHash: sha256(refreshToken) });

    const accessToken = makeAccessToken(user);
    const school = await getSchoolOrNull(schoolId);

    res.cookie(REFRESH_COOKIE_NAME, refreshToken, REFRESH_COOKIE_OPTIONS);

    return res.json({
      ok: true,
      token: accessToken,
      firstLogin: !!user.firstLogin,
      user: {
        id: String(user._id),
        role: user.role,
        subject: user.subject || "",
        schoolId: user.schoolId,
        name: user.name || "",
      },
      school: school ? { id: school.schoolId, name: school.name, logoUrl: school.logoUrl, theme: school.theme, deviceLimits: school.deviceLimits } : null,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

app.post("/api/auth/refresh", async (req, res) => {
  try {
    const rt = req.cookies?.[REFRESH_COOKIE_NAME];
    if (!rt) return res.status(401).json({ ok: false, message: "Missing refresh token" });

    let payload;
    try {
      payload = jwt.verify(rt, REFRESH_SECRET);
    } catch (e) {
      return res.status(401).json({ ok: false, message: "Invalid/Expired refresh token" });
    }

    const session = await Session.findById(payload.ses);
    if (!session) return res.status(401).json({ ok: false, message: "Session not found" });
    if (session.refreshHash !== sha256(rt)) {
      return res.status(401).json({ ok: false, message: "Refresh token mismatch" });
    }

    const user = await User.findById(payload.uid);
    if (!user || !user.isActive) return res.status(401).json({ ok: false, message: "User not found" });

    await Session.updateOne({ _id: session._id }, { lastSeenAtISO: nowISO() });

    const accessToken = makeAccessToken(user);
    return res.json({ ok: true, token: accessToken });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

app.post("/api/auth/logout", async (req, res) => {
  try {
    const rt = req.cookies?.[REFRESH_COOKIE_NAME];
    if (rt) {
      try {
        const payload = jwt.verify(rt, REFRESH_SECRET);
        await Session.deleteOne({ _id: payload.ses });
      } catch (_) {}
    }
    res.clearCookie(REFRESH_COOKIE_NAME, { path: "/api/auth/refresh" });
    return res.json({ ok: true, message: "Logged out" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

app.post("/api/auth/change-password", auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body || {};
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ ok: false, message: "New password must be 6+ chars" });
    }

    const user = await User.findById(req.user.uid);
    if (!user) return res.status(404).json({ ok: false, message: "User not found" });

    if (!user.firstLogin) {
      if (!oldPassword) return res.status(400).json({ ok: false, message: "Old password required" });
      const ok = bcrypt.compareSync(oldPassword, user.passwordHash);
      if (!ok) return res.status(401).json({ ok: false, message: "Old password incorrect" });
    }

    user.passwordHash = bcrypt.hashSync(newPassword, 10);
    user.firstLogin = false;
    await user.save();

    return res.json({ ok: true, message: "Password updated" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// ===== CONTENT =====
app.get("/api/content/bootstrap", optionalAuth, async (req, res) => {
  try {
    const role = req.user?.role || "guest";
    const sid = req.user?.sid || process.env.DEFAULT_SCHOOL_ID || "SCH001";
    const school = (await getSchoolOrNull(sid)) || (await getSchoolOrNull(process.env.DEFAULT_SCHOOL_ID || "SCH001"));
    const items = await filterContentForUser(sid, role);

    return res.json({
      ok: true,
      role,
      school: school ? { id: school.schoolId, name: school.name, logoUrl: school.logoUrl, theme: school.theme } : null,
      items,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// ===== ADMIN: CONTENT IMPORT (sheet: content) =====
app.post("/api/admin/content/import", auth, requireRole("admin"), upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, message: "Excel file required (field name: file)" });

    let workbook;
    try {
      workbook = XLSX.read(req.file.buffer, { type: "buffer" });
    } catch (e) {
      return res.status(400).json({ ok: false, message: "Invalid excel file" });
    }

    const sheet = workbook.Sheets["content"];
    if (!sheet) return res.status(400).json({ ok: false, message: 'Sheet "content" not found' });

    const rows = XLSX.utils.sheet_to_json(sheet, { defval: "" });

    let added = 0, updated = 0, skipped = 0;
    const allowedTypes = ["book", "worksheet", "activity", "video", "trm", "answerkey", "testpaper"];

    for (const r of rows) {
      const schoolId = String(r.schoolId || "ALL").trim() || "ALL";
      const className = String(r.className || "").trim();
      const subject = String(r.subject || "").trim();
      const chapter = String(r.chapter || "").trim();
      const bookTitle = String(r.bookTitle || "").trim();
      const type = String(r.type || "").trim().toLowerCase();
      const title = String(r.title || "").trim();
      const url = String(r.url || "").trim();
      const forRole = String(r.forRole || "all").trim().toLowerCase();
      const sortOrder = Number(r.sortOrder || 0);

      if (!type || !url || !allowedTypes.includes(type)) { skipped++; continue; }

      const query = { schoolId, type, className, subject, bookTitle, chapter, url };
      const updateDoc = { title, forRole, sortOrder, isActive: true };

      const result = await ContentItem.updateOne(query, { $set: updateDoc }, { upsert: true });
      if (result.upsertedCount) added++;
      else updated++;
    }

    return res.json({ ok: true, message: "Content import complete", added, updated, skipped });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// ===== ADMIN: USERS IMPORT (teachers sheet) =====
app.post("/api/admin/users/import/teachers", auth, requireRole("admin"), upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, message: "Excel file required (field name: file)" });

    let workbook;
    try {
      workbook = XLSX.read(req.file.buffer, { type: "buffer" });
    } catch (e) {
      return res.status(400).json({ ok: false, message: "Invalid excel file" });
    }

    const sheet = workbook.Sheets["teachers"];
    if (!sheet) return res.status(400).json({ ok: false, message: 'Sheet "teachers" not found' });

    const rows = XLSX.utils.sheet_to_json(sheet, { defval: "" });
    let created = 0, updated = 0, skipped = 0;

    for (const r of rows) {
      const schoolId = String(r.schoolId || "").trim();
      const name = String(r.name || "").trim();
      const email = String(r.email || "").trim().toLowerCase();
      const phone = String(r.phone || "").trim();
      const subject = String(r.subject || "").trim();
      const password = String(r.password || "").trim();

      if (!schoolId || (!email && !phone) || !password) { skipped++; continue; }

      const passwordHash = bcrypt.hashSync(password, 10);
      const filter = email ? { schoolId, email } : { schoolId, phone };

      const doc = {
        schoolId,
        role: "teacher",
        name,
        email,
        phone,
        subject,
        passwordHash,
        firstLogin: true,
        isActive: true,
      };

      const exists = await User.findOne(filter);
      if (exists) {
        await User.updateOne({ _id: exists._id }, { $set: doc });
        updated++;
      } else {
        await User.create(doc);
        created++;
      }
    }

    return res.json({ ok: true, message: "Teachers import complete", created, updated, skipped });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// ===== ADMIN: USERS IMPORT (students sheet) =====
app.post("/api/admin/users/import/students", auth, requireRole("admin"), upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, message: "Excel file required (field name: file)" });

    let workbook;
    try {
      workbook = XLSX.read(req.file.buffer, { type: "buffer" });
    } catch (e) {
      return res.status(400).json({ ok: false, message: "Invalid excel file" });
    }

    const sheet = workbook.Sheets["students"];
    if (!sheet) return res.status(400).json({ ok: false, message: 'Sheet "students" not found' });

    const rows = XLSX.utils.sheet_to_json(sheet, { defval: "" });
    let created = 0, updated = 0, skipped = 0;

    for (const r of rows) {
      const schoolId = String(r.schoolId || "").trim();
      const className = String(r.className || "").trim();
      const roll = String(r.roll || "").trim();
      const name = String(r.name || "").trim();
      const password = String(r.password || "").trim();

      if (!schoolId || !roll || !password) { skipped++; continue; }

      const passwordHash = bcrypt.hashSync(password, 10);
      const filter = { schoolId, roll };

      const doc = {
        schoolId,
        role: "student",
        className,
        roll,
        name,
        passwordHash,
        firstLogin: true,
        isActive: true,
      };

      const exists = await User.findOne(filter);
      if (exists) {
        await User.updateOne({ _id: exists._id }, { $set: doc });
        updated++;
      } else {
        await User.create(doc);
        created++;
      }
    }

    return res.json({ ok: true, message: "Students import complete", created, updated, skipped });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, message: "Server error" });
  }
});

// ===== BOOTSTRAP DEFAULTS =====
async function bootstrapDefaults() {
  const defaultSchoolId = process.env.DEFAULT_SCHOOL_ID || "SCH001";

  const existingSchool = await School.findOne({ schoolId: defaultSchoolId });
  if (!existingSchool) {
    await School.create({
      schoolId: defaultSchoolId,
      name: process.env.DEFAULT_SCHOOL_NAME || "STC Publishing House (Default)",
      logoUrl: process.env.DEFAULT_SCHOOL_LOGO || "assets/logo.png",
      deviceLimits: { student: 100, teacher: 10, admin: 10 },
    });
    console.log("✅ Default school created:", defaultSchoolId);
  }

  const adminEmail = (process.env.DEFAULT_ADMIN_EMAIL || "admin@school.com").toLowerCase();
  const adminPhone = process.env.DEFAULT_ADMIN_PHONE || "9999999999";
  const adminPass = process.env.DEFAULT_ADMIN_PASSWORD || "Admin@123";

  const existingAdmin = await User.findOne({
    schoolId: defaultSchoolId,
    role: "admin",
    $or: [{ email: adminEmail }, { phone: adminPhone }],
  });

  if (!existingAdmin) {
    await User.create({
      schoolId: defaultSchoolId,
      role: "admin",
      name: "Admin",
      email: adminEmail,
      phone: adminPhone,
      passwordHash: bcrypt.hashSync(adminPass, 10),
      firstLogin: false,
      isActive: true,
    });
    console.log("✅ Default admin created:", adminEmail, "/", adminPhone);
  }
}

// ===== START =====
async function main() {
  await mongoose.connect(MONGODB_URI, { dbName: process.env.MONGODB_DB || undefined });
  console.log("✅ MongoDB connected");

  await bootstrapDefaults();

  app.listen(PORT, () => console.log(`✅ Backend running on http://localhost:${PORT} (${NODE_ENV})`));
}

main().catch((e) => {
  console.error("❌ Failed to start:", e);
  process.exit(1);
});
