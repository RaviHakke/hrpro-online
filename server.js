require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const DataStore = require("./models/DataStore");

const app = express();
const PORT = process.env.PORT || 3000;
const DEFAULT_KEY = "hrpro-main-data";
const ACCESS_VALUES = ["hidden", "read", "write"];
const PAGE_KEYS = ["dashboard", "employees", "interviews", "settings"];

const DEFAULT_PERMISSIONS = {
  dashboard: "read",
  employees: "hidden",
  interviews: "read",
  settings: "hidden"
};

const SUPERADMIN_PERMISSIONS = {
  dashboard: "write",
  employees: "write",
  interviews: "write",
  settings: "write"
};

app.set("trust proxy", 1);
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

app.use(session({
  name: "hrpro.sid",
  secret: process.env.SESSION_SECRET || "hrpro-super-secret-key-2026",
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "lax",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname, "public")));

const permissionSchema = new mongoose.Schema({
  dashboard: { type: String, enum: ACCESS_VALUES, default: "read" },
  employees: { type: String, enum: ACCESS_VALUES, default: "hidden" },
  interviews: { type: String, enum: ACCESS_VALUES, default: "read" },
  settings: { type: String, enum: ACCESS_VALUES, default: "hidden" }
}, { _id: false });

const userSchema = new mongoose.Schema({
  fullName: { type: String, trim: true, maxlength: 80, default: "" },
  username: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["superadmin", "user"], default: "user" },
  permissions: { type: permissionSchema, default: () => ({ ...DEFAULT_PERMISSIONS }) },
  active: { type: Boolean, default: true },
  level: { type: Number, enum: [1, 2, 3], default: 1 }
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model("User", userSchema);

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase().replace(/\s+/g, "");
}

function normalizePermissions(value) {
  const source = value && typeof value === "object" ? value : {};
  const result = {};
  PAGE_KEYS.forEach((key) => {
    const access = String(source[key] || "hidden").toLowerCase();
    result[key] = ACCESS_VALUES.includes(access) ? access : "hidden";
  });
  return result;
}

function permissionsFromLevel(level) {
  if (Number(level) === 3) return { ...SUPERADMIN_PERMISSIONS };
  if (Number(level) === 2) {
    return { dashboard: "read", employees: "read", interviews: "read", settings: "hidden" };
  }
  return { dashboard: "hidden", employees: "hidden", interviews: "read", settings: "hidden" };
}

function isSuperAdmin(user) {
  return Boolean(user && (user.role === "superadmin" || Number(user.level) === 3));
}

function safeUser(user) {
  const superAdmin = isSuperAdmin(user);
  return {
    id: String(user._id),
    _id: String(user._id),
    fullName: user.fullName || user.username,
    username: user.username,
    role: superAdmin ? "superadmin" : "user",
    level: superAdmin ? 3 : 1,
    permissions: superAdmin
      ? { ...SUPERADMIN_PERMISSIONS }
      : normalizePermissions(user.permissions || permissionsFromLevel(user.level)),
    active: user.active !== false
  };
}

function accessOf(user, page) {
  if (isSuperAdmin(user)) return "write";
  const permissions = user.permissions || permissionsFromLevel(user.level);
  const access = String(permissions[page] || "hidden").toLowerCase();
  return ACCESS_VALUES.includes(access) ? access : "hidden";
}

function canRead(user, page) {
  return ["read", "write"].includes(accessOf(user, page));
}

function canWrite(user, page) {
  return accessOf(user, page) === "write";
}

async function requireAuth(req, res, next) {
  try {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ message: "Authentication required" });
    }
    const user = await User.findById(req.session.userId);
    if (!user || user.active === false) {
      req.session.destroy(() => {});
      return res.status(401).json({ message: "Session expired or account disabled" });
    }
    req.authUser = user;
    next();
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(500).json({ message: "Unable to verify session" });
  }
}

function requireSuperAdmin(req, res, next) {
  if (isSuperAdmin(req.authUser)) return next();
  return res.status(403).json({ message: "Only Super Admin can perform this action" });
}

mongoose.connect(process.env.MONGODB_URI).then(async () => {
  console.log("MongoDB connected successfully");

  const users = await User.find({});
  if (users.length === 0) {
    const hashedPassword = await bcrypt.hash("Hrpro@2026", 12);
    await User.create({
      fullName: "Super Admin",
      username: "superadmin",
      password: hashedPassword,
      role: "superadmin",
      level: 3,
      permissions: SUPERADMIN_PERMISSIONS
    });
    console.log("Default Super Admin created (superadmin / Hrpro@2026)");
  } else {
    for (const user of users) {
      let changed = false;
      if (Number(user.level) === 3 && user.role !== "superadmin") {
        user.role = "superadmin";
        user.permissions = SUPERADMIN_PERMISSIONS;
        changed = true;
      } else if (!user.role) {
        user.role = "user";
        user.permissions = permissionsFromLevel(user.level);
        changed = true;
      }
      if (!user.fullName) {
        user.fullName = user.username;
        changed = true;
      }
      if (changed) await user.save();
    }
  }
}).catch((error) => console.error("MongoDB connection failed:", error.message));

app.post("/api/auth/login", async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || "");
    const user = await User.findOne({ username });

    if (!user || user.active === false || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    if (Number(user.level) === 3 && user.role !== "superadmin") {
      user.role = "superadmin";
      user.permissions = SUPERADMIN_PERMISSIONS;
      await user.save();
    }

    req.session.userId = String(user._id);
    req.session.username = user.username;
    req.session.role = isSuperAdmin(user) ? "superadmin" : "user";
    req.session.level = isSuperAdmin(user) ? 3 : 1;

    req.session.save((error) => {
      if (error) return res.status(500).json({ message: "Unable to create login session" });
      res.json({ message: "Login successful", user: safeUser(user) });
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/logout", (req, res) => {
  if (!req.session) return res.json({ message: "Logged out successfully" });
  req.session.destroy(() => {
    res.clearCookie("hrpro.sid");
    res.json({ message: "Logged out successfully" });
  });
});

app.get("/api/auth/session", requireAuth, (req, res) => {
  res.json({ authenticated: true, user: safeUser(req.authUser) });
});

app.put("/api/auth/change-password", requireAuth, async (req, res) => {
  try {
    const currentPassword = String(req.body.currentPassword || "");
    const newPassword = String(req.body.newPassword || "");
    const confirmPassword = String(req.body.confirmPassword || "");

    if (newPassword.length < 8) {
      return res.status(400).json({ message: "New password must contain at least 8 characters" });
    }
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }
    if (!(await bcrypt.compare(currentPassword, req.authUser.password))) {
      return res.status(400).json({ message: "Incorrect current password" });
    }

    req.authUser.password = await bcrypt.hash(newPassword, 12);
    await req.authUser.save();
    res.json({ message: "Password changed successfully" });
  } catch (error) {
    console.error("Password error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/create-user", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const fullName = String(req.body.fullName || "").trim().slice(0, 80);
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || "");
    const role = req.body.role === "superadmin" ? "superadmin" : "user";

    if (!fullName) return res.status(400).json({ message: "Full name is required" });
    if (!/^[a-z0-9._-]{3,50}$/.test(username)) {
      return res.status(400).json({ message: "Username must be 3-50 characters and use only letters, numbers, dots, underscores or hyphens" });
    }
    if (password.length < 8) {
      return res.status(400).json({ message: "Password must contain at least 8 characters" });
    }
    if (await User.exists({ username })) {
      return res.status(409).json({ message: "Username already exists" });
    }

    const user = await User.create({
      fullName,
      username,
      password: await bcrypt.hash(password, 12),
      role,
      level: role === "superadmin" ? 3 : 1,
      permissions: role === "superadmin" ? SUPERADMIN_PERMISSIONS : normalizePermissions(req.body.permissions),
      active: true
    });

    res.status(201).json({ message: `Account '${username}' created successfully`, user: safeUser(user) });
  } catch (error) {
    console.error("Create user error:", error);
    res.status(500).json({ message: "Error creating user" });
  }
});

app.get("/api/auth/users", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const users = await User.find({}).sort({ role: 1, fullName: 1, username: 1 });
    res.json({ users: users.map(safeUser) });
  } catch (error) {
    res.status(500).json({ message: "Unable to load accounts" });
  }
});


// Update an existing standard account: name, username, optional password and page permissions.
app.put("/api/auth/users/:id", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid account ID" });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ message: "Account not found" });
    }

    // Protect the fixed Super Admin account from accidental modification.
    if (isSuperAdmin(user)) {
      return res.status(400).json({
        message: "Super Admin account cannot be changed from Previous Users"
      });
    }

    const fullName = String(req.body.fullName || "").trim().slice(0, 80);
    const username = normalizeUsername(req.body.username);
    const newPassword = String(req.body.password || "");

    if (!fullName) {
      return res.status(400).json({ message: "Full name is required" });
    }

    if (!/^[a-z0-9._-]{3,50}$/.test(username)) {
      return res.status(400).json({
        message: "Username must be 3-50 characters and use only letters, numbers, dots, underscores or hyphens"
      });
    }

    const duplicate = await User.exists({
      username,
      _id: { $ne: user._id }
    });

    if (duplicate) {
      return res.status(409).json({ message: "Username already exists" });
    }

    if (newPassword && newPassword.length < 8) {
      return res.status(400).json({
        message: "New password must contain at least 8 characters"
      });
    }

    user.fullName = fullName;
    user.username = username;
    user.role = "user";
    user.level = 1;
    user.permissions = normalizePermissions(req.body.permissions);

    // Blank password means retain the user's current password.
    if (newPassword) {
      user.password = await bcrypt.hash(newPassword, 12);
    }

    await user.save();

    res.json({
      message: "Previous user updated successfully",
      user: safeUser(user)
    });
  } catch (error) {
    console.error("Existing user update error:", error);

    if (error && error.code === 11000) {
      return res.status(409).json({ message: "Username already exists" });
    }

    res.status(500).json({ message: "Unable to update previous user" });
  }
});

app.put("/api/auth/users/:id/permissions", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: "Invalid account ID" });
    }
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: "Account not found" });
    if (isSuperAdmin(user)) {
      return res.status(400).json({ message: "Super Admin permissions cannot be reduced" });
    }

    user.role = "user";
    user.level = 1;
    user.permissions = normalizePermissions(req.body.permissions);
    await user.save();
    res.json({ message: "Permissions updated successfully", user: safeUser(user) });
  } catch (error) {
    console.error("Permission update error:", error);
    res.status(500).json({ message: "Unable to update permissions" });
  }
});

app.get("/api/health", (req, res) => res.json({ status: "ok", message: "Running" }));

function emptyPayload() {
  return { employees: [], interviews: [], trash: [], reminders: [], settings: { theme: "light" } };
}

function normalizePayload(value) {
  const data = value && typeof value === "object" ? value : {};
  return {
    employees: Array.isArray(data.employees) ? data.employees : [],
    interviews: Array.isArray(data.interviews) ? data.interviews : [],
    trash: Array.isArray(data.trash) ? data.trash : [],
    reminders: Array.isArray(data.reminders) ? data.reminders : [],
    settings: data.settings && typeof data.settings === "object" ? data.settings : { theme: "light" }
  };
}

function same(a, b) {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

app.get("/api/data", requireAuth, async (req, res) => {
  try {
    const record = await DataStore.findOne({ key: DEFAULT_KEY });
    const payload = normalizePayload(record ? record.payload : emptyPayload());

    res.json({
      employees: canRead(req.authUser, "employees") ? payload.employees : [],
      interviews: canRead(req.authUser, "interviews") ? payload.interviews : [],
      trash: canRead(req.authUser, "employees") || canRead(req.authUser, "interviews") ? payload.trash : [],
      reminders: canRead(req.authUser, "interviews") ? payload.reminders : [],
      settings: payload.settings
    });
  } catch (error) {
    console.error("Load data error:", error);
    res.status(500).json({ message: "Failed to load data" });
  }
});

app.put("/api/data", requireAuth, async (req, res) => {
  try {
    const existing = await DataStore.findOne({ key: DEFAULT_KEY });
    const oldPayload = normalizePayload(existing ? existing.payload : emptyPayload());
    const requested = normalizePayload(req.body);
    const merged = { ...oldPayload };
    const denied = [];

    if (!same(oldPayload.employees, requested.employees)) {
      if (canWrite(req.authUser, "employees")) merged.employees = requested.employees;
      else denied.push("Employee Master");
    }
    if (!same(oldPayload.interviews, requested.interviews)) {
      if (canWrite(req.authUser, "interviews")) merged.interviews = requested.interviews;
      else denied.push("Interview Tracker");
    }
    if (!same(oldPayload.reminders, requested.reminders)) {
      if (canWrite(req.authUser, "interviews")) merged.reminders = requested.reminders;
      else denied.push("Interview Reminders");
    }
    if (!same(oldPayload.trash, requested.trash)) {
      if (canWrite(req.authUser, "employees") || canWrite(req.authUser, "interviews")) merged.trash = requested.trash;
      else denied.push("Recycle Bin");
    }
    if (!same(oldPayload.settings, requested.settings)) {
      if (canWrite(req.authUser, "settings") || isSuperAdmin(req.authUser)) merged.settings = requested.settings;
      else {
        const themeOnly = { ...(oldPayload.settings || {}), theme: requested.settings?.theme || "light" };
        const requestedWithoutTheme = { ...(requested.settings || {}) };
        const themeOnlyWithoutTheme = { ...themeOnly };
        delete requestedWithoutTheme.theme;
        delete themeOnlyWithoutTheme.theme;
        if (same(requestedWithoutTheme, themeOnlyWithoutTheme)) merged.settings = themeOnly;
        else denied.push("Settings");
      }
    }

    if (denied.length) {
      return res.status(403).json({ message: `Write access denied for: ${denied.join(", ")}` });
    }

    const record = await DataStore.findOneAndUpdate(
      { key: DEFAULT_KEY },
      { key: DEFAULT_KEY, payload: merged },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    res.json({ message: "HRPro data saved successfully", updatedAt: record.updatedAt });
  } catch (error) {
    console.error("Save data error:", error);
    res.status(500).json({ message: "Failed to save data" });
  }
});

app.use((req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, "0.0.0.0", () => {
  console.log("HRPro server running on http://0.0.0.0:" + PORT);
});
