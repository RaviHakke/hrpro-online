require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const DataStore = require("./models/DataStore");

const app = express();

app.set("trust proxy", 1);
app.use(cors());
app.use(express.json({ limit: "50mb" }));

// Initialize Sessions
app.use(session({
  secret: process.env.SESSION_SECRET || "hrpro-super-secret-key-2026",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // False allows it to work on local LAN and Railway
    httpOnly: true
  }
}));

app.use(express.static(path.join(__dirname, "public")));
const DEFAULT_KEY = "hrpro-main-data";

// --- DATABASE: User Schema with Levels ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  level: { type: Number, required: true, default: 1 } // 1=Int Read, 2=All Read, 3=Super Admin
});
const User = mongoose.model("User", userSchema);

mongoose.connect(process.env.MONGODB_URI).then(async function () {
  console.log("MongoDB connected successfully");
  // Auto-create Super Admin if no users exist
  const count = await User.countDocuments();
  if (count === 0) {
    const hashedPassword = await bcrypt.hash("Hrpro@2026", 10);
    await User.create({ username: "superadmin", password: hashedPassword, level: 3 });
    console.log("Default Super Admin created (superadmin / Hrpro@2026)");
  }
}).catch((err) => console.error("MongoDB connection failed:", err.message));


// --- SECURITY MIDDLEWARE ---
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) next();
  else res.status(401).json({ message: "Authentication required" });
}

function requireSuperAdmin(req, res, next) {
  if (req.session && req.session.userId && req.session.level === 3) next();
  else res.status(403).json({ message: "Access denied. Super Admin required." });
}

// --- AUTHENTICATION ROUTES ---
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.level = user.level;
    res.json({ message: "Login successful", user: { username: user.username, level: user.level } });
  } catch (error) { res.status(500).json({ message: "Server error" }); }
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy();
  res.json({ message: "Logged out successfully" });
});

app.get("/api/auth/session", (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ authenticated: true, user: { username: req.session.username, level: req.session.level } });
  } else {
    res.json({ authenticated: false });
  }
});

app.put("/api/auth/change-password", requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    if (newPassword !== confirmPassword) return res.status(400).json({ message: "Passwords do not match" });
    const user = await User.findById(req.session.userId);
    if (!(await bcrypt.compare(currentPassword, user.password))) return res.status(400).json({ message: "Incorrect current password" });
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ message: "Password changed successfully" });
  } catch (error) { res.status(500).json({ message: "Server error" }); }
});

// Create New Accounts (Only Super Admin can do this)
app.post("/api/auth/create-user", requireSuperAdmin, async (req, res) => {
  try {
    const { username, password, level } = req.body;
    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ message: "Username already exists" });
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ username, password: hashedPassword, level });
    res.json({ message: `Account '${username}' created at Level ${level}` });
  } catch (error) { res.status(500).json({ message: "Error creating user" }); }
});


// --- STANDARD APP ROUTES ---
app.get("/api/health", (req, res) => res.json({ status: "ok", message: "Running" }));

// EVERYONE logged in can READ data
app.get("/api/data", requireAuth, async function (req, res) {
  try {
    const record = await DataStore.findOne({ key: DEFAULT_KEY });
    if (!record) return res.json({ employees: [], interviews: [], trash: [], reminders: [], settings: { theme: "light" } });
    res.json(record.payload || {});
  } catch (error) { res.status(500).json({ message: "Failed to load data" }); }
});

// ONLY LEVEL 3 (Super Admin) can SAVE data
app.put("/api/data", requireSuperAdmin, async function (req, res) {
  try {
    const record = await DataStore.findOneAndUpdate(
      { key: DEFAULT_KEY }, { key: DEFAULT_KEY, payload: req.body || {} }, { new: true, upsert: true }
    );
    res.json({ message: "HRPro data saved successfully", updatedAt: record.updatedAt });
  } catch (error) { res.status(500).json({ message: "Failed to save data" }); }
});

app.use((req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => console.log("HRPro server running on http://0.0.0.0:" + PORT));