require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const DataStore = require("./models/DataStore");

const app = express();

// Trust cloud proxies (Required for Railway/Render secure cookies)
app.set("trust proxy", 1);

app.use(cors());
app.use(express.json({ limit: "50mb" }));

// Initialize Sessions
app.use(session({
  secret: process.env.SESSION_SECRET || "hrpro-super-secret-key-2026",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production", // true on Railway, false on localhost
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 // Session lasts 24 hours
  }
}));

app.use(express.static(path.join(__dirname, "public")));

const DEFAULT_KEY = "hrpro-main-data";

// Define the Admin Database Schema
const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const Admin = mongoose.model("Admin", adminSchema);

// Connect to MongoDB & Create Default Admin if missing
mongoose
  .connect(process.env.MONGODB_URI)
  .then(async function () {
    console.log("MongoDB connected successfully");
    
    // Check if an admin exists; if not, create the default one
    const adminCount = await Admin.countDocuments();
    if (adminCount === 0) {
      const hashedPassword = await bcrypt.hash("Hrpro@2026", 10);
      await Admin.create({ username: "admin", password: hashedPassword });
      console.log("Default admin created! Username: admin | Password: Hrpro@2026");
    }
  })
  .catch(function (error) {
    console.error("MongoDB connection failed:", error.message);
  });

// --- SECURITY MIDDLEWARE ---
// This function blocks access if the user is not logged in
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ message: "Authentication required" });
  }
}

// --- AUTHENTICATION ROUTES ---

// 1. Login Route
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username });
    
    if (!admin) return res.status(401).json({ message: "Invalid username or password" });
    
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid username or password" });

    // Save user info to session
    req.session.userId = admin._id;
    req.session.username = admin.username;
    res.json({ message: "Login successful", user: { username: admin.username } });
  } catch (error) {
    res.status(500).json({ message: "Server error during login" });
  }
});

// 2. Logout Route
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy();
  res.json({ message: "Logged out successfully" });
});

// 3. Session Check Route (runs every time the page loads)
app.get("/api/auth/session", (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ authenticated: true, user: { username: req.session.username } });
  } else {
    res.json({ authenticated: false });
  }
});

// 4. Change Password Route
app.put("/api/auth/change-password", requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "New passwords do not match" });
    }

    const admin = await Admin.findById(req.session.userId);
    const isMatch = await bcrypt.compare(currentPassword, admin.password);
    
    if (!isMatch) return res.status(400).json({ message: "Incorrect current password" });

    // Hash and save the new password
    admin.password = await bcrypt.hash(newPassword, 10);
    await admin.save();
    
    res.json({ message: "Password changed successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error during password change" });
  }
});

// --- STANDARD APP ROUTES ---

app.get("/api/health", function (req, res) {
  res.json({ status: "ok", message: "HRPro server is running" });
});

// SECURED: Get Data
app.get("/api/data", requireAuth, async function (req, res) {
  try {
    const record = await DataStore.findOne({ key: DEFAULT_KEY });
    if (!record) {
      return res.json({ employees: [], interviews: [], trash: [], reminders: [], settings: { theme: "light" } });
    }
    res.json(record.payload || {});
  } catch (error) {
    res.status(500).json({ message: "Failed to load HRPro data" });
  }
});

// SECURED: Save Data
app.put("/api/data", requireAuth, async function (req, res) {
  try {
    const record = await DataStore.findOneAndUpdate(
      { key: DEFAULT_KEY },
      { key: DEFAULT_KEY, payload: req.body || {} },
      { new: true, upsert: true }
    );
    res.json({ message: "HRPro data saved successfully", updatedAt: record.updatedAt });
  } catch (error) {
    res.status(500).json({ message: "Failed to save HRPro data" });
  }
});

// Catch-all route to serve the frontend
app.use(function (req, res) {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", function () {
  console.log("HRPro server running on http://0.0.0.0:" + PORT);
});