require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");

const DataStore = require("./models/DataStore");

const app = express();

app.use(cors());
app.use(express.json({ limit: "50mb" }));

app.use(express.static(path.join(__dirname, "public")));

const DEFAULT_KEY = "hrpro-main-data";

mongoose
  .connect(process.env.MONGODB_URI)
  .then(function () {
    console.log("MongoDB connected successfully");
  })
  .catch(function (error) {
    console.error("MongoDB connection failed:", error.message);
  });

app.get("/api/health", function (req, res) {
  res.json({
    status: "ok",
    message: "HRPro server is running"
  });
});

app.get("/api/data", async function (req, res) {
  try {
    const record = await DataStore.findOne({ key: DEFAULT_KEY });

    if (!record) {
      return res.json({
        employees: [],
        interviews: [],
        trash: [],
        reminders: [],
        settings: {
          theme: "light"
        }
      });
    }

    res.json(record.payload || {});
  } catch (error) {
    console.error("GET /api/data error:", error);
    res.status(500).json({
      message: "Failed to load HRPro data"
    });
  }
});

app.put("/api/data", async function (req, res) {
  try {
    const payload = req.body || {};

    const record = await DataStore.findOneAndUpdate(
      { key: DEFAULT_KEY },
      {
        key: DEFAULT_KEY,
        payload: payload
      },
      {
        new: true,
        upsert: true
      }
    );

    res.json({
      message: "HRPro data saved successfully",
      updatedAt: record.updatedAt
    });
  } catch (error) {
    console.error("PUT /api/data error:", error);
    res.status(500).json({
      message: "Failed to save HRPro data"
    });
  }
});

app.use(function (req, res) {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", function () {
  console.log("HRPro server running on http://0.0.0.0:" + PORT);
});