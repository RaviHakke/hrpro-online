const mongoose = require("mongoose");

const AdminUserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      minlength: 3,
      maxlength: 50
    },

    passwordHash: {
      type: String,
      required: true,
      select: false
    },

    role: {
      type: String,
      enum: ["admin"],
      default: "admin",
      required: true
    },

    passwordChangedAt: {
      type: Date,
      default: Date.now
    },

    lastLoginAt: {
      type: Date,
      default: null
    },

    failedLoginCount: {
      type: Number,
      default: 0
    },

    lockedUntil: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model("AdminUser", AdminUserSchema);