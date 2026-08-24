const express = require("express");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");

const AdminUser = require("../models/AdminUser");
const requireAuth = require("../middleware/requireAuth");

const router = express.Router();

const PASSWORD_MIN_LENGTH = 10;
const MAX_FAILED_ATTEMPTS = 5;
const ACCOUNT_LOCK_MINUTES = 15;

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    authenticated: false,
    message: "Too many login attempts. Please try again later."
  }
});

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= PASSWORD_MIN_LENGTH &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[0-9]/.test(password)
  );
}

function normalizeUsername(username) {
  return String(username || "").trim().toLowerCase();
}

router.post("/login", loginLimiter, async function (req, res) {
  try {
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || "");

    if (!username || !password) {
      return res.status(400).json({
        authenticated: false,
        message: "Username and password are required"
      });
    }

    const admin = await AdminUser.findOne({ username: username }).select(
      "+passwordHash"
    );

    if (!admin) {
      return res.status(401).json({
        authenticated: false,
        message: "Invalid username or password"
      });
    }

    if (admin.lockedUntil && admin.lockedUntil.getTime() > Date.now()) {
      const remainingMinutes = Math.ceil(
        (admin.lockedUntil.getTime() - Date.now()) / 60000
      );

      return res.status(423).json({
        authenticated: false,
        message:
          "Account temporarily locked. Try again in " +
          remainingMinutes +
          " minute(s)."
      });
    }

    if (admin.lockedUntil && admin.lockedUntil.getTime() <= Date.now()) {
      admin.failedLoginCount = 0;
      admin.lockedUntil = null;
    }

    const passwordMatches = await bcrypt.compare(
      password,
      admin.passwordHash
    );

    if (!passwordMatches) {
      admin.failedLoginCount = (admin.failedLoginCount || 0) + 1;

      if (admin.failedLoginCount >= MAX_FAILED_ATTEMPTS) {
        admin.lockedUntil = new Date(
          Date.now() + ACCOUNT_LOCK_MINUTES * 60 * 1000
        );
        admin.failedLoginCount = 0;
      }

      await admin.save();

      return res.status(401).json({
        authenticated: false,
        message: "Invalid username or password"
      });
    }

    admin.failedLoginCount = 0;
    admin.lockedUntil = null;
    admin.lastLoginAt = new Date();

    await admin.save();

    req.session.regenerate(function (sessionError) {
      if (sessionError) {
        console.error("Session regeneration failed:", sessionError);

        return res.status(500).json({
          authenticated: false,
          message: "Unable to create login session"
        });
      }

      req.session.user = {
        id: admin._id.toString(),
        username: admin.username,
        role: admin.role
      };

      req.session.save(function (saveError) {
        if (saveError) {
          console.error("Session save failed:", saveError);

          return res.status(500).json({
            authenticated: false,
            message: "Unable to save login session"
          });
        }

        res.json({
          authenticated: true,
          message: "Login successful",
          user: {
            username: admin.username,
            role: admin.role,
            lastLoginAt: admin.lastLoginAt
          }
        });
      });
    });
  } catch (error) {
    console.error("POST /api/auth/login error:", error);

    res.status(500).json({
      authenticated: false,
      message: "Login failed"
    });
  }
});

router.get("/session", function (req, res) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({
      authenticated: false
    });
  }

  res.json({
    authenticated: true,
    user: req.session.user
  });
});

router.post("/logout", function (req, res) {
  if (!req.session) {
    return res.json({
      authenticated: false,
      message: "Logged out successfully"
    });
  }

  req.session.destroy(function (error) {
    if (error) {
      console.error("Session destruction failed:", error);

      return res.status(500).json({
        message: "Logout failed"
      });
    }

    res.clearCookie("hrpro.sid");

    res.json({
      authenticated: false,
      message: "Logged out successfully"
    });
  });
});

router.put("/change-password", requireAuth, async function (req, res) {
  try {
    const currentPassword = String(req.body.currentPassword || "");
    const newPassword = String(req.body.newPassword || "");
    const confirmPassword = String(req.body.confirmPassword || "");

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({
        message: "All password fields are required"
      });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        message: "New password and confirmation do not match"
      });
    }

    if (!validPassword(newPassword)) {
      return res.status(400).json({
        message:
          "New password must contain at least 10 characters, one uppercase letter, one lowercase letter, and one number"
      });
    }

    if (currentPassword === newPassword) {
      return res.status(400).json({
        message: "New password must be different from the current password"
      });
    }

    const admin = await AdminUser.findById(req.session.user.id).select(
      "+passwordHash"
    );

    if (!admin) {
      return res.status(404).json({
        message: "Administrator account not found"
      });
    }

    const currentPasswordMatches = await bcrypt.compare(
      currentPassword,
      admin.passwordHash
    );

    if (!currentPasswordMatches) {
      return res.status(401).json({
        message: "Current password is incorrect"
      });
    }

    admin.passwordHash = await bcrypt.hash(newPassword, 12);
    admin.passwordChangedAt = new Date();

    await admin.save();

    req.session.regenerate(function (sessionError) {
      if (sessionError) {
        console.error(
          "Session regeneration after password change failed:",
          sessionError
        );

        return res.status(500).json({
          message:
            "Password changed, but the login session could not be refreshed"
        });
      }

      req.session.user = {
        id: admin._id.toString(),
        username: admin.username,
        role: admin.role
      };

      req.session.save(function (saveError) {
        if (saveError) {
          return res.status(500).json({
            message:
              "Password changed, but the login session could not be saved"
          });
        }

        res.json({
          message: "Administrator password changed successfully"
        });
      });
    });
  } catch (error) {
    console.error("PUT /api/auth/change-password error:", error);

    res.status(500).json({
      message: "Failed to change administrator password"
    });
  }
});

module.exports = router;