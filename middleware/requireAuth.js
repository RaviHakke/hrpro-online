function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({
      authenticated: false,
      message: "Authentication required"
    });
  }

  if (req.session.user.role !== "admin") {
    return res.status(403).json({
      authenticated: false,
      message: "Administrator access required"
    });
  }

  next();
}

module.exports = requireAuth;