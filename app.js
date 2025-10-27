const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

// 🧠 Hardcoded Users (for testing)
const users = [
  { id: 1, username: "adminUser", password: "admin123", role: "Admin" },
  { id: 2, username: "modUser", password: "mod123", role: "Moderator" },
  { id: 3, username: "normalUser", password: "user123", role: "User" },
];

// 🧾 Login Route — issues JWT token
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Generate JWT with role info
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    "secretkey",
    { expiresIn: "1h" }
  );

  res.json({ token });
});

// 🔒 Middleware to verify token
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(401).json({ message: "Token missing" });
  }

  try {
    const decoded = jwt.verify(token, "secretkey");
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
}

// 🎭 Middleware for role-based access
function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ message: "Access denied: insufficient role" });
    }
    next();
  };
}

// 👑 Admin-only route
app.get("/admin-dashboard", verifyToken, authorizeRoles("Admin"), (req, res) => {
  res.json({
    message: "Welcome to the Admin dashboard",
    user: req.user,
  });
});

// 🛡️ Moderator & Admin route
app.get(
  "/moderator-panel",
  verifyToken,
  authorizeRoles("Moderator", "Admin"),
  (req, res) => {
    res.json({
      message: "Welcome to the Moderator panel",
      user: req.user,
    });
  }
);

// 👤 All users route
app.get(
  "/user-profile",
  verifyToken,
  authorizeRoles("User", "Admin", "Moderator"),
  (req, res) => {
    res.json({
      message: `Welcome to your profile, ${req.user.username}`,
      user: req.user,
    });
  }
);

// 🚀 Start the server
app.listen(3000, () => console.log("Server running on port 3000"));
