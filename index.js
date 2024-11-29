const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;

// Middleware Setup
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: "replace_this_with_a_secure_key", // Change this for production use
    resave: false,
    saveUninitialized: false,
  })
);

// Set EJS as templating engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// In-memory User Storage
const USERS = [
  {
    id: 1,
    username: "AdminUser",
    email: "admin@example.com",
    password: bcrypt.hashSync("admin123", SALT_ROUNDS),
    role: "admin",
    lastLogin: null,
  },
  {
    id: 2,
    username: "RegularUser",
    email: "user@example.com",
    password: bcrypt.hashSync("user123", SALT_ROUNDS),
    role: "user",
    lastLogin: null,
  },
  {
    id: 3,
    username: "SonicTheHeadge",
    email: "SonicTHeadge@Beans.com",
    password: bcrypt.hashSync("password123", SALT_ROUNDS),
    role: "user",
    lastLogin: null,
  },
];

// Middleware to make 'user' available in all EJS templates
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  next();
});

// Middleware to Check Authentication
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  }
  res.redirect("/");
}

// Middleware to Check Admin Role
function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === "admin") {
    return next();
  }
  res.redirect("/homePage");
}

// Debug route to view USERS array (for development only)
app.get("/debug-users", (req, res) => {
  res.json(USERS);
});

// login - Render login form
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

// login - Authenticate user
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render("login", { error: "All fields are required." });
  }

  const user = USERS.find((u) => u.email === email);
  if (!user) {
    return res.render("login", { error: "Invalid email or password." });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.render("login", { error: "Invalid email or password." });
  }

  user.lastLogin = new Date(); // Track last login time
  console.log(`User ${user.username} logged in at ${user.lastLogin}`);

  req.session.user = {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
  };

  res.redirect("/homePage");
});

// signup - Render signup form
app.get("/signup", (req, res) => {
  res.render("signup", { error: null });
});

// signup - Register new user
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.render("signup", { error: "All fields are required." });
  }

  const existingUser = USERS.find((u) => u.email === email);
  if (existingUser) {
    return res.render("signup", { error: "Email already registered." });
  }

  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  const role = USERS.length === 0 ? "admin" : "user";

  const newUser = {
    id: USERS.length + 1,
    username,
    email,
    password: hashedPassword,
    role,
    lastLogin: null,
  };

  USERS.push(newUser);
  console.log("New user added:", newUser);

  res.redirect("/login");
});

// GET /users - Admin-only route to view all users
app.get("/users", isAuthenticated, isAdmin, (req, res) => {
  res.render("users", { users: USERS });
});

// get Home Page
app.get("/", (req, res) => {
  if (req.session.user) {
    return res.redirect("/homePage");
  }
  res.render("index");
});

// homePage - User/Admin Dashboard
app.get("/homePage", isAuthenticated, (req, res) => {
  const user = req.session.user;

  if (user.role === "admin") {
    return res.render("homePage", { user, users: USERS });
  }

  res.render("homePage", { user, users: null });
});

// logout - Logout User
app.get("/logout", (req, res) => {
  if (req.session.user) {
    console.log(`User ${req.session.user.username} logged out`);
  }
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
      return res.redirect("/homePage");
    }
    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
