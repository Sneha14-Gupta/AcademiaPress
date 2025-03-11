console.clear();
require("dotenv").config();

const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const sanitizeHTML = require("sanitize-html");

const db = require("better-sqlite3")("database.db");
db.pragma("journal_mode = WAL"); // Performance

const PORT = process.env.PORT || 3000;

const app = express();
app.set("view engine", "ejs"); // Setting ejs for templates
app.use(express.static("public")); // Adding public dir
app.use(express.urlencoded({ extended: false })); // Parse Form Data
app.use(cookieParser());

// Database Setup
const createTables = db.transaction(() => {
  // Create users table
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )
    `
  ).run();
});

createTables();

// Global Middleware: Implement Auth
app.use(function (req, res, next) {
  res.locals.errors = []; // For ejs templates

  try {
    const decoded = jwt.verify(req.cookies.user, process.env.JWTSECRET);

    const { userId, username } = decoded;

    req.user = { userId, username }; // give access to every route
  } catch (err) {
    req.user = false;
  }

  res.locals.user = req.user; // access from templates
  console.log(req.user);

  next();
});

// MARK: Routes
// --- Home
app.get("/", (req, res) => {
  if (req.user) {
    // TODO: Show research papers on dashboard
    return res.render("dashboard");
  }

  return res.render("homepage");
});

// --- Register
app.post("/register", (req, res) => {
  let { username, password } = req.body;
  const errors = [];

  username = username.trim();

  if (typeof username !== "string") username = "";
  if (typeof password !== "string") password = "";

  // Validation: Username
  if (!username) {
    errors.push("You must provide a username");
  }
  if (username && username.length < 4) {
    errors.push("Username must be atleast 4 characters");
  }
  if (username && username.length > 11) {
    errors.push("Username must be exceed 11 characters");
  }
  if (username && !username.match(/^[a-zA-Z0-9]+$/)) {
    errors.push("Username can not contain special characters");
  }
  // Check if username already there in the database
  const usernameExistsStatement = db.prepare(
    `SELECT * FROM users WHERE username = ?`
  );
  const usernameExists = usernameExistsStatement.get(username);

  if (usernameExists) {
    errors.push("User is already registered");
  }

  // Validation: Password
  if (!password) {
    errors.push("You must provide a password");
  }
  if (username && username.length < 6) {
    errors.push("Password must be atleast 6 characters");
  }
  if (username && username.length > 20) {
    errors.push("Password must be exceed 20 characters");
  }

  if (errors.length) {
    return res.render("homepage", { errors });
  }

  // Add user to the database
  const salt = bcrypt.genSaltSync(10);
  password = bcrypt.hashSync(password, salt);

  const query = db.prepare(
    `INSERT INTO users (username, password) VALUES (?, ?)`
  );

  const result = query.run(username, password);

  // Get the recently created user
  const findStatement = db.prepare(`SELECT * FROM users WHERE ROWID = ?`);
  const ourUser = findStatement.get(result.lastInsertRowid);

  // Send back a JWT token
  const tokenValue = jwt.sign(
    {
      userId: ourUser.id,
      username: username,
      exp: Date.now() / 1000 + 60 * 60 * 24,
    },
    process.env.JWTSECRET
  );

  // Send a cookie back to the client
  res.cookie("user", tokenValue, {
    httpOnly: true, // Only for server
    secure: true, // Runs on only https connection
    sameSite: "strict", // CSRF Attacks but not for subdomains
    maxAge: 1000 * 60 * 60 * 24, // Valid for a week
  });

  res.send(`User registration complete: ${username}`);
});

// --- Login
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  let errors = [];

  if (typeof username !== "string") username = "";
  if (typeof password !== "string") password = "";

  if (!username || !password) {
    errors.push("Invalid Username or Password");
  }

  if (errors.length) {
    return res.render("login", { errors });
  }

  // Check for user in database
  const userInDBStatement = db.prepare(
    `SELECT * FROM users WHERE USERNAME = ?`
  );

  const userInDB = userInDBStatement.get(username);

  if (!userInDB) {
    errors = ["User not found"];
    return res.render("login", { errors });
  }

  // Check password comparison
  const passwordCheck = bcrypt.compareSync(password, userInDB.password);
  console.log("Password check", passwordCheck);
  if (!passwordCheck) {
    errors = ["Invalid username/password"];

    return res.render("login", { errors });
  }

  // Send back a JWT token
  const tokenValue = jwt.sign(
    {
      userId: userInDB.id,
      username: username,
      exp: Date.now() / 1000 + 60 * 60 * 24,
    },
    process.env.JWTSECRET
  );

  // Send a cookie back to the client
  res.cookie("user", tokenValue, {
    httpOnly: true, // Only for server
    secure: true, // Runs on only https connection
    sameSite: "strict", // CSRF Attacks but not for subdomains
    maxAge: 1000 * 60 * 60 * 24, // Valid for a week
  });

  return res.redirect("/");
});

// Logout
app.get("/logout", (req, res) => {
  res.clearCookie("user");
  return res.redirect("/");
});

// --- Paper
function mustBeLoggedIn(req, res, next) {
  // comes from global middleware
  if (req.user) {
    next();
  }

  return res.redirect("/");
}

// Paper html validtion
function postValidation(req) {
  let errors = [];

  if (typeof req.body.title !== "string") req.body.title = "";
  if (typeof req.body.body !== "string") req.body.body = "";

  // Clean HTML Part
  req.body.title = sanitizeHTML(req.body.title, {
    allowedTags: ["b", "i", "em", "strong", "a", "p"],
    allowedAttributes: {
      a: ["href"],
    },
  });
  req.body.body = sanitizeHTML(req.body.body, {
    allowedTags: ["b", "i", "em", "strong", "a", "p"],
    allowedAttributes: {
      a: ["href"],
    },
  });

  if (!req.body.title) errors.push("Title must not be empty");
  if (!req.body.body) errors.push("Body must not be empty");

  return errors;
}

app.get("/create-paper", mustBeLoggedIn, (req, res) => {
  return res.render("create-paper");
});

app.post("/create-paper", mustBeLoggedIn, (req, res) => {
  // we will get title and body from the post request
  const errors = postValidation(req);

  console.log(req.body);

  res.send("OK");
});

app.listen(PORT, () => {
  console.log(`Server fired up 🔥 on PORT ${PORT}`);
});