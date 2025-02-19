const express = require("express");

const app = express();
app.set("view engine", "ejs"); // Setting ejs for templates
app.use(express.static("public")); // Adding public dir
app.use(express.urlencoded({ extended: false })); // Parse Form Data

app.use(function (req, res, next) {
  res.locals.errors = [];

  next();
});

const users = {};

// MARK: Routes
app.get("/", (req, res) => {
  res.render("homepage");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/register", (req, res) => {
  let { username, password } = req.body;
  const errors = [];

  username = username.trim();

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

  users[username] = password;

  res.send(`User registration complete: ${username}`);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (users[username] === password) {
    res.send("You are now logged in!");
  } else {
    res.send("Login failed");
  }
});

app.listen(3000, () => {
  console.log("Server fired up 🔥");
});