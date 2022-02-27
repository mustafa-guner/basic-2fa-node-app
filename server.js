const express = require("express");
const app = express();
const bp = require("body-parser");
const mongoose = require("mongoose");
const base32 = require("thirty-two");
const flash = require("connect-flash");
const session = require("express-session");
const User = require("./User");
const passport = require("passport");
const cors = require("cors");
const utils = require("./utils");
const TotpStrategy = require("./TotpStrategy");

require("./passport")(passport);

app.set("view engine", "ejs");
app.set("views", "./views");
app.use(cors({ origin: "http://127.0.0.1:5500", credentials: true }));
app.use(bp.json());
app.use(flash());
app.use(bp.urlencoded({ extended: false }));
app.use(
  session({
    cookie: { maxAge: 60000 },
    secret: "woot",
    resave: false,
    saveUninitialized: false,
  })
);

let keys = {};

const findKeyForUserId = (id, fn) => {
  return fn(null, keys[id]);
};
const saveKeyForUserID = (id, key, fn) => {
  keys[id] = key;
  return fn(null);
};

passport.use(
  new TotpStrategy(async function (user, done) {
    findKeyForUserId(user._id, function (err, obj) {
      if (err) return done(err);
      return done(null, obj.key, obj.period);
    });
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose
  .connect(
    "mongodb+srv://admin:admin@cluster0.c10jd.mongodb.net/test?authSource=admin&replicaSet=atlas-kmnq2b-shard-0&readPreference=primary&appname=MongoDB%20Compass&ssl=true"
  )
  .then(() => console.log("Connected to database."))
  .catch((err) => console.log(err));

app.get("/", (req, res, next) => {
  return res.render("./index.ejs");
});

app.get("/register", (req, res, next) => {
  return res.render("./register.ejs", {
    error: "",
  });
});

app.get("/login", (req, res, next) => {
  return res.render("./login.ejs", {
    message: req.flash("message"),
    error: req.flash("error"),
  });
});

const authenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  return res.redirect("/");
};

const ensureSecondFactor = (req, res, next) => {
  if (req.session.secondFactor == "totp") {
    return next();
  }

  return res.redirect("/two-factor-auth");
};

app.get("/profile", ensureSecondFactor, (req, res, next) => {
  console.log(req.user);
  if (!req.user) return res.redirect("/login");
  return res.render("./profile.ejs", { user: req.user });
});

app.get("/two-factor-auth", authenticated, async (req, res, next) => {
  let key = utils.randomKey(10);
  let encodedKey = base32.encode(key);

  var otpUrl =
    "otpauth://totp/" + req.user.email + "?secret=" + encodedKey + "&period=30";
  var qrImage =
    "https://chart.googleapis.com/chart?chs=166x166&chld=L|0&cht=qr&chl=" +
    encodeURIComponent(otpUrl);

  saveKeyForUserID(req.user._id, { key: key, period: 30 }, function (err) {
    if (err) return next();
    return res.render("two-factor.ejs", {
      user: req.user,
      key: encodedKey,
      qrImage: qrImage,
    });
  });
});

app.post(
  "/two-factor-auth",
  passport.authenticate("totp", {
    failureRedirect: "/two-factor-auth",
    failureFlash: true,
  }),
  function (req, res) {
    req.session.secondFactor = "totp";
    res.redirect("/profile");
  }
);

app.post(
  "/signin",
  passport.authenticate("local", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  function (req, res, next) {
    return res.redirect("/two-factor-auth");
  }
);

app.post("/signup", async (req, res, next) => {
  try {
    const { username, password, email } = req.body;
    const user = await User.findOne({ username, password, email });
    if (user) {
      req.flash("error", "User is already exists");
      return res.redirect("/register");
    }
    const newUser = new User({
      username,
      password,
      email,
    });

    await newUser.save();

    return res.redirect("/login");
  } catch (error) {
    console.log(error.message);
    req.flash("error", error.message);
    return res.redirect("/register");
  }
});

app.listen(5000, () => console.log("Server is up. PORT: 5000"));
