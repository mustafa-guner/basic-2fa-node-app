const mongoose = require("mongoose");

const userSchema = mongoose.Schema({
  username: String,
  password: String,
  email: String,
});

const User = mongoose.model("User", userSchema, "test_users");

module.exports = User;
