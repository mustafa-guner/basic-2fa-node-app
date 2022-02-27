const LocalStrategy = require("passport-local");

const User = require("./User");

module.exports = (passport) => {
  passport.use(
    new LocalStrategy(async function (username, password, done) {
      try {
        if (!username || !password) {
          if (!username)
            return done(null, false, { message: "Username is required." });
          if (!password)
            return done(null, false, { message: "Password is required." });
        }

        const user = await User.findOne({ username });

        if (!user)
          return done(null, false, { message: "Could not found account." });

        if (user.username === username && user.password !== password) {
          return done(null, false, { message: "Wrong Password" });
        }

        return done(null, user);
      } catch (error) {
        console.log(error.message);
        return done(error);
      }
    })
  );

  passport.serializeUser((user, done) => {
    done(null, user._id);
  });

  passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
      done(err, user);
    });
  });
};
