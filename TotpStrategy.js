const passport = require("passport-strategy");
const totp = require("notp").totp;
const util = require("util");

function Strategy(options, setup) {
  if (typeof options == "function") {
    setup = options;
    options = {};
  }

  this._codeField = options.codeField || "code";
  this._window = options.window !== undefined ? options.window : 6;

  passport.Strategy.call(this);
  this._setup = setup;
  this.name = "totp";
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
  console.log("CODE FIELD: " + this._codeField);
  var value =
    lookup(req.body, this._codeField) || lookup(req.query, this._codeField);

  console.log("VALUE: " + value);

  var self = this;
  this._setup(req.user, function (err, key, period = 30) {
    console.log("KEY: " + key);
    console.log("PERIOD: " + period);
    if (err) {
      return self.error(err);
    }
    console.log(self);
    console.log("WINDOW: " + self._window);
    console.log("TOTP: ", totp);
    var rv = totp.verify(value, key, { window: self._window, time: period });
    console.log("RV: " + rv);
    if (!rv) {
      return self.fail();
    }
    return self.success(req.user);
  });

  function lookup(obj, field) {
    if (!obj) {
      return null;
    }
    var chain = field.split("]").join("").split("[");
    for (var i = 0, len = chain.length; i < len; i++) {
      var prop = obj[chain[i]];
      if (typeof prop === "undefined") {
        return null;
      }
      if (typeof prop !== "object") {
        return prop;
      }
      obj = prop;
    }
    return null;
  }
};

module.exports = Strategy;
