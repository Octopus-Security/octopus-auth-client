module.exports = {
  ...require('./lib/verify'),
  ...require('./lib/middleware'),
  ...require('./lib/remote-verify'),
  ...require('./lib/client'),
};
