const { login, requireAuth } = require('./auth');
module.exports = (app, db) => {
  app.post('/api/login', async (req, res) => res.json({ token: await login(db, req.body.email, req.body.password) }));
  app.get('/api/me', requireAuth, (req, res) => res.json(req.user));
};
