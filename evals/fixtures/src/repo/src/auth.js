// Plain source repo used as a NEGATIVE eval: the skill should not run RE tooling on this.
const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET;
async function login(db, email, password) {
  const user = await db.users.findOne({ email });
  if (!user || !(await user.verifyPassword(password))) throw new Error('invalid credentials');
  return jwt.sign({ sub: user.id, role: user.role }, SECRET, { expiresIn: '1h' });
}
function requireAuth(req, res, next) {
  try { req.user = jwt.verify(req.headers.authorization.replace('Bearer ', ''), SECRET); next(); }
  catch { res.status(401).json({ error: 'unauthorized' }); }
}
module.exports = { login, requireAuth };
