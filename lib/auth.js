const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
    throw new Error('JWT_SECRET nao definido.');
}

function signToken(user) {
    return jwt.sign({ sub: user.id, email: user.email }, SECRET, { expiresIn: '30d' });
}

function requireAuth(req, res, next) {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'nao autenticado' });
    try {
          req.user = jwt.verify(token, SECRET);
          next();
    } catch (e) {
          return res.status(401).json({ error: 'sessao invalida ou expirada' });
    }
}

module.exports = { signToken, requireAuth };
