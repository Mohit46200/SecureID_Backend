import jwt from 'jsonwebtoken';

export function requireSession(req, res, next) {
  if (!req.session?.userId) {
    return res.status(401).json({
      message: 'Authentication required.',
    });
  }

  return next();
}

export function requireJwt(req, res, next) {
  const authorization = req.headers.authorization || '';
  const token = authorization.startsWith('Bearer ')
    ? authorization.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      message: 'Bearer token required.',
    });
  }

  try {
    req.jwtUser = jwt.verify(
      token,
      process.env.JWT_SECRET || 'dev-jwt-secret',
    );

    return next();
  } catch {
    return res.status(401).json({
      message: 'Invalid or expired token.',
    });
  }
}
