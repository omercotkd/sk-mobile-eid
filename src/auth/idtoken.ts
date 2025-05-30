import * as jwt from 'jsonwebtoken';

// You should set this secret in your environment variables in production!
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

export function signIdToken(payload: Record<string, any>): string {
  // You can customize the payload as needed (e.g., add iat, iss, etc.)
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    algorithm: 'HS256',
  });
}
