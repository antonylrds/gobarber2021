import { Request, Response, NextFunction } from 'express';
import { verify } from 'jsonwebtoken';

import AppError from '../errors/AppError';

import authConfig from '../config/auth';

interface TokenPayload {
  iat: number;
  exp: number;
  sub: string;
}

export default function ensureAuthenticated(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    throw new AppError('JWT token does not exists', 401);
  }

  const [, token] = authHeader.split(' ');

  const decoded = verify(token, authConfig.jwt.secret);

  const { sub } = decoded as TokenPayload;

  req.user = {
    id: sub,
  };

  return next();
}
