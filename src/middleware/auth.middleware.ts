import { Request, Response, NextFunction } from 'express';
import jwtService from '../services/jwt.service';

export interface AuthRequest extends Request {
  user?: {
    userId: string;
    email: string;
    role?: string;
  };
}

/**
 * Middleware para validar el access token localmente
 * Este middleware NO consulta al Auth Service, solo verifica la firma y expiración
 * Implementa validación LOCAL como requiere el Pilar 1
 */
export const authenticate = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Token no proporcionado',
      });
    }

    const token = authHeader.substring(7);

    // Verificar si el token está en la blacklist
    const isRevoked = await jwtService.isTokenRevoked(token);
    if (isRevoked) {
      return res.status(401).json({
        success: false,
        message: 'Token revocado',
      });
    }

    // Verificar y decodificar el token (validación local)
    const payload = jwtService.verifyAccessToken(token);

    // Agregar información del usuario al request
    // Compatible con ambos formatos: sub (estándar) y userId (legacy)
    req.user = {
      userId: payload.sub || payload.userId,
      email: payload.email,
      role: payload.role,
    };

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: error instanceof Error ? error.message : 'Token inválido',
    });
  }
};

/**
 * Middleware opcional para validar token (no falla si no hay token)
 */
export const optionalAuthenticate = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const isRevoked = await jwtService.isTokenRevoked(token);
      
      if (!isRevoked) {
        const payload = jwtService.verifyAccessToken(token);
        req.user = {
          userId: payload.sub || payload.userId,
          email: payload.email,
          role: payload.role,
        };
      }
    }
  } catch (error) {
    // No hacer nada, simplemente no agregar el usuario
  }

  next();
};
