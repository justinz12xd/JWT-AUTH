import { Request, Response } from 'express';
import authService from '../services/auth.service';
import jwtService from '../services/jwt.service';
import { AuthRequest } from '../middleware/auth.middleware';

class AuthController {
  /**
   * POST /auth/register
   * Registra un nuevo usuario
   */
  async register(req: Request, res: Response) {
    try {
      const { email, password, name } = req.body;

      const user = await authService.register({ email, password, name });

      res.status(201).json({
        success: true,
        message: 'Usuario registrado exitosamente',
        data: { user },
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Error al registrar usuario',
      });
    }
  }

  /**
   * POST /auth/login
   * Autentica un usuario y devuelve tokens
   */
  async login(req: Request, res: Response) {
    try {
      const { email, password } = req.body;
      const ipAddress = req.ip;
      const userAgent = req.headers['user-agent'];

      const { user, tokens } = await authService.login(
        { email, password },
        ipAddress,
        userAgent
      );

      res.status(200).json({
        success: true,
        message: 'Login exitoso',
        data: {
          user,
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
        },
      });
    } catch (error) {
      res.status(401).json({
        success: false,
        message: error instanceof Error ? error.message : 'Error al iniciar sesión',
      });
    }
  }

  /**
   * POST /auth/logout
   * Cierra la sesión revocando los tokens
   */
  async logout(req: AuthRequest, res: Response) {
    try {
      const authHeader = req.headers.authorization;
      const accessToken = authHeader?.substring(7) || '';
      const { refreshToken } = req.body;

      await authService.logout(accessToken, refreshToken);

      res.status(200).json({
        success: true,
        message: 'Logout exitoso',
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Error al cerrar sesión',
      });
    }
  }

  /**
   * POST /auth/refresh
   * Renueva el access token usando el refresh token
   */
  async refresh(req: Request, res: Response) {
    try {
      const { refreshToken } = req.body;
      const ipAddress = req.ip;
      const userAgent = req.headers['user-agent'];

      const tokens = await jwtService.refreshAccessToken(
        refreshToken,
        ipAddress,
        userAgent
      );

      res.status(200).json({
        success: true,
        message: 'Token renovado exitosamente',
        data: {
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
        },
      });
    } catch (error) {
      res.status(401).json({
        success: false,
        message: error instanceof Error ? error.message : 'Error al renovar token',
      });
    }
  }

  /**
   * GET /auth/me
   * Obtiene información del usuario autenticado
   */
  async me(req: AuthRequest, res: Response) {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'No autenticado',
        });
      }

      const user = await authService.getUserById(req.user.userId);

      res.status(200).json({
        success: true,
        data: { user },
      });
    } catch (error) {
      res.status(400).json({
        success: false,
        message: error instanceof Error ? error.message : 'Error al obtener usuario',
      });
    }
  }

  /**
   * GET /auth/validate
   * Endpoint interno para validar tokens (usado por otros microservicios)
   * Este endpoint puede ser usado por otros servicios para validar tokens
   * pero la validación LOCAL debe ser preferida
   */
  async validate(req: AuthRequest, res: Response) {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Token inválido',
        });
      }

      res.status(200).json({
        success: true,
        data: {
          userId: req.user.userId,
          email: req.user.email,
        },
      });
    } catch (error) {
      res.status(401).json({
        success: false,
        message: 'Token inválido',
      });
    }
  }
}

export default new AuthController();
