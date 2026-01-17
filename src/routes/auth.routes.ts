import { Router } from 'express';
import authController from '../controllers/auth.controller';
import { authenticate } from '../middleware/auth.middleware';
import { validate } from '../middleware/validation.middleware';
import { loginLimiter, registerLimiter } from '../middleware/rate-limit.middleware';

const router = Router();

/**
 * @route   POST /auth/register
 * @desc    Registrar nuevo usuario
 * @access  Public
 */
router.post(
  '/register',
  registerLimiter,
  validate('register'),
  authController.register
);

/**
 * @route   POST /auth/login
 * @desc    Iniciar sesión
 * @access  Public
 */
router.post(
  '/login',
  loginLimiter,
  validate('login'),
  authController.login
);

/**
 * @route   POST /auth/logout
 * @desc    Cerrar sesión
 * @access  Private
 */
router.post('/logout', authenticate, authController.logout);

/**
 * @route   POST /auth/refresh
 * @desc    Renovar access token
 * @access  Public
 */
router.post('/refresh', validate('refresh'), authController.refresh);

/**
 * @route   GET /auth/me
 * @desc    Obtener información del usuario autenticado
 * @access  Private
 */
router.get('/me', authenticate, authController.me);

/**
 * @route   GET /auth/validate
 * @desc    Validar token (endpoint interno para otros microservicios)
 * @access  Private
 */
router.get('/validate', authenticate, authController.validate);

export default router;
