import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { AppDataSource } from '../data-source';
import { RefreshToken } from '../entities/RefreshToken';
import { RevokedToken } from '../entities/RevokedToken';
import { User } from '../entities/User';

// Decodificar el secret de base64 para compatibilidad con Supabase/Rust
const rawAccessSecret = process.env.ACCESS_TOKEN_SECRET || 'access_secret_key_change_this';
const rawRefreshSecret = process.env.REFRESH_TOKEN_SECRET || 'refresh_secret_key_change_this';

// Si el secret parece ser base64, decodificarlo; si no, usar como está
const isBase64 = (str: string) => {
  try {
    return Buffer.from(str, 'base64').toString('base64') === str;
  } catch {
    return false;
  }
};

const ACCESS_TOKEN_SECRET = isBase64(rawAccessSecret) 
  ? Buffer.from(rawAccessSecret, 'base64')
  : rawAccessSecret;

const REFRESH_TOKEN_SECRET = isBase64(rawRefreshSecret)
  ? Buffer.from(rawRefreshSecret, 'base64')
  : rawRefreshSecret;

const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m';
const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';

/**
 * Payload del token compatible con API Gateway
 * Usa 'sub' como estándar JWT para el ID de usuario
 */
export interface TokenPayload {
  sub: string;      // Subject - ID del usuario (estándar JWT)
  userId: string;   // Alias para compatibilidad
  email: string;
  role?: string;    // Rol del usuario
  aud?: string;     // Audience - requerido por REST API (Rust)
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

class JWTService {
  /**
   * Genera un par de tokens (access y refresh)
   * El payload es compatible con el API Gateway para validación local
   */
  async generateTokenPair(
    user: User,
    ipAddress?: string,
    userAgent?: string
  ): Promise<TokenPair> {
    // Payload compatible con API Gateway (usa 'sub' estándar JWT)
    const payload: TokenPayload = {
      sub: user.id,       // Estándar JWT - requerido por API Gateway
      userId: user.id,    // Alias para compatibilidad
      email: user.email,
      role: 'normal',     // Rol por defecto
      aud: 'authenticated', // Requerido por REST API (Rust)
    };

    // Generar access token (corta duración)
    const accessToken = jwt.sign(payload, ACCESS_TOKEN_SECRET, {
      expiresIn: ACCESS_TOKEN_EXPIRES_IN,
      jwtid: uuidv4(),
      algorithm: 'HS256',
    });

    // Generar refresh token (larga duración)
    const refreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET, {
      expiresIn: REFRESH_TOKEN_EXPIRES_IN,
      jwtid: uuidv4(),
      algorithm: 'HS256',
    });

    // Guardar refresh token en la base de datos
    const refreshTokenRepo = AppDataSource.getRepository(RefreshToken);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 días

    await refreshTokenRepo.save({
      token: refreshToken,
      userId: user.id,
      expiresAt,
      ipAddress,
      userAgent,
    });

    return { accessToken, refreshToken };
  }

  /**
   * Verifica y decodifica un access token
   */
  verifyAccessToken(token: string): TokenPayload {
    try {
      const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET) as TokenPayload;
      return decoded;
    } catch (error) {
      throw new Error('Token inválido o expirado');
    }
  }

  /**
   * Verifica y decodifica un refresh token
   */
  verifyRefreshToken(token: string): TokenPayload {
    try {
      const decoded = jwt.verify(token, REFRESH_TOKEN_SECRET) as TokenPayload;
      return decoded;
    } catch (error) {
      throw new Error('Refresh token inválido o expirado');
    }
  }

  /**
   * Verifica si un token está en la blacklist
   */
  async isTokenRevoked(token: string): Promise<boolean> {
    const revokedTokenRepo = AppDataSource.getRepository(RevokedToken);
    const revokedToken = await revokedTokenRepo.findOne({ where: { token } });
    return !!revokedToken;
  }

  /**
   * Revoca un token añadiéndolo a la blacklist
   */
  async revokeToken(token: string, reason: string): Promise<void> {
    const revokedTokenRepo = AppDataSource.getRepository(RevokedToken);
    
    // Decodificar el token para obtener la expiración
    const decoded: any = jwt.decode(token);
    const expiresAt = new Date(decoded.exp * 1000);

    await revokedTokenRepo.save({
      token,
      expiresAt,
      reason,
    });
  }

  /**
   * Revoca un refresh token específico
   */
  async revokeRefreshToken(token: string): Promise<void> {
    const refreshTokenRepo = AppDataSource.getRepository(RefreshToken);
    await refreshTokenRepo.update({ token }, { isRevoked: true });
  }

  /**
   * Revoca todos los refresh tokens de un usuario
   */
  async revokeAllUserRefreshTokens(userId: string): Promise<void> {
    const refreshTokenRepo = AppDataSource.getRepository(RefreshToken);
    await refreshTokenRepo.update({ userId }, { isRevoked: true });
  }

  /**
   * Valida y renueva un refresh token
   */
  async refreshAccessToken(
    refreshToken: string,
    ipAddress?: string,
    userAgent?: string
  ): Promise<TokenPair> {
    // Verificar que el refresh token sea válido
    const payload = this.verifyRefreshToken(refreshToken);

    // Verificar que el refresh token no esté revocado en la DB
    const refreshTokenRepo = AppDataSource.getRepository(RefreshToken);
    const storedToken = await refreshTokenRepo.findOne({
      where: { token: refreshToken },
      relations: ['user'],
    });

    if (!storedToken || storedToken.isRevoked) {
      throw new Error('Refresh token revocado o inválido');
    }

    if (new Date() > storedToken.expiresAt) {
      throw new Error('Refresh token expirado');
    }

    // Revocar el refresh token antiguo
    await this.revokeRefreshToken(refreshToken);

    // Generar un nuevo par de tokens
    return this.generateTokenPair(storedToken.user, ipAddress, userAgent);
  }

  /**
   * Limpia tokens expirados de la blacklist (mantenimiento)
   */
  async cleanExpiredRevokedTokens(): Promise<void> {
    const revokedTokenRepo = AppDataSource.getRepository(RevokedToken);
    await revokedTokenRepo
      .createQueryBuilder()
      .delete()
      .where('expiresAt < :now', { now: new Date() })
      .execute();
  }

  /**
   * Limpia refresh tokens expirados (mantenimiento)
   */
  async cleanExpiredRefreshTokens(): Promise<void> {
    const refreshTokenRepo = AppDataSource.getRepository(RefreshToken);
    await refreshTokenRepo
      .createQueryBuilder()
      .delete()
      .where('expiresAt < :now', { now: new Date() })
      .execute();
  }
}

export default new JWTService();
