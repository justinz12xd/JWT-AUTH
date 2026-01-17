import bcrypt from 'bcryptjs';
import { AppDataSource } from '../data-source';
import { User } from '../entities/User';
import jwtService, { TokenPair } from './jwt.service';

interface RegisterDto {
  email: string;
  password: string;
  name?: string;
}

interface LoginDto {
  email: string;
  password: string;
}

class AuthService {
  private userRepository = AppDataSource.getRepository(User);

  /**
   * Registra un nuevo usuario
   */
  async register(data: RegisterDto): Promise<User> {
    const { email, password, name } = data;

    // Verificar si el usuario ya existe
    const existingUser = await this.userRepository.findOne({ where: { email } });
    if (existingUser) {
      throw new Error('El email ya está registrado');
    }

    // Hash de la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear usuario
    const user = this.userRepository.create({
      email,
      password: hashedPassword,
      name,
    });

    await this.userRepository.save(user);

    // Eliminar la contraseña del objeto de respuesta
    delete (user as any).password;

    return user;
  }

  /**
   * Autentica un usuario y genera tokens
   */
  async login(
    data: LoginDto,
    ipAddress?: string,
    userAgent?: string
  ): Promise<{ user: User; tokens: TokenPair }> {
    const { email, password } = data;

    // Buscar usuario
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new Error('Credenciales inválidas');
    }

    // Verificar que el usuario esté activo
    if (!user.isActive) {
      throw new Error('Usuario inactivo');
    }

    // Verificar contraseña
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new Error('Credenciales inválidas');
    }

    // Generar tokens
    const tokens = await jwtService.generateTokenPair(user, ipAddress, userAgent);

    // Eliminar la contraseña del objeto de respuesta
    delete (user as any).password;

    return { user, tokens };
  }

  /**
   * Cierra sesión revocando los tokens
   */
  async logout(accessToken: string, refreshToken: string): Promise<void> {
    // Revocar ambos tokens
    await Promise.all([
      jwtService.revokeToken(accessToken, 'logout'),
      jwtService.revokeRefreshToken(refreshToken),
    ]);
  }

  /**
   * Obtiene un usuario por ID
   */
  async getUserById(userId: string): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new Error('Usuario no encontrado');
    }

    delete (user as any).password;
    return user;
  }

  /**
   * Cierra todas las sesiones de un usuario
   */
  async logoutAll(userId: string): Promise<void> {
    await jwtService.revokeAllUserRefreshTokens(userId);
  }
}

export default new AuthService();
