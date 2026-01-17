import express, { Request, Response } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { AppDataSource } from './data-source';
import authRoutes from './routes/auth.routes';
import { errorHandler } from './middleware/error.middleware';
import { apiLimiter } from './middleware/rate-limit.middleware';
import jwtService from './services/jwt.service';

// Cargar variables de entorno
dotenv.config();

const app = express();
const PORT = process.env.PORT || 8090;

// Middleware de seguridad
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true,
}));

// Parsear JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting global
app.use(apiLimiter);

// Health check
app.get('/health', (req: Request, res: Response) => {
  res.status(200).json({
    success: true,
    message: 'Auth Service is running',
    timestamp: new Date().toISOString(),
  });
});

// Rutas
app.use('/auth', authRoutes);

// Manejador de errores
app.use(errorHandler);

// Ruta no encontrada
app.use('*', (req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    message: 'Ruta no encontrada',
  });
});

// Inicializar base de datos y servidor
const startServer = async () => {
  try {
    // Conectar a la base de datos
    await AppDataSource.initialize();
    console.log('✅ Database connected successfully');

    // Iniciar limpieza periódica de tokens expirados (cada 24 horas)
    setInterval(async () => {
      try {
        await jwtService.cleanExpiredRevokedTokens();
        await jwtService.cleanExpiredRefreshTokens();
        console.log('🧹 Expired tokens cleaned');
      } catch (error) {
        console.error('Error cleaning expired tokens:', error);
      }
    }, 24 * 60 * 60 * 1000); // 24 horas

    // Iniciar servidor
    app.listen(PORT, () => {
      console.log(` Auth Service running on port ${PORT}`);
      console.log(` Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('❌ Error starting server:', error);
    process.exit(1);
  }
};

// Manejo de errores no capturados
process.on('unhandledRejection', (error: Error) => {
  console.error('Unhandled Rejection:', error);
});

process.on('uncaughtException', (error: Error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

// Manejo de señales de terminación
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, closing server...');
  if (AppDataSource.isInitialized) {
    await AppDataSource.destroy();
  }
  process.exit(0);
});

startServer();

export default app;
