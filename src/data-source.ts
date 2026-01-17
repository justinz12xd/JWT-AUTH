import { DataSource } from 'typeorm';
import { User } from './entities/User';
import { RefreshToken } from './entities/RefreshToken';
import { RevokedToken } from './entities/RevokedToken';

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  username: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: process.env.DB_NAME || 'auth_db',
  synchronize: process.env.NODE_ENV === 'development',
  logging: process.env.NODE_ENV === 'development',
  entities: [User, RefreshToken, RevokedToken],
  migrations: ['src/migrations/**/*.ts'],
  subscribers: [],
});
