import { DataSource } from 'typeorm';
import { User } from './entities/User';
import { RefreshToken } from './entities/RefreshToken';
import { RevokedToken } from './entities/RevokedToken';

export const AppDataSource = new DataSource({
  type: 'postgres',
  url: process.env.DATABASE_URL,
  synchronize: process.env.NODE_ENV === 'development',
  logging: process.env.NODE_ENV === 'development',
  entities: [User, RefreshToken, RevokedToken],
  migrations: ['src/migrations/**/*.ts'],
  subscribers: [],
  ssl: process.env.DATABASE_URL?.includes('supabase') ? { rejectUnauthorized: false } : false,
});
