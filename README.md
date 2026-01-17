# 🔐 Auth Service - Pilar 1 (15%)

**Universidad Laica Eloy Alfaro de Manabí (ULEAM)**  
**Segundo Parcial - Aplicación para el Servidor Web**

## Descripción

Microservicio de autenticación independiente para Love4Pets con JWT (access + refresh tokens), validación local y base de datos propia.

**Características**:
- ✅ JWT: Access tokens (15 min) + Refresh tokens (7 días)
- ✅ Validación local sin llamadas HTTP al Auth Service
- ✅ Base de datos PostgreSQL propia (`auth_db`)
- ✅ Rate limiting, bcrypt, blacklist de tokens
- ✅ 6 endpoints completos

**Stack**: Node.js, TypeScript, Express, TypeORM, PostgreSQL, Docker

---

## Arquitectura

```
Cliente → Auth Service (8090) → Genera JWT
Cliente → Love4Pets REST (8080) + JWT → Valida LOCALMENTE
```

| Servicio | Puerto | Base de Datos | Función |
|----------|--------|---------------|---------|
| Auth Service | 8090 | `auth_db` | Autenticación |
| Love4Pets REST | 8080 | `love4pets_db` | Lógica de negocio |

---

## Requisitos

- Node.js v18+
- PostgreSQL v15+
- Docker (opcional)

---

## Instalación Rápida

### Con Docker (Recomendado)

```bash
cd JWT-AUTH
docker-compose up -d
curl http://localhost:8090/health
```

### Sin Docker

```bash
npm install
cp .env.example .env
npm run dev
```

**Variables de Entorno**:
```env
PORT=8090
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=auth_db
ACCESS_TOKEN_SECRET=tu_secreto_cambiar_produccion
REFRESH_TOKEN_SECRET=tu_secreto_refresh_cambiar_produccion
ACCESS_TOKEN_EXPIRES_IN=15m
REFRESH_TOKEN_EXPIRES_IN=7d
```

⚠️ **IMPORTANTE**: `ACCESS_TOKEN_SECRET` debe ser el mismo en Auth Service y Love4Pets REST.

---

## Base de Datos

**3 Tablas en `auth_db`**:

1. **users**: id, email, password (bcrypt), name, isActive
2. **refresh_tokens**: id, token, userId, expiresAt, isRevoked, ipAddress
3. **revoked_tokens**: id, token, expiresAt, reason (blacklist)

---

## Endpoints (Base URL: http://localhost:8090)

### 1. POST /auth/register
```json
{
  "email": "user@ejemplo.com",
  "password": "Pass123!",
  "name": "Juan"
}
```
**Rate limit**: 3/hora

### 2. POST /auth/login  
```json
{
  "email": "user@ejemplo.com",
  "password": "Pass123!"
}
```
**Response**: `{ accessToken, refreshToken }`  
**Rate limit**: 5/15min

### 3. POST /auth/refresh
```json
{
  "refreshToken": "token_aqui"
}
```
**Response**: Nuevo par de tokens

### 4. GET /auth/me
**Header**: `Authorization: Bearer <token>`  
**Response**: Info del usuario

### 5. POST /auth/logout
**Header**: `Authorization: Bearer <token>`  
**Body**: `{ refreshToken }`

### 6. GET /auth/validate
**Header**: `Authorization: Bearer <token>`  
**Uso**: Solo para casos especiales, NO en cada request

---

## Integración con Love4Pets (Rust + Axum)

### 1. Agregar a Cargo.toml
```toml
jsonwebtoken = "9.2"
```

### 2. Configurar .env en Love4Pets
```env
JWT_SECRET=tu_secreto_cambiar_produccion
```
⚠️ Debe ser el MISMO secreto que `ACCESS_TOKEN_SECRET` del Auth Service

### 3. Código Rust para Validación Local

**claims.rs**:
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub exp: usize,
}
```

**jwt.rs**:
```rust
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::env;

pub fn validate_token(token: &str) -> Result<Claims, String> {
    let secret = env::var("JWT_SECRET")?;
    let validation = Validation::new(Algorithm::HS256);
    
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation
    )
    .map(|data| data.claims)
    .map_err(|_| "Token inválido".to_string())
}
```

**middleware.rs**:
```rust
use axum::{extract::Request, http::HeaderMap, middleware::Next, response::Response};

pub async fn auth_middleware(headers: HeaderMap, mut req: Request, next: Next) 
    -> Result<Response, StatusCode> 
{
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let claims = validate_token(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
```

**Uso en main.rs**:
```rust
let app = Router::new()
    .route("/api/pets", get(get_pets))
    .layer(middleware::from_fn(auth_middleware));
```

### Flujo Completo
1. Cliente hace login en Auth Service (8090) → Recibe tokens
2. Cliente llama Love4Pets REST (8080) con token
3. Love4Pets valida JWT **localmente** (sin HTTP call)
4. Si válido, procesa el request

---

## Seguridad

- **Rate Limiting**: Login (5/15min), Registro (3/hora)
- **Bcrypt**: Hash de contraseñas (10 salt rounds)
- **Blacklist**: Tokens revocados en tabla `revoked_tokens`
- **CORS**: Configurable en `.env`
- **Helmet**: Headers de seguridad HTTP

---

## Validación Local (Clave del Pilar 1)

**❌ Antipatrón (NO hacer)**:
```
Cliente → Love4Pets → HTTP a Auth Service /validate → Respuesta
```
Problemas: latencia, cuello de botella, dependencia

**✅ Correcto (implementado)**:
```
Cliente → Love4Pets → Valida JWT localmente → Respuesta
```
Beneficios: latencia mínima, sin dependencia, escalable

**Cómo funciona**:
1. Auth Service y Love4Pets comparten `JWT_SECRET`
2. Auth Service firma JWT con ese secreto
3. Love4Pets verifica firma localmente con `jsonwebtoken`
4. Sin llamadas HTTP entre servicios

---

## Cumplimiento Pilar 1 (15%)

| Requisito | ✅ | Evidencia |
|-----------|---|-----------|
| Auth Service independiente | ✅ | Puerto 8090, BD propia |
| JWT (access 15min + refresh 7d) | ✅ | Implementado |
| Validación local | ✅ | Código Rust incluido |
| BD propia (3 tablas) | ✅ | users, refresh_tokens, revoked_tokens |
| 6 endpoints | ✅ | register, login, refresh, logout, me, validate |
| Seguridad | ✅ | Rate limit, bcrypt, blacklist |

---

## Pruebas Rápidas

```bash
curl -X POST http://localhost:8090/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@uleam.edu.ec","password":"Pass123!","name":"Test"}'

curl -X POST http://localhost:8090/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@uleam.edu.ec","password":"Pass123!"}'

TOKEN="<accessToken_del_login>"

curl http://localhost:8080/api/pets \
  -H "Authorization: Bearer $TOKEN"
```

**Verificar independencia**: Detener Auth Service, Love4Pets sigue validando tokens existentes.

---

## Comandos

```bash
docker-compose up -d
docker-compose logs -f auth-service
docker-compose down

npm run dev
npm run build
npm start
```

---

## Estructura

```
src/
├── entities/         # User, RefreshToken, RevokedToken
├── services/         # auth.service, jwt.service
├── controllers/      # auth.controller
├── middleware/       # auth, validation, rate-limit, error
├── routes/           # auth.routes
└── server.ts         # Main
```

---

## Resumen

✅ **Pilar 1 completo (15%)**:
- Microservicio independiente (8090)
- JWT: access (15min) + refresh (7d)
- Validación local sin HTTP calls
- BD propia (3 tablas)
- 6 endpoints + seguridad

**Antipatrón evitado**: Love4Pets valida JWT localmente, sin consultar Auth Service en cada request.
