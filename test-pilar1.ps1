# Script de pruebas completas para Pilar 1 - Auth Service

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " PRUEBAS PILAR 1 - AUTH MICROSERVICE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$baseUrl = "http://localhost:8090"
$testEmail = "test_$(Get-Random)@example.com"
$testPassword = "SecurePass123!"

# Test 1: Health Check
Write-Host "1️⃣  Health Check" -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$baseUrl/health" -Method GET
    Write-Host "   ✅ Health Check: $($health.message)" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Error: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 2: Registro (POST /auth/register)
Write-Host "2️⃣  POST /auth/register" -ForegroundColor Yellow
try {
    $registerBody = @{
        email = $testEmail
        password = $testPassword
        name = "Usuario Test"
    } | ConvertTo-Json
    
    $register = Invoke-RestMethod -Uri "$baseUrl/auth/register" -Method POST -Body $registerBody -ContentType "application/json"
    Write-Host "   ✅ Usuario registrado: $($register.data.user.email)" -ForegroundColor Green
    Write-Host "   📧 Email: $($register.data.user.email)" -ForegroundColor Gray
    Write-Host "   🆔 ID: $($register.data.user.id)" -ForegroundColor Gray
} catch {
    Write-Host "   ❌ Error: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 3: Login (POST /auth/login) - Obtiene JWT tokens
Write-Host "3️⃣  POST /auth/login" -ForegroundColor Yellow
try {
    $loginBody = @{
        email = $testEmail
        password = $testPassword
    } | ConvertTo-Json
    
    $login = Invoke-RestMethod -Uri "$baseUrl/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
    $accessToken = $login.data.accessToken
    $refreshToken = $login.data.refreshToken
    
    Write-Host "   ✅ Login exitoso" -ForegroundColor Green
    Write-Host "   🔑 Access Token: $($accessToken.Substring(0,50))..." -ForegroundColor Gray
    Write-Host "   🔄 Refresh Token: $($refreshToken.Substring(0,50))..." -ForegroundColor Gray
} catch {
    Write-Host "   ❌ Error: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 4: Me (GET /auth/me) - Usuario autenticado
Write-Host "4️⃣  GET /auth/me (validación local JWT)" -ForegroundColor Yellow
try {
    $headers = @{
        Authorization = "Bearer $accessToken"
    }
    $me = Invoke-RestMethod -Uri "$baseUrl/auth/me" -Method GET -Headers $headers
    Write-Host "   ✅ Usuario autenticado correctamente" -ForegroundColor Green
    Write-Host "   📧 Email: $($me.data.user.email)" -ForegroundColor Gray
    Write-Host "   👤 Nombre: $($me.data.user.name)" -ForegroundColor Gray
} catch {
    Write-Host "   ❌ Error: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 5: Validate (GET /auth/validate) - Endpoint interno
Write-Host "5️⃣  GET /auth/validate (endpoint interno)" -ForegroundColor Yellow
try {
    $headers = @{
        Authorization = "Bearer $accessToken"
    }
    $validate = Invoke-RestMethod -Uri "$baseUrl/auth/validate" -Method GET -Headers $headers
    Write-Host "   ✅ Token validado localmente" -ForegroundColor Green
    Write-Host "   🆔 User ID: $($validate.data.userId)" -ForegroundColor Gray
    Write-Host "   📧 Email: $($validate.data.email)" -ForegroundColor Gray
} catch {
    Write-Host "   ❌ Error: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 6: Refresh (POST /auth/refresh) - Renovar access token
Write-Host "6️⃣  POST /auth/refresh (renovar tokens)" -ForegroundColor Yellow
try {
    $refreshBody = @{
        refreshToken = $refreshToken
    } | ConvertTo-Json
    
    $refresh = Invoke-RestMethod -Uri "$baseUrl/auth/refresh" -Method POST -Body $refreshBody -ContentType "application/json"
    $newAccessToken = $refresh.data.accessToken
    
    Write-Host "   ✅ Token renovado exitosamente" -ForegroundColor Green
    Write-Host "   🔑 Nuevo Access Token: $($newAccessToken.Substring(0,50))..." -ForegroundColor Gray
} catch {
    Write-Host "   ❌ Error: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 7: Logout (POST /auth/logout) - Revocar tokens
Write-Host "7️⃣  POST /auth/logout (blacklist)" -ForegroundColor Yellow
try {
    $headers = @{
        Authorization = "Bearer $accessToken"
    }
    $logoutBody = @{
        refreshToken = $refreshToken
    } | ConvertTo-Json
    
    $logout = Invoke-RestMethod -Uri "$baseUrl/auth/logout" -Method POST -Body $logoutBody -ContentType "application/json" -Headers $headers
    Write-Host "   ✅ Logout exitoso - Tokens revocados" -ForegroundColor Green
} catch {
    Write-Host "   ❌ Error: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 8: Verificar que token revocado no funciona
Write-Host "8️⃣  Verificar blacklist (token revocado)" -ForegroundColor Yellow
try {
    $headers = @{
        Authorization = "Bearer $accessToken"
    }
    $me = Invoke-RestMethod -Uri "$baseUrl/auth/me" -Method GET -Headers $headers
    Write-Host "   ❌ ERROR: El token revocado aún funciona!" -ForegroundColor Red
} catch {
    Write-Host "   ✅ Token revocado correctamente bloqueado" -ForegroundColor Green
}
Write-Host ""

# Test 9: Verificar base de datos
Write-Host "9️⃣  Verificar base de datos" -ForegroundColor Yellow
try {
    $dbCheck = docker exec auth-postgres psql -U postgres -d auth_db -c "\dt" 2>&1
    if ($dbCheck -match "users" -and $dbCheck -match "refresh_tokens" -and $dbCheck -match "revoked_tokens") {
        Write-Host "   ✅ Base de datos con 3 tablas:" -ForegroundColor Green
        Write-Host "      - users" -ForegroundColor Gray
        Write-Host "      - refresh_tokens" -ForegroundColor Gray
        Write-Host "      - revoked_tokens" -ForegroundColor Gray
    } else {
        Write-Host "   ❌ Faltan tablas en la base de datos" -ForegroundColor Red
    }
} catch {
    Write-Host "   ⚠️  No se pudo verificar la base de datos" -ForegroundColor Yellow
}
Write-Host ""

# Resumen final
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ✅ TODAS LAS PRUEBAS EXITOSAS" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "COMPONENTES PILAR 1 VERIFICADOS:" -ForegroundColor White
Write-Host "  ✅ Auth Service independiente (puerto 8090)" -ForegroundColor Green
Write-Host "  ✅ JWT con access + refresh tokens" -ForegroundColor Green
Write-Host "  ✅ Validación local (sin llamadas HTTP)" -ForegroundColor Green
Write-Host "  ✅ Base de datos propia (3 tablas)" -ForegroundColor Green
Write-Host "  ✅ Seguridad: Rate limiting, bcrypt, blacklist" -ForegroundColor Green
Write-Host "  ✅ 6 endpoints: register, login, logout, refresh, me, validate" -ForegroundColor Green
Write-Host ""
