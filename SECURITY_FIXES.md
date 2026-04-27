# Security Fixes - security-enforcer

## 🛡️ Vulnerabilidades Arregladas

### 1. Command Injection (CRITICAL)
**Problema:** Uso de subprocess con inputs no validados
**Fix:** 
- Creado `utils/validation.py` con validación de IPs, container names, etc.
- Creado `utils/auth.py` con wrappers seguros
- Todos los comandos del sistema ahora validan inputs antes de ejecutar

### 2. API Sin Autenticación (CRITICAL)
**Problema:** API REST expuesta sin auth
**Fix:**
- Creado middleware de autenticación con Bearer tokens
- Rate limiting para prevenir brute force
- Decoradores `@require_auth` y `@rate_limited`

### 3. Path Traversal (HIGH)
**Problema:** Funciones backup/restore permitían `../../../etc/passwd`
**Fix:**
- Validación de paths con whitelist de directorios
- Resolución de paths absolutos y verificación

### 4. Secrets en Config (HIGH)
**Problema:** Passwords SMTP en config.json
**Fix:**
- Documentación actualizada para usar variables de entorno
- API `/api/config` ahora filtra todos los secrets

## 📋 Archivos Agregados

- `utils/auth.py` - Autenticación y rate limiting
- `utils/validation.py` - Validación de inputs
- `SECURITY_FIXES.md` - Este archivo

## 🚀 Uso Seguro

```bash
# Setear API key
export ENFORCER_API_KEY="tu-api-key-segura-aqui"

# Ejecutar con validaciones activadas
python3 enforcer.py --secure-mode
```

