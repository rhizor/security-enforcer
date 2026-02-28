# 🛡️ Dynamic Security Policy Enforcer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-success.svg" alt="Status">
</p>

> **Automatización de seguridad en tiempo real** - Detecta vulnerabilidades, ataques e indicadores de amenaza, y aplica reglas de firewall dinámicamente.

## 📋 Tabla de Contenidos

- [Características](#-características)
- [Arquitectura](#-arquitectura)
- [Instalación](#-instalación)
- [Configuración](#-configuración)
- [Uso](#-uso)
- [API REST](#-api-rest)
- [Módulos](#-módulos)
- [Docker](#-docker)
- [Solución de Problemas](#-solución-de-problemas)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)

---

## 🚀 Características

### Core
- ✅ **Monitoreo de CVEs** desde NVD, CIRCL y fuentes personalizadas
- ✅ **Detección de ataques** desde múltiples fuentes (fail2ban, logs, redes)
- ✅ **Reglas de firewall dinámicas** (nftables + iptables)
- ✅ **80+ servicios** mapeados para correlación CVE→Puerto

### Threat Intelligence
- ✅ **ThreatFox** - Indicadores de compromiso (IOCs)
- ✅ **Malware Bazaar** - Muestras de malware recientes
- ✅ **URLHaus** - URLs maliciosas
- ✅ **FireHOL** - Blacklists de IPs conocidas
- ✅ **AWS Security Hub** - Hallazgos de AWS
- ✅ **Azure Sentinel** - Incidentes de Azure
- ✅ **GCP Security Command Center** - Hallazgos de GCP

### Seguridad Avanzada
- ✅ **Container Security** - Docker & Kubernetes
- ✅ **File Integrity Monitor** - Detección de cambios en archivos críticos
- ✅ **SIEM Integration** - Splunk, Elasticsearch, Syslog

### Notificaciones & Automation
- ✅ **Slack** - Alertas en canales de Slack
- ✅ **Telegram** - Notificaciones bot de Telegram
- ✅ **Webhook** - Integración con cualquier sistema
- ✅ **Email (SMTP)** - Alertas críticas por correo
- ✅ **Scheduler** - Ejecución automática programada
- ✅ **API REST** - Control completo via HTTP

### Reportes
- ✅ **HTML** - Reportes visuales interactivos
- ✅ **JSON** - Exportación para otros sistemas

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SECURITY ENFORCER ORCHESTRATOR                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │   CVEs      │  │  Attacks     │  │  Threat     │              │
│  │  Fetcher    │  │  Detector    │  │  Intel      │              │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │
│         │                  │                  │                      │
│         └──────────────────┼──────────────────┘                      │
│                            ▼                                         │
│                 ┌─────────────────────┐                             │
│                 │   Policy Engine     │                             │
│                 │  (Rule Generator)    │                             │
│                 └──────────┬──────────┘                             │
│                            │                                         │
│         ┌──────────────────┼──────────────────┐                      │
│         ▼                  ▼                  ▼                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  Firewall    │  │ Container    │  │     FIM      │              │
│  │  Manager     │  │  Security    │  │   Monitor    │              │
│  └──────┬───────┘  └──────────────┘  └──────────────┘              │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  Notifier    │  │    SIEM      │  │   Reports    │              │
│  │  (Slack/TG)  │  │  Integration │  │  (HTML/JSON) │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Instalación

### Requisitos

- **Python 3.8+**
- **Linux** (desarrollado para nftables/iptables)
- **Permisos de root** (para modificar firewall)

### Pasos

```bash
# 1. Clonar o descargar el repositorio
git clone https://github.com/tu-usuario/security-enforcer.git
cd security-enforcer

# 2. Crear entorno virtual (recomendado)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# 3. Instalar dependencias
pip install requests

# 4. Verificar instalación
python3 enforcer.py
```

### Dependencias del Sistema (opcionales)

```bash
# Para full funcionalidad
sudo apt install -y nftables iptables fail2ban docker.io kubectl awscli az gcloud

# Verificar
nft --version
iptables --version
docker --version
```

---

## ⚙️ Configuración

### Archivo `config.json`

```json
{
  "dry_run": true,
  "firewall_backend": "nft",

  "cve_days": 7,
  "min_cve_severity": "7.0",
  "enable_attack_detection": true,

  "threat_intel": {
    "enable_threatfox": true,
    "enable_malware_bazaar": true,
    "enable_urlhaus": true,
    "enable_aws_security_hub": false,
    "enable_azure_sentinel": false,
    "enable_gcp_security_command": false
  },

  "notifications": {
    "webhook_url": "https://tu-webhook.com/endpoint",
    "slack_webhook": "https://hooks.slack.com/services/XXX",
    "telegram_token": "BOT_TOKEN",
    "telegram_chat_id": "CHAT_ID",
    "smtp": {
      "enabled": false,
      "host": "smtp.gmail.com",
      "port": 587,
      "username": "tu-email@gmail.com",
      "password": "APP_PASSWORD",
      "from": "security@tu-dominio.com",
      "to": "admin@tu-dominio.com"
    }
  },

  "siem": {
    "splunk": {
      "enabled": false,
      "host": "splunk.example.com",
      "hec_token": "TU_HEC_TOKEN",
      "verify_ssl": true
    },
    "elk": {
      "enabled": false,
      "url": "http://localhost:9200",
      "index": "security-logs"
    },
    "syslog": {
      "enabled": false,
      "host": "siem.example.com",
      "port": 514
    }
  },

  "container_security": {
    "enabled": true,
    "check_docker": true,
    "check_kubernetes": true
  },

  "file_integrity": {
    "enabled": true,
    "paths": [
      "/etc/passwd",
      "/etc/shadow",
      "/etc/ssh/sshd_config"
    ]
  },

  "api_server": {
    "enabled": false,
    "port": 8080
  },

  "scheduler": {
    "enabled": false,
    "interval_minutes": 60
  }
}
```

### Explicación de Parámetros

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `dry_run` | boolean | Si `true`, solo simula sin aplicar reglas |
| `firewall_backend` | string | `nft` (nftables) o `iptables` |
| `cve_days` | int | Días hacia atrás para buscar CVEs |
| `min_cve_severity` | float | Severidad mínima (7.0 = Medium) |
| `enable_attack_detection` | boolean | Habilitar detección de ataques |
| `scheduler.enabled` | boolean | Ejecución automática |
| `scheduler.interval_minutes` | int | Minutos entre ejecuciones |

---

## 🎮 Uso

### Modo Básico (Dry-Run)

```bash
python3 enforcer.py
```

Salida:
```
╔═══════════════════════════════════════════════════════════╗
║     🛡️ Dynamic Security Policy Enforcer v1.0              ║
╚═══════════════════════════════════════════════════════════╝
    
Configuración: dry_run=True

📊 Resumen:
   CVEs encontrados: 12
   Ataques detectados: 5
   Reglas generadas: 8
   Aplicadas: 8
   Fallidas: 0
```

### Modo Producción

```bash
# Editar config.json y cambiar dry_run a false
nano config.json
# "dry_run": false

# Ejecutar
python3 enforcer.py
```

### Orquestador Completo

```bash
# Ejecuta todo: enforcer + containers + FIM + reports + SIEM
python3 orchestrator.py
```

### CLI helper

```bash
# Ver estado
./enforcerctl status

# Dry-run
./enforcerctl dry-run

# Producción
./enforcerctl run

# Ver reglas activas
./enforcerctl list-rules

# Limpiar estado
./enforcerctl clear
```

---

## 🌐 API REST

### Iniciar API Server

```bash
# Habilitar en config.json
"api_server": {
  "enabled": true,
  "port": 8080
}

# Ejecutar
python3 orchestrator.py
```

### Endpoints

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/status` | Estado del sistema |
| GET | `/api/rules` | Lista de reglas aplicadas |
| GET | `/api/logs` | Logs recientes |
| GET | `/api/config` | Configuración actual |
| GET | `/api/threats` | CVEs, ataques, threat intel |
| POST | `/api/run` | Ejecutar enforcer |
| POST | `/api/block` | Bloquear IP |
| POST | `/api/unblock` | Desbloquear IP |

### Ejemplos

```bash
# Ver estado
curl http://localhost:8080/api/status

# Bloquear IP
curl -X POST http://localhost:8080/api/block \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100", "reason": "Brute force attack"}'

# Ejecutar enforcer
curl -X POST http://localhost:8080/api/run
```

---

## 🐳 Docker

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    nftables \
    iptables \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY . /app
RUN pip install requests

CMD ["python3", "orchestrator.py"]
```

### Build & Run

```bash
docker build -t security-enforcer .
docker run -d \
  --cap-add=NET_ADMIN \
  --network=host \
  -v $(pwd)/config.json:/app/config.json \
  security-enforcer
```

---

## 📊 Módulos Detallados

### 1. CVE Fetcher
- **NVD API** - National Vulnerability Database
- **CIRCL.lu** - Centro de respuesta
- **Modo demo** - Datos de ejemplo sin API

### 2. Attack Detector
- **fail2ban** - IPs baneadas
- **Auth logs** - SSH/FTP brute force
- **Nginx/Apache** - Web attacks (SQLi, XSS, RCE)
- **UFW logs** - Logs de firewall
- **FireHOL** - Blacklists públicas

### 3. Threat Intelligence
- **ThreatFox** - IOCs de malware
- **Malware Bazaar** - Muestras recientes
- **URLHaus** - URLs de malware
- **Cloud Security** - AWS/Azure/GCP

### 4. Container Security
- Docker: Containers privilegiados, capabilities peligrosas
- Kubernetes: Pods privilegiados, capabilities

### 5. File Integrity Monitor
- Hash SHA256 de archivos críticos
- Detección de: creación, modificación, eliminación

### 6. SIEM Integration
- **Splunk** - HTTP Event Collector (HEC)
- **Elasticsearch** - Index directo
- **Syslog** - UDP/TCP

---

## 🔧 Solución de Problemas

### Error: "fail2ban no disponible"
```
# Instalar fail2ban
sudo apt install fail2ban
sudo systemctl enable fail2ban
```

### Error: "nftables not found"
```
# Instalar nftables
sudo apt install nftables
sudo systemctl enable nftables
```

### APIs de CVE no responden
El sistema automáticamente usa datos de demo. Para producción, obtener API key de NVD:
```
https://nvd.nist.gov/developers/request-an-api-key
```

### Permisos denegados
```bash
# Ejecutar con sudo para firewall
sudo python3 enforcer.py
```

---

## 🤝 Contribuir

1. Fork el proyecto
2. Crear branch (`git checkout -b feature/AmazingFeature`)
3. Commit cambios (`git commit -m 'Add AmazingFeature'`)
4. Push al branch (`git push origin feature/AmazingFeature`)
5. Abrir Pull Request

---

## 📝 Licencia

MIT License - ver [LICENSE](LICENSE) para detalles.

---

## ⚠️ Advertencias de Seguridad

1. **Siempre probar en dry-run primero**
2. **Hacer backup de reglas de firewall antes de producción**
3. **Revisar logs antes de activar automatización**
4. **Usar API keys de NVD para datos actualizados**
5. **No exponer API REST sin autenticación en producción**

---

## 🔗 Enlaces Útiles

- [NVD API](https://nvd.nist.gov/developers/vulnerabilities)
- [ThreatFox API](https://threatfox.abuse.ch/api/)
- [URLHaus API](https://urlhaus-api.abuse.ch/)
- [FireHOL Blocklists](https://firehol.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

<p align="center">
  <sub>Construido con 🔒 y ☕</sub>
</p>
