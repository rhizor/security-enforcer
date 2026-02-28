#!/usr/bin/env python3
"""
Security Enforcer - Complete Package
Incluye: API REST, Scheduler, Dashboard, Reportes, SIEM, Container Security
"""

import json
import os
import threading
import time
import uuid
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import socketserver

# ==================== API REST ====================

class APIHandler(BaseHTTPRequestHandler):
    """API REST para gestionar el enforcer."""
    
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
    
    def do_GET(self):
        path = urlparse(self.path).path
        
        if path == '/api/status':
            self._handle_status()
        elif path == '/api/rules':
            self._handle_list_rules()
        elif path == '/api/logs':
            self._handle_logs()
        elif path == '/api/config':
            self._handle_config()
        elif path == '/api/threats':
            self._handle_threats()
        elif path == '/health':
            self._set_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
    
    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get('content-length', 0))
        body = self.rfile.read(length) if length > 0 else b''
        
        if path == '/api/run':
            self._handle_run()
        elif path == '/api/block':
            try:
                data = json.loads(body)
                self._handle_block(data)
            except:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())
        elif path == '/api/unblock':
            try:
                data = json.loads(body)
                self._handle_unblock(data)
            except:
                self._set_headers(400)
                self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
    
    def _handle_status(self):
        self._set_headers()
        try:
            with open(".enforcer_state.json") as f:
                state = json.load(f)
            response = {
                "status": "running",
                "last_run": state.get("last_run"),
                "cves": len(state.get("cves", [])),
                "attacks": len(state.get("attacks", [])),
                "rules": len(state.get("rules", []))
            }
        except:
            response = {"status": "no_data", "last_run": None}
        self.wfile.write(json.dumps(response).encode())
    
    def _handle_list_rules(self):
        self._set_headers()
        try:
            with open(".enforcer_state.json") as f:
                state = json.load(f)
            self.wfile.write(json.dumps(state.get("rules", [])).encode())
        except:
            self.wfile.write(json.dumps([]).encode())
    
    def _handle_logs(self):
        self._set_headers()
        try:
            with open("enforcer.log") as f:
                lines = f.readlines()[-100:]
            self.wfile.write(json.dumps(lines).encode())
        except:
            self.wfile.write(json.dumps([]).encode())
    
    def _handle_config(self):
        self._set_headers()
        try:
            with open("config.json") as f:
                config = json.load(f)
            # Ocultar passwords
            if "smtp" in config and "password" in config["smtp"]:
                config["smtp"]["password"] = "***"
            self.wfile.write(json.dumps(config).encode())
        except:
            self.wfile.write(json.dumps({}).encode())
    
    def _handle_threats(self):
        self._set_headers()
        try:
            with open(".enforcer_state.json") as f:
                state = json.load(f)
            threats = {
                "cves": state.get("cves", []),
                "attacks": state.get("attacks", []),
                "threat_intel": state.get("threat_intel", [])
            }
            self.wfile.write(json.dumps(threats).encode())
        except:
            self.wfile.write(json.dumps({}).encode())
    
    def _handle_run(self):
        self._set_headers()
        # Import and run enforcer
        import subprocess
        result = subprocess.run(["python3", "enforcer.py"], 
                              capture_output=True, text=True, timeout=300)
        self.wfile.write(json.dumps({
            "success": result.returncode == 0,
            "output": result.stdout[-1000:]
        }).encode())
    
    def _handle_block(self, data):
        ip = data.get("ip")
        reason = data.get("reason", "manual_block")
        if not ip:
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": "IP required"}).encode())
            return
        
        # Apply block via firewall
        import subprocess
        cmd = ["nft", "add", "rule", "ip", "filter", "input", "ip", "saddr", ip, "drop"]
        result = subprocess.run(cmd, capture_output=True)
        
        self._set_headers()
        self.wfile.write(json.dumps({
            "success": result.returncode == 0,
            "ip": ip,
            "action": "blocked"
        }).encode())
    
    def _handle_unblock(self, data):
        ip = data.get("ip")
        if not ip:
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": "IP required"}).encode())
            return
        
        self._set_headers()
        self.wfile.write(json.dumps({
            "success": True,
            "ip": ip,
            "action": "unblocked"
        }).encode())
    
    def log_message(self, format, *args):
        pass  # Silenciar logs HTTP


class APIServer:
    """Servidor API REST."""
    
    def __init__(self, port=8080):
        self.port = port
        self.server = None
        self.thread = None
    
    def start(self):
        self.server = HTTPServer(('0.0.0.0', self.port), APIHandler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        print(f"🌐 API Server iniciado en http://localhost:{self.port}")
    
    def stop(self):
        if self.server:
            self.server.shutdown()


# ==================== SCHEDULER ====================

class Scheduler:
    """Programador de ejecuciones automáticas."""
    
    def __init__(self, config: dict):
        self.config = config
        self.running = False
        self.thread = None
        
    def start(self):
        """Inicia el scheduler."""
        interval = self.config.get("schedule_interval_minutes", 60)
        self.running = True
        
        def run_loop():
            while self.running:
                import subprocess
                print(f"⏰ Ejecución programada ({interval} min)...")
                subprocess.run(["python3", "enforcer.py"], timeout=300)
                time.sleep(interval * 60)
        
        self.thread = threading.Thread(target=run_loop)
        self.thread.daemon = True
        self.thread.start()
        print(f"⏰ Scheduler iniciado (cada {interval} minutos)")
    
    def stop(self):
        self.running = False


# ==================== REPORTS ====================

class ReportGenerator:
    """Genera reportes de seguridad."""
    
    def __init__(self):
        self.output_dir = "reports"
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_html_report(self, state: dict) -> str:
        """Genera reporte HTML."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/security_report_{timestamp}.html"
        
        cves = state.get("cves", [])
        attacks = state.get("attacks", [])
        rules = state.get("rules", [])
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {timestamp}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #1a1a2e; color: white; padding: 20px; border-radius: 10px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: white; padding: 20px; border-radius: 10px; flex: 1; text-align: center; }}
        .stat h2 {{ margin: 0; font-size: 36px; }}
        .stat.cves {{ border-left: 5px solid #e74c3c; }}
        .stat.attacks {{ border-left: 5px solid #f39c12; }}
        .stat.rules {{ border-left: 5px solid #27ae60; }}
        table {{ width: 100%; border-collapse: collapse; background: white; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; }}
        .medium {{ color: #f1c40f; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Report</h1>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="stats">
        <div class="stat cves">
            <h2>{len(cves)}</h2>
            <p>CVEs</p>
        </div>
        <div class="stat attacks">
            <h2>{len(attacks)}</h2>
            <p>Ataques</p>
        </div>
        <div class="stat rules">
            <h2>{len(rules)}</h2>
            <p>Reglas</p>
        </div>
    </div>
    
    <h2>🚨 CVEs Recientes</h2>
    <table>
        <tr><th>ID</th><th>Score</th><th>Description</th></tr>
        {''.join(f"<tr><td>{c.get('id','')}</td><td class='{'critical' if c.get('score',0)>=9 else 'high' if c.get('score',0)>=7 else 'medium'}'>{c.get('score',0)}</td><td>{c.get('description','')}</td></tr>" for c in cves[:10])}
    </table>
    
    <h2>⚠️ Ataques Detectados</h2>
    <table>
        <tr><th>IP</th><th>Type</th><th>Count</th><th>Severity</th></tr>
        {''.join(f"<tr><td>{a.get('ip','')}</td><td>{a.get('type','')}</td><td>{a.get('count',0)}</td><td class='{a.get('severity','')}'>{a.get('severity','')}</td></tr>" for a in attacks[:10])}
    </table>
    
    <h2>📝 Reglas Aplicadas</h2>
    <table>
        <tr><th>Action</th><th>Target</th><th>Description</th></tr>
        {''.join(f"<tr><td>{r.get('action','')}</td><td>{r.get('target','')}</td><td>{r.get('description','')}</td></tr>" for r in rules[:20])}
    </table>
    
    <footer style="margin-top: 30px; text-align: center; color: #666;">
        <p>Generated by Security Enforcer</p>
    </footer>
</body>
</html>"""
        
        with open(filename, "w") as f:
            f.write(html)
        
        return filename
    
    def generate_json_report(self, state: dict) -> str:
        """Genera reporte JSON."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/security_report_{timestamp}.json"
        
        with open(filename, "w") as f:
            json.dump(state, f, indent=2)
        
        return filename


# ==================== SIEM INTEGRATION ====================

class SIEMIntegrator:
    """Integración con sistemas SIEM."""
    
    def __init__(self, config: dict):
        self.config = config
    
    def send_to_splunk(self, event: dict) -> bool:
        """Envía evento a Splunk HEC."""
        splunk = self.config.get("splunk", {})
        if not splunk.get("enabled"):
            return False
        
        try:
            import requests
            url = f"https://{splunk['host']}:8088/services/collector"
            headers = {"Authorization": f"Splunk {splunk['hec_token']}"}
            payload = {"event": event, "time": time.time()}
            
            response = requests.post(url, json=payload, headers=headers, 
                                  verify=splunk.get("verify_ssl", True), timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"Splunk error: {e}")
            return False
    
    def send_to_elk(self, event: dict) -> bool:
        """Envía evento a Elasticsearch/Logstash."""
        elk = self.config.get("elk", {})
        if not elk.get("enabled"):
            return False
        
        try:
            import requests
            url = f"{elk['url']}/{elk['index']}/_doc"
            payload = {"@timestamp": datetime.now().isoformat(), **event}
            
            response = requests.post(url, json=payload, timeout=10)
            return response.status_code in [200, 201]
        except Exception as e:
            print(f"ELK error: {e}")
            return False
    
    def send_to_syslog(self, event: dict, severity: int = 6) -> bool:
        """Envía evento via syslog."""
        import socket
        syslog_config = self.config.get("syslog", {})
        if not syslog_config.get("enabled"):
            return False
        
        try:
            message = json.dumps(event)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # RFC 5424 format simplificado
            syslog_msg = f"<{severity}>1 {datetime.now().isoformat()} security-enforcer - - - {message}"
            sock.sendto(syslog_msg.encode(), (syslog_config.get("host", "localhost"), 
                                              int(syslog_config.get("port", 514))))
            sock.close()
            return True
        except Exception as e:
            print(f"Syslog error: {e}")
            return False
    
    def broadcast_event(self, event: dict):
        """Envía evento a todos los SIEMs configurados."""
        self.send_to_splunk(event)
        self.send_to_elk(event)
        self.send_to_syslog(event)


# ==================== CONTAINER SECURITY ====================

class ContainerSecurity:
    """Monitoreo de seguridad de contenedores."""
    
    def __init__(self, config: dict):
        self.config = config
    
    def check_docker(self) -> list:
        """Verifica seguridad de Docker."""
        issues = []
        
        try:
            # Containers sin privileged
            result = os.popen("docker ps --format '{{.Names}}'").read()
            containers = result.strip().split("\n")
            
            for container in containers:
                if not container:
                    continue
                
                # Check if privileged
                inspect = os.popen(f"docker inspect --format '{{.HostConfig.Privileged}}' {container}").read()
                if "true" in inspect.lower():
                    issues.append({
                        "type": "privileged_container",
                        "container": container,
                        "severity": "critical",
                        "message": f"Container {container} está ejecutándose en modo privilegiado"
                    })
                
                # Check for caps
                caps = os.popen(f"docker inspect --format '{{.HostConfig.CapAdd}}' {container}").read()
                if "NET_ADMIN" in caps or "SYS_ADMIN" in caps:
                    issues.append({
                        "type": "dangerous_capability",
                        "container": container,
                        "severity": "high",
                        "message": f"Container {container} tiene capacidades peligrosas: {caps}"
                    })
                
        except Exception as e:
            print(f"Docker check error: {e}")
        
        return issues
    
    def check_kubernetes(self) -> list:
        """Verifica seguridad de Kubernetes."""
        issues = []
        
        try:
            # Check pods privilegiados
            result = os.popen("kubectl get pods -o json").read()
            import json
            pods = json.loads(result).get("items", [])
            
            for pod in pods:
                spec = pod.get("spec", {})
                for container in spec.get("containers", []):
                    security = container.get("securityContext", {})
                    
                    if security.get("privileged"):
                        issues.append({
                            "type": "privileged_pod",
                            "namespace": pod.get("metadata", {}).get("namespace"),
                            "pod": pod.get("metadata", {}).get("name"),
                            "severity": "critical"
                        })
                    
                    # Check capabilities
                    caps = security.get("capabilities", {}).get("add", [])
                    dangerous = ["SYS_ADMIN", "NET_ADMIN", "SYS_MODULE"]
                    if any(c in caps for c in dangerous):
                        issues.append({
                            "type": "dangerous_capabilities",
                            "pod": pod.get("metadata", {}).get("name"),
                            "capabilities": caps,
                            "severity": "high"
                        })
                        
        except Exception as e:
            print(f"K8s check error: {e}")
        
        return issues
    
    def run_checks(self) -> list:
        """Ejecuta todas las verificaciones."""
        all_issues = []
        all_issues.extend(self.check_docker())
        all_issues.extend(self.check_kubernetes())
        return all_issues


# ==================== FILE INTEGRITY MONITOR ====================

class FileIntegrityMonitor:
    """Monitoreo de integridad de archivos."""
    
    def __init__(self, config: dict):
        self.config = config
        self.watch_paths = config.get("fim_paths", [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/var/www/html",
            "/home"
        ])
        self.baseline_file = ".fim_baseline.json"
        self.load_baseline()
    
    def load_baseline(self):
        """Carga baseline de hashes."""
        if os.path.exists(self.baseline_file):
            with open(self.baseline_file) as f:
                self.baseline = json.load(f)
        else:
            self.baseline = {}
    
    def calculate_hash(self, filepath: str) -> str:
        """Calcula hash SHA256 de un archivo."""
        try:
            import hashlib
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return None
    
    def generate_baseline(self):
        """Genera nuevo baseline."""
        for path in self.watch_paths:
            if os.path.isfile(path):
                self.baseline[path] = self.calculate_hash(path)
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        self.baseline[filepath] = self.calculate_hash(filepath)
        
        with open(self.baseline_file, "w") as f:
            json.dump(self.baseline, f)
        
        print(f"✓ Baseline generado: {len(self.baseline)} archivos")
    
    def check_integrity(self) -> list:
        """Verifica integridad de archivos."""
        changes = []
        
        for path, old_hash in self.baseline.items():
            if not os.path.exists(path):
                changes.append({
                    "type": "deleted",
                    "path": path,
                    "severity": "critical"
                })
                continue
            
            current_hash = self.calculate_hash(path)
            if current_hash != old_hash:
                changes.append({
                    "type": "modified",
                    "path": path,
                    "old_hash": old_hash[:16] + "...",
                    "new_hash": current_hash[:16] + "..." if current_hash else "N/A",
                    "severity": "high"
                })
        
        # Nuevos archivos
        for path in self.watch_paths:
            if os.path.isfile(path) and path not in self.baseline:
                changes.append({
                    "type": "created",
                    "path": path,
                    "severity": "medium"
                })
        
        return changes


# ==================== MAIN ORCHESTRATOR ====================

class SecurityOrchestrator:
    """Orquestador central de todos los módulos."""
    
    def __init__(self):
        self.load_config()
        self.api_server = None
        self.scheduler = None
        self.reporter = ReportGenerator()
        self.siem = SIEMIntegrator(self.config)
        self.container = ContainerSecurity(self.config)
        self.fim = FileIntegrityMonitor(self.config)
    
    def load_config(self):
        """Carga configuración."""
        default = {
            "api_server": {"enabled": False, "port": 8080},
            "scheduler": {"enabled": False, "interval_minutes": 60},
            "splunk": {"enabled": False},
            "elk": {"enabled": False},
            "syslog": {"enabled": False},
            "fim_paths": ["/etc/passwd", "/etc/shadow"]
        }
        
        if os.path.exists("config.json"):
            with open("config.json") as f:
                user = json.load(f)
                default.update(user)
        
        self.config = default
    
    def start_api_server(self):
        """Inicia servidor API."""
        if self.config.get("api_server", {}).get("enabled"):
            self.api_server = APIServer(
                port=self.config["api_server"].get("port", 8080)
            )
            self.api_server.start()
    
    def start_scheduler(self):
        """Inicia scheduler."""
        if self.config.get("scheduler", {}).get("enabled"):
            self.scheduler = Scheduler(self.config)
            self.scheduler.start()
    
    def run_all_checks(self):
        """Ejecuta todas las verificaciones."""
        print("\n" + "="*60)
        print("🔍 ORQUESTADOR DE SEGURIDAD - EJECUCIÓN COMPLETA")
        print("="*60)
        
        # 1. Enforcer principal
        print("\n[1/5] Ejecutando Enforcer principal...")
        import subprocess
        subprocess.run(["python3", "enforcer.py"], timeout=120)
        
        # 2. Container Security
        print("\n[2/5] Verificando contenedores...")
        container_issues = self.container.run_checks()
        if container_issues:
            print(f"   ⚠️ {len(container_issues)} problemas encontrados")
            for issue in container_issues:
                print(f"   - {issue.get('message', issue.get('type'))}")
        
        # 3. File Integrity
        print("\n[3/5] Verificando integridad de archivos...")
        fim_changes = self.fim.check_integrity()
        if fim_changes:
            print(f"   ⚠️ {len(fim_changes)} cambios detectados")
        
        # 4. Generar reporte
        print("\n[4/5] Generando reportes...")
        try:
            with open(".enforcer_state.json") as f:
                state = json.load(f)
            html_report = self.reporter.generate_html_report(state)
            json_report = self.reporter.generate_json_report(state)
            print(f"   ✓ HTML: {html_report}")
            print(f"   ✓ JSON: {json_report}")
        except Exception as e:
            print(f"   Error generando reportes: {e}")
        
        # 5. SIEM broadcast
        print("\n[5/5] Enviando a SIEMs...")
        try:
            with open(".enforcer_state.json") as f:
                state = json.load(f)
            self.siem.broadcast_event({
                "source": "security_enforcer",
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "cves": len(state.get("cves", [])),
                    "attacks": len(state.get("attacks", [])),
                    "rules": len(state.get("rules", []))
                }
            })
            print("   ✓ Evento enviado")
        except Exception as e:
            print(f"   Error: {e}")
        
        print("\n" + "="*60)
        print("✅ EJECUCIÓN COMPLETA")
        print("="*60)
    
    def run(self):
        """Ejecuta el orquestador."""
        print("""
╔══════════════════════════════════════════════════════════════════╗
║          🛡️ SECURITY ENFORCER - ORQUESTADOR COMPLETO             ║
║                                                                  ║
║  Modulos disponibles:                                           ║
║  • Enforcer principal (CVEs, ataques, firewall)                ║
║  • Threat Intelligence (ThreatFox, URLHaus, etc)               ║
║  • Container Security (Docker, Kubernetes)                      ║
║  • File Integrity Monitor                                       ║
║  • SIEM Integration (Splunk, ELK, Syslog)                       ║
║  • Reportes (HTML, JSON)                                        ║
║  • API REST (opcional)                                          ║
║  • Scheduler (opcional)                                         ║
╚══════════════════════════════════════════════════════════════════╝
        """)
        
        self.start_api_server()
        self.start_scheduler()
        
        if self.config.get("run_orchestrator", True):
            self.run_all_checks()


if __name__ == "__main__":
    orchestrator = SecurityOrchestrator()
    orchestrator.run()
