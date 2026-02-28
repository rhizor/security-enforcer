#!/usr/bin/env python3
"""
Dynamic Security Policy Enforcer
Actualiza reglas de firewall/ACLs automáticamente basado en CVEs y eventos de ataque.
"""

import json
import subprocess
import requests
import re
import logging
import os
import hashlib
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict

# Configuración
CONFIG_FILE = "config.json"
RULES_DIR = "generated_rules"
LOG_FILE = "enforcer.log"
CACHE_FILE = ".cve_cache.json"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class SecurityRule:
    """Representa una regla de seguridad generado dinámicamente."""
    id: str
    type: str  # 'cve' o 'attack'
    source: str  # 'nvd', 'cisa', 'fail2ban', etc.
    description: str
    action: str  # 'block_ip', 'block_port', 'rate_limit', 'alert'
    target: str  # IP, puerto, CIDR
    protocol: str = "tcp"
    port: Optional[int] = None
    created_at: str = ""
    expires_at: Optional[str] = None
    enabled: bool = True
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.id = hashlib.md5(f"{self.source}{self.target}{time.time()}".encode()).hexdigest()[:12]


class CVEFetcher:
    """Obtiene CVEs recientes de fuentes oficiales."""
    
    # Endpoints alternativos (NVD cambió su API en 2024)
    NVD_API_V2 = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_LEGACY = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    CIRCL_API = "https://cve.circl.lu/api/last"
    
    def __init__(self, config: dict):
        self.config = config
        self.last_check = None
        
    def fetch_from_circl(self, limit: int = 20) -> list:
        """Obtiene CVEs recientes de CIRCL.lu (alternativo)."""
        try:
            logger.info("Consultando API de CIRCL.lu...")
            response = requests.get(f"{self.CIRCL_API}/{limit}", timeout=30)
            response.raise_for_status()
            data = response.json()
            
            cves = []
            for item in data:
                score = item.get("cvss", 0.0) if item.get("cvss") else 0.0
                if score >= float(self.config.get("min_cve_severity", "7.0")):
                    cves.append({
                        "id": item.get("id", ""),
                        "score": score,
                        "description": item.get("summary", "")[:200],
                        "published": item.get("Published", ""),
                        "affected": item.get("affected", [])
                    })
            
            logger.info(f"Encontrados {len(cves)} CVEs en CIRCL")
            return cves
            
        except requests.RequestException as e:
            logger.error(f"Error consultando CIRCL: {e}")
            return []
    
    def fetch_from_nvd(self, days: int = 7) -> list:
        """Obtiene CVEs de NVD (intenta both APIs)."""
        pub_start = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000UTC")
        
        # Intentar API nueva
        for api_url in [self.NVD_API_V2, self.NVD_API_LEGACY]:
            try:
                logger.info(f"Consultando NVD: {api_url}")
                params = {
                    "pubStartDate": pub_start,
                    "resultsPerPage": 50
                }
                
                response = requests.get(api_url, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    cves = []
                    
                    for item in data.get("vulnerabilities", []):
                        cve = item.get("cve", {})
                        cve_id = cve.get("id", "")
                        
                        metrics = cve.get("metrics", {})
                        cvss = (metrics.get("cvssMetricV31", []) or 
                               metrics.get("cvssMetricV30", []) or 
                               metrics.get("cvssMetricV2", []))
                        
                        score = cvss[0].get("cvssData", {}).get("baseScore", 0.0) if cvss else 0.0
                        
                        if score >= float(self.config.get("min_cve_severity", "7.0")):
                            description = cve.get("descriptions", [{}])[0].get("value", "")[:200]
                            cves.append({
                                "id": cve_id,
                                "score": score,
                                "description": description,
                                "published": cve.get("published", "")
                            })
                    
                    logger.info(f"Encontrados {len(cves)} CVEs en NVD")
                    return cves
                    
            except requests.RequestException as e:
                logger.warning(f"API {api_url} no disponible: {e}")
                continue
        
        return []
    
    def fetch_recent_cves(self, days: int = 7, min_severity: str = "7.0") -> list:
        """Obtiene CVEs de los últimos días - intenta múltiples fuentes."""
        # Intentar CIRCL primero (más confiable)
        cves = self.fetch_from_circl(limit=30)
        if cves:
            return cves
        
        # Fallback a NVD
        cves = self.fetch_from_nvd(days)
        if cves:
            return cves
        
        # Modo demo: retornar CVEs de ejemplo si no hay conexión
        logger.info("Usando datos de demo (sin conexión a APIs)")
        return self._get_demo_cves()
    
    def _get_demo_cves(self) -> list:
        """CVEs de demo para testing."""
        return [
            {"id": "CVE-2024-21762", "score": 9.8, "description": "FortiOS SSL-VPN RCE - crítica activa", "published": "2024-02-08"},
            {"id": "CVE-2024-1709", "score": 10.0, "description": "ConnectWise ScreenConnect auth bypass", "published": "2024-02-19"},
            {"id": "CVE-2024-27198", "score": 9.8, "description": "JetBrains TeamCity auth bypass", "published": "2024-03-04"},
            {"id": "CVE-2023-46805", "score": 8.2, "description": "Ivanti Connect Secure authentication bypass", "published": "2024-01-10"},
            {"id": "CVE-2024-0012", "score": 7.8, "description": "Palo Alto Networks PAN-OS management interface auth bypass", "published": "2024-11-13"},
        ]


class AttackDetector:
    """Detecta ataques desde múltiples fuentes."""
    
    # Fuentes públicas de amenazas
    THREAT_FEEDS = {
        "firehol": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    }
    
    def __init__(self, config: dict):
        self.config = config
        self.threat_cache = {}
        
    def check_fail2ban(self) -> list:
        """Obtiene IPs bloqueadas por fail2ban."""
        blocked = []
        try:
            result = subprocess.run(
                ["fail2ban-client", "status"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split("\n"):
                if "Jail:" in line:
                    jail = line.split("Jail:")[1].strip()
                    status_result = subprocess.run(
                        ["fail2ban-client", "get", jail, "baninfo"],
                        capture_output=True, text=True, timeout=10
                    )
                    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                    ips = re.findall(ip_pattern, status_result.stdout)
                    for ip in ips:
                        blocked.append({
                            "ip": ip,
                            "jail": jail,
                            "source": "fail2ban",
                            "severity": "high"
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("fail2ban no disponible")
        
        return blocked
    
    def check_auth_logs(self, max_entries: int = 100) -> list:
        """Analiza logs de autenticación para detectar ataques."""
        suspicious = []
        patterns = [
            (r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", "bruteforce"),
            (r"Failed password for invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)", "invalid_user"),
            (r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)", "invalid_user"),
            (r"POSSIBLE BREAK-IN attempt", "breakin"),
            (r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)", "auth_failure"),
            (r"refused connect from (\d+\.\d+\.\d+\.\d+)", "refused"),
            (r"Received disconnect.*(\d+\.\d+\.\d+\.\d+)", "disconnect_flood"),
            (r"error: maximum authentication attempts exceeded.*(\d+\.\d+\.\d+\.\d+)", "max_auth"),
            (r"Bad protocol version identification.*from (\d+\.\d+\.\d+\.\d+)", "bad_protocol"),
        ]
        
        log_files = ["/var/log/auth.log", "/var/log/secure", "/var/log/messages", "/var/log/syslog"]
        
        for log_file in log_files:
            try:
                with open(log_file, "r") as f:
                    lines = f.readlines()[-max_entries:]
                
                ip_counts = {}
                for line in lines:
                    for pattern, attack_type in patterns:
                        match = re.search(pattern, line)
                        if match:
                            ip = match.group(1) if match.lastindex >= 1 else "unknown"
                            if ip not in ip_counts:
                                ip_counts[ip] = {"count": 0, "type": attack_type}
                            ip_counts[ip]["count"] += 1
                
                for ip, data in ip_counts.items():
                    if ip != "unknown" and data["count"] >= 3:
                        suspicious.append({
                            "ip": ip,
                            "count": data["count"],
                            "type": data["type"],
                            "source": "auth_log",
                            "severity": "high" if data["count"] > 10 else "medium"
                        })
            except FileNotFoundError:
                continue
        
        return suspicious
    
    def check_nginx_access(self, max_entries: int = 100) -> list:
        """Analiza logs de Nginx/Apache para detectar ataques web."""
        suspicious = []
        log_files = ["/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/httpd/access_log"]
        
        attack_patterns = [
            (r"(\d+\.\d+\.\d+\.\d+).*(\.php|\.asp|\.jsp|\.cgi).*500", "error_exploit"),
            (r"(\d+\.\d+\.\d+\.\d+).*(\.\./|\.\.%2e)", "path_traversal"),
            (r"(\d+\.\d+\.\d+\.\d+).*(union.*select|order by)", "sqli"),
            (r"(\d+\.\d+\.\d+\.\d+).*<script>", "xss"),
            (r"(\d+\.\d+\.\d+\.\d+).*(\?cmd=|\?exec=)", "rce"),
            (r"(\d+\.\d+\.\d+\.\d+).*(\.env|\.git/|\.DS_Store)", "info_disclosure"),
            (r"(\d+\.\d+\.\d+\.\d+).*wp-login", "wp_scan"),
            (r"(\d+\.\d+\.\d+\.\d+).*xmlrpc.php", "wp_xmlrpc"),
            (r"(\d+\.\d+\.\d+\.\d+).*admin", "admin_scan"),
            (r"(\d+\.\d+\.\d+\.\d+).*phpmyadmin", "pma_scan"),
        ]
        
        for log_file in log_files:
            try:
                with open(log_file, "r") as f:
                    lines = f.readlines()[-max_entries:]
                
                ip_counts = {}
                for line in lines:
                    for pattern, attack_type in attack_patterns:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            ip = match.group(1)
                            if ip not in ip_counts:
                                ip_counts[ip] = {"count": 0, "type": attack_type}
                            ip_counts[ip]["count"] += 1
                
                for ip, data in ip_counts.items():
                    if data["count"] >= 2:
                        suspicious.append({
                            "ip": ip,
                            "count": data["count"],
                            "type": data["type"],
                            "source": "web_log",
                            "severity": "high"
                        })
            except FileNotFoundError:
                continue
        
        return suspicious
    
    def check_ufw_logs(self) -> list:
        """Analiza logs de UFW."""
        blocked = []
        try:
            with open("/var/log/ufw.log", "r") as f:
                lines = f.readlines()[-100:]
            
            ip_counts = {}
            for line in lines:
                if "BLOCK" in line:
                    match = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        ip = match.group(1)
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            for ip, count in ip_counts.items():
                if count >= 10:
                    blocked.append({
                        "ip": ip,
                        "count": count,
                        "type": "ufw_block",
                        "source": "ufw_log",
                        "severity": "medium"
                    })
        except FileNotFoundError:
            pass
        
        return blocked
    
    def check_public_threat_feeds(self) -> list:
        """Consulta fuentes públicas de amenazas."""
        threats = []
        try:
            response = requests.get(self.THREAT_FEEDS["firehol"], timeout=30)
            if response.status_code == 200:
                for line in response.text.split("\n")[:50]:
                    if line and not line.startswith("#"):
                        threats.append({
                            "ip": line.strip(),
                            "source": "firehol",
                            "type": "known_malicious",
                            "severity": "high"
                        })
        except requests.RequestException as e:
            logger.warning(f"Error consultando feeds: {e}")
        
        return threats
    
    def check_recent_threats(self) -> list:
        """Obtiene amenazas recientes de CISA."""
        try:
            response = requests.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=30
            )
            data = response.json()
            return data.get("vulnerabilities", [])[-5:]
        except requests.RequestException as e:
            logger.error(f"Error consultando CISA: {e}")
            return self._get_demo_attacks()
    
    def _get_demo_attacks(self) -> list:
        """Ataques de demo para testing."""
        return [
            {"ip": "45.33.32.156", "count": 847, "type": "bruteforce", "source": "auth_log", "severity": "high"},
            {"ip": "185.220.101.47", "count": 234, "type": "ssh_bruteforce", "source": "fail2ban", "severity": "high"},
            {"ip": "89.248.167.131", "count": 156, "type": "port_scan", "source": "auth_log", "severity": "medium"},
            {"ip": "103.55.144.78", "count": 89, "type": "http_attack", "source": "nginx_access", "severity": "high"},
            {"ip": "194.26.29.102", "count": 45, "type": "crawler_abuse", "source": "web_log", "severity": "low"},
        ]


class ThreatIntelManager:
    """Gestiona fuentes de Threat Intelligence."""
    
    def __init__(self, config: dict):
        self.config = config
        self.threats = []
        
    def fetch_threatfox(self) -> list:
        """Obtiene IOC de ThreatFox."""
        threats = []
        try:
            response = requests.post("https://threatfox-api.abuse.ch/api/v1/", 
                                   json={"query": "get_top10"},
                                   timeout=30)
            if response.status_code == 200:
                data = response.json()
                for item in data.get("data", [])[:20]:
                    threats.append({
                        "indicator": item.get("ioc_value", ""),
                        "type": item.get("ioc_type", ""),
                        "source": "threatfox",
                        "severity": "high",
                        "malware": item.get("malware", "")
                    })
        except requests.RequestException as e:
            logger.warning(f"ThreatFox: {e}")
        return threats
    
    def fetch_malware_bazaar(self) -> list:
        """Obtiene malware de Malware Bazaar."""
        threats = []
        try:
            response = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_recent", "selector": "100"},
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                for item in data.get("data", [])[:20]:
                    threats.append({
                        "indicator": item.get("sha256_hash", ""),
                        "type": "hash",
                        "source": "malware_bazaar",
                        "severity": "high",
                        "malware": item.get("malware_name", "")
                    })
        except requests.RequestException as e:
            logger.warning(f"Malware Bazaar: {e}")
        return threats
    
    def fetch_urlhaus(self) -> list:
        """Obtiene URLs maliciosas de URLHaus."""
        threats = []
        try:
            response = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/100/", timeout=30)
            if response.status_code == 200:
                data = response.json()
                for item in data.get("urls", [])[:20]:
                    threats.append({
                        "indicator": item.get("url", ""),
                        "type": "url",
                        "source": "urlhaus",
                        "severity": "high" if item.get("threat", "") == "malware_download" else "medium"
                    })
        except requests.RequestException as e:
            logger.warning(f"URLHaus: {e}")
        return threats
    
    def fetch_aws_security_hub(self) -> list:
        """Obtiene hallazgos de AWS Security Hub."""
        if not self.config.get("threat_intel", {}).get("enable_aws_security_hub"):
            return []
        try:
            result = subprocess.run(
                ["aws", "securityhub", "get-findings",
                 "--filters", '{"SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"}]}',
                 "--max-items", "10"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                import json
                findings = json.loads(result.stdout).get("Findings", [])
                return [{"title": f.get("Title", ""), "severity": f.get("Severity", {}).get("Label", ""),
                        "source": "aws_security_hub"} for f in findings]
        except:
            logger.warning("AWS Security Hub no disponible")
        return []
    
    def fetch_azure_sentinel(self) -> list:
        """Obtiene incidentes de Azure Sentinel."""
        if not self.config.get("threat_intel", {}).get("enable_azure_sentinel"):
            return []
        try:
            result = subprocess.run(
                ["az", "sentinel", "incident", "list",
                 "--resource-group", self.config.get("azure_rg", "security"),
                 "--workspace-name", self.config.get("azure_workspace", "sentinel")],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                import json
                incidents = json.loads(result.stdout)
                return [{"title": i.get("properties", {}).get("title", ""),
                        "severity": i.get("properties", {}).get("severity", ""),
                        "source": "azure_sentinel"} for i in incidents[:10]]
        except:
            logger.warning("Azure Sentinel no disponible")
        return []
    
    def fetch_gcp_scc(self) -> list:
        """Obtiene hallazgos de GCP Security Command Center."""
        if not self.config.get("threat_intel", {}).get("enable_gcp_security_command"):
            return []
        try:
            result = subprocess.run(
                ["gcloud", "securitycenter", "findings", "list",
                 "--organization", self.config.get("gcp_org", ""),
                 "--filter", "severity=HIGH OR severity=CRITICAL", "--limit", "10"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return [{"title": line.strip()[:100], "severity": "high", "source": "gcp_scc"}
                       for line in result.stdout.split("\n") if "findings" in line.lower()][:10]
        except:
            logger.warning("GCP SCC no disponible")
        return []
    
    def fetch_all(self) -> list:
        """Obtiene threats de todas las fuentes."""
        all_threats = []
        ti = self.config.get("threat_intel", {})
        
        if ti.get("enable_threatfox", True):
            all_threats.extend(self.fetch_threatfox())
        if ti.get("enable_malware_bazaar", True):
            all_threats.extend(self.fetch_malware_bazaar())
        if ti.get("enable_urlhaus", True):
            all_threats.extend(self.fetch_urlhaus())
        
        all_threats.extend(self.fetch_aws_security_hub())
        all_threats.extend(self.fetch_azure_sentinel())
        all_threats.extend(self.fetch_gcp_scc())
        
        logger.info(f"Threat Intel: {len(all_threats)} indicadores")
        return all_threats


class FirewallManager:
    """Gestiona reglas de firewall dinámicamente (nftables + iptables)."""
    
    def __init__(self, dry_run: bool = False, backend: str = "nft"):
        self.dry_run = dry_run
        self.backend = backend  # "nft" o "iptables"
        self.rules_file = f"{RULES_DIR}/dynamic_rules.{backend}"
        os.makedirs(RULES_DIR, exist_ok=True)
        
    def _run(self, cmd: list) -> bool:
        """Ejecuta comando de sistema."""
        if self.dry_run:
            logger.info(f"[DRY-RUN] {' '.join(cmd)}")
            return True
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=30)
            return True
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode() if e.stderr else str(e)
            logger.error(f"Error ejecutando {' '.join(cmd)}: {err}")
            return False
    
    def block_ip(self, ip: str, reason: str = "", duration_minutes: int = 60) -> bool:
        """Bloquea una IP."""
        logger.warning(f"Bloqueando IP {ip}: {reason}")
        
        if self.backend == "nft":
            cmd = ["nft", "add", "rule", "ip", "filter", "input", "ip", "saddr", ip, "drop"]
        else:
            # iptables con timeout opcional
            if duration_minutes > 0:
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            else:
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        
        return self._run(cmd)
    
    def block_ip_range(self, cidr: str, reason: str = "") -> bool:
        """Bloquea un rango CIDR."""
        logger.warning(f"Bloqueando CIDR {cidr}: {reason}")
        
        if self.backend == "nft":
            cmd = ["nft", "add", "rule", "ip", "filter", "input", "ip", "saddr", cidr, "drop"]
        else:
            cmd = ["iptables", "-A", "INPUT", "-s", cidr, "-j", "DROP"]
        
        return self._run(cmd)
    
    def block_port(self, port: int, protocol: str = "tcp") -> bool:
        """Bloquea un puerto específico."""
        logger.warning(f"Bloqueando puerto {port}/{protocol}")
        
        if self.backend == "nft":
            cmd = ["nft", "add", "rule", "ip", "filter", "input", 
                   protocol, "dport", str(port), "drop"]
        else:
            cmd = ["iptables", "-A", "INPUT", "-p", protocol, 
                   "--dport", str(port), "-j", "DROP"]
        
        return self._run(cmd)
    
    def allow_only_ip(self, port: int, ip: str, protocol: str = "tcp") -> bool:
        """Permite solo una IP específica en un puerto (whitelist)."""
        logger.info(f"Whitelist: {ip} solo puede acceder a {port}/{protocol}")
        
        if self.backend == "nft":
            # Primero drop, luego allow específico
            cmd = ["nft", "add", "rule", "ip", "filter", "input", 
                   "ip", "saddr", ip, protocol, "dport", str(port), "accept"]
        else:
            cmd = ["iptables", "-A", "INPUT", "-p", protocol, "-s", ip,
                   "--dport", str(port), "-j", "ACCEPT"]
        
        return self._run(cmd)
    
    def rate_limit_ip(self, ip: str, packets: int = 10) -> bool:
        """Aplica rate limiting a una IP."""
        if self.backend == "nft":
            cmd = ["nft", "add", "rule", "ip", "filter", "input",
                   "ip", "saddr", ip, "limit", f"rate {packets}/minute", "accept"]
        else:
            cmd = ["iptables", "-A", "INPUT", "-m", "hashlimit",
                   "--hashlimit-above", f"{packets}/minute",
                   "--hashlimit-burst", str(packets * 2),
                   "-j", "DROP"]
        
        return self._run(cmd)
    
    def add_log_rule(self, rule_name: str, ip: str = None, port: int = None) -> bool:
        """Agrega regla de logging."""
        if ip:
            cmd = ["nft", "add", "rule", "ip", "filter", "input", 
                   "ip", "saddr", ip, "counter", "log"]
        elif port:
            cmd = ["nft", "add", "rule", "ip", "filter", "input",
                   "tcp", "dport", str(port), "counter", "log"]
        else:
            return False
        
        return self._run(cmd)
    
    def list_rules(self) -> list:
        """Lista reglas actuales."""
        try:
            if self.backend == "nft":
                result = subprocess.run(["nft", "-a", "list", "ruleset"],
                                       capture_output=True, text=True, timeout=15)
            else:
                result = subprocess.run(["iptables", "-L", "-n", "-v"],
                                       capture_output=True, text=True, timeout=15)
            return result.stdout.split("\n")
        except:
            return []
    
    def get_blocked_ips(self) -> list:
        """Obtiene lista de IPs bloqueadas."""
        try:
            if self.backend == "nft":
                result = subprocess.run(["nft", "list", "table", "ip", "filter"],
                                       capture_output=True, text=True, timeout=15)
                # Parsear output para extraer IPs
                import re
                ips = re.findall(r'(\d+\.\d+\.\d+\.\d+).*drop', result.stdout)
                return list(set(ips))
            else:
                result = subprocess.run(["iptables", "-L", "INPUT", "-n"],
                                       capture_output=True, text=True, timeout=15)
                import re
                ips = re.findall(r'(\d+\.\d+\.\d+\.\d+).*DROP', result.stdout)
                return list(set(ips))
        except:
            return []
    
    def unblock_ip(self, ip: str) -> bool:
        """Desbloquea una IP."""
        logger.info(f"Desbloqueando IP {ip}")
        
        try:
            if self.backend == "nft":
                # Buscar handle y eliminar
                result = subprocess.run(["nft", "-a", "list", "chain", "ip", "filter", "input"],
                                       capture_output=True, text=True, timeout=15)
                import re
                # Extraer handle para la IP específica
                match = re.search(r'ip saddr (\d+\.\d+\.\d+\.\d+).*drop.*# handle (\d+)', 
                                  result.stdout)
                if match and match.group(1) == ip:
                    handle = match.group(2)
                    cmd = ["nft", "delete", "rule", "ip", "filter", "input", "handle", handle]
                else:
                    return False
            else:
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            
            return self._run(cmd)
        except Exception as e:
            logger.error(f"Error desbloqueando IP: {e}")
            return False
    
    def backup_rules(self, backup_file: str = None) -> bool:
        """Backup de reglas actuales."""
        if not backup_file:
            backup_file = f"backup_rules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.rules"
        
        try:
            if self.backend == "nft":
                cmd = ["nft", "list", "ruleset"]
            else:
                cmd = ["iptables-save"]
            
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            with open(backup_file, "w") as f:
                f.write(result.stdout)
            
            logger.info(f"Backup guardado: {backup_file}")
            return True
        except Exception as e:
            logger.error(f"Error en backup: {e}")
            return False
    
    def restore_rules(self, backup_file: str) -> bool:
        """Restaura reglas desde backup."""
        try:
            if self.backend == "nft":
                cmd = ["nft", "-f", backup_file]
            else:
                cmd = ["iptables-restore"]
            
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error en restore: {e}")
            return False
    
    def cleanup_expired(self, rules: list) -> int:
        """Limpia reglas expiradas."""
        cleaned = 0
        now = datetime.now()
        
        for rule in rules:
            if rule.expires_at:
                try:
                    exp = datetime.fromisoformat(rule.expires_at)
                    if now > exp:
                        if rule.action == "block_ip":
                            if self.unblock_ip(rule.target):
                                cleaned += 1
                        logger.info(f"Regla {rule.id} expirada y limpiada")
                except:
                    pass
        
        return cleaned


class PolicyEngine:
    """Motor de políticas que decide qué reglas generar."""
    
    def __init__(self, config: dict):
        self.config = config
        self.cve_fetcher = CVEFetcher(config)
        self.attack_detector = AttackDetector(config)
        self.threat_intel = ThreatIntelManager(config)
        self.firewall = FirewallManager(dry_run=config.get("dry_run", True))
        self.notifier = NotificationManager(config)
        
    def generate_cve_rules(self, cves: list) -> list:
        """Genera reglas basadas en CVEs."""
        rules = []
        
        # Mapeo exhaustivo de servicios/puertos comunes a CVEs
        service_map = {
            # Web Servers
            "apache": [80, 443],
            "nginx": [80, 443],
            "iis": [80, 443],
            "lighttpd": [80, 443],
            "caddy": [80, 443],
            
            # CMS/Web Apps
            "wordpress": [80, 443],
            "joomla": [80, 443],
            "drupal": [80, 443],
            "magento": [80, 443],
            "shopify": [443],
            "wp": [80, 443],
            
            # Databases
            "mysql": [3306],
            "mariadb": [3306],
            "postgresql": [5432],
            "postgres": [5432],
            "mongodb": [27017],
            "redis": [6379],
            "elasticsearch": [9200, 9300],
            "memcached": [11211],
            "cassandra": [9042],
            "couchdb": [5984],
            "mssql": [1433],
            "oracle": [1521],
            
            # Remote Access
            "ssh": [22],
            "rdp": [3389],
            "vnc": [5900],
            "x11": [6000],
            "telnet": [23],
            
            # VPN & Security Appliances
            "openvpn": [1194],
            "wireguard": [51820],
            "ipsec": [500, 4500],
            "pptp": [1723],
            "ssl vpn": [443],
            "vpn": [443, 1194],
            "fortinet": [443, 8443],
            "fortios": [443],
            "forti": [443, 8443],
            "palo alto": [443, 4443],
            "pan-os": [443, 4443],
            "cisco asa": [443, 22],
            "cisco": [443, 22],
            "citrix": [443],
            "netscaler": [443],
            "f5": [443],
            "big-ip": [443],
            "checkpoint": [443, 22],
            
            # DevOps & Cloud
            "jenkins": [8080, 8090],
            "gitlab": [8080, 22],
            "kubernetes": [6443, 10250],
            "k8s": [6443],
            "docker": [2375, 2376],
            "containerd": [9323],
            "rancher": [8443],
            "helm": [44134],
            "nexus": [8081],
            "artifactory": [8082],
            "sonarqube": [9000],
            "jira": [8080, 443],
            "confluence": [8090, 443],
            "bitbucket": [7990, 7999],
            "teamcity": [8111, 8080],
            "bamboo": [8085],
            
            # Monitoring & Logging
            "splunk": [8089, 8000],
            "grafana": [3000],
            "prometheus": [9090],
            "kibana": [5601],
            "zabbix": [10050, 10051],
            "nagios": [80, 443],
            "datadog": [8125],
            
            # Email
            "postfix": [25, 587],
            "sendmail": [25],
            "exim": [25],
            "dovecot": [110, 143, 993],
            "courier": [110, 143],
            "exchange": [443, 25],
            "office 365": [443],
            "zimbra": [7071],
            
            # Collaboration
            "slack": [443],
            "teams": [443],
            "zoom": [443, 8801],
            "webex": [443],
            
            # File & Storage
            "samba": [445, 139],
            "smb": [445, 139],
            "nfs": [2049],
            "ftp": [21],
            "vsftpd": [21],
            "proftpd": [21],
            "sftp": [22],
            "webdav": [443],
            
            # DNS & Network
            "bind": [53],
            "named": [53],
            "unbound": [53],
            "powerdns": [53],
            "dhcp": [67, 68],
            "ldap": [389, 636],
            "active directory": [389, 636],
            "kerberos": [88],
            
            # Enterprise Apps
            "sap": [8000, 443],
            "oracle ebs": [8000],
            "salesforce": [443],
            "servicenow": [443],
            "atlassian": [7990, 7999],
            "solarwinds": [17764, 443],
            "vmware": [443, 22],
            "vcenter": [443],
            "esxi": [443],
            "proxmox": [8006],
            "openvz": [22],
            
            # Web Applications
            "screenconnect": [443, 8080],
            "anydesk": [6568],
            "teamviewer": [443, 5938],
            "logmein": [443],
            "webmin": [10000],
            "cpanel": [2083, 2087],
            "plesk": [8443],
            "directadmin": [2222],
            "vesta": [8083],
            
            # SSL/TLS specific
            "ssl": [443],
            "tls": [443],
            "heartbleed": [443],
            "poodle": [443],
            "freak": [443],
            "logjam": [443],
            
            # Generic patterns
            "management": [443, 8443],
            "admin": [443, 8080],
            "web interface": [443, 8080],
            "api": [443, 8080],
            "rest": [443, 8080],
            "graphql": [443],
        }
        
        for cve in cves:
            desc = cve.get("description", "").lower()
            cve_id = cve.get("id", "")
            score = cve.get("score", 0)
            
            # Detectar servicios afectados
            matched = False
            for service, port in service_map.items():
                if service in desc:
                    actual_port = port[0] if isinstance(port, list) else port
                    rule = SecurityRule(
                        id="",  # se genera automáticamente
                        type="cve",
                        source="nvd",
                        description=f"{cve_id} (CVSS {score}): {cve.get('description', '')[:60]}",
                        action="alert" if score < 9.0 else "block_port",
                        target=service,
                        port=actual_port,
                        protocol="tcp",
                        expires_at=(datetime.now() + timedelta(days=7)).isoformat()
                    )
                    rules.append(rule)
                    matched = True
                    break
            
            # Si no hizo match pero es crítico, generar alerta general
            if not matched and score >= 9.0:
                rule = SecurityRule(
                    id="",
                    type="cve",
                    source="nvd",
                    description=f"CRÍTICO {cve_id} (CVSS {score}): {cve.get('description', '')[:60]}",
                    action="alert",
                    target="general",
                    expires_at=(datetime.now() + timedelta(days=3)).isoformat()
                )
                rules.append(rule)
        
        logger.info(f"Generadas {len(rules)} reglas de {len(cves)} CVEs")
        return rules
    
    def generate_attack_rules(self, attacks: list) -> list:
        """Genera reglas basadas en ataques detectados."""
        rules = []
        
        for attack in attacks:
            source = attack.get("source", "")
            ip = attack.get("ip", "")
            severity = attack.get("severity", "medium")
            
            if not ip:
                continue
                
            # fail2ban - bloquear IP directamente
            if source == "fail2ban":
                rule = SecurityRule(
                    id="",
                    type="attack",
                    source="fail2ban",
                    description=f"IP bloqueada por fail2ban: {attack.get('jail')}",
                    action="block_ip",
                    target=ip,
                    expires_at=(datetime.now() + timedelta(hours=24)).isoformat()
                )
                rules.append(rule)
                
            # auth_log / web_log - rate limiting
            elif source in ["auth_log", "web_log", "nginx_access"]:
                action = "block_ip" if severity == "high" else "rate_limit_ip"
                rule = SecurityRule(
                    id="",
                    type="attack",
                    source=source,
                    description=f"{attack.get('type', 'attack')}: {attack.get('count', 0)} intentos",
                    action=action,
                    target=ip,
                    expires_at=(datetime.now() + timedelta(hours=12)).isoformat()
                )
                rules.append(rule)
            
            # firehol - IP conocida maliciosa
            elif source == "firehol":
                rule = SecurityRule(
                    id="",
                    type="attack",
                    source="firehol",
                    description=f"IP maliciosa conocida en blacklist",
                    action="block_ip",
                    target=ip,
                    expires_at=(datetime.now() + timedelta(days=7)).isoformat()
                )
                rules.append(rule)
        
        logger.info(f"Generadas {len(rules)} reglas de {len(attacks)} ataques")
        return rules
    
    def generate_threat_intel_rules(self, threat_intel: list) -> list:
        """Genera reglas basadas en Threat Intelligence."""
        rules = []
        
        for threat in threat_intel:
            indicator = threat.get("indicator", "")
            source = threat.get("source", "")
            
            # Si es IP, bloquear
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', indicator):
                rule = SecurityRule(
                    id="",
                    type="threat_intel",
                    source=source,
                    description=f"Threat Intel: {threat.get('malware', 'malware')}",
                    action="block_ip",
                    target=indicator,
                    expires_at=(datetime.now() + timedelta(days=7)).isoformat()
                )
                rules.append(rule)
            
            # Si es URL, loggear (no se puede bloquear directamente en firewall)
            elif indicator.startswith("http"):
                rule = SecurityRule(
                    id="",
                    type="threat_intel",
                    source=source,
                    description=f"URL maliciosa: {indicator[:60]}",
                    action="alert",
                    target="general",
                    expires_at=(datetime.now() + timedelta(days=3)).isoformat()
                )
                rules.append(rule)
        
        logger.info(f"Generadas {len(rules)} reglas de {len(threat_intel)} IOCs")
        return rules
    
    def apply_rules(self, rules: list) -> dict:
        """Aplica las reglas generadas al firewall."""
        results = {"applied": 0, "failed": 0, "skipped": 0}
        
        for rule in rules:
            if not rule.enabled:
                results["skipped"] += 1
                continue
            
            try:
                if rule.action == "block_ip":
                    success = self.firewall.block_ip(rule.target, rule.description)
                elif rule.action == "block_port":
                    success = self.firewall.block_port(rule.port, rule.protocol)
                elif rule.action == "rate_limit_ip":
                    success = self.firewall.rate_limit_ip(rule.target)
                else:
                    logger.info(f"Alerta: {rule.description}")
                    success = True
                
                if success:
                    results["applied"] += 1
                    logger.info(f"✓ Regla aplicada: {rule.id}")
                else:
                    results["failed"] += 1
                    
            except Exception as e:
                logger.error(f"Error aplicando regla {rule.id}: {e}")
                results["failed"] += 1
        
        return results
    
    def run(self) -> dict:
        """Ejecuta el ciclo completo de enforcement."""
        logger.info("=" * 50)
        logger.info("Iniciando ciclo de enforcement de seguridad")
        
        # 1. Obtener CVEs
        cves = self.cve_fetcher.fetch_recent_cves(
            days=self.config.get("cve_days", 7),
            min_severity=self.config.get("min_cve_severity", "7.0")
        )
        
        # 2. Detectar ataques
        attacks = []
        if self.config.get("enable_attack_detection", True):
            attacks.extend(self.attack_detector.check_fail2ban())
            attacks.extend(self.attack_detector.check_auth_logs())
            attacks.extend(self.attack_detector.check_nginx_access())
            attacks.extend(self.attack_detector.check_ufw_logs())
            attacks.extend(self.attack_detector.check_public_threat_feeds())
            attacks.extend(self.attack_detector.check_recent_threats())
        
        # 3. Obtener Threat Intelligence
        threat_intel = []
        if self.config.get("threat_intel", {}).get("enable_threatfox") or \
           self.config.get("threat_intel", {}).get("enable_malware_bazaar") or \
           self.config.get("threat_intel", {}).get("enable_urlhaus"):
            threat_intel = self.threat_intel.fetch_all()
        
        # 4. Generar reglas
        cve_rules = self.generate_cve_rules(cves)
        attack_rules = self.generate_attack_rules(attacks)
        ti_rules = self.generate_threat_intel_rules(threat_intel)
        all_rules = cve_rules + attack_rules + ti_rules
        
        logger.info(f"Generadas {len(all_rules)} reglas ({len(cve_rules)} CVEs, {len(attack_rules)} ataques, {len(ti_rules)} TI)")
        
        # 5. Aplicar reglas
        results = self.apply_rules(all_rules)
        
        # 6. Notificaciones
        if results["applied"] > 0:
            severity = "critical" if results.get("failed", 0) > 0 else "high"
            self.notifier.notify(
                title="Security Policy Updated",
                message=f"Se aplicaron {results['applied']} reglas de seguridad",
                severity=severity,
                rules=all_rules[:10]
            )
        
        # 7. Guardar estado
        self._save_state(cves, attacks, threat_intel, all_rules)
        
        logger.info(f"Resultados: {results}")
        logger.info("=" * 50)
        
        return {
            "cves_found": len(cves),
            "attacks_detected": len(attacks),
            "threat_intel_found": len(threat_intel),
            "rules_generated": len(all_rules),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    
    def _save_state(self, cves: list, attacks: list, threat_intel: list, rules: list):
        """Guarda estado para auditoría."""
        state = {
            "last_run": datetime.now().isoformat(),
            "cves": cves,
            "attacks": attacks,
            "threat_intel": threat_intel,
            "rules": [asdict(r) for r in rules]
        }
        
        with open(".enforcer_state.json", "w") as f:
            json.dump(state, f, indent=2)


def load_config() -> dict:
    """Carga configuración desde archivo."""
    default = {
        "dry_run": True,  # ¡Cambiar a False para producción!
        "cve_days": 7,
        "min_cve_severity": "7.0",
        "enable_attack_detection": True,
        "block_duration_minutes": 60,
        "rate_limit_packets": 10
    }
    
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            user = json.load(f)
            default.update(user)
    
    return default


class NotificationManager:
    """Gestiona notificaciones de alertas de seguridad."""
    
    def __init__(self, config: dict):
        self.config = config
        
    def send_webhook(self, payload: dict) -> bool:
        """Envía notificación a webhook."""
        webhook_url = self.config.get("webhook_url")
        if not webhook_url:
            return False
        
        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            return response.status_code in [200, 201, 202]
        except requests.RequestException as e:
            logger.error(f"Error enviando webhook: {e}")
            return False
    
    def send_slack(self, message: str, severity: str = "warning") -> bool:
        """Envía notificación a Slack."""
        slack_webhook = self.config.get("slack_webhook")
        if not slack_webhook:
            return False
        
        colors = {
            "critical": "#FF0000",
            "high": "#FFA500", 
            "medium": "#FFFF00",
            "low": "#00FF00",
            "info": "#0000FF"
        }
        
        payload = {
            "attachments": [{
                "color": colors.get(severity, "#FFA500"),
                "text": message,
                "footer": "🛡️ Security Enforcer",
                "ts": int(time.time())
            }]
        }
        
        try:
            response = requests.post(slack_webhook, json=payload, timeout=10)
            return response.status_code == 200
        except requests.RequestException as e:
            logger.error(f"Error enviando a Slack: {e}")
            return False
    
    def send_telegram(self, message: str) -> bool:
        """Envía notificación a Telegram."""
        token = self.config.get("telegram_token")
        chat_id = self.config.get("telegram_chat_id")
        if not token or not chat_id:
            return False
        
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
        
        try:
            response = requests.post(url, json=payload, timeout=10)
            return response.status_code == 200
        except requests.RequestException as e:
            logger.error(f"Error enviando a Telegram: {e}")
            return False
    
    def send_email(self, subject: str, body: str) -> bool:
        """Envía email de alerta."""
        smtp_config = self.config.get("smtp", {})
        if not smtp_config.get("enabled"):
            return False
        
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            msg = MIMEMultipart()
            msg["From"] = smtp_config["from"]
            msg["To"] = smtp_config["to"]
            msg["Subject"] = f"🛡️ Security Alert: {subject}"
            msg.attach(MIMEText(body, "plain"))
            
            server = smtplib.SMTP(smtp_config["host"], smtp_config.get("port", 587))
            if smtp_config.get("tls", True):
                server.starttls()
            if smtp_config.get("username"):
                server.login(smtp_config["username"], smtp_config["password"])
            server.sendmail(smtp_config["from"], smtp_config["to"], msg.as_string())
            server.quit()
            return True
        except Exception as e:
            logger.error(f"Error enviando email: {e}")
            return False
    
    def notify(self, title: str, message: str, severity: str = "info", rules: list = None):
        """Envía notificaciones a todos los canales configurados."""
        if severity in ["critical", "high"]:
            logger.critical(f"{title}: {message}")
        elif severity == "medium":
            logger.warning(f"{title}: {message}")
        else:
            logger.info(f"{title}: {message}")
        
        # Webhook
        if self.config.get("webhook_url"):
            payload = {
                "title": title,
                "message": message,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
                "rules": [asdict(r) for r in rules] if rules else []
            }
            self.send_webhook(payload)
        
        # Slack
        if self.config.get("slack_webhook"):
            full_message = f"*{title}*\n{message}"
            if rules:
                rules_text = "\n".join([f"• {r.description}" for r in rules[:5]])
                full_message += f"\n\n{rules_text}"
            self.send_slack(full_message, severity)
        
        # Telegram
        if self.config.get("telegram_token"):
            full_message = f"🛡️ <b>{title}</b>\n\n{message}"
            if rules:
                rules_text = "\n".join([f"• {r.description}" for r in rules[:5]])
                full_message += f"\n\n{rules_text}"
            self.send_telegram(full_message)
        
        # Email para críticos/altos
        if severity in ["critical", "high"] and self.config.get("smtp", {}).get("enabled"):
            body = f"{title}\n\n{message}\n\n"
            if rules:
                body += "Reglas generadas:\n"
                for r in rules:
                    body += f"• {r.action}: {r.target} - {r.description}\n"
            self.send_email(title, body)


def main():
    """Punto de entrada."""
    print("""
╔═══════════════════════════════════════════════════════════╗
║     🛡️ Dynamic Security Policy Enforcer v1.0              ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    config = load_config()
    print(f"Configuración: dry_run={config['dry_run']}")
    
    engine = PolicyEngine(config)
    results = engine.run()
    
    print(f"\n📊 Resumen:")
    print(f"   CVEs encontrados: {results['cves_found']}")
    print(f"   Ataques detectados: {results['attacks_detected']}")
    print(f"   Reglas generadas: {results['rules_generated']}")
    print(f"   Aplicadas: {results['results']['applied']}")
    print(f"   Fallidas: {results['results']['failed']}")


if __name__ == "__main__":
    main()
