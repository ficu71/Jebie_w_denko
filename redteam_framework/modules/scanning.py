import logging
import asyncio
import socket
import ipaddress
import subprocess
import re
import os
from typing import Dict, List, Any, Optional

from redteam_framework.core.logger import logger
from redteam_framework.core.config import DEFAULT_CREDENTIALS

# Check optional imports
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not installed. Network scanning will be limited.")

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    logger.warning("Paramiko not installed. SSH functionality will be limited.")

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    logger.warning("aiohttp not installed. Web interactions will be limited.")


class NetworkScanner:
    """
    Handles network scanning and vulnerability assessment.
    """
    
    def __init__(self, wordlist_path: Optional[str] = None):
        self.credentials = self.load_credentials(wordlist_path)
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
            # verbose=False to reduce noise
            answered, _ = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)

            for _, received in answered:
                ip = received.psrc
                mac = received.hwsrc
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
                    # Async subprocess would be better here in a real refactor, but keeping logic similar for now
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
        if not mac:
            return 'Unknown'
        mac_prefix = mac.replace(':', '').upper()[:6]
        vendors = {
            '00:1A:2B': 'Cisco',
            '00:14:BF': 'Samsung',
            '00:22:FB': 'Apple',
            '00:1C:B3': 'Intel',
            '00:24:E8': 'TP-Link',
            '00:1A:79': 'Netgear',
            '00:0F:CC': 'D-Link',
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
            return False
            
        for cred in self.credentials:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=22, username=cred['username'], password=cred['password'], timeout=3)
                client.close()
                logger.info(f"Weak SSH auth found on {ip} with {cred['username']}:{cred['password']}")
                return True
            except:
                continue
        return False

    async def _check_web_vulns(self, ip: str) -> Dict[str, bool]:
        """Check for common web vulnerabilities."""
        if not AIOHTTP_AVAILABLE:
            return {}
            
        vulns = {}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
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
        except Exception:
            pass
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
                        connection_timeout=3
                    )
                    conn.close()
                    logger.info(f"Weak MySQL auth found on {ip} with {cred['username']}")
                    return True
                except:
                    continue
        except ImportError:
            logger.warning("mysql-connector not available, skipping MySQL check.")
        except Exception:
            pass
        return False

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
