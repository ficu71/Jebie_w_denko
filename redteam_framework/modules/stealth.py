import asyncio
import random
import os
import subprocess
import logging
from typing import Dict, Any, List

# Local imports
from redteam_framework.core.logger import logger

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
