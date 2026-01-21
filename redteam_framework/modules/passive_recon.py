#!/usr/bin/env python3
"""
Passive Reconnaissance & Side-Channel Module
Handles passive network monitoring, information gathering, and side-channel analysis.
"""

import time
import subprocess
import logging
from collections import defaultdict
from typing import Dict, List, Optional

# Try imports
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Configure logging
logger = logging.getLogger('PassiveRecon')

class PassiveRecon:
    """
    Handles passive network reconnaissance techniques.
    """
    
    def __init__(self, interface: str = 'wlan0'):
        self.interface = interface
        self.devices = defaultdict(dict)
        self.dhcp_info = defaultdict(dict)
        self.arps = []
        
    def start_monitoring(self, timeout: int = 60) -> None:
        """Start passive monitoring on the network interface."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available. Passive monitoring disabled.")
            return

        logger.info(f"Starting passive monitoring on interface {self.interface} for {timeout}s")
        
        try:
            # Check for privileges/scapy functionality (sniff works better with root)
            # Filter for ARP or DHCP (UDP port 67/68)
            scapy.sniff(iface=self.interface, prn=self._process_packet, timeout=timeout, store=0, filter="arp or (udp and (port 67 or port 68))")
        except Exception as e:
            logger.error(f"Error during passive monitoring: {e}")
    
    def _process_packet(self, packet):
        """Process captured network packets."""
        try:
            if packet.haslayer(scapy.ARP):
                self._process_arp_packet(packet)
            elif packet.haslayer(scapy.DHCP):
                self._process_dhcp_packet(packet)
        except Exception as e:
            logger.debug(f"Error processing packet: {e}")
    
    def _process_arp_packet(self, packet):
        """Process ARP packets for device discovery."""
        arp = packet[scapy.ARP]
        # ARP Reply (op=2) is useful for seeing devices exist
        if arp.op == 2:  
            if arp.psrc not in self.devices:
                self.devices[arp.psrc] = {
                    'mac': arp.hwsrc,
                    'vendor': self._get_vendor_from_mac(arp.hwsrc),
                    'first_seen': time.time(),
                    'last_seen': time.time()
                }
                logger.debug(f"Discovered device via ARP: {arp.psrc} ({arp.hwsrc})")
    
    def _process_dhcp_packet(self, packet):
        """Process DHCP packets for device fingerprinting."""
        if not packet.haslayer(scapy.DHCP):
            return
            
        dhcp_options = packet[scapy.DHCP].options
        # Look for message type
        msg_type = next((opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 'message-type'), None)
        
        if msg_type == 1:  # DHCP Discover
            # Ethernet src or BOOTP chaddr
            client_mac = packet[scapy.Ether].src
            client_vendor = self._get_vendor_from_mac(client_mac)
            
            self.dhcp_info[client_mac] = {
                'vendor': client_vendor,
                'hostname': next((opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 'hostname'), 'Unknown'),
                'timestamp': time.time()
            }
            logger.debug(f"DHCP discover from: {client_mac} ({client_vendor})")
    
    def _get_vendor_from_mac(self, mac: str) -> str:
        """Get device vendor from MAC address."""
        mac_prefixes = {
            '00:1A:2B': 'Cisco', '00:14:BF': 'Samsung', '00:22:FB': 'Apple',
            '00:1C:B3': 'Intel', '00:24:E8': 'TP-Link', '00:1A:79': 'Netgear',
            '00:0F:CC': 'D-Link', 'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Android',
            '70:85:C2': 'Nintendo', 'E0:CB:4E': 'PlayStation'
        }
        clean_mac = mac.replace(':', '').upper()[:6]
        for prefix, vendor in mac_prefixes.items():
            if clean_mac.startswith(prefix.replace(':', '')):
                return vendor
        return 'Unknown'
    
    def get_discovered_devices(self) -> Dict:
        return dict(self.devices)
    
    def get_dhcp_fingerprints(self) -> Dict:
        return dict(self.dhcp_info)

class SideChannelCollector:
    """
    Handles side-channel data collection techniques.
    """
    
    def __init__(self):
        self.timing_data = []
        self.metadata_analysis = []
    
    def perform_timing_attack(self, target_url: str, payload: str) -> float:
        """Perform timing attack to infer system state."""
        if not REQUESTS_AVAILABLE:
            return 0.0
            
        start_time = time.time()
        try:
            requests.get(target_url, params={'test': payload}, timeout=10)
            end_time = time.time()
            response_time = end_time - start_time
            
            self.timing_data.append({
                'url': target_url,
                'payload': payload,
                'response_time': response_time,
                'timestamp': time.time()
            })
            return response_time
        except Exception as e:
            logger.error(f"Timing attack failed: {e}")
            return 0.0
    
    def analyze_metadata(self, file_path: str) -> Dict:
        """Analyze file metadata (EXIF, etc.)."""
        metadata = {}
        if not PIL_AVAILABLE:
            logger.warning("Pillow not installed. Cannot analyze metadata.")
            return {}
            
        try:
            image = Image.open(file_path)
            exif_data = image._getexif()
            
            if exif_data:
                for tag_id in exif_data:
                    tag = TAGS.get(tag_id, tag_id)
                    metadata[tag] = str(exif_data.get(tag_id)) # Convert to str for safety
                
                self.metadata_analysis.append({
                    'file': file_path,
                    'metadata': metadata,
                    'timestamp': time.time()
                })
                return metadata
        except Exception as e:
            logger.debug(f"Metadata analysis not possible or failed: {e}")
            return {}
        return {}
        
    def analyze_bluetooth_devices(self) -> List[Dict]:
        """Scan for nearby Bluetooth devices."""
        devices = []
        try:
            # hcitool scan requires root/sudo often
            result = subprocess.run(['hcitool', 'scan'], capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')
            for line in lines:
                if line.strip() and 'Scanning ...' not in line:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        devices.append({'mac': parts[1].strip(), 'name': parts[2].strip()})
        except Exception:
            pass # Fail silently if tool not present
        return devices
