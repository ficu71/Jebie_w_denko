#!/usr/bin/env python3
"""
Mobile and IoT Support Module
Handles interaction with mobile devices and IoT devices.

Author: Independent Red Team Consultant
Classification: Professional Use Only
"""

import asyncio
import subprocess
import re
import logging
from typing import List, Dict, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MobileIoTSupport')

class MobileIoTSupport:
    """
    Handles interaction with mobile and IoT devices.
    Currently supports Android devices via ADB.
    """
    
    def __init__(self):
        """Initialize the mobile and IoT support module."""
        self.adb_path = self._find_adb()
        if not self.adb_path:
            logger.error("ADB not found in PATH")
            self.adb_available = False
        else:
            self.adb_available = True
            logger.info(f"ADB found at {self.adb_path}")

    def _find_adb(self) -> Optional[str]:
        """Find the ADB executable in the system PATH."""
        try:
            result = subprocess.run(['which', 'adb'], capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    async def connect_to_android(self, device_id: str) -> bool:
        """
        Connect to an Android device via ADB.
        
        Args:
            device_id (str): Device ID or IP address.
            
        Returns:
            bool: True if connection successful, False otherwise.
        """
        if not self.adb_available:
            logger.error("ADB not available")
            return False
            
        try:
            # Connect to the device
            result = subprocess.run([self.adb_path, 'connect', device_id], capture_output=True, text=True)
            if 'connected' in result.stdout:
                logger.info(f"Connected to Android device {device_id}")
                return True
            else:
                logger.error(f"Failed to connect to Android device {device_id}")
                return False
        except Exception as e:
            logger.error(f"Error connecting to Android device: {e}")
            return False

    async def get_android_apps(self, device_id: str) -> List[Dict]:
        """
        Get list of installed apps on an Android device.
        
        Args:
            device_id (str): Device ID or IP address.
            
        Returns:
            List[Dict]: List of apps with their package names and permissions.
        """
        if not self.adb_available:
            return []
            
        try:
            # List installed packages
            result = subprocess.run([self.adb_path, '-s', device_id, 'shell', 'pm', 'list', 'packages'], 
                                 capture_output=True, text=True)
            
            apps = []
            for line in result.stdout.split('\n'):
                if line.startswith('package:'):
                    package_name = line.split(':')[1].strip()
                    apps.append({'package_name': package_name})
            
            logger.info(f"Found {len(apps)} apps on Android device {device_id}")
            return apps
        except Exception as e:
            logger.error(f"Error getting Android apps: {e}")
            return []

    async def extract_android_data(self, device_id: str, package_name: str) -> Dict:
        """
        Extract data from a specific Android app.
        
        Args:
            device_id (str): Device ID or IP address.
            package_name (str): Package name of the app.
            
        Returns:
            Dict: Extracted data from the app.
        """
        if not self.adb_available:
            return {}
            
        extracted_data = {
            'package_name': package_name,
            'contacts': [],
            'messages': [],
            'files': []
        }
        
        try:
            # Example: Extract contacts (simplified)
            contacts_result = subprocess.run([self.adb_path, '-s', device_id, 'shell', 'content', 'query', '--uri', 'content://contacts/phones', '--projection', '_id:number'], 
                                         capture_output=True, text=True)
            for line in contacts_result.stdout.split('\n'):
                if line.strip():
                    extracted_data['contacts'].append(line.strip())
            
            # Example: Extract SMS messages (simplified)
            sms_result = subprocess.run([self.adb_path, '-s', device_id, 'shell', 'content', 'query', '--uri', 'content://sms/', '--projection', '_id:address:date'], 
                                     capture_output=True, text=True)
            for line in sms_result.stdout.split('\n'):
                if line.strip():
                    extracted_data['messages'].append(line.strip())
            
            logger.info(f"Extracted data from Android app {package_name}")
            return extracted_data
        except Exception as e:
            logger.error(f"Error extracting Android data: {e}")
            return extracted_data

    async def scan_iot_devices(self, network_range: str) -> List[Dict]:
        """
        Scan for IoT devices in the network.
        
        Args:
            network_range (str): Network range to scan (e.g., 192.168.1.0/24).
            
        Returns:
            List[Dict]: List of detected IoT devices.
        """
        # This would involve using tools like nmap with specific IoT detection scripts
        # For demonstration, we'll return a mock list
        logger.info(f"Scanning IoT devices in {network_range}")
        
        mock_iot_devices = [
            {'ip': '192.168.1.50', 'type': 'Smart TV', 'vendor': 'Samsung'},
            {'ip': '192.168.1.51', 'type': 'Smart Speaker', 'vendor': 'Amazon'},
            {'ip': '192.168.1.52', 'type': 'Security Camera', 'vendor': 'Hikvision'}
        ]
        
        return mock_iot_devices

    async def analyze_iot_vulnerabilities(self, device: Dict) -> List[Dict]:
        """
        Analyze vulnerabilities in an IoT device.
        
        Args:
            device (Dict): IoT device information.
            
        Returns:
            List[Dict]: List of detected vulnerabilities.
        """
        vulnerabilities = []
        
        # Example vulnerability analysis based on device type
        device_type = device.get('type', '')
        if 'Camera' in device_type:
            vulnerabilities.append({
                'type': 'Default Credentials',
                'severity': 'High',
                'description': 'Many security cameras use default admin credentials'
            })
        elif 'Speaker' in device_type:
            vulnerabilities.append({
                'type': 'Insecure API',
                'severity': 'Medium',
                'description': 'Smart speakers may have insecure web APIs'
            })
        
        logger.info(f"Analyzed vulnerabilities for IoT device {device['ip']}")
        return vulnerabilities

# Example usage (for testing purposes only)
if __name__ == "__main__":
    # This part should be integrated into the main framework's async loop.
    # For standalone testing, we can run it directly.
    mobile_iot = MobileIoTSupport()
    
    if mobile_iot.adb_available:
        # Test Android connection (replace with actual device ID)
        asyncio.run(mobile_iot.connect_to_android('emulator-5554'))
        
        # Test getting apps
        apps = asyncio.run(mobile_iot.get_android_apps('emulator-5554'))
        print(f"Android Apps: {apps}")
        
        # Test extracting data
        data = asyncio.run(mobile_iot.extract_android_data('emulator-5554', 'com.android.contacts'))
        print(f"Extracted Data: {data}")
    
    # Test IoT scanning
    iot_devices = asyncio.run(mobile_iot.scan_iot_devices('192.168.1.0/24'))
    print(f"IoT Devices: {iot_devices}")
    
    for device in iot_devices:
        vulns = asyncio.run(mobile_iot.analyze_iot_vulnerabilities(device))
        print(f"Vulnerabilities for {device['ip']}: {vulns}")