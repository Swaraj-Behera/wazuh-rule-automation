#!/usr/bin/env python3
"""
Wazuh Rule Automation Tool - Complete Updated Version
Supports Wazuh 4.x+ with integrated API
"""

import os
import sys
import json
import shutil
import logging
import requests
import argparse
import subprocess
import paramiko
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

class WazuhRuleManager:
    def __init__(self, host: str, user: str, password: str, port: int = 55000, ssh_key: Optional[str] = None):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.ssh_key = ssh_key
        self.base_url = f"https://{host}:{port}"
        self.session = requests.Session()
        self.session.verify = False  # For self-signed certs
        self.token = None
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging for the automation"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('wazuh_update.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def authenticate(self) -> bool:
        """Authenticate with Wazuh API"""
        try:
            auth_url = f"{self.base_url}/security/user/authenticate"
            response = self.session.post(
                auth_url,
                json={"username": self.user, "password": self.password},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                self.token = response.json()['data']['token']
                self.session.headers.update({
                    'Authorization': f'Bearer {self.token}'
                })
                self.logger.info("Authentication successful")
                return True
            else:
                self.logger.error(f"Authentication failed: {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False
    
    def backup_current_rules(self, backup_dir: str) -> bool:
        """Backup current Wazuh rules"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = Path(backup_dir) / f"rules_backup_{timestamp}"
            backup_path.mkdir(parents=True, exist_ok=True)
            
            # Backup via API
            rules_url = f"{self.base_url}/rules"
            response = self.session.get(rules_url)
            
            if response.status_code == 200:
                backup_file = backup_path / "rules_backup.json"
                with open(backup_file, 'w') as f:
                    json.dump(response.json(), f, indent=2)
                self.logger.info(f"Rules backed up to {backup_file}")
                return True
            else:
                self.logger.error(f"Failed to backup rules: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Backup error: {e}")
            return False
    
    def backup_rules_files(self, backup_dir: str) -> bool:
        """Backup actual rule files via SSH"""
        try:
            ssh = self._get_ssh_connection()
            if not ssh:
                self.logger.warning("SSH not available, skipping file backup")
                return True
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = Path(backup_dir) / f"rules_files_backup_{timestamp}"
            backup_path.mkdir(parents=True, exist_ok=True)
            
            # Backup rules directory
            commands = [
                "sudo cp -r /var/ossec/etc/rules/* /tmp/rules_backup",
                "sudo tar -czf /tmp/rules_backup.tar.gz -C /tmp rules_backup",
                "sudo rm -rf /tmp/rules_backup"
            ]
            
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                error = stderr.read().decode()
                if error:
                    self.logger.error(f"Backup command failed: {error}")
                    return False
            
            # Download backup
            sftp = ssh.open_sftp()
            sftp.get('/tmp/rules_backup.tar.gz', str(backup_path / 'rules_backup.tar.gz'))
            sftp.close()
            
            # Cleanup remote backup
            ssh.exec_command("sudo rm -f /tmp/rules_backup.tar.gz")
            
            self.logger.info(f"Rule files backed up to {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"File backup error: {e}")
            return False
    
    def _get_ssh_connection(self):
        """Establish SSH connection"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if self.ssh_key:
                # Use SSH key authentication
                private_key = paramiko.RSAKey.from_private_key_file(self.ssh_key)
                ssh.connect(
                    hostname=self.host,
                    username=self.user,
                    pkey=private_key,
                    timeout=30
                )
            else:
                # Use password authentication
                ssh.connect(
                    hostname=self.host,
                    username=self.user,
                    password=self.password,
                    timeout=30
                )
            
            return ssh
        except Exception as e:
            self.logger.error(f"SSH connection failed: {e}")
            return None
    
    def upload_rule(self, rule_file: str) -> bool:
        """Upload new rule to Wazuh"""
        try:
            # Validate file existence
            if not os.path.exists(rule_file):
                self.logger.error(f"Rule file not found: {rule_file}")
                return False
            
            # Method 1: Upload via API
            with open(rule_file, 'r') as f:
                rule_content = f.read()
            
            upload_url = f"{self.base_url}/rules"
            response = self.session.post(
                upload_url,
                files={'file': (os.path.basename(rule_file), rule_content, 'application/xml')}
            )
            
            if response.status_code in [200, 201]:
                self.logger.info(f"Rule uploaded successfully via API: {rule_file}")
                return True
            
            # Method 2: Upload via SSH (fallback)
            self.logger.warning("API upload failed, trying SSH method...")
            return self._upload_rule_via_ssh(rule_file)
                
        except Exception as e:
            self.logger.error(f"Upload error: {e}")
            return False
    
    def _upload_rule_via_ssh(self, rule_file: str) -> bool:
        """Upload rule via SSH (fallback method)"""
        try:
            ssh = self._get_ssh_connection()
            if not ssh:
                self.logger.error("SSH connection failed")
                return False
            
            filename = os.path.basename(rule_file)
            
            # Check if rules directory exists
            stdin, stdout, stderr = ssh.exec_command("sudo test -d /var/ossec/etc/rules")
            if stderr.read().decode():
                self.logger.error("Rules directory not found")
                return False
            
            # Copy rule file to remote
            with open(rule_file, 'r') as f:
                content = f.read()
            
            sftp = ssh.open_sftp()
            remote_path = f"/tmp/{filename}"
            with sftp.open(remote_path, 'w') as remote_file:
                remote_file.write(content)
            sftp.close()
            
            # Move to rules directory
            commands = [
                f"sudo mv /tmp/{filename} /var/ossec/etc/rules/{filename}",
                "sudo chown root:wazuh /var/ossec/etc/rules/*.xml",
                "sudo chmod 660 /var/ossec/etc/rules/*.xml"
            ]
            
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                error = stderr.read().decode()
                if error:
                    self.logger.error(f"Command failed: {error}")
                    return False
            
            self.logger.info(f"Rule uploaded via SSH: {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"SSH upload error: {e}")
            return False
    
    def restart_wazuh_manager(self) -> bool:
        """Restart Wazuh manager (works with integrated API in 4.x+)"""
        try:
            # Method 1: Try API restart first
            try:
                restart_url = f"{self.base_url}/manager/restart"
                response = self.session.put(restart_url)
                
                if response.status_code == 200:
                    self.logger.info("Manager restart initiated via API")
                    return self._wait_for_manager_restart()
            except Exception as e:
                self.logger.warning(f"API restart failed: {e}")
            
            # Method 2: SSH restart (most reliable)
            self.logger.info("Attempting SSH restart...")
            return self._restart_via_ssh()
            
        except Exception as e:
            self.logger.error(f"Restart error: {e}")
            return False
    
    def _restart_via_ssh(self) -> bool:
        """Restart Wazuh manager via SSH"""
        try:
            ssh = self._get_ssh_connection()
            if not ssh:
                self.logger.error("SSH connection failed for restart")
                return False
            
            # Restart with sudo
            stdin, stdout, stderr = ssh.exec_command('sudo systemctl restart wazuh-manager')
            error = stderr.read().decode()
            
            # Check if restart was successful
            if error and 'not found' in error.lower():
                # Fallback to older init script
                stdin, stdout, stderr = ssh.exec_command('sudo /var/ossec/bin/ossec-control restart')
                error = stderr.read().decode()
            
            if error:
                self.logger.error(f"Restart failed: {error}")
                return False
            
            self.logger.info("Wazuh manager restarted via SSH")
            return self._wait_for_manager_restart()
            
        except Exception as e:
            self.logger.error(f"SSH restart error: {e}")
            return False
    
    def _wait_for_manager_restart(self, timeout: int = 120) -> bool:
        """Wait for manager to restart successfully"""
        self.logger.info(f"Waiting for manager to restart (timeout: {timeout}s)...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                status_url = f"{self.base_url}/manager/status"
                response = self.session.get(status_url, timeout=5)
                
                if response.status_code == 200:
                    status = response.json().get('data', {}).get('status', 'unknown')
                    self.logger.info(f"Manager status: {status}")
                    
                    if status == 'running':
                        self.logger.info("Manager is running!")
                        return True
                
                time.sleep(5)
                
            except Exception as e:
                self.logger.warning(f"Waiting for manager: {e}")
                time.sleep(5)
                continue
        
        self.logger.error("Manager restart timeout")
        return False
    
    def check_manager_status(self) -> bool:
        """Check if Wazuh manager is running properly"""
        try:
            status_url = f"{self.base_url}/manager/status"
            response = self.session.get(status_url)
            
            if response.status_code == 200:
                data = response.json()
                status = data.get('data', {}).get('status', 'unknown')
                self.logger.info(f"Wazuh manager status: {status}")
                return status == 'running'
            else:
                self.logger.error(f"Failed to get manager status: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Status check error: {e}")
            return False
    
    def validate_rule_file(self, rule_file: str) -> bool:
        """Validate rule file format and content"""
        try:
            # Check if file exists
            if not os.path.exists(rule_file):
                self.logger.error(f"Rule file not found: {rule_file}")
                return False
            
            # Basic XML validation
            import xml.etree.ElementTree as ET
            try:
                tree = ET.parse(rule_file)
                root = tree.getroot()
                
                # Check for rule elements
                if root.tag != 'rules':
                    self.logger.warning("Root element should be 'rules'")
                
                rule_count = len(root.findall('.//rule'))
                self.logger.info(f"Found {rule_count} rules in file")
                
                if rule_count == 0:
                    self.logger.warning("No rules found in file")
                    
                return True
                
            except ET.ParseError as e:
                self.logger.error(f"Invalid XML: {e}")
                return False
                
        except Exception as e:
            self.logger.error(f"Validation error: {e}")
            return False
    
    def rollback_rule(self, backup_path: str) -> bool:
        """Rollback to previous rule version"""
        try:
            self.logger.warning(f"Initiating rollback from {backup_path}")
            
            # Find latest backup
            backup_dir = Path(backup_path)
            if not backup_dir.exists():
                self.logger.error("Backup directory not found")
                return False
            
            # Get latest backup file
            backup_files = sorted(backup_dir.glob("rules_backup_*.json"))
            if not backup_files:
                self.logger.error("No backup files found")
                return False
            
            latest_backup = backup_files[-1]
            self.logger.info(f"Restoring from {latest_backup}")
            
            # Restore via API
            with open(latest_backup, 'r') as f:
                backup_data = json.load(f)
            
            restore_url = f"{self.base_url}/rules"
            response = self.session.post(restore_url, json=backup_data)
            
            if response.status_code in [200, 201]:
                self.logger.info("Rollback successful")
                return True
            else:
                self.logger.error(f"Rollback failed: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Rollback error: {e}")
            return False
    
    def create_summary(self, success: bool, backup_dir: str) -> None:
        """Create summary report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        summary_file = f"update_summary_{timestamp}.json"
        
        summary = {
            "timestamp": timestamp,
            "success": success,
            "host": self.host,
            "backup_dir": backup_dir,
            "action": "rule_update"
        }
        
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        self.logger.info(f"Summary report created: {summary_file}")

def main():
    parser = argparse.ArgumentParser(description='Wazuh Rule Automation Tool')
    parser.add_argument('--host', required=True, help='Wazuh server host')
    parser.add_argument('--user', required=True, help='Wazuh API username')
    parser.add_argument('--password', required=True, help='Wazuh API password')
    parser.add_argument('--port', type=int, default=55000, help='Wazuh API port')
    parser.add_argument('--rule-file', required=True, help='Path to rule file')
    parser.add_argument('--backup-dir', default='backups', help='Backup directory')
    parser.add_argument('--ssh-key', help='SSH key path for authentication')
    parser.add_argument('--rollback', action='store_true', help='Rollback to previous version')
    
    args = parser.parse_args()
    
    # Initialize manager
    manager = WazuhRuleManager(
        args.host, 
        args.user, 
        args.password, 
        args.port,
        args.ssh_key
    )
    
    # Step 1: Authenticate
    if not manager.authenticate():
        sys.exit(1)
    
    # Handle rollback if requested
    if args.rollback:
        if manager.rollback_rule(args.backup_dir):
            manager.logger.info("Rollback completed successfully")
            manager.create_summary(True, args.backup_dir)
            sys.exit(0)
        else:
            manager.logger.error("Rollback failed")
            sys.exit(1)
    
    # Step 2: Validate rule file
    if not manager.validate_rule_file(args.rule_file):
        sys.exit(1)
    
    # Step 3: Backup current rules
    if not manager.backup_current_rules(args.backup_dir):
        sys.exit(1)
    
    # Step 4: Backup actual files (optional)
    if args.ssh_key or manager.user:
        manager.backup_rules_files(args.backup_dir)
    
    # Step 5: Upload new rules
    if not manager.upload_rule(args.rule_file):
        # Try rollback on failure
        manager.logger.error("Upload failed, attempting rollback...")
        if manager.rollback_rule(args.backup_dir):
            manager.logger.info("Rolled back to previous version")
        sys.exit(1)
    
    # Step 6: Restart Wazuh manager
    if not manager.restart_wazuh_manager():
        manager.logger.error("Restart failed, attempting rollback...")
        if manager.rollback_rule(args.backup_dir):
            manager.logger.info("Rolled back to previous version")
        sys.exit(1)
    
    # Step 7: Verify manager status
    if not manager.check_manager_status():
        manager.logger.error("Manager verification failed, attempting rollback...")
        if manager.rollback_rule(args.backup_dir):
            manager.logger.info("Rolled back to previous version")
        sys.exit(1)
    
    manager.logger.info("="*50)
    manager.logger.info("Wazuh rule update completed successfully!")
    manager.logger.info("="*50)
    manager.create_summary(True, args.backup_dir)
    sys.exit(0)

if __name__ == "__main__":
    main()
