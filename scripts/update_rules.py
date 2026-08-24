#!/usr/bin/env python3
"""
Wazuh Rule Automation Tool - Free version using GitHub Actions
"""

import os
import sys
import json
import shutil
import logging
import requests
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

class WazuhRuleManager:
    def __init__(self, host: str, user: str, password: str, port: int = 55000):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
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
    
    def upload_rule(self, rule_file: str) -> bool:
        """Upload new rule to Wazuh"""
        try:
            with open(rule_file, 'r') as f:
                rule_content = f.read()
            
            # Upload rule via API
            upload_url = f"{self.base_url}/rules"
            response = self.session.post(
                upload_url,
                files={'file': (os.path.basename(rule_file), rule_content, 'application/xml')}
            )
            
            if response.status_code in [200, 201]:
                self.logger.info(f"Rule uploaded successfully: {rule_file}")
                return True
            else:
                self.logger.error(f"Failed to upload rule: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Upload error: {e}")
            return False
    
    def restart_wazuh_manager(self) -> bool:
        """Restart Wazuh manager"""
        try:
            restart_url = f"{self.base_url}/manager/restart"
            response = self.session.put(restart_url)
            
            if response.status_code == 200:
                self.logger.info("Wazuh manager restart initiated successfully")
                return True
            else:
                self.logger.error(f"Failed to restart manager: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Restart error: {e}")
            return False
    
    def check_manager_status(self) -> bool:
        """Check if Wazuh manager is running properly"""
        try:
            status_url = f"{self.base_url}/manager/status"
            response = self.session.get(status_url)
            
            if response.status_code == 200:
                status = response.json().get('data', {}).get('status', 'unknown')
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

def main():
    parser = argparse.ArgumentParser(description='Wazuh Rule Automation Tool')
    parser.add_argument('--host', required=True, help='Wazuh server host')
    parser.add_argument('--user', required=True, help='Wazuh API username')
    parser.add_argument('--password', required=True, help='Wazuh API password')
    parser.add_argument('--port', type=int, default=55000, help='Wazuh API port')
    parser.add_argument('--rule-file', required=True, help='Path to rule file')
    parser.add_argument('--backup-dir', default='backups', help='Backup directory')
    
    args = parser.parse_args()
    
    # Initialize manager
    manager = WazuhRuleManager(args.host, args.user, args.password, args.port)
    
    # Step 1: Authenticate
    if not manager.authenticate():
        sys.exit(1)
    
    # Step 2: Validate rule file
    if not manager.validate_rule_file(args.rule_file):
        sys.exit(1)
    
    # Step 3: Backup current rules
    if not manager.backup_current_rules(args.backup_dir):
        sys.exit(1)
    
    # Step 4: Upload new rules
    if not manager.upload_rule(args.rule_file):
        sys.exit(1)
    
    # Step 5: Restart Wazuh manager
    if not manager.restart_wazuh_manager():
        sys.exit(1)
    
    # Step 6: Verify manager status
    if not manager.check_manager_status():
        sys.exit(1)
    
    manager.logger.info("Wazuh rule update completed successfully!")
    sys.exit(0)

if __name__ == "__main__":
    main()
