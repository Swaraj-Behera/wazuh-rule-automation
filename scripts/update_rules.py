#!/usr/bin/env python3
"""
Wazuh Rule Automation Tool - Pure API Version
NO SSH, NO Server Installation Required
"""

import os
import sys
import json
import time
import logging
import requests
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
import xml.etree.ElementTree as ET

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
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if response.status_code == 200:
                self.token = response.json()['data']['token']
                self.session.headers.update({
                    'Authorization': f'Bearer {self.token}'
                })
                self.logger.info("✅ Authentication successful")
                return True
            else:
                self.logger.error(f"❌ Authentication failed: {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"❌ Authentication error: {e}")
            return False
    
    def backup_current_rules(self, backup_dir: str) -> bool:
        """Backup current rules via API"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = Path(backup_dir) / f"rules_backup_{timestamp}"
            backup_path.mkdir(parents=True, exist_ok=True)
            
            # Get all rules via API
            rules_url = f"{self.base_url}/rules"
            response = self.session.get(rules_url, timeout=30)
            
            if response.status_code == 200:
                # Save backup
                backup_file = backup_path / "rules_backup.json"
                with open(backup_file, 'w') as f:
                    json.dump(response.json(), f, indent=2)
                
                # Also save as XML if possible
                rules_data = response.json().get('data', {}).get('items', [])
                if rules_data:
                    xml_backup = backup_path / "rules_backup.xml"
                    self._save_rules_as_xml(rules_data, xml_backup)
                
                self.logger.info(f"✅ Rules backed up to {backup_path}")
                return True
            else:
                self.logger.error(f"❌ Failed to backup rules: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Backup error: {e}")
            return False
    
    def _save_rules_as_xml(self, rules_data: list, output_file: Path):
        """Convert rules to XML format"""
        try:
            root = ET.Element("rules")
            for rule in rules_data:
                rule_elem = ET.SubElement(root, "rule")
                for key, value in rule.items():
                    if key in ['id', 'level', 'description']:
                        rule_elem.set(key, str(value))
            
            tree = ET.ElementTree(root)
            tree.write(output_file, encoding='utf-8', xml_declaration=True)
        except Exception as e:
            self.logger.warning(f"Could not save XML backup: {e}")
    
    def upload_rule(self, rule_file: str) -> bool:
        """Upload new rule via API"""
        try:
            # Validate file exists
            if not os.path.exists(rule_file):
                self.logger.error(f"❌ Rule file not found: {rule_file}")
                return False
            
            # Read rule content
            with open(rule_file, 'r') as f:
                rule_content = f.read()
            
            # Upload via API
            upload_url = f"{self.base_url}/rules"
            files = {
                'file': (os.path.basename(rule_file), rule_content, 'application/xml')
            }
            
            response = self.session.post(upload_url, files=files, timeout=30)
            
            if response.status_code in [200, 201]:
                self.logger.info(f"✅ Rule uploaded successfully: {rule_file}")
                return True
            else:
                self.logger.error(f"❌ Upload failed: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Upload error: {e}")
            return False
    
    def validate_rule_file(self, rule_file: str) -> bool:
        """Validate rule file format"""
        try:
            if not os.path.exists(rule_file):
                self.logger.error(f"❌ Rule file not found: {rule_file}")
                return False
            
            # Parse XML
            try:
                tree = ET.parse(rule_file)
                root = tree.getroot()
                
                if root.tag != 'rules':
                    self.logger.warning("⚠️ Root element should be 'rules'")
                
                rule_count = len(root.findall('.//rule'))
                self.logger.info(f"📊 Found {rule_count} rules in file")
                
                if rule_count == 0:
                    self.logger.warning("⚠️ No rules found in file")
                    return False
                
                # Validate each rule
                for rule in root.findall('.//rule'):
                    rule_id = rule.get('id')
                    if not rule_id:
                        self.logger.warning("⚠️ Rule without ID found")
                        continue
                    
                    # Check for required elements
                    description = rule.find('description')
                    if description is None:
                        self.logger.warning(f"⚠️ Rule {rule_id} has no description")
                
                self.logger.info("✅ Rule validation passed")
                return True
                
            except ET.ParseError as e:
                self.logger.error(f"❌ Invalid XML: {e}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Validation error: {e}")
            return False
    
    def restart_wazuh_manager(self) -> bool:
        """Restart Wazuh manager via API only"""
        try:
            self.logger.info("🔄 Restarting Wazuh manager via API...")
            
            # Method 1: Try API restart
            restart_url = f"{self.base_url}/manager/restart"
            response = self.session.put(restart_url, timeout=30)
            
            if response.status_code == 200:
                self.logger.info("✅ Restart initiated via API")
                return self._wait_for_manager_restart()
            else:
                self.logger.warning(f"⚠️ API restart returned: {response.status_code}")
                
                # Method 2: Try shutdown and start
                shutdown_url = f"{self.base_url}/manager/shutdown"
                shutdown_response = self.session.put(shutdown_url, timeout=30)
                
                if shutdown_response.status_code == 200:
                    self.logger.info("✅ Shutdown initiated, waiting for restart...")
                    time.sleep(10)
                    
                    # Start manager
                    start_url = f"{self.base_url}/manager/start"
                    start_response = self.session.put(start_url, timeout=30)
                    
                    if start_response.status_code == 200:
                        self.logger.info("✅ Start initiated")
                        return self._wait_for_manager_restart()
                
                self.logger.error("❌ All restart methods failed")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Restart error: {e}")
            return False
    
    def _wait_for_manager_restart(self, timeout: int = 120) -> bool:
        """Wait for manager to restart"""
        self.logger.info(f"⏳ Waiting up to {timeout}s for manager restart...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                status_url = f"{self.base_url}/manager/status"
                response = self.session.get(status_url, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    status = data.get('data', {}).get('status', 'unknown')
                    self.logger.info(f"📊 Manager status: {status}")
                    
                    if status == 'running':
                        self.logger.info("✅ Manager is running!")
                        return True
                
                time.sleep(5)
                
            except requests.exceptions.ConnectionError:
                self.logger.info("⏳ Manager is restarting... (connection refused)")
                time.sleep(10)
            except Exception as e:
                self.logger.warning(f"⏳ Waiting for manager: {e}")
                time.sleep(5)
                continue
        
        self.logger.error("❌ Manager restart timeout")
        return False
    
    def check_manager_status(self) -> bool:
        """Check manager status via API"""
        try:
            status_url = f"{self.base_url}/manager/status"
            response = self.session.get(status_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                status = data.get('data', {}).get('status', 'unknown')
                version = data.get('data', {}).get('version', 'unknown')
                
                self.logger.info(f"📊 Wazuh version: {version}")
                self.logger.info(f"📊 Manager status: {status}")
                
                return status == 'running'
            else:
                self.logger.error(f"❌ Status check failed: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Status check error: {e}")
            return False
    
    def test_api_connection(self) -> bool:
        """Test basic API connectivity"""
        try:
            # Test root endpoint
            response = self.session.get(f"{self.base_url}/", timeout=10)
            if response.status_code == 200:
                self.logger.info("✅ API is reachable")
                return True
            else:
                self.logger.error(f"❌ API returned: {response.status_code}")
                return False
        except Exception as e:
            self.logger.error(f"❌ API connection failed: {e}")
            return False
    
    def rollback_rule(self, backup_dir: str) -> bool:
        """Rollback to previous version via API"""
        try:
            backup_path = Path(backup_dir)
            if not backup_path.exists():
                self.logger.error("❌ Backup directory not found")
                return False
            
            # Get latest backup
            backup_files = sorted(backup_path.glob("rules_backup_*/rules_backup.json"))
            if not backup_files:
                self.logger.error("❌ No backup files found")
                return False
            
            latest_backup = backup_files[-1]
            self.logger.info(f"🔄 Restoring from {latest_backup}")
            
            with open(latest_backup, 'r') as f:
                backup_data = json.load(f)
            
            # Restore via API
            restore_url = f"{self.base_url}/rules"
            response = self.session.post(restore_url, json=backup_data, timeout=30)
            
            if response.status_code in [200, 201]:
                self.logger.info("✅ Rollback successful")
                return True
            else:
                self.logger.error(f"❌ Rollback failed: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Rollback error: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Wazuh Rule Automation - API Only')
    parser.add_argument('--host', required=True, help='Wazuh server host')
    parser.add_argument('--user', required=True, help='Wazuh API username')
    parser.add_argument('--password', required=True, help='Wazuh API password')
    parser.add_argument('--port', type=int, default=55000, help='Wazuh API port')
    parser.add_argument('--rule-file', required=True, help='Path to rule file')
    parser.add_argument('--backup-dir', default='backups', help='Backup directory')
    parser.add_argument('--rollback', action='store_true', help='Rollback to previous version')
    parser.add_argument('--test-only', action='store_true', help='Test connection only')
    
    args = parser.parse_args()
    
    # Initialize manager
    manager = WazuhRuleManager(args.host, args.user, args.password, args.port)
    
    # Step 1: Test API connection
    if not manager.test_api_connection():
        sys.exit(1)
    
    # Step 2: Authenticate
    if not manager.authenticate():
        sys.exit(1)
    
    # Test-only mode
    if args.test_only:
        manager.logger.info("✅ API connection test passed!")
        manager.check_manager_status()
        sys.exit(0)
    
    # Handle rollback
    if args.rollback:
        if manager.rollback_rule(args.backup_dir):
            manager.logger.info("✅ Rollback completed!")
            sys.exit(0)
        else:
            sys.exit(1)
    
    # Step 3: Validate rule file
    if not manager.validate_rule_file(args.rule_file):
        sys.exit(1)
    
    # Step 4: Backup current rules
    if not manager.backup_current_rules(args.backup_dir):
        sys.exit(1)
    
    # Step 5: Upload new rules
    if not manager.upload_rule(args.rule_file):
        manager.logger.error("❌ Upload failed, attempting rollback...")
        manager.rollback_rule(args.backup_dir)
        sys.exit(1)
    
    # Step 6: Restart manager
    if not manager.restart_wazuh_manager():
        manager.logger.error("❌ Restart failed, attempting rollback...")
        manager.rollback_rule(args.backup_dir)
        sys.exit(1)
    
    # Step 7: Verify status
    if not manager.check_manager_status():
        manager.logger.error("❌ Verification failed, attempting rollback...")
        manager.rollback_rule(args.backup_dir)
        sys.exit(1)
    
    # Success!
    manager.logger.info("="*50)
    manager.logger.info("✅ Wazuh rule update completed successfully!")
    manager.logger.info("="*50)
    sys.exit(0)

if __name__ == "__main__":
    main()
