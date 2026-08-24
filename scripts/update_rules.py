#!/usr/bin/env python3
"""
Wazuh Rule Automation - API Only
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
import xml.etree.ElementTree as ET

class WazuhRuleManager:
    def __init__(self, host, user, password, port=55000):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.base_url = f"https://{host}:{port}"
        self.session = requests.Session()
        self.session.verify = False
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
    
    def authenticate(self):
        try:
            auth_url = f"{self.base_url}/security/user/authenticate"
            response = self.session.post(
                auth_url,
                json={"username": self.user, "password": self.password},
                timeout=30
            )
            
            if response.status_code == 200:
                self.token = response.json()['data']['token']
                self.session.headers.update({'Authorization': f'Bearer {self.token}'})
                self.logger.info("✅ Authentication successful")
                return True
            else:
                self.logger.error(f"❌ Authentication failed: {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"❌ Authentication error: {e}")
            return False
    
    def backup_current_rules(self, backup_dir):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = Path(backup_dir) / f"rules_backup_{timestamp}"
            backup_path.mkdir(parents=True, exist_ok=True)
            
            rules_url = f"{self.base_url}/rules"
            response = self.session.get(rules_url, timeout=30)
            
            if response.status_code == 200:
                backup_file = backup_path / "rules_backup.json"
                with open(backup_file, 'w') as f:
                    json.dump(response.json(), f, indent=2)
                self.logger.info(f"✅ Rules backed up to {backup_path}")
                return True
            else:
                self.logger.error(f"❌ Backup failed: {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"❌ Backup error: {e}")
            return False
    
    def validate_rule_file(self, rule_file):
        try:
            if not os.path.exists(rule_file):
                self.logger.error(f"❌ File not found: {rule_file}")
                return False
            
            tree = ET.parse(rule_file)
            root = tree.getroot()
            
            if root.tag != 'rules':
                self.logger.warning("⚠️ Root should be 'rules'")
            
            rule_count = len(root.findall('.//rule'))
            self.logger.info(f"📊 Found {rule_count} rules")
            
            if rule_count == 0:
                self.logger.warning("⚠️ No rules found")
                return False
            
            return True
        except ET.ParseError as e:
            self.logger.error(f"❌ Invalid XML: {e}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Validation error: {e}")
            return False
    
    def upload_rule(self, rule_file):
        try:
            if not os.path.exists(rule_file):
                self.logger.error(f"❌ Rule file not found: {rule_file}")
                return False
            
            with open(rule_file, 'r') as f:
                rule_content = f.read()
            
            upload_url = f"{self.base_url}/rules"
            files = {'file': (os.path.basename(rule_file), rule_content, 'application/xml')}
            
            response = self.session.post(upload_url, files=files, timeout=30)
            
            if response.status_code in [200, 201]:
                self.logger.info(f"✅ Rule uploaded: {rule_file}")
                return True
            else:
                self.logger.error(f"❌ Upload failed: {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"❌ Upload error: {e}")
            return False
    
    def restart_wazuh_manager(self):
        try:
            self.logger.info("🔄 Restarting Wazuh manager...")
            restart_url = f"{self.base_url}/manager/restart"
            response = self.session.put(restart_url, timeout=30)
            
            if response.status_code == 200:
                self.logger.info("✅ Restart initiated")
                return self._wait_for_manager_restart()
            else:
                self.logger.error(f"❌ Restart failed: {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"❌ Restart error: {e}")
            return False
    
    def _wait_for_manager_restart(self, timeout=120):
        self.logger.info(f"⏳ Waiting up to {timeout}s for manager restart...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                status_url = f"{self.base_url}/manager/status"
                response = self.session.get(status_url, timeout=5)
                
                if response.status_code == 200:
                    status = response.json().get('data', {}).get('status', 'unknown')
                    if status == 'running':
                        self.logger.info("✅ Manager is running!")
                        return True
                time.sleep(5)
            except Exception as e:
                self.logger.info(f"⏳ Waiting: {e}")
                time.sleep(10)
        
        self.logger.error("❌ Restart timeout")
        return False
    
    def check_manager_status(self):
        try:
            status_url = f"{self.base_url}/manager/status"
            response = self.session.get(status_url, timeout=10)
            
            if response.status_code == 200:
                status = response.json().get('data', {}).get('status', 'unknown')
                self.logger.info(f"📊 Manager status: {status}")
                return status == 'running'
            else:
                self.logger.error(f"❌ Status check failed: {response.text}")
                return False
        except Exception as e:
            self.logger.error(f"❌ Status error: {e}")
            return False
    
    def rollback_rule(self, backup_dir):
        try:
            backup_path = Path(backup_dir)
            if not backup_path.exists():
                self.logger.error("❌ Backup not found")
                return False
            
            backup_files = sorted(backup_path.glob("rules_backup_*/rules_backup.json"))
            if not backup_files:
                self.logger.error("❌ No backups found")
                return False
            
            latest_backup = backup_files[-1]
            self.logger.info(f"🔄 Restoring from {latest_backup}")
            
            with open(latest_backup, 'r') as f:
                backup_data = json.load(f)
            
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
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True, help='Wazuh server host')
    parser.add_argument('--user', required=True, help='API username')
    parser.add_argument('--password', required=True, help='API password')
    parser.add_argument('--port', type=int, default=55000, help='API port')
    parser.add_argument('--rule-file', required=True, help='Rule file path')
    parser.add_argument('--backup-dir', default='backups', help='Backup directory')
    parser.add_argument('--rollback', action='store_true', help='Rollback to previous version')
    
    args = parser.parse_args()
    
    manager = WazuhRuleManager(args.host, args.user, args.password, args.port)
    
    if not manager.authenticate():
        sys.exit(1)
    
    if args.rollback:
        if manager.rollback_rule(args.backup_dir):
            sys.exit(0)
        else:
            sys.exit(1)
    
    if not manager.validate_rule_file(args.rule_file):
        sys.exit(1)
    
    if not manager.backup_current_rules(args.backup_dir):
        sys.exit(1)
    
    if not manager.upload_rule(args.rule_file):
        manager.logger.error("❌ Upload failed, attempting rollback...")
        manager.rollback_rule(args.backup_dir)
        sys.exit(1)
    
    if not manager.restart_wazuh_manager():
        manager.logger.error("❌ Restart failed, attempting rollback...")
        manager.rollback_rule(args.backup_dir)
        sys.exit(1)
    
    if not manager.check_manager_status():
        manager.logger.error("❌ Verification failed, attempting rollback...")
        manager.rollback_rule(args.backup_dir)
        sys.exit(1)
    
    manager.logger.info("="*50)
    manager.logger.info("✅ Wazuh rule update completed successfully!")
    manager.logger.info("="*50)
    sys.exit(0)

if __name__ == "__main__":
    main()
