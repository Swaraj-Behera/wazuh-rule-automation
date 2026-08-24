#!/usr/bin/env python3
"""
Wazuh Verification Script - Updated for modern Wazuh
"""

import sys
import json
import logging
import argparse
import requests
import time
import socket

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def check_port(host: str, port: int) -> bool:
    """Check if port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def verify_wazuh_status(host: str, port: int, retries: int = 3) -> bool:
    """Verify Wazuh manager is running properly"""
    try:
        base_url = f"https://{host}:{port}"
        logger.info(f"Checking Wazuh manager at {base_url}")
        
        # Check port first
        if not check_port(host, port):
            logger.error(f"Port {port} is not open")
            return False
        
        # Check manager version (works with integrated API)
        version_url = f"{base_url}/manager/info"
        response = requests.get(version_url, verify=False, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            version = data.get('data', {}).get('version', 'unknown')
            logger.info(f"✅ Wazuh manager version: {version}")
            
            # Check API status
            api_status_url = f"{base_url}/"
            api_response = requests.get(api_status_url, verify=False, timeout=10)
            
            if api_response.status_code == 200:
                logger.info("✅ Wazuh API is responding")
            else:
                logger.warning(f"⚠️ API status check: {api_response.status_code}")
            
            # Check if rules are loaded
            rules_url = f"{base_url}/rules"
            rules_response = requests.get(rules_url, verify=False, timeout=10)
            
            if rules_response.status_code == 200:
                rules_data = rules_response.json()
                total_rules = len(rules_data.get('data', {}).get('items', []))
                logger.info(f"✅ Loaded {total_rules} rules")
                return True
            else:
                logger.error(f"❌ Rules check failed: {rules_response.status_code}")
                return False
        else:
            logger.error(f"❌ Version check failed: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        logger.error("❌ Connection refused - Wazuh manager may not be running")
        return False
    except Exception as e:
        logger.error(f"❌ Verification error: {e}")
        return False

def verify_rule_file(rule_file: str) -> bool:
    """Verify a specific rule file"""
    try:
        import xml.etree.ElementTree as ET
        
        if not rule_file:
            return True
            
        logger.info(f"Verifying rule file: {rule_file}")
        tree = ET.parse(rule_file)
        root = tree.getroot()
        
        rule_count = len(root.findall('.//rule'))
        logger.info(f"Found {rule_count} rules in file")
        
        return True
    except Exception as e:
        logger.error(f"Rule file verification failed: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True, help='Wazuh server host')
    parser.add_argument('--port', type=int, default=55000, help='Wazuh API port')
    parser.add_argument('--rule-file', help='Optional rule file to verify')
    parser.add_argument('--timeout', type=int, default=120, help='Timeout in seconds')
    args = parser.parse_args()
    
    # Verify rule file if provided
    if args.rule_file:
        if not verify_rule_file(args.rule_file):
            sys.exit(1)
    
    # Wait for manager to start
    logger.info(f"Waiting up to {args.timeout} seconds for Wazuh...")
    start_time = time.time()
    success = False
    
    while time.time() - start_time < args.timeout:
        if verify_wazuh_status(args.host, args.port):
            success = True
            break
        time.sleep(10)
    
    if success:
        logger.info("✅ Wazuh verification completed successfully!")
        sys.exit(0)
    else:
        logger.error("❌ Wazuh verification failed!")
        sys.exit(1)
