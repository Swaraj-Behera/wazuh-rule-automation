#!/usr/bin/env python3

import sys
import json
import logging
import argparse
import requests
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def verify_wazuh_status(host: str, port: int) -> bool:
    """Verify Wazuh manager is running properly"""
    try:
        # Check basic connectivity
        base_url = f"https://{host}:{port}"
        logger.info(f"Checking Wazuh manager at {base_url}")
        
        # Check manager version
        version_url = f"{base_url}/manager/info"
        response = requests.get(version_url, verify=False, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            version = data.get('data', {}).get('version', 'unknown')
            logger.info(f"Wazuh manager version: {version}")
            
            # Check if rules are loaded
            rules_url = f"{base_url}/rules"
            rules_response = requests.get(rules_url, verify=False, timeout=10)
            
            if rules_response.status_code == 200:
                rules_data = rules_response.json()
                rule_count = len(rules_data.get('data', {}).get('items', []))
                logger.info(f"Loaded {rule_count} rules")
                return True
            else:
                logger.error(f"Rules check failed: {rules_response.text}")
                return False
        else:
            logger.error(f"Version check failed: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Verification error: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=55000)
    args = parser.parse_args()
    
    # Wait for restart to complete
    for i in range(12):  # 2 minutes
        logger.info(f"Waiting for Wazuh to start... ({i+1}/12)")
        if verify_wazuh_status(args.host, args.port):
            logger.info("Wazuh is running properly!")
            sys.exit(0)
        time.sleep(10)
    
    logger.error("Wazuh verification failed!")
    sys.exit(1)
