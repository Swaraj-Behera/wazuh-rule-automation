#!/usr/bin/env python3

import sys
import json
import logging
import argparse
import requests
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def verify_wazuh(host, port):
    try:
        base_url = f"https://{host}:{port}"
        session = requests.Session()
        session.verify = False
        
        # Check status
        status_url = f"{base_url}/manager/status"
        response = session.get(status_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            status = data.get('data', {}).get('status', 'unknown')
            version = data.get('data', {}).get('version', 'unknown')
            
            logger.info(f"📊 Wazuh version: {version}")
            logger.info(f"📊 Manager status: {status}")
            
            if status == 'running':
                logger.info("✅ Wazuh is running properly!")
                return True
        else:
            logger.error(f"❌ Status check failed: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Verification error: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=55000)
    args = parser.parse_args()
    
    sys.exit(0 if verify_wazuh(args.host, args.port) else 1)
