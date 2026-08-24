#!/usr/bin/env python3
"""
Wazuh Verification - API Only
"""

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

def verify_wazuh_status(host: str, port: int, user: str = None, password: str = None) -> bool:
    """Verify Wazuh via API only"""
    try:
        base_url = f"https://{host}:{port}"
        session = requests.Session()
        session.verify = False
        
        # Check API reachability
        logger.info(f"Checking API at {base_url}")
        response = session.get(f"{base_url}/", timeout=10)
        
        if response.status_code == 200:
            logger.info("✅ API is reachable")
        else:
            logger.error(f"❌ API returned: {response.status_code}")
            return False
        
        # Try authentication if credentials provided
        if user and password:
            auth_url = f"{base_url}/security/user/authenticate"
            auth_response = session.post(
                auth_url,
                json={"username": user, "password": password},
                timeout=10
            )
            
            if auth_response.status_code == 200:
                token = auth_response.json()['data']['token']
                session.headers.update({'Authorization': f'Bearer {token}'})
                logger.info("✅ Authentication successful")
            else:
                logger.warning(f"⚠️ Authentication failed: {auth_response.status_code}")
        
        # Check manager status
        status_url = f"{base_url}/manager/status"
        status_response = session.get(status_url, timeout=10)
        
        if status_response.status_code == 200:
            data = status_response.json()
            status = data.get('data', {}).get('status', 'unknown')
            version = data.get('data', {}).get('version', 'unknown')
            
            logger.info(f"📊 Wazuh version: {version}")
            logger.info(f"📊 Manager status: {status}")
            
            if status == 'running':
                logger.info("✅ Manager is running")
            else:
                logger.warning(f"⚠️ Manager status: {status}")
        
        # Check rules
        rules_url = f"{base_url}/rules"
        rules_response = session.get(rules_url, timeout=10)
        
        if rules_response.status_code == 200:
            rules_data = rules_response.json()
            total_rules = len(rules_data.get('data', {}).get('items', []))
            logger.info(f"📊 Total rules loaded: {total_rules}")
            logger.info("✅ Rules check passed")
            return True
        else:
            logger.error(f"❌ Rules check failed: {rules_response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        logger.error("❌ Connection refused - API may be down")
        return False
    except Exception as e:
        logger.error(f"❌ Verification error: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=55000)
    parser.add_argument('--user', help='API username (optional)')
    parser.add_argument('--password', help='API password (optional)')
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    
    logger.info(f"⏳ Verifying Wazuh at {args.host}:{args.port}")
    start_time = time.time()
    
    while time.time() - start_time < args.timeout:
        if verify_wazuh_status(args.host, args.port, args.user, args.password):
            logger.info("✅ Wazuh verification passed!")
            sys.exit(0)
        time.sleep(10)
    
    logger.error("❌ Wazuh verification failed!")
    sys.exit(1)
