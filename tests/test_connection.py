#!/usr/bin/env python3
"""
Quick test script for Wazuh API connection
No installation required - runs from GitHub Actions
"""

import sys
import requests
import json

def test_api(host, port, user, password):
    """Test Wazuh API connectivity"""
    
    base_url = f"https://{host}:{port}"
    session = requests.Session()
    session.verify = False
    
    print(f"Testing connection to {base_url}")
    
    # Test 1: Basic connectivity
    try:
        response = session.get(f"{base_url}/", timeout=10)
        print(f"✅ API reachable: {response.status_code}")
    except Exception as e:
        print(f"❌ API not reachable: {e}")
        return False
    
    # Test 2: Authentication
    try:
        auth_url = f"{base_url}/security/user/authenticate"
        response = session.post(
            auth_url,
            json={"username": user, "password": password},
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ Authentication successful")
            token = response.json()['data']['token']
            session.headers.update({'Authorization': f'Bearer {token}'})
        else:
            print(f"❌ Authentication failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Authentication error: {e}")
        return False
    
    # Test 3: Manager status
    try:
        response = session.get(f"{base_url}/manager/status", timeout=10)
        if response.status_code == 200:
            data = response.json()
            status = data.get('data', {}).get('status', 'unknown')
            version = data.get('data', {}).get('version', 'unknown')
            print(f"✅ Manager status: {status}")
            print(f"✅ Wazuh version: {version}")
        else:
            print(f"❌ Status check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Status error: {e}")
        return False
    
    # Test 4: Rules API
    try:
        response = session.get(f"{base_url}/rules", timeout=10)
        if response.status_code == 200:
            data = response.json()
            total = len(data.get('data', {}).get('items', []))
            print(f"✅ Rules API working: {total} rules found")
        else:
            print(f"⚠️ Rules API returned: {response.status_code}")
    except Exception as e:
        print(f"⚠️ Rules API error: {e}")
    
    print("\n✅ All API tests passed!")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python test_connection.py <host> <port> <user> <password>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    user = sys.argv[3]
    password = sys.argv[4]
    
    sys.exit(0 if test_api(host, port, user, password) else 1)
