#!/usr/bin/env python3
"""Test script to verify Wazuh connection"""

import requests
import socket

def test_connection(host, port):
    """Test Wazuh API connection"""
    try:
        # Test port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result != 0:
            print(f"❌ Port {port} is closed")
            return False
            
        print(f"✅ Port {port} is open")
        
        # Test API
        url = f"https://{host}:{port}"
        response = requests.get(url, verify=False, timeout=10)
        print(f"✅ API response: {response.status_code}")
        return True
        
    except Exception as e:
        print(f"❌ Connection test failed: {e}")
        return False

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python test_wazuh_connection.py <host> <port>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    sys.exit(0 if test_connection(host, port) else 1)
