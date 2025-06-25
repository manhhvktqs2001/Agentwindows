#!/usr/bin/env python3
"""
Test Server Connectivity
Simple test to check if the EDR server is accessible
"""

import asyncio
import aiohttp
import socket
import time

async def test_server_connectivity():
    """Test if the EDR server is accessible"""
    print("🧪 Testing Server Connectivity")
    print("=" * 40)
    
    # Test servers
    servers = [
        {'host': 'localhost', 'port': 5000, 'name': 'Local Server'},
        {'host': '127.0.0.1', 'port': 5000, 'name': 'Loopback Server'},
        {'host': '192.168.20.85', 'port': 5000, 'name': 'Configured Server'},
    ]
    
    for server in servers:
        print(f"\nTesting {server['name']} ({server['host']}:{server['port']})")
        
        # Test 1: TCP connection
        print("   🔌 Testing TCP connection...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((server['host'], server['port']))
            sock.close()
            
            if result == 0:
                print("   ✅ TCP connection successful")
            else:
                print(f"   ❌ TCP connection failed (error code: {result})")
                continue
        except Exception as e:
            print(f"   ❌ TCP connection error: {e}")
            continue
        
        # Test 2: HTTP health check
        print("   🌐 Testing HTTP health check...")
        try:
            timeout = aiohttp.ClientTimeout(total=3)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"http://{server['host']}:{server['port']}/health"
                async with session.get(url) as response:
                    if response.status == 200:
                        print("   ✅ HTTP health check successful")
                        data = await response.text()
                        print(f"   📄 Response: {data[:100]}...")
                    else:
                        print(f"   ⚠️ HTTP health check failed (status: {response.status})")
        except Exception as e:
            print(f"   ❌ HTTP health check error: {e}")
        
        # Test 3: API endpoint
        print("   🔗 Testing API endpoint...")
        try:
            timeout = aiohttp.ClientTimeout(total=3)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"http://{server['host']}:{server['port']}/api/v1/status"
                async with session.get(url) as response:
                    if response.status == 200:
                        print("   ✅ API endpoint accessible")
                        data = await response.json()
                        print(f"   📄 API Response: {data}")
                    else:
                        print(f"   ⚠️ API endpoint failed (status: {response.status})")
        except Exception as e:
            print(f"   ❌ API endpoint error: {e}")
    
    print("\n" + "=" * 40)
    print("✅ Connectivity test completed!")

if __name__ == "__main__":
    asyncio.run(test_server_connectivity()) 