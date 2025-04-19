import requests
import time
import os
from datetime import datetime

def test_local_api():
    """Test if the local API is running and responsive"""
    base_url = "http://localhost:10000"
    print(f"Testing local API at {base_url}...")
    
    # Test health endpoint
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            print(f"✅ API health check successful")
            print(f"   Response: {response.json()}")
        else:
            print(f"❌ API health check failed with status code {response.status_code}")
            print(f"   Response: {response.text[:100]}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to API at {base_url}")
        print("   Is the API running? Try starting it with 'python attendance_api.py'")
        return False
    except Exception as e:
        print(f"❌ Error testing API health: {str(e)}")
        return False
    
    # Test scraper selection endpoint
    try:
        response = requests.get(f"{base_url}/api/debug/scraper-selection", timeout=5)
        if response.status_code == 200:
            print(f"✅ Scraper selection check successful")
            data = response.json()
            print(f"   Available scrapers: {data.get('available_scrapers', [])}")
            print(f"   Selected scraper: {data.get('selected_scraper', 'None')}")
        else:
            print(f"❌ Scraper selection check failed with status code {response.status_code}")
            print(f"   Response: {response.text[:100]}")
    except Exception as e:
        print(f"❌ Error testing scraper selection: {str(e)}")
    
    return True

def test_remote_scrapers():
    """Test if the configured scrapers are responsive"""
    scrapers = [
        "https://scraper-production-0be9.up.railway.app",
        "https://scraper-tl07.onrender.com"
    ]
    
    print("\nTesting remote scrapers...")
    for scraper in scrapers:
        try:
            start_time = time.time()
            response = requests.get(f"{scraper}/health", timeout=10)
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                print(f"✅ Scraper at {scraper} is healthy (response time: {elapsed:.2f}s)")
            else:
                print(f"❌ Scraper at {scraper} returned status code {response.status_code}")
        except requests.exceptions.Timeout:
            print(f"❌ Scraper at {scraper} timed out after 10 seconds")
        except requests.exceptions.ConnectionError:
            print(f"❌ Scraper at {scraper} connection error - service may be down")
        except Exception as e:
            print(f"❌ Scraper at {scraper} error: {str(e)}")

def main():
    """Run all tests"""
    print(f"API Test Utility - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    
    # Test local API
    api_ok = test_local_api()
    
    # If API is running, test scrapers
    if api_ok:
        test_remote_scrapers()
    
    print("\nTest completed.")

if __name__ == "__main__":
    main()
