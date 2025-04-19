import requests
import time
import sys
from datetime import datetime

def test_scraper(url):
    """Test if a scraper is responsive"""
    print(f"Testing scraper at {url}...")
    try:
        start_time = time.time()
        response = requests.get(f"{url}/health", timeout=10)
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            print(f"✅ Scraper at {url} is healthy (response time: {elapsed:.2f}s)")
            try:
                data = response.json()
                print(f"   Details: {data}")
            except:
                print(f"   Response: {response.text[:100]}")
            return True
        else:
            print(f"❌ Scraper at {url} returned status code {response.status_code}")
            print(f"   Response: {response.text[:100]}")
            return False
    except requests.exceptions.Timeout:
        print(f"❌ Scraper at {url} timed out after 10 seconds")
        return False
    except requests.exceptions.ConnectionError:
        print(f"❌ Scraper at {url} connection error - service may be down")
        return False
    except Exception as e:
        print(f"❌ Scraper at {url} error: {str(e)}")
        return False

def main():
    """Test all scrapers provided in arguments or use defaults"""
    print(f"Scraper Test Utility - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)
    
    # Use command line arguments or default scrapers
    if len(sys.argv) > 1:
        scrapers = sys.argv[1:]
    else:
        scrapers = [
            "https://scraper-production-0be9.up.railway.app",
            "https://scraper-tl07.onrender.com"
        ]
    
    results = []
    for scraper in scrapers:
        result = test_scraper(scraper)
        results.append((scraper, result))
    
    print("\nSummary:")
    print("-" * 50)
    healthy = sum(1 for _, result in results if result)
    print(f"Total scrapers tested: {len(results)}")
    print(f"Healthy scrapers: {healthy}")
    print(f"Unhealthy scrapers: {len(results) - healthy}")
    
    if healthy == 0:
        print("\n⚠️ WARNING: No healthy scrapers found!")
        print("Please check your scraper deployments and ensure they are running.")
    
if __name__ == "__main__":
    main()
