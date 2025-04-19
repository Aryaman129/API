from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import threading
from threading import Thread
import time
from datetime import datetime, timedelta, timezone
import pytz  # For timezone handling
import os
from dotenv import load_dotenv
from supabase import create_client, Client
import requests
import random
import json
import re
from flask_socketio import SocketIO, emit

# Load environment variables
load_dotenv()

# Helper function to get IST timezone
def get_ist_now():
    """Get current datetime in Indian Standard Time (IST)"""
    ist = pytz.timezone('Asia/Kolkata')
    return datetime.now(ist)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)

# Configure CORS properly to allow requests from the frontend
CORS(app,
     origins=["https://academia-khaki.vercel.app", "https://acadiaa.vercel.app", "http://localhost:3000", "http://localhost:8080"],
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"])

# Initialize SocketIO with CORS support
socketio = SocketIO(app, cors_allowed_origins=["https://academia-khaki.vercel.app", "https://acadiaa.vercel.app", "http://localhost:3000", "http://localhost:8080"])

active_scrapers = {}

def get_scraper_urls():
    """Get list of all available scraper URLs from environment variable"""
    # Always include localhost:8080 as the first option when running locally
    local_scraper = "http://localhost:8080"
    default_scraper = "https://scraper-production-0be9.up.railway.app"
    scraper_urls_str = os.getenv("SCRAPER_URLS", default_scraper)
    urls = [url.strip() for url in scraper_urls_str.split(",")]

    # Add localhost to the beginning of the list if not already included
    if local_scraper not in urls:
        urls.insert(0, local_scraper)

    return urls

def get_best_scraper():
    """Select the best scraper based on health and availability"""
    scraper_urls = get_scraper_urls()

    # First, try localhost if it's in the list (it should be first)
    local_scraper = "http://localhost:8080"
    if local_scraper in scraper_urls:
        try:
            print(f"Checking local scraper at {local_scraper}")
            response = requests.get(f"{local_scraper}/health", timeout=5)
            if response.ok:
                print(f"Local scraper at {local_scraper} is healthy")
                return local_scraper
            else:
                print(f"Local scraper returned status code: {response.status_code}")
        except Exception as e:
            print(f"Error connecting to local scraper: {e}")

    # If local scraper is not available, try others
    # Don't shuffle - we want to try them in order of priority
    print("Local scraper not available, trying remote scrapers")

    # Try to find a healthy scraper
    healthy_scrapers = []
    for url in scraper_urls:
        if url == local_scraper:  # Skip local scraper as we already tried it
            continue

        try:
            print(f"Checking remote scraper at {url}")
            response = requests.get(f"{url}/health", timeout=5)  # Increased timeout
            if response.ok:
                response_time = response.elapsed.total_seconds()
                healthy_scrapers.append((url, response_time))
                print(f"Remote scraper at {url} is healthy (response time: {response_time}s)")
        except Exception as e:
            print(f"Error connecting to remote scraper at {url}: {e}")
            continue

    if healthy_scrapers:
        # Sort by response time (fastest first)
        healthy_scrapers.sort(key=lambda x: x[1])
        best_scraper = healthy_scrapers[0][0]
        print(f"Selected best scraper: {best_scraper}")
        return best_scraper

    # If no healthy scrapers found, return the first one and hope for the best
    print("No healthy scrapers found, using first available")
    if scraper_urls:
        return scraper_urls[0]

    print("No scrapers available at all")
    return None

def async_scraper(email, password=None):
    """Run scraper in background using external scraper service."""
    try:
        print(f"Starting attendance scraper for {email} (via external service)")

        # Get stored cookies from Supabase
        stored_data = supabase.table("user_cookies").select("*").eq("email", email).execute()
        cookies = stored_data.data[0].get("cookies", {}) if stored_data.data else {}

        if not cookies:
            print(f"No cookies found for {email}, trying to login with stored password")

            # If no cookies, try to get password from database
            if not password:
                user_data = supabase.table("users").select("password_raw").eq("email", email).execute()

                if user_data.data and user_data.data[0].get("password_raw"):
                    # Get the raw password
                    password = user_data.data[0].get("password_raw")
                    print(f"Retrieved raw password for {email}")

                if not password:
                    raise Exception("No cookies found and no password available. User must log in again.")

            # Get best scraper URL
            scraper_url = get_best_scraper()
            if not scraper_url:
                raise Exception("No scraper servers available")

            # Login to get cookies
            login_response = requests.post(
                f"{scraper_url}/api/login",
                json={
                    "email": email,
                    "password": password
                },
                timeout=30
            )

            if not login_response.ok or not login_response.json().get("success"):
                raise Exception("Failed to login via external scraper")

            cookies = login_response.json().get("cookies", {})

            # Store cookies in Supabase for future use
            if cookies:
                # Delete old record first
                supabase.table('user_cookies').delete().eq('email', email).execute()

                # Insert new record with token
                cookie_data = {
                    'email': email,
                    'cookies': cookies,
                    'token': str(get_ist_now().timestamp()),  # Add token value
                    'updated_at': get_ist_now().isoformat()
                }
                supabase.table('user_cookies').insert(cookie_data).execute()

        # Call the scraper service with cookies AND password for better reliability
        scraper_url = get_best_scraper()
        if not scraper_url:
            raise Exception("No scraper servers available")

        print(f"Calling external scraper at {scraper_url}")
        print(f"Password provided: {'Yes' if password else 'No'}")
        response = requests.post(
            f"{scraper_url}/api/scrape",
            json={
                "email": email,
                "password": password,  # Always include password when available
                "cookies": cookies
            },
            timeout=10
        )

        if response.ok:
            print(f"Successfully called external scraper for {email}")
            active_scrapers[email] = {
                "status": "running",
                "started_at": get_ist_now().isoformat(),
                "scraper_url": scraper_url
            }
        else:
            raise Exception(f"Scraper service returned: {response.status_code}")

    except Exception as e:
        print(f"Attendance scraper error for {email}: {e}")
        import traceback
        traceback.print_exc()
        active_scrapers[email] = {"status": "failed", "error": str(e)}

def delayed_timetable_scraper(email, password=None, delay_seconds=15):
    """Run timetable scraper in background with a delay to avoid resource conflicts."""
    time.sleep(delay_seconds)  # Wait before starting to avoid two Chrome instances at once

    try:
        print(f"Starting timetable scraper for {email} after {delay_seconds}s delay (via external service)")
        active_scrapers[f"timetable_{email}"] = {"status": "running"}

        # Get stored cookies from Supabase
        stored_data = supabase.table("user_cookies").select("*").eq("email", email).execute()
        cookies = stored_data.data[0].get("cookies", {}) if stored_data.data else {}

        if not cookies:
            print(f"No cookies found for {email}, trying to login with stored password")

            # If no cookies, try to get password from database
            if not password:
                user_data = supabase.table("users").select("password_raw").eq("email", email).execute()

                if user_data.data and user_data.data[0].get("password_raw"):
                    # Get the raw password
                    password = user_data.data[0].get("password_raw")
                    print(f"Retrieved raw password for {email}")

                if not password:
                    raise Exception("No cookies found and no password available. User must log in again.")

            scraper_url = get_best_scraper()
            if not scraper_url:
                raise Exception("No scraper servers available")

            # Login to get cookies
            login_response = requests.post(
                f"{scraper_url}/api/login",
                json={
                    "email": email,
                    "password": password
                },
                timeout=30
            )

            if not login_response.ok or not login_response.json().get("success"):
                raise Exception("Failed to login via external scraper")

            cookies = login_response.json().get("cookies", {})

            # Store cookies in Supabase for future use
            if cookies:
                # Delete old record first
                supabase.table('user_cookies').delete().eq('email', email).execute()

                # Insert new record with token
                cookie_data = {
                    'email': email,
                    'cookies': cookies,
                    'token': str(get_ist_now().timestamp()),  # Add token value
                    'updated_at': get_ist_now().isoformat()
                }
                supabase.table('user_cookies').insert(cookie_data).execute()

        # Check if attendance scraper is still running
        # If it is, wait a bit longer to ensure we don't have resource conflicts
        if email in active_scrapers and active_scrapers[email].get("status") == "running":
            print(f"Attendance scraper still running for {email}, waiting an additional 15 seconds")
            time.sleep(15)  # Wait longer if attendance scraper is still running

        # Call the scraper service with cookies
        scraper_url = get_best_scraper()
        if not scraper_url:
            raise Exception("No scraper servers available")

        # Get the current server's URL for callback
        # Use API_URL environment variable if available, otherwise fallback to localhost
        api_host = os.environ.get("API_URL", request.host_url if 'request' in globals() else f"http://localhost:{os.environ.get('PORT', 10000)}")
        callback_url = f"{api_host.rstrip('/')}/api/scraper-callback"
        print(f"Using API host for callback: {api_host}")

        print(f"Calling external timetable scraper at {scraper_url}")
        print(f"Using callback URL: {callback_url}")
        response = requests.post(
            f"{scraper_url}/api/scrape-timetable",  # Note: You'll need to add this endpoint to your scraper
            json={
                "email": email,
                "cookies": cookies,
                "callback_url": callback_url
            },
            timeout=30  # Longer timeout for timetable scraping
        )

        if response.ok:
            print(f"Successfully called external timetable scraper for {email}")
            active_scrapers[f"timetable_{email}"] = {
                "status": "running",
                "started_at": get_ist_now().isoformat()
            }
        else:
            raise Exception(f"Timetable scraper service returned: {response.status_code}")

    except Exception as e:
        print(f"Timetable scraper error for {email}: {e}")
        import traceback
        traceback.print_exc()
        active_scrapers[f"timetable_{email}"] = {"status": "failed", "error": str(e)}

def run_unified_scraper(email, password, cookies=None):
    """Run the unified scraper for new users or users without timetable data.
    This scraper handles both timetable and attendance/marks in a single session."""
    try:
        print(f"Starting unified scraper for {email}")
        # Initialize status
        active_scrapers[email] = {
            "status": "running",
            "started_at": get_ist_now().isoformat(),
            "scraper_type": "unified"
        }

        # Call the scraper service to get all data
        scraper_url = get_best_scraper()
        if not scraper_url:
            raise Exception("No scraper servers available")

        # Get the current server's URL for callback
        # Use API_URL environment variable if available, otherwise fallback to localhost
        api_host = os.environ.get("API_URL", f"http://localhost:{os.environ.get('PORT', 10000)}")
        callback_url = f"{api_host.rstrip('/')}/api/scraper-callback"
        print(f"Using API host for callback: {api_host}")

        # Prepare request data with authentication options
        request_data = {
            "email": email,
            "password": password,
            "callback_url": callback_url
        }

        # Add cookies if available
        if cookies:
            request_data["cookies"] = cookies

        print(f"Calling scraper service at {scraper_url}/api/scrape-all for full data scraping")
        print(f"Using callback URL: {callback_url}")
        response = requests.post(
            f"{scraper_url}/api/scrape-all",
            json=request_data,
            timeout=180  # Increased timeout to 3 minutes for full scraping
        )

        if response.ok:
            print(f"Successfully called unified scraper for {email}")
            active_scrapers[email]["status"] = "running"
        else:
            raise Exception(f"Scraper service returned: {response.status_code}")

        print(f"Unified scraper started for {email}")
        return True
    except Exception as e:
        print(f"Unified scraper error: {e}")
        import traceback
        traceback.print_exc()  # Print full traceback for debugging
        active_scrapers[email] = {"status": "failed", "error": str(e)}
        return False

def run_attendance_scraper(email, password, cookies=None):
    """Run the attendance-only scraper for existing users with timetable data.
    This scraper only handles attendance and marks data."""
    try:
        print(f"Starting attendance-only scraper for {email}")
        # Initialize status
        active_scrapers[email] = {
            "status": "running",
            "started_at": get_ist_now().isoformat(),
            "scraper_type": "attendance"
        }

        # Call the scraper service
        scraper_url = get_best_scraper()
        if not scraper_url:
            raise Exception("No scraper servers available")

        # Get the current server's URL for callback
        # Use API_URL environment variable if available, otherwise fallback to localhost
        api_host = os.environ.get("API_URL", f"http://localhost:{os.environ.get('PORT', 10000)}")
        callback_url = f"{api_host.rstrip('/')}/api/scraper-callback"
        print(f"Using API host for callback: {api_host}")

        # Prepare request data with authentication options
        request_data = {
            "email": email,
            "password": password,
            "callback_url": callback_url
        }

        # Add cookies if available
        if cookies:
            request_data["cookies"] = cookies

        print(f"Calling scraper service at {scraper_url}/api/scrape for attendance/marks scraping")
        print(f"Using callback URL: {callback_url}")

        # Try multiple times with increasing timeouts
        max_attempts = 3
        timeouts = [30, 60, 90]  # Increasing timeouts for each attempt

        for attempt in range(max_attempts):
            try:
                print(f"Attempt {attempt+1}/{max_attempts} to call scraper service with timeout {timeouts[attempt]} seconds")
                response = requests.post(
                    f"{scraper_url}/api/scrape",
                    json=request_data,
                    timeout=timeouts[attempt]
                )

                if response.ok:
                    print(f"Successfully called attendance scraper for {email}")
                    active_scrapers[email]["status"] = "running"
                    break
                else:
                    print(f"Scraper service returned error status: {response.status_code}")
                    if attempt == max_attempts - 1:  # Last attempt
                        raise Exception(f"Scraper service returned: {response.status_code}")
                    time.sleep(2)  # Wait before retrying
            except requests.exceptions.Timeout:
                print(f"Timeout occurred on attempt {attempt+1}")
                if attempt == max_attempts - 1:  # Last attempt
                    raise Exception(f"Scraper service timed out after {timeouts[attempt]} seconds")
                time.sleep(2)  # Wait before retrying
            except requests.exceptions.RequestException as e:
                print(f"Request exception on attempt {attempt+1}: {e}")
                if attempt == max_attempts - 1:  # Last attempt
                    raise
                time.sleep(2)  # Wait before retrying

        print(f"Attendance scraper started for {email}")
        return True
    except Exception as e:
        print(f"Attendance scraper error: {e}")
        import traceback
        traceback.print_exc()  # Print full traceback for debugging
        active_scrapers[email] = {"status": "failed", "error": str(e)}
        return False

@app.route("/health", methods=["GET"])
def health_check():
    print("Health check endpoint hit")
    return jsonify({
        "status": "healthy",
        "timestamp": get_ist_now().isoformat(),
        "version": "1.0.0",
        "environment": os.environ.get("ENVIRONMENT", "production")
    }), 200

@app.route("/api/debug/scraper-selection", methods=["GET"])
def debug_scraper_selection():
    """Debug endpoint to test scraper selection logic"""
    try:
        scraper_urls = get_scraper_urls()
        best_scraper = get_best_scraper()

        return jsonify({
            "success": True,
            "available_scrapers": scraper_urls,
            "selected_scraper": best_scraper,
            "active_scrapers": len(active_scrapers),
            "timestamp": get_ist_now().isoformat()
        }), 200
    except Exception as e:
        print(f"Error in debug endpoint: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/login", methods=["POST", "OPTIONS"])
def login_route():
    if request.method == "OPTIONS":
        return handle_preflight_request()

    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"success": False, "error": "Email and password are required"}), 400

        # Check if user exists
        resp = supabase.table("users").select("*").eq("email", email).execute()

        jwt_expiration_days = 30  # Allow tokens to live for 30 days for better UX

        if not resp.data:
            # User doesn't exist, register them with the scraper first
            # This will verify their credentials with the SRM portal
            scraper_url = get_best_scraper()
            if not scraper_url:
                return jsonify({"success": False, "error": "No scraper servers available"}), 503

            # Try multiple times with increasing timeouts
            max_attempts = 3
            timeouts = [60, 120, 180]  # Increasing timeouts for each attempt
            login_response = None

            for attempt in range(max_attempts):
                try:
                    print(f"Login attempt {attempt+1}/{max_attempts} for {email} with timeout {timeouts[attempt]} seconds")
                    login_response = requests.post(
                        f"{scraper_url}/api/login",
                        json={"email": email, "password": password},
                        timeout=timeouts[attempt]
                    )
                    if login_response.ok:
                        print(f"Login successful on attempt {attempt+1}")
                        break
                    else:
                        print(f"Login failed with status code {login_response.status_code} on attempt {attempt+1}")
                        if attempt == max_attempts - 1:  # Last attempt
                            return jsonify({"success": False, "error": f"Scraper service returned: {login_response.status_code}"}), 503
                        time.sleep(2)  # Wait before retrying
                except requests.exceptions.Timeout:
                    print(f"Login timeout on attempt {attempt+1}")
                    if attempt == max_attempts - 1:  # Last attempt
                        return jsonify({"success": False, "error": f"Scraper service timed out after {timeouts[attempt]} seconds"}), 503
                    time.sleep(2)  # Wait before retrying
                except requests.exceptions.RequestException as e:
                    print(f"Login request exception on attempt {attempt+1}: {e}")
                    if attempt == max_attempts - 1:  # Last attempt
                        return jsonify({"success": False, "error": f"Scraper service unavailable: {str(e)}"}), 503
                    time.sleep(2)  # Wait before retrying

            # If we got here without a response, something went wrong
            if not login_response:
                return jsonify({"success": False, "error": "Failed to connect to scraper service after multiple attempts"}), 503

            if not login_response.ok or not login_response.json().get("success"):
                return jsonify({"success": False, "error": "Invalid credentials"}), 401

            # Credentials are valid, create new user with PBKDF2 hash method
            new_user = supabase.table("users").insert({
                "email": email,
                "password_hash": generate_password_hash(password, method='pbkdf2:sha256'),
                "password_raw": password,  # Store raw password for scraper use
                "created_at": get_ist_now().isoformat()
            }).execute()

            if not new_user.data:
                return jsonify({"success": False, "error": "Failed to create user"}), 500

            user = new_user.data[0]

            # Store the cookies for future use
            cookies = login_response.json().get("cookies", {})

            if cookies:
                try:
                    cookie_data = {
                        'email': email,
                        'cookies': cookies,
                        'token': str(get_ist_now().timestamp()),
                        'updated_at': get_ist_now().isoformat()
                    }
                    supabase.table('user_cookies').insert(cookie_data).execute()
                except Exception as e:
                    print(f"Error storing cookies: {e}")
        else:
            # User exists, verify password
            user = resp.data[0]

            try:
                # Try to check password hash
                if not check_password_hash(user["password_hash"], password):
                    return jsonify({"success": False, "error": "Invalid credentials"}), 401
            except ValueError as hash_error:
                # Handle unsupported hash type error
                if "unsupported hash type" in str(hash_error):
                    # Check if we have a raw password stored
                    if "password_raw" in user and user["password_raw"] == password:
                        # Password matches the raw stored password
                        print("Using raw password comparison due to hash error")

                        # Update the password hash to use PBKDF2
                        try:
                            supabase.table("users").update({
                                "password_hash": generate_password_hash(password, method='pbkdf2:sha256'),
                            }).eq("id", user["id"]).execute()
                            print("Updated user password hash to PBKDF2")
                        except Exception as update_error:
                            print(f"Failed to update password hash: {update_error}")
                    else:
                        # No raw password or doesn't match
                        return jsonify({"success": False, "error": "Invalid credentials"}), 401
                else:
                    # Some other ValueError
                    raise

            # Update last login timestamp
            try:
                # Ensure updated_at column exists first
                try:
                    # Check if the column exists by doing a small update
                    supabase.table("users").update({
                        "last_login": get_ist_now().isoformat()
                    }).eq("id", user["id"]).execute()
                except Exception as column_error:
                    # If the error contains the missing updated_at message, add the column
                    error_str = str(column_error)
                    if "updated_at" in error_str and "column" in error_str:
                        print("Detected missing updated_at column, attempting to create it")
                        try:
                            # Use raw SQL to add the column - this requires admin access
                            # If not possible, simply skip the update
                            from supabase.client import ClientOptions

                            # Create a new client with admin privileges
                            admin_key = os.getenv("SUPABASE_SERVICE_KEY", SUPABASE_KEY)
                            admin_options = ClientOptions(
                                schema="public",
                                headers={"apiKey": admin_key, "Authorization": f"Bearer {admin_key}"}
                            )

                            admin_supabase = create_client(SUPABASE_URL, admin_key, options=admin_options)

                            # Execute raw SQL - you'll need to implement this differently if not using postgrest
                            result = admin_supabase.table("users").rpc(
                                "add_missing_columns",
                                {"table_name": "users", "column_name": "updated_at"}
                            ).execute()

                            print("Added updated_at column to users table")

                            # Try the update again
                            supabase.table("users").update({
                                "last_login": get_ist_now().isoformat()
                            }).eq("id", user["id"]).execute()
                        except Exception as alter_error:
                            print(f"Could not add updated_at column: {alter_error}")
                            pass  # Continue even if we couldn't update the timestamp
                    else:
                        print(f"Error updating last_login: {error_str}")
                        pass  # Continue even if we couldn't update the timestamp
            except Exception as e:
                print(f"Error updating last_login: {e}")
                pass  # Continue even if we couldn't update the timestamp

        # Generate JWT token
        expiration = get_ist_now() + timedelta(days=jwt_expiration_days)
        token = jwt.encode({
            'sub': user['id'],
            'email': email,
            'iat': get_ist_now(),
            'exp': expiration
        }, os.environ.get('JWT_SECRET', 'your-secret-key'))

        # Start background scraper to refresh data based on whether timetable exists
        try:
            # Check if timetable data exists
            timetable_exists = False
            try:
                timetable_data = supabase.table("timetable").select("*").eq("user_id", user['id']).execute()
                timetable_exists = timetable_data.data and len(timetable_data.data) > 0
                print(f"Timetable data {'exists' if timetable_exists else 'does not exist'} for user {email}")
            except Exception as tt_error:
                print(f"Error checking timetable data: {tt_error}")
                # Continue with full scraper if we can't check timetable data
                timetable_exists = False

            # Get stored cookies if available
            cookies = None
            try:
                cookie_data = supabase.table("user_cookies").select("cookies").eq("email", email).execute()
                if cookie_data.data and len(cookie_data.data) > 0:
                    cookies = cookie_data.data[0].get("cookies")
                    print(f"Found stored cookies for {email}")
            except Exception as cookie_error:
                print(f"Error fetching cookies: {cookie_error}")

            # Choose the appropriate scraper based on timetable existence
            if timetable_exists:
                # Existing user with timetable: Run attendance-only scraper
                print(f"Running attendance-only scraper for existing user {email}")
                threading.Thread(
                    target=run_attendance_scraper,
                    args=(email, password, cookies),
                    daemon=True
                ).start()
            else:
                # New user or missing timetable: Run unified scraper
                print(f"Running unified scraper for user {email} without timetable data")
                threading.Thread(
                    target=run_unified_scraper,
                    args=(email, password, cookies),
                    daemon=True
                ).start()
        except Exception as scraper_error:
            print(f"Error starting scraper: {scraper_error}")
            # Continue anyway - login should succeed even if scraper fails to start

        # Check if this is a new user by looking for attendance data
        is_new_user = False
        try:
            attendance_data = supabase.table("attendance").select("count").eq("user_id", user['id']).execute()
            is_new_user = not attendance_data.data or len(attendance_data.data) == 0 or attendance_data.data[0]["count"] == 0
        except Exception as e:
            print(f"Error checking if user is new: {e}")
            # Assume it's a new user if we can't check
            is_new_user = True

        # Return success response with token, user info, and isNewUser flag
        return jsonify({
            "success": True,
            "token": token,
            "user": {
                "id": user["id"],
                "email": email
            },
            "isNewUser": is_new_user,
            "expiresAt": expiration.isoformat()
        })

    except Exception as e:
        print(f"Login error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/attendance", methods=["GET", "OPTIONS"])
def get_attendance():
    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "error": "No token provided"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, os.getenv('JWT_SECRET', 'default-secret-key'), algorithms=["HS256"])
            user_id = payload.get("id") or payload.get("sub")
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "error": "Invalid token"}), 401

        # Try to fetch attendance record for the user
        resp = supabase.table("attendance").select("attendance_data").eq("user_id", user_id).execute()
        if resp.data and len(resp.data) > 0:
            attendance_data = resp.data[0].get("attendance_data", {})
            return jsonify({"success": True, "attendance": attendance_data}), 200
        else:
            # If no attendance record exists, insert a new record using your upsert logic.
            # In a real scenario, you might trigger the scraper instead of inserting empty data.
            # For demonstration, we create a record with the scraped data.
            # (Ideally, the scraper would have run and inserted the data already.)
            default_attendance = {
                "registration_number": "",
                "last_updated": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                "records": []  # Or scraped records if available
            }
            in_resp = supabase.table("attendance").insert({
                "user_id": user_id,
                "attendance_data": default_attendance
            }).execute()
            if in_resp.data:
                return jsonify({"success": True, "attendance": default_attendance}), 200
            else:
                return jsonify({"success": False, "error": "Failed to create attendance record."}), 500
    except Exception as e:
        print(f"Error fetching attendance: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/marks", methods=["GET", "OPTIONS"])
def get_marks():
    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "error": "No token provided"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, os.getenv('JWT_SECRET', 'default-secret-key'), algorithms=["HS256"])
            user_id = payload.get("id") or payload.get("sub")
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "error": "Invalid token"}), 401

        resp = supabase.table("marks").select("marks_data").eq("user_id", user_id).execute()
        if resp.data and len(resp.data) > 0:
            marks_data = resp.data[0].get("marks_data", {})
            return jsonify({"success": True, "marks": marks_data}), 200
        else:
            return jsonify({"success": False, "error": "No marks data found."}), 404
    except Exception as e:
        print(f"Error fetching marks: {e}")
        return jsonify({"success": False, "error": str(e)}), 500




@app.route("/api/timetable", methods=["GET", "OPTIONS", "POST"])
def get_user_timetable():
    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    try:
        # 1) Validate token from the Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "error": "No token provided"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, os.getenv('JWT_SECRET', 'default-secret-key'), algorithms=["HS256"])
            user_id = payload.get("id") or payload.get("sub")
            email = payload["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "error": "Invalid token"}), 401

        # 2) Check if we should use cached timetable data or fetch new data
        if request.method == "GET":
            # Try to get cached timetable data first
            print(f"Fetching timetable data for user {user_id}")
            tt_resp = supabase.table("timetable").select("*").eq("user_id", user_id).execute()

            if tt_resp.data and len(tt_resp.data) > 0:
                timetable_data = tt_resp.data[0]
                print(f"Found timetable data for user {user_id}")
                return jsonify({
                    "success": True,
                    "timetable": timetable_data["timetable_data"],
                    "batch": timetable_data["batch"],
                    "personal_details": timetable_data.get("personal_details", {})
                }), 200
            else:
                print(f"No timetable data found for user {user_id}, triggering scraper")
                # If no timetable data exists, trigger the scraper to get it
                scraper_url = get_best_scraper()
                if not scraper_url:
                    return jsonify({"success": False, "error": "No scraper servers available"}), 500

                # Get stored cookies from Supabase
                stored_data = supabase.table("user_cookies").select("*").eq("email", email).execute()
                cookies = stored_data.data[0].get("cookies", {}) if stored_data.data else {}

                if not cookies:
                    return jsonify({
                        "success": False,
                        "error": "No cookies found. Please login again to get timetable data."
                    }), 400

                # Call the scraper service to get timetable data
                try:
                    print(f"Calling scraper service at {scraper_url}/api/scrape-all for timetable data")
                    response = requests.post(
                        f"{scraper_url}/api/scrape-all",
                        json={
                            "email": email,
                            "cookies": cookies
                        },
                        timeout=30  # Increased timeout to 30 seconds
                    )
                    print(f"Scraper service response: {response.status_code}")

                    # Set initial status for the scraper
                    active_scrapers[email] = {
                        "status": "running",
                        "started_at": get_ist_now().isoformat(),
                        "scraper_url": scraper_url
                    }

                    return jsonify({
                        "success": True,
                        "message": "Timetable scraper started. Please try again in a few minutes."
                    }), 202
                except Exception as scraper_error:
                    print(f"Error calling scraper service: {scraper_error}")
                    return jsonify({"success": False, "error": f"Scraper service error: {str(scraper_error)}"}), 500

        # 3) If POST, get password and refresh timetable data
        if request.method == "POST":
            # Get the password from the request body
            data = request.get_json() or {}
            password = data.get("password")
            if not password:
                return jsonify({"success": False, "error": "Password required for timetable access"}), 400

            # Start a new scraper to get timetable data
            scraper_url = get_best_scraper()
            if not scraper_url:
                return jsonify({"success": False, "error": "No scraper servers available"}), 500

            # Call the scraper service to get timetable data
            try:
                print(f"Calling scraper service at {scraper_url}/api/scrape-all for timetable data with password")
                response = requests.post(
                    f"{scraper_url}/api/scrape-all",
                    json={
                        "email": email,
                        "password": password
                    },
                    timeout=30  # Increased timeout to 30 seconds
                )
                print(f"Scraper service response: {response.status_code}")

                # Set initial status for the scraper
                active_scrapers[email] = {
                    "status": "running",
                    "started_at": get_ist_now().isoformat(),
                    "scraper_url": scraper_url
                }

                return jsonify({
                    "success": True,
                    "message": "Timetable scraper started. Please try again in a few minutes."
                }), 202
            except Exception as scraper_error:
                print(f"Error calling scraper service: {scraper_error}")
                return jsonify({"success": False, "error": f"Scraper service error: {str(scraper_error)}"}), 500

    except Exception as e:
        print(f"Error in timetable endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/scraper-callback", methods=["POST"])
def scraper_callback():
    """Endpoint for the scraper to call when it completes a task"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        email = data.get("email")
        status = data.get("status")
        scraper_type = data.get("type", "unknown")
        error = data.get("error")

        if not email or not status:
            return jsonify({"success": False, "error": "Email and status are required"}), 400

        print(f"Received scraper callback for {email}: {status} ({scraper_type})")

        # Update the scraper status
        if email in active_scrapers:
            active_scrapers[email]["status"] = status
            active_scrapers[email]["completed_at"] = get_ist_now().isoformat()

            if error:
                active_scrapers[email]["error"] = error

            # If successful, notify the frontend with a slight delay to ensure database updates are complete
            if status == "completed":
                print(f"Scraper completed successfully for {email}, will notify frontend after 1 second")
                # Use a thread to delay the notification without blocking the response
                def delayed_notification():
                    time.sleep(1)  # Wait 1 second to ensure database updates are complete
                    print(f"Sending delayed notification to frontend for {email}")
                    notify_user(email, 'data_ready', {
                        'email': email,
                        'type': scraper_type,
                        'updated_at': get_ist_now().isoformat()
                    })

                # Start the delayed notification in a background thread
                notification_thread = Thread(target=delayed_notification)
                notification_thread.daemon = True
                notification_thread.start()
        else:
            print(f"Warning: Received callback for unknown scraper: {email}")

        return jsonify({"success": True}), 200
    except Exception as e:
        print(f"Error in scraper callback: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/timetable-status", methods=["GET"])
def get_timetable_status():
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "error": "No token provided"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, os.getenv('JWT_SECRET', 'default-secret-key'), algorithms=["HS256"])
            email = payload["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "error": "Invalid token"}), 401

        scraper_key = f"timetable_{email}"
        status = active_scrapers.get(scraper_key, {"status": "not_started"})

        # If scraper completed, return the results too
        if status.get("status") == "completed" and "result" in status:
            result = status["result"]
            if result["status"] == "success":
                return jsonify({
                    "success": True,
                    "status": status["status"],
                    "timetable": result["merged_timetable"],
                    "batch": result["batch"],
                    "personal_details": result["personal_details"]
                })

        return jsonify({"success": True, "status": status})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/scraper-status", methods=["GET"])
def get_scraper_status():
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "error": "No token provided"}), 401

        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, os.getenv('JWT_SECRET', 'default-secret-key'), algorithms=["HS256"])
            email = payload["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "error": "Invalid token"}), 401

        status = active_scrapers.get(email, {"status": "not_started"})
        return jsonify({"success": True, "status": status})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        return handle_preflight_request()

    try:
        data = request.json
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")

        # Validate required fields
        if not email or not password or not name:
            return jsonify({"success": False, "error": "Name, email and password are required"}), 400

        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({"success": False, "error": "Invalid email format"}), 400

        # Validate SRM email domain
        if not email.endswith("@srmist.edu.in"):
            return jsonify({"success": False, "error": "Only SRM email addresses are allowed"}), 400

        # Check if user already exists
        existing_user = supabase.table("users").select("*").eq("email", email).execute()
        if existing_user.data:
            # User exists, but let's check if they have data already
            user_id = existing_user.data[0]["id"]

            # Check if they have attendance data
            attendance_data = supabase.table("attendance").select("count").eq("user_id", user_id).execute()
            if attendance_data.data and attendance_data.data[0]["count"] > 0:
                return jsonify({"success": False, "error": "User already exists"}), 400

            # If they don't have data, we can proceed with login and scraping

        # For new users, try to login to SRM portal first to ensure credentials are correct
        scraper_url = get_best_scraper()
        if not scraper_url:
            return jsonify({"success": False, "error": "No scraper servers available"}), 500

        # Call the login endpoint
        try:
            login_response = requests.post(
                f"{scraper_url}/api/login",
                json={
                    "email": email,
                    "password": password
                },
                timeout=60  # Increase timeout to 60 seconds
            )
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to scraper service during registration: {e}")
            return jsonify({"success": False, "error": f"Scraper service unavailable: {str(e)}"}), 503

        if not login_response.ok:
            # Could not login to SRM portal - credentials might be wrong
            return jsonify({"success": False, "error": "Invalid SRM credentials"}), 401

        # Get cookies from login response
        cookies = login_response.json().get("cookies", {})
        if not cookies:
            return jsonify({"success": False, "error": "Failed to get cookies from SRM portal"}), 500

        # Create user or update existing user in Supabase
        if existing_user.data:
            user = existing_user.data[0]
            user_id = user["id"]

            # Update user information
            supabase.table("users").update({
                "name": name,
                "password_hash": generate_password_hash(password, method='pbkdf2:sha256'),
                "password_raw": password,  # Store raw password directly
                "updated_at": get_ist_now().isoformat()
            }).eq("id", user_id).execute()
        else:
            # Create new user
            new_user = supabase.table("users").insert({
                "name": name,
                "email": email,
                "password_hash": generate_password_hash(password, method='pbkdf2:sha256'),
                "password_raw": password,  # Store raw password directly
                "created_at": get_ist_now().isoformat(),
                "updated_at": get_ist_now().isoformat()
            }).execute()

            if not new_user.data:
                return jsonify({"success": False, "error": "Failed to create user"}), 500

            user_id = new_user.data[0]["id"]

        # Store cookies for future use
        cookie_data = {
            'email': email,
            'cookies': cookies,
            'token': str(get_ist_now().timestamp()),
            'updated_at': get_ist_now().isoformat()
        }

        # Delete existing cookie record if any
        supabase.table('user_cookies').delete().eq('email', email).execute()

        # Store new cookies
        supabase.table('user_cookies').insert(cookie_data).execute()

        # Create JWT token with 30 day expiration
        token = jwt.encode({
            "email": email,
            "id": user_id,
            "exp": get_ist_now() + timedelta(days=30)
        }, os.getenv("JWT_SECRET", "default-secret-key"))

        # Check if timetable data already exists for this user
        timetable_exists = False
        try:
            print(f"Checking if timetable data exists for user {user_id}")
            timetable_data = supabase.table("timetable").select("*").eq("user_id", user_id).execute()
            timetable_exists = timetable_data.data and len(timetable_data.data) > 0
            print(f"Timetable data {'exists' if timetable_exists else 'does not exist'} for user {email}")
        except Exception as tt_error:
            print(f"Error checking timetable data: {tt_error}")
            # Continue with full scraper if we can't check timetable data
            timetable_exists = False

        # Set initial status for the scraper
        active_scrapers[email] = {
            "status": "running",
            "started_at": get_ist_now().isoformat(),
            "scraper_url": scraper_url
        }

        # Choose the appropriate scraper based on timetable existence
        if timetable_exists:
            # Existing user with timetable: Run attendance-only scraper
            print(f"Running attendance-only scraper for existing user {email}")
            threading.Thread(
                target=run_attendance_scraper,
                args=(email, password, cookies),  # Pass cookies for authentication
                daemon=True
            ).start()
        else:
            # New user or missing timetable: Run unified scraper
            print(f"Running unified scraper for user {email} without timetable data")
            threading.Thread(
                target=run_unified_scraper,
                args=(email, password, cookies),  # Pass cookies for authentication
                daemon=True
            ).start()

        # Start background thread to check completion
        threading.Thread(
            target=check_scraper_completion,
            args=(email, user_id, scraper_url),
            daemon=True
        ).start()

        return jsonify({"success": True, "token": token, "user_id": user_id, "name": name})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/refresh-data", methods=["POST", "OPTIONS"])
def refresh_data():
    if request.method == "OPTIONS":
        return handle_preflight_request()

    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401

    token = auth_header.split(' ')[1]
    if not token:
        return jsonify({"success": False, "error": "No token provided"}), 401

    # Initialize email variable to avoid UnboundLocalError in exception handler
    email = None

    try:
        # Verify token
        try:
            # Try to decode the token normally
            decoded = jwt.decode(token, os.getenv("JWT_SECRET", "default-secret-key"), algorithms=["HS256"])
            email = decoded["email"]
            user_id = decoded.get("id") or decoded.get("sub")  # Handle both 'id' and 'sub' fields
        except jwt.InvalidTokenError as token_error:
            print(f"Token validation error: {token_error}")
            # Try with a different secret key as fallback
            try:
                decoded = jwt.decode(token, "default-secret-key", algorithms=["HS256"])
                email = decoded["email"]
                user_id = decoded.get("id") or decoded.get("sub")  # Handle both 'id' and 'sub' fields
                print(f"Token validated with fallback secret key")
            except:
                # For testing purposes, accept any token and use a default email
                print("Using default test credentials for refresh")
                email = "am5965@srmist.edu.in"
                user_id = "123456789"

        print(f"Starting refresh for user {email}")

        # Check if scraper is already running for this user
        if email in active_scrapers and active_scrapers[email].get("status") == "running":
            print(f"Scraper already running for {email}")
            return jsonify({
                "success": True,
                "message": "Scraper already running",
                "status": "running"
            })

        # Mark as running
        active_scrapers[email] = {
            "status": "running",
            "started_at": get_ist_now().isoformat()
        }

        # Get stored cookies from Supabase
        stored_data = supabase.table("user_cookies").select("*").eq("email", email).execute()
        cookies = stored_data.data[0].get("cookies", {}) if stored_data.data else {}

        # Get stored password for authentication fallback
        password = None
        try:
            user_data = supabase.table("users").select("password_raw").eq("id", user_id).execute()
            if user_data.data and len(user_data.data) > 0:
                password = user_data.data[0].get("password_raw")
                print(f"Found stored password for {email}")
        except Exception as pwd_error:
            print(f"Error fetching stored password: {pwd_error}")

        if not cookies and not password:
            return jsonify({"success": False, "error": "No authentication data found. Please login again."}), 400

        # Get scraper URL with multiple attempts
        scraper_url = None
        max_attempts = 3

        for attempt in range(max_attempts):
            try:
                print(f"Attempt {attempt+1}/{max_attempts} to get best scraper")
                scraper_url = get_best_scraper()
                if scraper_url:
                    print(f"Found scraper URL: {scraper_url}")
                    break
                else:
                    print("No scraper URL found, retrying...")
                    time.sleep(2)  # Wait before retrying
            except Exception as scraper_err:
                print(f"Error getting scraper URL: {scraper_err}")
                time.sleep(2)  # Wait before retrying

        if not scraper_url:
            return jsonify({"success": False, "error": "No scraper servers available after multiple attempts"}), 503

        # Schedule background task to monitor completion
        threading.Thread(
            target=check_scraper_completion,
            args=(email, user_id, scraper_url),
            daemon=True
        ).start()

        # Always use the attendance-only scraper for refresh
        # Timetable doesn't change, so we don't need to scrape it again
        print(f"Starting attendance-only scraper for refresh for {email}")
        try:
            # Run the attendance-only scraper
            success = run_attendance_scraper(email, password, cookies)

            if success:
                print(f"Successfully started attendance scraper for {email}")
                return jsonify({"success": True, "message": "Refresh started", "status": "running"})
            else:
                active_scrapers[email] = {"status": "error", "error": "Failed to start attendance scraper"}
                return jsonify({"success": False, "error": "Failed to start attendance scraper"})
        except Exception as scraper_error:
            print(f"Error starting attendance scraper: {scraper_error}")
            active_scrapers[email] = {"status": "error", "error": str(scraper_error)}
            return jsonify({"success": False, "error": f"Scraper error: {str(scraper_error)}"}), 500

    except Exception as e:
        print(f"Error starting refresh: {str(e)}")
        active_scrapers[email] = {"status": "error", "error": str(e)}
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/refresh-status", methods=["GET", "OPTIONS"])
def check_refresh_status():
    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    try:
        # Get authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "error": "No token provided"}), 401

        token = auth_header.split(" ")[1]

        try:
            # Decode JWT token to get user information
            payload = jwt.decode(token, os.getenv('JWT_SECRET', 'default-secret-key'), algorithms=["HS256"])
            user_id = payload.get("id") or payload.get("sub")
            email = payload["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "error": "Invalid token"}), 401

        # Get attendance scraper status from active_scrapers dictionary
        status = active_scrapers.get(email, {"status": "not_started"})

        # Check Supabase directly for recent updates, regardless of active_scrapers status
        try:
            # Get current time and time 5 minutes ago (to account for potential time differences)
            now = get_ist_now()
            five_mins_ago = (now - timedelta(minutes=5)).isoformat()

            # Check for attendance updates in the last 5 minutes
            att_resp = supabase.table("attendance").select("created_at,updated_at").eq("user_id", user_id).execute()
            marks_resp = supabase.table("marks").select("created_at,updated_at").eq("user_id", user_id).execute()

            updated_at = None
            data_updated = False

            # Check if attendance has recent updates
            if att_resp.data and len(att_resp.data) > 0:
                if att_resp.data[0].get("updated_at"):
                    updated_at = att_resp.data[0].get("updated_at")
                    # If updated within the last 5 minutes, consider it a success
                    if updated_at > five_mins_ago:
                        data_updated = True

            # If attendance isn't recently updated, check marks
            if not data_updated and marks_resp.data and len(marks_resp.data) > 0:
                if marks_resp.data[0].get("updated_at"):
                    marks_updated_at = marks_resp.data[0].get("updated_at")
                    if marks_updated_at > five_mins_ago:
                        data_updated = True
                        updated_at = marks_updated_at

            # If we found recent updates, override the status
            if data_updated:
                print(f"✅ Found recent data updates for {email}, marking refresh as completed")
                status = {"status": "completed", "updated_at": updated_at}
                # Update the active_scrapers dictionary too
                active_scrapers[email] = status
            elif status.get("status") == "running":
                # Check if the job has been running too long (more than 3 minutes)
                if "started_at" in status:
                    start_time = datetime.fromisoformat(status["started_at"])
                    elapsed = (now - start_time).total_seconds()
                    if elapsed > 180:  # 3 minutes
                        # Check if we have any data at all
                        if updated_at:
                            print(f"⚠️ Scraper for {email} ran for over 3 minutes, but we have some data. Marking as completed.")
                            status = {"status": "completed", "updated_at": updated_at}
                            active_scrapers[email] = status
                        else:
                            print(f"⚠️ Scraper for {email} timed out after 3 minutes with no data")
                            status = {"status": "timeout", "error": "Scraper took too long to respond"}
                            active_scrapers[email] = status
        except Exception as check_err:
            print(f"Error checking Supabase for updates: {check_err}")

        return jsonify({
            "success": True,
            "status": status.get("status", "not_started"),
            "updated_at": status.get("updated_at", None)
        }), 200

    except Exception as e:
        print(f"Error checking refresh status: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/scraper-health", methods=["GET"])
def scraper_health():
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "error": "No token provided"}), 401

        token = auth_header.split(" ")[1]
        try:
            jwt.decode(token, os.getenv('JWT_SECRET', 'default-secret-key'), algorithms=["HS256"])
        except:
            return jsonify({"success": False, "error": "Invalid token"}), 401

        scraper_urls = get_scraper_urls()
        results = {}

        for url in scraper_urls:
            try:
                response = requests.get(f"{url}/health", timeout=5)
                results[url] = {
                    "status": "healthy" if response.ok else "unhealthy",
                    "status_code": response.status_code,
                    "response_time_ms": response.elapsed.total_seconds() * 1000
                }
            except Exception as e:
                results[url] = {
                    "status": "error",
                    "error": str(e)
                }

        all_healthy = any(r.get("status") == "healthy" for r in results.values())

        return jsonify({
            "success": True,
            "all_healthy": all_healthy,
            "scrapers": results
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Add this function immediately before the /api/refresh-data route
def check_scraper_completion(email, user_id, scraper_url):
    """Background task to check if scraper completed and update active_scrapers accordingly"""
    try:
        # Wait a bit for scraper to start working
        time.sleep(10)

        print(f"Checking completion status for {email} scraper job...")
        max_attempts = 20

        for attempt in range(max_attempts):
            try:
                # Check Supabase for updated data
                att_resp = supabase.table("attendance").select("updated_at").eq("user_id", user_id).execute()
                marks_resp = supabase.table("marks").select("updated_at").eq("user_id", user_id).execute()

                # Get the current status
                status = active_scrapers.get(email, {})
                started_at = status.get("started_at")

                # Check if we have attendance data updated after scraper started
                if att_resp.data and len(att_resp.data) > 0 and att_resp.data[0].get("updated_at"):
                    updated_at = att_resp.data[0].get("updated_at")
                    if not started_at or updated_at > started_at:
                        print(f"✅ Detected completion for {email}: attendance data updated")
                        active_scrapers[email] = {"status": "completed", "updated_at": updated_at}

                        # Notify frontend that data is ready
                        # Wait 2 seconds to ensure data is fully processed
                        time.sleep(2)
                        # Send notification to the specific user
                        notify_user(email, 'data_ready', {
                            'email': email,
                            'type': 'attendance',
                            'updated_at': updated_at
                        })

                        return

                # Check marks data too
                if marks_resp.data and len(marks_resp.data) > 0 and marks_resp.data[0].get("updated_at"):
                    updated_at = marks_resp.data[0].get("updated_at")
                    if not started_at or updated_at > started_at:
                        print(f"✅ Detected completion for {email}: marks data updated")
                        active_scrapers[email] = {"status": "completed", "updated_at": updated_at}

                        # Notify frontend that data is ready
                        # Wait 2 seconds to ensure data is fully processed
                        time.sleep(2)
                        # Send notification to the specific user
                        notify_user(email, 'data_ready', {
                            'email': email,
                            'type': 'marks',
                            'updated_at': updated_at
                        })

                        return

                # If still running and we've checked too many times, mark as error
                if attempt == max_attempts - 1:
                    print(f"⚠️ Scraper for {email} timed out after {max_attempts} checks")
                    active_scrapers[email] = {"status": "error", "error": "Scraper took too long to update data"}

                    # Notify frontend of the error
                    notify_user(email, 'data_error', {
                        'email': email,
                        'error': "Scraper took too long to update data"
                    })

                    return

                # Wait before checking again
                time.sleep(10)

            except Exception as e:
                print(f"Error checking completion for {email}: {str(e)}")
                # Don't update status on error, keep trying

    except Exception as e:
        print(f"Background task error for {email}: {str(e)}")
        active_scrapers[email] = {"status": "error", "error": str(e)}

        # Notify frontend of the error
        notify_user(email, 'data_error', {
            'email': email,
            'error': str(e)
        })

# Helper function to handle preflight OPTIONS requests
def handle_preflight_request():
    response = jsonify({"success": True})
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    response.headers.add("Access-Control-Allow-Credentials", "true")
    return response, 200

@app.route("/api/schema-check", methods=["GET"])
def schema_check():
    """Endpoint to verify database schema and add missing columns"""
    try:
        # Connect to Supabase with admin privileges
        admin_key = os.getenv("SUPABASE_SERVICE_KEY", SUPABASE_KEY)

        # Create a standard query first
        result = supabase.table("users").select("count").limit(1).execute()

        # This function creates the stored procedure for adding columns if it doesn't exist
        # Then uses it to add the updated_at column if missing
        create_utility_functions = """
        -- Create function to add missing columns if it doesn't exist
        CREATE OR REPLACE FUNCTION add_missing_column(
            table_name text,
            column_name text,
            column_type text DEFAULT 'text',
            column_default text DEFAULT NULL
        ) RETURNS boolean AS $$
        DECLARE
            column_exists boolean;
            sql_command text;
        BEGIN
            -- Check if column exists
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = add_missing_column.table_name
                AND column_name = add_missing_column.column_name
            ) INTO column_exists;

            IF NOT column_exists THEN
                -- Add column with default if provided
                IF column_default IS NOT NULL THEN
                    sql_command := format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS %I %s DEFAULT %s',
                        table_name, column_name, column_type, column_default);
                ELSE
                    sql_command := format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS %I %s',
                        table_name, column_name, column_type);
                END IF;

                EXECUTE sql_command;
                RETURN true;
            END IF;

            RETURN false;
        END;
        $$ LANGUAGE plpgsql;
        """

        # Use raw SQL to execute the function creation
        from supabase.client import ClientOptions
        admin_options = ClientOptions(
            schema="public",
            headers={"apiKey": admin_key, "Authorization": f"Bearer {admin_key}"}
        )

        admin_supabase = create_client(SUPABASE_URL, admin_key, options=admin_options)

        # Execute the function creation
        try:
            admin_supabase.rpc('exec_sql', {'sql': create_utility_functions}).execute()
        except Exception as sql_error:
            # If the exec_sql function doesn't exist yet, create it
            if "function exec_sql" in str(sql_error).lower() and "does not exist" in str(sql_error).lower():
                # Create the exec_sql function first
                create_exec_sql = """
                CREATE OR REPLACE FUNCTION exec_sql(sql text) RETURNS void AS $$
                BEGIN
                    EXECUTE sql;
                END;
                $$ LANGUAGE plpgsql SECURITY DEFINER;

                GRANT EXECUTE ON FUNCTION exec_sql TO authenticated;
                """

                # Execute raw SQL to create the function
                try:
                    # This direct execution requires full admin privileges
                    response = requests.post(
                        f"{SUPABASE_URL}/rest/v1/rpc/exec_sql",
                        headers={
                            "apikey": admin_key,
                            "Authorization": f"Bearer {admin_key}",
                            "Content-Type": "application/json"
                        },
                        json={"sql": create_exec_sql}
                    )

                    if not response.ok:
                        print(f"Failed to create exec_sql function: {response.status_code} {response.text}")
                        return jsonify({
                            "success": False,
                            "error": f"Failed to create exec_sql function: {response.status_code}"
                        }), 500

                    # Now try to create the utility function again
                    admin_supabase.rpc('exec_sql', {'sql': create_utility_functions}).execute()
                except Exception as direct_error:
                    print(f"Error creating exec_sql function: {direct_error}")
                    return jsonify({
                        "success": False,
                        "error": f"Error creating SQL utility functions: {direct_error}"
                    }), 500

        # Now add the missing columns
        fixes = [
            # Add updated_at column to users table if missing
            "SELECT add_missing_column('users', 'updated_at', 'timestamp with time zone', 'CURRENT_TIMESTAMP')",

            # Add last_login column to users table if missing
            "SELECT add_missing_column('users', 'last_login', 'timestamp with time zone', 'NULL')",

            # Add password_raw column to users table if missing
            "SELECT add_missing_column('users', 'password_raw', 'text', 'NULL')"
        ]

        results = {}
        for fix in fixes:
            try:
                result = admin_supabase.rpc('exec_sql', {'sql': fix}).execute()
                results[fix] = "Success"
            except Exception as e:
                results[fix] = f"Error: {str(e)}"

        # Create a trigger for updated_at if it doesn't exist
        try:
            create_trigger = """
            -- Create update function if it doesn't exist
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = CURRENT_TIMESTAMP;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;

            -- Drop and recreate trigger
            DROP TRIGGER IF EXISTS update_users_updated_at ON users;
            CREATE TRIGGER update_users_updated_at
            BEFORE UPDATE ON users
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
            """

            result = admin_supabase.rpc('exec_sql', {'sql': create_trigger}).execute()
            results["create_trigger"] = "Success"
        except Exception as trigger_error:
            results["create_trigger"] = f"Error: {str(trigger_error)}"

        # Create scraper_status table if it doesn't exist
        try:
            create_status_table = """
            CREATE TABLE IF NOT EXISTS scraper_status (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id UUID REFERENCES users(id),
                status TEXT NOT NULL,
                details JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
            """

            result = admin_supabase.rpc('exec_sql', {'sql': create_status_table}).execute()
            results["create_status_table"] = "Success"
        except Exception as table_error:
            results["create_status_table"] = f"Error: {str(table_error)}"

        return jsonify({
            "success": True,
            "message": "Schema check completed",
            "results": results
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/debug/scraper-selection", methods=["GET"])
def debug_scraper_selection():
    selected_url = get_best_scraper()
    all_urls = get_scraper_urls()
    return jsonify({
        "selected_scraper": selected_url,
        "all_scrapers": all_urls,
        "selection_time": get_ist_now().isoformat()
    })

@app.route("/api/data-status", methods=["GET", "OPTIONS"])
def get_data_status():
    """Unified endpoint to check the status of all data types (timetable, attendance, marks)"""
    if request.method == "OPTIONS":
        return jsonify({"success": True}), 200

    try:
        # Get authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "error": "No token provided"}), 401

        token = auth_header.split(" ")[1]

        try:
            # Decode JWT token to get user information
            payload = jwt.decode(token, os.getenv('JWT_SECRET', 'default-secret-key'), algorithms=["HS256"])
            user_id = payload.get("id") or payload.get("sub")
            email = payload["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "error": "Invalid token"}), 401

        # Check if any scraper is running
        scraper_running = False
        for key in active_scrapers:
            if key.startswith(email) or key == email:
                if active_scrapers[key].get("status") == "running":
                    scraper_running = True
                    break

        # Get data timestamps from database
        timetable_data = None
        attendance_data = None
        marks_data = None

        try:
            # Check timetable data
            tt_resp = supabase.table("timetable").select("updated_at").eq("user_id", user_id).execute()
            if tt_resp.data and len(tt_resp.data) > 0:
                timetable_data = {
                    "exists": True,
                    "updated_at": tt_resp.data[0].get("updated_at")
                }
            else:
                timetable_data = {"exists": False}

            # Check attendance data
            att_resp = supabase.table("attendance").select("updated_at").eq("user_id", user_id).execute()
            if att_resp.data and len(att_resp.data) > 0:
                attendance_data = {
                    "exists": True,
                    "updated_at": att_resp.data[0].get("updated_at")
                }
            else:
                attendance_data = {"exists": False}

            # Check marks data
            marks_resp = supabase.table("marks").select("updated_at").eq("user_id", user_id).execute()
            if marks_resp.data and len(marks_resp.data) > 0:
                marks_data = {
                    "exists": True,
                    "updated_at": marks_resp.data[0].get("updated_at")
                }
            else:
                marks_data = {"exists": False}

        except Exception as db_error:
            print(f"Error checking database for data status: {db_error}")
            return jsonify({"success": False, "error": f"Database error: {str(db_error)}"}), 500

        # Return comprehensive status
        return jsonify({
            "success": True,
            "scraper_running": scraper_running,
            "timetable": timetable_data,
            "attendance": attendance_data,
            "marks": marks_data,
            "timestamp": get_ist_now().isoformat()
        }), 200

    except Exception as e:
        print(f"Error in data-status endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

# Deadline management endpoints
@app.route("/api/deadlines", methods=["GET", "OPTIONS"])
def get_deadlines():
    if request.method == "OPTIONS":
        return handle_preflight_request()

    try:
        # Get user ID from token
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"success": False, "error": "Authentication required"}), 401

        # Verify token
        try:
            payload = jwt.decode(token, os.getenv("JWT_SECRET", "default-secret-key"), algorithms=["HS256"])
            user_id = payload.get("id") or payload.get("sub")
            if not user_id:
                return jsonify({"success": False, "error": "Invalid token"}), 401
        except Exception as e:
            return jsonify({"success": False, "error": f"Invalid token: {str(e)}"}), 401

        # Deadlines are stored in localStorage, not in the database
        # Return an empty array to avoid errors
        return jsonify({
            "success": True,
            "deadlines": []
        })
    except Exception as e:
        print(f"Error getting deadlines: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/deadlines", methods=["POST", "OPTIONS"])
def add_deadline():
    if request.method == "OPTIONS":
        return handle_preflight_request()

    try:
        # Get user ID from token
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"success": False, "error": "Authentication required"}), 401

        # Verify token
        try:
            payload = jwt.decode(token, os.getenv("JWT_SECRET", "default-secret-key"), algorithms=["HS256"])
            user_id = payload.get("id") or payload.get("sub")
            if not user_id:
                return jsonify({"success": False, "error": "Invalid token"}), 401
        except Exception as e:
            return jsonify({"success": False, "error": f"Invalid token: {str(e)}"}), 401

        # Get deadline data from request
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        title = data.get("title")
        due_date = data.get("due_date")
        description = data.get("description", "")
        course = data.get("course", "")

        if not title or not due_date:
            return jsonify({"success": False, "error": "Title and due date are required"}), 400

        # Deadlines are stored in localStorage, not in the database
        # Create a mock result for compatibility
        result = {
            "data": [{
                "id": "local-" + str(int(time.time())),
                "user_id": user_id,
                "title": title,
                "due_date": due_date,
                "description": description,
                "course": course,
                "created_at": get_ist_now().isoformat()
            }]
        }

        # Check for upcoming deadline (today or tomorrow) and send notification if needed
        now = get_ist_now()
        tomorrow = now + timedelta(days=1)
        due_date_str = due_date.split('T')[0]  # Get just the date part
        today_str = now.strftime('%Y-%m-%d')
        tomorrow_str = tomorrow.strftime('%Y-%m-%d')

        # Get user email
        user_data = supabase.table("users").select("email").eq("id", user_id).execute()
        if user_data.data and user_data.data[0].get("email"):
            user_email = user_data.data[0].get("email")

            if due_date_str == today_str:
                # Send notification for deadline today
                notify_user(user_email, 'deadline_reminder', {
                    'email': user_email,
                    'title': title,
                    'dueText': "today",
                    'dueDate': due_date_str
                })
            elif due_date_str == tomorrow_str:
                # Send notification for deadline tomorrow
                notify_user(user_email, 'deadline_reminder', {
                    'email': user_email,
                    'title': title,
                    'dueText': "tomorrow",
                    'dueDate': due_date_str
                })

        return jsonify({
            "success": True,
            "deadline": result.data[0] if result.data else None
        })
    except Exception as e:
        print(f"Error adding deadline: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/deadlines/<deadline_id>", methods=["DELETE", "OPTIONS"])
def delete_deadline(deadline_id):
    if request.method == "OPTIONS":
        return handle_preflight_request()

    try:
        # Get user ID from token
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"success": False, "error": "Authentication required"}), 401

        # Verify token
        try:
            payload = jwt.decode(token, os.getenv("JWT_SECRET", "default-secret-key"), algorithms=["HS256"])
            user_id = payload.get("id") or payload.get("sub")
            if not user_id:
                return jsonify({"success": False, "error": "Invalid token"}), 401
        except Exception as e:
            return jsonify({"success": False, "error": f"Invalid token: {str(e)}"}), 401

        # Deadlines are stored in localStorage, not in the database
        # No need to delete from database

        return jsonify({
            "success": True,
            "message": "Deadline deleted successfully"
        })
    except Exception as e:
        print(f"Error deleting deadline: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    print('Client connected to WebSocket')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected from WebSocket')

@socketio.on('subscribe')
def handle_subscribe(data):
    email = data.get('email')
    if email:
        print(f'Client subscribed to updates for {email}')
        # Join a room specific to this user
        from flask_socketio import join_room
        join_room(email)
        # Acknowledge subscription
        return {'status': 'subscribed', 'email': email}
    return {'status': 'error', 'message': 'No email provided'}

# Function to send notification to a specific user
def notify_user(email, event_type, data):
    try:
        # Send notifications for all event types
        socketio.emit(event_type, data, room=email)

        # Log the notification
        if event_type == 'deadline_reminder':
            print(f'Deadline notification sent to {email}: {data["title"]}')
        elif event_type == 'data_ready':
            print(f'Data ready notification sent to {email}: {data.get("type", "unknown")}')
        else:
            print(f'Notification sent to {email}: {event_type}')

        return True
    except Exception as e:
        print(f'Error sending notification to {email}: {str(e)}')
        return False

# Function to check for upcoming deadlines and send notifications
def check_deadlines():
    try:
        print("Checking for upcoming deadlines...")
        # No need to get current date since we're not checking deadlines in the database
        # Just log that we're checking

        # No need to format dates since we're not checking deadlines in the database

        # Get all users
        users = supabase.table("users").select("id,email").execute()

        if not users.data:
            print("No users found")
            return

        # Check each user's cookies for localStorage data
        for user in users.data:
            try:
                user_id = user.get("id")
                user_email = user.get("email")

                if not user_id or not user_email:
                    continue

                # Get user's cookies
                cookies_data = supabase.table("user_cookies").select("cookies").eq("email", user_email).execute()

                if not cookies_data.data or not cookies_data.data[0].get("cookies"):
                    continue

                # Extract localStorage deadlines from cookies if available
                # Note: This is a simplified approach - in reality, cookies don't contain localStorage
                # We would need a different approach to access localStorage data

                # Deadlines are stored in localStorage, not in the database
                # We can't access localStorage from the server, so we can't check for deadlines
                # This functionality would need to be implemented in the frontend
                pass
            except Exception as user_error:
                print(f"Error processing user {user.get('id')}: {user_error}")
                continue
    except Exception as e:
        print(f"Error checking deadlines: {e}")

# Schedule deadline checks
def start_deadline_checker():
    import threading
    import time

    def deadline_checker_thread():
        while True:
            try:
                # Check deadlines
                check_deadlines()
                # Wait for 1 hour before checking again
                time.sleep(3600)  # 3600 seconds = 1 hour
            except Exception as e:
                print(f"Error in deadline checker thread: {e}")
                # If there's an error, wait 5 minutes before trying again
                time.sleep(300)

    # Start the deadline checker in a background thread
    thread = threading.Thread(target=deadline_checker_thread, daemon=True)
    thread.start()
    print("Deadline checker started in background")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    print(f"Starting server on port {port} with WebSocket support...")

    # Start the deadline checker
    start_deadline_checker()

    # Run the Flask-SocketIO app
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)
