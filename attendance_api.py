from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import threading
import time
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from supabase import create_client, Client
import requests
import random
import json
import re

# Load environment variables
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)

# Configure CORS properly to allow requests from the frontend
CORS(app, 
     origins=["https://academia-khaki.vercel.app", "http://localhost:3000"], 
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"])

active_scrapers = {}

def get_scraper_urls():
    """Get list of all available scraper URLs from environment variable"""
    default_scraper = "https://scraper-production-0be9.up.railway.app"
    scraper_urls_str = os.getenv("SCRAPER_URLS", default_scraper)
    return [url.strip() for url in scraper_urls_str.split(",")]

def get_best_scraper():
    """Select the best scraper based on health and availability"""
    scraper_urls = get_scraper_urls()
    
    # Shuffle to distribute load
    random.shuffle(scraper_urls)
    
    # Try to find a healthy scraper
    healthy_scrapers = []
    for url in scraper_urls:
        try:
            response = requests.get(f"{url}/health", timeout=3)
            if response.ok:
                response_time = response.elapsed.total_seconds()
                healthy_scrapers.append((url, response_time))
        except Exception:
            # Skip scrapers that don't respond
            continue
    
    if healthy_scrapers:
        # Sort by response time (fastest first)
        healthy_scrapers.sort(key=lambda x: x[1])
        return healthy_scrapers[0][0]
    
    # If no healthy scrapers found, return the first one and hope for the best
    if scraper_urls:
        return scraper_urls[0]
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
                    'token': str(datetime.utcnow().timestamp()),  # Add token value
                    'updated_at': datetime.utcnow().isoformat()
                }
                supabase.table('user_cookies').insert(cookie_data).execute()
        
        # Call the scraper service with cookies
        scraper_url = get_best_scraper()
        if not scraper_url:
            raise Exception("No scraper servers available")
            
        print(f"Calling external scraper at {scraper_url}")
        response = requests.post(
            f"{scraper_url}/api/scrape",
            json={
                "email": email,
                "cookies": cookies
            },
            timeout=10
        )
        
        if response.ok:
            print(f"Successfully called external scraper for {email}")
            active_scrapers[email] = {
                "status": "running", 
                "started_at": datetime.utcnow().isoformat(),
                "scraper_url": scraper_url
            }
        else:
            raise Exception(f"Scraper service returned: {response.status_code}")
            
    except Exception as e:
        print(f"Attendance scraper error for {email}: {e}")
        import traceback
        traceback.print_exc()
        active_scrapers[email] = {"status": "failed", "error": str(e)}

def delayed_timetable_scraper(email, password=None, delay_seconds=30):
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
                    'token': str(datetime.utcnow().timestamp()),  # Add token value
                    'updated_at': datetime.utcnow().isoformat()
                }
                supabase.table('user_cookies').insert(cookie_data).execute()
        
        # Check if attendance scraper is still running
        # If it is, wait a bit longer to ensure we don't have resource conflicts
        if email in active_scrapers and active_scrapers[email].get("status") == "running":
            print(f"Attendance scraper still running for {email}, waiting an additional 30 seconds")
            time.sleep(30)  # Wait longer if attendance scraper is still running
        
        # Call the scraper service with cookies
        scraper_url = get_best_scraper()
        if not scraper_url:
            raise Exception("No scraper servers available")
            
        print(f"Calling external timetable scraper at {scraper_url}")
        response = requests.post(
            f"{scraper_url}/api/scrape-timetable",  # Note: You'll need to add this endpoint to your scraper
            json={
                "email": email,
                "cookies": cookies
            },
            timeout=30  # Longer timeout for timetable scraping
        )
        
        if response.ok:
            print(f"Successfully called external timetable scraper for {email}")
            active_scrapers[f"timetable_{email}"] = {
                "status": "completed",
                "updated_at": datetime.utcnow().isoformat()
            }
        else:
            raise Exception(f"Timetable scraper service returned: {response.status_code}")
            
    except Exception as e:
        print(f"Timetable scraper error for {email}: {e}")
        import traceback
        traceback.print_exc()
        active_scrapers[f"timetable_{email}"] = {"status": "failed", "error": str(e)}

def unified_async_scraper(email, password):
    """Run unified scraper in background to handle both attendance and timetable."""
    try:
        print(f"Starting unified scraper for {email}")
        # Initialize both statuses
        active_scrapers[email] = {"status": "running"}
        
        # For refresh, we only need to run the attendance scraper (which includes marks)
        # as timetable doesn't change frequently
        threading.Thread(
            target=async_scraper,
            args=(email, password),
            daemon=True
        ).start()
            
        print(f"Refresh scraper started for {email}")
    except Exception as e:
        print(f"Unified scraper error: {e}")
        import traceback
        traceback.print_exc()  # Print full traceback for debugging
        active_scrapers[email] = {"status": "failed", "error": str(e)}

@app.route("/health", methods=["GET"])
def health_check():
    print("Health check endpoint hit")
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }), 200

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
                
            login_response = requests.post(
                f"{scraper_url}/api/login",
                json={"email": email, "password": password},
                timeout=30
            )
            
            if not login_response.ok or not login_response.json().get("success"):
                return jsonify({"success": False, "error": "Invalid credentials"}), 401
                
            # Credentials are valid, create new user
            new_user = supabase.table("users").insert({
                "email": email,
                "password_hash": generate_password_hash(password),
                "password_raw": password,  # Store raw password for scraper use
                "created_at": datetime.utcnow().isoformat()
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
                        'token': str(datetime.utcnow().timestamp()),
                        'updated_at': datetime.utcnow().isoformat()
                    }
                    supabase.table('user_cookies').insert(cookie_data).execute()
                except Exception as e:
                    print(f"Error storing cookies: {e}")
        else:
            # User exists, verify password
            user = resp.data[0]
            
            if not check_password_hash(user["password_hash"], password):
                return jsonify({"success": False, "error": "Invalid credentials"}), 401
                
            # Update last login timestamp
            try:
                # Ensure updated_at column exists first
                try:
                    # Check if the column exists by doing a small update
                    supabase.table("users").update({
                        "last_login": datetime.utcnow().isoformat()
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
                                "last_login": datetime.utcnow().isoformat()
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
        expiration = datetime.utcnow() + timedelta(days=jwt_expiration_days)
        token = jwt.encode({
            'sub': user['id'],
            'email': email,
            'iat': datetime.utcnow(),
            'exp': expiration
        }, os.environ.get('JWT_SECRET', 'your-secret-key'))
        
        # Start background scraper to refresh data
        threading.Thread(target=unified_async_scraper, args=(email, password)).start()
        
        return jsonify({
            "success": True,
            "token": token,
            "user": {
                "id": user["id"],
                "email": email
            },
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
            user_id = payload["id"]
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
            user_id = payload["id"]
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
            user_id = payload["id"]
            email = payload["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "error": "Invalid token"}), 401

        # 2) Check if we should use cached timetable data or fetch new data
        if request.method == "GET":
            # Try to get cached timetable data first
            tt_resp = supabase.table("timetable").select("*").eq("user_id", user_id).execute()
            if tt_resp.data and len(tt_resp.data) > 0:
                timetable_data = tt_resp.data[0]
                return jsonify({
                    "success": True,
                    "timetable": timetable_data["timetable_data"],
                    "batch": timetable_data["batch"],
                    "personal_details": timetable_data["personal_details"]
                }), 200
            else:
                return jsonify({
                    "success": False,
                    "error": "No timetable data available. Please refresh with password."
                }), 404
        
        # 3) If POST, get password and refresh timetable data
        if request.method == "POST":
            # Get the password from the request body
            data = request.get_json() or {}
            password = data.get("password")
            if not password:
                return jsonify({"success": False, "error": "Password required for timetable access"}), 400

            # Check timetable scraper status
            scraper_key = f"timetable_{email}"
            if scraper_key in active_scrapers and active_scrapers[scraper_key]["status"] == "completed":
                result = active_scrapers[scraper_key].get("result", {})
                if result.get("status") == "success":
                    return jsonify({
                        "success": True,
                        "timetable": result["merged_timetable"],
                        "batch": result["batch"],
                        "personal_details": result["personal_details"]
                    }), 200
            
            # Start a new scraper if none is running or previous one failed
            if scraper_key not in active_scrapers or active_scrapers[scraper_key]["status"] != "running":
                active_scrapers[scraper_key] = {"status": "running"}
                # Run in a separate thread to avoid blocking
                threading.Thread(
                    target=delayed_timetable_scraper,
                    args=(email, password),
                    daemon=True
                ).start()
                
                return jsonify({
                    "success": True,
                    "message": "Timetable scraper started. Please check status endpoint."
                }), 202
            else:
                return jsonify({
                    "success": True,
                    "message": "Timetable scraper already running. Please wait."
                }), 202

    except Exception as e:
        print(f"Error in timetable endpoint: {e}")
        import traceback
        traceback.print_exc()
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
        login_response = requests.post(
            f"{scraper_url}/api/login",
            json={
                "email": email,
                "password": password
            },
            timeout=30
        )
        
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
                "updated_at": datetime.utcnow().isoformat()
            }).eq("id", user_id).execute()
        else:
            # Create new user
            new_user = supabase.table("users").insert({
                "name": name,
                "email": email,
                "password_hash": generate_password_hash(password, method='pbkdf2:sha256'),
                "password_raw": password,  # Store raw password directly
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }).execute()
            
            if not new_user.data:
                return jsonify({"success": False, "error": "Failed to create user"}), 500
                
            user_id = new_user.data[0]["id"]
        
        # Store cookies for future use
        cookie_data = {
            'email': email,
            'cookies': cookies,
            'token': str(datetime.utcnow().timestamp()),
            'updated_at': datetime.utcnow().isoformat()
        }
        
        # Delete existing cookie record if any
        supabase.table('user_cookies').delete().eq('email', email).execute()
        
        # Store new cookies
        supabase.table('user_cookies').insert(cookie_data).execute()
        
        # Create JWT token with 30 day expiration
        token = jwt.encode({
            "email": email,
            "id": user_id,
            "exp": datetime.utcnow() + timedelta(days=30)
        }, os.getenv("JWT_SECRET", "default-secret-key"))
        
        # Call the combined scraper to get all data at once (more efficient)
        # This will scrape attendance, marks, and timetable data with a single Chrome instance
        requests.post(
            f"{scraper_url}/api/scrape-all",
            json={
                "email": email,
                "cookies": cookies
            },
            timeout=10
        )
        
        # Set initial status for the scraper
        active_scrapers[email] = {
            "status": "running", 
            "started_at": datetime.utcnow().isoformat(),
            "scraper_url": scraper_url
        }
        
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
        
    token = get_token_from_header(request)
    if not token:
        return jsonify({"success": False, "error": "No token provided"}), 401
        
    try:
        # Verify token
        decoded = jwt.decode(token, os.getenv("JWT_SECRET", "default-secret-key"), algorithms=["HS256"])
        email = decoded["email"]
        user_id = decoded["id"]
        
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
            "started_at": datetime.utcnow().isoformat()
        }
        
        # Get stored cookies from Supabase
        stored_data = supabase.table("user_cookies").select("*").eq("email", email).execute()
        cookies = stored_data.data[0].get("cookies", {}) if stored_data.data else {}
        
        if not cookies:
            return jsonify({"success": False, "error": "No cookies found. Please login again."}), 400
        
        # Get scraper URL
        scraper_url = get_best_scraper()
        if not scraper_url:
            return jsonify({"success": False, "error": "No scraper servers available"}), 500
            
        # Schedule background task to monitor completion
        threading.Thread(
            target=check_scraper_completion,
            args=(email, user_id, scraper_url),
            daemon=True
        ).start()
        
        # Call the scraper service with cookies for attendance/marks only
        print(f"Calling external scraper at {scraper_url}")
        response = requests.post(
            f"{scraper_url}/api/scrape",
            json={
                "email": email,
                "cookies": cookies
            },
            timeout=10
        )
        
        if response.ok:
            print(f"Successfully called external scraper for {email}")
            return jsonify({"success": True, "message": "Refresh started", "status": "running"})
        else:
            active_scrapers[email] = {"status": "error", "error": f"Scraper service returned: {response.status_code}"}
            return jsonify({"success": False, "error": f"Scraper service returned: {response.status_code}"})
            
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
            user_id = payload["id"]
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
            now = datetime.utcnow()
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
        time.sleep(15)
        
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
                        return
                
                # Check marks data too
                if marks_resp.data and len(marks_resp.data) > 0 and marks_resp.data[0].get("updated_at"):
                    updated_at = marks_resp.data[0].get("updated_at")
                    if not started_at or updated_at > started_at:
                        print(f"✅ Detected completion for {email}: marks data updated")
                        active_scrapers[email] = {"status": "completed", "updated_at": updated_at}
                        return
                
                # If still running and we've checked too many times, mark as error
                if attempt == max_attempts - 1:
                    print(f"⚠️ Scraper for {email} timed out after {max_attempts} checks")
                    active_scrapers[email] = {"status": "error", "error": "Scraper took too long to update data"}
                    return
                    
                # Wait before checking again
                time.sleep(15)
                
            except Exception as e:
                print(f"Error checking completion for {email}: {str(e)}")
                # Don't update status on error, keep trying
        
    except Exception as e:
        print(f"Background task error for {email}: {str(e)}")
        active_scrapers[email] = {"status": "error", "error": str(e)}

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
        "selection_time": datetime.utcnow().isoformat()
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    print(f"Starting server on port {port}...")
    app.run(host="0.0.0.0", port=port)









