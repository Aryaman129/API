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

# Load environment variables
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)

# Enable CORS for all routes with proper configuration
CORS(app, origins=["https://academia-khaki.vercel.app", "http://localhost:3000"], supports_credentials=True, allow_headers=["Content-Type", "Authorization"])

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

def async_scraper(email, password):
    """Run scraper in background using external scraper service."""
    try:
        print(f"Starting attendance scraper for {email} (via external service)")
        
        # Get stored cookies from Supabase
        stored_data = supabase.table("user_cookies").select("*").eq("email", email).execute()
        cookies = stored_data.data[0].get("cookies", {}) if stored_data.data else {}
        
        if not cookies:
            # If no cookies, login and get cookies
            
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

def delayed_timetable_scraper(email, password, delay_seconds=1):
    """Run timetable scraper in background with a delay to avoid resource conflicts."""
    time.sleep(delay_seconds)  # Wait before starting to avoid two Chrome instances at once
    active_scrapers[f"timetable_{email}"] = {"status": "waiting"}
    
    try:
        print(f"Starting timetable scraper for {email} after {delay_seconds}s delay (via external service)")
        active_scrapers[f"timetable_{email}"] = {"status": "running"}
        
        # Get stored cookies from Supabase
        stored_data = supabase.table("user_cookies").select("*").eq("email", email).execute()
        cookies = stored_data.data[0].get("cookies", {}) if stored_data.data else {}
        
        if not cookies:
            # If no cookies, login and get cookies
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
        return jsonify({"success": True}), 200
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        email = data.get("email")
        password = data.get("password")
        if not email or not password:
            return jsonify({"success": False, "error": "Email and password required"}), 400

        print(f"Login attempt for email: {email}")

        # 1) Check if user exists by email
        try:
            resp = supabase.table("users").select("*").eq("email", email).execute()
            if not resp.data or len(resp.data) == 0:
                # 2) Create new user with empty registration_number
                new_user = {
                    "email": email,
                    "password_hash": generate_password_hash(password, method='pbkdf2:sha256'),
                    "registration_number": ""
                }
                insert_resp = supabase.table("users").insert(new_user).execute()
                if not insert_resp.data:
                    raise Exception("Failed to create user record")
                user = insert_resp.data[0]
            else:
                user = resp.data[0]
                try:
                    # Try to verify with existing hash
                    if not check_password_hash(user["password_hash"], password):
                        # If verification fails, update to new hash
                        new_hash = generate_password_hash(password, method='pbkdf2:sha256')
                        update_resp = supabase.table("users").update({"password_hash": new_hash}).eq("id", user["id"]).execute()
                        if not update_resp.data:
                            raise Exception("Failed to update password hash")
                        user = update_resp.data[0]
                except ValueError as e:
                    if "unsupported hash type" in str(e):
                        # If old hash is incompatible, update to new hash
                        new_hash = generate_password_hash(password, method='pbkdf2:sha256')
                        update_resp = supabase.table("users").update({"password_hash": new_hash}).eq("id", user["id"]).execute()
                        if not update_resp.data:
                            raise Exception("Failed to update password hash")
                        user = update_resp.data[0]
                    else:
                        raise
        except Exception as e:
            print(f"Database error during user lookup/creation: {e}")
            return jsonify({"success": False, "error": "Database operation failed"}), 500

        # 4) Generate token with user["id"]
        token = jwt.encode({
            "email": email,
            "id": user["id"],
            "exp": datetime.utcnow() + timedelta(days=30)
        }, os.getenv("JWT_SECRET", "default-secret-key"))

        # 5) First, check if user already has timetable data
        timetable_resp = supabase.table("timetable").select("*").eq("user_id", user["id"]).execute()
        if not timetable_resp.data or len(timetable_resp.data) == 0:
            # If no timetable data exists, we need to run timetable scraper first
            print(f"No timetable data found for {email}, starting timetable scraper first")
            # Start timetable scraper first
            threading.Thread(
                target=delayed_timetable_scraper,
                args=(email, password, 0),  # No delay for first run
                daemon=True
            ).start()
            
            # Then start attendance scraper with a delay
            threading.Thread(
                target=async_scraper,
                args=(email, password),
                daemon=True
            ).start()
        else:
            # If timetable data exists, just update attendance and marks
            print(f"Timetable data exists for {email}, updating attendance only")
            threading.Thread(
                target=async_scraper,
                args=(email, password),
                daemon=True
            ).start()

        return jsonify({
            "success": True,
            "token": token,
            "user": {"email": email, "id": user["id"]}
        })

    except Exception as e:
        print(f"Login error: {e}")
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
        return jsonify({"success": True}), 200
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
        print(f"Registration attempt for email: {email}")
        if not email or not password:
            return jsonify({"success": False, "error": "Email and password required"}), 400

        # Check if user already exists
        resp = supabase.table("users").select("*").eq("email", email).execute()
        if resp.data and len(resp.data) > 0:
            return jsonify({"success": False, "error": "User already exists"}), 400

        new_user = {
            "email": email,
            "password_hash": generate_password_hash(password, method='pbkdf2:sha256'),
            "registration_number": ""
        }
        insert_resp = supabase.table("users").insert(new_user).execute()
        if not insert_resp.data:
            return jsonify({"success": False, "error": "Failed to create user"}), 500

        user = insert_resp.data[0]
        token = jwt.encode({
            "email": email,
            "id": user["id"],
            "exp": datetime.utcnow() + timedelta(days=30)
        }, os.getenv("JWT_SECRET", "default-secret-key"))

        return jsonify({
            "success": True,
            "token": token,
            "user": {"email": email, "id": user["id"]}
        })
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/refresh-data", methods=["POST", "OPTIONS"])
def refresh_data():
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
        
        # Get stored cookies from Supabase
        stored_data = supabase.table("user_cookies").select("*").eq("email", email).execute()
        cookies = stored_data.data[0].get("cookies", {}) if stored_data.data else {}
        
        if not cookies:
            return jsonify({"success": False, "error": "No cookies found. Please login again."}), 400
        
        # Get all available scraper URLs
        scraper_urls = get_scraper_urls()
        if not scraper_urls:
            return jsonify({"success": False, "error": "No scraper servers configured"}), 500
        
        # Try scrapers in random order until one works
        successful = False
        errors = []
        used_scraper_url = None
        
        # Load balancing - try in order: best scraper first, then random order
        best_scraper = get_best_scraper()
        if best_scraper:
            # Put the best scraper first
            scraper_urls = [best_scraper] + [url for url in scraper_urls if url != best_scraper]
        
        for scraper_url in scraper_urls:
            try:
                print(f"Calling scraper at {scraper_url}/api/scrape for {email}")
                
                # Call the scraper service
                response = requests.post(
                    f"{scraper_url}/api/scrape",
                    json={
                        "email": email,
                        "cookies": cookies
                    },
                    timeout=10  # 10 second timeout
                )
                
                if response.ok:
                    successful = True
                    used_scraper_url = scraper_url
                    print(f"✅ Successfully called scraper at {scraper_url}")
                    # Update scraper status
                    started_at = datetime.utcnow().isoformat()
                    active_scrapers[email] = {
                        "status": "running", 
                        "started_at": started_at,
                        "scraper_url": scraper_url
                    }
                    
                    # Start background thread to check completion
                    print(f"Starting background completion checker for {email}")
                    completion_thread = threading.Thread(
                        target=check_scraper_completion,
                        args=(email, user_id, scraper_url)
                    )
                    completion_thread.daemon = True
                    completion_thread.start()
                    
                    break
                else:
                    errors.append(f"Scraper {scraper_url} returned: {response.status_code} - {response.text}")
            except Exception as e:
                errors.append(f"Failed to connect to {scraper_url}: {str(e)}")
                print(f"Error connecting to {scraper_url}: {e}")
        
        if successful:
            return jsonify({
                "success": True,
                "message": "Refresh process started via external scraper",
                "status": "running",
                "scraper_url": used_scraper_url
            }), 202
        else:
            error_msg = "; ".join(errors)
            print(f"All scrapers failed: {error_msg}")
            active_scrapers[email] = {"status": "failed", "error": error_msg}
            return jsonify({"success": False, "error": f"All scrapers failed: {error_msg}"}), 500
            
    except Exception as e:
        print(f"Error starting refresh: {e}")
        import traceback
        traceback.print_exc()
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    print(f"Starting server on port {port}...")
    app.run(host="0.0.0.0", port=port)









