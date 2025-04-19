import json
import os
import sys
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Supabase client
supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_KEY")
supabase = create_client(supabase_url, supabase_key)

def check_timetable_structure(email=None, user_id=None):
    """
    Check the structure of timetable data for a user
    """
    try:
        # Get user ID if email is provided
        if email and not user_id:
            user_query = supabase.table("users").select("id").eq("email", email).execute()
            if not user_query.data:
                print(f"User not found for email: {email}")
                return None
            user_id = user_query.data[0]["id"]
            print(f"Found user ID: {user_id} for email: {email}")
        
        # Get timetable data
        tt_resp = supabase.table("timetable").select("*").eq("user_id", user_id).execute()
        if not tt_resp.data or len(tt_resp.data) == 0:
            print(f"No timetable data found for user ID: {user_id}")
            return None
        
        timetable_data = tt_resp.data[0]
        print(f"Found timetable data for user ID: {user_id}")
        
        # Check timetable structure
        merged_tt = timetable_data.get("timetable_data", {})
        
        # Count empty and non-empty course arrays
        empty_count = 0
        non_empty_count = 0
        
        for day, day_data in merged_tt.items():
            print(f"\nDay: {day}")
            for time_slot, slot_data in day_data.items():
                courses = slot_data.get("courses", [])
                if not courses:
                    empty_count += 1
                    print(f"  {time_slot}: Empty courses array, slot code: {slot_data.get('original_slot', 'N/A')}")
                else:
                    non_empty_count += 1
                    course_titles = [c.get("title", "Unknown") for c in courses]
                    print(f"  {time_slot}: {', '.join(course_titles)}")
        
        print(f"\nSummary: {empty_count} empty slots, {non_empty_count} non-empty slots")
        
        # Return the timetable data for further analysis
        return timetable_data
    
    except Exception as e:
        print(f"Error checking timetable structure: {e}")
        import traceback
        traceback.print_exc()
        return None

def fix_timetable_data(email=None, user_id=None):
    """
    Fix timetable data for a user by ensuring courses are properly mapped
    """
    try:
        # Get user ID if email is provided
        if email and not user_id:
            user_query = supabase.table("users").select("id").eq("email", email).execute()
            if not user_query.data:
                print(f"User not found for email: {email}")
                return False
            user_id = user_query.data[0]["id"]
            print(f"Found user ID: {user_id} for email: {email}")
        
        # Get timetable data
        tt_resp = supabase.table("timetable").select("*").eq("user_id", user_id).execute()
        if not tt_resp.data or len(tt_resp.data) == 0:
            print(f"No timetable data found for user ID: {user_id}")
            return False
        
        timetable_data = tt_resp.data[0]
        print(f"Found timetable data for user ID: {user_id}")
        
        # Get course data
        course_data = timetable_data.get("course_data", [])
        if not course_data:
            print("No course data found in timetable record")
            return False
        
        print(f"Found {len(course_data)} courses in timetable record")
        
        # Create enhanced mapping
        enhanced_mapping = {}
        
        # Process each course
        for course in course_data:
            slot = course.get("slot", "").strip()
            if not slot:
                continue
            
            course_info = {
                "title": course.get("course_title", "").strip(),
                "faculty": course.get("faculty_name", "").strip(),
                "room": course.get("room_no", "").strip(),
                "code": course.get("course_code", "").strip(),
                "type": course.get("course_type", "").strip(),
                "gcr_code": course.get("gcr_code", "").strip()
            }
            
            print(f"Processing course: {course_info['code']} - {course_info['title']} with slot {slot}")
            
            # Handle regular slots with possible "/X" format
            if "/" in slot and "-" not in slot:
                slot_parts = [s.strip() for s in slot.split("/") if s.strip()]
                for part in slot_parts:
                    enhanced_mapping[part] = course_info
                    print(f"Mapped slot part '{part}' to course {course_info['title']}")
                    
                    # Also map with dash
                    if not part.endswith("-"):
                        enhanced_mapping[f"{part}-"] = course_info
                        print(f"Also mapped with dash '{part}-' to course {course_info['title']}")
            
            # Special handling for multi-slot lab courses
            elif "-" in slot:
                slot_codes = []
                
                # Handle different lab slot formats
                import re
                if re.search(r'P\d+-P\d+-', slot):  # Format: P37-P38-P39-
                    slot_parts = [s.strip() for s in re.findall(r'(P\d+)-', slot)]
                    slot_codes.extend(slot_parts)
                else:  # Format: P37-38-39- (without repeating P)
                    prefix_match = re.match(r'(P)(\d+)-', slot)
                    if prefix_match:
                        prefix = prefix_match.group(1)
                        numbers = re.findall(r'(\d+)-', slot)
                        slot_codes = [f"{prefix}{num}" for num in numbers]
                
                # Register these slot codes with the course
                for code in slot_codes:
                    # With dash
                    enhanced_mapping[f"{code}-"] = course_info
                    print(f"Mapped lab slot code '{code}-' to course {course_info['title']}")
                    
                    # Without dash
                    enhanced_mapping[code] = course_info
                    print(f"Also mapped without dash '{code}' to course {course_info['title']}")
                
                # Also register the full original slot
                enhanced_mapping[slot] = course_info
            
            # Regular single slot
            else:
                # Map both with and without dash
                enhanced_mapping[slot] = course_info
                print(f"Mapped regular slot '{slot}' to course {course_info['title']}")
                
                if slot.endswith("-"):
                    slot_without_dash = slot[:-1]
                    enhanced_mapping[slot_without_dash] = course_info
                    print(f"Also mapped without dash '{slot_without_dash}' to course {course_info['title']}")
                else:
                    slot_with_dash = f"{slot}-"
                    enhanced_mapping[slot_with_dash] = course_info
                    print(f"Also mapped with dash '{slot_with_dash}' to course {course_info['title']}")
        
        # Now update the timetable data
        merged_tt = timetable_data.get("timetable_data", {})
        
        # Count fixed slots
        fixed_count = 0
        
        for day, day_data in merged_tt.items():
            for time_slot, slot_data in day_data.items():
                original_slot = slot_data.get("original_slot", "")
                
                # Skip empty slots
                if not original_slot or original_slot in ["X", "-", "empty", "break"]:
                    continue
                
                # If courses array is empty, try to find a match
                if not slot_data.get("courses", []):
                    # Try exact match
                    if original_slot in enhanced_mapping:
                        course_info = enhanced_mapping[original_slot]
                        merged_tt[day][time_slot]["courses"] = [course_info]
                        merged_tt[day][time_slot]["display"] = f"{course_info['title']} ({time_slot})"
                        fixed_count += 1
                        print(f"Fixed {day} {time_slot} with slot {original_slot} -> {course_info['title']}")
                    
                    # Try with dash
                    elif f"{original_slot}-" in enhanced_mapping:
                        course_info = enhanced_mapping[f"{original_slot}-"]
                        merged_tt[day][time_slot]["courses"] = [course_info]
                        merged_tt[day][time_slot]["display"] = f"{course_info['title']} ({time_slot})"
                        fixed_count += 1
                        print(f"Fixed {day} {time_slot} with slot {original_slot}- -> {course_info['title']}")
                    
                    # Try without dash
                    elif original_slot.endswith("-") and original_slot[:-1] in enhanced_mapping:
                        course_info = enhanced_mapping[original_slot[:-1]]
                        merged_tt[day][time_slot]["courses"] = [course_info]
                        merged_tt[day][time_slot]["display"] = f"{course_info['title']} ({time_slot})"
                        fixed_count += 1
                        print(f"Fixed {day} {time_slot} with slot {original_slot[:-1]} -> {course_info['title']}")
                    
                    # Handle slots with "/"
                    elif "/" in original_slot:
                        parts = [s.strip() for s in original_slot.split("/") if s.strip()]
                        matched = []
                        
                        for p in parts:
                            if p in enhanced_mapping:
                                matched.append(enhanced_mapping[p])
                            elif f"{p}-" in enhanced_mapping:
                                matched.append(enhanced_mapping[f"{p}-"])
                        
                        if matched:
                            titles = " / ".join(mc["title"] for mc in matched)
                            merged_tt[day][time_slot]["courses"] = matched
                            merged_tt[day][time_slot]["display"] = f"{titles} ({time_slot})"
                            fixed_count += 1
                            print(f"Fixed {day} {time_slot} with slot {original_slot} -> {titles}")
        
        print(f"\nFixed {fixed_count} slots in the timetable")
        
        # Update the timetable data in the database
        update_data = {
            "timetable_data": merged_tt
        }
        
        update_resp = supabase.table("timetable").update(update_data).eq("user_id", user_id).execute()
        if not update_resp.data:
            print("Failed to update timetable data in database")
            return False
        
        print("Successfully updated timetable data in database")
        return True
    
    except Exception as e:
        print(f"Error fixing timetable data: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # Check if email is provided as command line argument
    if len(sys.argv) > 1:
        email = sys.argv[1]
        print(f"Checking timetable structure for email: {email}")
        timetable_data = check_timetable_structure(email=email)
        
        if timetable_data:
            # Ask if user wants to fix the timetable data
            response = input("Do you want to fix the timetable data? (y/n): ")
            if response.lower() == "y":
                success = fix_timetable_data(email=email)
                if success:
                    print("Timetable data fixed successfully")
                else:
                    print("Failed to fix timetable data")
    else:
        print("Usage: python debug_timetable.py <email>")
