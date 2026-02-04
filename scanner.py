import requests
import base64
import datetime

# --- CONFIGURATION ---
# Your "Security Badge" (API Key)
API_KEY = 'YOUR_API_KEY_HERE'

# --- PHASE 1: INPUT & ENRICHMENT ---
target_url = input("Which URL should I investigate? ")

# Scramble URL for VirusTotal (Base64)
url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")

# Setting up the request
url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
headers = {"x-apikey": API_KEY}

print(f"\nChecking {target_url}...")
response = requests.get(url, headers=headers)

# --- PHASE 2: LOGIC & OUTPUT ---
if response.status_code == 200:
    result = response.json()
    stats = result['data']['attributes']['last_analysis_stats']
    
    # Extract the numbers
    m_count = stats['malicious']
    s_count = stats['suspicious']
    h_count = stats['harmless']
    
    print("-" * 30)
    print(f"REPORT FOR: {target_url}")
    print(f"Malicious:  {m_count}")
    print(f"Suspicious: {s_count}")
    print(f"Harmless:   {h_count}")
    print("-" * 30)
    
    # Determine the Status Message
    if m_count > 1:
        status_msg = "🚨 DANGER"
    elif m_count == 1 or s_count > 0:
        status_msg = "⚠️ REVIEW REQUIRED"
    else:
        status_msg = "✅ CLEAN"
        
    print(f"FINAL RESULT: {status_msg}")

    # --- PHASE 3: RECORD KEEPING (LOGGING) ---
    # We log everything that isn't 100% clean
    if status_msg != "✅ CLEAN":
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("alerts.log", "a") as log_file:
            log_file.write(f"[{now}] {status_msg} | URL: {target_url} | M:{m_count} S:{s_count}\n")
        print(f"\n[System] Entry successfully added to alerts.log")

else:
    print(f"Error: {response.status_code}. Please check your API key or the URL.")
