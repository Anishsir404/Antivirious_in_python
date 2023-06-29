import os
import hashlib
import requests
from concurrent.futures import ThreadPoolExecutor

API_KEY = 'e84d1a122b9276169e70ff67f7b80fedf2ed9d826f3bcd9d3c326f69c930b2e0'  # Replace with your VirusTotal API key
MAX_THREADS = 8  # Maximum number of threads to use for scanning
MAX_FILE_SIZE = 10 * 1024 * 1024  # Maximum file size to scan in bytes (10 MB)

def calculate_md5(file_path):
    # Calculate the MD5 hash of a file
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def search_hash_virustotal(md5_hash):
    # Search VirusTotal for a given MD5 hash
    api_url = f"https://www.virustotal.com/api/v3/files/{md5_hash}"
    headers = {'x-apikey': API_KEY}
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def scan_file(file_path):
    md5_hash = calculate_md5(file_path)
    result = search_hash_virustotal(md5_hash)
    if result and result.get('data') and result['data'].get('attributes'):
        if result['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            return file_path
    return None

def scan_system():
    suspicious_files = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for root, dirs, files in os.walk('D:\\'):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.getsize(file_path) <= MAX_FILE_SIZE:
                    future = executor.submit(scan_file, file_path)
                    suspicious_file = future.result()
                    if suspicious_file:
                        suspicious_files.append(suspicious_file)

    if suspicious_files:
        print("Suspicious files found:")
        for file_path in suspicious_files:
            print(file_path)
        # Prompt the user for confirmation before taking any action

# Example usage
scan_system()
