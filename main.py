import os
import yara
import hashlib
import concurrent.futures
from pybloom_live import BloomFilter
import datetime

# Constants
MAX_THREADS = 8  # Maximum number of threads to use for scanning
MAX_FILE_SIZE = 10 * 1024 * 1024  # Maximum file size to scan in bytes (10 MB)

def load_yara_rules(rule_dir):
    try:
        rule_files = {file: os.path.join(rule_dir, file) for file in os.listdir(rule_dir) if file.endswith('.yar')}
        yara_rules = yara.compile(filepaths=rule_files)
        return yara_rules
    except yara.SyntaxError as e:
        print(f"SyntaxError in YARA rules: {e}")
        return None
    except Exception as e:
        print(f"Error loading YARA rules: {e}")
        return None

def get_threat_level(meta):
    if 'threat_level' in meta:
        return meta['threat_level']
    return 'Unknown'

def calculate_md5(file_path):
    # Calculate the MD5 hash of a file
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def create_malware_bloom_filter(malware_hash_file):
    # Create a Bloom filter from the malware_hash.txt file
    malware_bloom_filter = BloomFilter(capacity=1000000, error_rate=0.001)
    with open(malware_hash_file, 'r') as f:
        for line in f:
            hash_value = line.strip()
            if hash_value:
                malware_bloom_filter.add(hash_value)
    return malware_bloom_filter

def scan_file(file_path, yara_rules, malware_bloom_filter, suspicious_files):
    # Scan a file using YARA rules and check for malware hashes using the Bloom filter
    try:
        matches = yara_rules.match(filepath=file_path)
        md5_hash = calculate_md5(file_path)
        if matches or md5_hash in malware_bloom_filter:
            print(f"File: {file_path}")
            for match in matches:
                print(f"Rule: {match.rule}")
                print(f"Metadata: {match.meta}")
                print(f"Threat Level: {get_threat_level(match.meta)}")
            if md5_hash in malware_bloom_filter:
                print("Detected as malware (based on MD5 hash)")
            print("-----------------------")
            suspicious_files.append(file_path)
    except Exception as e:
        print(f"Error scanning file {file_path}: {e}")

def scan_directory(directory_path, yara_rules, malware_bloom_filter):
    if yara_rules is None:
        return

    print("Scanning directory...")
    suspicious_files = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for root, dirs, files in os.walk(directory_path):
            for dir_name in list(dirs):
                if rule_dir in os.path.join(root, dir_name):
                    dirs.remove(dir_name)
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.getsize(file_path) <= MAX_FILE_SIZE:
                    executor.submit(scan_file, file_path, yara_rules, malware_bloom_filter, suspicious_files)

    if suspicious_files:
        print("\nSuspicious files found:")
        for i, file_path in enumerate(suspicious_files):
            print(f"{i+1}. {file_path}")
        
        # Prompt the user for confirmation
        for file_path in suspicious_files:
                choice = input(f"Do you want to delete the file '{file_path}'? (y/n): ")
                if choice.lower() == "y":
                    try:
                        os.remove(file_path)
                        print(f"Deleted: {file_path}")
                    except Exception as e:
                        print(f"Error deleting file {file_path}: {e}")
                else:
                    print(f"Skipped: {file_path}")

    print("Writing scan results to log file...")

    # Write scan results to log file
    log_file_path = 'scan_results.log'
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file_path, 'a') as log_file:
        log_file.write(f"\nScan Time: {current_time}\n")
        log_file.write(f"Directory: {directory_path}\n")
        log_file.write(f"Number of Suspicious Files: {len(suspicious_files)}\n")
        log_file.write("-----------------------\n")
        for file_path in suspicious_files:
            log_file.write(f"File: {file_path}\n")
            for match in yara_rules.match(filepath=file_path):
                log_file.write(f"Rule: {match.rule}\n")
                log_file.write(f"Metadata: {match.meta}\n")
                log_file.write(f"Threat Level: {get_threat_level(match.meta)}\n")
            log_file.write("-----------------------\n")

    print(f"Scan results written to log file: {log_file_path}")

# Example usage
while True:
    rule_dir = "D:\\3rd-sem\\programming\\project\\antivirus\\rules"
    yara_rules = load_yara_rules(rule_dir)
    malware_hash_file = "malware_hash.txt"
    malware_bloom_filter = create_malware_bloom_filter(malware_hash_file)
    print("Antivirus Scanner")
    print("1. Scan All Files")
    print("2. Scan Directory")
    print("3. Exit")

    choice = input("Enter your choice (1-3): ")

    if choice == '1':
        scan_directory('/')
    elif choice == '2':
        directory_path = input("Enter the directory path to scan: ")
        scan_directory(directory_path, yara_rules, malware_bloom_filter)
    elif choice == '3':
        break
    else:
        print("Invalid choice. Please try again.")

print("Exiting...")