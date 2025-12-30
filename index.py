#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
БЕЛЫЙ АНГЕЛ - OSINT Investigator v2.1
Автономный инструмент для сбора открытой информации
GitHub: https://github.com/yourusername/white-angel
Лицензия: MIT
"""

import urllib.request
import urllib.error
import json
import socket
import re
import os
import sys
import ssl
from datetime import datetime
from urllib.parse import quote

class WhiteAngel:
    """Main OSINT investigation tool class"""
    
    def __init__(self):
        self.user_agent = "WhiteAngel/2.1"
        self.timeout = 8
        self.results = []
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'purple': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'end': '\033[0m'
        }
    
    def print_logo(self):
        """Display ASCII logo"""
        logo = f"""
{self.colors['cyan']}
╔══════════════════════════════════════════════════════╗
║                                                      ║
║     ██████╗ ███████╗██╗     ██╗    ██╗    ███████╗  ║
║     ██╔══██╗██╔════╝██║     ██║    ██║    ██╔════╝  ║
║     ██████╔╝█████╗  ██║     ██║ █╗ ██║    █████╗    ║
║     ██╔══██╗██╔══╝  ██║     ██║███╗██║    ██╔══╝    ║
║     ██████╔╝███████╗███████╗╚███╔███╔╝    ███████╗  ║
║     ╚═════╝ ╚══════╝╚══════╝ ╚══╝╚══╝     ╚══════╝  ║
║                                                      ║
║     █████╗ ███╗   ██╗ ██████╗ ███████╗██╗           ║
║    ██╔══██╗████╗  ██║██╔════╝ ██╔════╝██║           ║
║    ███████║██╔██╗ ██║██║  ███╗█████╗  ██║           ║
║    ██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██║           ║
║    ██║  ██║██║ ╚████║╚██████╔╝███████╗███████╗      ║
║    ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝      ║
║                                                      ║
║               W H I T E   A N G E L                  ║
║               OSINT Investigator v2.1                ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
{self.colors['end']}"""
        print(logo)
        print(f"{self.colors['yellow']}[Session: {self.session_id}] [Time: {datetime.now().strftime('%H:%M:%S')}]{self.colors['end']}")
        print(f"{self.colors['white']}{'='*58}{self.colors['end']}")
    
    def safe_request(self, url, method='GET'):
        """Safe HTTP request with error handling"""
        try:
            context = ssl._create_unverified_context()
            request = urllib.request.Request(
                url,
                headers={'User-Agent': self.user_agent},
                method=method
            )
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:
                return {
                    'status': response.status,
                    'content': response.read().decode('utf-8', 'ignore'),
                    'headers': dict(response.getheaders())
                }
        except urllib.error.HTTPError as e:
            return {'error': f'HTTP {e.code}: {e.reason}', 'status': e.code}
        except urllib.error.URLError as e:
            return {'error': f'URL Error: {e.reason}', 'status': 0}
        except Exception as e:
            return {'error': str(e), 'status': 0}
    
    # ==================== ANALYSIS MODULES ====================
    
    def analyze_ip(self, ip):
        """Analyze IP address"""
        print(f"{self.colors['blue']}[🔍] Analyzing IP: {ip}{self.colors['end']}")
        print(f"{self.colors['white']}{'-'*50}{self.colors['end']}")
        
        results = []
        
        # IP-API.com for geolocation
        data = self.safe_request(f"http://ip-api.com/json/{ip}")
        if data.get('content'):
            info = json.loads(data['content'])
            if info.get('status') == 'success':
                results.append(f"{self.colors['green']}[+] Country: {info.get('country', 'N/A')}")
                results.append(f"[+] City: {info.get('city', 'N/A')}")
                results.append(f"[+] ISP: {info.get('isp', 'N/A')}")
                results.append(f"[+] Coordinates: {info.get('lat', 'N/A')}, {info.get('lon', 'N/A')}")
                results.append(f"[+] Timezone: {info.get('timezone', 'N/A')}{self.colors['end']}")
        
        # AbuseIPDB check
        try:
            abuse_check = self.safe_request(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}")
            if abuse_check.get('content'):
                abuse_data = json.loads(abuse_check['content'])
                if abuse_data.get('data'):
                    results.append(f"{self.colors['yellow']}[!] Abuse Score: {abuse_data['data'].get('abuseConfidenceScore', 'N/A')}")
                    results.append(f"[!] Reports: {abuse_data['data'].get('totalReports', 'N/A')}{self.colors['end']}")
        except:
            pass
        
        # Display results
        for line in results:
            print(line)
        
        self.results.extend(results)
        return results
    
    def analyze_domain(self, domain):
        """Analyze domain information"""
        print(f"{self.colors['blue']}[🌐] Analyzing Domain: {domain}{self.colors['end']}")
        print(f"{self.colors['white']}{'-'*50}{self.colors['end']}")
        
        results = []
        
        # WHOIS information
        whois_data = self.safe_request(f"https://api.hackertarget.com/whois/?q={domain}")
        if whois_data.get('content') and 'error' not in whois_data['content'].lower():
            results.append(f"{self.colors['green']}[+] WHOIS Information:{self.colors['end']}")
            for line in whois_data['content'].split('\n')[:10]:
                if line.strip():
                    results.append(f"   {line}")
        
        # DNS records
        dns_data = self.safe_request(f"https://api.hackertarget.com/dnslookup/?q={domain}")
        if dns_data.get('content') and 'error' not in dns_data['content'].lower():
            results.append(f"{self.colors['green']}[+] DNS Records:{self.colors['end']}")
            for line in dns_data['content'].split('\n')[:8]:
                if line.strip():
                    results.append(f"   {line}")
        
        # Subdomain search
        subs_data = self.safe_request(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if subs_data.get('content') and 'error' not in subs_data['content'].lower():
            subdomains = [line.split(',')[0] for line in subs_data['content'].split('\n') if line]
            if subdomains:
                results.append(f"{self.colors['green']}[+] Found Subdomains:{self.colors['end']}")
                for sub in subdomains[:5]:
                    results.append(f"   • {sub}")
        
        # Display results
        for line in results:
            print(line)
        
        self.results.extend(results)
        return results
    
    def analyze_phone(self, phone):
        """Analyze phone number"""
        print(f"{self.colors['blue']}[📱] Analyzing Phone: {phone}{self.colors['end']}")
        print(f"{self.colors['white']}{'-'*50}{self.colors['end']}")
        
        results = []
        
        # Clean phone number
        clean = re.sub(r'[^0-9+]', '', phone)
        results.append(f"{self.colors['green']}[+] Clean Number: {clean}")
        
        # Messaging links
        results.append(f"[+] Messaging Links:{self.colors['end']}")
        results.append(f"   WhatsApp: https://wa.me/{clean}")
        results.append(f"   Telegram: https://t.me/{clean}")
        results.append(f"   Viber: viber://chat?number={clean}")
        
        # Google search
        query = quote(f'"{phone}" OR "{clean}"')
        results.append(f"{self.colors['green']}[+] Search Links:{self.colors['end']}")
        results.append(f"   Google: https://www.google.com/search?q={query}")
        
        # Display results
        for line in results:
            print(line)
        
        self.results.extend(results)
        return results
    
    def analyze_email(self, email):
        """Analyze email address"""
        print(f"{self.colors['blue']}[📧] Analyzing Email: {email}{self.colors['end']}")
        print(f"{self.colors['white']}{'-'*50}{self.colors['end']}")
        
        results = []
        
        # Validate format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            print(f"{self.colors['red']}[-] Invalid email format{self.colors['end']}")
            return results
        
        results.append(f"{self.colors['green']}[+] Valid Email: Yes")
        
        # Split email
        local, domain = email.split('@')
        results.append(f"[+] Local Part: {local}")
        results.append(f"[+] Domain: {domain}")
        
        # Social media search
        results.append(f"[+] Social Media Links:{self.colors['end']}")
        results.append(f"   VK: https://vk.com/{local}")
        results.append(f"   Telegram: https://t.me/{local}")
        results.append(f"   GitHub: https://github.com/{local}")
        
        # Breach check links
        results.append(f"{self.colors['green']}[+] Breach Check:{self.colors['end']}")
        results.append(f"   HaveIBeenPwned: https://haveibeenpwned.com/account/{email}")
        results.append(f"   Firefox Monitor: https://monitor.firefox.com/scan/{email}")
        
        # Display results
        for line in results:
            print(line)
        
        self.results.extend(results)
        return results
    
    def search_username(self, username):
        """Search username across platforms"""
        print(f"{self.colors['blue']}[👤] Searching Username: {username}{self.colors['end']}")
        print(f"{self.colors['white']}{'-'*50}{self.colors['end']}")
        
        results = []
        found = []
        
        # Platforms to check
        platforms = [
            ('VK', f'https://vk.com/{username}'),
            ('Telegram', f'https://t.me/{username}'),
            ('GitHub', f'https://github.com/{username}'),
            ('Instagram', f'https://instagram.com/{username}'),
            ('Twitter/X', f'https://twitter.com/{username}'),
            ('YouTube', f'https://youtube.com/@{username}'),
            ('Twitch', f'https://twitch.tv/{username}')
        ]
        
        print(f"{self.colors['yellow']}[*] Checking platforms...{self.colors['end']}")
        
        for platform, url in platforms:
            try:
                response = self.safe_request(url)
                if response.get('status', 0) < 400:
                    found.append((platform, url))
                    print(f"{self.colors['green']}   ✓ {platform}{self.colors['end']}")
                else:
                    print(f"{self.colors['white']}   ✗ {platform}{self.colors['end']}")
            except:
                print(f"{self.colors['white']}   ? {platform}{self.colors['end']}")
        
        if found:
            results.append(f"{self.colors['green']}[+] Found Profiles:{self.colors['end']}")
            for platform, url in found:
                results.append(f"   • {platform}: {url}")
        else:
            results.append(f"{self.colors['yellow']}[-] No profiles found{self.colors['end']}")
        
        # Search engines
        results.append(f"{self.colors['green']}[+] Search Engine Links:{self.colors['end']}")
        results.append(f"   Google: https://www.google.com/search?q=%22{username}%22")
        results.append(f"   Yandex: https://yandex.ru/search/?text=%22{username}%22")
        
        # Display results
        for line in results:
            print(line)
        
        self.results.extend(results)
        return results
    
    def save_report(self):
        """Save results to file"""
        if not self.results:
            print(f"{self.colors['red']}[-] No data to save{self.colors['end']}")
            return
        
        filename = f"white_angel_report_{self.session_id}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write(f"WHITE ANGEL OSINT REPORT - {datetime.now()}\n")
                f.write("=" * 60 + "\n\n")
                
                for result in self.results:
                    clean_result = re.sub(r'\033\[[0-9;]*m', '', result)
                    f.write(clean_result + "\n")
            
            print(f"{self.colors['green']}[+] Report saved: {filename}{self.colors['end']}")
            return filename
        except Exception as e:
            print(f"{self.colors['red']}[-] Error saving report: {e}{self.colors['end']}")
            return None
    
    def show_menu(self):
        """Display main menu"""
        while True:
            print(f"\n{self.colors['purple']}{'='*50}{self.colors['end']}")
            print(f"{self.colors['cyan']}[ WHITE ANGEL MENU ]{self.colors['end']}")
            print(f"{self.colors['purple']}{'='*50}{self.colors['end']}")
            
            print(f"{self.colors['white']}1. 🔍 Analyze IP Address")
            print("2. 🌐 Analyze Domain")
            print("3. 📱 Analyze Phone Number")
            print("4. 📧 Analyze Email")
            print("5. 👤 Search Username")
            print("6. 💾 Save Report")
            print("7. 🚪 Exit")
            print(f"{self.colors['purple']}{'='*50}{self.colors['end']}")
            
            choice = input(f"\n{self.colors['yellow']}[?] Select option (1-7): {self.colors['end']}").strip()
            
            if choice == '1':
                target = input(f"{self.colors['blue']}[IP] Enter IP address: {self.colors['end']}").strip()
                if target:
                    self.analyze_ip(target)
            
            elif choice == '2':
                target = input(f"{self.colors['blue']}[Domain] Enter domain: {self.colors['end']}").strip()
                if target:
                    self.analyze_domain(target)
            
            elif choice == '3':
                target = input(f"{self.colors['blue']}[Phone] Enter phone number: {self.colors['end']}").strip()
                if target:
                    self.analyze_phone(target)
            
            elif choice == '4':
                target = input(f"{self.colors['blue']}[Email] Enter email: {self.colors['end']}").strip()
                if target:
                    self.analyze_email(target)
            
            elif choice == '5':
                target = input(f"{self.colors['blue']}[Username] Enter username: {self.colors['end']}").strip()
                if target:
                    self.search_username(target)
            
            elif choice == '6':
                self.save_report()
            
            elif choice == '7':
                print(f"\n{self.colors['green']}[+] Thank you for using White Angel!{self.colors['end']}")
                break
            
            else:
                print(f"\n{self.colors['red']}[-] Invalid choice{self.colors['end']}")
            
            input(f"\n{self.colors['white']}[Press Enter to continue...]{self.colors['end']}")

def main():
    """Main entry point"""
    try:
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Create tool instance
        tool = WhiteAngel()
        
        # Show logo
        tool.print_logo()
        
        # Run menu
        tool.show_menu()
        
    except KeyboardInterrupt:
        print(f"\n{self.colors['yellow']}[!] Interrupted by user{self.colors['end']}")
    except Exception as e:
        print(f"\n{self.colors['red']}[!] Critical error: {e}{self.colors['end']}")

if __name__ == "__main__":
    # Check Python version
    if sys.version_info[0] < 3:
        print("White Angel requires Python 3.6 or higher")
        sys.exit(1)
    
    # Run main function
    main()
