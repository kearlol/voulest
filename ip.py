import requests
import subprocess
import socket
import sys
import ssl
import concurrent.futures
import whois
from requests.exceptions import RequestException
from datetime import datetime
import os

def current_time_hour():
    return datetime.now().strftime("%H:%M:%S")

def Title(text):
    print(f"\n[INFO] {text}\n")

def Error(message):
    print(f"[ERROR] {message}\n")

def ErrorModule(exception):
    Error(f"Failed to import modules: {exception}")

def Continue():
    input("\nPress Enter to continue...")

def Reset():
    os.system('cls' if os.name == 'nt' else 'clear')

def Slow(text):
    print(text)

def ip_type(ip):
    if ':' in ip:
        type = "ipv6"
    elif '.' in ip:
        type = "ipv4"
    else:
        type = "Unknown"
    print(f"[INFO] IP Type: {type}")

def ip_ping(ip):
    try:
        if sys.platform.startswith("win"):
            result = subprocess.run(['ping', '-n', '1', ip], capture_output=True, text=True, timeout=1)
        else:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], capture_output=True, text=True, timeout=1)
        if result.returncode == 0:
            ping = "Succeed"
        else:
            ping = "Fail"
    except:
        ping = "Fail"
    print(f"[INFO] Ping: {ping}")

def ip_port(ip):
    port_protocol_map = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
        80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 194: "IRC", 389: "LDAP",
        443: "HTTPS", 161: "SNMP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        1521: "Oracle DB", 3389: "RDP"
    }
    port_list = [21, 22, 23, 25, 53, 69, 80, 110, 123, 143, 194, 389, 443, 161, 3306, 5432, 6379, 1521, 3389]

    def scan_port(ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                protocol = identify_protocol(ip, port)
                print(f"[INFO] Port: {port} Status: Open Protocol: {protocol}")
            sock.close()
        except:
            pass

    def identify_protocol(ip, port):
        try:
            if port in port_protocol_map:
                return port_protocol_map[port]
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((ip, port))
                
                sock.send(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip).encode('utf-8'))
                response = sock.recv(100).decode('utf-8')
                if "HTTP" in response:
                    return "HTTP"

                sock.send(b"\r\n")
                response = sock.recv(100).decode('utf-8')
                if "FTP" in response:
                    return "FTP"

                sock.send(b"\r\n")
                response = sock.recv(100).decode('utf-8')
                if "SSH" in response:
                    return "SSH"

                return "Unknown"
        except:
            return "Unknown"

    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = {executor.submit(scan_port, ip, port): port for port in port_list}
    concurrent.futures.wait(results)

def ip_dns(ip):
    try:
        dns, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
        print(f"[INFO] DNS: {dns}")
    except:
        print("[INFO] DNS: None")

def ip_host_info(ip):
    api_url = f"https://ipinfo.io/{ip}/json"
    try:
        response = requests.get(api_url)
        api = response.json()
    except RequestException:
        api = {}

    host_ip = api.get('ip', 'None')
    host_hostname = api.get('hostname', 'None')
    host_city = api.get('city', 'None')
    host_region = api.get('region', 'None')
    host_country = api.get('country', 'None')
    host_location = api.get('loc', 'None')
    host_timezone = api.get('timezone', 'None')
    host_isp = api.get('org', 'None')
    host_as = api.get('asn', 'None')

    if host_ip != "None":
        print(f"[INFO] IP: {host_ip}")
    if host_hostname != "None":
        print(f"[INFO] Hostname: {host_hostname}")
    if host_city != "None":
        print(f"[INFO] City: {host_city}")
    if host_region != "None":
        print(f"[INFO] Region: {host_region}")
    if host_country != "None":
        print(f"[INFO] Country: {host_country}")
    if host_location != "None":
        loc_lat, loc_lon = host_location.split(',')
        print(f"[INFO] Location: Latitude {loc_lat}, Longitude {loc_lon}")
    if host_timezone != "None":
        print(f"[INFO] Timezone: {host_timezone}")
    if host_isp != "None":
        print(f"[INFO] ISP: {host_isp}")
    if host_as != "None":
        print(f"[INFO] AS: {host_as}")

def ssl_certificate_check(ip):
    port = 443
    try:
        sock = socket.create_connection((ip, port), timeout=1)
        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=ip) as ssock:
            cert = ssock.getpeercert()
            print(f"[INFO] SSL Certificate: {cert}")
    except Exception as e:
        print(f"[INFO] SSL Certificate Check Failed: {e}")

def whois_info(ip):
    try:
        w = whois.whois(ip)
        print(f"[INFO] WHOIS Information:")
        print(f"[INFO] Domain Name: {w.domain_name}")
        print(f"[INFO] Registrar: {w.registrar}")
        print(f"[INFO] Creation Date: {w.creation_date}")
        print(f"[INFO] Expiration Date: {w.expiration_date}")
        print(f"[INFO] Updated Date: {w.updated_date}")
        print(f"[INFO] Name Servers: {w.name_servers}")
        print(f"[INFO] Status: {w.status}")
    except Exception as e:
        print(f"[INFO] WHOIS Information Check Failed: {e}")

def main_menu():
    map_banner = r"""
    __        ______  _    _   _      ____   _____ _______ 
    \ \      / / __ \| |  | | | |    / __ \ / ____|__   __|
     \ \    / / |  | | |  | | | |   | |  | | (___    | |   
      \ \  / /| |  | | |  | | | |   | |  | |\___ \   | |   
       \ \/ / | |__| | |__| | | |___| |__| |____) |  | |   
        \__/   \____/ \____/  |______\____/|_____/   |_|   
                                                          
    """
    print(map_banner)
    ip = input(f"[INFO] Enter IP address to lookup: ").strip()
    print(f"[INFO] Information Recovery..")
    print(f"[INFO] IP: {ip}")
    
    ip_type(ip)
    ip_ping(ip)
    ip_dns(ip)
    ip_port(ip)
    ip_host_info(ip)
    ssl_certificate_check(ip)
    whois_info(ip)
    
    Continue()
    Reset()

if __name__ == "__main__":
    try:
        Title("IP Scanner")
        Slow("Starting IP Scanner...")
        while True:
            main_menu()
    except Exception as e:
        Error(e)
