import os
import time
import requests
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Warna untuk tampilan
COLOR = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "RED": "\033[91m",
    "END": "\033[0m",
    "BOLD": "\033[1m"
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_header():
    clear_screen()
    print(f"""{COLOR['HEADER']}
╔══════════════════════════╗#
║██████╗░██╗░░░██╗░██████╗░║  - "   |   -   '   __
║██╔══██╗██║░░░██║██╔════╝░║-7  -  _
║██████╦╝██║░░░██║██║░░██╗░║ +          _||
║██╔══██╗██║░░░██║██║░░╚██╗║ 0  *   <"  
║██████╦╝╚██████╔╝╚██████╔╝║ ×  -   *   =   <"  _
║╚═════╝░░╚═════╝░░╚═════╝░╚═════════════════════════╗
║██████╗░░█████╗░██╗░░░██╗███╗░░██╗████████╗██╗░░░██╗║
║██╔══██╗██╔══██╗██║░░░██║████╗░██║╚══██╔══╝╚██╗░██╔╝║
║██████╦╝██║░░██║██║░░░██║██╔██╗██║░░░██║░░░░╚████╔╝░║
║██╔══██╗██║░░██║██║░░░██║██║╚████║░░░██║░░░░░╚██╔╝░░║
║██████╦╝╚█████╔╝╚██████╔╝██║░╚███║░░░██║░░░░░░██║░░░║
║╚═════╝░░╚════╝░░╚═════╝░╚═╝░░╚══╝░░░╚═╝░░░░░░╚═╝░░░║
╚════════════════════════════════════════════════════╝
    {COLOR['END']}{COLOR['BOLD']}v1.0 | Created by x dev{COLOR['END']}
    """)

def display_menu():
    print(f"""
    {COLOR['GREEN']}[1]{COLOR['END']} Memindai Kerentanan Situs Web (Pemindaian Mendalam)
    {COLOR['GREEN']}[2]{COLOR['END']} Tentang Program
    {COLOR['GREEN']}[3]{COLOR['END']} Keluar
    """)

def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def deep_scan(target):
    print(f"\n{COLOR['BLUE']}[+] Memulai pemindaian mendalam {target}{COLOR['END']}\n")
    time.sleep(1)

    vulnerabilities = []

    # 1. Check HTTP headers and server info
    try:
        print(f"{COLOR['BLUE']}[+] Memeriksa header HTTP...{COLOR['END']}")
        response = requests.get(target, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
        headers = response.headers

        # Check for sensitive headers
        sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']
        for header in sensitive_headers:
            if header in headers:
                vuln = f"Info server terekspos di {header}: {headers[header]}"
                print(f"{COLOR['YELLOW']}[!] {vuln}{COLOR['END']}")
                vulnerabilities.append(vuln)

        # Check security headers
        security_headers = ['x-frame-options', 'x-xss-protection', 'x-content-type-options', 
                           'content-security-policy', 'strict-transport-security']
        missing_headers = [h for h in security_headers if h not in headers]
        if missing_headers:
            vuln = f"Header keamanan hilang: {', '.join(missing_headers)}"
            print(f"{COLOR['YELLOW']}[!] {vuln}{COLOR['END']}")
            vulnerabilities.append(vuln)

    except Exception as e:
        print(f"{COLOR['RED']}[!] Kesalahan saat memeriksa header: {str(e)}{COLOR['END']}")

    # 2. Check for sensitive files
    print(f"\n{COLOR['BLUE']}[+] Memeriksa file sensitif...{COLOR['END']}")
    sensitive_files = [
        'robots.txt', '.env', 'config.php', 'database.db', 'backup.zip',
        'wp-config.php', 'settings.ini', 'web.config', '.git/config',
        '.htaccess', 'phpinfo.php', 'adminer.php', 'dump.sql',
        'backup.tar.gz', 'credentials.json', 'config.json'
    ]

    for file in sensitive_files:
        try:
            url = f"{target}/{file}" if target.endswith('/') else f"{target}/{file}"
            res = requests.get(url, timeout=10, allow_redirects=False)

            if res.status_code == 200:
                vuln = f"File sensitif terekspos: {url}"
                print(f"{COLOR['YELLOW']}[!] {vuln}{COLOR['END']}")
                vulnerabilities.append(vuln)

                # If it's a database file, check if we can download it
                if file.endswith(('.db', '.sql', '.zip', '.tar.gz')):
                    try:
                        content = res.content
                        if len(content) > 0:
                            vuln = f"Database/backup file dapat diunduh: {url} (Size: {len(content)} bytes)"
                            print(f"{COLOR['RED']}[!] CRITICAL: {vuln}{COLOR['END']}")
                            vulnerabilities.append(vuln)
                    except:
                        pass

        except:
            pass

    # 3. Check directory listing
    print(f"\n{COLOR['BLUE']}[+] Memeriksa daftar direktori...{COLOR['END']}")
    test_dirs = ['images/', 'uploads/', 'assets/', 'backup/', 'admin/']
    for directory in test_dirs:
        try:
            url = f"{target}/{directory}" if target.endswith('/') else f"{target}/{directory}"
            res = requests.get(url, timeout=10)

            # Simple check for directory listing
            if "Index of /" in res.text or "Daftar direktori untuk /" in res.text:
                vuln = f"Daftar direktori diaktifkan: {url}"
                print(f"{COLOR['YELLOW']}[!] {vuln}{COLOR['END']}")
                vulnerabilities.append(vuln)
        except:
            pass

    # 4. Check common admin panels
    print(f"\n{COLOR['BLUE']}[+] Memeriksa admin panel...{COLOR['END']}")
    admin_panels = [
        'admin/', 'wp-admin/', 'administrator/', 'login/', 
        'dashboard/', 'manager/', 'admin.php', 'admin.asp'
    ]

    for panel in admin_panels:
        try:
            url = f"{target}/{panel}" if target.endswith('/') else f"{target}/{panel}"
            res = requests.get(url, timeout=10, allow_redirects=False)

            if res.status_code == 200:
                vuln = f"Admin panel ditemukan: {url}"
                print(f"{COLOR['YELLOW']}[!] {vuln}{COLOR['END']}")
                vulnerabilities.append(vuln)
        except:
            pass

    # 5. Check for SQL injection vulnerability (basic check)
    print(f"\n{COLOR['BLUE']}[+] Memeriksa kerentanan SQLi dasar...{COLOR['END']}")
    try:
        test_url = f"{target}/product?id=1'"
        res = requests.get(test_url, timeout=15)

        sql_errors = [
            "SQL syntax", "MySQL server", "syntax error", "unclosed quotation mark",
            "ODBC Driver", "ORA-", "PostgreSQL", "Microsoft OLE DB Provider"
        ]

        if any(error in res.text for error in sql_errors):
            vuln = f"Kemungkinan kerentanan injeksi SQL di: {test_url}"
            print(f"{COLOR['RED']}[!] CRITICAL: {vuln}{COLOR['END']}")
            vulnerabilities.append(vuln)
    except:
        pass

    # 6. Check for XSS vulnerability (basic check)
    print(f"\n{COLOR['BLUE']}[+] Memeriksa kerentanan XSS dasar...{COLOR['END']}")
    try:
        test_url = f"{target}/search?q=<script>alert('XSS')</script>"
        res = requests.get(test_url, timeout=15)

        if "<script>alert('XSS')</script>" in res.text:
            vuln = f"Kemungkinan kerentanan XSS di: {test_url}"
            print(f"{COLOR['RED']}[!] CRITICAL: {vuln}{COLOR['END']}")
            vulnerabilities.append(vuln)
    except:
        pass

    # 7. Check for open ports
    print(f"\n{COLOR['BLUE']}[+] Memeriksa port yang terbuka....{COLOR['END']}")
    try:
        domain = urlparse(target).netloc.split(':')[0]
        ports_to_check = [21, 22, 23, 80, 443, 3306, 3389, 8080, 8443]

        for port in ports_to_check:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            if result == 0:
                vuln = f"Port {port} terbuka"
                print(f"{COLOR['YELLOW']}[!] {vuln}{COLOR['END']}")
                vulnerabilities.append(vuln)
            sock.close()
    except Exception as e:
        print(f"{COLOR['RED']}[!] Kesalahan saat memeriksa port: {str(e)}{COLOR['END']}")

    return vulnerabilities

def generate_report(target, vulnerabilities):
    if not vulnerabilities:
        print(f"\n{COLOR['GREEN']}[✓] Tidak ditemukan kerentanan yang jelas {COLOR['END']}")
        return

    print(f"\n{COLOR['RED']}[!] Ditemukan {len(vulnerabilities)} kerentanan:{COLOR['END']}")
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f" {i}. {vuln}")

    print(f"\n{COLOR['BLUE']}[+] Rekomendasi keamanan:{COLOR['END']}")
    print(" 1. Hapus atau batasi akses ke file sensitif")
    print(" 2. Nonaktifkan daftar direktori dalam konfigurasi server")
    print(" 3. Terapkan header keamanan yang tepat")
    print(" 4. Bersihkan semua masukan pengguna untuk mencegah SQLi/XSS") 
    print(" 5. Tutup port yang tidak diperlukan") 
    print(" 6. Sembunyikan informasi versi server") 
    print(" 7. Terapkan pembatasan laju dan WAF") 
    print(" 8. Perbarui semua komponen perangkat lunak secara berkala")

def about_program():
    display_header()
    print(f"""
    {COLOR['BLUE']}[ Tentang Bug Bounty Scanner ]{COLOR['END']}
    
    Ini adalah pemindai kerentanan web komprehensif yang dirancang untuk membantu peneliti keamanan dan pemburu bug bounty mengidentifikasi masalah keamanan umum dalam aplikasi web.
    
    {COLOR['BOLD']}Features:{COLOR['END']}
    - Deteksi berkas sensitif (berkas konfigurasi, basis data, cadangan) - Pemeriksaan daftar direktori - Penemuan panel admin - Pengujian injeksi SQL dasar - Pengujian XSS dasar - Pemindaian port terbuka - Analisis header HTTP - Rekomendasi keamanan terperinci
    
    {COLOR['BOLD']}Note:{COLOR['END']}
    - Selalu dapatkan otorisasi yang sesuai sebelum memindai situs web apa pun 
    - Alat ini hanya untuk tujuan pengujian pendidikan dan etika 
    - Tidak semua temuan mungkin merupakan kerentanan yang sebenarnya (positif palsu mungkin terjadi)
    
    Created by: PIKLIE EL RIMEM
    Version: 1.0
    """)
    input("\nTekan Enter untuk kembali ke menu...")

def main():
    while True:
        display_header()
        display_menu()

        choice = input(f"{COLOR['BOLD']}Pilih Opsi [1-3]: {COLOR['END']}")

        if choice == "1":
            display_header()
            print(f"{COLOR['BLUE']}[ Pemindai Kerentanan Situs Website ]{COLOR['END']}\n")
            target = input("Masukkan URL situs web (misalnya, https://example.com): ").strip()

            if not validate_url(target):
                print(f"\n{COLOR['RED']}[!] Format URL tidak valid. Harap sertakan http:// atau https://{COLOR['END']}")
                time.sleep(2)
                continue

            vulnerabilities = deep_scan(target)
            generate_report(target, vulnerabilities)

            input("\nTekan Enter Untuk Lanjut...")

        elif choice == "2":
            about_program()

        elif choice == "3":
            print(f"\n{COLOR['GREEN']}[+] Terima kasih telah menggunakan Bug Bounty Scanner. Goodbye!{COLOR['END']}")
            break

        else:
            print(f"\n{COLOR['RED']}[!] Pilihan tidak valid. Silakan pilih 1-3.{COLOR['END']}")
            time.sleep(1)

if __name__ == "__main__":
    main()
