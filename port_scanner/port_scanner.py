import socket
import sys
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from collections import defaultdict
import os
import re

# Thread-safe printing
print_lock = Lock()

def safe_print(message):
    """Thread-safe print function"""
    with print_lock:
        print(message)

def parse_target(target_str):
    """
    Parse target - can be single IP, hostname, CIDR notation, or comma-separated values
    Args:
        target_str (str): Target specification (IP, hostname, CIDR, or CSV string)
    Returns:
        list: List of IP addresses to scan
    """
    targets = []
    try:
        # Check if it's a comma-separated string
        if ',' in target_str:
            items = [item.strip() for item in target_str.split(',')]
            for item in items:
                if item:
                    targets.extend(parse_single_target(item))
            safe_print(f"[*] Parsed comma-separated targets: {len(targets)} total")
        # Check if it's CIDR notation
        elif '/' in target_str:
            network = ipaddress.ip_network(target_str, strict=False)
            targets = [str(ip) for ip in network.hosts()]
            safe_print(f"[*] Parsed CIDR {target_str}: {len(targets)} hosts")
        else:
            # Single IP or hostname
            targets = [target_str]
    except ValueError as e:
        safe_print(f"[!] Invalid target format: {e}")
        sys.exit(1)
    return targets

def parse_single_target(target_str):
    """
    Parse a single target (IP, hostname, or CIDR)
    Args:
        target_str (str): Single target specification
    Returns:
        list: List of IP addresses
    """
    targets = []
    target_str = target_str.strip()
    if not target_str:
        return targets
    # Check if it's CIDR notation
    if '/' in target_str:
        network = ipaddress.ip_network(target_str, strict=False)
        targets = [str(ip) for ip in network.hosts()]
    else:
        # Single IP or hostname
        targets = [target_str]
    return targets

def parse_ports(port_str):
    """
    Parse port specification into a list of ports
    Args:
        port_str (str): Port specification (e.g., "22,80,443" or "1-1000")
    Returns:
        list: List of port numbers to scan
    """
    ports = []
    try:
        if ',' in port_str:
            # List of ports or ranges
            for part in port_str.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
        elif '-' in port_str:
            # Port range
            start, end = map(int, port_str.split('-'))
            ports = list(range(start, end + 1))
        else:
            # Single port
            ports = [int(port_str)]
    except ValueError:
        safe_print(f"[!] Invalid port format: {port_str}")
        sys.exit(1)
    return sorted(set(ports))  # Remove duplicates and sort

def scan_port_tcp(target, port, timeout=1.0):
    """
    Scan a single port on the target host use appropriate probe for banner grabbing
    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds
    Returns:
        tuple: (port, status, banner, service_info) if port is open, None otherwise
    """
    # Define probes for known services
    banner_probes = {
        80: b'GET / HTTP/1.0\r\nHost: ' + target.encode() + b'\r\n\r\n',
        8080: b'GET / HTTP/1.0\r\n\r\n',
        22: b'',  # SSH sends banner immediately
        21: b'',  # FTP sends banner immediately
        25: b'EHLO scanner\r\n',
        110: b'USER test\r\n',
        143: b'A001 CAPABILITY\r\n',
        3306: b'',  # MySQL sends banner immediately
        5432: b'',  # PostgreSQL sends banner immediately
        6379: b'INFO\r\n',  # Redis
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        banner = None
        service_info = None
        if result == 0:
            probe = banner_probes.get(port, b'\r\n')
            try:
                banner_data = sock.recv(1024)
                if(banner_data):
                    banner = banner_data.decode('utf-8', errors='ignore').strip()
                    service_info = parse_banner(banner, port)
                elif probe:
                    sock.send(probe)
                    banner_data = sock.recv(1024)
                    banner = banner_data.decode('utf-8', errors='ignore').strip()
                    service_info = parse_banner(banner, port)
            except:
                pass
            sock.close()
            return (port, 'open', banner, service_info)
        else:
            sock.close()
            return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def scan_port_multi(target, port, scan_types, timeout=1.0):
    """
    Perform multiple scan types on a single port
    Args:
        target (str): IP address to scan
        port (int): Port number to scan
        scan_types (list): List of scan types to perform
        timeout (float): Connection timeout in seconds
    Returns:
        dict: Results from each scan type
    """
    results = {}
    for scan_type in scan_types:
        if scan_type == 'tcp':
            results['tcp'] = scan_port_tcp(target, port, timeout)
    return (port, results)

def scan_host(target, ports, scan_types, timeout=1.0, max_workers=100):
    """
    Scan specific ports on the target host with multiple scan types
    Args:
        target (str): IP address to scan
        ports (list): List of port numbers to scan
        timeout (float): Connection timeout
        max_workers (int): Maximum number of concurrent threads
    Returns:
        dict: Results dictionary with scan results
    """
    results = defaultdict(lambda: defaultdict(dict))
    scan_types_str = '+'.join(s.upper() for s in scan_types)
    safe_print(f"[*] Scanning {target} - {len(ports)} ports with {scan_types_str}")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all port scan tasks
        future_to_port = {
            executor.submit(scan_port_multi, target, port, scan_types, timeout): port
            for port in ports
        }
        
        completed = 0
        total = len(future_to_port)
        
        # Collect results as they complete
        for future in as_completed(future_to_port):
            completed += 1
            port, scan_results = future.result()
            
            # Store results in dictionary
            for scan_type, result in scan_results.items():
                if result:
                    port_num, status, banner, service_info = result
                    results[port][scan_type] = {
                        'status': status,
                        'banner': banner,
                        'service_info': service_info
                    }
                    if status in ['open', 'open|filtered']:
                        banner_str = f" - {banner[:50]}" if banner else ""
                        safe_print(f"[+] {target}:{port} {scan_type.upper()} {status.upper()}{banner_str}")
            
            # Progress indicator
            if completed % 50 == 0:
                safe_print(f"[*] Progress: {completed}/{total} ports scanned")
    
    return {
        'target': target,
        'scan_types': scan_types,
        'results': dict(results)
    }

def scan_subnet(targets, ports, scan_types, timeout=1.0, max_workers=100):
    """
    Scan multiple hosts in a subnet
    Args:
        targets (list): List of IP addresses to scan
        ports (list): List of port numbers to scan
        scan_types (list): List of scan types to perform (e.g., ['tcp'])
        timeout (float): Connection timeout
        max_workers (int): Maximum number of concurrent threads
    Returns:
        returns: List of results for each host
    """
    all_results = []
    scan_types_str = '+'.join([s.upper() for s in scan_types])
    safe_print(f"[*] Starting {scan_types_str} scan of {len(targets)} hosts")
    safe_print(f"[*] Ports: {len(ports)} ports to scan per host")
    safe_print(f"[*] Port range: {ports[0]}-{ports[-1]}")
    
    for i, target in enumerate(targets, 1):
        safe_print(f"\n[*] Progress: {i}/{len(targets)} hosts")
        result = scan_host(target, ports, scan_types, timeout, max_workers)
        if result['results']:
            all_results.append(result)
    
    return all_results

def parse_banner(banner, port):
    """
    Flexibly parse service banners into structured information
    Args:
        banner (str): Raw banner string from service
        port (int): Port number (helps with context)
    Returns:
        dict: Parsed service information
    """
    if not banner:
        return {
            'service': 'unknown',
            'product': 'unknown',
            'version': 'unknown',
            'os': 'unknown',
            'cpe': None,
            'extra_info': []
        }
    
    info = {
        'service': 'unknown',
        'product': 'unknown',
        'version': 'unknown',
        'os': 'unknown',
        'cpe': None,
        'extra_info': []
    }
    
    banner_lower = banner.lower()
    
    # ==================== SSH FINGERPRINTING ====================
    if 'ssh' in banner_lower or port == 22:
        info['service'] = 'SSH'
        # Parse SSH banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
        # The pattern needs to handle: SSH-<protocol>-<product_version> <os_info>
        ssh_pattern = r'SSH-([\d.]+)-([^\s]+)(?:\s+(.+))?'
        match = re.match(ssh_pattern, banner, re.IGNORECASE)
        
        if match:
            protocol_version = match.group(1)
            product_and_version = match.group(2)  # e.g., "OpenSSH_9.6p1"
            os_info = match.group(3) if match.group(3) else ''
            
            # Split product and version
            # Handle patterns like: OpenSSH_9.6p1, Dropbear_2020.81, libssh-0.9.6
            if '_' in product_and_version:
                parts = product_and_version.split('_', 1)
                info['product'] = parts[0]
                info['version'] = parts[1] if len(parts) > 1 else 'unknown'
            elif '-' in product_and_version and not product_and_version.startswith('-'):
                # Handle cases like libssh-0.9.6 (but not just "-something")
                parts = product_and_version.rsplit('-', 1)
                if len(parts) > 1 and parts[1][0].isdigit():
                    info['product'] = parts[0]
                    info['version'] = parts[1]
                else:
                    info['product'] = product_and_version
                    info['version'] = 'unknown'
            else:
                # No version separator found
                info['product'] = product_and_version
                info['version'] = 'unknown'
            
            info['extra_info'].append(f'protocol {protocol_version}')
            
            # Parse OS from various formats
            if os_info:
                info['os'] = parse_os_info(os_info)
                info['extra_info'].append(os_info.strip())
            else:
                info['os'] = 'unknown'
    
    # ==================== HTTP/HTTPS FINGERPRINTING ====================
    elif port in [80, 443, 8000, 8008, 8080, 8443, 8888] or 'http' in banner_lower:
        info['service'] = 'HTTP' if port != 443 else 'HTTPS'
        
        # Apache variants
        if 'apache' in banner_lower:
            info['product'] = 'Apache httpd'
            # Apache/2.4.41 (Ubuntu) or Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.2
            apache_pattern = r'apache[/\s]*([\d.]+)'
            match = re.search(apache_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
            
            info['os'] = parse_os_info(banner)
            
            # Extract modules
            modules = []
            if 'openssl' in banner_lower:
                ssl_match = re.search(r'openssl[/\s]*([\d.]+\w*)', banner_lower)
                if ssl_match:
                    modules.append(f'OpenSSL {ssl_match.group(1)}')
            if 'php' in banner_lower:
                php_match = re.search(r'php[/\s]*([\d.]+)', banner_lower)
                if php_match:
                    modules.append(f'PHP {php_match.group(1)}')
            if 'mod_ssl' in banner_lower:
                modules.append('mod_ssl')
            
            info['extra_info'].extend(modules)
        
        # Nginx
        elif 'nginx' in banner_lower:
            info['product'] = 'nginx'
            # nginx/1.18.0 (Ubuntu)
            nginx_pattern = r'nginx[/\s]*([\d.]+)'
            match = re.search(nginx_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
            info['os'] = parse_os_info(banner)
        
        # Microsoft IIS
        elif 'microsoft-iis' in banner_lower or 'iis' in banner_lower:
            info['product'] = 'Microsoft IIS'
            # Microsoft-IIS/10.0
            iis_pattern = r'(?:microsoft-)?iis[/\s]*([\d.]+)'
            match = re.search(iis_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
                # Map IIS version to Windows version
                info['os'] = map_iis_to_windows(match.group(1))
            else:
                info['os'] = 'Windows'
        
        # LiteSpeed
        elif 'litespeed' in banner_lower:
            info['product'] = 'LiteSpeed'
            ls_pattern = r'litespeed[/\s]*([\d.]+)'
            match = re.search(ls_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
        
        # Apache Tomcat
        elif 'tomcat' in banner_lower:
            info['product'] = 'Apache Tomcat'
            tomcat_pattern = r'tomcat[/\s]*([\d.]+)'
            match = re.search(tomcat_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
        
        # Jetty
        elif 'jetty' in banner_lower:
            info['product'] = 'Jetty'
            jetty_pattern = r'jetty[/\s]*([\d.]+)'
            match = re.search(jetty_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
    
    # ==================== FTP FINGERPRINTING ====================
    elif port == 21 or 'ftp' in banner_lower:
        info['service'] = 'FTP'
        
        # ProFTPD
        if 'proftpd' in banner_lower:
            info['product'] = 'ProFTPD'
            # ProFTPD 1.3.5 Server (Debian)
            proftpd_pattern = r'proftpd\s+([\d.]+\w*)'
            match = re.search(proftpd_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
            info['os'] = parse_os_info(banner)
        
        # vsftpd
        elif 'vsftpd' in banner_lower:
            info['product'] = 'vsftpd'
            # (vsFTPd 3.0.3)
            vsftpd_pattern = r'vsftpd\s+([\d.]+)'
            match = re.search(vsftpd_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
        
        # Pure-FTPd
        elif 'pure-ftpd' in banner_lower:
            info['product'] = 'Pure-FTPd'
            pure_pattern = r'pure-ftpd\s*(?:\[privsep\])?\s*\[TLS\]'
            if re.search(pure_pattern, banner_lower):
                info['extra_info'].append('TLS enabled')
        
        # FileZilla Server
        elif 'filezilla' in banner_lower:
            info['product'] = 'FileZilla Server'
            fz_pattern = r'filezilla\s+server\s+(?:version\s+)?([\d.]+)'
            match = re.search(fz_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
        
        # Microsoft FTP
        elif 'microsoft ftp' in banner_lower:
            info['product'] = 'Microsoft ftpd'
            info['os'] = 'Windows'
    
    # ==================== SMTP FINGERPRINTING ====================
    elif port in [25, 465, 587] or 'smtp' in banner_lower or 'esmtp' in banner_lower:
        info['service'] = 'SMTP'
        
        # Postfix
        if 'postfix' in banner_lower:
            info['product'] = 'Postfix'
            info['os'] = parse_os_info(banner)
        
        # Sendmail
        elif 'sendmail' in banner_lower:
            info['product'] = 'Sendmail'
            # Sendmail 8.15.2/8.15.2
            sendmail_pattern = r'sendmail\s+([\d.]+)'
            match = re.search(sendmail_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
        
        # Exim
        elif 'exim' in banner_lower:
            info['product'] = 'Exim'
            exim_pattern = r'exim\s+([\d.]+)'
            match = re.search(exim_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
        
        # Microsoft Exchange
        elif 'exchange' in banner_lower or 'microsoft esmtp' in banner_lower:
            info['product'] = 'Microsoft Exchange'
            info['os'] = 'Windows'
    
    # ==================== DATABASE FINGERPRINTING ====================
    # MySQL/MariaDB
    elif port == 3306 or 'mysql' in banner_lower or 'mariadb' in banner_lower:
        if 'mariadb' in banner_lower:
            info['service'] = 'MySQL'
            info['product'] = 'MariaDB'
            mariadb_pattern = r'([\d.]+)-mariadb'
            match = re.search(mariadb_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
        else:
            info['service'] = 'MySQL'
            info['product'] = 'MySQL'
            # 5.7.36-0ubuntu0.18.04.1
            mysql_pattern = r'^([\d.]+)'
            match = re.search(mysql_pattern, banner)
            if match:
                info['version'] = match.group(1)
        
        info['os'] = parse_os_info(banner)
    
    # PostgreSQL
    elif port == 5432 or 'postgresql' in banner_lower:
        info['service'] = 'PostgreSQL'
        info['product'] = 'PostgreSQL'
        # Parse version if available
        pg_pattern = r'postgresql[/\s]*([\d.]+)'
        match = re.search(pg_pattern, banner_lower)
        if match:
            info['version'] = match.group(1)
    
    # MongoDB
    elif port == 27017 or 'mongodb' in banner_lower:
        info['service'] = 'MongoDB'
        info['product'] = 'MongoDB'
        mongo_pattern = r'mongodb[/\s]*([\d.]+)'
        match = re.search(mongo_pattern, banner_lower)
        if match:
            info['version'] = match.group(1)
    
    # Redis
    elif port == 6379 or 'redis' in banner_lower:
        info['service'] = 'Redis'
        info['product'] = 'Redis'
        # redis_version:6.2.6
        redis_pattern = r'redis_version:([\d.]+)'
        match = re.search(redis_pattern, banner_lower)
        if match:
            info['version'] = match.group(1)
    
    # Microsoft SQL Server
    elif port == 1433 or 'microsoft sql' in banner_lower or 'mssql' in banner_lower:
        info['service'] = 'MS-SQL'
        info['product'] = 'Microsoft SQL Server'
        info['os'] = 'Windows'
    
    # ==================== OTHER SERVICES ====================
    # Telnet
    elif port == 23 or 'telnet' in banner_lower:
        info['service'] = 'Telnet'
        info['os'] = parse_os_info(banner)
    
    # POP3
    elif port in [110, 995] or 'pop3' in banner_lower:
        info['service'] = 'POP3'
        if 'dovecot' in banner_lower:
            info['product'] = 'Dovecot'
            dovecot_pattern = r'dovecot\s+ready'
            if re.search(dovecot_pattern, banner_lower):
                info['extra_info'].append('ready')
        elif 'courier' in banner_lower:
            info['product'] = 'Courier'
    
    # IMAP
    elif port in [143, 993] or 'imap' in banner_lower:
        info['service'] = 'IMAP'
        if 'dovecot' in banner_lower:
            info['product'] = 'Dovecot'
        elif 'courier' in banner_lower:
            info['product'] = 'Courier'
        elif 'cyrus' in banner_lower:
            info['product'] = 'Cyrus'
    
    # SMB/CIFS
    elif port == 445 or 'smb' in banner_lower or 'samba' in banner_lower:
        info['service'] = 'SMB'
        if 'samba' in banner_lower:
            info['product'] = 'Samba'
            samba_pattern = r'samba\s+([\d.]+)'
            match = re.search(samba_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
        else:
            info['product'] = 'Microsoft SMB'
            info['os'] = 'Windows'
    
    # VNC
    elif port in [5900, 5901] or 'rfb' in banner_lower or 'vnc' in banner_lower:
        info['service'] = 'VNC'
        # RFB 003.008
        rfb_pattern = r'rfb\s+([\d.]+)'
        match = re.search(rfb_pattern, banner_lower)
        if match:
            info['extra_info'].append(f'RFB protocol {match.group(1)}')
    
    # RDP
    elif port == 3389:
        info['service'] = 'RDP'
        info['product'] = 'Microsoft Terminal Services'
        info['os'] = 'Windows'
    
    # DNS
    elif port == 53:
        info['service'] = 'DNS'
        if 'bind' in banner_lower:
            info['product'] = 'ISC BIND'
            bind_pattern = r'bind\s+([\d.]+)'
            match = re.search(bind_pattern, banner_lower)
            if match:
                info['version'] = match.group(1)
    
    # LDAP
    elif port in [389, 636]:
        info['service'] = 'LDAP'
        if 'openldap' in banner_lower:
            info['product'] = 'OpenLDAP'
        elif 'active directory' in banner_lower:
            info['product'] = 'Active Directory'
            info['os'] = 'Windows'
    
    return info

def parse_os_info(text):
    """
    Flexibly parse OS information from banner text
    Args:
        text (str): Banner or text containing OS info
    Returns:
        str: Identified OS or 'unknown'
    """
    if not text:
        return 'unknown'
    
    text_lower = text.lower()
    
    # Linux distributions
    if 'ubuntu' in text_lower:
        # Try to extract version: Ubuntu-3ubuntu13 or (Ubuntu 20.04)
        ubuntu_pattern = r'ubuntu[- ]?([\d.]+)?'
        match = re.search(ubuntu_pattern, text_lower)
        if match and match.group(1):
            return f'Ubuntu {match.group(1)}'
        return 'Ubuntu Linux'
    
    elif 'debian' in text_lower:
        debian_pattern = r'debian[- ]?([\d.]+)?'
        match = re.search(debian_pattern, text_lower)
        if match and match.group(1):
            return f'Debian {match.group(1)}'
        return 'Debian Linux'
    
    elif 'centos' in text_lower:
        centos_pattern = r'centos[- ]?([\d.]+)?'
        match = re.search(centos_pattern, text_lower)
        if match and match.group(1):
            return f'CentOS {match.group(1)}'
        return 'CentOS Linux'
    
    elif 'red hat' in text_lower or 'redhat' in text_lower or 'rhel' in text_lower:
        rhel_pattern = r'(?:red\s*hat|rhel)[- ]?([\d.]+)?'
        match = re.search(rhel_pattern, text_lower)
        if match and match.group(1):
            return f'Red Hat Enterprise Linux {match.group(1)}'
        return 'Red Hat Enterprise Linux'
    
    elif 'fedora' in text_lower:
        fedora_pattern = r'fedora[- ]?([\d.]+)?'
        match = re.search(fedora_pattern, text_lower)
        if match and match.group(1):
            return f'Fedora {match.group(1)}'
        return 'Fedora Linux'
    
    elif 'suse' in text_lower or 'opensuse' in text_lower:
        return 'SUSE Linux'
    
    elif 'arch' in text_lower and 'linux' in text_lower:
        return 'Arch Linux'
    
    elif 'alpine' in text_lower:
        alpine_pattern = r'alpine[- ]?([\d.]+)?'
        match = re.search(alpine_pattern, text_lower)
        if match and match.group(1):
            return f'Alpine Linux {match.group(1)}'
        return 'Alpine Linux'
    
    elif 'kali' in text_lower:
        return 'Kali Linux'
    
    # BSD variants
    elif 'freebsd' in text_lower:
        freebsd_pattern = r'freebsd[- /]?([\d.]+)?'
        match = re.search(freebsd_pattern, text_lower)
        if match and match.group(1):
            return f'FreeBSD {match.group(1)}'
        return 'FreeBSD'
    
    elif 'openbsd' in text_lower:
        openbsd_pattern = r'openbsd[- ]?([\d.]+)?'
        match = re.search(openbsd_pattern, text_lower)
        if match and match.group(1):
            return f'OpenBSD {match.group(1)}'
        return 'OpenBSD'
    
    elif 'netbsd' in text_lower:
        return 'NetBSD'
    
    # Windows variants
    elif 'win64' in text_lower or 'windows' in text_lower:
        # Try to identify Windows version
        if 'server 2022' in text_lower:
            return 'Windows Server 2022'
        elif 'server 2019' in text_lower:
            return 'Windows Server 2019'
        elif 'server 2016' in text_lower:
            return 'Windows Server 2016'
        elif 'server 2012' in text_lower:
            return 'Windows Server 2012'
        elif 'windows 11' in text_lower:
            return 'Windows 11'
        elif 'windows 10' in text_lower:
            return 'Windows 10'
        elif 'win64' in text_lower:
            return 'Windows (64-bit)'
        elif 'win32' in text_lower:
            return 'Windows (32-bit)'
        else:
            return 'Windows'
    
    elif 'win32' in text_lower:
        return 'Windows (32-bit)'
    
    # macOS/Darwin
    elif 'darwin' in text_lower or 'macos' in text_lower or 'mac os' in text_lower:
        darwin_pattern = r'darwin[- /]?([\d.]+)?'
        match = re.search(darwin_pattern, text_lower)
        if match and match.group(1):
            return f'macOS (Darwin {match.group(1)})'
        return 'macOS'
    
    # Unix (generic)
    elif 'unix' in text_lower:
        return 'Unix'
    
    # If contains "linux" but no specific distro
    elif 'linux' in text_lower:
        return 'Linux (unknown distribution)'
    
    return 'unknown'

def map_iis_to_windows(iis_version):
    """
    Map IIS version to Windows version
    """
    version_map = {
        '10.0': 'Windows Server 2016/2019 or Windows 10',
        '8.5': 'Windows Server 2012 R2 or Windows 8.1',
        '8.0': 'Windows Server 2012 or Windows 8',
        '7.5': 'Windows Server 2008 R2 or Windows 7',
        '7.0': 'Windows Server 2008 or Windows Vista',
        '6.0': 'Windows Server 2003 or Windows XP',
    }
    return version_map.get(iis_version, 'Windows')

def display_results(results, scan_types):
    """
    Display scan results in a formatted table with service information
    Args:
        results (list): List of scan results
        scan_types (list): List of scan types used
    """
    print(f"\n{'='*120}")
    print(f"[+] Scan Complete!")
    print(f"{'='*120}")
    
    for result in results:
        target = result['target']
        ports_data = result['results']
        
        if not ports_data:
            continue
        
        print(f"\n[+] Target: {target}")
        print(f"[+] Open/Filtered Ports: {len(ports_data)}")
        print(f"\n{'Port':<8} {'State':<15} {'Service':<12} {'Product':<20} {'Version':<12} {'OS':<25} {'Info':<25}")
        print("-" * 120)
        
        # Results for each port
        for port in sorted(ports_data.keys()):
            port_results = ports_data[port]
            
            # Determine the best status and service info to display
            status = 'unknown'
            service_info = None
            banner = None
            
            # Prioritize: open > open|filtered > closed > filtered
            priority = {'open': 1, 'open|filtered': 2, 'closed': 3, 'filtered': 4, 'error': 5}
            best_priority = 999
            
            for scan_type in scan_types:
                if scan_type in port_results:
                    current_status = port_results[scan_type]['status']
                    current_priority = priority.get(current_status, 999)
                    
                    if current_priority < best_priority:
                        best_priority = current_priority
                        status = current_status
                        service_info = port_results[scan_type].get('service_info')
                        banner = port_results[scan_type].get('banner')
            
            # Format scan types and their results
            scan_results_str = []
            for scan_type in scan_types:
                if scan_type in port_results:
                    st = port_results[scan_type]['status']
                    scan_results_str.append(f"{scan_type.upper()}:{st}")
            
            state_str = f"{status} ({', '.join(scan_results_str)})"
            
            # Extract service information
            if service_info:
                service = service_info.get('service', 'unknown')
                product = service_info.get('product', 'unknown')
                version = service_info.get('version', 'unknown')
                os = service_info.get('os', 'unknown')
                extra = service_info.get('extra_info', [])
            else:
                service = 'unknown'
                product = 'unknown'
                version = 'unknown'
                os = 'unknown'
                extra = []
            
            # Truncate long strings
            product = product[:18] + '..' if len(product) > 20 else product
            os = os[:23] + '..' if len(os) > 25 else os
            
            print(f"{port:<8} {state_str:<15} {service:<12} {product:<20} {version:<12} {os:<25} {', '.join(extra[:3]):<25}")
            
            # Print raw banner if verbose and no service info
            if banner and not service_info:
                banner_preview = banner[:80].replace('\n', ' ').replace('\r', '')
                print(f"{'':8} Banner: {banner_preview}")

import json
from datetime import datetime

def export_to_json(results, scan_types, output_file='port_scan_results.jsonl'):
    """
    Export scan results to a JSON file
    Args:
        results (list): List of scan results
        scan_types (list): List of scan types used
        output_file (str, optional): Output filename. If None, generates timestamped filename
    Returns:
        str: Path to the created JSON file
    """
    # Generate default filename if none provided
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"scan_results_{timestamp}.jsonl"
    
    # Ensure .jsonl extension
    if not output_file.endswith('.jsonl'):
        output_file += '.jsonl'
    
    # Structure the data for JSONL export
    export_data = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "scan_types": scan_types,
            "total_targets": len(results)
        },
        "results": []
    }
    
    for result in results:
        target = result['target']
        ports_data = result['results']
        
        target_data = {
            "target": target,
            "open_filtered_ports_count": len(ports_data),
            "ports": []
        }
        
        # Process each port
        for port in sorted(ports_data.keys()):
            port_results = ports_data[port]
            
            # Determine the best status and service info
            status = 'unknown'
            service_info = None
            banner = None
            
            priority = {'open': 1, 'open|filtered': 2, 'closed': 3, 'filtered': 4, 'error': 5}
            best_priority = 999
            
            for scan_type in scan_types:
                if scan_type in port_results:
                    current_status = port_results[scan_type]['status']
                    current_priority = priority.get(current_status, 999)
                    
                    if current_priority < best_priority:
                        best_priority = current_priority
                        status = current_status
                        service_info = port_results[scan_type].get('service_info')
                        banner = port_results[scan_type].get('banner')
            
            # Collect scan results for this port
            scan_results = {}
            for scan_type in scan_types:
                if scan_type in port_results:
                    scan_results[scan_type] = port_results[scan_type]['status']
            
            # Build port entry
            port_entry = {
                "port": port,
                "status": status,
                "scan_results": scan_results,
                "service_info": {
                    "service": service_info.get('service', 'unknown') if service_info else 'unknown',
                    "product": service_info.get('product', 'unknown') if service_info else 'unknown',
                    "version": service_info.get('version', 'unknown') if service_info else 'unknown',
                    "os": service_info.get('os', 'unknown') if service_info else 'unknown',
                    "extra_info": service_info.get('extra_info', []) if service_info else []
                },
                "banner": banner,
                "raw_results": port_results  # Include full raw data for reference
            }
            
            target_data["ports"].append(port_entry)
        
        export_data["results"].append(target_data)
    
    # Write to JSON file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Results exported to: {output_file}")
        return output_file
    except Exception as e:
        print(f"\n[-] Error writing JSON file: {e}")
        return None

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python3 port_scanner.py <target> [options]")
        print("\nPositional Arguments:")
        print("  target              Target IP, hostname, or CIDR notation (e.g., 192.168.1.0/24)")
        print("\nOptional Arguments:")
        print("  -p, --ports         Port range (e.g., 1-1000), list (e.g., 22,80,443), or mixed")
        print("                      Default: 21-23")
        print("  -t, --timeout       Timeout in seconds (default: 1.0)")
        print("  -w, --workers       Maximum concurrent threads (default: 100)")
        print("  -o, --output        Output JSON file")
        print("\nExamples:")
        print("  TCP Connect Scan:           python3 port_scanner.py 192.168.1.1 -p 1-1000")
        print("  Subnet Scan:                python3 port_scanner.py 192.168.1.0/24 -p 22,80,443")
        print("  Fast Scan:                  python3 port_scanner.py 10.0.0.1 -p 1-1000 -t 0.5 -w 200")
        print("  Export Results to JSON:     python3 port_scanner.py 192.168.1.1 -p 1-1000 -o output.jsonl")
        sys.exit(1)
    
    target_str = sys.argv[1]
    
    # Default values
    port_str = '21-23'
    scan_types = ['tcp']
    timeout = 1.0
    max_workers = 100
    output_file = None
    
    # Parse optional arguments
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        
        if arg in ['-p', '--ports']:
            if i + 1 < len(sys.argv):
                port_str = sys.argv[i + 1]
                i += 2
            else:
                safe_print(f"[!] Error: {arg} requires a value")
                sys.exit(1)
        
        elif arg in ['-t', '--timeout']:
            if i + 1 < len(sys.argv):
                try:
                    timeout = float(sys.argv[i + 1])
                    i += 2
                except ValueError:
                    safe_print(f"[!] Error: Invalid timeout value: {sys.argv[i + 1]}")
                    sys.exit(1)
            else:
                safe_print(f"[!] Error: {arg} requires a value")
                sys.exit(1)
        
        elif arg in ['-w', '--workers']:
            if i + 1 < len(sys.argv):
                try:
                    max_workers = int(sys.argv[i + 1])
                    i += 2
                except ValueError:
                    safe_print(f"[!] Error: Invalid workers value: {sys.argv[i + 1]}")
                    sys.exit(1)
            else:
                safe_print(f"[!] Error: {arg} requires a value")
                sys.exit(1)
        
        elif arg in ['-o', '--output']:
            if i + 1 < len(sys.argv):
                output_file = sys.argv[i + 1]
                i += 2
            else:
                safe_print(f"[!] Error: {arg} requires a value")
                sys.exit(1)
        
        else:
            safe_print(f"[!] Error: Unknown argument: {arg}")
            sys.exit(1)
    
    # Parse ports
    ports = parse_ports(port_str)
    
    # Validate port range
    if not all(1 <= p <= 65535 for p in ports):
        safe_print("[!] All ports must be between 1 and 65535")
        sys.exit(1)
    
    # Parse targets
    targets = parse_target(target_str)
    
    # Warn for large scans
    total_scans = len(targets) * len(ports) * len(scan_types)
    if total_scans > 100000:
        safe_print(f"[!] WARNING: This will perform {total_scans:,} scan attempts!")
        safe_print(f"[!] ({len(targets)} hosts × {len(ports)} ports × {len(scan_types)} scan types)")
        response = input("Continue? (yes/no): ")
        if response.lower() != 'yes':
            sys.exit(0)
    
    scan_types_str = '+'.join([s.upper() for s in scan_types])
    print(f"\n[*] Starting {scan_types_str} port scan")
    print(f"[*] Targets: {len(targets)}")
    print(f"[*] Ports: {len(ports)}")
    print(f"[*] Scan Types: {', '.join(scan_types)}")
    print(f"[*] Timeout: {timeout}s")
    print(f"[*] Workers: {max_workers}\n")
    
    # Perform scan
    if len(targets) == 1:
        result = scan_host(targets[0], ports, scan_types, timeout, max_workers)
        results = [result] if result['results'] else []
    else:
        results = scan_subnet(targets, ports, scan_types, timeout, max_workers)
    
    # Display results
    display_results(results, scan_types)
    
    # Export results to JSON if output_file is specified
    if output_file:
        export_to_json(results, scan_types, output_file)
    
    # Summary statistics
    total_hosts_scanned = len(targets)
    hosts_with_findings = len(results)
    total_open_ports = sum(len(r['results']) for r in results)
    
    print(f"\n{'='*120}")
    print(f"[+] Summary Statistics")
    print(f"{'='*120}")
    print(f"[+] Hosts scanned: {total_hosts_scanned}")
    print(f"[+] Hosts with open/filtered ports: {hosts_with_findings}")
    print(f"[+] Total open/filtered ports found: {total_open_ports}")
    print(f"[+] Scan types used: {', '.join(scan_types)}")
    if output_file:
        print(f"[+] Results exported to: {output_file}")
    print(f"{'='*120}\n")

if __name__ == "__main__":
    main()
