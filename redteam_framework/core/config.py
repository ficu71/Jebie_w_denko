# Default Configuration

DEFAULT_CONFIG = {
    'general': {
        'verbose': True,
        'log_level': "INFO",
        'output_dir': "./reports",
        'temp_dir': "/tmp",
        'max_concurrent_scans': 10,
        'request_delay': 0.5,
        'timeout': 10,
        # Safety: Restricted network range (must be set by user)
        'allowed_network_range': "127.0.0.1/32" 
    },
    'stealth': {
        'level': "high",  # 'low', 'medium', 'high'
        'use_proxy': False,
        'proxy_url': "socks5://127.0.0.1:9050",
        'mimic_user_agent': True,
        'random_delay_range': [0.2, 1.0],
        'rotate_ip_on_new_scan': False,
        'interface': "wlan0"
    },
    'exfiltration': {
        'c2_url': "http://127.0.0.1:8080/exfiltrate",
        'encryption_key': "your-32-byte-encryption-key-here-32bytes!!",
        'method': "https",  # 'https', 'dns', 'icmp', 'email'
        'proxy_url': None
    },
    'ml': {
        'window_size': 100,
        'model_path': "./models/behavior_model.pkl",
        'learning_rate': 0.1,
        'stealth_threshold': 0.8,
        'adaptation_frequency': 10
    },
    'brute_force': {
        'wordlist': "./wordlists/common_creds.txt",
        'max_concurrent': 10,
        'delay_between_attempts': 1.0,
        'max_attempts_per_service': 50
    },
    'c2_server': {
        'host': "0.0.0.0",
        'port': 8080,
        'encryption_key': "your-32-byte-encryption-key-here-32bytes!!"
    },
    'advanced_network_attacks': {
        'mitm': {
            'arp_interval': 2.0,
            'restore_on_exit': True
        },
        'credential_hijacker': {
            'interface': "wlan0"
        },
        'memory_executor': {
            'cleanup_temp_files': True
        }
    },
    'scanning': {
        'nmap_args': "-sn --host-timeout 300s",
        'ping_sweep': True,
        'arp_scan': True,
        'port_scan_range': "1-1024,8080,8443,3389,5900"
    },
    'mobile_iot': {
        'adb_path': "/usr/bin/adb",
        'scan_iot_networks': True,
        'iot_scan_ports': [23, 22, 80, 443, 554, 1883, 5683]
    },
    'reporting': {
        'generate_json': True,
        'generate_pdf': False,
        'include_sensitive_data': False,
        'report_filename_prefix': "pentest_report"
    }
}

DEFAULT_CREDENTIALS = [
    {'username': 'admin', 'password': 'admin'},
    {'username': 'root', 'password': 'root'},
    {'username': 'root', 'password': 'password'},
    {'username': 'user', 'password': 'user'},
    {'username': 'guest', 'password': 'guest'},
    {'username': 'pi', 'password': 'raspberry'},
    {'username': 'test', 'password': 'test'},
    {'username': 'ubuntu', 'password': 'ubuntu'},
    {'username': 'oracle', 'password': 'oracle'},
    {'username': 'postgres', 'password': 'postgres'},
    {'username': 'mysql', 'password': 'mysql'},
    {'username': 'cisco', 'password': 'cisco'},
    {'username': 'enable', 'password': 'enable'},
    {'username': 'service', 'password': 'service'},
    {'username': 'backup', 'password': 'backup'}
]
