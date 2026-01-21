import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from redteam_framework.core.logger import logger

class ReportGenerator:
    """
    Generates comprehensive reports from penetration test results.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.output_dir = Path(config.get('output_dir', './reports'))
        self.output_dir.mkdir(exist_ok=True)

    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate a comprehensive penetration test report."""
        report_data = {
            'scan_time': results.get('scan_time'),
            'target_network': results.get('target_network'),
            'executive_summary': self._generate_executive_summary(results),
            'data_summary': self._generate_data_summary(results),
            'critical_findings': self._count_critical_findings(results),
            'security_posture': self._assess_security_posture(results),
            'recommendations': self._generate_recommendations(results),
            'raw_data': results if self.config.get('include_sensitive_data', False) else self._sanitize_report(results)
        }

        # Save report to JSON
        report_filename = self.output_dir / f"{self.config.get('report_filename_prefix', 'pentest_report')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Report generated: {report_filename}")
        return str(report_filename)

    def _generate_executive_summary(self, results: Dict[str, Any]) -> str:
        """Generate high-level executive summary."""
        summary = f"""
        Executive Summary:
        - Network scanned: {results.get('target_network', 'Unknown')}
        - Total devices discovered: {len(results.get('devices', []))}
        - Successfully exploited: {results.get('summary', {}).get('successfully_exploited', 0)}
        - Privilege escalation achieved: {results.get('summary', {}).get('privilege_escalation_success', 0)}
        - Persistence established: {results.get('summary', {}).get('persistence_established', 0)}
        - Critical findings: {len(results.get('summary', {}).get('critical_findings', []))}
        """
        return summary.strip()

    def _generate_data_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed data summary."""
        summary = {
            'total_devices': len(results.get('devices', [])),
            'exploited_devices': results.get('summary', {}).get('successfully_exploited', 0),
            'vulnerable_ports': 0,
            'credentials_found': 0,
            'sensitive_files': 0,
            'network_configurations': 0
        }

        for device in results.get('devices', []):
            if device.get('port_scan'):
                summary['vulnerable_ports'] += len(device['port_scan'].get('vulnerable_ports', []))
            if device.get('extracted_data'):
                # Handle potentially multiple extractions
                for extracted in device['extracted_data']:
                    summary['credentials_found'] += len(extracted.get('credentials', []))
                    summary['sensitive_files'] += len(extracted.get('files', []))
                    summary['network_configurations'] += 1 if extracted.get('network_info') else 0

        return summary

    def _count_critical_findings(self, results: Dict[str, Any]) -> List[str]:
        """Count and list critical findings."""
        findings = []
        for device in results.get('devices', []):
            ip = device.get('ip', 'unknown')
            if device.get('vulnerabilities', {}).get('sql_injection'):
                findings.append(f"SQL Injection vulnerability found on {ip}")
            if device.get('vulnerabilities', {}).get('ftp_anonymous_access'):
                findings.append(f"Anonymous FTP access enabled on {ip}")
            if device.get('privilege_escalated'):
                findings.append(f"Root access obtained on {ip}")
            if device.get('extracted_data'):
                for sensitive in [d.get('sensitive_data', {}) for d in device['extracted_data']]:
                    if sensitive.get('credit_cards'):
                        findings.append(f"Credit card data found on {ip}")
                    if sensitive.get('passwords'):
                        findings.append(f"Plaintext passwords found on {ip}")
        return findings

    def _assess_security_posture(self, results: Dict[str, Any]) -> Dict[str, str]:
        """Assess overall security posture."""
        summary = results.get('summary', {})
        exploited = summary.get('successfully_exploited', 0)
        total = len(results.get('devices', []))
        
        if total == 0:
            return {'risk_level': 'unknown', 'description': 'No devices scanned'}
        
        exploitation_rate = exploited / total
        
        if exploitation_rate >= 0.5:
            risk_level = 'critical'
            description = 'High percentage of devices successfully exploited. Immediate security measures required.'
        elif exploitation_rate >= 0.25:
            risk_level = 'high'
            description = 'Significant number of devices exploited. Comprehensive security review needed.'
        elif exploitation_rate > 0:
            risk_level = 'medium'
            description = 'Some devices were exploited. Security improvements recommended.'
        else:
            risk_level = 'low'
            description = 'No devices successfully exploited. Security posture appears strong.'
        
        return {'risk_level': risk_level, 'description': description}

    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Add recommendations based on findings
        for device in results.get('devices', []):
            if device.get('vulnerabilities', {}).get('ssh_weak_auth'):
                recommendations.append("Implement strong SSH authentication and disable password-based login.")
            if device.get('vulnerabilities', {}).get('ftp_anonymous_access'):
                recommendations.append("Disable anonymous FTP access or implement proper authentication.")
            if device.get('vulnerabilities', {}).get('web_vulns'):
                recommendations.append("Update web applications and implement input validation.")
            
            if device.get('extracted_data'):
                 for extracted in device['extracted_data']:
                    if extracted.get('credentials'):
                        recommendations.append("Implement credential rotation and use of password managers.")
        
        # Add general recommendations
        if not recommendations:
            recommendations.append("No specific vulnerabilities found. Maintain current security practices.")
        
        # Remove duplicates
        return list(set(recommendations))

    def _sanitize_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize report to remove sensitive data."""
        sanitized = results.copy()
        
        # Remove sensitive content from extracted data
        for device in sanitized.get('devices', []):
            if 'extracted_data' in device:
                # Iterate over copy to modify
                new_extracted_list = []
                for extracted in device['extracted_data']:
                    ext_copy = extracted.copy()
                    if 'credentials' in ext_copy:
                        # Keep only metadata, remove actual content
                        for cred in ext_copy['credentials']:
                            if 'content' in cred:
                                cred['content'] = '[REDACTED]'
                    if 'files' in ext_copy:
                        for file_entry in ext_copy['files']:
                            if 'content' in file_entry:
                                file_entry['content'] = '[REDACTED]'
                    if 'sensitive_data' in ext_copy:
                        ext_copy['sensitive_data'] = {
                            k: f'[REDACTED - {len(v)} items]' if isinstance(v, list) else '[REDACTED]'
                            for k, v in ext_copy['sensitive_data'].items()
                        }
                    new_extracted_list.append(ext_copy)
                device['extracted_data'] = new_extracted_list
        
        return sanitized
