#!/usr/bin/env python3
"""
Machine Learning Adaptation Module
Handles automatic adaptation, behavioral analysis, and anomaly detection.

Author: Independent Red Team Consultant
Classification: Professional Use Only
"""

import asyncio
import aiohttp
import json
import time
import logging
import random
import statistics
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MLAdaptation')

class BehavioralAnalyzer:
    """
    Analyzes network behavior to establish baselines and detect anomalies.
    """
    
    def __init__(self, window_size: int = 100):
        """
        Initialize the behavioral analyzer.
        
        Args:
            window_size (int): Size of the sliding window for anomaly detection.
        """
        self.window_size = window_size
        self.normal_traffic = deque(maxlen=window_size)
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.baseline_established = False

    def collect_traffic_data(self, traffic_data: Dict) -> None:
        """
        Collect traffic data for baseline establishment.
        
        Args:
            traffic_data (Dict): Traffic data with features like packet_size, interval, etc.
        """
        if not self.baseline_established:
            self.normal_traffic.append(traffic_data)
            logger.debug(f"Collected traffic data: {traffic_data}")
            
            # Check if we have enough data to establish baseline
            if len(self.normal_traffic) >= self.window_size:
                self._establish_baseline()
                self.baseline_established = True
                logger.info("Baseline established for anomaly detection")

    def _establish_baseline(self) -> None:
        """Establish the normal behavior baseline using collected data."""
        try:
            # Convert deque to numpy array for ML processing
            traffic_array = np.array(list(self.normal_traffic))
            
            # Scale the data
            scaled_data = self.scaler.fit_transform(traffic_array)
            
            # Train the anomaly detector
            self.anomaly_detector.fit(scaled_data)
            self.is_trained = True
            logger.info("Anomaly detector trained on normal traffic data")
        except Exception as e:
            logger.error(f"Error establishing baseline: {e}")
            self.is_trained = False

    def detect_anomaly(self, current_traffic: Dict) -> bool:
        """
        Detect if current traffic is an anomaly.
        
        Args:
            current_traffic (Dict): Current traffic data.
            
        Returns:
            bool: True if anomaly detected, False otherwise.
        """
        if not self.is_trained:
            logger.warning("Anomaly detector not trained yet")
            return False
            
        try:
            # Scale the current traffic data
            current_array = np.array([list(current_traffic.values())])
            scaled_current = self.scaler.transform(current_array)
            
            # Predict anomaly
            prediction = self.anomaly_detector.predict(scaled_current)
            is_anomaly = prediction[0] == -1  # -1 indicates anomaly in IsolationForest
            
            if is_anomaly:
                logger.warning(f"Anomaly detected in traffic: {current_traffic}")
            else:
                logger.debug(f"Traffic is normal: {current_traffic}")
                
            return is_anomaly
        except Exception as e:
            logger.error(f"Error detecting anomaly: {e}")
            return False

class AdaptiveScanner:
    """
    Handles adaptive scanning based on behavioral analysis.
    """
    
    def __init__(self, behavioral_analyzer: BehavioralAnalyzer):
        """
        Initialize the adaptive scanner.
        
        Args:
            behavioral_analyzer (BehavioralAnalyzer): Instance of behavioral analyzer.
        """
        self.behavioral_analyzer = behavioral_analyzer
        self.scanning_strategy = self._get_initial_strategy()
        self.adaptation_history = []

    def _get_initial_strategy(self) -> Dict:
        """Get the initial scanning strategy."""
        return {
            'scan_speed': 'medium',
            'aggressiveness': 'low',
            'target_services': ['http', 'https'],
            'avoid_detection': True
        }

    def adapt_strategy(self, traffic_data: Dict, scan_results: Dict) -> None:
        """
        Adapt scanning strategy based on traffic analysis and scan results.
        
        Args:
            traffic_data (Dict): Current traffic data.
            scan_results (Dict): Results of the last scan.
        """
        # Detect anomalies in traffic
        is_anomaly = self.behavioral_analyzer.detect_anomaly(traffic_data)
        
        # Analyze scan results
        vulnerabilities_found = scan_results.get('total_vulnerabilities', 0)
        critical_vulnerabilities = scan_results.get('critical_vulnerabilities', 0)
        
        # Adapt strategy based on findings
        if is_anomaly:
            # If anomaly detected, reduce aggressiveness
            self.scanning_strategy['scan_speed'] = 'slow'
            self.scanning_strategy['aggressiveness'] = 'very_low'
            self.scanning_strategy['avoid_detection'] = True
            logger.info("Adapting strategy: Anomaly detected - reducing aggressiveness")
        
        elif vulnerabilities_found > 0:
            # If vulnerabilities found, increase aggressiveness
            self.scanning_strategy['scan_speed'] = 'fast'
            self.scanning_strategy['aggressiveness'] = 'high'
            self.scanning_strategy['target_services'].extend(['ssh', 'ftp', 'rdp'])
            logger.info(f"Adapting strategy: {vulnerabilities_found} vulnerabilities found - increasing aggressiveness")
        
        elif critical_vulnerabilities > 0:
            # If critical vulnerabilities found, maximum aggressiveness
            self.scanning_strategy['scan_speed'] = 'fastest'
            self.scanning_strategy['aggressiveness'] = 'critical'
            self.scanning_strategy['target_services'] = ['all']
            logger.info(f"Adapting strategy: {critical_vulnerabilities} critical vulnerabilities found - maximum aggressiveness")
        
        else:
            # If no issues, maintain normal strategy
            self.scanning_strategy['scan_speed'] = 'medium'
            self.scanning_strategy['aggressiveness'] = 'low'
            logger.info("Adapting strategy: No issues detected - maintaining normal strategy")
        
        # Record adaptation
        self.adaptation_history.append({
            'timestamp': time.time(),
            'strategy': self.scanning_strategy.copy(),
            'reason': 'anomaly' if is_anomaly else 'vulnerabilities' if vulnerabilities_found > 0 else 'normal'
        })

    def get_current_strategy(self) -> Dict:
        """Get the current scanning strategy."""
        return self.scanning_strategy.copy()

    def predict_best_attack_vector(self, device_info: Dict) -> str:
        """
        Predict the best attack vector for a device based on its characteristics.
        
        Args:
            device_info (Dict): Information about the device.
            
        Returns:
            str: Predicted best attack vector.
        """
        # Simple prediction based on device characteristics
        open_ports = device_info.get('open_ports', [])
        services = device_info.get('services', {})
        
        # Count services by type
        web_services = sum(1 for port, service in services.items() if 'http' in service.lower())
        database_services = sum(1 for port, service in services.items() if 'mysql' in service.lower() or 'postgres' in service.lower())
        remote_services = sum(1 for port, service in services.items() if 'ssh' in service.lower() or 'rdp' in service.lower())
        
        # Predict best attack vector
        if web_services > 0:
            return 'web_application'
        elif database_services > 0:
            return 'database'
        elif remote_services > 0:
            return 'remote_access'
        else:
            return 'network_service'

class MLAdaptationFramework:
    """
    Main ML adaptation framework integrating behavioral analysis and adaptive scanning.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the ML adaptation framework.
        
        Args:
            config (Dict): Configuration dictionary.
                Expected keys: 'window_size', 'initial_strategy'.
        """
        self.behavioral_analyzer = BehavioralAnalyzer(config.get('window_size', 100))
        self.adaptive_scanner = AdaptiveScanner(self.behavioral_analyzer)
        self.config = config
        self.traffic_monitor = self._setup_traffic_monitor()

    def _setup_traffic_monitor(self) -> Any:
        """Set up traffic monitoring (simplified for demonstration)."""
        # In a real implementation, this would use packet capture libraries
        # For demonstration, we'll return a mock monitor
        class MockTrafficMonitor:
            def __init__(self):
                self.traffic_data = []
            
            def capture_traffic(self) -> Dict:
                # Generate mock traffic data
                return {
                    'packet_size': random.randint(64, 1500),
                    'interval': random.uniform(0.1, 2.0),
                    'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
                    'source_port': random.randint(1024, 65535),
                    'destination_port': random.randint(1, 1024)
                }
        
        return MockTrafficMonitor()

    async def monitor_and_adapt(self, network_devices: List[Dict], scan_results: Dict) -> None:
        """
        Monitor network traffic and adapt scanning strategy.
        
        Args:
            network_devices (List[Dict]): List of network devices.
            scan_results (Dict): Results of the last scan.
        """
        # Capture current traffic
        traffic_data = self.traffic_monitor.capture_traffic()
        
        # Collect traffic data for baseline
        self.behavioral_analyzer.collect_traffic_data(traffic_data)
        
        # Adapt scanning strategy
        self.adaptive_scanner.adapt_strategy(traffic_data, scan_results)
        
        # Get current strategy
        current_strategy = self.adaptive_scanner.get_current_strategy()
        logger.info(f"Current scanning strategy: {current_strategy}")
        
        # Predict best attack vectors for devices
        for device in network_devices:
            best_vector = self.adaptive_scanner.predict_best_attack_vector(device)
            device['predicted_attack_vector'] = best_vector
            logger.info(f"Predicted best attack vector for {device['ip']}: {best_vector}")

    def get_adaptation_history(self) -> List[Dict]:
        """Get the adaptation history."""
        return self.adaptive_scanner.adaptation_history

# Example usage (for testing purposes only)
if __name__ == "__main__":
    # This part should be integrated into the main framework's async loop.
    # For standalone testing, we can run it directly.
    config = {
        'window_size': 100,
        'initial_strategy': {
            'scan_speed': 'medium',
            'aggressiveness': 'low',
            'target_services': ['http', 'https'],
            'avoid_detection': True
        }
    }
    
    ml_framework = MLAdaptationFramework(config)
    
    # Mock network devices and scan results
    mock_devices = [
        {'ip': '192.168.1.100', 'open_ports': [80, 443], 'services': {80: 'http', 443: 'https'}},
        {'ip': '192.168.1.101', 'open_ports': [22, 3306], 'services': {22: 'ssh', 3306: 'mysql'}}
    ]
    
    mock_scan_results = {
        'total_vulnerabilities': 5,
        'critical_vulnerabilities': 2
    }
    
    # Run adaptation
    asyncio.run(ml_framework.monitor_and_adapt(mock_devices, mock_scan_results))
    
    # Print adaptation history
    history = ml_framework.get_adaptation_history()
    print("Adaptation History:")
    for entry in history:
        print(json.dumps(entry, indent=2))