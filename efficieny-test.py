#!/usr/bin/env python3
"""
Shodan OpenVPN Fingerprinting Efficiency Tester

This program tests the efficiency and accuracy of the OpenVPN fingerprinting tool
using real-world data from Shodan. It processes Shodan JSON data, extracts OpenVPN
targets, runs the fingerprinting tool, and analyzes the results.

Usage:
    python3 shodan_openvpn_tester.py -f openvpn.json.gz -o results/
    python3 shodan_openvpn_tester.py --shodan-file openvpn.json.gz --sample 1000 --verbose

Features:
- Processes compressed Shodan JSON data
- Extracts OpenVPN targets from Shodan results
- Runs fingerprinting tool with configurable parameters
- Analyzes efficiency and accuracy metrics
- Generates comprehensive reports and visualizations
- Supports sampling for large datasets

Installation:
    pip install colorama pandas matplotlib seaborn
"""

import json
import gzip
import argparse
import sys
import os
import time
import subprocess
import ipaddress
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import tempfile
import shutil
import logging
from datetime import datetime
import random
import statistics

try:
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns
    ANALYSIS_LIBS_AVAILABLE = True
except ImportError:
    print("⚠️  Install pandas, matplotlib, seaborn for advanced analysis:")
    print("   pip install pandas matplotlib seaborn")
    ANALYSIS_LIBS_AVAILABLE = False

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""
    COLORAMA_AVAILABLE = False

class ShodanOpenVPNTester:
    def __init__(self, verbose: bool = False, output_dir: str = "results"):
        self.verbose = verbose
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.setup_logging()
        
        # Results storage
        self.shodan_targets = []
        self.fingerprint_results = {}
        self.analysis_results = {}
        
        self.log("Initialized Shodan OpenVPN Tester", "SUCCESS")
    
    def setup_logging(self):
        """Setup logging configuration."""
        log_level = logging.DEBUG if self.verbose else logging.INFO
        
        # Create formatters
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        console_formatter = logging.Formatter(
            '%(levelname)s - %(message)s'
        )
        
        # Setup file handler
        log_file = self.output_dir / f"shodan_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(file_formatter)
        
        # Setup console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(console_formatter)
        
        # Configure logger
        self.logger = logging.getLogger('ShodanTester')
        self.logger.setLevel(log_level)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def log(self, message: str, level: str = "INFO"):
        """Log messages with colors and emojis."""
        emoji_map = {
            "DEBUG": "🔍",
            "INFO": "ℹ️",
            "SUCCESS": "✅",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "PROGRESS": "⏳",
            "ANALYSIS": "📊"
        }
        
        color_map = {
            "DEBUG": Fore.CYAN,
            "INFO": Fore.BLUE,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "PROGRESS": Fore.MAGENTA,
            "ANALYSIS": Fore.YELLOW
        }
        
        emoji = emoji_map.get(level, "📝")
        color = color_map.get(level, Fore.WHITE) if COLORAMA_AVAILABLE else ""
        reset = Style.RESET_ALL if COLORAMA_AVAILABLE else ""
        
        formatted_message = f"{color}{emoji} {message}{reset}"
        
        if level == "DEBUG":
            self.logger.debug(message)
        elif level == "WARNING":
            self.logger.warning(message)
        elif level == "ERROR":
            self.logger.error(message)
        else:
            self.logger.info(message)
        
        # Print to console with colors only if not using file logging
        if self.verbose or level in ["SUCCESS", "WARNING", "ERROR"]:
            print(formatted_message)
    
    def parse_shodan_data(self, shodan_file: str, sample_size: Optional[int] = None) -> List[Dict]:
        """Parse Shodan JSON data and extract OpenVPN targets."""
        self.log(f"Parsing Shodan data from: {shodan_file}", "PROGRESS")
        
        targets = []
        total_records = 0
        
        try:
            if shodan_file.endswith('.gz'):
                file_handle = gzip.open(shodan_file, 'rt', encoding='utf-8')
            else:
                file_handle = open(shodan_file, 'r', encoding='utf-8')
            
            with file_handle as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        total_records += 1
                        data = json.loads(line.strip())
                        
                        # Extract relevant fields
                        target = {
                            'ip': data.get('ip_str', ''),
                            'port': data.get('port', 1194),
                            'transport': data.get('transport', 'udp'),
                            'timestamp': data.get('timestamp', ''),
                            'country': data.get('location', {}).get('country_name', ''),
                            'org': data.get('org', ''),
                            'asn': data.get('asn', ''),
                            'hostnames': data.get('hostnames', []),
                            'shodan_data': data.get('data', ''),
                            'shodan_hash': data.get('hash', 0),
                            'tags': data.get('tags', []),
                            'line_number': line_num
                        }
                        
                        # Validate IP address
                        if target['ip']:
                            try:
                                ipaddress.ip_address(target['ip'])
                                targets.append(target)
                                
                                if sample_size and len(targets) >= sample_size:
                                    self.log(f"Reached sample size limit: {sample_size}", "INFO")
                                    break
                                    
                            except ValueError:
                                self.log(f"Invalid IP address: {target['ip']} (line {line_num})", "WARNING")
                    
                    except json.JSONDecodeError as e:
                        self.log(f"JSON decode error on line {line_num}: {e}", "WARNING")
                    except Exception as e:
                        self.log(f"Error processing line {line_num}: {e}", "ERROR")
                    
                    # Progress updates
                    if total_records % 10000 == 0:
                        self.log(f"Processed {total_records} records, found {len(targets)} targets", "PROGRESS")
        
        except Exception as e:
            self.log(f"Error reading Shodan file: {e}", "ERROR")
            return []
        
        self.log(f"Parsing complete: {len(targets)} targets from {total_records} records", "SUCCESS")
        self.shodan_targets = targets
        
        # Save parsed targets
        targets_file = self.output_dir / "shodan_targets.json"
        with open(targets_file, 'w') as f:
            json.dump(targets, f, indent=2)
        self.log(f"Saved targets to: {targets_file}", "SUCCESS")
        
        return targets
    
    def create_target_file(self, targets: List[Dict], protocol_filter: Optional[str] = None) -> str:
        """Create a target file for the fingerprinting tool."""
        if protocol_filter:
            filtered_targets = [t for t in targets if t['transport'].lower() == protocol_filter.lower()]
        else:
            filtered_targets = targets
        
        # Create temporary file with targets
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        
        for target in filtered_targets:
            temp_file.write(f"{target['ip']}\n")
        
        temp_file.close()
        
        self.log(f"Created target file with {len(filtered_targets)} targets: {temp_file.name}", "DEBUG")
        return temp_file.name
    
    def run_fingerprinting_tool(self, targets: List[Dict], protocol: str = "both", 
                               timeout: float = 5.0, threads: int = 50) -> Dict:
        """Run the OpenVPN fingerprinting tool on the targets."""
        self.log(f"Starting fingerprinting scan: {len(targets)} targets, protocol={protocol}", "PROGRESS")
        
        # Create target file
        target_file = self.create_target_file(targets, 
                                            protocol_filter=None if protocol == "both" else protocol)
        
        try:
            # Prepare command
            cmd = [
                sys.executable, "openvpn-fingerprint.py",
                "-f", target_file,
                "--protocol", protocol,
                "--timeout", str(timeout),
                "--threads", str(threads),
                "--json"
            ]
            
            self.log(f"Running command: {' '.join(cmd)}", "DEBUG")
            
            # Run the fingerprinting tool
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            scan_duration = time.time() - start_time
            
            if result.returncode != 0:
                self.log(f"Fingerprinting tool failed with code {result.returncode}", "ERROR")
                self.log(f"STDERR: {result.stderr}", "ERROR")
                return {}
            
            # Parse JSON output
            try:
                fingerprint_data = json.loads(result.stdout)
                fingerprint_data['actual_scan_duration'] = scan_duration
                
                # Save raw results
                results_file = self.output_dir / f"fingerprint_results_{protocol}_{int(time.time())}.json"
                with open(results_file, 'w') as f:
                    json.dump(fingerprint_data, f, indent=2)
                
                self.log(f"Fingerprinting complete in {scan_duration:.2f}s", "SUCCESS")
                self.log(f"Results saved to: {results_file}", "SUCCESS")
                
                return fingerprint_data
                
            except json.JSONDecodeError as e:
                self.log(f"Failed to parse fingerprinting results: {e}", "ERROR")
                self.log(f"STDOUT: {result.stdout[:500]}...", "DEBUG")
                return {}
        
        finally:
            # Clean up temporary file
            try:
                os.unlink(target_file)
            except:
                pass
    
    def analyze_results(self, shodan_targets: List[Dict], fingerprint_results: Dict) -> Dict:
        """Analyze fingerprinting results against Shodan ground truth."""
        self.log("Analyzing fingerprinting results", "ANALYSIS")
        
        if not fingerprint_results or 'results' not in fingerprint_results:
            self.log("No fingerprinting results to analyze", "WARNING")
            return {}
        
        # Create IP lookup for Shodan data
        shodan_by_ip = {target['ip']: target for target in shodan_targets}
        
        # Analysis metrics
        analysis = {
            'total_shodan_targets': len(shodan_targets),
            'total_fingerprint_attempts': len(fingerprint_results['results']),
            'protocol_breakdown': {},
            'detection_metrics': {},
            'performance_metrics': {},
            'geographical_analysis': {},
            'confidence_analysis': {},
            'evidence_analysis': {},
            'timing_analysis': {},
            'false_positives': [],
            'false_negatives': [],
            'true_positives': [],
            'accuracy_by_protocol': {}
        }
        
        # Protocol breakdown from Shodan
        protocol_counts = {}
        for target in shodan_targets:
            protocol = target['transport'].lower()
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        analysis['protocol_breakdown']['shodan'] = protocol_counts
        
        # Analyze fingerprinting results
        fp_protocol_detections = {'tcp': 0, 'udp': 0, 'both': 0}
        true_positives = 0
        false_positives = 0
        false_negatives = 0
        
        # Confidence score tracking
        confidence_scores = {'tcp': [], 'udp': [], 'combined': []}
        evidence_types = {}
        timing_patterns = {'tcp_base_probe_differential': [], 'udp_response_patterns': []}
        
        for fp_result in fingerprint_results['results']:
            ip = fp_result['host']
            shodan_target = shodan_by_ip.get(ip)
            
            if not shodan_target:
                continue
            
            shodan_protocol = shodan_target['transport'].lower()
            
            # Determine if fingerprinting detected OpenVPN
            if 'overall_assessment' in fp_result:
                # Both protocol scan
                tcp_detected = fp_result['overall_assessment']['tcp_openvpn']
                udp_detected = fp_result['overall_assessment']['udp_openvpn']
                any_detected = fp_result['overall_assessment']['any_openvpn']
                
                tcp_confidence = fp_result.get('tcp', {}).get('confidence', 0)
                udp_confidence = fp_result.get('udp', {}).get('confidence', 0)
                
                # Track confidence scores
                if tcp_detected:
                    confidence_scores['tcp'].append(tcp_confidence)
                    fp_protocol_detections['tcp'] += 1
                if udp_detected:
                    confidence_scores['udp'].append(udp_confidence)
                    fp_protocol_detections['udp'] += 1
                if any_detected:
                    confidence_scores['combined'].append(max(tcp_confidence, udp_confidence))
                    fp_protocol_detections['both'] += 1
                
                # Analyze evidence types
                tcp_evidence = fp_result.get('tcp', {}).get('evidence', [])
                udp_evidence = fp_result.get('udp', {}).get('evidence', [])
                
                for evidence in tcp_evidence + udp_evidence:
                    evidence_key = evidence.split('(')[0].strip()  # Remove technical details
                    evidence_types[evidence_key] = evidence_types.get(evidence_key, 0) + 1
                
                # Analyze timing patterns
                tcp_probes = fp_result.get('tcp', {}).get('probe_results', {})
                if 'base_probe_1' in tcp_probes and 'base_probe_2' in tcp_probes:
                    probe1_time = tcp_probes['base_probe_1'].get('time', 0)
                    probe2_time = tcp_probes['base_probe_2'].get('time', 0)
                    if probe1_time > 0 and probe2_time > 0:
                        time_diff = abs(probe2_time - probe1_time)
                        timing_patterns['tcp_base_probe_differential'].append(time_diff)
                
                # Ground truth: Shodan found OpenVPN on this IP/port
                if any_detected:
                    true_positives += 1
                    analysis['true_positives'].append({
                        'ip': ip,
                        'shodan_protocol': shodan_protocol,
                        'detected_tcp': tcp_detected,
                        'detected_udp': udp_detected,
                        'tcp_confidence': tcp_confidence,
                        'udp_confidence': udp_confidence,
                        'tcp_evidence_count': len(tcp_evidence),
                        'udp_evidence_count': len(udp_evidence),
                        'country': shodan_target.get('country', ''),
                        'org': shodan_target.get('org', ''),
                        'expected_protocol': shodan_protocol
                    })
                else:
                    false_negatives += 1
                    analysis['false_negatives'].append({
                        'ip': ip,
                        'shodan_protocol': shodan_protocol,
                        'shodan_data': shodan_target.get('shodan_data', ''),
                        'org': shodan_target.get('org', ''),
                        'country': shodan_target.get('country', ''),
                        'tcp_confidence': tcp_confidence,
                        'udp_confidence': udp_confidence,
                        'tcp_evidence': tcp_evidence,
                        'udp_evidence': udp_evidence
                    })
            
            else:
                # Single protocol scan
                detected = fp_result['is_openvpn']
                fp_protocol = fp_result['protocol']
                confidence = fp_result.get('confidence', 0)
                evidence = fp_result.get('evidence', [])
                
                if detected:
                    confidence_scores[fp_protocol].append(confidence)
                    fp_protocol_detections[fp_protocol] += 1
                    
                    # Analyze evidence
                    for ev in evidence:
                        evidence_key = ev.split('(')[0].strip()
                        evidence_types[evidence_key] = evidence_types.get(evidence_key, 0) + 1
                    
                    # Since all Shodan targets should be OpenVPN
                    true_positives += 1
                    analysis['true_positives'].append({
                        'ip': ip,
                        'protocol': fp_protocol,
                        'confidence': confidence,
                        'evidence_count': len(evidence),
                        'expected_protocol': shodan_protocol,
                        'protocol_match': fp_protocol == shodan_protocol
                    })
                else:
                    false_negatives += 1
                    analysis['false_negatives'].append({
                        'ip': ip,
                        'shodan_protocol': shodan_protocol,
                        'confidence': confidence,
                        'evidence': evidence,
                        'scanned_protocol': fp_protocol
                    })
        
        # Calculate metrics
        total_targets = len(shodan_targets)
        analysis['detection_metrics'] = {
            'true_positives': true_positives,
            'false_positives': false_positives,  # Should be 0 for Shodan OpenVPN data
            'false_negatives': false_negatives,
            'true_negatives': 0,  # We don't have non-OpenVPN targets from Shodan
            'precision': true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0,
            'recall': true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0,
            'detection_rate': true_positives / total_targets if total_targets > 0 else 0,
            'accuracy': true_positives / total_targets if total_targets > 0 else 0  # Since all should be OpenVPN
        }
        
        # Calculate F1 score
        precision = analysis['detection_metrics']['precision']
        recall = analysis['detection_metrics']['recall']
        analysis['detection_metrics']['f1_score'] = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Confidence analysis
        analysis['confidence_analysis'] = {
            'tcp': self._calculate_stats(confidence_scores['tcp']),
            'udp': self._calculate_stats(confidence_scores['udp']),
            'combined': self._calculate_stats(confidence_scores['combined'])
        }
        
        # Evidence analysis
        analysis['evidence_analysis'] = {
            'type_counts': evidence_types,
            'most_common': sorted(evidence_types.items(), key=lambda x: x[1], reverse=True)[:5]
        }
        
        # Timing analysis
        if timing_patterns['tcp_base_probe_differential']:
            analysis['timing_analysis']['tcp_probe_differential'] = self._calculate_stats(
                timing_patterns['tcp_base_probe_differential']
            )
        
        # Performance metrics from fingerprinting results
        if 'scan_stats' in fingerprint_results:
            stats = fingerprint_results['scan_stats']
            analysis['performance_metrics'] = {
                'scan_duration': stats.get('total_scan_time', 0),
                'actual_duration': fingerprint_results.get('actual_scan_duration', 0),
                'targets_per_second': total_targets / stats.get('total_scan_time', 1) if stats.get('total_scan_time', 0) > 0 else 0,
                'average_time_per_host': stats.get('average_time_per_host', 0)
            }
        
        # Geographical analysis
        country_detections = {}
        for tp in analysis['true_positives']:
            country = tp.get('country', 'Unknown')
            if country not in country_detections:
                country_detections[country] = {'detected': 0, 'total': 0}
            country_detections[country]['detected'] += 1
        
        for target in shodan_targets:
            country = target.get('country', 'Unknown')
            if country not in country_detections:
                country_detections[country] = {'detected': 0, 'total': 0}
            country_detections[country]['total'] += 1
        
        # Calculate detection rate by country
        for country, counts in country_detections.items():
            if counts['total'] > 0:
                counts['detection_rate'] = counts['detected'] / counts['total']
        
        analysis['geographical_analysis'] = country_detections
        
        # Protocol-specific accuracy
        for protocol in ['tcp', 'udp']:
            protocol_targets = [t for t in shodan_targets if t['transport'].lower() == protocol]
            if protocol_targets:
                protocol_detected = sum(1 for tp in analysis['true_positives'] 
                                      if tp.get('expected_protocol', tp.get('protocol', '')) == protocol)
                analysis['accuracy_by_protocol'][protocol] = {
                    'total': len(protocol_targets),
                    'detected': protocol_detected,
                    'accuracy': protocol_detected / len(protocol_targets)
                }
        
        self.analysis_results = analysis
        
        # Save analysis results
        analysis_file = self.output_dir / f"analysis_results_{int(time.time())}.json"
        with open(analysis_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        self.log(f"Analysis results saved to: {analysis_file}", "SUCCESS")
        
        return analysis
    
    def _calculate_stats(self, values: List[float]) -> Dict:
        """Calculate statistics for a list of values."""
        if not values:
            return {
                'count': 0,
                'mean': 0,
                'median': 0,
                'min': 0,
                'max': 0,
                'std': 0
            }
        
        return {
            'count': len(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'min': min(values),
            'max': max(values),
            'std': statistics.stdev(values) if len(values) > 1 else 0
        }
    
    def generate_report(self):
        """Generate a comprehensive report of the testing results."""
        self.log("Generating comprehensive report", "ANALYSIS")
        
        if not self.analysis_results:
            self.log("No analysis results available for report generation", "WARNING")
            return
        
        # Generate text report
        report_lines = [
            "=" * 80,
            "SHODAN OPENVPN FINGERPRINTING TEST REPORT",
            "=" * 80,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "SUMMARY",
            "-" * 40,
            f"Total Shodan Targets: {self.analysis_results['total_shodan_targets']}",
            f"Total Fingerprinting Attempts: {self.analysis_results['total_fingerprint_attempts']}",
            "",
            "DETECTION METRICS",
            "-" * 40
        ]
        
        metrics = self.analysis_results['detection_metrics']
        report_lines.extend([
            f"True Positives: {metrics['true_positives']}",
            f"False Positives: {metrics['false_positives']}",
            f"False Negatives: {metrics['false_negatives']}",
            f"Precision: {metrics['precision']:.3f}",
            f"Recall: {metrics['recall']:.3f}",
            f"F1 Score: {metrics['f1_score']:.3f}",
            f"Overall Detection Rate: {metrics['detection_rate']:.1%}",
            "",
            "PROTOCOL BREAKDOWN",
            "-" * 40
        ])
        
        if 'shodan' in self.analysis_results['protocol_breakdown']:
            for protocol, count in self.analysis_results['protocol_breakdown']['shodan'].items():
                report_lines.append(f"Shodan {protocol.upper()}: {count}")
        
        report_lines.extend([
            "",
            "CONFIDENCE ANALYSIS",
            "-" * 40
        ])
        
        for protocol, stats in self.analysis_results['confidence_analysis'].items():
            if stats['count'] > 0:
                report_lines.extend([
                    f"{protocol.upper()} Confidence:",
                    f"  Mean: {stats['mean']:.2f}",
                    f"  Median: {stats['median']:.2f}",
                    f"  Range: {stats['min']:.2f} - {stats['max']:.2f}",
                    ""
                ])
        
        report_lines.extend([
            "EVIDENCE ANALYSIS",
            "-" * 40,
            "Most Common Evidence Types:"
        ])
        
        for evidence_type, count in self.analysis_results['evidence_analysis']['most_common']:
            report_lines.append(f"  {evidence_type}: {count}")
        
        if 'performance_metrics' in self.analysis_results:
            perf = self.analysis_results['performance_metrics']
            report_lines.extend([
                "",
                "PERFORMANCE METRICS",
                "-" * 40,
                f"Scan Duration: {perf.get('scan_duration', 0):.2f}s",
                f"Targets per Second: {perf.get('targets_per_second', 0):.2f}",
                f"Average Time per Host: {perf.get('average_time_per_host', 0):.3f}s"
            ])
        
        # Top false negatives
        if self.analysis_results['false_negatives']:
            report_lines.extend([
                "",
                "TOP FALSE NEGATIVES",
                "-" * 40
            ])
            
            for i, fn in enumerate(self.analysis_results['false_negatives'][:5], 1):
                report_lines.extend([
                    f"{i}. IP: {fn['ip']}",
                    f"   Expected Protocol: {fn['shodan_protocol']}",
                    f"   Organization: {fn.get('org', 'N/A')}",
                    f"   Country: {fn.get('country', 'N/A')}",
                    ""
                ])
        
        # Save text report
        report_file = self.output_dir / f"test_report_{int(time.time())}.txt"
        with open(report_file, 'w') as f:
            f.write('\n'.join(report_lines))
        
        self.log(f"Text report saved to: {report_file}", "SUCCESS")
        
        # Generate visualizations if available
        if ANALYSIS_LIBS_AVAILABLE:
            self.generate_visualizations()
    
    def generate_visualizations(self):
        """Generate visualization plots for the analysis results."""
        self.log("Generating visualizations", "ANALYSIS")
        
        # Set style
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (12, 8)
        
        # 1. Detection Metrics Bar Chart
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        metrics = self.analysis_results['detection_metrics']
        metrics_names = ['Precision', 'Recall', 'F1 Score', 'Detection Rate']
        metrics_values = [
            metrics['precision'],
            metrics['recall'],
            metrics['f1_score'],
            metrics['detection_rate']
        ]
        
        bars = ax1.bar(metrics_names, metrics_values, color=['#2ecc71', '#3498db', '#9b59b6', '#e74c3c'])
        ax1.set_ylim(0, 1.1)
        ax1.set_ylabel('Score')
        ax1.set_title('Detection Performance Metrics')
        
        # Add value labels on bars
        for bar, value in zip(bars, metrics_values):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height + 0.02,
                    f'{value:.3f}', ha='center', va='bottom')
        
        # 2. Confidence Distribution
        confidence_data = []
        confidence_labels = []
        
        for protocol, stats in self.analysis_results['confidence_analysis'].items():
            if stats['count'] > 0:
                # Get raw confidence scores
                if protocol == 'tcp':
                    scores = [tp['tcp_confidence'] for tp in self.analysis_results['true_positives'] 
                             if 'tcp_confidence' in tp and tp['tcp_confidence'] > 0]
                elif protocol == 'udp':
                    scores = [tp['udp_confidence'] for tp in self.analysis_results['true_positives'] 
                             if 'udp_confidence' in tp and tp['udp_confidence'] > 0]
                else:
                    scores = [max(tp.get('tcp_confidence', 0), tp.get('udp_confidence', 0)) 
                             for tp in self.analysis_results['true_positives']]
                
                if scores:
                    confidence_data.append(scores)
                    confidence_labels.append(protocol.upper())
        
        if confidence_data:
            ax2.violinplot(confidence_data, showmeans=True, showmedians=True)
            ax2.set_xticks(range(1, len(confidence_labels) + 1))
            ax2.set_xticklabels(confidence_labels)
            ax2.set_ylabel('Confidence Score')
            ax2.set_title('Confidence Score Distribution by Protocol')
            ax2.set_ylim(0, 110)
        
        plt.tight_layout()
        plot_file = self.output_dir / f"detection_metrics_{int(time.time())}.png"
        plt.savefig(plot_file, dpi=300, bbox_inches='tight')
        plt.close()
        self.log(f"Detection metrics plot saved to: {plot_file}", "SUCCESS")
        
        # 3. Geographic Analysis
        if self.analysis_results['geographical_analysis']:
            fig, ax = plt.subplots(figsize=(14, 8))
            
            countries = []
            detection_rates = []
            totals = []
            
            for country, data in sorted(self.analysis_results['geographical_analysis'].items(), 
                                      key=lambda x: x[1]['total'], reverse=True)[:20]:
                if data['total'] > 0:
                    countries.append(country[:20])  # Truncate long names
                    detection_rates.append(data.get('detection_rate', 0))
                    totals.append(data['total'])
            
            if countries:
                x = range(len(countries))
                bars = ax.bar(x, detection_rates, color='#3498db', alpha=0.7)
                
                # Add target count labels
                for i, (bar, total) in enumerate(zip(bars, totals)):
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                           f'n={total}', ha='center', va='bottom', fontsize=8)
                
                ax.set_xticks(x)
                ax.set_xticklabels(countries, rotation=45, ha='right')
                ax.set_ylabel('Detection Rate')
                ax.set_ylim(0, 1.2)
                ax.set_title('Detection Rate by Country (Top 20)')
                ax.axhline(y=metrics['detection_rate'], color='r', linestyle='--', 
                          label=f"Overall: {metrics['detection_rate']:.1%}")
                ax.legend()
                
                plt.tight_layout()
                plot_file = self.output_dir / f"geographic_analysis_{int(time.time())}.png"
                plt.savefig(plot_file, dpi=300, bbox_inches='tight')
                plt.close()
                self.log(f"Geographic analysis plot saved to: {plot_file}", "SUCCESS")
        
        # 4. Evidence Type Analysis
        if self.analysis_results['evidence_analysis']['type_counts']:
            fig, ax = plt.subplots(figsize=(12, 8))
            
            evidence_types = []
            counts = []
            
            for ev_type, count in sorted(self.analysis_results['evidence_analysis']['type_counts'].items(),
                                       key=lambda x: x[1], reverse=True)[:15]:
                evidence_types.append(ev_type)
                counts.append(count)
            
            y_pos = range(len(evidence_types))
            ax.barh(y_pos, counts, color='#27ae60')
            ax.set_yticks(y_pos)
            ax.set_yticklabels(evidence_types)
            ax.set_xlabel('Count')
            ax.set_title('Most Common Evidence Types')
            
            # Add count labels
            for i, count in enumerate(counts):
                ax.text(count + max(counts) * 0.01, i, str(count), 
                       va='center', fontsize=9)
            
            plt.tight_layout()
            plot_file = self.output_dir / f"evidence_analysis_{int(time.time())}.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            self.log(f"Evidence analysis plot saved to: {plot_file}", "SUCCESS")
        
        # 5. Protocol Accuracy Comparison
        if self.analysis_results['accuracy_by_protocol']:
            fig, ax = plt.subplots(figsize=(10, 6))
            
            protocols = []
            accuracies = []
            totals = []
            
            for protocol, data in self.analysis_results['accuracy_by_protocol'].items():
                protocols.append(protocol.upper())
                accuracies.append(data['accuracy'])
                totals.append(data['total'])
            
            x = range(len(protocols))
            bars = ax.bar(x, accuracies, color=['#e74c3c', '#3498db'])
            
            # Add labels
            for i, (bar, total, detected) in enumerate(zip(bars, totals, 
                [self.analysis_results['accuracy_by_protocol'][p.lower()]['detected'] for p in protocols])):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + 0.02,
                       f'{detected}/{total}\n({height:.1%})', 
                       ha='center', va='bottom')
            
            ax.set_xticks(x)
            ax.set_xticklabels(protocols)
            ax.set_ylabel('Accuracy')
            ax.set_ylim(0, 1.2)
            ax.set_title('Detection Accuracy by Protocol')
            
            plt.tight_layout()
            plot_file = self.output_dir / f"protocol_accuracy_{int(time.time())}.png"
            plt.savefig(plot_file, dpi=300, bbox_inches='tight')
            plt.close()
            self.log(f"Protocol accuracy plot saved to: {plot_file}", "SUCCESS")
    
    def run_full_test(self, shodan_file: str, sample_size: Optional[int] = None,
                     protocol: str = "both", timeout: float = 5.0, threads: int = 50):
        """Run the complete testing workflow."""
        self.log("Starting full Shodan OpenVPN fingerprinting test", "PROGRESS")
        
        # Step 1: Parse Shodan data
        targets = self.parse_shodan_data(shodan_file, sample_size)
        if not targets:
            self.log("No targets found in Shodan data", "ERROR")
            return
        
        # Step 2: Run fingerprinting tool
        fingerprint_results = self.run_fingerprinting_tool(
            targets, protocol=protocol, timeout=timeout, threads=threads
        )
        if not fingerprint_results:
            self.log("Fingerprinting failed", "ERROR")
            return
        
        # Step 3: Analyze results
        analysis = self.analyze_results(targets, fingerprint_results)
        
        # Step 4: Generate report
        self.generate_report()
        
        # Print summary
        self.print_summary()
        
        self.log("Testing complete!", "SUCCESS")
    
    def print_summary(self):
        """Print a summary of the test results to console."""
        if not self.analysis_results:
            return
        
        metrics = self.analysis_results['detection_metrics']
        
        print("\n" + "=" * 60)
        print("SHODAN OPENVPN FINGERPRINTING TEST SUMMARY")
        print("=" * 60)
        print(f"Total Targets: {self.analysis_results['total_shodan_targets']}")
        print(f"Detection Rate: {metrics['detection_rate']:.1%}")
        print(f"Precision: {metrics['precision']:.3f}")
        print(f"Recall: {metrics['recall']:.3f}")
        print(f"F1 Score: {metrics['f1_score']:.3f}")
        print(f"False Negatives: {metrics['false_negatives']}")
        
        if 'performance_metrics' in self.analysis_results:
            perf = self.analysis_results['performance_metrics']
            print(f"\nScan Duration: {perf.get('scan_duration', 0):.2f}s")
            print(f"Targets per Second: {perf.get('targets_per_second', 0):.2f}")
        
        print("\nFull report available in:", self.output_dir)
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='Test OpenVPN fingerprinting tool efficiency using Shodan data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with a Shodan JSON file
  python3 shodan_openvpn_tester.py -f openvpn.json.gz

  # Test with sampling and specific protocol
  python3 shodan_openvpn_tester.py -f openvpn.json.gz --sample 1000 --protocol tcp

  # Test with custom parameters
  python3 shodan_openvpn_tester.py -f openvpn.json.gz --threads 100 --timeout 10 -v
        """
    )
    
    parser.add_argument('-f', '--shodan-file', required=True,
                       help='Shodan JSON file (can be gzipped)')
    parser.add_argument('-o', '--output-dir', default='results',
                       help='Output directory for results (default: results)')
    parser.add_argument('--sample', type=int, metavar='N',
                       help='Sample N random targets from Shodan data')
    parser.add_argument('--protocol', choices=['tcp', 'udp', 'both'], default='both',
                       help='Protocol to test (default: both)')
    parser.add_argument('--timeout', type=float, default=5.0,
                       help='Timeout per connection in seconds (default: 5.0)')
    parser.add_argument('--threads', type=int, default=50,
                       help='Number of concurrent threads (default: 50)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Verify Shodan file exists
    if not os.path.exists(args.shodan_file):
        print(f"{Fore.RED}❌ Error: Shodan file not found: {args.shodan_file}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Verify fingerprinting tool exists
    if not os.path.exists('openvpn-fingerprint.py'):
        print(f"{Fore.RED}❌ Error: openvpn-fingerprint.py not found in current directory{Style.RESET_ALL}")
        sys.exit(1)
    
    # Create tester instance
    tester = ShodanOpenVPNTester(verbose=args.verbose, output_dir=args.output_dir)
    
    try:
        # Run the full test
        tester.run_full_test(
            shodan_file=args.shodan_file,
            sample_size=args.sample,
            protocol=args.protocol,
            timeout=args.timeout,
            threads=args.threads
        )
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Test interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}❌ Unexpected error: {e}{Style.RESET_ALL}")
        if tester.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()