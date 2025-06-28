#!/usr/bin/env python3
"""
OpenVPN TCP/UDP Fingerprinting Tool (Enhanced Version)
Based on research: "OpenVPN Is Open to VPN Fingerprinting" (ACM CACM 2024)
Source: https://cacm.acm.org/research/openvpn-is-open-to-vpn-fingerprinting/
GitHub: https://github.com/jonaslejon/openvpn-fingerprint

This enhanced version includes:
- Adaptive confidence thresholds
- Improved RST pattern detection
- Connection timeout analysis
- Retry logic for network failures
- Enhanced UDP response pattern analysis
- Probe order randomization
- Adaptive timeout calculation
- Statistical confidence calculation
- Evidence weighting system
- Server behavioral profiling

Author: Based on research by Xue et al.
Reference: Diwen Xue, Reethika Ramesh, Arham Jain, Michaelis Kallitsis, 
           J. Alex Halderman, Jedidiah R. Crandall, and Roya Ensafi.
           "OpenVPN Is Open to VPN Fingerprinting." 
           Communications of the ACM, 2024.

License: MIT
"""
import socket
import time
import struct
import argparse
import sys
import json
from typing import Tuple, Optional, Dict, List
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import math
from dataclasses import dataclass
from enum import Enum

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    print("⚠️  Install colorama for colored output: pip install colorama")
    COLORAMA_AVAILABLE = False
    # Fallback color class
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""


class EvidenceType(Enum):
    """Evidence types with their respective weights."""
    OPENVPN_SERVER_RESET_V2 = ("P_CONTROL_HARD_RESET_SERVER_V2", 1.0)
    OPENVPN_SERVER_RESET_V1 = ("P_CONTROL_HARD_RESET_SERVER_V1", 0.9)
    OPENVPN_CONTROL_V1 = ("P_CONTROL_V1", 0.7)
    OPENVPN_ACK = ("P_ACK_V1", 0.6)
    OPENVPN_DATA = ("P_DATA_V1", 0.5)
    VALID_TCP_STRUCTURE = ("Valid OpenVPN TCP packet structure", 0.5)
    NEAR_VALID_TCP_STRUCTURE = ("Near-valid OpenVPN TCP packet structure", 0.3)
    NON_ZERO_SESSION_ID = ("Non-zero session ID suggests active OpenVPN session", 0.3)
    RECENT_TIMESTAMP = ("Recent timestamp suggests active OpenVPN server", 0.4)
    TCP_TIMING_DIFFERENTIAL = ("TCP timing differential suggests OpenVPN", 0.4)
    RST_ON_2K_PAYLOAD = ("RST on 2K payload suggests OpenVPN buffer behavior", 0.4)
    UDP_SELECTIVE_RESPONSE = ("UDP selective response pattern suggests OpenVPN", 0.6)
    UDP_CLIENT_RESET_RESPONSE = ("UDP server responded to Client Reset", 0.5)
    UDP_PORT_DIFFERENTIATION = ("UDP port differentiation pattern", 0.7)
    TIMEOUT_PATTERN = ("Timeout pattern suggests OpenVPN", 0.3)
    BEHAVIORAL_PROFILE_MATCH = ("Behavioral profile matches OpenVPN", 0.5)


@dataclass
class OpenVPNProfile:
    """Profile for different OpenVPN server configurations."""
    name: str
    tcp_rst_on_invalid: bool
    tcp_rst_on_large: bool
    tcp_timing_differential: bool
    udp_selective_response: bool
    udp_responds_to_reset: bool
    udp_port_differentiation: bool
    timeout_selective: bool
    
    def match_score(self, behaviors: Dict[str, bool]) -> float:
        """Calculate match score against observed behaviors."""
        matches = 0
        total = 0
        
        for attr in ['tcp_rst_on_invalid', 'tcp_rst_on_large', 'tcp_timing_differential',
                     'udp_selective_response', 'udp_responds_to_reset', 'udp_port_differentiation', 
                     'timeout_selective']:
            if attr in behaviors:
                total += 1
                if getattr(self, attr) == behaviors[attr]:
                    matches += 1
        
        return matches / total if total > 0 else 0.0


# Common OpenVPN server profiles
OPENVPN_PROFILES = [
    OpenVPNProfile(
        name="strict",
        tcp_rst_on_invalid=True,
        tcp_rst_on_large=True,
        tcp_timing_differential=True,
        udp_selective_response=True,
        udp_responds_to_reset=True,
        udp_port_differentiation=False,
        timeout_selective=False
    ),
    OpenVPNProfile(
        name="permissive",
        tcp_rst_on_invalid=False,
        tcp_rst_on_large=True,
        tcp_timing_differential=True,
        udp_selective_response=True,
        udp_responds_to_reset=True,
        udp_port_differentiation=True,
        timeout_selective=True
    ),
    OpenVPNProfile(
        name="hardened",
        tcp_rst_on_invalid=True,
        tcp_rst_on_large=True,
        tcp_timing_differential=False,
        udp_selective_response=True,
        udp_responds_to_reset=False,
        udp_port_differentiation=True,
        timeout_selective=True
    )
]


class OpenVPNFingerprinter:
    def __init__(self, timeout: float = 5.0, verbose: bool = False, super_verbose: bool = False, json_output: bool = False, logging_enabled: bool = True):
        self.timeout = timeout
        self.verbose = verbose
        self.super_verbose = super_verbose
        self.json_output = json_output
        self.logging_enabled = logging_enabled
        self.results = {}
        self.scan_metadata = {
            'tool_name': 'OpenVPN TCP/UDP Fingerprinting Tool',
            'version': '2.4.3',  # Keep consistent with banner,
            'scan_timestamp': time.time(),
            'scan_time_iso': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        
        # Evidence weight mapping
        self.evidence_weights = {ev.value[0]: ev.value[1] for ev in EvidenceType}
        
    def log(self, message: str, level: str = "DEBUG"):
        """Print verbose logging messages with emojis and colors."""
        if not self.logging_enabled:
            return
        if self.json_output:
            return  # Suppress all output in JSON mode except final JSON
            
        if not self.verbose and not self.super_verbose:
            return
            
        if level == "DEBUG" and not self.super_verbose:
            return
            
        emoji_map = {
            "DEBUG": "🔍",
            "INFO": "ℹ️",
            "SUCCESS": "✅",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "NETWORK": "🌐",
            "PACKET": "📦",
            "TIMING": "⏱️",
            "ANALYSIS": "🧪",
            "PROFILE": "👤",
            "CONFIDENCE": "📊"
        }
        
        color_map = {
            "DEBUG": Fore.CYAN,
            "INFO": Fore.BLUE,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "NETWORK": Fore.MAGENTA,
            "PACKET": Fore.BLUE,
            "TIMING": Fore.YELLOW,
            "ANALYSIS": Fore.GREEN,
            "PROFILE": Fore.CYAN,
            "CONFIDENCE": Fore.MAGENTA
        }
        
        # Check if message already starts with an emoji to avoid duplication
        # Common emojis used in messages
        common_emojis = ['🌐', '✅', '📥', '📭', '⏰', '🔌', '🚫', '❌', '⏱️', '📡', '🎯', '🔍', '📏', '🆔', '🔄', '🕐', '🔐', '👤', '📊', '🏁']
        message_has_emoji = any(message.strip().startswith(emoji) for emoji in common_emojis)
        
        emoji = emoji_map.get(level, "🔧")
        color = color_map.get(level, Fore.WHITE)
        
        timestamp = time.strftime("%H:%M:%S")
        
        # Only add emoji if message doesn't already have one
        if message_has_emoji:
            print(f"{color}[{timestamp}] {message}{Style.RESET_ALL}")
        else:
            print(f"{color}[{timestamp}] {emoji} {message}{Style.RESET_ALL}")
    
    def log_packet(self, direction: str, data: bytes, protocol: str = "TCP"):
        """Log packet data in super verbose mode."""
        if not self.logging_enabled:
            return
        if self.json_output or not self.super_verbose:
            return
            
        arrow = "➡️" if direction == "SEND" else "⬅️"
        color = Fore.CYAN if direction == "SEND" else Fore.GREEN
        
        hex_data = data[:32].hex()  # First 32 bytes
        ascii_data = ''.join(c if 32 <= ord(c) <= 126 else '.' for c in data[:32].decode('latin-1'))
        
        self.log(f"{arrow} {protocol} {direction}: {len(data)} bytes", "PACKET")
        if self.super_verbose:
            print(f"    {color}HEX: {hex_data}{Style.RESET_ALL}")
            print(f"    {color}ASCII: {ascii_data}{Style.RESET_ALL}")
            
            # Decode OpenVPN fields if possible
            if len(data) >= 1:
                opcode = data[0]
                opcode_names = {
                    0x20: "P_CONTROL_HARD_RESET_CLIENT_V1",
                    0x28: "P_CONTROL_HARD_RESET_SERVER_V1", 
                    0x38: "P_CONTROL_HARD_RESET_CLIENT_V2",
                    0x48: "P_CONTROL_HARD_RESET_SERVER_V2",
                    0x30: "P_CONTROL_SOFT_RESET_V1",
                    0x40: "P_CONTROL_V1",
                    0x50: "P_ACK_V1",
                    0x60: "P_DATA_V1"
                }
                if opcode in opcode_names:
                    self.log(f"    🏷️  Opcode: 0x{opcode:02x} ({opcode_names[opcode]})", "ANALYSIS")
    
    def get_detection_threshold(self, protocol: str) -> float:
        """Get protocol-specific detection thresholds."""
        thresholds = {
            'tcp': 0.18,  # Lowered from 0.2 to catch servers with only RST evidence
            'udp': 0.3,   # Keep at 0.3
            'combined': 0.25
        }
        return thresholds.get(protocol.lower(), 0.3)
    
    def calculate_adaptive_timeout(self, host: str, port: int) -> float:
        """Calculate adaptive timeout based on network conditions."""
        self.log(f"Calculating adaptive timeout for {host}:{port}", "TIMING")
        
        # Quick connectivity test
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((host, port))
            sock.close()
            rtt = time.time() - start
            
            # Set timeout to 10x RTT, minimum 3s, maximum 10s
            adaptive_timeout = max(3.0, min(10.0, rtt * 10))
            self.log(f"RTT: {rtt:.3f}s, Adaptive timeout: {adaptive_timeout:.3f}s", "TIMING")
            return adaptive_timeout
        except:
            self.log(f"Failed to calculate adaptive timeout, using default: {self.timeout}s", "WARNING")
            return self.timeout
    
    def apply_evidence_weight(self, evidence: str) -> float:
        """Get weight for specific evidence type."""
        for pattern, weight in self.evidence_weights.items():
            if pattern in evidence:
                self.log(f"Evidence '{evidence}' matched pattern '{pattern}' with weight {weight}", "CONFIDENCE")
                return weight
        self.log(f"Evidence '{evidence}' using default weight 0.2", "CONFIDENCE")
        return 0.2  # Default weight
    
    def calculate_bayesian_confidence(self, evidence_list: List[Tuple[str, float]]) -> float:
        """Calculate confidence using Bayesian inference."""
        if not evidence_list:
            return 0.0
        
        # Prior probability (base rate of OpenVPN servers)
        prior = 0.1
        
        # Calculate likelihood from weighted evidence
        likelihood = 1.0
        for evidence, weight in evidence_list:
            likelihood *= (1 + weight)
        
        # Normalize to 0-1 range
        posterior = (prior * likelihood) / (prior * likelihood + (1 - prior))
        confidence = min(1.0, posterior)
        
        self.log(f"Bayesian confidence calculation: prior={prior}, likelihood={likelihood:.3f}, posterior={confidence:.3f}", "CONFIDENCE")
        return confidence
    
    def analyze_timeout_patterns(self, probe_results: Dict) -> Tuple[float, str]:
        """Analyze timeout patterns for OpenVPN characteristics."""
        timeout_count = sum(1 for r in probe_results.values() 
                           if r['time'] > self.timeout - 0.5)
        total_probes = len(probe_results)
        
        if total_probes == 0:
            return 0.0, ""
        
        timeout_ratio = timeout_count / total_probes
        self.log(f"Timeout pattern analysis: {timeout_count}/{total_probes} = {timeout_ratio:.2f}", "ANALYSIS")
        
        # OpenVPN often shows selective timeout behavior
        if 0.3 < timeout_ratio < 0.7:
            return 0.3, "Selective timeout pattern suggests OpenVPN"
        elif timeout_ratio > 0.8:
            return 0.6, "High timeout rate suggests filtered OpenVPN"
        
        return 0.0, ""
    
    def analyze_udp_response_pattern(self, probe_results: Dict) -> Tuple[float, str]:
        """Analyze UDP response patterns for OpenVPN characteristics."""
        responded = {name: result.get('got_response', False) 
                    for name, result in probe_results.items()
                    if not name.startswith('control_')}  # Exclude control port results
        
        # OpenVPN typically responds to client_reset but not invalid probes
        if (responded.get('client_reset', False) and 
            not responded.get('invalid_opcode', False) and
            not responded.get('additional_generic', False)):
            self.log("Detected classic OpenVPN UDP response pattern", "ANALYSIS")
            return 0.6, "UDP selective response pattern suggests OpenVPN"
        
        # Alternative pattern: responds only to valid OpenVPN packets
        valid_responses = sum(1 for k, v in responded.items() if k in ['client_reset', 'short_packet'] and v)
        invalid_responses = sum(1 for k, v in responded.items() if 'additional' in k and v)
        
        if valid_responses > 0 and invalid_responses == 0:
            self.log("Detected alternative OpenVPN UDP pattern", "ANALYSIS")
            return 0.4, "UDP responds only to valid OpenVPN packets"
        
        return 0.0, ""
    
    def analyze_udp_port_differentiation(self, target_results: Dict, control_results: List[Dict]) -> Tuple[float, str]:
        """Analyze differences between target port and control port responses.
        This detects OpenVPN by comparing behavior on port 1194 vs random ports."""
        
        if not control_results:
            return 0.0, ""
        
        self.log("Analyzing UDP port differentiation patterns", "ANALYSIS")
        
        # Count response types for target port (1194)
        target_responses = sum(1 for r in target_results.values() if r.get('got_response', False))
        target_timeouts = sum(1 for r in target_results.values() if r['time'] > self.timeout - 0.5)
        target_errors = sum(1 for r in target_results.values() if r.get('got_icmp_unreachable', False))
        
        # Count response types for control ports
        control_responses = sum(1 for r in control_results if r.get('got_response', False))
        control_timeouts = sum(1 for r in control_results if r['time'] > 0.25)  # Control ports use 0.3s timeout
        control_errors = sum(1 for r in control_results if r.get('got_icmp_unreachable', False))
        
        # Calculate average times
        avg_target_time = sum(r['time'] for r in target_results.values()) / len(target_results) if target_results else 0
        avg_control_time = sum(r['time'] for r in control_results) / len(control_results) if control_results else 0
        
        self.log(f"Target port 1194: {target_responses} responses, {target_timeouts} timeouts, {target_errors} ICMP unreachable", "ANALYSIS")
        self.log(f"Control ports: {control_responses} responses, {control_timeouts} timeouts, {control_errors} ICMP unreachable", "ANALYSIS")
        self.log(f"Average times - Target: {avg_target_time:.3f}s, Control: {avg_control_time:.3f}s", "ANALYSIS")
        
        # Pattern 1: Target port silent/timeout but control ports return ICMP unreachable
        # This is the classic nmap pattern - OpenVPN is open|filtered while others are closed
        if target_timeouts > 0 and control_errors >= len(control_results) * 0.75:
            return 0.9, "UDP port 1194 open|filtered while control ports closed (strong classic OpenVPN pattern)"
        
        # Pattern 2: Different response patterns
        if target_responses > 0 and control_responses == 0 and control_errors > 0:
            return 0.6, "UDP port 1194 responds while control ports are closed"
        
        # Pattern 3: All timeouts on target but mixed on control
        if target_timeouts == len(target_results) and control_errors > control_timeouts:
            return 0.5, "UDP port differentiation suggests filtered OpenVPN"
        
        # Pattern 4: Target port times out but control ports respond quickly (no timeout)
        # This indicates target port is filtered/open while control ports are truly closed
        if target_timeouts > 0 and control_timeouts == 0 and control_errors == 0:
            # Control ports responded quickly (not timing out) - likely closed/filtered differently
            if avg_control_time < 0.2:  # Very quick response indicates closed
                return 0.7, "UDP port 1194 filtered (timeout) while control ports closed (quick response)"
        
        # Pattern 5: Significant timing difference between target and control ports
        # Even without explicit ICMP, timing differences can indicate different handling
        if avg_target_time > 0 and avg_control_time > 0:
            time_ratio = avg_target_time / avg_control_time
            
            # Target port takes significantly longer (filtered/processing)
            if time_ratio > 5.0 and target_timeouts > 0:
                return 0.6, f"UDP port 1194 shows significant timing difference ({time_ratio:.1f}x slower)"
            
            # Control ports are consistently faster (closed) vs target (open/filtered)
            if time_ratio > 3.0 and avg_control_time < 0.6:
                return 0.5, f"UDP timing pattern suggests port 1194 filtered (control ports {time_ratio:.1f}x faster)"
        
        # Pattern 6: All timeouts but with different characteristics
        # If everything times out but target port shows longer/consistent timeouts
        if target_timeouts == len(target_results) and control_timeouts == len(control_results):
            # Check if target port has more consistent timeout behavior (OpenVPN dropping packets)
            target_times = [r['time'] for r in target_results.values()]
            control_times = [r['time'] for r in control_results]
            
            if target_times and control_times:
                import statistics
                target_stdev = statistics.stdev(target_times) if len(target_times) > 1 else 0
                control_stdev = statistics.stdev(control_times) if len(control_times) > 1 else 0
                
                # OpenVPN tends to have consistent timeout behavior
                if target_stdev < control_stdev * 0.5 and avg_target_time > 4.5:
                    return 0.4, "Consistent timeout pattern on port 1194 suggests filtered OpenVPN"
        
        return 0.0, ""
    
    def measure_udp_timing_control_port(self, host: str, port: int, probe_data: bytes) -> Dict:
        """Measure UDP timing on a control port, detecting ICMP unreachable responses."""
        start_time = time.time()
        got_response = False
        got_icmp_unreachable = False
        response_data = b''
        
        self.log(f"📡 Sending UDP control probe to {host}:{port}", "NETWORK")
        
        try:
            # Use raw socket to better detect ICMP if we have permissions
            try:
                # Try to create an ICMP socket to listen for ICMP messages
                import os
                if os.name != 'nt' and os.geteuid() == 0:  # Unix and root
                    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    icmp_sock.settimeout(0.3)
                else:
                    icmp_sock = None
            except:
                icmp_sock = None
            
            # Regular UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.3)  # Shorter timeout for control ports
            
            # Enable ICMP error reception if possible
            if hasattr(socket, 'IP_RECVERR'):
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVERR, 1)
                except:
                    pass
            
            # Send probe
            try:
                sock.sendto(probe_data, (host, port))
            except socket.error as e:
                # Immediate error might indicate port unreachable
                if e.errno in [111, 10061, 10054]:  # Connection refused
                    got_icmp_unreachable = True
                    self.log(f"🚫 Immediate ICMP unreachable from control port {port}", "SUCCESS")
            
            # Try to receive response
            try:
                response_data, addr = sock.recvfrom(1024)
                if response_data:
                    got_response = True
                    self.log(f"📥 Got response from control port {port}", "SUCCESS")
            except socket.timeout:
                # For control ports, a quick timeout (no hanging) suggests closed
                response_time = time.time() - start_time
                if response_time < 0.35:  # Very quick "timeout" suggests ICMP was received
                    got_icmp_unreachable = True
                    self.log(f"🚫 Quick timeout suggests ICMP unreachable from port {port}", "DEBUG")
            except socket.error as e:
                # ICMP port unreachable generates socket error
                if e.errno in [111, 10054, 10061, 113]:  # Connection refused / Port unreachable
                    got_icmp_unreachable = True
                    self.log(f"🚫 Socket error indicates ICMP unreachable from port {port}: {e}", "SUCCESS")
                else:
                    self.log(f"Socket error on control port {port}: {e}", "WARNING")
            
            # Check ICMP socket if available
            if icmp_sock and not got_icmp_unreachable:
                try:
                    icmp_data, icmp_addr = icmp_sock.recvfrom(1024)
                    # Parse ICMP packet (type 3 = destination unreachable, code 3 = port unreachable)
                    if len(icmp_data) > 1 and icmp_data[0] == 3:
                        got_icmp_unreachable = True
                        self.log(f"🚫 ICMP unreachable detected via raw socket from port {port}", "SUCCESS")
                except:
                    pass
                finally:
                    icmp_sock.close()
            
            sock.close()
            
        except Exception as e:
            self.log(f"❌ Control port {port} error: {e}", "ERROR")
        
        response_time = time.time() - start_time
        
        # Heuristic: If we got neither response nor explicit ICMP, but timing is consistent
        # with closed port behavior (very close to timeout), assume it's closed
        if not got_response and not got_icmp_unreachable and 0.28 < response_time < 0.32:
            got_icmp_unreachable = True  # Assume closed based on timing
            self.log(f"🚫 Timing pattern suggests closed port {port} (no explicit ICMP)", "DEBUG")
        
        return {
            'port': port,
            'time': response_time,
            'got_response': got_response,
            'got_icmp_unreachable': got_icmp_unreachable,
            'response_length': len(response_data) if response_data else 0
        }
    
    def match_behavioral_profile(self, behaviors: Dict[str, bool]) -> Tuple[str, float]:
        """Match observed behaviors to known OpenVPN profiles."""
        best_profile = None
        best_score = 0.0
        
        for profile in OPENVPN_PROFILES:
            score = profile.match_score(behaviors)
            self.log(f"Profile '{profile.name}' match score: {score:.2f}", "PROFILE")
            
            if score > best_score:
                best_profile = profile.name
                best_score = score
        
        if best_score > 0.6:
            self.log(f"Strong match with '{best_profile}' profile (score: {best_score:.2f})", "PROFILE")
            return best_profile, best_score * 0.5  # Convert to confidence boost
        
        return "", 0.0
    
    def create_openvpn_client_reset_tcp(self) -> bytes:
        """
        Create a standard OpenVPN Client Reset packet for TCP.
        Format: [length][opcode][session_id][packet_id][timestamp]
        """
        self.log("Creating TCP OpenVPN Client Reset packet", "DEBUG")
        
        # OpenVPN Client Reset packet structure
        opcode = 0x38  # P_CONTROL_HARD_RESET_CLIENT_V2
        session_id = b'\x00' * 8  # 8-byte session ID
        packet_id = b'\x00\x00\x00\x00'  # 4-byte packet ID
        timestamp = struct.pack('>I', int(time.time()))  # 4-byte timestamp
        
        # Complete packet: length + opcode + session_id + packet_id + timestamp
        packet_data = bytes([opcode]) + session_id + packet_id + timestamp
        packet_length = struct.pack('>H', len(packet_data))
        
        full_packet = packet_length + packet_data
        self.log(f"Created TCP packet: {len(full_packet)} bytes, opcode=0x{opcode:02x}", "DEBUG")
        
        return full_packet
    
    def create_openvpn_client_reset_udp(self) -> bytes:
        """
        Create a standard OpenVPN Client Reset packet for UDP.
        Format: [opcode][session_id][packet_id][timestamp]
        No length prefix needed for UDP.
        """
        self.log("Creating UDP OpenVPN Client Reset packet", "DEBUG")
        
        # OpenVPN Client Reset packet structure
        opcode = 0x38  # P_CONTROL_HARD_RESET_CLIENT_V2
        session_id = b'\x00' * 8  # 8-byte session ID
        packet_id = b'\x00\x00\x00\x00'  # 4-byte packet ID
        timestamp = struct.pack('>I', int(time.time()))  # 4-byte timestamp
        
        packet = bytes([opcode]) + session_id + packet_id + timestamp
        self.log(f"Created UDP packet: {len(packet)} bytes, opcode=0x{opcode:02x}", "DEBUG")
        
        return packet
    
    def create_tcp_base_probes(self) -> Dict[str, bytes]:
        """Create TCP-specific base probes."""
        self.log("Creating TCP base probe suite", "INFO")
        
        complete_packet = self.create_openvpn_client_reset_tcp()
        
        probes = {
            'base_probe_1': complete_packet,
            'base_probe_2': complete_packet[:-1],  # Missing last byte
            'invalid_length': b'\xFF\xFF' + complete_packet[2:],  # Invalid length
            'zero_length': b'\x00\x00' + complete_packet[2:]  # Zero length
        }
        
        self.log(f"Created {len(probes)} TCP base probes", "SUCCESS")
        return probes
    
    def create_udp_base_probes(self) -> Dict[str, bytes]:
        """Create UDP-specific base probes."""
        self.log("Creating UDP base probe suite", "INFO")
        
        client_reset = self.create_openvpn_client_reset_udp()
        
        probes = {
            'client_reset': client_reset,
            'invalid_opcode': b'\xFF' + client_reset[1:],  # Invalid opcode
            'short_packet': client_reset[:8],  # Truncated packet
            'oversized_packet': client_reset + b'\x00' * 100  # Oversized packet
        }
        
        self.log(f"Created {len(probes)} UDP base probes", "SUCCESS")
        return probes
    
    def create_udp_control_probes(self) -> Dict[str, Tuple[int, bytes]]:
        """Create UDP probes for random high ports to detect differential responses.
        Returns dict of probe_name: (port, data)"""
        self.log("Creating UDP control probes for port differentiation", "INFO")
        
        # Random high ports to test
        control_ports = [
            random.randint(30000, 40000),  # Random high port 1
            random.randint(40001, 50000),  # Random high port 2
            2349,  # Known commonly closed port
            9993,  # Another commonly closed port
        ]
        
        # Use same OpenVPN client reset packet on different ports
        client_reset = self.create_openvpn_client_reset_udp()
        
        control_probes = {}
        for i, port in enumerate(control_ports):
            control_probes[f'control_port_{i+1}'] = (port, client_reset)
            
        self.log(f"Created {len(control_probes)} control probes on ports: {control_ports}", "SUCCESS")
        return control_probes
    
    def create_additional_probes(self) -> Dict[str, bytes]:
        """
        Create additional probes for more comprehensive fingerprinting.
        """
        self.log("Creating additional protocol probes", "INFO")
        
        probes = {
            'generic': b'\x0d\x0a\x0d\x0a',
            'one_zero': b'\x00',
            'two_zero': b'\x00\x00',
            'epmd': b'\x00\x01\x6e',
            'ssh': b'SSH-2.0-OpenSSH-8.1\r\n',
            'http_get': b'GET / HTTP/1.0\r\n\r\n',
            'tls_hello': self.create_tls_client_hello(),
            'random_2k': self.create_random_payload(2000),
            'random_small': self.create_random_payload(16)
        }
        
        self.log(f"Created {len(probes)} additional probes", "SUCCESS")
        return probes
    
    def create_tls_client_hello(self) -> bytes:
        """Create a basic TLS Client Hello packet."""
        self.log("Creating TLS Client Hello probe", "DEBUG")
        
        # Simplified TLS Client Hello
        return (b'\x16\x03\x01\x00\x2a\x01\x00\x00\x26\x03\x03' +
                b'\x00' * 32 +  # Random
                b'\x00\x00\x02\x00\x35\x01\x00')
    
    def create_random_payload(self, size: int) -> bytes:
        """Create random payload of specified size."""
        self.log(f"Creating random payload: {size} bytes", "DEBUG")
        return bytes([random.randint(0, 255) for _ in range(size)])
    
    def measure_tcp_timing_with_retry(self, host: str, port: int, probe_data: bytes, max_retries: int = 2) -> Tuple[float, bool, bool, bytes]:
        """TCP probe with retry logic for network failures."""
        for attempt in range(max_retries + 1):
            self.log(f"TCP probe attempt {attempt + 1}/{max_retries + 1}", "NETWORK")
            
            result = self.measure_tcp_timing(host, port, probe_data)
            if result[0] != -1:  # Success or valid failure
                return result
            
            if attempt < max_retries:
                retry_delay = 0.5 * (attempt + 1)  # Exponential backoff
                self.log(f"Retrying after {retry_delay}s delay", "NETWORK")
                time.sleep(retry_delay)
        
        return result
    
    def measure_tcp_timing(self, host: str, port: int, probe_data: bytes) -> Tuple[float, bool, bool, bytes]:
        """
        Send TCP probe and measure response timing.
        Returns: (response_time, got_response, got_rst, response_data)
        """
        start_time = time.time()
        got_response = False
        got_rst = False
        response_data = b''
        
        self.log(f"Connecting to {host}:{port} via TCP", "NETWORK")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Connect to target
            connect_start = time.time()
            sock.connect((host, port))
            connect_time = time.time() - connect_start
            
            self.log(f"TCP connection established in {connect_time:.3f}s", "SUCCESS")
            self.log_packet("SEND", probe_data, "TCP")
            
            # Send probe
            sock.send(probe_data)
            
            # Try to receive response
            recv_start = time.time()
            try:
                response_data = sock.recv(1024)
                recv_time = time.time() - recv_start
                
                if response_data:
                    got_response = True
                    self.log(f"Received TCP response in {recv_time:.3f}s", "SUCCESS")
                    self.log_packet("RECV", response_data, "TCP")
                else:
                    self.log("Empty TCP response received", "WARNING")
                    
            except socket.timeout:
                self.log(f"TCP socket timeout after {self.timeout}s", "WARNING")
            except ConnectionResetError:
                got_rst = True
                self.log("TCP connection reset by peer", "WARNING")
            
            sock.close()
            self.log("TCP connection closed", "DEBUG")
            
        except ConnectionRefusedError:
            self.log(f"TCP connection refused to {host}:{port}", "ERROR")
            return -2, False, False, b''
        except socket.timeout:
            self.log(f"TCP connection timeout to {host}:{port}", "ERROR")
            return -1, False, False, b''
        except Exception as e:
            self.log(f"TCP connection error: {e}", "ERROR")
            return -1, False, False, b''
        
        response_time = time.time() - start_time
        self.log(f"Total TCP operation time: {response_time:.3f}s", "TIMING")
        
        return response_time, got_response, got_rst, response_data
    
    def measure_udp_timing_with_retry(self, host: str, port: int, probe_data: bytes, max_retries: int = 2) -> Tuple[float, bool, bool, bytes]:
        """UDP probe with retry logic for potential packet loss."""
        for attempt in range(max_retries + 1):
            self.log(f"UDP probe attempt {attempt + 1}/{max_retries + 1}", "NETWORK")
            
            result = self.measure_udp_timing(host, port, probe_data)
            # Unpack new result tuple
            probe_time, got_response, got_icmp_unreachable, response_data = result

            if got_response or got_icmp_unreachable:  # Success or definitive failure
                return result
            
            if attempt < max_retries:
                retry_delay = 0.3 * (attempt + 1)
                self.log(f"No UDP response, retrying after {retry_delay}s", "NETWORK")
                time.sleep(retry_delay)
        
        return result
    
    def measure_udp_timing(self, host: str, port: int, probe_data: bytes) -> Tuple[float, bool, bool, bytes]:
        """
        Send UDP probe and measure response timing, detecting ICMP unreachable.
        Returns: (response_time, got_response, got_icmp_unreachable, response_data)
        """
        start_time = time.time()
        got_response = False
        got_icmp_unreachable = False
        response_data = b''
        
        self.log(f"📡 Sending UDP probe to {host}:{port}", "NETWORK")
        
        try:
            # Use raw socket to better detect ICMP if we have permissions
            try:
                import os
                if os.name != 'nt' and os.geteuid() == 0:  # Unix and root
                    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    icmp_sock.settimeout(self.timeout)
                else:
                    icmp_sock = None
            except:
                icmp_sock = None

            # Regular UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # Enable ICMP error reception if possible
            if hasattr(socket, 'IP_RECVERR'):
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVERR, 1)
                except:
                    pass
            
            self.log_packet("SEND", probe_data, "UDP")
            
            # Send probe
            try:
                sock.sendto(probe_data, (host, port))
            except socket.error as e:
                if e.errno in [111, 10061, 10054, 113]:  # Connection refused / Port unreachable
                    got_icmp_unreachable = True
                    self.log(f"🚫 Immediate ICMP unreachable from {host}:{port}", "SUCCESS")

            # Try to receive response
            try:
                response_data, addr = sock.recvfrom(1024)
                if response_data:
                    got_response = True
                    self.log(f"📥 Received UDP response from {addr}", "SUCCESS")
                    self.log_packet("RECV", response_data, "UDP")
            except socket.timeout:
                self.log(f"⏰ UDP socket timeout after {self.timeout}s for {host}:{port}", "WARNING")
            except socket.error as e:
                # ICMP port unreachable generates socket error
                if e.errno in [111, 10054, 10061, 113]:  # Connection refused / Port unreachable
                    got_icmp_unreachable = True
                    self.log(f"🚫 Socket error indicates ICMP unreachable from {host}:{port}: {e}", "SUCCESS")
                else:
                    self.log(f"Socket error on {host}:{port}: {e}", "WARNING")

            # Check ICMP socket if available
            if icmp_sock and not got_icmp_unreachable and not got_response:
                try:
                    icmp_data, icmp_addr = icmp_sock.recvfrom(1024)
                    # Parse ICMP packet (type 3 = destination unreachable)
                    if len(icmp_data) > 1 and icmp_data[0] == 3:
                        got_icmp_unreachable = True
                        self.log(f"🚫 ICMP unreachable detected via raw socket from {host}:{port}", "SUCCESS")
                except:
                    pass
                finally:
                    icmp_sock.close()

            sock.close()
            
        except Exception as e:
            self.log(f"❌ UDP error: {e}", "ERROR")
            return -1, False, False, b''
        
        response_time = time.time() - start_time
        
        # Heuristic removed: A full timeout is not necessarily a closed port.
        # OpenVPN with tls-auth will silently drop packets, causing a timeout.
        # The differential analysis is responsible for distinguishing this.
        
        self.log(f"⏱️  Total UDP operation time: {response_time:.3f}s", "TIMING")
        
        return response_time, got_response, got_icmp_unreachable, response_data
    
    def analyze_openvpn_response(self, response_data: bytes, protocol: str) -> List[Tuple[str, float]]:
        """
        Analyze response data for OpenVPN characteristics.
        Returns list of (evidence, weight) tuples.
        """
        evidence = []
        
        if not response_data:
            return evidence
        
        self.log(f"🧪 Analyzing {protocol.upper()} response: {len(response_data)} bytes", "ANALYSIS")

        opcode_offset = 2 if protocol == 'tcp' else 0
        
        # Check for OpenVPN Server Reset
        if len(response_data) >= opcode_offset:
            opcode = response_data[opcode_offset]
            
            opcode_mapping = {
                0x48: (EvidenceType.OPENVPN_SERVER_RESET_V2, "🎯 Classic OpenVPN Server Reset!"),
                0x28: (EvidenceType.OPENVPN_SERVER_RESET_V1, "🎯 OpenVPN Server Reset (v1)!"),
                0x40: (EvidenceType.OPENVPN_CONTROL_V1, "🔐 OpenVPN Control Packet"),
                0x50: (EvidenceType.OPENVPN_ACK, "✅ OpenVPN ACK Packet"),
                0x60: (EvidenceType.OPENVPN_DATA, "📊 OpenVPN Data Packet")
            }
            
            if opcode in opcode_mapping:
                evidence_type, desc = opcode_mapping[opcode]
                evidence_text = f"OpenVPN {evidence_type.value[0]} detected (opcode: 0x{opcode:02x})"
                evidence.append((evidence_text, evidence_type.value[1]))
                self.log(f"{desc} - Opcode: 0x{opcode:02x}", "SUCCESS")
            else:
                self.log(f"🔍 Unknown opcode: 0x{opcode:02x}", "DEBUG")
        
        # Check packet structure
        if protocol == 'tcp' and len(response_data) >= 2:
            # TCP packets have length prefix
            declared_length = struct.unpack('>H', response_data[:2])[0]
            actual_length = len(response_data) - 2
            
            self.log(f"📏 TCP packet length analysis: declared={declared_length}, actual={actual_length}", "ANALYSIS")
            
            if declared_length == actual_length:
                evidence.append((EvidenceType.VALID_TCP_STRUCTURE.value[0], EvidenceType.VALID_TCP_STRUCTURE.value[1]))
                self.log("✅ Valid TCP packet length structure", "SUCCESS")
            elif abs(declared_length - actual_length) <= 2:
                evidence.append((EvidenceType.NEAR_VALID_TCP_STRUCTURE.value[0], EvidenceType.NEAR_VALID_TCP_STRUCTURE.value[1]))
                self.log("⚠️  Near-valid TCP packet length structure", "WARNING")
        
        # Check for session ID pattern
        session_id_offset = 1 if protocol == 'udp' else 3
        if len(response_data) >= session_id_offset + 8:
            session_id = response_data[session_id_offset:session_id_offset + 8]
            
            self.log(f"🆔 Session ID: {session_id.hex()}", "ANALYSIS")
            
            if session_id != b'\x00' * 8:
                evidence.append((EvidenceType.NON_ZERO_SESSION_ID.value[0], EvidenceType.NON_ZERO_SESSION_ID.value[1]))
                self.log("🔄 Active session detected (non-zero session ID)", "SUCCESS")
        
        # Check for timestamp field
        timestamp_offset = session_id_offset + 8 + 4  # session_id + packet_id
        if len(response_data) >= timestamp_offset + 4:
            timestamp = struct.unpack('>I', response_data[timestamp_offset:timestamp_offset + 4])[0]
            current_time = int(time.time())
            time_diff = abs(timestamp - current_time)
            
            self.log(f"⏰ Timestamp analysis: packet={timestamp}, current={current_time}, diff={time_diff}s", "ANALYSIS")
            
            if time_diff < 3600:  # Within 1 hour
                evidence_text = f"Recent timestamp suggests active OpenVPN server (diff: {time_diff}s)"
                evidence.append((evidence_text, EvidenceType.RECENT_TIMESTAMP.value[1]))
                self.log(f"🕐 Recent timestamp detected (within {time_diff}s)", "SUCCESS")
        
        return evidence
    
    def execute_probes_randomized(self, probes: Dict[str, bytes], host: str, port: int, protocol: str) -> Dict:
        """Execute probes in random order to avoid detection patterns."""
        probe_items = list(probes.items())
        random.shuffle(probe_items)
        
        results = {}
        
        for probe_name, probe_data in probe_items:
            # Add small random delay between probes
            if probe_name != probe_items[0][0]:  # Not first probe
                delay = random.uniform(0.1, 0.3)
                time.sleep(delay)
                self.log(f"Random delay: {delay:.3f}s", "TIMING")
            
            if protocol == 'tcp':
                probe_time, got_response, got_rst, response_data = self.measure_tcp_timing_with_retry(
                    host, port, probe_data
                )
                results[probe_name] = {
                    'time': probe_time,
                    'got_response': got_response,
                    'got_rst': got_rst,
                    'response_length': len(response_data),
                    'response_data': response_data
                }
            else:  # UDP
                probe_time, got_response, got_icmp_unreachable, response_data = self.measure_udp_timing_with_retry(
                    host, port, probe_data
                )
                results[probe_name] = {
                    'time': probe_time,
                    'got_response': got_response,
                    'got_icmp_unreachable': got_icmp_unreachable,
                    'response_length': len(response_data) if response_data else 0,
                    'response_data': response_data
                }
        
        return results
    
    def analyze_tcp_openvpn(self, host: str, port: int) -> Dict:
        """
        Perform TCP-specific OpenVPN fingerprinting analysis with enhancements.
        """
        self.log(f"🚀 Starting enhanced TCP OpenVPN fingerprinting for {host}:{port}", "INFO")
        
        # Calculate adaptive timeout
        adaptive_timeout = self.calculate_adaptive_timeout(host, port)
        original_timeout = self.timeout
        self.timeout = adaptive_timeout
        
        results = {
            'protocol': 'tcp',
            'host': host,
            'port': port,
            'is_openvpn': False,
            'confidence': 0.0,
            'evidence': [],
            'probe_results': {},
            'behavioral_profile': {},
            'adaptive_timeout': adaptive_timeout,
            'tcp_refused': False
        }
        
        # Collect weighted evidence
        weighted_evidence = []
        behavioral_traits = {}
        
        # Test TCP base probes
        tcp_probes = self.create_tcp_base_probes()
        base_results = self.execute_probes_randomized(tcp_probes, host, port, 'tcp')
        results['probe_results'].update(base_results)
        
        # Check if we got ANY actual responses (not just RSTs)
        got_any_response = any(r.get('got_response', False) and r.get('response_length', 0) > 0 
                              for r in base_results.values())
        
        # Analyze each probe result
        for probe_name, probe_result in base_results.items():
            if probe_result['time'] < 0:
                if probe_result['time'] == -2:
                    results['tcp_refused'] = True
                if probe_name == 'base_probe_1':  # If first probe fails, host is unreachable
                    if probe_result['time'] == -2:
                        results['evidence'].append("Host actively refused connection")
                        self.log("🚫 Host actively refused connection, aborting TCP analysis", "ERROR")
                    else:
                        results['evidence'].append("Host unreachable or port closed")
                        self.log("🚫 Host unreachable, aborting TCP analysis", "ERROR")
                    self.timeout = original_timeout
                    return results
                continue
            
            # Analyze response
            response_evidence = self.analyze_openvpn_response(
                probe_result.get('response_data', b''), 'tcp'
            )
            for evidence_text, weight in response_evidence:
                results['evidence'].append(evidence_text)
                weighted_evidence.append((evidence_text, weight))
            
            # Check for RST behavior
            if probe_result.get('got_rst', False):
                if probe_name == 'invalid_length':
                    behavioral_traits['tcp_rst_on_invalid'] = True
        
        # Analyze timing patterns
        if 'base_probe_1' in base_results and 'base_probe_2' in base_results:
            probe1_time = base_results['base_probe_1']['time']
            probe2_time = base_results['base_probe_2']['time']
            
            if probe1_time > 0 and probe2_time > 0:
                time_diff = abs(probe2_time - probe1_time)
                self.log(f"⏱️  TCP timing analysis: probe1={probe1_time:.3f}s, probe2={probe2_time:.3f}s, diff={time_diff:.3f}s", "TIMING")
                
                # OpenVPN characteristic: Probe2 should take longer (waiting for more data)
                if probe2_time > probe1_time and time_diff > 0.5:
                    evidence_msg = f"TCP timing differential suggests OpenVPN (Δ={time_diff:.3f}s)"
                    results['evidence'].append(evidence_msg)
                    weighted_evidence.append((evidence_msg, EvidenceType.TCP_TIMING_DIFFERENTIAL.value[1]))
                    behavioral_traits['tcp_timing_differential'] = True
                    self.log(f"🎯 {evidence_msg}", "SUCCESS")
        
        # Test additional probes
        additional_probes = self.create_additional_probes()
        additional_results = self.execute_probes_randomized(additional_probes, host, port, 'tcp')
        
        # Count RSTs across all probes
        total_rst_count = 0
        
        for probe_name, probe_result in additional_results.items():
            results['probe_results'][f'additional_{probe_name}'] = probe_result
            
            if probe_result['time'] > 0:
                if probe_result.get('got_rst', False):
                    total_rst_count += 1
                    
                # Check for RST behavior on large random payload
                if probe_name == 'random_2k' and probe_result.get('got_rst', False):
                    behavioral_traits['tcp_rst_on_large'] = True
                    
                    # Only consider RST evidence if we also got actual responses
                    # or if there's other supporting evidence
                    if got_any_response or len(weighted_evidence) > 0:
                        evidence_msg = EvidenceType.RST_ON_2K_PAYLOAD.value[0]
                        results['evidence'].append(evidence_msg)
                        weighted_evidence.append((evidence_msg, EvidenceType.RST_ON_2K_PAYLOAD.value[1]))
                        self.log(f"🎯 {evidence_msg}", "SUCCESS")
                    else:
                        # RST without any actual OpenVPN responses is likely just a closed port
                        self.log("RST on 2K payload detected but no OpenVPN responses - likely closed port", "WARNING")
        
        # If ALL probes got RST and NO actual responses, this is likely a closed port
        total_probes = len(base_results) + len(additional_results)
        if total_rst_count == total_probes and not got_any_response:
            self.log("All probes received RST with no OpenVPN responses - port is closed", "WARNING")
            # Clear any RST-based evidence
            weighted_evidence = [(ev, w) for ev, w in weighted_evidence 
                               if "RST" not in ev]
            results['evidence'] = [ev for ev in results['evidence'] 
                                 if "RST" not in ev]
        
        # Analyze timeout patterns
        timeout_boost, timeout_evidence = self.analyze_timeout_patterns(results['probe_results'])
        if timeout_boost > 0:
            results['evidence'].append(timeout_evidence)
            weighted_evidence.append((timeout_evidence, timeout_boost))
            behavioral_traits['timeout_selective'] = True
        
        # Match behavioral profile
        profile_name, profile_boost = self.match_behavioral_profile(behavioral_traits)
        if profile_boost > 0 and got_any_response:  # Only assign profile if we got actual responses
            profile_evidence = f"Behavioral profile matches OpenVPN '{profile_name}' configuration"
            results['evidence'].append(profile_evidence)
            weighted_evidence.append((profile_evidence, profile_boost))
            results['behavioral_profile'] = {'name': profile_name, 'confidence': profile_boost}
        
        # Calculate final confidence using Bayesian method
        results['confidence'] = self.calculate_bayesian_confidence(weighted_evidence)
        
        # Determine if OpenVPN based on threshold
        threshold = self.get_detection_threshold('tcp')
        results['is_openvpn'] = results['confidence'] >= threshold
        
        self.log(f"🏁 TCP analysis complete. Final confidence: {results['confidence']:.3f} (threshold: {threshold})", "INFO")
        
        # Restore original timeout
        self.timeout = original_timeout
        
        return results
    
    def analyze_udp_openvpn(self, host: str, port: int, tcp_was_refused: bool = False) -> Dict:
        """
        Perform UDP-specific OpenVPN fingerprinting analysis with enhancements.
        Now includes control port testing for differential analysis.
        """
        self.log(f"🚀 Starting enhanced UDP OpenVPN fingerprinting for {host}:{port}", "INFO")
        
        results = {
            'protocol': 'udp',
            'host': host,
            'port': port,
            'is_openvpn': False,
            'confidence': 0.0,
            'evidence': [],
            'probe_results': {},
            'control_port_results': [],
            'behavioral_profile': {},
            'detection_note': None,  # Add this field to track special detection cases
            'tls_crypt_likely': False  # Track if tls-crypt/tls-auth is likely enabled
        }
        
        # Collect weighted evidence
        weighted_evidence = []
        behavioral_traits = {}
        
        # Test UDP base probes on target port
        udp_probes = self.create_udp_base_probes()
        base_results = self.execute_probes_randomized(udp_probes, host, port, 'udp')
        results['probe_results'].update(base_results)
        
        # If the initial client_reset probe indicates ICMP unreachable, the port is closed.
        if base_results.get('client_reset', {}).get('got_icmp_unreachable', False):
            self.log(f"🚫 Port {port} is closed (initial client_reset probe received ICMP Port Unreachable). Aborting UDP analysis.", "SUCCESS")
            results['detection_note'] = "Port is closed (ICMP Port Unreachable)"
            results['is_openvpn'] = False
            results['confidence'] = 0.0
            results['evidence'].append(results['detection_note'])
            return results
        
        # Test control ports for differential analysis
        control_probes = self.create_udp_control_probes()
        control_results = []
        
        for probe_name, (control_port, probe_data) in control_probes.items():
            control_result = self.measure_udp_timing_control_port(host, control_port, probe_data)
            control_results.append(control_result)
            self.log(f"Control port {control_port}: ICMP={control_result.get('got_icmp_unreachable', False)}, "
                    f"Response={control_result.get('got_response', False)}, Time={control_result['time']:.3f}s", "DEBUG")
        
        results['control_port_results'] = control_results
        
        # Log detailed control port timing for analysis
        if control_results:
            avg_control_time = sum(r['time'] for r in control_results) / len(control_results)
            self.log(f"Average control port response time: {avg_control_time:.3f}s", "ANALYSIS")
        
        # Analyze port differentiation patterns
        diff_boost, diff_evidence = self.analyze_udp_port_differentiation(base_results, control_results)
        if diff_boost > 0:
            results['evidence'].append(diff_evidence)
            weighted_evidence.append((diff_evidence, diff_boost))
            behavioral_traits['udp_port_differentiation'] = True
            self.log(f"🎯 {diff_evidence}", "SUCCESS")
        
        # Analyze each probe result
        for probe_name, probe_result in base_results.items():
            # Analyze response
            if probe_result.get('got_response', False):
                response_evidence = self.analyze_openvpn_response(
                    probe_result.get('response_data', b''), 'udp'
                )
                for evidence_text, weight in response_evidence:
                    results['evidence'].append(evidence_text)
                    weighted_evidence.append((evidence_text, weight))
        
        # Test additional UDP probes (limited set)
        additional_probes = self.create_additional_probes()
        limited_additional = {k: v for k, v in list(additional_probes.items())[:5]}
        additional_results = self.execute_probes_randomized(limited_additional, host, port, 'udp')
        
        for probe_name, probe_result in additional_results.items():
            results['probe_results'][f'additional_{probe_name}'] = probe_result
        
        # UDP-specific analysis
        if base_results.get('client_reset', {}).get('got_response', False):
            evidence_msg = EvidenceType.UDP_CLIENT_RESET_RESPONSE.value[0]
            results['evidence'].append(evidence_msg)
            weighted_evidence.append((evidence_msg, EvidenceType.UDP_CLIENT_RESET_RESPONSE.value[1]))
            behavioral_traits['udp_responds_to_reset'] = True
            self.log(f"🎯 {evidence_msg}", "SUCCESS")
        
        # Analyze UDP response patterns
        pattern_boost, pattern_evidence = self.analyze_udp_response_pattern(results['probe_results'])
        if pattern_boost > 0:
            results['evidence'].append(pattern_evidence)
            weighted_evidence.append((pattern_evidence, pattern_boost))
            behavioral_traits['udp_selective_response'] = True
        
        # Check response patterns
        response_count = sum(1 for r in results['probe_results'].values() if r.get('got_response', False))
        total_probes = len(results['probe_results'])
        
        self.log(f"📊 UDP response pattern: {response_count}/{total_probes} probes got responses", "ANALYSIS")
        
        # Analyze timeout patterns
        timeout_boost, timeout_evidence = self.analyze_timeout_patterns(results['probe_results'])
        if timeout_boost > 0:
            results['evidence'].append(timeout_evidence)
            weighted_evidence.append((timeout_evidence, timeout_boost))
            behavioral_traits['timeout_selective'] = True
        
        # Match behavioral profile
        profile_name, profile_boost = self.match_behavioral_profile(behavioral_traits)
        if profile_boost > 0:
            profile_evidence = f"Behavioral profile matches OpenVPN '{profile_name}' configuration"
            results['evidence'].append(profile_evidence)
            weighted_evidence.append((profile_evidence, profile_boost))
            results['behavioral_profile'] = {'name': profile_name, 'confidence': profile_boost}
        
        # Calculate final confidence using Bayesian method
        results['confidence'] = self.calculate_bayesian_confidence(weighted_evidence)

        # If TCP was refused, it's highly unlikely UDP is OpenVPN, so penalize score
        if tcp_was_refused:
            self.log("TCP connection was refused, penalizing UDP confidence", "WARNING")
            results['confidence'] *= 0.1  # Reduce confidence by 90%

        # Check if this looks like a tls-crypt/tls-auth protected server
        # (port differentiation but no actual OpenVPN responses)
        got_any_openvpn_response = any(
            ev[0] for ev in weighted_evidence 
            if 'OpenVPN' in ev[0] and any(keyword in ev[0] for keyword in ['detected', 'Reset', 'Control', 'ACK', 'Data'])
        )

        # Check for the classic port differentiation pattern, which is a strong indicator
        # but should not override the final confidence score.
        if diff_boost >= 0.7 and len(weighted_evidence) > 0:
            results['detection_note'] = "Detected classic port differentiation pattern"
            # If we got port differentiation but no OpenVPN protocol responses,
            # this suggests tls-crypt/tls-auth is enabled
            if not got_any_openvpn_response:
                results['tls_crypt_likely'] = True
                results['detection_note'] += " (likely tls-crypt/tls-auth enabled)"

        # Final detection logic
        threshold = self.get_detection_threshold('udp')
        results['is_openvpn'] = results['confidence'] >= threshold
        results['detection_status'] = 'NOT_DETECTED'

        if results['is_openvpn']:
            if got_any_openvpn_response:
                results['detection_status'] = 'DETECTED_CONFIRMED'
            else:
                results['detection_status'] = 'DETECTED_CIRCUMSTANTIAL'
                results['detection_note'] = "Ambiguous result: Port behavior is consistent with OpenVPN, but could also be a firewall."

        # If not detected, clear any special detection notes to avoid confusion
        if not results['is_openvpn']:
            if 'detection_note' in results:
                del results['detection_note']
            if 'tls_crypt_likely' in results:
                results['tls_crypt_likely'] = False

        # Log final results
        log_message = f"🏁 UDP analysis complete. Final confidence: {results['confidence']:.3f}"
        if results.get('detection_note'):
            log_message += f" - {results['detection_note']}"
        else:
            log_message += f" (threshold: {threshold})"
        self.log(log_message, "INFO")

        return results

    
    def scan_host_both_protocols(self, host: str, port: int = 1194) -> Dict:
        """
        Scan a host using both TCP and UDP protocols.
        """
        self.log(f"🎯 Starting comprehensive scan of {host}:{port} (TCP + UDP)", "INFO")
        
        # Test TCP
        tcp_results = self.analyze_tcp_openvpn(host, port)
        
        # Test UDP, passing TCP refusal info
        udp_results = self.analyze_udp_openvpn(host, port, tcp_was_refused=tcp_results.get('tcp_refused', False))
        
        # Get thresholds
        tcp_threshold = self.get_detection_threshold('tcp')
        udp_threshold = self.get_detection_threshold('udp')
        
        # Combine results - FIX: Use the actual is_openvpn field from results
        combined_results = {
            'host': host,
            'port': port,
            'tcp': tcp_results,
            'udp': udp_results,
            'overall_assessment': {
                'tcp_openvpn': tcp_results['is_openvpn'],  # Use the actual detection result
                'udp_openvpn': udp_results['is_openvpn'],  # Use the actual detection result
                'any_openvpn': tcp_results['is_openvpn'] or udp_results['is_openvpn'],
                'combined_confidence': max(tcp_results['confidence'], udp_results['confidence'])
            }
        }
        
        self.log(f"🏆 Scan complete for {host}:{port}", "SUCCESS")
        
        return combined_results
    
    def scan_host_single_protocol(self, host: str, port: int, protocol: str) -> Dict:
        """
        Scan a host using a specific protocol.
        """
        if protocol.lower() == 'tcp':
            return self.analyze_tcp_openvpn(host, port)
        elif protocol.lower() == 'udp':
            # When scanning UDP only, we don't have TCP info, so default to False
            return self.analyze_udp_openvpn(host, port, tcp_was_refused=False)
        else:
            raise ValueError("Protocol must be 'tcp' or 'udp'")
    
    def scan_multiple_hosts(self, hosts: List[str], port: int = 1194, protocol: str = 'both', max_workers: int = 10) -> List[Dict]:
        """
        Scan multiple hosts concurrently.
        """
        results = []
        
        self.log(f"🚀 Starting scan of {len(hosts)} hosts with {max_workers} workers", "INFO")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            if protocol.lower() == 'both':
                future_to_host = {
                    executor.submit(self.scan_host_both_protocols, host, port): host 
                    for host in hosts
                }
            else:
                future_to_host = {
                    executor.submit(self.scan_host_single_protocol, host, port, protocol): host 
                    for host in hosts
                }
            
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if protocol.lower() == 'both':
                        self.print_combined_result(result)
                    else:
                        self.print_single_result(result)
                        
                except Exception as e:
                    if not self.json_output:
                        print(f"{Fore.RED}[!] ❌ Error scanning {host}: {e}{Style.RESET_ALL}")
        
        self.log(f"✅ Completed scan of all {len(hosts)} hosts", "SUCCESS")
        return results
    
    def print_combined_result(self, result: Dict):
        """Print results for both protocol scan with emojis and colors."""
        if self.json_output:
            return  # Skip console output in JSON mode
            
        host = result['host']
        port = result['port']
        tcp_detected = result['overall_assessment']['tcp_openvpn']
        udp_detected = result['overall_assessment']['udp_openvpn']
        
        # Get detection statuses
        tcp_status = result.get('tcp', {}).get('detection_status', 'NOT_DETECTED')
        udp_status = result.get('udp', {}).get('detection_status', 'NOT_DETECTED')

        if tcp_detected or udp_detected:
            protocols = []
            if tcp_detected:
                if tcp_status == 'DETECTED_CONFIRMED':
                    protocols.append(f"{Fore.GREEN}TCP (Confirmed){Style.RESET_ALL}(conf:{result['tcp']['confidence']:.3f})")
                else: # DETECTED_CIRCUMSTANTIAL
                    protocols.append(f"{Fore.YELLOW}TCP (Circumstantial){Style.RESET_ALL}(conf:{result['tcp']['confidence']:.3f})")

            if udp_detected:
                if udp_status == 'DETECTED_CONFIRMED':
                    protocols.append(f"{Fore.BLUE}UDP (Confirmed){Style.RESET_ALL}(conf:{result['udp']['confidence']:.3f})")
                else: # DETECTED_CIRCUMSTANTIAL
                    protocols.append(f"{Fore.YELLOW}UDP (Ambiguous){Style.RESET_ALL}(conf:{result['udp']['confidence']:.3f})")

            detection_level = Fore.GREEN if 'Confirmed' in ''.join(protocols) else Fore.YELLOW
            detection_text = "DETECTED" if 'Confirmed' in ''.join(protocols) else "AMBIGUOUS"
            
            print(f"{detection_level}[+] 🎯 {detection_text}: {Style.BRIGHT}{host}:{port}{Style.RESET_ALL} - {', '.join(protocols)}")
            
            if tcp_detected:
                print(f"    {Fore.CYAN}🔌 TCP Evidence:{Style.RESET_ALL}")
                for evidence in result['tcp']['evidence'][:3]:  # Show top 3
                    print(f"      {Fore.GREEN}└─ ✅ {evidence}{Style.RESET_ALL}")
                if result['tcp'].get('behavioral_profile', {}).get('name'):
                    print(f"      {Fore.MAGENTA}└─ 👤 Profile: {result['tcp']['behavioral_profile']['name']}{Style.RESET_ALL}")
            
            if udp_detected:
                print(f"    {Fore.MAGENTA}📡 UDP Evidence:{Style.RESET_ALL}")
                for evidence in result['udp']['evidence'][:3]:  # Show top 3
                    print(f"      {Fore.GREEN}└─ ✅ {evidence}{Style.RESET_ALL}")
                if result['udp'].get('detection_note'):
                    print(f"      {Fore.YELLOW}└─ ⚠️  {result['udp']['detection_note']}{Style.RESET_ALL}")
                if result['udp'].get('behavioral_profile', {}).get('name'):
                    print(f"      {Fore.MAGENTA}└─ 👤 Profile: {result['udp']['behavioral_profile']['name']}{Style.RESET_ALL}")
        else:
            tcp_conf = result['tcp']['confidence']
            udp_conf = result['udp']['confidence']
            print(f"{Fore.YELLOW}[-] ❌ Not OpenVPN: {host}:{port} {Style.DIM}(TCP: {tcp_conf:.3f}, UDP: {udp_conf:.3f}){Style.RESET_ALL}")
    
    def print_single_result(self, result: Dict):
        """Print results for single protocol scan with emojis and colors."""
        if self.json_output:
            return  # Skip console output in JSON mode
            
        host = result['host']
        port = result['port']
        protocol = result['protocol'].upper()
        protocol_emoji = "🔌" if protocol == "TCP" else "📡"
        status = result.get('detection_status', 'NOT_DETECTED')

        if result['is_openvpn']:
            if status == 'DETECTED_CONFIRMED':
                print(f"{Fore.GREEN}[+] 🎯 DETECTED: {Style.BRIGHT}{host}:{port}/{protocol}{Style.RESET_ALL} - Confidence: {Fore.GREEN}{result['confidence']:.3f}{Style.RESET_ALL}")
            else: # DETECTED_CIRCUMSTANTIAL
                print(f"{Fore.YELLOW}[+] 🎯 AMBIGUOUS: {Style.BRIGHT}{host}:{port}/{protocol}{Style.RESET_ALL} - Confidence: {Fore.YELLOW}{result['confidence']:.3f}{Style.RESET_ALL}")

            print(f"    {Fore.CYAN}{protocol_emoji} {protocol} Evidence:{Style.RESET_ALL}")
            for evidence in result['evidence'][:3]:  # Show top 3
                print(f"      {Fore.GREEN}└─ ✅ {evidence}{Style.RESET_ALL}")
            if result.get('detection_note'):
                print(f"      {Fore.YELLOW}└─ ⚠️  {result['detection_note']}{Style.RESET_ALL}")
            if result.get('behavioral_profile', {}).get('name'):
                print(f"      {Fore.MAGENTA}└─ 👤 Profile: {result['behavioral_profile']['name']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[-] ❌ Not OpenVPN: {host}:{port}/{protocol} {Style.DIM}- Confidence: {result['confidence']:.3f}{Style.RESET_ALL}")

    def print_detailed_probe_results(self, results: List[Dict], protocol: str = 'both'):
        """Print detailed probe results in super verbose mode."""
        if self.json_output or not self.super_verbose:
            return
            
        print(f"\n{Fore.CYAN}{Style.BRIGHT}📊 DETAILED PROBE RESULTS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        
        for result in results:
            host = result['host'] if 'host' in result else result['tcp']['host']
            port = result['port'] if 'port' in result else result['tcp']['port']
            
            print(f"\n{Fore.YELLOW}🎯 Target: {Style.BRIGHT}{host}:{port}{Style.RESET_ALL}")
            
            protocols_to_show = []
            if protocol == 'both':
                protocols_to_show = [('tcp', result['tcp']), ('udp', result['udp'])]
            else:
                protocols_to_show = [(protocol, result)]
            
            for proto_name, proto_result in protocols_to_show:
                if 'probe_results' not in proto_result:
                    continue
                    
                proto_emoji = "🔌" if proto_name.upper() == "TCP" else "📡"
                print(f"\n  {Fore.MAGENTA}{proto_emoji} {proto_name.upper()} Probe Results:{Style.RESET_ALL}")
                
                # Show confidence and threshold
                threshold = self.get_detection_threshold(proto_name)
                print(f"    📊 Confidence: {proto_result['confidence']:.3f} (threshold: {threshold})")
                
                if proto_result.get('adaptive_timeout'):
                    print(f"    ⏱️  Adaptive timeout: {proto_result['adaptive_timeout']:.3f}s")
                
                if proto_result.get('behavioral_profile', {}).get('name'):
                    print(f"    👤 Behavioral profile: {proto_result['behavioral_profile']['name']}")
                
                for probe_name, probe_data in proto_result['probe_results'].items():
                    status_emoji = "✅" if probe_data.get('got_response', False) else "❌"
                    rst_emoji = " 🔌💥" if probe_data.get('got_rst', False) else ""
                    
                    print(f"\n    {Fore.CYAN}📦 {probe_name}:{Style.RESET_ALL}")
                    print(f"      ⏱️  Time: {probe_data['time']:.3f}s")
                    print(f"      {status_emoji} Response: {probe_data.get('got_response', False)}")
                    if 'got_rst' in probe_data:
                        print(f"      🔌 RST: {probe_data['got_rst']}{rst_emoji}")
                    print(f"      📏 Length: {probe_data.get('response_length', 0)} bytes")
    
    def create_json_output(self, results: List[Dict], scan_config: Dict, scan_duration: float) -> Dict:
        """Create comprehensive JSON output."""
        
        # Calculate statistics
        if scan_config['protocol'] == 'both':
            tcp_detections = sum(1 for r in results if r['overall_assessment']['tcp_openvpn'])
            udp_detections = sum(1 for r in results if r['overall_assessment']['udp_openvpn'])
            any_detections = sum(1 for r in results if r['overall_assessment']['any_openvpn'])
            both_detections = sum(1 for r in results if r['overall_assessment']['tcp_openvpn'] and r['overall_assessment']['udp_openvpn'])
            
            statistics = {
                'total_targets': len(results),
                'tcp_detections': tcp_detections,
                'udp_detections': udp_detections,
                'any_protocol_detections': any_detections,
                'both_protocols_detections': both_detections,
                'tcp_only_detections': tcp_detections - both_detections,
                'udp_only_detections': udp_detections - both_detections,
                'overall_detection_rate': any_detections / len(results) if results else 0,
                'tcp_detection_rate': tcp_detections / len(results) if results else 0,
                'udp_detection_rate': udp_detections / len(results) if results else 0,
                'thresholds': {
                    'tcp': self.get_detection_threshold('tcp'),
                    'udp': self.get_detection_threshold('udp'),
                    'combined': self.get_detection_threshold('combined')
                }
            }
        else:
            detections = sum(1 for r in results if r['is_openvpn'])
            statistics = {
                'total_targets': len(results),
                'detections': detections,
                'detection_rate': detections / len(results) if results else 0,
                'protocol': scan_config['protocol'].upper(),
                'threshold': self.get_detection_threshold(scan_config['protocol'])
            }
        
        # Create comprehensive JSON structure
        json_output = {
            'metadata': {
                **self.scan_metadata,
                'scan_config': scan_config,
                'scan_duration_seconds': scan_duration,
                'scan_completed_at': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                'enhancements': [
                    'Adaptive confidence thresholds',
                    'Improved RST pattern detection',
                    'Connection timeout analysis',
                    'Retry logic for network failures',
                    'Enhanced UDP response pattern analysis',
                    'Probe order randomization',
                    'Adaptive timeout calculation',
                    'Bayesian confidence calculation',
                    'Evidence weighting system',
                    'Server behavioral profiling'
                ]
            },
            'statistics': statistics,
            'results': results,
            'research_attribution': {
                'title': 'OpenVPN Is Open to VPN Fingerprinting',
                'authors': [
                    'Diwen Xue',
                    'Reethika Ramesh', 
                    'Arham Jain',
                    'Michaelis Kallitsis',
                    'J. Alex Halderman',
                    'Jedidiah R. Crandall',
                    'Roya Ensafi'
                ],
                'publication': 'Communications of the ACM',
                'year': 2024,
                'url': 'https://cacm.acm.org/research/openvpn-is-open-to-vpn-fingerprinting/',
                'doi': '10.1145/3618117'
            }
        }
        
        return json_output


def print_banner():
    """Print colorful banner with emojis."""
    if COLORAMA_AVAILABLE:
        banner = fr"""
{Fore.CYAN}{Style.BRIGHT}
                                    __ _                            _     _
 ___ _ __  ___ _ ___ ___ __ _ _    / _(_)_ _  __ _ ___ _ _ _ __ _ _(_)_ _| |_ 
/ _ \ '_ \/ -_) ' \ V / '_ \ ' \  |  _| | ' \/ _` / -_) '_| '_ \ '_| | ' \  _|
\___/ .__/\___|_||_\_/| .__/_||_| |_| |_|_||_\__, \___|_| | .__/_| |_|_||_\__|
    |_|               |_|                    |___/        |_|
                                                                
{Fore.YELLOW}🔍 OpenVPN Fingerprinting Tool v2.4.3 🔍{Style.RESET_ALL}
{Fore.GREEN}📡 Based on: "OpenVPN Is Open to VPN Fingerprinting" (ACM CACM 2024) 📡{Style.RESET_ALL}
{Fore.BLUE}🔗 Source: https://cacm.acm.org/research/openvpn-is-open-to-vpn-fingerprinting/ 🔗{Style.RESET_ALL}
{Fore.BLUE}🔗 GitHub: https://github.com/jonaslejon/openvpn-fingerprint 🔗{Style.RESET_ALL}
{Fore.MAGENTA}✨ Enhanced with adaptive algorithms and behavioral profiling ✨{Style.RESET_ALL}
{Fore.RED}⚠️ For educational and research purposes only! ⚠️{Style.RESET_ALL}
{Style.RESET_ALL}"""
    else:
        banner = r"""
OpenVPN Fingerprinting Tool v2.4.3
Based on: "OpenVPN Is Open to VPN Fingerprinting" (ACM CACM 2024)
Source: https://cacm.acm.org/research/openvpn-is-open-to-vpn-fingerprinting/
GitHub: https://github.com/jonaslejon/openvpn-fingerprint
Enhanced with adaptive algorithms and behavioral profiling
For educational and research purposes only!
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description="OpenVPN TCP/UDP Fingerprinting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.CYAN if COLORAMA_AVAILABLE else ''}Examples:{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}
  python3 openvpn-fingerprint.py -t 1.2.3.4
  python3 openvpn-fingerprint.py -t 1.2.3.4 -p 443 --protocol tcp
  python3 openvpn-fingerprint.py -f targets.txt -v --protocol udp
  python3 openvpn-fingerprint.py -t example.com --protocol both -vv
  python3 openvpn-fingerprint.py -f targets.txt --json > results.json
  
{Fore.YELLOW if COLORAMA_AVAILABLE else ''}Target file format (one per line):{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}
  1.2.3.4
  example.com
  192.168.1.1:1194

{Fore.GREEN if COLORAMA_AVAILABLE else ''}Verbose Levels:{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}
  {Fore.CYAN if COLORAMA_AVAILABLE else ''}-v{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}   : Show progress and results
  {Fore.CYAN if COLORAMA_AVAILABLE else ''}-vv{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}  : Show detailed packet analysis and timing
  {Fore.CYAN if COLORAMA_AVAILABLE else ''}--json{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}: Output results in JSON format
"""
)
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-t', '--target', help='🎯 Single target host')
    group.add_argument('-f', '--file', help='📄 File containing target hosts')
    
    parser.add_argument('-p', '--port', type=int, default=1194, 
                       help='🔌 Target port (default: 1194)')
    parser.add_argument('--protocol', choices=['tcp', 'udp', 'both'], default='both',
                       help='📡 Protocol to scan (default: both)')
    
    verbose_group = parser.add_mutually_exclusive_group()
    verbose_group.add_argument('-v', '--verbose', action='store_true',
                       help='📢 Enable verbose output')
    verbose_group.add_argument('-vv', '--super-verbose', action='store_true',
                       help='🔍 Enable super verbose output (packet details)')
    
    parser.add_argument('--json', action='store_true',
                       help='📋 Output results in JSON format')
    parser.add_argument('--timeout', type=float, default=5.0,
                       help='⏰ Connection timeout in seconds (default: 5.0)')
    parser.add_argument('--threads', type=int, default=10,
                       help='🧵 Number of concurrent threads (default: 10)')
    
    args = parser.parse_args()
    
    # Initialize fingerprinter
    fingerprinter = OpenVPNFingerprinter(
        timeout=args.timeout,
        verbose=args.verbose or args.super_verbose,
        super_verbose=args.super_verbose,
        json_output=args.json
    )
    
    # Show banner only if not in JSON mode
    if not args.json:
        print_banner()
    
    # Prepare target list
    targets = []
    
    if args.target:
        targets = [args.target]
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            if args.json:
                error_json = {
                    'error': 'File not found',
                    'message': f"File '{args.file}' not found",
                    'metadata': fingerprinter.scan_metadata
                }
                print(json.dumps(error_json, indent=2))
            else:
                print(f"{Fore.RED if COLORAMA_AVAILABLE else ''}❌ Error: File '{args.file}' not found{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            sys.exit(1)
    
    if not targets:
        if args.json:
            error_json = {
                'error': 'No targets specified',
                'message': 'No targets were provided for scanning',
                'metadata': fingerprinter.scan_metadata
            }
            print(json.dumps(error_json, indent=2))
        else:
            print(f"{Fore.RED if COLORAMA_AVAILABLE else ''}❌ Error: No targets specified{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        sys.exit(1)
    
    # Show scan info only if not in JSON mode
    if not args.json:
        print(f"{Fore.CYAN if COLORAMA_AVAILABLE else ''}🚀 Scanning {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{len(targets)}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}{Fore.CYAN if COLORAMA_AVAILABLE else ''} target(s) on port {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{args.port}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"{Fore.CYAN if COLORAMA_AVAILABLE else ''}📡 Protocol: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{args.protocol.upper()}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}{Fore.CYAN if COLORAMA_AVAILABLE else ''}, ⏰ Timeout: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{args.timeout}s{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}{Fore.CYAN if COLORAMA_AVAILABLE else ''}, 🧵 Threads: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{args.threads}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"{Fore.MAGENTA if COLORAMA_AVAILABLE else ''}🎯 Detection Thresholds: TCP≥{fingerprinter.get_detection_threshold('tcp')}, UDP≥{fingerprinter.get_detection_threshold('udp')}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"{Fore.YELLOW if COLORAMA_AVAILABLE else ''}{'─' * 60}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
    
    # Perform scanning
    start_time = time.time()
    results = fingerprinter.scan_multiple_hosts(targets, args.port, args.protocol, args.threads)
    scan_duration = time.time() - start_time
    
    # Prepare scan configuration for JSON output
    scan_config = {
        'targets': targets,
        'port': args.port,
        'protocol': args.protocol,
        'timeout': args.timeout,
        'threads': args.threads,
        'verbose': args.verbose,
        'super_verbose': args.super_verbose
    }
    
    if args.json:
        # Output JSON results
        json_output = fingerprinter.create_json_output(results, scan_config, scan_duration)
        print(json.dumps(json_output, indent=2, default=str))
    else:
        # Print detailed probe results if super verbose
        fingerprinter.print_detailed_probe_results(results, args.protocol)
        
        # Summary
        print(f"\n{Fore.CYAN if COLORAMA_AVAILABLE else ''}{Style.BRIGHT if COLORAMA_AVAILABLE else ''}📊 SCAN SUMMARY{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        print(f"{Fore.CYAN if COLORAMA_AVAILABLE else ''}{'=' * 60}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        
        if args.protocol == 'both':
            tcp_count = sum(1 for r in results if r['overall_assessment']['tcp_openvpn'])
            udp_count = sum(1 for r in results if r['overall_assessment']['udp_openvpn'])
            any_count = sum(1 for r in results if r['overall_assessment']['any_openvpn'])
            
            print(f"{Fore.WHITE if COLORAMA_AVAILABLE else ''}📈 Total targets scanned: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{len(results)}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            print(f"{Fore.GREEN if COLORAMA_AVAILABLE else ''}🔌 TCP OpenVPN servers detected: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{tcp_count}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            print(f"{Fore.BLUE if COLORAMA_AVAILABLE else ''}📡 UDP OpenVPN servers detected: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{udp_count}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            print(f"{Fore.YELLOW if COLORAMA_AVAILABLE else ''}🎯 Any OpenVPN protocol detected: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{any_count}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            if len(results) > 0:
                print(f"{Fore.MAGENTA if COLORAMA_AVAILABLE else ''}📊 Overall detection rate: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{any_count/len(results)*100:.1f}%{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            else:
                print(f"{Fore.MAGENTA if COLORAMA_AVAILABLE else ''}📊 Overall detection rate: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}N/A{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            
            if any_count > 0:
                print(f"\n{Fore.GREEN if COLORAMA_AVAILABLE else ''}🏆 DETECTED SERVERS BREAKDOWN:{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                both_count = sum(1 for r in results if r['overall_assessment']['tcp_openvpn'] and r['overall_assessment']['udp_openvpn'])
                tcp_only = tcp_count - both_count
                udp_only = udp_count - both_count
                
                if both_count > 0:
                    print(f"  {Fore.CYAN if COLORAMA_AVAILABLE else ''}🔌📡 Both TCP & UDP: {both_count}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                if tcp_only > 0:
                    print(f"  {Fore.GREEN if COLORAMA_AVAILABLE else ''}🔌   TCP only: {tcp_only}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                if udp_only > 0:
                    print(f"  {Fore.BLUE if COLORAMA_AVAILABLE else ''}📡   UDP only: {udp_only}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                    
        else:
            detected_count = sum(1 for r in results if r['is_openvpn'])
            print(f"{Fore.WHITE if COLORAMA_AVAILABLE else ''}📈 Total targets scanned: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{len(results)}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            print(f"{Fore.GREEN if COLORAMA_AVAILABLE else ''}🎯 {args.protocol.upper()} OpenVPN servers detected: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{detected_count}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            if len(results) > 0:
                print(f"{Fore.MAGENTA if COLORAMA_AVAILABLE else ''}📊 Detection rate: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{detected_count/len(results)*100:.1f}%{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            else:
                print(f"{Fore.MAGENTA if COLORAMA_AVAILABLE else ''}📊 Detection rate: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}N/A{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        
        print(f"{Fore.CYAN if COLORAMA_AVAILABLE else ''}⏱️  Total scan time: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{scan_duration:.2f} seconds{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        if len(results) > 0:
            print(f"{Fore.CYAN if COLORAMA_AVAILABLE else ''}⚡ Average time per target: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{scan_duration/len(results):.2f} seconds{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        else:
            print(f"{Fore.CYAN if COLORAMA_AVAILABLE else ''}⚡ Average time per target: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}N/A{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        
        # Show top confidence results
        if args.protocol == 'both':
            high_confidence = sorted(
                [r for r in results if r['overall_assessment']['any_openvpn']],
                key=lambda x: x['overall_assessment']['combined_confidence'],
                reverse=True
            )
        else:
            high_confidence = sorted(
                [r for r in results if r['is_openvpn']],
                key=lambda x: x['confidence'],
                reverse=True
            )
        
        if high_confidence and (args.verbose or args.super_verbose):
            print(f"\n{Fore.GREEN if COLORAMA_AVAILABLE else ''}🏅 HIGH CONFIDENCE DETECTIONS:{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            for result in high_confidence[:5]:  # Show top 5
                if args.protocol == 'both':
                    host = result['host']
                    tcp_conf = result['tcp']['confidence']
                    udp_conf = result['udp']['confidence']
                    max_conf = max(tcp_conf, udp_conf)
                    profiles = []
                    if result['tcp'].get('behavioral_profile', {}).get('name'):
                        profiles.append(f"TCP:{result['tcp']['behavioral_profile']['name']}")
                    if result['udp'].get('behavioral_profile', {}).get('name'):
                        profiles.append(f"UDP:{result['udp']['behavioral_profile']['name']}")
                    profile_str = f" [{', '.join(profiles)}]" if profiles else ""
                    print(f"  {Fore.YELLOW if COLORAMA_AVAILABLE else ''}🎯 {host}: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{max_conf:.3f}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''} {Style.DIM if COLORAMA_AVAILABLE else ''}(TCP:{tcp_conf:.3f}, UDP:{udp_conf:.3f}){profile_str}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                else:
                    host = result['host']
                    conf = result['confidence']
                    profile = result.get('behavioral_profile', {}).get('name', '')
                    profile_str = f" [{profile}]" if profile else ""
                    print(f"  {Fore.YELLOW if COLORAMA_AVAILABLE else ''}🎯 {host}: {Style.BRIGHT if COLORAMA_AVAILABLE else ''}{conf:.3f}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}{profile_str}")
        
        # Enhanced statistics
        if args.protocol == 'both' and results:
            print(f"\n{Fore.MAGENTA if COLORAMA_AVAILABLE else ''}📊 BEHAVIORAL PROFILES DETECTED:{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            profile_counts = {}
            for r in results:
                for proto in ['tcp', 'udp']:
                    profile = r[proto].get('behavioral_profile', {}).get('name')
                    if profile:
                        key = f"{proto.upper()}-{profile}"
                        profile_counts[key] = profile_counts.get(key, 0) + 1
            
            for profile, count in sorted(profile_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"  {Fore.CYAN if COLORAMA_AVAILABLE else ''}👤 {profile}: {count}{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
        
        print(f"\n{Fore.MAGENTA if COLORAMA_AVAILABLE else ''}✨ Enhanced with adaptive algorithms and behavioral profiling{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")


if __name__ == "__main__":
    main()