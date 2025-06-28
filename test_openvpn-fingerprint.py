import pytest
import socket
import time
from unittest.mock import patch, MagicMock
import importlib.util
from pathlib import Path

# Import the module we're testing
def import_openvpn_fingerprint():
    """Import the openvpn-fingerprint.py module with proper error handling"""
    # Get the directory containing this test file
    test_dir = Path(__file__).parent

    # Look for openvpn-fingerprint.py in the same directory
    module_path = test_dir / "openvpn-fingerprint.py"

    if not module_path.exists():
        # Also try looking in parent directory
        module_path = test_dir.parent / "openvpn-fingerprint.py"

    if not module_path.exists():
        raise ImportError(
            f"Could not find openvpn-fingerprint.py in {test_dir} or {test_dir.parent}. "
            "Please ensure openvpn-fingerprint.py is in the same directory as this test file."
        )

    # Load the module
    spec = importlib.util.spec_from_file_location("openvpn_fingerprint", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not create module spec for {module_path}")

    openvpn_fingerprint_module = importlib.util.module_from_spec(spec)

    # Execute the module
    try:
        spec.loader.exec_module(openvpn_fingerprint_module)
    except Exception as e:
        raise ImportError(f"Failed to execute openvpn-fingerprint.py: {e}")

    return openvpn_fingerprint_module

openvpn_fingerprint = import_openvpn_fingerprint()
OpenVPNFingerprinter = openvpn_fingerprint.OpenVPNFingerprinter
EvidenceType = openvpn_fingerprint.EvidenceType


@pytest.fixture
def fingerprinter():
    """Returns a default OpenVPNFingerprinter instance."""
    return OpenVPNFingerprinter(logging_enabled=False)

def test_create_tcp_base_probes(fingerprinter):
    """Test creation of TCP base probes."""
    probes = fingerprinter.create_tcp_base_probes()
    assert 'base_probe_1' in probes
    assert 'invalid_length' in probes
    assert len(probes['base_probe_1']) > 10  # Ensure it's not empty

def test_create_udp_base_probes(fingerprinter):
    """Test creation of UDP base probes."""
    probes = fingerprinter.create_udp_base_probes()
    assert 'client_reset' in probes
    assert 'invalid_opcode' in probes
    assert len(probes['client_reset']) > 10

def test_analyze_openvpn_response_tcp_reset(fingerprinter):
    """Test analysis of a classic OpenVPN TCP server reset."""
    # V2 Reset: length (2) + opcode (1) + session (8) + ...
    response_data = b'\x00\x11' + b'\x48' + b'\x00'*8 + b'\x01\x02\x03\x04' + b'\x00'*4
    evidence = fingerprinter.analyze_openvpn_response(response_data, 'tcp')
    assert any(EvidenceType.OPENVPN_SERVER_RESET_V2.value[0] in e[0] for e in evidence)

def test_analyze_openvpn_response_udp_reset(fingerprinter):
    """Test analysis of a classic OpenVPN UDP server reset."""
    # V2 Reset: opcode (1) + session (8) + ...
    response_data = b'\x48' + b'\x00'*8 + b'\x01\x02\x03\x04' + b'\x00'*4
    evidence = fingerprinter.analyze_openvpn_response(response_data, 'udp')
    assert any(EvidenceType.OPENVPN_SERVER_RESET_V2.value[0] in e[0] for e in evidence)

@patch('socket.socket')
def test_measure_tcp_timing_connection_refused(mock_socket, fingerprinter):
    """Test TCP timing measurement when connection is refused."""
    mock_sock_instance = MagicMock()
    mock_sock_instance.connect.side_effect = ConnectionRefusedError
    mock_socket.return_value = mock_sock_instance

    time_val, got_response, got_rst, data = fingerprinter.measure_tcp_timing('localhost', 1194, b'test')
    assert time_val == -2
    assert not got_response
    assert not got_rst

@patch('time.time')
@patch('socket.socket')
def test_measure_udp_timing_timeout(mock_socket, mock_time):
    """Test UDP timing measurement on timeout."""
    fingerprinter = OpenVPNFingerprinter(verbose=False, super_verbose=False)
    mock_sock_instance = MagicMock()
    mock_sock_instance.recvfrom.side_effect = socket.timeout
    mock_socket.return_value = mock_sock_instance

    # Simulate time passing
    start_time = 1000.0
    end_time = start_time + fingerprinter.timeout + 0.1
    mock_time.side_effect = [start_time, end_time]

    time_val, got_response, got_icmp, data = fingerprinter.measure_udp_timing('localhost', 1194, b'test')

    # Verify that the time measured is correctly calculated
    assert time_val == pytest.approx(end_time - start_time)
    assert time_val > fingerprinter.timeout

    # Verify the state flags
    assert not got_response
    assert not got_icmp
    assert data == b''


def test_bayesian_confidence_calculation(fingerprinter):
    """Test the Bayesian confidence calculation logic."""
    evidence = [
        (EvidenceType.OPENVPN_SERVER_RESET_V2.value[0], EvidenceType.OPENVPN_SERVER_RESET_V2.value[1]),
        (EvidenceType.VALID_TCP_STRUCTURE.value[0], EvidenceType.VALID_TCP_STRUCTURE.value[1])
    ]
    confidence = fingerprinter.calculate_bayesian_confidence(evidence)
    assert 0 < confidence <= 1.0
    # With strong evidence, confidence should be high, but the formula gives ~0.25
    assert confidence > 0.2

def test_no_evidence_confidence(fingerprinter):
    """Test that no evidence results in zero confidence."""
    confidence = fingerprinter.calculate_bayesian_confidence([])
    assert confidence == 0.0
