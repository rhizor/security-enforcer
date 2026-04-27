"""
Input validation and sanitization utilities
Prevents injection attacks and path traversal
"""

import re
import ipaddress
from typing import Optional, Union

# Regular expression patterns for validation
IPV4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
CIDR_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$")
CONTAINER_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
HANDLE_PATTERN = re.compile(r"^[0-9]+$")
FILENAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$")

# Dangerous characters that should never appear in command arguments
DANGEROUS_CHARS = [';', '|', '&', '$', '`', '>', '<', '{', '}', '(', ')', '#', '\\', '\"', \"'\"]

class ValidationError(Exception):
    """Raised when input validation fails."""
    pass

def validate_ipv4(ip: str) -> bool:
    """
    Validate IPv4 address.
    
    Args:
        ip: IP address string
    
    Returns:
        True if valid IPv4 address
    """
    if not ip or not isinstance(ip, str):
        return False
    
    # First check pattern
    if not IPV4_PATTERN.match(ip):
        return False
    
    # Then use ipaddress module for thorough validation
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def validate_cidr(cidr: str) -> bool:
    """
    Validate CIDR notation (e.g., 192.168.1.0/24).
    
    Args:
        cidr: CIDR string
    
    Returns:
        True if valid CIDR
    """
    if not cidr or not isinstance(cidr, str):
        return False
    
    if not CIDR_PATTERN.match(cidr):
        return False
    
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except ValueError:
        return False

def validate_port(port: Union[str, int]) -> bool:
    """
    Validate port number.
    
    Args:
        port: Port number (1-65535)
    
    Returns:
        True if valid port
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def validate_container_name(name: str) -> bool:
    """
    Validate Docker container name.
    
    Rules:
        - Must start with alphanumeric
        - Can contain alphanumeric, underscore, dot, hyphen
        - Max 64 characters
    
    Args:
        name: Container name
    
    Returns:
        True if valid container name
    """
    if not name or not isinstance(name, str):
        return False
    
    if len(name) > 64:
        return False
    
    return bool(CONTAINER_NAME_PATTERN.match(name))

def validate_handle(handle: str) -> bool:
    """
    Validate nftables/iptables handle (numeric string).
    
    Args:
        handle: Handle string
    
    Returns:
        True if valid handle
    """
    if not handle or not isinstance(handle, str):
        return False
    
    return bool(HANDLE_PATTERN.match(handle))

def validate_filename(filename: str, allowed_extensions: Optional[list] = None) -> bool:
    """
    Validate filename to prevent path traversal.
    
    Args:
        filename: Filename to validate
        allowed_extensions: List of allowed extensions (e.g., ['.txt', '.json'])
    
    Returns:
        True if valid filename
    """
    if not filename or not isinstance(filename, str):
        return False
    
    # Check for path traversal attempts
    if '..' in filename or '/' in filename or '\\' in filename:
        return False
    
    # Check for dangerous characters
    for char in DANGEROUS_CHARS:
        if char in filename:
            return False
    
    # Validate extension if specified
    if allowed_extensions:
        has_valid_ext = any(filename.endswith(ext) for ext in allowed_extensions)
        if not has_valid_ext:
            return False
    
    return bool(FILENAME_PATTERN.match(filename))

def sanitize_command_arg(arg: str) -> str:
    """
    Sanitize command argument to prevent injection.
    
    Args:
        arg: Command argument
    
    Returns:
        Sanitized argument
    
    Raises:
        ValidationError: If dangerous characters detected
    """
    if not isinstance(arg, str):
        raise ValidationError(f"Argument must be string, got {type(arg)}")
    
    # Check for dangerous characters
    for char in DANGEROUS_CHARS:
        if char in arg:
            raise ValidationError(f"Dangerous character '{char}' detected in argument")
    
    # Check for null bytes
    if '\x00' in arg:
        raise ValidationError("Null bytes not allowed")
    
    return arg

def sanitize_ip(ip: str) -> str:
    """
    Sanitize and validate IP address.
    
    Args:
        ip: IP address
    
    Returns:
        Validated IP address
    
    Raises:
        ValidationError: If invalid IP
    """
    if not validate_ipv4(ip):
        raise ValidationError(f"Invalid IPv4 address: {ip}")
    return ip

def sanitize_cidr(cidr: str) -> str:
    """
    Sanitize and validate CIDR notation.
    
    Args:
        cidr: CIDR string
    
    Returns:
        Validated CIDR
    
    Raises:
        ValidationError: If invalid CIDR
    """
    if not validate_cidr(cidr):
        raise ValidationError(f"Invalid CIDR: {cidr}")
    return cidr

def sanitize_port(port: Union[str, int]) -> int:
    """
    Sanitize and validate port number.
    
    Args:
        port: Port number
    
    Returns:
        Validated port as integer
    
    Raises:
        ValidationError: If invalid port
    """
    if not validate_port(port):
        raise ValidationError(f"Invalid port: {port}")
    return int(port)

def validate_protocol(protocol: str) -> bool:
    """
    Validate protocol (tcp, udp, icmp).
    
    Args:
        protocol: Protocol name
    
    Returns:
        True if valid protocol
    """
    if not protocol or not isinstance(protocol, str):
        return False
    
    return protocol.lower() in ('tcp', 'udp', 'icmp')

def validate_log_line(line: str, max_length: int = 4096) -> bool:
    """
    Validate log line to prevent ReDoS attacks with regex.
    
    Args:
        line: Log line
        max_length: Maximum allowed length
    
    Returns:
        True if valid
    """
    if not isinstance(line, str):
        return False
    
    if len(line) > max_length:
        return False
    
    # Check for potentially dangerous patterns
    suspicious_patterns = [
        r'(.)\1{100,}',  # Repeated characters (ReDoS)
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, line):
            return False
    
    return True

class InputValidator:
    """
    Context manager for validating multiple inputs.
    """
    
    def __init__(self):
        self.errors = []
    
    def validate_ip(self, name: str, value: str) -> 'InputValidator':
        """Add IP validation."""
        if not validate_ipv4(value):
            self.errors.append(f"{name}: Invalid IPv4 address")
        return self
    
    def validate_port(self, name: str, value: Union[str, int]) -> 'InputValidator':
        """Add port validation."""
        if not validate_port(value):
            self.errors.append(f"{name}: Invalid port (must be 1-65535)")
        return self
    
    def validate_container(self, name: str, value: str) -> 'InputValidator':
        """Add container name validation."""
        if not validate_container_name(value):
            self.errors.append(f"{name}: Invalid container name")
        return self
    
    def validate_filename(self, name: str, value: str) -> 'InputValidator':
        """Add filename validation."""
        if not validate_filename(value):
            self.errors.append(f"{name}: Invalid filename")
        return self
    
    def raise_if_invalid(self):
        """Raise ValidationError if any validation failed."""
        if self.errors:
            raise ValidationError("; ".join(self.errors))
