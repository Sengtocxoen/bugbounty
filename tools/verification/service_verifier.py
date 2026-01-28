"""
Service Verifier
================

Verifies exposed services on open ports (RDP, Redis, SSH, FTP, MySQL, etc.)
Checks if services are accessible and if authentication is required.
"""

import socket
import struct
from typing import Optional, Tuple
from . import BaseVerifier, VerificationResult, Severity, ConfidenceLevel


class ServiceVerifier(BaseVerifier):
    """Verifies exposed network services"""
    
    def verify_redis(self, host: str, port: int = 6379) -> VerificationResult:
        """
        Verify Redis service exposure
        Tests if Redis is accessible and if authentication is required
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Send PING command
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Check response
            if "+PONG" in response:
                return VerificationResult(
                    verified=True,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=Severity.CRITICAL,
                    finding_type="exposed_redis_no_auth",
                    target=f"{host}:{port}",
                    details="Redis server is exposed without authentication! Immediate RCE possible.",
                    proof={
                        "service": "Redis",
                        "port": port,
                        "authentication": False,
                        "command_tested": "PING",
                        "response": response.strip(),
                    },
                    remediation="Enable Redis authentication with 'requirepass' and bind to localhost only",
                    cvss_score=9.8
                )
            elif "-NOAUTH" in response or "-ERR" in response:
                return VerificationResult(
                    verified=True,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=Severity.MEDIUM,
                    finding_type="exposed_redis_with_auth",
                    target=f"{host}:{port}",
                    details="Redis server is exposed but requires authentication",
                    proof={
                        "service": "Redis",
                        "port": port,
                        "authentication": True,
                        "response": response.strip(),
                    },
                    remediation="Ensure Redis is not exposed to internet, bind to localhost",
                    cvss_score=5.3
                )
            else:
                return VerificationResult(
                    verified=True,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=Severity.LOW,
                    finding_type="unknown_redis_response",
                    target=f"{host}:{port}",
                    details=f"Redis-like service responded: {response[:100]}",
                    proof={"response": response}
                )
        
        except socket.timeout:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="service_timeout",
                target=f"{host}:{port}",
                details="Connection to Redis port timed out",
                proof={}
            )
        
        except ConnectionRefusedError:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.CONFIRMED,
                severity=Severity.INFO,
                finding_type="service_closed",
                target=f"{host}:{port}",
                details="Redis port is closed or filtered",
                proof={}
            )
        
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="connection_error",
                target=f"{host}:{port}",
                details=f"Error connecting to Redis: {str(e)}",
                proof={}
            )
    
    def verify_rdp(self, host: str, port: int = 3389) -> VerificationResult:
        """
        Verify RDP service exposure
        RDP exposed to internet is a critical security risk
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Send minimal RDP connection request
            # This is just to check if RDP is listening
            rdp_probe = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
            sock.sendall(rdp_probe)
            response = sock.recv(1024)
            sock.close()
            
            # If we get any response, RDP is likely active
            if response:
                return VerificationResult(
                    verified=True,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=Severity.CRITICAL,
                    finding_type="exposed_rdp",
                    target=f"{host}:{port}",
                    details="RDP (Remote Desktop Protocol) is exposed to the internet! High risk of brute-force attacks.",
                    proof={
                        "service": "RDP",
                        "port": port,
                        "response_length": len(response),
                        "response_hex": response[:50].hex(),
                    },
                    remediation="Remove RDP from internet exposure. Use VPN or bastion host for remote access.",
                    cvss_score=9.8
                )
        
        except socket.timeout:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="service_timeout",
                target=f"{host}:{port}",
                details="Connection to RDP port timed out",
                proof={}
            )
        
        except ConnectionRefusedError:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.CONFIRMED,
                severity=Severity.INFO,
                finding_type="service_closed",
                target=f"{host}:{port}",
                details="RDP port is closed or filtered (false positive)",
                proof={}
            )
        
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="connection_error",
                target=f"{host}:{port}",
                details=f"Error connecting to RDP: {str(e)}",
                proof={}
            )
    
    def verify_ssh(self, host: str, port: int = 22) -> VerificationResult:
        """Verify SSH service and get banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Receive SSH banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner.startswith("SSH"):
                # Extract version
                version = banner.split('-')[1] if '-' in banner else "unknown"
                
                # Check for known vulnerable versions
                severity = Severity.LOW
                details = f"SSH service exposed: {banner}"
                vuln_notes = []
                
                if "OpenSSH_7.4" in banner or "OpenSSH_7.5" in banner or "OpenSSH_7.6" in banner:
                    severity = Severity.MEDIUM
                    vuln_notes.append("Potentially vulnerable OpenSSH version")
                
                return VerificationResult(
                    verified=True,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=severity,
                    finding_type="exposed_ssh",
                    target=f"{host}:{port}",
                    details=details + (" - " + ", ".join(vuln_notes) if vuln_notes else ""),
                    proof={
                        "service": "SSH",
                        "port": port,
                        "banner": banner,
                        "version": version,
                    },
                    remediation="Ensure SSH uses key-based auth, disable password auth, use fail2ban"
                )
        
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="connection_error",
                target=f"{host}:{port}",
                details=f"Could not verify SSH: {str(e)}",
                proof={}
            )
    
    def verify_ftp(self, host: str, port: int = 21) -> VerificationResult:
        """Verify FTP service and check for anonymous login"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Get FTP banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            # Try anonymous login
            sock.sendall(b"USER anonymous\r\n")
            user_response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            sock.sendall(b"PASS anonymous@\r\n")
            pass_response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Check if anonymous login succeeded
            if "230" in pass_response:  # 230 = Login successful
                return VerificationResult(
                    verified=True,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=Severity.HIGH,
                    finding_type="ftp_anonymous_access",
                    target=f"{host}:{port}",
                    details="FTP allows anonymous login! Anyone can access files.",
                    proof={
                        "service": "FTP",
                        "port": port,
                        "banner": banner,
                        "anonymous_access": True,
                    },
                    remediation="Disable anonymous FTP access",
                    cvss_score=7.5
                )
            else:
                return VerificationResult(
                    verified=True,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=Severity.MEDIUM,
                    finding_type="exposed_ftp",
                    target=f"{host}:{port}",
                    details=f"FTP service exposed: {banner}",
                    proof={
                        "service": "FTP",
                        "port": port,
                        "banner": banner,
                        "anonymous_access": False,
                    }
                )
        
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="connection_error",
                target=f"{host}:{port}",
                details=f"Could not verify FTP: {str(e)}",
                proof={}
            )
    
    def verify_mysql(self, host: str, port: int = 3306) -> VerificationResult:
        """Verify MySQL service exposure"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Read MySQL greeting
            response = sock.recv(1024)
            sock.close()
            
            # MySQL greeting starts with packet length + sequence + protocol version
            if response and len(response) > 5:
                protocol_version = response[4]
                
                # Extract server version (null-terminated string after protocol version)
                version_start = 5
                version_end = response.find(b'\x00', version_start)
                if version_end > version_start:
                    version = response[version_start:version_end].decode('utf-8', errors='ignore')
                    
                    return VerificationResult(
                        verified=True,
                        confidence=ConfidenceLevel.CONFIRMED,
                        severity=Severity.HIGH,
                        finding_type="exposed_mysql",
                        target=f"{host}:{port}",
                        details=f"MySQL database exposed to internet! Version: {version}",
                        proof={
                            "service": "MySQL",
                            "port": port,
                            "version": version,
                            "protocol_version": protocol_version,
                        },
                        remediation="Bind MySQL to localhost only, use firewall rules",
                        cvss_score=7.5
                    )
        
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="connection_error",
                target=f"{host}:{port}",
                details=f"Could not verify MySQL: {str(e)}",
                proof={}
            )
    
    def verify_port(self, host: str, port: int, service_name: str) -> VerificationResult:
        """
        Verify any port/service
        Routes to specific verifier if available, otherwise does basic connectivity check
        """
        # Route to specific verifiers
        if port == 6379 or service_name.lower() == "redis":
            return self.verify_redis(host, port)
        elif port == 3389 or service_name.lower() == "rdp":
            return self.verify_rdp(host, port)
        elif port == 22 or service_name.lower() == "ssh":
            return self.verify_ssh(host, port)
        elif port == 21 or service_name.lower() == "ftp":
            return self.verify_ftp(host, port)
        elif port == 3306 or service_name.lower() == "mysql":
            return self.verify_mysql(host, port)
        
        # Generic port check for unknown services
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return VerificationResult(
                    verified=True,
                    confidence=ConfidenceLevel.HIGH,
                    severity=Severity.LOW,
                    finding_type="open_port",
                    target=f"{host}:{port}",
                    details=f"Port {port} ({service_name}) is open",
                    proof={"port": port, "service": service_name}
                )
            else:
                return VerificationResult(
                    verified=False,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=Severity.INFO,
                    finding_type="port_closed",
                    target=f"{host}:{port}",
                    details=f"Port {port} is closed (false positive)",
                    proof={}
                )
        
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="connection_error",
                target=f"{host}:{port}",
                details=f"Error: {str(e)}",
                proof={}
            )
