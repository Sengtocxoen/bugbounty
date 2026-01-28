"""
Backup File Verifier
=====================

Verifies exposure of database backup files and sensitive archives.
"""

import requests
from typing import List, Optional
from . import BaseVerifier, VerificationResult, Severity, ConfidenceLevel


class BackupVerifier(BaseVerifier):
    """Verifies database backup and sensitive file exposure"""
    
    BACKUP_FILES = [
        # Database backups
        ("backup.sql", "database"),
        ("db.sql", "database"),
        ("dump.sql", "database"),
        ("database.sql", "database"),
        ("mysql.sql", "database"),
        ("backup.sql.gz", "compressed_database"),
        ("db.sql.gz", "compressed_database"),
        
        # Archive backups
        ("backup.zip", "archive"),
        ("backup.tar.gz", "archive"),
        ("backup.tar", "archive"),
        ("site.zip", "archive"),
        ("www.zip", "archive"),
        ("backup.rar", "archive"),
        
        # Code backups
        ("backup.php", "code"),
        ("backup.bak", "code"),
        ("index.php.bak", "code"),
        ("config.php.bak", "code"),
        
        # Common backup directories
        ("backup/", "directory"),
        ("backups/", "directory"),
        ("old/", "directory"),
    ]
    
    # Magic bytes for file type detection
    MAGIC_BYTES = {
        "sql": [b"-- MySQL", b"CREATE TABLE", b"INSERT INTO", b"DROP TABLE"],
        "zip": [b"PK\x03\x04"],
        "gzip": [b"\x1f\x8b"],
        "tar": [b"ustar"],
    }
    
    def verify(self, base_url: str) -> List[VerificationResult]:
        """
        Check for exposed backup files
        
        Args:
            base_url: Base URL to check
        
        Returns:
            List of VerificationResults for found backup files
        """
        if not base_url.startswith('http'):
            base_url = f"https://{base_url}"
        
        base_url = base_url.rstrip('/')
        results = []
        
        for filename, file_type in self.BACKUP_FILES:
            url = f"{base_url}/{filename}"
            result = self._check_backup_file(url, file_type)
            
            if result.verified:
                results.append(result)
        
        return results if results else [VerificationResult(
            verified=False,
            confidence=ConfidenceLevel.HIGH,
            severity=Severity.INFO,
            finding_type="no_backups",
            target=base_url,
            details="No accessible backup files found",
            proof={}
        )]
    
    def _check_backup_file(self, url: str, file_type: str) -> VerificationResult:
        """Check a specific backup file"""
        try:
            # Use HEAD request first to avoid downloading entire file
            head_response = requests.head(
                url,
                headers=self.get_headers(),
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            
            if head_response.status_code == 200:
                content_length = int(head_response.headers.get("Content-Length", 0))
                content_type = head_response.headers.get("Content-Type", "")
                
                # If file exists and has content, verify it's actually a backup
                if content_length > 0:
                    # Download first few bytes to verify file type
                    verified_type = self._verify_file_type(url)
                    
                    # Determine severity based on file type and size
                    if file_type == "database" or verified_type == "database":
                        severity = Severity.CRITICAL
                        details = f"Database backup file exposed! File accessible: {url.split('/')[-1]} ({self._format_size(content_length)})"
                        cvss = 9.1
                    elif file_type == "archive" or verified_type in ["zip", "gzip", "tar"]:
                        severity = Severity.HIGH
                        details = f"Archive backup file exposed! {url.split('/')[-1]} ({self._format_size(content_length)})"
                        cvss = 8.2
                    elif file_type == "code":
                        severity = Severity.HIGH
                        details = f"Code backup file exposed! {url.split('/')[-1]}"
                        cvss = 7.5
                    else:
                        severity = Severity.MEDIUM
                        details = f"Backup file exposed: {url.split('/')[-1]} ({self._format_size(content_length)})"
                        cvss = 6.5
                    
                    return VerificationResult(
                        verified=True,
                        confidence=ConfidenceLevel.CONFIRMED,
                        severity=severity,
                        finding_type="backup_file_exposed",
                        target=url,
                        details=details,
                        proof={
                            "url": url,
                            "filename": url.split('/')[-1],
                            "file_type": verified_type or file_type,
                            "size_bytes": content_length,
                            "size_human": self._format_size(content_length),
                            "content_type": content_type,
                            "downloadable": True,
                        },
                        remediation="Remove backup files from web root. Store backups in secure, non-web-accessible locations.",
                        cvss_score=cvss
                    )
            
            elif head_response.status_code == 404:
                return VerificationResult(
                    verified=False,
                    confidence=ConfidenceLevel.CONFIRMED,
                    severity=Severity.INFO,
                    finding_type="backup_not_found",
                    target=url,
                    details="Backup file not found",
                    proof={}
                )
            
            else:
                return VerificationResult(
                    verified=False,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=Severity.INFO,
                    finding_type="backup_check_failed",
                    target=url,
                    details=f"Status code: {head_response.status_code}",
                    proof={}
                )
        
        except Exception as e:
            return VerificationResult(
                verified=False,
                confidence=ConfidenceLevel.UNVERIFIED,
                severity=Severity.INFO,
                finding_type="verification_error",
                target=url,
                details=f"Error: {str(e)}",
                proof={}
            )
    
    def _verify_file_type(self, url: str) -> Optional[str]:
        """Download first few bytes to verify file type"""
        try:
            # Download first 512 bytes
            headers = self.get_headers()
            headers["Range"] = "bytes=0-511"
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code in [200, 206]:  # 206 = Partial Content
                content = response.content
                
                # Check magic bytes
                for file_type, magic_list in self.MAGIC_BYTES.items():
                    for magic in magic_list:
                        if content.startswith(magic) or magic in content:
                            return file_type
        except:
            pass
        
        return None
    
    def _format_size(self, bytes_size: int) -> str:
        """Format byte size to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} TB"
