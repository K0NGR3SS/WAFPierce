"""
WAFPierce Custom Exceptions
Comprehensive error handling for penetration testing operations
"""


class WAFPierceError(Exception):
    """Base exception for all WAFPierce errors"""
    
    def __init__(self, message, details=None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)
    
    def __str__(self):
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({details_str})"
        return self.message


# Network-related errors
class NetworkError(WAFPierceError):
    """Base class for network-related errors"""
    pass


class TargetUnreachableError(NetworkError):
    """Target cannot be reached"""
    pass


class RequestTimeoutError(NetworkError):
    """Request timed out"""
    pass


# Alias for backwards compatibility
TimeoutError = RequestTimeoutError


class SSLError(NetworkError):
    """SSL/TLS certificate validation failed"""
    pass


class DNSResolutionError(NetworkError):
    """DNS lookup failed"""
    pass


class TooManyRedirectsError(NetworkError):
    """Too many redirects encountered"""
    pass


class ProxyError(NetworkError):
    """Proxy connection failed"""
    pass


# Target validation errors
class ValidationError(WAFPierceError):
    """Base class for validation errors"""
    pass


class InvalidTargetError(ValidationError):
    """Target URL is invalid or malformed"""
    pass


class InvalidSchemeError(ValidationError):
    """URL scheme must be http or https"""
    pass


class NotCloudFrontError(ValidationError):
    """Target is not a CloudFront distribution"""
    pass


class UnauthorizedTargetError(ValidationError):
    """Target is not in authorized scope"""
    pass


# Scanning errors
class ScanError(WAFPierceError):
    """Base class for scanning errors"""
    pass


class BaselineFailedError(ScanError):
    """Failed to establish baseline response"""
    pass


class NoBypassFoundError(ScanError):
    """No bypass techniques succeeded"""
    pass


class RateLimitError(ScanError):
    """Rate limit exceeded"""
    pass


class ScanInterruptedError(ScanError):
    """Scan was interrupted by user or system"""
    pass


# Backend Detection errors
class BackendDetectionError(WAFPierceError):
    """Base class for backend detection errors"""
    pass


class NoBackendDetectedError(BackendDetectionError):
    """No backend origin could be detected"""
    pass


class S3DetectionError(BackendDetectionError):
    """Error detecting S3 bucket origin"""
    pass


class ELBDetectionError(BackendDetectionError):
    """Error detecting Elastic Load Balancer origin"""
    pass


class EC2DetectionError(BackendDetectionError):
    """Error detecting EC2 instance origin"""
    pass


class MediaServicesDetectionError(BackendDetectionError):
    """Error detecting MediaPackage/MediaStore origin"""
    pass


class HeaderAnalysisError(BackendDetectionError):
    """Error analyzing response headers for backend detection"""
    pass


# Resource errors
class ResourceError(WAFPierceError):
    """Base class for resource errors"""
    pass


class WordlistNotFoundError(ResourceError):
    """Wordlist file not found"""
    pass


class OutputDirectoryError(ResourceError):
    """Cannot create or write to output directory"""
    pass


class InsufficientPermissionsError(ResourceError):
    """Insufficient permissions to perform operation"""
    pass


# Configuration errors
class ConfigurationError(WAFPierceError):
    """Base class for configuration errors"""
    pass


class InvalidThreadCountError(ConfigurationError):
    """Thread count must be positive integer"""
    pass


class InvalidDelayError(ConfigurationError):
    """Delay must be non-negative number"""
    pass


class InvalidTimeoutError(ConfigurationError):
    """Timeout must be positive number"""
    pass


# Legal/Authorization errors
class AuthorizationError(WAFPierceError):
    """Base class for authorization errors"""
    pass


class ConsentNotProvidedError(AuthorizationError):
    """User did not provide explicit consent"""
    pass


class ScopeViolationError(AuthorizationError):
    """Target is outside authorized scope"""
    pass