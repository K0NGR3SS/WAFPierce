"""
Error Handler Utilities
Provides retry logic, graceful degradation, and error logging
"""
import time
import logging
from functools import wraps
from typing import Callable, Any, Optional, Tuple, Type
import requests

from .exceptions import (
    TargetUnreachableError,
    TimeoutError,
    SSLError,
    DNSResolutionError,
    TooManyRedirectsError,
    ProxyError,
    RateLimitError,
    NetworkError,
)


logger = logging.getLogger(__name__)


def retry_on_network_error(
    max_retries: int = 3,
    backoff_factor: float = 1.0,
    exceptions: Tuple[Type[Exception], ...] = (NetworkError,)
):
    """
    Decorator to retry function on network errors with exponential backoff
    
    Args:
        max_retries: Maximum number of retry attempts
        backoff_factor: Multiplier for exponential backoff (wait = backoff_factor * (2 ** attempt))
        exceptions: Tuple of exception types to catch and retry
    
    Usage:
        @retry_on_network_error(max_retries=3, backoff_factor=0.5)
        def make_request(url):
            return requests.get(url)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt < max_retries - 1:
                        wait_time = backoff_factor * (2 ** attempt)
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries} failed: {e}. "
                            f"Retrying in {wait_time:.1f}s..."
                        )
                        time.sleep(wait_time)
                    else:
                        logger.error(f"All {max_retries} attempts failed: {e}")
            
            # Re-raise the last exception if all retries failed
            raise last_exception
        
        return wrapper
    return decorator


def handle_request_errors(url: str, exception: Exception) -> None:
    """
    Convert requests library exceptions to WAFPierce exceptions
    
    Args:
        url: The URL that was being requested
        exception: The exception that was raised
    
    Raises:
        Appropriate WAFPierce exception based on the requests exception type
    """
    if isinstance(exception, requests.exceptions.ConnectionError):
        # Check for specific connection errors
        error_msg = str(exception).lower()
        
        if 'name or service not known' in error_msg or 'nodename nor servname' in error_msg:
            raise DNSResolutionError(
                f"DNS lookup failed for {url}",
                details={'url': url, 'original_error': str(exception)}
            )
        elif 'certificate verify failed' in error_msg:
            raise SSLError(
                f"SSL certificate verification failed for {url}",
                details={'url': url, 'original_error': str(exception)}
            )
        elif 'proxy' in error_msg:
            raise ProxyError(
                f"Proxy connection failed for {url}",
                details={'url': url, 'original_error': str(exception)}
            )
        else:
            raise TargetUnreachableError(
                f"Cannot connect to {url}",
                details={'url': url, 'original_error': str(exception)}
            )
    
    elif isinstance(exception, requests.exceptions.Timeout):
        raise TimeoutError(
            f"Request to {url} timed out",
            details={'url': url, 'original_error': str(exception)}
        )
    
    elif isinstance(exception, requests.exceptions.SSLError):
        raise SSLError(
            f"SSL error for {url}",
            details={'url': url, 'original_error': str(exception)}
        )
    
    elif isinstance(exception, requests.exceptions.TooManyRedirects):
        raise TooManyRedirectsError(
            f"Too many redirects for {url}",
            details={'url': url, 'original_error': str(exception)}
        )
    
    elif isinstance(exception, requests.exceptions.HTTPError):
        # Check for rate limiting
        if hasattr(exception, 'response') and exception.response is not None:
            if exception.response.status_code == 429:
                retry_after = exception.response.headers.get('Retry-After', 'unknown')
                raise RateLimitError(
                    f"Rate limit exceeded for {url}",
                    details={
                        'url': url,
                        'retry_after': retry_after,
                        'status_code': 429
                    }
                )
    
    # If we can't classify it, re-raise as generic NetworkError
    raise NetworkError(
        f"Network error for {url}: {str(exception)}",
        details={'url': url, 'original_error': str(exception)}
    )


def safe_request(
    url: str,
    method: str = 'GET',
    headers: Optional[dict] = None,
    timeout: int = 5,
    allow_redirects: bool = False,
    **kwargs
) -> Optional[requests.Response]:
    """
    Make a safe HTTP request with comprehensive error handling
    
    Args:
        url: Target URL
        method: HTTP method
        headers: Request headers
        timeout: Request timeout in seconds
        allow_redirects: Whether to follow redirects
        **kwargs: Additional arguments to pass to requests
    
    Returns:
        Response object if successful, None if failed gracefully
    
    Raises:
        WAFPierce exceptions for various error conditions
    """
    try:
        if method.upper() == 'GET':
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
                **kwargs
            )
        elif method.upper() == 'POST':
            response = requests.post(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
                **kwargs
            )
        elif method.upper() == 'HEAD':
            response = requests.head(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
                **kwargs
            )
        else:
            response = requests.request(
                method,
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=allow_redirects,
                **kwargs
            )
        
        return response
    
    except Exception as e:
        handle_request_errors(url, e)


class GracefulErrorHandler:
    """
    Context manager for graceful error handling in scan operations
    Logs errors but allows scan to continue
    """
    
    def __init__(self, operation_name: str, continue_on_error: bool = True):
        self.operation_name = operation_name
        self.continue_on_error = continue_on_error
        self.error_count = 0
        self.errors = []
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.error_count += 1
            self.errors.append({
                'type': exc_type.__name__,
                'message': str(exc_val),
                'operation': self.operation_name
            })
            
            logger.error(f"Error in {self.operation_name}: {exc_val}")
            
            # Suppress the exception if continue_on_error is True
            if self.continue_on_error:
                logger.info(f"Continuing despite error in {self.operation_name}")
                return True  # Suppress exception
            
        return False  # Don't suppress exception
    
    def get_error_summary(self) -> dict:
        """Get summary of all errors encountered"""
        return {
            'error_count': self.error_count,
            'errors': self.errors
        }


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate URL format and scheme
    
    Args:
        url: URL to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        
        if not parsed.scheme:
            return False, "URL must include scheme (http:// or https://)"
        
        if parsed.scheme not in ['http', 'https']:
            return False, f"Invalid scheme '{parsed.scheme}'. Must be http or https"
        
        if not parsed.netloc:
            return False, "URL must include domain/host"
        
        return True, None
    
    except Exception as e:
        return False, f"Malformed URL: {str(e)}"


def setup_logging(log_file: Optional[str] = None, level: str = 'INFO') -> None:
    """
    Configure logging for WAFPierce
    
    Args:
        log_file: Optional log file path
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    
    # Configure root logger
    logger = logging.getLogger('wafpierce')
    logger.setLevel(log_level)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not create log file {log_file}: {e}")
    
    return logger