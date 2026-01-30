"""WAFPierce - CloudFront WAF Bypass Tool"""
from .pierce import CloudFrontBypasser
from .chain import FullPentestChain

__all__ = ['CloudFrontBypasser', 'FullPentestChain']
__version__ = '1.0.0'