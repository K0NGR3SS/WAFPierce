"""
WAFPierce Plugin System
Allows users to create custom bypass modules and share them with the community
"""
import os
import sys
import json
import hashlib
import importlib.util
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from abc import ABC, abstractmethod


def _get_plugins_dir() -> str:
    """Get the plugins directory path."""
    if os.name == 'nt':
        base = os.getenv('APPDATA') or os.path.expanduser('~')
    else:
        base = os.path.join(os.path.expanduser('~'), '.config')
    d = os.path.join(base, 'wafpierce', 'plugins')
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return d


class BypassPlugin(ABC):
    """
    Base class for WAFPierce bypass plugins.
    
    To create a custom plugin:
    1. Create a new .py file in the plugins directory
    2. Create a class that inherits from BypassPlugin
    3. Implement the required methods
    4. Register your plugin by creating an instance at module level
    
    Example:
        class MyCustomBypass(BypassPlugin):
            name = "My Custom Bypass"
            version = "1.0.0"
            author = "Your Name"
            description = "Description of what this bypass does"
            category = "encoding"  # bypass, encoding, header, injection, etc.
            
            def execute(self, target, session, **kwargs):
                # Your bypass logic here
                payload = self.encode_payload(kwargs.get('payload', ''))
                return self.make_request(target, payload)
    """
    
    # Plugin metadata (override these in your plugin)
    name: str = "Unnamed Plugin"
    version: str = "1.0.0"
    author: str = "Unknown"
    description: str = "No description provided"
    category: str = "bypass"
    tags: List[str] = []
    
    # WAF compatibility (empty = all WAFs)
    compatible_wafs: List[str] = []
    
    # Plugin settings
    settings: Dict[str, Any] = {}
    
    def __init__(self):
        self.enabled = True
        self.last_run = None
        self.success_count = 0
        self.fail_count = 0
    
    @abstractmethod
    def execute(self, target: str, session: Any, **kwargs) -> Dict[str, Any]:
        """
        Execute the bypass technique.
        
        Args:
            target: Target URL
            session: requests.Session object
            **kwargs: Additional arguments (payload, headers, etc.)
        
        Returns:
            Dict with keys:
                - success: bool
                - bypass: bool (did it bypass the WAF?)
                - response: response object or None
                - technique: str (name of technique used)
                - reason: str (why this is considered a bypass/success)
                - severity: str (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        """
        pass
    
    def setup(self, config: Dict[str, Any] = None):
        """Optional setup method called before first execution."""
        if config:
            self.settings.update(config)
    
    def teardown(self):
        """Optional cleanup method called after all executions."""
        pass
    
    def validate_target(self, target: str) -> bool:
        """Check if this plugin should run against the target."""
        return True
    
    def get_payloads(self) -> List[str]:
        """Return a list of payloads this plugin uses."""
        return []
    
    # Utility methods for plugin authors
    def encode_payload(self, payload: str, encoding: str = 'url') -> str:
        """Encode a payload using various methods."""
        import urllib.parse
        
        if encoding == 'url':
            return urllib.parse.quote(payload)
        elif encoding == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == 'hex':
            return ''.join(f'%{ord(c):02x}' for c in payload)
        elif encoding == 'base64':
            import base64
            return base64.b64encode(payload.encode()).decode()
        else:
            return payload
    
    def make_request(self, target: str, payload: str = None, method: str = 'GET',
                     headers: Dict[str, str] = None, session: Any = None, **kwargs) -> Any:
        """Make an HTTP request with the given parameters."""
        import requests
        
        s = session or requests.Session()
        
        if method.upper() == 'GET':
            return s.get(target, params={'payload': payload} if payload else None,
                        headers=headers, **kwargs)
        elif method.upper() == 'POST':
            return s.post(target, data={'payload': payload} if payload else None,
                         headers=headers, **kwargs)
        else:
            return s.request(method, target, headers=headers, **kwargs)
    
    def is_blocked(self, response: Any) -> bool:
        """Check if the response indicates WAF blocking."""
        if response is None:
            return True
        
        # Common WAF block indicators
        block_codes = [403, 406, 429, 503]
        block_phrases = [
            'blocked', 'forbidden', 'access denied', 'security',
            'firewall', 'waf', 'attack', 'malicious', 'not allowed'
        ]
        
        if response.status_code in block_codes:
            return True
        
        text_lower = response.text.lower()
        return any(phrase in text_lower for phrase in block_phrases)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert plugin metadata to dictionary."""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'category': self.category,
            'tags': self.tags,
            'compatible_wafs': self.compatible_wafs,
            'enabled': self.enabled,
            'success_count': self.success_count,
            'fail_count': self.fail_count,
            'last_run': self.last_run.isoformat() if self.last_run else None
        }


class PluginManager:
    """Manages loading, running, and organizing plugins."""
    
    def __init__(self, db=None):
        self.plugins_dir = _get_plugins_dir()
        self.plugins: Dict[str, BypassPlugin] = {}
        self.db = db
        self._create_example_plugin()
    
    def _create_example_plugin(self):
        """Create an example plugin file if none exist."""
        example_path = os.path.join(self.plugins_dir, 'example_plugin.py')
        if not os.path.exists(example_path):
            example_code = '''"""
Example WAFPierce Plugin
This is a template for creating your own bypass plugins.
"""
from wafpierce.plugins import BypassPlugin


class UnicodeBypassPlugin(BypassPlugin):
    """Example plugin that uses Unicode normalization for bypasses."""
    
    name = "Unicode Normalization Bypass"
    version = "1.0.0"
    author = "WAFPierce Community"
    description = "Uses Unicode character variations to bypass WAF filters"
    category = "encoding"
    tags = ["unicode", "encoding", "obfuscation"]
    compatible_wafs = ["cloudflare", "akamai", "imperva"]
    
    def execute(self, target, session, **kwargs):
        """Execute the Unicode bypass technique."""
        import requests
        
        payload = kwargs.get('payload', '<script>alert(1)</script>')
        
        # Unicode fullwidth characters
        unicode_payload = ''.join(
            chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c
            for c in payload
        )
        
        try:
            resp = session.get(target, params={'q': unicode_payload}, timeout=10)
            
            bypassed = not self.is_blocked(resp)
            
            return {
                'success': True,
                'bypass': bypassed,
                'response': resp,
                'technique': self.name,
                'reason': 'Unicode fullwidth characters bypassed filter' if bypassed else 'Blocked',
                'severity': 'HIGH' if bypassed else 'INFO',
                'payload': unicode_payload
            }
        except Exception as e:
            return {
                'success': False,
                'bypass': False,
                'response': None,
                'technique': self.name,
                'reason': str(e),
                'severity': 'INFO'
            }


# Register the plugin (required)
PLUGIN_CLASS = UnicodeBypassPlugin
'''
            try:
                with open(example_path, 'w', encoding='utf-8') as f:
                    f.write(example_code)
            except Exception:
                pass
    
    def discover_plugins(self) -> List[str]:
        """Discover all plugin files in the plugins directory."""
        plugin_files = []
        
        if not os.path.exists(self.plugins_dir):
            return plugin_files
        
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith('.py') and not filename.startswith('_'):
                plugin_files.append(os.path.join(self.plugins_dir, filename))
        
        return plugin_files
    
    def load_plugin(self, file_path: str) -> Optional[BypassPlugin]:
        """Load a plugin from a file."""
        try:
            # Calculate checksum for integrity
            with open(file_path, 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()
            
            # Load module
            module_name = os.path.splitext(os.path.basename(file_path))[0]
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            # Get the plugin class
            plugin_class = getattr(module, 'PLUGIN_CLASS', None)
            if plugin_class and issubclass(plugin_class, BypassPlugin):
                plugin = plugin_class()
                self.plugins[plugin.name] = plugin
                
                # Save to database
                if self.db:
                    self.db.save_plugin(
                        name=plugin.name,
                        version=plugin.version,
                        file_path=file_path,
                        author=plugin.author,
                        description=plugin.description,
                        category=plugin.category,
                        source='local',
                        checksum=checksum
                    )
                
                return plugin
        except Exception as e:
            print(f"[!] Failed to load plugin {file_path}: {e}")
        
        return None
    
    def load_all_plugins(self):
        """Load all discovered plugins."""
        for file_path in self.discover_plugins():
            self.load_plugin(file_path)
    
    def get_plugin(self, name: str) -> Optional[BypassPlugin]:
        """Get a loaded plugin by name."""
        return self.plugins.get(name)
    
    def get_enabled_plugins(self) -> List[BypassPlugin]:
        """Get all enabled plugins."""
        return [p for p in self.plugins.values() if p.enabled]
    
    def get_plugins_by_category(self, category: str) -> List[BypassPlugin]:
        """Get plugins filtered by category."""
        return [p for p in self.plugins.values() if p.category == category]
    
    def get_plugins_for_waf(self, waf_type: str) -> List[BypassPlugin]:
        """Get plugins compatible with a specific WAF."""
        return [
            p for p in self.plugins.values()
            if not p.compatible_wafs or waf_type.lower() in [w.lower() for w in p.compatible_wafs]
        ]
    
    def run_plugin(self, plugin_name: str, target: str, session: Any, **kwargs) -> Dict[str, Any]:
        """Run a specific plugin."""
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            return {'success': False, 'reason': 'Plugin not found'}
        
        if not plugin.enabled:
            return {'success': False, 'reason': 'Plugin is disabled'}
        
        try:
            result = plugin.execute(target, session, **kwargs)
            plugin.last_run = datetime.now()
            
            if result.get('success'):
                plugin.success_count += 1
            else:
                plugin.fail_count += 1
            
            # Update database stats
            if self.db:
                self.db.update_plugin_stats(plugin_name, result.get('success', False))
            
            return result
        except Exception as e:
            plugin.fail_count += 1
            return {'success': False, 'reason': str(e)}
    
    def run_all_enabled(self, target: str, session: Any, **kwargs) -> List[Dict[str, Any]]:
        """Run all enabled plugins against a target."""
        results = []
        for plugin in self.get_enabled_plugins():
            if plugin.validate_target(target):
                result = self.run_plugin(plugin.name, target, session, **kwargs)
                result['plugin_name'] = plugin.name
                results.append(result)
        return results
    
    def enable_plugin(self, name: str):
        """Enable a plugin."""
        if name in self.plugins:
            self.plugins[name].enabled = True
            if self.db:
                self.db.toggle_plugin(name, True)
    
    def disable_plugin(self, name: str):
        """Disable a plugin."""
        if name in self.plugins:
            self.plugins[name].enabled = False
            if self.db:
                self.db.toggle_plugin(name, False)
    
    def uninstall_plugin(self, name: str) -> bool:
        """Uninstall a plugin."""
        plugin = self.plugins.get(name)
        if not plugin:
            return False
        
        # Find and remove the plugin file
        for file_path in self.discover_plugins():
            loaded = self.load_plugin(file_path)
            if loaded and loaded.name == name:
                try:
                    os.remove(file_path)
                except Exception:
                    pass
        
        # Remove from memory
        del self.plugins[name]
        
        # Remove from database
        if self.db:
            self.db.delete_plugin(name)
        
        return True
    
    def get_plugin_info(self) -> List[Dict[str, Any]]:
        """Get info about all plugins."""
        return [p.to_dict() for p in self.plugins.values()]


# Community Plugin Marketplace (placeholder for future implementation)
class PluginMarketplace:
    """Interface to the WAFPierce community plugin marketplace."""
    
    MARKETPLACE_URL = "https://wafpierce.github.io/plugins"  # Placeholder
    
    def __init__(self, manager: PluginManager):
        self.manager = manager
        self.cache: Dict[str, Any] = {}
    
    def search(self, query: str = '', category: str = None) -> List[Dict[str, Any]]:
        """Search for plugins in the marketplace."""
        # Placeholder - would fetch from actual marketplace API
        return [
            {
                'name': 'Advanced SQL Bypass',
                'version': '2.0.0',
                'author': 'SecurityResearcher',
                'description': 'Advanced SQL injection bypass techniques',
                'category': 'injection',
                'downloads': 1250,
                'rating': 4.8,
                'compatible_wafs': ['cloudflare', 'aws_waf', 'imperva']
            },
            {
                'name': 'XSS Filter Evasion',
                'version': '1.5.0',
                'author': 'XSSHunter',
                'description': 'Comprehensive XSS filter bypass techniques',
                'category': 'encoding',
                'downloads': 890,
                'rating': 4.5,
                'compatible_wafs': ['akamai', 'cloudflare']
            },
            {
                'name': 'Request Smuggling Toolkit',
                'version': '1.0.0',
                'author': 'HTTPExpert',
                'description': 'HTTP Request Smuggling techniques',
                'category': 'protocol',
                'downloads': 450,
                'rating': 4.7,
                'compatible_wafs': ['aws_alb', 'nginx']
            }
        ]
    
    def get_plugin_details(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed info about a marketplace plugin."""
        plugins = self.search()
        for p in plugins:
            if p['name'] == name:
                return p
        return None
    
    def install(self, name: str) -> bool:
        """Install a plugin from the marketplace."""
        # Placeholder - would download and install from marketplace
        print(f"[*] Installing plugin '{name}' from marketplace...")
        print("[!] Marketplace installation is not yet implemented.")
        print(f"[*] You can manually download plugins and place them in: {self.manager.plugins_dir}")
        return False
    
    def check_updates(self) -> List[Dict[str, Any]]:
        """Check for updates to installed plugins."""
        updates = []
        # Placeholder - would check each installed plugin against marketplace
        return updates
