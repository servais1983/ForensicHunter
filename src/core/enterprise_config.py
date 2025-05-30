"""
ForensicHunter Enterprise Configuration
Advanced target and module system inspired by KAPE but significantly enhanced
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import yaml
import json

class ForensicTarget:
    """Enhanced forensic target (KAPE-inspired but more powerful)"""
    
    def __init__(self, name: str, description: str, author: str, version: str):
        self.name = name
        self.description = description
        self.author = author
        self.version = version
        self.category = ""
        self.paths = []
        self.masks = []
        self.recursive = False
        self.max_depth = 0
        self.file_filters = []
        self.size_limits = {}
        self.created = datetime.now()
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'description': self.description,
            'author': self.author,
            'version': self.version,
            'category': self.category,
            'paths': self.paths,
            'masks': self.masks,
            'recursive': self.recursive,
            'max_depth': self.max_depth,
            'file_filters': self.file_filters,
            'size_limits': self.size_limits,
            'created': self.created.isoformat()
        }

class ForensicModule:
    """Enhanced forensic module (KAPE-inspired but more powerful)"""
    
    def __init__(self, name: str, description: str, author: str, version: str):
        self.name = name
        self.description = description
        self.author = author
        self.version = version
        self.category = ""
        self.executable = ""
        self.command_line = ""
        self.expected_output = []
        self.processors = []
        self.dependencies = []
        self.timeout = 300  # 5 minutes default
        self.priority = "NORMAL"
        self.created = datetime.now()
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'description': self.description,
            'author': self.author,
            'version': self.version,
            'category': self.category,
            'executable': self.executable,
            'command_line': self.command_line,
            'expected_output': self.expected_output,
            'processors': self.processors,
            'dependencies': self.dependencies,
            'timeout': self.timeout,
            'priority': self.priority,
            'created': self.created.isoformat()
        }

class EnterpriseConfig:
    """Enterprise configuration manager"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "config/enterprise.yaml"
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load enterprise configuration"""
        default_config = {
            'forensichunter': {
                'version': '2.0.0-enterprise',
                'name': 'ForensicHunter Enterprise',
                'description': 'Advanced Digital Forensics Platform',
                'author': 'ForensicHunter Team'
            },
            'database': {
                'url': 'postgresql://fh_user:fh_pass@localhost/forensichunter',
                'pool_size': 20,
                'max_overflow': 30,
                'echo': False
            },
            'redis': {
                'url': 'redis://localhost:6379/0',
                'max_connections': 100
            },
            'security': {
                'secret_key': 'your-secret-key-change-in-production',
                'algorithm': 'HS256',
                'access_token_expire_minutes': 60,
                'refresh_token_expire_days': 30,
                'password_min_length': 12,
                'require_2fa': True
            },
            'forensics': {
                'max_concurrent_collections': 5,
                'max_file_size_mb': 1024,  # 1GB
                'max_total_size_gb': 100,  # 100GB
                'supported_formats': [
                    'raw', 'dd', 'e01', 'ex01', 'vmdk', 'vhd', 'vhdx'
                ],
                'volatility_symbols': '/opt/volatility3/symbols',
                'yara_rules': '/opt/forensichunter/rules'
            },
            'storage': {
                'evidence_path': '/opt/forensichunter/evidence',
                'reports_path': '/opt/forensichunter/reports',
                'temp_path': '/tmp/forensichunter',
                'backup_enabled': True,
                'compression_enabled': True,
                'encryption_enabled': True
            },
            'logging': {
                'level': 'INFO',
                'format': 'json',
                'file': '/var/log/forensichunter/forensichunter.log',
                'max_size': '100MB',
                'backup_count': 10,
                'syslog_enabled': True,
                'siem_enabled': False,
                'siem_endpoint': 'https://your-siem.com/api/logs'
            },
            'api': {
                'host': '0.0.0.0',
                'port': 8000,
                'workers': 4,
                'cors_origins': [],
                'rate_limit': '100/minute',
                'docs_enabled': True
            },
            'monitoring': {
                'prometheus_enabled': True,
                'prometheus_port': 9090,
                'health_check_interval': 30,
                'metrics_retention_days': 90
            }
        }
        
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    loaded_config = yaml.safe_load(f)
                    # Merge with defaults
                    return self._merge_configs(default_config, loaded_config)
            else:
                # Create default config file
                os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    yaml.dump(default_config, f, default_flow_style=False)
                return default_config
        except Exception as e:
            print(f"Error loading config: {e}, using defaults")
            return default_config
    
    def _merge_configs(self, default: Dict, override: Dict) -> Dict:
        """Deep merge configuration dictionaries"""
        result = default.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        return result
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def save(self):
        """Save current configuration"""
        with open(self.config_path, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, default_flow_style=False)

# Enhanced Target Definitions (KAPE-inspired but more comprehensive)
ENTERPRISE_TARGETS = {
    "WindowsSystemFiles": {
        "name": "Windows System Files",
        "description": "Critical Windows system files and registry hives",
        "author": "ForensicHunter Team",
        "version": "2.0",
        "category": "System",
        "paths": [
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SECURITY",
            "C:\\Windows\\System32\\config\\SOFTWARE", 
            "C:\\Windows\\System32\\config\\SYSTEM",
            "C:\\Windows\\System32\\config\\DEFAULT",
            "C:\\Windows\\System32\\config\\RegBack\\*",
            "C:\\Windows\\System32\\config\\systemprofile\\*"
        ],
        "priority": "CRITICAL",
        "size_limits": {"max_file_size": "500MB"}
    },
    
    "WindowsEventLogs": {
        "name": "Windows Event Logs",
        "description": "All Windows Event Log files (.evtx)",
        "author": "ForensicHunter Team", 
        "version": "2.0",
        "category": "Logs",
        "paths": [
            "C:\\Windows\\System32\\winevt\\Logs\\*.evtx"
        ],
        "recursive": True,
        "priority": "HIGH"
    },
    
    "WindowsPrefetch": {
        "name": "Windows Prefetch",
        "description": "Windows Prefetch files showing program execution",
        "author": "ForensicHunter Team",
        "version": "2.0", 
        "category": "Execution",
        "paths": [
            "C:\\Windows\\Prefetch\\*.pf",
            "C:\\Windows\\Prefetch\\Layout.ini",
            "C:\\Windows\\Prefetch\\ReadyBoot\\*"
        ],
        "priority": "HIGH"
    },
    
    "UserProfiles": {
        "name": "User Profile Artifacts",
        "description": "User registry hives and profile data",
        "author": "ForensicHunter Team",
        "version": "2.0",
        "category": "Users",
        "paths": [
            "C:\\Users\\*\\NTUSER.DAT",
            "C:\\Users\\*\\NTUSER.DAT.LOG*",
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat*",
            "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*",
            "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Office\\Recent\\*"
        ],
        "recursive": True,
        "max_depth": 3,
        "priority": "HIGH"
    },
    
    "BrowserArtifacts": {
        "name": "Web Browser Artifacts", 
        "description": "Comprehensive browser history and data",
        "author": "ForensicHunter Team",
        "version": "2.0",
        "category": "Internet",
        "paths": [
            # Chrome
            "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\History*",
            "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Cookies*",
            "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Bookmarks*",
            "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Login Data*",
            "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Web Data*",
            # Firefox
            "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\*.sqlite*",
            "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite*",
            "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\cookies.sqlite*",
            # Edge
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\History*",
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\Cookies*",
            # IE/WebCache
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\WebCache\\*",
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\*",
            "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCookies\\*"
        ],
        "recursive": True,
        "max_depth": 5,
        "priority": "MEDIUM"
    },
    
    "NTFSArtifacts": {
        "name": "NTFS File System Artifacts",
        "description": "NTFS metadata and journal files",
        "author": "ForensicHunter Team",
        "version": "2.0",
        "category": "FileSystem", 
        "paths": [
            "C:\\$MFT",
            "C:\\$LogFile",
            "C:\\$Volume", 
            "C:\\$AttrDef",
            "C:\\$Bitmap",
            "C:\\$Boot",
            "C:\\$BadClus",
            "C:\\$Secure",
            "C:\\$UpCase",
            "C:\\$Extend\\$ObjId",
            "C:\\$Extend\\$Quota", 
            "C:\\$Extend\\$Reparse",
            "C:\\$Extend\\$UsnJrnl"
        ],
        "priority": "CRITICAL"
    },
    
    "ScheduledTasks": {
        "name": "Scheduled Tasks",
        "description": "Windows Task Scheduler artifacts",
        "author": "ForensicHunter Team",
        "version": "2.0",
        "category": "Persistence",
        "paths": [
            "C:\\Windows\\Tasks\\*",
            "C:\\Windows\\System32\\Tasks\\*"
        ],
        "recursive": True,
        "priority": "MEDIUM"
    },
    
    "StartupItems": {
        "name": "Startup and Persistence Items",
        "description": "Various Windows startup and persistence mechanisms",
        "author": "ForensicHunter Team", 
        "version": "2.0",
        "category": "Persistence",
        "paths": [
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
            "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
            "C:\\Windows\\System32\\drivers\\*",
            "C:\\Windows\\System32\\wbem\\Repository\\*"
        ],
        "recursive": True,
        "max_depth": 2,
        "priority": "MEDIUM"
    }
}

# Enhanced Module Definitions (KAPE-inspired processing)
ENTERPRISE_MODULES = {
    "VolatilityMemoryAnalysis": {
        "name": "Volatility 3 Memory Analysis",
        "description": "Advanced memory dump analysis using Volatility 3",
        "author": "ForensicHunter Team",
        "version": "2.0",
        "category": "Memory",
        "executable": "vol.py",
        "command_line": "-f {input_file} -o {output_dir} {plugin}",
        "expected_output": ["json", "txt"],
        "priority": "HIGH",
        "timeout": 1800  # 30 minutes
    },
    
    "YaraScanning": {
        "name": "YARA Malware Detection",
        "description": "Scan files with YARA rules for malware detection",
        "author": "ForensicHunter Team",
        "version": "2.0", 
        "category": "Malware",
        "executable": "yara",
        "command_line": "-r {rules_dir} {target_dir}",
        "expected_output": ["txt", "json"],
        "priority": "HIGH",
        "timeout": 900  # 15 minutes
    },
    
    "RegistryAnalysis": {
        "name": "Registry Hive Analysis", 
        "description": "Parse and analyze Windows registry hives",
        "author": "ForensicHunter Team",
        "version": "2.0",
        "category": "Registry",
        "executable": "python",
        "command_line": "forensichunter/modules/registry_parser.py {input_file}",
        "expected_output": ["json", "csv"],
        "priority": "HIGH",
        "timeout": 600  # 10 minutes
    },
    
    "EventLogAnalysis": {
        "name": "Windows Event Log Analysis",
        "description": "Parse and analyze Windows Event Logs",
        "author": "ForensicHunter Team",
        "version": "2.0",
        "category": "Logs",
        "executable": "python",
        "command_line": "forensichunter/modules/eventlog_parser.py {input_file}",
        "expected_output": ["json", "csv"],
        "priority": "MEDIUM", 
        "timeout": 600  # 10 minutes
    },
    
    "TimelineGeneration": {
        "name": "Forensic Timeline Generation",
        "description": "Generate comprehensive forensic timeline",
        "author": "ForensicHunter Team",
        "version": "2.0",
        "category": "Timeline",
        "executable": "python", 
        "command_line": "forensichunter/modules/timeline_generator.py {evidence_dir}",
        "expected_output": ["csv", "json", "html"],
        "priority": "MEDIUM",
        "timeout": 1200  # 20 minutes
    }
}