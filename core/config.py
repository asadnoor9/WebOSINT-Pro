"""
WebOSINT Pro - Configuration Manager
"""

import os
import json
from pathlib import Path


PROFILE_SETTINGS = {
    'safe': {
        'threads': 5,
        'timeout': 15,
        'delay': 1.0,
        'rate_limit': 20,
        'aggressive': False,
        'passive_only': True,
        'stealth': False,
        'modules_blacklist': ['ports', 'waf', 'ids'],
    },
    'medium': {
        'threads': 10,
        'timeout': 10,
        'delay': 0.3,
        'rate_limit': 50,
        'aggressive': False,
        'passive_only': False,
        'stealth': False,
        'modules_blacklist': [],
    },
    'aggressive': {
        'threads': 25,
        'timeout': 8,
        'delay': 0.0,
        'rate_limit': 200,
        'aggressive': True,
        'passive_only': False,
        'stealth': False,
        'modules_blacklist': [],
    },
    'stealth': {
        'threads': 3,
        'timeout': 20,
        'delay': 3.0,
        'rate_limit': 10,
        'aggressive': False,
        'passive_only': False,
        'stealth': True,
        'modules_blacklist': [],
        'randomize_order': True,
        'jitter': 2.0,
    },
}

ALL_MODULES = [
    'dns', 'ip', 'whois', 'subdomains', 'http', 'ssl',
    'ports', 'dirs', 'webapp', 'javascript', 'api',
    'websocket', 'database', 'mail', 'waf', 'ids',
    'siem', 'honeypot', 'cve', 'osint',
]

DEFAULT_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
]


class Config:
    def __init__(self, args):
        self.target = args.target
        self.targets_file = getattr(args, 'targets_file', None)
        self.profile = args.profile
        self.verbose = args.verbose
        self.no_external = args.no_external
        self.proxy = getattr(args, 'proxy', None)
        self.shodan_key = getattr(args, 'shodan_key', None)
        self.nvd_key = getattr(args, 'nvd_key', None)

        # Dirs
        self.output_dir = getattr(args, 'output_dir', 'reports')
        self.report_format = getattr(args, 'output', 'both')
        self.report_name = getattr(args, 'report_name', None)
        self.log_dir = 'logs'
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)

        # Profile defaults
        profile = PROFILE_SETTINGS[self.profile]
        self.threads = getattr(args, 'threads', None) or profile['threads']
        self.timeout = getattr(args, 'timeout', None) or profile['timeout']
        self.delay = getattr(args, 'delay', None) or profile['delay']
        self.rate_limit = getattr(args, 'rate_limit', None) or profile['rate_limit']
        self.retries = getattr(args, 'retries', 2)
        self.aggressive = profile['aggressive']
        self.passive_only = profile['passive_only']
        self.stealth = profile['stealth']
        self.jitter = profile.get('jitter', 0.0)
        self.randomize_order = profile.get('randomize_order', False)
        self.profile_modules_blacklist = profile.get('modules_blacklist', [])

        # Modules
        mod_arg = getattr(args, 'modules', 'all')
        skip_arg = getattr(args, 'skip_modules', '')
        if mod_arg == 'all':
            self.modules = list(ALL_MODULES)
        else:
            self.modules = [m.strip() for m in mod_arg.split(',') if m.strip()]

        skip = [m.strip() for m in skip_arg.split(',') if m.strip()]
        skip += self.profile_modules_blacklist
        self.modules = [m for m in self.modules if m not in skip]

        # Wordlists
        self.wordlist = getattr(args, 'wordlist', None) or self._default_wordlist('subdomains.txt')
        self.dir_wordlist = getattr(args, 'dir_wordlist', None) or self._default_wordlist('directories.txt')

        # User agent
        self.user_agent = getattr(args, 'user_agent', None) or DEFAULT_USER_AGENTS[0]

        # Load config file overrides
        config_file = getattr(args, 'config', 'config.json')
        if os.path.exists(config_file):
            self._load_file(config_file)

    def _default_wordlist(self, name):
        base = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wordlists', name)
        return base if os.path.exists(base) else None

    def _load_file(self, path):
        try:
            with open(path) as f:
                data = json.load(f)
            for k, v in data.items():
                if hasattr(self, k):
                    setattr(self, k, v)
        except Exception:
            pass

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()
                if not k.startswith('_') and not callable(v)}
