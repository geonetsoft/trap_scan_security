import os
import argparse
import configparser
import shutil
import logging
from logging.handlers import RotatingFileHandler
import datetime
import stat
import sys
import json # Adăugat pentru a lucra cu fișierele cache JSON

# Define default configuration path and quarantine directory
DEFAULT_CONFIG_PATH = '/etc/trap_scan/config.ini'
DEFAULT_QUARANTINE_DIR = '/var/quarantine_trap_scan'
DEFAULT_LOG_FILE = '/var/log/trap_scan.log'
DEFAULT_SCANNED_CACHE_FILE = '/var/lib/trap_scan/scanned_cache.json'

class AppConfig:
    def __init__(self, config_path=DEFAULT_CONFIG_PATH):
        self.config = configparser.ConfigParser()
        self.config_path = config_path
        self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            self._create_default_config()
        self.config.read(self.config_path)

        # Set defaults if sections or keys are missing
        if 'SCAN' not in self.config:
            self.config['SCAN'] = {}
        if 'LOGGING' not in self.config:
            self.config['LOGGING'] = {}
        if 'QUARANTINE' not in self.config:
            self.config['QUARANTINE'] = {}
        if 'CACHE' not in self.config:
            self.config['CACHE'] = {}

        self.target_directories = self.config['SCAN'].get('target_directories', '').split(',')
        self.target_directories = [d.strip() for d in self.target_directories if d.strip()]
        self.suspicion_threshold = self.config['SCAN'].getint('suspicion_threshold', 5)
        self.quarantine_dir = self.config['QUARANTINE'].get('quarantine_dir', DEFAULT_QUARANTINE_DIR)
        self.log_file = self.config['LOGGING'].get('log_file', DEFAULT_LOG_FILE)
        self.scanned_cache_file = self.config['CACHE'].get('scanned_cache_file', DEFAULT_SCANNED_CACHE_FILE)

    def _create_default_config(self):
        # Ensure directories exist for default config and logs if not present
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.scanned_cache_file), exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)


        self.config['SCAN'] = {
            'target_directories': '/var/www/html,/home/cpanel_user/public_html',
            'suspicion_threshold': '5'
        }
        self.config['LOGGING'] = {
            'log_file': DEFAULT_LOG_FILE
        }
        self.config['QUARANTINE'] = {
            'quarantine_dir': DEFAULT_QUARANTINE_DIR
        }
        self.config['CACHE'] = {
            'scanned_cache_file': DEFAULT_SCANNED_CACHE_FILE
        }
        with open(self.config_path, 'w') as configfile:
            self.config.write(configfile)
        print(f"Fișier de configurare implicit creat la: {self.config_path}")
        print(f"Asigurați-vă că 'target_directories' sunt setate corect în '{self.config_path}'")

def setup_logging(log_file):
    log_dir = os.path.dirname(log_file)
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger('trap_scan')
    logger.setLevel(logging.INFO)

    # Use RotatingFileHandler for log rotation
    handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5) # 5MB per file, keep 5 backups
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # Clear existing handlers to prevent duplicate logs
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(handler)

    # Also log to console for immediate feedback
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger

def log_event(message, level="INFO", log_file=DEFAULT_LOG_FILE):
    logger = setup_logging(log_file) # Re-setup logging to ensure handlers are correct
    if level == "INFO":
        logger.info(message)
    elif level == "WARNING":
        logger.warning(message)
    elif level == "ERROR":
        logger.error(message)
    elif level == "CRITICAL":
        logger.critical(message)
    else:
        logger.debug(message) # Default to debug for unknown levels


def scan_file(filepath, app_config):
    """
    Simulează scanarea unui fișier pentru conținut malițios.
    Înlocuiește cu logica reală de scanare.
    Returnează True dacă este suspect, False altfel.
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Simple keyword-based detection (to be replaced by actual scanner logic)
        suspicious_keywords = [
            'eval(', 'base64_decode', 'shell_exec', 'system(', 'passthru',
            'exec(', 'assert(', 'str_rot13', 'gzinflate', 'file_put_contents',
            'chmod', 'unlink', 'wp_insert_user', 'add_action(.*,.*wp_.*_user)',
            'create_function', 'phar://', 'php://input', 'data://', 'error_reporting(0)',
            '$GLOBALS', '$_FILES', '$_POST', '$_GET', '$_REQUEST', '$_SERVER'
        ]
        
        suspicion_score = 0
        for keyword in suspicious_keywords:
            if keyword in content:
                suspicion_score += 1
        
        if suspicion_score >= app_config.suspicion_threshold:
            log_event(f"SUSPECT: '{filepath}' - Score: {suspicion_score}", "WARNING", app_config.log_file)
            return True
        else:
            log_event(f"CLEAN: '{filepath}' - Score: {suspicion_score}", "INFO", app_config.log_file)
            return False
    except Exception as e:
        log_event(f"Eroare la scanarea fișierului '{filepath}': {e}", "ERROR", app_config.log_file)
        return False

def get_scanned_files_cache(cache_file):
    if not os.path.exists(cache_file):
        return {}
    try:
        with open(cache_file, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}
    except Exception as e:
        log_event(f"Eroare la citirea cache-ului '{cache_file}': {e}", "ERROR", DEFAULT_LOG_FILE)
        return {}

def save_scanned_files_cache(cache_file, cache):
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache, f, indent=4)
    except Exception as e:
        log_event(f"Eroare la salvarea cache-ului '{cache_file}': {e}", "ERROR", DEFAULT_LOG_FILE)


def scan_directory(directory, app_config, scanned_cache):
    if not os.path.isdir(directory):
        log_event(f"Directorul '{directory}' nu există sau nu este un director valid.", "ERROR", app_config.log_file)
        return

    log_event(f"Începe scanarea directorului: {directory}", "INFO", app_config.log_file)
    
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            
            # Skip if recently scanned and not modified
            if filepath in scanned_cache and \
               os.path.getmtime(filepath) == scanned_cache[filepath]:
                # log_event(f"Skipping unmodified file: '{filepath}'", "DEBUG", app_config.log_file)
                continue
            
            # Check for common web file extensions
            if not any(filepath.lower().endswith(ext) for ext in ['.php', '.html', '.js', '.css', '.htaccess', '.py', '.pl', '.rb']):
                # log_event(f"Skipping non-web file: '{filepath}'", "DEBUG", app_config.log_file)
                continue

            try:
                if scan_file(filepath, app_config):
                    quarantine_file(filepath, app_config)
                scanned_cache[filepath] = os.path.getmtime(filepath)
            except Exception as e:
                log_event(f"Eroare generală la procesarea fișierului '{filepath}': {e}", "ERROR", app_config.log_file)
    
    log_event(f"Scanare terminată pentru directorul: {directory}", "INFO", app_config.log_file)


def quarantine_file(filepath, app_config):
    try:
        os.makedirs(app_config.quarantine_dir, exist_ok=True)
        filename = os.path.basename(filepath)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_path = os.path.join(app_config.quarantine_dir, f"{filename}.{timestamp}.quarantined")
        
        shutil.move(filepath, quarantine_path