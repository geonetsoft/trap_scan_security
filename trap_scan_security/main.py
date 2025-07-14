import os
import argparse
import configparser
import shutil
import logging
from logging.handlers import RotatingFileHandler
import datetime
import stat
import sys
import json

# Define default configuration path and quarantine directory
DEFAULT_CONFIG_PATH = '/etc/trap_scan/config.ini'
DEFAULT_QUARANTINE_DIR = '/var/quarantine_trap_scan'
DEFAULT_LOG_FILE = '/var/log/trap_scan.log'
DEFAULT_SCANNED_CACHE_FILE = '/var/lib/trap_scan/scanned_cache.json'
DEFAULT_JSON_LOG_FILE = '/var/log/trap_scan_json.log' # Added for JSON logging

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
        self.json_log_file = self.config['LOGGING'].get('json_log_file', DEFAULT_JSON_LOG_FILE) # Added
        self.scanned_cache_file = self.config['CACHE'].get('scanned_cache_file', DEFAULT_SCANNED_CACHE_FILE)

    def _create_default_config(self):
        # Ensure directories exist for default config and logs if not present
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        # Use default constants directly for directory creation as attributes are not set yet
        os.makedirs(os.path.dirname(DEFAULT_LOG_FILE), exist_ok=True)
        os.makedirs(os.path.dirname(DEFAULT_SCANNED_CACHE_FILE), exist_ok=True)
        os.makedirs(DEFAULT_QUARANTINE_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(DEFAULT_JSON_LOG_FILE), exist_ok=True) # Added

        self.config['SCAN'] = {
            'target_directories': '/var/www/html,/home/cpanel_user/public_html',
            'suspicion_threshold': '5'
        }
        self.config['LOGGING'] = {
            'log_file': DEFAULT_LOG_FILE,
            'json_log_file': DEFAULT_JSON_LOG_FILE # Added
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

def setup_logging(log_file, json_log_file): # Modified to accept json_log_file
    log_dir = os.path.dirname(log_file)
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(os.path.dirname(json_log_file), exist_ok=True) # Ensure JSON log directory exists

    logger = logging.getLogger('trap_scan')
    logger.setLevel(logging.INFO)

    # Clear existing handlers to prevent duplicate logs
    if logger.hasHandlers():
        logger.handlers.clear()

    # Human-readable file handler
    file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # JSON file handler
    json_handler = RotatingFileHandler(json_log_file, maxBytes=5*1024*1024, backupCount=5)
    # The 'message' part expects a JSON string, which log_event will provide via `extra`
    json_formatter = logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}')
    json_handler.setFormatter(json_formatter)
    logger.addHandler(json_handler)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger

def log_event(message, level="INFO", log_file=DEFAULT_LOG_FILE, json_log_file=DEFAULT_JSON_LOG_FILE): # Modified
    # Re-setup logging to ensure all handlers are correct (including JSON)
    logger = setup_logging(log_file, json_log_file) # Pass json_log_file

    # Prepare message for human-readable log (simple string)
    human_readable_message = message

    # Prepare message for JSON log (structured dictionary)
    json_data = {
        "event_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_level": level,
        "raw_message": message # Keep the original message for debugging
    }
    
    # Add more context to JSON log for specific events
    if "SUSPECT" in message:
        json_data["type"] = "suspicious_file_detected"
        # Safely extract file_path and suspicion_score
        parts = message.split("'")
        if len(parts) > 1:
            json_data["file_path"] = parts[1]
        score_match = re.search(r'Score: (\d+)', message)
        if score_match:
            json_data["suspicion_score"] = int(score_match.group(1))
    elif "CLEAN" in message:
        json_data["type"] = "file_scanned_clean"
        parts = message.split("'")
        if len(parts) > 1:
            json_data["file_path"] = parts[1]
        score_match = re.search(r'Score: (\d+)', message)
        if score_match:
            json_data["suspicion_score"] = int(score_match.group(1))
    elif "Eroare la scanarea fișierului" in message:
        json_data["type"] = "file_scan_error"
        parts = message.split("'")
        if len(parts) > 1:
            json_data["file_path"] = parts[1]
        json_data["error_details"] = message.split(":", 1)[1].strip() if ":" in message else message
    elif "Fișier carantinat" in message:
        json_data["type"] = "file_quarantined"
        parts = message.split("'")
        if len(parts) > 3: # Expecting 'filepath' and 'quarantine_path'
            json_data["original_path"] = parts[1]
            json_data["quarantine_path"] = parts[3]
        else:
            json_data["details"] = message # Fallback if parsing fails
    elif "job adăugat" in message or "Systemd" in message: # For scheduler setup messages
        json_data["type"] = "scheduler_configuration"
        json_data["details"] = message
    elif "Pornind scanarea" in message:
        json_data["type"] = "scan_start"
    elif "Scanare finalizată" in message:
        json_data["type"] = "scan_complete"
    elif "Fișier de configurare implicit creat" in message:
        json_data["type"] = "config_initialized"
        json_data["config_path"] = DEFAULT_CONFIG_PATH
    elif "Fișier de configurare suprascris" in message:
        json_data["type"] = "config_overwritten"
        json_data["config_path"] = DEFAULT_CONFIG_PATH
    elif "Alegere invalidă" in message:
        json_data["type"] = "invalid_scheduler_choice"

    json_message_str = json.dumps(json_data, ensure_ascii=False) # Convert dict to JSON string

    if level == "INFO":
        logger.info(human_readable_message, extra={'message': json_message_str})
    elif level == "WARNING":
        logger.warning(human_readable_message, extra={'message': json_message_str})
    elif level == "ERROR":
        logger.error(human_readable_message, extra={'message': json_message_str})
    elif level == "CRITICAL":
        logger.critical(human_readable_message, extra={'message': json_message_str})
    else:
        logger.debug(human_readable_message, extra={'message': json_message_str})


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
            log_event(f"SUSPECT: '{filepath}' - Score: {suspicion_score}", "WARNING", app_config.log_file, app_config.json_log_file)
            return True
        else:
            log_event(f"CLEAN: '{filepath}' - Score: {suspicion_score}", "INFO", app_config.log_file, app_config.json_log_file)
            return False
    except Exception as e:
        log_event(f"Eroare la scanarea fișierului '{filepath}': {e}", "ERROR", app_config.log_file, app_config.json_log_file)
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
        log_event(f"Eroare la citirea cache-ului '{cache_file}': {e}", "ERROR", DEFAULT_LOG_FILE, DEFAULT_JSON_LOG_FILE)
        return {}

def save_scanned_files_cache(cache_file, cache):
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache, f, indent=4)
    except Exception as e:
        log_event(f"Eroare la salvarea cache-ului '{cache_file}': {e}", "ERROR", DEFAULT_LOG_FILE, DEFAULT_JSON_LOG_FILE)


def scan_directory(directory, app_config, scanned_cache):
    if not os.path.isdir(directory):
        log_event(f"Directorul '{directory}' nu există sau nu este un director valid.", "ERROR", app_config.log_file, app_config.json_log_file)
        return

    log_event(f"Începe scanarea directorului: {directory}", "INFO", app_config.log_file, app_config.json_log_file)
    
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            
            # Skip if recently scanned and not modified
            if filepath in scanned_cache and \
               os.path.getmtime(filepath) == scanned_cache[filepath]:
                # log_event(f"Skipping unmodified file: '{filepath}'", "DEBUG", app_config.log_file, app_config.json_log_file) # Too verbose for debug
                continue
            
            # Check for common web file extensions
            if not any(filepath.lower().endswith(ext) for ext in ['.php', '.html', '.js', '.css', '.htaccess', '.py', '.pl', '.rb']):
                # log_event(f"Skipping non-web file: '{filepath}'", "DEBUG", app_config.log_file, app_config.json_log_file) # Too verbose for debug
                continue

            try:
                if scan_file(filepath, app_config):
                    quarantine_file(filepath, app_config)
                scanned_cache[filepath] = os.path.getmtime(filepath)
            except Exception as e:
                log_event(f"Eroare generală la procesarea fișierului '{filepath}': {e}", "ERROR", app_config.log_file, app_config.json_log_file)
    
    log_event(f"Scanare terminată pentru directorul: {directory}", "INFO", app_config.log_file, app_config.json_log_file)


def quarantine_file(filepath, app_config):
    try:
        os.makedirs(app_config.quarantine_dir, exist_ok=True)
        filename = os.path.basename(filepath)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_path = os.path.join(app_config.quarantine_dir, f"{filename}.{timestamp}.quarantined")
        
        shutil.move(filepath, quarantine_path)
        log_event(f"Fișier carantinat: '{filepath}' mutat la '{quarantine_path}'", "WARNING", app_config.log_file, app_config.json_log_file)
        
        # Optionally, leave a placeholder file
        with open(filepath + ".QUARANTINED", "w") as f:
            f.write(f"Acest fișier a fost mutat în carantină de Trap Scan Security la {timestamp}. Locație originală: {filepath}. Locație carantină: {quarantine_path}")
        
    except Exception as e:
        log_event(f"Eroare la carantinarea fișierului '{filepath}': {e}", "ERROR", app_config.log_file, app_config.json_log_file)

def run_scan(app_config):
    log_event("Pornind scanarea Trap Scan Security...", "INFO", app_config.log_file, app_config.json_log_file)
    scanned_cache = get_scanned_files_cache(app_config.scanned_cache_file)

    for directory in app_config.target_directories:
        scan_directory(directory, app_config, scanned_cache)
    
    save_scanned_files_cache(app_config.scanned_cache_file, scanned_cache)
    log_event("Scanare Trap Scan Security finalizată.", "INFO", app_config.log_file, app_config.json_log_file)

def setup_scheduler_command(app_config, args):
    print("\n--- Setare Rulare Programată (Scheduler) ---")
    print("Această funcție va configura fie Cron (recomandat pentru simplitate) fie Systemd Timer (mai avansat).")

    # Calea absolută a acestui script (main.py)
    current_script_path = os.path.abspath(__file__)
    # Calea către directorul rădăcină al pachetului trap_scan_security
    # Mergem înapoi din trap_scan_security/trap_scan_security/main.py -> trap_scan_security/trap_scan_security/
    # Apoi încă o dată înapoi -> trap_scan_security/ (care e directorul pachetului Python instalat)
    # Apoi încă o dată înapoi la rădăcina proiectului unde este venv
    # Adică, 4 nivele înapoi de la `main.py`
    package_root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_script_path))))
    
    # Calea către executabilul trap-scan în mediul virtual
    executable_path = os