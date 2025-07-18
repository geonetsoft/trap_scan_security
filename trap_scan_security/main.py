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
import re # Added for improved parsing in log_event

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
        self.project_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # Correctly defined
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
        self.json_log_file = self.config['LOGGING'].get('json_log_file', DEFAULT_JSON_LOG_FILE)
        self.scanned_cache_file = self.config['CACHE'].get('scanned_cache_file', DEFAULT_SCANNED_CACHE_FILE)

    def _create_default_config(self):
        # Ensure directories exist for default config and logs if not present
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        # Use default constants directly for directory creation as attributes are not set yet
        os.makedirs(os.path.dirname(DEFAULT_LOG_FILE), exist_ok=True)
        os.makedirs(os.path.dirname(DEFAULT_SCANNED_CACHE_FILE), exist_ok=True)
        os.makedirs(DEFAULT_QUARANTINE_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(DEFAULT_JSON_LOG_FILE), exist_ok=True)

        self.config['SCAN'] = {
            'target_directories': '/var/www/html,/home/cpanel_user/public_html',
            'suspicion_threshold': '5'
        }
        self.config['LOGGING'] = {
            'log_file': DEFAULT_LOG_FILE,
            'json_log_file': DEFAULT_JSON_LOG_FILE
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

def setup_logging(log_file, json_log_file):
    log_dir = os.path.dirname(log_file)
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(os.path.dirname(json_log_file), exist_ok=True)

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
    json_formatter = logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s", "json_payload": %(json_payload)s}')
    json_handler.setFormatter(json_formatter)
    logger.addHandler(json_handler)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger

def log_event(message, level="INFO", log_file=DEFAULT_LOG_FILE, json_log_file=DEFAULT_JSON_LOG_FILE):
    logger = setup_logging(log_file, json_log_file)

    human_readable_message = message
    
    json_data = {
        "event_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_level": level,
        "raw_message": message
    }
    
    # Add more context to JSON log for specific events
    if "SUSPECT" in message:
        json_data["type"] = "suspicious_file_detected"
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
        if len(parts) > 3:
            json_data["original_path"] = parts[1]
            json_data["quarantine_path"] = parts[3]
        else:
            json_data["details"] = message
    elif "job adăugat" in message or "Systemd" in message:
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

    json_message_str = json.dumps(json_data, ensure_ascii=False)

    if level == "INFO":
        logger.info(human_readable_message, extra={'json_payload': json_message_str})
    elif level == "WARNING":
        logger.warning(human_readable_message, extra={'json_payload': json_message_str})
    elif level == "ERROR":
        logger.error(human_readable_message, extra={'json_payload': json_message_str})
    elif level == "CRITICAL":
        logger.critical(human_readable_message, extra={'json_payload': json_message_str}) # Corrected 'eextra' to 'extra'
    else:
        logger.debug(human_readable_message, extra={'json_payload': json_message_str})


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
                continue
            
            # Check for common web file extensions
            if not any(filepath.lower().endswith(ext) for ext in ['.php', '.html', '.js', '.css', '.htaccess', '.py', '.pl', '.rb']):
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
    # Aceasta este acum obținută din app_config.project_root_dir
    package_root_dir = app_config.project_root_dir # Use the attribute from AppConfig
    
    # Calea către executabilul trap-scan în mediul virtual
    executable_path = os.path.join(package_root_dir, "venv", "bin", "trap-scan")

    # Aici verificăm dacă calea executabilului este corectă
    if not os.path.exists(executable_path):
        log_event(f"Eroare: Executabilul '{executable_path}' nu a fost găsit. Asigurați-vă că mediul virtual este creat și pachetul este instalat în el.", "ERROR", app_config.log_file, app_config.json_log_file)
        print(f"\nEROARE: Executabilul '{executable_path}' nu a fost găsit.")
        print(f"Asigurați-vă că mediul virtual a fost creat (ex: `python3 -m venv venv`) și pachetul instalat în el (`source venv/bin/activate && pip install .`).")
        return

    print(f"\nComanda completă care va fi executată: {executable_path} scan")
    print("Asigurați-vă că fișierul de configurare este corect: /etc/trap_scan/config.ini")

    scheduler_type = input("Alegeți tipul de scheduler (1 pentru Cron, 2 pentru Systemd Timer): ")
    
    if scheduler_type == '1':
        print("\n--- Configurare Cron ---")
        print("Exemple de frecvențe: hourly, daily, weekly, monthly")
        print("Sau o expresie Cron (ex: '0 * * * *' pentru fiecare oră).")
        frequency = input("Introduceți frecvența de rulare (ex: daily, hourly, 0 * * * *): ")

        # Check if it's a special keyword or a numeric cron expression
        if frequency in ['hourly', 'daily', 'weekly', 'monthly', 'reboot']:
            cron_prefix = "@"
        else:
            cron_prefix = "" # No "@" for numeric expressions

        cron_entry = f"{cron_prefix} {frequency} {executable_path} scan >> {app_config.log_file} 2>&1"
        
        try:
            # Add to root's crontab
            os.system(f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -')
            log_event(f"Cron job adăugat: {cron_entry}", "INFO", app_config.log_file, app_config.json_log_file)
            print(f"Job Cron adăugat cu succes. Puteți verifica cu 'sudo crontab -l'.")
        except Exception as e:
            log_event(f"Eroare la adăugarea jobului Cron: {e}", "ERROR", app_config.log_file, app_config.json_log_file)
            print(f"Eroare la adăugarea jobului Cron: {e}")

    elif scheduler_type == '2':
        print("\n--- Configurare Systemd Timer ---")
        print("Exemple de frecvențe: 1h (every hour), 1d (every day), weekly, monthly")
        frequency = input("Introduceți frecvența de rulare (ex: 1h, 1d, weekly): ")
        
        # Create systemd service file
        service_content = f"""
[Unit]
Description=Trap Scan Security Scanner
After=network.target

[Service]
Type=oneshot # Added Type=oneshot for robustness
ExecStart={executable_path} scan
WorkingDirectory={package_root_dir}
StandardOutput=append:{app_config.log_file}
StandardError=append:{app_config.log_file}
User=root
Group=root

[Install]
WantedBy=multi-user.target
"""
        # Create systemd timer file
        timer_content = f"""
[Unit]
Description=Trap Scan Security Timer
RefuseManualStart=no
RefuseManualStop=no

[Timer]
OnBootSec=1min
OnUnitActiveSec={frequency}
Unit=trap-scan.service

[Install]
WantedBy=timers.target
"""
        service_path = "/etc/systemd/system/trap-scan.service"
        timer_path = "/etc/systemd/system/trap-scan.timer"

        try:
            with open(service_path, "w") as f:
                f.write(service_content)
            with open(timer_path, "w") as f:
                f.write(timer_content)

            os.system("systemctl daemon-reload")
            os.system("systemctl enable trap-scan.timer")
            os.system("systemctl start trap-scan.timer")
            
            log_event(f"Systemd service și timer create și activate. Serviciu: {service_path}, Timer: {timer_path}", "INFO", app_config.log_file, app_config.json_log_file)
            print(f"Systemd service și timer create și activate.")
            print(f"Puteți verifica statusul cu 'sudo systemctl status trap-scan.timer'.")
        except Exception as e:
            log_event(f"Eroare la configurarea Systemd: {e}", "ERROR", app_config.log_file, app_config.json_log_file)
            print(f"Eroare la configurarea Systemd: {e}")

    else:
        print("Alegere invalidă. Vă rugăm să alegeți 1 sau 2.")


def main():
    parser = argparse.ArgumentParser(description="Trap Scan Security - Un scaner de securitate pentru fișierele web.")
    parser.add_argument('--config', default=DEFAULT_CONFIG_PATH,
                        help=f"Calea către fișierul de configurare (implicit: {DEFAULT_CONFIG_PATH})")

    subparsers = parser.add_subparsers(dest='command', help='Comenzi disponibile')

    # Sub-parser for 'scan' command
    scan_parser = subparsers.add_parser('scan', help='Rulează o scanare a fișierelor specificate în configurare.')

    # Sub-parser for 'init-config' command
    init_config_parser = subparsers.add_parser('init-config', help=f'Creează un fișier de configurare implicit la {DEFAULT_CONFIG_PATH}.')

    # Sub-parser for 'setup-scheduler' command
    setup_scheduler_parser = subparsers.add_parser('setup-scheduler', help='Configurează o rulare programată (Cron sau Systemd Timer).')

    args = parser.parse_args()

    app_config = AppConfig(args.config)
    setup_logging(app_config.log_file, app_config.json_log_file)

    if args.command == 'scan':
        run_scan(app_config)
    elif args.command == 'init-config':
        if not os.path.exists(app_config.config_path):
            app_config._create_default_config()
        else:
            overwrite = input(f"Fișierul de configurare '{app_config.config_path}' există deja. Doriți să-l suprascrieți cu valorile implicite? (y/N): ").lower()
            if overwrite == 'y':
                app_config._create_default_config()
                log_event("Fișier de configurare suprascris cu valorile implicite.", "INFO", app_config.log_file, app_config.json_log_file)
            else:
                print("Operare anulată. Fișierul de configurare nu a fost modificat.")
                log_event("Creare fișier de configurare implicită anulată.", "INFO", app_config.log_file, app_config.json_log_file)
    elif args.command == 'setup-scheduler':
        setup_scheduler_command(app_config, args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()