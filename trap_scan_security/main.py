import os
import argparse
import configparser
import shutil
import logging
from logging.handlers import RotatingFileHandler
import datetime
import stat
import sys
import json # Added to work with JSON cache files

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
        # Use default constants directly for directory creation as attributes are not set yet
        os.makedirs(os.path.dirname(DEFAULT_LOG_FILE), exist_ok=True)
        os.makedirs(os.path.dirname(DEFAULT_SCANNED_CACHE_FILE), exist_ok=True)
        os.makedirs(DEFAULT_QUARANTINE_DIR, exist_ok=True)

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
        
        shutil.move(filepath, quarantine_path) # THIS IS LINE 204
        log_event(f"Fișier carantinat: '{filepath}' mutat la '{quarantine_path}'", "WARNING", app_config.log_file)
        
        # Optionally, leave a placeholder file
        with open(filepath + ".QUARANTINED", "w") as f:
            f.write(f"Acest fișier a fost mutat în carantină de Trap Scan Security la {timestamp}. Locație originală: {filepath}. Locație carantină: {quarantine_path}")
        
    except Exception as e:
        log_event(f"Eroare la carantinarea fișierului '{filepath}': {e}", "ERROR", app_config.log_file)

def run_scan(app_config):
    log_event("Pornind scanarea Trap Scan Security...", "INFO", app_config.log_file)
    scanned_cache = get_scanned_files_cache(app_config.scanned_cache_file)

    for directory in app_config.target_directories:
        scan_directory(directory, app_config, scanned_cache)
    
    save_scanned_files_cache(app_config.scanned_cache_file, scanned_cache)
    log_event("Scanare Trap Scan Security finalizată.", "INFO", app_config.log_file)

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
    executable_path = os.path.join(package_root_dir, "venv", "bin", "trap-scan")

    # Aici verificăm dacă calea executabilului este corectă
    if not os.path.exists(executable_path):
        log_event(f"Eroare: Executabilul '{executable_path}' nu a fost găsit. Asigurați-vă că mediul virtual este creat și pachetul este instalat în el.", "ERROR", app_config.log_file)
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

        cron_entry = f"@ {frequency} {executable_path} scan >> {app_config.log_file} 2>&1"
        
        try:
            # Add to root's crontab
            os.system(f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -')
            log_event(f"Cron job adăugat: {cron_entry}", "INFO", app_config.log_file)
            print(f"Job Cron adăugat cu succes. Puteți verifica cu 'sudo crontab -l'.")
        except Exception as e:
            log_event(f"Eroare la adăugarea jobului Cron: {e}", "ERROR", app_config.log_file)
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
            
            log_event(f"Systemd service și timer create și activate. Serviciu: {service_path}, Timer: {timer_path}", "INFO", app_config.log_file)
            print(f"Systemd service și timer create și activate.")
            print(f"Puteți verifica statusul cu 'sudo systemctl status trap-scan.timer'.")
        except Exception as e:
            log_event(f"Eroare la configurarea Systemd: {e}", "ERROR", app_config.log_file)
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
    setup_logging(app_config.log_file) # Initialize logging based on config

    if args.command == 'scan':
        run_scan(app_config)
    elif args.command == 'init-config':
        # init-config already handled by AppConfig._create_default_config if file doesn't exist
        # But we can explicitly call it if user wants to re-initialize
        if not os.path.exists(app_config.config_path):
            app_config._create_default_config()
        else:
            overwrite = input(f"Fișierul de configurare '{app_config.config_path}' există deja. Doriți să-l suprascrieți cu valorile implicite? (y/N): ").lower()
            if overwrite == 'y':
                app_config._create_default_config()
                log_event("Fișier de configurare suprascris cu valorile implicite.", "INFO", app_config.log_file)
            else:
                print("Operare anulată. Fișierul de configurare nu a fost modificat.")
                log_event("Creare fișier de configurare implicită anulată.", "INFO", app_config.log_file)
    elif args.command == 'setup-scheduler':
        setup_scheduler_command(app_config, args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()