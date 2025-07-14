import os
import re
import shutil
import datetime
import json
import argparse
import subprocess # Pentru a rula comenzi systemctl/crontab
import sys        # Pentru sys.exit() și stdin/stdout

from .config import Config, DEFAULT_CONFIG_PATH
from .util import log_event, ensure_directory_exists, get_file_hash

# --- Pattern-uri pentru detectarea codului suspect (mută-le din scriptul vechi) ---
SUSPICIOUS_PATTERNS = [
    re.compile(r'<\?php\s*(eval|assert|system|passthru|shell_exec|exec|base64_decode|gzinflate|str_rot13|create_function|preg_replace)\s*\(', re.IGNORECASE),
    re.compile(r'\$_GET\[[\'"]?\w+[\'"]?\]', re.IGNORECASE),
    re.compile(r'\$_POST\[[\'"]?\w+[\'"]?\]', re.IGNORECASE),
    re.compile(r'\$_REQUEST\[[\'"]?\w+[\'"]?\]', re.IGNORECASE),
    re.compile(r'http:\/\/|\.ru|\.cn', re.IGNORECASE),
    re.compile(r'data:text\/html;base64', re.IGNORECASE),
    re.compile(r'phpinfo\(\)', re.IGNORECASE),
    re.compile(r'file_put_contents\s*\(', re.IGNORECASE),
    re.compile(r'chmod\s*\(', re.IGNORECASE),
    re.compile(r'unlink\s*\(', re.IGNORECASE),
    re.compile(r'error_reporting\(0\)', re.IGNORECASE),
    re.compile(r'die\(\s*\'\'\s*\)', re.IGNORECASE),
    re.compile(r'set_time_limit\s*\(', re.IGNORECASE),
    re.compile(r'ignore_user_abort\s*\(', re.IGNORECASE),
    re.compile(r'curl_exec\s*\(', re.IGNORECASE),
    re.compile(r'fsockopen\s*\(', re.IGNORECASE),
    re.compile(r'proc_open\s*\(', re.IGNORECASE),
    re.compile(r'pcntl_exec\s*\(', re.IGNORECASE),
    re.compile(r'symlink\s*\(', re.IGNORECASE),
    re.compile(r'ob_start\s*\(', re.IGNORECASE),
    re.compile(r'header\s*\(', re.IGNORECASE),
    re.compile(r'<?php system\(\$_GET\[\'cmd\'\]\); echo \'mr0x02\'; ?>', re.IGNORECASE)
]

# Variabilă globală pentru configurare (va fi instanțiată în main)
app_config = None

# --- Funcții pentru cache-ul de scanare ---

def load_scanned_cache(cache_file_path):
    """Încarcă cache-ul de fișiere scanate din fișier."""
    if not cache_file_path:
        log_event("Calea pentru fișierul cache nu este specificată. Cache-ul nu va fi utilizat.", "WARNING", None)
        return {}
    if not os.path.exists(cache_file_path):
        return {} # Returnează cache gol dacă fișierul nu există încă
    try:
        with open(cache_file_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        log_event(f"Eroare la citirea cache-ului JSON '{cache_file_path}': {e}. Se va crea un cache nou.", "WARNING", app_config.log_file if app_config else None)
        return {}
    except Exception as e:
        log_event(f"Eroare neașteptată la încărcarea cache-ului '{cache_file_path}': {e}.", "ERROR", app_config.log_file if app_config else None)
        return {}

def save_scanned_cache(cache, cache_file_path):
    """Salvează cache-ul de fișiere scanate în fișier."""
    if not cache_file_path:
        log_event("Calea pentru fișierul cache nu este specificată. Cache-ul nu va fi salvat.", "WARNING", None)
        return
    try:
        with open(cache_file_path, 'w') as f:
            json.dump(cache, f, indent=4)
    except Exception as e:
        log_event(f"Eroare la salvarea cache-ului '{cache_file_path}': {e}", "ERROR", app_config.log_file if app_config else None)

# --- Funcția de carantină ---
def quarantine_file(filepath, quarantine_dir):
    filename = os.path.basename(filepath)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    quarantined_path = os.path.join(quarantine_dir, f"{filename}.quarantined_{timestamp}")

    try:
        shutil.move(filepath, quarantined_path)
        log_event(f"Fișierul '{filepath}' a fost mutat în carantină la '{quarantined_path}'.", "ALERT", app_config.log_file)
    except Exception as e:
        log_event(f"Eroare la mutarea fișierului '{filepath}' în carantină: {e}", "ERROR", app_config.log_file)

# --- Funcția de scanare a unui singur fișier ---
def scan_file(filepath, scanned_cache, suspicion_threshold, quarantine_dir):
    suspicion_level = 0
    try:
        # Verificăm dacă fișierul există înainte de a-l deschide
        if not os.path.exists(filepath):
            log_event(f"Fișierul {filepath} nu a fost găsit. Posibil șters între timp.", "WARNING", app_config.log_file)
            # Scoate fișierul din cache dacă nu mai există
            if filepath in scanned_cache:
                del scanned_cache[filepath]
            return False, 0

        current_mtime = os.path.getmtime(filepath)
        # Folosim get_file_hash pentru robustete, dar e mai lent.
        # Alternativ, putem folosi doar current_mtime
        # current_file_hash = get_file_hash(filepath)

        # Verifică dacă fișierul este deja în cache și nu a fost modificat
        # Dacă ai folosi hash-uri: and scanned_cache[filepath] == current_file_hash
        if filepath in scanned_cache and scanned_cache[filepath] == current_mtime:
            log_event(f"Fișierul {filepath} este deja scanat și validat (cache). Se omite.", "INFO", app_config.log_file)
            return False, 0

        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()

        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern.search(line):
                    suspicion_level += 1
                    # log_event(f"Pattern suspect '{pattern.pattern}' găsit în {filepath} la linia {line_num}. Nivel suspiciune: {suspicion_level}", "DEBUG", app_config.log_file)
                    # Nu mai punem break aici

        if suspicion_level >= suspicion_threshold:
            log_event(f"Fișier suspect detectat: {filepath} (Nivel suspiciune: {suspicion_level}). Se mută în carantină.", "ALERT", app_config.log_file)
            quarantine_file(filepath, quarantine_dir)
            # Se scoate din cache dacă e carantinat, pentru a fi scanat din nou dacă apare altundeva cu același nume
            if filepath in scanned_cache:
                del scanned_cache[filepath]
            return True, suspicion_level
        else:
            log_event(f"Fișierul {filepath} a fost scanat și este considerat legitim (Nivel suspiciune: {suspicion_level}).", "INFO", app_config.log_file)
            # Adaugă fișierul în cache dacă este legitim
            # Dacă ai folosi hash-uri: scanned_cache[filepath] = current_file_hash
            scanned_cache[filepath] = current_mtime
            return False, suspicion_level

    except PermissionError:
        log_event(f"Permisiuni insuficiente pentru a citi fișierul {filepath}. Se omite.", "WARNING", app_config.log_file)
        return False, 0
    except Exception as e:
        log_event(f"Eroare la scanarea fișierului {filepath}: {e}", "ERROR", app_config.log_file)
        return False, 0

# --- Funcția principală de scanare ---
def run_scan_operation():
    log_event("Începe scanarea fișierelor suspecte...", "INFO", app_config.log_file)

    target_directories = app_config.get_list_setting("Paths", "target_directories")
    quarantine_dir = app_config.get_setting("Paths", "quarantine_dir")
    suspicion_threshold = app_config.get_int_setting("Scanner", "suspicion_threshold")
    scanned_cache_file = app_config.get_setting("Paths", "scanned_cache_file")

    # Asigură-te că directoarele de cache/carantină sunt create
    if not ensure_directory_exists(quarantine_dir, "director de carantină") or \
       not ensure_directory_exists(os.path.dirname(scanned_cache_file), "director cache scanare"):
        log_event("Nu se pot asigura toate directoarele necesare. Scanarea poate întâmpina probleme.", "CRITICAL", app_config.log_file)
        # Poți decide să ieși aici sau să continui cu avertisment

    scanned_cache = load_scanned_cache(scanned_cache_file)

    total_files_scanned = 0
    total_files_quarantined = 0

    for target_dir in target_directories:
        if not os.path.isdir(target_dir):
            log_event(f"Directorul țintă '{target_dir}' nu există sau nu este un director. Se omite.", "WARNING", app_config.log_file)
            continue
        if not os.access(target_dir, os.R_OK): # Verifică permisiunile de citire
            log_event(f"Permisiuni insuficiente pentru a citi directorul '{target_dir}'. Se omite.", "ERROR", app_config.log_file)
            continue

        for root, _, files in os.walk(target_dir):
            for file_name in files:
                filepath = os.path.join(root, file_name)
                if os.path.islink(filepath):
                    continue

                is_suspect, _ = scan_file(filepath, scanned_cache, suspicion_threshold, quarantine_dir)
                if is_suspect:
                    total_files_quarantined += 1
                total_files_scanned += 1

    save_scanned_cache(scanned_cache, scanned_cache_file)

    log_event(f"Scanare finalizată. Total fișiere scanate: {total_files_scanned}.", "INFO", app_config.log_file)
    log_event(f"Total fișiere carantinate: {total_files_quarantined}.", "ALERT" if total_files_quarantined > 0 else "INFO", app_config.log_file)


# --- Funcții pentru CLI ---

def initialize_config_command():
    """Comanda pentru a inițializa fișierul de configurare."""
    log_event(f"Se inițializează fișierul de configurare la '{DEFAULT_CONFIG_PATH}'.", "INFO", None) # Logăm aici fără app_config.log_file inițial
    # Instanțiem Config pentru a declanșa crearea fișierului dacă nu există
    config_obj = Config(config_path=DEFAULT_CONFIG_PATH) # Va seta și app_config.log_file intern
    log_event("Configurare inițializată. Vă rugăm să editați fișierul de configurare.", "INFO", config_obj.log_file)
    print(f"\nFișierul de configurare a fost creat/actualizat la: {DEFAULT_CONFIG_PATH}")
    print(f"Vă rugăm să-l editați pentru a seta directoarele țintă și alte opțiuni.")
    print(f"Exemplu: `sudo nano {DEFAULT_CONFIG_PATH}`")

def setup_scheduler_command():
    """Comanda pentru a configura rularea periodică (Cron/systemd)."""
    log_event("Începe configurarea programatorului de sarcini...", "INFO", app_config.log_file)

    if os.geteuid() != 0:
        log_event("Această operațiune necesită privilegii de root. Rulați cu 'sudo'.", "ERROR", app_config.log_file)
        print("\nEROARE: Această comandă necesită privilegii de root. Vă rugăm să rulați cu `sudo`.")
        return

    print("\nSelectați metoda de programare:")
    print("  1. Cron (tradițional, simplu)")
    print("  2. Systemd Timer (modern, mai robust pe sisteme noi)")

    choice = input("Introduceți 1 sau 2: ").strip()

    if choice not in ['1', '2']:
        print("Alegere invalidă. Vă rugăm să introduceți 1 sau 2.")
        return

    # Obține calea executabilului, care e instalat de pip.
    # În medii virtuale, acesta poate fi sub venv/bin, global /usr/local/bin etc.
    executable_path = shutil.which("trap-scan")
    if not executable_path:
        log_event("Eroare: Executabilul 'trap-scan' nu a fost găsit în PATH. Asigurați-vă că pachetul este instalat corect.", "ERROR", app_config.log_file)
        print("\nEROARE: Executabilul 'trap-scan' nu a fost găsit.")
        print("Asigurați-vă că pachetul este instalat corect (ex: `sudo pip install .`) și că '/usr/local/bin' sau directorul venv/bin este în PATH.")
        return

    print(f"\nExecutable Path detectat: {executable_path}")
    frequency = input("Introduceți frecvența de rulare (ex: hourly, daily, weekly, sau o expresie specifică Cron/systemd, e.g., '0 * * * *' pentru Cron sau 'OnCalendar=*-*-* 00:00:00' pentru systemd zilnic): ").strip()
    if not frequency:
        print("Frecvența nu poate fi goală. Anulare.")
        return

    if choice == '1':
        # Cron
        # Construim intrarea Cron bazându-ne pe frecvență sau pe formatul cron direct
        cron_schedule = ""
        if frequency.lower() == 'hourly':
            cron_schedule = "0 * * * *"
        elif frequency.lower() == 'daily':
            cron_schedule = "0 0 * * *"
        elif frequency.lower() == 'weekly':
            cron_schedule = "0 0 * * 0"
        else:
            cron_schedule = frequency # Presupunem că utilizatorul a introdus o expresie Cron validă

        cron_entry = f"{cron_schedule} {executable_path} --scan >> {app_config.get_setting('Paths', 'log_file')} 2>&1"


        log_event(f"Încercarea de adăugare intrare Cron: {cron_entry}", "INFO", app_config.log_file)
        try:
            # Verifică dacă intrarea există deja în crontab-ul root
            result = subprocess.run(['sudo', 'crontab', '-l'], capture_output=True, text=True, check=False)
            current_crontab = result.stdout

            if result.returncode != 0 and "no crontab for root" not in result.stderr:
                # A apărut o eroare la citirea crontab-ului
                log_event(f"Eroare la citirea crontab-ului: {result.stderr}", "ERROR", app_config.log_file)
                print(f"Eroare la citirea crontab-ului: {result.stderr}")
                return

            if cron_entry in current_crontab:
                log_event("Intrarea Cron există deja. Nu se adaugă.", "INFO", app_config.log_file)
                print("Intrarea Cron există deja. Nu se adaugă.")
            else:
                # Adaugă intrarea în crontab
                temp_cron_file = "/tmp/trap_scan_crontab_temp"
                with open(temp_cron_file, 'w') as f:
                    f.write(current_crontab + "\n" + cron_entry + "\n")

                subprocess.run(['sudo', 'crontab', temp_cron_file], check=True)
                os.remove(temp_cron_file)
                log_event("Intrarea Cron a fost adăugată cu succes.", "INFO", app_config.log_file)
                print("Intrarea Cron a fost adăugată cu succes. Verificați `sudo crontab -l`.")
        except subprocess.CalledProcessError as e:
            log_event(f"Eroare la adăugarea intrării Cron: {e}. Output: {e.stderr}", "ERROR", app_config.log_file)
            print("Eroare la adăugarea intrării Cron. Verificați log-urile pentru detalii.")
        except FileNotFoundError:
            log_event("Comanda 'crontab' nu a fost găsită. Asigurați-vă că 'cron' este instalat și în PATH.", "ERROR", app_config.log_file)
            print("Comanda 'crontab' nu a fost găsită. Asigurați-vă că 'cron' este instalat și în PATH.")

    elif choice == '2':
        # Systemd Timer
        service_content = f"""