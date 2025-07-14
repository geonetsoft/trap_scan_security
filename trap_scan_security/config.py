import configparser
import os
import shutil
import sys

from .util import log_event, ensure_directory_exists

# Numele fișierului de configurare în sistem (poate fi modificat de utilizator)
DEFAULT_CONFIG_FILE_NAME = "config.ini"
# Locația implicită unde vom încerca să plasăm/citim fișierul de configurare
DEFAULT_CONFIG_PATH = os.path.join("/etc", "trap_scan", DEFAULT_CONFIG_FILE_NAME)
# Locația șablonului de configurare în pachet
PACKAGE_CONFIG_TEMPLATE = os.path.join(os.path.dirname(__file__), "defaults.ini")


class Config:
    def __init__(self, config_path=None):
        self.config = configparser.ConfigParser()
        self.config_path = config_path if config_path else DEFAULT_CONFIG_PATH
        self.log_file = None # Va fi setat după încărcarea configurației
        self.load_config()

    def load_config(self):
        if not os.path.exists(self.config_path):
            log_event(f"Fișierul de configurare '{self.config_path}' nu a fost găsit. Se va crea un fișier implicit.", "WARNING")
            self.create_default_config()

        try:
            self.config.read(self.config_path)
            # Acum că avem calea log-ului, putem seta log_file pentru util.log_event
            # Atenție: log_file este o proprietate a obiectului Config, nu o variabilă globală
            self.log_file = self.get_setting("Paths", "log_file")
            # Aici asigurăm că directoarele necesare există
            self._ensure_all_paths_exist()

        except Exception as e:
            log_event(f"EROARE CRITICĂ: Nu se poate citi fișierul de configurare '{self.config_path}': {e}. Asigurați-vă că este formatat corect.", "CRITICAL")
            sys.exit(1)

    def create_default_config(self):
        """Creează un fișier de configurare implicit la calea specificată."""
        config_dir = os.path.dirname(self.config_path)
        if not ensure_directory_exists(config_dir, "director de configurare"):
            log_event(f"Nu se poate crea directorul pentru configurare '{config_dir}'. Vă rugăm să-l creați manual și să plasați '{DEFAULT_CONFIG_FILE_NAME}' în el.", "CRITICAL")
            sys.exit(1)

        try:
            shutil.copyfile(PACKAGE_CONFIG_TEMPLATE, self.config_path)
            log_event(f"Fișierul de configurare implicit a fost creat la '{self.config_path}'. Vă rugăm să-l editați conform nevoilor dumneavoastră.", "INFO")
        except Exception as e:
            log_event(f"EROARE CRITICĂ: Nu se poate copia fișierul de configurare implicit din '{PACKAGE_CONFIG_TEMPLATE}' în '{self.config_path}': {e}.", "CRITICAL")
            sys.exit(1)

    def get_setting(self, section, option, default=None):
        """Obține o setare din fișierul de configurare."""
        try:
            return self.config.get(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError):
            if default is not None:
                log_event(f"Setarea '{option}' din secțiunea '[{section}]' nu a fost găsită. Se folosește valoarea implicită: {default}", "WARNING", self.log_file)
                return default
            else:
                log_event(f"Setarea '{option}' din secțiunea '[{section}]' nu a fost găsită și nu are o valoare implicită. Verificați fișierul de configurare.", "CRITICAL", self.log_file)
                sys.exit(1)

    def get_list_setting(self, section, option):
        """Obține o listă de setări (separate prin virgulă)."""
        value = self.get_setting(section, option)
        if value:
            return [item.strip() for item in value.split(',') if item.strip()]
        return []

    def get_int_setting(self, section, option):
        """Obține o setare ca număr întreg."""
        try:
            return int(self.get_setting(section, option))
        except ValueError:
            log_event(f"Valoare incorectă pentru '{option}' din secțiunea '[{section}]'. Trebuie să fie un număr întreg.", "CRITICAL", self.log_file)
            sys.exit(1)

    def _ensure_all_paths_exist(self):
        """Asigură existența tuturor directoarelor necesare definite în configurație."""
        # Se asigură că directorul de carantină există
        quarantine_dir = self.get_setting("Paths", "quarantine_dir")
        if not ensure_directory_exists(quarantine_dir, "director de carantină"):
            log_event("Eroare la crearea/verificarea directorului de carantină. Operațiunile de carantină pot eșua.", "CRITICAL", self.log_file)
            sys.exit(1) # Oprire dacă directorul de carantină nu poate fi asigurat

        # Se asigură că directorul pentru log-uri există
        log_file_path = self.get_setting("Paths", "log_file")
        log_dir = os.path.dirname(log_file_path)
        if not ensure_directory_exists(log_dir, "director de log-uri"):
            log_event("Eroare la crearea/verificarea directorului de log-uri. Logarea poate fi afectată.", "WARNING", self.log_file)
            # Nu sys.exit(1) aici, scriptul poate rula și fără log-uri în fișier, dar cu avertisment

        # Se asigură că directorul pentru cache-ul de scanare există
        scanned_cache_file = self.get_setting("Paths", "scanned_cache_file")
        cache_dir = os.path.dirname(scanned_cache_file)
        if not ensure_directory_exists(cache_dir, "director cache scanare"):
            log_event("Eroare la crearea/verificarea directorului cache. Performanța poate fi afectată.", "WARNING", self.log_file)
            # Nu sys.exit(1) aici, scriptul poate rula și fără cache, dar cu avertisment