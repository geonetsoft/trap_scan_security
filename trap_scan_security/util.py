import os
import sys
import datetime
import hashlib # Adăugat aici pentru get_file_hash

# Constante pentru nivele de logare
LOG_LEVELS = {
    "DEBUG": 0,
    "INFO": 1,
    "WARNING": 2,
    "ERROR": 3,
    "CRITICAL": 4,
    "ALERT": 5 # Nivel adăugat pentru alerte specifice de securitate
}

def log_event(message, level="INFO", log_file_path=None):
    """
    Loghează un mesaj la consolă și într-un fișier.
    Necesită `log_file_path` setat pentru a scrie în fișier.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_message = f"[{timestamp}] [{level}] {message}"

    print(formatted_message) # Afișează mereu la consolă

    if log_file_path:
        try:
            # Asigură-te că directorul de log există înainte de a scrie
            log_dir = os.path.dirname(log_file_path)
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            with open(log_file_path, 'a') as f:
                f.write(formatted_message + "\n")
        except Exception as e:
            # Acesta este un caz de eroare la eroare, deci printăm direct
            print(f"EROARE CRITICĂ: Nu se poate scrie în fișierul de log '{log_file_path}': {e}", file=sys.stderr)

def ensure_directory_exists(directory_path, role="director de operare"):
    """
    Asigură că un director există și este scriibil.
    Oferă mesaje de eroare specifice dacă nu poate fi creat.
    Returnează True la succes, False la eșec.
    """
    if not directory_path:
        log_event(f"Calea pentru {role} nu este specificată. Verificarea directorului omisă.", "WARNING")
        return False

    if not os.path.exists(directory_path):
        try:
            # Folosim 0o755 pentru permisiuni standard: rwx pentru owner, rx pentru grup/alții
            os.makedirs(directory_path, mode=0o755, exist_ok=True)
            log_event(f"Directorul '{directory_path}' ({role}) a fost creat cu succes.", "INFO")
            return True
        except PermissionError:
            log_event(
                f"EROARE CRITICĂ: Permisiuni insuficiente pentru a crea directorul '{directory_path}' ({role}). "
                f"Verificați permisiunile utilizatorului care rulează scriptul. "
                f"Încercați să rulați cu 'sudo' dacă este necesar.", "CRITICAL"
            )
            return False
        except OSError as e:
            log_event(
                f"EROARE CRITICĂ: Nu se poate crea directorul '{directory_path}' ({role}). "
                f"Cauza: {e}. "
                f"Verificați calea sau spațiul disponibil pe disc.", "CRITICAL"
            )
            return False
    else:
        # Verifică dacă directorul existent este scriibil
        if not os.access(directory_path, os.W_OK):
             log_event(
                f"AVERTISMENT: Directorul '{directory_path}' ({role}) există, dar nu este scriibil pentru acest utilizator. "
                f"Asigurați-vă că scriptul are permisiuni de scriere în acest director.", "WARNING"
            )
             return False # Considerăm un avertisment critic pentru funcționalitate
        return True

def get_file_hash(filepath, block_size=65536):
    """Calculează hash-ul SHA256 al unui fișier."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            buf = f.read(block_size)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(block_size)
        return hasher.hexdigest()
    except Exception as e:
        log_event(f"Eroare la calcularea hash-ului pentru {filepath}: {e}", "ERROR")
        return None