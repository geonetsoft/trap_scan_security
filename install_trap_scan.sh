#!/bin/bash

# --- Variabile Configurabile ---
PROJECT_DIR="/opt/projects/trap_scan_security"
GITHUB_REPO="https://github.com/geonetsoft/trap_scan_security.git" # Asigură-te că acesta este URL-ul corect al repo-ului tău!
CONFIG_PATH="/etc/trap_scan/config.ini"
LOG_FILE="/var/log/trap_scan.log" # Folosit pentru logarea scheduler-ului

# --- Funcții Utilitare ---
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Acest script trebuie rulat cu privilegii de root sau cu sudo."
        exit 1
    fi
}

# --- Rularea Scriptului ---
log_message "Pornind instalarea Trap Scan Security..."
check_root

# 1. Instalare Dependențe de Sistem (git, python3-venv)
log_message "Instalare dependințe de sistem (git, python3-venv)..."
if command -v dnf &> /dev/null; then
    sudo dnf install -y git python3-devel python3-pip
elif command -v yum &> /dev/null; then # <-- ADAUGAT SUPORT PENTRU YUM
    sudo yum install -y git python3-devel python3-pip
elif command -v apt-get &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y git python3-venv python3-pip python3-dev
else
    log_message "Atenție: Niciun manager de pachete (dnf, yum, apt-get) recunoscut. Instalați manual git și python3-venv."
    exit 1
fi

# 2. Creare Director Proiect
log_message "Creare director proiect: $PROJECT_DIR"
sudo mkdir -p "$PROJECT_DIR"
sudo chown -R $(logname):$(logname) "$PROJECT_DIR" # Setează owner-ul la utilizatorul care rulează scriptul
cd "$PROJECT_DIR" || { log_message "Eroare: Nu se poate naviga la $PROJECT_DIR"; exit 1; }

# 3. Clonare Repository Git
if [ -d ".git" ]; then
    log_message "Repository Git existent. Se va face pull."
    git pull
else
    log_message "Clonare repository Git din $GITHUB_REPO..."
    git clone "$GITHUB_REPO" . # Clonează în directorul curent
    if [ $? -ne 0 ]; then
        log_message "Eroare la clonarea repository-ului Git. Verificați URL-ul și permisiunile."
        exit 1
    fi
fi

# 4. Creare și Activare Mediu Virtual
log_message "Creare mediu virtual Python..."
python3 -m venv venv
if [ $? -ne 0 ]; then
    log_message "Eroare la crearea mediului virtual. Asigurați-vă că python3-venv este instalat."
    exit 1
fi
source venv/bin/activate

# 5. Instalare Proiect Python
log_message "Instalare pachet Trap Scan Security..."
pip install -e .
if [ $? -ne 0 ]; then
    log_message "Eroare la instalarea pachetului Python. Verificați dependințele."
    exit 1
fi

# 6. Inițializare Configurație
log_message "Inițializare fișier de configurare implicit: $CONFIG_PATH"
# Verificăm dacă fișierul de configurare există înainte de a-l inițializa.
# Această abordare evită prompt-ul "overwrite" în script.
if [ -f "$CONFIG_PATH" ]; then
    log_message "Fișierul de configurare există deja. Se va păstra versiunea existentă. Editați-l manual."
else
    # Rulăm init-config, dar fișierul nu există, deci nu va cere suprascriere
    trap-scan init-config
    if [ $? -ne 0 ]; then
        log_message "Eroare la inițializarea fișierului de configurare."
        exit 1
    fi
    log_message "Fișier de configurare inițializat. Editați-l pentru a seta 'target_directories'."
fi


# 7. Configurare Scheduler (Opțional, de rulat manual după instalare)
log_message "Instalare finalizată! Pentru a configura o rulare programată, rulați manual:"
log_message "cd $PROJECT_DIR && source venv/bin/activate && sudo trap-scan setup-scheduler"
log_message "Nu uitați să editați $CONFIG_PATH pentru a seta directorii țintă de scanare."

log_message "Instalarea Trap Scan Security a fost finalizată cu succes!"