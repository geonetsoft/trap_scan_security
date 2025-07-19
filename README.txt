===============================================================================
                       TRAP SCAN SECURITY - MANUAL UTILIZARE
===============================================================================

  Un instrument Python pentru detectarea și carantinarea fișierelor suspecte
  (malware, shell-uri web) pe serverele Linux, ideal pentru medii cPanel
  sau servere web dedicate.

-------------------------------------------------------------------------------
                                  CUPRINS
-------------------------------------------------------------------------------

  1.  CARACTERISTICI
  2.  CERINTE PRELIMINARE
  3.  INSTALARE
  4.  CONFIGURARE
  5.  UTILIZARE
  6.  CONFIGURAREA RULARII PROGRAMATE (SCHEDULER)
  7.  GESTIONAREA FISIERELOR CARANTINATE
  8.  DEPANARE (TROUBLESHOOTING)
  9.  CONTRIBUTII
  10. LICENTA


===============================================================================
1. CARACTERISTICI
===============================================================================

  * Scanare recursiva a directoarelor tinta.
  * Detectie bazata pe pattern-uri suspecte (expresii regulate).
  * Sistem de carantina pentru fisierele detectate.
  * Cache inteligent pentru fisierele scanate (evita re-scanarea fisierelor
    nemodificate).
  * Fisier de configurare extern (config.ini) pentru personalizare usoara.
  * Interfata de linie de comanda (CLI) intuitiva.
  * Optiuni de programare automata via Cron sau Systemd Timer.
  * Logare detaliata a evenimentelor.


===============================================================================
2. CERINTE PRELIMINARE
===============================================================================

  Inainte de a instala, asigura-te ca sistemul tau indeplineste urmatoarele
  cerinte:

  * Sistem de operare: Linux (testat pe distributii bazate pe RHEL/CentOS
    si Debian/Ubuntu).
  * Python: Versiunea 3.6 sau mai noua. Poti verifica versiunea cu:
      python3 --version
  * Git: Necesar pentru clonarea depozitului. Instaleaza-l cu:
      sudo yum install git -y    (pentru RHEL/CentOS)
      sau
      sudo apt install git -y    (pentru Debian/Ubuntu)
  * Privilegii: Acces 'sudo' sau 'root' este necesar pentru anumite operatiuni
    de instalare si configurare (ex: initializarea configuratiei in /etc,
    configurarea scheduler-ului).


===============================================================================
3. INSTALARE
===============================================================================

  Urmeaza acesti pasi pentru a instala 'trap-scan-security' pe serverul tau:

  1.  Conecteaza-te prin SSH la serverul tau ca utilizator 'root' sau cu
      privilegii 'sudo'.

  2.  Creeaza un director pentru proiect (recomandat '/opt/projects'):
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      sudo mkdir -p /opt/projects
      sudo chown ${USER}:${USER} /opt/projects
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      (Asigura-te ca utilizatorul tau are drepturi de scriere.
       Inlocuieste '${USER}' cu numele tau de utilizator daca nu esti root.)

  3.  Navigheaza in directorul creat:
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      cd /opt/projects/
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  4.  Cloneaza depozitul GitHub:
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      git clone https://github.com/geonetsoft/trap_scan_security.git
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      (Asigura-te ca folosesti URL-ul corect al depozitului tau, daca l-ai
       forkat.)

  5.  Acceseaza directorul proiectului:
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      cd trap_scan_security
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  6.  Creeaza si activeaza un mediu virtual Python (recomandat):
      Este esential sa folosesti un mediu virtual pentru a izola dependentele
      proiectului.
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      python3 -m venv venv
      source venv/bin/activate
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      (Vei vedea '(venv)' in fata promptului, de exemplu
       '(venv) [user@server trap_scan_security]$', indicand ca mediul virtual
       este activ.)

  7.  Instaleaza pachetul 'trap-scan-security':
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      pip install -e .
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      (Mesajul 'Successfully installed trap-scan-security-0.1.0' confirma
       instalarea.)

  8.  Verifica instalarea:
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      trap-scan --help
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      (Ar trebui sa vezi mesajul de ajutor cu comenzile disponibile.)


===============================================================================
4. CONFIGURARE
===============================================================================

  Dupa instalare, trebuie sa personalizezi setarile scanerului.

  1.  Initializeaza fisierul de configurare implicit:
      Aceasta comanda va crea fisierul 'config.ini' la '/etc/trap_scan/config.ini'.
      Este necesar 'sudo' pentru a scrie in '/etc/'.
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      sudo trap-scan init-config
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      (Daca fisierul exista deja, vei fi intrebat daca doresti sa-l suprascrii.
       Raspunde 'y' pentru a folosi valorile implicite.)

  2.  Editeaza fisierul de configurare:
      Acesta este pasul cel mai important pentru a personaliza scanerul.
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      sudo nano /etc/trap_scan/config.ini
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      Modifica urmatoarele sectiuni si optiuni:

      * [Paths]
          -  target_directories: Listeaza caile absolute ale directoarelor
             pe care doresti sa le scanezi, separate prin virgula
             (ex: /var/www/html,/home/cpaneluser/public_html,/opt/alt_web_root).
          -  quarantine_dir: Specifica directorul unde vor fi mutate fisierele
             suspecte (implicit: /var/quarantine_trap_scan). Asigura-te ca
             acest director exista si ca scanerul are permisiuni de scriere acolo.
          -  log_file: Calea completa catre fisierul de logare principal
             (implicit: /var/log/trap_scan.log).
          -  scanned_cache_file: Calea catre fisierul cache JSON pentru fisierele
             scanate (implicit: /var/log/trap_scan_cache.json).

      * [Scanner]
          -  suspicion_threshold: Seteaza nivelul de suspiciune necesar pentru
             a marca un fisier ca suspect si a-l carantina (implicit: 2).
             Valori mai mici fac scanerul mai sensibil.

      * [Scheduler]
          -  Aceste optiuni sunt informative. Configurarea reala se face cu
             comanda 'setup-scheduler'.

      * Salveaza modificarile (in 'nano': Ctrl + O, Enter, Ctrl + X).


===============================================================================
5. UTILIZARE
===============================================================================

  Dupa configurare, poti rula o scanare manuala:

  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  trap-scan scan
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  * Comanda va afisa progresul si rezultatele la consola.
  * Toate evenimentele sunt inregistrate in fisierul de log specificat in
    'config.ini' (implicit: /var/log/trap_scan.log). Poti monitoriza log-urile
    in timp real cu:
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      tail -f /var/log/trap_scan.log
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


===============================================================================
6. CONFIGURAREA RULARII PROGRAMATE (SCHEDULER)
===============================================================================

  Recomandat pentru monitorizare continua. Aceasta operatiune necesita
  privilegii de 'root'.

  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  sudo trap-scan setup-scheduler
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  Urmeaza instructiunile interactive:

  1.  Alege metoda de programare:
      * 1. Cron: Traditional, simplu, ideal pentru servere mai vechi sau unde
            Systemd nu este folosit.
      * 2. Systemd Timer: Modern, mai robust, preferat pe sistemele Linux noi.

  2.  Introdu frecventa de rulare:
      * Exemple comune: 'hourly', 'daily', 'weekly'.
      * Poti folosi si expresii specifice:
          -  Pentru Cron: '0 * * * *' (la fiecare ora), '0 0 * * *' (zilnic la
             miezul noptii).
          -  Pentru Systemd: 'OnCalendar=hourly', 'OnCalendar=daily', sau o
             expresie specifica (ex: 'OnCalendar=*-*-* 00:00:00' pentru zilnic
             la miezul noptii).

  Verificarea Scheduler-ului:
  * Cron:
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      sudo crontab -l
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      (pentru a vedea intrarea adaugata pentru root).

  * Systemd Timer:
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      sudo systemctl status trap-scan.timer
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      journalctl -u trap-scan.service
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      (pentru a vedea log-urile rularilor systemd).


===============================================================================
7. GESTIONAREA FISIERELOR CARANTINATE
===============================================================================

  Fisierele suspecte sunt mutate in directorul specificat de 'quarantine_dir'
  (implicit: /var/quarantine_trap_scan).

  * Inspectare: Poti inspecta manual fisierele din acest director.
  * Restaurare: Pentru a restaura un fisier, pur si simplu muta-l inapoi la
      locatia originala.
  * Stergere: Sterge fisierele carantinate doar dupa ce esti sigur ca nu mai
      sunt necesare.


===============================================================================
8. DEPANARE (TROUBLESHOOTING)
===============================================================================

  * Erori de permisiuni: Asigura-te ca scriptul este rulat cu permisiuni
      suficiente (foloseste 'sudo' unde este necesar, mai ales pentru
      'init-config' si 'setup-scheduler'). Verifica permisiunile directoarelor
      'target_directories', 'quarantine_dir' si al celor de log ('/var/log').
  * Fisier de configurare lipsa/incorect: Ruleaza 'sudo trap-scan init-config'
      pentru a recrea fisierul. Asigura-te ca ai editat corect
      'target_directories' si 'quarantine_dir'.
  * Executabilul 'trap-scan' nu este gasit: Asigura-te ca mediul virtual Python
      este activ ('source venv/bin/activate') si ca pachetul a fost instalat
      corect ('pip install -e .').
  * Verifica log-urile: Cel mai bun loc pentru a identifica problemele sunt
      fisierele de log: '/var/log/trap_scan.log' si, pentru Systemd,
      'journalctl -u trap-scan.service'.


===============================================================================
9. CONTRIBUTII
===============================================================================

  Daca doresti sa contribui la proiect, te rugam sa forkezi depozitul, sa faci
  modificarile si sa deschizi un Pull Request.


===============================================================================
10. LICENTA
===============================================================================

  Acest proiect este licentiat sub [Numele_Licentei] - vezi fisierul
  [LICENSE](LICENSE) pentru detalii.