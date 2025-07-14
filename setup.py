from setuptools import setup, find_packages
import os

# Funcție pentru a citi conținutul unui fișier (ex: README)
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='trap-scan-security',
    version='0.1.0', # Poți actualiza versiunea pe măsură ce dezvolți
    author='Numele Tau',
    author_email='email@exemplu.com',
    description='Un scaner Python pentru detectarea și carantinarea fișierelor suspecte pe servere.',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    url='https://github.com/YourUsername/trap_scan_security', # Înlocuiește cu repo-ul tău, dacă există
    packages=find_packages(), # Găsește automat pachetele în director
    include_package_data=True, # Include fișierele specificate în MANIFEST.in
    install_requires=[
        # Nu avem dependențe externe majore momentan, dar e bine să ai lista pregătită
    ],
    entry_points={
        'console_scripts': [
            'trap-scan = trap_scan_security.main:main', # Aici definești comanda 'trap-scan'
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License', # Sau licența aleasă de tine
        'Operating System :: POSIX :: Linux', # Scriptul e gândit pentru Linux
        'Topic :: Security',
        'Topic :: System :: Monitoring',
        'Environment :: Console',
    ],
    python_requires='>=3.6', # Specifică versiunea minimă de Python
)