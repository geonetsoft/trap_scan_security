#!/bin/bash

echo "Starting pre-installation checks for Trap Scan Security..."

# Check for root privileges (or sudo)
# If not root and sudo is available, re-run with sudo.
# Otherwise, instruct user to run as root.
if [ "$EUID" -ne 0 ]; then
    echo "This script needs to be run with root privileges (or sudo)."
    echo "Attempting to re-run with sudo..."
    if command -v sudo &> /dev/null; then
        # Re-run the script itself with sudo
        sudo "$0" "$@"
        exit $?
    else
        echo "Error: sudo command not found. Please run this script as root directly (e.g., 'su -' then run) or install sudo."
        exit 1
    fi
fi

# Determine OS and package manager
PACKAGE_MANAGER=""
PYTHON_PIP_PACKAGE=""
GIT_PACKAGE=""

if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    PACKAGE_MANAGER="apt"
    PYTHON_PIP_PACKAGE="python3-pip"
    GIT_PACKAGE="git"
elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ] || [ -f /etc/fedora-release ]; then
    # CentOS/RHEL/Fedora
    if command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
    else
        PACKAGE_MANAGER="yum"
    fi
    PYTHON_PIP_PACKAGE="python3-pip" # Or python-pip for older versions, but python3-pip is safer for modern systems
    GIT_PACKAGE="git"
else
    echo "Unsupported operating system. This script supports Debian/Ubuntu and CentOS/RHEL/Fedora."
    exit 1
fi

echo "Detected OS: $PACKAGE_MANAGER based system."

# Update package lists
echo "Updating package lists..."
if ! $PACKAGE_MANAGER update -y; then
    echo "Error updating package lists. Please check your internet connection or repository configuration."
    exit 1
fi

# Install python3-pip
echo "Checking for and installing $PYTHON_PIP_PACKAGE..."
# Check if package is installed using dpkg (Debian) or rpm (RPM-based)
if ! dpkg -s "$PYTHON_PIP_PACKAGE" &> /dev/null && ! rpm -q "$PYTHON_PIP_PACKAGE" &> /dev/null; then
    if ! $PACKAGE_MANAGER install "$PYTHON_PIP_PACKAGE" -y; then
        echo "Error installing $PYTHON_PIP_PACKAGE. Please install it manually or check your package manager."
        exit 1
    fi
else
    echo "$PYTHON_PIP_PACKAGE is already installed."
fi

# Install git
echo "Checking for and installing $GIT_PACKAGE..."
# Check if package is installed using dpkg (Debian) or rpm (RPM-based)
if ! dpkg -s "$GIT_PACKAGE" &> /dev/null && ! rpm -q "$GIT_PACKAGE" &> /dev/null; then
    if ! $PACKAGE_MANAGER install "$GIT_PACKAGE" -y; then
        echo "Error installing $GIT_PACKAGE. Please install it manually or check your package manager."
        exit 1
    fi
else
    echo "$GIT_PACKAGE is already installed."
fi

echo "Pre-installation checks completed successfully."
echo "You can now run 'python3 -m pip install .' to install the project."