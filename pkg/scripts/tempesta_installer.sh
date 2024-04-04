#!/bin/bash
#
# Tempesta FW install script.
#
# Copyright (C) 2017-2024 Tempesta Technologies, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59
# Temple Place - Suite 330, Boston, MA 02111-1307, USA.

declare -r LOG_LEVEL="INFO"
declare -r LOGFILE="/var/log/tempesta-install.log"

declare -r TFW_NAME=`basename $0`
declare -r LONG_OPTS="help,install,remove,purge"
declare -r DOWNLOAD_DIR=tfw_downloads

declare -r GITHUB_USER="tempesta-tech"
declare -r GITHUB_REPO_TEMPESTA="tempesta"
declare -r GITHUB_REPO_LINUX="linux-5.10.35-tfw"

#TODO: currently Ubuntu 20 is the only supported distribution, other
# distributions may have other names.
# Don't install packages with debug symbols.
declare -a FILES_LINUX=("linux-image-[\d.]+\.tfw-[\da-f]+"
                        "linux-kbuild-[\d.]+_[\d.]+"
                        "linux-headers-[\d.]+\.tfw-[\da-f]+"
                        "linux-compiler")
declare -a FILES_TEMPESTA=("tempesta-fw-dkms")

if [ "$(id -u)" != "0" ]; then
	echo
	echo "This script must be run as root"
	echo
	exit 1
fi

usage()
{
	echo -e "\nUsage: ${TFW_NAME} {action}\n"
	echo -e "Actions:"
	echo -e "  --install    Install or Update TempestaFW and all dependencies."
	echo -e "  --remove     Remove TempestaFW, but hold the configuration."
	echo -e "  --purge      Remove TempestaFW and all configuration files."
}

log() {
    local LEVEL=$1
    shift
    local MESSAGE="$@"
    local TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    
    if [ -z "$LOGFILE" ]; then
        echo "Error: LOGFILE is not defined."
        return 1
    fi

    echo "${TIMESTAMP} [${LEVEL}] - ${MESSAGE}" | tee -a $LOGFILE
}

# Use github API to get information about latest release.
#
# `latest` release shows ONLY releases which are not marked as `prereleases`.
# Github restricts 60 API requests per hour without authorisation. Enough for
# our needs.
tfw_download()
{
	log "INFO" "Starting download process..."

    release_tag=`curl -s https://api.github.com/repos/$GITHUB_USER/$GITHUB_REPO_TEMPESTA/tags | grep \"$DISTRO/ | cut -d '"' -f 4 | sort -V -r | head -n1`
	if [[ ! "$release_tag" ]]; then
		log "ERROR" "Can't find the latest release in repo: https://github.com/$GITHUB_USER/$GITHUB_REPO_TEMPESTA"
		log "INFO" "Attempting to download using fallback URLs."
	else
        log "INFO" "Found the latest release tag: $release_tag"
        uri="https://api.github.com/repos/$GITHUB_USER/$GITHUB_REPO_LINUX/releases/tags/${release_tag}"
        links=`curl -s $uri | grep browser_download_url | grep -P "$2" | cut -d '"' -f 4`
	fi
	
	if [[ ! "$links" ]]; then
		log "INFO" "Can't download file $2 from release ${release_tag} in repo:"
		log "INFO" "https://github.com/$GITHUB_USER/$GITHUB_REPO_LINUX"
		#TODO: show next line only if received 403 status code.
		log "INFO" "Or may be Github API rate limit exceeded. Fallback download from repo instead github.com"
		fall_links=("http://tempesta-vm.cloud.cherryservers.net:8081/repository/tempesta/pool/l/linux-headers-5.10.35.tfw-4c9ba16/linux-headers-5.10.35.tfw-4c9ba16_5.10.35.tfw-4c9ba16-1_amd64.deb"
		"http://tempesta-vm.cloud.cherryservers.net:8081/repository/tempesta/pool/l/linux-image-5.10.35.tfw-4c9ba16/linux-image-5.10.35.tfw-4c9ba16_5.10.35.tfw-4c9ba16-1_amd64.deb"
		"http://tempesta-vm.cloud.cherryservers.net:8081/repository/tempesta/pool/l/linux-libc-dev/linux-libc-dev_5.10.35.tfw-4c9ba16-1_amd64.deb"
		"http://tempesta-vm.cloud.cherryservers.net:8081/repository/tempesta/pool/t/tempesta-fw-dkms/tempesta-fw-dkms_0.7.1_amd64.deb -O tempesta-fw-dkms.deb")

		for file in ${fall_links[@]}
		do
			log "INFO" "Downloading $file using fallback URL"
			wget -q --show-progress -P $DOWNLOAD_DIR/$repo $file || log "ERROR" "Failed to download $file"
		done
	fi

	for file in ${links}
	do
		wget -q --show-progress -P $DOWNLOAD_DIR/$repo $file || log "ERROR" "Failed to download $file"
	done
}

tfw_install_packages()
{
	repo="${1}"
	shift
	files=("${@}")

  case $DISTRO in
	"debian-11")
    log "INFO" "Downloading latest packages from github.com/$GITHUB_USER/$repo ..."
    mkdir -p $DOWNLOAD_DIR/$repo
    ;;
	"ubuntu-20")
    repo=""
    log "INFO" "Downloading latest packages from github.com/$GITHUB_USER/$repo ..."
    mkdir -p $DOWNLOAD_DIR/$repo
    ;;
	"ubuntu-22")
    repo=""
    log "INFO" "Downloading latest packages from github.com/$GITHUB_USER/$repo ..."
    mkdir -p $DOWNLOAD_DIR/$repo
    ;;
  *)
		;;
  esac
	tfw_download $repo $file

	# Packages can depend on each other, install with single command to
	# make all packages setup correctly.
	dpkg -R -i $DOWNLOAD_DIR/$repo
	if [ $? -eq 0 ]; then
        log "INFO" "Packages from $repo installed successfully"
    else
        log "ERROR" "Failed to install packages from $repo"
        return 1
    fi
}

tfw_install_deps()
{
	echo ""
	log "INFO" "Install dependencies ..."
	APT_OPTS=

	case $DISTRO in
	"debian-11")
		echo ""
		log "INFO" "Installation on Debian 11 requires updating system from bullseye repository before installing TempestaFW."
		log "INFO" "Updating system from bullseye repository for Debian 11."
		tfw_confirm

		echo "deb http://deb.debian.org/debian/ " \
		        "bullseye main" >> /etc/apt/sources.list
		apt-get update || log "ERROR" "Failed to update package lists for Debian 11."
		apt-get -t jessie-backports dist-upgrade -y || log "ERROR" "Failed to dist-upgrade on Debian 11."
		;;
	"ubuntu-20")
        echo ""
		log "INFO" "Installation on Ubuntu 20 LTS requires updating system from jessie-backports repository before installing TempestaFW."
		log "INFO" "Updating system from focal repository for Ubuntu 20 LTS."
		tfw_confirm

		echo "deb http://ru.archive.ubuntu.com/ubuntu " \
		        "focal main" >> /etc/apt/sources.list
		apt-get update || log "ERROR" "Failed to update package lists for Ubuntu 20 LTS."
		apt-get dist-upgrade -y || log "ERROR" "Failed to dist-upgrade on Ubuntu 20 LTS."
    ;;
	"ubuntu-22")
        echo ""
		log "INFO" "Installation on Ubuntu 22 LTS requires updating system from jessie-backports repository before installing TempestaFW."
		log "INFO" "Updating system from jammy repository for Ubuntu 22 LTS."
		tfw_confirm

		echo "deb http://ru.archive.ubuntu.com/ubuntu " \
		        "jammy main" >> /etc/apt/sources.list
		apt-get update || log "ERROR" "Failed to update package lists for Ubuntu 22 LTS."
		apt-get dist-upgrade -y || log "ERROR" "Failed to dist-upgrade on Ubuntu 22 LTS."
    ;;
	*)
	log "ERROR" "Unsupported distribution: $DISTRO"
	return 1
		;;
	esac

	echo ""
	echo "Since TempestaFW is implemented as in-kernel module and it is"
	echo "under development, issues in it can affect stability of the"
	echo "kernel and may lead to a kernel crush. It is highly recommended"
	echo "to enable 'kdump-tools' by default in the next dialogue."
	read -n 1 -s -p "Press any key to continue..."
	# curl and wget are required for the script itself.
	apt-get ${APT_OPTS} install -y dkms libboost-dev libboost-program-options-dev \
	     kdump-tools curl wget ethtool bc libtemplate-perl
	if [ $? -eq 0 ]; then
		log "INFO" "Dependencies installation completed."
	else
		log "ERROR" "Failed to install required packages."
	return 1
	fi
	echo ""
}

tfw_install()
{
	log "INFO" "Starting Tempesta FW installation."
	rm -rf $DOWNLOAD_DIR
	mkdir -p $DOWNLOAD_DIR

	tfw_install_deps
	if [ $? -ne 0 ]; then
    	log "ERROR" "Failed to install dependencies."
    	exit 2
	fi
	
	# TempestaFW is shipped as DKMS module. By default, dkms framework
	# installs module only for running kernel. Configure dkms to install
	# module to all kernels. BUILD_EXCLUSIVE variable in TempestaFW's
	# dkms.conf will prevent building against unsupported kernels.
	log "INFO" "Configuring DKMS for all kernels."
	echo -e "autoinstall_all_kernels=\"yes\"" >> /etc/dkms/framework.conf
	echo ""
    echo "*************************************************************************"
    echo "* IMPORTANT: TempestaFW is distributed as a DKMS module.                *"
    echo "* We will now attempt to build the package for supported kernels.       *"
    echo "* You may encounter error messages due to the presence of unsupported   *"
    echo "* kernels in your system. Please disregard these errors as they are     *"
    echo "* expected under these circumstances.                                   *"
    echo "*************************************************************************"
    read -n 1 -s -p "Press any key to continue..."
    echo ""
	log "INFO" "Installing packages from $GITHUB_REPO_LINUX."
	tfw_install_packages $GITHUB_REPO_LINUX "${FILES_LINUX[@]}"
    if [ $? -ne 0 ]; then
        log "ERROR" "Failed to install packages."
        exit 2
    fi

	# tfw_install_packages $GITHUB_REPO_TEMPESTA "${FILES_TEMPESTA[@]}"
}

# Find all installed packages that suit *_FILES regular expressions and save
# them to RM_PACKAGES variable.
tfw_find_packages()
{
	log "INFO" "Searching for packages to be removed or updated."
	files=("${@}")

	for file in "${files[@]}"
	do
		#save file to one var
		log "INFO" "Searching for packages matching pattern: $file"
		PACKAGES=`dpkg -l | grep -P $file | awk '{print $2}' | xargs echo`

		if [ -z "$PACKAGES" ]; then
            log "INFO" "No packages found matching pattern: $file"
        else
            log "INFO" "Found packages for pattern $file: $PACKAGES"
            RM_PACKAGES="$RM_PACKAGES $PACKAGES"
        fi

	done
}

tfw_remove()
{
	log "INFO" "Starting the removal process for Tempesta FW packages."
	RM_PACKAGES=
	RM_METHOD=$1
	
	tfw_find_packages "${FILES_LINUX[@]}"
	tfw_find_packages "${FILES_TEMPESTA[@]}"
	if echo "$RM_PACKAGES" | grep -q '[^[:space:]]'; then
        log "INFO" "Packages found for removal: $RM_PACKAGES"
        log "INFO" "Removing packages: $RM_PACKAGES"
        apt-get $RM_METHOD $RM_PACKAGES
        if [ $? -eq 0 ]; then
            log "INFO" "Successfully removed packages: $RM_PACKAGES"
        else
            log "ERROR" "Failed to remove packages: $RM_PACKAGES"
            return 1
        fi
    else
        log "INFO" "No packages to remove."
    fi

	# User should check list of packages to remove, so don't remove them
	# one-by-one, combine into one command instead.	
}

tfw_confirm()
{
	local response
	local msg="${1:-Continue installing TempestaFW?} [y/N] "; shift

	read -r $* -p "$msg" response || echo
	case "$response" in
	[yY][eE][sS]|[yY])
		return 1
		;;
	*)
		log "INFO" "Installation was canceled."
		exit
		;;
	esac
}

tfw_try_distro()
{
	log "INFO" "Determining the operating system distribution."
	d_name=`cat /etc/os-release | grep PRETTY_NAME | cut -d '"' -f 2`
	log "INFO" "Detected distribution name: $d_name"

	case $d_name in
	"Debian GNU/Linux bullseye")
		DISTRO="debian-11"
		;;
	Ubuntu[[:space:]]20*)
		DISTRO="ubuntu-20"
		;;
	Ubuntu[[:space:]]22*)
		DISTRO="ubuntu-22"
		;;
	*)
		log "ERROR" "Installer does not support $d_name distro!"
		return 1
		;;
	esac
}

tfw_set_grub_default()
{
	log "INFO" "Setting GRUB default entry for Tempesta patched kernel."

	if [[ "$TFW_SKIP_GRUB_DFT" ]]; then
		log "INFO" "Skipping GRUB reconfiguration as requested."
		return
	fi

	u_entry=`grep menuentry /boot/grub/grub.cfg | grep 5.10.35.tfw | head -n1 | cut -d "'" -f 2`
	entry=`grep menuentry /boot/grub/grub.cfg | grep tempesta | head -n1 | cut -d "'" -f 2`

	if [[ ! "$entry" && ! "$u_entry" ]]; then
		log "ERROR" "Can't find Tempesta patched kernel in /boot/grub/grub.cfg!"
		return
	fi
	if [[ "$entry" ]]; then
		log "INFO" "Setting GRUB default to Tempesta kernel for Debian: $entry"
		echo "GRUB_DEFAULT='Advanced options for Debian GNU/Linux>$entry'" >> /etc/default/grub
	fi
	if [[ "$u_entry" ]]; then
		log "INFO" "Setting GRUB default to Tempesta kernel for Ubuntu: $entry"
		echo "GRUB_DEFAULT='Advanced options for Ubuntu>$u_entry'" >> /etc/default/grub
	fi

	update-grub
    if [ $? -eq 0 ]; then
        log "INFO" "GRUB update completed."
    else
        log "ERROR" "Failed to update GRUB."
        return 1
    fi
}

log "INFO" "Tempesta FW installation script started"

if [ $# -eq 0 ]; then
    log "ERROR" "No arguments provided."
    usage
    exit 1
fi

tfw_try_distro
if [ $? -ne 0 ]; then
    log "ERROR" "Unsupported distribution detected, unable to continue."
    exit 2
fi

args=$(getopt -o ":" -a -l "$LONG_OPTS" -- "$@")
if [ $? -ne 0 ]; then
    log "ERROR" "Invalid arguments provided."
    usage
    exit 2
fi
eval set -- "${args}"
for opt in ${args}
do
	case "$opt" in
	--install)
		tfw_install
		if [ $? -ne 0 ]; then
			log "ERROR" "Installation failed."
			exit 1
		fi
		tfw_set_grub_default # At the end of install set default kernel for GRUB.
		if [ $? -ne 0 ]; then
		    log "ERROR" "GRUB configuration failed."
    		exit 1
		fi
		;;
	--remove)
		tfw_remove remove
		if [ $? -ne 0 ]; then
			log "ERROR" "Failed to remove TempestaFW."
			exit 1
		fi
		exit
		;;
	--purge)
		tfw_remove purge
		if [ $? -ne 0 ]; then
			log "ERROR" "Failed to purge TempestaFW."
			exit 1
		fi
		exit
		;;
	--help)
		usage
		exit
		;;
	--no-grub-default)
		TFW_SKIP_GRUB_DFT=true
		;;
	"?")
		log "ERROR" "Invalid argument: $2"
		usage
		exit 2
		;;
	"--") ;;
	*)
		log "ERROR" "Bad command line argument: $opt"
		usage
		exit 2
		;;
	esac
done

echo ""
echo "Installation is completed!"
if [[ ! "$TFW_SKIP_GRUB_DFT" ]]; then
	echo "Reboot to finish installation of TempestaFW. The patched kernel"
	echo "is set as default."
else
	echo "Reboot to Tempesta patched kernel to run TempestaFW."
fi
echo ""
echo "More information about TempestaFW configuration and troubleshooting"
echo "can be found in readme and wiki on project page:"
echo "https://github.com/tempesta-tech/tempesta"
