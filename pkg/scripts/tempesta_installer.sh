#!/bin/bash
#
# Tempesta FW install script.
#
# Copyright (C) 2017 Tempesta Technologies, Inc.
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

declare -r TFW_NAME=`basename $0`
declare -r LONG_OPTS="help,install,remove,purge"
declare -r DOWNLOAD_DIR=tfw_downloads

declare -r GITHUB_USER="tempesta-tech"
declare -r GITHUB_REPO_TEMPESTA="tempesta"
declare -r GITHUB_REPO_LINUX="linux-4.9.35-tfw"

#TODO: currently Debian 9 is the only supported distribution, other
# distributions may have other names.
# Don't install packages with debug symbols.
declare -a FILES_LINUX=("linux-image-[\d.]+-tempesta(.bpo)?-amd64_"
                        "linux-kbuild-[\d.]+_[\d.]+"
                        "linux-headers-[\d.]+-tempesta"
                        "linux-compiler")
declare -a FILES_TEMPESTA=("tempesta-fw-dkms")

if [ "$(id -u)" != "0" ]; then
	echo "This script must be run as root" 2>&1
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

# Use github API to get information about latest release.
#
# `latest` release shows ONLY releases which are not marked as `prereleases`.
# Github restricts 60 API requests per hour without authorisation. Enough for
# our needs.
tfw_download()
{
	repo="${1}"
	tag=`curl -s https://api.github.com/repos/$GITHUB_USER/$repo/tags | grep -P 'name": "\d+' | cut -d '"' -f 4 | sort -V -r | head -n1`
	if [[ ! "$tag" ]]; then
		echo "Can't find latest release in repo: https://github.com/$GITHUB_USER/$repo"
		#TODO: show next line only if received 403 status code.
		echo "Or may be Github API rate limit exceeded."
		exit 2
	fi

	release_tag="$DISTRO/$tag"
	uri="https://api.github.com/repos/$GITHUB_USER/$repo/releases/tags/${release_tag}"

	links=`curl -s $uri | grep browser_download_url | grep -P "$2" | cut -d '"' -f 4`
	if [[ ! "$links" ]]; then
		echo "Can't download file $2 from release ${release_tag} in repo:"
		echo "https://github.com/$GITHUB_USER/$repo"
		#TODO: show next line only if received 403 status code.
		echo "Or may be Github API rate limit exceeded."
		exit 2
	fi

	for file in ${links}
	do
		wget -q --show-progress -P $DOWNLOAD_DIR/$repo $file
	done
}

tfw_install_packages()
{
	repo="${1}"
	shift
	files=("${@}")

	echo "Downloading latest packages from github.com/$GITHUB_USER/$repo ..."
	mkdir -p $DOWNLOAD_DIR/$repo

	for file in "${files[@]}"
	do
		tfw_download $repo $file
	done

	# Packages can depend on each other, install with single command to
	# make all packages setup correctly.
	dpkg -R -i $DOWNLOAD_DIR/$repo
}

tfw_install_deps()
{
	echo ""
	echo "Install dependencies ..."
	APT_OPTS=

	case $DISTRO in
	"debian-8")
		echo ""
		echo "Installation on Debian 8 requires updating system from"
		echo "jessie-backports repository before installing TempestaFW."
		tfw_confirm

		echo "deb http://deb.debian.org/debian/ " \
		        "jessie-backports main" >> /etc/apt/sources.list
		apt-get update
		apt-get -t jessie-backports dist-upgrade -y
		APT_OPTS="-t jessie-backports"
		;;
	*)
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

	echo ""
}

tfw_install()
{
	rm -rf $DOWNLOAD_DIR
	mkdir -p $DOWNLOAD_DIR

	tfw_install_deps
	# TempestaFW is shipped as DKMS module. By default, dkms framework
	# installs module only for running kernel. Configure dkms to install
	# module to all kernels. BUILD_EXCLUSIVE variable in TempestaFW's
	# dkms.conf will prevent building against unsupported kernels.
	echo -e "autoinstall_all_kernels=\"yes\"" >> /etc/dkms/framework.conf

	tfw_install_packages $GITHUB_REPO_LINUX "${FILES_LINUX[@]}"
	tfw_install_packages $GITHUB_REPO_TEMPESTA "${FILES_TEMPESTA[@]}"
}

# Find all installed packages that suit *_FILES regular expressions and save
# them to RM_PACKAGES variable.
tfw_find_packages()
{
	files=("${@}")

	for file in "${files[@]}"
	do
		#save file to one var
		PACKAGES=`dpkg -l | grep -P $file | awk '{print $2}' | xargs echo`
		RM_PACKAGES="$RM_PACKAGES $PACKAGES"
	done
}

tfw_remove()
{
	RM_PACKAGES=
	RM_METHOD=$1

	tfw_find_packages "${FILES_LINUX[@]}"
	tfw_find_packages "${FILES_TEMPESTA[@]}"

	# User should check list of packages to remove, so don't remove them
	# one-by-one, combine into one command instead.
	apt-get $RM_METHOD $RM_PACKAGES
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
		echo "Installation was canceled."
		exit
		;;
	esac
}

tfw_try_distro()
{
	d_name=`cat /etc/os-release | grep PRETTY_NAME | cut -d '"' -f 2`

	case $d_name in
	"Debian GNU/Linux 8 (jessie)")
		DISTRO="debian-8"
		;;
	"Debian GNU/Linux 9 (stretch)")
		DISTRO="debian-9"
		;;
	*)
		echo "Installer does not support $d_name distro!"
		exit 2
		;;
	esac
}

tfw_set_grub_default()
{
	if [[ "$TFW_SKIP_GRUB_DFT" ]]; then
		return
	fi

	entry=`grep menuentry /boot/grub/grub.cfg | grep tempesta | head -n1 | cut -d "'" -f 2`
	if [[ ! "$entry" ]]; then
		echo "Error: Can't find Tempesta patched kernel in /boot/grub/grub.cfg!"
		return
	fi

	echo "GRUB_DEFAULT='Advanced options for Debian GNU/Linux>$entry'" >> /etc/default/grub
	update-grub
}


tfw_try_distro

args=$(getopt -o ":" -a -l "$LONG_OPTS" -- "$@")
eval set -- "${args}"
for opt in ${args}
do
	case "$opt" in
	--install)
		tfw_install
		;;
	--remove)
		tfw_remove remove
		exit
		;;
	--purge)
		tfw_remove purge
		exit
		;;
	--help)
		usage
		exit
		;;
	--no-grub-default)
		TFW_SKIP_GRUB_DFT=true
		;;
	"--") ;;
	*)
		echo "Bad command line argument: $opt"
		usage
		exit 2
		;;
	esac
done

# At the end of install set default kernel for GRUB.
tfw_set_grub_default

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

