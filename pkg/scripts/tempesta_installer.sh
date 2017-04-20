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
declare -r GITHUB_REPO_LINUX="linux-4.8.15-tfw"

#TODO: currently Debian 9 is the only supported distribution, other
# distributions may have other names.
# Don't install packages with debug symbols.
declare -a FILES_LINUX=("linux-image-[\d.]+-tempesta-amd64-unsigned"
                        "linux-kbuild-[\d.]+_[\d.]+"
                        "linux-headers-[\d.]+-tempesta")
declare -a FILES_TEMPESTA=("tempesta-fw-dkms")


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
# Github restricts 60 API requests per hour without autorisation. Enough for
# our needs.
tfw_download()
{
	repo="${1}"
	uri="https://api.github.com/repos/$GITHUB_USER/$1/releases/latest"

	links=`curl -s $uri | grep browser_download_url | grep -P $2 | cut -d '"' -f 4`

	if [[ ! "$links" ]]; then
		# Github api rate limit exceded
		echo "Github API rate limit exceded: more than 60 requests" \
		     "during last hour. Try again later."

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
	echo "Install dependencies ..."
	apt-get install -y dkms libboost-dev libboost-program-options-dev kdump-tools
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

args=$(getopt -o "" -a -l "$LONG_OPTS" -- "$@")
eval set -- "${args}"
while :; do
	case "$1" in
		# Selectors for internal usage.
		--install)
			tfw_install
			exit
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
		*)
			echo "Bad command line argument: $opt"
			usage
			exit 2
			;;
	esac
done
