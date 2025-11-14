#
# Tempesta FW regexp script.
#
# Copyright (C) 2025 Tempesta Technologies, Inc.
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

regex_tmp_path="/tmp/tempesta"

print_dmesg()
{
	echo "[tempesta regexp]: $@" > /dev/kmsg
}

start_regex()
{
	count=0

	rmdir /sys/kernel/config/rex/* 2> /dev/null

	for filename in ${regex_tmp_path}/*.txt; do
	    name=$(basename "$filename" .txt)
	    if [[ "$name" != "*" ]]; then
		db_path="/sys/kernel/config/rex/${name}"

		rm -rf ${regex_tmp_path}/out/ && mkdir ${regex_tmp_path}/out
		r=$(hscollider -e ${filename} -V5 -ao ${regex_tmp_path}/out/ -n1 2>&1)
		if [ $? -ne 0 ]; then
			print_dmesg $r
			echo "Error: Can't compile regexp. See dmesg for details."
			return 1
		fi
		failed=$(grep "Expressions with failures" <<< "$r" | awk '{print $NF}')
		if [ $failed -ne 0 ]; then
			regexp=$(cat ${filename})
			print_dmesg "Failed compilation of \"${filename}\" contains: ${regexp}"
			print_dmesg $r
			echo "Error: Can't compile regexp. See dmesg for details."
			return 1
		fi
		mkdir $db_path
		r=$(dd if=$(echo ${regex_tmp_path}/out/*.db) of=${db_path}/database 2>&1)
		if [ $? -ne 0 ]; then
			print_dmesg $r
			echo "Error: Can't copy regexp to database. See dmesg for details."
			return 1
		fi
		cat "${filename}" > ${db_path}/note
		echo "$name" > ${db_path}/id
		((count++))
	    fi
	done

	if [ $count -gt 0 ]; then
		print_dmesg "Compiled ${count} regexp databases"
	fi
}

stop_regex()
{
	rm -f ${regex_tmp_path}/*.txt
	rm -rf ${regex_tmp_path}/out
	rmdir /sys/kernel/config/rex/* 2> /dev/null
}
