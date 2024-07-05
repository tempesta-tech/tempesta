#!/bin/bash

rmdir /sys/kernel/config/rex/* 2> /dev/null

script_path="$(dirname $0)"
tmp_path="/tmp/tempesta"

echo "Start compilation of regex." > /dev/kmsg

for filename in ${tmp_path}/*.txt; do
    name=$(basename "$filename" .txt)
    if [[ "$name" != "*" ]]; then
        db_path="/sys/kernel/config/rex/${name}"

        rm -rf ${tmp_path}/out/ && mkdir ${tmp_path}/out
        #${script_path}/hscollider -e ${filename} -ao ${tmp_path}/out/ -n1 #this version for single block strings
        #${script_path}/hscollider -e ${filename} -V5 -ao ${tmp_path}/out/ -n1 #this version starts hscollider from scripts directory
        hscollider -e ${filename} -V5 -ao ${tmp_path}/out/ -n1

        mkdir $db_path
        dd if=$(echo ${tmp_path}/out/*.db) of=${db_path}/database
        cat "${filename}" > ${db_path}/note
        echo "$name" > ${db_path}/id
    fi
done

echo "Compilation of regex files is complete." > /dev/kmsg

