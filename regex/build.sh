#!/bin/bash -xe

kernel_source_dir="$1"
linux_image=/boot/"vmlinuz-${kernelver}"
shift 1

# Make our own source tree and extract vmlinux into it.
subdirs=$(ls -A "${kernel_source_dir}"/)
mkdir -p linux
for d in $subdirs; do
    ln -s "${kernel_source_dir}"/"$d" linux/"$d"
done

linux/scripts/extract-vmlinux "${linux_image}" \
    > linux/vmlinux

exec make -C linux "$@"
