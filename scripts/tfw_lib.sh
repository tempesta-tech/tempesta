# Common utilities for Tempesta scripts
#
# Copyright (C) 2016-2017 Tempesta Technologies, Inc.
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

# Resolve root to absolute path which is handy for kernel.
# pwd is used instead of readlink to avoid symlink resolution.
TFW_ROOT=$(dirname "$0")
pushd "$TFW_ROOT/.." > /dev/null
TFW_ROOT="$(pwd)"
popd > /dev/null

declare -r TFW_NAME=`basename $0` # program name (comm name in ps)
declare -r TFW_NETDEV_PATH="/sys/class/net/"
declare -r TFW_SCRIPTS="$TFW_ROOT/scripts"
declare -r CPUS_N=$(grep -c processor /proc/cpuinfo)

calc()
{
	echo "$1" | bc -iq | tail -1
}

distribute_queues()
{
	dev=$1
	RXQ_MAX=$2

	echo "...set rx channels to $RXQ_MAX, please wait..."
	# Set maximum number of available channels for better
	# packets hashing.
	res=$(ethtool -L $dev rx $RXQ_MAX 2>&1)
	if [ $? -ne 0 -a -z "$(echo $res | grep -P '^rx unmodified, ignoring')" ]
	then
		printf "Error: cannot set new queues count for %s:\n %s\n" \
			$dev "$res"
		return
	fi

	# Wait for the interface reconfiguration.
	opstate="$TFW_NETDEV_PATH/$dev/operstate"
	while [ "$(cat $opstate)" = "down" ]; do
		sleep 1
	done

	# Interrupts may not have interface-like description in
	# '/proc/interrupts' - so, to find the vectors we also need
	# to check the MSI directory for device.
	dev_irqs_path="/sys/class/net/$dev/device/msi_irqs"
	irqs=($(grep $dev /proc/interrupts | sed -e 's/\s*\|:.*//g'))
	if [ -z "$irqs" -a -d $dev_irqs_path ]; then
		irqs=($(ls $dev_irqs_path))
	fi

	if [ -z "$irqs" ]; then
		echo "Error: cannot find interrupts for $dev"
		return
	fi

	# Skip the first IRQ since this is general async interrupt
	# for device (not assigned to any of the queues).
	irqs=(${irqs[@]:1})
	irq0=${irqs[0]}
	for i in ${irqs[@]}; do
		# Wrap around CPU mask if number of queues is
		# larger than CPUS_N.
		if [ $(calc "$i - $irq0") -gt $CPUS_N ]; then
			irq0=$i;
		fi
		perl -le '
			my $a = 1 << ('$i' - '$irq0');
			if ($a <= 0x80000000) {
				printf("%x\n", $a)
			} else {
				$a = $a / 0x100000000;
				printf("%x,00000000\n", $a)
			}
		' > /proc/irq/$i/smp_affinity
	done
}

# Enable RSS for networking interfaces. Enable RPS for those devices which
# doesn't have enough hardware queues.
tfw_set_net_queues()
{
	devs=$1
	min_queues=$(calc "$CPUS_N / 2")
	cpu_mask=$(perl -le 'printf("%x", (1 << '$CPUS_N') - 1)')

	for dev in $devs; do
		queues=$(ethtool -l $dev 2>/dev/null \
				| grep -m 1 RX | sed -e 's/RX\:\s*//')
		if [ -n "$queues" -a ${queues:-0} -gt $min_queues ]; then
			# Switch off RPS for multi-queued interfaces.
			for rx in $TFW_NETDEV_PATH/$dev/queues/rx-*; do
				echo 0 > $rx/rps_cpus
			done

			echo "...distribute $dev queues"
			distribute_queues $dev $queues
		else
			echo "...enable RPS on $dev"
			for rx in $TFW_NETDEV_PATH/$dev/queues/rx-*; do
				echo $cpu_mask > $rx/rps_cpus
			done
		fi
	done
}
