# Common utilities for Tempesta scripts
#
# Copyright (C) 2016 Tempesta Technologies, Inc.
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
	RXQ_MAX=$(ethtool -l $dev 2>/dev/null \
		  | grep -m 1 RX | sed -e 's/RX\:\s*//')

	echo "...distribute $dev queues"

	if [ -n "$RXQ_MAX" -a $RXQ_MAX -gt 0 ]; then
		echo "...set rx channels to $RXQ_MAX, please wait..."
		# Set maximum number of available channels for better
		# packets hashing.
		ethtool -L $dev rx $RXQ_MAX >/dev/null 2>&1
		# Wait for the interface reconfiguration.
		opstate="$TFW_NETDEV_PATH/$dev/operstate"
		while [ "$(cat $opstate)" = "down" ]; do
			sleep 1
		done
	else
		echo "...0 channels for $dev - skip"
		return
	fi

	irqs=($(grep $dev /proc/interrupts | sed -e 's/\s*\|:.*//g'))
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

# Enable RPS for specified, or all by default, networking interfaces.
# This is required for loopback interface for proper local delivery,
# but physical interfaces can have RSS.
tfw_set_net_queues()
{
	devs=$1
	min_queues=$(calc "$CPUS_N / 2")
	cpu_mask=$(perl -le 'printf("%x", (1 << '$CPUS_N') - 1)')

	for dev in $devs; do
		queues=$(ls -d /sys/class/net/$dev/queues/rx-* | wc -l)
		if [ $queues -le $min_queues ]; then
			echo "...enable RPS on $dev"
			for rx in $TFW_NETDEV_PATH/$dev/queues/rx-*; do
				echo $cpu_mask > $rx/rps_cpus
			done
		else

			# Switch off RPS for multi-queued interfaces.
			for rx in $TFW_NETDEV_PATH/$dev/queues/rx-*; do
				echo 0 > $rx/rps_cpus
			done

			distribute_queues $dev
		fi
	done
}

