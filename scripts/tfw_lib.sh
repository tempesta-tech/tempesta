# Common utilities for Tempesta scripts
#
# Copyright (C) 2016-2026 Tempesta Technologies, Inc.
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
declare -r TFW_SCRIPTS="$TFW_ROOT/scripts"
declare OUTPUT_TIME=false

log()
{
  local message="$1"
  if "$OUTPUT_TIME"; then
    echo "$(date '+%H:%M:%S') $message"
  else
    echo "$message"
  fi
}
