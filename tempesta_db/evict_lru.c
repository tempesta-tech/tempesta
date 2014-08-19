/**
 *		Tempesta DB
 *
 * LRU eviction stratagy.
 *
 * The storage works in deffered interrupt context, so it can't sleep on
 * disk operations, but it is persistent. So all data is mmap()'ed and
 * mlock()'ed which makes Linux syncronize the memory region with disk
 * and vise versa. Generic storage is applicable for application caches,
 * filter rules, access log, traffic dumps and resolver results.
 *
 * The storage works with plugable replicator and cache evictor.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
