/**
 *		Tempesta FW
 *
 * Tempesta Configuration Framework.
 *
 * Requirements:
 *  - The configuring process must be habitual for any system administrator.
 *    The best way would be to store the configuration in a plain text file
 *    with a syntax similar to Nginx configuration files.
 *  - An ability to specify relatively complex entities (lists, dictionaries,
 *    trees, etc).
 *  - Decomposition into modules. Other Tempesta subsystems should be able to
 *    register their sections in a configuration file. That should be possible
 *    for other kernel modules as well, so late binding has to be used.
 *  - An ability to refresh configuration in run time, at least for certain
 *    entities like lists of rules, etc.
 *  - An ability to manage very large lists (e.g. blocked IP addresses).
 *
 *  None of existing approaches (sysfs, configfs, sysctl, ioctl) mets all the
 *  requirements, so we implement our own subsystem for that.
 *
 *  Basically, we store configuration in plain-text files.
 *  Upon a "reload" event (triggered via sysctl) we read it via VFS and parse
 *  right in the kernel space.
 *  All the configuration files are parsed into a single tree, that represents
 *  all nested sections and their values.
 *  Various modules may create hooks on the tree. When a certain section is met,
 *  the corresponding subtree is passed into the registered callback. Therefore,
 *  the coupling between modules is reduced, and each module works with its own
 *  subtree and doesn't violate encapsulation of other modules.
 *
 * The configuration framework is decomposed into the following units:
 *  - cfg_userspace_if.c
 *     Delivers all the configuration from user-space to registered modules.
 *     Listens for start/stop/reload events via sysctl, reads the configuration
 *     via VFS, passes it to the parser, and then to the registered modules.
 *  - cfg_module.c
 *     An API for other modules that allows to register callbacks for various
 *     sections and directives, add some validation rules, etc.
 *  - cfg_parser.c
 *     Code that deserializes plain-text configuration into a tree of all
 *     nested sections and so on.
 *     Also the unit defines TfwCfgNode (the basic building block of the parsed
 *     configuration tree) and a bunch of methods for querying the parsed tree.
 *
 * Major TODO items:
 *  - Managing large sets of data via Tempesta DB.
 *  - "include" directives.
 *  - XPath-like tree querying.
 *  - References within the configuration file.
 *  - Improve efficiency.
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
#ifndef __TFW_CFG_H__
#define __TFW_CFG_H__

#include "cfg_module.h"
#include "cfg_userspace_if.h"

#endif /* __TFW_CFG_H__ */
