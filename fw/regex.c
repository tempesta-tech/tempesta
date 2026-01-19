/**
 *		Tempesta FW
 *
 * Copyright (C) 2026 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * Prototype for fast percentiles calculation.
 */

#include "regex.h"
#include "log.h"
#include "regex/kmod/rex.h"
#include "tempesta_fw.h"

static char *regex_setup_script_path = "/lib/tempesta/scripts/regex_setup.sh";
module_param(regex_setup_script_path, charp, 0444);
MODULE_PARM_DESC(regex_setup_script_path, "Path to regex user space helper.");

/* Path to folder where tfw_write_regexp() writes regexp files for compilation. */
static char *regex_dir_path = "/opt/tempesta/regex";
module_param(regex_dir_path, charp, 0444);
MODULE_PARM_DESC(regex_dir_path, "Path to regex databases.");

/* Number of databases which we will use to look for expression. */
static unsigned short number_of_regex;
/*
 * Count of expressions. Could be used to know wich exactly expression was
 * matched. Also used as ID in the database.
 */
static unsigned short number_of_db_regex;

/*
 * Here, we create a text file for each regex string that can be read by hscollider.
 * Next, hscollider compiles it and saves it to a temporary database.
 * It is then loaded into the regex module database.
 * All operations except creation are handled in the script regex_setup.sh.
 *
 * Since this is a potentially possible scenario in which one database contains
 * several expressions, we count both the number of databases(see number_of_regex)
 * and the number of expressions(see number_of_regex).
 *
 * Directory /opt/tempesta/regex is created from tempesta.sh script.
 *
 * @arg - expression to write into the database.
 * @out_db_num - the database ID in which the expression has been written
 */
int
tfw_write_regex(const char *arg, unsigned short *out_db_num)
{
	struct file *fl;
	loff_t off = 0;
	size_t size;
	char reg_number[8];
	char *file_path;
	int r, len1, len = strlen(arg);

	/*
	 * Length of regexp string must be greater or equal to sizeof(number_of_regex)
	 * because we use memory where this string was allocated for storing id
	 * of the regexp.
	 */
	if (len < sizeof(number_of_regex)) {
		T_ERR_NL("String of regex too short.\n");
		return -EINVAL;
	}

	if (number_of_db_regex == USHRT_MAX) {
		T_ERR_NL("Maximum number of regular expression databases has been reached.\n");
		return -EINVAL;
	}

	if (number_of_regex == USHRT_MAX) {
		T_ERR_NL("Maximum number of regular expressions has been reached.\n");
		return -EINVAL;
	}

	if (strlen(regex_dir_path) > PATH_MAX) {
		T_ERR_NL("Too large path for regex directory.");
		return -EINVAL;
	}

	++number_of_db_regex;

	/* Calculate size. */
	size = snprintf(NULL, 0, "%s/%u.txt", regex_dir_path,
			number_of_db_regex);
	/* add null */
	size += 1;
	if (size > PATH_MAX) {
		T_ERR_NL("Too large path for regex file.");
		return -EINVAL;
	}

	file_path = kmalloc(size, GFP_KERNEL);
	if (!file_path)
		return -ENOMEM;

	snprintf(file_path, size, "%s/%u.txt", regex_dir_path,
		 number_of_db_regex);

	fl = filp_open(file_path, O_CREAT | O_WRONLY, 0600);
	if (IS_ERR(fl)) {
		T_ERR_NL("Cannot create regex file %s. Check if the directory exists.\n",
			 regex_dir_path);
		kfree(file_path);
		return -EINVAL;
	}
	BUG_ON(!fl || !fl->f_path.dentry);

	if (!fl->f_op->fallocate) {
		T_ERR_NL("File requires filesystem with fallocate support\n");
		kfree(file_path);
		filp_close(fl, NULL);
		return -EINVAL;
	}

	++number_of_regex;
	snprintf(reg_number, sizeof(reg_number), "%i:", number_of_regex);
	len1 = strlen(reg_number);
	r = kernel_write(fl, (void *)reg_number, len1, &off);
	if (r != len1)
		goto err;

	r = kernel_write(fl, (void *)arg, len, &off);
	if (r != len)
		goto err;

	r = kernel_write(fl, "\n", 1, &off);
	if (r != 1)
		goto err;

	kfree(file_path);
	filp_close(fl, NULL);

	*out_db_num = number_of_db_regex;

	return 0;
err:
	T_ERR_NL("Cannot write regex\n");
	kfree(file_path);
	filp_close(fl, NULL);
	return r;
}

bool
tfw_match_regex(const char *cstr, const TfwStr *arg)
{
	int r;
	struct rex_scan_attr attr = {};

	memcpy(&attr.database_id, cstr, sizeof(unsigned short));

	if (!arg->len)
		return false;

	r = rex_scan_tfwstr(arg, &attr);
	return (!r && attr.nr_events && attr.last_event.expression);
}

static int
tfw_regex_start(void)
{
	int ret;
	size_t size;
	static const char regex_dir_var_name[] = "REGEX_DIR_PATH=";
	char *regex_path;
	char *envp[] = {"HOME=/", "TERM=linux",
			"PATH=/sbin:/bin:/usr/sbin:/usr/bin",
			NULL, NULL};
	char *argv[] = {
		"/bin/bash",
		"-i", (char *)regex_setup_script_path,
		NULL };

	size = sizeof(regex_dir_var_name) + strlen(regex_dir_path);
	if (size > PATH_MAX) {
		T_ERR_NL("Too large path for regex directory path.");
		return -EINVAL;
	}

	regex_path = kmalloc(size, GFP_KERNEL);
	ret = snprintf(regex_path, size, "%s%s", regex_dir_var_name,
		       regex_dir_path);
	if (ret >= size) {
		T_WARN("Wrong path size for regex directory path.");
		kfree(regex_path);
		return -EINVAL;
	}

	envp[3] = regex_path;

	T_LOG_NL("Compiling regex\n");
	/* Execute helper script. */
	ret = call_usermodehelper("/bin/bash", argv, envp, UMH_WAIT_PROC);
	if (ret) {
		T_ERR_NL("Can't compile regex database. err = %#x. Please check path %s\n",
			 ret, regex_setup_script_path);
		kfree(regex_path);
		return ret;
	}
	/*
	 * When the compilation is finished, reset these counters to have
	 * correct values during live reconfiguration.
	 */
	number_of_regex = 0;
	number_of_db_regex = 0;
	kfree(regex_path);

	return 0;
}

static TfwCfgSpec tfw_regex_specs[] = {
	{ 0 }
};

TfwMod tfw_regex_mod = {
	.name	= "regex",
	.start	= tfw_regex_start,
	.specs	= tfw_regex_specs
};

int
tfw_regex_init(void)
{
	tfw_mod_register(&tfw_regex_mod);
	return 0;
}

void
tfw_regex_exit(void)
{
	tfw_mod_unregister(&tfw_regex_mod);
}
