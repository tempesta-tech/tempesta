/**
 *		Tempesta FW
 *
 * HTTP/2 Compare strings tests.
 *
 * Copyright (C) 2017 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "../../pool.h"
#include "../../str.h"
#include "../buffers.h"

TfwStr test1 = { "Tests is tests...", NULL, 17, 0, 0 };

TfwStr test2[4] = {
	{ "Tests", NULL, 5, 0, 0 },
	{ " is ", NULL, 4, 0, 0 },
	{ "tests", NULL, 5, 0, 0 },
	{ "...", NULL, 3, 0, 0 }
};
TfwStr test3 = { "Tests is tests..", NULL, 16, 0, 0 };
TfwStr test4 = { "Tests is tests...!", NULL, 18, 0, 0 };
TfwStr test7 = { test2, NULL, 17, 0, 4 << 8 };

int common_cdecl
main(void)
{
	static TfwStr fragments[3];
	static TfwStr root;

	buffer_str_print(&test1);
	puts("");
	buffer_str_print(&test7);
	puts("");
	printf("Hash: %08" PRIxPTR "\n", buffer_str_hash(&test1));
	printf("Hash: %08" PRIxPTR "\n", buffer_str_hash(&test7));
	printf("Compare: %" PRIdPTR "\n", buffer_str_cmp(&test1, &test7));
	printf("Compare: %" PRIdPTR "\n", buffer_str_cmp(&test3, &test7));
	printf("Compare: %" PRIdPTR "\n", buffer_str_cmp(&test4, &test7));
	printf("Compare: %" PRIdPTR "\n",
	       buffer_str_cmp_plain((unsigned char *)"Tests is tests...", test2,
				    17));
	printf("Compare: %" PRIdPTR "\n",
	       buffer_str_cmp_plain((unsigned char *)"Tests is tests..!", test2,
				    16));
	printf("Compare: %" PRIdPTR "\n",
	       buffer_str_cmp_plain((unsigned char *)"Tests is tests`", test2,
				    15));
	printf("Compare: %" PRIdPTR "\n",
	       buffer_str_cmp_plain((unsigned char *)"Tests is tests ", test2,
				    15));
	return 0;
}
