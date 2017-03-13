/**
 *		Tempesta FW
 *
 * HTTP/2 HPack parser test data.
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

static HPackTestData test [] = {

	{23, 0,
	 "\x40"                               /* == Literal indexed ==       */
	 "\x0A"                               /* Literal name (len = 10)     */
	 "\x63\x75\x73\x74\x6F\x6D\x2D\x6B"   /* custom-key                  */
	 "\x65\x79"                           /*                             */
	 "\x0D"                               /* Literal value (len = 13)    */
	 "\x63\x75\x73\x74\x6F\x6D\x2D\x68"   /* custom-header               */
	 "\x65\x61\x64\x65\x72"},             /*                             */

	{14, 0,
	 "\x04"                               /* == Literal not indexed ==   */
					      /* Indexed name (idx = 4)      */
					      /* :path			     */
	 "\x0C"                               /* Literal value (len = 12)    */
	 "\x2F\x73\x61\x6D\x70\x6C\x65\x2F"   /* /sample/path                */
	 "\x70\x61\x74\x68"},                 /*                             */

	{17, 0,
	 "\x10"                               /* == Literal never indexed == */
	 "\x08"                               /* Literal name (len = 8)      */
	 "\x70\x61\x73\x73\x77\x6F\x72\x64"   /* password                    */
	 "\x06"                               /* Literal value (len = 6)     */
	 "\x73\x65\x63\x72\x65\x74"},         /* secret                      */

	{1, 0,
	 "\x82"},                             /* == Indexed - Add ==         */
					      /* idx = 2		     */
					      /* :method		     */
					      /* GET			     */

	{19, -4096,
	 "\x82"                               /* == Indexed - Add ==         */
					      /* idx = 2		     */
					      /* :method		     */
					      /* GET			     */
	 "\x86"                               /* == Indexed - Add ==         */
					      /* idx = 6		     */
					      /* :scheme		     */
					      /* http			     */
	 "\x84"                               /* == Indexed - Add ==         */
					      /* idx = 4		     */
					      /* :path			     */
					      /* /			     */
	 "\x41"                               /* == Literal indexed ==       */
					      /* Indexed name (idx = 1)      */
					      /* :authority		     */
					      /* Literal value (len = 15)    */
	 "\x77\x77\x77\x2E\x65\x78\x61\x6D"   /* www.example.com             */
	 "\x70\x6C\x65\x2E\x63\x6F\x6D"},     /*                             */

	{14, 0,
	 "\x82"                               /* == Indexed - Add ==         */
					      /* idx = 2		     */
					      /* :method		     */
					      /* GET			     */
	 "\x86"                               /* == Indexed - Add ==         */
					      /* idx = 6		     */
					      /* :scheme		     */
					      /* http			     */
	 "\x84"                               /* == Indexed - Add ==         */
					      /* idx = 4		     */
					      /* :path			     */
					      /* /			     */
	 "\xBE"                               /* == Indexed - Add ==         */
					      /* idx = 62		     */
					      /* :authority		     */
					      /* www.example.com	     */
	 "\x58"                               /* == Literal indexed ==       */
					      /* Indexed name (idx = 24)     */
					      /* cache-control		     */
	 "\x08"                               /* Literal value (len = 8)     */
	 "\x6E\x6F\x2D\x63\x61\x63\x68\x65"}, /* no-cache                    */

	{29, 0,
	 "\x82"                               /* == Indexed - Add ==         */
					      /* idx = 2		     */
					      /* :method		     */
					      /* GET			     */
	 "\x87"                               /* == Indexed - Add ==         */
					      /* idx = 7		     */
					      /* :scheme		     */
					      /* https			     */
	 "\x85"                               /* == Indexed - Add ==         */
					      /* idx = 5		     */
					      /* :path			     */
					      /* /index.html		     */
	 "\xBF"                               /* == Indexed - Add ==         */
					      /* idx = 63		     */
					      /* :authority		     */
					      /* www.example.com	     */
	 "\x40"                               /* == Literal indexed ==       */
	 "\x0A"                               /* Literal name (len = 10)     */
	 "\x63\x75\x73\x74\x6F\x6D\x2D\x6B"   /* custom-key                  */
	 "\x65\x79"                           /*                             */
	 "\x0C"                               /* Literal value (len = 12)    */
	 "\x63\x75\x73\x74\x6F\x6D\x2D\x76"   /* custom-value                */
	 "\x61\x6C\x75\x65"},                 /*                             */

	{17, -4096,
	 "\x82"                               /* == Indexed - Add ==         */
					      /* idx = 2		     */
					      /* :method		     */
					      /* GET			     */
	 "\x86"                               /* == Indexed - Add ==         */
					      /* idx = 6		     */
					      /* :scheme		     */
					      /* http			     */
	 "\x84"                               /* == Indexed - Add ==         */
					      /* idx = 4		     */
					      /* :path			     */
					      /* /			     */
	 "\x41"                               /* == Literal indexed ==       */
					      /* Indexed name (idx = 1)      */
					      /* :authority		     */
	 "\x8C"                               /* Literal value (len = 12)    */
					      /* Huffman encoded:	     */
	 "\xF1\xE3\xC2\xE5\xF2\x3A\x6B\xA0"   /* www.example.com             */
	 "\xAB\x90\xF4\xFF"},                 /*                             */

	{12, 0,
	 "\x82"                               /* == Indexed - Add ==         */
					      /* idx = 2		     */
					      /* :method		     */
					      /* GET			     */
	 "\x86"                               /* == Indexed - Add ==         */
					      /* idx = 6		     */
					      /* :scheme		     */
					      /* http			     */
	 "\x84"                               /* == Indexed - Add ==         */
					      /* idx = 4		     */
					      /* :path			     */
					      /* /			     */
	 "\xBE"                               /* == Indexed - Add ==         */
					      /* idx = 62		     */
					      /* :authority		     */
					      /* www.example.com	     */
	 "\x58"                               /* == Literal indexed ==       */
					      /* Indexed name (idx = 24)     */
					      /* cache-control		     */
	 "\x86"                               /* Literal value (len = 6)     */
					      /* Huffman encoded:	     */
	 "\xA8\xEB\x10\x64\x9C\xBF"},         /* no-cache                    */

	{24, 0,
	 "\x82"                               /* == Indexed - Add ==         */
					      /* idx = 2		     */
					      /* :method		     */
					      /* GET			     */
	 "\x87"                               /* == Indexed - Add ==         */
					      /* idx = 7		     */
					      /* :scheme		     */
					      /* https			     */
	 "\x85"                               /* == Indexed - Add ==         */
					      /* idx = 5		     */
					      /* :path			     */
					      /* /index.html		     */
	 "\xBF"                               /* == Indexed - Add ==         */
					      /* idx = 63		     */
					      /* :authority		     */
					      /* www.example.com	     */
	 "\x40"                               /* == Literal indexed ==       */
	 "\x88"                               /* Literal name (len = 8)      */
					      /* Huffman encoded:	     */
	 "\x25\xA8\x49\xE9\x5B\xA9\x7D\x7F"   /* custom-key                  */
	 "\x89"                               /* Literal value (len = 9)     */
					      /* Huffman encoded:	     */
	 "\x25\xA8\x49\xE9\x5B\xB8\xE8\xB4"   /* custom-value                */
	 "\xBF"}                              /*                             */
};
