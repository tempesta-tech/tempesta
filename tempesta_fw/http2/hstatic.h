/**
 *		Tempesta FW
 *
 * Static table from HPACK standard (RFC-7541).
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

#ifndef HPACK_STATIC_H
#define HPACK_STATIC_H

#include "common.h"
#include "../str.h"
#include "hpack.h"
#include "hindex.h"

typedef struct {
	HPackStr name;
	HPackStr value;
} HPackStatic;

static const HPackStatic static_data [] = {
	{{":authority", 10, 0, 0},                  {NULL, 0, 0, 0}},
	{{":method", 7, 0, 0},                      {"GET", 3, 0, 0}},
	{{":method", 7, 0, 0},                      {"POST", 4, 0, 0}},
	{{":path", 5, 0, 0},                        {"/", 1, 0, 0}},
	{{":path", 5, 0, 0},                        {"/index.html", 11, 0, 0}},
	{{":scheme", 7, 0, 0},                      {"http", 4, 0, 0}},
	{{":scheme", 7, 0, 0},                      {"https", 5, 0, 0}},
	{{":status", 7, 0, 0},                      {"200", 3, 0, 0}},
	{{":status", 7, 0, 0},                      {"204", 3, 0, 0}},
	{{":status", 7, 0, 0},                      {"206", 3, 0, 0}},
	{{":status", 7, 0, 0},                      {"304", 3, 0, 0}},
	{{":status", 7, 0, 0},                      {"400", 3, 0, 0}},
	{{":status", 7, 0, 0},                      {"404", 3, 0, 0}},
	{{":status", 7, 0, 0},                      {"500", 3, 0, 0}},
	{{"accept-charset", 14, 0, 0},              {NULL, 0, 0, 0}},
	{{"accept-encoding", 15, 0, 0},             {"gzip, deflate", 13, 0, 0}},
	{{"accept-language", 15, 0, 0},             {NULL, 0, 0, 0}},
	{{"accept-ranges", 13, 0, 0},               {NULL, 0, 0, 0}},
	{{"accept", 6, 0, 0},                       {NULL, 0, 0, 0}},
	{{"access-control-allow-origin", 27, 0, 0}, {NULL, 0, 0, 0}},
	{{"age", 3, 0, 0},                          {NULL, 0, 0, 0}},
	{{"allow", 5, 0, 0},                        {NULL, 0, 0, 0}},
	{{"authorization", 13, 0, 0},               {NULL, 0, 0, 0}},
	{{"cache-control", 13, 0, 0},               {NULL, 0, 0, 0}},
	{{"content-disposition", 19, 0, 0},         {NULL, 0, 0, 0}},
	{{"content-encoding", 16, 0, 0},            {NULL, 0, 0, 0}},
	{{"content-language", 16, 0, 0},            {NULL, 0, 0, 0}},
	{{"content-length", 14, 0, 0},              {NULL, 0, 0, 0}},
	{{"content-location", 16, 0, 0},            {NULL, 0, 0, 0}},
	{{"content-range", 13, 0, 0},               {NULL, 0, 0, 0}},
	{{"content-type", 12, 0, 0},                {NULL, 0, 0, 0}},
	{{"cookie", 6, 0, 0},                       {NULL, 0, 0, 0}},
	{{"date", 4, 0, 0},                         {NULL, 0, 0, 0}},
	{{"etag", 4, 0, 0},                         {NULL, 0, 0, 0}},
	{{"expect", 6, 0, 0},                       {NULL, 0, 0, 0}},
	{{"expires", 7, 0, 0},                      {NULL, 0, 0, 0}},
	{{"from", 4, 0, 0},                         {NULL, 0, 0, 0}},
	{{"host", 4, 0, 0},                         {NULL, 0, 0, 0}},
	{{"if-match", 8, 0, 0},                     {NULL, 0, 0, 0}},
	{{"if-modified-since", 17, 0, 0},           {NULL, 0, 0, 0}},
	{{"if-none-match", 13, 0, 0},               {NULL, 0, 0, 0}},
	{{"if-range", 8, 0, 0},                     {NULL, 0, 0, 0}},
	{{"if-unmodified-since", 19, 0, 0},         {NULL, 0, 0, 0}},
	{{"last-modified", 13, 0, 0},               {NULL, 0, 0, 0}},
	{{"link", 4, 0, 0},                         {NULL, 0, 0, 0}},
	{{"location", 8, 0, 0},                     {NULL, 0, 0, 0}},
	{{"max-forwards", 12, 0, 0},                {NULL, 0, 0, 0}},
	{{"proxy-authenticate", 18, 0, 0},          {NULL, 0, 0, 0}},
	{{"proxy-authorization", 19, 0, 0},         {NULL, 0, 0, 0}},
	{{"range", 5, 0, 0},                        {NULL, 0, 0, 0}},
	{{"referer", 7, 0, 0},                      {NULL, 0, 0, 0}},
	{{"refresh", 7, 0, 0},                      {NULL, 0, 0, 0}},
	{{"retry-after", 11, 0, 0},                 {NULL, 0, 0, 0}},
	{{"server", 6, 0, 0},                       {NULL, 0, 0, 0}},
	{{"set-cookie", 10, 0, 0},                  {NULL, 0, 0, 0}},
	{{"strict-transport-security", 25, 0, 0},   {NULL, 0, 0, 0}},
	{{"transfer-encoding", 17, 0, 0},           {NULL, 0, 0, 0}},
	{{"user-agent", 10, 0, 0},                  {NULL, 0, 0, 0}},
	{{"vary", 4, 0, 0},                         {NULL, 0, 0, 0}},
	{{"via", 3, 0, 0},                          {NULL, 0, 0, 0}},
	{{"www-authenticate", 16, 0, 0},            {NULL, 0, 0, 0}}
};

#define HPACK_STATIC_ENTRIES (sizeof(static_data) / sizeof(HPackStatic))

static HPackEntry static_table [HPACK_STATIC_ENTRIES];

#endif
