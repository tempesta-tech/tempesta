/**
 *		Tempesta TLS
 *
 * Generic ASN.1 processing.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2020 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <linux/slab.h>

#include "asn1.h"
#include "bignum.h"
#include "tls_internal.h"

/*
 * ASN.1 DER decoding routines
 */
int ttls_asn1_get_len(unsigned char **p,
				  const unsigned char *end,
				  size_t *len)
{
	if ((end - *p) < 1)
		return(TTLS_ERR_ASN1_OUT_OF_DATA);

	if ((**p & 0x80) == 0)
		*len = *(*p)++;
	else
	{
		switch(**p & 0x7F)
		{
		case 1:
			if ((end - *p) < 2)
				return(TTLS_ERR_ASN1_OUT_OF_DATA);

			*len = (*p)[1];
			(*p) += 2;
			break;

		case 2:
			if ((end - *p) < 3)
				return(TTLS_ERR_ASN1_OUT_OF_DATA);

			*len = ((size_t)(*p)[1] << 8) | (*p)[2];
			(*p) += 3;
			break;

		case 3:
			if ((end - *p) < 4)
				return(TTLS_ERR_ASN1_OUT_OF_DATA);

			*len = ((size_t)(*p)[1] << 16) |
				   ((size_t)(*p)[2] << 8 ) | (*p)[3];
			(*p) += 4;
			break;

		case 4:
			if ((end - *p) < 5)
				return(TTLS_ERR_ASN1_OUT_OF_DATA);

			*len = ((size_t)(*p)[1] << 24) | ((size_t)(*p)[2] << 16) |
				   ((size_t)(*p)[3] << 8 ) |		   (*p)[4];
			(*p) += 5;
			break;

		default:
			return(TTLS_ERR_ASN1_INVALID_LENGTH);
		}
	}

	if (*len > (size_t) (end - *p))
		return(TTLS_ERR_ASN1_OUT_OF_DATA);

	return 0;
}

int ttls_asn1_get_tag(unsigned char **p,
				  const unsigned char *end,
				  size_t *len, int tag)
{
	if ((end - *p) < 1)
		return(TTLS_ERR_ASN1_OUT_OF_DATA);

	if (**p != tag)
		return(TTLS_ERR_ASN1_UNEXPECTED_TAG);

	(*p)++;

	return(ttls_asn1_get_len(p, end, len));
}

int ttls_asn1_get_bool(unsigned char **p,
				   const unsigned char *end,
				   int *val)
{
	int ret;
	size_t len;

	if ((ret = ttls_asn1_get_tag(p, end, &len, TTLS_ASN1_BOOLEAN)) != 0)
		return ret;

	if (len != 1)
		return(TTLS_ERR_ASN1_INVALID_LENGTH);

	*val = (**p != 0) ? 1 : 0;
	(*p)++;

	return 0;
}

int ttls_asn1_get_int(unsigned char **p,
				  const unsigned char *end,
				  int *val)
{
	int ret;
	size_t len;

	if ((ret = ttls_asn1_get_tag(p, end, &len, TTLS_ASN1_INTEGER)) != 0)
		return ret;

	if (len == 0 || len > sizeof(int) || (**p & 0x80) != 0)
		return(TTLS_ERR_ASN1_INVALID_LENGTH);

	*val = 0;

	while (len-- > 0)
	{
		*val = (*val << 8) | **p;
		(*p)++;
	}

	return 0;
}

int
ttls_asn1_get_mpi(unsigned char **p, const unsigned char *end, TlsMpi *X)
{
	int ret;
	size_t len;

	if ((ret = ttls_asn1_get_tag(p, end, &len, TTLS_ASN1_INTEGER)))
		return ret;

	ret = ttls_mpi_read_binary(X, *p, len);

	*p += len;

	return ret;
}

int ttls_asn1_get_bitstring(unsigned char **p, const unsigned char *end,
			ttls_asn1_bitstring *bs)
{
	int ret;

	/* Certificate type is a single byte bitstring */
	if ((ret = ttls_asn1_get_tag(p, end, &bs->len, TTLS_ASN1_BIT_STRING)) != 0)
		return ret;

	/* Check length, subtract one for actual bit string length */
	if (bs->len < 1)
		return(TTLS_ERR_ASN1_OUT_OF_DATA);
	bs->len -= 1;

	/* Get number of unused bits, ensure unused bits <= 7 */
	bs->unused_bits = **p;
	if (bs->unused_bits > 7)
		return(TTLS_ERR_ASN1_INVALID_LENGTH);
	(*p)++;

	/* Get actual bitstring */
	bs->p = *p;
	*p += bs->len;

	if (*p != end)
		return(TTLS_ERR_ASN1_LENGTH_MISMATCH);

	return 0;
}

/*
 * Get a bit string without unused bits
 */
int ttls_asn1_get_bitstring_null(unsigned char **p, const unsigned char *end,
				 size_t *len)
{
	int ret;

	if ((ret = ttls_asn1_get_tag(p, end, len, TTLS_ASN1_BIT_STRING)) != 0)
		return ret;

	if ((*len)-- < 2 || *(*p)++ != 0)
		return(TTLS_ERR_ASN1_INVALID_DATA);

	return 0;
}

/*
 *  Parses and splits an ASN.1 "SEQUENCE OF <tag>"
 */
int ttls_asn1_get_sequence_of(unsigned char **p,
			  const unsigned char *end,
			  ttls_asn1_sequence *cur,
			  int tag)
{
	int ret;
	size_t len;
	ttls_asn1_buf *buf;

	/* Get main sequence tag */
	if ((ret = ttls_asn1_get_tag(p, end, &len,
			TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
		return ret;

	if (*p + len != end)
		return(TTLS_ERR_ASN1_LENGTH_MISMATCH);

	while (*p < end)
	{
		buf = &(cur->buf);
		buf->tag = **p;

		if ((ret = ttls_asn1_get_tag(p, end, &buf->len, tag)) != 0)
			return ret;

		buf->p = *p;
		*p += buf->len;

		/* Allocate and assign next pointer */
		if (*p < end)
		{
			cur->next = kmalloc(sizeof(ttls_asn1_sequence),
					    GFP_KERNEL);

			if (cur->next == NULL)
				return(TTLS_ERR_ASN1_ALLOC_FAILED);

			cur = cur->next;
		}
	}

	/* Set final sequence entry's next pointer to NULL */
	cur->next = NULL;

	if (*p != end)
		return(TTLS_ERR_ASN1_LENGTH_MISMATCH);

	return 0;
}

int ttls_asn1_get_alg(unsigned char **p,
				  const unsigned char *end,
				  ttls_asn1_buf *alg, ttls_asn1_buf *params)
{
	int ret;
	size_t len;

	if ((ret = ttls_asn1_get_tag(p, end, &len,
			TTLS_ASN1_CONSTRUCTED | TTLS_ASN1_SEQUENCE)) != 0)
		return ret;

	if ((end - *p) < 1)
		return(TTLS_ERR_ASN1_OUT_OF_DATA);

	alg->tag = **p;
	end = *p + len;

	if ((ret = ttls_asn1_get_tag(p, end, &alg->len, TTLS_ASN1_OID)) != 0)
		return ret;

	alg->p = *p;
	*p += alg->len;

	if (*p == end)
	{
		ttls_bzero_safe(params, sizeof(ttls_asn1_buf));
		return 0;
	}

	params->tag = **p;
	(*p)++;

	if ((ret = ttls_asn1_get_len(p, end, &params->len)) != 0)
		return ret;

	params->p = *p;
	*p += params->len;

	if (*p != end)
		return(TTLS_ERR_ASN1_LENGTH_MISMATCH);

	return 0;
}

int ttls_asn1_get_alg_null(unsigned char **p,
		   const unsigned char *end,
		   ttls_asn1_buf *alg)
{
	int ret;
	ttls_asn1_buf params;

	memset(&params, 0, sizeof(ttls_asn1_buf));

	if ((ret = ttls_asn1_get_alg(p, end, alg, &params)) != 0)
		return ret;

	if ((params.tag != TTLS_ASN1_NULL && params.tag != 0) || params.len != 0)
		return(TTLS_ERR_ASN1_INVALID_DATA);

	return 0;
}

/**
 * Write a length field in ASN.1 format.
 * Note: function works backwards in data buffer.
 *
 * @p		- reference to current position pointer;
 * @start	- start of the buffer (for bounds-checking);
 * @len		- the length to write.
 *
 * @return the length written or a negative error code.
 */
int
ttls_asn1_write_len(unsigned char **p, unsigned char *start, size_t len)
{
	if (len < 0x80) {
		if (*p - start < 1)
			return -ENOSPC;
		*--(*p) = (unsigned char) len;
		return 1;
	}

	if (len <= 0xFF) {
		if (*p - start < 2)
			return -ENOSPC;

		*--(*p) = (unsigned char) len;
		*--(*p) = 0x81;
		return 2;
	}

	if (len <= 0xFFFF) {
		if (*p - start < 3)
			return -ENOSPC;

		*--(*p) = len & 0xFF;
		*--(*p) = (len >> 8) & 0xFF;
		*--(*p) = 0x82;
		return 3;
	}

	if (len <= 0xFFFFFF) {
		if (*p - start < 4)
			return -ENOSPC;

		*--(*p) = len & 0xFF;
		*--(*p) = (len >> 8) & 0xFF;
		*--(*p) = (len >> 16) & 0xFF;
		*--(*p) = 0x83;
		return 4;
	}

	if (len <= 0xFFFFFFFF) {
		if (*p - start < 5)
			return -ENOSPC;

		*--(*p) = len & 0xFF;
		*--(*p) = (len >>  8) & 0xFF;
		*--(*p) = (len >> 16) & 0xFF;
		*--(*p) = (len >> 24) & 0xFF;
		*--(*p) = 0x84;
		return 5;
	}

	return -EINVAL;
}

/**
 * Write a ASN.1 tag in ASN.1 format.
 * Note: function works backwards in data buffer
 *
 * @p		- reference to current position pointer;
 * @start	- start of the buffer (for bounds-checking);
 * @tag		- the tag to write.
 *
 * @return the length written or a negative error code.
 */
int
ttls_asn1_write_tag(unsigned char **p, unsigned char *start, unsigned char tag)
{
	if (*p - start < 1)
		return -ENOSPC;

	*--(*p) = tag;

	return 1;
}

/**
 * Write a big number (TTLS_ASN1_INTEGER) in ASN.1 format.
 * Note: function works backwards in data buffer
 *
 * @p		- reference to current position pointer;
 * @start	- start of the buffer (for bounds-checking);
 * @X		- the MPI to write.
 *
 * @return the length written or a negative error code.
 */
int
ttls_asn1_write_mpi(unsigned char **p, unsigned char *start, const TlsMpi *X)
{
	int ret;
	size_t len = ttls_mpi_size(X);

	if (*p < start || (size_t)(*p - start) < len)
		return -ENOSPC;

	(*p) -= len;
	TTLS_MPI_CHK(ttls_mpi_write_binary(X, *p, len));

	/*
	 * DER format assumes 2s complement for numbers, so the leftmost bit
	 * should be 0 for positive numbers and 1 for negative numbers.
	 */
	if (X->s ==1 && **p & 0x80) {
		if (*p - start < 1)
			return -ENOSPC;

		*--(*p) = 0x00;
		len += 1;
	}

	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_len(p, start, len));
	TTLS_ASN1_CHK_ADD(len, ttls_asn1_write_tag(p, start, TTLS_ASN1_INTEGER));

	ret = (int)len;

cleanup:
	return ret;
}
