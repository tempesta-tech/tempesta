/**
 *		Tempesta TLS
 *
 * Error message information.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2019 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0
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
#include "config.h"
#include "bignum.h"
#include "crypto.h"
#if defined(TTLS_DHM_C)
#include "dhm.h"
#endif
#include "ecp.h"
#include "oid.h"
#include "pem.h"
#include "pk.h"
#include "rsa.h"
#include "ttls.h"
#include "x509.h"

/*
 * TODO the function must be removed. All the descriptions must be moved to
 * the code which returns the staus codes.
 */
void ttls_strerror(int ret, char *buf, size_t buflen)
{
	size_t len;
	int use_ret;

	if (buflen == 0)
		return;

	memset(buf, 0x00, buflen);

	if (ret < 0)
		ret = -ret;

	if (ret & 0xFF80)
	{
		use_ret = ret & 0xFF80;

#if defined(TTLS_DHM_C)
		if (use_ret == -(TTLS_ERR_DHM_BAD_INPUT_DATA))
			snprintf(buf, buflen, "DHM - Bad input parameters");
		if (use_ret == -(TTLS_ERR_DHM_READ_PARAMS_FAILED))
			snprintf(buf, buflen, "DHM - Reading of the DHM parameters failed");
		if (use_ret == -(TTLS_ERR_DHM_MAKE_PARAMS_FAILED))
			snprintf(buf, buflen, "DHM - Making of the DHM parameters failed");
		if (use_ret == -(TTLS_ERR_DHM_READ_PUBLIC_FAILED))
			snprintf(buf, buflen, "DHM - Reading of the public values failed");
		if (use_ret == -(TTLS_ERR_DHM_MAKE_PUBLIC_FAILED))
			snprintf(buf, buflen, "DHM - Making of the public value failed");
		if (use_ret == -(TTLS_ERR_DHM_CALC_SECRET_FAILED))
			snprintf(buf, buflen, "DHM - Calculation of the DHM secret failed");
		if (use_ret == -(TTLS_ERR_DHM_INVALID_FORMAT))
			snprintf(buf, buflen, "DHM - The ASN.1 data is not formatted correctly");
		if (use_ret == -(TTLS_ERR_DHM_ALLOC_FAILED))
			snprintf(buf, buflen, "DHM - Allocation of memory failed");
		if (use_ret == -(TTLS_ERR_DHM_FILE_IO_ERROR))
			snprintf(buf, buflen, "DHM - Read or write of file failed");
		if (use_ret == -(TTLS_ERR_DHM_HW_ACCEL_FAILED))
			snprintf(buf, buflen, "DHM - DHM hardware accelerator failed");
		if (use_ret == -(TTLS_ERR_DHM_SET_GROUP_FAILED))
			snprintf(buf, buflen, "DHM - Setting the modulus and generator failed");
#endif /* TTLS_DHM_C */

		if (use_ret == -(TTLS_ERR_ECP_BAD_INPUT_DATA))
			snprintf(buf, buflen, "ECP - Bad input parameters to function");
		if (use_ret == -(TTLS_ERR_ECP_BUFFER_TOO_SMALL))
			snprintf(buf, buflen, "ECP - The buffer is too small to write to");
		if (use_ret == -(TTLS_ERR_ECP_FEATURE_UNAVAILABLE))
			snprintf(buf, buflen, "ECP - Requested curve not available");
		if (use_ret == -(TTLS_ERR_ECP_VERIFY_FAILED))
			snprintf(buf, buflen, "ECP - The signature is not valid");
		if (use_ret == -(TTLS_ERR_ECP_ALLOC_FAILED))
			snprintf(buf, buflen, "ECP - Memory allocation failed");
		if (use_ret == -(TTLS_ERR_ECP_RANDOM_FAILED))
			snprintf(buf, buflen, "ECP - Generation of random value, such as (ephemeral) key, failed");
		if (use_ret == -(TTLS_ERR_ECP_INVALID_KEY))
			snprintf(buf, buflen, "ECP - Invalid private or public key");
		if (use_ret == -(TTLS_ERR_ECP_SIG_LEN_MISMATCH))
			snprintf(buf, buflen, "ECP - Signature is valid but shorter than the user-supplied length");
		if (use_ret == -(TTLS_ERR_ECP_HW_ACCEL_FAILED))
			snprintf(buf, buflen, "ECP - ECP hardware accelerator failed");

		if (use_ret == -(TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT))
			snprintf(buf, buflen, "PEM - No PEM header or footer found");
		if (use_ret == -(TTLS_ERR_PEM_INVALID_DATA))
			snprintf(buf, buflen, "PEM - PEM string is not as expected");
		if (use_ret == -(TTLS_ERR_PEM_ALLOC_FAILED))
			snprintf(buf, buflen, "PEM - Failed to allocate memory");
		if (use_ret == -(TTLS_ERR_PEM_INVALID_ENC_IV))
			snprintf(buf, buflen, "PEM - RSA IV is not in hex-format");
		if (use_ret == -(TTLS_ERR_PEM_UNKNOWN_ENC_ALG))
			snprintf(buf, buflen, "PEM - Unsupported key encryption algorithm");
		if (use_ret == -(TTLS_ERR_PEM_PASSWORD_REQUIRED))
			snprintf(buf, buflen, "PEM - Private key password can't be empty");
		if (use_ret == -(TTLS_ERR_PEM_PASSWORD_MISMATCH))
			snprintf(buf, buflen, "PEM - Given private key password does not allow for correct decryption");
		if (use_ret == -(TTLS_ERR_PEM_FEATURE_UNAVAILABLE))
			snprintf(buf, buflen, "PEM - Unavailable feature, e.g. hashing/encryption combination");

		if (use_ret == -(TTLS_ERR_PK_ALLOC_FAILED))
			snprintf(buf, buflen, "PK - Memory allocation failed");
		if (use_ret == -(TTLS_ERR_PK_TYPE_MISMATCH))
			snprintf(buf, buflen, "PK - Type mismatch, eg attempt to encrypt with an ECDSA key");
		if (use_ret == -(TTLS_ERR_PK_BAD_INPUT_DATA))
			snprintf(buf, buflen, "PK - Bad input parameters to function");
		if (use_ret == -(TTLS_ERR_PK_FILE_IO_ERROR))
			snprintf(buf, buflen, "PK - Read/write of file failed");
		if (use_ret == -(TTLS_ERR_PK_KEY_INVALID_VERSION))
			snprintf(buf, buflen, "PK - Unsupported key version");
		if (use_ret == -(TTLS_ERR_PK_KEY_INVALID_FORMAT))
			snprintf(buf, buflen, "PK - Invalid key tag or value");
		if (use_ret == -(TTLS_ERR_PK_UNKNOWN_PK_ALG))
			snprintf(buf, buflen, "PK - Key algorithm is unsupported (only RSA and EC are supported)");
		if (use_ret == -(TTLS_ERR_PK_PASSWORD_REQUIRED))
			snprintf(buf, buflen, "PK - Private key password can't be empty");
		if (use_ret == -(TTLS_ERR_PK_PASSWORD_MISMATCH))
			snprintf(buf, buflen, "PK - Given private key password does not allow for correct decryption");
		if (use_ret == -(TTLS_ERR_PK_INVALID_PUBKEY))
			snprintf(buf, buflen, "PK - The pubkey tag or value is invalid (only RSA and EC are supported)");
		if (use_ret == -(TTLS_ERR_PK_INVALID_ALG))
			snprintf(buf, buflen, "PK - The algorithm tag or value is invalid");
		if (use_ret == -(TTLS_ERR_PK_UNKNOWN_NAMED_CURVE))
			snprintf(buf, buflen, "PK - Elliptic curve is unsupported (only NIST curves are supported)");
		if (use_ret == -(TTLS_ERR_PK_FEATURE_UNAVAILABLE))
			snprintf(buf, buflen, "PK - Unavailable feature, e.g. RSA disabled for RSA key");
		if (use_ret == -(TTLS_ERR_PK_SIG_LEN_MISMATCH))
			snprintf(buf, buflen, "PK - The signature is valid but its length is less than expected");
		if (use_ret == -(TTLS_ERR_PK_HW_ACCEL_FAILED))
			snprintf(buf, buflen, "PK - PK hardware accelerator failed");

		if (use_ret == -(TTLS_ERR_RSA_BAD_INPUT_DATA))
			snprintf(buf, buflen, "RSA - Bad input parameters to function");
		if (use_ret == -(TTLS_ERR_RSA_INVALID_PADDING))
			snprintf(buf, buflen, "RSA - Input data contains invalid padding and is rejected");
		if (use_ret == -(TTLS_ERR_RSA_KEY_GEN_FAILED))
			snprintf(buf, buflen, "RSA - Something failed during generation of a key");
		if (use_ret == -(TTLS_ERR_RSA_KEY_CHECK_FAILED))
			snprintf(buf, buflen, "RSA - Key failed to pass the validity check of the library");
		if (use_ret == -(TTLS_ERR_RSA_PUBLIC_FAILED))
			snprintf(buf, buflen, "RSA - The public key operation failed");
		if (use_ret == -(TTLS_ERR_RSA_PRIVATE_FAILED))
			snprintf(buf, buflen, "RSA - The private key operation failed");
		if (use_ret == -(TTLS_ERR_RSA_VERIFY_FAILED))
			snprintf(buf, buflen, "RSA - The PKCS#1 verification failed");
		if (use_ret == -(TTLS_ERR_RSA_OUTPUT_TOO_LARGE))
			snprintf(buf, buflen, "RSA - The output buffer for decryption is not large enough");
		if (use_ret == -(TTLS_ERR_RSA_RNG_FAILED))
			snprintf(buf, buflen, "RSA - The random generator failed to generate non-zeros");
		if (use_ret == -(TTLS_ERR_RSA_UNSUPPORTED_OPERATION))
			snprintf(buf, buflen, "RSA - The implementation does not offer the requested operation, for example, because of security violations or lack of functionality");
		if (use_ret == -(TTLS_ERR_RSA_HW_ACCEL_FAILED))
			snprintf(buf, buflen, "RSA - RSA hardware accelerator failed");

		if (use_ret == -(TTLS_ERR_FEATURE_UNAVAILABLE))
			snprintf(buf, buflen, "TLS - The requested feature is not available");
		if (use_ret == -(TTLS_ERR_BAD_INPUT_DATA))
			snprintf(buf, buflen, "TLS - Bad input parameters to function");
		if (use_ret == -(TTLS_ERR_INVALID_MAC))
			snprintf(buf, buflen, "TLS - Verification of the message MAC failed");
		if (use_ret == -(TTLS_ERR_INVALID_RECORD))
			snprintf(buf, buflen, "TLS - An invalid TLS record was received");
		if (use_ret == -(TTLS_ERR_CONN_EOF))
			snprintf(buf, buflen, "TLS - The connection indicated an EOF");
		if (use_ret == -(TTLS_ERR_NO_CLIENT_CERTIFICATE))
			snprintf(buf, buflen, "TLS - No client certification received from the client, but required by the authentication mode");
		if (use_ret == -(TTLS_ERR_CERTIFICATE_TOO_LARGE))
			snprintf(buf, buflen, "TLS - Our own certificate(s) is/are too large to send in an TLS message");
		if (use_ret == -(TTLS_ERR_CERTIFICATE_REQUIRED))
			snprintf(buf, buflen, "TLS - The own certificate is not set, but needed by the server");
		if (use_ret == -(TTLS_ERR_PRIVATE_KEY_REQUIRED))
			snprintf(buf, buflen, "TLS - The own private key or pre-shared key is not set, but needed");
		if (use_ret == -(TTLS_ERR_CA_CHAIN_REQUIRED))
			snprintf(buf, buflen, "TLS - No CA Chain is set, but required to operate");
		if (use_ret == -(TTLS_ERR_UNEXPECTED_MESSAGE))
			snprintf(buf, buflen, "TLS - An unexpected message was received from our peer");
		if (use_ret == -(TTLS_ERR_BAD_HS_CLIENT_HELLO))
			snprintf(buf, buflen, "TLS - Processing of the ClientHello handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_SERVER_HELLO))
			snprintf(buf, buflen, "TLS - Processing of the ServerHello handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_CERTIFICATE))
			snprintf(buf, buflen, "TLS - Processing of the Certificate handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_CERTIFICATE_REQUEST))
			snprintf(buf, buflen, "TLS - Processing of the CertificateRequest handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE))
			snprintf(buf, buflen, "TLS - Processing of the ServerKeyExchange handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_SERVER_HELLO_DONE))
			snprintf(buf, buflen, "TLS - Processing of the ServerHelloDone handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE))
			snprintf(buf, buflen, "TLS - Processing of the ClientKeyExchange handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_RP))
			snprintf(buf, buflen, "TLS - Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Read Public");
		if (use_ret == -(TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_CS))
			snprintf(buf, buflen, "TLS - Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Calculate Secret");
		if (use_ret == -(TTLS_ERR_BAD_HS_CERTIFICATE_VERIFY))
			snprintf(buf, buflen, "TLS - Processing of the CertificateVerify handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_CHANGE_CIPHER_SPEC))
			snprintf(buf, buflen, "TLS - Processing of the ChangeCipherSpec handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_FINISHED))
			snprintf(buf, buflen, "TLS - Processing of the Finished handshake message failed");
		if (use_ret == -(TTLS_ERR_ALLOC_FAILED))
			snprintf(buf, buflen, "TLS - Memory allocation failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_PROTOCOL_VERSION))
			snprintf(buf, buflen, "TLS - Handshake protocol not within min/max boundaries");
		if (use_ret == -(TTLS_ERR_BAD_HS_NEW_SESSION_TICKET))
			snprintf(buf, buflen, "TLS - Processing of the NewSessionTicket handshake message failed");
		if (use_ret == -(TTLS_ERR_SESSION_TICKET_EXPIRED))
			snprintf(buf, buflen, "TLS - Session ticket has expired");
		if (use_ret == -(TTLS_ERR_PK_TYPE_MISMATCH))
			snprintf(buf, buflen, "TLS - Public key type mismatch (eg, asked for RSA key exchange and presented EC key)");
		if (use_ret == -(TTLS_ERR_INTERNAL_ERROR))
			snprintf(buf, buflen, "TLS - Internal error (eg, unexpected failure in lower-level module)");
		if (use_ret == -(TTLS_ERR_BUFFER_TOO_SMALL))
			snprintf(buf, buflen, "TLS - A buffer is too small to receive or write a message");
		if (use_ret == -(TTLS_ERR_INVALID_VERIFY_HASH))
			snprintf(buf, buflen, "TLS - Couldn't set the hash for verifying CertificateVerify");

		if (use_ret == -(TTLS_ERR_X509_FEATURE_UNAVAILABLE))
			snprintf(buf, buflen, "X509 - Unavailable feature, e.g. RSA hashing/encryption combination");
		if (use_ret == -(TTLS_ERR_X509_UNKNOWN_OID))
			snprintf(buf, buflen, "X509 - Requested OID is unknown");
		if (use_ret == -(TTLS_ERR_X509_INVALID_FORMAT))
			snprintf(buf, buflen, "X509 - The CRT/CRL/CSR format is invalid, e.g. different type expected");
		if (use_ret == -(TTLS_ERR_X509_INVALID_VERSION))
			snprintf(buf, buflen, "X509 - The CRT/CRL/CSR version element is invalid");
		if (use_ret == -(TTLS_ERR_X509_INVALID_SERIAL))
			snprintf(buf, buflen, "X509 - The serial tag or value is invalid");
		if (use_ret == -(TTLS_ERR_X509_INVALID_ALG))
			snprintf(buf, buflen, "X509 - The algorithm tag or value is invalid");
		if (use_ret == -(TTLS_ERR_X509_INVALID_NAME))
			snprintf(buf, buflen, "X509 - The name tag or value is invalid");
		if (use_ret == -(TTLS_ERR_X509_INVALID_DATE))
			snprintf(buf, buflen, "X509 - The date tag or value is invalid");
		if (use_ret == -(TTLS_ERR_X509_INVALID_SIGNATURE))
			snprintf(buf, buflen, "X509 - The signature tag or value invalid");
		if (use_ret == -(TTLS_ERR_X509_INVALID_EXTENSIONS))
			snprintf(buf, buflen, "X509 - The extension tag or value is invalid");
		if (use_ret == -(TTLS_ERR_X509_UNKNOWN_VERSION))
			snprintf(buf, buflen, "X509 - CRT/CRL/CSR has an unsupported version number");
		if (use_ret == -(TTLS_ERR_X509_UNKNOWN_SIG_ALG))
			snprintf(buf, buflen, "X509 - Signature algorithm (oid) is unsupported");
		if (use_ret == -(TTLS_ERR_X509_SIG_MISMATCH))
			snprintf(buf, buflen, "X509 - Signature algorithms do not match. (see \\c ::ttls_x509_crt sig_oid)");
		if (use_ret == -(TTLS_ERR_X509_CERT_VERIFY_FAILED))
			snprintf(buf, buflen, "X509 - Certificate verification failed, e.g. CRL, CA or signature check failed");
		if (use_ret == -(TTLS_ERR_X509_CERT_UNKNOWN_FORMAT))
			snprintf(buf, buflen, "X509 - Format not recognized as DER or PEM");
		if (use_ret == -(TTLS_ERR_X509_BAD_INPUT_DATA))
			snprintf(buf, buflen, "X509 - Input invalid");
		if (use_ret == -(TTLS_ERR_X509_ALLOC_FAILED))
			snprintf(buf, buflen, "X509 - Allocation of memory failed");
		if (use_ret == -(TTLS_ERR_X509_FILE_IO_ERROR))
			snprintf(buf, buflen, "X509 - Read/write of file failed");
		if (use_ret == -(TTLS_ERR_X509_BUFFER_TOO_SMALL))
			snprintf(buf, buflen, "X509 - Destination buffer is too small");
		if (use_ret == -(TTLS_ERR_X509_FATAL_ERROR))
			snprintf(buf, buflen, "X509 - A fatal error occurred, eg the chain is too long or the vrfy callback failed");
		// END generated code

		if (strlen(buf) == 0)
			snprintf(buf, buflen, "UNKNOWN ERROR CODE (%04X)", use_ret);
	}

	use_ret = ret & ~0xFF80;

	if (use_ret == 0)
		return;

	// If high level code is present, make a concatenation between both
	// error strings.
	//
	len = strlen(buf);

	if (len > 0)
	{
		if (buflen - len < 5)
			return;

		snprintf(buf + len, buflen - len, " : ");

		buf += len + 3;
		buflen -= len + 3;
	}

	if (use_ret == -(TTLS_ERR_ASN1_OUT_OF_DATA))
		snprintf(buf, buflen, "ASN1 - Out of data when parsing an ASN1 data structure");
	if (use_ret == -(TTLS_ERR_ASN1_UNEXPECTED_TAG))
		snprintf(buf, buflen, "ASN1 - ASN1 tag was of an unexpected value");
	if (use_ret == -(TTLS_ERR_ASN1_INVALID_LENGTH))
		snprintf(buf, buflen, "ASN1 - Error when trying to determine the length or invalid length");
	if (use_ret == -(TTLS_ERR_ASN1_LENGTH_MISMATCH))
		snprintf(buf, buflen, "ASN1 - Actual length differs from expected length");
	if (use_ret == -(TTLS_ERR_ASN1_INVALID_DATA))
		snprintf(buf, buflen, "ASN1 - Data is invalid. (not used)");
	if (use_ret == -(TTLS_ERR_ASN1_ALLOC_FAILED))
		snprintf(buf, buflen, "ASN1 - Memory allocation failed");
	if (use_ret == -(TTLS_ERR_ASN1_BUF_TOO_SMALL))
		snprintf(buf, buflen, "ASN1 - Buffer too small when writing ASN.1 data structure");

	if (use_ret == -(TTLS_ERR_BASE64_BUFFER_TOO_SMALL))
		snprintf(buf, buflen, "BASE64 - Output buffer too small");
	if (use_ret == -(TTLS_ERR_BASE64_INVALID_CHARACTER))
		snprintf(buf, buflen, "BASE64 - Invalid character in input");

	if (use_ret == -(TTLS_ERR_MPI_FILE_IO_ERROR))
		snprintf(buf, buflen, "BIGNUM - An error occurred while reading from or writing to a file");
	if (use_ret == -(TTLS_ERR_MPI_BAD_INPUT_DATA))
		snprintf(buf, buflen, "BIGNUM - Bad input parameters to function");
	if (use_ret == -(TTLS_ERR_MPI_INVALID_CHARACTER))
		snprintf(buf, buflen, "BIGNUM - There is an invalid character in the digit string");
	if (use_ret == -(TTLS_ERR_MPI_BUFFER_TOO_SMALL))
		snprintf(buf, buflen, "BIGNUM - The buffer is too small to write to");
	if (use_ret == -(TTLS_ERR_MPI_NEGATIVE_VALUE))
		snprintf(buf, buflen, "BIGNUM - The input arguments are negative or result in illegal output");
	if (use_ret == -(TTLS_ERR_MPI_DIVISION_BY_ZERO))
		snprintf(buf, buflen, "BIGNUM - The input argument for division is zero, which is not allowed");
	if (use_ret == -(TTLS_ERR_MPI_NOT_ACCEPTABLE))
		snprintf(buf, buflen, "BIGNUM - The input arguments are not acceptable");
	if (use_ret == -(TTLS_ERR_MPI_ALLOC_FAILED))
		snprintf(buf, buflen, "BIGNUM - Memory allocation failed");

	if (use_ret == -(TTLS_ERR_OID_NOT_FOUND))
		snprintf(buf, buflen, "OID - OID is not found");
	if (use_ret == -(TTLS_ERR_OID_BUF_TOO_SMALL))
		snprintf(buf, buflen, "OID - output buffer is too small");

	if (strlen(buf) != 0)
		return;

	snprintf(buf, buflen, "UNKNOWN ERROR CODE (%04X)", use_ret);
}
