/*
 *  Error message information
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  Copyright (C) 2015-2018 Tempesta Technologies, Inc.
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#include "config.h"
#if defined(TTLS_BASE64_C)
#include "base64.h"
#endif
#include "bignum.h"
#include "cipher.h"
#if defined(TTLS_DHM_C)
#include "dhm.h"
#endif
#include "ecp.h"
#if defined(TTLS_HMAC_DRBG_C)
#include "hmac_drbg.h"
#endif
#include "md.h"
#include "oid.h"
#include "pem.h"
#include "pk.h"
#include "rsa.h"
#include "ttls.h"
#include "x509.h"

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

		// High level error codes
		//
		// BEGIN generated code
		if (use_ret == -(TTLS_ERR_CIPHER_FEATURE_UNAVAILABLE))
			ttls_snprintf(buf, buflen, "CIPHER - The selected feature is not available");
		if (use_ret == -(TTLS_ERR_CIPHER_BAD_INPUT_DATA))
			ttls_snprintf(buf, buflen, "CIPHER - Bad input parameters");
		if (use_ret == -(TTLS_ERR_CIPHER_ALLOC_FAILED))
			ttls_snprintf(buf, buflen, "CIPHER - Failed to allocate memory");
		if (use_ret == -(TTLS_ERR_CIPHER_INVALID_PADDING))
			ttls_snprintf(buf, buflen, "CIPHER - Input data contains invalid padding and is rejected");
		if (use_ret == -(TTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED))
			ttls_snprintf(buf, buflen, "CIPHER - Decryption of block requires a full block");
		if (use_ret == -(TTLS_ERR_CIPHER_AUTH_FAILED))
			ttls_snprintf(buf, buflen, "CIPHER - Authentication failed (for AEAD modes)");
		if (use_ret == -(TTLS_ERR_CIPHER_INVALID_CONTEXT))
			ttls_snprintf(buf, buflen, "CIPHER - The context is invalid. For example, because it was freed");
		if (use_ret == -(TTLS_ERR_CIPHER_HW_ACCEL_FAILED))
			ttls_snprintf(buf, buflen, "CIPHER - Cipher hardware accelerator failed");

#if defined(TTLS_DHM_C)
		if (use_ret == -(TTLS_ERR_DHM_BAD_INPUT_DATA))
			ttls_snprintf(buf, buflen, "DHM - Bad input parameters");
		if (use_ret == -(TTLS_ERR_DHM_READ_PARAMS_FAILED))
			ttls_snprintf(buf, buflen, "DHM - Reading of the DHM parameters failed");
		if (use_ret == -(TTLS_ERR_DHM_MAKE_PARAMS_FAILED))
			ttls_snprintf(buf, buflen, "DHM - Making of the DHM parameters failed");
		if (use_ret == -(TTLS_ERR_DHM_READ_PUBLIC_FAILED))
			ttls_snprintf(buf, buflen, "DHM - Reading of the public values failed");
		if (use_ret == -(TTLS_ERR_DHM_MAKE_PUBLIC_FAILED))
			ttls_snprintf(buf, buflen, "DHM - Making of the public value failed");
		if (use_ret == -(TTLS_ERR_DHM_CALC_SECRET_FAILED))
			ttls_snprintf(buf, buflen, "DHM - Calculation of the DHM secret failed");
		if (use_ret == -(TTLS_ERR_DHM_INVALID_FORMAT))
			ttls_snprintf(buf, buflen, "DHM - The ASN.1 data is not formatted correctly");
		if (use_ret == -(TTLS_ERR_DHM_ALLOC_FAILED))
			ttls_snprintf(buf, buflen, "DHM - Allocation of memory failed");
		if (use_ret == -(TTLS_ERR_DHM_FILE_IO_ERROR))
			ttls_snprintf(buf, buflen, "DHM - Read or write of file failed");
		if (use_ret == -(TTLS_ERR_DHM_HW_ACCEL_FAILED))
			ttls_snprintf(buf, buflen, "DHM - DHM hardware accelerator failed");
		if (use_ret == -(TTLS_ERR_DHM_SET_GROUP_FAILED))
			ttls_snprintf(buf, buflen, "DHM - Setting the modulus and generator failed");
#endif /* TTLS_DHM_C */

		if (use_ret == -(TTLS_ERR_ECP_BAD_INPUT_DATA))
			ttls_snprintf(buf, buflen, "ECP - Bad input parameters to function");
		if (use_ret == -(TTLS_ERR_ECP_BUFFER_TOO_SMALL))
			ttls_snprintf(buf, buflen, "ECP - The buffer is too small to write to");
		if (use_ret == -(TTLS_ERR_ECP_FEATURE_UNAVAILABLE))
			ttls_snprintf(buf, buflen, "ECP - Requested curve not available");
		if (use_ret == -(TTLS_ERR_ECP_VERIFY_FAILED))
			ttls_snprintf(buf, buflen, "ECP - The signature is not valid");
		if (use_ret == -(TTLS_ERR_ECP_ALLOC_FAILED))
			ttls_snprintf(buf, buflen, "ECP - Memory allocation failed");
		if (use_ret == -(TTLS_ERR_ECP_RANDOM_FAILED))
			ttls_snprintf(buf, buflen, "ECP - Generation of random value, such as (ephemeral) key, failed");
		if (use_ret == -(TTLS_ERR_ECP_INVALID_KEY))
			ttls_snprintf(buf, buflen, "ECP - Invalid private or public key");
		if (use_ret == -(TTLS_ERR_ECP_SIG_LEN_MISMATCH))
			ttls_snprintf(buf, buflen, "ECP - Signature is valid but shorter than the user-supplied length");
		if (use_ret == -(TTLS_ERR_ECP_HW_ACCEL_FAILED))
			ttls_snprintf(buf, buflen, "ECP - ECP hardware accelerator failed");

		if (use_ret == -(TTLS_ERR_MD_FEATURE_UNAVAILABLE))
			ttls_snprintf(buf, buflen, "MD - The selected feature is not available");
		if (use_ret == -(TTLS_ERR_MD_BAD_INPUT_DATA))
			ttls_snprintf(buf, buflen, "MD - Bad input parameters to function");
		if (use_ret == -(TTLS_ERR_MD_ALLOC_FAILED))
			ttls_snprintf(buf, buflen, "MD - Failed to allocate memory");
		if (use_ret == -(TTLS_ERR_MD_FILE_IO_ERROR))
			ttls_snprintf(buf, buflen, "MD - Opening or reading of file failed");
		if (use_ret == -(TTLS_ERR_MD_HW_ACCEL_FAILED))
			ttls_snprintf(buf, buflen, "MD - MD hardware accelerator failed");

		if (use_ret == -(TTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT))
			ttls_snprintf(buf, buflen, "PEM - No PEM header or footer found");
		if (use_ret == -(TTLS_ERR_PEM_INVALID_DATA))
			ttls_snprintf(buf, buflen, "PEM - PEM string is not as expected");
		if (use_ret == -(TTLS_ERR_PEM_ALLOC_FAILED))
			ttls_snprintf(buf, buflen, "PEM - Failed to allocate memory");
		if (use_ret == -(TTLS_ERR_PEM_INVALID_ENC_IV))
			ttls_snprintf(buf, buflen, "PEM - RSA IV is not in hex-format");
		if (use_ret == -(TTLS_ERR_PEM_UNKNOWN_ENC_ALG))
			ttls_snprintf(buf, buflen, "PEM - Unsupported key encryption algorithm");
		if (use_ret == -(TTLS_ERR_PEM_PASSWORD_REQUIRED))
			ttls_snprintf(buf, buflen, "PEM - Private key password can't be empty");
		if (use_ret == -(TTLS_ERR_PEM_PASSWORD_MISMATCH))
			ttls_snprintf(buf, buflen, "PEM - Given private key password does not allow for correct decryption");
		if (use_ret == -(TTLS_ERR_PEM_FEATURE_UNAVAILABLE))
			ttls_snprintf(buf, buflen, "PEM - Unavailable feature, e.g. hashing/encryption combination");
		if (use_ret == -(TTLS_ERR_PEM_BAD_INPUT_DATA))
			ttls_snprintf(buf, buflen, "PEM - Bad input parameters to function");

		if (use_ret == -(TTLS_ERR_PK_ALLOC_FAILED))
			ttls_snprintf(buf, buflen, "PK - Memory allocation failed");
		if (use_ret == -(TTLS_ERR_PK_TYPE_MISMATCH))
			ttls_snprintf(buf, buflen, "PK - Type mismatch, eg attempt to encrypt with an ECDSA key");
		if (use_ret == -(TTLS_ERR_PK_BAD_INPUT_DATA))
			ttls_snprintf(buf, buflen, "PK - Bad input parameters to function");
		if (use_ret == -(TTLS_ERR_PK_FILE_IO_ERROR))
			ttls_snprintf(buf, buflen, "PK - Read/write of file failed");
		if (use_ret == -(TTLS_ERR_PK_KEY_INVALID_VERSION))
			ttls_snprintf(buf, buflen, "PK - Unsupported key version");
		if (use_ret == -(TTLS_ERR_PK_KEY_INVALID_FORMAT))
			ttls_snprintf(buf, buflen, "PK - Invalid key tag or value");
		if (use_ret == -(TTLS_ERR_PK_UNKNOWN_PK_ALG))
			ttls_snprintf(buf, buflen, "PK - Key algorithm is unsupported (only RSA and EC are supported)");
		if (use_ret == -(TTLS_ERR_PK_PASSWORD_REQUIRED))
			ttls_snprintf(buf, buflen, "PK - Private key password can't be empty");
		if (use_ret == -(TTLS_ERR_PK_PASSWORD_MISMATCH))
			ttls_snprintf(buf, buflen, "PK - Given private key password does not allow for correct decryption");
		if (use_ret == -(TTLS_ERR_PK_INVALID_PUBKEY))
			ttls_snprintf(buf, buflen, "PK - The pubkey tag or value is invalid (only RSA and EC are supported)");
		if (use_ret == -(TTLS_ERR_PK_INVALID_ALG))
			ttls_snprintf(buf, buflen, "PK - The algorithm tag or value is invalid");
		if (use_ret == -(TTLS_ERR_PK_UNKNOWN_NAMED_CURVE))
			ttls_snprintf(buf, buflen, "PK - Elliptic curve is unsupported (only NIST curves are supported)");
		if (use_ret == -(TTLS_ERR_PK_FEATURE_UNAVAILABLE))
			ttls_snprintf(buf, buflen, "PK - Unavailable feature, e.g. RSA disabled for RSA key");
		if (use_ret == -(TTLS_ERR_PK_SIG_LEN_MISMATCH))
			ttls_snprintf(buf, buflen, "PK - The signature is valid but its length is less than expected");
		if (use_ret == -(TTLS_ERR_PK_HW_ACCEL_FAILED))
			ttls_snprintf(buf, buflen, "PK - PK hardware accelerator failed");

		if (use_ret == -(TTLS_ERR_RSA_BAD_INPUT_DATA))
			ttls_snprintf(buf, buflen, "RSA - Bad input parameters to function");
		if (use_ret == -(TTLS_ERR_RSA_INVALID_PADDING))
			ttls_snprintf(buf, buflen, "RSA - Input data contains invalid padding and is rejected");
		if (use_ret == -(TTLS_ERR_RSA_KEY_GEN_FAILED))
			ttls_snprintf(buf, buflen, "RSA - Something failed during generation of a key");
		if (use_ret == -(TTLS_ERR_RSA_KEY_CHECK_FAILED))
			ttls_snprintf(buf, buflen, "RSA - Key failed to pass the validity check of the library");
		if (use_ret == -(TTLS_ERR_RSA_PUBLIC_FAILED))
			ttls_snprintf(buf, buflen, "RSA - The public key operation failed");
		if (use_ret == -(TTLS_ERR_RSA_PRIVATE_FAILED))
			ttls_snprintf(buf, buflen, "RSA - The private key operation failed");
		if (use_ret == -(TTLS_ERR_RSA_VERIFY_FAILED))
			ttls_snprintf(buf, buflen, "RSA - The PKCS#1 verification failed");
		if (use_ret == -(TTLS_ERR_RSA_OUTPUT_TOO_LARGE))
			ttls_snprintf(buf, buflen, "RSA - The output buffer for decryption is not large enough");
		if (use_ret == -(TTLS_ERR_RSA_RNG_FAILED))
			ttls_snprintf(buf, buflen, "RSA - The random generator failed to generate non-zeros");
		if (use_ret == -(TTLS_ERR_RSA_UNSUPPORTED_OPERATION))
			ttls_snprintf(buf, buflen, "RSA - The implementation does not offer the requested operation, for example, because of security violations or lack of functionality");
		if (use_ret == -(TTLS_ERR_RSA_HW_ACCEL_FAILED))
			ttls_snprintf(buf, buflen, "RSA - RSA hardware accelerator failed");

		if (use_ret == -(TTLS_ERR_FEATURE_UNAVAILABLE))
			ttls_snprintf(buf, buflen, "SSL - The requested feature is not available");
		if (use_ret == -(TTLS_ERR_BAD_INPUT_DATA))
			ttls_snprintf(buf, buflen, "SSL - Bad input parameters to function");
		if (use_ret == -(TTLS_ERR_INVALID_MAC))
			ttls_snprintf(buf, buflen, "SSL - Verification of the message MAC failed");
		if (use_ret == -(TTLS_ERR_INVALID_RECORD))
			ttls_snprintf(buf, buflen, "SSL - An invalid SSL record was received");
		if (use_ret == -(TTLS_ERR_CONN_EOF))
			ttls_snprintf(buf, buflen, "SSL - The connection indicated an EOF");
		if (use_ret == -(TTLS_ERR_UNKNOWN_CIPHER))
			ttls_snprintf(buf, buflen, "SSL - An unknown cipher was received");
		if (use_ret == -(TTLS_ERR_NO_CIPHER_CHOSEN))
			ttls_snprintf(buf, buflen, "SSL - The server has no ciphersuites in common with the client");
		if (use_ret == -(TTLS_ERR_NO_RNG))
			ttls_snprintf(buf, buflen, "SSL - No RNG was provided to the SSL module");
		if (use_ret == -(TTLS_ERR_NO_CLIENT_CERTIFICATE))
			ttls_snprintf(buf, buflen, "SSL - No client certification received from the client, but required by the authentication mode");
		if (use_ret == -(TTLS_ERR_CERTIFICATE_TOO_LARGE))
			ttls_snprintf(buf, buflen, "SSL - Our own certificate(s) is/are too large to send in an SSL message");
		if (use_ret == -(TTLS_ERR_CERTIFICATE_REQUIRED))
			ttls_snprintf(buf, buflen, "SSL - The own certificate is not set, but needed by the server");
		if (use_ret == -(TTLS_ERR_PRIVATE_KEY_REQUIRED))
			ttls_snprintf(buf, buflen, "SSL - The own private key or pre-shared key is not set, but needed");
		if (use_ret == -(TTLS_ERR_CA_CHAIN_REQUIRED))
			ttls_snprintf(buf, buflen, "SSL - No CA Chain is set, but required to operate");
		if (use_ret == -(TTLS_ERR_UNEXPECTED_MESSAGE))
			ttls_snprintf(buf, buflen, "SSL - An unexpected message was received from our peer");
		if (use_ret == -(TTLS_ERR_FATAL_ALERT_MESSAGE))
		{
			ttls_snprintf(buf, buflen, "SSL - A fatal alert message was received from our peer");
			return;
		}
		if (use_ret == -(TTLS_ERR_PEER_VERIFY_FAILED))
			ttls_snprintf(buf, buflen, "SSL - Verification of our peer failed");
		if (use_ret == -(TTLS_ERR_PEER_CLOSE_NOTIFY))
			ttls_snprintf(buf, buflen, "SSL - The peer notified us that the connection is going to be closed");
		if (use_ret == -(TTLS_ERR_BAD_HS_CLIENT_HELLO))
			ttls_snprintf(buf, buflen, "SSL - Processing of the ClientHello handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_SERVER_HELLO))
			ttls_snprintf(buf, buflen, "SSL - Processing of the ServerHello handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_CERTIFICATE))
			ttls_snprintf(buf, buflen, "SSL - Processing of the Certificate handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_CERTIFICATE_REQUEST))
			ttls_snprintf(buf, buflen, "SSL - Processing of the CertificateRequest handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_SERVER_KEY_EXCHANGE))
			ttls_snprintf(buf, buflen, "SSL - Processing of the ServerKeyExchange handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_SERVER_HELLO_DONE))
			ttls_snprintf(buf, buflen, "SSL - Processing of the ServerHelloDone handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE))
			ttls_snprintf(buf, buflen, "SSL - Processing of the ClientKeyExchange handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_RP))
			ttls_snprintf(buf, buflen, "SSL - Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Read Public");
		if (use_ret == -(TTLS_ERR_BAD_HS_CLIENT_KEY_EXCHANGE_CS))
			ttls_snprintf(buf, buflen, "SSL - Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Calculate Secret");
		if (use_ret == -(TTLS_ERR_BAD_HS_CERTIFICATE_VERIFY))
			ttls_snprintf(buf, buflen, "SSL - Processing of the CertificateVerify handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_CHANGE_CIPHER_SPEC))
			ttls_snprintf(buf, buflen, "SSL - Processing of the ChangeCipherSpec handshake message failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_FINISHED))
			ttls_snprintf(buf, buflen, "SSL - Processing of the Finished handshake message failed");
		if (use_ret == -(TTLS_ERR_ALLOC_FAILED))
			ttls_snprintf(buf, buflen, "SSL - Memory allocation failed");
		if (use_ret == -(TTLS_ERR_HW_ACCEL_FAILED))
			ttls_snprintf(buf, buflen, "SSL - Hardware acceleration function returned with error");
		if (use_ret == -(TTLS_ERR_HW_ACCEL_FALLTHROUGH))
			ttls_snprintf(buf, buflen, "SSL - Hardware acceleration function skipped / left alone data");
		if (use_ret == -(TTLS_ERR_COMPRESSION_FAILED))
			ttls_snprintf(buf, buflen, "SSL - Processing of the compression / decompression failed");
		if (use_ret == -(TTLS_ERR_BAD_HS_PROTOCOL_VERSION))
			ttls_snprintf(buf, buflen, "SSL - Handshake protocol not within min/max boundaries");
		if (use_ret == -(TTLS_ERR_BAD_HS_NEW_SESSION_TICKET))
			ttls_snprintf(buf, buflen, "SSL - Processing of the NewSessionTicket handshake message failed");
		if (use_ret == -(TTLS_ERR_SESSION_TICKET_EXPIRED))
			ttls_snprintf(buf, buflen, "SSL - Session ticket has expired");
		if (use_ret == -(TTLS_ERR_PK_TYPE_MISMATCH))
			ttls_snprintf(buf, buflen, "SSL - Public key type mismatch (eg, asked for RSA key exchange and presented EC key)");
		if (use_ret == -(TTLS_ERR_UNKNOWN_IDENTITY))
			ttls_snprintf(buf, buflen, "SSL - Unknown identity received (eg, PSK identity)");
		if (use_ret == -(TTLS_ERR_INTERNAL_ERROR))
			ttls_snprintf(buf, buflen, "SSL - Internal error (eg, unexpected failure in lower-level module)");
		if (use_ret == -(TTLS_ERR_COUNTER_WRAPPING))
			ttls_snprintf(buf, buflen, "SSL - A counter would wrap (eg, too many messages exchanged)");
		if (use_ret == -(TTLS_ERR_HELLO_VERIFY_REQUIRED))
			ttls_snprintf(buf, buflen, "SSL - DTLS client must retry for hello verification");
		if (use_ret == -(TTLS_ERR_BUFFER_TOO_SMALL))
			ttls_snprintf(buf, buflen, "SSL - A buffer is too small to receive or write a message");
		if (use_ret == -(TTLS_ERR_NO_USABLE_CIPHERSUITE))
			ttls_snprintf(buf, buflen, "SSL - None of the common ciphersuites is usable (eg, no suitable certificate, see debug messages)");
		if (use_ret == -(TTLS_ERR_WANT_READ))
			ttls_snprintf(buf, buflen, "SSL - Connection requires a read call");
		if (use_ret == -(TTLS_ERR_WANT_WRITE))
			ttls_snprintf(buf, buflen, "SSL - Connection requires a write call");
		if (use_ret == -(TTLS_ERR_TIMEOUT))
			ttls_snprintf(buf, buflen, "SSL - The operation timed out");
		if (use_ret == -(TTLS_ERR_UNEXPECTED_RECORD))
			ttls_snprintf(buf, buflen, "SSL - Record header looks valid but is not expected");
		if (use_ret == -(TTLS_ERR_NON_FATAL))
			ttls_snprintf(buf, buflen, "SSL - The alert message received indicates a non-fatal error");
		if (use_ret == -(TTLS_ERR_INVALID_VERIFY_HASH))
			ttls_snprintf(buf, buflen, "SSL - Couldn't set the hash for verifying CertificateVerify");

		if (use_ret == -(TTLS_ERR_X509_FEATURE_UNAVAILABLE))
			ttls_snprintf(buf, buflen, "X509 - Unavailable feature, e.g. RSA hashing/encryption combination");
		if (use_ret == -(TTLS_ERR_X509_UNKNOWN_OID))
			ttls_snprintf(buf, buflen, "X509 - Requested OID is unknown");
		if (use_ret == -(TTLS_ERR_X509_INVALID_FORMAT))
			ttls_snprintf(buf, buflen, "X509 - The CRT/CRL/CSR format is invalid, e.g. different type expected");
		if (use_ret == -(TTLS_ERR_X509_INVALID_VERSION))
			ttls_snprintf(buf, buflen, "X509 - The CRT/CRL/CSR version element is invalid");
		if (use_ret == -(TTLS_ERR_X509_INVALID_SERIAL))
			ttls_snprintf(buf, buflen, "X509 - The serial tag or value is invalid");
		if (use_ret == -(TTLS_ERR_X509_INVALID_ALG))
			ttls_snprintf(buf, buflen, "X509 - The algorithm tag or value is invalid");
		if (use_ret == -(TTLS_ERR_X509_INVALID_NAME))
			ttls_snprintf(buf, buflen, "X509 - The name tag or value is invalid");
		if (use_ret == -(TTLS_ERR_X509_INVALID_DATE))
			ttls_snprintf(buf, buflen, "X509 - The date tag or value is invalid");
		if (use_ret == -(TTLS_ERR_X509_INVALID_SIGNATURE))
			ttls_snprintf(buf, buflen, "X509 - The signature tag or value invalid");
		if (use_ret == -(TTLS_ERR_X509_INVALID_EXTENSIONS))
			ttls_snprintf(buf, buflen, "X509 - The extension tag or value is invalid");
		if (use_ret == -(TTLS_ERR_X509_UNKNOWN_VERSION))
			ttls_snprintf(buf, buflen, "X509 - CRT/CRL/CSR has an unsupported version number");
		if (use_ret == -(TTLS_ERR_X509_UNKNOWN_SIG_ALG))
			ttls_snprintf(buf, buflen, "X509 - Signature algorithm (oid) is unsupported");
		if (use_ret == -(TTLS_ERR_X509_SIG_MISMATCH))
			ttls_snprintf(buf, buflen, "X509 - Signature algorithms do not match. (see \\c ::ttls_x509_crt sig_oid)");
		if (use_ret == -(TTLS_ERR_X509_CERT_VERIFY_FAILED))
			ttls_snprintf(buf, buflen, "X509 - Certificate verification failed, e.g. CRL, CA or signature check failed");
		if (use_ret == -(TTLS_ERR_X509_CERT_UNKNOWN_FORMAT))
			ttls_snprintf(buf, buflen, "X509 - Format not recognized as DER or PEM");
		if (use_ret == -(TTLS_ERR_X509_BAD_INPUT_DATA))
			ttls_snprintf(buf, buflen, "X509 - Input invalid");
		if (use_ret == -(TTLS_ERR_X509_ALLOC_FAILED))
			ttls_snprintf(buf, buflen, "X509 - Allocation of memory failed");
		if (use_ret == -(TTLS_ERR_X509_FILE_IO_ERROR))
			ttls_snprintf(buf, buflen, "X509 - Read/write of file failed");
		if (use_ret == -(TTLS_ERR_X509_BUFFER_TOO_SMALL))
			ttls_snprintf(buf, buflen, "X509 - Destination buffer is too small");
		if (use_ret == -(TTLS_ERR_X509_FATAL_ERROR))
			ttls_snprintf(buf, buflen, "X509 - A fatal error occured, eg the chain is too long or the vrfy callback failed");
		// END generated code

		if (strlen(buf) == 0)
			ttls_snprintf(buf, buflen, "UNKNOWN ERROR CODE (%04X)", use_ret);
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

		ttls_snprintf(buf + len, buflen - len, " : ");

		buf += len + 3;
		buflen -= len + 3;
	}

	// Low level error codes
	//
	// BEGIN generated code
	if (use_ret == -(TTLS_ERR_AES_INVALID_KEY_LENGTH))
		ttls_snprintf(buf, buflen, "AES - Invalid key length");
	if (use_ret == -(TTLS_ERR_AES_INVALID_INPUT_LENGTH))
		ttls_snprintf(buf, buflen, "AES - Invalid data input length");
	if (use_ret == -(TTLS_ERR_AES_FEATURE_UNAVAILABLE))
		ttls_snprintf(buf, buflen, "AES - Feature not available. For example, an unsupported AES key size");
	if (use_ret == -(TTLS_ERR_AES_HW_ACCEL_FAILED))
		ttls_snprintf(buf, buflen, "AES - AES hardware accelerator failed");

	if (use_ret == -(TTLS_ERR_ASN1_OUT_OF_DATA))
		ttls_snprintf(buf, buflen, "ASN1 - Out of data when parsing an ASN1 data structure");
	if (use_ret == -(TTLS_ERR_ASN1_UNEXPECTED_TAG))
		ttls_snprintf(buf, buflen, "ASN1 - ASN1 tag was of an unexpected value");
	if (use_ret == -(TTLS_ERR_ASN1_INVALID_LENGTH))
		ttls_snprintf(buf, buflen, "ASN1 - Error when trying to determine the length or invalid length");
	if (use_ret == -(TTLS_ERR_ASN1_LENGTH_MISMATCH))
		ttls_snprintf(buf, buflen, "ASN1 - Actual length differs from expected length");
	if (use_ret == -(TTLS_ERR_ASN1_INVALID_DATA))
		ttls_snprintf(buf, buflen, "ASN1 - Data is invalid. (not used)");
	if (use_ret == -(TTLS_ERR_ASN1_ALLOC_FAILED))
		ttls_snprintf(buf, buflen, "ASN1 - Memory allocation failed");
	if (use_ret == -(TTLS_ERR_ASN1_BUF_TOO_SMALL))
		ttls_snprintf(buf, buflen, "ASN1 - Buffer too small when writing ASN.1 data structure");

#if defined(TTLS_BASE64_C)
	if (use_ret == -(TTLS_ERR_BASE64_BUFFER_TOO_SMALL))
		ttls_snprintf(buf, buflen, "BASE64 - Output buffer too small");
	if (use_ret == -(TTLS_ERR_BASE64_INVALID_CHARACTER))
		ttls_snprintf(buf, buflen, "BASE64 - Invalid character in input");
#endif /* TTLS_BASE64_C */

	if (use_ret == -(TTLS_ERR_MPI_FILE_IO_ERROR))
		ttls_snprintf(buf, buflen, "BIGNUM - An error occurred while reading from or writing to a file");
	if (use_ret == -(TTLS_ERR_MPI_BAD_INPUT_DATA))
		ttls_snprintf(buf, buflen, "BIGNUM - Bad input parameters to function");
	if (use_ret == -(TTLS_ERR_MPI_INVALID_CHARACTER))
		ttls_snprintf(buf, buflen, "BIGNUM - There is an invalid character in the digit string");
	if (use_ret == -(TTLS_ERR_MPI_BUFFER_TOO_SMALL))
		ttls_snprintf(buf, buflen, "BIGNUM - The buffer is too small to write to");
	if (use_ret == -(TTLS_ERR_MPI_NEGATIVE_VALUE))
		ttls_snprintf(buf, buflen, "BIGNUM - The input arguments are negative or result in illegal output");
	if (use_ret == -(TTLS_ERR_MPI_DIVISION_BY_ZERO))
		ttls_snprintf(buf, buflen, "BIGNUM - The input argument for division is zero, which is not allowed");
	if (use_ret == -(TTLS_ERR_MPI_NOT_ACCEPTABLE))
		ttls_snprintf(buf, buflen, "BIGNUM - The input arguments are not acceptable");
	if (use_ret == -(TTLS_ERR_MPI_ALLOC_FAILED))
		ttls_snprintf(buf, buflen, "BIGNUM - Memory allocation failed");

#if defined(TTLS_CAMELLIA_C)
	if (use_ret == -(TTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH))
		ttls_snprintf(buf, buflen, "CAMELLIA - Invalid key length");
	if (use_ret == -(TTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH))
		ttls_snprintf(buf, buflen, "CAMELLIA - Invalid data input length");
	if (use_ret == -(TTLS_ERR_CAMELLIA_HW_ACCEL_FAILED))
		ttls_snprintf(buf, buflen, "CAMELLIA - Camellia hardware accelerator failed");
#endif /* TTLS_CAMELLIA_C */

	if (use_ret == -(TTLS_ERR_CCM_BAD_INPUT))
		ttls_snprintf(buf, buflen, "CCM - Bad input parameters to the function");
	if (use_ret == -(TTLS_ERR_CCM_AUTH_FAILED))
		ttls_snprintf(buf, buflen, "CCM - Authenticated decryption failed");
	if (use_ret == -(TTLS_ERR_CCM_HW_ACCEL_FAILED))
		ttls_snprintf(buf, buflen, "CCM - CCM hardware accelerator failed");

	if (use_ret == -(TTLS_ERR_GCM_AUTH_FAILED))
		ttls_snprintf(buf, buflen, "GCM - Authenticated decryption failed");
	if (use_ret == -(TTLS_ERR_GCM_HW_ACCEL_FAILED))
		ttls_snprintf(buf, buflen, "GCM - GCM hardware accelerator failed");
	if (use_ret == -(TTLS_ERR_GCM_BAD_INPUT))
		ttls_snprintf(buf, buflen, "GCM - Bad input parameters to function");

#if defined(TTLS_HMAC_DRBG_C)
	if (use_ret == -(TTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG))
		ttls_snprintf(buf, buflen, "HMAC_DRBG - Too many random requested in single call");
	if (use_ret == -(TTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG))
		ttls_snprintf(buf, buflen, "HMAC_DRBG - Input too large (Entropy + additional)");
	if (use_ret == -(TTLS_ERR_HMAC_DRBG_FILE_IO_ERROR))
		ttls_snprintf(buf, buflen, "HMAC_DRBG - Read/write error in file");
	if (use_ret == -(TTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED))
		ttls_snprintf(buf, buflen, "HMAC_DRBG - The entropy source failed");
#endif /* TTLS_HMAC_DRBG_C */

	if (use_ret == -(TTLS_ERR_OID_NOT_FOUND))
		ttls_snprintf(buf, buflen, "OID - OID is not found");
	if (use_ret == -(TTLS_ERR_OID_BUF_TOO_SMALL))
		ttls_snprintf(buf, buflen, "OID - output buffer is too small");

	if (strlen(buf) != 0)
		return;

	ttls_snprintf(buf, buflen, "UNKNOWN ERROR CODE (%04X)", use_ret);
}
