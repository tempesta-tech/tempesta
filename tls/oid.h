/**
 *		Tempesta TLS
 *
 * Object Identifier (OID) database.
 *
 * Based on mbed TLS, https://tls.mbed.org.
 *
 * Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 * Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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
#ifndef TTLS_OID_H
#define TTLS_OID_H
#include "asn1.h"
#include "pk.h"
#include "crypto.h"
#include "x509.h"

#define TTLS_WITH_OID_FMT(asn1_buf, fmtd_oid_var_name, action_expr)	\
    do {								\
	char fmtd_oid_var_name[32] = { 0 };				\
	ttls_oid_get_numeric_string(fmtd_oid_var_name,			\
		ARRAY_SIZE(fmtd_oid_var_name), asn1_buf);		\
	action_expr;							\
    } while (0)

/*
 * Top level OID tuples
 */
/* {iso(1) member-body(2)} */
#define TTLS_OID_ISO_MEMBER_BODIES	"\x2a"
/* {iso(1) identified-organization(3)} */
#define TTLS_OID_ISO_IDENTIFIED_ORG	"\x2b"
/* {joint-iso-ccitt(2) ds(5)} */
#define TTLS_OID_ISO_CCITT_DS		"\x55"
/* {joint-iso-itu-t(2) country(16)} */
#define TTLS_OID_ISO_ITU_COUNTRY	"\x60"

/*
 * ISO Member bodies OID parts
 */
#define TTLS_OID_COUNTRY_US		"\x86\x48" /* {us(840)} */
#define TTLS_OID_ORG_RSA_DATA_SECURITY	"\x86\xf7\x0d"  /* {rsadsi(113549)} */
/* {iso(1) member-body(2) us(840) rsadsi(113549)} */
#define TTLS_OID_RSA_COMPANY		TTLS_OID_ISO_MEMBER_BODIES	\
					TTLS_OID_COUNTRY_US		\
					TTLS_OID_ORG_RSA_DATA_SECURITY
#define TTLS_OID_ORG_ANSI_X9_62		"\xce\x3d" /* ansi-X9-62(10045) */
#define TTLS_OID_ANSI_X9_62		TTLS_OID_ISO_MEMBER_BODIES	\
					TTLS_OID_COUNTRY_US TTLS_OID_ORG_ANSI_X9_62

/*
 * ISO Identified organization OID parts
 */
#define TTLS_OID_ORG_DOD		 "\x06"		  /* {dod(6)} */
#define TTLS_OID_ORG_OIW		 "\x0e"
#define TTLS_OID_OIW_SECSIG				  TTLS_OID_ORG_OIW "\x03"
#define TTLS_OID_OIW_SECSIG_ALG			  TTLS_OID_OIW_SECSIG "\x02"
#define TTLS_OID_OIW_SECSIG_SHA1			 TTLS_OID_OIW_SECSIG_ALG "\x1a"
#define TTLS_OID_ORG_CERTICOM				"\x81\x04"  /* certicom(132) */
#define TTLS_OID_CERTICOM		TTLS_OID_ISO_IDENTIFIED_ORG TTLS_OID_ORG_CERTICOM
#define TTLS_OID_ORG_TELETRUST			   "\x24" /* teletrust(36) */
#define TTLS_OID_TELETRUST				   TTLS_OID_ISO_IDENTIFIED_ORG TTLS_OID_ORG_TELETRUST

/*
 * ISO ITU OID parts
 */
#define TTLS_OID_ORGANIZATION				"\x01"		  /* {organization(1)} */
#define TTLS_OID_ISO_ITU_US_ORG			  TTLS_OID_ISO_ITU_COUNTRY TTLS_OID_COUNTRY_US TTLS_OID_ORGANIZATION /* {joint-iso-itu-t(2) country(16) us(840) organization(1)} */

#define TTLS_OID_ORG_GOV		 "\x65"		  /* {gov(101)} */
#define TTLS_OID_GOV			 TTLS_OID_ISO_ITU_US_ORG TTLS_OID_ORG_GOV /* {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)} */

#define TTLS_OID_ORG_NETSCAPE				"\x86\xF8\x42"  /* {netscape(113730)} */
#define TTLS_OID_NETSCAPE		TTLS_OID_ISO_ITU_US_ORG TTLS_OID_ORG_NETSCAPE /* Netscape OID {joint-iso-itu-t(2) country(16) us(840) organization(1) netscape(113730)} */

/* ISO arc for standard certificate and CRL extensions */
#define TTLS_OID_ID_CE		   TTLS_OID_ISO_CCITT_DS "\x1D" /**< id-ce OBJECT IDENTIFIER  ::=  {joint-iso-ccitt(2) ds(5) 29} */

/**
 * Private Internet Extensions
 * { iso(1) identified-organization(3) dod(6) internet(1)
 *		  security(5) mechanisms(5) pkix(7) }
 */
#define TTLS_OID_PKIX			TTLS_OID_ISO_IDENTIFIED_ORG TTLS_OID_ORG_DOD "\x01\x05\x05\x07"

/*
 * Arc for standard naming attributes
 */
/* id-at OBJECT IDENTIFIER ::= {joint-iso-ccitt(2) ds(5) 4} */
#define TTLS_OID_AT				TTLS_OID_ISO_CCITT_DS "\x04"
/* id-at-commonName AttributeType:= {id-at 3} */
#define TTLS_OID_AT_CN				TTLS_OID_AT "\x03"
/* id-at-surName AttributeType:= {id-at 4} */
#define TTLS_OID_AT_SUR_NAME			TTLS_OID_AT "\x04"
/* id-at-serialNumber AttributeType:= {id-at 5} */
#define TTLS_OID_AT_SERIAL_NUMBER		TTLS_OID_AT "\x05"
/* id-at-countryName AttributeType:= {id-at 6} */
#define TTLS_OID_AT_COUNTRY			TTLS_OID_AT "\x06"
/* id-at-locality AttributeType:= {id-at 7} */
#define TTLS_OID_AT_LOCALITY			TTLS_OID_AT "\x07"
/* id-at-state AttributeType:= {id-at 8} */
#define TTLS_OID_AT_STATE			TTLS_OID_AT "\x08"
/* id-at-organizationName AttributeType:= {id-at 10} */
#define TTLS_OID_AT_ORGANIZATION		TTLS_OID_AT "\x0A"
/* id-at-organizationalUnitName AttributeType:= {id-at 11} */
#define TTLS_OID_AT_ORG_UNIT			TTLS_OID_AT "\x0B"
/* id-at-title AttributeType:= {id-at 12} */
#define TTLS_OID_AT_TITLE			TTLS_OID_AT "\x0C"
/* id-at-postalAddress AttributeType:= {id-at 16} */
#define TTLS_OID_AT_POSTAL_ADDRESS		TTLS_OID_AT "\x10"
/* id-at-postalCode AttributeType:= {id-at 17} */
#define TTLS_OID_AT_POSTAL_CODE			TTLS_OID_AT "\x11"
/* id-at-givenName AttributeType:= {id-at 42} */
#define TTLS_OID_AT_GIVEN_NAME			TTLS_OID_AT "\x2A"
/* id-at-initials AttributeType:= {id-at 43} */
#define TTLS_OID_AT_INITIALS			TTLS_OID_AT "\x2B"
/* id-at-generationQualifier AttributeType:= {id-at 44} */
#define TTLS_OID_AT_GENERATION_QUALIFIER	TTLS_OID_AT "\x2C"
/* id-at-uniqueIdentifier AttributType:= {id-at 45} */
#define TTLS_OID_AT_UNIQUE_IDENTIFIER		TTLS_OID_AT "\x2D"
/* id-at-dnQualifier AttributeType:= {id-at 46} */
#define TTLS_OID_AT_DN_QUALIFIER		TTLS_OID_AT "\x2E"
/* id-at-pseudonym AttributeType:= {id-at 65} */
#define TTLS_OID_AT_PSEUDONYM			TTLS_OID_AT "\x41"

#define TTLS_OID_DOMAIN_COMPONENT			"\x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x19" /** id-domainComponent AttributeType:= {itu-t(0) data(9) pss(2342) ucl(19200300) pilot(100) pilotAttributeType(1) domainComponent(25)} */

/*
 * OIDs for standard certificate extensions
 */
#define TTLS_OID_AUTHORITY_KEY_IDENTIFIER	TTLS_OID_ID_CE "\x23" /**< id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 } */
#define TTLS_OID_SUBJECT_KEY_IDENTIFIER	  TTLS_OID_ID_CE "\x0E" /**< id-ce-subjectKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 14 } */
#define TTLS_OID_KEY_USAGE				   TTLS_OID_ID_CE "\x0F" /**< id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 } */
#define TTLS_OID_CERTIFICATE_POLICIES		TTLS_OID_ID_CE "\x20" /**< id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 } */
#define TTLS_OID_POLICY_MAPPINGS			 TTLS_OID_ID_CE "\x21" /**< id-ce-policyMappings OBJECT IDENTIFIER ::=  { id-ce 33 } */
#define TTLS_OID_SUBJECT_ALT_NAME			TTLS_OID_ID_CE "\x11" /**< id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 } */
#define TTLS_OID_ISSUER_ALT_NAME			 TTLS_OID_ID_CE "\x12" /**< id-ce-issuerAltName OBJECT IDENTIFIER ::=  { id-ce 18 } */
#define TTLS_OID_SUBJECT_DIRECTORY_ATTRS	 TTLS_OID_ID_CE "\x09" /**< id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::=  { id-ce 9 } */
#define TTLS_OID_BASIC_CONSTRAINTS		   TTLS_OID_ID_CE "\x13" /**< id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 } */
#define TTLS_OID_NAME_CONSTRAINTS			TTLS_OID_ID_CE "\x1E" /**< id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 } */
#define TTLS_OID_POLICY_CONSTRAINTS		  TTLS_OID_ID_CE "\x24" /**< id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 } */
#define TTLS_OID_EXTENDED_KEY_USAGE		  TTLS_OID_ID_CE "\x25" /**< id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 } */
#define TTLS_OID_CRL_DISTRIBUTION_POINTS	 TTLS_OID_ID_CE "\x1F" /**< id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 } */
#define TTLS_OID_INIHIBIT_ANYPOLICY		  TTLS_OID_ID_CE "\x36" /**< id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 } */
#define TTLS_OID_FRESHEST_CRL				TTLS_OID_ID_CE "\x2E" /**< id-ce-freshestCRL OBJECT IDENTIFIER ::=  { id-ce 46 } */

/*
 * Netscape certificate extensions
 */
#define TTLS_OID_NS_CERT				 TTLS_OID_NETSCAPE "\x01"
#define TTLS_OID_NS_CERT_TYPE			TTLS_OID_NS_CERT  "\x01"
#define TTLS_OID_NS_BASE_URL			 TTLS_OID_NS_CERT  "\x02"
#define TTLS_OID_NS_REVOCATION_URL	   TTLS_OID_NS_CERT  "\x03"
#define TTLS_OID_NS_CA_REVOCATION_URL	TTLS_OID_NS_CERT  "\x04"
#define TTLS_OID_NS_RENEWAL_URL		  TTLS_OID_NS_CERT  "\x07"
#define TTLS_OID_NS_CA_POLICY_URL		TTLS_OID_NS_CERT  "\x08"
#define TTLS_OID_NS_SERVER_NAME	  TTLS_OID_NS_CERT  "\x0C"
#define TTLS_OID_NS_COMMENT			  TTLS_OID_NS_CERT  "\x0D"
#define TTLS_OID_NS_DATA_TYPE			TTLS_OID_NETSCAPE "\x02"
#define TTLS_OID_NS_CERT_SEQUENCE		TTLS_OID_NS_DATA_TYPE "\x05"

/*
 * OIDs for CRL extensions
 */
#define TTLS_OID_PRIVATE_KEY_USAGE_PERIOD	TTLS_OID_ID_CE "\x10"
#define TTLS_OID_CRL_NUMBER				  TTLS_OID_ID_CE "\x14" /**< id-ce-cRLNumber OBJECT IDENTIFIER ::= { id-ce 20 } */

/*
 * X.509 v3 Extended key usage OIDs
 */
#define TTLS_OID_ANY_EXTENDED_KEY_USAGE	  TTLS_OID_EXTENDED_KEY_USAGE "\x00" /**< anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 } */

#define TTLS_OID_KP			  TTLS_OID_PKIX "\x03" /**< id-kp OBJECT IDENTIFIER ::= { id-pkix 3 } */
#define TTLS_OID_SERVER_AUTH				 TTLS_OID_KP "\x01" /**< id-kp-serverAuth OBJECT IDENTIFIER ::= { id-kp 1 } */
#define TTLS_OID_CLIENT_AUTH				 TTLS_OID_KP "\x02" /**< id-kp-clientAuth OBJECT IDENTIFIER ::= { id-kp 2 } */
#define TTLS_OID_CODE_SIGNING				TTLS_OID_KP "\x03" /**< id-kp-codeSigning OBJECT IDENTIFIER ::= { id-kp 3 } */
#define TTLS_OID_EMAIL_PROTECTION			TTLS_OID_KP "\x04" /**< id-kp-emailProtection OBJECT IDENTIFIER ::= { id-kp 4 } */
#define TTLS_OID_TIME_STAMPING			   TTLS_OID_KP "\x08" /**< id-kp-timeStamping OBJECT IDENTIFIER ::= { id-kp 8 } */
#define TTLS_OID_OCSP_SIGNING				TTLS_OID_KP "\x09" /**< id-kp-OCSPSigning OBJECT IDENTIFIER ::= { id-kp 9 } */

/*
 * PKCS definition OIDs
 */

#define TTLS_OID_PKCS				TTLS_OID_RSA_COMPANY "\x01" /**< pkcs OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) 1 } */
#define TTLS_OID_PKCS1			   TTLS_OID_PKCS "\x01" /**< pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 } */
#define TTLS_OID_PKCS9			   TTLS_OID_PKCS "\x09" /**< pkcs-9 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 } */

/*
 * PKCS#1 OIDs
 */
#define TTLS_OID_PKCS1_RSA		   TTLS_OID_PKCS1 "\x01" /**< rsaEncryption OBJECT IDENTIFIER ::= { pkcs-1 1 } */
#define TTLS_OID_PKCS1_SHA256		TTLS_OID_PKCS1 "\x0b" /**< sha256WithRSAEncryption ::= { pkcs-1 11 } */
#define TTLS_OID_PKCS1_SHA384		TTLS_OID_PKCS1 "\x0c" /**< sha384WithRSAEncryption ::= { pkcs-1 12 } */
#define TTLS_OID_PKCS1_SHA512		TTLS_OID_PKCS1 "\x0d" /**< sha512WithRSAEncryption ::= { pkcs-1 13 } */

#define TTLS_OID_RSA_SHA_OBS		 "\x2B\x0E\x03\x02\x1D"

#define TTLS_OID_PKCS9_EMAIL		 TTLS_OID_PKCS9 "\x01" /**< emailAddress AttributeType ::= { pkcs-9 1 } */

/* RFC 4055 */
#define TTLS_OID_RSASSA_PSS		  TTLS_OID_PKCS1 "\x0a" /**< id-RSASSA-PSS ::= { pkcs-1 10 } */
#define TTLS_OID_MGF1				TTLS_OID_PKCS1 "\x08" /**< id-mgf1 ::= { pkcs-1 8 } */

/*
 * Digest algorithms
 */
#define TTLS_OID_DIGEST_ALG_MD2			  TTLS_OID_RSA_COMPANY "\x02\x02" /**< id-ttls_md2 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 2 } */
#define TTLS_OID_DIGEST_ALG_MD4			  TTLS_OID_RSA_COMPANY "\x02\x04" /**< id-ttls_md4 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 4 } */
#define TTLS_OID_DIGEST_ALG_MD5			  TTLS_OID_RSA_COMPANY "\x02\x05" /**< id-ttls_md5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 5 } */
#define TTLS_OID_DIGEST_ALG_SHA1			 TTLS_OID_ISO_IDENTIFIED_ORG TTLS_OID_OIW_SECSIG_SHA1 /**< id-ttls_sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 26 } */
#define TTLS_OID_DIGEST_ALG_SHA224		   TTLS_OID_GOV "\x03\x04\x02\x04" /**< id-sha224 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 4 } */
#define TTLS_OID_DIGEST_ALG_SHA256		   TTLS_OID_GOV "\x03\x04\x02\x01" /**< id-ttls_sha256 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 1 } */

#define TTLS_OID_DIGEST_ALG_SHA384		   TTLS_OID_GOV "\x03\x04\x02\x02" /**< id-sha384 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 2 } */

#define TTLS_OID_DIGEST_ALG_SHA512		   TTLS_OID_GOV "\x03\x04\x02\x03" /**< id-ttls_sha512 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashalgs(2) 3 } */

#define TTLS_OID_HMAC_SHA1				   TTLS_OID_RSA_COMPANY "\x02\x07" /**< id-hmacWithSHA1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 7 } */

#define TTLS_OID_HMAC_SHA224				 TTLS_OID_RSA_COMPANY "\x02\x08" /**< id-hmacWithSHA224 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 8 } */

#define TTLS_OID_HMAC_SHA256				 TTLS_OID_RSA_COMPANY "\x02\x09" /**< id-hmacWithSHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 9 } */

#define TTLS_OID_HMAC_SHA384				 TTLS_OID_RSA_COMPANY "\x02\x0A" /**< id-hmacWithSHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 10 } */

#define TTLS_OID_HMAC_SHA512				 TTLS_OID_RSA_COMPANY "\x02\x0B" /**< id-hmacWithSHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) digestAlgorithm(2) 11 } */

/*
 * Encryption algorithms
 */
#define TTLS_OID_DES_CBC		 TTLS_OID_ISO_IDENTIFIED_ORG TTLS_OID_OIW_SECSIG_ALG "\x07" /**< desCBC OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) 7 } */
#define TTLS_OID_DES_EDE3_CBC				TTLS_OID_RSA_COMPANY "\x03\x07" /**< des-ede3-cbc OBJECT IDENTIFIER ::= { iso(1) member-body(2) -- us(840) rsadsi(113549) encryptionAlgorithm(3) 7 } */

/*
 * EC key algorithms from RFC 5480
 */

/* id-ecPublicKey OBJECT IDENTIFIER ::= {
 *	   iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 } */
#define TTLS_OID_EC_ALG_UNRESTRICTED		 TTLS_OID_ANSI_X9_62 "\x02\01"

/*   id-ecDH OBJECT IDENTIFIER ::= {
 *	 iso(1) identified-organization(3) certicom(132)
 *	 schemes(1) ecdh(12) } */
#define TTLS_OID_EC_ALG_ECDH				 TTLS_OID_CERTICOM "\x01\x0c"

/*
 * ECParameters namedCurve identifiers, from RFC 5480, RFC 5639, and SEC2
 */

/* secp256r1 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 7 } */
#define TTLS_OID_EC_GRP_SECP256R1	TTLS_OID_ANSI_X9_62 "\x03\x01\x07"

/*
 * SEC1 C.1
 *
 * prime-field OBJECT IDENTIFIER ::= { id-fieldType 1 }
 * id-fieldType OBJECT IDENTIFIER ::= { ansi-X9-62 fieldType(1)}
 */
#define TTLS_OID_ANSI_X9_62_FIELD_TYPE   TTLS_OID_ANSI_X9_62 "\x01"
#define TTLS_OID_ANSI_X9_62_PRIME_FIELD  TTLS_OID_ANSI_X9_62_FIELD_TYPE "\x01"

/*
 * ECDSA signature identifiers, from RFC 5480
 */
#define TTLS_OID_ANSI_X9_62_SIG		  TTLS_OID_ANSI_X9_62 "\x04" /* signatures(4) */
#define TTLS_OID_ANSI_X9_62_SIG_SHA2	 TTLS_OID_ANSI_X9_62_SIG "\x03" /* ecdsa-with-SHA2(3) */

/* ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4) 1 } */
#define TTLS_OID_ECDSA_SHA1			  TTLS_OID_ANSI_X9_62_SIG "\x01"

/* ecdsa-with-SHA224 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 1 } */
#define TTLS_OID_ECDSA_SHA224			TTLS_OID_ANSI_X9_62_SIG_SHA2 "\x01"

/* ecdsa-with-SHA256 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 2 } */
#define TTLS_OID_ECDSA_SHA256			TTLS_OID_ANSI_X9_62_SIG_SHA2 "\x02"

/* ecdsa-with-SHA384 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 3 } */
#define TTLS_OID_ECDSA_SHA384			TTLS_OID_ANSI_X9_62_SIG_SHA2 "\x03"

/* ecdsa-with-SHA512 OBJECT IDENTIFIER ::= {
 *   iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *   ecdsa-with-SHA2(3) 4 } */
#define TTLS_OID_ECDSA_SHA512			TTLS_OID_ANSI_X9_62_SIG_SHA2 "\x04"

/**
 * Base OID descriptor structure.
 *
 * @asn1	- OID ASN.1 representation;
 * @asn1_len	- length of asn1;
 * @name	- official name (e.g. from RFC);
 * @description	- human friendly description.
 */
typedef struct {
	const char		*asn1;
	size_t			asn1_len;
	const char		*name;
	const char		*description;
} ttls_oid_descriptor_t;

/**
 * \brief		   Translate an ASN.1 OID into its numeric representation
 *				  (e.g. "\x2A\x86\x48\x86\xF7\x0D" into "1.2.840.113549")
 *
 * \param buf	   buffer to put representation in
 * \param size	  size of the buffer
 * \param oid	   OID to translate
 */
void ttls_oid_get_numeric_string(char *buf, size_t size, const ttls_asn1_buf *oid);

/**
 * \brief		  Translate an X.509 extension OID into local values
 *
 * \param oid	  OID to use
 * \param ext_type place to store the extension type
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_x509_ext_type(const ttls_asn1_buf *oid, int *ext_type);

/**
 * \brief		  Translate an X.509 attribute type OID into the short name
 *				 (e.g. the OID for an X520 Common Name into "CN")
 *
 * \param oid	  OID to use
 * \param short_name	place to store the string pointer
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_attr_short_name(const ttls_asn1_buf *oid, const char **short_name);

/**
 * \brief		  Translate PublicKeyAlgorithm OID into pk_type
 *
 * \param oid	  OID to use
 * \param pk_alg   place to store public key algorithm
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_pk_alg(const ttls_asn1_buf *oid, ttls_pk_type_t *pk_alg);

/**
 * \brief		  Translate pk_type into PublicKeyAlgorithm OID
 *
 * \param pk_alg   Public key type to look for
 * \param oid	  place to store ASN.1 OID string pointer
 * \param olen	 length of the OID
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_oid_by_pk_alg(ttls_pk_type_t pk_alg,
			   const char **oid, size_t *olen);

/**
 * \brief		  Translate NamedCurve OID into an EC group identifier
 *
 * \param oid	  OID to use
 * \param grp_id   place to store group id
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_ec_grp(const ttls_asn1_buf *oid, ttls_ecp_group_id *grp_id);

/**
 * \brief		  Translate EC group identifier into NamedCurve OID
 *
 * \param grp_id   EC group identifier
 * \param oid	  place to store ASN.1 OID string pointer
 * \param olen	 length of the OID
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_oid_by_ec_grp(ttls_ecp_group_id grp_id,
			   const char **oid, size_t *olen);

/**
 * \brief		  Translate SignatureAlgorithm OID into md_type and pk_type
 *
 * \param oid	  OID to use
 * \param md_alg   place to store message digest algorithm
 * \param pk_alg   place to store public key algorithm
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_sig_alg(const ttls_asn1_buf *oid,
		 ttls_md_type_t *md_alg, ttls_pk_type_t *pk_alg);

/**
 * \brief		  Translate SignatureAlgorithm OID into description
 *
 * \param oid	  OID to use
 * \param desc	 place to store string pointer
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_sig_alg_desc(const ttls_asn1_buf *oid, const char **desc);

/**
 * \brief		  Translate md_type and pk_type into SignatureAlgorithm OID
 *
 * \param md_alg   message digest algorithm
 * \param pk_alg   public key algorithm
 * \param oid	  place to store ASN.1 OID string pointer
 * \param olen	 length of the OID
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_oid_by_sig_alg(ttls_pk_type_t pk_alg, ttls_md_type_t md_alg,
				const char **oid, size_t *olen);

/**
 * \brief		  Translate hash algorithm OID into md_type
 *
 * \param oid	  OID to use
 * \param md_alg   place to store message digest algorithm
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_md_alg(const ttls_asn1_buf *oid, ttls_md_type_t *md_alg);

/**
 * \brief		  Translate hmac algorithm OID into md_type
 *
 * \param oid	  OID to use
 * \param md_hmac  place to store message hmac algorithm
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_md_hmac(const ttls_asn1_buf *oid, ttls_md_type_t *md_hmac);

/**
 * \brief		  Translate md_type into hash algorithm OID
 *
 * \param md_alg   message digest algorithm
 * \param oid	  place to store ASN.1 OID string pointer
 * \param olen	 length of the OID
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_oid_by_md(ttls_md_type_t md_alg, const char **oid, size_t *olen);

/**
 * \brief		  Translate encryption algorithm OID into cipher_type
 *
 * \param oid		   OID to use
 * \param cipher_alg	place to store cipher algorithm
 *
 * \return		 0 if successful, or -1
 */
int ttls_oid_get_cipher_alg(const ttls_asn1_buf *oid, ttls_cipher_type_t *cipher_alg);

#endif /* oid.h */
