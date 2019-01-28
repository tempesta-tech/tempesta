/**
 *		Tempesta FW
 *
 * Copyright (C) 2018-2019 Tempesta Technologies, Inc.
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
#include <linux/types.h>
#include <asm/fpu/api.h>
#include <linux/bug.h>
#include <linux/kernel.h>

#include "test.h"
#include "ttls.h"

/*
 * ------------------------------------------------------------------------
 *	Testing mocks
 * ------------------------------------------------------------------------
 */
void
ttls_md_init(TlsMdCtx *ctx)
{
}

void
ttls_md_free(TlsMdCtx *ctx)
{
}

int
ttls_md_finish(TlsMdCtx *ctx, unsigned char *output)
{
	return 0;
}

int
ttls_md(const TlsMdInfo *md_info, const unsigned char *input,
		   size_t ilen, unsigned char *output)
{
	return 0;
}

int
ttls_md_setup(TlsMdCtx *ctx, const TlsMdInfo *md_info, int hmac)
{
	return 0;
}

const TlsMdInfo *
ttls_md_info_from_type(ttls_md_type_t md_type)
{
	return NULL;
}

int
ttls_md_update(TlsMdCtx *ctx, const unsigned char *input, size_t ilen)
{
	return 0;
}

/*
 * ------------------------------------------------------------------------
 *	Tests for Tempesta TLS low-level basic math/crypto operations.
 *
 * Note that some of the routines are designed to be called in process
 * context during Tempesta FW intialization and some of them are for
 * run-time softirq context, so the testing routines must enable/disable
 * FPU for them on its own.
 * ------------------------------------------------------------------------
 */
#include "../../../tls/bignum.c"
#include "../../../tls/ecp_curves.c"
#include "../../../tls/ecp.c"
#include "../../../tls/rsa_internal.c"
#include "../../../tls/rsa.c"

#define GCD_PAIR_COUNT  3

static const int gcd_pairs[GCD_PAIR_COUNT][3] =
{
	{ 693, 609, 21 },
	{ 1764, 868, 28 },
	{ 768454923, 542167814, 1 }
};

/**
 * MPI uses FPU only for primes, so no need to store/restore FPU state now.
 * TODO #1064: add tests for primes.
 */
TEST(tls, mpi)
{
	int ret, i;
	ttls_mpi A, E, N, X, Y, U, V;

	ttls_mpi_init(&Y);
	ttls_mpi_init(&V);
	ttls_mpi_init(&A);
	TTLS_MPI_CHK(ttls_mpi_read_string(&A, 16,
					  "EFE021C2645FD1DC586E69184AF4A31E"
					  "D5F53E93B5F123FA41680867BA110131"
					  "944FE7952E2517337780CB0DB80E61AA"
					  "E7C8DDC6C5C6AADEB34EB38A2F40D5E6"));
	ttls_mpi_init(&E);
	TTLS_MPI_CHK(ttls_mpi_read_string(&E, 16,
					  "B2E7EFD37075B9F03FF989C7C5051C20"
					  "34D2A323810251127E7BF8625A4F49A5"
					  "F3E27F4DA8BD59C47D6DAABA4C8127BD"
					  "5B5C25763222FEFCCFC38B832366C29E"));
	ttls_mpi_init(&N);
	TTLS_MPI_CHK(ttls_mpi_read_string(&N, 16,
					  "0066A198186C18C10B2F5ED9B522752A"
					  "9830B69916E535C8F047518A889A43A5"
					  "94B6BED27A168D31D4A52F88925AA8F5"));
	ttls_mpi_init(&X);
	TTLS_MPI_CHK(ttls_mpi_mul_mpi(&X, &A, &N));
	ttls_mpi_init(&U);
	TTLS_MPI_CHK(ttls_mpi_read_string(&U, 16,
					  "602AB7ECA597A3D6B56FF9829A5E8B85"
					  "9E857EA95A03512E2BAE7391688D264A"
					  "A5663B0341DB9CCFD2C4C5F421FEC814"
					  "8001B72E848A38CAE1C65F78E56ABDEF"
					  "E12D3C039B8A02D6BE593F0BBBDA56F1"
					  "ECF677152EF804370C1A305CAF3B5BF1"
					  "30879B56C61DE584A0F53A2447A51E"));

	pr_info("  MPI test #1 (mul_mpi): ");

	if ((ret = ttls_mpi_cmp_mpi(&X, &U)))
		goto cleanup;
	pr_info("passed\n");

	TTLS_MPI_CHK(ttls_mpi_div_mpi(&X, &Y, &A, &N));
	TTLS_MPI_CHK(ttls_mpi_read_string(&U, 16,
					"256567336059E52CAE22925474705F39A94"));
	TTLS_MPI_CHK(ttls_mpi_read_string(&V, 16,
					  "6613F26162223DF488E9CD48CC132C7A"
					  "0AC93C701B001B092E4E5B9F73BCD27B"
					  "9EE50D0657C77F374E903CDFA4C642"));

	pr_info("  MPI test #2 (div_mpi): ");

	if ((ret = ttls_mpi_cmp_mpi(&X, &U)))
		goto cleanup;
	if ((ret = ttls_mpi_cmp_mpi(&Y, &V)))
		goto cleanup;
	pr_info("passed\n");

	TTLS_MPI_CHK(ttls_mpi_exp_mod(&X, &A, &E, &N, NULL));
	TTLS_MPI_CHK(ttls_mpi_read_string(&U, 16,
					  "36E139AEA55215609D2816998ED020BB"
					  "BD96C37890F65171D948E9BC7CBAA4D9"
					  "325D24D6A3C12710F10A09FA08AB87"));

	pr_info("  MPI test #3 (exp_mod): ");

	if ((ret = ttls_mpi_cmp_mpi(&X, &U)))
		goto cleanup;
	pr_info("passed\n");

	TTLS_MPI_CHK(ttls_mpi_inv_mod(&X, &A, &N));
	TTLS_MPI_CHK(ttls_mpi_read_string(&U, 16,
					  "003A0AAEDD7E784FC07D8F9EC6E3BFD5"
					  "C3DBA76456363A10869622EAC2DD84EC"
					  "C5B8A74DAC4D09E03B5E0BE779F2DF61"));

	pr_info("  MPI test #4 (inv_mod): ");

	if ((ret = ttls_mpi_cmp_mpi(&X, &U)))
		goto cleanup;
	pr_info("passed\n");

	pr_info("  MPI test #5 (simple gcd): ");

	for (i = 0; i < GCD_PAIR_COUNT; i++) {
		TTLS_MPI_CHK(ttls_mpi_lset(&X, gcd_pairs[i][0]));
		TTLS_MPI_CHK(ttls_mpi_lset(&Y, gcd_pairs[i][1]));

		TTLS_MPI_CHK(ttls_mpi_gcd(&A, &X, &Y));

		if ((ret = ttls_mpi_cmp_int(&A, gcd_pairs[i][2]))) {
			pr_info("failed at %d\n", i);
			goto cleanup;
		}
	}
	pr_info("passed\n\n");

cleanup:
	if (ret)
		pr_info("failed: return code = %08X\n\n", ret);

	ttls_mpi_free(&A);
	ttls_mpi_free(&E);
	ttls_mpi_free(&N);
	ttls_mpi_free(&X);
	ttls_mpi_free(&Y);
	ttls_mpi_free(&U);
	ttls_mpi_free(&V);

	EXPECT_ZERO(ret);
}

TEST(tls, ecp)
{
	int ret;
	size_t i;
	ttls_ecp_group grp;
	ttls_ecp_point R, P;
	ttls_mpi m;
	unsigned long add_c_prev, dbl_c_prev, mul_c_prev;
	/* Exponents especially adapted for secp192r1. */
	const char *exponents[] = {
		/* one */
		"000000000000000000000000000000000000000000000001",
		/* N - 1 */
		"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22830",
		/* random */
		"5EA6F389A38B8BC81E767753B15AA5569E1782E30ABE7D25",
		/* one and zeros */
		"400000000000000000000000000000000000000000000000",
		/* all ones */
		"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		/* 101010... */
		"555555555555555555555555555555555555555555555555",
	};

	ttls_ecp_group_init(&grp);
	ttls_ecp_point_init(&R);
	ttls_ecp_point_init(&P);
	ttls_mpi_init(&m);

	/* Use secp192r1 if available, or any available curve */
	TTLS_MPI_CHK(ttls_ecp_group_load(&grp, TTLS_ECP_DP_SECP192R1));

	pr_info("  ECP test #1 (constant op_count, base point G): ");

	/* Do a dummy multiplication first to trigger precomputation */
	TTLS_MPI_CHK(ttls_mpi_lset(&m, 2));
	TTLS_MPI_CHK(ttls_ecp_mul(&grp, &P, &m, &grp.G, false));

	add_count = 0;
	dbl_count = 0;
	mul_count = 0;
	TTLS_MPI_CHK(ttls_mpi_read_string(&m, 16, exponents[0]));
	TTLS_MPI_CHK(ttls_ecp_mul(&grp, &R, &m, &grp.G, false));

	for (i = 1; i < sizeof(exponents) / sizeof(exponents[0]); i++) {
		add_c_prev = add_count;
		dbl_c_prev = dbl_count;
		mul_c_prev = mul_count;
		add_count = 0;
		dbl_count = 0;
		mul_count = 0;

		TTLS_MPI_CHK(ttls_mpi_read_string(&m, 16, exponents[i]));
		TTLS_MPI_CHK(ttls_ecp_mul(&grp, &R, &m, &grp.G, false));

		if (add_count != add_c_prev || dbl_count != dbl_c_prev
		    || mul_count != mul_c_prev)
		{
			pr_info("failed (%u)\n", (unsigned int)i);
			ret = 1;
			goto cleanup;
		}
	}
	pr_info("passed\n");

	pr_info("  ECP test #2 (constant op_count, other point): ");
	/* We computed P = 2G last time, use it */

	add_count = 0;
	dbl_count = 0;
	mul_count = 0;
	TTLS_MPI_CHK(ttls_mpi_read_string(&m, 16, exponents[0]));
	TTLS_MPI_CHK(ttls_ecp_mul(&grp, &R, &m, &P, false));

	for (i = 1; i < sizeof(exponents) / sizeof(exponents[0]); i++) {
		add_c_prev = add_count;
		dbl_c_prev = dbl_count;
		mul_c_prev = mul_count;
		add_count = 0;
		dbl_count = 0;
		mul_count = 0;

		TTLS_MPI_CHK(ttls_mpi_read_string(&m, 16, exponents[i]));
		TTLS_MPI_CHK(ttls_ecp_mul(&grp, &R, &m, &P, false));

		if (add_count != add_c_prev || dbl_count != dbl_c_prev
		    || mul_count != mul_c_prev)
		{
			pr_info("failed (%u)\n", (unsigned int)i);
			ret = 1;
			goto cleanup;
		}
	}
	pr_info("passed\n\n");

cleanup:
	if (ret < 0)
		pr_info("Unexpected error, return code = %08X\n\n", ret);

	ttls_ecp_group_free(&grp);
	ttls_ecp_point_free(&R);
	ttls_ecp_point_free(&P);
	ttls_mpi_free(&m);

	EXPECT_ZERO(ret);
}

/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN	128
#define PT_LEN  24

#define RSA_N	"9292758453063D803DD603D5E777D788"			\
		"8ED1D5BF35786190FA2F23EBC0848AEA"			\
		"DDA92CA6C3D80B32C4D109BE0F36D6AE"			\
		"7130B9CED7ACDF54CFC7555AC14EEBAB"			\
		"93A89813FBF3C4F8066D2D800F7C38A8"			\
		"1AE31942917403FF4946B0A83D3D3E05"			\
		"EE57C6F5F5606FB5D4BC6CD34EE0801A"			\
		"5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E	"10001"

#define RSA_D	"24BF6185468786FDD303083D25E64EFC"			\
		"66CA472BC44D253102F8B4A9D3BFA750"			\
		"91386C0077937FE33FA3252D28855837"			\
		"AE1B484A8A9A45F7EE8C0C634F99E8CD"			\
		"DF79C5CE07EE72C7F123142198164234"			\
		"CABB724CF78B8173B9F880FC86322407"			\
		"AF1FEDFDDE2BEB674CA15F3E81A1521E"			\
		"071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P	"C36D0EB7FCD285223CFB5AABA5BDA3D8"			\
		"2C01CAD19EA484A87EA4377637E75500"			\
		"FCB2005C5C7DD6EC4AC023CDA285D796"			\
		"C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q	"C000DF51A7C77AE8D7C7370C1FF55B69"			\
		"E211C2B9E5DB1ED0BF61D0D9899620F4"			\
		"910E4168387E3C30AA1E00C339A79508"			\
		"8452DD96A9A5EA5D9DCA68DA636032AF"

#define RSA_PT	"\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF"	\
		"\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

TEST(tls, rsa)
{
	int ret = 0;
	size_t len;
	ttls_rsa_context rsa;
	unsigned char rsa_plaintext[PT_LEN];
	unsigned char rsa_decrypted[PT_LEN];
	unsigned char rsa_ciphertext[KEY_LEN];

	ttls_mpi K;

	ttls_mpi_init(&K);
	ttls_rsa_init(&rsa, TTLS_RSA_PKCS_V15, 0);

	TTLS_MPI_CHK(ttls_mpi_read_string(&K, 16, RSA_N ));
	TTLS_MPI_CHK(ttls_rsa_import(&rsa, &K, NULL, NULL, NULL, NULL));
	TTLS_MPI_CHK(ttls_mpi_read_string(&K, 16, RSA_P ));
	TTLS_MPI_CHK(ttls_rsa_import(&rsa, NULL, &K, NULL, NULL, NULL));
	TTLS_MPI_CHK(ttls_mpi_read_string(&K, 16, RSA_Q ));
	TTLS_MPI_CHK(ttls_rsa_import(&rsa, NULL, NULL, &K, NULL, NULL));
	TTLS_MPI_CHK(ttls_mpi_read_string(&K, 16, RSA_D ));
	TTLS_MPI_CHK(ttls_rsa_import(&rsa, NULL, NULL, NULL, &K, NULL));
	TTLS_MPI_CHK(ttls_mpi_read_string(&K, 16, RSA_E ));
	TTLS_MPI_CHK(ttls_rsa_import(&rsa, NULL, NULL, NULL, NULL, &K));

	TTLS_MPI_CHK(ttls_rsa_complete(&rsa));

	pr_info("  RSA key validation: ");

	if ((ret = ttls_rsa_check_pubkey(&rsa)))
		goto cleanup;
	if ((ret = ttls_rsa_check_privkey(&rsa)))
		goto cleanup;
	pr_info("passed\n");

	pr_info("  PKCS#1 encryption : ");

	/* Run-time (softirq) logic. */
	kernel_fpu_begin();

	memcpy(rsa_plaintext, RSA_PT, PT_LEN);
	ret = ttls_rsa_pkcs1_encrypt(&rsa, TTLS_RSA_PUBLIC, PT_LEN,
				     rsa_plaintext, rsa_ciphertext);
	if (ret)
		goto cleanup_si;
	pr_info("passed\n");

	pr_info("  PKCS#1 decryption : ");

	ret = ttls_rsa_pkcs1_decrypt(&rsa, TTLS_RSA_PRIVATE, &len, rsa_ciphertext,
				     rsa_decrypted, sizeof(rsa_decrypted));
	if (ret)
		goto cleanup_si;

	if ((ret = memcmp(rsa_decrypted, rsa_plaintext, len)))
		goto cleanup_si;
	pr_info("passed\n\n");

cleanup_si:
	kernel_fpu_end();
cleanup:
	if (ret)
		pr_info("failed: return code = %08X\n\n", ret);

	ttls_mpi_free(&K);
	ttls_rsa_free(&rsa);

	EXPECT_ZERO(ret);
}

TEST_SUITE(tls)
{
	ttls_mpi_modinit();

	TEST_RUN(tls, mpi);
	TEST_RUN(tls, ecp);
	TEST_RUN(tls, rsa);

	ttls_mpi_modexit();
}
