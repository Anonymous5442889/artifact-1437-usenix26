#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <gmssl/sm9.h>
#include <gmssl/sha2.h>
#include "art_bls.h"

// Final exponent can be computed only once for multiple pairings multiplication
void sm9_z256_miller_loop(sm9_z256_fp12_t r, const SM9_Z256_TWIST_POINT *Q, const SM9_Z256_POINT *P) {
	const char *abits = "00100000000000000000000000000000000000010000101100020200101000020";

	SM9_Z256_TWIST_POINT T;
	SM9_Z256_TWIST_POINT Q1;
	SM9_Z256_TWIST_POINT Q2;
	
	sm9_z256_fp2_copy(T.X, Q->X);
	sm9_z256_fp2_copy(T.Y, Q->Y);
	sm9_z256_fp2_copy(T.Z, Q->Z);
	
	SM9_Z256_AFFINE_POINT P_;
	sm9_z256_point_to_affine(&P_, P);
	sm9_z256_twist_point_neg(&Q1, Q);
	
	sm9_z256_fp2_t lw[3];
	sm9_z256_fp2_t pre[5]; // same for Q and -Q
	
	sm9_z256_fp2_sqr(pre[0], Q->Y);
	sm9_z256_fp2_mul(pre[4], Q->X, Q->Z);
	sm9_z256_fp2_dbl(pre[4], pre[4]);
	sm9_z256_fp2_sqr(pre[1], Q->Z);
	sm9_z256_fp2_mul(pre[1], pre[1], Q->Z);
	sm9_z256_fp2_mul_fp(pre[2], pre[1], P_.Y);
	sm9_z256_fp2_dbl(pre[2], pre[2]);
	sm9_z256_fp2_mul_fp(pre[3], pre[1], P_.X);
	sm9_z256_fp2_dbl(pre[3], pre[3]);
	sm9_z256_fp2_neg(pre[3], pre[3]);

	sm9_z256_fp12_set_one(r);

	int i;
	for (i = 0; i < strlen(abits); i++) {
		sm9_z256_fp12_sqr(r, r);
		sm9_z256_eval_g_tangent(&T, lw, &T, &P_);
		sm9_z256_fp12_line_mul(r, r, lw);

		if (abits[i] == '1') {
			//sm9_z256_eval_g_line_no_pre(&T, lw, &T, Q, &P_);
			sm9_z256_eval_g_line(&T, lw, pre, &T, Q, &P_);
			sm9_z256_fp12_line_mul(r, r, lw);
		} else if (abits[i] == '2') {
			//sm9_z256_eval_g_line_no_pre(&T, lw, &T, &Q1, &P_);
			sm9_z256_eval_g_line(&T, lw, pre, &T, &Q1, &P_);
			sm9_z256_fp12_line_mul(r, r, lw);
		}
	}

	sm9_z256_twist_point_pi1(&Q1, Q);
	sm9_z256_twist_point_neg_pi2(&Q2, Q);

	sm9_z256_eval_g_line_no_pre(&T, lw, &T, &Q1, &P_);
	sm9_z256_fp12_line_mul(r, r, lw);

	sm9_z256_eval_g_line_no_pre(&T, lw, &T, &Q2, &P_);
	sm9_z256_fp12_line_mul(r, r, lw);
}

void sm9_z256_point_copy(SM9_Z256_POINT *P, const SM9_Z256_POINT *Q) {
	sm9_z256_copy(P->X, Q->X);
	sm9_z256_copy(P->Y, Q->Y);
	sm9_z256_copy(P->Z, Q->Z);
}

void sm9_z256_twist_point_copy(SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q) {
	sm9_z256_fp2_copy(P->X, Q->X);
	sm9_z256_fp2_copy(P->Y, Q->Y);
	sm9_z256_fp2_copy(P->Z, Q->Z);
}

void sm9_z256_twist_point_from_hash(SM9_Z256_TWIST_POINT *P, const sm9_z256_t r) {
	sm9_z256_twist_point_mul_generator(P, r);
}

void sm9_z256_hash_to_twist_point(SM9_Z256_TWIST_POINT *ht, const uint8_t *data, size_t datalen) {
	sm9_z256_t hash;
	uint8_t dgst[32];
	SHA256_CTX ctx;
	
	sha256_init(&ctx);
	sha256_update(&ctx, data, datalen);
	sha256_finish(&ctx, dgst);
	
	sm9_z256_from_bytes(hash, dgst);
	sm9_z256_twist_point_from_hash(ht, hash);
}

void sm9_z256_hash_to_fn(sm9_z256_t r, const uint8_t *data, size_t datalen) {
	sm9_z256_t hash;
	uint8_t dgst[32];
	SHA256_CTX ctx;
	
	sha256_init(&ctx);
	sha256_update(&ctx, data, datalen);
	sha256_finish(&ctx, dgst);
	
	sm9_z256_from_bytes(r, dgst);
	if (sm9_z256_cmp(r, SM9_Z256_N) >= 0) {
		sm9_z256_sub(r, r, SM9_Z256_N);
	}
}

void sm9_z256_hash_swe_ct(sm9_z256_t r, const SM9_SWE_CIPHERTEXT *ct) {
	sm9_z256_t hash;
	uint8_t dgst[32], buf[129];
	SHA256_CTX ctx;
	int i;
	
	sha256_init(&ctx);
	sm9_z256_point_to_uncompressed_octets(&(ct->h), buf);
	sha256_update(&ctx, buf, 65);
	sm9_z256_point_to_uncompressed_octets(&(ct->c), buf);
	sha256_update(&ctx, buf, 65);
	sm9_z256_point_to_uncompressed_octets(&(ct->c0), buf);
	sha256_update(&ctx, buf, 65);
	for (i = 0; i < ct->n; i++) {
		sm9_z256_point_to_uncompressed_octets(&(ct->cs[i]), buf);
		sha256_update(&ctx, buf, 65);
	}
	for (i = 0; i < ct->l; i++) {
		sm9_z256_twist_point_to_uncompressed_octets(&(ct->cs_[i]), buf);
		sha256_update(&ctx, buf, 129);
	}
	sha256_finish(&ctx, dgst);
	
	sm9_z256_from_bytes(r, dgst);
	if (sm9_z256_cmp(r, SM9_Z256_N) >= 0) {
		sm9_z256_sub(r, r, SM9_Z256_N);
	}
}

void sm9_z256_hash_swe_prf1(sm9_z256_t r, const SM9_SWE_PROOF_1 *prf1, const SM9_Z256_POINT *c) {
	sm9_z256_t hash;
	uint8_t dgst[32], buf[65];
	SHA256_CTX ctx;
	int i;
	
	sha256_init(&ctx);
	sm9_z256_point_to_uncompressed_octets(&(SM9_Z256_MONT_P1), buf);
	sha256_update(&ctx, buf, 65);
	sm9_z256_point_to_uncompressed_octets(c, buf);
	sha256_update(&ctx, buf, 65);
	sm9_z256_point_to_uncompressed_octets(&(prf1->g_), buf);
	sha256_update(&ctx, buf, 65);
	sm9_z256_point_to_uncompressed_octets(&(prf1->c_), buf);
	sha256_update(&ctx, buf, 65);
	sm9_z256_point_to_uncompressed_octets(&(prf1->f), buf);
	sha256_finish(&ctx, dgst);
	
	sm9_z256_from_bytes(r, dgst);
	if (sm9_z256_cmp(r, SM9_Z256_N) >= 0) {
		sm9_z256_sub(r, r, SM9_Z256_N);
	}
}

void sm9_z256_modn_parity_check_den(sm9_z256_t pck[], const sm9_z256_t zeta[], uint16_t num) {
	assert (num <= SM9_BLS_MAX_MEMBER + 1);
	
	sm9_z256_t den[SM9_BLS_MAX_MEMBER + 1], tmp;
	int i, j;
	
	for (i = 0; i < num; i++) {
		sm9_z256_set_one(den[i]);
		if (i & 1) sm9_z256_sub(den[i], SM9_Z256_N, den[i]);
	}
	
	for (i = 0; i < num; i++) {
		for (j = i+1; j < num; j++) {
			sm9_z256_modn_sub(tmp, zeta[j], zeta[i]);
			sm9_z256_modn_mul(den[i], den[i], tmp);
			sm9_z256_modn_mul(den[j], den[j], tmp);
		}
	}
	sm9_z256_modn_batch_inv(pck, den, num);
}

void sm9_z256_modn_lagrange(sm9_z256_t lgr[], const sm9_z256_t zeta[], uint16_t num) {
	assert (num <= SM9_BLS_MAX_MEMBER);
	
	sm9_z256_t den[SM9_BLS_MAX_MEMBER], prod, tmp;
	int i, j;
	
	sm9_z256_set_one(prod);
	for (i = 0; i < num; i++) {
		sm9_z256_set_one(den[i]);
		if (i & 1) sm9_z256_sub(den[i], SM9_Z256_N, den[i]);
	}
	for (i = 0; i < num; i++) {
		sm9_z256_modn_mul(prod, prod, zeta[i]); // prod = prod(zeta)
		sm9_z256_modn_mul(den[i], den[i], zeta[i]);
		for (j = i+1; j < num; j++) {
			sm9_z256_modn_sub(tmp, zeta[j], zeta[i]);
			sm9_z256_modn_mul(den[i], den[i], tmp);
			sm9_z256_modn_mul(den[j], den[j], tmp);
		}
	}

	sm9_z256_modn_batch_inv(lgr, den, num);
	
	for (i = 0; i < num; i++) {
		sm9_z256_modn_mul(lgr[i], lgr[i], prod);
	}
}

// "Fast Multi-scalar Multiplication Methods on Elliptic Curves
// with Precomputation Strategy Using Montgomery Trick", Section 4.1
// 3(n-1)*M + I for n*I
void sm9_z256_modn_batch_inv(sm9_z256_t b[], const sm9_z256_t a[], uint16_t num) {
	sm9_z256_t c[SM9_BLS_MAX_MEMBER + 1];
	int i;
	
	sm9_z256_copy(c[0], a[0]);
	for (i = 1; i < num; i++) {
		sm9_z256_modn_mul(c[i], c[i-1], a[i]);
	}
	sm9_z256_modn_inv(c[num-1], c[num-1]); // c[num-1] = u
	for (i = num-1; i > 0; i--) {
		sm9_z256_modn_mul(b[i], c[i-1], c[num-1]);
		sm9_z256_modn_mul(c[num-1], c[num-1], a[i]);
	}
	sm9_z256_copy(b[0], c[num-1]);
}


#if SM9_SWE_MAX_MESSAGE == 32
uint16_t sm9_z256_discrete_log(const sm9_z256_fp12_t r) {
	int i, j;
	sm9_z256_fp12_t c;
	
	for (i = 0; i < 16; i++) {
		sm9_z256_fp12_mul(c, r, gt_gstep_8[i]);
		for (j = 0; j < 16; j++) {
			if (sm9_z256_fp12_equ(c, gt_bstep_8[j])) {
				return (uint16_t)(i * 16 + j);
			}
		}
	}
	return 65535;
}
#elif SM9_SWE_MAX_MESSAGE == 16
int sm9_z256_discrete_log(const sm9_z256_fp12_t r) {
	int i, j;
	sm9_z256_fp12_t c;
	
	for (i = 0; i < 256; i++) {
		sm9_z256_fp12_mul(c, r, gt_gstep_16[i]);
		for (j = 0; j < 256; j++) {
			if (sm9_z256_fp12_equ(c, baby_step_16[j])) {
				return i * 256 + j;
			}
		}
	}
	return -1;
}
#endif
