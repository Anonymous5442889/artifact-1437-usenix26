#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <gmssl/sm9.h>
#include "art_bls.h"

int sm9_swe_prove_1(SM9_SWE_PROOF_1 *prf1, const SM9_SWE_CIPHERTEXT *ct,
		const SM9_Z256_POINT vks[], const sm9_z256_t r) {
	sm9_z256_t v[SM9_BLS_MAX_MEMBER + 1], zeta[SM9_BLS_MAX_MEMBER + 1]; // n+1
	sm9_z256_t w[SM9_BLS_MAX_MEMBER + 1], pow, val; // n+1
	uint8_t out[32], buf[65];
	int i, j, k = ct->n + 1 - ct->t;
	
	SM9_Z256_POINT P;
	
	sm9_z256_hash_swe_ct(v[0], ct);
	for (i = 1; i < k; i++) {
		sm9_z256_to_bytes(v[i-1], out);
		sm9_z256_hash_to_fn(v[i], out, 32);
	}
	
	sm9_z256_set_zero(zeta[0]);
	for (i = 0; i < ct->n; i++) {
		sm9_z256_point_to_uncompressed_octets(&vks[i], buf);
		sm9_z256_hash_to_fn(zeta[i + 1], buf, 65);
	}
	
	for (i = 0; i <= ct->n; i++) {
		sm9_z256_set_one(pow);
		sm9_z256_set_zero(w[i]);
		for (j = 0; j < k; j++) {
			sm9_z256_modn_mul(val, v[j], pow);
			sm9_z256_modn_add(w[i], w[i], val);
			sm9_z256_modn_mul(pow, pow, zeta[i]);
		}
	}
	sm9_z256_modn_parity_check_den(v, zeta, ct->n + 1);
	for (i = 0; i <= ct->n; i++) {
		sm9_z256_modn_mul(w[i], w[i], v[i]);
	}
	
	if (ct -> n > 50) { // Faster MSM
		sm9_z256_point_mul(&(prf1->c_), w[0], &(ct->c0));
		msm_bos_coster_heap(&P, w + 1, ct->cs, ct->n);
		sm9_z256_point_add(&(prf1->c_), &(prf1->c_), &P);

		sm9_z256_point_mul(&(prf1->g_), w[0], &(ct->h));
		msm_bos_coster_heap(&P, w + 1, vks, ct->n);
		sm9_z256_point_add(&(prf1->g_), &(prf1->g_), &P);
	}
	else {
		sm9_z256_point_mul(&(prf1->c_), w[0], &(ct->c0));
		for (i = 1; i <= ct->n; i++) {
			sm9_z256_point_mul(&P, w[i], &(ct->cs[i-1]));
			sm9_z256_point_add(&(prf1->c_), &(prf1->c_), &P);
		}
		
		sm9_z256_point_mul(&(prf1->g_), w[0], &(ct->h));
		for (i = 1; i <= ct->n; i++) {
			sm9_z256_point_mul(&P, w[i], &(vks[i-1]));
			sm9_z256_point_add(&(prf1->g_), &(prf1->g_), &P);
		}
	}

	sm9_z256_rand_range(val, sm9_z256_order());
	sm9_z256_point_mul_generator(&(prf1->f), val);
	sm9_z256_point_mul(&(prf1->f_), val, &(prf1->g_));
	
	sm9_z256_copy(prf1->z, val);
	sm9_z256_hash_swe_prf1(val, prf1, &(ct->c));
	sm9_z256_modn_mul(val, val, r);
	sm9_z256_modn_add(prf1->z, prf1->z, val);
	
	return 1;
}

int sm9_swe_verify_1(const SM9_SWE_PROOF_1 *prf1, const SM9_SWE_CIPHERTEXT *ct) {
	sm9_z256_t val; // n+1
	uint8_t out[32], buf[65];
	int i, j;
	
	SM9_Z256_POINT P, Q;
	
	sm9_z256_hash_swe_prf1(val, prf1, &(ct->c));
	sm9_z256_point_mul(&P, val, &(prf1->c_));
	sm9_z256_point_add(&P, &P, &(prf1->f_));
	sm9_z256_point_mul(&Q, prf1->z, &(prf1->g_));
	if (!sm9_z256_point_equ(&P, &Q)) {
		return 0;
	}
	
	sm9_z256_point_mul(&P, val, &(ct->c));
	sm9_z256_point_add(&P, &P, &(prf1->f));
	sm9_z256_point_mul_generator(&Q, prf1->z);
	
	return sm9_z256_point_equ(&P, &Q);
}

int sm9_swe_prove_2(SM9_SWE_PROOF_2 *prf2, const SM9_SWE_CIPHERTEXT *ct, const uint16_t m[],
		const sm9_z256_t r, const sm9_z256_t r0, const sm9_z256_t rho, const SM9_Z256_TWIST_POINT crs[]) {
	sm9_z256_t u[SM9_SWE_MAX_MESSAGE]; // l
	sm9_z256_t r_, r0_, rho_, val;
	int i;

	for (i = 0; i < ct->l; i++) {
		sm9_z256_rand_range(u[i], sm9_z256_order());
	}
	sm9_z256_rand_range(r_, sm9_z256_order());
	sm9_z256_rand_range(r0_, sm9_z256_order());
	sm9_z256_rand_range(rho_, sm9_z256_order());

	sm9_swe_commitment_2(&(prf2->c_), &(ct->h), crs, u, r_, r0_, ct->l);
	sm9_swe_commitment_1(&(prf2->C_), u, ct->l, rho_);

	//sm9_z256_hash_swe_prf2(val);
	val[0] = 0x1234;
	val[1] = 0x5678;
	val[2] = 0x90ab;
	val[3] = 0xcdef;

	// mv = u[i] + val * m[i]
	prf2->mv = (sm9_z256_t *) malloc(sizeof(sm9_z256_t) * ct->l);
	for (i = 0; i < ct->l; i++) {
		sm9_z256_set_zero(prf2->mv[i]);
		prf2->mv[i][0] = m[i];
		sm9_z256_modn_mul(prf2->mv[i], prf2->mv[i], val);
		sm9_z256_modn_add(prf2->mv[i], prf2->mv[i], u[i]);
	}
	
	// rv = r_ + val * r
	sm9_z256_modn_mul(prf2->rv, r, val);
	sm9_z256_modn_add(prf2->rv, prf2->rv, r_);

	// r0v = r0_ + val * r0
	sm9_z256_modn_mul(prf2->r0v, r0, val);
	sm9_z256_modn_add(prf2->r0v, prf2->r0v, r0_);

	// rhov = rho_ + val * rho
	sm9_z256_modn_mul(prf2->rhov, rho, val);
	sm9_z256_modn_add(prf2->rhov, prf2->rhov, rho_);
}

int sm9_swe_verify_2(SM9_SWE_PROOF_2 *prf2, const SM9_SWE_CIPHERTEXT *ct,
		const SM9_Z256_TWIST_POINT crs[]) {
	SM9_SWE_COMMITMENT comv;
	sm9_z256_t val;
	int i;

	SM9_Z256_POINT P, Q;
	SM9_Z256_TWIST_POINT R;

	//sm9_z256_hash_swe_prf2(val);
	val[0] = 0x1234;
	val[1] = 0x5678;
	val[2] = 0x90ab;
	val[3] = 0xcdef;
	sm9_swe_commitment_2(&comv, &(ct->h), crs, prf2->mv, prf2->rv, prf2->r0v, ct->l);
	
	// Commitment equality
	sm9_z256_point_mul(&P, val, &(prf2->C));
	sm9_z256_point_add(&P, &P, &(prf2->C_));
	sm9_swe_commitment_1(&Q, prf2->mv, ct->l, prf2->rhov);
	free(prf2->mv); prf2->mv = NULL;

	if (!sm9_z256_point_equ(&P, &Q)) {
		return 0;
	}
	sm9_z256_point_mul(&P, val, &(ct->c));
	sm9_z256_point_add(&P, &P, &(prf2->c_.P));
	if (!sm9_z256_point_equ(&P, &(comv.P))) {
		return 0;
	}

	sm9_z256_point_mul(&P, val, &(ct->c0));
	sm9_z256_point_add(&P, &P, &(prf2->c_.Q));
	if (!sm9_z256_point_equ(&P, &(comv.Q))) {
		return 0;
	}

	sm9_z256_twist_point_copy(&R, &(ct->cs_[0]));
	for (int i = 1; i < ct->l; i++) {
		sm9_z256_twist_point_add_full(&R, &R, &(ct->cs_[i]));
	}
	sm9_z256_twist_point_mul(&R, val, &R);
	sm9_z256_twist_point_add_full(&R, &R, &(prf2->c_.R));
	if (!sm9_z256_twist_point_equ(&R, &(comv.R))) {
		return 0;
	}

	return 1;
}

void sm9_swe_commitment_1(SM9_Z256_POINT *C, const sm9_z256_t p[], uint16_t l, const sm9_z256_t r) {
	SM9_Z256_POINT P;
	int i;
	
	sm9_z256_point_mul_generator(C, r);
	for (int i = 0; i < l; i++) {
		sm9_z256_point_mul(&P, p[i], &CRS[i]);
		sm9_z256_point_add(C, C, &P);
	}
}

void sm9_swe_commitment_2(SM9_SWE_COMMITMENT *com, const SM9_Z256_POINT *H,
		const SM9_Z256_TWIST_POINT crs[], const sm9_z256_t m[],
		const sm9_z256_t r, const sm9_z256_t r0, uint16_t l) {
	SM9_Z256_POINT T;
	SM9_Z256_TWIST_POINT R;
	sm9_z256_t msum;
	int i;
	
	sm9_z256_point_mul_generator(&(com->P), r);

	sm9_z256_point_mul_generator(&(com->Q), r0);
	sm9_z256_point_mul(&T, r, H);
	sm9_z256_point_add(&(com->Q), &(com->Q), &T);

	// com->R = sum(m[i] * G2 + r0 * crs[i])
	// Combine all m[i] && combine all r0*
	sm9_z256_copy(msum, m[0]);
	sm9_z256_twist_point_copy(&R, &crs[0]);
	for (int i = 1; i < l; i++) {
		sm9_z256_modn_add(msum, msum, m[i]);
		sm9_z256_twist_point_add_full(&R, &R, &crs[i]);
	}
	sm9_z256_twist_point_mul(&R, r0, &R);
	sm9_z256_twist_point_mul_generator(&(com->R), msum);
	sm9_z256_twist_point_add_full(&(com->R), &(com->R), &R);
}
