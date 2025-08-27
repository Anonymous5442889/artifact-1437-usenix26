#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <sys/time.h>
#include <gmssl/sm9.h>
#include "art_bls.h"

void sm9_swe_init() {
	sm9_z256_t r;
	int i;
	
	for (i = 0; i < SM9_SWE_MAX_MESSAGE; i++) {
		sm9_z256_rand_range(r, sm9_z256_order());
		sm9_z256_point_mul_generator(&CRS[i], r);
	}
}

int sm9_swe_encrypt(SM9_SWE_CIPHERTEXT *ct, const SM9_Z256_POINT vks[], uint16_t n,
		const uint8_t *data, size_t datalen[], uint16_t m[], uint16_t l, uint16_t t) {
	assert (l <= SM9_SWE_MAX_MESSAGE);
	assert (n <= SM9_BLS_MAX_MEMBER);
	assert (t <= n);
	
	ct->n = n;
	ct->t = t;
	ct->l = l;
	
	sm9_z256_t r, rs[SM9_BLS_MAX_THRESHOLD]; // t
	sm9_z256_t zeta[SM9_BLS_MAX_MEMBER], s[SM9_BLS_MAX_MEMBER], pow, val; // n
	int i, j;
	size_t sum_len = 0;
	uint8_t buf[65];
	
	SM9_Z256_POINT P;
	SM9_Z256_TWIST_POINT ht;
	
	for (i = 0; i < l; i++) {
		if (m[i] >= SM9_SWE_MAX_MESSAGE_VALUE) {
			printf("Message must less than SM9_SWE_MAX_MESSAGE_VALUE\n");
			return -1;
		}
	}
	
	sm9_z256_rand_range(r, sm9_z256_order());

	for (i = 0; i < t; i++) {
		sm9_z256_rand_range(rs[i], sm9_z256_order());
	}

	for (i = 0; i < n; i++) {
		sm9_z256_point_to_uncompressed_octets(&vks[i], buf);
		sm9_z256_hash_to_fn(zeta[i], buf, 65);

		// s[i] = sum(rs[j] * zeta[i]^j), for j in [t]
		sm9_z256_set_one(pow);
		sm9_z256_set_zero(s[i]);
		for (j = 0; j < t; j++) {
			sm9_z256_modn_mul(val, rs[j], pow);
			sm9_z256_modn_add(s[i], s[i], val);
			sm9_z256_modn_mul(pow, pow, zeta[i]);
		}
	}
	
	// c = r * G1
	sm9_z256_point_mul_generator(&(ct->c), r);
	
	// h = rand G1 point
	sm9_z256_rand_range(val, sm9_z256_order());
	sm9_z256_point_mul_generator(&(ct->h), val);
	
	// c0 = r * h + r0 * G1
	sm9_z256_point_mul_generator(&(ct->c0), rs[0]);
	sm9_z256_point_mul(&P, r, &(ct->h));
	sm9_z256_point_add(&(ct->c0), &(ct->c0), &P);
	
	// cs[j] = r * vks[j] + s[j] * G1, for j in [n]
	ct->cs = (SM9_Z256_POINT *) malloc(sizeof(SM9_Z256_POINT) * n);
	for (j = 0; j < n; j++) {
		sm9_z256_point_mul_generator(&(ct->cs[j]), s[j]);
		sm9_z256_point_mul(&P, r, &(vks[j]));
		sm9_z256_point_add(&(ct->cs[j]), &(ct->cs[j]), &P);
	}
	
	// cs_[i] = rs[0] * H(T[i]) + m[i] * G2, for i in range[l]
	ct->cs_ = (SM9_Z256_TWIST_POINT *) malloc(sizeof(SM9_Z256_TWIST_POINT) * l);
	for (i = 0; i < l; i++) {
		sm9_z256_twist_point_copy(&(ct->cs_[i]), &(g2_256[m[i]])); // table
	
		sm9_z256_hash_to_twist_point(&ht, data + sum_len, datalen[i]);
		sum_len += datalen[i];
		
		sm9_z256_twist_point_mul(&ht, rs[0], &ht);
		sm9_z256_twist_point_add_full(&(ct->cs_[i]), &(ct->cs_[i]), &ht);
	}
	
	return 1;
}

// vks = U and id[] is their index in [n]
// default id = 0 ~ k-1 of V
int sm9_swe_decrypt(uint16_t m[], SM9_SWE_CIPHERTEXT *ct, 
		const SM9_Z256_TWIST_POINT sigs[], const SM9_Z256_POINT vks[],// uint16_t id[],
		uint16_t k, const uint8_t *data, size_t datalen[]) {
	assert (k <= ct->n && k >= ct->t);
	
	sm9_z256_t zeta[SM9_BLS_MAX_MEMBER], lgr[SM9_BLS_MAX_MEMBER]; // k
	sm9_z256_fp12_t z[SM9_SWE_MAX_MESSAGE], r; // l
	int i;
	size_t sum_len = 0;
	uint8_t buf[65];
	
	SM9_Z256_POINT cstar, Q;
	SM9_Z256_TWIST_POINT ht;

	for (i = 0; i < k; i++) {
		sm9_z256_point_to_uncompressed_octets(&(vks[i]), buf);
		sm9_z256_hash_to_fn(zeta[i], buf, 65);
	}
	sm9_z256_modn_lagrange(lgr, zeta, k);

	// cstar = sum(lgr[i] * cs[i]), for i in id
	// Faster MSM
	if (k > 50) {
		msm_bos_coster_heap(&cstar, lgr, ct->cs, k);
	} else {
		//assert (id[0] < ct->n);
		//sm9_z256_point_mul(&cstar, lgr[0], &(ct->cs[id[0]]));
		sm9_z256_point_mul(&cstar, lgr[0], &(ct->cs[0]));
		for (i = 1; i < k; i++) {
			//assert (id[i] < ct->n);
			//sm9_z256_point_mul(&Q, lgr[i], &(ct->cs[id[i]]));
			sm9_z256_point_mul(&Q, lgr[i], &(ct->cs[i]));
			sm9_z256_point_add(&cstar, &cstar, &Q);
		}
	}
	sm9_z256_point_neg(&cstar, &cstar); // instead of an fp12_inv
	
	// z[i] = e(cs_[i], G1) * e(sig[i], c) * e(H(T[i]), cstar)
	for (i = 0; i < ct->l; i++) {
		//sm9_z256_pairing(z[i], &(ct->cs_[i]), &SM9_Z256_MONT_P1);
		sm9_z256_miller_loop(z[i], &(ct->cs_[i]), &SM9_Z256_MONT_P1);

		//sm9_z256_pairing(r, &(sigs[i]), &(ct->c));
		sm9_z256_miller_loop(r, &(sigs[i]), &(ct->c));
		sm9_z256_fp12_mul(z[i], z[i], r);
		
		sm9_z256_hash_to_twist_point(&ht, data + sum_len, datalen[i]);
		sum_len += datalen[i];
		//sm9_z256_pairing(r, &ht, &cstar);
		sm9_z256_miller_loop(r, &ht, &cstar);
		sm9_z256_fp12_mul(z[i], z[i], r);
		
		sm9_z256_final_exponent(z[i], z[i]);
	}
	
	// m[i] = dlog(z[i], GT)
	for (i = 0; i < ct->l; i++) {
		m[i] = sm9_z256_discrete_log(z[i]);
		if (m[i] == 65535) {
			printf("Decrypt message %d failed\n", i);
		}
	}
	free(ct->cs); ct->cs = NULL;
	free(ct->cs_); ct->cs_ = NULL;

	return 1;
}

int sm9_swe_encrypt_and_prove(SM9_SWE_CIPHERTEXT *ct, SM9_SWE_PROOF_1 *prf1,
		SM9_SWE_PROOF_2 *prf2, const SM9_Z256_POINT vks[], uint16_t n,
		const uint8_t *data, size_t datalen[], uint16_t m[], uint16_t l, uint16_t t) {
	assert (l <= SM9_SWE_MAX_MESSAGE);
	assert (n <= SM9_BLS_MAX_MEMBER);
	assert (t <= n);

	ct->n = n;
	ct->t = t;
	ct->l = l;
	
	sm9_z256_t r, rs[SM9_BLS_MAX_THRESHOLD]; // t
	sm9_z256_t s[SM9_BLS_MAX_MEMBER], pow, val; // n
	sm9_z256_t v[SM9_BLS_MAX_MEMBER + 1], w[SM9_BLS_MAX_MEMBER + 1], zeta[SM9_BLS_MAX_MEMBER + 1]; // n+1
	int i, j, k = n + 1 - t;
	size_t sum_len = 0;
	uint8_t out[32], buf[65];
	
	SM9_Z256_POINT P;
	SM9_Z256_TWIST_POINT HT;
	
	for (i = 0; i < l; i++) {
		if (m[i] >= SM9_SWE_MAX_MESSAGE_VALUE) {
			printf("Message must less than SM9_SWE_MAX_MESSAGE_VALUE\n");
			return -1;
		}
	}

	sm9_z256_rand_range(r, sm9_z256_order());

	for (i = 0; i < t; i++) {
		sm9_z256_rand_range(rs[i], sm9_z256_order());
	}

	sm9_z256_set_zero(zeta[0]);
	for (i = 0; i < n; i++) {
		sm9_z256_point_to_uncompressed_octets(&vks[i], buf);
		sm9_z256_hash_to_fn(zeta[i + 1], buf, 65);

		// s[i] = sum(rs[j] * zeta[i+1]^j), for j in [t]
		sm9_z256_set_one(pow);
		sm9_z256_set_zero(s[i]);
		for (j = 0; j < t; j++) {
			sm9_z256_modn_mul(val, rs[j], pow);
			sm9_z256_modn_add(s[i], s[i], val);
			sm9_z256_modn_mul(pow, pow, zeta[i + 1]);
		}
	}
	
	// c = r * G1
	sm9_z256_point_mul_generator(&(ct->c), r);
	
	// h = rand G1 point
	sm9_z256_rand_range(val, sm9_z256_order());
	sm9_z256_point_mul_generator(&(ct->h), val);
	
	// c0 = r * h + r0 * G1
	sm9_z256_point_mul_generator(&(ct->c0), rs[0]);
	sm9_z256_point_mul(&P, r, &(ct->h));
	sm9_z256_point_add(&(ct->c0), &(ct->c0), &P);
	
	// cs[j] = r * vks[j] + s[j] * G1, for j in [n]
	ct->cs = (SM9_Z256_POINT *) malloc(sizeof(SM9_Z256_POINT) * n);
	for (j = 0; j < n; j++) {
		sm9_z256_point_mul_generator(&(ct->cs[j]), s[j]);
		sm9_z256_point_mul(&P, r, &(vks[j]));
		sm9_z256_point_add(&(ct->cs[j]), &(ct->cs[j]), &P);
	}
	
	// cs_[i] = rs[0] * H(T[i]) + m[i] * G2, for i in range[l]
	ct->cs_ = (SM9_Z256_TWIST_POINT *) malloc(sizeof(SM9_Z256_TWIST_POINT) * l);
	for (i = 0; i < l; i++) {
		sm9_z256_twist_point_copy(&(ct->cs_[i]), &(g2_256[m[i]])); // table
	
		sm9_z256_hash_to_twist_point(&crs[i], data + sum_len, datalen[i]);
		sum_len += datalen[i];
		
		sm9_z256_twist_point_mul(&HT, rs[0], &crs[i]);
		sm9_z256_twist_point_add_full(&(ct->cs_[i]), &(ct->cs_[i]), &HT);
	}

	// Prove 1
	sm9_z256_hash_swe_ct(v[0], ct);
	for (i = 1; i < k; i++) {
		sm9_z256_to_bytes(v[i-1], out);
		sm9_z256_hash_to_fn(v[i], out, 32);
	}
	
	for (i = 0; i <= n; i++) {
		sm9_z256_set_one(pow);
		sm9_z256_set_zero(w[i]);
		for (j = 0; j < k; j++) {
			sm9_z256_modn_mul(val, v[j], pow);
			sm9_z256_modn_add(w[i], w[i], val);
			sm9_z256_modn_mul(pow, pow, zeta[i]);
		}
	}
	sm9_z256_modn_parity_check_den(v, zeta, n + 1);
	for (i = 0; i <= n; i++) {
		sm9_z256_modn_mul(w[i], w[i], v[i]);
	}
	
	if (n > 50) {
		sm9_z256_point_mul(&(prf1->c_), w[0], &(ct->c0));
		msm_bos_coster_heap(&P, w + 1, ct->cs, n);
		sm9_z256_point_add(&(prf1->c_), &(prf1->c_), &P);

		sm9_z256_point_mul(&(prf1->g_), w[0], &(ct->h));
		msm_bos_coster_heap(&P, w + 1, vks, n);
		sm9_z256_point_add(&(prf1->g_), &(prf1->g_), &P);
	} else {
		sm9_z256_point_mul(&(prf1->c_), w[0], &(ct->c0));
		for (i = 1; i <= n; i++) {
			sm9_z256_point_mul(&P, w[i], &(ct->cs[i-1]));
			sm9_z256_point_add(&(prf1->c_), &(prf1->c_), &P);
		}
		
		sm9_z256_point_mul(&(prf1->g_), w[0], &(ct->h));
		for (i = 1; i <= n; i++) {
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

	// Prove 2
	sm9_z256_t rho, r_, r0_, rho_;
	sm9_z256_t m256[SM9_SWE_MAX_MESSAGE], u[SM9_SWE_MAX_MESSAGE]; // l

	for (i = 0; i < l; i++) {
		sm9_z256_set_zero(m256[i]);
		m256[i][0] = m[i];
	}

	sm9_z256_rand_range(rho, sm9_z256_order());
	sm9_swe_commitment_1(&(prf2->C), m256, l, rho);

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
		sm9_z256_modn_mul(prf2->mv[i], m256[i], val);
		sm9_z256_modn_add(prf2->mv[i], prf2->mv[i], u[i]);
	}
	
	// rv = r_ + val * r
	sm9_z256_modn_mul(prf2->rv, r, val);
	sm9_z256_modn_add(prf2->rv, prf2->rv, r_);

	// r0v = r0_ + val * r0
	sm9_z256_modn_mul(prf2->r0v, rs[0], val);
	sm9_z256_modn_add(prf2->r0v, prf2->r0v, r0_);

	// rhov = rho_ + val * rho
	sm9_z256_modn_mul(prf2->rhov, rho, val);
	sm9_z256_modn_add(prf2->rhov, prf2->rhov, rho_);

	return 1;
}
