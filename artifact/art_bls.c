#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <gmssl/sm9.h>
#include "art_bls.h"

const sm9_z256_t SM9_Z256_MODP_MONT_ONE = {0x1a9064d81caeba83, 0xde0d6cb4e5851124, 0x29fc54b00a7138ba, 0x49bffffffd5c590e};

int sm9_z256_fp12_is_mont_one(const sm9_z256_fp12_t r) {
	return sm9_z256_equ(r[0][0][0], SM9_Z256_MODP_MONT_ONE)
		&& sm9_z256_is_zero(r[0][0][1]) && sm9_z256_fp2_is_zero(r[0][1])
		&& sm9_z256_fp4_is_zero(r[1]) && sm9_z256_fp4_is_zero(r[2]);
}

int sm9_bls_keygen(SM9_BLS_KEY *key) {
	sm9_z256_rand_range(key->sk, sm9_z256_order());
	sm9_z256_point_mul_generator(&(key->vk), key->sk);
	return 1;
}

void sm9_bls_sign(SM9_Z256_TWIST_POINT *sig, const sm9_z256_t sk,
		const uint8_t *data, size_t datalen) {
	SM9_Z256_TWIST_POINT ht;
	
	sm9_z256_hash_to_twist_point(&ht, data, datalen);
	sm9_z256_twist_point_mul(sig, sk, &ht);
}

int sm9_bls_verify(const SM9_Z256_TWIST_POINT *sig, const SM9_Z256_POINT *vk,
		const uint8_t *data, size_t datalen) {
	SM9_Z256_TWIST_POINT ht;
	SM9_Z256_POINT P;
	sm9_z256_fp12_t r1, r2;
	
	sm9_z256_hash_to_twist_point(&ht, data, datalen);
	sm9_z256_point_neg(&P, vk);
	
	// save a final expo
	sm9_z256_miller_loop(r1, &ht, &P);
	sm9_z256_miller_loop(r2, sig, &SM9_Z256_MONT_P1);
	sm9_z256_fp12_mul(r1, r1, r2);
	sm9_z256_final_exponent(r1, r1);
	
	return sm9_z256_fp12_is_mont_one(r1);
}

void sm9_bls_aggregate(SM9_Z256_TWIST_POINT *aggr_sig, const SM9_Z256_TWIST_POINT sigs[],
		const SM9_Z256_POINT vks[], uint16_t num) {
	assert (num <= SM9_BLS_MAX_MEMBER);
	
	SM9_Z256_TWIST_POINT T;
	sm9_z256_t zeta[SM9_BLS_MAX_MEMBER], lgr[SM9_BLS_MAX_MEMBER];
	uint8_t buf[65];
	int i;
	
	for (i = 0; i < num; i++) {
		sm9_z256_point_to_uncompressed_octets(&vks[i], buf);
		sm9_z256_hash_to_fn(zeta[i], buf, 65);
	}
	sm9_z256_modn_lagrange(lgr, zeta, num);
	
	sm9_z256_twist_point_mul(aggr_sig, lgr[0], &sigs[0]);
	for (i = 1; i < num; i++) {
		sm9_z256_twist_point_mul(&T, lgr[i], &sigs[i]);
		sm9_z256_twist_point_add_full(aggr_sig, aggr_sig, &T);
	}
}

int sm9_bls_aggregate_verify(const SM9_Z256_TWIST_POINT *aggr_sig, const SM9_Z256_POINT vks[],
		const uint8_t *data, size_t datalen[], uint16_t num) {
	assert (num <= SM9_BLS_MAX_MEMBER);
	
	SM9_Z256_TWIST_POINT ht;
	SM9_Z256_POINT pt;
	sm9_z256_t zeta[SM9_BLS_MAX_MEMBER], lgr[SM9_BLS_MAX_MEMBER];
	uint8_t buf[65];
	sm9_z256_fp12_t r1, r2;
	size_t sum_len = 0;
	int i;
	
	for (i = 0; i < num; i++) {
		sm9_z256_point_to_uncompressed_octets(&vks[i], buf);
		sm9_z256_hash_to_fn(zeta[i], buf, 65);
	}
	sm9_z256_modn_lagrange(lgr, zeta, num);
	
	sm9_z256_fp12_set_one(r1);
	for (i = 0; i < num; i++) {
		sm9_z256_hash_to_twist_point(&ht, data + sum_len, datalen[i]);

		// Speed: fp_pow = 1.7 * ep2_mul = 6.8 * ep1_mul
		//sm9_z256_pairing(r2, &ht, &(vks[i]));
		//sm9_z256_fp12_pow(r2, r2, lgr[i]);
		sm9_z256_point_mul(&pt, lgr[i], &(vks[i]));
		
		// save n final expo
		sm9_z256_miller_loop(r2, &ht, &pt);

		sm9_z256_fp12_mul(r1, r1, r2);
		sum_len += datalen[i];
	}
	sm9_z256_point_neg(&pt, &SM9_Z256_MONT_P1);
	sm9_z256_miller_loop(r2, aggr_sig, &pt);
	sm9_z256_fp12_mul(r1, r1, r2);
	
	sm9_z256_final_exponent(r1, r1);
	
	return sm9_z256_fp12_is_mont_one(r1);
}
