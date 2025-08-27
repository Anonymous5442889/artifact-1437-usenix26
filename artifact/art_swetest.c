#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <gmssl/sm9.h>
#include "art_bls.h"

#define TOTAL_MEMBER SM9_BLS_MAX_MEMBER
#define THRESHOLD_MEMBER (TOTAL_MEMBER*2/3)
#define SIGN_MEMBER TOTAL_MEMBER

const sm9_z256_t z256_max = {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};

int test_bls() {
	SM9_BLS_KEY key;
	SM9_Z256_TWIST_POINT sig;
	sm9_z256_t k;
	uint8_t data[32];

	sm9_bls_keygen(&key);
	sm9_z256_rand_range(k, z256_max);
	sm9_z256_to_bytes(k, data);
	
	sm9_bls_sign(&sig, key.sk, data, 32);

	if (!sm9_bls_verify(&sig, &(key.vk), data, 32)) {
		printf("%s test failed\n", __FUNCTION__);
		return -1;
	}
	
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int test_bls_aggregate() {
	SM9_BLS_KEY key[TOTAL_MEMBER];
	SM9_Z256_TWIST_POINT sigs[TOTAL_MEMBER], aggr_sig;
	SM9_Z256_POINT vks[TOTAL_MEMBER];
	sm9_z256_t k;
	uint8_t data[32 * TOTAL_MEMBER];
	size_t datalen[TOTAL_MEMBER];
	int i;

	for (i = 0; i < TOTAL_MEMBER; i++) {
		sm9_bls_keygen(&(key[i]));
		sm9_z256_point_copy(&(vks[i]), &(key[i].vk));
		sm9_z256_rand_range(k, z256_max);
		sm9_z256_to_bytes(k, data + 32 * i);
		datalen[i] = 32;
		sm9_bls_sign(&(sigs[i]), key[i].sk, data + 32 * i, 32);
	}

	sm9_bls_aggregate(&aggr_sig, sigs, vks, TOTAL_MEMBER);

	if (!sm9_bls_aggregate_verify(&aggr_sig, vks, data, datalen, TOTAL_MEMBER)) {
		printf("%s test failed\n", __FUNCTION__);
		return -1;
	}
	
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}


#define STR(x) #x
#define STR2(x) STR(x)

#define filename "../data/data_2_3_" STR2(SM9_BLS_MAX_MEMBER) ".txt"

void create_file() {
	SM9_BLS_KEY key[TOTAL_MEMBER];
	SM9_Z256_TWIST_POINT aggr_sigs[SM9_SWE_MAX_MESSAGE], sigs[SIGN_MEMBER];
	SM9_Z256_POINT vks[TOTAL_MEMBER];
	sm9_z256_t k;
	uint8_t data[32];
	int i, j;

	// vks, data, aggr_sigs
	FILE *f = fopen(filename, "w+");
	if (f) {
		for (i = 0; i < SM9_BLS_MAX_MEMBER; i++) {
			sm9_bls_keygen(&(key[i]));
			sm9_z256_point_copy(&(vks[i]), &(key[i].vk));
			sm9_z256_point_to_file(&(key[i].vk), f);
		}
		for (j = 0; j < SM9_SWE_MAX_MESSAGE; j++) {
			sm9_z256_rand_range(k, z256_max);
			sm9_z256_to_file(k, f);
			sm9_z256_to_bytes(k, data);
			for (i = 0; i < SIGN_MEMBER; i++) {
				sm9_bls_sign(&(sigs[i]), key[i].sk, data, 32);
			}
			sm9_bls_aggregate(&aggr_sigs[j], sigs, vks, SIGN_MEMBER);
			sm9_z256_twist_point_to_file(&(aggr_sigs[j]), f);
		}
		fclose(f);
	}
}

int test_swe() {
	struct timeval start, end;
	long timeuse;

	SM9_SWE_CIPHERTEXT ct;
	SM9_Z256_TWIST_POINT aggr_sigs[SM9_SWE_MAX_MESSAGE];
	SM9_Z256_POINT vks[TOTAL_MEMBER];
	sm9_z256_t secret, k;
	uint16_t m[SM9_SWE_MAX_MESSAGE], v[SM9_SWE_MAX_MESSAGE];
	uint8_t data[32 * SM9_SWE_MAX_MESSAGE];
	size_t datalen[SM9_SWE_MAX_MESSAGE];
	SM9_SWE_PROOF_1 prf1;
	SM9_SWE_PROOF_2 prf2;
	int i, j;

	sm9_z256_rand_range(secret, z256_max);
	sm9_z256_to_bytes(secret, data);
	for (i = 0; i < SM9_SWE_MAX_MESSAGE; i++) {
		m[i] = (uint16_t)(data[i]);
	}

	FILE *f = fopen(filename, "r");
	if (f == NULL) {
		create_file();
		f = fopen(filename, "r");
	}
	
	for (i = 0; i < TOTAL_MEMBER; i++) {
		// sm9_bls_keygen(&(key[i]));
		// sm9_z256_point_copy(&(vks[i]), &(key[i].vk));
		sm9_z256_point_from_file(&(vks[i]), f);
	}

	gettimeofday(&start, NULL);
	for (j = 0; j < SM9_SWE_MAX_MESSAGE; j++) {
		//sm9_z256_rand_range(k, z256_max);
		sm9_z256_from_file(k, f);
		sm9_z256_to_bytes(k, data + 32 * j);
		datalen[j] = 32;
		// for (i = 0; i < SIGN_MEMBER; i++) {
		// 	sm9_bls_sign(&(sigs[i]), key[i].sk, data + 32 * j, 32);
		// }
		// sm9_bls_aggregate(&aggr_sigs[j], sigs, vks, SIGN_MEMBER);
		sm9_z256_twist_point_from_file(&aggr_sigs[j], f);
	}
	fclose(f);

	sm9_swe_init();
	gettimeofday(&end, NULL);
	timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
	printf("sm9_swe_init time = %f\n", timeuse / 1000000.0);
	
	gettimeofday(&start, NULL);
	/*if (sm9_swe_encrypt(&ct, vks, TOTAL_MEMBER, data, datalen, m, SM9_SWE_MAX_MESSAGE, THRESHOLD_MEMBER) != 1) {
		printf("%s test encrypt failed\n", __FUNCTION__);
		return -1;
	}*/
	if (sm9_swe_encrypt_and_prove(&ct, &prf1, &prf2, vks, TOTAL_MEMBER, data, datalen, m, SM9_SWE_MAX_MESSAGE, THRESHOLD_MEMBER) != 1) {
		printf("%s test encrypt and prove failed\n", __FUNCTION__);
		return -1;
	}
	gettimeofday(&end, NULL);
	timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
	printf("sm9_swe_encrypt and prove time = %f\n", timeuse / 1000000.0);

	gettimeofday(&start, NULL);
	if (sm9_swe_verify_1(&prf1, &ct) != 1) {
		printf("%s test verify 1 failed\n", __FUNCTION__);
		return -1;
	}
	if (sm9_swe_verify_2(&prf2, &ct, crs) != 1) {
		printf("%s test verify 2 failed\n", __FUNCTION__);
		return -1;
	}
	gettimeofday(&end, NULL);
	timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
	printf("sm9_swe_verify time = %f\n", timeuse / 1000000.0);

	//uint16_t id[SIGN_MEMBER];
	//for (i = 0; i < SIGN_MEMBER; i++) {
	//	id[i] = i;
	//}
	gettimeofday(&start, NULL);
	sm9_swe_decrypt(v, &ct, aggr_sigs, vks, SIGN_MEMBER, data, datalen);
	gettimeofday(&end, NULL);
	timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
	printf("sm9_swe_decrypt time = %f\n", timeuse / 1000000.0);

	for (j = 0; j < SM9_SWE_MAX_MESSAGE; j++) {
		if (v[j] != m[j]) {
			printf("%s test decrypt failed at position %d: %d != %d\n", __FUNCTION__, j, v[j], m[j]);
			return -1;
		}
	}
	
	printf("%s() ok\n", __FUNCTION__);
	return 1;
}

int main(void) {
	//if (test_bls() != 1) goto err;
	//if (test_bls_aggregate() != 1) goto err;
	if (test_swe() != 1) goto err;
	printf("%s all tests passed\n", __FILE__);
	return 0;
err:
	return -1;
}
