#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <gmssl/sm9.h>

#define SM9_BLS_MAX_MEMBER 8192
#define SM9_BLS_MAX_THRESHOLD SM9_BLS_MAX_MEMBER 
#define SM9_SWE_MAX_MESSAGE 32
#define SM9_SWE_MAX_MESSAGE_VALUE (1<<(256/SM9_SWE_MAX_MESSAGE))

extern const sm9_z256_t SM9_Z256_N;
extern const SM9_Z256_POINT SM9_Z256_MONT_P1;
extern const SM9_Z256_TWIST_POINT SM9_Z256_MONT_P2;

const sm9_z256_fp12_t gt_bstep_8[16];
const sm9_z256_fp12_t gt_gstep_8[16];
const SM9_Z256_TWIST_POINT g2_256[256];
SM9_Z256_POINT CRS[SM9_SWE_MAX_MESSAGE];
SM9_Z256_TWIST_POINT crs[SM9_SWE_MAX_MESSAGE];

typedef struct {
	sm9_z256_t sk;
	SM9_Z256_POINT vk;
} SM9_BLS_KEY;

typedef struct {
	SM9_Z256_POINT h;
	SM9_Z256_POINT c;
	SM9_Z256_POINT c0;
	SM9_Z256_POINT *cs;
	SM9_Z256_TWIST_POINT *cs_;
	uint16_t n; // num of vk (cs)
	uint16_t t; // num of vk threshold
	uint16_t l; // num of message (cs_)
} SM9_SWE_CIPHERTEXT;

typedef struct {
	SM9_Z256_POINT P;
	SM9_Z256_POINT Q;
	SM9_Z256_TWIST_POINT R;
} SM9_SWE_COMMITMENT;

typedef struct {
	SM9_Z256_POINT f;
	SM9_Z256_POINT f_;
	SM9_Z256_POINT c_;
	SM9_Z256_POINT g_;
	sm9_z256_t z;
} SM9_SWE_PROOF_1;

typedef struct {
	SM9_SWE_COMMITMENT c_;
	SM9_Z256_POINT C_;
	SM9_Z256_POINT C;
	sm9_z256_t *mv;
	sm9_z256_t rv;
	sm9_z256_t r0v;
	sm9_z256_t rhov;
} SM9_SWE_PROOF_2;

void sm9_z256_point_copy(SM9_Z256_POINT *P, const SM9_Z256_POINT *Q);
void sm9_z256_twist_point_copy(SM9_Z256_TWIST_POINT *P, const SM9_Z256_TWIST_POINT *Q);
void sm9_z256_twist_point_from_hash(SM9_Z256_TWIST_POINT *P, const sm9_z256_t r);
void sm9_z256_hash_to_twist_point(SM9_Z256_TWIST_POINT *ht, const uint8_t *data, size_t datalen);
void sm9_z256_hash_to_fn(sm9_z256_t ht, const uint8_t *data, size_t datalen);
void sm9_z256_hash_swe_ct(sm9_z256_t r, const SM9_SWE_CIPHERTEXT *ct);
void sm9_z256_hash_swe_prf1(sm9_z256_t r, const SM9_SWE_PROOF_1 *prf1, const SM9_Z256_POINT *c);
void sm9_z256_modn_parity_check_den(sm9_z256_t pck[], const sm9_z256_t zeta[], uint16_t num);
void sm9_z256_modn_lagrange(sm9_z256_t lgr[], const sm9_z256_t zeta[], uint16_t num);
void sm9_z256_modn_batch_inv(sm9_z256_t b[], const sm9_z256_t a[], uint16_t num);
void sm9_z256_miller_loop(sm9_z256_fp12_t r, const SM9_Z256_TWIST_POINT *Q, const SM9_Z256_POINT *P);
uint16_t sm9_z256_discrete_log(const sm9_z256_fp12_t r);

int  sm9_bls_keygen(SM9_BLS_KEY *key);
void sm9_bls_sign(SM9_Z256_TWIST_POINT *sig, const sm9_z256_t sk,
		const uint8_t *data, size_t datalen);
int  sm9_bls_verify(const SM9_Z256_TWIST_POINT *sig, const SM9_Z256_POINT *vk,
		const uint8_t *data, size_t datalen);
void sm9_bls_aggregate(SM9_Z256_TWIST_POINT *aggr_sig, const SM9_Z256_TWIST_POINT sigs[],
		const SM9_Z256_POINT vks[], uint16_t num);
int  sm9_bls_aggregate_verify(const SM9_Z256_TWIST_POINT *aggr_sig, const SM9_Z256_POINT vks[],
		const uint8_t *data, size_t datalen[], uint16_t num);

void sm9_swe_init();
int  sm9_swe_encrypt(SM9_SWE_CIPHERTEXT *ct, const SM9_Z256_POINT vks[], uint16_t n,
		const uint8_t *data, size_t datalen[], uint16_t m[], uint16_t l, uint16_t t);
int sm9_swe_decrypt(uint16_t m[], SM9_SWE_CIPHERTEXT *ct, 
		const SM9_Z256_TWIST_POINT sigs[], const SM9_Z256_POINT vks[],// uint16_t id[],
		uint16_t k, const uint8_t *data, size_t datalen[]);

int sm9_swe_encrypt_and_prove(SM9_SWE_CIPHERTEXT *ct, SM9_SWE_PROOF_1 *prf1,
		SM9_SWE_PROOF_2 *prf2, const SM9_Z256_POINT vks[], uint16_t n,
		const uint8_t *data, size_t datalen[], uint16_t m[], uint16_t l, uint16_t t);
int sm9_swe_prove_1(SM9_SWE_PROOF_1 *prf1, const SM9_SWE_CIPHERTEXT *ct,
		const SM9_Z256_POINT vks[], const sm9_z256_t r);
int sm9_swe_verify_1(const SM9_SWE_PROOF_1 *prf1, const SM9_SWE_CIPHERTEXT *ct);
int sm9_swe_prove_2(SM9_SWE_PROOF_2 *prf2, const SM9_SWE_CIPHERTEXT *ct, const uint16_t m[],
		const sm9_z256_t r, const sm9_z256_t r0, const sm9_z256_t rho, const SM9_Z256_TWIST_POINT crs[]);
int sm9_swe_verify_2(SM9_SWE_PROOF_2 *prf2, const SM9_SWE_CIPHERTEXT *ct,
		const SM9_Z256_TWIST_POINT crs[]);

void sm9_swe_commitment_1(SM9_Z256_POINT *C, const sm9_z256_t p[], uint16_t l, const sm9_z256_t r);
void sm9_swe_commitment_2(SM9_SWE_COMMITMENT *com, const SM9_Z256_POINT *H,
		const SM9_Z256_TWIST_POINT crs[], const sm9_z256_t m[],
		const sm9_z256_t r, const sm9_z256_t r0, uint16_t l);

void sm9_z256_to_file(const sm9_z256_t r, FILE *f);
void sm9_z256_point_to_file(const SM9_Z256_POINT *R, FILE *f);
void sm9_z256_twist_point_to_file(const SM9_Z256_TWIST_POINT *R, FILE *f);
void sm9_z256_from_file(sm9_z256_t r, FILE *f);
void sm9_z256_point_from_file(SM9_Z256_POINT *R, FILE *f);
void sm9_z256_twist_point_from_file(SM9_Z256_TWIST_POINT *R, FILE *f);

void msm_bos_coster_heap(SM9_Z256_POINT *R, const sm9_z256_t a[], const SM9_Z256_POINT P[], int n);
