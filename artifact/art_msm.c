#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm9.h>
#include "art_bls.h"

#define NUM SM9_BLS_MAX_MEMBER

typedef struct {
	sm9_z256_t k;
	SM9_Z256_POINT P;
} sm;

void swap(sm *a, sm *b) {
	sm9_z256_t p;
	sm9_z256_copy(p, b->k);
	sm9_z256_copy(b->k, a->k);
	sm9_z256_copy(a->k, p);
	
	sm9_z256_copy(p, b->P.X);
	sm9_z256_copy(b->P.X, a->P.X);
	sm9_z256_copy(a->P.X, p);
	
	sm9_z256_copy(p, b->P.Y);
	sm9_z256_copy(b->P.Y, a->P.Y);
	sm9_z256_copy(a->P.Y, p);
	
	sm9_z256_copy(p, b->P.Z);
	sm9_z256_copy(b->P.Z, a->P.Z);
	sm9_z256_copy(a->P.Z, p);
}

void down(int p, int len, sm *S) {	
	while(p*2+1 < len && sm9_z256_cmp(S[p].k, S[p*2+1].k) < 0
	   || p*2+2 < len && sm9_z256_cmp(S[p].k, S[p*2+2].k) < 0) {
		if(p*2+2 >= len || sm9_z256_cmp(S[p*2+1].k, S[p*2+2].k) > 0) {
			swap(&S[p], &S[p*2+1]);
			p = p*2+1;
		}
		else {
			swap(&S[p], &S[p*2+2]);
			p = p*2+2;
		}
	}
}

int pop(int len, sm *S) {
	if (len > 2) {
		if (sm9_z256_cmp(S[1].k, S[2].k) > 0) {
			sm9_z256_sub(S[0].k, S[0].k, S[1].k);
			sm9_z256_point_add(&S[1].P, &S[1].P, &S[0].P);
			if (sm9_z256_is_zero(S[0].k)) {
				swap(&S[0], &S[len-1]);
				down(0, len-1, S);
				return len-1;
			}
			else {
				swap(&S[0], &S[1]);
				down(1, len, S);
				return len;
			}
		}
		else {
			sm9_z256_sub(S[0].k, S[0].k, S[2].k);
			sm9_z256_point_add(&S[2].P, &S[2].P, &S[0].P);
			if (sm9_z256_is_zero(S[0].k)) {
				swap(&S[0], &S[len-1]);
				down(0, len-1, S);
				return len-1;
			}
			else {
				swap(&S[0], &S[2]);
				down(2, len, S);
				return len;
			}
		}
	}
	else {
		sm9_z256_sub(S[0].k, S[0].k, S[1].k);
		sm9_z256_point_add(&S[1].P, &S[1].P, &S[0].P);
		if (sm9_z256_is_zero(S[0].k)) {
			swap(&S[0], &S[1]);
			return len-1;
		}
		else if (sm9_z256_cmp(S[0].k, S[1].k) < 0) {
			swap(&S[0], &S[1]);
			return len;
		}
	}
	return 0;
}

void msm_bos_coster_heap(SM9_Z256_POINT *R, const sm9_z256_t a[], const SM9_Z256_POINT P[], int n) {
	sm S[NUM];
	int i, len = n;
	
	for (i = 0; i < n; i++) {
		sm9_z256_copy(S[i].k, a[i]);
		sm9_z256_copy(S[i].P.X, P[i].X);
		sm9_z256_copy(S[i].P.Y, P[i].Y);
		sm9_z256_copy(S[i].P.Z, P[i].Z);
		
		int p = i;
		while(p > 0 && sm9_z256_cmp(S[p].k, S[(p-1)/2].k) >= 0) {
			swap(&S[p], &S[(p-1)/2]);
			p = (p-1)/2;
		}
	}

	while (len > 1) {
		len = pop(len, S);
	}
	sm9_z256_point_mul(R, S[0].k, &(S[0].P));
}
