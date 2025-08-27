#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <gmssl/sm9.h>
#include "art_bls.h"

void sm9_z256_to_file(const sm9_z256_t r, FILE *f) {
	char tmp[255] = {};
	sm9_z256_to_hex(r, tmp);
	fputs(tmp, f);
	fputc(10, f);
}

void sm9_z256_point_to_file(const SM9_Z256_POINT *R, FILE *f) {
	sm9_z256_to_file(R->X, f);
	sm9_z256_to_file(R->Y, f);
	sm9_z256_to_file(R->Z, f);
}

void sm9_z256_twist_point_to_file(const SM9_Z256_TWIST_POINT *R, FILE *f) {
	sm9_z256_to_file(R->X[0], f);
	sm9_z256_to_file(R->X[1], f);
	sm9_z256_to_file(R->Y[0], f);
	sm9_z256_to_file(R->Y[1], f);
	sm9_z256_to_file(R->Z[0], f);
	sm9_z256_to_file(R->Z[1], f);
}

void sm9_z256_from_file(sm9_z256_t r, FILE *f) {
	char tmp[255] = {};
	fgets(tmp, 255, f);
	sm9_z256_from_hex(r, tmp);
}

void sm9_z256_point_from_file(SM9_Z256_POINT *R, FILE *f) {
	sm9_z256_from_file(R->X, f);
	sm9_z256_from_file(R->Y, f);
	sm9_z256_from_file(R->Z, f);
}

void sm9_z256_twist_point_from_file(SM9_Z256_TWIST_POINT *R, FILE *f) {
	sm9_z256_from_file(R->X[0], f);
	sm9_z256_from_file(R->X[1], f);
	sm9_z256_from_file(R->Y[0], f);
	sm9_z256_from_file(R->Y[1], f);
	sm9_z256_from_file(R->Z[0], f);
	sm9_z256_from_file(R->Z[1], f);
}