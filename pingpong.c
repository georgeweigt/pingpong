#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>

#define len(p) (p)[-1]

#define Trace printf("file %s, line %d\n", __FILE__, __LINE__);

extern int ec_malloc_count;

struct point {
	uint32_t *x, *y, *z;
};

struct atom {
	struct atom *car;
	struct atom *cdr;
	int length;
	uint8_t *string;
};
uint32_t * ec_modinv(uint32_t *c, uint32_t *p);
void ec_projectify(struct point *S);
void ec_affinify(struct point *S, uint32_t *p);
void ec_double(struct point *R, struct point *S, uint32_t *p);
void ec_add_xyz(struct point *R, struct point *S, struct point *T, uint32_t *p);
void ec_full_add(struct point *R, struct point *S, struct point *T, uint32_t *p);
void ec_full_sub(struct point *R, struct point *S, struct point *T, uint32_t *p);
void ec_mult(struct point *R, uint32_t *d, struct point *S, uint32_t *p);
int ec_get_msbit_index(uint32_t *u);
int ec_get_bit(uint32_t *u, int k);
int ec_F(int t);
void ec_twin_mult(struct point *R, uint32_t *d0, struct point *S, uint32_t *d1, struct point *T, uint32_t *p);
void ec_free_xyz(struct point *u);
uint32_t * ec_add(uint32_t *u, uint32_t *v);
uint32_t * ec_sub(uint32_t *u, uint32_t *v);
uint32_t * ec_mul(uint32_t *u, uint32_t *v);
uint32_t * ec_div(uint32_t *u, uint32_t *v);
void ec_mod(uint32_t *u, uint32_t *v);
uint32_t * ec_pow(uint32_t *u, uint32_t *v);
void ec_shr(uint32_t *u);
int ec_cmp(uint32_t *u, uint32_t *v);
int ec_equal(uint32_t *u, uint32_t v);
uint32_t * ec_int(int k);
uint32_t * ec_new(int n);
void ec_free(uint32_t *u);
uint32_t * ec_dup(uint32_t *u);
void ec_norm(uint32_t *u);
uint32_t * ec_hexstr_to_bignum(char *s);
uint32_t * ec_buf_to_bignum(uint8_t *buf, int len);
void ec_test();
void ec_test_full_add();
void ec_test_full_sub();
void ec_test_double();
void ec_test_mult();
void ec_test_twin_mult();
void test_boot_key(void);
int ecdhe256_verify_hash(uint8_t *hash, int hashlen, uint8_t *rr, int r_length, uint8_t *ss, int s_length, uint8_t *xx, uint8_t *yy);
int ecdsa256_verify_f(uint32_t *h, uint32_t *r, uint32_t *s, uint32_t *x, uint32_t *y);
void ecdsa256_sign_f(uint32_t *h, uint32_t *d, uint8_t *sig);
int ecdhe384_verify_hash(uint8_t *hash, int hashlen, uint8_t *rr, int r_length, uint8_t *ss, int s_length, uint8_t *xx, uint8_t *yy);
int ecdsa384_verify_f(uint32_t *h, uint32_t *r, uint32_t *s, uint32_t *x, uint32_t *y);
void ecdsa384_sign_f(uint32_t *h, uint32_t *d, uint8_t *sig);
void ecdsa_init(void);
uint8_t * theta(uint8_t *A);
uint8_t * rho(uint8_t *A);
uint8_t * pi(uint8_t *A);
uint8_t * chi(uint8_t *A);
uint8_t rc(int t);
uint8_t * iota(uint8_t *A, int ir);
uint8_t * Rnd(uint8_t *A, int ir);
void Keccak(uint8_t *S);
uint8_t * sponge(uint8_t *N, int len);
char * keccak256(uint8_t *buf, int len);
void test_keccak256(void);
int main();
int rlp_encode(uint8_t *outbuf, struct atom *p);
int rlp_encode_list(uint8_t *outbuf, struct atom *p);
int rlp_encode_string(uint8_t *outbuf, struct atom *p);
int rlp_length(struct atom *p, int level);
void rlp_decode(struct atom *p);

int ec_malloc_count;

// returns 1/c mod p

uint32_t *
ec_modinv(uint32_t *c, uint32_t *p)
{
	uint32_t *k, *r, *u, *v, *t, *x1, *x2;
	u = ec_dup(c);
	v = ec_dup(p);
	x1 = ec_int(1);
	x2 = ec_int(0);
	while (!ec_equal(u, 1) && !ec_equal(v, 1)) {
		while ((u[0] & 1) == 0) {
			ec_shr(u);
			if (x1[0] & 1) {
				t = ec_add(x1, p);
				ec_free(x1);
				x1 = t;
			}
			ec_shr(x1);
		}
		while ((v[0] & 1) == 0) {
			ec_shr(v);
			if (x2[0] & 1) {
				t = ec_add(x2, p);
				ec_free(x2);
				x2 = t;
			}
			ec_shr(x2);
		}
		if (ec_cmp(u, v) >= 0) {
			t = ec_sub(u, v);
			ec_free(u);
			u = t;
			// x1 = x1 - x2
			k = ec_sub(p, x2);
			t = ec_add(x1, k);
			ec_free(x1);
			x1 = t;
			ec_mod(x1, p);
			ec_free(k);
		} else {
			t = ec_sub(v, u);
			ec_free(v);
			v = t;
			// x2 = x2 - x1
			k = ec_sub(p, x1);
			t = ec_add(x2, k);
			ec_free(x2);
			x2 = t;
			ec_mod(x2, p);
			ec_free(k);
		}
	}
	if (ec_equal(u, 1)) {
		r = x1;
		ec_free(x2);
	} else {
		r = x2;
		ec_free(x1);
	}
	ec_free(u);
	ec_free(v);
	return r;
}

void
ec_projectify(struct point *S)
{
	ec_free(S->z);
	S->z = ec_int(1);
}

void
ec_affinify(struct point *S, uint32_t *p)
{
	uint32_t *lambda, *lambda2, *lambda3, *x, *y;

	if (ec_equal(S->z, 0)) {
		printf("cannot affinify\n");
		return;
	}

	lambda = ec_modinv(S->z, p);

	lambda2 = ec_mul(lambda, lambda);
	ec_mod(lambda2, p);

	lambda3 = ec_mul(lambda2, lambda);
	ec_mod(lambda3, p);

	x = ec_mul(lambda2, S->x);
	ec_mod(x, p);

	y = ec_mul(lambda3, S->y);
	ec_mod(y, p);

	ec_free_xyz(S);

	S->x = x;
	S->y = y;

	ec_free(lambda);
	ec_free(lambda2);
	ec_free(lambda3);
}

void
ec_double(struct point *R, struct point *S, uint32_t *p)
{
	uint32_t *k, *t, *t1, *t2, *t3, *t4, *t5;

	// take care to handle the case when R and S are the same pointer

	t1 = ec_dup(S->x);
	t2 = ec_dup(S->y);
	t3 = ec_dup(S->z);

	ec_free_xyz(R);

	if (ec_equal(t3, 0)) {
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		ec_free(t1);
		ec_free(t2);
		ec_free(t3);
		return;
	}

	// 7: t4 = t3 * t3

	t4 = ec_mul(t3, t3);
	ec_mod(t4, p);

	// 8: t5 = t1 - t4

	t = ec_sub(p, t4);
	t5 = ec_add(t1, t);
	ec_free(t);
	ec_mod(t5, p);

	// 9: t4 = t1 + t4

	t = ec_add(t1, t4);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 10: t5 = t4 * t5

	t = ec_mul(t4, t5);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 11: t4 = 3 * t5

	k = ec_int(3);
	ec_free(t4);
	t4 = ec_mul(k, t5);
	ec_free(k);
	ec_mod(t4, p);

	// 12: t3 = t3 * t2

	t = ec_mul(t3, t2);
	ec_free(t3);
	t3 = t;
	ec_mod(t3, p);

	// 13: t3 = 2 * t3

	t = ec_add(t3, t3);
	ec_free(t3);
	t3 = t;
	ec_mod(t3, p);

	// 14: t2 = t2 * t2

	t = ec_mul(t2, t2);
	ec_free(t2);
	t2 = t;
	ec_mod(t2, p);

	// 15: t5 = t1 * t2

	t = ec_mul(t1, t2);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 16: t5 = 4 * t5

	k = ec_int(4);
	t = ec_mul(k, t5);
	ec_free(t5);
	t5 = t;
	ec_free(k);
	ec_mod(t5, p);

	// 17: t1 = t4 * t4

	ec_free(t1);
	t1 = ec_mul(t4, t4);
	ec_mod(t1, p);

	// 18: t1 = t1 - 2 * t5

	k = ec_sub(p, t5);
	t = ec_add(t1, k);
	ec_free(t1);
	t1 = ec_add(t, k);
	ec_free(k);
	ec_free(t);
	ec_mod(t1, p);

	// 19: t2 = t2 * t2

	t = ec_mul(t2, t2);
	ec_free(t2);
	t2 = t;
	ec_mod(t2, p);

	// 20: t2 = 8 * t2

	k = ec_int(8);
	t = ec_mul(k, t2);
	ec_free(t2);
	t2 = t;
	ec_free(k);
	ec_mod(t2, p);

	// 21: t5 = t5 - t1

	k = ec_sub(p, t1);
	t = ec_add(t5, k);
	ec_free(t5);
	t5 = t;
	ec_free(k);
	ec_mod(t5, p);

	// 22: t5 = t4 * t5

	t = ec_mul(t4, t5);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 23: t2 = t5 - t2

	t = ec_sub(p, t2);
	ec_free(t2);
	t2 = ec_add(t5, t);
	ec_free(t);
	ec_mod(t2, p);

	R->x = t1;
	R->y = t2;
	R->z = t3;

	ec_free(t4);
	ec_free(t5);
}

void
ec_add_xyz(struct point *R, struct point *S, struct point *T, uint32_t *p)
{
	uint32_t *k, *t, *t1, *t2, *t3, *t4, *t5, *t6, *t7;

	t1 = ec_dup(S->x);
	t2 = ec_dup(S->y);
	t3 = ec_dup(S->z);

	t4 = ec_dup(T->x);
	t5 = ec_dup(T->y);
	t6 = ec_dup(T->z);

	ec_free_xyz(R);

	if (!ec_equal(t6, 1)) {

		// 4: t7 = t6 * t6

		t7 = ec_mul(t6, t6);
		ec_mod(t7, p);

		// 5: t1 = t1 * t7

		t = ec_mul(t1, t7);
		ec_free(t1);
		t1 = t;
		ec_mod(t1, p);

		// 6: t7 = t6 * t7

		t = ec_mul(t6, t7);
		ec_free(t7);
		t7 = t;
		ec_mod(t7, p);

		// 7: t2 = t2 * t7

		t = ec_mul(t2, t7);
		ec_free(t2);
		t2 = t;
		ec_mod(t2, p);

		ec_free(t7);
	}

	// 9: t7 = t3 * t3

	t7 = ec_mul(t3, t3);
	ec_mod(t7, p);

	// 10: t4 = t4 * t7

	t = ec_mul(t4, t7);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 11: t7 = t3 * t7

	t = ec_mul(t3, t7);
	ec_free(t7);
	t7 = t;
	ec_mod(t7, p);

	// 12: t5 = t5 * t7

	t = ec_mul(t5, t7);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 13: t4 = t1 - t4

	t = ec_sub(p, t4);
	ec_free(t4);
	t4 = ec_add(t1, t);
	ec_free(t);
	ec_mod(t4, p);

	// 14: t5 = t2 - t5

	t = ec_sub(p, t5);
	ec_free(t5);
	t5 = ec_add(t2, t);
	ec_free(t);
	ec_mod(t5, p);

	if (ec_equal(t4, 0)) {
		if (ec_equal(t5, 0)) {
			R->x = ec_int(0);
			R->y = ec_int(0);
			R->z = ec_int(0);
		} else {
			R->x = ec_int(1);
			R->y = ec_int(1);
			R->z = ec_int(0);
		}
		ec_free(t1);
		ec_free(t2);
		ec_free(t3);
		ec_free(t4);
		ec_free(t5);
		ec_free(t6);
		ec_free(t7);
		return;
	}

	// 22: t1 = 2 * t1 - t4

	t = ec_add(t1, t1);
	ec_free(t1);
	t1 = t;
	k = ec_sub(p, t4);
	t = ec_add(t1, k);
	ec_free(t1);
	t1 = t;
	ec_free(k);
	ec_mod(t1, p);

	// 23: t2 = 2 * t2 - t5

	t = ec_add(t2, t2);
	ec_free(t2);
	t2 = t;
	k = ec_sub(p, t5);
	t = ec_add(t2, k);
	ec_free(t2);
	t2 = t;
	ec_free(k);
	ec_mod(t2, p);

	if (!ec_equal(t6, 1)) {

		// 25: t3 = t3 * t6

		t = ec_mul(t3, t6);
		ec_free(t3);
		t3 = t;
		ec_mod(t3, p);
	}

	// 27: t3 = t3 * t4

	t = ec_mul(t3, t4);
	ec_free(t3);
	t3 = t;
	ec_mod(t3, p);

	// 28: t7 = t4 * t4

	t = ec_mul(t4, t4);
	ec_free(t7);
	t7 = t;
	ec_mod(t7, p);

	// 29: t4 = t4 * t7

	t = ec_mul(t4, t7);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 30: t7 = t1 * t7

	t = ec_mul(t1, t7);
	ec_free(t7);
	t7 = t;
	ec_mod(t7, p);

	// 31: t1 = t5 * t5

	ec_free(t1);
	t1 = ec_mul(t5, t5);
	ec_mod(t1, p);

	// 32: t1 = t1 - t7

	k = ec_sub(p, t7);
	t = ec_add(t1, k);
	ec_free(t1);
	t1 = t;
	ec_free(k);
	ec_mod(t1, p);

	// 33: t7 = t7 - 2 * t1

	k = ec_sub(p, t1);
	t = ec_add(t7, k);
	ec_free(t7);
	t7 = ec_add(t, k);
	ec_free(k);
	ec_free(t);
	ec_mod(t7, p);

	// 34: t5 = t5 * t7

	t = ec_mul(t5, t7);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 35: t4 = t2 * t4

	t = ec_mul(t2, t4);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 36: t2 = t5 - t4

	t = ec_sub(p, t4);
	ec_free(t2);
	t2 = ec_add(t5, t);
	ec_free(t);
	ec_mod(t2, p);

	// 37: t2 = t2 / 2

	if (t2[0] & 1) {
		t = ec_add(t2, p);
		ec_free(t2);
		t2 = t;
	}
	ec_shr(t2);

	R->x = t1;
	R->y = t2;
	R->z = t3;

	ec_free(t4);
	ec_free(t5);
	ec_free(t6);
	ec_free(t7);
}

void
ec_full_add(struct point *R, struct point *S, struct point *T, uint32_t *p)
{
	uint32_t *x, *y, *z;
	struct point U;

	if (ec_equal(S->z, 0)) {
		x = ec_dup(T->x);
		y = ec_dup(T->y);
		z = ec_dup(T->z);
		ec_free_xyz(R);
		R->x = x;
		R->y = y;
		R->z = z;
		return;
	}

	if (ec_equal(T->z, 0)) {
		x = ec_dup(S->x);
		y = ec_dup(S->y);
		z = ec_dup(S->z);
		ec_free_xyz(R);
		R->x = x;
		R->y = y;
		R->z = z;
		return;
	}

	U.x = NULL;
	U.y = NULL;
	U.z = NULL;

	ec_add_xyz(&U, S, T, p);

	if (ec_equal(U.x, 0) && ec_equal(U.y, 0) && ec_equal(U.z, 0)) {
		ec_free_xyz(&U);
		ec_double(&U, S, p);
	}

	ec_free_xyz(R);

	R->x = U.x;
	R->y = U.y;
	R->z = U.z;
}

void
ec_full_sub(struct point *R, struct point *S, struct point *T, uint32_t *p)
{
	struct point U;

	U.x = ec_dup(T->x);
	U.y = ec_sub(p, T->y);
	U.z = ec_dup(T->z);

	ec_full_add(R, S, &U, p);

	ec_free_xyz(&U);
}

void
ec_mult(struct point *R, uint32_t *d, struct point *S, uint32_t *p)
{
	int h, i, k, l;
	uint32_t *t, *u, *x, *y, *z;
	struct point U;

	if (ec_equal(d, 0)) {
		ec_free_xyz(R);
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		return;
	}

	if (ec_equal(d, 1)) {
		x = ec_dup(S->x);
		y = ec_dup(S->y);
		z = ec_dup(S->z);
		ec_free_xyz(R);
		R->x = x;
		R->y = y;
		R->z = z;
		return;
	}

	if (ec_equal(S->z, 0)) {
		ec_free_xyz(R);
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		return;
	}

	if (!ec_equal(S->z, 1)) {
		ec_affinify(S, p);
		ec_projectify(S);
	}

	x = ec_dup(S->x);
	y = ec_dup(S->y);
	z = ec_dup(S->z);

	ec_free_xyz(R);

	R->x = x;
	R->y = y;
	R->z = z;

	u = ec_int(3);
	t = ec_mul(u, d);
	ec_free(u);

	l = ec_get_msbit_index(t);

	for (i = l - 1; i > 0; i--) {

		U.x = NULL;
		U.y = NULL;
		U.z = NULL;

		ec_double(R, R, p);

		h = ec_get_bit(t, i);
		k = ec_get_bit(d, i);

		if (h == 1 && k == 0)
			ec_full_add(&U, R, S, p);

		if (h == 0 && k == 1)
			ec_full_sub(&U, R, S, p);

		if (h != k) {
			ec_free_xyz(R);
			R->x = U.x;
			R->y = U.y;
			R->z = U.z;
		}
	}

	ec_free(t);
}

int
ec_get_msbit_index(uint32_t *u)
{
	int k, n;
	uint32_t m;
	m = 0x80000000;
	n = len(u);
	k = 32 * n - 1;
	while (m > 1) {
		if (u[n - 1] & m)
			break;
		m >>= 1;
		k--;
	}
	return k;
}

int
ec_get_bit(uint32_t *u, int k)
{
	int j;
	uint32_t m;
	if (k < 0)
		return 0;
	j = k / 32;
	if (j >= len(u))
		return 0;
	m = 1 << (k % 32);
	if (u[j] & m)
		return 1;
	else
		return 0;
}

int
ec_F(int t)
{
	if (18 <= t && t < 22)
		return 9;

	if (14 <= t && t < 18)
		return 10;

	if (22 <= t && t < 24)
		return 11;

	if (4 <= t && t < 12)
		return 14;

	return 12;
}

// R cannot point to S or T

void
ec_twin_mult(struct point *R, uint32_t *d0, struct point *S, uint32_t *d1, struct point *T, uint32_t *p)
{
	int c[2][6], h[2], i, k, m, m0, m1, u[2];
	struct point SpT, SmT;

	if (R == S || R == T) {
		printf("arg error\n");
		return;
	}

	SpT.x = NULL;
	SpT.y = NULL;
	SpT.z = NULL;

	SmT.x = NULL;
	SmT.y = NULL;
	SmT.z = NULL;

	ec_full_add(&SpT, S, T, p);
	ec_full_sub(&SmT, S, T, p);

	m0 = ec_get_msbit_index(d0) + 1;
	m1 = ec_get_msbit_index(d1) + 1;

	if (m0 > m1)
		m = m0;
	else
		m = m1;

	c[0][0] = 0;
	c[0][1] = 0;
	c[0][2] = ec_get_bit(d0, m - 1);
	c[0][3] = ec_get_bit(d0, m - 2);
	c[0][4] = ec_get_bit(d0, m - 3);
	c[0][5] = ec_get_bit(d0, m - 4);

	c[1][0] = 0;
	c[1][1] = 0;
	c[1][2] = ec_get_bit(d1, m - 1);
	c[1][3] = ec_get_bit(d1, m - 2);
	c[1][4] = ec_get_bit(d1, m - 3);
	c[1][5] = ec_get_bit(d1, m - 4);

	R->x = ec_int(1);
	R->y = ec_int(1);
	R->z = ec_int(0);

	for (k = m; k > -1; k--) {

		for (i = 0; i < 2; i++) {
			h[i] = 16 * c[i][1] + 8 * c[i][2] + 4 * c[i][3] + 2 * c[i][4] + c[i][5];
			if (c[i][0] == 1)
				h[i] = 31 - h[i];
		}

		for (i = 0; i < 2; i++) {
			if (h[i] < ec_F(h[1 - i]))
				u[i] = 0;
			else {
				if (c[i][0] & 1)
					u[i] = -1;
				else
					u[i] = 1;
			}
		}

		c[0][0] = abs(u[0]) ^ c[0][1];
		c[0][1] = c[0][2];
		c[0][2] = c[0][3];
		c[0][3] = c[0][4];
		c[0][4] = c[0][5];
		c[0][5] = ec_get_bit(d0, k - 5);

		c[1][0] = abs(u[1]) ^ c[1][1];
		c[1][1] = c[1][2];
		c[1][2] = c[1][3];
		c[1][3] = c[1][4];
		c[1][4] = c[1][5];
		c[1][5] = ec_get_bit(d1, k - 5);

		ec_double(R, R, p);

		if (u[0] == -1 && u[1] == -1)
			ec_full_sub(R, R, &SpT, p);

		if (u[0] == -1 && u[1] == 0)
			ec_full_sub(R, R, S, p);

		if (u[0] == -1 && u[1] == 1)
			ec_full_sub(R, R, &SmT, p);

		if (u[0] == 0 && u[1] == -1)
			ec_full_sub(R, R, T, p);

		if (u[0] == 0 && u[1] == 1)
			ec_full_add(R, R, T, p);

		if (u[0] == 1 && u[1] == -1)
			ec_full_add(R, R, &SmT, p);

		if (u[0] == 1 && u[1] == 0)
			ec_full_add(R, R, S, p);

		if (u[0] == 1 && u[1] == 1)
			ec_full_add(R, R, &SpT, p);
	}

	ec_free_xyz(&SpT);
	ec_free_xyz(&SmT);
}

void
ec_free_xyz(struct point *u)
{
	ec_free(u->x);
	ec_free(u->y);
	ec_free(u->z);
	u->x = NULL;
	u->y = NULL;
	u->z = NULL;
}

// returns u + v

uint32_t *
ec_add(uint32_t *u, uint32_t *v)
{
	int i, nu, nv, nw;
	uint64_t t;
	uint32_t *w;
	nu = len(u);
	nv = len(v);
	if (nu > nv)
		nw = nu + 1;
	else
		nw = nv + 1;
	w = ec_new(nw);
	for (i = 0; i < nu; i++)
		w[i] = u[i];
	for (i = nu; i < nw; i++)
		w[i] = 0;
	t = 0;
	for (i = 0; i < nv; i++) {
		t += (uint64_t) w[i] + v[i];
		w[i] = t;
		t >>= 32;
	}
	for (i = nv; i < nw; i++) {
		t += w[i];
		w[i] = t;
		t >>= 32;
	}
	ec_norm(w);
	return w;
}

// returns u - v

uint32_t *
ec_sub(uint32_t *u, uint32_t *v)
{
	int i, nu, nv, nw;
	uint64_t t;
	uint32_t *w;
	nu = len(u);
	nv = len(v);
	if (nu > nv)
		nw = nu;
	else
		nw = nv;
	w = ec_new(nw);
	for (i = 0; i < nu; i++)
		w[i] = u[i];
	for (i = nu; i < nw; i++)
		w[i] = 0;
	t = 0;
	for (i = 0; i < nv; i++) {
		t += (uint64_t) w[i] - v[i];
		w[i] = t;
		t = (int64_t) t >> 32; // cast to extend sign
	}
	for (i = nv; i < nw; i++) {
		t += w[i];
		w[i] = t;
		t = (int64_t) t >> 32; // cast to extend sign
	}
	ec_norm(w);
	return w;
}

// returns u * v

uint32_t *
ec_mul(uint32_t *u, uint32_t *v)
{
	int i, j, nu, nv, nw;
	uint64_t t;
	uint32_t *w;
	nu = len(u);
	nv = len(v);
	nw = nu + nv;
	w = ec_new(nw);
	for (i = 0; i < nu; i++)
		w[i] = 0;
	for (j = 0; j < nv; j++) {
		t = 0;
		for (i = 0; i < nu; i++) {
			t += (uint64_t) u[i] * v[j] + w[i + j];
			w[i + j] = t;
			t >>= 32;
		}
		w[i + j] = t;
	}
	ec_norm(w);
	return w;
}

// returns floor(u / v)

uint32_t *
ec_div(uint32_t *u, uint32_t *v)
{
	int i, k, nu, nv;
	uint32_t *q, qhat, *w;
	uint64_t a, b, t;
	ec_norm(u);
	ec_norm(v);
	if (len(v) == 1 && v[0] == 0)
		return NULL; // v = 0
	nu = len(u);
	nv = len(v);
	k = nu - nv;
	if (k < 0) {
		q = ec_new(1);
		q[0] = 0;
		return q; // u < v, return zero
	}
	u = ec_dup(u);
	q = ec_new(k + 1);
	w = ec_new(nv + 1);
	b = v[nv - 1];
	do {
		q[k] = 0;
		while (nu >= nv + k) {
			// estimate 32-bit partial quotient
			a = u[nu - 1];
			if (nu > nv + k)
				a = a << 32 | u[nu - 2];
			if (a < b)
				break;
			qhat = a / (b + 1);
			if (qhat == 0)
				qhat = 1;
			// w = qhat * v
			t = 0;
			for (i = 0; i < nv; i++) {
				t += (uint64_t) qhat * v[i];
				w[i] = t;
				t >>= 32;
			}
			w[nv] = t;
			// u = u - w
			t = 0;
			for (i = k; i < nu; i++) {
				t += (uint64_t) u[i] - w[i - k];
				u[i] = t;
				t = (int64_t) t >> 32; // cast to extend sign
			}
			if (t) {
				// u is negative, restore u
				t = 0;
				for (i = k; i < nu; i++) {
					t += (uint64_t) u[i] + w[i - k];
					u[i] = t;
					t >>= 32;
				}
				break;
			}
			q[k] += qhat;
			ec_norm(u);
			nu = len(u);
		}
	} while (--k >= 0);
	ec_norm(q);
	ec_free(u);
	ec_free(w);
	return q;
}

// u = u mod v

void
ec_mod(uint32_t *u, uint32_t *v)
{
	int i, k, nu, nv;
	uint32_t qhat, *w;
	uint64_t a, b, t;
	ec_norm(u);
	ec_norm(v);
	if (len(v) == 1 && v[0] == 0)
		return; // v = 0
	nu = len(u);
	nv = len(v);
	k = nu - nv;
	if (k < 0)
		return; // u < v
	w = ec_new(nv + 1);
	b = v[nv - 1];
	do {
		while (nu >= nv + k) {
			// estimate 32-bit partial quotient
			a = u[nu - 1];
			if (nu > nv + k)
				a = a << 32 | u[nu - 2];
			if (a < b)
				break;
			qhat = a / (b + 1);
			if (qhat == 0)
				qhat = 1;
			// w = qhat * v
			t = 0;
			for (i = 0; i < nv; i++) {
				t += (uint64_t) qhat * v[i];
				w[i] = t;
				t >>= 32;
			}
			w[nv] = t;
			// u = u - w
			t = 0;
			for (i = k; i < nu; i++) {
				t += (uint64_t) u[i] - w[i - k];
				u[i] = t;
				t = (int64_t) t >> 32; // cast to extend sign
			}
			if (t) {
				// u is negative, restore u
				t = 0;
				for (i = k; i < nu; i++) {
					t += (uint64_t) u[i] + w[i - k];
					u[i] = t;
					t >>= 32;
				}
				break;
			}
			ec_norm(u);
			nu = len(u);
		}
	} while (--k >= 0);
	ec_free(w);
}

// returns u ** v

uint32_t *
ec_pow(uint32_t *u, uint32_t *v)
{
	uint32_t *t, *w;
	u = ec_dup(u);
	v = ec_dup(v);
	// w = 1
	w = ec_new(1);
	w[0] = 1;
	for (;;) {
		if (v[0] & 1) {
			// w = w * u
			t = ec_mul(w, u);
			ec_free(w);
			w = t;
		}
		// v = v >> 1
		ec_shr(v);
		// v = 0?
		if (len(v) == 1 && v[0] == 0)
			break;
		// u = u * u
		t = ec_mul(u, u);
		ec_free(u);
		u = t;
	}
	ec_free(u);
	ec_free(v);
	return w;
}

// u = u >> 1

void
ec_shr(uint32_t *u)
{
	int i;
	for (i = 0; i < len(u) - 1; i++) {
		u[i] >>= 1;
		if (u[i + 1] & 1)
			u[i] |= 0x80000000;
	}
	u[i] >>= 1;
	ec_norm(u);
}

// compare u and v

int
ec_cmp(uint32_t *u, uint32_t *v)
{
	int i;
	ec_norm(u);
	ec_norm(v);
	if (len(u) < len(v))
		return -1;
	if (len(u) > len(v))
		return 1;
	for (i = len(u) - 1; i >= 0; i--) {
		if (u[i] < v[i])
			return -1;
		if (u[i] > v[i])
			return 1;
	}
	return 0; // u = v
}

int
ec_equal(uint32_t *u, uint32_t v)
{
	if (len(u) == 1 && u[0] == v)
		return 1;
	else
		return 0;
}

uint32_t *
ec_int(int k)
{
	uint32_t *u;
	u = ec_new(1);
	u[0] = k;
	return u;
}

uint32_t *
ec_new(int n)
{
	uint32_t *u;
	u = (uint32_t *) malloc((n + 1) * sizeof (uint32_t));
	if (u == NULL) {
		printf("malloc error\n");
		exit(1);
	}
	ec_malloc_count++;
	u[0] = n;
	return u + 1;
}

void
ec_free(uint32_t *u)
{
	if (u) {
		free(u - 1);
		ec_malloc_count--;
	}
}

uint32_t *
ec_dup(uint32_t *u)
{
	int i;
	uint32_t *v;
	v = ec_new(len(u));
	for (i = 0; i < len(u); i++)
		v[i] = u[i];
	return v;
}

// remove leading zeroes

void
ec_norm(uint32_t *u)
{
	while (len(u) > 1 && u[len(u) - 1] == 0)
		len(u)--;
}

uint32_t *
ec_hexstr_to_bignum(char *s)
{
	int d, i, len, n;
	uint32_t *u;
	len = strlen(s);
	n = (len + 7) / 8; // convert len to number of uint32_t ints
	u = ec_new(n);
	for (i = 0; i < n; i++)
		u[i] = 0;
	for (i = 0; i < len; i++) {
		d = s[len - i - 1];
		if ('0' <= d && d <= '9')
			d -= '0';
		else if ('A' <= d && d <= 'F')
			d -= 'A' - 10;
		else if ('a' <= d && d <= 'f')
			d -= 'a' - 10;
		else {
			ec_free(u);
			return NULL;
		}
		u[i / 8] |= d << (4 * (i % 8));
	}
	ec_norm(u);
	return u;
}

uint32_t *
ec_buf_to_bignum(uint8_t *buf, int len)
{
	int i, n, t;
	uint32_t *u;
	n = (len + 3) / 4;
	u = ec_new(n);
	t = 0;
	for (i = 0; i < len; i++) {
		t = t << 8 | buf[i];
		if ((len - i - 1) % 4 == 0) {
			u[--n] = t;
			t = 0;
		}
	}
	ec_norm(u);
	return u;
}

void
ec_test()
{
	ec_test_full_add();
	ec_test_full_sub();
	ec_test_double();
	ec_test_mult();
	ec_test_twin_mult();
}

void
ec_test_full_add()
{
	uint32_t *p, *x, *y;
	struct point R, S, T;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_xt =
		"aacc05202e7fda6fc73d82f0a66220527da8117ee8f8330e"
		"ad7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051";

	char *str_yt =
		"84009a263fefba7c2c57cffa5db3634d286131afc0fca8d2"
		"5afa22a7b5dce0d9470da89233cee178592f49b6fecb5092";

	char *str_xr =
		"12dc5ce7acdfc5844d939f40b4df012e68f865b89c3213ba"
		"97090a247a2fc009075cf471cd2e85c489979b65ee0b5eed";

	char *str_yr =
		"167312e58fe0c0afa248f2854e3cddcb557f983b3189b67f"
		"21eee01341e7e9fe67f6ee81b36988efa406945c8804a4b0";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	T.x = ec_hexstr_to_bignum(str_xt);
	T.y = ec_hexstr_to_bignum(str_yt);
	T.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	ec_full_add(&R, &S, &T, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ec_full_add ok\n");
	else
		printf("ec_full_add fail\n");

	ec_free(p);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
	ec_free_xyz(&T);
}

void
ec_test_full_sub()
{
	uint32_t *p, *x, *y;
	struct point R, S, T;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_xt =
		"aacc05202e7fda6fc73d82f0a66220527da8117ee8f8330e"
		"ad7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051";

	char *str_yt =
		"84009a263fefba7c2c57cffa5db3634d286131afc0fca8d2"
		"5afa22a7b5dce0d9470da89233cee178592f49b6fecb5092";

	char *str_xr =
		"6afdaf8da8b11c984cf177e551cee542cda4ac2f25cd522d"
		"0cd710f88059c6565aef78f6b5ed6cc05a6666def2a2fb59";

	char *str_yr =
		"7bed0e158ae8cc70e847a60347ca1548c348decc6309f48b"
		"59bd5afc9a9b804e7f7876178cb5a7eb4f6940a9c73e8e5e";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	T.x = ec_hexstr_to_bignum(str_xt);
	T.y = ec_hexstr_to_bignum(str_yt);
	T.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	ec_full_sub(&R, &S, &T, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ec_full_sub ok\n");
	else
		printf("ec_full_sub fail\n");

	ec_free(p);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
	ec_free_xyz(&T);
}

void
ec_test_double()
{
	uint32_t *p, *x, *y;
	struct point R, S;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_xr =
		"2a2111b1e0aa8b2fc5a1975516bc4d58017ff96b25e1bdff"
		"3c229d5fac3bacc319dcbec29f9478f42dee597b4641504c";

	char *str_yr =
		"fa2e3d9dc84db8954ce8085ef28d7184fddfd1344b4d4797"
		"343af9b5f9d837520b450f726443e4114bd4e5bdb2f65ddd";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	ec_double(&R, &S, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ec_double ok\n");
	else
		printf("ec_double fail\n");

	ec_free(p);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
}

void
ec_test_mult()
{
	uint32_t *d, *p, *x, *y;
	struct point R, S;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_d =
		"a4ebcae5a665983493ab3e626085a24c104311a761b5a8fd"
		"ac052ed1f111a5c44f76f45659d2d111a61b5fdd97583480";

	char *str_xr =
		"e4f77e7ffeb7f0958910e3a680d677a477191df166160ff7"
		"ef6bb5261f791aa7b45e3e653d151b95dad3d93ca0290ef2";

	char *str_yr =
		"ac7dee41d8c5f4a7d5836960a773cfc1376289d3373f8cf7"
		"417b0c6207ac32e913856612fc9ff2e357eb2ee05cf9667f";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	d = ec_hexstr_to_bignum(str_d);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	ec_mult(&R, d, &S, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ec_mult ok\n");
	else
		printf("ec_mult fail\n");

	ec_free(p);
	ec_free(d);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
}

void
ec_test_twin_mult()
{
	uint32_t *d, *e, *p, *x, *y;
	struct point R, S, T;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_xt =
		"aacc05202e7fda6fc73d82f0a66220527da8117ee8f8330e"
		"ad7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051";

	char *str_yt =
		"84009a263fefba7c2c57cffa5db3634d286131afc0fca8d2"
		"5afa22a7b5dce0d9470da89233cee178592f49b6fecb5092";

	char *str_d =
		"a4ebcae5a665983493ab3e626085a24c104311a761b5a8fd"
		"ac052ed1f111a5c44f76f45659d2d111a61b5fdd97583480";

	char *str_e =
		"afcf88119a3a76c87acbd6008e1349b29f4ba9aa0e12ce89"
		"bcfcae2180b38d81ab8cf15095301a182afbc6893e75385d";

	char *str_xr =
		"917ea28bcd641741ae5d18c2f1bd917ba68d34f0f0577387"
		"dc81260462aea60e2417b8bdc5d954fc729d211db23a02dc";

	char *str_yr =
		"1a29f7ce6d074654d77b40888c73e92546c8f16a5ff6bcbd"
		"307f758d4aee684beff26f6742f597e2585c86da908f7186";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	T.x = ec_hexstr_to_bignum(str_xt);
	T.y = ec_hexstr_to_bignum(str_yt);
	T.z = ec_int(1);

	d = ec_hexstr_to_bignum(str_d);
	e = ec_hexstr_to_bignum(str_e);

	ec_twin_mult(&R, d, &S, e, &T, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ec_twin_mult ok\n");
	else
		printf("ec_twin_mult fail\n");

	ec_free(p);
	ec_free(d);
	ec_free(e);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
	ec_free_xyz(&T);
}

// secp256k1

#define P "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"

// Sepolia boot node geth

#define X "9246d00bc8fd1742e5ad2428b80fc4dc45d786283e05ef6edbd9002cbc335d40"
#define Y "998444732fbe921cb88e1d2c73d1b1de53bae6a2237996e9bfe14f871baf7066"

void
test_boot_key(void)
{
	uint32_t *n3, *n7, *x, *x3, *y, *y2, *p, *r;

	ec_test();
	printf("ec_malloc_count %d\n", ec_malloc_count); // should be zero (no memory leaks)

	p = ec_hexstr_to_bignum(P);
	x = ec_hexstr_to_bignum(X);
	y = ec_hexstr_to_bignum(Y);

	// y^2 mod p == (x^3 + 7) mod p

	y2 = ec_mul(y, y);
	ec_mod(y2, p);

	n3 = ec_int(3);
	x3 = ec_pow(x, n3);
	n7 = ec_int(7);
	r = ec_add(x3, n7);
	ec_mod(r, p);

	if (ec_cmp(y2, r) == 0)
		printf("ok\n");
	else
		printf("fail\n");
}

uint32_t *p256, *q256, *gx256, *gy256;
uint32_t *p384, *q384, *gx384, *gy384;

// returns 0 for ok, -1 otherwise

int
ecdhe256_verify_hash(uint8_t *hash, int hashlen, uint8_t *rr, int r_length, uint8_t *ss, int s_length, uint8_t *xx, uint8_t *yy)
{
	int err;
	uint32_t *h, *r, *s, *x, *y;

	if (hashlen > 32)
		hashlen = 32;

	h = ec_buf_to_bignum(hash, hashlen);

	r = ec_buf_to_bignum(rr, r_length);
	s = ec_buf_to_bignum(ss, s_length);

	x = ec_buf_to_bignum(xx, 32);
	y = ec_buf_to_bignum(yy, 32);

	err = ecdsa256_verify_f(h, r, s, x, y);

	ec_free(h);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);

	return err;
}

// Returns 0 for ok, -1 otherwise
//
// All arguments are bignums
//
//	h	hash of certificate
//
//	r, s	signature
//
//	x, y	public key

int
ecdsa256_verify_f(uint32_t *h, uint32_t *r, uint32_t *s, uint32_t *x, uint32_t *y)
{
	int err;
	uint32_t *u, *v, *w;
	struct point R, S, T;

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	S.x = gx256;
	S.y = gy256;
	S.z = ec_int(1);

	T.x = x;
	T.y = y;
	T.z = ec_int(1);

	w = ec_modinv(s, q256);

	u = ec_mul(h, w);
	ec_mod(u, q256);

	v = ec_mul(r, w);
	ec_mod(v, q256);

	ec_twin_mult(&R, u, &S, v, &T, p256);

	ec_affinify(&R, p256);

	ec_mod(R.x, q256);

	if (ec_cmp(R.x, r) == 0)
		err = 0;
	else
		err = -1;

	ec_free_xyz(&R);

	ec_free(S.z);
	ec_free(T.z);
	ec_free(u);
	ec_free(v);
	ec_free(w);

	return err;
}

//	h	hash of certificate
//
//	d	private key
//
//	sig	pointer to 64-byte buffer

void
ecdsa256_sign_f(uint32_t *h, uint32_t *d, uint8_t *sig)
{
	int i;
	uint32_t *k, *r, *s, *t;
	struct point G, R;

	G.x = gx256;
	G.y = gy256;
	G.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	for (;;) {

		// choose k from [1, n - 1]

		k = ec_new(8);
		for (i = 0; i < 8; i++)
			k[i] = random();
		ec_norm(k);
		ec_mod(k, q256);
		if (ec_equal(k, 0)) {
			ec_free(k);
			continue;
		}

		// R = k * G

		ec_mult(&R, k, &G, p256);
		ec_affinify(&R, p256);

		// r = R.x mod n

		r = ec_dup(R.x);
		ec_mod(r, q256);

		if (ec_equal(r, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free_xyz(&R);
			continue;
		}

		// k = 1 / k

		t = ec_modinv(k, q256);
		ec_free(k);
		k = t;

		// s = k * (h + r * d) mod n

		s = ec_mul(r, d);
		ec_mod(s, q256);

		t = ec_add(h, s);
		ec_free(s);
		s = t;
		ec_mod(s, q256);

		t = ec_mul(k, s);
		ec_free(s);
		s = t;
		ec_mod(s, q256);

		if (ec_equal(s, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free(s);
			ec_free_xyz(&R);
			continue;
		}

		break;
	}

	// the signature is the pair (r, s)

	bzero(sig, 64);

	for (i = 0; i < len(r); i++) {
		sig[32 - 4 * i - 4] = r[i] >> 24;
		sig[32 - 4 * i - 3] = r[i] >> 16;
		sig[32 - 4 * i - 2] = r[i] >> 8;
		sig[32 - 4 * i - 1] = r[i];
	}

	for (i = 0; i < len(s); i++) {
		sig[64 - 4 * i - 4] = s[i] >> 24;
		sig[64 - 4 * i - 3] = s[i] >> 16;
		sig[64 - 4 * i - 2] = s[i] >> 8;
		sig[64 - 4 * i - 1] = s[i];
	}

	ec_free(k);
	ec_free(r);
	ec_free(s);

	ec_free(G.z);

	ec_free_xyz(&R);
}

// returns 0 for ok, -1 otherwise

int
ecdhe384_verify_hash(uint8_t *hash, int hashlen, uint8_t *rr, int r_length, uint8_t *ss, int s_length, uint8_t *xx, uint8_t *yy)
{
	int err;
	uint32_t *h, *r, *s, *x, *y;

	if (hashlen > 48)
		hashlen = 48;

	h = ec_buf_to_bignum(hash, hashlen);

	r = ec_buf_to_bignum(rr, r_length);
	s = ec_buf_to_bignum(ss, s_length);

	x = ec_buf_to_bignum(xx, 48);
	y = ec_buf_to_bignum(yy, 48);

	err = ecdsa384_verify_f(h, r, s, x, y);

	ec_free(h);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);

	return err;
}

// Returns 0 for ok, -1 otherwise
//
// All arguments are bignums
//
//	h	hash of certificate
//
//	r, s	signature
//
//	x, y	public key

int
ecdsa384_verify_f(uint32_t *h, uint32_t *r, uint32_t *s, uint32_t *x, uint32_t *y)
{
	int err;
	uint32_t *u, *v, *w;
	struct point R, S, T;

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	S.x = gx384;
	S.y = gy384;
	S.z = ec_int(1);

	T.x = x;
	T.y = y;
	T.z = ec_int(1);

	w = ec_modinv(s, q384);

	u = ec_mul(h, w);
	ec_mod(u, q384);

	v = ec_mul(r, w);
	ec_mod(v, q384);

	ec_twin_mult(&R, u, &S, v, &T, p384);

	ec_affinify(&R, p384);

	ec_mod(R.x, q384);

	if (ec_cmp(R.x, r) == 0)
		err = 0;
	else
		err = -1;

	ec_free_xyz(&R);

	ec_free(S.z);
	ec_free(T.z);
	ec_free(u);
	ec_free(v);
	ec_free(w);

	return err;
}

//	h	hash of certificate
//
//	d	private key
//
//	sig	pointer to 96-byte buffer

void
ecdsa384_sign_f(uint32_t *h, uint32_t *d, uint8_t *sig)
{
	int i;
	uint32_t *k, *r, *s, *t;
	struct point G, R;

	G.x = gx384;
	G.y = gy384;
	G.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	for (;;) {

		// choose k from [1, n - 1]

		k = ec_new(12);
		for (i = 0; i < 12; i++)
			k[i] = random();
		ec_norm(k);
		ec_mod(k, q384);
		if (ec_equal(k, 0)) {
			ec_free(k);
			continue;
		}

		// R = k * G

		ec_mult(&R, k, &G, p384);
		ec_affinify(&R, p384);

		// r = R.x mod n

		r = ec_dup(R.x);
		ec_mod(r, q384);

		if (ec_equal(r, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free_xyz(&R);
			continue;
		}

		// k = 1 / k

		t = ec_modinv(k, q384);
		ec_free(k);
		k = t;

		// s = k * (h + r * d) mod n

		s = ec_mul(r, d);
		ec_mod(s, q384);

		t = ec_add(h, s);
		ec_free(s);
		s = t;
		ec_mod(s, q384);

		t = ec_mul(k, s);
		ec_free(s);
		s = t;
		ec_mod(s, q384);

		if (ec_equal(s, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free(s);
			ec_free_xyz(&R);
			continue;
		}

		break;
	}

	// the signature is the pair (r, s)

	bzero(sig, 96);

	for (i = 0; i < len(r); i++) {
		sig[48 - 4 * i - 4] = r[i] >> 24;
		sig[48 - 4 * i - 3] = r[i] >> 16;
		sig[48 - 4 * i - 2] = r[i] >> 8;
		sig[48 - 4 * i - 1] = r[i];
	}

	for (i = 0; i < len(s); i++) {
		sig[96 - 4 * i - 4] = s[i] >> 24;
		sig[96 - 4 * i - 3] = s[i] >> 16;
		sig[96 - 4 * i - 2] = s[i] >> 8;
		sig[96 - 4 * i - 1] = s[i];
	}

	ec_free(k);
	ec_free(r);
	ec_free(s);

	ec_free(G.z);

	ec_free_xyz(&R);
}

#if 0
static char *str_p256 =
	"ffffffff00000001000000000000000000000000ffffffff"
	"ffffffffffffffff";

static char *str_q256 =
	"ffffffff00000000ffffffffffffffffbce6faada7179e84"
	"f3b9cac2fc632551";

static char *str_gx256 =
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0"
	"f4a13945d898c296";

static char *str_gy256 =
	"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ece"
	"cbb6406837bf51f5";

static char *str_p384 =
	"ffffffffffffffffffffffffffffffffffffffffffffffff"
	"fffffffffffffffeffffffff0000000000000000ffffffff";

static char *str_q384 =
	"ffffffffffffffffffffffffffffffffffffffffffffffff"
	"c7634d81f4372ddf581a0db248b0a77aecec196accc52973";

static char *str_gx384 =
	"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98"
	"59f741e082542a385502f25dbf55296c3a545e3872760ab7";

static char *str_gy384 =
	"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147c"
	"e9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
#endif

// secp256k1

#define P "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
#define Q "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define GX "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#define GY "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

void
ecdsa_init(void)
{
	p256 = ec_hexstr_to_bignum(P);
	q256 = ec_hexstr_to_bignum(Q);
	gx256 = ec_hexstr_to_bignum(GX);
	gy256 = ec_hexstr_to_bignum(GY);
}

// Keccak-256 (see Table 3 on page 22 of FIPS PUB 202)
//
// Rate      r = 1088 bits (136 bytes)
// 
// Capacity  c =  512 bits ( 64 bytes)

#define RATE 136

#define A(x,y,z) A[320 * (x) + 64 * (y) + (z)]
#define Aprime(x,y,z) Aprime[320 * (x) + 64 * (y) + (z)]

uint8_t RC[64][24] = {
	{1,0,0,0,1,1,1,1,0,0,1,0,1,1,1,1,0,0,0,0,1,0,1,0},
	{0,1,1,0,1,0,0,0,1,0,0,1,1,1,0,1,1,0,1,1,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,1,0,1,0,0,1,1,1,1,1,1,1,1,0,0,0,1,1,0,0,0,1},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,1,1,0,1,0,1,0,1,1,0,0,1,1,1,0,0,1,0,0,1,1,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,1,1,1,1,0,1,1,0,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,1,0,1,1,0,0,0,1,1,1,0,0,0,0,0,0,1,1,0,1,1},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,1,1,0,0,1,1,0,0,0,0,0,1,1,1,1,1,0,1,1,1,0,1},
};

uint8_t *
theta(uint8_t *A)
{
	int x, y, z;
	static uint8_t Aprime[1600], C[5][64], D[5][64];

	for (x = 0; x < 5; x++)
		for (z = 0; z < 64; z++)
			C[x][z] = A(x,0,z) ^ A(x,1,z) ^ A(x,2,z) ^ A(x,3,z) ^ A(x,4,z);

	for (x = 0; x < 5; x++)
		for (z = 0; z < 64; z++)
			D[x][z] = C[(5 + x - 1) % 5][z] ^ C[(x + 1) % 5][(64 + z - 1) % 64];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				Aprime(x,y,z) = A(x,y,z) ^ D[x][z];

	return Aprime;
}

uint8_t *
rho(uint8_t *A)
{
	int t, u, x, y, z;
	static uint8_t Aprime[1600];

	for (z = 0; z < 64; z++)
		Aprime(0,0,z) = A(0,0,z);

	x = 1;
	y = 0;

	for (t = 0; t < 24; t++) {
		for (z = 0; z < 64; z++)
			Aprime(x,y,z) = A(x,y,(320 + z - (t + 1) * (t + 2) / 2) % 64);
		u = y;
		y = (2 * x + 3 * y) % 5;
		x = u;
	}

	return Aprime;
}

uint8_t *
pi(uint8_t *A)
{
	int x, y, z;
	static uint8_t Aprime[1600];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				Aprime(x,y,z) = A((x + 3 * y) % 5,x,z);

	return Aprime;
}

uint8_t *
chi(uint8_t *A)
{
	int x, y, z;
	static uint8_t Aprime[1600];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				Aprime(x,y,z) = A(x,y,z) ^ ((A((x + 1) % 5,y,z) ^ 1) & A((x + 2) % 5,y,z));

	return Aprime;
}

uint8_t
rc(int t)
{
	int i, R;

	if (t % 255 == 0)
		return 1;

	R = 1;

	for (i = 1; i <= t % 255; i++) {
		R <<= 1;
		if (R & 0x100)
			R ^= 0x171;
	}

	return R & 1;
}

uint8_t *
iota(uint8_t *A, int ir)
{
	int z;

	for (z = 0; z < 64; z++)
		A(0,0,z) ^= RC[z][ir];

	return A;
}

uint8_t *
Rnd(uint8_t *A, int ir)
{
	return iota(chi(pi(rho(theta(A)))), ir);
}

uint8_t mask[8] = {1,2,4,8,0x10,0x20,0x40,0x80};

void
Keccak(uint8_t *S)
{
	int ir, k, x, y, z;
	static uint8_t a[1600], *A = a;

	// convert S to A

	memset(A, 0, 1600);

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++) {
				k = 64 * (5 * y + x) + z;
				if (S[k / 8] & mask[k % 8])
					A(x,y,z) = 1;
			}

	for (ir = 0; ir < 24; ir++)
		A = Rnd(A, ir);

	// convert A to S

	memset(S, 0, 200);

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				if (A(x,y,z)) {
					k = 64 * (5 * y + x) + z;
					S[k / 8] |= mask[k % 8];
				}
}

uint8_t *
sponge(uint8_t *N, int len)
{
	int i, j, k, n;
	static uint8_t S[200]; // 1600 bits

	memset(S, 0, 200);

	n = len / RATE; // number of full blocks

	for (i = 0; i < n; i++) {
		for (j = 0; j < RATE; j++)
			S[j] ^= N[RATE * i + j];
		Keccak(S);
	}

	// pad last block

	k = len % RATE;

	for (i = 0; i < k; i++)
		S[i] ^= N[RATE * n + i];

	S[k] ^= 0x01;
	S[RATE - 1] ^= 0x80;

	Keccak(S);

	return S;
}

char *
keccak256(uint8_t *buf, int len)
{
	int i;
	uint8_t *S;
	static char Z[65];

	S = sponge(buf, len);

	for (i = 0; i < 32; i++)
		sprintf(Z + 2 * i, "%02x", S[i]);

	return Z;
}

void
test_keccak256(void)
{
	int err;
	char *Z;
	static uint8_t buf[RATE + 1];

	printf("Testing keccak256\n");

	memset(buf, 'a', sizeof buf);

	Z = keccak256(NULL, 0);
	err = strcmp(Z, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
	printf("%s %s\n", Z, err ? "err" : "ok");

	Z = keccak256((uint8_t *) "hello", 5);
	err = strcmp(Z, "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8");
	printf("%s %s\n", Z, err ? "err" : "ok");

	Z = keccak256(buf, RATE - 1);
	err = strcmp(Z, "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446");
	printf("%s %s\n", Z, err ? "err" : "ok");

	Z = keccak256(buf, RATE);
	err = strcmp(Z, "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e");
	printf("%s %s\n", Z, err ? "err" : "ok");

	Z = keccak256(buf, RATE + 1);
	err = strcmp(Z, "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39");
	printf("%s %s\n", Z, err ? "err" : "ok");
}

#define TIMEOUT 1000 // poll timeout in milliseconds

// Sepolia boot node geth
// see https://github.com/ethereum/go-ethereum/blob/master/params/bootnodes.go

#define DST_IP "127.0.0.1" // loopback for now instead of "18.168.182.86"
#define DST_PORT 30303
#define SRC_PORT 30303

#define X "9246d00bc8fd1742e5ad2428b80fc4dc45d786283e05ef6edbd9002cbc335d40"
#define Y "998444732fbe921cb88e1d2c73d1b1de53bae6a2237996e9bfe14f871baf7066"

// secp256k1

#define P "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
#define Q "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define GX "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#define GY "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

uint32_t *bignum_x;
uint32_t *bignum_y;
uint32_t *bignum_p;
uint32_t *bignum_q;
uint32_t *bignum_gx;
uint32_t *bignum_gy;

char buf[1000];

int
main()
{
	int err, fd, len, n;
	struct sockaddr_in addr;
	struct pollfd pollfd;
	socklen_t addrlen;

	bignum_x = ec_hexstr_to_bignum(X);
	bignum_y = ec_hexstr_to_bignum(Y);
	bignum_p = ec_hexstr_to_bignum(P);
	bignum_q = ec_hexstr_to_bignum(Q);
	bignum_gx = ec_hexstr_to_bignum(GX);
	bignum_gy = ec_hexstr_to_bignum(GY);

	// get socket

	fd = socket(PF_INET, SOCK_DGRAM, 0);

	if (fd < 0) {
		perror("socket");
		exit(1);
	}

	// set src port

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(SRC_PORT);

	err = bind(fd, (struct sockaddr *) &addr, sizeof addr);

	if (err) {
		perror("bind");
		exit(1);
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(DST_IP);
	addr.sin_port = htons(DST_PORT);

	strcpy(buf, "hello");
	len = strlen(buf);

	n = sendto(fd, buf, len, 0, (struct sockaddr *) &addr, sizeof addr);

	if (n < 0) {
		perror("sendto");
		exit(1);
	}

	if (n < len) {
		printf("sendto?\n");
		exit(1);
	}

	pollfd.fd = fd;
	pollfd.events = POLLIN;

	n = poll(&pollfd, 1, TIMEOUT);

	if (n < 0) {
		perror("poll");
		exit(1);
	}

	if (n < 1 || (pollfd.revents & POLLIN) == 0) {
		printf("pollfd?\n");
		exit(1);
	}

	addrlen = sizeof addr;

	n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *) &addr, &addrlen);

	if (n < 0) {
		perror("recvfrom");
		exit(1);
	}

	buf[n] = '\0';

	printf("%s\n", buf);
}

int
rlp_encode(uint8_t *outbuf, struct atom *p)
{
	if (p->car)
		return rlp_encode_list(outbuf, p);
	else
		return rlp_encode_string(outbuf, p);
}

int
rlp_encode_list(uint8_t *outbuf, struct atom *p)
{
	int h, len;
	uint8_t *t;

	len = rlp_length(p, 0); // raw length (no header)

	if (len > 65535)
		h = 4;
	else if (len > 255)
		h = 3;
	else if (len > 55)
		h = 2;
	else
		h = 1;

	t = outbuf;

	outbuf += h;

	while (p) {
		outbuf += rlp_encode(outbuf, p->car);
		p = p->cdr;
	}

	outbuf = t;

	switch (h) {
	case 1:
		outbuf[0] = 0xc0 + len;
		break;
	case 2:
		outbuf[0] = 0xf7 + 1;
		outbuf[1] = len;
		break;
	case 3:
		outbuf[0] = 0xf7 + 2;
		outbuf[1] = len >> 8;
		outbuf[2] = len;
		break;
	case 4:
		outbuf[0] = 0xf7 + 3;
		outbuf[1] = len >> 16;
		outbuf[2] = len >> 8;
		outbuf[3] = len;
		break;
	}

	return h + len;
}

int
rlp_encode_string(uint8_t *outbuf, struct atom *p)
{
	int h, len;

	len = p->length;

	if (len == 1) {
		outbuf[0] = p->string[0];
		return 1;
	}

	if (len > 65535)
		h = 4;
	else if (len > 255)
		h = 3;
	else if (len > 55)
		h = 2;
	else
		h = 1;

	memcpy(outbuf + h, p->string, len);

	switch (h) {
	case 1:
		outbuf[0] = 0x80 + len;
		break;
	case 2:
		outbuf[0] = 0xb7 + 1;
		outbuf[1] = len;
		break;
	case 3:
		outbuf[0] = 0xb7 + 2;
		outbuf[1] = len >> 8;
		outbuf[2] = len;
		break;
	case 4:
		outbuf[0] = 0xb7 + 3;
		outbuf[1] = len >> 16;
		outbuf[2] = len >> 8;
		outbuf[3] = len;
		break;
	}

	return h + len;
}

// level == 0 returns raw length (no header)

int
rlp_length(struct atom *p, int level)
{
	int h, len;

	if (p->car) {

		len = 0;

		while (p) {
			len += rlp_length(p->car, 1);
			p = p->cdr;
		}

	} else {

		len = p->length;

		if (len == 1)
			return 1;
	}

	if (level == 0)
		return len;

	if (len > 65535)
		h = 4;
	else if (len > 255)
		h = 3;
	else if (len > 55)
		h = 2;
	else
		h = 1;

	return h + len;
}

void
rlp_decode(struct atom *p)
{
}
