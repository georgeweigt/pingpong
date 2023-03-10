// See 'Mathematical routines for the NIST prime elliptic curves'

// Returns (1 / a) mod p

uint32_t *
ec_modinv(uint32_t *a, uint32_t *p)
{
	return ec_modinv_v1(a, p);
}

uint32_t *
ec_modinv_v1(uint32_t *a, uint32_t *p)
{
	uint32_t *k, *r, *u, *v, *t, *x1, *x2;
	u = ec_dup(a);
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

// Ref. Anton Iliev, Nikolay Kyurkchiev, Asen Rahnev paper

uint32_t *
ec_modinv_v2(uint32_t *a, uint32_t *p)
{
	int i;
	uint32_t *q, *r, *u1, *u3, *v1, *v3, *t, *t1, *t3;

	u1 = ec_int(1);
	u3 = ec_dup(a);
	v1 = ec_int(0);
	v3 = ec_dup(p);

	q = NULL;
	t = NULL;
	t1 = NULL;
	t3 = NULL;

	i = 1;

	while (!ec_equal(v3, 0)) {

		// q = u3 / v3

		ec_free(q);
		q = ec_div(u3, v3);

		// t3 = u3 % v3

		ec_free(t3);
		t3 = ec_dup(u3);
		ec_mod(t3, v3);

		// t1 = u1 + q * v1;

		ec_free(t);
		t = ec_mul(q, v1);
		ec_free(t1);
		t1 = ec_add(u1, t);

		// u1 = v1

		// v1 = t1

		ec_free(u1);
		u1 = v1;
		v1 = t1;
		t1 = NULL;

		// u3 = v3

		// v3 = t3

		ec_free(u3);
		u3 = v3;
		v3 = t3;
		t3 = NULL;

		i = -i;
	}

	if (!ec_equal(u3, 1))
		r = ec_int(0);
	else if (i < 0)
		r = ec_sub(p, u1);
	else {
		r = u1;
		u1 = NULL;
	}

	ec_free(q);
	ec_free(u1);
	ec_free(u3);
	ec_free(v1);
	ec_free(v3);
	ec_free(t);
	ec_free(t1);
	ec_free(t3);

	return r;
}

// Ref. M. Brown, D. Hankerson, J. Lopez, A. Menezes paper

// (not working)

uint32_t *
ec_modinv_v3(uint32_t *a, uint32_t *p)
{
	uint32_t *t, *u, *v, *A, *C;

	u = ec_dup(a);
	v = ec_dup(p);

	A = ec_int(1);
	C = ec_int(0);

	while (!ec_equal(u, 0)) {

		// while u is even

		while ((u[0] & 1) == 0) {
			// u = u / 2
			ec_shr(u);
			// if A is odd then A = A + p
			if (A[0] & 1) {
				t = ec_add(A, p);
				ec_free(A);
				A = t;
			}
			// A = A / 2
			ec_shr(A);
		}

		// while v is even

		while ((v[0] & 1) == 0) {
			// v = v / 2
			ec_shr(v);
			// if C is odd then C = C + p
			if (C[0] & 1) {
				t = ec_add(C, p);
				ec_free(C);
				C = t;
			}
			// C = C / 2
			ec_shr(C);
		}

		if (ec_cmp(u, v) >= 0) {
			// u = u - v
			t = ec_sub(u, v);
			ec_free(u);
			u = t;
			// A = A - C
			t = ec_sub(A, C);
			ec_free(A);
			A = t;
		} else {
			// v = v - u
			t = ec_sub(v, u);
			ec_free(v);
			v = t;
			// C = C - A
			t = ec_sub(C, A);
			ec_free(C);
			C = t;
		}
	}

	ec_mod(C, p);

	ec_free(u);
	ec_free(v);
	ec_free(A);

	return C;
}

void
ec_projectify(struct point *S)
{
	ec_free(S->z);
	S->z = ec_int(1);
}

int
ec_affinify(struct point *S, uint32_t *p)
{
	uint32_t *lambda, *lambda2, *lambda3, *x, *y;

	if (ec_equal(S->z, 0)) {
		trace();
		return -1;
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

	return 0;
}

void
ec_double(struct point *R, struct point *S, uint32_t *p)
{
	if (ec_equal(a256, 0))
		ec_double_v2k1(R, S, p);
	else
		ec_double_v2r1(R, S, p, a256);
}

// Ref. Shay Gueron, Vlad Krasnov paper

void
ec_double_v2k1(struct point *R, struct point *S, uint32_t *p)
{
	uint32_t *x, *y, *z;
	uint32_t *xp, *yp, *zp;
	uint32_t *c2, *c3, *c4, *c8, *m, *s, *t, *u, *v, *x2, *y2, *y4;

	x = S->x;
	y = S->y;
	z = S->z;

	c2 = ec_int(2);
	c3 = ec_int(3);
	c4 = ec_int(4);
	c8 = ec_int(8);

	// s == 4 x y^2

	y2 = ec_mul(y, y);
	ec_mod(y2, p);

	t = ec_mul(x, y2);
	s = ec_mul(c4, t);
	ec_free(t);
	ec_mod(s, p);

	// m = 3 x^2 + a Z^4, a = 0 for secp256k1

	x2 = ec_mul(x, x);
	m = ec_mul(c3, x2);
	ec_mod(m, p);

	// x' = m^2 - 2 s

	u = ec_mul(m, m);
	ec_mod(u, p);

	v = ec_mul(c2, s);
	ec_mod(v, p);

	if (ec_cmp(u, v) < 0) {
		t = ec_add(u, p);
		ec_free(u);
		u = t;
	}

	xp = ec_sub(u, v);
	ec_mod(xp, p);

	ec_free(u);
	ec_free(v);

	// y' = m (s - x') - 8 y^4

	if (ec_cmp(s, xp) < 0) {
		t = ec_add(s, p);
		ec_free(s);
		s = t;
	}

	t = ec_sub(s, xp);
	u = ec_mul(m, t);
	ec_free(t);
	ec_mod(u, p);

	y4 = ec_mul(y2, y2);
	v = ec_mul(c8, y4);
	ec_mod(v, p);

	if (ec_cmp(u, v) < 0) {
		t = ec_add(u, p);
		ec_free(u);
		u = t;
	}

	yp = ec_sub(u, v);
	ec_mod(yp, p);

	ec_free(u);
	ec_free(v);

	// z' = 2 y z

	t = ec_mul(y, z);
	zp = ec_mul(c2, t);
	ec_free(t);
	ec_mod(zp, p);

	// return x', y', z'

	ec_free_xyz(R);

	R->x = xp;
	R->y = yp;
	R->z = zp;

	ec_free(c2);
	ec_free(c3);
	ec_free(c4);
	ec_free(c8);
	ec_free(m);
	ec_free(s);
	ec_free(x2);
	ec_free(y2);
	ec_free(y4);
}

void
ec_double_v2r1(struct point *R, struct point *S, uint32_t *p, uint32_t *a)
{
	uint32_t *x, *y, *z;
	uint32_t *xp, *yp, *zp;
	uint32_t *c2, *c3, *c4, *c8, *m, *s, *t, *u, *v, *x2, *y2, *y4, *z2, *z4;

	x = S->x;
	y = S->y;
	z = S->z;

	c2 = ec_int(2);
	c3 = ec_int(3);
	c4 = ec_int(4);
	c8 = ec_int(8);

	// s == 4 x y^2

	y2 = ec_mul(y, y);
	ec_mod(y2, p);

	t = ec_mul(x, y2);
	s = ec_mul(c4, t);
	ec_free(t);
	ec_mod(s, p);

	// m = 3 x^2 + a Z^4

	x2 = ec_mul(x, x);
	ec_mod(x2, p);
	u = ec_mul(c3, x2);

	z2 = ec_mul(z, z);
	ec_mod(z2, p);

	z4 = ec_mul(z2, z2);
	ec_mod(z4, p);

	v = ec_mul(a, z4);

	m = ec_add(u, v);

	ec_free(u);
	ec_free(v);

	ec_mod(m, p);

	// x' = m^2 - 2 s

	u = ec_mul(m, m);
	ec_mod(u, p);

	v = ec_mul(c2, s);
	ec_mod(v, p);

	if (ec_cmp(u, v) < 0) {
		t = ec_add(u, p);
		ec_free(u);
		u = t;
	}

	xp = ec_sub(u, v);
	ec_mod(xp, p);

	ec_free(u);
	ec_free(v);

	// y' = m (s - x') - 8 y^4

	if (ec_cmp(s, xp) < 0) {
		t = ec_add(s, p);
		ec_free(s);
		s = t;
	}

	t = ec_sub(s, xp);
	u = ec_mul(m, t);
	ec_free(t);
	ec_mod(u, p);

	y4 = ec_mul(y2, y2);
	v = ec_mul(c8, y4);
	ec_mod(v, p);

	if (ec_cmp(u, v) < 0) {
		t = ec_add(u, p);
		ec_free(u);
		u = t;
	}

	yp = ec_sub(u, v);
	ec_mod(yp, p);

	ec_free(u);
	ec_free(v);

	// z' = 2 y z

	t = ec_mul(y, z);
	zp = ec_mul(c2, t);
	ec_free(t);
	ec_mod(zp, p);

	// return x', y', z'

	ec_free_xyz(R);

	R->x = xp;
	R->y = yp;
	R->z = zp;

	ec_free(c2);
	ec_free(c3);
	ec_free(c4);
	ec_free(c8);
	ec_free(m);
	ec_free(s);
	ec_free(x2);
	ec_free(y2);
	ec_free(y4);
	ec_free(z2);
	ec_free(z4);
}

// This code is from 'Mathematical routines for the NIST prime elliptic curves'

// This code works for secp256r1 but does not work for secp256k1

// (Because "a" is different in the polynomial y^2 = x^3 + a x + b)

void
ec_double_v1(struct point *R, struct point *S, uint32_t *p)
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

	if (ec_equal(U.x, 0) && ec_equal(U.y, 0) && ec_equal(U.z, 0))
		ec_double(&U, S, p);

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

// R = (d S) mod p

#if 1

void
ec_mult(struct point *R, uint32_t *d, struct point *S, uint32_t *p)
{
	int i;

	ec_free_xyz(R);

	if (ec_equal(d, 0)) {
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		return;
	}

	if (ec_equal(d, 1)) {
		R->x = ec_dup(S->x);
		R->y = ec_dup(S->y);
		R->z = ec_dup(S->z);
		return;
	}

	if (ec_equal(S->z, 0)) {
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		return;
	}

	if (!ec_equal(S->z, 1)) {
		ec_affinify(S, p);
		ec_projectify(S);
	}

	R->x = ec_int(0);
	R->y = ec_int(0);
	R->z = ec_int(0);

	for (i = 32 * len(d) - 1; i >= 0; i--) {

		ec_double(R, R, p);

		if (ec_get_bit(d, i))
			ec_full_add(R, R, S, p);
	}
}

#else

// original NIST algorithm

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

#endif

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
	ec_mod_v1(u, v);
}

void
ec_mod_v1(uint32_t *u, uint32_t *v)
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

void
ec_mod_v2(uint32_t *u, uint32_t *v)
{
	uint32_t *q, *r, *t;

	q = ec_div(u, v);
	t = ec_mul(q, v);
	r = ec_sub(u, t);

	memcpy(u, r, len(r) * sizeof (uint32_t));

	len(u) = len(r);

	ec_free(q);
	ec_free(r);
	ec_free(t);
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
	u = (uint32_t *) alloc_mem((n + 1) * sizeof (uint32_t));
	if (u == NULL) {
		trace();
		exit(1);
	}
	u[0] = n;
	return u + 1;
}

void
ec_free(uint32_t *u)
{
	if (u)
		free_mem(u - 1);
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

uint32_t *p256, *q256, *gx256, *gy256, *a256, *b256, *lower_s;

// secp256k1

#define STR_P "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFE" "FFFFFC2F"
#define STR_Q "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFE" "BAAEDCE6" "AF48A03B" "BFD25E8C" "D0364141"
#define STR_GX "79BE667E" "F9DCBBAC" "55A06295" "CE870B07" "029BFCDB" "2DCE28D9" "59F2815B" "16F81798"
#define STR_GY "483ADA77" "26A3C465" "5DA4FBFC" "0E1108A8" "FD17B448" "A6855419" "9C47D08F" "FB10D4B8"
#define STR_A "0"
#define STR_B "7"

// see go-ethereum-master/crypto/secp256k1/libsecp256k1/include/secp256k1.h

#define STR_LOWER_S "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"

void
ec_init(void)
{
	p256 = ec_hexstr_to_bignum(STR_P);
	q256 = ec_hexstr_to_bignum(STR_Q);
	gx256 = ec_hexstr_to_bignum(STR_GX);
	gy256 = ec_hexstr_to_bignum(STR_GY);
	a256 = ec_hexstr_to_bignum(STR_A);
	b256 = ec_hexstr_to_bignum(STR_B);
	lower_s = ec_hexstr_to_bignum(STR_LOWER_S);
}
