// hash, r, s, public_key_x, public_key y --> ec_verify --> -1 or 0

int
ec_verify(uint8_t *hash, uint8_t *rbuf, uint8_t *sbuf, uint8_t *public_key_x, uint8_t *public_key_y)
{
	int err;
	uint32_t *h, *r, *s, *u, *v, *w;
	struct point R, S, T;

	h = ec_buf_to_bignum(hash, 32);
	r = ec_buf_to_bignum(rbuf, 32);
	s = ec_buf_to_bignum(sbuf, 32);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	S.x = ec_dup(gx256);
	S.y = ec_dup(gy256);
	S.z = ec_int(1);

	T.x = ec_buf_to_bignum(public_key_x, 32);
	T.y = ec_buf_to_bignum(public_key_y, 32);
	T.z = ec_int(1);

	w = ec_modinv(s, q256);

	u = ec_mul(h, w);
	ec_mod(u, q256);

	v = ec_mul(r, w);
	ec_mod(v, q256);

	ec_twin_mult(&R, u, &S, v, &T, p256);

	ec_affinify(&R, p256);

	ec_mod(R.x, q256);

	err = ec_cmp(R.x, r) == 0 ? 0 : -1;

	ec_free(h);
	ec_free(r);
	ec_free(s);
	ec_free(u);
	ec_free(v);
	ec_free(w);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
	ec_free_xyz(&T);

	return err;
}
