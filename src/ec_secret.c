// generate 32 byte secret from private key k and public_key

void
ec_secret(uint8_t *secret, uint8_t *k, uint8_t *public_key)
{
	int i;
	uint32_t *d;
	struct point R, S;

	d = ec_buf_to_bignum(k, 32);

	R.x = ec_buf_to_bignum(public_key, 32); // X
	R.y = ec_buf_to_bignum(public_key + 32, 32); // Y
	R.z = ec_int(1);

	S.x = NULL;
	S.y = NULL;
	S.z = NULL;

	ec_mult(&S, d, &R, p256); // S = d * R
	ec_affinify(&S, p256);

	memset(secret, 0, 32);

	for (i = 0; i < len(S.x); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err
		secret[32 - 4 * i - 4] = S.x[i] >> 24;
		secret[32 - 4 * i - 3] = S.x[i] >> 16;
		secret[32 - 4 * i - 2] = S.x[i] >> 8;
		secret[32 - 4 * i - 1] = S.x[i];
	}

	ec_free(d);
	ec_free_xyz(&R);
	ec_free_xyz(&S);
}
