// ecdh_key	32 bytes (result)
// private_key	32 bytes
// public_key	64 bytes

int
ec_ecdh(uint8_t *ecdh_key, uint8_t *private_key, uint8_t *public_key)
{
	int i;
	uint32_t *d;
	struct point R, S;

	d = ec_buf_to_bignum(private_key, 32);

	R.x = ec_buf_to_bignum(public_key, 32);
	R.y = ec_buf_to_bignum(public_key + 32, 32);
	R.z = ec_int(1);

	S.x = NULL;
	S.y = NULL;
	S.z = NULL;

	ec_mod(d, q256);

	if (ec_equal(d, 0))
		return -1;

	// generate ecdh key

	ec_mult(&S, d, &R, p256);
	ec_affinify(&S, p256);

	// save ecdh key

	memset(ecdh_key, 0, 32);

	for (i = 0; i < len(S.x); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err
		ecdh_key[32 - 4 * i - 4] = S.x[i] >> 24;
		ecdh_key[32 - 4 * i - 3] = S.x[i] >> 16;
		ecdh_key[32 - 4 * i - 2] = S.x[i] >> 8;
		ecdh_key[32 - 4 * i - 1] = S.x[i];
	}

	ec_free(d);
	ec_free_xyz(&R);
	ec_free_xyz(&S);

	return 0;
}
