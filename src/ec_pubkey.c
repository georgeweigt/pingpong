// public_key	64 bytes (result)
// private_key	32 bytes

void
ec_pubkey(uint8_t *public_key, uint8_t *private_key)
{
	int i;
	uint32_t *d;
	struct point R, S;

	d = ec_buf_to_bignum(private_key, 32);

	R.x = gx256;
	R.y = gy256;
	R.z = ec_int(1);

	S.x = NULL;
	S.y = NULL;
	S.z = NULL;

	ec_mult(&S, d, &R, p256);
	ec_affinify(&S, p256);

	// save public key

	memset(public_key, 0, 64);

	for (i = 0; i < len(S.x) && i < 8; i++) {
		// bignums are LE, this converts to BE
		public_key[32 - 4 * i - 4] = S.x[i] >> 24;
		public_key[32 - 4 * i - 3] = S.x[i] >> 16;
		public_key[32 - 4 * i - 2] = S.x[i] >> 8;
		public_key[32 - 4 * i - 1] = S.x[i];
	}

	for (i = 0; i < len(S.y) && i < 8; i++) {
		// bignums are LE, this converts to BE
		public_key[64 - 4 * i - 4] = S.y[i] >> 24;
		public_key[64 - 4 * i - 3] = S.y[i] >> 16;
		public_key[64 - 4 * i - 2] = S.y[i] >> 8;
		public_key[64 - 4 * i - 1] = S.y[i];
	}

	ec_free(d);
	ec_free(R.z);
	ec_free_xyz(&S);
}
