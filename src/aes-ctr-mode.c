#define CTR1 ((uint8_t *) state + 176) // 176 bytes = 44 uint32_t
#define CTR2 ((uint8_t *) state + 240) // 240 bytes = 60 uint32_t

// state	192 bytes (48 uint32_t)
// key		16 bytes
// iv		16 bytes

void
aes128ctr_setup(uint32_t *state, uint8_t *key, uint8_t *iv)
{
	uint32_t v[44];
	aes128_expand_key(key, state, v);
	memcpy(CTR1, iv, 16);
}

// used for both encryption and decryption

void
aes128ctr_encrypt(uint32_t *state, uint8_t *buf, int len)
{
	int i;
	uint8_t block[16];

	while (len > 0) {

		aes128_encrypt_block(state, CTR1, block);

		for (i = 0; i < 16 && i < len; i++)
			buf[i] ^= block[i];

		// increment counter

		for (i = 15; i >= 0; i--)
			if (++CTR1[i] > 0)
				break;

		buf += 16;
		len -= 16;
	}
}

// state	256 bytes (64 uint32_t)
// key		32 bytes
// iv		16 bytes

void
aes256ctr_setup(uint32_t *state, uint8_t *key, uint8_t *iv)
{
	uint32_t v[60];
	aes256_expand_key(key, state, v);
	memcpy(CTR2, iv, 16);
}

// used for both encryption and decryption

void
aes256ctr_encrypt(uint32_t *state, uint8_t *buf, int len)
{
	int i;
	uint8_t block[16];

	while (len > 0) {

		aes256_encrypt_block(state, CTR2, block);

		for (i = 0; i < 16 && i < len; i++)
			buf[i] ^= block[i];

		// increment counter

		for (i = 15; i >= 0; i--)
			if (++CTR2[i] > 0)
				break;

		buf += 16;
		len -= 16;
	}
}
