#define CTR128 ((uint8_t *) expanded_key + 176) // 44 uint32_t
#define CTR256 ((uint8_t *) expanded_key + 240) // 60 uint32_t

// expanded_key	192 bytes (48 uint32_t)
// key		16 bytes
// iv		16 bytes

void
aes128ctr_setup(uint32_t *expanded_key, uint8_t *key, uint8_t *iv)
{
	uint32_t v[44];
	aes128_expand_key(key, expanded_key, v);
	if (iv == NULL)
		memset(CTR128, 0, 16);
	else
		memcpy(CTR128, iv, 16);
}

// used for both encryption and decryption

void
aes128ctr_encrypt(uint32_t *expanded_key, uint8_t *buf, int len)
{
	int i;
	uint8_t block[16];

	while (len > 0) {

		aes128_encrypt_block(expanded_key, CTR128, block);

		for (i = 0; i < 16 && i < len; i++)
			buf[i] ^= block[i];

		// increment counter

		for (i = 15; i >= 0; i--)
			if (++CTR128[i] > 0)
				break;

		buf += 16;
		len -= 16;
	}
}

// expanded_key	256 bytes (64 uint32_t)
// key		32 bytes
// iv		16 bytes

void
aes256ctr_setup(uint32_t *expanded_key, uint8_t *key, uint8_t *iv)
{
	uint32_t v[60];
	aes256_expand_key(key, expanded_key, v);
	if (iv == NULL)
		memset(CTR256, 0, 16);
	else
		memcpy(CTR256, iv, 16);
}

// used for both encryption and decryption

void
aes256ctr_encrypt(uint32_t *expanded_key, uint8_t *buf, int len)
{
	int i;
	uint8_t block[16];

	while (len > 0) {

		aes256_encrypt_block(expanded_key, CTR256, block);

		for (i = 0; i < 16 && i < len; i++)
			buf[i] ^= block[i];

		// increment counter

		for (i = 15; i >= 0; i--)
			if (++CTR256[i] > 0)
				break;

		buf += 16;
		len -= 16;
	}
}
