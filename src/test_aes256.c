#define KEY "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define PLAIN "00112233445566778899aabbccddeeff"
#define CRYPTO "8ea2b7ca516745bfeafc49904b496089"

void
test_aes256(void)
{
	int err;
	uint8_t k[32], p[16], c[16];
	uint32_t w[60];

	printf("Test aes256 ");

	hextobin(k, 32, KEY);
	hextobin(p, 16, PLAIN);
	hextobin(c, 16, CRYPTO);

	aes256_expand_key(k, w);

	aes256_encrypt_block(w, p, p);

	err = memcmp(p, c, 16);

	if (err) {
		trace();
		return;
	}

	printf("ok\n");
}
