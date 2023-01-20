#define KEY "000102030405060708090a0b0c0d0e0f"
#define PLAIN "00112233445566778899aabbccddeeff"
#define CRYPTO "69c4e0d86a7b0430d8cdb78070b4c55a"

void
test_aes128(void)
{
	int err;
	uint8_t k[16], p[16], c[16];
	uint32_t w[44], v[44];

	printf("Test aes128 ");

	hextobin(k, 16, KEY);
	hextobin(p, 16, PLAIN);
	hextobin(c, 16, CRYPTO);

	aes128_expand_key(k, w, v);

	aes128_encrypt_block(w, p, p);

	err = memcmp(p, c, 16);

	if (err) {
		trace();
		return;
	}

	printf("ok\n");
}
