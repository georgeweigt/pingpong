#define STR1 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define STR2 "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
#define STR3 "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
#define STR4 "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"

void
test_sha256(void)
{
	int err;
	uint8_t h[32], hash[32];

	printf("Test sha256 ");

	hextobin(h, 32, STR1);
	sha256((uint8_t *) "", 0, hash);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	hextobin(h, 32, STR2);
	sha256((uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	hextobin(h, 32, STR3);
	hmac_sha256((uint8_t *) "", 0, (uint8_t *) "", 0, hash);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	hextobin(h, 32, STR4);
	hmac_sha256((uint8_t *) "key", 3, (uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	printf("ok\n");
}
