#define RATE 136
#define STR1 "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
#define STR2 "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
#define STR3 "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"
#define STR4 "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"
#define STR5 "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39"

void
test_keccak256(void)
{
	int err;
	uint8_t buf[RATE + 1], h[32], hash[32];
	struct mac state;

	printf("Test keccak256 ");

	memset(buf, 'a', sizeof buf);

	hextobin(h, 32, STR1);
	keccak256(hash, buf, 0);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	hextobin(h, 32, STR2);
	keccak256(hash, (uint8_t *) "hello", 5);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	hextobin(h, 32, STR3);
	keccak256(hash, buf, RATE - 1);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	hextobin(h, 32, STR4);
	keccak256(hash, buf, RATE);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	hextobin(h, 32, STR5);
	keccak256(hash, buf, RATE + 1);
	err = memcmp(h, hash, 32);
	if (err) {
		trace();
		return;
	}

	keccak256_setup(&state);
	keccak256_update(&state, buf, RATE + 1);
	keccak256_digest(&state, hash);
	err = memcmp(h, hash, 32);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

#undef RATE
#undef STR1
#undef STR2
#undef STR3
#undef STR4
#undef STR5
