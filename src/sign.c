void
sign(uint8_t *sig, uint8_t *msg, int msglen, uint8_t *private_key)
{
	int v;
	uint8_t buf[60], hash[32], r[32], s[32];
	struct atom *p;

	memcpy(buf, "\x19" "Ethereum Signed Message:\n32", 28); // 28 chars

	keccak256(buf + 28, msg, msglen);

	keccak256(hash, buf, 60);

	ec_sign(r, s, hash, private_key);

	v = 27; // FIXME

	push_string(r, 32);
	push_string(s, 32);
	push_number(v);
	list(3);

	p = pop();

	encode(sig, p);
}

#define PRIVATE_KEY "\x62\x55\x58\xec\x2a\xe8\x94\x4a\x19\x49\x5c\xff\x74\xb0\xdc\x51\x66\x33\x48\x73\x64\x3c\x98\x69\x32\x7b\x23\xc6\x6b\x8b\x45\x67"

void
test_sign(void)
{
	int i;
	uint8_t sig[SIGLEN];

	printf("Testing sign ");

	sign(sig, (uint8_t *) "hello", 5, (uint8_t *) PRIVATE_KEY);

	for (i = 0; i < SIGLEN; i++)
		printf("%02x", sig[i]);

	printf("\n");
}
