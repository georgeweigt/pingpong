void
sign(uint8_t *sig, uint8_t *msg, int msglen)
{
	int v;
	uint8_t buf[60], hash[32], r[32], s[32];
	struct atom *p;

	memcpy(buf, "\x19" "Ethereum Signed Message:\n32", 28); // 28 chars

	keccak256(buf + 28, msg, msglen);

	keccak256(hash, buf, 60);

	ec_sign(r, s, hash, private_key);

	v = 27 + (public_key_y[31] & 1); // 27 even, 28 odd

	push_string(r, 32);
	push_string(s, 32);
	push_number(v);
	list(3);

	p = pop();

	encode(sig, p);
}

void
test_sign(void)
{
	int i;
	uint8_t sig[SIGLEN];

	printf("Testing sign ");

	sign(sig, (uint8_t *) "hello", 5);

	for (i = 0; i < SIGLEN; i++)
		printf("%02x", sig[i]);

	printf("\n");
}
