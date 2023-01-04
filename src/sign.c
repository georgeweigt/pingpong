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

	encode(sig, SIGLEN, p);
}

void
test_sign(void)
{
	int err;
	uint8_t buf[60], hash[32], sig[SIGLEN];

	printf("Testing sign ");

	sign(sig, (uint8_t *) "hello", 5);

	if (decode_check(sig, SIGLEN) == SIGLEN) {
		memcpy(buf, "\x19" "Ethereum Signed Message:\n32", 28);
		keccak256(buf + 28, (uint8_t *) "hello", 5);
		keccak256(hash, buf, 60);
		err = ec_verify(hash, sig + 3, sig + 36, public_key_x, public_key_y);
	} else
		err = 1;

	printf("%s\n", err ? "err" : "ok");
}
