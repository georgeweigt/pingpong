void
sign(uint8_t *sig, uint8_t *msg, int msglen, struct account *acct)
{
	int v;
	uint8_t buf[60], hash[32], r[32], s[32];
	struct atom *p;

	memcpy(buf, "\x19" "Ethereum Signed Message:\n32", 28); // 28 chars

	keccak256(buf + 28, msg, msglen);

	keccak256(hash, buf, 60);

	ec_sign(r, s, hash, acct->private_key);

	v = 27 + (acct->public_key_y[31] & 1); // 27 even, 28 odd

	push_string(r, 32);
	push_string(s, 32);
	push_number(v);
	list(3);

	p = pop();

	rencode(sig, SIGLEN, p);
}

// sig		65 bytes
// buf		32
// private_key	32
// public_key	64 (X || Y)

void
signbuf(uint8_t *sig, uint8_t *buf, uint8_t *private_key, uint8_t *public_key)
{
	int v;
	uint8_t r[32], s[32];

	ec_sign(r, s, buf, private_key);

	v = 27 + (public_key[63] & 1); // 27 even, 28 odd

	memcpy(sig, r, 32);
	memcpy(sig + 32, s, 32);
	sig[64] = v;
}

void
test_sign(struct account *acct)
{
	int err;
	uint8_t buf[60], hash[32], sig[SIGLEN];

	printf("Testing sign ");

	sign(sig, (uint8_t *) "hello", 5, acct);

	err = rdecode(sig, SIGLEN);

	if (!err) {
		free_list(pop());
		memcpy(buf, "\x19" "Ethereum Signed Message:\n32", 28);
		keccak256(buf + 28, (uint8_t *) "hello", 5);
		keccak256(hash, buf, 60);
		err = ec_verify(hash, sig + 3, sig + 36, acct->public_key_x, acct->public_key_y);
	}

	printf("%s\n", err ? "err" : "ok");
}
