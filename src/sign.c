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

	v = 27 + (acct->public_key[63] & 1); // 27 even, 28 odd

	push_string(r, 32);
	push_string(s, 32);
	push_number(v);
	list(3);

	p = pop();

	rencode(sig, SIGLEN, p);
}

void
test_sign(struct account *acct)
{
	int err;
	uint8_t buf[60], hash[32], sig[SIGLEN];

	printf("Test sign ");

	sign(sig, (uint8_t *) "hello", 5, acct);

	err = rdecode(sig, SIGLEN);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}
	free_list(pop()); // discard result from rdecode

	memcpy(buf, "\x19" "Ethereum Signed Message:\n32", 28);
	keccak256(buf + 28, (uint8_t *) "hello", 5);
	keccak256(hash, buf, 60);
	err = ec_verify(hash, sig + 3, sig + 36, acct->public_key, acct->public_key + 32);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}
