#define ETHSTR "\x19" "Ethereum Signed Message:\n32"

// private_key	32 bytes
// public_key	64 bytes

// returns list [r,s,v] on stack

void
sign(uint8_t *msg, int msglen, uint8_t *private_key, uint8_t *public_key)
{
	uint8_t buf[28 + 32], hash[32], sig[65];

	memcpy(buf, ETHSTR, 28); // 28 chars

	keccak256(buf + 28, msg, msglen);

	keccak256(hash, buf, sizeof buf);

	ec_sign(sig, hash, private_key);

	push_string(sig, 32);
	push_string(sig + 32, 32);
	push_number(sig[64] + 27); // 27 even, 28 odd

	list(3);
}

void
test_sign(void)
{
	int err;
	uint8_t buf[60], hash[32], private_key[32], public_key[64], *r, *s;
	struct atom *list;

	printf("Test sign ");

	ec_genkey(private_key, public_key);

	sign((uint8_t *) "hello", 5, private_key, public_key);

	list = pop();

	r = list->car->string;
	s = list->cdr->car->string;

	memcpy(buf, "\x19" "Ethereum Signed Message:\n32", 28);
	keccak256(buf + 28, (uint8_t *) "hello", 5);
	keccak256(hash, buf, 60);

	err = !ec_verify(hash, r, s, public_key);

	free_list(list);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}
