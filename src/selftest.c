#define X "1ecbbdb04f54b68d99a9fb0d60786d29164ffe9776bad9118ec896f2764ec9f7"
#define Y "11ec2e6f8e0e21c1f0f9abe4515c45949e6bf776d84b54d08f7c32de60e8c480"

void
selftest(void)
{
	printf("test public key %s\n", test_public_key(X, Y) ? "err" : "ok");
	test_sha256();
	test_keccak256();
	test_encode();
	test_decode();
	test_ec_genkey();
	test_sign(account_table + 0);
	test_ping_payload(account_table + 0);
}

int
test_public_key(char *public_key_x, char *public_key_y)
{
	int err;
	uint32_t *x, *y;

	x = ec_hexstr_to_bignum(public_key_x);
	y = ec_hexstr_to_bignum(public_key_y);

	err = test_public_key_secp256k1(x, y);

	ec_free(x);
	ec_free(y);

	return err;
}
