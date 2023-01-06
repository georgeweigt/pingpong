void
selftest(void)
{
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
