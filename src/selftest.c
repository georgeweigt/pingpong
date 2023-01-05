void
selftest(void)
{
//	test_boot_key();
	test_keccak256();
	test_encode();
	test_decode();
	test_ec_genkey();
	test_sign(account_table + 0);
	test_ping_payload(account_table + 0);
}

// Sepolia boot node geth

#define X "9246d00bc8fd1742e5ad2428b80fc4dc45d786283e05ef6edbd9002cbc335d40"
#define Y "998444732fbe921cb88e1d2c73d1b1de53bae6a2237996e9bfe14f871baf7066"

void
test_boot_key(void)
{
	int err;
	uint32_t *x, *y;

	printf("Testing boot key ");

	x = ec_hexstr_to_bignum(X);
	y = ec_hexstr_to_bignum(Y);

	err = test_public_keys_secp256k1(x, y);

	printf("%s\n", err ? "err" : "ok");

	ec_free(x);
	ec_free(y);
}
