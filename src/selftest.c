void
selftest(void)
{
	ec_test();
	test_boot_key();
	test_keccak256();
}

// secp256k1

#define P "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"

// Sepolia boot node geth

#define X "9246d00bc8fd1742e5ad2428b80fc4dc45d786283e05ef6edbd9002cbc335d40"
#define Y "998444732fbe921cb88e1d2c73d1b1de53bae6a2237996e9bfe14f871baf7066"

void
test_boot_key(void)
{
	uint32_t *n3, *n7, *x, *x3, *y, *y2, *p, *r;

	printf("Testing boot key ");

	p = ec_hexstr_to_bignum(P);
	x = ec_hexstr_to_bignum(X);
	y = ec_hexstr_to_bignum(Y);

	// y^2 mod p == (x^3 + 7) mod p

	y2 = ec_mul(y, y);
	ec_mod(y2, p);

	n3 = ec_int(3);
	x3 = ec_pow(x, n3);
	n7 = ec_int(7);
	r = ec_add(x3, n7);
	ec_mod(r, p);

	if (ec_cmp(y2, r) == 0)
		printf("ok\n");
	else
		printf("fail\n");
}
