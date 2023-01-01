void
selftest(void)
{
	test_ec();
	test_boot_key();
	test_keccak256();
	test_encode();
	test_ec_mint_key();
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

	ec_free(n3);
	ec_free(n7);
	ec_free(x);
	ec_free(x3);
	ec_free(y);
	ec_free(y2);
	ec_free(p);
	ec_free(r);
}

void
test_public_keys_secp256k1(uint32_t *x, uint32_t *y)
{
	uint32_t *n3, *n7, *x3, *y2, *r;

	// y^2 mod p == (x^3 + 7) mod p

	y2 = ec_mul(y, y);
	ec_mod(y2, p256);

	n3 = ec_int(3);
	x3 = ec_pow(x, n3);
	n7 = ec_int(7);
	r = ec_add(x3, n7);
	ec_mod(r, p256);

	printf("%s\n", ec_cmp(y2, r) == 0 ? "ok" : "fail");

	ec_free(n3);
	ec_free(n7);
	ec_free(x3);
	ec_free(y2);
	ec_free(r);
}

#define A "FFFFFFFF" "00000001" "00000000" "00000000" "00000000" "FFFFFFFF" "FFFFFFFF" "FFFFFFFC"
#define B "5AC635D8" "AA3A93E7" "B3EBBD55" "769886BC" "651D06B0" "CC53B0F6" "3BCE3C3E" "27D2604B"

void
test_public_keys_secp256r1(uint32_t *x, uint32_t *y)
{
	uint32_t *a, *b, *n3, *x3, *y2, *r, *t1, *t2;

	// y^2 mod p == (x^3 + a x + b) mod p

	y2 = ec_mul(y, y);
	ec_mod(y2, p256);

	n3 = ec_int(3);
	x3 = ec_pow(x, n3);

	a = ec_hexstr_to_bignum(A);
	b = ec_hexstr_to_bignum(B);

	t1 = ec_mul(a, x);

	t2 = ec_add(x3, t1);
	r = ec_add(t2, b);

	ec_mod(r, p256);

	printf("%s\n", ec_cmp(y2, r) == 0 ? "ok" : "fail");

	ec_free(a);
	ec_free(b);
	ec_free(n3);
	ec_free(x3);
	ec_free(y2);
	ec_free(r);
	ec_free(t1);
	ec_free(t2);
}
