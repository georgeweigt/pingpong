void
test(void)
{
	test_aes128();
	test_aes256();
	test_sha256();
	test_keccak256();
	test_encode();
	test_decode();
	test_genkey();
	test_pubkey();
	test_kdf();
	test_hmac();
	test_sign();
	test_decrypt();
	test_snappy();
}

// does this public key belong to secp256k1? (0 yes, -1 no)

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

void
test_encode(void)
{
	int err, i, n;
	struct atom *p;
	uint8_t buf[256], enc[256];

	printf("Test encode ");

	// items

	push_string(NULL, 0);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x80", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_string((uint8_t *) "", 0);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x80", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_string((uint8_t *) "a", 1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "a", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_string((uint8_t *) "ab", 2);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 3 || memcmp(buf, "\x82" "ab", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_string((uint8_t *) "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "fffff", 55);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 56 || memcmp(buf, "\xb7" "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "fffff", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_string((uint8_t *) "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "ffffff", 56);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 58 || memcmp(buf, "\xb8\x38" "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "ffffff", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(0);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x00", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x01", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(127);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x7f", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(128);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 2 || memcmp(buf, "\x81\x80", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(255);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 2 || memcmp(buf, "\x81\xff", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(256);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 3 || memcmp(buf, "\x82\x01\x00", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(65535);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 3 || memcmp(buf, "\x82\xff\xff", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(65536);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 4 || memcmp(buf, "\x83\x01\x00\x00", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// []

	list(0);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\xc0", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// [[]]

	list(0);
	list(1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 2 || memcmp(buf, "\xc1\xc0", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// [1, [], 2]

	push_number(1);
	list(0);
	push_number(2);
	list(3);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 4 || memcmp(buf, "\xc3\x01\xc0\x02", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// list of one 54 byte string

	for (i = 0; i < 54; i++)
		buf[i] = i;
	push_string(buf, 54);
	list(1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 56) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}
	enc[0] = 0xc0 + 55; // 55 byte list
	enc[1] = 0x80 + 54; // 54 byte string
	for (i = 0; i < 54; i++)
		enc[2 + i] = i;
	err = memcmp(buf, enc, 56);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// list of one 55 byte string

	for (i = 0; i < 55; i++)
		buf[i] = i;
	push_string(buf, 55);
	list(1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 58) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}
	enc[0] = 0xf8; // list with 1 length byte
	enc[1] = 56;
	enc[2] = 0x80 + 55; // 55 byte string
	for (i = 0; i < 55; i++)
		enc[3 + i] = i;
	err = memcmp(buf, enc, 58);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// list of one 56 byte string

	for (i = 0; i < 56; i++)
		buf[i] = i;
	push_string(buf, 56);
	list(1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 60) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}
	enc[0] = 0xf8; // list with 1 length byte
	enc[1] = 58;
	enc[2] = 0xb8; // string with 1 length byte
	enc[3] = 56;
	for (i = 0; i < 56; i++)
		enc[4 + i] = i;
	err = memcmp(buf, enc, 60);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	if (atom_count) {
		printf("err memory leak %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

void
test_decode(void)
{
	int err, len, n;
	struct atom *p, *q;
	uint8_t buf[2000];

	printf("Test decode ");

	// []

	list(0);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err < 0)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// [[]]

	list(0);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err < 0)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// [[],[]]

	list(0);
	list(0);
	list(2);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err < 0)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// "" (empty string)

	push_string(NULL, 0);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err < 0)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// string

	for (n = 0; n <= 1000; n++) {
		push_string(buf, n);
		p = pop();
		len = rencode(buf, sizeof buf, p);
		err = rdecode(buf, len);
		if (err < 0)
			q = NULL;
		else {
			q = pop();
			err = compare_lists(p, q);
		}
		free_list(p);
		free_list(q);
		if (err) {
			printf("err %s line %d", __FILE__, __LINE__);
			return;
		}
	}

	// list of one 54 byte string

	push_string(buf, 54);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err < 0)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// list of one 55 byte string

	push_string(buf, 55);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err < 0)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// list of one 56 byte string

	push_string(buf, 56);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err < 0)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// list of one 57 byte string

	push_string(buf, 57);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err < 0)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

void
test_genkey(void)
{
	int err;
	uint8_t private_key[32], public_key[64];
	uint8_t r[32], s[32], hash[32];

	printf("Test genkey ");

	ec_genkey(private_key, public_key);

	memset(hash, 0xf5, sizeof hash);

	ec_sign(r, s, hash, private_key);

	err = !ec_verify(hash, r, s, public_key);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	if (ec_alloc_count != 0) {
		printf("err memory leak %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

int
test_public_key_secp256k1(uint32_t *x, uint32_t *y)
{
	int err;
	uint32_t *n3, *n7, *p, *x3, *y2, *r;

	p = ec_hexstr_to_bignum("FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFE" "FFFFFC2F");

	// y^2 mod p == (x^3 + 7) mod p

	y2 = ec_mul(y, y);
	ec_mod(y2, p);

	n3 = ec_int(3);
	x3 = ec_pow(x, n3);
	n7 = ec_int(7);
	r = ec_add(x3, n7);
	ec_mod(r, p);

	err = ec_cmp(y2, r); // 0 = ok

	ec_free(n3);
	ec_free(n7);
	ec_free(p);
	ec_free(x3);
	ec_free(y2);
	ec_free(r);

	return err;
}

#define COEFF_A "FFFFFFFF" "00000001" "00000000" "00000000" "00000000" "FFFFFFFF" "FFFFFFFF" "FFFFFFFC"
#define COEFF_B "5AC635D8" "AA3A93E7" "B3EBBD55" "769886BC" "651D06B0" "CC53B0F6" "3BCE3C3E" "27D2604B"

int
test_public_key_secp256r1(uint32_t *x, uint32_t *y)
{
	int err;
	uint32_t *a, *b, *n3, *p, *x3, *y2, *r, *t1, *t2;

	p = ec_hexstr_to_bignum("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

	// y^2 mod p == (x^3 + a x + b) mod p

	y2 = ec_mul(y, y);
	ec_mod(y2, p);

	n3 = ec_int(3);
	x3 = ec_pow(x, n3);

	a = ec_hexstr_to_bignum(COEFF_A);
	b = ec_hexstr_to_bignum(COEFF_B);

	t1 = ec_mul(a, x);

	t2 = ec_add(x3, t1);
	r = ec_add(t2, b);

	ec_mod(r, p);

	err = ec_cmp(y2, r); // 0 = ok

	ec_free(a);
	ec_free(b);
	ec_free(n3);
	ec_free(p);
	ec_free(x3);
	ec_free(y2);
	ec_free(r);
	ec_free(t1);
	ec_free(t2);

	return err;
}

/*
def test_agree():
secret = fromHex("0x332143e9629eedff7d142d741f896258f5a1bfab54dab2121d3ec5000093d74b")
public = fromHex(
"0xf0d2b97981bd0d415a843b5dfe8ab77a30300daab3658c578f2340308a2da1a07f0821367332598b6aa4e180a41e92f4ebbae3518da847f0b1c0bbfe20bcf4e1")
agreeExpected = fromHex("0xee1418607c2fcfb57fda40380e885a707f49000a5dda056d828b7d9bd1f29a08")
e = crypto.ECCx(raw_privkey=secret)
agreeTest = e.raw_get_ecdh_key(pubkey_x=public[:32], pubkey_y=public[32:])
assert(agreeExpected == agreeTest)
*/

#define K "332143e9629eedff7d142d741f896258f5a1bfab54dab2121d3ec5000093d74b"
#define X "f0d2b97981bd0d415a843b5dfe8ab77a30300daab3658c578f2340308a2da1a0"
#define Y "7f0821367332598b6aa4e180a41e92f4ebbae3518da847f0b1c0bbfe20bcf4e1"
#define E "ee1418607c2fcfb57fda40380e885a707f49000a5dda056d828b7d9bd1f29a08"

void
test_ecdh(void)
{
	int err;
	uint8_t e[32], ecdh[32], priv[32], pub[64];

	printf("Test ecdh ");

	hextobin(priv, 32, K);
	hextobin(pub, 32, X);
	hextobin(pub + 32, 32, Y);
	hextobin(e, 32, E);

	ec_ecdh(ecdh, priv, pub);

	err = memcmp(e, ecdh, 32);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

#undef K
#undef X
#undef Y
#undef E

/*
def test_kdf():
input1 = fromHex("0x0de72f1223915fa8b8bf45dffef67aef8d89792d116eb61c9a1eb02c422a4663")
expect1 = fromHex("0x1d0c446f9899a3426f2b89a8cb75c14b")
test1 = crypto.eciesKDF(input1, 16)
assert len(test1) == len(expect1)
assert(test1 == expect1)

kdfInput2 = fromHex("0x961c065873443014e0371f1ed656c586c6730bf927415757f389d92acf8268df")
kdfExpect2 = fromHex("0x4050c52e6d9c08755e5a818ac66fabe478b825b1836fd5efc4d44e40d04dabcc")
kdfTest2 = crypto.eciesKDF(kdfInput2, 32)
assert(len(kdfTest2) == len(kdfExpect2))
assert(kdfTest2 == kdfExpect2)
*/

#define A1 "0de72f1223915fa8b8bf45dffef67aef8d89792d116eb61c9a1eb02c422a4663"
#define B1 "1d0c446f9899a3426f2b89a8cb75c14b"

#define A2 "961c065873443014e0371f1ed656c586c6730bf927415757f389d92acf8268df"
#define B2 "4050c52e6d9c08755e5a818ac66fabe478b825b1836fd5efc4d44e40d04dabcc"

void
test_kdf(void)
{
	uint8_t a[32], b[32], buf[36];

	printf("Test kdf ");

	hextobin(a, 32, A1);
	hextobin(b, 16, B1);

	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 1;

	memcpy(buf + 4, a, 32);

	sha256(buf, 36, buf);

	if (memcmp(b, buf, 16) != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	hextobin(a, 32, A2);
	hextobin(b, 32, B2);

	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 1;

	memcpy(buf + 4, a, 32);

	sha256(buf, 36, buf);

	if (memcmp(b, buf, 32) != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

#undef A1
#undef B1

#undef A2
#undef B2

/*
def test_hmac():
k_mac = fromHex("0x07a4b6dfa06369a570f2dcba2f11a18f")
indata = fromHex("0x4dcb92ed4fc67fe86832")
hmacExpected = fromHex("0xc90b62b1a673b47df8e395e671a68bfa68070d6e2ef039598bb829398b89b9a9")
hmacOut = crypto.hmac_sha256(k_mac, indata)
assert(hmacExpected == hmacOut)

# go messageTag
tagSecret = fromHex("0xaf6623e52208c596e17c72cea6f1cb09")
tagInput = fromHex("0x3461282bcedace970df2")
tagExpected = fromHex("0xb3ce623bce08d5793677ba9441b22bb34d3e8a7de964206d26589df3e8eb5183")
hmacOut = crypto.hmac_sha256(tagSecret, tagInput)
assert(hmacOut == tagExpected)
*/

#define KMAC1 "07a4b6dfa06369a570f2dcba2f11a18f"
#define DATA1 "4dcb92ed4fc67fe86832"
#define HMAC1 "c90b62b1a673b47df8e395e671a68bfa68070d6e2ef039598bb829398b89b9a9"

#define KMAC2 "af6623e52208c596e17c72cea6f1cb09"
#define DATA2 "3461282bcedace970df2"
#define HMAC2 "b3ce623bce08d5793677ba9441b22bb34d3e8a7de964206d26589df3e8eb5183"

void
test_hmac(void)
{
	uint8_t kmac[16], data[10], hmac[32], out[32];

	printf("Test hmac ");

	hextobin(kmac, 16, KMAC1);
	hextobin(data, 10, DATA1);
	hextobin(hmac, 32, HMAC1);

	hmac_sha256(kmac, 16, data, 10, out);

	if (memcmp(hmac, out, 32) != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	hextobin(kmac, 16, KMAC2);
	hextobin(data, 10, DATA2);
	hextobin(hmac, 32, HMAC2);

	hmac_sha256(kmac, 16, data, 10, out);

	if (memcmp(hmac, out, 32) != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

#undef KMAC1
#undef DATA1
#undef HMAC1

#undef KMAC2
#undef DATA2
#undef HMAC2

/*
def test_privtopub():
kenc = fromHex("0x472413e97f1fd58d84e28a559479e6b6902d2e8a0cee672ef38a3a35d263886b")
penc = fromHex(
"0x7a2aa2951282279dc1171549a7112b07c38c0d97c0fe2c0ae6c4588ba15be74a04efc4f7da443f6d61f68a9279bc82b73e0cc8d090048e9f87e838ae65dd8d4c")
assert(penc == crypto.privtopub(kenc))
return kenc, penc
*/

#define K "472413e97f1fd58d84e28a559479e6b6902d2e8a0cee672ef38a3a35d263886b"
#define P "7a2aa2951282279dc1171549a7112b07c38c0d97c0fe2c0ae6c4588ba15be74a04efc4f7da443f6d61f68a9279bc82b73e0cc8d090048e9f87e838ae65dd8d4c"

void
test_pubkey(void)
{
	uint8_t k[32], p[64], q[64];

	printf("Test pubkey ");

	hextobin(k, 32, K);
	hextobin(p, 64, P);

	ec_pubkey(q, k);

	if (memcmp(p, q, 64) != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	if (ec_alloc_count != 0) {
		printf("err memory leak %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

#undef K
#undef P

#define K "472413e97f1fd58d84e28a559479e6b6902d2e8a0cee672ef38a3a35d263886b"
#define C "04c4e40c86bb5324e017e598c6d48c19362ae527af8ab21b077284a4656c8735e62d73fb3d740acefbec30ca4c024739a1fcdff69ecaf03301eebf156eb5f17cca6f9d7a7e214a1f3f6e34d1ee0ec00ce0ef7d2b242fbfec0f276e17941f9f1bfbe26de10a15a6fac3cda039904ddd1d7e06e7b96b4878f61860e47f0b84c8ceb64f6a900ff23844f4359ae49b44154980a626d3c73226c19e"
#define P "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

void
test_decrypt(void)
{
	int err, len, msglen;
	uint8_t buf[153];
	uint8_t private_key[32], shared_secret[32];
	uint8_t hmac[32], hmac_key[32];
	uint8_t aes_key[16];
	uint32_t aes_expanded_key[64];

	printf("Test decrypt ");

	hextobin(private_key, 32, K);
	hextobin(buf, 153, C);

	len = 153;

	msglen = len - 65 - 16 - 32; // R, iv, hmac

	// derive shared_secret from private_key and R

	ec_ecdh(shared_secret, private_key, buf + 1);

	// derive aes_key and hmac_key from shared_secret

	kdf(aes_key, hmac_key, shared_secret);

	// check hmac

	hmac_sha256(hmac_key, 32, buf + 65, msglen + 16, hmac);

	err = memcmp(hmac, buf + len - 32, 32);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// decrypt

	aes128ctr_setup(aes_expanded_key, aes_key, buf + 65);
	aes128ctr_encrypt(aes_expanded_key, buf + 65 + 16, msglen);

	err = memcmp(buf + 65 + 16, P, 40);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

void
test_snappy(void)
{
	int err, i, len;
	int inlength, outlength;
	uint8_t buf[1000], inbuf[1000], outbuf[1010];

	printf("Test snappy ");

	// switch stmt because uniform distribution is incompressible

	for (i = 0; i < sizeof buf; i++) {
		switch (random() % 10) {
		case 0:
			buf[i] = ' ';
			break;
		case 1:
		case 2:
		case 3:
		case 4:
			buf[i] = 'a';
			break;
		case 5:
		case 6:
		case 7:
			buf[i] = 'b';
			break;
		case 8:
		case 9:
			buf[i] = 'c';
			break;
		}
	}

	for (len = 1; len <= sizeof buf; len *= 10) {

		outlength = compress(outbuf, sizeof outbuf, buf, len);

		if (outlength == 0) {
			trace();
			return;
		}

		inlength = decompress_nib(inbuf, sizeof inbuf, outbuf, outlength);

		if (len != inlength) {
			trace();
			return;
		}

		err = memcmp(buf, inbuf, len);

		if (err) {
			trace();
			return;
		}
	}

	printf("ok\n");
}
