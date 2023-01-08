void
test(void)
{
	test_aes();
	test_sha256();
	test_keccak256();
	test_rencode();
	test_rdecode();
	test_genkey();
	test_pubkey();
	test_kdf();
	test_hmac();
	test_sign(account_table + 0);
	test_ping(account_table + 0);
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
test_aes(void)
{
	int err, i;
	struct node node;
	uint8_t cipher[32], plain[32];

	printf("Test aes ");

	for (i = 0; i < 16; i++)
		node.aes_key[i] = random();

	for (i = 0; i < 32; i++)
		plain[i] = random();

	memcpy(cipher, plain, 32);

	aes128_init(&node);
	aes128_encrypt(&node, cipher, 2);
	aes128_decrypt(&node, cipher, 2);

	err = memcmp(cipher, plain, 32);

	if (err) {
		printf("err %s line %d\n", __func__, __LINE__);
		return;
	}

	printf("ok\n");
}

void
test_rencode(void)
{
	int err, i, n;
	struct atom *p;
	uint8_t buf[256], enc[256];

	printf("Test rencode ");

	// items

	push_string(NULL, 0);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x80", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_string((uint8_t *) "", 0);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x80", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_string((uint8_t *) "a", 1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "a", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_string((uint8_t *) "ab", 2);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 3 || memcmp(buf, "\x82" "ab", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_string((uint8_t *) "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "fffff", 55);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 56 || memcmp(buf, "\xb7" "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "fffff", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_string((uint8_t *) "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "ffffff", 56);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 58 || memcmp(buf, "\xb8\x38" "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "ffffff", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(0);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x00", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x01", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(127);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x7f", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(128);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 2 || memcmp(buf, "\x81\x80", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(255);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 2 || memcmp(buf, "\x81\xff", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(256);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 3 || memcmp(buf, "\x82\x01\x00", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(65535);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 3 || memcmp(buf, "\x82\xff\xff", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(65536);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 4 || memcmp(buf, "\x83\x01\x00\x00", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	// []

	list(0);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\xc0", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	// [[]]

	list(0);
	list(1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 2 || memcmp(buf, "\xc1\xc0", n)) {
		printf("err line %d\n", __LINE__);
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
		printf("err line %d\n", __LINE__);
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
		printf("err on line %d\n", __LINE__);
		return;
	}
	enc[0] = 0xc0 + 55; // 55 byte list
	enc[1] = 0x80 + 54; // 54 byte string
	for (i = 0; i < 54; i++)
		enc[2 + i] = i;
	err = memcmp(buf, enc, 56);
	if (err) {
		printf("err on line %d\n", __LINE__);
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
		printf("err on line %d\n", __LINE__);
		return;
	}
	enc[0] = 0xf8; // list with 1 length byte
	enc[1] = 56;
	enc[2] = 0x80 + 55; // 55 byte string
	for (i = 0; i < 55; i++)
		enc[3 + i] = i;
	err = memcmp(buf, enc, 58);
	if (err) {
		printf("err on line %d\n", __LINE__);
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
		printf("err on line %d\n", __LINE__);
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
		printf("err on line %d\n", __LINE__);
		return;
	}

	if (atom_count) {
		printf("memory leak\n");
		return;
	}

	printf("ok\n");
}

void
test_rdecode(void)
{
	int err, len, n;
	struct atom *p, *q;
	uint8_t buf[2000];

	printf("Test rdecode ");

	// []

	list(0);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err\n");
		return;
	}

	// [[]]

	list(0);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err\n");
		return;
	}

	// [[],[]]

	list(0);
	list(0);
	list(2);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err\n");
		return;
	}

	// "" (empty string)

	push_string(NULL, 0);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err\n");
		return;
	}

	// string

	for (n = 0; n <= 1000; n++) {
		push_string(buf, n);
		p = pop();
		len = rencode(buf, sizeof buf, p);
		err = rdecode(buf, len);
		if (err)
			q = NULL;
		else {
			q = pop();
			err = compare_lists(p, q);
		}
		free_list(p);
		free_list(q);
		if (err) {
			printf("err string, n = %d\n", n);
			return;
		}
	}

	// list of one 54 byte string

	push_string(buf, 54);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err on line %d\n", __LINE__);
		return;
	}

	// list of one 55 byte string

	push_string(buf, 55);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err on line %d\n", __LINE__);
		return;
	}

	// list of one 56 byte string

	push_string(buf, 56);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err on line %d\n", __LINE__);
		return;
	}

	// list of one 57 byte string

	push_string(buf, 57);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err on line %d\n", __LINE__);
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

	err = ec_verify(hash, r, s, public_key, public_key + 32);

	if (err) {
		printf("err %s line %d\n", __func__, __LINE__);
		return;
	}

	if (ec_malloc_count != 0) {
		printf("memory leak err %s line %d\n", __func__, __LINE__);
		return;
	}

	printf("ok\n");
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
	uint8_t e[32], ecdh[32], priv[32], pub[64];

	printf("Test ecdh ");

	hextobin(priv, 32, K);
	hextobin(pub, 32, X);
	hextobin(pub + 32, 32, Y);
	hextobin(e, 32, E);

	ec_ecdh(ecdh, priv, pub);

	if (memcmp(e, ecdh, 32) == 0)
		printf("ok\n");
	else
		printf("err\n");
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
		printf("err %s line %d\n", __func__, __LINE__);
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
		printf("err %s line %d\n", __func__, __LINE__);
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
		printf("err %s line %d\n", __func__, __LINE__);
		return;
	}

	hextobin(kmac, 16, KMAC2);
	hextobin(data, 10, DATA2);
	hextobin(hmac, 32, HMAC2);

	hmac_sha256(kmac, 16, data, 10, out);

	if (memcmp(hmac, out, 32) != 0) {
		printf("err %s line %d\n", __func__, __LINE__);
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
		printf("err %s line %d\n", __func__, __LINE__);
		return;
	}

	if (ec_malloc_count != 0) {
		printf("memory leak err %s line %d\n", __func__, __LINE__);
		return;
	}

	printf("ok\n");
}

#undef K
#undef P
