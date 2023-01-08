#define X "1ecbbdb04f54b68d99a9fb0d60786d29164ffe9776bad9118ec896f2764ec9f7"
#define Y "11ec2e6f8e0e21c1f0f9abe4515c45949e6bf776d84b54d08f7c32de60e8c480"

void
selftest(void)
{
	printf("test public key %s\n", test_public_key(X, Y) ? "err" : "ok");
	test_aes();
	test_sha256();
	test_keccak256();
	test_rencode();
	test_rdecode();
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

void
test_rencode(void)
{
	int err, i, n;
	struct atom *p;
	uint8_t buf[256], enc[256];

	printf("Testing rencode ");

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

	printf("Testing rdecode ");

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
