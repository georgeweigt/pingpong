int
encode(uint8_t *buf, int len, struct atom *p)
{
	if (enlength(p) > len)
		return 0;
	else
		return encode_nib(buf, p);
}

int
encode_nib(uint8_t *buf, struct atom *p)
{
	if (p == NULL || p->length < 0)
		return encode_list(buf, p);
	else
		return encode_string(buf, p);
}

int
encode_list(uint8_t *buf, struct atom *p)
{
	int padlen, sublen;
	uint8_t *t;

	sublen = sublength(p);

	padlen = padlength(p, sublen);

	t = buf + padlen;

	while (p) {
		t += encode_nib(t, p->car);
		p = p->cdr;
	}

	switch (padlen) {
	case 1:
		buf[0] = 0xc0 + sublen;
		break;
	case 2:
		buf[0] = 0xf7 + 1;
		buf[1] = sublen;
		break;
	case 3:
		buf[0] = 0xf7 + 2;
		buf[1] = sublen >> 8;
		buf[2] = sublen;
		break;
	case 4:
		buf[0] = 0xf7 + 3;
		buf[1] = sublen >> 16;
		buf[2] = sublen >> 8;
		buf[3] = sublen;
		break;
	}

	return padlen + sublen;
}

int
encode_string(uint8_t *buf, struct atom *p)
{
	int padlen, sublen;

	if (p->length == 1 && p->string[0] < 0x80) {
		buf[0] = p->string[0];
		return 1;
	}

	sublen = p->length;

	padlen = padlength(p, sublen);

	memcpy(buf + padlen, p->string, sublen);

	switch (padlen) {
	case 0:
		break;
	case 1:
		buf[0] = 0x80 + sublen;
		break;
	case 2:
		buf[0] = 0xb7 + 1;
		buf[1] = sublen;
		break;
	case 3:
		buf[0] = 0xb7 + 2;
		buf[1] = sublen >> 8;
		buf[2] = sublen;
		break;
	case 4:
		buf[0] = 0xb7 + 3;
		buf[1] = sublen >> 16;
		buf[2] = sublen >> 8;
		buf[3] = sublen;
		break;
	}

	return padlen + sublen;
}

void
test_encode(void)
{
	int n;
	struct atom *p;
	static uint8_t buf[100];

	printf("Testing encode ");

	// items

	push_string(NULL, 0);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x80", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_string((uint8_t *) "", 0);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x80", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_string((uint8_t *) "a", 1);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "a", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_string((uint8_t *) "ab", 2);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 3 || memcmp(buf, "\x82" "ab", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_string((uint8_t *) "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "fffff", 55);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 56 || memcmp(buf, "\xb7" "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "fffff", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_string((uint8_t *) "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "ffffff", 56);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 58 || memcmp(buf, "\xb8\x38" "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "ffffff", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(0);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x00", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(1);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x01", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(127);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x7f", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(128);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 2 || memcmp(buf, "\x81\x80", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(255);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 2 || memcmp(buf, "\x81\xff", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(256);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 3 || memcmp(buf, "\x82\x01\x00", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(65535);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 3 || memcmp(buf, "\x82\xff\xff", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	push_number(65536);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 4 || memcmp(buf, "\x83\x01\x00\x00", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	// []

	list(0);
	p = pop();
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\xc0", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	// [[]]

	list(0);
	list(1);
	p = pop();
	n = encode(buf, sizeof buf, p);
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
	n = encode(buf, sizeof buf, p);
	free_list(p);
	if (n != 4 || memcmp(buf, "\xc3\x01\xc0\x02", n)) {
		printf("err line %d\n", __LINE__);
		return;
	}

	if (atom_count) {
		printf("memory leak\n");
		return;
	}

	printf("ok\n");
}
