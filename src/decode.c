// returns result on stack or -1 on error

int
decode(uint8_t *buf, int length)
{
	int n = decode_nib(buf, length);
	if (n == -1)
		return -1; // decode error
	else if (n < length) {
		free_list(pop()); // buffer underrun, discard result
		return -1;
	} else
		return 0; // ok
}

// returns number of bytes read from buf or -1 on error

int
decode_nib(uint8_t *buf, int length)
{
	int err, i, n;
	uint64_t len;
	struct atom *p;

	if (length < 1)
		return -1;

	if (buf[0] < 0x80) {
		p = alloc_atom(1);
		p->string[0] = buf[0];
		push(p);
		return 1;
	}

	// string 0..55 bytes

	if (buf[0] < 0xb8) {
		len = buf[0] - 0x80;
		if (len + 1 > length)
			return -1;
		p = alloc_atom(len);
		memcpy(p->string, buf + 1, len);
		push(p);
		return len + 1;
	}

	// string > 55 bytes

	if (buf[0] < 0xc0) {
		n = buf[0] - 0xb7; // number of length bytes 1..8
		if (n + 1 > length)
			return -1;
		len = 0;
		for (i = 0; i < n; i++)
			len = (len << 8) | buf[i + 1];
		if (len > 1000000 || len + n + 1 > length) // cap at 1,000,000 bytes
			return -1;
		p = alloc_atom(len);
		memcpy(p->string, buf + n + 1, len);
		push(p);
		return len + n + 1;
	}

	// list 0..55 bytes

	if (buf[0] < 0xf8) {
		len = buf[0] - 0xc0;
		if (len + 1 > length)
			return -1;
		err = decode_list(buf + 1, len);
		if (err)
			return -1;
		else
			return len + 1;
	}

	// list > 55 bytes

	n = buf[0] - 0xf7; // number of length bytes 1..8
	if (n + 1 > length)
		return -1;
	len = 0;
	for (i = 0; i < n; i++)
		len = (len << 8) | buf[i + 1];
	if (len > 1000000 || len + n + 1 > length) // cap at 1,000,000 bytes
		return -1;
	err = decode_list(buf + n + 1, len);
	if (err)
		return -1;
	else
		return len + n + 1;
}

// if length is zero then NULL is pushed (empty list)

int
decode_list(uint8_t *buf, int length)
{
	int h, len, n;
	h = tos;
	len = 0;
	while (len < length) {
		n = decode_nib(buf + len, length - len);
		if (n < 0) {
			pop_all(tos - h);
			return -1; // err
		}
		len += n;
	}
	list(tos - h);
	return 0; // ok
}

void
test_decode(void)
{
	int err, len, n;
	struct atom *p, *q;
	uint8_t buf[2000];

	printf("Testing decode ");

	// []

	list(0);
	p = pop();
	len = encode(buf, sizeof buf, p);
	err = decode(buf, len);
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
	len = encode(buf, sizeof buf, p);
	err = decode(buf, len);
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
	len = encode(buf, sizeof buf, p);
	err = decode(buf, len);
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
	len = encode(buf, sizeof buf, p);
	err = decode(buf, len);
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
		len = encode(buf, sizeof buf, p);
		err = decode(buf, len);
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
	len = encode(buf, sizeof buf, p);
	err = decode(buf, len);
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
	len = encode(buf, sizeof buf, p);
	err = decode(buf, len);
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
	len = encode(buf, sizeof buf, p);
	err = decode(buf, len);
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
	len = encode(buf, sizeof buf, p);
	err = decode(buf, len);
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
