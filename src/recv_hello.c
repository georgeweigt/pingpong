int
recv_hello(struct node *p)
{
	int len, nbytes;
	uint8_t *buf, *data;
	struct atom *q;

	buf = recv_frame(p);

	if (buf == NULL)
		return -1;

	data = buf + 32; // skip over header

	len = buf[0] << 16 | buf[1] << 8 | buf[2]; // length of data

	// verify that msg id is the empty string ""

	if (len < 1 || data[0] != 0x80) {
		trace();
		free(buf);
		return -1; // not hello msg
	}

	data += 1;
	len -= 1;

	// msg data

	nbytes = rdecode_relax(data, len);

	if (nbytes < 0) {
		trace();
		free(buf);
		return -1; // fmt error
	}

	q = pop(); // list from rdecode
	recv_hello_data(q);
	free_list(q);

	free(buf);

	return 0;
}

void
recv_hello_data(struct atom *q)
{
//	print_list(q);
	print_client_id(q);
	print_capabilities(q);
}

void
print_client_id(struct atom *p)
{
	int i;

	if (p == NULL || p->cdr == NULL)
		return;

	p = p->cdr->car;

	if (p == NULL || p->length == -1)
		return;

	for (i = 0; i < p->length; i++)
		printf("%c", p->string[i]);

	printf("\n");
}

void
print_capabilities(struct atom *p)
{
	int i, n;
	struct atom *q, *q1, *q2;

	if (p == NULL || p->cdr == NULL || p->cdr->cdr == NULL)
		return;

	p = p->cdr->cdr->car;

	while (p) {

		q = p->car;

		if (q == NULL || q->cdr == NULL)
			return;

		q1 = q->car; // capability
		q2 = q->cdr->car; // version

		if (q1 == NULL || q2 == NULL)
			return;

		if (q1->length < 0 || q2->length < 0)
			return;

		// print capability

		for (i = 0; i < q1->length; i++)
			printf("%c", q1->string[i]);

		printf("/");

		// version

		n = 0;

		for (i = 0; i < q2->length; i++)
			n = 10 * n + q2->string[i];

		printf("%d\n", n);

		p = p->cdr;
	}
}
