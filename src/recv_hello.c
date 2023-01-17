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
	print_list(q);
	print_client_id(q);
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
