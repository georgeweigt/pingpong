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

printmem(data, 10);

	// msg id

	nbytes = rdecode_relax(data, len);

	if (nbytes < 0) {
		trace();
		free(buf);
		return -1;
	}

	q = pop(); // list from rdecode
	print_list(q);
	free_list(q);

	// msg data

	data += nbytes;
	len -= nbytes;

	nbytes = rdecode_relax(data, len);

	if (nbytes < 0) {
		trace();
		free(buf);
		return -1;
	}

	q = pop(); // list from rdecode
	print_list(q);
	print_client_id(q);
	free_list(q);

	free(buf);

	return 0;
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
