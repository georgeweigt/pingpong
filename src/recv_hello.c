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

	// msg id

	nbytes = rdecode_relax(data, len);

printf("msg id nbytes = %d\n", nbytes);

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

printf("msg data nbytes = %d\n", nbytes);

	if (nbytes < 0) {
		trace();
		free(buf);
		return -1;
	}

	q = pop(); // list from rdecode
	print_list(q);
	free_list(q);

	free(buf);

	return 0;
}
