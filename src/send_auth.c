void
send_auth(struct node *p)
{
	int len, msglen, n;
	uint8_t *buf, *msg;
	struct atom *list;

	list = auth_body(p);
	msglen = enlength(list);
	msg = malloc(msglen);
	if (msg == NULL)
		exit(1);
	encode(msg, msglen, list);

	buf = ecies_encrypt(p, msg, msglen, 2, &len); // header length = 2

	// set length in big endian

	buf[0] = (len - 2) >> 2;
	buf[1] = len - 2;

	// send

	n = send(p->fd, buf, len, 0);

	if (n < 0)
		perror("send");

	printf("%d bytes sent\n", n);

	free_list(list);
	free(msg);
	free(buf);
}
