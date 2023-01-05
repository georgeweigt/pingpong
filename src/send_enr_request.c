void
send_enr_request(int fd, char *dst_ip, int dst_port, struct account *acct)
{
	int len, n;
	uint8_t *buf;
	struct sockaddr_in dst_addr;

	buf = enr_request_payload(&len, acct);

	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
	dst_addr.sin_port = htons(dst_port);

	n = sendto(fd, buf, len, 0, (struct sockaddr *) &dst_addr, sizeof dst_addr);

	if (n < 0)
		perror("sendto");

	free(buf);
}

uint8_t *
enr_request_payload(int *plen, struct account *acct)
{
	int len;
	uint8_t *buf;
	struct atom *p;

	// data

	p = enr_request_data();
	len = enlength(p);
	buf = malloc(HASHLEN + SIGLEN + len + 1);
	if (buf == NULL)
		exit(1);
	encode(buf + HASHLEN + SIGLEN + 1, len, p);
	free_list(p);

	// packet type (enr request)

	buf[HASHLEN + SIGLEN] = 0x05;

	// signature

	sign(buf + HASHLEN, buf + HASHLEN + SIGLEN, len + 1, acct);

	// hash

	keccak256(buf, buf + HASHLEN, SIGLEN + len + 1);

	*plen = HASHLEN + SIGLEN + len + 1;

	return buf;
}

struct atom *
enr_request_data(void)
{
	time_t t;
	t = time(NULL) + 60;
	push_number(t);
	list(1);
	return pop();
}
