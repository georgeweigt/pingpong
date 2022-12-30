void
send_ping_packet(int fd, char *src_ip, char *dst_ip, int src_port, int dst_port, uint8_t *public_key_x, uint8_t *public_key_y)
{
	int len, n;
	uint8_t *buf;
	struct sockaddr_in dst_addr;

	buf = malloc(1000); // big enough that no length checks are required

	if (buf == NULL)
		exit(1);

	len = ping_payload(buf, src_ip, dst_ip, src_port, dst_port, public_key_x, public_key_y);

	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
	dst_addr.sin_port = htons(dst_port);

	n = sendto(fd, buf, len, 0, (struct sockaddr *) &dst_addr, sizeof dst_addr);

	if (n < 0)
		perror("sendto");

	free(buf);
}

int
ping_payload(uint8_t *outbuf, char *src_ip, char *dst_ip, int src_port, int dst_port, uint8_t *public_key_x, uint8_t *public_key_y)
{
	int len;
	struct atom *p;

	outbuf[64] = 0x01; // packet type (ping)

	p = ping_data(src_ip, dst_ip, src_port, dst_port);
	len = rlp_encode(outbuf + 65, p);
	free_list(p);

	// signature

	// sign(outbuf + 32, outbuf + 64, len + 1, public_key_x, public_key_y);

	// hash

	// hash(outbuf, outbuf + 32, len + 33);

	return len + 65;
}

struct atom *
ping_data(char *src_ip, char *dst_ip, int src_port, int dst_port)
{
	time_t t;
	in_addr_t src, dst;

	t = time(NULL) + 60;

	src = inet_addr(src_ip); // result is big endian
	dst = inet_addr(dst_ip); // result is big endian

	// version

	push_number(4);

	// from

	push_string((uint8_t *) &src, 4);
	push_number(src_port);
	push_number(0);
	list(3); // [sender-ip, sender-udp-port, sender-tcp-port]

	// to

	push_string((uint8_t *) &dst, 4);
	push_number(dst_port);
	push_number(0);
	list(3); // [recipient-ip, recipient-udp-port, 0]

	// expiration

	push_number(t);

	list(4); // [version, from, to, expiration]

	return pop();
}
