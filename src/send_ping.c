void
send_ping(int fd, char *src_ip, char *dst_ip, int src_port, int dst_port, uint8_t *private_key)
{
	int len, n;
	uint8_t *buf;
	struct sockaddr_in dst_addr;

	buf = malloc(UDPBUFLEN);

	if (buf == NULL)
		exit(1);

	len = ping_payload(buf, src_ip, dst_ip, src_port, dst_port, private_key);

	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
	dst_addr.sin_port = htons(dst_port);

	n = sendto(fd, buf, len, 0, (struct sockaddr *) &dst_addr, sizeof dst_addr);

	if (n < 0)
		perror("sendto");

	free(buf);
}

int
ping_payload(uint8_t *outbuf, char *src_ip, char *dst_ip, int src_port, int dst_port, uint8_t *private_key)
{
	int datalen;
	struct atom *p;

	outbuf[HASHLEN + SIGLEN] = 0x01; // packet type (ping)

	// data

	p = ping_data(src_ip, dst_ip, src_port, dst_port);
	datalen = encode(outbuf + HASHLEN + SIGLEN + 1, p);
	free_list(p);

	// signature

	sign(outbuf + HASHLEN, outbuf + HASHLEN + SIGLEN, datalen + 1, private_key);

	// hash

	keccak256(outbuf, outbuf + HASHLEN, SIGLEN + 1 + datalen);

	return HASHLEN + SIGLEN + 1 + datalen; // payload length
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

void
test_ping_payload(void)
{
	int err, len;
	uint8_t *buf, hash[32], m[60];

	printf("Testing ping_payload\n");

	buf = malloc(UDPBUFLEN);

	len = ping_payload(buf, "1.2.3.4", "5.6.7.8", 1234, 5678, private_key);

	// check length

	printf("checking length %s\n", len == 129 ? "ok" : "err");

	// check hash

	printf("checking hash ");
	keccak256(hash, buf + 32, len - 32);
	err = memcmp(buf, hash, 32);
	printf("%s\n", err ? "err" : "ok");

	// check signature

	printf("checking signature ");
	memcpy(m, "\x19" "Ethereum Signed Message:\n32", 28);
	keccak256(m + 28, buf + HASHLEN + SIGLEN, len - HASHLEN - SIGLEN);
	keccak256(hash, m, 60);
	err = ec_verify(hash, buf + R_INDEX, buf + S_INDEX, public_key_x, public_key_y);
	printf("%s\n", err ? "err" : "ok");

	free(buf);
}
