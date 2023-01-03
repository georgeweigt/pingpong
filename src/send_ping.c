void
send_ping(int fd, char *src_ip, char *dst_ip, int src_port, int dst_port)
{
	int len, n;
	uint8_t *buf;
	struct sockaddr_in dst_addr;

	buf = ping_payload(src_ip, dst_ip, src_port, dst_port, &len);

	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
	dst_addr.sin_port = htons(dst_port);

	n = sendto(fd, buf, len, 0, (struct sockaddr *) &dst_addr, sizeof dst_addr);

	if (n < 0)
		perror("sendto");

	free(buf);
}

uint8_t *
ping_payload(char *src_ip, char *dst_ip, int src_port, int dst_port, int *plen)
{
	int len;
	uint8_t *buf;
	struct atom *p;

	// data

	p = ping_data(src_ip, dst_ip, src_port, dst_port);
	len = enlength(p);
	buf = malloc(HASHLEN + SIGLEN + len + 1);
	if (buf == NULL)
		exit(1);
	encode(buf + HASHLEN + SIGLEN + 1, len, p);
	free_list(p);

	// packet type (ping)

	buf[HASHLEN + SIGLEN] = 0x01;

	// signature

	sign(buf + HASHLEN, buf + HASHLEN + SIGLEN, len + 1);

	// hash

	keccak256(buf, buf + HASHLEN, SIGLEN + len + 1);

	*plen = HASHLEN + SIGLEN + len + 1;

	return buf;
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
	int err, len, n;
	uint8_t *buf, hash[32], m[60];

	printf("Testing ping_payload");

	buf = ping_payload("1.2.3.4", "5.6.7.8", 1234, 5678, &len);

	// check length

	printf(" length %s", len < HASHLEN + SIGLEN + 1 ? "err" : "ok");

	// check hash

	printf(" hash ");
	keccak256(hash, buf + 32, len - 32);
	err = memcmp(buf, hash, 32);
	printf("%s", err ? "err" : "ok");

	// check signature

	printf(" signature ");
	if (decode_check(buf + HASHLEN, SIGLEN) == SIGLEN) {
		memcpy(m, "\x19" "Ethereum Signed Message:\n32", 28);
		keccak256(m + 28, buf + HASHLEN + SIGLEN, len - HASHLEN - SIGLEN);
		keccak256(hash, m, 60);
		err = ec_verify(hash, buf + R_INDEX, buf + S_INDEX, public_key_x, public_key_y);
	} else
		err = 1;
	printf("%s", err ? "err" : "ok");

	// check data

	printf(" data ");
	n = decode_check(buf + HASHLEN + SIGLEN + 1, len - HASHLEN - SIGLEN - 1);
	printf("%s", n == len - HASHLEN - SIGLEN - 1 ? "ok" : "err");

	printf("\n");

	free(buf);
}
