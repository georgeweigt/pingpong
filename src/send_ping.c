void
send_ping(int fd, char *src_ip, char *dst_ip, int src_port, int dst_port, struct account *acct)
{
	int len, n;
	uint8_t *buf;
	struct sockaddr_in dst_addr;

	buf = ping_payload(src_ip, dst_ip, src_port, dst_port, &len, acct);

	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
	dst_addr.sin_port = htons(dst_port);

	n = sendto(fd, buf, len, 0, (struct sockaddr *) &dst_addr, sizeof dst_addr);

	if (n < 0)
		perror("sendto");

	free(buf);
}

uint8_t *
ping_payload(char *src_ip, char *dst_ip, int src_port, int dst_port, int *plen, struct account *acct)
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
	rencode(buf + HASHLEN + SIGLEN + 1, len, p);
	free_list(p);

	// packet type (ping)

	buf[HASHLEN + SIGLEN] = 0x01;

	// signature

	sign(buf + HASHLEN, buf + HASHLEN + SIGLEN, len + 1, acct);

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
	push_number(src_port); // udp
	push_number(src_port); // tcp
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
test_ping(struct account *acct)
{
	int err, len;
	uint8_t buf[60], hash[32], *payload;

	printf("Test ping ");

	payload = ping_payload("1.2.3.4", "5.6.7.8", 1234, 5678, &len, acct);

	// check length

	if (len < HASHLEN + SIGLEN + 1) {
		free(payload);
		printf("err %s line %d\n", __func__, __LINE__);
		return;
	}

	// check hash

	keccak256(hash, payload + 32, len - 32);
	err = memcmp(hash, payload, 32);
	if (err) {
		free(payload);
		printf("err %s line %d\n", __func__, __LINE__);
		return;
	}

	// check signature

	err = rdecode(payload + HASHLEN, SIGLEN);
	if (err) {
		free(payload);
		printf("err %s line %d\n", __func__, __LINE__);
		return;
	}
	free_list(pop());
	memcpy(buf, "\x19" "Ethereum Signed Message:\n32", 28);
	keccak256(buf + 28, payload + HASHLEN + SIGLEN, len - HASHLEN - SIGLEN);
	keccak256(hash, buf, 60);
	err = ec_verify(hash, payload + R_INDEX, payload + S_INDEX, acct->public_key, acct->public_key + 32);
	if (err) {
		free(payload);
		printf("err %s line %d\n", __func__, __LINE__);
		return;
	}

	// check data

	err = rdecode(payload + HASHLEN + SIGLEN + 1, len - HASHLEN - SIGLEN - 1);
	if (err) {
		free(payload);
		printf("err %s line %d\n", __func__, __LINE__);
		return;
	}
	free_list(pop()); // discard result from rdecode

	free(payload);

	printf("ok\n");
}
