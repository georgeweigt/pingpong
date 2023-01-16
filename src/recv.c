// receives AUTH or ACK

uint8_t *
recv_msg(int fd)
{
	int err, len;
	uint8_t *buf, prefix[2];

	err = recv_bytes(fd, prefix, 2);

	if (err)
		return NULL;

	len = prefix[0] << 8 | prefix[1]; // length from prefix

	if (len < 1 || len > 1200) {
		trace();
		return NULL;
	}

	buf = malloc(len + 2);

	if (buf == NULL)
		exit(1);

	buf[0] = prefix[0];
	buf[1] = prefix[1];

	err = recv_bytes(fd, buf + 2, len);

	if (err) {
		free(buf);
		return NULL;
	}

	return buf;
}

// receives len bytes in buf

int
recv_bytes(int fd, uint8_t *buf, int len)
{
	int n;
	struct pollfd pollfd;

	pollfd.fd = fd;
	pollfd.events = POLLIN;

	while (len) {

		n = poll(&pollfd, 1, TIMEOUT);

		if (n < 0) {
			trace();
			perror("poll");
			return -1;
		}

		if (n < 1) {
			trace();
			return -1; // timeout
		}

		n = recv(fd, buf, len, 0);

		if (n < 0) {
			trace();
			perror("recv");
			return -1;
		}

		if (n < 1) {
			trace();
			return -1; // disconnect
		}

		buf += n;
		len -= n;
	}

	return 0;
}
