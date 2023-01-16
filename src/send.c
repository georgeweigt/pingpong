int
send_bytes(int fd, uint8_t *buf, int len)
{
	int err, n;

	while (len) {

		err = wait_for_pollout(fd);

		if (err)
			return -1;

		n = send(fd, buf, len, 0);

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
