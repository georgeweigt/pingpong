char *
read_file(char *filename)
{
	int fd, n;
	char *buf;
	off_t t;

	fd = open(filename, O_RDONLY, 0);

	if (fd < 0)
		return NULL;

	t = lseek(fd, 0, SEEK_END);

	if (t < 0 || t > 0x1000000) { // 16 MB max
		close(fd);
		return NULL;
	}

	if (lseek(fd, 0, SEEK_SET)) {
		close(fd);
		return NULL;
	}

	n = (int) t;

	buf = alloc_mem(n + 1);

	if (buf == NULL) {
		close(fd);
		return NULL;
	}

	if (read(fd, buf, n) != n) {
		close(fd);
		free_mem(buf);
		return NULL;
	}

	close(fd);

	buf[n] = '\0';

	return buf;
}
