void
test_snappy(void)
{
	int err, i, len, n;
	uint8_t buf[1000], *c, *d;

	printf("Test snappy ");

	for (i = 0; i < sizeof buf; i++)
		buf[i] = random() % 10 + 'a';

	for (len = 1; len <= sizeof buf; len *= 10) {

		c = compress(buf, len, &n);

		if (c == NULL) {
			trace();
			return;
		}

		d = decompress(c, n, &n);

		if (d == NULL) {
			trace();
			free(c);
			return;
		}

		if (n != len) {
			trace();
			free(c);
			free(d);
			return;
		}

		err = memcmp(buf, d, len);

		if (err) {
			trace();
			free(c);
			free(d);
			return;
		}

		free(c);
		free(d);
	}

	printf("ok\n");
}
