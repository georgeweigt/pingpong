
// returns length or -1 on error

int
decode_check(uint8_t *buf, int length)
{
	int err, i, len, n;
	uint64_t u;

	if (length == 0)
		return 0;

	if (buf[0] < 0x80)
		return 1;

	// string 0..55 bytes

	if (buf[0] < 0xb8) {
		len = 1 + buf[0] - 0x80;
		return len <= length ? len : -1;
	}

	// string > 55 bytes

	if (buf[0] < 0xc0) {

		n = buf[0] - 0xb7; // number of length bytes 1..8

		if (n + 1 > length)
			return -1;

		u = 0;

		for (i = 0; i < n; i++)
			u = (u << 8) | buf[i + 1];

		if (u > 65535)
			return -1; // not accepting insane lengths

		len = n + u + 1;

		return len > length ? -1 : len;
	}

	// list 0..55 bytes

	if (buf[0] < 0xf8) {

		len = 1 + buf[0] - 0xc0;

		if (len > length)
			return -1;

		err = decode_check_list(buf + 1, len - 1);

		return err ? -1 : len;
	}

	// list > 55 bytes

	n = buf[0] - 0xf7; // number of length bytes 1..8

	if (n + 1 > length)
		return -1;

	u = 0;

	for (i = 0; i < n; i++)
		u = (u << 8) | buf[i + 1];

	if (u > 65535)
		return -1; // not accepting insane lengths

	len = n + u + 1;

	err = decode_check_list(buf + n + 1, len - n - 1);

	return err ? -1 : len;
}

int
decode_check_list(uint8_t *buf, int length)
{
	int len = 0, n;

	while (len < length) {

		n = decode_check(buf + len, length - len);

		if (n == -1)
			return -1;

		len += n;
	}

	return 0;
}
