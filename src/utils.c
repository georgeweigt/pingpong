void
printmem(uint8_t *mem, int n)
{
	int i;
	for (i = 0; i < n; i++)
		printf("%02x", mem[i]);
	printf("\n");
}

void
hextobin(uint8_t *buf, int len, char *str)
{
	int d, i, n;

	n = strlen(str) / 2;

	if (n > len)
		n = len;

	for (i = 0; i < n; i++) {
		sscanf(str + 2 * i, "%2x", &d);
		buf[i] = d;
	}
}