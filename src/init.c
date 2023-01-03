// default keys

#define PRIVATE_KEY "\x62\x55\x58\xec\x2a\xe8\x94\x4a\x19\x49\x5c\xff\x74\xb0\xdc\x51\x66\x33\x48\x73\x64\x3c\x98\x69\x32\x7b\x23\xc6\x6b\x8b\x45\x67"
#define PUBLIC_KEY_X "\x25\xfc\x29\xdd\x14\x62\x64\xc7\x0d\xc2\xda\x19\x59\x60\xc3\x5c\x6d\x05\xbc\x21\xfe\x37\xc7\xc1\x53\xb5\x76\x1b\x86\x4b\x9f\x07"
#define PUBLIC_KEY_Y "\x40\x62\xfa\x26\x63\xb1\x2b\x6f\x30\x89\x90\x2b\xda\x03\x64\xdf\x41\x4c\x10\x5b\xa1\x14\x51\x1b\xd4\x63\xfc\xf7\x35\x35\xf3\x04"

uint8_t account_number[20];
uint8_t private_key[32];
uint8_t public_key_x[32];
uint8_t public_key_y[32];

void
init(void)
{
	int i;

	ec_init();
	memcpy(private_key, PRIVATE_KEY, 32);
	account();
	ec_public_keys(public_key_x, public_key_y, private_key);

	for (i = 0; i < 20; i++)
		printf("%02x", account_number[i]);
	printf("\n");

	for (i = 0; i < 32; i++)
		printf("%02x", private_key[i]);
	printf("\n");

	for (i = 0; i < 32; i++)
		printf("%02x", public_key_x[i]);
	printf("\n");

	for (i = 0; i < 32; i++)
		printf("%02x", public_key_y[i]);
	printf("\n");
}

void
account(void)
{
	int d, i;
	char *buf;

	buf = read_file("Account1");

	if (buf == NULL)
		return;

	if (strlen(buf) < 106) {
		free(buf);
		return;
	}

	for (i = 0; i < 20; i++) {
		sscanf(buf + 2 + 2 * i, "%2x", &d);
		account_number[i] = d;
	}

	for (i = 0; i < 32; i++) {
		sscanf(buf + 42 + 2 * i, "%2x", &d);
		private_key[i] = d;
	}

	free(buf);
}

char *
read_file(char *filename)
{
	int fd, n;
	char *buf;

	fd = open(filename, O_RDONLY, 0);

	if (fd == -1)
		return NULL;

	n = lseek(fd, 0, SEEK_END);

	if (n == -1) {
		close(fd);
		return NULL;
	}

	if (lseek(fd, 0, SEEK_SET) == -1) {
		close(fd);
		return NULL;
	}

	buf = malloc(n + 1);

	if (buf == NULL) {
		close(fd);
		return NULL;
	}

	if (read(fd, buf, n) != n) {
		close(fd);
		free(buf);
		return NULL;
	}

	close(fd);

	buf[n] = '\0';

	return buf;
}
