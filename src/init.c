
struct account account_table[2];

void
init(void)
{
	read_account(account_table + 0, "Account1");
//	print_account(account_table + 0);
}

void
read_account(struct account *p, char *filename)
{
	int d, i;
	char *buf;
	uint8_t hash[32], key[64];

	buf = read_file(filename);

	if (buf == NULL)
		return;

	if (strlen(buf) < 64) {
		free(buf);
		return;
	}

	for (i = 0; i < 32; i++) {
		sscanf(buf + 2 * i, "%2x", &d);
		p->private_key[i] = d;
	}

	free(buf);

	ec_public_key(p->public_key_x, p->public_key_y, p->private_key);

	// account number is hash of public keys

	memcpy(key, p->public_key_x, 32);
	memcpy(key + 32, p->public_key_y, 32);
	keccak256(hash, key, 64);

	for (i = 0; i < 20; i++)
		p->account_number[i] = hash[12 + i];
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

void
print_account(struct account *p)
{
	int i;

	for (i = 0; i < 20; i++)
		printf("%02x", p->account_number[i]);
	printf("\n");

	for (i = 0; i < 32; i++)
		printf("%02x", p->private_key[i]);
	printf("\n");

	for (i = 0; i < 32; i++)
		printf("%02x", p->public_key_x[i]);
	printf("\n");

	for (i = 0; i < 32; i++)
		printf("%02x", p->public_key_y[i]);
	printf("\n");
}
