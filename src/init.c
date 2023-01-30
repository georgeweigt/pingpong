
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
	char *buf;
	uint8_t hash[32];

	buf = read_file(filename);

	if (buf == NULL)
		return;

	if (strlen(buf) < 64) {
		free_mem(buf);
		return;
	}

	hextobin(p->private_key, 32, buf);

	free_mem(buf);

	ec_pubkey(p->public_key, p->private_key);

	// account number is hash of public keys

	keccak256(hash, p->public_key, 64);

	memcpy(p->account_number, hash + 12, 20);
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
		printf("%02x", p->public_key[i]);
	printf("\n");

	for (i = 0; i < 32; i++)
		printf("%02x", p->public_key[32 + i]);
	printf("\n");
}
