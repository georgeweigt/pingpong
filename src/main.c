int
main(int argc, char *argv[])
{
	ec_init();
	aes128_init();
	aes256_init();

	if (argc > 1) {
		if (strcmp(argv[1], "test") == 0)
			test();
		else if (strcmp(argv[1], "sim") == 0)
			sim();
		else
			printf("usage: pingpong | pinpong test | pingpong sim\n");
		exit(1);
	}

	nib();
}

void
nib(void)
{
	int err, i;
	struct node *p;

	// setup

	p = malloc(sizeof (struct node));

	if (p == NULL)
		exit(1);

	memset(p, 0, sizeof (struct node));

	hextobin(p->far_public_key, 64, GETH_PUBLIC_KEY);

	ec_genkey(p->private_key, p->public_key);

	// static_shared_secret = private_key * far_public_key

	ec_ecdh(p->static_shared_secret, p->private_key, p->far_public_key);

	// setup auth msg

	ec_genkey(p->auth_private_key, p->auth_public_key);

	for (i = 0; i < 32; i++)
		p->auth_nonce[i] = random();

	// establish connection

	p->fd = client_connect("127.0.0.1", 30303);

	// handshake

	printf("sending auth\n");
	err = send_auth(p);
	if (err)
		exit(1);

	printf("receiving ack\n");
	err = recv_ack(p);
	if (err)
		exit(1);

	// session setup

	session_setup(p, 1);

	// the rest is under construction

	uint8_t block[16];

	err = recv_bytes(p->fd, block, 16);
	if (err)
		exit(1);

	printmem(block, 16); // before decryption

	aes256ctr_encrypt(p->decrypt_state, block, 16); // encrypt does decrypt in ctr mode

	printmem(block, 16); // after decryption

	close(p->fd);
}
