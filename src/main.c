int
main(int argc, char *argv[])
{
	srandom(time(NULL));
	ec_init();
	aes_init();
	keccak_init();

	alloc_count = 0;

	if (argc > 1) {
		if (strcmp(argv[1], "test") == 0)
			test();
		else if (strcmp(argv[1], "sim") == 0)
			sim();
		else
			printf("usage: pingpong | pinpong test | pingpong sim\n");
		return 0;
	}

	pingpong();

	if (alloc_count)
		printf("memory leak\n");
}

void
pingpong(void)
{
	struct node *p;

	p = alloc_mem(sizeof (struct node));

	if (p == NULL)
		return;

	memset(p, 0, sizeof (struct node));

	// connect

	p->fd = client_connect("127.0.0.1", 30303);

	if (p->fd < 0) {
		free_mem(p);
		return;
	}

	pingpong_nib(p);

	close(p->fd);

	free_mem(p->auth_buf);
	free_mem(p->ack_buf);
	free_mem(p);
}

void
pingpong_nib(struct node *p)
{
	int err, i;

	hextobin(p->far_public_key, 64, GETH_PUBLIC_KEY);

	ec_genkey(p->private_key, p->public_key);

	// static_shared_secret = private_key * far_public_key

	ec_ecdh(p->static_shared_secret, p->private_key, p->far_public_key);

	// setup auth msg

	ec_genkey(p->auth_private_key, p->auth_public_key);

	for (i = 0; i < 32; i++)
		p->auth_nonce[i] = randf();

	// handshake

	printf("sending auth\n");
	err = send_auth(p);
	if (err)
		return;

	printf("receiving ack\n");
	err = recv_ack(p);
	if (err)
		return;

	// session setup

	session_setup(p, 1);

	// send and receive hello

	printf("sending hello\n");
	err = send_hello(p);
	if (err)
		return;

	printf("receiving hello\n");
	err = recv_hello(p);
	if (err)
		return;

	printf("receiving status\n");
	err = recv_status(p);
	if (err)
		return;

	printf("sending disconnect\n");
	err = send_disconnect(p);
	if (err)
		return;
}
