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
	int err, i, len;
	uint8_t *buf;
	struct node N;

	memset(&N, 0, sizeof N);

	hextobin(N.far_public_key, 64, GETH_PUBLIC_KEY);

	// generate keyset

	ec_genkey(N.private_key, N.public_key);

	// static_shared_secret = private_key * far_public_key

	ec_ecdh(N.static_shared_secret, N.private_key, N.far_public_key);

	// ephemeral key, nonce

	ec_genkey(N.auth_private_key, N.auth_public_key);

	for (i = 0; i < 32; i++)
		N.auth_nonce[i] = random();

	// establish connection

	N.fd = client_connect("127.0.0.1", 30303);

	// send auth

	send_auth(&N);

	// get ack

	wait_for_pollin(N.fd);

	buf = receive(N.fd, &len);

	err = recv_ack(&N, buf, len);

	free(buf);

	if (err) {
		printf("recv ack err\n");
		exit(1);
	}

	// session setup

	session(&N, 1);

	// wait for hello

	wait_for_pollin(N.fd);

	buf = receive(N.fd, &len);

	// the rest is under construction

	printmem(buf, 16); // before decryption

	aes256ctr_encrypt(N.decrypt_state, buf, 16); // encrypt does decrypt in ctr mode

	printmem(buf, 16); // after decryption

	close(N.fd);
}
