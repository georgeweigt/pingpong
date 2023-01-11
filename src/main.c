int
main(int argc, char *argv[])
{
	aes_init();
	ec_init();

	if (argc > 1 && strcmp(argv[1], "test") == 0) {
		test();
		exit(1);
	}

	nib();
}

void
nib(void)
{
	int i, len;
	uint8_t *buf;
	struct node N;

	// init

	hextobin(N.peer_public_key, 64, GETH_PUBLIC_KEY);

	// create private key

	ec_genkey(N.private_key, N.public_key);

	// derive static_shared_secret

	ec_ecdh(N.static_shared_secret, N.private_key, N.peer_public_key);

	for (i = 0; i < 32; i++)
		N.nonce[i] = random();

	// establish connection

	N.fd = client_connect("127.0.0.1", 30303);

	// send auth

	send_auth(&N);

	// get reply

	wait_for_pollin(N.fd);

	buf = receive(N.fd, &len);

	recv_ack(&N, buf, len);

	free(buf);

	close(initiator.fd);
}
