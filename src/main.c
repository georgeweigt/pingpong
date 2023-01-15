int
main(int argc, char *argv[])
{
	ec_init();
	aes128_init();
	aes256_init();

	if (argc > 1 && strcmp(argv[1], "test") == 0) {
		test();
		exit(1);
	}

	nib();
}

void
nib(void)
{
	int err, len;
	uint8_t *buf;
	struct node N;

	memset(&N, 0, sizeof N);

	hextobin(N.geth_public_key, 64, GETH_PUBLIC_KEY);

	// generate keyset

	ec_genkey(N.private_key, N.public_key);

	// static_shared_secret = private_key * geth_public_key

	ec_ecdh(N.static_shared_secret, N.private_key, N.geth_public_key);

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

	secrets(&N);

	macs(&N);

	// wait for hello

	wait_for_pollin(N.fd);

	buf = receive(N.fd, &len);

	close(N.fd);

	printmem(buf, 16);

	uint8_t iv[16];
	memset(iv, 0, 16);

	aes256ctr_setup(N.encrypt_state, N.aes_secret, iv);
	aes256ctr_setup(N.decrypt_state, N.aes_secret, iv);

	aes256ctr_encrypt(N.decrypt_state, buf, 16); // encrypt does decrypt in ctr mode

	printmem(buf, 16);
}
