// simulates geth

void
sim(void)
{
	int err, i, listen_fd;

	struct node A;
	struct node B;

	memset(&A, 0, sizeof A);
	memset(&B, 0, sizeof B);

	// generate keys

	ec_genkey(A.private_key, A.public_key);
	ec_genkey(B.private_key, B.public_key);

	memcpy(A.far_public_key, B.public_key, 64); // Alice knows Bob's public key
	memcpy(B.far_public_key, A.public_key, 64); // Bob knows Alice's public key

	ec_ecdh(A.static_shared_secret, A.private_key, A.far_public_key);
	ec_ecdh(B.static_shared_secret, B.private_key, B.far_public_key);

	// ephemeral keys, nonces

	ec_genkey(A.auth_private_key, A.auth_public_key);
	ec_genkey(B.auth_private_key, B.auth_public_key);

	ec_genkey(A.ack_private_key, A.ack_public_key);
	ec_genkey(B.ack_private_key, B.ack_public_key);

	for (i = 0; i < 32; i++) {
		A.auth_nonce[i] = random();
		A.ack_nonce[i] = random();
		B.auth_nonce[i] = random();
		B.ack_nonce[i] = random();
	}

	// establish connection

	listen_fd = start_listening(30303);
	A.fd = client_connect("127.0.0.1", 30303);
	err = wait_for_pollin(listen_fd);
	if (err)
		exit(1);
	B.fd = server_connect(listen_fd);
	close(listen_fd);

	// handshake

	printf("sending auth\n");
	err = send_auth(&A);
	if (err)
		exit(1);

	printf("receiving auth\n");
	err = recv_auth(&B);
	if (err)
		exit(1);

	printf("sending ack\n");
	err = send_ack(&B);
	if (err)
		exit(1);

	printf("receiving ack\n");
	err = recv_ack(&A);
	if (err)
		exit(1);

	// geth recovers public key from sig in auth msg

	// don't have recovery function so do this

	memcpy(B.auth_public_key, A.auth_public_key, 64);

	// sanity check

	err = memcmp(A.ack_public_key, B.ack_public_key, 64);
	if (err) {
		trace();
		exit(1);
	}

	err = memcmp(A.auth_nonce, B.auth_nonce, 32);
	if (err) {
		trace();
		exit(1);
	}

	err = memcmp(A.ack_nonce, B.ack_nonce, 32);
	if (err) {
		trace();
		exit(1);
	}

	// session setup

	session_setup(&A, 1);
	session_setup(&B, 0);

	// compare aes secrets

	err = memcmp(A.aes_secret, B.aes_secret, 32);
	if (err) {
		trace();
		exit(1);
	}

	close(A.fd);
	close(B.fd);

	printf("ok\n");
}
