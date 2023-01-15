// node simulator for debugging stuff

void
sim(void)
{
	int err, i, len, listen_fd;
	uint8_t *buf;

	struct node A; // Alice
	struct node B; // Bob

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
	wait_for_pollin(listen_fd);
	B.fd = server_connect(listen_fd);
	close(listen_fd);

	// send auth

	send_auth(&A);

	// recv auth

	wait_for_pollin(B.fd);

	buf = receive(B.fd, &len);

	err = recv_auth(&B, buf, len);

	free(buf);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	// send ack

	send_ack(&B);

	// recv ack

	wait_for_pollin(A.fd);

	buf = receive(A.fd, &len);

	err = recv_ack(&A, buf, len);

	free(buf);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	// geth recovers public key from sig in auth msg

	// don't have recovery function so do this

	memcpy(B.auth_public_key, A.auth_public_key, 64);

	// sanity check

	err = memcmp(A.auth_public_key, B.auth_public_key, 64);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	err = memcmp(A.ack_public_key, B.ack_public_key, 64);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	err = memcmp(A.auth_nonce, B.auth_nonce, 32);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	err = memcmp(A.ack_nonce, B.ack_nonce, 32);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	// session setup

	session(&A, 1);
	session(&B, 0);

	// compare aes secrets

	err = memcmp(A.aes_secret, B.aes_secret, 32);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	printf("ok\n");

	close(A.fd);
	close(B.fd);
}

uint8_t *
receive(int fd, int *plen)
{
	int n;
	uint8_t *buf;

	buf = malloc(1280);

	if (buf == NULL)
		exit(1);

	n = recv(fd, buf, 1280, 0);

	if (n < 0) {
		perror("recv");
		exit(1);
	}

	printf("%d bytes received\n", n);

	*plen = n;
	return buf;
}
