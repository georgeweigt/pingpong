// node simulator for debugging stuff

void
sim(void)
{
	int err, len, listen_fd;
	uint8_t *buf;

	struct node initiator; // Alice
	struct node recipient; // Bob

	memset(&initiator, 0, sizeof initiator);
	memset(&recipient, 0, sizeof recipient);

	// generate keys

	ec_genkey(initiator.private_key, initiator.public_key);
	ec_genkey(recipient.private_key, recipient.public_key);

	memcpy(initiator.geth_public_key, recipient.public_key, 64); // Alice knows Bob's public key
	memcpy(recipient.geth_public_key, initiator.public_key, 64); // Bob knows Alice's public key

	ec_ecdh(initiator.static_shared_secret, initiator.private_key, initiator.geth_public_key);
	ec_ecdh(recipient.static_shared_secret, recipient.private_key, recipient.geth_public_key);

	// establish connection

	listen_fd = start_listening(30303);
	initiator.fd = client_connect("127.0.0.1", 30303);
	wait_for_pollin(listen_fd);
	recipient.fd = server_connect(listen_fd);
	close(listen_fd);

	send_auth(&initiator); // Alice sends to Bob

	wait_for_pollin(recipient.fd);

	buf = receive(recipient.fd, &len); // Bob receives from Alice

	err = receive_auth(&recipient, buf, len);

	free(buf);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	// compare keys

	err = memcmp(initiator.public_key, recipient.geth_public_key, 64);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	printf("ok\n");

	close(initiator.fd);
	close(recipient.fd);
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
