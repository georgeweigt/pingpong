#define GETH_PUBLIC_KEY "1ecbbdb04f54b68d99a9fb0d60786d29164ffe9776bad9118ec896f2764ec9f711ec2e6f8e0e21c1f0f9abe4515c45949e6bf776d84b54d08f7c32de60e8c480"

void
node(void)
{
	int d, i, len;
	uint8_t *buf;
	char *geth_public_key = GETH_PUBLIC_KEY;

	// init

	ec_genkey(initiator.private_key, initiator.public_key);

	for (i = 0; i < 64; i++) {
		sscanf(geth_public_key + 2 * i, "%2x", &d);
		initiator.peer_public_key[i] = d;
	}

	for (i = 0; i < 32; i++)
		initiator.nonce[i] = random();

	// establish connection

	initiator.fd = client_connect("127.0.0.1", 30303);

	// send auth

	send_auth(&initiator);

	// get reply

	wait_for_pollin(initiator.fd);

	buf = receive(initiator.fd, &len);


	close(initiator.fd);
}
