#define GETH_PUBLIC_KEY "1ecbbdb04f54b68d99a9fb0d60786d29164ffe9776bad9118ec896f2764ec9f711ec2e6f8e0e21c1f0f9abe4515c45949e6bf776d84b54d08f7c32de60e8c480"

void
node(void)
{
	int i, len;
	uint8_t *buf;

	// init

	ec_genkey(initiator.private_key, initiator.public_key);

	hextobin(initiator.peer_public_key, 64, GETH_PUBLIC_KEY);

	ec_ecdh(initiator.static_shared_secret, initiator.private_key, initiator.peer_public_key);

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
