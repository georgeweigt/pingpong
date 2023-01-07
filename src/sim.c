// node simulator

struct node initiator, recipient;

void
sim(void)
{
	int listen_fd;

	ec_genkey(initiator.private_key, initiator.public_key);
	ec_genkey(recipient.private_key, recipient.public_key);

	memcpy(initiator.peer_public_key, recipient.public_key, 64); // Alice knows Bob's public key

	listen_fd = start_listening(30303);
	initiator.fd = client_connect("127.0.0.1", 30303);
	wait_for_pollin(listen_fd);
	recipient.fd = server_connect(listen_fd);
	close(listen_fd);

	printf("fd %d %d\n", initiator.fd, recipient.fd);

	send_auth_msg(&initiator); // send from initiator to recipient

	close(initiator.fd);
	close(recipient.fd);
}
