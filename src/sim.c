// node simulator

struct node initiator, recipient;

void
sim(void)
{
	int listen_fd;

	listen_fd = start_listening(30303);
	initiator.fd = client_connect("127.0.0.1", 30303);
	wait_for_pollin(listen_fd);
	recipient.fd = server_connect(listen_fd);
	close(listen_fd);

	printf("fd %d %d\n", initiator.fd, recipient.fd);

	send_auth_msg(&initiator);

	close(initiator.fd);
	close(recipient.fd);
}
