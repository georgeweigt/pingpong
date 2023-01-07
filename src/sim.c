// node p2p simulator

struct session initiator_session, recipient_session;

void
sim(void)
{
	int listen_fd, initiator_fd, recipient_fd;

	listen_fd = start_listening(30303);
	initiator_fd = client_connect("127.0.0.1", 30303);
	wait_for_pollin(listen_fd);
	recipient_fd = server_connect(listen_fd);

	close(listen_fd);
	close(initiator_fd);
	close(recipient_fd);
}
