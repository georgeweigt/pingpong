int
main()
{
	init();
	selftest();
	stub();
}

#define TIMEOUT 10000 // poll timeout in milliseconds

#if 0
#define SRC_IP "98.161.224.53"
#define DST_IP "18.168.182.86"
#else
#define SRC_IP "127.0.0.1"
#define DST_IP "127.0.0.1"
#endif

#define SRC_PORT 30000
#define DST_PORT 30303

void
stub(void)
{
	int err, fd1, fd2, n;
	struct sockaddr_in addr;
	struct pollfd pollfd;
	socklen_t addrlen;
	static char buf[1200];

	fd1 = socket(PF_INET, SOCK_DGRAM, 0);

	if (fd1 < 0) {
		perror("socket");
		exit(1);
	}

	fd2 = socket(PF_INET, SOCK_DGRAM, 0);

	if (fd2 < 0) {
		perror("socket");
		exit(1);
	}

	// bind (sets src port also)

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(SRC_PORT);

	err = bind(fd1, (struct sockaddr *) &addr, sizeof addr);

	if (err) {
		perror("bind");
		exit(1);
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(DST_PORT);

	err = bind(fd2, (struct sockaddr *) &addr, sizeof addr);

	if (err) {
		perror("bind");
		exit(1);
	}

	send_ping(fd1, SRC_IP, DST_IP, SRC_PORT, DST_PORT, account_table + 0);

	pollfd.fd = fd2;
	pollfd.events = POLLIN;

	n = poll(&pollfd, 1, TIMEOUT);

	if (n < 0) {
		perror("poll");
		exit(1);
	}

	if (n < 1 || (pollfd.revents & POLLIN) == 0) {
		printf("poll timeout\n");
		exit(1);
	}

	addrlen = sizeof addr;

	n = recvfrom(fd2, buf, sizeof buf, 0, (struct sockaddr *) &addr, &addrlen);

	if (n < 0) {
		perror("recvfrom");
		exit(1);
	}

	printf("%d bytes received\n", n);
}
