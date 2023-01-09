int
main()
{
	aes_init();
	ec_init();
	init();
	test();

	node();
//	sim();
}

#define TIMEOUT 10000 // poll timeout in milliseconds

#define SRC_IP "127.0.0.1"
#define DST_IP "127.0.0.1"

#define SRC_PORT 29000
#define DST_PORT 30303

void
stub(void)
{
	int err, fd0, fd1, fd2, i, n;
	struct sockaddr_in addr;
	struct pollfd pollfd[2];
	socklen_t addrlen;
	static uint8_t buf[1200];

	fd0 = start_listening(SRC_PORT);

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
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(SRC_PORT);

	err = bind(fd1, (struct sockaddr *) &addr, sizeof addr);

	if (err) {
		perror("bind");
		exit(1);
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(DST_PORT);

	err = bind(fd2, (struct sockaddr *) &addr, sizeof addr);

	if (err) {
		perror("bind");
		exit(1);
	}

	send_ping(fd1, SRC_IP, DST_IP, SRC_PORT, DST_PORT, account_table + 0);

	pollfd[0].fd = fd0;
	pollfd[0].events = POLLIN;

	pollfd[1].fd = fd2;
	pollfd[1].events = POLLIN;

	for (;;) {

		n = poll(pollfd, 2, TIMEOUT);

		if (n < 0) {
			perror("poll");
			exit(1);
		}

		if (n < 1) {
			printf("poll timeout\n");
			exit(1);
		}

		if (pollfd[1].revents & POLLIN) {
			addrlen = sizeof addr;
			n = recvfrom(fd2, buf, sizeof buf, 0, (struct sockaddr *) &addr, &addrlen);
			if (n < 0) {
				perror("recvfrom");
				exit(1);
			}
			printf("%d bytes received\n", n);
			for (i = 0; i < n; i++)
				printf("%02x", buf[i]);
			printf("\n");
		}
	}
}

int
start_listening(int port)
{
	int err, fd;
	struct sockaddr_in addr;

	fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0) {
		perror("socket");
		exit(1);
	}

	// struct sockaddr {
	//         unsigned short   sa_family;    // address family, AF_xxx
	//         char             sa_data[14];  // 14 bytes of protocol address
	// };
	//
	// struct sockaddr_in {
	//         short            sin_family;   // e.g. AF_INET, AF_INET6
	//         unsigned short   sin_port;     // e.g. htons(3490)
	//         struct in_addr   sin_addr;     // see struct in_addr, below
	//         char             sin_zero[8];  // zero this if you want to
	// };
	//
	// struct in_addr {
	//         unsigned long s_addr;          // load with inet_pton()
	// };

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	err = bind(fd, (struct sockaddr *) &addr, sizeof addr);

	if (err) {
		perror("bind");
		exit(1);
	}

	// listen

	err = listen(fd, 10);

	if (err) {
		perror("listen");
		exit(1);
	}

	return fd;
}

int
client_connect(char *ipaddr, int portnumber)
{
	int err, fd;
	struct sockaddr_in addr;

	// https://github.com/openbsd/src/blob/master/include/netdb.h
	//
	// /*
	//  * Structures returned by network data base library.  All addresses are
	//  * supplied in host order, and returned in network order (suitable for
	//  * use in system calls).
	//  */
	// struct  hostent {
	//         char    *h_name;        /* official name of host */
	//         char    **h_aliases;    /* alias list */
	//         int     h_addrtype;     /* host address type */
	//         int     h_length;       /* length of address */
	//         char    **h_addr_list;  /* list of addresses from name server */
	// #define h_addr  h_addr_list[0]  /* address, for backward compatibility */
	// };

	// open socket

	fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0) {
		perror("socket");
		exit(1);
	}

	// struct sockaddr {
	//         unsigned short   sa_family;    // address family, AF_xxx
	//         char             sa_data[14];  // 14 bytes of protocol address
	// };
	//
	// struct sockaddr_in {
	//         short            sin_family;   // e.g. AF_INET, AF_INET6
	//         unsigned short   sin_port;     // e.g. htons(3490)
	//         struct in_addr   sin_addr;     // see struct in_addr, below
	//         char             sin_zero[8];  // zero this if you want to
	// };
	//
	// struct in_addr {
	//         unsigned long s_addr;          // load with inet_pton()
	// };

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ipaddr);
	addr.sin_port = htons(portnumber);

	err = connect(fd, (struct sockaddr *) &addr, sizeof addr);

	if (err) {
		close(fd);
		perror("connect");
		exit(1);
	}

	// set nonblocking
#if 0
	err = fcntl(fd, F_SETFL, O_NONBLOCK);

	if (err == -1) {
		close(fd);
		perror("fcntl");
		exit(1);
	}
#endif
	return fd;
}

int
server_connect(int listen_fd)
{
	int fd;
	struct sockaddr_in addr;
	socklen_t addrlen;

	addrlen = sizeof addr;
	fd = accept(listen_fd, (struct sockaddr *) &addr, &addrlen);

	if (fd < 0) {
		perror("accept");
		exit(1);
	}

//	printf("connect from %s\n", inet_ntoa(addr.sin_addr));

	return fd;
}

void
wait_for_pollin(int fd)
{
	int n;
	struct pollfd pollfd;

	pollfd.fd = fd;
	pollfd.events = POLLIN;

	n = poll(&pollfd, 1, TIMEOUT);

	if (n < 0) {
		perror("poll");
		exit(1);
	}

	if (n < 1) {
		printf("timeout\n");
		exit(1);
	}
}

void
printmem(uint8_t *mem, int n)
{
	int i;
	for (i = 0; i < n; i++)
		printf("%02x", mem[i]);
	printf("\n");
}

void
hextobin(uint8_t *buf, int len, char *str)
{
	int d, i, n;

	n = strlen(str) / 2;

	if (n > len)
		n = len;

	for (i = 0; i < n; i++) {
		sscanf(str + 2 * i, "%2x", &d);
		buf[i] = d;
	}
}
