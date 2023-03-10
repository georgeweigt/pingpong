int
wait_for_pollin(int fd)
{
	int n;
	struct pollfd pollfd;

	pollfd.fd = fd;
	pollfd.events = POLLIN;

	n = poll(&pollfd, 1, TIMEOUT);

	if (n < 0) {
		trace();
		perror("poll");
		return -1;
	}

	if (n < 1) {
		trace();
		return -1; // timeout
	}

	return 0;
}

int
wait_for_pollout(int fd)
{
	int n;
	struct pollfd pollfd;

	pollfd.fd = fd;
	pollfd.events = POLLOUT;

	n = poll(&pollfd, 1, TIMEOUT);

	if (n < 0) {
		trace();
		perror("poll");
		return -1;
	}

	if (n < 1) {
		trace();
		return -1; // timeout
	}

	return 0;
}

int
start_listening(int port)
{
	int err, fd;
	struct sockaddr_in addr;

	fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0) {
		trace();
		perror("socket");
		return -1;
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
		trace();
		perror("bind");
		close(fd);
		return -1;
	}

	// listen

	err = listen(fd, 10);

	if (err) {
		trace();
		perror("listen");
		close(fd);
		return -1;
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
		trace();
		perror("socket");
		return -1;
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
		trace();
		perror("connect");
		close(fd);
		return -1;
	}
#if 0
	// set nonblocking

	err = fcntl(fd, F_SETFL, O_NONBLOCK);

	if (err) {
		trace();
		perror("fcntl");
		close(fd);
		return -1;
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
		trace();
		perror("accept");
		return -1;
	}

//	printf("connect from %s\n", inet_ntoa(addr.sin_addr));

	return fd;
}
