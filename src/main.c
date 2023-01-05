int
main()
{
	init();
	selftest();
	stub();
}

#define TIMEOUT 60000 // poll timeout in milliseconds

#define SRC_IP "98.161.224.53"
#define DST_IP "18.168.182.86"
#define SRC_PORT 7000
#define DST_PORT 30303

void
stub(void)
{
	int err, fd, n;
	struct sockaddr_in addr;
	struct pollfd pollfd;
	socklen_t addrlen;
	static char buf[1200];

	// create socket

	fd = socket(PF_INET, SOCK_DGRAM, 0);

	if (fd < 0) {
		perror("socket");
		exit(1);
	}

	// set src port

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(SRC_PORT);

	err = bind(fd, (struct sockaddr *) &addr, sizeof addr);

	if (err) {
		perror("bind");
		exit(1);
	}

	send_ping(fd, SRC_IP, DST_IP, SRC_PORT, DST_PORT, account_table + 0);

	pollfd.fd = fd;
	pollfd.events = POLLIN;

	n = poll(&pollfd, 1, TIMEOUT);

	if (n < 0) {
		perror("poll");
		exit(1);
	}

	if (n < 1 || (pollfd.revents & POLLIN) == 0) {
		printf("pollfd?\n");
		exit(1);
	}

	addrlen = sizeof addr;

	n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *) &addr, &addrlen);

	if (n < 0) {
		perror("recvfrom");
		exit(1);
	}

	printf("%d bytes received\n", n);
}

int
open_tcp_socket(char *hostname, int portnumber)
{
	int err, fd;
	struct hostent *p;
	uint8_t *ip;
	struct sockaddr_in sock;

	printf("hostname %s\n", hostname);

	// get ip address

	p = gethostbyname(hostname);

	if (p == NULL) {
		perror("gethostbyname");
		return -1;
	}

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

	ip = (uint8_t *) p->h_addr;

	printf("host ip %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);

	// open socket

	fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0) {
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

	sock.sin_family = AF_INET;
	sock.sin_port = htons(portnumber);
	memcpy(&sock.sin_addr.s_addr, ip, 4);

	err = connect(fd, (struct sockaddr *) &sock, sizeof sock);

	if (err) {
		close(fd);
		perror("connect");
		return -1;
	}

	// set nonblocking

	err = fcntl(fd, F_SETFL, O_NONBLOCK);

	if (err == -1) {
		close(fd);
		perror("fcntl");
		return -1;
	}

	return fd;
}

void
test(void)
{
	int fd;

	fd = open_tcp_socket("localhost", 30301);

	printf("fd %d\n", fd);
}
