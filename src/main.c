
#define TIMEOUT 1000 // poll timeout in milliseconds

// Sepolia boot node geth
// see https://github.com/ethereum/go-ethereum/blob/master/params/bootnodes.go

#define DST_IP "127.0.0.1" // loopback for now instead of "18.168.182.86"
#define DST_PORT 30303
#define SRC_PORT 30303

#define X "9246d00bc8fd1742e5ad2428b80fc4dc45d786283e05ef6edbd9002cbc335d40"
#define Y "998444732fbe921cb88e1d2c73d1b1de53bae6a2237996e9bfe14f871baf7066"

// secp256k1

#define P "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
#define Q "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define GX "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#define GY "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"

uint32_t *bignum_x;
uint32_t *bignum_y;
uint32_t *bignum_p;
uint32_t *bignum_q;
uint32_t *bignum_gx;
uint32_t *bignum_gy;

char buf[1000];

int
main()
{
	int err, fd, len, n;
	struct sockaddr_in addr;
	struct pollfd pollfd;
	socklen_t addrlen;

	bignum_x = ec_hexstr_to_bignum(X);
	bignum_y = ec_hexstr_to_bignum(Y);
	bignum_p = ec_hexstr_to_bignum(P);
	bignum_q = ec_hexstr_to_bignum(Q);
	bignum_gx = ec_hexstr_to_bignum(GX);
	bignum_gy = ec_hexstr_to_bignum(GY);

	// get socket

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

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(DST_IP);
	addr.sin_port = htons(DST_PORT);

	strcpy(buf, "hello");
	len = strlen(buf);

	n = sendto(fd, buf, len, 0, (struct sockaddr *) &addr, sizeof addr);

	if (n < 0) {
		perror("sendto");
		exit(1);
	}

	if (n < len) {
		printf("sendto?\n");
		exit(1);
	}

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

	buf[n] = '\0';

	printf("%s\n", buf);
}
