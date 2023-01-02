#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#define Trace printf("file %s, line %d\n", __FILE__, __LINE__);

#define SECP256K1 1 // set to 0 for secp256r1
#define BOOT_PORT 30303
#define UDPBUFLEN 1000
#define HASHLEN 32
#define SIGLEN 69

#define len(p) (p)[-1]

extern int ec_malloc_count;

struct point {
	uint32_t *x, *y, *z;
};

struct atom {
	struct atom *car;
	struct atom *cdr;
	int length;
	uint8_t string[0];
};

extern int atom_count;
extern int ec_malloc_count;
extern uint32_t *p256, *q256, *gx256, *gy256, *a256;
