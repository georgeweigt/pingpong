#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>

#define len(p) (p)[-1]

#define Trace printf("file %s, line %d\n", __FILE__, __LINE__);

#define BOOT_PORT 30303
#define UDPBUFLEN 1000
#define HASHLEN 32
#define SIGLEN 69

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
