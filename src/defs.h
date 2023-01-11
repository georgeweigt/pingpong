#define GETH_PUBLIC_KEY "1ecbbdb04f54b68d99a9fb0d60786d29164ffe9776bad9118ec896f2764ec9f711ec2e6f8e0e21c1f0f9abe4515c45949e6bf776d84b54d08f7c32de60e8c480"

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
#include <netdb.h>

#define Trace printf("file %s, line %d\n", __FILE__, __LINE__);

#define SECP256K1 1 // set to 0 for secp256r1
#define BOOT_PORT 30303
#define HASHLEN 32
#define SIGLEN 69
#define R_INDEX (HASHLEN + 3)
#define S_INDEX (HASHLEN + 36)

#define ENCAP_R 2
#define ENCAP_IV (2 + 65)
#define ENCAP_C (2 + 65 + 16)
#define ENCAP_OVERHEAD (2 + 65 + 16 + 32) // prefix + R + iv + hmac

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

struct account {
	uint8_t account_number[20];
	uint8_t private_key[32];
	uint8_t public_key[64];
};

struct mac {
	int state;
	uint8_t buf[64];
	uint32_t hash[8];
};

struct node {

	int fd;

	uint8_t private_key[32];
	uint8_t public_key[64];
	uint8_t peer_public_key[64];
	uint8_t static_shared_secret[32]; // == k_A * K_B == k_B * K_A
	uint8_t auth_nonce[32];
	uint8_t auth_private_key[32];
	uint8_t aes_secret[32];
	uint8_t mac_secret[32];
	struct mac ingress_mac;
	struct mac egress_mac;
};

extern int tos;
extern int atom_count;
extern int ec_malloc_count;
extern uint32_t *p256, *q256, *gx256, *gy256, *a256, *b256;
extern uint8_t private_key[32], public_key_x[32], public_key_y[32];
extern struct account account_table[];
extern struct node initiator, recipient;
