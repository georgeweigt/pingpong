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

struct node {

	int fd;

	uint8_t private_key[32];
	uint8_t public_key[64]; // X || Y
	uint8_t peer_public_key[64];
	uint8_t nonce[32];
	uint8_t peer_none[32];
	uint8_t shared_secret[32];
	uint8_t ephemeral_private_key[32];
	uint8_t ephemeral_public_key[64];
	uint8_t aes_key[16]; // k_E
	uint8_t hmac_key[32]; // k_M
	uint8_t *expanded_key; // points to 16 byte align in expanded key tab
	uint8_t expanded_key_tab[544 + 16]; // 16 bytes for alignment pad
};

extern int tos;
extern int atom_count;
extern int ec_malloc_count;
extern uint32_t *p256, *q256, *gx256, *gy256, *a256, *b256;
extern uint8_t private_key[32], public_key_x[32], public_key_y[32];
extern struct account account_table[];
extern struct node initiator, recipient;
