#define GETH_PUBLIC_KEY "1016734b1f701f642218ed503a96b18d972a9519e639901c659424b42febbffb62e165e63d78f2b8ab3d138e37e5f5c49d909073b085a81e7b390fb189825dba"

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

#define trace() printf("trace: %s line %d\n", __FILE__, __LINE__)
#define TIMEOUT 3000 // comm timeout in milliseconds
#define ENCAP_R 2
#define ENCAP_IV (2 + 65)
#define ENCAP_C (2 + 65 + 16)
#define ENCAP_OVERHEAD (2 + 65 + 16 + 32) // prefix + R + iv + hmac
#define len(p) (p)[-1]

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

struct mac_state_t {
	uint8_t S[200]; // 1600 bits
	int index;
	uint32_t expanded_key[64]; // RLPx uses AES256-ECB for MACs
};

struct node {
	int fd;
	uint8_t private_key[32];
	uint8_t public_key[64];
	uint8_t far_public_key[64];
	uint8_t static_shared_secret[32]; // == k_A * K_B == k_B * K_A
	uint8_t auth_private_key[32];
	uint8_t auth_public_key[64];
	uint8_t auth_nonce[32];
	uint8_t ack_private_key[32];
	uint8_t ack_public_key[64];
	uint8_t ack_nonce[32];
	uint8_t aes_secret[32];
	uint8_t mac_secret[32];
	uint32_t encrypt_state[64];
	uint32_t decrypt_state[64];
	struct mac_state_t ingress_mac;
	struct mac_state_t egress_mac;
	uint8_t *auth_buf;
	int auth_len;
	uint8_t *ack_buf;
	int ack_len;
};

struct compress_state_t {
	uint8_t *inbuf;
	int inindex;
	int inlength;
	uint8_t *outbuf;
	int outindex;
	int outmax;
	int match_offset;
	int match_length;
};

extern int tos;
extern int atom_count;
extern int alloc_count;
extern int ec_alloc_count;
extern uint32_t *p256, *q256, *gx256, *gy256, *a256, *b256, *lower_s;
