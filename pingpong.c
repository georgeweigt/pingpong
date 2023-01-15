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
	uint8_t S[200]; // 1600 bits
	int index;
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
	struct mac ingress_mac;
	struct mac egress_mac;
	uint8_t *auth_buf;
	int auth_len;
	uint8_t *ack_buf;
	int ack_len;
};

extern int tos;
extern int atom_count;
extern int ec_malloc_count;
extern uint32_t *p256, *q256, *gx256, *gy256, *a256, *b256;
extern struct account account_table[];
extern struct node initiator, recipient;
void aes128ctr_setup(uint32_t *expanded_key, uint8_t *key, uint8_t *iv);
void aes128ctr_encrypt(uint32_t *expanded_key, uint8_t *buf, int len);
int mul(int a, int b);
void aes128_init();
void aes128_expand_key(uint8_t *key, uint32_t *w, uint32_t *v);
void aes128_encrypt_block(uint32_t *w, uint8_t *in, uint8_t *out);
void aes128_decrypt_block(uint32_t *v, uint8_t *in, uint8_t *out);
void aes256ctr_setup(uint32_t *state, uint8_t *key, uint8_t *iv);
void aes256ctr_encrypt(uint32_t *state, uint8_t *buf, int len);
int aes256_mul(int a, int b);
void aes256_init();
void aes256_expand_key(uint32_t *w, uint8_t *key);
void aes256_encrypt_block(uint32_t *w, uint8_t *in, uint8_t *out);
int aes256_test_encrypt(void);
int decap(uint8_t *buf, int len, uint8_t *private_key);
uint32_t * ec_modinv(uint32_t *a, uint32_t *p);
uint32_t * ec_modinv_v1(uint32_t *a, uint32_t *p);
uint32_t * ec_modinv_v2(uint32_t *a, uint32_t *p);
uint32_t * ec_modinv_v3(uint32_t *a, uint32_t *p);
void ec_projectify(struct point *S);
int ec_affinify(struct point *S, uint32_t *p);
void ec_double(struct point *R, struct point *S, uint32_t *p);
void ec_double_v2k1(struct point *R, struct point *S, uint32_t *p);
void ec_double_v2r1(struct point *R, struct point *S, uint32_t *p, uint32_t *a);
void ec_double_v1(struct point *R, struct point *S, uint32_t *p);
void ec_add_xyz(struct point *R, struct point *S, struct point *T, uint32_t *p);
void ec_full_add(struct point *R, struct point *S, struct point *T, uint32_t *p);
void ec_full_sub(struct point *R, struct point *S, struct point *T, uint32_t *p);
void ec_mult(struct point *R, uint32_t *d, struct point *S, uint32_t *p);
void ec_mult(struct point *R, uint32_t *d, struct point *S, uint32_t *p);
int ec_get_msbit_index(uint32_t *u);
int ec_get_bit(uint32_t *u, int k);
int ec_F(int t);
void ec_twin_mult(struct point *R, uint32_t *d0, struct point *S, uint32_t *d1, struct point *T, uint32_t *p);
void ec_free_xyz(struct point *u);
uint32_t * ec_add(uint32_t *u, uint32_t *v);
uint32_t * ec_sub(uint32_t *u, uint32_t *v);
uint32_t * ec_mul(uint32_t *u, uint32_t *v);
uint32_t * ec_div(uint32_t *u, uint32_t *v);
void ec_mod(uint32_t *u, uint32_t *v);
void ec_mod_v1(uint32_t *u, uint32_t *v);
void ec_mod_v2(uint32_t *u, uint32_t *v);
uint32_t * ec_pow(uint32_t *u, uint32_t *v);
void ec_shr(uint32_t *u);
int ec_cmp(uint32_t *u, uint32_t *v);
int ec_equal(uint32_t *u, uint32_t v);
uint32_t * ec_int(int k);
uint32_t * ec_new(int n);
void ec_free(uint32_t *u);
uint32_t * ec_dup(uint32_t *u);
void ec_norm(uint32_t *u);
uint32_t * ec_hexstr_to_bignum(char *s);
uint32_t * ec_buf_to_bignum(uint8_t *buf, int len);
void ec_init(void);
void ec_ecdh(uint8_t *shared_secret, uint8_t *private_key, uint8_t *public_key);
void ec_genkey(uint8_t *private_key, uint8_t *public_key);
void ec_pubkey(uint8_t *public_key, uint8_t *private_key);
void ec_sign(uint8_t *rbuf, uint8_t *sbuf, uint8_t *hash, uint8_t *private_key);
int ec_verify(uint8_t *hash, uint8_t *rbuf, uint8_t *sbuf, uint8_t *public_key_x, uint8_t *public_key_y);
void encap(uint8_t *buf, int len, struct node *p);
int enlength(struct atom *p);
int sublength(struct atom *p);
int padlength(struct atom *p, int sublen);
void init(void);
void read_account(struct account *p, char *filename);
char * read_file(char *filename);
void print_account(struct account *p);
void kdf(uint8_t *aes_key, uint8_t *hmac_key, uint8_t *shared_secret);
uint8_t * theta(uint8_t *A);
uint8_t * rho(uint8_t *A);
uint8_t * pi(uint8_t *A);
uint8_t * chi(uint8_t *A);
uint8_t rc(int t);
uint8_t * iota(uint8_t *A, int ir);
uint8_t * Rnd(uint8_t *A, int ir);
void Keccak(uint8_t *S);
uint8_t * sponge(uint8_t *N, int len);
void keccak256(uint8_t *outbuf, uint8_t *inbuf, int inbuflen);
char * keccak256str(uint8_t *buf, int len);
void test_keccak256(void);
void keccak256_init(struct mac *p);
void keccak256_update(struct mac *p, uint8_t *inbuf, int len);
void keccak256_digest(struct mac *p, uint8_t *outbuf);
void list(int n);
void push(struct atom *p);
struct atom * pop(void);
void pop_all(int n);
void push_string(uint8_t *string, int length);
void push_number(uint64_t n);
struct atom * alloc_atom(int string_length);
void free_list(struct atom *p);
int compare_lists(struct atom *p, struct atom *q);
void print_list(struct atom *p);
void print_list_nib(struct atom *p, int level);
void macs(struct node *p);
int main(int argc, char *argv[]);
void nib(void);
int rdecode(uint8_t *buf, int length);
int rdecode_relax(uint8_t *buf, int length);
int rdecode_nib(uint8_t *buf, int length);
int rdecode_list(uint8_t *buf, int length);
int recv_ack(struct node *p, uint8_t *buf, int len);
int recv_ack_data(struct node *p, struct atom *q);
int recv_auth(struct node *p, uint8_t *buf, int len);
int recv_auth_data(struct node *p, struct atom *q);
int rencode(uint8_t *buf, int len, struct atom *p);
int rencode_nib(uint8_t *buf, struct atom *p);
int rencode_list(uint8_t *buf, struct atom *p);
int rencode_string(uint8_t *buf, struct atom *p);
void secrets(struct node *p, int initiator);
void send_ack(struct node *p);
struct atom * ack_body(struct node *p);
void send_auth(struct node *p);
struct atom * auth_body(struct node *p);
void hmac_sha256(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out);
void sha256(uint8_t *buf, int len, uint8_t *out);
void sha256_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out);
void sha256_hash_block(uint8_t *buf, uint32_t *hash);
void test_sha256(void);
void sign(uint8_t *msg, int msglen, uint8_t *private_key, uint8_t *public_key);
void test_sign(void);
void sim(void);
uint8_t * receive(int fd, int *plen);
void wait_for_pollin(int fd);
int start_listening(int port);
int client_connect(char *ipaddr, int portnumber);
int server_connect(int listen_fd);
void test(void);
int test_public_key(char *public_key_x, char *public_key_y);
void test_aes128(void);
void test_aes256(void);
void test_rencode(void);
void test_rdecode(void);
void test_genkey(void);
int test_public_key_secp256k1(uint32_t *x, uint32_t *y);
int test_public_key_secp256r1(uint32_t *x, uint32_t *y);
void test_ecdh(void);
void test_kdf(void);
void test_hmac(void);
void test_pubkey(void);
void test_decrypt(void);
void printmem(uint8_t *mem, int n);
void hextobin(uint8_t *buf, int len, char *str);
#define CTR ((uint8_t *) expanded_key + 176)

// expanded_key		192 bytes (48 uint32_t)
// key			16 bytes
// iv			16 bytes

void
aes128ctr_setup(uint32_t *expanded_key, uint8_t *key, uint8_t *iv)
{
	uint32_t w[44], v[44];
	aes128_expand_key(key, w, v);
	memcpy(expanded_key, w, 176);
	memcpy(CTR, iv, 16);
}

// used for both encryption and decryption

void
aes128ctr_encrypt(uint32_t *expanded_key, uint8_t *buf, int len)
{
	int i;
	uint8_t block[16];

	while (len > 0) {

		aes128_encrypt_block(expanded_key, CTR, block);

		for (i = 0; i < 16 && i < len; i++)
			buf[i] ^= block[i];

		// increment counter

		for (i = 15; i >= 0; i--)
			if (++CTR[i] > 0)
				break;

		buf += 16;
		len -= 16;
	}
}

uint32_t etab0[256]; // encryption tables
uint32_t etab1[256];
uint32_t etab2[256];
uint32_t etab3[256];

uint32_t dtab0[256]; // decryption tables
uint32_t dtab1[256];
uint32_t dtab2[256];
uint32_t dtab3[256];

uint32_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// sbox[] and inv_sbox[] are from FIPS Publication 197

uint8_t sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

uint8_t inv_sbox[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

// multiply a and b mod x^8 + x^4 + x^3 + x + 1 (see FIPS Pub 197, p. 10)

int
mul(int a, int b)
{
	int i, t = 0;
	for (i = 0; i < 8; i++) {
		t <<= 1;
		if (t & 0x100)
			t ^= 0x11b;
		a <<= 1;
		if (a & 0x100)
			t ^= b;
	}
	return t;
}

// multiply a times column b

#define MUL(a, b0, b1, b2, b3) mul(a, b0) | mul(a, b1) << 8 | mul(a, b2) << 16 | mul(a, b3) << 24

// Initialize encryption and decryption tables

void
aes128_init()
{
	int i, k;

	for (i = 0; i < 256; i++) {
		k = sbox[i];
		etab0[i] = MUL(k, 2, 1, 1, 3);
		etab1[i] = MUL(k, 3, 2, 1, 1);
		etab2[i] = MUL(k, 1, 3, 2, 1);
		etab3[i] = MUL(k, 1, 1, 3, 2);
		k = inv_sbox[i];
		dtab0[i] = MUL(k, 14, 9, 13, 11);
		dtab1[i] = MUL(k, 11, 14, 9, 13);
		dtab2[i] = MUL(k, 13, 11, 14, 9);
		dtab3[i] = MUL(k, 9, 13, 11, 14);
	}
}

// Initialize w[44] and v[44] from encryption key

void
aes128_expand_key(uint8_t *key, uint32_t *w, uint32_t *v)
{
	int i;
	uint32_t *k, t;

	k = w;

	k[0] = key[3] << 24 | key[2] << 16 | key[1] << 8 | key[0];
	k[1] = key[7] << 24 | key[6] << 16 | key[5] << 8 | key[4];
	k[2] = key[11] << 24 | key[10] << 16 | key[9] << 8 | key[8];
	k[3] = key[15] << 24 | key[14] << 16 | key[13] << 8 | key[12];

	for (i = 0; i < 10; i++) {
		t = k[3];
		k[4] = k[0] ^ (etab2[t >> 8 & 0xff] & 0xff) ^ (etab3[t >> 16 & 0xff] & 0xff00) ^ (etab0[t >> 24] & 0xff0000) ^ (etab1[t & 0xff] & 0xff000000) ^ rcon[i];
		k[5] = k[1] ^ k[4];
		k[6] = k[2] ^ k[5];
		k[7] = k[3] ^ k[6];
		k += 4;
	}

	for (i = 0; i < 44; i++)
		v[i] = w[i];

	k = v;

	for (i = 0; i < 9; i++) {
		k += 4;
		k[0] = dtab0[etab1[k[0] & 0xff] >> 24] ^ dtab1[etab1[k[0] >> 8 & 0xff] >> 24] ^ dtab2[etab1[k[0] >> 16 & 0xff] >> 24] ^ dtab3[etab1[k[0] >> 24 & 0xff] >> 24];
		k[1] = dtab0[etab1[k[1] & 0xff] >> 24] ^ dtab1[etab1[k[1] >> 8 & 0xff] >> 24] ^ dtab2[etab1[k[1] >> 16 & 0xff] >> 24] ^ dtab3[etab1[k[1] >> 24 & 0xff] >> 24];
		k[2] = dtab0[etab1[k[2] & 0xff] >> 24] ^ dtab1[etab1[k[2] >> 8 & 0xff] >> 24] ^ dtab2[etab1[k[2] >> 16 & 0xff] >> 24] ^ dtab3[etab1[k[2] >> 24 & 0xff] >> 24];
		k[3] = dtab0[etab1[k[3] & 0xff] >> 24] ^ dtab1[etab1[k[3] >> 8 & 0xff] >> 24] ^ dtab2[etab1[k[3] >> 16 & 0xff] >> 24] ^ dtab3[etab1[k[3] >> 24 & 0xff] >> 24];
	}
}

#define s03 (s0 >> 24)
#define s02 (s0 >> 16 & 0xff)
#define s01 (s0 >> 8 & 0xff)
#define s00 (s0 & 0xff)

#define s13 (s1 >> 24)
#define s12 (s1 >> 16 & 0xff)
#define s11 (s1 >> 8 & 0xff)
#define s10 (s1 & 0xff)

#define s23 (s2 >> 24)
#define s22 (s2 >> 16 & 0xff)
#define s21 (s2 >> 8 & 0xff)
#define s20 (s2 & 0xff)

#define s33 (s3 >> 24)
#define s32 (s3 >> 16 & 0xff)
#define s31 (s3 >> 8 & 0xff)
#define s30 (s3 & 0xff)

#define t03 (t0 >> 24)
#define t02 (t0 >> 16 & 0xff)
#define t01 (t0 >> 8 & 0xff)
#define t00 (t0 & 0xff)

#define t13 (t1 >> 24)
#define t12 (t1 >> 16 & 0xff)
#define t11 (t1 >> 8 & 0xff)
#define t10 (t1 & 0xff)

#define t23 (t2 >> 24)
#define t22 (t2 >> 16 & 0xff)
#define t21 (t2 >> 8 & 0xff)
#define t20 (t2 & 0xff)

#define t33 (t3 >> 24)
#define t32 (t3 >> 16 & 0xff)
#define t31 (t3 >> 8 & 0xff)
#define t30 (t3 & 0xff)

// encrypt one block (16 bytes)

void
aes128_encrypt_block(uint32_t *w, uint8_t *in, uint8_t *out)
{
	uint32_t s0, s1, s2, s3, t0, t1, t2, t3;

	s0 = in[3] << 24 | in[2] << 16 | in[1] << 8 | in[0];
	s1 = in[7] << 24 | in[6] << 16 | in[5] << 8 | in[4];
	s2 = in[11] << 24 | in[10] << 16 | in[9] << 8 | in[8];
	s3 = in[15] << 24 | in[14] << 16 | in[13] << 8 | in[12];

	s0 ^= w[0];
	s1 ^= w[1];
	s2 ^= w[2];
	s3 ^= w[3];

	t0 = etab0[s00] ^ etab1[s11] ^ etab2[s22] ^ etab3[s33] ^ w[4];
	t1 = etab0[s10] ^ etab1[s21] ^ etab2[s32] ^ etab3[s03] ^ w[5];
	t2 = etab0[s20] ^ etab1[s31] ^ etab2[s02] ^ etab3[s13] ^ w[6];
	t3 = etab0[s30] ^ etab1[s01] ^ etab2[s12] ^ etab3[s23] ^ w[7];

	s0 = etab0[t00] ^ etab1[t11] ^ etab2[t22] ^ etab3[t33] ^ w[8];
	s1 = etab0[t10] ^ etab1[t21] ^ etab2[t32] ^ etab3[t03] ^ w[9];
	s2 = etab0[t20] ^ etab1[t31] ^ etab2[t02] ^ etab3[t13] ^ w[10];
	s3 = etab0[t30] ^ etab1[t01] ^ etab2[t12] ^ etab3[t23] ^ w[11];

	t0 = etab0[s00] ^ etab1[s11] ^ etab2[s22] ^ etab3[s33] ^ w[12];
	t1 = etab0[s10] ^ etab1[s21] ^ etab2[s32] ^ etab3[s03] ^ w[13];
	t2 = etab0[s20] ^ etab1[s31] ^ etab2[s02] ^ etab3[s13] ^ w[14];
	t3 = etab0[s30] ^ etab1[s01] ^ etab2[s12] ^ etab3[s23] ^ w[15];

	s0 = etab0[t00] ^ etab1[t11] ^ etab2[t22] ^ etab3[t33] ^ w[16];
	s1 = etab0[t10] ^ etab1[t21] ^ etab2[t32] ^ etab3[t03] ^ w[17];
	s2 = etab0[t20] ^ etab1[t31] ^ etab2[t02] ^ etab3[t13] ^ w[18];
	s3 = etab0[t30] ^ etab1[t01] ^ etab2[t12] ^ etab3[t23] ^ w[19];

	t0 = etab0[s00] ^ etab1[s11] ^ etab2[s22] ^ etab3[s33] ^ w[20];
	t1 = etab0[s10] ^ etab1[s21] ^ etab2[s32] ^ etab3[s03] ^ w[21];
	t2 = etab0[s20] ^ etab1[s31] ^ etab2[s02] ^ etab3[s13] ^ w[22];
	t3 = etab0[s30] ^ etab1[s01] ^ etab2[s12] ^ etab3[s23] ^ w[23];

	s0 = etab0[t00] ^ etab1[t11] ^ etab2[t22] ^ etab3[t33] ^ w[24];
	s1 = etab0[t10] ^ etab1[t21] ^ etab2[t32] ^ etab3[t03] ^ w[25];
	s2 = etab0[t20] ^ etab1[t31] ^ etab2[t02] ^ etab3[t13] ^ w[26];
	s3 = etab0[t30] ^ etab1[t01] ^ etab2[t12] ^ etab3[t23] ^ w[27];

	t0 = etab0[s00] ^ etab1[s11] ^ etab2[s22] ^ etab3[s33] ^ w[28];
	t1 = etab0[s10] ^ etab1[s21] ^ etab2[s32] ^ etab3[s03] ^ w[29];
	t2 = etab0[s20] ^ etab1[s31] ^ etab2[s02] ^ etab3[s13] ^ w[30];
	t3 = etab0[s30] ^ etab1[s01] ^ etab2[s12] ^ etab3[s23] ^ w[31];

	s0 = etab0[t00] ^ etab1[t11] ^ etab2[t22] ^ etab3[t33] ^ w[32];
	s1 = etab0[t10] ^ etab1[t21] ^ etab2[t32] ^ etab3[t03] ^ w[33];
	s2 = etab0[t20] ^ etab1[t31] ^ etab2[t02] ^ etab3[t13] ^ w[34];
	s3 = etab0[t30] ^ etab1[t01] ^ etab2[t12] ^ etab3[t23] ^ w[35];

	t0 = etab0[s00] ^ etab1[s11] ^ etab2[s22] ^ etab3[s33] ^ w[36];
	t1 = etab0[s10] ^ etab1[s21] ^ etab2[s32] ^ etab3[s03] ^ w[37];
	t2 = etab0[s20] ^ etab1[s31] ^ etab2[s02] ^ etab3[s13] ^ w[38];
	t3 = etab0[s30] ^ etab1[s01] ^ etab2[s12] ^ etab3[s23] ^ w[39];

	s0 = (etab2[t00] & 0xff) ^ (etab3[t11] & 0xff00) ^ (etab0[t22] & 0xff0000) ^ (etab1[t33] & 0xff000000) ^ w[40];
	s1 = (etab2[t10] & 0xff) ^ (etab3[t21] & 0xff00) ^ (etab0[t32] & 0xff0000) ^ (etab1[t03] & 0xff000000) ^ w[41];
	s2 = (etab2[t20] & 0xff) ^ (etab3[t31] & 0xff00) ^ (etab0[t02] & 0xff0000) ^ (etab1[t13] & 0xff000000) ^ w[42];
	s3 = (etab2[t30] & 0xff) ^ (etab3[t01] & 0xff00) ^ (etab0[t12] & 0xff0000) ^ (etab1[t23] & 0xff000000) ^ w[43];

	out[0] = s0;
	out[1] = s0 >> 8;
	out[2] = s0 >> 16;
	out[3] = s0 >> 24;

	out[4] = s1;
	out[5] = s1 >> 8;
	out[6] = s1 >> 16;
	out[7] = s1 >> 24;

	out[8] = s2;
	out[9] = s2 >> 8;
	out[10] = s2 >> 16;
	out[11] = s2 >> 24;

	out[12] = s3;
	out[13] = s3 >> 8;
	out[14] = s3 >> 16;
	out[15] = s3 >> 24;
}

// decrypt one block (16 bytes)

void
aes128_decrypt_block(uint32_t *v, uint8_t *in, uint8_t *out)
{
	uint32_t s0, s1, s2, s3, t0, t1, t2, t3;

	s0 = in[3] << 24 | in[2] << 16 | in[1] << 8 | in[0];
	s1 = in[7] << 24 | in[6] << 16 | in[5] << 8 | in[4];
	s2 = in[11] << 24 | in[10] << 16 | in[9] << 8 | in[8];
	s3 = in[15] << 24 | in[14] << 16 | in[13] << 8 | in[12];

	s0 ^= v[40];
	s1 ^= v[41];
	s2 ^= v[42];
	s3 ^= v[43];

	t0 = dtab0[s00] ^ dtab1[s31] ^ dtab2[s22] ^ dtab3[s13] ^ v[36];
	t1 = dtab0[s10] ^ dtab1[s01] ^ dtab2[s32] ^ dtab3[s23] ^ v[37];
	t2 = dtab0[s20] ^ dtab1[s11] ^ dtab2[s02] ^ dtab3[s33] ^ v[38];
	t3 = dtab0[s30] ^ dtab1[s21] ^ dtab2[s12] ^ dtab3[s03] ^ v[39];

	s0 = dtab0[t00] ^ dtab1[t31] ^ dtab2[t22] ^ dtab3[t13] ^ v[32];
	s1 = dtab0[t10] ^ dtab1[t01] ^ dtab2[t32] ^ dtab3[t23] ^ v[33];
	s2 = dtab0[t20] ^ dtab1[t11] ^ dtab2[t02] ^ dtab3[t33] ^ v[34];
	s3 = dtab0[t30] ^ dtab1[t21] ^ dtab2[t12] ^ dtab3[t03] ^ v[35];

	t0 = dtab0[s00] ^ dtab1[s31] ^ dtab2[s22] ^ dtab3[s13] ^ v[28];
	t1 = dtab0[s10] ^ dtab1[s01] ^ dtab2[s32] ^ dtab3[s23] ^ v[29];
	t2 = dtab0[s20] ^ dtab1[s11] ^ dtab2[s02] ^ dtab3[s33] ^ v[30];
	t3 = dtab0[s30] ^ dtab1[s21] ^ dtab2[s12] ^ dtab3[s03] ^ v[31];

	s0 = dtab0[t00] ^ dtab1[t31] ^ dtab2[t22] ^ dtab3[t13] ^ v[24];
	s1 = dtab0[t10] ^ dtab1[t01] ^ dtab2[t32] ^ dtab3[t23] ^ v[25];
	s2 = dtab0[t20] ^ dtab1[t11] ^ dtab2[t02] ^ dtab3[t33] ^ v[26];
	s3 = dtab0[t30] ^ dtab1[t21] ^ dtab2[t12] ^ dtab3[t03] ^ v[27];

	t0 = dtab0[s00] ^ dtab1[s31] ^ dtab2[s22] ^ dtab3[s13] ^ v[20];
	t1 = dtab0[s10] ^ dtab1[s01] ^ dtab2[s32] ^ dtab3[s23] ^ v[21];
	t2 = dtab0[s20] ^ dtab1[s11] ^ dtab2[s02] ^ dtab3[s33] ^ v[22];
	t3 = dtab0[s30] ^ dtab1[s21] ^ dtab2[s12] ^ dtab3[s03] ^ v[23];

	s0 = dtab0[t00] ^ dtab1[t31] ^ dtab2[t22] ^ dtab3[t13] ^ v[16];
	s1 = dtab0[t10] ^ dtab1[t01] ^ dtab2[t32] ^ dtab3[t23] ^ v[17];
	s2 = dtab0[t20] ^ dtab1[t11] ^ dtab2[t02] ^ dtab3[t33] ^ v[18];
	s3 = dtab0[t30] ^ dtab1[t21] ^ dtab2[t12] ^ dtab3[t03] ^ v[19];

	t0 = dtab0[s00] ^ dtab1[s31] ^ dtab2[s22] ^ dtab3[s13] ^ v[12];
	t1 = dtab0[s10] ^ dtab1[s01] ^ dtab2[s32] ^ dtab3[s23] ^ v[13];
	t2 = dtab0[s20] ^ dtab1[s11] ^ dtab2[s02] ^ dtab3[s33] ^ v[14];
	t3 = dtab0[s30] ^ dtab1[s21] ^ dtab2[s12] ^ dtab3[s03] ^ v[15];

	s0 = dtab0[t00] ^ dtab1[t31] ^ dtab2[t22] ^ dtab3[t13] ^ v[8];
	s1 = dtab0[t10] ^ dtab1[t01] ^ dtab2[t32] ^ dtab3[t23] ^ v[9];
	s2 = dtab0[t20] ^ dtab1[t11] ^ dtab2[t02] ^ dtab3[t33] ^ v[10];
	s3 = dtab0[t30] ^ dtab1[t21] ^ dtab2[t12] ^ dtab3[t03] ^ v[11];

	t0 = dtab0[s00] ^ dtab1[s31] ^ dtab2[s22] ^ dtab3[s13] ^ v[4];
	t1 = dtab0[s10] ^ dtab1[s01] ^ dtab2[s32] ^ dtab3[s23] ^ v[5];
	t2 = dtab0[s20] ^ dtab1[s11] ^ dtab2[s02] ^ dtab3[s33] ^ v[6];
	t3 = dtab0[s30] ^ dtab1[s21] ^ dtab2[s12] ^ dtab3[s03] ^ v[7];

	s0 = inv_sbox[t00] ^ inv_sbox[t31] << 8 ^ inv_sbox[t22] << 16 ^ inv_sbox[t13] << 24 ^ v[0];
	s1 = inv_sbox[t10] ^ inv_sbox[t01] << 8 ^ inv_sbox[t32] << 16 ^ inv_sbox[t23] << 24 ^ v[1];
	s2 = inv_sbox[t20] ^ inv_sbox[t11] << 8 ^ inv_sbox[t02] << 16 ^ inv_sbox[t33] << 24 ^ v[2];
	s3 = inv_sbox[t30] ^ inv_sbox[t21] << 8 ^ inv_sbox[t12] << 16 ^ inv_sbox[t03] << 24 ^ v[3];

	out[0] = s0;
	out[1] = s0 >> 8;
	out[2] = s0 >> 16;
	out[3] = s0 >> 24;

	out[4] = s1;
	out[5] = s1 >> 8;
	out[6] = s1 >> 16;
	out[7] = s1 >> 24;

	out[8] = s2;
	out[9] = s2 >> 8;
	out[10] = s2 >> 16;
	out[11] = s2 >> 24;

	out[12] = s3;
	out[13] = s3 >> 8;
	out[14] = s3 >> 16;
	out[15] = s3 >> 24;
}

#undef CTR
#undef MUL

#undef s03
#undef s02
#undef s01
#undef s00

#undef s13
#undef s12
#undef s11
#undef s10

#undef s23
#undef s22
#undef s21
#undef s20

#undef s33
#undef s32
#undef s31
#undef s30

#undef t03
#undef t02
#undef t01
#undef t00

#undef t13
#undef t12
#undef t11
#undef t10

#undef t23
#undef t22
#undef t21
#undef t20

#undef t33
#undef t32
#undef t31
#undef t30
#define CTR ((uint8_t *) state + 240)

// state	256 bytes (64 uint32_t)
// key		32 bytes
// iv		16 bytes

void
aes256ctr_setup(uint32_t *state, uint8_t *key, uint8_t *iv)
{
	aes256_expand_key(state, key);
	memcpy(CTR, iv, 16);
}

// used for both encryption and decryption

void
aes256ctr_encrypt(uint32_t *state, uint8_t *buf, int len)
{
	int i;
	uint8_t block[16];

	while (len > 0) {

		aes256_encrypt_block(state, CTR, block);

		for (i = 0; i < 16 && i < len; i++)
			buf[i] ^= block[i];

		// increment counter

		for (i = 15; i >= 0; i--)
			if (++CTR[i] > 0)
				break;

		buf += 16;
		len -= 16;
	}
}

// encryption tables

uint32_t aes256_etab0[256];
uint32_t aes256_etab1[256];
uint32_t aes256_etab2[256];
uint32_t aes256_etab3[256];

uint32_t aes256_rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

// sbox[] and inv_sbox[] are from FIPS Publication 197

uint8_t aes256_sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

uint8_t aes256_inv_sbox[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

// multiply a and b mod x^8 + x^4 + x^3 + x + 1 (see FIPS Pub 197, p. 10)

int
aes256_mul(int a, int b)
{
	int i, t = 0;
	for (i = 0; i < 8; i++) {
		t <<= 1;
		if (t & 0x100)
			t ^= 0x11b;
		a <<= 1;
		if (a & 0x100)
			t ^= b;
	}
	return t;
}

// multiply a times column b

#define MUL(a, b0, b1, b2, b3) (aes256_mul(a, b0) | aes256_mul(a, b1) << 8 | aes256_mul(a, b2) << 16 | aes256_mul(a, b3) << 24)

void
aes256_init()
{
	int i, k;

	for (i = 0; i < 256; i++) {
		k = aes256_sbox[i];
		aes256_etab0[i] = MUL(k, 2, 1, 1, 3);
		aes256_etab1[i] = MUL(k, 3, 2, 1, 1);
		aes256_etab2[i] = MUL(k, 1, 3, 2, 1);
		aes256_etab3[i] = MUL(k, 1, 1, 3, 2);
	}
}

void
aes256_expand_key(uint32_t *w, uint8_t *key)
{
	int i;
	uint32_t temp;

	w[0] = key[3] << 24 | key[2] << 16 | key[1] << 8 | key[0];
	w[1] = key[7] << 24 | key[6] << 16 | key[5] << 8 | key[4];
	w[2] = key[11] << 24 | key[10] << 16 | key[9] << 8 | key[8];
	w[3] = key[15] << 24 | key[14] << 16 | key[13] << 8 | key[12];

	w[4] = key[19] << 24 | key[18] << 16 | key[17] << 8 | key[16];
	w[5] = key[23] << 24 | key[22] << 16 | key[21] << 8 | key[20];
	w[6] = key[27] << 24 | key[26] << 16 | key[25] << 8 | key[24];
	w[7] = key[31] << 24 | key[30] << 16 | key[29] << 8 | key[28];

	for (i = 8; i < 60; i++) {

		temp = w[i - 1];

		if (i % 8 == 0)
			temp = ((aes256_etab2[temp >> 8 & 0xff] & 0xff) | (aes256_etab3[temp >> 16 & 0xff] & 0xff00) | (aes256_etab0[temp >> 24] & 0xff0000) | (aes256_etab1[temp & 0xff] & 0xff000000)) ^ aes256_rcon[i / 8 - 1];
		else if (i % 8 == 4)
			temp = ((uint32_t) aes256_sbox[temp >> 24] << 24) | ((uint32_t) aes256_sbox[temp >> 16 & 0xff] << 16) | ((uint32_t) aes256_sbox[temp >> 8 & 0xff] << 8) | (uint32_t) aes256_sbox[temp & 0xff];

		w[i] = w[i - 8] ^ temp;
	}
}

#define s03 (s0 >> 24)
#define s02 (s0 >> 16 & 0xff)
#define s01 (s0 >> 8 & 0xff)
#define s00 (s0 & 0xff)

#define s13 (s1 >> 24)
#define s12 (s1 >> 16 & 0xff)
#define s11 (s1 >> 8 & 0xff)
#define s10 (s1 & 0xff)

#define s23 (s2 >> 24)
#define s22 (s2 >> 16 & 0xff)
#define s21 (s2 >> 8 & 0xff)
#define s20 (s2 & 0xff)

#define s33 (s3 >> 24)
#define s32 (s3 >> 16 & 0xff)
#define s31 (s3 >> 8 & 0xff)
#define s30 (s3 & 0xff)

#define t03 (t0 >> 24)
#define t02 (t0 >> 16 & 0xff)
#define t01 (t0 >> 8 & 0xff)
#define t00 (t0 & 0xff)

#define t13 (t1 >> 24)
#define t12 (t1 >> 16 & 0xff)
#define t11 (t1 >> 8 & 0xff)
#define t10 (t1 & 0xff)

#define t23 (t2 >> 24)
#define t22 (t2 >> 16 & 0xff)
#define t21 (t2 >> 8 & 0xff)
#define t20 (t2 & 0xff)

#define t33 (t3 >> 24)
#define t32 (t3 >> 16 & 0xff)
#define t31 (t3 >> 8 & 0xff)
#define t30 (t3 & 0xff)

void
aes256_encrypt_block(uint32_t *w, uint8_t *in, uint8_t *out)
{
	int i;
	uint32_t s0, s1, s2, s3, t0, t1, t2, t3;

	s0 = in[3] << 24 | in[2] << 16 | in[1] << 8 | in[0];
	s1 = in[7] << 24 | in[6] << 16 | in[5] << 8 | in[4];
	s2 = in[11] << 24 | in[10] << 16 | in[9] << 8 | in[8];
	s3 = in[15] << 24 | in[14] << 16 | in[13] << 8 | in[12];

	s0 ^= w[0];
	s1 ^= w[1];
	s2 ^= w[2];
	s3 ^= w[3];

	for (i = 4; i < 52; i += 8) {

		t0 = aes256_etab0[s00] ^ aes256_etab1[s11] ^ aes256_etab2[s22] ^ aes256_etab3[s33] ^ w[i + 0];
		t1 = aes256_etab0[s10] ^ aes256_etab1[s21] ^ aes256_etab2[s32] ^ aes256_etab3[s03] ^ w[i + 1];
		t2 = aes256_etab0[s20] ^ aes256_etab1[s31] ^ aes256_etab2[s02] ^ aes256_etab3[s13] ^ w[i + 2];
		t3 = aes256_etab0[s30] ^ aes256_etab1[s01] ^ aes256_etab2[s12] ^ aes256_etab3[s23] ^ w[i + 3];

		s0 = aes256_etab0[t00] ^ aes256_etab1[t11] ^ aes256_etab2[t22] ^ aes256_etab3[t33] ^ w[i + 4];
		s1 = aes256_etab0[t10] ^ aes256_etab1[t21] ^ aes256_etab2[t32] ^ aes256_etab3[t03] ^ w[i + 5];
		s2 = aes256_etab0[t20] ^ aes256_etab1[t31] ^ aes256_etab2[t02] ^ aes256_etab3[t13] ^ w[i + 6];
		s3 = aes256_etab0[t30] ^ aes256_etab1[t01] ^ aes256_etab2[t12] ^ aes256_etab3[t23] ^ w[i + 7];
	}

	t0 = aes256_etab0[s00] ^ aes256_etab1[s11] ^ aes256_etab2[s22] ^ aes256_etab3[s33] ^ w[52];
	t1 = aes256_etab0[s10] ^ aes256_etab1[s21] ^ aes256_etab2[s32] ^ aes256_etab3[s03] ^ w[53];
	t2 = aes256_etab0[s20] ^ aes256_etab1[s31] ^ aes256_etab2[s02] ^ aes256_etab3[s13] ^ w[54];
	t3 = aes256_etab0[s30] ^ aes256_etab1[s01] ^ aes256_etab2[s12] ^ aes256_etab3[s23] ^ w[55];

	s0 = (aes256_etab2[t00] & 0xff) ^ (aes256_etab3[t11] & 0xff00) ^ (aes256_etab0[t22] & 0xff0000) ^ (aes256_etab1[t33] & 0xff000000) ^ w[56];
	s1 = (aes256_etab2[t10] & 0xff) ^ (aes256_etab3[t21] & 0xff00) ^ (aes256_etab0[t32] & 0xff0000) ^ (aes256_etab1[t03] & 0xff000000) ^ w[57];
	s2 = (aes256_etab2[t20] & 0xff) ^ (aes256_etab3[t31] & 0xff00) ^ (aes256_etab0[t02] & 0xff0000) ^ (aes256_etab1[t13] & 0xff000000) ^ w[58];
	s3 = (aes256_etab2[t30] & 0xff) ^ (aes256_etab3[t01] & 0xff00) ^ (aes256_etab0[t12] & 0xff0000) ^ (aes256_etab1[t23] & 0xff000000) ^ w[59];

	out[0] = s0;
	out[1] = s0 >> 8;
	out[2] = s0 >> 16;
	out[3] = s0 >> 24;

	out[4] = s1;
	out[5] = s1 >> 8;
	out[6] = s1 >> 16;
	out[7] = s1 >> 24;

	out[8] = s2;
	out[9] = s2 >> 8;
	out[10] = s2 >> 16;
	out[11] = s2 >> 24;

	out[12] = s3;
	out[13] = s3 >> 8;
	out[14] = s3 >> 16;
	out[15] = s3 >> 24;
}

int
aes256_test_encrypt(void)
{
	uint8_t key[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
	uint8_t plaintext[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	uint8_t ciphertext[16] = {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89};
	uint32_t w[60];

	aes256_expand_key(w, key);

	aes256_encrypt_block(w, plaintext, plaintext);

	if (memcmp(plaintext, ciphertext, 16) == 0)
		return 0;
	else
		return -1;
}

#undef CTR
#undef MUL

#undef s03
#undef s02
#undef s01
#undef s00

#undef s13
#undef s12
#undef s11
#undef s10

#undef s23
#undef s22
#undef s21
#undef s20

#undef s33
#undef s32
#undef s31
#undef s30

#undef t03
#undef t02
#undef t01
#undef t00

#undef t13
#undef t12
#undef t11
#undef t10

#undef t23
#undef t22
#undef t21
#undef t20

#undef t33
#undef t32
#undef t31
#undef t30
// encap format
//
// prefix || 0x04 || R || iv || c || d
//
// prefix	length (2 bytes)
// R		ephemeral public key (64 bytes)
// iv		initialization vector (16 bytes)
// c		ciphertext
// d		hmac (32 bytes)

// returns 0 ok, -1 err

int
decap(uint8_t *buf, int len, uint8_t *private_key)
{
	int err, msglen;
	uint8_t *msg;
	uint8_t shared_secret[32];
	uint8_t hmac[32], hmac_key[32];
	uint8_t aes_key[16];
	uint32_t aes_expanded_key[48];

	msg = buf + ENCAP_C;		// ENCAP_C == 2 + 65 + 16
	msglen = len - ENCAP_OVERHEAD;	// ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	// check length

	if (msglen < 0 || (buf[0] << 8 | buf[1]) != len - 2)
		return -1;

	// derive shared_secret from private_key and R

	ec_ecdh(shared_secret, private_key, buf + ENCAP_R + 1); // R + 1 to skip over format byte

	// derive aes_key and hmac_key from ephemeral_shared_secret

	kdf(aes_key, hmac_key, shared_secret);

	// check hmac

	memcpy(hmac, buf + len - 32, 32); // save hmac

	buf[len - 32] = buf[0]; // copy prefix
	buf[len - 31] = buf[1];

	hmac_sha256(hmac_key, 32, buf + ENCAP_IV, msglen + 16 + 2, buf + len - 32); // overwrite received hmac

	err = memcmp(hmac, buf + len - 32, 32); // compare

	if (err)
		return -1; // hmac err

	// decrypt

	aes128ctr_setup(aes_expanded_key, aes_key, buf + ENCAP_IV);
	aes128ctr_encrypt(aes_expanded_key, msg, msglen); // encrypt does decrypt in CTR mode

	return 0;
}
// Returns (1 / a) mod p

uint32_t *
ec_modinv(uint32_t *a, uint32_t *p)
{
	return ec_modinv_v1(a, p);
}

uint32_t *
ec_modinv_v1(uint32_t *a, uint32_t *p)
{
	uint32_t *k, *r, *u, *v, *t, *x1, *x2;
	u = ec_dup(a);
	v = ec_dup(p);
	x1 = ec_int(1);
	x2 = ec_int(0);
	while (!ec_equal(u, 1) && !ec_equal(v, 1)) {
		while ((u[0] & 1) == 0) {
			ec_shr(u);
			if (x1[0] & 1) {
				t = ec_add(x1, p);
				ec_free(x1);
				x1 = t;
			}
			ec_shr(x1);
		}
		while ((v[0] & 1) == 0) {
			ec_shr(v);
			if (x2[0] & 1) {
				t = ec_add(x2, p);
				ec_free(x2);
				x2 = t;
			}
			ec_shr(x2);
		}
		if (ec_cmp(u, v) >= 0) {
			t = ec_sub(u, v);
			ec_free(u);
			u = t;
			// x1 = x1 - x2
			k = ec_sub(p, x2);
			t = ec_add(x1, k);
			ec_free(x1);
			x1 = t;
			ec_mod(x1, p);
			ec_free(k);
		} else {
			t = ec_sub(v, u);
			ec_free(v);
			v = t;
			// x2 = x2 - x1
			k = ec_sub(p, x1);
			t = ec_add(x2, k);
			ec_free(x2);
			x2 = t;
			ec_mod(x2, p);
			ec_free(k);
		}
	}
	if (ec_equal(u, 1)) {
		r = x1;
		ec_free(x2);
	} else {
		r = x2;
		ec_free(x1);
	}
	ec_free(u);
	ec_free(v);
	return r;
}

// Ref. Anton Iliev, Nikolay Kyurkchiev, Asen Rahnev paper

uint32_t *
ec_modinv_v2(uint32_t *a, uint32_t *p)
{
	int i;
	uint32_t *q, *r, *u1, *u3, *v1, *v3, *t, *t1, *t3;

	u1 = ec_int(1);
	u3 = ec_dup(a);
	v1 = ec_int(0);
	v3 = ec_dup(p);

	q = NULL;
	t = NULL;
	t1 = NULL;
	t3 = NULL;

	i = 1;

	while (!ec_equal(v3, 0)) {

		// q = u3 / v3

		ec_free(q);
		q = ec_div(u3, v3);

		// t3 = u3 % v3

		ec_free(t3);
		t3 = ec_dup(u3);
		ec_mod(t3, v3);

		// t1 = u1 + q * v1;

		ec_free(t);
		t = ec_mul(q, v1);
		ec_free(t1);
		t1 = ec_add(u1, t);

		// u1 = v1

		// v1 = t1

		ec_free(u1);
		u1 = v1;
		v1 = t1;
		t1 = NULL;

		// u3 = v3

		// v3 = t3

		ec_free(u3);
		u3 = v3;
		v3 = t3;
		t3 = NULL;

		i = -i;
	}

	if (!ec_equal(u3, 1))
		r = ec_int(0);
	else if (i < 0)
		r = ec_sub(p, u1);
	else {
		r = u1;
		u1 = NULL;
	}

	ec_free(q);
	ec_free(u1);
	ec_free(u3);
	ec_free(v1);
	ec_free(v3);
	ec_free(t);
	ec_free(t1);
	ec_free(t3);

	return r;
}

// Ref. M. Brown, D. Hankerson, J. Lopez, A. Menezes paper

// This code does not work

uint32_t *
ec_modinv_v3(uint32_t *a, uint32_t *p)
{
	uint32_t *t, *u, *v, *A, *C;

	u = ec_dup(a);
	v = ec_dup(p);

	A = ec_int(1);
	C = ec_int(0);

	while (!ec_equal(u, 0)) {

		// while u is even

		while ((u[0] & 1) == 0) {
			// u = u / 2
			ec_shr(u);
			// if A is odd then A = A + p
			if (A[0] & 1) {
				t = ec_add(A, p);
				ec_free(A);
				A = t;
			}
			// A = A / 2
			ec_shr(A);
		}

		// while v is even

		while ((v[0] & 1) == 0) {
			// v = v / 2
			ec_shr(v);
			// if C is odd then C = C + p
			if (C[0] & 1) {
				t = ec_add(C, p);
				ec_free(C);
				C = t;
			}
			// C = C / 2
			ec_shr(C);
		}

		if (ec_cmp(u, v) >= 0) {
			// u = u - v
			t = ec_sub(u, v);
			ec_free(u);
			u = t;
			// A = A - C
			t = ec_sub(A, C);
			ec_free(A);
			A = t;
		} else {
			// v = v - u
			t = ec_sub(v, u);
			ec_free(v);
			v = t;
			// C = C - A
			t = ec_sub(C, A);
			ec_free(C);
			C = t;
		}
	}

	ec_mod(C, p);

	ec_free(u);
	ec_free(v);
	ec_free(A);

	return C;
}

void
ec_projectify(struct point *S)
{
	ec_free(S->z);
	S->z = ec_int(1);
}

int
ec_affinify(struct point *S, uint32_t *p)
{
	uint32_t *lambda, *lambda2, *lambda3, *x, *y;

	if (ec_equal(S->z, 0))
		return -1;

	lambda = ec_modinv(S->z, p);

	lambda2 = ec_mul(lambda, lambda);
	ec_mod(lambda2, p);

	lambda3 = ec_mul(lambda2, lambda);
	ec_mod(lambda3, p);

	x = ec_mul(lambda2, S->x);
	ec_mod(x, p);

	y = ec_mul(lambda3, S->y);
	ec_mod(y, p);

	ec_free_xyz(S);

	S->x = x;
	S->y = y;

	ec_free(lambda);
	ec_free(lambda2);
	ec_free(lambda3);

	return 0;
}

void
ec_double(struct point *R, struct point *S, uint32_t *p)
{
	if (ec_equal(a256, 0))
		ec_double_v2k1(R, S, p);
	else
		ec_double_v2r1(R, S, p, a256);
}

// Ref. Shay Gueron, Vlad Krasnov paper

void
ec_double_v2k1(struct point *R, struct point *S, uint32_t *p)
{
	uint32_t *x, *y, *z;
	uint32_t *xp, *yp, *zp;
	uint32_t *c2, *c3, *c4, *c8, *m, *s, *t, *u, *v, *x2, *y2, *y4;

	x = S->x;
	y = S->y;
	z = S->z;

	c2 = ec_int(2);
	c3 = ec_int(3);
	c4 = ec_int(4);
	c8 = ec_int(8);

	// s == 4 x y^2

	y2 = ec_mul(y, y);
	ec_mod(y2, p);

	t = ec_mul(x, y2);
	s = ec_mul(c4, t);
	ec_free(t);
	ec_mod(s, p);

	// m = 3 x^2 + a Z^4, a = 0 for secp256k1

	x2 = ec_mul(x, x);
	m = ec_mul(c3, x2);
	ec_mod(m, p);

	// x' = m^2 - 2 s

	u = ec_mul(m, m);
	ec_mod(u, p);

	v = ec_mul(c2, s);
	ec_mod(v, p);

	if (ec_cmp(u, v) < 0) {
		t = ec_add(u, p);
		ec_free(u);
		u = t;
	}

	xp = ec_sub(u, v);
	ec_mod(xp, p);

	ec_free(u);
	ec_free(v);

	// y' = m (s - x') - 8 y^4

	if (ec_cmp(s, xp) < 0) {
		t = ec_add(s, p);
		ec_free(s);
		s = t;
	}

	t = ec_sub(s, xp);
	u = ec_mul(m, t);
	ec_free(t);
	ec_mod(u, p);

	y4 = ec_mul(y2, y2);
	v = ec_mul(c8, y4);
	ec_mod(v, p);

	if (ec_cmp(u, v) < 0) {
		t = ec_add(u, p);
		ec_free(u);
		u = t;
	}

	yp = ec_sub(u, v);
	ec_mod(yp, p);

	ec_free(u);
	ec_free(v);

	// z' = 2 y z

	t = ec_mul(y, z);
	zp = ec_mul(c2, t);
	ec_free(t);
	ec_mod(zp, p);

	// return x', y', z'

	ec_free_xyz(R);

	R->x = xp;
	R->y = yp;
	R->z = zp;

	ec_free(c2);
	ec_free(c3);
	ec_free(c4);
	ec_free(c8);
	ec_free(m);
	ec_free(s);
	ec_free(x2);
	ec_free(y2);
	ec_free(y4);
}

void
ec_double_v2r1(struct point *R, struct point *S, uint32_t *p, uint32_t *a)
{
	uint32_t *x, *y, *z;
	uint32_t *xp, *yp, *zp;
	uint32_t *c2, *c3, *c4, *c8, *m, *s, *t, *u, *v, *x2, *y2, *y4, *z2, *z4;

	x = S->x;
	y = S->y;
	z = S->z;

	c2 = ec_int(2);
	c3 = ec_int(3);
	c4 = ec_int(4);
	c8 = ec_int(8);

	// s == 4 x y^2

	y2 = ec_mul(y, y);
	ec_mod(y2, p);

	t = ec_mul(x, y2);
	s = ec_mul(c4, t);
	ec_free(t);
	ec_mod(s, p);

	// m = 3 x^2 + a Z^4

	x2 = ec_mul(x, x);
	ec_mod(x2, p);
	u = ec_mul(c3, x2);

	z2 = ec_mul(z, z);
	ec_mod(z2, p);

	z4 = ec_mul(z2, z2);
	ec_mod(z4, p);

	v = ec_mul(a, z4);

	m = ec_add(u, v);

	ec_free(u);
	ec_free(v);

	ec_mod(m, p);

	// x' = m^2 - 2 s

	u = ec_mul(m, m);
	ec_mod(u, p);

	v = ec_mul(c2, s);
	ec_mod(v, p);

	if (ec_cmp(u, v) < 0) {
		t = ec_add(u, p);
		ec_free(u);
		u = t;
	}

	xp = ec_sub(u, v);
	ec_mod(xp, p);

	ec_free(u);
	ec_free(v);

	// y' = m (s - x') - 8 y^4

	if (ec_cmp(s, xp) < 0) {
		t = ec_add(s, p);
		ec_free(s);
		s = t;
	}

	t = ec_sub(s, xp);
	u = ec_mul(m, t);
	ec_free(t);
	ec_mod(u, p);

	y4 = ec_mul(y2, y2);
	v = ec_mul(c8, y4);
	ec_mod(v, p);

	if (ec_cmp(u, v) < 0) {
		t = ec_add(u, p);
		ec_free(u);
		u = t;
	}

	yp = ec_sub(u, v);
	ec_mod(yp, p);

	ec_free(u);
	ec_free(v);

	// z' = 2 y z

	t = ec_mul(y, z);
	zp = ec_mul(c2, t);
	ec_free(t);
	ec_mod(zp, p);

	// return x', y', z'

	ec_free_xyz(R);

	R->x = xp;
	R->y = yp;
	R->z = zp;

	ec_free(c2);
	ec_free(c3);
	ec_free(c4);
	ec_free(c8);
	ec_free(m);
	ec_free(s);
	ec_free(x2);
	ec_free(y2);
	ec_free(y4);
	ec_free(z2);
	ec_free(z4);
}

// This code is from 'Mathematical routines for the NIST prime elliptic curves'

// This code works for secp256r1 but does not work for secp256k1

// (Because "a" is different in the polynomial y^2 = x^3 + a x + b)

void
ec_double_v1(struct point *R, struct point *S, uint32_t *p)
{
	uint32_t *k, *t, *t1, *t2, *t3, *t4, *t5;

	// take care to handle the case when R and S are the same pointer

	t1 = ec_dup(S->x);
	t2 = ec_dup(S->y);
	t3 = ec_dup(S->z);

	ec_free_xyz(R);

	if (ec_equal(t3, 0)) {
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		ec_free(t1);
		ec_free(t2);
		ec_free(t3);
		return;
	}

	// 7: t4 = t3 * t3

	t4 = ec_mul(t3, t3);
	ec_mod(t4, p);

	// 8: t5 = t1 - t4

	t = ec_sub(p, t4);
	t5 = ec_add(t1, t);
	ec_free(t);
	ec_mod(t5, p);

	// 9: t4 = t1 + t4

	t = ec_add(t1, t4);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 10: t5 = t4 * t5

	t = ec_mul(t4, t5);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 11: t4 = 3 * t5

	k = ec_int(3);
	ec_free(t4);
	t4 = ec_mul(k, t5);
	ec_free(k);
	ec_mod(t4, p);

	// 12: t3 = t3 * t2

	t = ec_mul(t3, t2);
	ec_free(t3);
	t3 = t;
	ec_mod(t3, p);

	// 13: t3 = 2 * t3

	t = ec_add(t3, t3);
	ec_free(t3);
	t3 = t;
	ec_mod(t3, p);

	// 14: t2 = t2 * t2

	t = ec_mul(t2, t2);
	ec_free(t2);
	t2 = t;
	ec_mod(t2, p);

	// 15: t5 = t1 * t2

	t = ec_mul(t1, t2);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 16: t5 = 4 * t5

	k = ec_int(4);
	t = ec_mul(k, t5);
	ec_free(t5);
	t5 = t;
	ec_free(k);
	ec_mod(t5, p);

	// 17: t1 = t4 * t4

	ec_free(t1);
	t1 = ec_mul(t4, t4);
	ec_mod(t1, p);

	// 18: t1 = t1 - 2 * t5

	k = ec_sub(p, t5);
	t = ec_add(t1, k);
	ec_free(t1);
	t1 = ec_add(t, k);
	ec_free(k);
	ec_free(t);
	ec_mod(t1, p);

	// 19: t2 = t2 * t2

	t = ec_mul(t2, t2);
	ec_free(t2);
	t2 = t;
	ec_mod(t2, p);

	// 20: t2 = 8 * t2

	k = ec_int(8);
	t = ec_mul(k, t2);
	ec_free(t2);
	t2 = t;
	ec_free(k);
	ec_mod(t2, p);

	// 21: t5 = t5 - t1

	k = ec_sub(p, t1);
	t = ec_add(t5, k);
	ec_free(t5);
	t5 = t;
	ec_free(k);
	ec_mod(t5, p);

	// 22: t5 = t4 * t5

	t = ec_mul(t4, t5);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 23: t2 = t5 - t2

	t = ec_sub(p, t2);
	ec_free(t2);
	t2 = ec_add(t5, t);
	ec_free(t);
	ec_mod(t2, p);

	R->x = t1;
	R->y = t2;
	R->z = t3;

	ec_free(t4);
	ec_free(t5);
}

void
ec_add_xyz(struct point *R, struct point *S, struct point *T, uint32_t *p)
{
	uint32_t *k, *t, *t1, *t2, *t3, *t4, *t5, *t6, *t7;

	t1 = ec_dup(S->x);
	t2 = ec_dup(S->y);
	t3 = ec_dup(S->z);

	t4 = ec_dup(T->x);
	t5 = ec_dup(T->y);
	t6 = ec_dup(T->z);

	ec_free_xyz(R);

	if (!ec_equal(t6, 1)) {

		// 4: t7 = t6 * t6

		t7 = ec_mul(t6, t6);
		ec_mod(t7, p);

		// 5: t1 = t1 * t7

		t = ec_mul(t1, t7);
		ec_free(t1);
		t1 = t;
		ec_mod(t1, p);

		// 6: t7 = t6 * t7

		t = ec_mul(t6, t7);
		ec_free(t7);
		t7 = t;
		ec_mod(t7, p);

		// 7: t2 = t2 * t7

		t = ec_mul(t2, t7);
		ec_free(t2);
		t2 = t;
		ec_mod(t2, p);

		ec_free(t7);
	}

	// 9: t7 = t3 * t3

	t7 = ec_mul(t3, t3);
	ec_mod(t7, p);

	// 10: t4 = t4 * t7

	t = ec_mul(t4, t7);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 11: t7 = t3 * t7

	t = ec_mul(t3, t7);
	ec_free(t7);
	t7 = t;
	ec_mod(t7, p);

	// 12: t5 = t5 * t7

	t = ec_mul(t5, t7);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 13: t4 = t1 - t4

	t = ec_sub(p, t4);
	ec_free(t4);
	t4 = ec_add(t1, t);
	ec_free(t);
	ec_mod(t4, p);

	// 14: t5 = t2 - t5

	t = ec_sub(p, t5);
	ec_free(t5);
	t5 = ec_add(t2, t);
	ec_free(t);
	ec_mod(t5, p);

	if (ec_equal(t4, 0)) {
		if (ec_equal(t5, 0)) {
			R->x = ec_int(0);
			R->y = ec_int(0);
			R->z = ec_int(0);
		} else {
			R->x = ec_int(1);
			R->y = ec_int(1);
			R->z = ec_int(0);
		}
		ec_free(t1);
		ec_free(t2);
		ec_free(t3);
		ec_free(t4);
		ec_free(t5);
		ec_free(t6);
		ec_free(t7);
		return;
	}

	// 22: t1 = 2 * t1 - t4

	t = ec_add(t1, t1);
	ec_free(t1);
	t1 = t;
	k = ec_sub(p, t4);
	t = ec_add(t1, k);
	ec_free(t1);
	t1 = t;
	ec_free(k);
	ec_mod(t1, p);

	// 23: t2 = 2 * t2 - t5

	t = ec_add(t2, t2);
	ec_free(t2);
	t2 = t;
	k = ec_sub(p, t5);
	t = ec_add(t2, k);
	ec_free(t2);
	t2 = t;
	ec_free(k);
	ec_mod(t2, p);

	if (!ec_equal(t6, 1)) {

		// 25: t3 = t3 * t6

		t = ec_mul(t3, t6);
		ec_free(t3);
		t3 = t;
		ec_mod(t3, p);
	}

	// 27: t3 = t3 * t4

	t = ec_mul(t3, t4);
	ec_free(t3);
	t3 = t;
	ec_mod(t3, p);

	// 28: t7 = t4 * t4

	t = ec_mul(t4, t4);
	ec_free(t7);
	t7 = t;
	ec_mod(t7, p);

	// 29: t4 = t4 * t7

	t = ec_mul(t4, t7);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 30: t7 = t1 * t7

	t = ec_mul(t1, t7);
	ec_free(t7);
	t7 = t;
	ec_mod(t7, p);

	// 31: t1 = t5 * t5

	ec_free(t1);
	t1 = ec_mul(t5, t5);
	ec_mod(t1, p);

	// 32: t1 = t1 - t7

	k = ec_sub(p, t7);
	t = ec_add(t1, k);
	ec_free(t1);
	t1 = t;
	ec_free(k);
	ec_mod(t1, p);

	// 33: t7 = t7 - 2 * t1

	k = ec_sub(p, t1);
	t = ec_add(t7, k);
	ec_free(t7);
	t7 = ec_add(t, k);
	ec_free(k);
	ec_free(t);
	ec_mod(t7, p);

	// 34: t5 = t5 * t7

	t = ec_mul(t5, t7);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 35: t4 = t2 * t4

	t = ec_mul(t2, t4);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 36: t2 = t5 - t4

	t = ec_sub(p, t4);
	ec_free(t2);
	t2 = ec_add(t5, t);
	ec_free(t);
	ec_mod(t2, p);

	// 37: t2 = t2 / 2

	if (t2[0] & 1) {
		t = ec_add(t2, p);
		ec_free(t2);
		t2 = t;
	}
	ec_shr(t2);

	R->x = t1;
	R->y = t2;
	R->z = t3;

	ec_free(t4);
	ec_free(t5);
	ec_free(t6);
	ec_free(t7);
}

void
ec_full_add(struct point *R, struct point *S, struct point *T, uint32_t *p)
{
	uint32_t *x, *y, *z;
	struct point U;

	if (ec_equal(S->z, 0)) {
		x = ec_dup(T->x);
		y = ec_dup(T->y);
		z = ec_dup(T->z);
		ec_free_xyz(R);
		R->x = x;
		R->y = y;
		R->z = z;
		return;
	}

	if (ec_equal(T->z, 0)) {
		x = ec_dup(S->x);
		y = ec_dup(S->y);
		z = ec_dup(S->z);
		ec_free_xyz(R);
		R->x = x;
		R->y = y;
		R->z = z;
		return;
	}

	U.x = NULL;
	U.y = NULL;
	U.z = NULL;

	ec_add_xyz(&U, S, T, p);

	if (ec_equal(U.x, 0) && ec_equal(U.y, 0) && ec_equal(U.z, 0))
		ec_double(&U, S, p);

	ec_free_xyz(R);

	R->x = U.x;
	R->y = U.y;
	R->z = U.z;
}

void
ec_full_sub(struct point *R, struct point *S, struct point *T, uint32_t *p)
{
	struct point U;

	U.x = ec_dup(T->x);
	U.y = ec_sub(p, T->y);
	U.z = ec_dup(T->z);

	ec_full_add(R, S, &U, p);

	ec_free_xyz(&U);
}

// R = (d S) mod p

#if 1

void
ec_mult(struct point *R, uint32_t *d, struct point *S, uint32_t *p)
{
	int i;

	ec_free_xyz(R);

	if (ec_equal(d, 0)) {
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		return;
	}

	if (ec_equal(d, 1)) {
		R->x = ec_dup(S->x);
		R->y = ec_dup(S->y);
		R->z = ec_dup(S->z);
		return;
	}

	if (ec_equal(S->z, 0)) {
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		return;
	}

	if (!ec_equal(S->z, 1)) {
		ec_affinify(S, p);
		ec_projectify(S);
	}

	R->x = ec_int(0);
	R->y = ec_int(0);
	R->z = ec_int(0);

	for (i = 32 * len(d) - 1; i >= 0; i--) {

		ec_double(R, R, p);

		if (ec_get_bit(d, i))
			ec_full_add(R, R, S, p);
	}
}

#else

// original NIST algorithm

void
ec_mult(struct point *R, uint32_t *d, struct point *S, uint32_t *p)
{
	int h, i, k, l;
	uint32_t *t, *u, *x, *y, *z;
	struct point U;

	if (ec_equal(d, 0)) {
		ec_free_xyz(R);
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		return;
	}

	if (ec_equal(d, 1)) {
		x = ec_dup(S->x);
		y = ec_dup(S->y);
		z = ec_dup(S->z);
		ec_free_xyz(R);
		R->x = x;
		R->y = y;
		R->z = z;
		return;
	}

	if (ec_equal(S->z, 0)) {
		ec_free_xyz(R);
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		return;
	}

	if (!ec_equal(S->z, 1)) {
		ec_affinify(S, p);
		ec_projectify(S);
	}

	x = ec_dup(S->x);
	y = ec_dup(S->y);
	z = ec_dup(S->z);

	ec_free_xyz(R);

	R->x = x;
	R->y = y;
	R->z = z;

	u = ec_int(3);
	t = ec_mul(u, d);
	ec_free(u);

	l = ec_get_msbit_index(t);

	for (i = l - 1; i > 0; i--) {

		U.x = NULL;
		U.y = NULL;
		U.z = NULL;

		ec_double(R, R, p);

		h = ec_get_bit(t, i);
		k = ec_get_bit(d, i);

		if (h == 1 && k == 0)
			ec_full_add(&U, R, S, p);

		if (h == 0 && k == 1)
			ec_full_sub(&U, R, S, p);

		if (h != k) {
			ec_free_xyz(R);
			R->x = U.x;
			R->y = U.y;
			R->z = U.z;
		}
	}

	ec_free(t);
}

#endif

int
ec_get_msbit_index(uint32_t *u)
{
	int k, n;
	uint32_t m;
	m = 0x80000000;
	n = len(u);
	k = 32 * n - 1;
	while (m > 1) {
		if (u[n - 1] & m)
			break;
		m >>= 1;
		k--;
	}
	return k;
}

int
ec_get_bit(uint32_t *u, int k)
{
	int j;
	uint32_t m;
	if (k < 0)
		return 0;
	j = k / 32;
	if (j >= len(u))
		return 0;
	m = 1 << (k % 32);
	if (u[j] & m)
		return 1;
	else
		return 0;
}

int
ec_F(int t)
{
	if (18 <= t && t < 22)
		return 9;

	if (14 <= t && t < 18)
		return 10;

	if (22 <= t && t < 24)
		return 11;

	if (4 <= t && t < 12)
		return 14;

	return 12;
}

// R cannot point to S or T

void
ec_twin_mult(struct point *R, uint32_t *d0, struct point *S, uint32_t *d1, struct point *T, uint32_t *p)
{
	int c[2][6], h[2], i, k, m, m0, m1, u[2];
	struct point SpT, SmT;

	if (R == S || R == T) {
		printf("arg error\n");
		return;
	}

	SpT.x = NULL;
	SpT.y = NULL;
	SpT.z = NULL;

	SmT.x = NULL;
	SmT.y = NULL;
	SmT.z = NULL;

	ec_full_add(&SpT, S, T, p);
	ec_full_sub(&SmT, S, T, p);

	m0 = ec_get_msbit_index(d0) + 1;
	m1 = ec_get_msbit_index(d1) + 1;

	if (m0 > m1)
		m = m0;
	else
		m = m1;

	c[0][0] = 0;
	c[0][1] = 0;
	c[0][2] = ec_get_bit(d0, m - 1);
	c[0][3] = ec_get_bit(d0, m - 2);
	c[0][4] = ec_get_bit(d0, m - 3);
	c[0][5] = ec_get_bit(d0, m - 4);

	c[1][0] = 0;
	c[1][1] = 0;
	c[1][2] = ec_get_bit(d1, m - 1);
	c[1][3] = ec_get_bit(d1, m - 2);
	c[1][4] = ec_get_bit(d1, m - 3);
	c[1][5] = ec_get_bit(d1, m - 4);

	R->x = ec_int(1);
	R->y = ec_int(1);
	R->z = ec_int(0);

	for (k = m; k > -1; k--) {

		for (i = 0; i < 2; i++) {
			h[i] = 16 * c[i][1] + 8 * c[i][2] + 4 * c[i][3] + 2 * c[i][4] + c[i][5];
			if (c[i][0] == 1)
				h[i] = 31 - h[i];
		}

		for (i = 0; i < 2; i++) {
			if (h[i] < ec_F(h[1 - i]))
				u[i] = 0;
			else {
				if (c[i][0] & 1)
					u[i] = -1;
				else
					u[i] = 1;
			}
		}

		c[0][0] = abs(u[0]) ^ c[0][1];
		c[0][1] = c[0][2];
		c[0][2] = c[0][3];
		c[0][3] = c[0][4];
		c[0][4] = c[0][5];
		c[0][5] = ec_get_bit(d0, k - 5);

		c[1][0] = abs(u[1]) ^ c[1][1];
		c[1][1] = c[1][2];
		c[1][2] = c[1][3];
		c[1][3] = c[1][4];
		c[1][4] = c[1][5];
		c[1][5] = ec_get_bit(d1, k - 5);

		ec_double(R, R, p);

		if (u[0] == -1 && u[1] == -1)
			ec_full_sub(R, R, &SpT, p);

		if (u[0] == -1 && u[1] == 0)
			ec_full_sub(R, R, S, p);

		if (u[0] == -1 && u[1] == 1)
			ec_full_sub(R, R, &SmT, p);

		if (u[0] == 0 && u[1] == -1)
			ec_full_sub(R, R, T, p);

		if (u[0] == 0 && u[1] == 1)
			ec_full_add(R, R, T, p);

		if (u[0] == 1 && u[1] == -1)
			ec_full_add(R, R, &SmT, p);

		if (u[0] == 1 && u[1] == 0)
			ec_full_add(R, R, S, p);

		if (u[0] == 1 && u[1] == 1)
			ec_full_add(R, R, &SpT, p);
	}

	ec_free_xyz(&SpT);
	ec_free_xyz(&SmT);
}

void
ec_free_xyz(struct point *u)
{
	ec_free(u->x);
	ec_free(u->y);
	ec_free(u->z);
	u->x = NULL;
	u->y = NULL;
	u->z = NULL;
}

// returns u + v

uint32_t *
ec_add(uint32_t *u, uint32_t *v)
{
	int i, nu, nv, nw;
	uint64_t t;
	uint32_t *w;
	nu = len(u);
	nv = len(v);
	if (nu > nv)
		nw = nu + 1;
	else
		nw = nv + 1;
	w = ec_new(nw);
	for (i = 0; i < nu; i++)
		w[i] = u[i];
	for (i = nu; i < nw; i++)
		w[i] = 0;
	t = 0;
	for (i = 0; i < nv; i++) {
		t += (uint64_t) w[i] + v[i];
		w[i] = t;
		t >>= 32;
	}
	for (i = nv; i < nw; i++) {
		t += w[i];
		w[i] = t;
		t >>= 32;
	}
	ec_norm(w);
	return w;
}

// returns u - v

uint32_t *
ec_sub(uint32_t *u, uint32_t *v)
{
	int i, nu, nv, nw;
	uint64_t t;
	uint32_t *w;
	nu = len(u);
	nv = len(v);
	if (nu > nv)
		nw = nu;
	else
		nw = nv;
	w = ec_new(nw);
	for (i = 0; i < nu; i++)
		w[i] = u[i];
	for (i = nu; i < nw; i++)
		w[i] = 0;
	t = 0;
	for (i = 0; i < nv; i++) {
		t += (uint64_t) w[i] - v[i];
		w[i] = t;
		t = (int64_t) t >> 32; // cast to extend sign
	}
	for (i = nv; i < nw; i++) {
		t += w[i];
		w[i] = t;
		t = (int64_t) t >> 32; // cast to extend sign
	}
	ec_norm(w);
	return w;
}

// returns u * v

uint32_t *
ec_mul(uint32_t *u, uint32_t *v)
{
	int i, j, nu, nv, nw;
	uint64_t t;
	uint32_t *w;
	nu = len(u);
	nv = len(v);
	nw = nu + nv;
	w = ec_new(nw);
	for (i = 0; i < nu; i++)
		w[i] = 0;
	for (j = 0; j < nv; j++) {
		t = 0;
		for (i = 0; i < nu; i++) {
			t += (uint64_t) u[i] * v[j] + w[i + j];
			w[i + j] = t;
			t >>= 32;
		}
		w[i + j] = t;
	}
	ec_norm(w);
	return w;
}

// returns floor(u / v)

uint32_t *
ec_div(uint32_t *u, uint32_t *v)
{
	int i, k, nu, nv;
	uint32_t *q, qhat, *w;
	uint64_t a, b, t;
	ec_norm(u);
	ec_norm(v);
	if (len(v) == 1 && v[0] == 0)
		return NULL; // v = 0
	nu = len(u);
	nv = len(v);
	k = nu - nv;
	if (k < 0) {
		q = ec_new(1);
		q[0] = 0;
		return q; // u < v, return zero
	}
	u = ec_dup(u);
	q = ec_new(k + 1);
	w = ec_new(nv + 1);
	b = v[nv - 1];
	do {
		q[k] = 0;
		while (nu >= nv + k) {
			// estimate 32-bit partial quotient
			a = u[nu - 1];
			if (nu > nv + k)
				a = a << 32 | u[nu - 2];
			if (a < b)
				break;
			qhat = a / (b + 1);
			if (qhat == 0)
				qhat = 1;
			// w = qhat * v
			t = 0;
			for (i = 0; i < nv; i++) {
				t += (uint64_t) qhat * v[i];
				w[i] = t;
				t >>= 32;
			}
			w[nv] = t;
			// u = u - w
			t = 0;
			for (i = k; i < nu; i++) {
				t += (uint64_t) u[i] - w[i - k];
				u[i] = t;
				t = (int64_t) t >> 32; // cast to extend sign
			}
			if (t) {
				// u is negative, restore u
				t = 0;
				for (i = k; i < nu; i++) {
					t += (uint64_t) u[i] + w[i - k];
					u[i] = t;
					t >>= 32;
				}
				break;
			}
			q[k] += qhat;
			ec_norm(u);
			nu = len(u);
		}
	} while (--k >= 0);
	ec_norm(q);
	ec_free(u);
	ec_free(w);
	return q;
}

// u = u mod v

void
ec_mod(uint32_t *u, uint32_t *v)
{
	ec_mod_v1(u, v);
}

void
ec_mod_v1(uint32_t *u, uint32_t *v)
{
	int i, k, nu, nv;
	uint32_t qhat, *w;
	uint64_t a, b, t;
	ec_norm(u);
	ec_norm(v);
	if (len(v) == 1 && v[0] == 0)
		return; // v = 0
	nu = len(u);
	nv = len(v);
	k = nu - nv;
	if (k < 0)
		return; // u < v
	w = ec_new(nv + 1);
	b = v[nv - 1];
	do {
		while (nu >= nv + k) {
			// estimate 32-bit partial quotient
			a = u[nu - 1];
			if (nu > nv + k)
				a = a << 32 | u[nu - 2];
			if (a < b)
				break;
			qhat = a / (b + 1);
			if (qhat == 0)
				qhat = 1;
			// w = qhat * v
			t = 0;
			for (i = 0; i < nv; i++) {
				t += (uint64_t) qhat * v[i];
				w[i] = t;
				t >>= 32;
			}
			w[nv] = t;
			// u = u - w
			t = 0;
			for (i = k; i < nu; i++) {
				t += (uint64_t) u[i] - w[i - k];
				u[i] = t;
				t = (int64_t) t >> 32; // cast to extend sign
			}
			if (t) {
				// u is negative, restore u
				t = 0;
				for (i = k; i < nu; i++) {
					t += (uint64_t) u[i] + w[i - k];
					u[i] = t;
					t >>= 32;
				}
				break;
			}
			ec_norm(u);
			nu = len(u);
		}
	} while (--k >= 0);
	ec_free(w);
}

void
ec_mod_v2(uint32_t *u, uint32_t *v)
{
	uint32_t *q, *r, *t;

	q = ec_div(u, v);
	t = ec_mul(q, v);
	r = ec_sub(u, t);

	memcpy(u, r, len(r) * sizeof (uint32_t));

	len(u) = len(r);

	ec_free(q);
	ec_free(r);
	ec_free(t);
}

// returns u ** v

uint32_t *
ec_pow(uint32_t *u, uint32_t *v)
{
	uint32_t *t, *w;
	u = ec_dup(u);
	v = ec_dup(v);
	// w = 1
	w = ec_new(1);
	w[0] = 1;
	for (;;) {
		if (v[0] & 1) {
			// w = w * u
			t = ec_mul(w, u);
			ec_free(w);
			w = t;
		}
		// v = v >> 1
		ec_shr(v);
		// v = 0?
		if (len(v) == 1 && v[0] == 0)
			break;
		// u = u * u
		t = ec_mul(u, u);
		ec_free(u);
		u = t;
	}
	ec_free(u);
	ec_free(v);
	return w;
}

// u = u >> 1

void
ec_shr(uint32_t *u)
{
	int i;
	for (i = 0; i < len(u) - 1; i++) {
		u[i] >>= 1;
		if (u[i + 1] & 1)
			u[i] |= 0x80000000;
	}
	u[i] >>= 1;
	ec_norm(u);
}

// compare u and v

int
ec_cmp(uint32_t *u, uint32_t *v)
{
	int i;
	ec_norm(u);
	ec_norm(v);
	if (len(u) < len(v))
		return -1;
	if (len(u) > len(v))
		return 1;
	for (i = len(u) - 1; i >= 0; i--) {
		if (u[i] < v[i])
			return -1;
		if (u[i] > v[i])
			return 1;
	}
	return 0; // u = v
}

int
ec_equal(uint32_t *u, uint32_t v)
{
	if (len(u) == 1 && u[0] == v)
		return 1;
	else
		return 0;
}

uint32_t *
ec_int(int k)
{
	uint32_t *u;
	u = ec_new(1);
	u[0] = k;
	return u;
}

int ec_malloc_count;

uint32_t *
ec_new(int n)
{
	uint32_t *u;
	u = (uint32_t *) malloc((n + 1) * sizeof (uint32_t));
	if (u == NULL) {
		printf("malloc error\n");
		exit(1);
	}
	ec_malloc_count++;
	u[0] = n;
	return u + 1;
}

void
ec_free(uint32_t *u)
{
	if (u) {
		free(u - 1);
		ec_malloc_count--;
	}
}

uint32_t *
ec_dup(uint32_t *u)
{
	int i;
	uint32_t *v;
	v = ec_new(len(u));
	for (i = 0; i < len(u); i++)
		v[i] = u[i];
	return v;
}

// remove leading zeroes

void
ec_norm(uint32_t *u)
{
	while (len(u) > 1 && u[len(u) - 1] == 0)
		len(u)--;
}

uint32_t *
ec_hexstr_to_bignum(char *s)
{
	int d, i, len, n;
	uint32_t *u;
	len = strlen(s);
	n = (len + 7) / 8; // convert len to number of uint32_t ints
	u = ec_new(n);
	for (i = 0; i < n; i++)
		u[i] = 0;
	for (i = 0; i < len; i++) {
		d = s[len - i - 1];
		if ('0' <= d && d <= '9')
			d -= '0';
		else if ('A' <= d && d <= 'F')
			d -= 'A' - 10;
		else if ('a' <= d && d <= 'f')
			d -= 'a' - 10;
		else {
			ec_free(u);
			return NULL;
		}
		u[i / 8] |= d << (4 * (i % 8));
	}
	ec_norm(u);
	return u;
}

uint32_t *
ec_buf_to_bignum(uint8_t *buf, int len)
{
	int i, n, t;
	uint32_t *u;
	n = (len + 3) / 4;
	u = ec_new(n);
	t = 0;
	for (i = 0; i < len; i++) {
		t = t << 8 | buf[i];
		if ((len - i - 1) % 4 == 0) {
			u[--n] = t;
			t = 0;
		}
	}
	ec_norm(u);
	return u;
}

uint32_t *p256, *q256, *gx256, *gy256, *a256, *b256;

#if SECP256K1

// secp256k1

#define STR_P "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFE" "FFFFFC2F"
#define STR_Q "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFE" "BAAEDCE6" "AF48A03B" "BFD25E8C" "D0364141"
#define STR_GX "79BE667E" "F9DCBBAC" "55A06295" "CE870B07" "029BFCDB" "2DCE28D9" "59F2815B" "16F81798"
#define STR_GY "483ADA77" "26A3C465" "5DA4FBFC" "0E1108A8" "FD17B448" "A6855419" "9C47D08F" "FB10D4B8"
#define STR_A "0"
#define STR_B "7"

#else

// secp256r1

#define STR_P "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
#define STR_Q "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
#define STR_GX "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define STR_GY "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
#define STR_A "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"
#define STR_B "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"

#endif

void
ec_init(void)
{
	p256 = ec_hexstr_to_bignum(STR_P);
	q256 = ec_hexstr_to_bignum(STR_Q);
	gx256 = ec_hexstr_to_bignum(STR_GX);
	gy256 = ec_hexstr_to_bignum(STR_GY);
	a256 = ec_hexstr_to_bignum(STR_A);
	b256 = ec_hexstr_to_bignum(STR_B);

	ec_malloc_count = 0;
}
// shared_secret	32 bytes (result)
// private_key		32 bytes
// public_key		64 bytes

void
ec_ecdh(uint8_t *shared_secret, uint8_t *private_key, uint8_t *public_key)
{
	int i;
	uint32_t *d;
	struct point R, S;

	d = ec_buf_to_bignum(private_key, 32);

	R.x = ec_buf_to_bignum(public_key, 32);
	R.y = ec_buf_to_bignum(public_key + 32, 32);
	R.z = ec_int(1);

	S.x = NULL;
	S.y = NULL;
	S.z = NULL;

	// generate ecdh

	ec_mult(&S, d, &R, p256);
	ec_affinify(&S, p256);

	// save ecdh

	memset(shared_secret, 0, 32);

	for (i = 0; i < len(S.x); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err, result greater than 32 bytes, truncate
		// bignums are LE, this converts to BE
		shared_secret[32 - 4 * i - 4] = S.x[i] >> 24;
		shared_secret[32 - 4 * i - 3] = S.x[i] >> 16;
		shared_secret[32 - 4 * i - 2] = S.x[i] >> 8;
		shared_secret[32 - 4 * i - 1] = S.x[i];
	}

	ec_free(d);
	ec_free_xyz(&R);
	ec_free_xyz(&S);
}
// private_key	32 bytes (result)
// public_key	64 bytes (result)

void
ec_genkey(uint8_t *private_key, uint8_t *public_key)
{
	int i;
	uint32_t *d;
	struct point R, S;

	R.x = gx256;
	R.y = gy256;
	R.z = ec_int(1);

	S.x = NULL;
	S.y = NULL;
	S.z = NULL;

	d = NULL;

	do {
		ec_free(d);
		d = ec_new(8);

		// generate private key d

		for (i = 0; i < 8; i++)
			d[i] = random();

		ec_norm(d);
		ec_mod(d, q256);

	} while (ec_equal(d, 0));

	// generate public key

	ec_mult(&S, d, &R, p256);
	ec_affinify(&S, p256);

	// save private key

	memset(private_key, 0, 32);

	for (i = 0; i < len(d); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err, result greater than 32 bytes
		// bignums are LE, this converts to BE
		private_key[32 - 4 * i - 4] = d[i] >> 24;
		private_key[32 - 4 * i - 3] = d[i] >> 16;
		private_key[32 - 4 * i - 2] = d[i] >> 8;
		private_key[32 - 4 * i - 1] = d[i];
	}

	// save public key

	memset(public_key, 0, 64);

	for (i = 0; i < len(S.x); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err, result greater than 32 bytes
		// bignums are LE, this converts to BE
		public_key[32 - 4 * i - 4] = S.x[i] >> 24;
		public_key[32 - 4 * i - 3] = S.x[i] >> 16;
		public_key[32 - 4 * i - 2] = S.x[i] >> 8;
		public_key[32 - 4 * i - 1] = S.x[i];
	}

	for (i = 0; i < len(S.y); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err, result greater than 32 bytes
		// bignums are LE, this converts to BE
		public_key[64 - 4 * i - 4] = S.y[i] >> 24;
		public_key[64 - 4 * i - 3] = S.y[i] >> 16;
		public_key[64 - 4 * i - 2] = S.y[i] >> 8;
		public_key[64 - 4 * i - 1] = S.y[i];
	}

	ec_free(d);
	ec_free(R.z);
	ec_free_xyz(&S);
}
// public_key	64 bytes (result)
// private_key	32 bytes

void
ec_pubkey(uint8_t *public_key, uint8_t *private_key)
{
	int i;
	uint32_t *d;
	struct point R, S;

	d = ec_buf_to_bignum(private_key, 32);

	R.x = gx256;
	R.y = gy256;
	R.z = ec_int(1);

	S.x = NULL;
	S.y = NULL;
	S.z = NULL;

	ec_mult(&S, d, &R, p256);
	ec_affinify(&S, p256);

	// save public key

	memset(public_key, 0, 64);

	for (i = 0; i < len(S.x); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err, result greater than 32 bytes
		// bignums are LE, this converts to BE
		public_key[32 - 4 * i - 4] = S.x[i] >> 24;
		public_key[32 - 4 * i - 3] = S.x[i] >> 16;
		public_key[32 - 4 * i - 2] = S.x[i] >> 8;
		public_key[32 - 4 * i - 1] = S.x[i];
	}

	for (i = 0; i < len(S.y); i++) {
		if (32 - 4 * i - 4 < 0)
			break; // err, result greater than 32 bytes
		// bignums are LE, this converts to BE
		public_key[64 - 4 * i - 4] = S.y[i] >> 24;
		public_key[64 - 4 * i - 3] = S.y[i] >> 16;
		public_key[64 - 4 * i - 2] = S.y[i] >> 8;
		public_key[64 - 4 * i - 1] = S.y[i];
	}

	ec_free(d);
	ec_free(R.z);
	ec_free_xyz(&S);
}
// rbuf		32 bytes (result)
// sbuf		32 bytes (result)
// hash		32 bytes typically the sha256 of text or binary data
// private_key	32 bytes

void
ec_sign(uint8_t *rbuf, uint8_t *sbuf, uint8_t *hash, uint8_t *private_key)
{
	int err, i;
	uint8_t h1[32], V[97], K[32];
	uint32_t *d, *h, *k, *r, *s, *t, *u;
	struct point G, R;

	d = ec_buf_to_bignum(private_key, 32);
	h = ec_buf_to_bignum(hash, 32);

	G.x = gx256;
	G.y = gy256;
	G.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	// see RFC 6979 section 3.2

	// a. h1 = H(m)

	sha256(hash, 32, h1); // hash == m

	// b. V = 0x01 0x01 0x01 ... 0x01

	memset(V, 0x01, 32);

	// c. K = 0x00 0x00 0x00 ... 0x00

	memset(K, 0x00, 32);

	// d. K = HMAC_K(V || 0x00 || x || h1)

	V[32] = 0x00;

	memcpy(V + 33, private_key, 32); // private_key == x
	memcpy(V + 65, h1, 32);

	hmac_sha256(K, 32, V, 97, K);

	// e. V = HMAC_K(V)

	hmac_sha256(K, 32, V, 32, V);

	// f. K = HMAC_K(V || 0x01 || x || h1)

	V[32] = 0x01;

	hmac_sha256(K, 32, V, 97, K);

	// g. V = HMAC_K(V)

	hmac_sha256(K, 32, V, 32, V);

	// h.

	V[32] = 0x00;

	for (;;) { // loop until return r, s

		// V = HMAC_K(V)

		hmac_sha256(K, 32, V, 32, V);

		// for this V, attempt to derive r, s

		for (;;) { // doesn't actually loop, code will either break or return

			k = ec_buf_to_bignum(V, 32);

			// 0 < k < q256 ?

			if (ec_equal(k, 0) || ec_cmp(k, q256) >= 0) {
				ec_free(k);
				break;
			}

			// R = k * G

			ec_mult(&R, k, &G, p256);
			err = ec_affinify(&R, p256);

			if (err) {
				ec_free(k);
				ec_free_xyz(&R);
				break;
			}

			// r = R.x mod n

			r = ec_dup(R.x);
			ec_mod(r, q256);

			if (ec_equal(r, 0)) {
				ec_free(k);
				ec_free(r);
				ec_free_xyz(&R);
				break;
			}

			// k = 1 / k

			t = ec_modinv(k, q256);
			ec_free(k);
			k = t;

			// s = k * (h + r * d) mod n

			t = ec_mul(r, d);

			ec_mod(t, q256);

			u = ec_add(h, t);
			ec_free(t);
			t = u;

			s = ec_mul(k, t);
			ec_free(t);

			ec_mod(s, q256);

			if (ec_equal(s, 0)) {
				ec_free(k);
				ec_free(r);
				ec_free(s);
				ec_free_xyz(&R);
				break;
			}

			// success

			// save r

			memset(rbuf, 0, 32);

			for (i = 0; i < len(r); i++) {
				if (32 - 4 * i - 4 < 0)
					break; // err, result greater than 32 bytes, truncate
				// bignums are LE, this converts to BE
				rbuf[32 - 4 * i - 4] = r[i] >> 24;
				rbuf[32 - 4 * i - 3] = r[i] >> 16;
				rbuf[32 - 4 * i - 2] = r[i] >> 8;
				rbuf[32 - 4 * i - 1] = r[i];
			}

			// save s

			memset(sbuf, 0, 32);

			for (i = 0; i < len(s); i++) {
				if (32 - 4 * i - 4 < 0)
					break; // err, result greater than 32 bytes, truncate
				// bignums are LE, this converts to BE
				sbuf[32 - 4 * i - 4] = s[i] >> 24;
				sbuf[32 - 4 * i - 3] = s[i] >> 16;
				sbuf[32 - 4 * i - 2] = s[i] >> 8;
				sbuf[32 - 4 * i - 1] = s[i];
			}

			ec_free(d);
			ec_free(h);
			ec_free(k);
			ec_free(r);
			ec_free(s);
			ec_free(G.z);
			ec_free_xyz(&R);

			return;
		}

		// K = HMAC_K(V || 0x00)

		hmac_sha256(K, 32, V, 33, K);
	}
}
// hash, r, s, public_key_x, public_key y --> ec_verify --> -1 or 0

int
ec_verify(uint8_t *hash, uint8_t *rbuf, uint8_t *sbuf, uint8_t *public_key_x, uint8_t *public_key_y)
{
	int err;
	uint32_t *h, *r, *s, *u, *v, *w;
	struct point R, S, T;

	h = ec_buf_to_bignum(hash, 32);
	r = ec_buf_to_bignum(rbuf, 32);
	s = ec_buf_to_bignum(sbuf, 32);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	S.x = gx256;
	S.y = gy256;
	S.z = ec_int(1);

	T.x = ec_buf_to_bignum(public_key_x, 32);
	T.y = ec_buf_to_bignum(public_key_y, 32);
	T.z = ec_int(1);

	w = ec_modinv(s, q256);

	u = ec_mul(h, w);
	ec_mod(u, q256);

	v = ec_mul(r, w);
	ec_mod(v, q256);

	ec_twin_mult(&R, u, &S, v, &T, p256);

	ec_affinify(&R, p256);

	ec_mod(R.x, q256);

	err = ec_cmp(R.x, r) == 0 ? 0 : -1;

	ec_free(h);
	ec_free(r);
	ec_free(s);
	ec_free(u);
	ec_free(v);
	ec_free(w);

	ec_free(S.z);

	ec_free_xyz(&R);
	ec_free_xyz(&T);

	return err;
}
// encap format
//
// prefix || 0x04 || R || iv || c || d
//
// prefix	length (2 bytes)
// R		ephemeral public key (64 bytes)
// iv		initialization vector (16 bytes)
// c		ciphertext
// d		hmac (32 bytes)

void
encap(uint8_t *buf, int len, struct node *p)
{
	int i, msglen;
	uint8_t *msg;
	uint8_t ephemeral_private_key[32];
	uint8_t ephemeral_public_key[64];
	uint8_t shared_secret[32];
	uint8_t hmac_key[32];
	uint8_t aes_key[16];
	uint32_t aes_expanded_key[48];

	msg = buf + ENCAP_C;		// ENCAP_C == 2 + 65 + 16
	msglen = len - ENCAP_OVERHEAD;	// ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	// derive shared secret

	ec_genkey(ephemeral_private_key, ephemeral_public_key);

	ec_ecdh(shared_secret, ephemeral_private_key, p->far_public_key);

	// derive AES and HMAC keys

	kdf(aes_key, hmac_key, shared_secret);

	// prefix

	buf[0] = (len - 2) >> 8;
	buf[1] = len - 2;

	// ephemeral key R

	buf[ENCAP_R] = 0x04; // uncompressed format
	memcpy(buf + ENCAP_R + 1, ephemeral_public_key, 64);

	// iv

	for (i = 0; i < 16; i++)
		buf[ENCAP_IV + i] = random();

	// encrypt the message

	aes128ctr_setup(aes_expanded_key, aes_key, buf + ENCAP_IV);
	aes128ctr_encrypt(aes_expanded_key, msg, msglen);

	// compute hmac over IV || C || prefix

	buf[len - 32] = buf[0];
	buf[len - 31] = buf[1];

	hmac_sha256(hmac_key, 32, buf + ENCAP_IV, msglen + 16 + 2, buf + len - 32);
}
int
enlength(struct atom *p)
{
	int len = sublength(p);
	return padlength(p, len) + len;
}

int
sublength(struct atom *p)
{
	int len;

	if (p == NULL)
		// empty list
		return 0;

	if (p->length < 0) {
		// list
		len = 0;
		while (p) {
			len += enlength(p->car);
			p = p->cdr;
		}
		return len;
	} else
		// string
		return p->length;
}

int
padlength(struct atom *p, int sublen)
{
	if (p == NULL)
		// empty list
		return 1;

	if (p->length == 1 && p->string[0] < 0x80)
		return 0;

	if (sublen < 56)
		return 1;

	if (sublen < 256)
		return 2;

	if (sublen < 65536)
		return 3;

	return 4;
}

struct account account_table[2];

void
init(void)
{
	read_account(account_table + 0, "Account1");
//	print_account(account_table + 0);
}

void
read_account(struct account *p, char *filename)
{
	char *buf;
	uint8_t hash[32];

	buf = read_file(filename);

	if (buf == NULL)
		return;

	if (strlen(buf) < 64) {
		free(buf);
		return;
	}

	hextobin(p->private_key, 32, buf);

	free(buf);

	ec_pubkey(p->public_key, p->private_key);

	// account number is hash of public keys

	keccak256(hash, p->public_key, 64);

	memcpy(p->account_number, hash + 12, 20);
}

char *
read_file(char *filename)
{
	int fd, n;
	char *buf;

	fd = open(filename, O_RDONLY, 0);

	if (fd == -1)
		return NULL;

	n = lseek(fd, 0, SEEK_END);

	if (n == -1) {
		close(fd);
		return NULL;
	}

	if (lseek(fd, 0, SEEK_SET) == -1) {
		close(fd);
		return NULL;
	}

	buf = malloc(n + 1);

	if (buf == NULL) {
		close(fd);
		return NULL;
	}

	if (read(fd, buf, n) != n) {
		close(fd);
		free(buf);
		return NULL;
	}

	close(fd);

	buf[n] = '\0';

	return buf;
}

void
print_account(struct account *p)
{
	int i;

	for (i = 0; i < 20; i++)
		printf("%02x", p->account_number[i]);
	printf("\n");

	for (i = 0; i < 32; i++)
		printf("%02x", p->private_key[i]);
	printf("\n");

	for (i = 0; i < 32; i++)
		printf("%02x", p->public_key[i]);
	printf("\n");

	for (i = 0; i < 32; i++)
		printf("%02x", p->public_key[32 + i]);
	printf("\n");
}
// aes_key		16 bytes (result)
// hmac_key		32 bytes (result)
// shared_secret	32 bytes

void
kdf(uint8_t *aes_key, uint8_t *hmac_key, uint8_t *shared_secret)
{
	uint8_t buf[36];

	// big endian counter = 1

	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 1;

	memcpy(buf + 4, shared_secret, 32);

	sha256(buf, 36, buf);

	// first 16 bytes are the AES key

	memcpy(aes_key, buf, 16);

	// hash last 16 bytes to get HMAC key

	sha256(buf + 16, 16, buf);

	memcpy(hmac_key, buf, 32);
}
// Keccak-256 (see Table 3 on page 22 of FIPS PUB 202 for rate and capacity)
//
// Rate		r = 1088 bits (136 bytes)
//
// Capacity	c = 512 bits (64 bytes)

#define RATE 136

#define A(x,y,z) A[320 * (x) + 64 * (y) + (z)]
#define Aprime(x,y,z) Aprime[320 * (x) + 64 * (y) + (z)]

uint8_t RC[64][24] = {
	{1,0,0,0,1,1,1,1,0,0,1,0,1,1,1,1,0,0,0,0,1,0,1,0},
	{0,1,1,0,1,0,0,0,1,0,0,1,1,1,0,1,1,0,1,1,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,1,0,1,0,0,1,1,1,1,1,1,1,1,0,0,0,1,1,0,0,0,1},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,1,1,0,1,0,1,0,1,1,0,0,1,1,1,0,0,1,0,0,1,1,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,1,1,1,1,0,1,1,0,0,1,0,1,0,1,1,1,0,1,0,1,1,0,1},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,1,0,1,1,0,0,0,1,1,1,0,0,0,0,0,0,1,1,0,1,1},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
	{0,0,1,1,0,0,1,1,0,0,0,0,0,1,1,1,1,1,0,1,1,1,0,1},
};

uint8_t *
theta(uint8_t *A)
{
	int x, y, z;
	static uint8_t Aprime[1600], C[5][64], D[5][64];

	for (x = 0; x < 5; x++)
		for (z = 0; z < 64; z++)
			C[x][z] = A(x,0,z) ^ A(x,1,z) ^ A(x,2,z) ^ A(x,3,z) ^ A(x,4,z);

	for (x = 0; x < 5; x++)
		for (z = 0; z < 64; z++)
			D[x][z] = C[(5 + x - 1) % 5][z] ^ C[(x + 1) % 5][(64 + z - 1) % 64];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				Aprime(x,y,z) = A(x,y,z) ^ D[x][z];

	return Aprime;
}

uint8_t *
rho(uint8_t *A)
{
	int t, u, x, y, z;
	static uint8_t Aprime[1600];

	for (z = 0; z < 64; z++)
		Aprime(0,0,z) = A(0,0,z);

	x = 1;
	y = 0;

	for (t = 0; t < 24; t++) {
		for (z = 0; z < 64; z++)
			Aprime(x,y,z) = A(x,y,(320 + z - (t + 1) * (t + 2) / 2) % 64);
		u = y;
		y = (2 * x + 3 * y) % 5;
		x = u;
	}

	return Aprime;
}

uint8_t *
pi(uint8_t *A)
{
	int x, y, z;
	static uint8_t Aprime[1600];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				Aprime(x,y,z) = A((x + 3 * y) % 5,x,z);

	return Aprime;
}

uint8_t *
chi(uint8_t *A)
{
	int x, y, z;
	static uint8_t Aprime[1600];

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				Aprime(x,y,z) = A(x,y,z) ^ ((A((x + 1) % 5,y,z) ^ 1) & A((x + 2) % 5,y,z));

	return Aprime;
}

uint8_t
rc(int t)
{
	int i, R;

	if (t % 255 == 0)
		return 1;

	R = 1;

	for (i = 1; i <= t % 255; i++) {
		R <<= 1;
		if (R & 0x100)
			R ^= 0x171;
	}

	return R & 1;
}

uint8_t *
iota(uint8_t *A, int ir)
{
	int z;

	for (z = 0; z < 64; z++)
		A(0,0,z) ^= RC[z][ir];

	return A;
}

uint8_t *
Rnd(uint8_t *A, int ir)
{
	return iota(chi(pi(rho(theta(A)))), ir);
}

uint8_t mask[8] = {1,2,4,8,0x10,0x20,0x40,0x80};

void
Keccak(uint8_t *S)
{
	int ir, k, x, y, z;
	static uint8_t a[1600], *A = a;

	// convert S to A

	memset(A, 0, 1600);

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++) {
				k = 64 * (5 * y + x) + z;
				if (S[k / 8] & mask[k % 8])
					A(x,y,z) = 1;
			}

	for (ir = 0; ir < 24; ir++)
		A = Rnd(A, ir);

	// convert A to S

	memset(S, 0, 200);

	for (x = 0; x < 5; x++)
		for (y = 0; y < 5; y++)
			for (z = 0; z < 64; z++)
				if (A(x,y,z)) {
					k = 64 * (5 * y + x) + z;
					S[k / 8] |= mask[k % 8];
				}
}

uint8_t *
sponge(uint8_t *N, int len)
{
	int i, j, k, n;
	static uint8_t S[200]; // 1600 bits

	memset(S, 0, 200);

	n = len / RATE; // number of full blocks

	for (i = 0; i < n; i++) {
		for (j = 0; j < RATE; j++)
			S[j] ^= N[RATE * i + j];
		Keccak(S);
	}

	// pad last block

	k = len % RATE;

	for (i = 0; i < k; i++)
		S[i] ^= N[RATE * n + i];

	S[k] ^= 0x01;
	S[RATE - 1] ^= 0x80;

	Keccak(S);

	return S;
}

void
keccak256(uint8_t *outbuf, uint8_t *inbuf, int inbuflen)
{
	uint8_t *S = sponge(inbuf, inbuflen);
	memcpy(outbuf, S, 32);
}

char *
keccak256str(uint8_t *buf, int len)
{
	int i;
	uint8_t *S;
	static char Z[65];

	S = sponge(buf, len);

	for (i = 0; i < 32; i++)
		sprintf(Z + 2 * i, "%02x", S[i]);

	return Z;
}

void
test_keccak256(void)
{
	int err;
	char *s;
	uint8_t buf[RATE + 1];

	printf("Test keccak256 ");

	memset(buf, 'a', sizeof buf);

	s = keccak256str(NULL, 0);
	err = strcmp(s, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	s = keccak256str((uint8_t *) "hello", 5);
	err = strcmp(s, "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8");
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	s = keccak256str(buf, RATE - 1);
	err = strcmp(s, "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446");
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	s = keccak256str(buf, RATE);
	err = strcmp(s, "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e");
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	s = keccak256str(buf, RATE + 1);
	err = strcmp(s, "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39");
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

void
keccak256_init(struct mac *p)
{
	memset(p->S, 0, 200);
	p->index = 0;
}

void
keccak256_update(struct mac *p, uint8_t *inbuf, int len)
{
	int i, j, n;

	// finish pending block

	if (p->index + len > RATE)
		n = RATE - p->index;
	else
		n = len;

	for (i = 0; i < n; i++)
		p->S[p->index + i] ^= inbuf[i];

	p->index += n;

	if (p->index < RATE)
		return;

	Keccak(p->S);

	// remaining blocks

	inbuf += n;
	len -= n;

	n = len / RATE; // number of full blocks

	for (i = 0; i < n; i++) {
		for (j = 0; j < RATE; j++)
			p->S[j] ^= inbuf[RATE * i + j];
		Keccak(p->S);
	}

	// remainder

	p->index = len % RATE;

	for (i = 0; i < p->index; i++)
		p->S[i] ^= inbuf[RATE * n + i];
}

void
keccak256_digest(struct mac *p, uint8_t *outbuf)
{
	uint8_t S[200];

	memcpy(S, p->S, 200);

	S[p->index] ^= 0x01;
	S[RATE - 1] ^= 0x80;

	Keccak(S);

	memcpy(outbuf, S, 32);
}

#undef RATE
#undef A
#undef Aprime
void
list(int n)
{
	int i;
	struct atom *p, *q;

	p = NULL;

	for (i = 0; i < n; i++) {
		q = alloc_atom(-1);
		q->cdr = p;
		q->car = pop();
		p = q;
	}

	push(p);
}

#define STACKSIZE 1000

int atom_count;
int tos;
struct atom *stack[STACKSIZE];

void
push(struct atom *p)
{
	if (tos == STACKSIZE) {
		printf("stack overrun\n");
		exit(1);
	}

	stack[tos++] = p;
}

struct atom *
pop(void)
{
	if (tos == 0) {
		printf("stack underrun\n");
		exit(1);
	}

	return stack[--tos];
}

void
pop_all(int n)
{
	int i;
	for (i = 0; i < n; i++)
		free_list(pop());
}

void
push_string(uint8_t *string, int length)
{
	struct atom *p;
	p = alloc_atom(length);
	memcpy(p->string, string, length);
	push(p);
}

void
push_number(uint64_t n)
{
	int i;
	uint8_t buf[8];

	buf[0] = n >> 56;
	buf[1] = n >> 48;
	buf[2] = n >> 40;
	buf[3] = n >> 32;
	buf[4] = n >> 24;
	buf[5] = n >> 16;
	buf[6] = n >> 8;
	buf[7] = n;

	for (i = 0; i < 7; i++)
		if (buf[i])
			break;

	push_string(buf + i, 8 - i);
}

struct atom *
alloc_atom(int string_length)
{
	int n;
	struct atom *p;
	n = string_length;
	if (n < 0)
		n = 0;
	p = malloc(sizeof (struct atom) + n);
	if (p == NULL)
		exit(1);
	p->car = NULL;
	p->cdr = NULL;
	p->length = string_length;
	atom_count++;
	return p;
}

void
free_list(struct atom *p)
{
	struct atom *t;

	if (p == NULL)
		return;

	if (p->length < 0)
		while (p) {
			t = p->cdr;
			free_list(p->car);
			free(p);
			atom_count--;
			p = t;
		}
	else {
		free(p);
		atom_count--;
	}
}

// returns 0 for equal

int
compare_lists(struct atom *p, struct atom *q)
{
	int d;

	if (p == NULL && q == NULL)
		return 0;

	if (p == NULL && q != NULL)
		return -1;

	if (p != NULL && q == NULL)
		return 1;

	if (p->length == -1 && q->length == -1) {
		while (p && q) {
			d = compare_lists(p->car, q->car);
			if (d)
				return d;
			p = p->cdr;
			q = q->cdr;
		}
		return compare_lists(p, q);
	}

	if (p->length < q->length)
		return -1;

	if (p->length > q->length)
		return 1;

	return memcmp(p->string, q->string, p->length);
}

void
print_list(struct atom *p)
{
	print_list_nib(p, 0);
	printf("\n");
}

void
print_list_nib(struct atom *p, int level)
{
	int i;

	for (i = 0; i < level; i++)
		printf("\t");

	if (p == NULL) {
		printf("[]");
		return;
	}

	if (p->length == -1) {

		printf("[\n");

		while (p) {
			print_list_nib(p->car, level + 1);
			printf(",\n");
			p = p->cdr;
		}

		for (i = 0; i < level; i++)
			printf("\t");

		printf("]");

		return;
	}

	for (i = 0; i < p->length; i++)
		printf("%02x", p->string[i]);
}
void
macs(struct node *p)
{
	int i;
	uint8_t buf[32];

	// ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)

	for (i = 0; i < 32; i++)
		buf[i] = p->mac_secret[i] ^ p->auth_nonce[i];

	keccak256_init(&p->ingress_mac);
	keccak256_update(&p->ingress_mac, buf, 32);
	keccak256_update(&p->ingress_mac, p->ack_buf, p->ack_len);

	// egress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)

	for (i = 0; i < 32; i++)
		buf[i] = p->mac_secret[i] ^ p->ack_nonce[i];

	keccak256_init(&p->egress_mac);
	keccak256_update(&p->egress_mac, buf, 32);
	keccak256_update(&p->egress_mac, p->auth_buf, p->auth_len);
}
int
main(int argc, char *argv[])
{
	ec_init();
	aes128_init();
	aes256_init();

	if (argc > 1) {
		if (strcmp(argv[1], "test") == 0)
			test();
		else if (strcmp(argv[1], "sim") == 0)
			sim();
		else
			printf("usage: pingpong | pinpong test | pingpong sim\n");
		exit(1);
	}

	nib();
}

void
nib(void)
{
	int err, i, len;
	uint8_t *buf;
	struct node N;

	memset(&N, 0, sizeof N);

	hextobin(N.far_public_key, 64, GETH_PUBLIC_KEY);

	// generate keyset

	ec_genkey(N.private_key, N.public_key);

	// static_shared_secret = private_key * far_public_key

	ec_ecdh(N.static_shared_secret, N.private_key, N.far_public_key);

	// ephemeral key, nonce

	ec_genkey(N.auth_private_key, N.auth_public_key);

	for (i = 0; i < 32; i++)
		N.auth_nonce[i] = random();

	// establish connection

	N.fd = client_connect("127.0.0.1", 30303);

	// send auth

	send_auth(&N);

	// get ack

	wait_for_pollin(N.fd);

	buf = receive(N.fd, &len);

	err = recv_ack(&N, buf, len);

	free(buf);

	if (err) {
		printf("recv ack err\n");
		exit(1);
	}

	secrets(&N, 1);

	macs(&N);

	// wait for hello

	wait_for_pollin(N.fd);

	buf = receive(N.fd, &len);

	close(N.fd);

	printmem(buf, 16);

	uint8_t iv[16];
	memset(iv, 0, 16);

	aes256ctr_setup(N.encrypt_state, N.aes_secret, iv);
	aes256ctr_setup(N.decrypt_state, N.aes_secret, iv);

	aes256ctr_encrypt(N.decrypt_state, buf, 16); // encrypt does decrypt in ctr mode

	printmem(buf, 16);
}
// returns result on stack or -1 on error

int
rdecode(uint8_t *buf, int length)
{
	int n = rdecode_nib(buf, length);
	if (n == -1)
		return -1; // decode error
	else if (n < length) {
		free_list(pop());
		return -1; // buffer underrun
	} else
		return 0; // ok
}

// ok to have trailing data

int
rdecode_relax(uint8_t *buf, int length)
{
	int n = rdecode_nib(buf, length);
	if (n == -1)
		return -1; // decode error
	else
		return 0; // ok
}

// returns number of bytes read from buf or -1 on error

int
rdecode_nib(uint8_t *buf, int length)
{
	int err, i, n;
	uint64_t len;
	struct atom *p;

	if (length < 1)
		return -1;

	if (buf[0] < 0x80) {
		p = alloc_atom(1);
		p->string[0] = buf[0];
		push(p);
		return 1;
	}

	// string 0..55 bytes

	if (buf[0] < 0xb8) {
		len = buf[0] - 0x80;
		if (len + 1 > length)
			return -1;
		p = alloc_atom(len);
		memcpy(p->string, buf + 1, len);
		push(p);
		return len + 1;
	}

	// string > 55 bytes

	if (buf[0] < 0xc0) {
		n = buf[0] - 0xb7; // number of length bytes 1..8
		if (n + 1 > length)
			return -1;
		len = 0;
		for (i = 0; i < n; i++)
			len = (len << 8) | buf[i + 1];
		if (len > 0xffffff || len + n + 1 > length) // cap len to prevent arithmetic overflow
			return -1;
		p = alloc_atom(len);
		memcpy(p->string, buf + n + 1, len);
		push(p);
		return len + n + 1;
	}

	// list 0..55 bytes

	if (buf[0] < 0xf8) {
		len = buf[0] - 0xc0;
		if (len + 1 > length)
			return -1;
		err = rdecode_list(buf + 1, len);
		if (err)
			return -1;
		else
			return len + 1;
	}

	// list > 55 bytes

	n = buf[0] - 0xf7; // number of length bytes 1..8
	if (n + 1 > length)
		return -1;
	len = 0;
	for (i = 0; i < n; i++)
		len = (len << 8) | buf[i + 1];
	if (len > 0xffffff || len + n + 1 > length) // cap len to prevent arithmetic overflow
		return -1;
	err = rdecode_list(buf + n + 1, len);
	if (err)
		return -1;
	else
		return len + n + 1;
}

// if length is zero then NULL is pushed (empty list)

int
rdecode_list(uint8_t *buf, int length)
{
	int h, len, n;
	h = tos;
	len = 0;
	while (len < length) {
		n = rdecode_nib(buf + len, length - len);
		if (n < 0) {
			pop_all(tos - h);
			return -1; // err
		}
		len += n;
	}
	list(tos - h);
	return 0; // ok
}
int
recv_ack(struct node *p, uint8_t *buf, int len)
{
	int err, msglen;
	uint8_t *msg;
	struct atom *q;

	// save a copy of buf for later

	if (p->ack_buf)
		free(p->ack_buf);
	p->ack_buf = malloc(len);
	if (p->ack_buf == NULL)
		exit(1);
	memcpy(p->ack_buf, buf, len);
	p->ack_len = len;

	// decrypt

	err = decap(buf, len, p->private_key);

	if (err)
		return -1;

	msg = buf + ENCAP_C;		// ENCAP_C == 2 + 65 + 16
	msglen = len - ENCAP_OVERHEAD;	// ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	err = rdecode_relax(msg, msglen); // relax allows trailing data

	if (err)
		return -1;

	q = pop(); // result from rdecode

	err = recv_ack_data(p, q);

	free_list(q);

	return err;
}

// returns 0 ok, -1 err

int
recv_ack_data(struct node *p, struct atom *q)
{
	struct atom *q1, *q2;

	// length == -1 indicates a list item

	if (q == NULL || q->length != -1 || q->cdr == NULL)
		return -1;

	q1 = q->car;		// 1st item: ephemeral public key
	q2 = q->cdr->car;	// 2nd item: nonce

	if (q1 == NULL || q2 == NULL)
		return -1;

	if (q1->length != 64 || q2->length != 32)
		return -1;

	memcpy(p->ack_public_key, q1->string, 64);
	memcpy(p->ack_nonce, q2->string, 32);

	return 0;
}
// prefix	2 bytes
// public key	65 bytes
// iv		16 bytes
// ciphertext	msglen bytes
// hmac		32 bytes

int
recv_auth(struct node *p, uint8_t *buf, int len)
{
	int err, msglen;
	struct atom *q;

	err = decap(buf, len, p->private_key);

	if (err)
		return -1;

	memcpy(p->auth_public_key, buf + 3, 64);

	msglen = len - ENCAP_OVERHEAD; // ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	err = rdecode_relax(buf + ENCAP_C, msglen);

	if (err)
		return -1;

	q = pop();

	err = recv_auth_data(p, q);

	free_list(q);

	return err;
}

int
recv_auth_data(struct node *p, struct atom *q)
{
	struct atom *q1, *q2, *q3;

	// length == -1 indicates a list item

	if (q == NULL || q->length != -1 || q->cdr == NULL || q->cdr->cdr == NULL)
		return -1;

	q1 = q->car;		// 1st item: sig
	q2 = q->cdr->car;	// 2nd item: public key
	q3 = q->cdr->cdr->car;	// 3rd item: nonce

	if (q1 == NULL || q2 == NULL || q3 == NULL)
		return -1;

	if (q2->length != 64 || q3->length != 32)
		return -1;

	memcpy(p->auth_nonce, q3->string, 32);

	return 0;
}
int
rencode(uint8_t *buf, int len, struct atom *p)
{
	if (enlength(p) > len)
		return 0;
	else
		return rencode_nib(buf, p);
}

int
rencode_nib(uint8_t *buf, struct atom *p)
{
	if (p == NULL || p->length < 0)
		return rencode_list(buf, p);
	else
		return rencode_string(buf, p);
}

int
rencode_list(uint8_t *buf, struct atom *p)
{
	int padlen, sublen;
	uint8_t *t;

	sublen = sublength(p);

	padlen = padlength(p, sublen);

	t = buf + padlen;

	while (p) {
		t += rencode_nib(t, p->car);
		p = p->cdr;
	}

	switch (padlen) {
	case 1:
		buf[0] = 0xc0 + sublen;
		break;
	case 2:
		buf[0] = 0xf7 + 1;
		buf[1] = sublen;
		break;
	case 3:
		buf[0] = 0xf7 + 2;
		buf[1] = sublen >> 8;
		buf[2] = sublen;
		break;
	case 4:
		buf[0] = 0xf7 + 3;
		buf[1] = sublen >> 16;
		buf[2] = sublen >> 8;
		buf[3] = sublen;
		break;
	}

	return padlen + sublen;
}

int
rencode_string(uint8_t *buf, struct atom *p)
{
	int padlen, sublen;

	if (p->length == 1 && p->string[0] < 0x80) {
		buf[0] = p->string[0];
		return 1;
	}

	sublen = p->length;

	padlen = padlength(p, sublen);

	memcpy(buf + padlen, p->string, sublen);

	switch (padlen) {
	case 1:
		buf[0] = 0x80 + sublen;
		break;
	case 2:
		buf[0] = 0xb7 + 1;
		buf[1] = sublen;
		break;
	case 3:
		buf[0] = 0xb7 + 2;
		buf[1] = sublen >> 8;
		buf[2] = sublen;
		break;
	case 4:
		buf[0] = 0xb7 + 3;
		buf[1] = sublen >> 16;
		buf[2] = sublen >> 8;
		buf[3] = sublen;
		break;
	}

	return padlen + sublen;
}
void
secrets(struct node *p, int initiator)
{
	uint8_t ephemeral_secret[32];
	uint8_t shared_secret[32];
	uint8_t buf[64];

	// ephemeral_secret = ephemeral private_key * ephemeral public_key

	if (initiator)
		ec_ecdh(ephemeral_secret, p->auth_private_key, p->ack_public_key);
	else
		ec_ecdh(ephemeral_secret, p->ack_private_key, p->auth_public_key);

	// shared_secret = keccak256(ephemeral_secret || keccak256(ack_nonce || auth_nonce))

	memcpy(buf, p->ack_nonce, 32);
	memcpy(buf + 32, p->auth_nonce, 32);

	keccak256(buf + 32, buf, 64);

	memcpy(buf, ephemeral_secret, 32);

	keccak256(shared_secret, buf, 64);

	// aes_secret = keccak256(ephemeral_secret || shared_secret)

	memcpy(buf, ephemeral_secret, 32);
	memcpy(buf + 32, shared_secret, 32);

	keccak256(p->aes_secret, buf, 64);

	// mac_secret = keccak256(ephemeral_secret || aes_secret)

	memcpy(buf, ephemeral_secret, 32);
	memcpy(buf + 32, p->aes_secret, 32);

	keccak256(p->mac_secret, buf, 64);
}
void
send_ack(struct node *p)
{
	int len, msglen, n;
	uint8_t *buf;
	struct atom *q;

	q = ack_body(p);

	msglen = enlength(q);

	// pad with random amount of data, at least 100 bytes

	n = 100 + random() % 100;

	len = msglen + n + ENCAP_OVERHEAD; // ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	buf = malloc(len);

	if (buf == NULL)
		exit(1);

	rencode(buf + ENCAP_C, msglen, q); // ENCAP_C == 2 + 65 + 16

	free_list(q);

	encap(buf, len, p);

	// save buf for later

	if (p->ack_buf)
		free(p->ack_buf);

	p->ack_buf = buf;
	p->ack_len = len;

	// send buf

	n = send(p->fd, buf, len, 0);

	if (n < 0)
		perror("send");

	printf("%d bytes sent\n", n);
}

struct atom *
ack_body(struct node *p)
{
	// public key

	push_string(p->ack_public_key, 64);

	// nonce

	push_string(p->ack_nonce, 32);

	// version

	push_number(4);

	list(3);

	return pop();
}
void
send_auth(struct node *p)
{
	int len, msglen, n;
	uint8_t *buf;
	struct atom *q;

	q = auth_body(p);

	msglen = enlength(q);

	// pad with random amount of data, at least 100 bytes

	n = 100 + random() % 100;

	len = msglen + n + ENCAP_OVERHEAD; // ENCAP_OVERHEAD == 2 + 65 + 16 + 32

	buf = malloc(len);

	if (buf == NULL)
		exit(1);

	rencode(buf + ENCAP_C, msglen, q); // ENCAP_C == 2 + 65 + 16

	free_list(q);

	encap(buf, len, p);

	// save buf for later

	if (p->auth_buf)
		free(p->auth_buf);

	p->auth_buf = buf;
	p->auth_len = len;

	// send buf

	n = send(p->fd, buf, len, 0);

	if (n < 0)
		perror("send");

	printf("%d bytes sent\n", n);
}

struct atom *
auth_body(struct node *p)
{
	int i;
	uint8_t hash[32], sig[65];

	// sig (see rlpx.go line 557)

	for (i = 0; i < 32; i++)
		hash[i] = p->static_shared_secret[i] ^ p->auth_nonce[i];

	ec_sign(sig, sig + 32, hash, p->auth_private_key);

	sig[64] = p->public_key[63] & 1;

	push_string(sig, 65);

	// initiator public key

	push_string(p->public_key, 64);

	// initiator nonce

	push_string(p->auth_nonce, 32);

	// auth version

	push_number(4);

	list(4);

	return pop();
}
void
hmac_sha256(uint8_t *key, int keylen, uint8_t *buf, int len, uint8_t *out)
{
	int i;
	uint8_t pad[64], hash[32];

	memset(pad, 0, 64);

	// keys longer than 64 are hashed

	if (keylen > 64)
		sha256(key, keylen, pad);
	else
		memcpy(pad, key, keylen);

	// xor ipad

	for (i = 0; i < 64; i++)
		pad[i] ^= 0x36;

	// hash

	sha256_with_key(pad, buf, len, hash);

	// xor opad

	for (i = 0; i < 64; i++)
		pad[i] ^= 0x36 ^ 0x5c;

	// hash

	sha256_with_key(pad, hash, 32, out);
}

void
sha256(uint8_t *buf, int len, uint8_t *out)
{
	int i, n, r;
	uint8_t block[64];
	uint32_t hash[8];
	uint64_t m;

	n = len / 64;	// number of blocks
	r = len % 64;	// remainder bytes

	hash[0] = 0x6a09e667;
	hash[1] = 0xbb67ae85;
	hash[2] = 0x3c6ef372;
	hash[3] = 0xa54ff53a;
	hash[4] = 0x510e527f;
	hash[5] = 0x9b05688c;
	hash[6] = 0x1f83d9ab;
	hash[7] = 0x5be0cd19;

	for (i = 0; i < n; i++) {
		sha256_hash_block(buf, hash);
		buf += 64;
	}

	// depending on remainder, hash 1 or 2 more blocks

	memset(block, 0, 64);
	memcpy(block, buf, r);
	block[r] = 0x80;

	if (r >= 56) {
		sha256_hash_block(block, hash);
		memset(block, 0, 64);
	}

	m = (uint64_t) 8 * len; // number of bits

	block[56] = m >> 56;
	block[57] = m >> 48;
	block[58] = m >> 40;
	block[59] = m >> 32;
	block[60] = m >> 24;
	block[61] = m >> 16;
	block[62] = m >> 8;
	block[63] = m;

	sha256_hash_block(block, hash);

	for (i = 0; i < 8; i++) {
		out[4 * i + 0] = hash[i] >> 24;
		out[4 * i + 1] = hash[i] >> 16;
		out[4 * i + 2] = hash[i] >> 8;
		out[4 * i + 3] = hash[i];
	}
}

// key is 64 bytes

void
sha256_with_key(uint8_t *key, uint8_t *buf, int len, uint8_t *out)
{
	int i, n, r;
	uint8_t block[64];
	uint32_t hash[8];
	uint64_t m;

	n = len / 64;	// number of blocks
	r = len % 64;	// remainder bytes

	hash[0] = 0x6a09e667;
	hash[1] = 0xbb67ae85;
	hash[2] = 0x3c6ef372;
	hash[3] = 0xa54ff53a;
	hash[4] = 0x510e527f;
	hash[5] = 0x9b05688c;
	hash[6] = 0x1f83d9ab;
	hash[7] = 0x5be0cd19;

	sha256_hash_block(key, hash);

	for (i = 0; i < n; i++) {
		sha256_hash_block(buf, hash);
		buf += 64;
	}

	// depending on remainder, hash 1 or 2 more blocks

	memset(block, 0, 64);
	memcpy(block, buf, r);
	block[r] = 0x80;

	if (r >= 56) {
		sha256_hash_block(block, hash);
		memset(block, 0, 64);
	}

	m = (uint64_t) 8 * (len + 64); // number of bits

	block[56] = m >> 56;
	block[57] = m >> 48;
	block[58] = m >> 40;
	block[59] = m >> 32;
	block[60] = m >> 24;
	block[61] = m >> 16;
	block[62] = m >> 8;
	block[63] = m;

	sha256_hash_block(block, hash);

	for (i = 0; i < 8; i++) {
		out[4 * i + 0] = hash[i] >> 24;
		out[4 * i + 1] = hash[i] >> 16;
		out[4 * i + 2] = hash[i] >> 8;
		out[4 * i + 3] = hash[i];
	}
}

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROTR(n, x) (((x) >> (n)) | ((x) << (32 - (n))))

#define Sigma0(x) (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x))
#define Sigma1(x) (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x))

#define sigma0(x) (ROTR(7, x) ^ ROTR(18, x) ^ ((x) >> 3))
#define sigma1(x) (ROTR(17, x) ^ ROTR(19, x) ^ ((x) >> 10))

uint32_t K256[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

void
sha256_hash_block(uint8_t *buf, uint32_t *hash)
{
	int t;
	uint32_t a, b, c, d, e, f, g, h, T1, T2, W[64];

	for (t = 0; t < 16; t++) {
		W[t] = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
		buf += 4;
	}

	for (t = 16; t < 64; t++)
		W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];
	f = hash[5];
	g = hash[6];
	h = hash[7];

	for (t = 0; t < 64; t++) {
		T1 = h + Sigma1(e) + Ch(e, f, g) + K256[t] + W[t];
		T2 = Sigma0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
	hash[5] += f;
	hash[6] += g;
	hash[7] += h;
}

void
test_sha256(void)
{
	int i;
	char s[65];
	uint8_t hash[32];

	printf("Test sha256 ");

	sha256((uint8_t *) "", 0, hash);
	for (i = 0; i < 32; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);
	if (strcmp(s, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	sha256((uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);
	for (i = 0; i < 32; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);
	if (strcmp(s, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592") != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	hmac_sha256((uint8_t *) "", 0, (uint8_t *) "", 0, hash);
	for (i = 0; i < 32; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);
	if (strcmp(s, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad") != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	hmac_sha256((uint8_t *) "key", 3, (uint8_t *) "The quick brown fox jumps over the lazy dog", 43, hash);
	for (i = 0; i < 32; i++)
		sprintf(s + 2 * i, "%02x", hash[i]);
	if (strcmp(s, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8") != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}
#define ETHSTR "\x19" "Ethereum Signed Message:\n32"

// private_key	32 bytes
// public_key	64 bytes

// returns list [r,s,v] on stack

void
sign(uint8_t *msg, int msglen, uint8_t *private_key, uint8_t *public_key)
{
	int v;
	uint8_t buf[28 + 32], hash[32], r[32], s[32];

	memcpy(buf, ETHSTR, 28); // 28 chars

	keccak256(buf + 28, msg, msglen);

	keccak256(hash, buf, sizeof buf);

	ec_sign(r, s, hash, private_key);

	v = 27 + (public_key[63] & 1); // 27 even, 28 odd

	push_string(r, 32);
	push_string(s, 32);
	push_number(v);

	list(3);
}

void
test_sign(void)
{
	int err;
	uint8_t buf[60], hash[32], private_key[32], public_key[64], *r, *s;
	struct atom *list;

	printf("Test sign ");

	ec_genkey(private_key, public_key);

	sign((uint8_t *) "hello", 5, private_key, public_key);

	list = pop();

	r = list->car->string;
	s = list->cdr->car->string;

	memcpy(buf, "\x19" "Ethereum Signed Message:\n32", 28);
	keccak256(buf + 28, (uint8_t *) "hello", 5);
	keccak256(hash, buf, 60);

	err = ec_verify(hash, r, s, public_key, public_key + 32);

	free_list(list);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}
// node simulator for debugging stuff

void
sim(void)
{
	int err, i, len, listen_fd;
	uint8_t *buf;

	struct node A; // Alice
	struct node B; // Bob

	memset(&A, 0, sizeof A);
	memset(&B, 0, sizeof B);

	// generate keys

	ec_genkey(A.private_key, A.public_key);
	ec_genkey(B.private_key, B.public_key);

	memcpy(A.far_public_key, B.public_key, 64); // Alice knows Bob's public key
	memcpy(B.far_public_key, A.public_key, 64); // Bob knows Alice's public key

	ec_ecdh(A.static_shared_secret, A.private_key, A.far_public_key);
	ec_ecdh(B.static_shared_secret, B.private_key, B.far_public_key);

	// ephemeral keys, nonces

	ec_genkey(A.auth_private_key, A.auth_public_key);
	ec_genkey(B.auth_private_key, B.auth_public_key);

	ec_genkey(A.ack_private_key, A.ack_public_key);
	ec_genkey(B.ack_private_key, B.ack_public_key);

	for (i = 0; i < 32; i++) {
		A.auth_nonce[i] = random();
		A.ack_nonce[i] = random();
		B.auth_nonce[i] = random();
		B.ack_nonce[i] = random();
	}

	// establish connection

	listen_fd = start_listening(30303);
	A.fd = client_connect("127.0.0.1", 30303);
	wait_for_pollin(listen_fd);
	B.fd = server_connect(listen_fd);
	close(listen_fd);

	// send auth

	send_auth(&A);

	// recv auth

	wait_for_pollin(B.fd);

	buf = receive(B.fd, &len);

	err = recv_auth(&B, buf, len);

	free(buf);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	// send ack

	send_ack(&B);

	// recv ack

	wait_for_pollin(A.fd);

	buf = receive(A.fd, &len);

	err = recv_ack(&A, buf, len);

	free(buf);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	// geth recovers public key from sig in auth msg

	// don't have recovery function so do this

	memcpy(B.auth_public_key, A.auth_public_key, 64);

	// sanity check

	err = memcmp(A.auth_public_key, B.auth_public_key, 64);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	err = memcmp(A.ack_public_key, B.ack_public_key, 64);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	err = memcmp(A.auth_nonce, B.auth_nonce, 32);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	err = memcmp(A.ack_nonce, B.ack_nonce, 32);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	// secrets

	secrets(&A, 1);
	secrets(&B, 0);

	// compare aes secrets

	err = memcmp(A.aes_secret, B.aes_secret, 32);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	printf("ok\n");

	close(A.fd);
	close(B.fd);
}

uint8_t *
receive(int fd, int *plen)
{
	int n;
	uint8_t *buf;

	buf = malloc(1280);

	if (buf == NULL)
		exit(1);

	n = recv(fd, buf, 1280, 0);

	if (n < 0) {
		perror("recv");
		exit(1);
	}

	printf("%d bytes received\n", n);

	*plen = n;
	return buf;
}
#define TIMEOUT 3000 // timeout in milliseconds

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
test(void)
{
	test_aes128();
	test_aes256();
	test_sha256();
	test_keccak256();
	test_rencode();
	test_rdecode();
	test_genkey();
	test_pubkey();
	test_kdf();
	test_hmac();
	test_sign();
//	test_ping(account_table + 0);
	test_decrypt();
}

// does this public key belong to secp256k1? (0 yes, -1 no)

int
test_public_key(char *public_key_x, char *public_key_y)
{
	int err;
	uint32_t *x, *y;

	x = ec_hexstr_to_bignum(public_key_x);
	y = ec_hexstr_to_bignum(public_key_y);

	err = test_public_key_secp256k1(x, y);

	ec_free(x);
	ec_free(y);

	return err;
}

void
test_aes128(void)
{
	int err, i;
	uint8_t cipher[32], plain[32], iv[16];
	uint8_t aes_key[16];
	uint32_t aes_expanded_key[48];

	printf("Test aes128 ");

	for (i = 0; i < 16; i++)
		aes_key[i] = random();

	for (i = 0; i < 16; i++)
		iv[i] = random();

	for (i = 0; i < 32; i++)
		plain[i] = random();

	memcpy(cipher, plain, 32);

	aes128ctr_setup(aes_expanded_key, aes_key, iv);
	aes128ctr_encrypt(aes_expanded_key, cipher, 32);

	aes128ctr_setup(aes_expanded_key, aes_key, iv);
	aes128ctr_encrypt(aes_expanded_key, cipher, 32);

	err = memcmp(cipher, plain, 32);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

void
test_aes256(void)
{
	int err;

	printf("Test aes256 ");

	err = aes256_test_encrypt();

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

void
test_rencode(void)
{
	int err, i, n;
	struct atom *p;
	uint8_t buf[256], enc[256];

	printf("Test rencode ");

	// items

	push_string(NULL, 0);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x80", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_string((uint8_t *) "", 0);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x80", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_string((uint8_t *) "a", 1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "a", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_string((uint8_t *) "ab", 2);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 3 || memcmp(buf, "\x82" "ab", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_string((uint8_t *) "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "fffff", 55);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 56 || memcmp(buf, "\xb7" "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "fffff", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_string((uint8_t *) "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "ffffff", 56);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 58 || memcmp(buf, "\xb8\x38" "aaaaaaaaaa" "bbbbbbbbbb" "cccccccccc" "dddddddddd" "eeeeeeeeee" "ffffff", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(0);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x00", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x01", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(127);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\x7f", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(128);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 2 || memcmp(buf, "\x81\x80", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(255);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 2 || memcmp(buf, "\x81\xff", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(256);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 3 || memcmp(buf, "\x82\x01\x00", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(65535);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 3 || memcmp(buf, "\x82\xff\xff", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	push_number(65536);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 4 || memcmp(buf, "\x83\x01\x00\x00", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// []

	list(0);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 1 || memcmp(buf, "\xc0", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// [[]]

	list(0);
	list(1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 2 || memcmp(buf, "\xc1\xc0", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// [1, [], 2]

	push_number(1);
	list(0);
	push_number(2);
	list(3);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 4 || memcmp(buf, "\xc3\x01\xc0\x02", n)) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// list of one 54 byte string

	for (i = 0; i < 54; i++)
		buf[i] = i;
	push_string(buf, 54);
	list(1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 56) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}
	enc[0] = 0xc0 + 55; // 55 byte list
	enc[1] = 0x80 + 54; // 54 byte string
	for (i = 0; i < 54; i++)
		enc[2 + i] = i;
	err = memcmp(buf, enc, 56);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// list of one 55 byte string

	for (i = 0; i < 55; i++)
		buf[i] = i;
	push_string(buf, 55);
	list(1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 58) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}
	enc[0] = 0xf8; // list with 1 length byte
	enc[1] = 56;
	enc[2] = 0x80 + 55; // 55 byte string
	for (i = 0; i < 55; i++)
		enc[3 + i] = i;
	err = memcmp(buf, enc, 58);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// list of one 56 byte string

	for (i = 0; i < 56; i++)
		buf[i] = i;
	push_string(buf, 56);
	list(1);
	p = pop();
	n = rencode(buf, sizeof buf, p);
	free_list(p);
	if (n != 60) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}
	enc[0] = 0xf8; // list with 1 length byte
	enc[1] = 58;
	enc[2] = 0xb8; // string with 1 length byte
	enc[3] = 56;
	for (i = 0; i < 56; i++)
		enc[4 + i] = i;
	err = memcmp(buf, enc, 60);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	if (atom_count) {
		printf("err memory leak %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

void
test_rdecode(void)
{
	int err, len, n;
	struct atom *p, *q;
	uint8_t buf[2000];

	printf("Test rdecode ");

	// []

	list(0);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// [[]]

	list(0);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// [[],[]]

	list(0);
	list(0);
	list(2);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// "" (empty string)

	push_string(NULL, 0);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// string

	for (n = 0; n <= 1000; n++) {
		push_string(buf, n);
		p = pop();
		len = rencode(buf, sizeof buf, p);
		err = rdecode(buf, len);
		if (err)
			q = NULL;
		else {
			q = pop();
			err = compare_lists(p, q);
		}
		free_list(p);
		free_list(q);
		if (err) {
			printf("err %s line %d", __FILE__, __LINE__);
			return;
		}
	}

	// list of one 54 byte string

	push_string(buf, 54);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// list of one 55 byte string

	push_string(buf, 55);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// list of one 56 byte string

	push_string(buf, 56);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// list of one 57 byte string

	push_string(buf, 57);
	list(1);
	p = pop();
	len = rencode(buf, sizeof buf, p);
	err = rdecode(buf, len);
	if (err)
		q = NULL;
	else {
		q = pop();
		err = compare_lists(p, q);
	}
	free_list(p);
	free_list(q);
	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

void
test_genkey(void)
{
	int err;
	uint8_t private_key[32], public_key[64];
	uint8_t r[32], s[32], hash[32];

	printf("Test genkey ");

	ec_genkey(private_key, public_key);

	memset(hash, 0xf5, sizeof hash);

	ec_sign(r, s, hash, private_key);

	err = ec_verify(hash, r, s, public_key, public_key + 32);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	if (ec_malloc_count != 0) {
		printf("err memory leak %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

int
test_public_key_secp256k1(uint32_t *x, uint32_t *y)
{
	int err;
	uint32_t *n3, *n7, *p, *x3, *y2, *r;

	p = ec_hexstr_to_bignum("FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFE" "FFFFFC2F");

	// y^2 mod p == (x^3 + 7) mod p

	y2 = ec_mul(y, y);
	ec_mod(y2, p);

	n3 = ec_int(3);
	x3 = ec_pow(x, n3);
	n7 = ec_int(7);
	r = ec_add(x3, n7);
	ec_mod(r, p);

	err = ec_cmp(y2, r); // 0 = ok

	ec_free(n3);
	ec_free(n7);
	ec_free(p);
	ec_free(x3);
	ec_free(y2);
	ec_free(r);

	return err;
}

#define COEFF_A "FFFFFFFF" "00000001" "00000000" "00000000" "00000000" "FFFFFFFF" "FFFFFFFF" "FFFFFFFC"
#define COEFF_B "5AC635D8" "AA3A93E7" "B3EBBD55" "769886BC" "651D06B0" "CC53B0F6" "3BCE3C3E" "27D2604B"

int
test_public_key_secp256r1(uint32_t *x, uint32_t *y)
{
	int err;
	uint32_t *a, *b, *n3, *p, *x3, *y2, *r, *t1, *t2;

	p = ec_hexstr_to_bignum("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

	// y^2 mod p == (x^3 + a x + b) mod p

	y2 = ec_mul(y, y);
	ec_mod(y2, p);

	n3 = ec_int(3);
	x3 = ec_pow(x, n3);

	a = ec_hexstr_to_bignum(COEFF_A);
	b = ec_hexstr_to_bignum(COEFF_B);

	t1 = ec_mul(a, x);

	t2 = ec_add(x3, t1);
	r = ec_add(t2, b);

	ec_mod(r, p);

	err = ec_cmp(y2, r); // 0 = ok

	ec_free(a);
	ec_free(b);
	ec_free(n3);
	ec_free(p);
	ec_free(x3);
	ec_free(y2);
	ec_free(r);
	ec_free(t1);
	ec_free(t2);

	return err;
}

/*
def test_agree():
secret = fromHex("0x332143e9629eedff7d142d741f896258f5a1bfab54dab2121d3ec5000093d74b")
public = fromHex(
"0xf0d2b97981bd0d415a843b5dfe8ab77a30300daab3658c578f2340308a2da1a07f0821367332598b6aa4e180a41e92f4ebbae3518da847f0b1c0bbfe20bcf4e1")
agreeExpected = fromHex("0xee1418607c2fcfb57fda40380e885a707f49000a5dda056d828b7d9bd1f29a08")
e = crypto.ECCx(raw_privkey=secret)
agreeTest = e.raw_get_ecdh_key(pubkey_x=public[:32], pubkey_y=public[32:])
assert(agreeExpected == agreeTest)
*/

#define K "332143e9629eedff7d142d741f896258f5a1bfab54dab2121d3ec5000093d74b"
#define X "f0d2b97981bd0d415a843b5dfe8ab77a30300daab3658c578f2340308a2da1a0"
#define Y "7f0821367332598b6aa4e180a41e92f4ebbae3518da847f0b1c0bbfe20bcf4e1"
#define E "ee1418607c2fcfb57fda40380e885a707f49000a5dda056d828b7d9bd1f29a08"

void
test_ecdh(void)
{
	int err;
	uint8_t e[32], ecdh[32], priv[32], pub[64];

	printf("Test ecdh ");

	hextobin(priv, 32, K);
	hextobin(pub, 32, X);
	hextobin(pub + 32, 32, Y);
	hextobin(e, 32, E);

	ec_ecdh(ecdh, priv, pub);

	err = memcmp(e, ecdh, 32);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

#undef K
#undef X
#undef Y
#undef E

/*
def test_kdf():
input1 = fromHex("0x0de72f1223915fa8b8bf45dffef67aef8d89792d116eb61c9a1eb02c422a4663")
expect1 = fromHex("0x1d0c446f9899a3426f2b89a8cb75c14b")
test1 = crypto.eciesKDF(input1, 16)
assert len(test1) == len(expect1)
assert(test1 == expect1)

kdfInput2 = fromHex("0x961c065873443014e0371f1ed656c586c6730bf927415757f389d92acf8268df")
kdfExpect2 = fromHex("0x4050c52e6d9c08755e5a818ac66fabe478b825b1836fd5efc4d44e40d04dabcc")
kdfTest2 = crypto.eciesKDF(kdfInput2, 32)
assert(len(kdfTest2) == len(kdfExpect2))
assert(kdfTest2 == kdfExpect2)
*/

#define A1 "0de72f1223915fa8b8bf45dffef67aef8d89792d116eb61c9a1eb02c422a4663"
#define B1 "1d0c446f9899a3426f2b89a8cb75c14b"

#define A2 "961c065873443014e0371f1ed656c586c6730bf927415757f389d92acf8268df"
#define B2 "4050c52e6d9c08755e5a818ac66fabe478b825b1836fd5efc4d44e40d04dabcc"

void
test_kdf(void)
{
	uint8_t a[32], b[32], buf[36];

	printf("Test kdf ");

	hextobin(a, 32, A1);
	hextobin(b, 16, B1);

	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 1;

	memcpy(buf + 4, a, 32);

	sha256(buf, 36, buf);

	if (memcmp(b, buf, 16) != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	hextobin(a, 32, A2);
	hextobin(b, 32, B2);

	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 1;

	memcpy(buf + 4, a, 32);

	sha256(buf, 36, buf);

	if (memcmp(b, buf, 32) != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

#undef A1
#undef B1

#undef A2
#undef B2

/*
def test_hmac():
k_mac = fromHex("0x07a4b6dfa06369a570f2dcba2f11a18f")
indata = fromHex("0x4dcb92ed4fc67fe86832")
hmacExpected = fromHex("0xc90b62b1a673b47df8e395e671a68bfa68070d6e2ef039598bb829398b89b9a9")
hmacOut = crypto.hmac_sha256(k_mac, indata)
assert(hmacExpected == hmacOut)

# go messageTag
tagSecret = fromHex("0xaf6623e52208c596e17c72cea6f1cb09")
tagInput = fromHex("0x3461282bcedace970df2")
tagExpected = fromHex("0xb3ce623bce08d5793677ba9441b22bb34d3e8a7de964206d26589df3e8eb5183")
hmacOut = crypto.hmac_sha256(tagSecret, tagInput)
assert(hmacOut == tagExpected)
*/

#define KMAC1 "07a4b6dfa06369a570f2dcba2f11a18f"
#define DATA1 "4dcb92ed4fc67fe86832"
#define HMAC1 "c90b62b1a673b47df8e395e671a68bfa68070d6e2ef039598bb829398b89b9a9"

#define KMAC2 "af6623e52208c596e17c72cea6f1cb09"
#define DATA2 "3461282bcedace970df2"
#define HMAC2 "b3ce623bce08d5793677ba9441b22bb34d3e8a7de964206d26589df3e8eb5183"

void
test_hmac(void)
{
	uint8_t kmac[16], data[10], hmac[32], out[32];

	printf("Test hmac ");

	hextobin(kmac, 16, KMAC1);
	hextobin(data, 10, DATA1);
	hextobin(hmac, 32, HMAC1);

	hmac_sha256(kmac, 16, data, 10, out);

	if (memcmp(hmac, out, 32) != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	hextobin(kmac, 16, KMAC2);
	hextobin(data, 10, DATA2);
	hextobin(hmac, 32, HMAC2);

	hmac_sha256(kmac, 16, data, 10, out);

	if (memcmp(hmac, out, 32) != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

#undef KMAC1
#undef DATA1
#undef HMAC1

#undef KMAC2
#undef DATA2
#undef HMAC2

/*
def test_privtopub():
kenc = fromHex("0x472413e97f1fd58d84e28a559479e6b6902d2e8a0cee672ef38a3a35d263886b")
penc = fromHex(
"0x7a2aa2951282279dc1171549a7112b07c38c0d97c0fe2c0ae6c4588ba15be74a04efc4f7da443f6d61f68a9279bc82b73e0cc8d090048e9f87e838ae65dd8d4c")
assert(penc == crypto.privtopub(kenc))
return kenc, penc
*/

#define K "472413e97f1fd58d84e28a559479e6b6902d2e8a0cee672ef38a3a35d263886b"
#define P "7a2aa2951282279dc1171549a7112b07c38c0d97c0fe2c0ae6c4588ba15be74a04efc4f7da443f6d61f68a9279bc82b73e0cc8d090048e9f87e838ae65dd8d4c"

void
test_pubkey(void)
{
	uint8_t k[32], p[64], q[64];

	printf("Test pubkey ");

	hextobin(k, 32, K);
	hextobin(p, 64, P);

	ec_pubkey(q, k);

	if (memcmp(p, q, 64) != 0) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	if (ec_malloc_count != 0) {
		printf("err memory leak %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

#undef K
#undef P

#define K "472413e97f1fd58d84e28a559479e6b6902d2e8a0cee672ef38a3a35d263886b"
#define C "04c4e40c86bb5324e017e598c6d48c19362ae527af8ab21b077284a4656c8735e62d73fb3d740acefbec30ca4c024739a1fcdff69ecaf03301eebf156eb5f17cca6f9d7a7e214a1f3f6e34d1ee0ec00ce0ef7d2b242fbfec0f276e17941f9f1bfbe26de10a15a6fac3cda039904ddd1d7e06e7b96b4878f61860e47f0b84c8ceb64f6a900ff23844f4359ae49b44154980a626d3c73226c19e"
#define P "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

void
test_decrypt(void)
{
	int err, len, msglen;
	uint8_t buf[153];
	uint8_t private_key[32], shared_secret[32];
	uint8_t hmac[32], hmac_key[32];
	uint8_t aes_key[16];
	uint32_t aes_expanded_key[64];

	printf("Test decrypt ");

	hextobin(private_key, 32, K);
	hextobin(buf, 153, C);

	len = 153;

	msglen = len - 65 - 16 - 32; // R, iv, hmac

	// derive shared_secret from private_key and R

	ec_ecdh(shared_secret, private_key, buf + 1);

	// derive aes_key and hmac_key from shared_secret

	kdf(aes_key, hmac_key, shared_secret);

	// check hmac

	hmac_sha256(hmac_key, 32, buf + 65, msglen + 16, hmac);

	err = memcmp(hmac, buf + len - 32, 32);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	// decrypt

	aes128ctr_setup(aes_expanded_key, aes_key, buf + 65);
	aes128ctr_encrypt(aes_expanded_key, buf + 65 + 16, msglen);

	err = memcmp(buf + 65 + 16, P, 40);

	if (err) {
		printf("err %s line %d\n", __FILE__, __LINE__);
		return;
	}

	printf("ok\n");
}

#undef K
#undef C
#undef P
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
