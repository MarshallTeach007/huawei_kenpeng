#ifndef __SM2_JOB_H
#define __SM2_JOB_H


struct sm2_ecc_dma
{
	unsigned long long p;
	unsigned long long a;
	unsigned long long b;
	unsigned long long gx;
	unsigned long long gy;
	unsigned long long n;
};

struct sm2_pubkey_dma
{
	unsigned long long x;
	unsigned long long y;
};

struct sm2_ciphertext_dma
{
	unsigned long long c1;
	unsigned long long c2;
	unsigned long long c3;
};

struct sm2_signature_dma
{
	unsigned long long r;
	unsigned long long s;
};

struct sm2_genkey_private_dma
{
	struct sm2_ecc_dma ecc_dma;
	struct sm2_pubkey_dma pubkey_dma;
	unsigned long long prikey_dma;
	unsigned int plen;
	unsigned int nlen;
	unsigned char ecc_mode;
	unsigned char rng_mode;
};

struct sm2_enc_private_dma
{
	struct sm2_ecc_dma ecc_dma;
	struct sm2_pubkey_dma pubkey_dma;
	struct sm2_ciphertext_dma ciphertext_dma;
	unsigned long long msg_dma;
	unsigned long long k_dma;
	unsigned long long hashin_dma;
	//unsigned long long hashout_dma;
	unsigned long long ct_dma;
	unsigned int plen;
	unsigned int nlen;
	unsigned int klen;
	unsigned int ct;
	unsigned char ecc_mode;
	unsigned char rng_mode;
	unsigned char endian_mode;
};

struct sm2_dec_private_dma
{
	struct sm2_ecc_dma ecc_dma;
	struct sm2_ciphertext_dma ciphertext_dma;
	unsigned long long prikey_dma;
	unsigned long long msg_dma;
	unsigned long long hashin_dma;
	//unsigned long long hashout_dma;
	unsigned long long ct_dma;
	unsigned int plen;
	unsigned int nlen;
	unsigned int klen;
	unsigned int ct;
	unsigned char ecc_mode;
	unsigned char endian_mode;
};

struct sm2_sig_private_dma
{
	struct sm2_ecc_dma ecc_dma;
	struct sm2_signature_dma sig_dma;
	unsigned long long prikey_dma;
	unsigned long long z_dma;
	unsigned long long msg_dma;
	unsigned long long e_dma;
	unsigned long long k_dma;
	unsigned long long one_dma;
	unsigned int plen;
	unsigned int nlen;
	unsigned int klen;
	unsigned int zlen;
	unsigned char ecc_mode;
	unsigned char sig_mode;
	unsigned char rng_mode;
};

struct sm2_ver_private_dma
{
	struct sm2_ecc_dma ecc_dma;
	struct sm2_pubkey_dma pubkey_dma;
	struct sm2_signature_dma sig_dma;
	unsigned long long z_dma;
	unsigned long long msg_dma;
	unsigned long long e_dma;
	unsigned long long one_dma;
	unsigned int plen;
	unsigned int nlen;
	unsigned int klen;
	unsigned int zlen;
	unsigned char ecc_mode;
	unsigned char sig_mode;
};

struct sm2_exc_private_dma
{
	struct sm2_ecc_dma ecc_dma;
	struct sm2_pubkey_dma self_tmp_pubkey_dma;
	struct sm2_pubkey_dma other_pubkey_dma;
	struct sm2_pubkey_dma other_tmp_pubkey_dma;
	struct sm2_pubkey_dma u_dma;
	unsigned long long h_dma;
	unsigned long long self_prikey_dma;
	unsigned long long self_tmp_prikey_dma;
	unsigned long long self_x_dma;
	unsigned long long other_x_dma;
	unsigned long long zain_dma;
	unsigned long long zbin_dma;
	unsigned long long za_dma;
	unsigned long long zb_dma;
	unsigned long long ct_dma;
	unsigned long long key_dma;
	unsigned long long hashout_dma;
	unsigned long long s1_head_dma;
	unsigned long long s2_head_dma;
	unsigned long long s1_dma;
	unsigned long long s2_dma;
	unsigned long long desc_dma;
	unsigned int plen;
	unsigned int nlen;
	unsigned int zain_len;
	unsigned int zbin_len;
	unsigned int klen;
	unsigned char ecc_mode;
	unsigned char endian_mode;
	unsigned char exc_mode;
	unsigned char id_mode;
};

enum sm2_ecc_mode
{
	FP = 0,
	F2M = 1
};

enum sm2_rng_mode
{
	HARDWARE = 0,
	CONSTANT = 1
};

enum sm2_endian_mode
{
	LITTLE = 0,
	BIG = 1
};

enum sm2_signature_mode
{
	WITHID = 0,
	NOID = 1
};

enum sm2_exchange_mode
{
	A = 0,
	B = 1
};

#endif
