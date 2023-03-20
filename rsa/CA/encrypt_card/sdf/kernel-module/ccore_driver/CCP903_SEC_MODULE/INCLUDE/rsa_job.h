#ifndef __RSA_JOB_H
#define __RSA_JOB_H

#include "./compate.h"
#include "./pci_csec.h"
#include "./jr.h"

struct rsa_intermediate_var_dma
{
	unsigned long long r0_dma;
	unsigned long long r1_dma;
	unsigned long long r2_dma;
	unsigned long long r3_dma;
	unsigned long long r4_dma;
	unsigned long long r5_dma;
	unsigned long long r6_dma;
	unsigned long long r7_dma;
	unsigned long long r8_dma;
	unsigned long long r9_dma;
};

struct rsa_sec_var_dma
{
	unsigned long long p_dma;
	unsigned long long q_dma;
	unsigned long long e_dma;
	unsigned long long n_dma;
	unsigned long long d_dma;
	unsigned long long dp_dma;
	unsigned long long dq_dma;
	unsigned long long qInv_dma;
};

struct rsa_genkey_dma
{
	struct rsa_intermediate_var_dma r_dma;
	struct rsa_sec_var_dma sec_dma;
	unsigned int blen;
	unsigned int elen;
	unsigned int crt;
	unsigned long long desc_dma;
	unsigned long long desc2_dma;
	unsigned long long desc3_dma;
	unsigned long long desc_crt_dma;
};

struct rsa_pub_priv_dma
{	
	unsigned int blen;
	unsigned int crt;
	unsigned long long e_dma;
	unsigned long long n_dma;
	unsigned long long in_dma;
	unsigned long long out_dma;
	unsigned long long p_dma;
	unsigned long long q_dma;
	unsigned long long dp_dma;
	unsigned long long dq_dma;
	unsigned long long qInv_dma;
};

struct rsa_para_genkey_dma
{
	unsigned long long privkey_prime;
	unsigned long long privkey_prime2 ;
	unsigned long long pubkey_exponent;
	unsigned long long pubkey_modulus;
	unsigned long long privkey_exponent ;
	unsigned long long privkey_primeExponent;
	unsigned long long privkey_primeExponent2;
	unsigned long long privkey_coefficient;
//	unsigned long long privkey_modulus;
//	unsigned long long privkey_publicExponent;
};

struct rng_para_dma
{
	unsigned int rng_size;
	unsigned long long rng_dma;
};

struct rsa_para_genkey_st
{
	unsigned char *p;
	unsigned char *q;
	unsigned char *e;
	unsigned char *n;
	unsigned char *d;
	unsigned char *dp;
	unsigned char *dq;
	unsigned char *qInv;
};

struct rsa_pub_priv_st
{
	unsigned int rsa_bits;
	unsigned int outLen;
	unsigned int inLen;
	unsigned char *out;
	unsigned char *in;
	unsigned char *e;
	unsigned char *n;
	unsigned char *d;
	unsigned char *p;
	unsigned char *q;	
	unsigned char *dp;
	unsigned char *dq;
	unsigned char *qInv;
};
/*
struct rsa_pci_sesskey
{
	unsigned int key_addr_hi;
	unsigned int key_addr_low;
};

struct rsa_pci_sesscrt
{
	unsigned int privkey_modulus_hi;
	unsigned int privkey_modulus_low;

	unsigned int privkey_prime_hi;
	unsigned int privkey_prime_low;
	
	unsigned int privkey_prime2_hi;
	unsigned int privkey_prime2_low;

	unsigned int privkey_primeExponent_hi;
	unsigned int privkey_primeExponent_low;

	unsigned int privkey_primeExponent2_hi;
	unsigned int privkey_primeExponent2_low;

	unsigned int privkey_coefficient_hi;
	unsigned int privkey_coefficient_low;
};
*/
//extern void inline_cnstr_jobdesc_rsa_genkey_simplified(unsigned int *desc, struct rsa_genkey_dma *para);
//extern void inline_cnstr_jobdesc_rsa_pub_priv_simplified(unsigned int *desc, struct rsa_pub_priv_dma *para);
//extern void inline_cnstr_jobdesc_rsa_priv_crt_simplified(unsigned int *desc, struct rsa_priv_crt_dma *para);
#endif

