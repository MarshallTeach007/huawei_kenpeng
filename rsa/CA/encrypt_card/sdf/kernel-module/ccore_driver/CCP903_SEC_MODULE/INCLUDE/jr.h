/***************************************************
 * jr.h
 *
 * Created on: Mar 20, 2017
 * Author: zjjin@ccore.com
 ***************************************************/

#ifndef __JR_H
#define __JR_H

#include "./compate.h"
/* RNG_CFG_SEL: Choose RNG Source
 * 1: RNG Config in Driver
 * 0: RNG Config in Cos
 */
#define RNG_CFG_SEL 0
/* RNG_SRC_SEL: Choose RNG Source
 * 1: Internal RNG
 * 0: External RNG
 */
#define RNG_SRC_SEL 1

/* We support at most 32 Scatter/Gather Entries.*/
#define MAX_SG_32 32

#define JR_SIZE 0x200  //need to 2^n

//#define Ring_Size  0x400
#define Ring_Size JR_SIZE
#define Ring_Num 1

#define DIR_MASK 0x01
#define DONE_MASK 0x02
#define ST_ERR_MASK 0x04
#define AAI_SK_MASK 0x80
#define HSUB_MASK 0x20
#define SPLICTK_MASK 0x40
#define AAI_SK_SEL 0x800
#define HSUB_SEL 0x100
#define ST_ERR 0x04

#define PKHA_DONE_MASK 0x10
#define PKHA_ERR_MASK 0x20

/* Timeout currently defined as 90 sec */
#define CONFIG_SEC_DEQ_TIMEOUT 90000000U

#define DEFAULT_JR_ID 0
#define DEFAULT_JR_LIODN 0
#define DEFAULT_IRQ 0 /* Interrupts not to be configured */

#define MCFGR_SWRST ((uint32_t)(1) << 31)   /* Software Reset */
#define MCFGR_DMA_RST ((uint32_t)(1) << 28) /* DMA Reset */
#define MCFGR_PS_SHIFT 16
#define MCFGR_AWCACHE_SHIFT 8
#define MCFGR_AWCACHE_MASK (0xf << MCFGR_AWCACHE_SHIFT)
#define MCFGR_ARCACHE_SHIFT 12
#define MCFGR_ARCACHE_MASK (0xf << MCFGR_ARCACHE_SHIFT)

#define JR_INTMASK 0x00000001
#define JR_INT 0x00000001
#define JR_ERRMASK 0x00000002
#define JR_ERR 0x00000002
#define JRCR_RESET 0x01
#define JRINT_ERR_HALT_INPROGRESS 0x4
#define JRINT_ERR_HALT_COMPLETE 0x8
#define JRINT_ERR_HALT_MASK 0xc
#define JRNSLIODN_SHIFT 16
#define JRNSLIODN_MASK 0x0fff0000
#define JRSLIODN_SHIFT 0
#define JRSLIODN_MASK 0x00000fff

#define JQ_DEQ_ERR -1
#define JQ_DEQ_TO_ERR -2
#define JQ_ENQ_ERR -3

//#define OR4W

struct op_ring {
  dma_addr_t desc;

  uint32_t status;
#ifdef OR4W
  uint32_t reserve;
#endif
} __attribute((packed));

struct jr_info {
  dma_addr_t desc_phys_addr;
  void      *desc_virt;
  void (*callback)(void *csec_priv, uint32_t *desc_addr, dma_addr_t desc_phys,
                   uint32_t status, void *arg);
  uint32_t desc_len;
  uint32_t op_done;
  void    *arg;
};

struct jobring {
  /* Head is the index where software would enq the descriptor in
	 * the i/p ring
	 */
  int head;
  /* Tail index would be used by s/w ehile enqueuing to determine if
	 * there is any space left in the s/w maintained i/p rings
	 */
  /* Also in case of deq tail will be incremented only in case of
	 * in-order job completion
	 */
  int tail;
  /* Read index of the output ring. It may not match with tail in case
	 * of out of order completetion
	 */
  int dequeue_hw_idx;

  int size;
  /* Op ring size aligned to cache line size */
  int op_size;

  spinlock_t i_lock ____cacheline_aligned;
  spinlock_t o_lock ____cacheline_aligned;
  //spinlock_t iolock ____cacheline_aligned;

  struct jr_regs __iomem *regs;

  dma_addr_t *input_ring;
  /* Circular Ring of o/p descriptors */
  /* Circula Ring containing info regarding descriptors in i/p
	 * and o/p ring
	 */
  /* This ring can be on the stack */
  struct jr_info  info[JR_SIZE];
  struct op_ring *output_ring;
  atomic_t        state;
};

struct result {
  struct completion op_done;
  /* recovery: To check if the output data is moved out. Just for asyn test. */
  atomic_t     recovery;
  volatile int rst;
  void        *sg_virt;
  dma_addr_t   sg_phy;
};

#define array_size \
  (sizeof(dma_addr_t) * Ring_Size + sizeof(struct op_ring) * Ring_Size)
#define CIRC_CNT(head, tail, size) (((head) - (tail)) & (size))

struct cipher_api {
  unsigned char alg;
  unsigned char type;
  unsigned char as;  //init/updata/final
  unsigned char opt;
  unsigned      key_len;
  unsigned      iv_len;
  unsigned      data_len;
};

struct cipher_core {
  unsigned char alg;
  unsigned char type;
  unsigned char as;  //init/updata/final
  unsigned char opt;
  unsigned      key_len;
  unsigned      iv_len;
  unsigned      data_len;
  dma_addr_t    key_addr;
  dma_addr_t    iv_addr;
  dma_addr_t    data_addr;
};


struct cipher_ccm_api {
  unsigned char alg;
  unsigned char auth_m_len;
  unsigned char as;
  unsigned char opt;
  unsigned      key_len;
  unsigned      aad_len;
  unsigned      data_len;
};

struct hash_api {
  ;
};

struct snoop_api {
  ;
};

struct pkha_api {
  unsigned int   mode;
  unsigned short e_len;
  unsigned short n_len;
  unsigned short a_len;
  unsigned short b_len;
  unsigned short a0_len;
  unsigned short a1_len;
  unsigned short a2_len;
  unsigned short a3_len;
  unsigned short b0_len;
  unsigned short b1_len;
  unsigned short b2_len;
  unsigned short b3_len;
};

struct sm2_api {
  unsigned int field;
  unsigned int plen;
  unsigned int nlen;
  unsigned int klen;
  unsigned int entla;
  unsigned int entlb;
};

struct sm2_api_ext {
  void         *hashin;
  void         *hashout;
  void         *k;
  void         *zain;
  void         *zaout;
  void         *one;
  unsigned int *desc_ext;
  dma_addr_t    hashin_phys;
  dma_addr_t    hashout_phys;
  dma_addr_t    k_phys;
  dma_addr_t    zain_phys;
  dma_addr_t    zaout_phys;
  dma_addr_t    one_phys;
  dma_addr_t    desc_ext_phys;
};


struct rscp_api {
  unsigned char  algo_type;
  unsigned char  mode;
  unsigned char  output_buf_maxsize;
  unsigned char  fill_length_size;
  unsigned char  hash_db_size;
  unsigned char  as;
  unsigned short wk_len;
  unsigned short iv_len;
  unsigned short udd_len;
  unsigned short mk_len;
  unsigned short temp_len;
  unsigned int   hash_length[4];
  unsigned int   in_len;
  unsigned int   out_len;
};

struct rsa_api {
  unsigned int field;
  unsigned int rsa_random_bit;
  unsigned int fixed;
  unsigned int crt;
};

struct rsa_api_ext {
  void      *rsa_p;
  void      *rsa_q;
  void      *rsa_e;
  void      *rsa_n;
  void      *rsa_d;
  void      *rsa_dp;
  void      *rsa_dq;
  void      *rsa_qInv;
  void      *r0;
  void      *r1;
  void      *r2;
  void      *r3;
  void      *r4;
  void      *r5;
  void      *r6;
  void      *r7;
  void      *r8;
  void      *r9;
  void      *desc_ext;
  void      *desc_ext2;
  void      *desc_ext3;
  dma_addr_t rsa_p_phys;
  dma_addr_t rsa_q_phys;
  dma_addr_t rsa_e_phys;
  dma_addr_t rsa_n_phys;
  dma_addr_t rsa_d_phys;
  dma_addr_t rsa_dp_phys;
  dma_addr_t rsa_dq_phys;
  dma_addr_t rsa_qInv_phys;
  dma_addr_t r0_phys;
  dma_addr_t r1_phys;
  dma_addr_t r2_phys;
  dma_addr_t r3_phys;
  dma_addr_t r4_phys;
  dma_addr_t r5_phys;
  dma_addr_t r6_phys;
  dma_addr_t r7_phys;
  dma_addr_t r8_phys;
  dma_addr_t r9_phys;
  dma_addr_t desc_ext_phys;
  dma_addr_t desc_ext2_phys;
  dma_addr_t desc_ext3_phys;
};

struct crypto_api {
  union {
    struct cipher_api     capi;
    struct cipher_ccm_api ccmapi;
    struct hash_api       hapi;
    struct snoop_api      sapi;
    struct pkha_api       papi;
    struct sm2_api        smapi;
    struct rscp_api       rapi;
    struct rsa_api        rsaapi;
  };
};

extern void sec_dump(void *ptr, unsigned int size);

extern u32 sec_in32(volatile u32 *a);

extern void sec_out32(volatile u32 *a, u32 v);

extern u32 jr_in32(volatile u32 *a);

extern void jr_out32(volatile u32 *a, u32 v);

extern u64 m64_2_cpu(volatile void *a);

void cpu_2_m64(volatile void *a, u64 v);


#endif
