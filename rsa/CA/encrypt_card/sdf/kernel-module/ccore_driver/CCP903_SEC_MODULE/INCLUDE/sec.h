/***************************************************
 * sec.h
 *
 * Created on: Mar 20, 2017
 * Author: zjjin@ccore.com
 ***************************************************/

#ifndef SEC_H_
#define SEC_H_

#include "./compate.h"
#include "./pci_csec.h"
#include "./jr.h"

#define CSEC_ERROR_STR_MAX 302

typedef struct sg_entry_struct {
  unsigned int *sg_virt;
  dma_addr_t   *sg_dma;
  unsigned int  sg_e_len;
} sg_e_st, *sg_e_ptr;

typedef struct sg_list_struct {
  struct sg_list_struct *next;
  struct sg_list_struct *pre;
  sg_e_st                sg_entry;
} sg_l_st, *sg_l_ptr;

#define dev_err

/*
 * Common internal memory map for some Freescale SoCs
 *
 * Copyright 2014 Freescale Semiconductor, Inc.
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */


struct rng4tst {
#define RTMCTL_PRGM 0x00010000 /* 1 -> program mode, 0 -> run mode */
#define RTMCTL_SAMP_MODE_VON_NEUMANN_ES_SC \
  0 /* use von Neumann data in
						    both entropy shifter and
						    statistical checker */
#define RTMCTL_SAMP_MODE_RAW_ES_SC \
  1 /* use raw data in both
						    entropy shifter and
						    statistical checker */
#define RTMCTL_SAMP_MODE_VON_NEUMANN_ES_RAW_SC \
  2                                /* use von Neumann data in
						    entropy shifter, raw data
						    in statistical checker */
#define RTMCTL_SAMP_MODE_INVALID 3 /* invalid combination */
  u32 rtmctl;                      /* misc. control register */
  u32 rtscmisc;                    /* statistical check misc. register */
  u32 rtpkrrng;                    /* poker range register */
#define RTSDCTL_ENT_DLY_MIN 3200
#define RTSDCTL_ENT_DLY_MAX 12800
  union {
    u32 rtpkrmax; /* PRGM=1: poker max. limit register */
    u32 rtpkrsq;  /* PRGM=0: poker square calc. result register */
  };
#define RTSDCTL_ENT_DLY_SHIFT 16
#define RTSDCTL_ENT_DLY_MASK (0xffff << RTSDCTL_ENT_DLY_SHIFT)
  u32 rtsdctl; /* seed control register */
  union {
    u32 rtsblim;  /* PRGM=1: sparse bit limit register */
    u32 rttotsam; /* PRGM=0: total samples register */
  };
  u32 rtfreqmin; /* frequency count min. limit register */
#define RTFRQMAX_DISABLE (1 << 20)
  union {
    u32 rtfreqmax; /* PRGM=1: freq. count max. limit register */
    u32 rtfreqcnt; /* PRGM=0: freq. count register */
  };
  u32 rsvd1[40];
#define RNG_STATE0_HANDLE_INSTANTIATED 0x00000001
  u32 rdsta; /*RNG DRNG Status Register*/
  u32 rsvd2[15];
};

typedef struct ccsr_sec {
  u32 res0;
  u32 mcfgr; /* Master CFG Register */
  u8  res1[0x4];
  u32 scfgr;
  struct {
    u32 ms; /* Job Ring LIODN Register, MS */
    u32 ls; /* Job Ring LIODN Register, LS */
  } jrliodnr[4];
  u8  res2[0x2c];
  u32 jrstartr; /* Job Ring Start Register */
  struct {
    u32 ms; /* RTIC LIODN Register, MS */
    u32 ls; /* RTIC LIODN Register, LS */
  } rticliodnr[4];
  u8  res3[0x1c];
  u32 decorr; /* DECO Request Register */
  struct {
    u32 ms; /* DECO LIODN Register, MS */
    u32 ls; /* DECO LIODN Register, LS */
  } decoliodnr[8];
  u8             res4[0x40];
  u32            dar; /* DECO Avail Register */
  u32            drr; /* DECO Reset Register */
  u8             res5[0x4d8];
  struct rng4tst rng; /* RNG Registers */
  u8             res6[0x8a0];
  u32            crnr_ms; /* CHA Revision Number Register, MS */
  u32            crnr_ls; /* CHA Revision Number Register, LS */
  u32            ctpr_ms; /* Compile Time Parameters Register, MS */
  u32            ctpr_ls; /* Compile Time Parameters Register, LS */
  u8             res7[0x10];
  u32            far_ms; /* Fault Address Register, MS */
  u32            far_ls; /* Fault Address Register, LS */
  u32            falr;   /* Fault Address LIODN Register */
  u32            fadr;   /* Fault Address Detail Register */
  u8             res8[0x4];
  u32            csta;      /* CSEC Status Register */
  u32            smpart;    /* Secure Memory Partition Parameters */
  u32            smvid;     /* Secure Memory Version ID */
  u32            rvid;      /* Run Time Integrity Checking Version ID Reg.*/
  u32            ccbvid;    /* CHA Cluster Block Version ID Register */
  u32            chavid_ms; /* CHA Version ID Register, MS */
  u32            chavid_ls; /* CHA Version ID Register, LS */
  u32            chanum_ms; /* CHA Number Register, MS */
  u32            chanum_ls; /* CHA Number Register, LS */
  u32            secvid_ms; /* SEC Version ID Register, MS */
  u32            secvid_ls; /* SEC Version ID Register, LS */
  u8             res9[0x6020];
  u32            qilcr_ms; /* Queue Interface LIODN CFG Register, MS */
  u32            qilcr_ls; /* Queue Interface LIODN CFG Register, LS */
  u8             res10[0x8fd8];
} ccsr_sec_t;

#define SEC_CTPR_MS_AXI_LIODN 0x08000000
#define SEC_CTPR_MS_QI 0x02000000
#define SEC_CTPR_MS_VIRT_EN_INCL 0x00000001
#define SEC_CTPR_MS_VIRT_EN_POR 0x00000002
#define SEC_RVID_MA 0x0f000000
#define SEC_CHANUM_MS_JRNUM_MASK 0xf0000000
#define SEC_CHANUM_MS_JRNUM_SHIFT 28
#define SEC_CHANUM_MS_DECONUM_MASK 0x0f000000
#define SEC_CHANUM_MS_DECONUM_SHIFT 24
#define SEC_SECVID_MS_IPID_MASK 0xffff0000
#define SEC_SECVID_MS_IPID_SHIFT 16
#define SEC_SECVID_MS_MAJ_REV_MASK 0x0000ff00
#define SEC_SECVID_MS_MAJ_REV_SHIFT 8
#define SEC_CCBVID_ERA_MASK 0xff000000
#define SEC_CCBVID_ERA_SHIFT 24
#define SEC_SCFGR_RDBENABLE 0x00000400
#define SEC_SCFGR_VIRT_EN 0x00008000
#define SEC_CHAVID_LS_RNG_SHIFT 16
#define SEC_CHAVID_RNG_LS_MASK 0x000f0000

#define CONFIG_JRSTARTR_JR0 0x00000001
#define CONFIG_JRSTARTR_JR1 0x00000002
#define CONFIG_JRSTARTR_JR2 0x00000004
#define CONFIG_JRSTARTR_JR3 0x00000008

struct jr_regs {
#if defined(CONFIG_SYS_FSL_SEC_LE) && \
    !(defined(CONFIG_MX6) || defined(CONFIG_MX7))
  u32 irba_l;
  u32 irba_h;
#else
  u32      irba_h;
  u32      irba_l;
#endif
  u32 rsvd1;
  u32 irs;
  u32 rsvd2;
  u32 irsa;
  u32 rsvd3;
  u32 irja;
#if defined(CONFIG_SYS_FSL_SEC_LE) && \
    !(defined(CONFIG_MX6) || defined(CONFIG_MX7))
  u32 orba_l;
  u32 orba_h;
#else
  u32      orba_h;
  u32      orba_l;
#endif
  u32 rsvd4;
  u32 ors;
  u32 rsvd5;
  u32 orjr;
  u32 rsvd6;
  u32 orsf;
  u32 rsvd7;
  u32 jrsta;
  u32 rsvd8;
  u32 jrint;
  u32 jrcfg0;
  u32 jrcfg1;
  u32 rsvd9;
  u32 irri;
  u32 rsvd10;
  u32 orwi;
  u32 rsvd11;
  u32 jrcr;
};

/*
 * Scatter Gather Entry - Specifies the the Scatter Gather Format
 * related information
 */
#define SG_ENTRY_LENGTH_MASK 0x3FFFFFFF
#define SG_ENTRY_EXTENSION_BIT 0x80000000
#define SG_ENTRY_FINAL_BIT 0x40000000

#define SG_ENTRY_BPID_MASK 0x00FF0000
#define SG_ENTRY_BPID_SHIFT 16
#define SG_ENTRY_OFFSET_MASK 0x00001FFF
#define SG_ENTRY_OFFSET_SHIFT 0

struct sg_entry {
#ifdef SG_LE
  uint32_t addr_lo; /* Memory Address - lo */
  uint32_t addr_hi; /* Memory Address of start of buffer - hi */
#else
  uint32_t addr_hi; /* Memory Address of start of buffer - hi */
  uint32_t addr_lo; /* Memory Address - lo */
#endif

  uint32_t len_flag; /* Length of the data in the frame */

  uint32_t bpid_offset;
};

/* blob_dek:
 * Encapsulates the src in a secure blob and stores it dst
 * @src: reference to the plaintext
 * @dst: reference to the output adrress
 * @len: size in bytes of src
 * @return: 0 on success, error otherwise
 */
extern int blob_dek(const u8 *src, u8 *dst, u8 len);

extern int sec_init(struct csec_priv_t *csec_priv);

enum cipher_algos {
  AES= 0x10,
  DES= 0x20,
  DES3= 0x21,
  ARC4= 0x30,
  RNG= 0x50,
  SNOW_3G_f8= 0x60,
  Kasumi= 0x70,
  SM1= 0x80,
  SM4= 0x90,
  SSF33= 0xA0,
  SM6= 0xB0
};  //need to compate with csec define

enum hash_algos {
  H_MD5= 0x40,
  H_SHA1= 0x41,
  H_SHA224= 0x42,
  H_SHA256= 0x43,
  H_SHA384= 0x44,
  H_SHA512= 0x45,
  H_SHA0= 0x46,
  H_SM3= 0x47,
  H_CRC= 0x90,
  H_S3Gf9= 0xa0
};  //need to compate with csec define

enum hash_algos_b {
  MD5= 0x40,
  SHA1= 0x41,
  SHA224= 0x42,
  SHA256= 0x43,
  SHA384= 0x44,
  SHA512= 0x45,
  SHA0= 0x46,
  SM3= 0x47,
  CRC= 0x90,
  S3Gf9= 0xa0
};  //need to compate with csec define

enum encdec { DEC= 0, ENC };  //need to compate with csec define

enum atype {
  CBC= 0x10,
  ECB= 0x20,
  CFB= 0x30,
  CFB1= 0x31,
  CFB8= 0x32,
  CFB16= 0x33,
  CFB32= 0x34,
  CFB64= 0x35,
  OFB= 0x40,
  OFB1= 0x41,
  OFB8= 0x42,
  OFB16= 0x43,
  OFB32= 0x44,
  OFB64= 0x45,
  CTR= 0x00,
  CCM= 0x80,
};  //need to compate with csec define

enum htype { T_HASH= 0x00, T_HMAC= 0x01, T_SMAC= 0x02, T_HMAC_IOPAD= 0x04 };

enum asvalue { UPDATA= 0, INIT, FINAL, INITFINAL };

#define JRSTA_CCBERR_JUMP 0x08000000
#define JRSTA_CCBERR_INDEX_MASK 0xff00
#define JRSTA_CCBERR_INDEX_SHIFT 8
#define JRSTA_CCBERR_CHAID_MASK 0x00f0
#define JRSTA_CCBERR_CHAID_SHIFT 4
#define JRSTA_CCBERR_ERRID_MASK 0x000f

#define JRSTA_CCBERR_CHAID_AES (0x01 << JRSTA_CCBERR_CHAID_SHIFT)
#define JRSTA_CCBERR_CHAID_DES (0x02 << JRSTA_CCBERR_CHAID_SHIFT)
#define JRSTA_CCBERR_CHAID_ARC4 (0x03 << JRSTA_CCBERR_CHAID_SHIFT)
#define JRSTA_CCBERR_CHAID_MD (0x04 << JRSTA_CCBERR_CHAID_SHIFT)
#define JRSTA_CCBERR_CHAID_RNG (0x05 << JRSTA_CCBERR_CHAID_SHIFT)
#define JRSTA_CCBERR_CHAID_SNOW (0x06 << JRSTA_CCBERR_CHAID_SHIFT)
#define JRSTA_CCBERR_CHAID_KASUMI (0x07 << JRSTA_CCBERR_CHAID_SHIFT)
#define JRSTA_CCBERR_CHAID_PK (0x08 << JRSTA_CCBERR_CHAID_SHIFT)
#define JRSTA_CCBERR_CHAID_CRC (0x09 << JRSTA_CCBERR_CHAID_SHIFT)

#define JRSTA_CCBERR_ERRID_NONE 0x00
#define JRSTA_CCBERR_ERRID_MODE 0x01
#define JRSTA_CCBERR_ERRID_DATASIZ 0x02
#define JRSTA_CCBERR_ERRID_KEYSIZ 0x03
#define JRSTA_CCBERR_ERRID_PKAMEMSZ 0x04
#define JRSTA_CCBERR_ERRID_PKBMEMSZ 0x05
#define JRSTA_CCBERR_ERRID_SEQUENCE 0x06
#define JRSTA_CCBERR_ERRID_PKDIVZRO 0x07
#define JRSTA_CCBERR_ERRID_PKMODEVN 0x08
#define JRSTA_CCBERR_ERRID_KEYPARIT 0x09
#define JRSTA_CCBERR_ERRID_ICVCHK 0x0a
#define JRSTA_CCBERR_ERRID_HARDWARE 0x0b
#define JRSTA_CCBERR_ERRID_CCMAAD 0x0c
#define JRSTA_CCBERR_ERRID_INVCHA 0x0f

#endif /* SEC_H_ */
