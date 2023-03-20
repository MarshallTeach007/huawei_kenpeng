/***************************************************
 * compate.h
 *
 * Created on: Mar 20, 2017
 * Author: zjjin@ccore.com
 ***************************************************/

#ifndef _COMPATE_H_
#define _COMPATE_H_

#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/pci.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/platform_device.h>
#include <linux/crypto.h>
#include <linux/rtnetlink.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/preempt.h>
#include <linux/compiler.h>
#include <linux/version.h>
#include <asm/atomic.h>

#include <crypto/algapi.h>
#include <crypto/aes.h>
#include <crypto/des.h>
#include <crypto/sha.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
#include <crypto/md5.h>
#endif
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <crypto/hash.h>
#include <crypto/internal/hash.h>
#include <crypto/scatterwalk.h>
#include <crypto/internal/skcipher.h>

#define CCP903T_PCIE_MAGIC 'c' 

#define ACLASS_MASK 0x70
#define ACLASS_CIPHER	0x00
#define ACLASS_RSCP_CIPHER	0x01
#define ACLASS_CIPHER_CCM	0x03
#define ACLASS_HASH		0x20
#define ACLASS_RSCP_HASH		0x21
#define ACLASS_SNOOP		0x30
#define ACLASS_PKHA		0x40
#define ACLASS_SM2_ENCRYPT	0x41
#define ACLASS_SM2_DECRYPT	0x42
#define ACLASS_SM2_SIGNATURE	0x43
#define ACLASS_SM2_VERIFY		0x44
#define ACLASS_SM2_GENKEY		0x45
#define ACLASS_SM2_SIGNATURE_NOID	0x46
#define ACLASS_SM2_VERIFY_NOID		0x47
#define ACLASS_SM2_KEY_AGREEMENTA		0x48
#define ACLASS_SM2_KEY_AGREEMENTB		0x49
#define ACLASS_SM2_GENKEY_SEED		0x4a
#define ACLASS_SM2_ENCRYPT_SEED	0x4b
#define ACLASS_SM2_SIGNATURE_NOID_SEED	0x4c
#define ACLASS_RSA_GENKEY		0x50
#define ACLASS_RSA_PUB			0x51
#define ACLASS_RSA_PRIV		0x52
#define ACLASS_RSA_PRIV_CRT		0x53
#define ACLASS_RSA_PUB_BIG			0x54
#define ACLASS_RSA_PRIV_BIG		0x55

#define PCI_DMA_COMMUNICATE		0x65
#endif
