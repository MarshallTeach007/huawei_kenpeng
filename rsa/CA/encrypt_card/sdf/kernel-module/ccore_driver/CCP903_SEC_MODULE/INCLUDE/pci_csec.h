/***************************************************
 * pci_csec.h
 *
 * Created on: Mar 20, 2017
 * Author: zjjin@ccore.com
 ***************************************************/

#ifndef _PCI_CSEC_H_
#define _PCI_CSEC_H_

#include "./compate.h"
#include "./jr.h"

#define cpu_2_le32	cpu_to_le32
#define le32_2_cpu	le32_to_cpu
//#define cpu_2_le32	
//#define le32_2_cpu	

#define CSEC_DEV_NAME        "csec"
#define CSEC_DEV_SYM_NAME        "csec_sym"
#define CSEC_DEV_ASYM_NAME        "csec_asym"

#define CRYCARD_VENDOR	0x9000
#define CRYCARD_DEV903T 0x0003
#define CRYCARD_DEV903H 0x0005

#define SYS_DMA	0
//#define SYS_DMA GFP_DMA

#define POLL_INVL (1*HZ)
//#define POLL_INVL (10)
#define CDEV_INVL (1*HZ)

#define CMP_TOUT  (1000000)

#define MAIN_DDR
//#define CARD_IHADDR 0x0UL
//#define PCIE_AREA_OFF (0x180000000UL)

#define CARD_IHADDR 0x80000000ULL
#define PCIE_AREA_OFF 0ULL

#define NO_SPLIT_KEY

//#define csec_debug printk
#define csec_debug  noprintk
//#define csec_debug2 printk
#define csec_debug2 noprintk
//#define csec_debug3 printk
#define csec_debug3 noprintk
//#define csec_debug4 printk
#define csec_debug4 noprintk
#define csec_error printk
//#define csec_error noprintk

#define mphys_addr_t u64

#define SEC_ADDR(idx)	(0x00000000e0100000ULL|(CARD_IHADDR<<32))			//c9000
#define INRAM_ADDR		(0x00000000e0310000ULL|(CARD_IHADDR<<32))
#define COMMU_SIZE	0x10

#define SIZE4KI	0x1000
//#define DATA_MARGIN 0x1000
#define DATA_MARGIN 0x04
#define SIZEMAX	0x11000

#define SGMAX	256

#define DQ_PEND		1
#define DQ_NOPEND	0

#define IATU_INDEX	(0x900)
#define IATU_CTRL1	(0x904)
#define IATU_CTRL2	(0x908)
#define IATU_LBA	(0x90c)
#define IATU_UBA	(0x910)
#define IATU_LAR	(0x914)
#define IATU_LTAR	(0x918)
#define IATU_UTAR	(0x91c)
#define IATU_CTRL3 	(0x920)

#define CSEC_MAX_COMP (128)
#define PW_CHECK	1
//add for custom api
#if 0
#define	MAX_CMD_LEN		0x10000     //64K
#define	PCIE_DATABUF_ADDR	0xE0360000  //缓冲区起始地址
#else
#define	MAX_CMD_LEN		0x08000     //32K
#define	PCIE_DATABUF_ADDR	0xE0370000  //缓冲区起始地址
#endif

#define	CMD_BUF_ADDR		(PCIE_DATABUF_ADDR + 0)
#define	RES_BUF_ADDR		(PCIE_DATABUF_ADDR + MAX_CMD_LEN)

#define 	CMD_FLAG_ADDR_OFFSET		(0x000FFFFC)
#define 	CMD_FLAG_VALID				(0x5D5D5D5D)


#define TIMEOUT_COUNT_VALUE		(100000)


#if LINUX_VERSION_CODE>=KERNEL_VERSION(3,19,0)
	#define MREAD_ONCE READ_ONCE
	#define MWRITE_ONCE WRITE_ONCE
#else
	#define MREAD_ONCE ACCESS_ONCE
	#define MWRITE_ONCE ACCESS_ONCE
	
#endif

struct ba_t {
	resource_size_t base_phy;
	resource_size_t len;
	unsigned long flags;
	void *base_virt;
};

typedef struct jr_total_st{
	struct jobring jr[Ring_Num];
	int i_nr;
}jrt_st;

struct ccore_cards_t
{
	struct cdev cdev;
	struct cdev cdev_sym;
	struct cdev cdev_asym;
	dev_t dev_no;
	dev_t dev_no_sym;
	dev_t dev_no_asym;
	struct list_head card_list;
	struct list_head alg_list;
	int current_card;
	int total_cards;
	spinlock_t cardlock ____cacheline_aligned;
	struct class *csec_classp;
	struct class *csec_classp_sym;
	struct class *csec_classp_asym;
	struct device *csec_class_devp;
	struct device *csec_class_devp_sym;
	struct device *csec_class_devp_asym;
	struct platform_device *pdev;
};

struct csec_priv_t
{
	// constant fields
	struct pci_dev *pci_dev;
	struct device *dev;
	struct timer_list timer; 
	struct ba_t ba[6];

	struct ccore_cards_t *ccore_cards;

	struct list_head card_entry;
	int card_idx;
	jrt_st jr_t;
	struct jobring *jr_g;
	int ring_total;
	mphys_addr_t inram_base;
	mphys_addr_t sec_base;
	mphys_addr_t ring_phy;
	mphys_addr_t commu_phy;
	void *ring_virt;
	void *commu_virt;
	struct work_struct dequeue_task[Ring_Num];
	
	spinlock_t seclock ____cacheline_aligned;

//add for custom api 
	void *cmd_buf;
	dma_addr_t cmd_phys_addr;
	size_t cmd_buf_size;
	struct completion trans_cmpl;

};

//add for custom api
struct cards_driver_cap
{	
	unsigned int cmd_max_size;	
	unsigned char *send_virt_buf;	
	unsigned char *recv_virt_buf;
};

extern void noprintk(const char *fmt,...);

extern dma_addr_t change_addr_for_sec(dma_addr_t addr);

extern dma_addr_t change_addr_for_cpu(dma_addr_t addr);

static inline int miszero(void *addr,u32 len)		//len bust 4bytes alian
{
	int i;
	u32 *maddr = (u32 *)addr;
	for(i=0;i<len/4;i++)
	{
		if(maddr[i]!=0)
			return -1;
	}
	return 0;
}

#endif
