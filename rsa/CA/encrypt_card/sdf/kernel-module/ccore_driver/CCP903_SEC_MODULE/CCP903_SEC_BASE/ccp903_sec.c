/***************************************************
 * ccp903_sec.c
 *
 * Created on: Mar 20, 2017
 * Author: zjjin@ccore.com
 ***************************************************/

#include "../INCLUDE/compate.h"
#include "../INCLUDE/pci_csec.h"
#include "../INCLUDE/jr.h"
#include "../INCLUDE/sec.h"

#include "../INCLUDE/ccp903_dbg.h"

#define PCIE_CARD_CSEC
//#define PLATFORM_CSEC
//#define BAR_CONFIG_IN_COS

extern int sec_init(struct csec_priv_t *csec_priv);
extern void sec_dequeue(void *data);
/*0: Success; -N: Error.*/
static int probe_status = 0;

#define DBI_BAR0	0x10
#define DBI_BAR1	0x14
#define DBI_BAR2	0x18
#define DBI_BAR3	0x1C
#define DBI_BAR4	0x20
#define DBI_BAR5	0x24

#ifdef PCIE_CARD_CSEC

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
static struct workqueue_struct *g_dq_work_queue[Ring_Num] = {NULL};
#endif

void schedule_work_unbound(struct work_struct *w, unsigned int ring_index)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	/*Latency work queue schedule scheme*/
	//schedule_work(w);
	if(!g_dq_work_queue[ring_index])
		return;
	queue_work(g_dq_work_queue[ring_index],w);
#else
	/* system_unbound_wq: Do not bind schedule worker to specific CPU core.*/
	queue_work(system_unbound_wq,w);
#endif
}

//add for custom api
void ep_dma_wr_init(struct pci_dev *pci_dev,  unsigned int len, unsigned int ctrl)
{
	struct csec_priv_t *csec_priv;

#ifdef BAR_CONFIG_IN_COS
	void __iomem *regaddr = NULL;
#endif

	csec_priv = pci_get_drvdata(pci_dev);

#ifdef BAR_CONFIG_IN_COS

	regaddr = (void __iomem *)(csec_priv->ba[5].base_virt);

	sec_out32(regaddr+0x4000+0x97c, cpu_2_le32(0x00000000));
	sec_out32(regaddr+0x4000+0x97c, cpu_2_le32(0x00000001));
	sec_out32(regaddr+0x4000+0x9c4, cpu_2_le32(0x00010001));
	sec_out32(regaddr+0x4000+0xa6c, cpu_2_le32(0x00000000));
	sec_out32(regaddr+0x4000+0xa70, cpu_2_le32(ctrl));
	sec_out32(regaddr+0x4000+0xa78, cpu_2_le32(len));
	sec_out32(regaddr+0x4000+0xa7c, cpu_2_le32(RES_BUF_ADDR));
	sec_out32(regaddr+0x4000+0xa80, cpu_2_le32(0x80000000));
	sec_out32(regaddr+0x4000+0xa84, cpu_2_le32((unsigned int)(csec_priv->cmd_phys_addr + MAX_CMD_LEN)));
	sec_out32(regaddr+0x4000+0xa88, cpu_2_le32((unsigned int)((csec_priv->cmd_phys_addr + MAX_CMD_LEN) >>32)));
	sec_out32(regaddr+0x4000+0x980, cpu_2_le32(0x00000000));
#else

	pci_write_config_dword(pci_dev, 0x97c, 0x00000000);
	pci_write_config_dword(pci_dev, 0x97c, 0x00000001);
	pci_write_config_dword(pci_dev, 0x9c4, 0x00010001);
	//write32_cfg(hDev, 0x9c4, 0x00000000);
	pci_write_config_dword(pci_dev, 0xa6c, 0x00000000);
	pci_write_config_dword(pci_dev, 0xa70, ctrl);
	pci_write_config_dword(pci_dev, 0xa78, len);
	pci_write_config_dword(pci_dev, 0xa7c, RES_BUF_ADDR);
	pci_write_config_dword(pci_dev, 0xa80, 0x80000000);
	pci_write_config_dword(pci_dev, 0xa84, (unsigned int)(csec_priv->cmd_phys_addr + MAX_CMD_LEN));
	pci_write_config_dword(pci_dev, 0xa88, (unsigned int)((csec_priv->cmd_phys_addr + MAX_CMD_LEN) >>32));
	pci_write_config_dword(pci_dev, 0x980, 0x00000000);
#endif
}

void ep_dma_rd_init(struct pci_dev *pci_dev, unsigned int len, unsigned int ctrl)
{
	struct csec_priv_t *csec_priv;

#ifdef BAR_CONFIG_IN_COS
	void __iomem *regaddr = NULL;
#endif

	csec_priv = pci_get_drvdata(pci_dev);

#ifdef BAR_CONFIG_IN_COS

	regaddr = (void __iomem *)(csec_priv->ba[5].base_virt);

	sec_out32(regaddr+0x4000+0x99c, cpu_2_le32(0x00000000));
	sec_out32(regaddr+0x4000+0x99c, cpu_2_le32(0x00000001));
	sec_out32(regaddr+0x4000+0xa18, cpu_2_le32(0x00000000));
	sec_out32(regaddr+0x4000+0xa6c, cpu_2_le32(0x80000000));
	sec_out32(regaddr+0x4000+0xa70, cpu_2_le32(ctrl));
	sec_out32(regaddr+0x4000+0xa78, cpu_2_le32(len));
	sec_out32(regaddr+0x4000+0xa7c, cpu_2_le32((unsigned int)csec_priv->cmd_phys_addr));
	sec_out32(regaddr+0x4000+0xa80, cpu_2_le32((unsigned int)(csec_priv->cmd_phys_addr >>32)));
	sec_out32(regaddr+0x4000+0xa84, cpu_2_le32(CMD_BUF_ADDR));
	sec_out32(regaddr+0x4000+0xa88, cpu_2_le32(0x80000000));
	sec_out32(regaddr+0x4000+0x9a0, cpu_2_le32(0x00000000));
#else
			
	pci_write_config_dword(pci_dev, 0x99c, 0x00000000); 
	pci_write_config_dword(pci_dev, 0x99c, 0x00000001);
	//pci_write_config_dword(pci_dev, 0xa18, 0x00010001);
	pci_write_config_dword(pci_dev, 0xa18, 0x00000000);
	pci_write_config_dword(pci_dev, 0xa6c, 0x80000000);
	pci_write_config_dword(pci_dev, 0xa70, ctrl);
	pci_write_config_dword(pci_dev, 0xa78, len);
	pci_write_config_dword(pci_dev, 0xa7c, (unsigned int)csec_priv->cmd_phys_addr);
	pci_write_config_dword(pci_dev, 0xa80, (unsigned int)(csec_priv->cmd_phys_addr >>32));
	pci_write_config_dword(pci_dev, 0xa84, CMD_BUF_ADDR);
	pci_write_config_dword(pci_dev, 0xa88, 0x80000000);
	pci_write_config_dword(pci_dev, 0x9a0, 0x00000000);
#endif
}

void pci_epdma_config(struct pci_dev *pci_dev)
{
	struct csec_priv_t *csec_priv;

#ifdef BAR_CONFIG_IN_COS
	void __iomem *regaddr = NULL;
#endif

	csec_priv = pci_get_drvdata(pci_dev);
		
	init_completion(&csec_priv->trans_cmpl);
	csec_priv->pci_dev = pci_dev;
	csec_priv->cmd_buf_size = 0x100000;
	csec_priv->cmd_buf = dma_alloc_coherent(csec_priv->dev, csec_priv->cmd_buf_size, &csec_priv->cmd_phys_addr, GFP_KERNEL|GFP_DMA);
	if(!csec_priv->cmd_buf){
		csec_debug("pci_csec_config:alloc cmd buf fail\n");
	}
	writel(0, csec_priv->cmd_buf + CMD_FLAG_ADDR_OFFSET);

#ifdef BAR_CONFIG_IN_COS

	regaddr = (void __iomem *)(csec_priv->ba[5].base_virt);

	sec_out32(regaddr+0x4000+IATU_INDEX, cpu_2_le32(0x00000001));
	sec_out32(regaddr+0x4000+IATU_LBA, cpu_2_le32(0x80000000));
	sec_out32(regaddr+0x4000+IATU_UBA, cpu_2_le32(0x00000001));
	sec_out32(regaddr+0x4000+IATU_LAR, cpu_2_le32(0x800fffff));
	sec_out32(regaddr+0x4000+IATU_LTAR, cpu_2_le32(csec_priv->cmd_phys_addr));
	sec_out32(regaddr+0x4000+IATU_UTAR, cpu_2_le32((csec_priv->cmd_phys_addr)>>32));
	sec_out32(regaddr+0x4000+IATU_CTRL1, cpu_2_le32(0x00000000));
	sec_out32(regaddr+0x4000+IATU_CTRL2, cpu_2_le32(0x80000000));
#else
	
	pci_write_config_dword(pci_dev, IATU_INDEX, 0x00000001);	//card inbound & index 2
	pci_write_config_dword(pci_dev, IATU_LBA, (unsigned)(0x80000000));
	pci_write_config_dword(pci_dev, IATU_UBA, (unsigned)(0x00000001));
	pci_write_config_dword(pci_dev, IATU_LAR, (unsigned)(0x800fffff));
	pci_write_config_dword(pci_dev, IATU_LTAR, (unsigned)(csec_priv->cmd_phys_addr));
	pci_write_config_dword(pci_dev, IATU_UTAR, (unsigned)((csec_priv->cmd_phys_addr)>>32));
	pci_write_config_dword(pci_dev, IATU_CTRL1,0x00000000);
	pci_write_config_dword(pci_dev, IATU_CTRL2,0x80000000);			//enable
#endif
	csec_error(KERN_ERR "CCP903T: Crypto card PCIe EPDMA initialized.\n");
}

/* 
 * host_from_ep_dma_read: Host read data from crypto card through DMA.
 * pci_dev:		pci devide pointer.
 * len:			length of data will be read from crypto card RAM.
 * ctrl:		Enable local DMA interrupt
 * ep_send_buf_addr:	The memory address of crypto card which used for
 *			holding the data ready to send.
 * offset:		The offset between 'cmd_phys_addr' and the host memory
 *			address mapping to ep_send_buf_addr. 
 */
void host_from_ep_dma_read(struct pci_dev *pci_dev,  unsigned int len, unsigned int ctrl,
				unsigned int ep_send_buf_addr, unsigned int offset)
{
	struct csec_priv_t *csec_priv;

#ifdef BAR_CONFIG_IN_COS
	void __iomem *regaddr = NULL;
#endif

	csec_priv = pci_get_drvdata(pci_dev);

#ifdef BAR_CONFIG_IN_COS

	regaddr = (void __iomem *)(csec_priv->ba[5].base_virt);

	sec_out32(regaddr+0x4000+0x97c, cpu_2_le32(0x00000000));
	sec_out32(regaddr+0x4000+0x97c, cpu_2_le32(0x00000001));
	sec_out32(regaddr+0x4000+0x9c4, cpu_2_le32(0x00010001));
	sec_out32(regaddr+0x4000+0xa6c, cpu_2_le32(0x00000000));
	sec_out32(regaddr+0x4000+0xa70, cpu_2_le32(ctrl));
	sec_out32(regaddr+0x4000+0xa78, cpu_2_le32(len));
	sec_out32(regaddr+0x4000+0xa7c, cpu_2_le32(ep_send_buf_addr));
	sec_out32(regaddr+0x4000+0xa80, cpu_2_le32(0x80000000));
	sec_out32(regaddr+0x4000+0xa84, cpu_2_le32((unsigned int)(csec_priv->cmd_phys_addr + offset)));
	sec_out32(regaddr+0x4000+0xa88, cpu_2_le32((unsigned int)((csec_priv->cmd_phys_addr + offset) >>32)));
	sec_out32(regaddr+0x4000+0x980, cpu_2_le32(0x00000000));
#else

	pci_write_config_dword(pci_dev, 0x97c, 0x00000000);
	pci_write_config_dword(pci_dev, 0x97c, 0x00000001);
	pci_write_config_dword(pci_dev, 0x9c4, 0x00010001);
	//write32_cfg(hDev, 0x9c4, 0x00000000);
	pci_write_config_dword(pci_dev, 0xa6c, 0x00000000);
	pci_write_config_dword(pci_dev, 0xa70, ctrl);
	pci_write_config_dword(pci_dev, 0xa78, len);
	pci_write_config_dword(pci_dev, 0xa7c, ep_send_buf_addr);
	pci_write_config_dword(pci_dev, 0xa80, 0x80000000);
	pci_write_config_dword(pci_dev, 0xa84, (unsigned int)(csec_priv->cmd_phys_addr + offset));
	pci_write_config_dword(pci_dev, 0xa88, (unsigned int)((csec_priv->cmd_phys_addr + offset) >>32));
	pci_write_config_dword(pci_dev, 0x980, 0x00000000);
#endif
}

/* host_to_ep_dma_write: Host read data from crypto card through DMA.
 * pci_dev:		pci devide pointer.
 * len:			length of data will be writen to crypto card RAM.
 * ctrl:		Enable local DMA interrupt
 * ep_recv_buf_addr:	The receive buffer memory address of crypto card.
 * offset:		The offset between 'cmd_phys_addr' and the host memory
 *			address mapping to ep_recv_buf_addr. 
 */
void host_to_ep_dma_write(struct pci_dev *pci_dev, unsigned int len, unsigned int ctrl,
				unsigned int ep_recv_buf_addr, unsigned int offset)
{
	struct csec_priv_t *csec_priv;

#ifdef BAR_CONFIG_IN_COS
	void __iomem *regaddr = NULL;
#endif

	csec_priv = pci_get_drvdata(pci_dev);

#ifdef BAR_CONFIG_IN_COS

	regaddr = (void __iomem *)(csec_priv->ba[5].base_virt);

	sec_out32(regaddr+0x4000+0x99c, cpu_2_le32(0x00000000));
	sec_out32(regaddr+0x4000+0x99c, cpu_2_le32(0x00000001));
	sec_out32(regaddr+0x4000+0xa18, cpu_2_le32(0x00000000));
	sec_out32(regaddr+0x4000+0xa6c, cpu_2_le32(0x80000000));
	sec_out32(regaddr+0x4000+0xa70, cpu_2_le32(ctrl));
	sec_out32(regaddr+0x4000+0xa78, cpu_2_le32(len));
	sec_out32(regaddr+0x4000+0xa7c, cpu_2_le32((unsigned int)csec_priv->cmd_phys_addr));
	sec_out32(regaddr+0x4000+0xa80, cpu_2_le32((unsigned int)(csec_priv->cmd_phys_addr >>32)));
	sec_out32(regaddr+0x4000+0xa84, cpu_2_le32(ep_recv_buf_addr)); //CMD_BUF_ADDR
	sec_out32(regaddr+0x4000+0xa88, cpu_2_le32(0x80000000));
	sec_out32(regaddr+0x4000+0x9a0, cpu_2_le32(0x00000000));
#else
			
	pci_write_config_dword(pci_dev, 0x99c, 0x00000000); 
	pci_write_config_dword(pci_dev, 0x99c, 0x00000001);
	//pci_write_config_dword(pci_dev, 0xa18, 0x00010001);
	pci_write_config_dword(pci_dev, 0xa18, 0x00000000);
	pci_write_config_dword(pci_dev, 0xa6c, 0x80000000);
	pci_write_config_dword(pci_dev, 0xa70, ctrl);
	pci_write_config_dword(pci_dev, 0xa78, len);
	pci_write_config_dword(pci_dev, 0xa7c, (unsigned int)(csec_priv->cmd_phys_addr + offset));
	pci_write_config_dword(pci_dev, 0xa80, (unsigned int)((csec_priv->cmd_phys_addr + offset) >>32));
	pci_write_config_dword(pci_dev, 0xa84, ep_recv_buf_addr);
	pci_write_config_dword(pci_dev, 0xa88, 0x80000000);
	pci_write_config_dword(pci_dev, 0x9a0, 0x00000000);
#endif
}

/* read info from bar
 *
 *
 */
int ccore_pci_read_from_bar(struct csec_priv_t *csec_priv, unsigned int bar_index, unsigned int offset, unsigned int size, unsigned int *pbuf)
{
	volatile unsigned int i;
	volatile unsigned int value;
	unsigned int *p;
	void __iomem *regaddr = NULL;
	
	if(csec_priv == NULL)
		return -ENODEV;

	if(bar_index >= 6)
		return -EINVAL;

	regaddr = (void __iomem *)(csec_priv->ba[bar_index].base_virt);
	if(regaddr == NULL){
		printk(KERN_ERR "bar[%d] unremap\n", bar_index);
		return -EINVAL;
	}

	p = pbuf;
	
	for(i=0; i<size; i+=4)
	{
		value = sec_in32(regaddr+offset+i);
		
		*p++ = value;		
	}

	return 0;
}

int ccore_pci_csec_init(struct csec_priv_t *csec_priv)
{	
	if(csec_priv == NULL)
		return -ENODEV;

	return 0;
}

int ccore_pci_csec_release(struct csec_priv_t *csec_priv)
{
	int ret = 0;
	
	csec_debug("ccore_pci_csec_release\n");
	if(csec_priv == NULL)
	{
		return -ENODEV; 
	}

	if(csec_priv->cmd_buf){
		dma_free_coherent(&csec_priv->pci_dev->dev, csec_priv->cmd_buf_size, csec_priv->cmd_buf, csec_priv->cmd_phys_addr);
		csec_priv->cmd_buf = NULL;
	}

	return ret;
}

void ccore_pci_transmint_init(struct csec_priv_t *csec_priv)
{	
	
	writel(0, csec_priv->cmd_buf + CMD_FLAG_ADDR_OFFSET);
	
}

int ccore_pci_transmit_wait_timeout(struct csec_priv_t *csec_priv, int seconds)
{
	volatile u32 stat;
	unsigned long timeout;
	unsigned long timeout1;

	timeout = jiffies + HZ*seconds;
	timeout1 = jiffies + HZ*5;
	
	do{
		stat = readl(csec_priv->cmd_buf + CMD_FLAG_ADDR_OFFSET);
		if(stat == CMD_FLAG_VALID){
			writel(0, csec_priv->cmd_buf + CMD_FLAG_ADDR_OFFSET);
			return 0;
		}

		if(time_after(jiffies, timeout)){
			return -ETIMEDOUT; 
		}
		else if(time_after(jiffies, timeout1)){
			msleep(1);
		}

		cpu_relax();
	}while(1);

	return -EINVAL;
}

int ccore_pci_transmit(struct csec_priv_t *csec_priv, unsigned char* pbInData, int InLen, unsigned char* pbOutData, int *pOutLen)
{
	int ret = 0;
	volatile unsigned int value;
	volatile unsigned int timeout;
	
#ifdef BAR_CONFIG_IN_COS
	void __iomem *regaddr = NULL;
#endif

	if(csec_priv == NULL)
	{
		return -ENODEV; 
	}

	if((InLen <= 0) || (InLen > MAX_CMD_LEN) || (*pOutLen <= 0) || (*pOutLen > MAX_CMD_LEN))
	{			
		printk(KERN_ERR "ccore_pci_transmit len ivalid\n");
		return -EINVAL;
	}

#ifdef BAR_CONFIG_IN_COS
	regaddr = (void __iomem *)(csec_priv->ba[5].base_virt);
#endif
	ccore_pci_transmint_init(csec_priv);

	ep_dma_rd_init(csec_priv->pci_dev, InLen, 8);

	ret = ccore_pci_transmit_wait_timeout(csec_priv, 60);
	if(ret)
	{
		printk(KERN_ERR "ccore_pci_transmit_wait_timeout\n");
		return ret;
	}
	
//	printk(KERN_INFO "%s()-recv flag\n", __func__);
	ep_dma_wr_init(csec_priv->pci_dev, *pOutLen, 8);

	timeout = TIMEOUT_COUNT_VALUE;
	ret = -ETIMEDOUT;
	
	while(timeout){
#ifdef BAR_CONFIG_IN_COS
		value = sec_in32(regaddr+0x4000+0x9bc);
#else
		pci_read_config_dword(csec_priv->pci_dev, 0x9bc, (u32 *)&value);
#endif
		if(value != cpu_2_le32(0x1)){
			timeout--;
			cpu_relax();
			continue;
		}else{
#ifdef BAR_CONFIG_IN_COS
			sec_out32(regaddr+0x4000+0x9c8, cpu_2_le32(0x00000001));
#else
			pci_write_config_dword(csec_priv->pci_dev, 0x9c8, cpu_2_le32(0x1));
#endif
			ret = 0;
			break;
		}

	}

	return ret;
}
int ccore_pci_dma_read(struct csec_priv_t *csec_priv, int len)
{
	int ret = 0;
	volatile unsigned int value;
	volatile unsigned int timeout;
#ifdef BAR_CONFIG_IN_COS
	void __iomem *regaddr = NULL;
#endif
		
	if(csec_priv == NULL)
	{
		return -ENODEV; 
	}

#ifdef BAR_CONFIG_IN_COS
	regaddr = (void __iomem *)(csec_priv->ba[5].base_virt);
#endif
	ccore_pci_transmint_init(csec_priv);

	host_from_ep_dma_read(csec_priv->pci_dev, len, 8, CMD_BUF_ADDR, 0); 

	timeout = TIMEOUT_COUNT_VALUE;
	ret = -ETIMEDOUT;
	
	while(timeout){
#ifdef BAR_CONFIG_IN_COS
		value = sec_in32(regaddr+0x4000+0x9bc);
#else
		pci_read_config_dword(csec_priv->pci_dev, 0x9bc, (u32 *)&value);
#endif
		if(value != cpu_2_le32(0x1)){
			timeout--;
			cpu_relax();
			continue;
		}else{
#ifdef BAR_CONFIG_IN_COS
			sec_out32(regaddr+0x4000+0x9c8, cpu_2_le32(0x00000001));
#else
			pci_write_config_dword(csec_priv->pci_dev, 0x9c8, cpu_2_le32(0x1));
#endif
			ret = 0;
			break;
		}

	}

	return ret;
}
int ccore_pci_dma_write(struct csec_priv_t *csec_priv, int len)
{
	int ret = 0;

#ifdef BAR_CONFIG_IN_COS
	void __iomem *regaddr = NULL;
#endif
		
	if(csec_priv == NULL)
	{
		return -ENODEV; 
	}

#ifdef BAR_CONFIG_IN_COS
	regaddr = (void __iomem *)(csec_priv->ba[5].base_virt);
#endif
	ccore_pci_transmint_init(csec_priv);

	host_to_ep_dma_write(csec_priv->pci_dev, len, 8, CMD_BUF_ADDR, 0);

	ret = ccore_pci_transmit_wait_timeout(csec_priv, 60);
	if(ret)
	{
		printk(KERN_ERR "ccore_pci_transmit_wait_timeout\n");
		return ret;
	}
	
	return ret;
}

void pci_csec_config(struct pci_dev *pci_dev)
{
	struct csec_priv_t *csec_priv;
	u32 dbi_val0,dbi_val1;
	csec_priv = pci_get_drvdata(pci_dev);

	pci_write_config_dword(pci_dev, IATU_INDEX, 	0x80000000);	//card inbound & index 0
	pci_read_config_dword(pci_dev,DBI_BAR0,&dbi_val0);
	pci_read_config_dword(pci_dev,DBI_BAR1,&dbi_val1);
	dbi_val0&=0xffffff80;
	pci_write_config_dword(pci_dev, IATU_LBA, 	dbi_val0);
	pci_write_config_dword(pci_dev, IATU_UBA,	dbi_val1);
	pci_write_config_dword(pci_dev, IATU_LAR, 	dbi_val0 +0xfffff );
	pci_write_config_dword(pci_dev, IATU_LTAR, 	(unsigned)(csec_priv->sec_base) );
	pci_write_config_dword(pci_dev, IATU_UTAR,	(unsigned)((csec_priv->sec_base)>>32) );
	pci_write_config_dword(pci_dev, IATU_CTRL1,	0x00000000);
	pci_write_config_dword(pci_dev, IATU_CTRL2,	0x80000000);			//enable

#ifndef MAIN_DDR
	pci_write_config_dword(pci_dev, IATU_INDEX, 	0x80000002);	//card inbound & index 2
	pci_read_config_dword(pci_dev,DBI_BAR3,&dbi_val0);
	dbi_val0&=0xffffff80;
	pci_write_config_dword(pci_dev, IATU_LBA, 	dbi_val0);
	pci_write_config_dword(pci_dev, IATU_UBA, 	0);
	pci_write_config_dword(pci_dev, IATU_LAR, 	dbi_val0+0xffff);
	pci_write_config_dword(pci_dev, IATU_LTAR, 	pci_2_le32((unsigned)(csec_priv->inram_base)));
	pci_write_config_dword(pci_dev, IATU_UTAR, 	pci_2_le32((unsigned)((csec_priv->inram_base)>>32)));
	pci_write_config_dword(pci_dev, IATU_CTRL1,	pci_2_le32(0x00000000));
	pci_write_config_dword(pci_dev, IATU_CTRL2,	pci_2_le32(0x80000000));			//enable
#endif

	
	csec_debug("pci_csec_config: base_addr is %llx,taget_addr is %llx\n",csec_priv->ba[0].base_phy,csec_priv->sec_base);
	csec_debug("pci_csec_config: base_addr32 li is %x,taget_addr32 hi is %x\n",(unsigned int)(csec_priv->ba[0].base_phy),(unsigned int)((csec_priv->sec_base)>>32));
	csec_debug("pci_csec_config: base_virt  is %llx\n",(u64)(csec_priv->ba[0].base_virt));
	csec_error(KERN_ERR "CCP903T: Crypto card PCIe IATU and BAR initialized.\n");
}

irqreturn_t  pci_csec_isr(int irq,void *data)
{
	struct csec_priv_t *csec_priv;
	struct jr_regs __iomem *regs=NULL;
	int i;
	
	//csec_debug2(KERN_INFO "ei\n");
	csec_priv = data;
	for(i=0;i<Ring_Num;i++)
	{
		if(atomic_read(&(csec_priv->jr_t.jr[i].state)) == DQ_NOPEND)
		{	

			regs = csec_priv->jr_t.jr[i].regs;
			smp_mb();
			//if(sec_in32(&regs->jrint)==1)
			{
				//sec_out32(&regs->jrint,cpu_2_le32(1));
				sec_out32(&regs->jrcfg1,cpu_2_le32(1));
				atomic_set(&(csec_priv->jr_t.jr[i].state), DQ_PEND);
				schedule_work_unbound(&csec_priv->dequeue_task[i], i);
			}
		}
	}
	mod_timer(&csec_priv->timer,jiffies+1);
	return IRQ_HANDLED;
}

#if LINUX_VERSION_CODE>=KERNEL_VERSION(4,15,0)
void csec_timer(struct timer_list *mytimer)
#else
void csec_timer(unsigned long data)
#endif
{
	struct csec_priv_t *csec_priv;
	struct jr_regs __iomem *regs=NULL;
	int i;
	unsigned long flags;
	#if LINUX_VERSION_CODE>=KERNEL_VERSION(4,15,0)
	csec_priv = from_timer(csec_priv,mytimer,timer);
	#else
	csec_priv = (struct csec_priv_t *)data;
	#endif
	csec_debug2(KERN_INFO "t\n");
	CSEC_DBG2("t\n");
	for(i=0;i<Ring_Num;i++)
	{
		local_irq_save(flags);
		if(atomic_read(&(csec_priv->jr_t.jr[i].state)) == DQ_NOPEND)
		{

			regs = csec_priv->jr_t.jr[i].regs;
			smp_mb();
			//sec_out32(&regs->jrint,cpu_2_le32(1));
			sec_out32(&regs->jrcfg1,cpu_2_le32(1));
			atomic_set(&(csec_priv->jr_t.jr[i].state), DQ_PEND);
			local_irq_restore(flags);
			schedule_work_unbound(&csec_priv->dequeue_task[i], i);
		} else {
			local_irq_restore(flags);
		}
	}
	mod_timer(&csec_priv->timer,jiffies + POLL_INVL);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
static int dq_work_info(char *buf, char *fmt, ...)
{
	va_list args;
	int len;

	va_start(args, fmt);
	len = vsprintf(buf, fmt, args);
	va_end(args);

	return (len);
}
#endif

static int pci_csec_probe(struct pci_dev *pci_dev, const struct pci_device_id *pci_id)
{
	int ret=-1, i;
	int err;
	struct csec_priv_t *csec_priv;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	char dqname[10];
#endif

	csec_debug(KERN_INFO "pci_csec_probe: called!\n");

	probe_status = 0;

	csec_priv =(struct csec_priv_t *)kzalloc(sizeof(struct csec_priv_t),GFP_KERNEL);

	csec_debug(KERN_INFO "csec_priv is 0x%llx\n",(u64)csec_priv );
	
	if(!csec_priv)
	{
		csec_error(KERN_ERR  "pci_csec_probe: failed to enable device pci_csec\n");
		goto err_no_mem;
	}

	pci_set_drvdata(pci_dev, csec_priv);

	if (!!(ret = pci_enable_device(pci_dev))) {
		csec_error(KERN_ERR  "pci_csec_probe: failed to enable device pci_csec\n");
		goto err_en_dev;
	}
	
	if(!!(ret = pci_request_regions(pci_dev, "csec's pcie device"))) {
		csec_error(KERN_ERR  "pci_csec_probe: failed to request regions\n");
		goto err_req_regions;
	}

	if (!pci_dev_msi_enabled(pci_dev)) {
		if (!!(ret = pci_enable_msi(pci_dev))) {
			csec_error(KERN_ERR  "pci_csec_probe: failed to enable msi,back to intc line\n");
		//	goto err_en_msi;
		}
	}
	
	pci_set_master(pci_dev);

	for (i = 0; i < sizeof(csec_priv->ba) / sizeof(struct ba_t); i++)
	{
		csec_priv->ba[i].base_phy = pci_resource_start(pci_dev, i);
		csec_priv->ba[i].len = pci_resource_len(pci_dev, i);
		csec_priv->ba[i].flags = pci_resource_flags(pci_dev, i);
		csec_debug(KERN_INFO "pci_csec_probe: bar%d: base = 0x%llx, length = 0x%llx, flag = 0x%x\n", i,(u64)((csec_priv->ba)[i].base_phy), (u64)((csec_priv->ba)[i].len), (u32)((csec_priv->ba)[i].flags));
		printk(KERN_INFO "pci_csec_probe: bar%d: base = 0x%llx, length = 0x%llx, flag = 0x%x\n", i,(u64)((csec_priv->ba)[i].base_phy), (u64)((csec_priv->ba)[i].len), (u32)((csec_priv->ba)[i].flags));
	}

	csec_priv->pci_dev = pci_dev;

	csec_priv->ring_total = Ring_Num;
	csec_priv->jr_g =csec_priv->jr_t.jr;
	csec_priv->sec_base = SEC_ADDR(0);
	csec_priv->inram_base = INRAM_ADDR;
	csec_priv->ba[0].base_virt = ioremap(csec_priv->ba[0].base_phy, csec_priv->ba[0].len);		//bar0 is iatu to card sec
#ifdef BAR_CONFIG_IN_COS
	csec_priv->ba[5].base_virt = ioremap(csec_priv->ba[5].base_phy, csec_priv->ba[5].len);		//bar5 is to card reg
#endif
	csec_priv->dev = &pci_dev->dev;
	for(i=0;i<Ring_Num;i++)
	{
		atomic_set(&(csec_priv->jr_t.jr[i].state),DQ_NOPEND);
	}
	
	err = dma_set_coherent_mask(&pci_dev->dev, DMA_BIT_MASK(32));
	if (err) {
		err = dma_set_coherent_mask(&pci_dev->dev, DMA_BIT_MASK(32));
		if(err)
		{		
				csec_error(KERN_ERR "No support 64bit coherent dma! back to 32 bit dma\n");
				goto err_dma;
		}
	}						    
	err = dma_set_mask(&pci_dev->dev, DMA_BIT_MASK(32));
	if (err) {
		err = dma_set_mask(&pci_dev->dev, DMA_BIT_MASK(32));
		if(err)
		{	
			csec_error(KERN_ERR "No support 64bit dma! back to 32 bit dma\n");
			goto err_dma;
		}	
	}

#ifdef BAR_CONFIG_IN_COS
	pci_epdma_config(pci_dev);//add for custom api
#else
	pci_csec_config(pci_dev);
	pci_epdma_config(pci_dev);//add for custom api
#endif

#ifdef MAIN_DDR
	csec_priv->commu_virt =dma_alloc_coherent(csec_priv->dev, array_size*Ring_Num+COMMU_SIZE, &(csec_priv->commu_phy), GFP_KERNEL|GFP_DMA);
	if(!csec_priv->commu_virt)
	{
		csec_error(KERN_ERR "pci_csec_probe:  csec_priv->commu_virt no enough mem");
		goto err_dma_mem;
	}
	csec_priv->ring_virt = csec_priv->commu_virt + COMMU_SIZE;
	csec_priv->ring_phy = change_addr_for_sec(csec_priv->commu_phy+COMMU_SIZE);
#else
	csec_priv->ring_phy = INRAM_ADDR+COMMU_SIZE;
	csec_priv->commu_virt = ioremap(csec_priv->ba[3].base_phy, array_size*Ring_Num+COMMU_SIZE);
	csec_priv->ring_virt = csec_priv->commu_virt + COMMU_SIZE;
#endif

	csec_debug(KERN_INFO "csec_priv->ring_virt is %llx,csec_priv->ring_phy %llx\n",(u64)(csec_priv->ring_virt),csec_priv->ring_phy);
	if(!csec_priv->ring_virt)
	{
		csec_error(KERN_ERR "pci_csec_probe:  csec_priv->ring_virt no enough mem");
		goto err_dma_mem;
	}

	csec_debug(KERN_INFO "pci_csec_probe: vendor = 0x%x, device = 0x%x\n", (unsigned int) pci_dev->vendor, (unsigned int) pci_dev->device);

	err = request_irq(csec_priv->pci_dev->irq,pci_csec_isr, 0,
				  "ccp903_card_irq", csec_priv);

	if (err) {
		csec_error(KERN_ERR "CCP903T: Binding MSI IRQ handler failed, IRQ=%d\n", csec_priv->pci_dev->irq);
	} else {
		csec_error(KERN_ERR "CCP903T: Registered irq handler to binding irq %d for processing sec jobs.\n",
				csec_priv->pci_dev->irq);
	}


	ret = sec_init(csec_priv);
	if(ret)
		goto err_sec_init;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	for(i=0; i<Ring_Num; i++)
	{
		memset(dqname,0,sizeof(dqname));
		dq_work_info(dqname, "dqwork""%d", i);
		g_dq_work_queue[i] = create_singlethread_workqueue(dqname);
		if(!g_dq_work_queue[i]){
			ret = -ENOMEM;
			goto err_sec_init;
		}
	}
#endif


#if LINUX_VERSION_CODE>=KERNEL_VERSION(4,15,0)
	timer_setup(&csec_priv->timer,csec_timer,0);
#else
	init_timer(&csec_priv->timer);
	csec_priv->timer.function = csec_timer;
	csec_priv->timer.data = (unsigned long)csec_priv;
#endif
	csec_priv->timer.expires = jiffies + POLL_INVL;
	add_timer(&csec_priv->timer);
	csec_error(KERN_ERR "CCP903T: Dequeue timer initialized!\n");

	csec_error(KERN_ERR "CCP903T: PCI driver probe crypto card initialized.\n");
	return 0;   

err_sec_init:
	free_irq(csec_priv->pci_dev->irq,csec_priv);

err_dma_mem:
	if (pci_dev_msi_enabled(pci_dev)) {
		pci_disable_msi(pci_dev);
	}

err_dma:
//err_en_msi:
	pci_release_regions(pci_dev);

err_req_regions:
	pci_disable_device(pci_dev);
	
err_en_dev:
	kfree(csec_priv);
	
err_no_mem:
#ifdef MAIN_DDR
	//csec_priv->ring_phy = change_addr_for_cpu(csec_priv->ring_phy);
	dma_free_coherent(csec_priv->dev, array_size*Ring_Num+COMMU_SIZE, csec_priv->commu_virt,csec_priv->commu_phy);
#else
	iounmap(csec_priv->ring_virt);
#endif
	csec_error("CCP903T: PCI driver probe crypto card failed!\n");
	probe_status = ret;
	return ret;
}

static void  pci_csec_remove(struct pci_dev *pdev)
{

	struct csec_priv_t *csec_priv;
	int i;

	csec_debug (KERN_INFO "pci_csec_remove is called\n");

	csec_priv = pci_get_drvdata(pdev);

#ifdef MAIN_DDR
	//csec_priv->ring_phy = change_addr_for_cpu(csec_priv->ring_phy-COMMU_SIZE);
	dma_free_coherent(csec_priv->dev, array_size*Ring_Num+COMMU_SIZE, csec_priv->commu_virt,csec_priv->commu_phy);
#else
	iounmap(csec_priv->ring_virt);
#endif
	free_irq(csec_priv->pci_dev->irq,csec_priv);
	if (pci_dev_msi_enabled(csec_priv->pci_dev)) {
		pci_disable_msi(csec_priv->pci_dev);
	}
	pci_release_regions(pdev);
	pci_disable_device(pdev);

	for(i=0;i<Ring_Num;i++)
		cancel_work_sync(&(csec_priv->dequeue_task[i]) );
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	for(i=0; i<Ring_Num; i++)
	{
		if(g_dq_work_queue[i]){
			destroy_workqueue(g_dq_work_queue[i]);
			g_dq_work_queue[i] = NULL;
		}
	}
#endif

	del_timer(&csec_priv->timer);

	kfree(csec_priv);
	csec_debug (KERN_INFO "pci_csec_remove is over!\n");
	return;
}

static int pci_csec_suspend(struct pci_dev *pdev, pm_message_t state)
{
	csec_debug(KERN_INFO "pci_csec_suspend is called\n");
	return 0;
}

static int pci_csec_resume(struct pci_dev *pdev)
{
	csec_debug(KERN_INFO "pci_csec_resume is called\n");
	return 0;
}

static struct pci_device_id pci_csec_pci_tbl [] __initdata = {
//static struct pci_device_id pci_csec_pci_tbl [] = {
	{PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0}
};

MODULE_DEVICE_TABLE(pci, pci_csec_pci_tbl);

static struct pci_driver pci_csec_pci_driver = {
	name: "csec's pcie device",
	id_table: pci_csec_pci_tbl,
	probe: pci_csec_probe,
	suspend: pci_csec_suspend,
	resume: pci_csec_resume,
	remove: pci_csec_remove,
};

int  pci_csec_init(void)
{
	struct pci_dev *pci_dev = NULL;
	int err;

	csec_debug(KERN_INFO "pci_csec_init is called\n");

	pci_dev = pci_get_device(CRYCARD_VENDOR, CRYCARD_DEV903T, NULL);
	if (pci_dev) {
		pci_dev_put(pci_dev);
		pci_csec_pci_tbl[0].device = CRYCARD_DEV903T;
		csec_error(KERN_ERR "CCP903T: New CCP903T card found,  PCI VendorID=%04x, DeviceID=%04x\n",
								CRYCARD_VENDOR, CRYCARD_DEV903T);
	} else {

		pci_dev = pci_get_device(CRYCARD_VENDOR, CRYCARD_DEV903H, NULL);
		if (pci_dev) {
			pci_dev_put(pci_dev);
			pci_csec_pci_tbl[0].device = CRYCARD_DEV903H;
			csec_error(KERN_ERR "CCP903H: New CCP903H card found,  PCI VendorID=%04x, DeviceID=%04x\n",
									CRYCARD_VENDOR, CRYCARD_DEV903H);
		} else {
			csec_error(KERN_ERR "CCP903T: CCP903T/H card not found!\n");
			return -EINVAL;
		}
	}
	pci_csec_pci_tbl[0].vendor = CRYCARD_VENDOR;

	err = pci_register_driver(&pci_csec_pci_driver);
	if (err || probe_status) {
		if(probe_status) {
			pci_unregister_driver(&pci_csec_pci_driver);
			err = probe_status;
		}
		csec_error(KERN_ERR "CCP903T: PCI driver register failed, error %d.\n", err);
	}

	return err;
}

void  pci_csec_exit(void)
{
	csec_debug(KERN_INFO "pci_csec_exit is called\n");
	pci_unregister_driver(&pci_csec_pci_driver);
}


#endif

