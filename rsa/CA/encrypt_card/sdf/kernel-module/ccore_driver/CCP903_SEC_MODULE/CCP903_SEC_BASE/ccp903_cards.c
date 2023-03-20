/***************************************************
 * ccp903_cards.c
 *
 * Created on: Mar 20, 2017
 * Author: zjjin@ccore.com
 ***************************************************/

#include "../INCLUDE/compate.h"
#include "../INCLUDE/pci_csec.h"
#include "../INCLUDE/sec.h"
#include "../INCLUDE/jr.h"

#include "../INCLUDE/ccp903_dbg.h"

struct ccore_cards_t *g_ccore_cards = NULL;

extern void schedule_work_unbound(struct work_struct *w, unsigned int ring_index);
extern int sec_enqueue(struct csec_priv_t *csec_priv,uint32_t *desc_addr,dma_addr_t desc_phy_addr,
	       void (*callback)(struct csec_priv_t *csec_priv,uint32_t *desc_addr,dma_addr_t desc_phy_addr,uint32_t status, void *arg),void *arg);
extern int sec_enqueue_ringx(struct csec_priv_t *csec_priv,unsigned ring_num,uint32_t *desc_addr,dma_addr_t desc_phy_addr,
	       void (*callback)(struct csec_priv_t *csec_priv,uint32_t *desc_addr,dma_addr_t desc_phy_addr,uint32_t status, void *arg),void *arg);
extern int sec_dequeue(void *data);
extern int  pci_csec_init(void);
extern void  pci_csec_exit(void);
extern struct file_operations cdev_csec_fops;

extern void dump_jr_info(struct csec_priv_t *csec_priv,struct jobring *jr_in);
extern int ccore_pci_read_from_bar(struct csec_priv_t *csec_priv, unsigned int bar_index, unsigned int offset, unsigned int size, unsigned int *pbuf);
extern int ccore_pci_csec_init(struct csec_priv_t *csec_priv);
extern int ccore_pci_csec_release(struct csec_priv_t *csec_priv);
extern int ccore_pci_transmit(struct csec_priv_t *csec_priv, unsigned char* pbInData, int InLen, unsigned char* pbOutData, int *pOutLen);
extern int ccore_pci_dma_read(struct csec_priv_t *csec_priv, int len);
extern int ccore_pci_dma_write(struct csec_priv_t *csec_priv, int len);


struct ccore_cards_t *get_ccore_cards(void)
{
	return g_ccore_cards;
}
EXPORT_SYMBOL_GPL(get_ccore_cards);


struct csec_priv_t* cards_enqueue_pre(struct ccore_cards_t *ccore_cards)
{
	struct csec_priv_t *csec_priv;


	//csec_debug(KERN_INFO "card_enqueue: called!\n");
	
	spin_lock(&ccore_cards->cardlock);
	list_for_each_entry(csec_priv,&ccore_cards->card_list,card_entry)
	{
		//csec_debug(KERN_INFO "card_enqueue_pre:  csec_priv is 0x%llx\n",csec_priv );
		if(csec_priv->card_idx == ccore_cards->current_card )
		{
			
			ccore_cards->current_card =  ccore_cards->current_card + 1;
			if(ccore_cards->current_card==ccore_cards->total_cards)
			{
				ccore_cards->current_card=0;
			}
			smp_wmb();
			spin_unlock(&ccore_cards->cardlock);
			//spin_unlock_irqrestore(&ccore_cards->cardlock,flags);
			return csec_priv;
		}
		
	}
	spin_unlock(&ccore_cards->cardlock);

	return 0;

}
EXPORT_SYMBOL_GPL(cards_enqueue_pre);

int cards_enqueue(struct csec_priv_t *csec_priv,uint32_t *desc_addr,dma_addr_t desc_phy_addr,
	       void (*callback)(struct csec_priv_t *csec_priv,uint32_t *desc_addr,dma_addr_t desc_phy_addr,uint32_t status, void *arg),void *arg)
{
	int ret= -EBUSY;
	unsigned long flags;
	int i;
	if(csec_priv)
	{
		ret =  sec_enqueue(csec_priv,  desc_addr, desc_phy_addr,callback,arg);
		
		if(ret==-EBUSY)
		{
			local_irq_save(flags);
			for(i=0;i<Ring_Num;i++)
			{
				if(atomic_read(&csec_priv->jr_t.jr[i].state)==DQ_NOPEND)
				{
					atomic_set(&csec_priv->jr_t.jr[i].state,DQ_PEND);
					schedule_work_unbound(&csec_priv->dequeue_task[i], i);
				}
			}
			local_irq_restore(flags);
			csec_debug2(KERN_INFO "y\n");

		}
	}
	return ret;
}
EXPORT_SYMBOL_GPL(cards_enqueue);

int cards_enqueue_ringx(struct csec_priv_t *csec_priv,unsigned ring_num,uint32_t *desc_addr,dma_addr_t desc_phy_addr,
	       void (*callback)(struct csec_priv_t *csec_priv,uint32_t *desc_addr,dma_addr_t desc_phy_addr,uint32_t status, void *arg),void *arg)
{
	int ret= -EBUSY;
	unsigned long flags;
	int i = ring_num;
	if(csec_priv)
	{
		ret =  sec_enqueue_ringx(csec_priv,ring_num, desc_addr, desc_phy_addr,callback,arg);
		
		if(ret==-EBUSY)
		{

			local_irq_save(flags);
			if(atomic_read(&csec_priv->jr_t.jr[i].state)==DQ_NOPEND)
			{
				atomic_set(&csec_priv->jr_t.jr[i].state,DQ_PEND);
				schedule_work_unbound(&csec_priv->dequeue_task[i], i);
			}
			local_irq_restore(flags);
		}
		csec_debug(KERN_INFO "y\n");
	}
	return ret;
}
EXPORT_SYMBOL_GPL(cards_enqueue_ringx);

extern int sec_halt(struct csec_priv_t *csec_priv);

int cards_halt_free(struct ccore_cards_t *ccore_cards)
{
	struct csec_priv_t *csec_priv;
	struct list_head *element;

	csec_debug(KERN_INFO "cards_halt_free: called!\n");

	while (!list_empty(&ccore_cards->card_list)) {
		element = ccore_cards->card_list.next;
		list_del(element);
		csec_priv = list_entry(element, struct csec_priv_t, card_entry);
		sec_halt(csec_priv);
	}
	return 0;
}

//custom api for single pci kernel crypto module
void *cards_init(struct device **dev)
{
	int ret = 0;
	
	struct ccore_cards_t *ccore_cards = NULL;
	struct csec_priv_t *csec_priv = NULL;

	if(g_ccore_cards == NULL){
		csec_debug(KERN_INFO "cards_init: NULL!\n");
		return NULL;
	}
	ccore_cards = g_ccore_cards;
	csec_priv = cards_enqueue_pre(ccore_cards);
	ret = ccore_pci_csec_init(csec_priv);
	if(ret)
		return NULL;
		
	if(dev)
		*dev = (struct device *)csec_priv->dev;
	
	return (void *)(ccore_cards);
}
EXPORT_SYMBOL_GPL(cards_init);


int cards_release(void *cards)
{
	int ret = 0;
	
	struct ccore_cards_t *ccore_cards = NULL;
	//struct csec_priv_t *csec_priv = NULL;

	ccore_cards = (struct ccore_cards_t *)cards;
	if(ccore_cards == NULL)
		return -ENODEV;

	return ret;
}
EXPORT_SYMBOL_GPL(cards_release);

int cards_del_timer(void *cards)
{
	int ret = 0;
	int i;
	
	struct ccore_cards_t *ccore_cards = NULL;
	struct csec_priv_t *csec_priv = NULL;

	ccore_cards = (struct ccore_cards_t *)cards;
	if(ccore_cards == NULL)
		return -ENODEV;
	csec_priv = cards_enqueue_pre(ccore_cards);
	if(csec_priv == NULL)
		return -ENODEV;

	for(i=0;i<Ring_Num;i++)
		cancel_work_sync(&(csec_priv->dequeue_task[i]) );

	del_timer(&csec_priv->timer);

	return ret;
}
EXPORT_SYMBOL_GPL(cards_del_timer);


int cards_transmit(void *cards, unsigned char* pbInData, int InLen, unsigned char* pbOutData, int *pOutLen)
{
	int ret = 0;	
	struct ccore_cards_t *ccore_cards = NULL;
	struct csec_priv_t *csec_priv = NULL;
	
	ccore_cards = (struct ccore_cards_t *)cards;
	if(ccore_cards == NULL)
		return -ENODEV;
	csec_priv = cards_enqueue_pre(ccore_cards);
	if(csec_priv == NULL)
		return -ENODEV;

	ret = ccore_pci_transmit(csec_priv, pbInData,  InLen, pbOutData, pOutLen);

	return ret;
}
EXPORT_SYMBOL_GPL(cards_transmit);
int host_from_cards_read(struct csec_priv_t *csec_priv,
				unsigned char* pbInData, int InLen, 
				unsigned char* pbOutData, int *pOutLen)
{
	return ccore_pci_dma_read(csec_priv, InLen);
}
EXPORT_SYMBOL_GPL(host_from_cards_read);
int host_to_cards_write(struct csec_priv_t *csec_priv,
				unsigned char* pbInData, int InLen, 
				unsigned char* pbOutData, int *pOutLen)
{
	return ccore_pci_dma_write(csec_priv, InLen);
}
EXPORT_SYMBOL_GPL(host_to_cards_write);

int cards_get_capbility(void *cards, struct cards_driver_cap *pcap)
{
	struct ccore_cards_t *ccore_cards = NULL;
	struct csec_priv_t *csec_priv = NULL;

	ccore_cards = (struct ccore_cards_t *)cards;
	if(ccore_cards == NULL || pcap == NULL)
	{			
		printk(KERN_INFO "ccore_pcie_get_capbility get no device\n");
		return -ENODEV;
	}
	csec_priv = cards_enqueue_pre(ccore_cards);
	if(csec_priv == NULL)
	{
		printk(KERN_INFO "ccore_pcie_get_capbility get no csec_priv\n");
		return -ENODEV;
	}

	pcap->cmd_max_size = MAX_CMD_LEN;
	pcap->send_virt_buf = csec_priv->cmd_buf;
	pcap->recv_virt_buf = csec_priv->cmd_buf + MAX_CMD_LEN;

	return 0;
}
EXPORT_SYMBOL_GPL(cards_get_capbility);

int cards_dma_sync_single_for_cpu(void *cards)
{
	struct ccore_cards_t *ccore_cards = NULL;
        struct csec_priv_t *csec_priv = NULL;

	ccore_cards = (struct ccore_cards_t *)cards;
        if(ccore_cards == NULL)
                return -ENODEV;
        csec_priv = cards_enqueue_pre(ccore_cards);

	if(csec_priv)
	{
		dma_sync_single_for_cpu(csec_priv->dev, csec_priv->cmd_phys_addr, csec_priv->cmd_buf_size, DMA_BIDIRECTIONAL);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(cards_dma_sync_single_for_cpu);

int cards_enqueue_wait(void *cards,uint32_t *desc_addr,dma_addr_t desc_phy_addr,
	       void (*callback)(void *data,uint32_t *desc_addr,dma_addr_t desc_phy_addr,uint32_t status, void *arg),void *arg)
{
	int ret= -EBUSY;
	struct ccore_cards_t *ccore_cards = NULL;
	struct csec_priv_t *csec_priv = NULL;
	unsigned long flags;
	int i;
	
	ccore_cards = (struct ccore_cards_t *)cards;
	if(ccore_cards == NULL)
		return -ENODEV;
	csec_priv = cards_enqueue_pre(ccore_cards);
	
	if(csec_priv)
	{
		do{
			ret =  sec_enqueue(csec_priv,  desc_addr, desc_phy_addr, (void *)callback,arg);
		
			if(ret==-EBUSY)
			{
				local_irq_save(flags);
				for(i=0;i<Ring_Num;i++)
				{
					if(atomic_read(&csec_priv->jr_t.jr[i].state)==DQ_NOPEND)
					{
						atomic_set(&csec_priv->jr_t.jr[i].state,DQ_PEND);
						schedule_work_unbound(&csec_priv->dequeue_task[i], i);
					}
				}
				local_irq_restore(flags);
				//add by lly for debug return ebusy error
				if(CDEV_INVL)
				{
					csec_debug2(KERN_ERR "sec_enqueue busy\n");
					set_current_state(TASK_INTERRUPTIBLE);
					schedule_timeout(CDEV_INVL/50);
					csec_debug2(KERN_INFO "ce0\n");
				}
			}
		}while(ret==-EBUSY);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(cards_enqueue_wait);

/*
*	debug api, not used 
*/
int cards_read_from_bar(void *cards, unsigned int bar_index, unsigned int offset, unsigned int size, unsigned int *pbuf)
{
	int ret = 0;
	struct ccore_cards_t *ccore_cards = NULL;
	struct csec_priv_t *csec_priv = NULL;

	ccore_cards = (struct ccore_cards_t *)cards;
	if(ccore_cards == NULL || pbuf == NULL)
	{			
		printk(KERN_INFO "cards_read_from_bar get no device\n");
		return -ENODEV;
	}
	csec_priv = cards_enqueue_pre(ccore_cards);
	if(csec_priv == NULL)
	{
		printk(KERN_INFO "cards_read_from_bar get no csec_priv\n");
		return -ENODEV;
	}
	
	ret = ccore_pci_read_from_bar(csec_priv, bar_index, offset, size, pbuf);

	return ret;
}
EXPORT_SYMBOL_GPL(cards_read_from_bar);

/*
*	debug api, not used
*/
int cards_dump_info(void *cards)
{
	int i;
	int ret = 0;
	struct ccore_cards_t *ccore_cards = NULL;
	struct csec_priv_t *csec_priv = NULL;

	ccore_cards = (struct ccore_cards_t *)cards;
	if(ccore_cards == NULL)
	{			
		printk(KERN_INFO "cards_dump_info get no device\n");
		return -ENODEV;
	}
	csec_priv = cards_enqueue_pre(ccore_cards);
	if(csec_priv == NULL)
	{
		printk(KERN_INFO "cards_dump_info get no csec_priv\n");
		return -ENODEV;
	}
	
	for(i=0;i<csec_priv->ring_total;i++)
	{
		printk("Job Ring ID %02d\n", i);
		dump_jr_info(csec_priv,&( (csec_priv->jr_g)[i] ));
	}
	
	return ret;	
}
EXPORT_SYMBOL_GPL(cards_dump_info);
//custom api for multi pci kernel crypto module
void *mcards_init(struct device **dev)
{
	int ret = 0;
	
	struct ccore_cards_t *ccore_cards = NULL;
	struct csec_priv_t *csec_priv = NULL;

	if(g_ccore_cards == NULL){
		csec_debug(KERN_INFO "cards_init: NULL!\n");
		return NULL;
	}
	ccore_cards = g_ccore_cards;
	csec_priv = cards_enqueue_pre(ccore_cards);
	ret = ccore_pci_csec_init(csec_priv);
	if(ret)
		return NULL;
		
	if(dev)
		*dev = (struct device *)csec_priv->dev;
	
	return (void *)(csec_priv);
}
EXPORT_SYMBOL_GPL(mcards_init);


int mcards_release(void *cards)
{
	int ret = 0;
	
	//struct ccore_cards_t *ccore_cards = NULL;
	//struct csec_priv_t *csec_priv = NULL;


	return ret;
}
EXPORT_SYMBOL_GPL(mcards_release);


int mcards_del_timer(void *cards)
{
	int ret = 0;
	struct csec_priv_t *csec_priv = NULL;
	int i;

	csec_priv = (struct csec_priv_t *)cards;
	if(csec_priv == NULL)
		return -ENODEV;

	for(i=0;i<Ring_Num;i++)
		cancel_work_sync(&(csec_priv->dequeue_task[i]) );

	del_timer(&csec_priv->timer);

	return ret;
}
EXPORT_SYMBOL_GPL(mcards_del_timer);


int mcards_transmit(void *cards, unsigned char* pbInData, int InLen, unsigned char* pbOutData, int *pOutLen)
{
	int ret = 0;	
	struct csec_priv_t *csec_priv = NULL;
	
	csec_priv = (struct csec_priv_t *)cards;
	if(csec_priv == NULL)
		return -ENODEV;

	ret = ccore_pci_transmit(csec_priv, pbInData,  InLen, pbOutData, pOutLen);

	return ret;
}
EXPORT_SYMBOL_GPL(mcards_transmit);

int mcards_get_capbility(void *cards, struct cards_driver_cap *pcap)
{
	struct csec_priv_t *csec_priv = NULL;

	csec_priv = (struct csec_priv_t *)cards;
	if(csec_priv == NULL)
		return -ENODEV;

	pcap->cmd_max_size = MAX_CMD_LEN;
	pcap->send_virt_buf = csec_priv->cmd_buf;
	pcap->recv_virt_buf = csec_priv->cmd_buf + MAX_CMD_LEN;

	return 0;
}
EXPORT_SYMBOL_GPL(mcards_get_capbility);


int mcards_enqueue_wait(void *cards,uint32_t *desc_addr,dma_addr_t desc_phy_addr,
	       void (*callback)(void *data,uint32_t *desc_addr,dma_addr_t desc_phy_addr,uint32_t status, void *arg),void *arg)
{
	int ret= -EBUSY;
	struct csec_priv_t *csec_priv = NULL;
	unsigned long flags;
	int i;
	
	csec_priv = (struct csec_priv_t *)cards;
	
	if(csec_priv)
	{
		do{
			ret =  sec_enqueue(csec_priv,  desc_addr, desc_phy_addr, (void *)callback,arg);
		
			if(ret==-EBUSY)
			{
				local_irq_save(flags);
				for(i=0;i<Ring_Num;i++)
				{
					if(atomic_read(&csec_priv->jr_t.jr[i].state)==DQ_NOPEND)
					{
						atomic_set(&csec_priv->jr_t.jr[i].state,DQ_PEND);
						schedule_work_unbound(&csec_priv->dequeue_task[i], i);
					}
				}
				local_irq_restore(flags);
				//add by lly for debug return ebusy error
				if(CDEV_INVL)
				{
					csec_debug2(KERN_ERR "sec_enqueue busy\n");
					set_current_state(TASK_INTERRUPTIBLE);
					schedule_timeout(CDEV_INVL/50);
					csec_debug2(KERN_INFO "ce0\n");
				}
			}
		}while(ret==-EBUSY);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(mcards_enqueue_wait);


//custom api for get cards information
int mcards_get_total_num(int *cards_num)
{
	if(g_ccore_cards == NULL){
		csec_debug(KERN_INFO "cards_init: NULL!\n");
		return -1;
	}

	if(cards_num == NULL){
		csec_debug(KERN_INFO "cards_num: NULL!\n");
		return -2;
	}

	*cards_num = g_ccore_cards->total_cards;

	return 0;
}
EXPORT_SYMBOL_GPL(mcards_get_total_num);


extern int ccore_alg_init(struct ccore_cards_t *ccore_cards);
extern int ccore_alg_remove(struct ccore_cards_t *ccore_cards);

static int __init ccp903_cards_init(void)
{
	struct ccore_cards_t *ccore_cards;
	struct pci_dev *card_dev=NULL;
	struct pci_dev *card_905_dev=NULL;
	struct pci_dev *card_903_dev=NULL;
	struct csec_priv_t *csec_priv=NULL;
	struct list_head *tmp;
	unsigned int crycard_dev = CRYCARD_DEV903T;
	int cnt=0,err=0;
	int find_loop = 0;


	csec_error("CCP903T: Start to initializing crypto card.\n");
	ccore_cards = kmalloc(sizeof(struct ccore_cards_t),GFP_KERNEL);
	if(!ccore_cards)
	{
		csec_error("ccp903_cards_init: mem alloc error\n");
		return -ENOMEM;
	}
	g_ccore_cards = ccore_cards;

	INIT_LIST_HEAD(&ccore_cards->card_list);
	INIT_LIST_HEAD(&ccore_cards->alg_list);
	ccore_cards->current_card=0;

	err = pci_csec_init();
	if(err) {
		goto err_no_dev;
	}else {
		csec_error("CCP903T: New crypto card pci device driver registered.\n");
	}

	csec_debug(KERN_INFO "ccp903_cards_init: s1!\n");

	spin_lock_init(&ccore_cards->cardlock);

	do{
		csec_debug(KERN_INFO "ccp903_cards_init: s2!\n");
		card_903_dev = pci_get_device(CRYCARD_VENDOR, CRYCARD_DEV903T, card_903_dev);
		if(card_903_dev == NULL) {
			card_905_dev = pci_get_device(CRYCARD_VENDOR, CRYCARD_DEV903H, card_905_dev);
			if(card_905_dev == NULL){
				break;
			}else{
				card_dev = card_905_dev;
			}
		}else{
			card_dev = card_903_dev;
		}
		/* *
		 * call the function pci_dev_put to decrement the usage count properly
		 * back to allow the kernel to clean up the device if it is removed.
		 */
		//pci_dev_put(card_dev);
		//card_dev_last = card_dev;

		csec_debug(KERN_INFO "ccp903_cards_init: s3!\n");
		csec_priv = pci_get_drvdata(card_dev);
		csec_priv -> ccore_cards = ccore_cards;
		list_add(&csec_priv->card_entry,&ccore_cards->card_list);
		csec_debug(KERN_INFO "ccp903_cards_init: s4!\n");
		csec_priv->card_idx=cnt;
		cnt++;
	}while(1);
	ccore_cards->total_cards = cnt;

	csec_debug(KERN_INFO "ccp903_cards_init: total_cards is 0x%x!\n",ccore_cards->total_cards);

	list_for_each(tmp,&ccore_cards->card_list)
	{
		if(tmp!=&ccore_cards->card_list)
			break;
		else
		{
			csec_error("CCP903T: Traverse CCP903T cards failed!\n");
			err = -ENODEV;
			goto err_no_dev;
		}
	}

	//ccore_alg_init(ccore_cards);
	csec_error(KERN_ERR "CCP903T: Crypto card driver initialized.\n");

	return 0;
err_no_dev:
	kfree(ccore_cards);
	return err;
}

static void __exit ccp903_cards_exit(void)
{
	//struct pci_dev *card_dev=NULL;
	struct ccore_cards_t *ccore_cards;
	struct csec_priv_t *csec_priv;

	csec_debug(KERN_INFO "ccp903_cards_exit: called!\n");
	
	//card_dev = pci_get_device(param_vendor,param_device,card_dev);
	//csec_priv = pci_get_drvdata(card_dev);

	//ccore_cards = csec_priv->ccore_cards;
	ccore_cards = get_ccore_cards();
	if(!ccore_cards){
		csec_debug(KERN_INFO "ccp903_cards_exit: no card!\n");
		return;
	}
	//ccore_pci_csec_release(csec_priv);
	//ccore_alg_remove(ccore_cards);

	list_for_each_entry(csec_priv,&ccore_cards->card_list,card_entry){
	ccore_pci_csec_release(csec_priv);
	//ccore_alg_remove(ccore_cards);
	}

	cards_halt_free(ccore_cards );

	pci_csec_exit();

	kfree(ccore_cards);

	csec_debug(KERN_INFO "ccp903_cards_exit: ended!\n");
}


module_init(ccp903_cards_init);
module_exit(ccp903_cards_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ccore support for base API");
MODULE_AUTHOR("zjjin@ccore.com");
MODULE_VERSION("V6.2.2");
