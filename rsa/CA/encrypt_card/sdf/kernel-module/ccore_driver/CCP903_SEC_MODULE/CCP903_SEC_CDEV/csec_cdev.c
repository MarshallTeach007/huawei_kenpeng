/***************************************************
 * csec_cdev.c
 *
 * Created on: Mar 20, 2017
 * Author: zjjin@ccore.com
 ***************************************************/

#include "../INCLUDE/compate.h"
#include "../INCLUDE/pci_csec.h"
#include "../INCLUDE/desc.h"
#include "../INCLUDE/desc_constr.h"
#include "../INCLUDE/sm2_job.h"
#include "../INCLUDE/rsa_job.h"
#include <linux/delay.h>

extern unsigned int get_icv_len(unsigned char alg);

extern struct ccore_cards_t *get_ccore_cards(void);

struct fpd_st //file private struct
{
	struct ccore_cards_t *ccore_cards;
	void* private_data;
};

static loff_t cdev_csec_llseek(struct file *filp, loff_t pos, int arg)
{

	csec_debug(KERN_INFO "cdev_csec_llseek is called\n");
	return 0;
	
}

static ssize_t cdev_csec_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{

	csec_debug(KERN_INFO "cdev_csec_read is called\n");
	return 0;
	
}

static ssize_t cdev_csec_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{

	csec_debug(KERN_INFO "cdev_csec_write is called\n");
	return 0;
	
}

static int cdev_csec_open(struct inode *inode, struct file *filp)
{
       struct ccore_cards_t *ccore_cards;
	struct fpd_st *fpd;
	csec_debug(KERN_INFO "cdev_csec_open is called\n");
	ccore_cards = container_of(inode->i_cdev,
					struct ccore_cards_t, cdev);
	fpd = kmalloc(sizeof(struct fpd_st),GFP_KERNEL);
	if(!fpd)
	{
		csec_error(KERN_ERR "cdev_csec_open: fpd mem err\n");
		return -ENOMEM;
	}
	fpd->ccore_cards = ccore_cards;
	filp->private_data = fpd;
	return 0;
	
}

static int cdev_csec_release(struct inode *inode, struct file *filp)
{
	struct fpd_st *fpd;
	csec_debug(KERN_INFO "cdev_csec_release is called\n");
	
	fpd = filp->private_data;
	kfree(fpd);
	csec_debug(KERN_INFO "cdev_csec_release is over\n");
	return 0;
	
}

void ioctl_desc_done(struct csec_priv_t *csec_priv,void *dma_virt,dma_addr_t desc,uint32_t status, void *arg)
{	
	struct result *op;
	//csec_debug(KERN_INFO "b\n");
	op = arg;
	op->rst = status;
	if(op->sg_virt)
	{
		dma_unmap_single(csec_priv->dev,op->sg_phy,SGMAX*16,DMA_TO_DEVICE);
		kfree(op->sg_virt);
	}
	complete(&(op->op_done));
}
EXPORT_SYMBOL_GPL(ioctl_desc_done);

const unsigned char key1_r2[512] = 
{
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x55,0x52,0x3C,0x7F,0xC4,0x52,0x3F,0x90,
	        0xEF,0xA0,0x0D,0xF3,0x77,0x4A,0x25,0x9F,0x2E,0x62,0xB4,0xC5,0xD9,0x9C,0xB5,0xAD,
	        0xB3,0x00,0xA0,0x28,0x5E,0x53,0x01,0x93,0x0E,0x0C,0x70,0xFB,0x68,0x76,0x93,0x9C,
	        0xE6,0x16,0xCE,0x62,0x4A,0x11,0xE0,0x08,0x6D,0x34,0x1E,0xBC,0xAC,0xA0,0xA1,0x05,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x55,0x52,0x3C,0x7F,0xC4,0x52,0x3F,0x90,
	        0xEF,0xA0,0x0D,0xF3,0x77,0x4A,0x25,0x9F,0x2E,0x62,0xB4,0xC5,0xD9,0x9C,0xB5,0xAD,
	        0xB3,0x00,0xA0,0x28,0x5E,0x53,0x01,0x93,0x0E,0x0C,0x70,0xFB,0x68,0x76,0x93,0x9C,
	        0xE6,0x16,0xCE,0x62,0x4A,0x11,0xE0,0x08,0x6D,0x34,0x1E,0xBC,0xAC,0xA0,0xA1,0x05,
	      		 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x55,0x52,0x3C,0x7F,0xC4,0x52,0x3F,0x90,
	        0xEF,0xA0,0x0D,0xF3,0x77,0x4A,0x25,0x9F,0x2E,0x62,0xB4,0xC5,0xD9,0x9C,0xB5,0xAD,
	        0xB3,0x00,0xA0,0x28,0x5E,0x53,0x01,0x93,0x0E,0x0C,0x70,0xFB,0x68,0x76,0x93,0x9C,
	        0xE6,0x16,0xCE,0x62,0x4A,0x11,0xE0,0x08,0x6D,0x34,0x1E,0xBC,0xAC,0xA0,0xA1,0x05,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x55,0x52,0x3C,0x7F,0xC4,0x52,0x3F,0x90,
	        0xEF,0xA0,0x0D,0xF3,0x77,0x4A,0x25,0x9F,0x2E,0x62,0xB4,0xC5,0xD9,0x9C,0xB5,0xAD,
	        0xB3,0x00,0xA0,0x28,0x5E,0x53,0x01,0x93,0x0E,0x0C,0x70,0xFB,0x68,0x76,0x93,0x9C,
	        0xE6,0x16,0xCE,0x62,0x4A,0x11,0xE0,0x08,0x6D,0x34,0x1E,0xBC,0xAC,0xA0,0xA1,0x05,
	       	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x55,0x52,0x3C,0x7F,0xC4,0x52,0x3F,0x90,
	        0xEF,0xA0,0x0D,0xF3,0x77,0x4A,0x25,0x9F,0x2E,0x62,0xB4,0xC5,0xD9,0x9C,0xB5,0xAD,
	        0xB3,0x00,0xA0,0x28,0x5E,0x53,0x01,0x93,0x0E,0x0C,0x70,0xFB,0x68,0x76,0x93,0x9C,
	        0xE6,0x16,0xCE,0x62,0x4A,0x11,0xE0,0x08,0x6D,0x34,0x1E,0xBC,0xAC,0xA0,0xA1,0x05,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x55,0x52,0x3C,0x7F,0xC4,0x52,0x3F,0x90,
	        0xEF,0xA0,0x0D,0xF3,0x77,0x4A,0x25,0x9F,0x2E,0x62,0xB4,0xC5,0xD9,0x9C,0xB5,0xAD,
	        0xB3,0x00,0xA0,0x28,0x5E,0x53,0x01,0x93,0x0E,0x0C,0x70,0xFB,0x68,0x76,0x93,0x9C,
	        0xE6,0x16,0xCE,0x62,0x4A,0x11,0xE0,0x08,0x6D,0x34,0x1E,0xBC,0xAC,0xA0,0xA1,0x05,
	       	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x55,0x52,0x3C,0x7F,0xC4,0x52,0x3F,0x90,
	        0xEF,0xA0,0x0D,0xF3,0x77,0x4A,0x25,0x9F,0x2E,0x62,0xB4,0xC5,0xD9,0x9C,0xB5,0xAD,
	        0xB3,0x00,0xA0,0x28,0x5E,0x53,0x01,0x93,0x0E,0x0C,0x70,0xFB,0x68,0x76,0x93,0x9C,
	        0xE6,0x16,0xCE,0x62,0x4A,0x11,0xE0,0x08,0x6D,0x34,0x1E,0xBC,0xAC,0xA0,0xA1,0x05,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x55,0x52,0x3C,0x7F,0xC4,0x52,0x3F,0x90,
	        0xEF,0xA0,0x0D,0xF3,0x77,0x4A,0x25,0x9F,0x2E,0x62,0xB4,0xC5,0xD9,0x9C,0xB5,0xAD,
	        0xB3,0x00,0xA0,0x28,0x5E,0x53,0x01,0x93,0x0E,0x0C,0x70,0xFB,0x68,0x76,0x93,0x9C,
	        0xE6,0x16,0xCE,0x62,0x4A,0x11,0xE0,0x08,0x6D,0x34,0x1E,0xBC,0xAC,0xA0,0xA1,0x05,
};

extern void inline_cnstr_jobdesc_cipher(void *desc,void *capi,dma_addr_t mem_phy_addr,dma_addr_t extern_key_addr);
//extern void inline_cnstr_jobdesc_cipher_wait(void *desc,void *capi,dma_addr_t mem_phy_addr);
extern int inline_cnstr_jobdesc_cipher_sg(struct csec_priv_t *csec_priv,uint32_t *desc,struct cipher_api *capi,dma_addr_t mem_addr,void **sg_virt,dma_addr_t *sg_phy,dma_addr_t extern_key_addr);
//extern void inline_cnstr_jobdesc_cipher_ccm(void *desc,void *capi,dma_addr_t mem_phy_addr);
extern void inline_cnstr_jobdesc_hash(void *desc,void *capi,dma_addr_t mem_phy_addr,dma_addr_t extern_key_addr);
//extern int inline_cnstr_jobdesc_hash_sg(struct csec_priv_t *csec_priv,void *desc,void *capi,dma_addr_t mem_phy_addr,void **sg_virt);
extern void inline_cnstr_jobdesc_sm2_genkey(unsigned int *desc, struct sm2_genkey_private_dma *para);
extern void inline_cnstr_jobdesc_sm2_encrypt(unsigned int *desc, struct sm2_enc_private_dma *para);
extern void inline_cnstr_jobdesc_sm2_decrypt(unsigned int *desc, struct sm2_dec_private_dma *para);
extern void inline_cnstr_jobdesc_sm2_signature(unsigned int *desc, struct sm2_sig_private_dma *para);
extern void inline_cnstr_jobdesc_sm2_verify(unsigned int *desc, struct sm2_ver_private_dma *para);
extern void inline_cnstr_jobdesc_sm2_exchange(unsigned int *desc, struct sm2_exc_private_dma *para);
extern void inline_cnstr_jobdesc_snoop(uint32_t *desc,struct cipher_api *capi,dma_addr_t mem_addr);
extern void inline_cnstr_jobdesc_pkha(uint32_t *desc,struct pkha_api *papi,dma_addr_t mem_addr);
extern void inline_cnstr_jobdesc_rscp_hash(uint32_t *desc,struct rscp_api *rapi,dma_addr_t mem_addr);
extern void  inline_cnstr_jobdesc_rscp_cipher(uint32_t *desc,struct rscp_api *rapi,dma_addr_t mem_addr);
extern void inline_cnstr_jobdesc_pkha_end_big(uint32_t *desc,struct pkha_api *papi,dma_addr_t mem_addr);
extern void inline_cnstr_jobdesc_rsa_genkey(uint32_t *desc, struct rsa_api *rapi,dma_addr_t mem_addr, struct rsa_api_ext *rapi_ext);
extern void inline_cnstr_jobdesc_rsa_priv_crt(uint32_t *desc,struct pkha_api *papi,dma_addr_t mem_addr);
extern void inline_cnstr_jobdesc_rsa_genkey_simplified(unsigned int *desc, struct rsa_genkey_dma *para);
extern void inline_cnstr_jobdesc_rsa_pub_priv_simplified(unsigned int *desc, struct rsa_pub_priv_dma *para);
//extern void inline_cnstr_jobdesc_rsa_priv_crt(unsigned int *desc, struct rsa_priv_crt_dma *para);
extern void inline_cnstr_jobdesc_rsa_priv_crt_simplified(uint32_t *desc,struct pkha_api *papi,dma_addr_t mem_addr);
extern void inline_cnstr_jobdesc_rng(uint32_t *desc, uint32_t flen, dma_addr_t mem_addr);

extern dma_addr_t change_addr_for_sec(dma_addr_t addr);

extern unsigned int hash_size(unsigned char alg);
extern int cards_enqueue(struct csec_priv_t *csec_priv,uint32_t *desc_addr,dma_addr_t desc_phy_addr,
	       void (*callback)(struct csec_priv_t *csec_priv_s,void *desc_addr_s,dma_addr_t desc_phy_addr_s,uint32_t status_s, void *arg_s),void *arg);

extern struct csec_priv_t* cards_enqueue_pre(struct ccore_cards_t *ccore_cards);

extern int cards_dequeue(void *data);

extern int _inline_cnstr_jobdesc_cipher_sg(struct csec_priv_t *csec_priv,uint32_t *desc,struct cipher_api *capi,dma_addr_t mem_addr,void **sg_virt,dma_addr_t *sg_phy,dma_addr_t extern_key_addr);
extern int host_to_cards_write(struct csec_priv_t *csec_priv,
				unsigned char* pbInData, int InLen, 
				unsigned char* pbOutData, int *pOutLen);
extern int host_from_cards_read(struct csec_priv_t *csec_priv,
				unsigned char* pbInData, int InLen, 
				unsigned char* pbOutData, int *pOutLen);

int  cdev_csec_do(struct csec_priv_t *csec_priv,struct crypto_api *cry_api,dma_addr_t capi_addr,unsigned size,unsigned char cmd_nr,struct result *done_op)
{
	dma_addr_t desc_phy_addr;
	dma_addr_t sg_phy_addr;
	uint32_t *desc;
	int status;
	struct sm2_api_ext *smapi_ext = NULL;
	struct rsa_api_ext *rsaapi_ext = NULL;
	int ret;

	void *sg_virt;
	dma_addr_t *extern_key_addr;
	
	//sec_dump(cry_api,size);
	
//	desc = kmalloc(MAX_CSEC_DESCSIZE,GFP_KERNEL|SYS_DMA);
	desc = dma_alloc_coherent(csec_priv->dev, MAX_CSEC_DESCSIZE*4, &desc_phy_addr, GFP_KERNEL | GFP_DMA);
	if(!desc )
	{
		csec_error(KERN_ERR "cdev_csec_do: desc kzalloc error\n");
		return -ENOMEM;
	}

	//csec_debug(KERN_INFO "desc is %llx\n",desc);
	if(cmd_nr == ACLASS_CIPHER)
	{		
		//if(cry_api->capi.data_len + 128 <SIZE4KI)
		if(1)
		{
			if(cry_api->capi.key_len & 0x80000000)
			{
				extern_key_addr = (dma_addr_t *)((char *)cry_api+sizeof(struct cipher_api));
				inline_cnstr_jobdesc_cipher(desc,&(cry_api->capi),capi_addr,*extern_key_addr);		
				//printk(KERN_ERR "extern_key_addr is %llx,*extern_key_addr is %llx\n",extern_key_addr,*extern_key_addr);		
			}else
			{

				inline_cnstr_jobdesc_cipher(desc,&(cry_api->capi),capi_addr,0);
			}

		}
		else
		{
			if(cry_api->capi.key_len & 0x80000000)
			{
				extern_key_addr = (dma_addr_t *)((char *)cry_api+sizeof(struct cipher_api));
				//printk(KERN_ERR "extern_key_addr is %llx,*extern_key_addr is %llx\n",extern_key_addr,*extern_key_addr);		
				ret = _inline_cnstr_jobdesc_cipher_sg(csec_priv,desc,&(cry_api->capi),capi_addr,&sg_virt,&sg_phy_addr,*extern_key_addr);
				if(ret)
				{
					return ret;
				}
			}
			else
			{
				ret = _inline_cnstr_jobdesc_cipher_sg(csec_priv,desc,&(cry_api->capi),capi_addr,&sg_virt,&sg_phy_addr,0);
				if(ret)
				{
					return ret;
				}
			}
			done_op->sg_virt =  sg_virt;
			done_op->sg_phy = sg_phy_addr;
		}
		//inline_cnstr_jobdesc_cipher_wait(desc,&(cry_api->capi),capi_addr);
	}
	else if(cmd_nr == ACLASS_HASH)
	{
		if(cry_api->capi.key_len & 0x80000000)
		{
			extern_key_addr = (dma_addr_t *)((char *)cry_api+sizeof(struct cipher_api));
			//printk(KERN_ERR "extern_key_addr is %llx,*extern_key_addr is %llx\n",extern_key_addr,*extern_key_addr);		
			inline_cnstr_jobdesc_hash(desc,&(cry_api->capi),capi_addr,*extern_key_addr);		
		}else
		{
			inline_cnstr_jobdesc_hash(desc,&(cry_api->capi),capi_addr,0);
		}

	}
	/*	
	else if(cmd_nr == ACLASS_CIPHER_CCM)
	{
		inline_cnstr_jobdesc_cipher_ccm(desc,&(cry_api->capi),capi_addr);
	}
	*/
	else if(cmd_nr == ACLASS_SNOOP)
	{
		inline_cnstr_jobdesc_snoop(desc,&(cry_api->capi),capi_addr);
	}
	
	else if(cmd_nr == ACLASS_PKHA)
	{
		inline_cnstr_jobdesc_pkha(desc,&(cry_api->papi),capi_addr);
	}else if(cmd_nr == ACLASS_RSCP_CIPHER)
	{
		inline_cnstr_jobdesc_rscp_cipher(desc,&(cry_api->rapi),capi_addr);
	}else if(cmd_nr == ACLASS_RSCP_HASH)
	{
		inline_cnstr_jobdesc_rscp_hash(desc,&(cry_api->rapi),capi_addr);
	}else if(cmd_nr == ACLASS_SM2_ENCRYPT)
	{
		struct sm2_enc_private_dma para;
		*((unsigned char *)cry_api+sizeof(struct sm2_api)+8*cry_api->smapi.plen+ cry_api->smapi.klen) = 0x04;
		smapi_ext = (struct sm2_api_ext *)kzalloc(sizeof(struct sm2_api_ext), GFP_KERNEL|SYS_DMA);
		if(!smapi_ext )
		{
			csec_error(KERN_INFO "smapi_ext kzalloc error\n");
			return -EINVAL;
		}
		smapi_ext->hashin = kmalloc(cry_api->smapi.plen*2+4, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->hashin )
		{
			csec_error(KERN_INFO "smapi_ext->hashin kmalloc error\n");
			return -EINVAL;
		}
		smapi_ext->hashout = kmalloc((cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen*cry_api->smapi.nlen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->hashout )
		{
			csec_error(KERN_INFO "smapi_ext->hashout kmalloc error\n");
			return -EINVAL;
		}
/*
		smapi_ext->desc_ext = kmalloc(MAX_CSEC_DESCSIZE,GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->desc_ext )
		{
			csec_error(KERN_INFO "smapi_ext->desc_ext kmalloc error\n");
			return -EINVAL;
		}
*/
		smapi_ext->k = kzalloc(cry_api->smapi.plen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->k )
		{
			csec_error(KERN_INFO "smapi_ext->k kzalloc error\n");
			return -EINVAL;
		}
		*(unsigned int *)smapi_ext->k = (cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen;

		smapi_ext->hashin_phys = dma_map_single(csec_priv->dev,smapi_ext->hashin,cry_api->smapi.plen*2+4, DMA_BIDIRECTIONAL);
		smapi_ext->hashout_phys = dma_map_single(csec_priv->dev,smapi_ext->hashout,(cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen*cry_api->smapi.nlen, DMA_BIDIRECTIONAL);
		smapi_ext->k_phys = dma_map_single(csec_priv->dev,smapi_ext->k,cry_api->smapi.plen, DMA_BIDIRECTIONAL);

#if 0
		inline_cnstr_jobdesc_sm2_encrypt(desc, &(cry_api->smapi), capi_addr, smapi_ext);
		smapi_ext->desc_ext_phys = dma_map_single(csec_priv->dev,smapi_ext->desc_ext,MAX_CSEC_DESCSIZE, DMA_TO_DEVICE);
		append_ptr(desc, change_addr_for_sec (smapi_ext->desc_ext_phys));
#else
		para.ecc_dma.p = capi_addr+sizeof(struct sm2_api);
		para.ecc_dma.a = para.ecc_dma.p+cry_api->smapi.plen;
		para.ecc_dma.b= para.ecc_dma.a+cry_api->smapi.plen;
		para.ecc_dma.gx = para.ecc_dma.b+cry_api->smapi.plen;
		para.ecc_dma.gy = para.ecc_dma.gx+cry_api->smapi.plen;
		para.ecc_dma.n = para.ecc_dma.gy+cry_api->smapi.plen;
		para.pubkey_dma.x= para.ecc_dma.n+cry_api->smapi.plen;
		para.pubkey_dma.y = para.pubkey_dma.x+cry_api->smapi.plen;
		para.msg_dma= para.pubkey_dma.y+cry_api->smapi.plen;
		para.ciphertext_dma.c1= para.msg_dma+cry_api->smapi.klen;
		para.ciphertext_dma.c2= para.ciphertext_dma.c1+cry_api->smapi.plen*2+1;
		para.ciphertext_dma.c3= para.ciphertext_dma.c2+cry_api->smapi.klen;
		para.hashin_dma = smapi_ext->hashin_phys;
		//para.hashout_dma = smapi_ext->hashout_phys;
		para.ct_dma = smapi_ext->k_phys;
		para.plen = cry_api->smapi.plen;
		para.nlen = cry_api->smapi.nlen;
		para.klen = cry_api->smapi.klen;
		para.ct = (cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen;
		para.ecc_mode = (cry_api->smapi.field == 0) ? FP : F2M;
		para.endian_mode = LITTLE;
		para.rng_mode = HARDWARE;
		inline_cnstr_jobdesc_sm2_encrypt(desc, &para);
#endif
	}else if(cmd_nr == ACLASS_SM2_ENCRYPT_SEED)
	{
		struct sm2_enc_private_dma para;
		*((unsigned char *)cry_api+sizeof(struct sm2_api)+9*cry_api->smapi.plen+ cry_api->smapi.klen) = 0x04;
		smapi_ext = (struct sm2_api_ext *)kzalloc(sizeof(struct sm2_api_ext), GFP_KERNEL|SYS_DMA);
		if(!smapi_ext )
		{
			csec_error(KERN_INFO "smapi_ext kzalloc error\n");
			return -EINVAL;
		}
		smapi_ext->hashin = kmalloc(cry_api->smapi.plen*2+4, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->hashin )
		{
			csec_error(KERN_INFO "smapi_ext->hashin kmalloc error\n");
			return -EINVAL;
		}
		smapi_ext->hashout = kmalloc((cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen*cry_api->smapi.nlen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->hashout )
		{
			csec_error(KERN_INFO "smapi_ext->hashout kmalloc error\n");
			return -EINVAL;
		}
/*
		smapi_ext->desc_ext = kmalloc(MAX_CSEC_DESCSIZE,GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->desc_ext )
		{
			csec_error(KERN_INFO "smapi_ext->desc_ext kmalloc error\n");
			return -EINVAL;
		}
*/
		smapi_ext->k = kzalloc(cry_api->smapi.plen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->k )
		{
			csec_error(KERN_INFO "smapi_ext->k kzalloc error\n");
			return -EINVAL;
		}
		*(unsigned int *)smapi_ext->k = (cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen;

		smapi_ext->hashin_phys = dma_map_single(csec_priv->dev,smapi_ext->hashin,cry_api->smapi.plen*2+4, DMA_BIDIRECTIONAL);
		smapi_ext->hashout_phys = dma_map_single(csec_priv->dev,smapi_ext->hashout,(cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen*cry_api->smapi.nlen, DMA_BIDIRECTIONAL);
		smapi_ext->k_phys = dma_map_single(csec_priv->dev,smapi_ext->k,cry_api->smapi.plen, DMA_BIDIRECTIONAL);
#if 0
		inline_cnstr_jobdesc_sm2_encrypt_seed(desc, &(cry_api->smapi), capi_addr, smapi_ext);
		smapi_ext->desc_ext_phys = dma_map_single(csec_priv->dev,smapi_ext->desc_ext,MAX_CSEC_DESCSIZE, DMA_TO_DEVICE);
		append_ptr(desc, change_addr_for_sec (smapi_ext->desc_ext_phys));
#else
		para.ecc_dma.p = capi_addr+sizeof(struct sm2_api);
		para.ecc_dma.a = para.ecc_dma.p+cry_api->smapi.plen;
		para.ecc_dma.b= para.ecc_dma.a+cry_api->smapi.plen;
		para.ecc_dma.gx = para.ecc_dma.b+cry_api->smapi.plen;
		para.ecc_dma.gy = para.ecc_dma.gx+cry_api->smapi.plen;
		para.ecc_dma.n = para.ecc_dma.gy+cry_api->smapi.plen;
		para.pubkey_dma.x= para.ecc_dma.n+cry_api->smapi.plen;
		para.pubkey_dma.y = para.pubkey_dma.x+cry_api->smapi.plen;
		para.msg_dma= para.pubkey_dma.y+cry_api->smapi.plen;
		para.k_dma = para.msg_dma+cry_api->smapi.klen;
		para.ciphertext_dma.c1= para.k_dma+cry_api->smapi.plen;
		para.ciphertext_dma.c2= para.ciphertext_dma.c1+cry_api->smapi.plen*2+1;
		para.ciphertext_dma.c3= para.ciphertext_dma.c2+cry_api->smapi.klen;
		para.hashin_dma = smapi_ext->hashin_phys;
		//para.hashout_dma = smapi_ext->hashout_phys;
		para.ct_dma = smapi_ext->k_phys;
		para.plen = cry_api->smapi.plen;
		para.nlen = cry_api->smapi.nlen;
		para.klen = cry_api->smapi.klen;
		para.ct = (cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen;
		para.ecc_mode = (cry_api->smapi.field == 0) ? FP : F2M;
		para.endian_mode = LITTLE;
		para.rng_mode = CONSTANT;
		inline_cnstr_jobdesc_sm2_encrypt(desc, &para);
#endif
	}else if(cmd_nr == ACLASS_SM2_DECRYPT)
	{
		struct sm2_dec_private_dma para;
		smapi_ext = (struct sm2_api_ext *)kzalloc(sizeof(struct sm2_api_ext), GFP_KERNEL|SYS_DMA);
		if(!smapi_ext )
		{
			csec_error(KERN_INFO "smapi_ext kzalloc error\n");
			return -EINVAL;
		}
		smapi_ext->hashin = kmalloc(cry_api->smapi.plen*2+4, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->hashin )
		{
			csec_error(KERN_INFO "smapi_ext->hashin kmalloc error\n");
			return -EINVAL;
		}
		smapi_ext->hashout = kmalloc((cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen*cry_api->smapi.nlen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->hashout )
		{
			csec_error(KERN_INFO "smapi_ext->hashout kmalloc error\n");
			return -EINVAL;
		}
/*
		smapi_ext->desc_ext = kmalloc(MAX_CSEC_DESCSIZE,GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->desc_ext )
		{
			csec_error(KERN_INFO "smapi_ext->desc_ext kmalloc error\n");
			return -EINVAL;
		}
*/
		smapi_ext->k = kzalloc(cry_api->smapi.plen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->k )
		{
			csec_error(KERN_INFO "smapi_ext->k kzalloc error\n");
			return -EINVAL;
		}
		*(unsigned int *)smapi_ext->k = (cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen;
		
		smapi_ext->hashin_phys = dma_map_single(csec_priv->dev,smapi_ext->hashin,cry_api->smapi.plen*2+4, DMA_BIDIRECTIONAL);
		smapi_ext->hashout_phys = dma_map_single(csec_priv->dev,smapi_ext->hashout,(cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen*cry_api->smapi.nlen, DMA_BIDIRECTIONAL);
		smapi_ext->k_phys = dma_map_single(csec_priv->dev,smapi_ext->k,cry_api->smapi.plen, DMA_BIDIRECTIONAL);
#if 0
		inline_cnstr_jobdesc_sm2_decrypt(desc, &(cry_api->smapi), capi_addr, smapi_ext);
		smapi_ext->desc_ext_phys = dma_map_single(csec_priv->dev,smapi_ext->desc_ext,MAX_CSEC_DESCSIZE, DMA_TO_DEVICE);
		append_ptr(desc, change_addr_for_sec (smapi_ext->desc_ext_phys));
#else
		para.ecc_dma.p = capi_addr+sizeof(struct sm2_api);
		para.ecc_dma.a = para.ecc_dma.p+cry_api->smapi.plen;
		para.ecc_dma.b= para.ecc_dma.a+cry_api->smapi.plen;
		para.ecc_dma.gx = para.ecc_dma.b+cry_api->smapi.plen;
		para.ecc_dma.gy = para.ecc_dma.gx+cry_api->smapi.plen;
		para.ecc_dma.n = para.ecc_dma.gy+cry_api->smapi.plen;
		para.prikey_dma= para.ecc_dma.n+cry_api->smapi.plen;
		para.ciphertext_dma.c1= para.prikey_dma+cry_api->smapi.plen;
		para.ciphertext_dma.c2= para.ciphertext_dma.c1+cry_api->smapi.plen*2+1;
		para.ciphertext_dma.c3= para.ciphertext_dma.c2+cry_api->smapi.klen;
		para.msg_dma = para.ciphertext_dma.c3+cry_api->smapi.nlen;
		para.hashin_dma = smapi_ext->hashin_phys;
		//para.hashout_dma = smapi_ext->hashout_phys;
		para.ct_dma = smapi_ext->k_phys;
		para.plen = cry_api->smapi.plen;
		para.nlen = cry_api->smapi.nlen;
		para.klen = cry_api->smapi.klen;
		para.ct = (cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen;
		para.ecc_mode = (cry_api->smapi.field == 0) ? FP : F2M;
		para.endian_mode = LITTLE;	
		inline_cnstr_jobdesc_sm2_decrypt(desc, &para);
#endif
	}else if(cmd_nr == ACLASS_SM2_SIGNATURE)
	{
		struct sm2_sig_private_dma para;
		smapi_ext = (struct sm2_api_ext *)kzalloc(sizeof(struct sm2_api_ext), GFP_KERNEL|SYS_DMA);
		if(!smapi_ext )
		{
			csec_error(KERN_INFO "smapi_ext kzalloc error\n");
			return -EINVAL;
		}
		smapi_ext->zain = kmalloc(2+cry_api->smapi.entla+cry_api->smapi.plen*6, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->zain )
		{
			csec_error(KERN_INFO "smapi_ext->zain kmalloc error\n");
			return -EINVAL;
		}
		smapi_ext->zaout = kmalloc(cry_api->smapi.nlen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->zaout )
		{
			csec_error(KERN_INFO "smapi_ext->zaout kmalloc error\n");
			return -EINVAL;
		}
/*
		smapi_ext->desc_ext = kmalloc(MAX_CSEC_DESCSIZE,GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->desc_ext )
		{
			csec_error(KERN_INFO "smapi_ext->desc_ext kmalloc error\n");
			return -EINVAL;
		}
*/
		smapi_ext->k = kzalloc(cry_api->smapi.plen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->k )
		{
			csec_error(KERN_INFO "smapi_ext->k kzalloc error\n");
			return -EINVAL;
		}
		smapi_ext->one = kzalloc(cry_api->smapi.plen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->one )
		{
			csec_error(KERN_INFO "smapi_ext->one kzalloc error\n");
			return -EINVAL;
		}
		((unsigned char *)smapi_ext->zain)[0] = ((cry_api->smapi.entla*8)&0xff00)>>8;
		((unsigned char *)smapi_ext->zain)[1] = (cry_api->smapi.entla*8)&0xff;
		memcpy((unsigned char *)smapi_ext->zain+2, (unsigned char *)cry_api+sizeof(struct sm2_api)+9*cry_api->smapi.plen+cry_api->smapi.klen, cry_api->smapi.entla);
		memcpy((unsigned char *)smapi_ext->zain+2+cry_api->smapi.entla, (unsigned char *)cry_api+sizeof(struct sm2_api)+cry_api->smapi.plen, 4*cry_api->smapi.plen);
		memcpy((unsigned char *)smapi_ext->zain+2+cry_api->smapi.entla+4*cry_api->smapi.plen, (unsigned char *)cry_api+sizeof(struct sm2_api)+6*cry_api->smapi.plen, 2*cry_api->smapi.plen);
		((unsigned char *)smapi_ext->one)[0] = 0x1;

		smapi_ext->zain_phys = dma_map_single(csec_priv->dev,smapi_ext->zain,2+cry_api->smapi.entla+cry_api->smapi.plen*6, DMA_TO_DEVICE);
		smapi_ext->zaout_phys = dma_map_single(csec_priv->dev,smapi_ext->zaout,cry_api->smapi.nlen, DMA_BIDIRECTIONAL);
		smapi_ext->k_phys = dma_map_single(csec_priv->dev,smapi_ext->k,cry_api->smapi.plen, DMA_BIDIRECTIONAL);
		smapi_ext->one_phys = dma_map_single(csec_priv->dev,smapi_ext->one,cry_api->smapi.plen, DMA_TO_DEVICE);

#if 0
		inline_cnstr_jobdesc_sm2_signature(desc, &(cry_api->smapi), capi_addr, smapi_ext);
		smapi_ext->desc_ext_phys = dma_map_single(csec_priv->dev,smapi_ext->desc_ext,MAX_CSEC_DESCSIZE, DMA_TO_DEVICE);
		append_ptr(desc, change_addr_for_sec (smapi_ext->desc_ext_phys));
#else
		para.ecc_dma.p = capi_addr+sizeof(struct sm2_api);
		para.ecc_dma.a = para.ecc_dma.p+cry_api->smapi.plen;
		para.ecc_dma.b= para.ecc_dma.a+cry_api->smapi.plen;
		para.ecc_dma.gx = para.ecc_dma.b+cry_api->smapi.plen;
		para.ecc_dma.gy = para.ecc_dma.gx+cry_api->smapi.plen;
		para.ecc_dma.n = para.ecc_dma.gy+cry_api->smapi.plen;
		para.prikey_dma= para.ecc_dma.n+3*cry_api->smapi.plen;
		para.msg_dma = para.prikey_dma+cry_api->smapi.plen;
		para.sig_dma.r = para.msg_dma+cry_api->smapi.klen+cry_api->smapi.entla;
		para.sig_dma.s = para.sig_dma.r+cry_api->smapi.plen;
		para.z_dma = smapi_ext->zain_phys;
		para.one_dma = smapi_ext->one_phys;
		para.plen = cry_api->smapi.plen;
		para.nlen = cry_api->smapi.nlen;
		para.klen = cry_api->smapi.klen;
		para.zlen = 2+cry_api->smapi.entla+6*cry_api->smapi.plen;
		para.ecc_mode = (cry_api->smapi.field == 0) ? FP : F2M;
		para.sig_mode = WITHID;
		para.rng_mode = HARDWARE;
		inline_cnstr_jobdesc_sm2_signature(desc, &para);		
#endif
	}
	else if(cmd_nr == ACLASS_SM2_VERIFY)
	{
		struct sm2_ver_private_dma para;
		smapi_ext = (struct sm2_api_ext *)kzalloc(sizeof(struct sm2_api_ext), GFP_KERNEL|SYS_DMA);
		if(!smapi_ext )
		{
			csec_error(KERN_INFO "smapi_ext kzalloc error\n");
			return -EINVAL;
		}
		smapi_ext->zain = kmalloc(2+cry_api->smapi.entla+cry_api->smapi.plen*6, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->zain )
		{
			csec_error(KERN_INFO "smapi_ext->zain kmalloc error\n");
			return -EINVAL;
		}
		smapi_ext->zaout = kmalloc(cry_api->smapi.nlen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->zaout )
		{
			csec_error(KERN_INFO "smapi_ext->zaout kmalloc error\n");
			return -EINVAL;
		}
/*
		smapi_ext->desc_ext = kmalloc(MAX_CSEC_DESCSIZE,GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->desc_ext )
		{
			csec_error(KERN_INFO "smapi_ext->desc_ext kmalloc error\n");
			return -EINVAL;
		}
*/
		smapi_ext->one = kzalloc(cry_api->smapi.plen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->one )
		{
			csec_error(KERN_INFO "smapi_ext->one kzalloc error\n");
			return -EINVAL;
		}
		((unsigned char *)smapi_ext->zain)[0] = ((cry_api->smapi.entla*8)&0xff00)>>8;
		((unsigned char *)smapi_ext->zain)[1] = (cry_api->smapi.entla*8)&0xff;
		memcpy((unsigned char *)smapi_ext->zain+2, (unsigned char *)cry_api+sizeof(struct sm2_api)+8*cry_api->smapi.plen+cry_api->smapi.klen, cry_api->smapi.entla);
		memcpy((unsigned char *)smapi_ext->zain+2+cry_api->smapi.entla, (unsigned char *)cry_api+sizeof(struct sm2_api)+cry_api->smapi.plen, 4*cry_api->smapi.plen);
		memcpy((unsigned char *)smapi_ext->zain+2+cry_api->smapi.entla+4*cry_api->smapi.plen, (unsigned char *)cry_api+sizeof(struct sm2_api)+6*cry_api->smapi.plen, 2*cry_api->smapi.plen);
		((unsigned char *)smapi_ext->one)[0] = 0x1;

		smapi_ext->zain_phys = dma_map_single(csec_priv->dev,smapi_ext->zain,2+cry_api->smapi.entla+cry_api->smapi.plen*6, DMA_TO_DEVICE);
		smapi_ext->zaout_phys = dma_map_single(csec_priv->dev,smapi_ext->zaout,cry_api->smapi.nlen, DMA_BIDIRECTIONAL);
		smapi_ext->one_phys = dma_map_single(csec_priv->dev,smapi_ext->one,cry_api->smapi.plen, DMA_TO_DEVICE);

#if 0
		inline_cnstr_jobdesc_sm2_verify(desc, &(cry_api->smapi), capi_addr, smapi_ext);
		smapi_ext->desc_ext_phys = dma_map_single(csec_priv->dev,smapi_ext->desc_ext,MAX_CSEC_DESCSIZE, DMA_TO_DEVICE);
		append_ptr(desc, change_addr_for_sec (smapi_ext->desc_ext_phys));
#else
		para.ecc_dma.p = capi_addr+sizeof(struct sm2_api);
		para.ecc_dma.a = para.ecc_dma.p+cry_api->smapi.plen;
		para.ecc_dma.b= para.ecc_dma.a+cry_api->smapi.plen;
		para.ecc_dma.gx = para.ecc_dma.b+cry_api->smapi.plen;
		para.ecc_dma.gy = para.ecc_dma.gx+cry_api->smapi.plen;
		para.ecc_dma.n = para.ecc_dma.gy+cry_api->smapi.plen;
		para.pubkey_dma.x= para.ecc_dma.n+cry_api->smapi.plen;
		para.pubkey_dma.y = para.pubkey_dma.x+cry_api->smapi.plen;
		para.msg_dma = para.pubkey_dma.y+cry_api->smapi.plen;
		para.sig_dma.r = para.msg_dma+cry_api->smapi.klen+cry_api->smapi.entla;
		para.sig_dma.s = para.sig_dma.r+cry_api->smapi.plen;
		para.z_dma = smapi_ext->zain_phys;
		para.one_dma = smapi_ext->one_phys;
		para.plen = cry_api->smapi.plen;
		para.nlen = cry_api->smapi.nlen;
		para.klen = cry_api->smapi.klen;
		para.zlen = 2+cry_api->smapi.entla+6*cry_api->smapi.plen;
		para.ecc_mode = (cry_api->smapi.field == 0) ? FP : F2M;
		para.sig_mode = WITHID;
		inline_cnstr_jobdesc_sm2_verify(desc, &para);
#endif
	}else if(cmd_nr == ACLASS_SM2_KEY_AGREEMENTA || cmd_nr == ACLASS_SM2_KEY_AGREEMENTB)
	{
		struct sm2_exc_private_dma para;
		smapi_ext = (struct sm2_api_ext *)kzalloc(sizeof(struct sm2_api_ext), GFP_KERNEL|SYS_DMA);
		if(!smapi_ext )
		{
			csec_error(KERN_INFO "smapi_ext kzalloc error\n");
			return -EINVAL;
		}
		smapi_ext->zain = kmalloc(4+cry_api->smapi.entla+cry_api->smapi.entlb+cry_api->smapi.plen*12, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->zain )
		{
			csec_error(KERN_INFO "smapi_ext->zain kmalloc error\n");
			return -EINVAL;
		}
		smapi_ext->zaout = kmalloc(cry_api->smapi.nlen*2, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->zaout )
		{
			csec_error(KERN_INFO "smapi_ext->zaout kmalloc error\n");
			return -EINVAL;
		}
		smapi_ext->hashin = kmalloc(4+cry_api->smapi.plen*2, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->hashin )
		{
			csec_error(KERN_INFO "smapi_ext->hashin kmalloc error\n");
			return -EINVAL;
		}
		smapi_ext->hashout = kmalloc(cry_api->smapi.nlen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->hashout )
		{
			csec_error(KERN_INFO "smapi_ext->hashout kmalloc error\n");
			return -EINVAL;
		}
		smapi_ext->k = kzalloc(cry_api->smapi.plen*2, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->k )
		{
			csec_error(KERN_INFO "smapi_ext->k kmalloc error\n");
			return -EINVAL;
		}
/*
		smapi_ext->desc_ext = kmalloc(MAX_CSEC_DESCSIZE,GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->desc_ext )
		{
			csec_error(KERN_INFO "smapi_ext->desc_ext kmalloc error\n");
			return -EINVAL;
		}
*/
		smapi_ext->one = kmalloc(2, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->one )
		{
			csec_error(KERN_INFO "smapi_ext->one kzalloc error\n");
			return -EINVAL;
		}
		((unsigned char *)smapi_ext->zain)[0] = ((cry_api->smapi.entla*8)&0xff00)>>8;
		((unsigned char *)smapi_ext->zain)[1] = (cry_api->smapi.entla*8)&0xff;
		((unsigned char *)smapi_ext->zain)[2+cry_api->smapi.entla+cry_api->smapi.plen*6] = ((cry_api->smapi.entlb*8)&0xff00)>>8;
		((unsigned char *)smapi_ext->zain)[3+cry_api->smapi.entla+cry_api->smapi.plen*6] = (cry_api->smapi.entlb*8)&0xff;
		if(cmd_nr == ACLASS_SM2_KEY_AGREEMENTA)
		{
			memcpy((unsigned char *)smapi_ext->zain+2, (unsigned char *)cry_api+sizeof(struct sm2_api)+10*cry_api->smapi.plen, cry_api->smapi.entla);
			memcpy((unsigned char *)smapi_ext->zain+2+cry_api->smapi.entla+4*cry_api->smapi.plen, (unsigned char *)cry_api+sizeof(struct sm2_api)+7*cry_api->smapi.plen, 2*cry_api->smapi.plen);
			memcpy((unsigned char *)smapi_ext->zain+4+cry_api->smapi.entla+cry_api->smapi.plen*6, (unsigned char *)cry_api+sizeof(struct sm2_api)+15*cry_api->smapi.plen+cry_api->smapi.entla, cry_api->smapi.entlb);
			memcpy((unsigned char *)smapi_ext->zain+4+cry_api->smapi.entla+cry_api->smapi.entlb+10*cry_api->smapi.plen, (unsigned char *)cry_api+sizeof(struct sm2_api)+13*cry_api->smapi.plen+cry_api->smapi.entla, 2*cry_api->smapi.plen);
		}
		else
		{
			memcpy((unsigned char *)smapi_ext->zain+2, (unsigned char *)cry_api+sizeof(struct sm2_api)+15*cry_api->smapi.plen+cry_api->smapi.entlb, cry_api->smapi.entla);
			memcpy((unsigned char *)smapi_ext->zain+2+cry_api->smapi.entla+4*cry_api->smapi.plen, (unsigned char *)cry_api+sizeof(struct sm2_api)+13*cry_api->smapi.plen+cry_api->smapi.entlb, 2*cry_api->smapi.plen);
			memcpy((unsigned char *)smapi_ext->zain+4+cry_api->smapi.entla+cry_api->smapi.plen*6, (unsigned char *)cry_api+sizeof(struct sm2_api)+10*cry_api->smapi.plen, cry_api->smapi.entlb);
			memcpy((unsigned char *)smapi_ext->zain+4+cry_api->smapi.entla+cry_api->smapi.entlb+10*cry_api->smapi.plen, (unsigned char *)cry_api+sizeof(struct sm2_api)+7*cry_api->smapi.plen, 2*cry_api->smapi.plen);
		}
		memcpy((unsigned char *)smapi_ext->zain+2+cry_api->smapi.entla, (unsigned char *)cry_api+sizeof(struct sm2_api)+cry_api->smapi.plen, 4*cry_api->smapi.plen);
		memcpy((unsigned char *)smapi_ext->zain+4+cry_api->smapi.entla+cry_api->smapi.entlb+cry_api->smapi.plen*6, (unsigned char *)cry_api+sizeof(struct sm2_api)+cry_api->smapi.plen, 4*cry_api->smapi.plen);

		((unsigned char *)smapi_ext->one)[0] = 0x2;
		((unsigned char *)smapi_ext->one)[1] = 0x3;

		if(cmd_nr == ACLASS_SM2_KEY_AGREEMENTA)
			memcpy((unsigned char *)smapi_ext->k+cry_api->smapi.plen-16, (unsigned char *)cry_api+sizeof(struct sm2_api)+cry_api->smapi.plen*11+cry_api->smapi.entla-16, 16);
		else
			memcpy((unsigned char *)smapi_ext->k+cry_api->smapi.plen-16, (unsigned char *)cry_api+sizeof(struct sm2_api)+cry_api->smapi.plen*11+cry_api->smapi.entlb-16, 16);
		memcpy((unsigned char *)smapi_ext->k+2*cry_api->smapi.plen-16, (unsigned char *)cry_api+sizeof(struct sm2_api)+cry_api->smapi.plen*16+cry_api->smapi.entla+cry_api->smapi.entlb-16, 16);
		((unsigned char *)smapi_ext->k)[cry_api->smapi.plen-16] |= 0x80;
		((unsigned char *)smapi_ext->k)[2*cry_api->smapi.plen-16] |= 0x80;
		
		smapi_ext->zain_phys = dma_map_single(csec_priv->dev,smapi_ext->zain,4+cry_api->smapi.entla+cry_api->smapi.entlb+cry_api->smapi.plen*12, DMA_TO_DEVICE);
		smapi_ext->zaout_phys = dma_map_single(csec_priv->dev,smapi_ext->zaout,cry_api->smapi.nlen*2, DMA_BIDIRECTIONAL);
		smapi_ext->k_phys = dma_map_single(csec_priv->dev,smapi_ext->k,cry_api->smapi.plen*2, DMA_BIDIRECTIONAL);
		smapi_ext->one_phys = dma_map_single(csec_priv->dev,smapi_ext->one,2, DMA_TO_DEVICE);
		smapi_ext->hashin_phys = dma_map_single(csec_priv->dev,smapi_ext->hashin,cry_api->smapi.plen*2+4, DMA_BIDIRECTIONAL);
		smapi_ext->hashout_phys = dma_map_single(csec_priv->dev,smapi_ext->hashout,cry_api->smapi.nlen, DMA_BIDIRECTIONAL);

#if 0
		if(cmd_nr == ACLASS_SM2_KEY_AGREEMENTA)
			inline_cnstr_jobdesc_sm2_agreementA(desc, &(cry_api->smapi), capi_addr, smapi_ext);
		else
			inline_cnstr_jobdesc_sm2_agreementB(desc, &(cry_api->smapi), capi_addr, smapi_ext);
		smapi_ext->desc_ext_phys = dma_map_single(csec_priv->dev,smapi_ext->desc_ext,MAX_CSEC_DESCSIZE, DMA_TO_DEVICE);
		append_ptr(desc, change_addr_for_sec (smapi_ext->desc_ext_phys));
#else
		para.ecc_dma.p = capi_addr+sizeof(struct sm2_api);
		para.ecc_dma.a = para.ecc_dma.p+cry_api->smapi.plen;
		para.ecc_dma.b= para.ecc_dma.a+cry_api->smapi.plen;
		para.ecc_dma.gx = para.ecc_dma.b+cry_api->smapi.plen;
		para.ecc_dma.gy = para.ecc_dma.gx+cry_api->smapi.plen;
		para.ecc_dma.n = para.ecc_dma.gy+cry_api->smapi.plen;
		para.h_dma = para.ecc_dma.n+cry_api->smapi.plen;
		para.self_prikey_dma = para.h_dma+3*cry_api->smapi.plen;
		para.zain_len = 2+cry_api->smapi.entla+6*cry_api->smapi.plen;
		para.zbin_len = 2+cry_api->smapi.entlb+6*cry_api->smapi.plen;
		if(cmd_nr == ACLASS_SM2_KEY_AGREEMENTA)
			para.self_tmp_pubkey_dma.x= para.self_prikey_dma+cry_api->smapi.entla+cry_api->smapi.plen;
		else
			para.self_tmp_pubkey_dma.x= para.self_prikey_dma+cry_api->smapi.entlb+cry_api->smapi.plen;
		para.self_tmp_pubkey_dma.y = para.self_tmp_pubkey_dma.x+cry_api->smapi.plen;
		para.self_tmp_prikey_dma = para.self_tmp_pubkey_dma.y+cry_api->smapi.plen;
		para.other_pubkey_dma.x= para.self_tmp_prikey_dma+cry_api->smapi.plen;
		para.other_pubkey_dma.y = para.other_pubkey_dma.x+cry_api->smapi.plen;
		if(cmd_nr == ACLASS_SM2_KEY_AGREEMENTA)
			para.other_tmp_pubkey_dma.x= para.other_pubkey_dma.y+cry_api->smapi.entlb+cry_api->smapi.plen;
		else
			para.other_tmp_pubkey_dma.x= para.other_pubkey_dma.y+cry_api->smapi.entla+cry_api->smapi.plen;	
		para.other_tmp_pubkey_dma.y = para.other_tmp_pubkey_dma.x+cry_api->smapi.plen;
		para.key_dma = para.other_tmp_pubkey_dma.y+cry_api->smapi.plen;
		para.s1_dma = para.key_dma+cry_api->smapi.klen;
		para.s2_dma = para.s1_dma+cry_api->smapi.nlen;
		para.zain_dma = smapi_ext->zain_phys;
		para.zbin_dma = smapi_ext->zain_phys+para.zain_len;
		para.za_dma = smapi_ext->zaout_phys;
		para.zb_dma = smapi_ext->zaout_phys+cry_api->smapi.nlen;
		if(cmd_nr == ACLASS_SM2_KEY_AGREEMENTA)
			para.exc_mode = A;
		else
			para.exc_mode = B;		
		para.u_dma.x = smapi_ext->hashin_phys;
		para.u_dma.y = smapi_ext->hashin_phys+cry_api->smapi.plen;
		para.self_x_dma = smapi_ext->k_phys;
		para.other_x_dma = smapi_ext->k_phys+cry_api->smapi.plen;
		para.ct_dma = smapi_ext->hashin_phys+2*cry_api->smapi.plen;
		para.hashout_dma = smapi_ext->hashout_phys;
		para.s1_head_dma = smapi_ext->one_phys;
		para.s2_head_dma = smapi_ext->one_phys+1;
		para.desc_dma = desc_phy_addr;
		para.plen = cry_api->smapi.plen;
		para.nlen = cry_api->smapi.nlen;
		para.klen = cry_api->smapi.klen;
		para.ecc_mode = (cry_api->smapi.field == 0) ? FP : F2M;
		para.endian_mode = LITTLE;
		para.id_mode = WITHID;
		inline_cnstr_jobdesc_sm2_exchange(desc, &para);		
#endif
	}else if(cmd_nr == ACLASS_SM2_GENKEY)
	{
		struct sm2_genkey_private_dma para;
#if 0
		inline_cnstr_jobdesc_sm2_genkey(desc, &(cry_api->smapi), capi_addr, smapi_ext);
#else
		para.ecc_dma.p = capi_addr+sizeof(struct sm2_api);
		para.ecc_dma.a = para.ecc_dma.p+cry_api->smapi.plen;
		para.ecc_dma.b= para.ecc_dma.a+cry_api->smapi.plen;
		para.ecc_dma.gx = para.ecc_dma.b+cry_api->smapi.plen;
		para.ecc_dma.gy = para.ecc_dma.gx+cry_api->smapi.plen;
		para.ecc_dma.n = para.ecc_dma.gy+cry_api->smapi.plen;
		para.prikey_dma = para.ecc_dma.n+cry_api->smapi.plen;
		para.pubkey_dma.x = para.prikey_dma+cry_api->smapi.plen;
		para.pubkey_dma.y = para.pubkey_dma.x+cry_api->smapi.plen;
		para.plen = cry_api->smapi.plen;
		para.nlen = cry_api->smapi.nlen;
		para.ecc_mode = (cry_api->smapi.field == 0) ? FP : F2M;
		para.rng_mode = HARDWARE;
		inline_cnstr_jobdesc_sm2_genkey(desc, &para);
#endif
	}else if(cmd_nr == ACLASS_SM2_GENKEY_SEED)
	{
		struct sm2_genkey_private_dma para;
#if 0
		inline_cnstr_jobdesc_sm2_genkey_seed(desc, &(cry_api->smapi), capi_addr, smapi_ext);
#else
		para.ecc_dma.p = capi_addr+sizeof(struct sm2_api);
		para.ecc_dma.a = para.ecc_dma.p+cry_api->smapi.plen;
		para.ecc_dma.b= para.ecc_dma.a+cry_api->smapi.plen;
		para.ecc_dma.gx = para.ecc_dma.b+cry_api->smapi.plen;
		para.ecc_dma.gy = para.ecc_dma.gx+cry_api->smapi.plen;
		para.ecc_dma.n = para.ecc_dma.gy+cry_api->smapi.plen;
		para.prikey_dma = para.ecc_dma.n+cry_api->smapi.plen;
		para.pubkey_dma.x = para.prikey_dma+cry_api->smapi.plen;
		para.pubkey_dma.y = para.pubkey_dma.x+cry_api->smapi.plen;
		para.plen = cry_api->smapi.plen;
		para.nlen = cry_api->smapi.nlen;
		para.ecc_mode = (cry_api->smapi.field == 0) ? FP : F2M;
		para.rng_mode = CONSTANT;
		inline_cnstr_jobdesc_sm2_genkey(desc, &para);		
#endif
	}else if(cmd_nr == ACLASS_SM2_SIGNATURE_NOID)
	{
		struct sm2_sig_private_dma para;
		smapi_ext = (struct sm2_api_ext *)kzalloc(sizeof(struct sm2_api_ext), GFP_KERNEL|SYS_DMA);
		if(!smapi_ext )
		{
			csec_error(KERN_INFO "smapi_ext kzalloc error\n");
			return -EINVAL;
		}
		smapi_ext->k = kzalloc(cry_api->smapi.plen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->k )
		{
			csec_error(KERN_INFO "smapi_ext->k kzalloc error\n");
			return -EINVAL;
		}
		smapi_ext->one = kzalloc(cry_api->smapi.plen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->one )
		{
			csec_error(KERN_INFO "smapi_ext->one kzalloc error\n");
			return -EINVAL;
		}
		((unsigned char *)smapi_ext->one)[0] = 0x1;

		smapi_ext->k_phys = dma_map_single(csec_priv->dev,smapi_ext->k,cry_api->smapi.plen, DMA_BIDIRECTIONAL);
		smapi_ext->one_phys = dma_map_single(csec_priv->dev,smapi_ext->one,cry_api->smapi.plen, DMA_TO_DEVICE);

#if 0
		inline_cnstr_jobdesc_sm2_signature_noid(desc, &(cry_api->smapi), capi_addr, smapi_ext);
#else
		para.ecc_dma.p = capi_addr+sizeof(struct sm2_api);
		para.ecc_dma.a = para.ecc_dma.p+cry_api->smapi.plen;
		para.ecc_dma.b= para.ecc_dma.a+cry_api->smapi.plen;
		para.ecc_dma.gx = para.ecc_dma.b+cry_api->smapi.plen;
		para.ecc_dma.gy = para.ecc_dma.gx+cry_api->smapi.plen;
		para.ecc_dma.n = para.ecc_dma.gy+cry_api->smapi.plen;
		para.prikey_dma= para.ecc_dma.n+cry_api->smapi.plen;
		para.e_dma = para.prikey_dma+cry_api->smapi.plen;
		para.sig_dma.r = para.e_dma+cry_api->smapi.nlen;
		para.sig_dma.s = para.sig_dma.r+cry_api->smapi.plen;
		para.one_dma = smapi_ext->one_phys;
		para.plen = cry_api->smapi.plen;
		para.nlen = cry_api->smapi.nlen;
		para.klen = cry_api->smapi.klen;
		para.ecc_mode = (cry_api->smapi.field == 0) ? FP : F2M;
		para.sig_mode = NOID;
		para.rng_mode = HARDWARE;
		inline_cnstr_jobdesc_sm2_signature(desc, &para);
#endif
	}else if(cmd_nr == ACLASS_SM2_SIGNATURE_NOID_SEED)
	{
		struct sm2_sig_private_dma para;
		smapi_ext = (struct sm2_api_ext *)kzalloc(sizeof(struct sm2_api_ext), GFP_KERNEL|SYS_DMA);
		if(!smapi_ext )
		{
			csec_error(KERN_INFO "smapi_ext kzalloc error\n");
			return -EINVAL;
		}
		smapi_ext->k = kzalloc(cry_api->smapi.plen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->k )
		{
			csec_error(KERN_INFO "smapi_ext->k kzalloc error\n");
			return -EINVAL;
		}
		smapi_ext->one = kzalloc(cry_api->smapi.plen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->one )
		{
			csec_error(KERN_INFO "smapi_ext->one kzalloc error\n");
			return -EINVAL;
		}
		((unsigned char *)smapi_ext->one)[0] = 0x1;

		smapi_ext->k_phys = dma_map_single(csec_priv->dev,smapi_ext->k,cry_api->smapi.plen, DMA_BIDIRECTIONAL);
		smapi_ext->one_phys = dma_map_single(csec_priv->dev,smapi_ext->one,cry_api->smapi.plen, DMA_TO_DEVICE);

#if 0
		inline_cnstr_jobdesc_sm2_signature_noid_seed(desc, &(cry_api->smapi), capi_addr, smapi_ext);
#else
		para.ecc_dma.p = capi_addr+sizeof(struct sm2_api);
		para.ecc_dma.a = para.ecc_dma.p+cry_api->smapi.plen;
		para.ecc_dma.b= para.ecc_dma.a+cry_api->smapi.plen;
		para.ecc_dma.gx = para.ecc_dma.b+cry_api->smapi.plen;
		para.ecc_dma.gy = para.ecc_dma.gx+cry_api->smapi.plen;
		para.ecc_dma.n = para.ecc_dma.gy+cry_api->smapi.plen;
		para.prikey_dma= para.ecc_dma.n+cry_api->smapi.plen;
		para.e_dma = para.prikey_dma+cry_api->smapi.plen;
		para.k_dma = para.e_dma+cry_api->smapi.nlen;
		para.sig_dma.r = para.k_dma+cry_api->smapi.plen;
		para.sig_dma.s = para.sig_dma.r+cry_api->smapi.plen;
		para.one_dma = smapi_ext->one_phys;
		para.plen = cry_api->smapi.plen;
		para.nlen = cry_api->smapi.nlen;
		para.klen = cry_api->smapi.klen;
		para.ecc_mode = (cry_api->smapi.field == 0) ? FP : F2M;
		para.sig_mode = NOID;
		para.rng_mode = CONSTANT;
		inline_cnstr_jobdesc_sm2_signature(desc, &para);
#endif
	}else if(cmd_nr == ACLASS_SM2_VERIFY_NOID)
	{
		struct sm2_ver_private_dma para;
		smapi_ext = (struct sm2_api_ext *)kzalloc(sizeof(struct sm2_api_ext), GFP_KERNEL|SYS_DMA);
		if(!smapi_ext )
		{
			csec_error(KERN_INFO "smapi_ext kzalloc error\n");
			return -EINVAL;
		}
		smapi_ext->one = kzalloc(cry_api->smapi.plen, GFP_KERNEL|SYS_DMA);
		if(!smapi_ext->one )
		{
			csec_error(KERN_INFO "smapi_ext->one kzalloc error\n");
			return -EINVAL;
		}
		((unsigned char *)smapi_ext->one)[0] = 0x1;

		smapi_ext->one_phys = dma_map_single(csec_priv->dev,smapi_ext->one,cry_api->smapi.plen, DMA_TO_DEVICE);

#if 0
		inline_cnstr_jobdesc_sm2_verify_noid(desc, &(cry_api->smapi), capi_addr, smapi_ext);
#else
		para.ecc_dma.p = capi_addr+sizeof(struct sm2_api);
		para.ecc_dma.a = para.ecc_dma.p+cry_api->smapi.plen;
		para.ecc_dma.b= para.ecc_dma.a+cry_api->smapi.plen;
		para.ecc_dma.gx = para.ecc_dma.b+cry_api->smapi.plen;
		para.ecc_dma.gy = para.ecc_dma.gx+cry_api->smapi.plen;
		para.ecc_dma.n = para.ecc_dma.gy+cry_api->smapi.plen;
		para.pubkey_dma.x= para.ecc_dma.n+cry_api->smapi.plen;
		para.pubkey_dma.y = para.pubkey_dma.x+cry_api->smapi.plen;
		para.e_dma= para.pubkey_dma.y+cry_api->smapi.plen;
		para.sig_dma.r = para.e_dma+cry_api->smapi.nlen;
		para.sig_dma.s = para.sig_dma.r+cry_api->smapi.plen;
		para.one_dma = smapi_ext->one_phys;
		para.plen = cry_api->smapi.plen;
		para.nlen = cry_api->smapi.nlen;
		para.klen = cry_api->smapi.klen;
		para.ecc_mode = (cry_api->smapi.field == 0) ? FP : F2M;
		para.sig_mode = NOID;
		inline_cnstr_jobdesc_sm2_verify(desc, &para);
#endif
	}else if(cmd_nr == ACLASS_RSA_GENKEY)
	{
		unsigned char j;
		unsigned int i;
		
		rsaapi_ext = (struct rsa_api_ext *)kzalloc(sizeof(struct rsa_api_ext), GFP_KERNEL|SYS_DMA);

		rsaapi_ext->r0 = kzalloc(cry_api->rsaapi.rsa_random_bit/8, GFP_KERNEL|SYS_DMA);
		rsaapi_ext->r1 = kzalloc(cry_api->rsaapi.rsa_random_bit/8, GFP_KERNEL|SYS_DMA);
		rsaapi_ext->r2 = kzalloc(cry_api->rsaapi.rsa_random_bit/8, GFP_KERNEL|SYS_DMA);
		rsaapi_ext->r3 = kzalloc(cry_api->rsaapi.rsa_random_bit/8, GFP_KERNEL|SYS_DMA);
		rsaapi_ext->r4 = kzalloc(cry_api->rsaapi.rsa_random_bit/8, GFP_KERNEL|SYS_DMA);
		rsaapi_ext->r5 = kzalloc(cry_api->rsaapi.rsa_random_bit/8, GFP_KERNEL|SYS_DMA);
		rsaapi_ext->r6 = kzalloc(cry_api->rsaapi.rsa_random_bit/8, GFP_KERNEL|SYS_DMA);
		rsaapi_ext->r7 = kzalloc(cry_api->rsaapi.rsa_random_bit/8, GFP_KERNEL|SYS_DMA);
		rsaapi_ext->r8 = kzalloc(cry_api->rsaapi.rsa_random_bit/8, GFP_KERNEL|SYS_DMA);
		rsaapi_ext->r9 = kzalloc(cry_api->rsaapi.rsa_random_bit/8, GFP_KERNEL|SYS_DMA);

		rsaapi_ext->desc_ext = kzalloc(MAX_CSEC_DESCSIZE,GFP_KERNEL|SYS_DMA);
		if(!rsaapi_ext->desc_ext )
		{ csec_error(KERN_INFO "desc_ext kzalloc error\n");
			return -EINVAL; 
		} 
		
		rsaapi_ext->desc_ext2 = kzalloc(MAX_CSEC_DESCSIZE,GFP_KERNEL|SYS_DMA);
		if(!rsaapi_ext->desc_ext2 )
		{ csec_error(KERN_INFO "desc_ext kzalloc error\n");
			return -EINVAL; 
		} 

		rsaapi_ext->desc_ext3 = kzalloc(MAX_CSEC_DESCSIZE,GFP_KERNEL|SYS_DMA);
		if(!rsaapi_ext->desc_ext3 )
		{ csec_error(KERN_INFO "desc_ext3 kzalloc error\n");
			return -EINVAL; 
		} 

//		csec_error(KERN_INFO "test point 0 here\n");
	
		*((unsigned char *)rsaapi_ext->r1 + cry_api->rsaapi.rsa_random_bit/8 -1) = 0x05;		

		for(i=0; i<cry_api->rsaapi.rsa_random_bit/8; i++)
		{
			((unsigned char *)rsaapi_ext->r2)[i] = key1_r2[i];
		}

		if(cry_api->rsaapi.fixed)		//use the fixed to be the size of e
		{

		}else{
//			cry_api->fixed = 3;				//set random_e 3 bytes
			do{
				get_random_bytes(&j, 1);
				cry_api->rsaapi.fixed = j;		//if rsaapi.fikxed==0, means random E, then rsaapi.fixed is now the data of E
			}while((cry_api->rsaapi.fixed <2) || (cry_api->rsaapi.fixed > (cry_api->rsaapi.rsa_random_bit/16 -4)));
		}
		
		get_random_bytes((unsigned char *)rsaapi_ext->r3+ cry_api->rsaapi.rsa_random_bit/8 -32, 32);					//	r3 is rng_seed
		*((unsigned char *)rsaapi_ext->r4 + cry_api->rsaapi.rsa_random_bit/16) = 0xC0;	
		//memset((unsigned char *)rsaapi_ext->r4, 0, cry_api->rsaapi.rsa_random_bit/8);
		*((unsigned char *)rsaapi_ext->r5 + cry_api->rsaapi.rsa_random_bit/8 -1) = 2;		
		*((unsigned char *)rsaapi_ext->r6 + cry_api->rsaapi.rsa_random_bit/8 -1) = 1;
		
		rsaapi_ext->r0_phys = dma_map_single(csec_priv->dev, (unsigned char *)rsaapi_ext->r0, cry_api->rsaapi.rsa_random_bit/8, DMA_BIDIRECTIONAL);
		rsaapi_ext->r1_phys = dma_map_single(csec_priv->dev, (unsigned char *)rsaapi_ext->r1, cry_api->rsaapi.rsa_random_bit/8, DMA_BIDIRECTIONAL);
		rsaapi_ext->r2_phys = dma_map_single(csec_priv->dev, (unsigned char *)rsaapi_ext->r2, cry_api->rsaapi.rsa_random_bit/8, DMA_BIDIRECTIONAL);
		rsaapi_ext->r3_phys = dma_map_single(csec_priv->dev, (unsigned char *)rsaapi_ext->r3, cry_api->rsaapi.rsa_random_bit/8, DMA_BIDIRECTIONAL);
		rsaapi_ext->r4_phys = dma_map_single(csec_priv->dev, (unsigned char *)rsaapi_ext->r4, cry_api->rsaapi.rsa_random_bit/8, DMA_BIDIRECTIONAL);
		rsaapi_ext->r5_phys = dma_map_single(csec_priv->dev, (unsigned char *)rsaapi_ext->r5, cry_api->rsaapi.rsa_random_bit/8, DMA_BIDIRECTIONAL);
		rsaapi_ext->r6_phys = dma_map_single(csec_priv->dev, (unsigned char *)rsaapi_ext->r6, cry_api->rsaapi.rsa_random_bit/8, DMA_BIDIRECTIONAL);
		rsaapi_ext->r7_phys = dma_map_single(csec_priv->dev, (unsigned char *)rsaapi_ext->r7, cry_api->rsaapi.rsa_random_bit/8, DMA_BIDIRECTIONAL);
		rsaapi_ext->r8_phys = dma_map_single(csec_priv->dev, (unsigned char *)rsaapi_ext->r8, cry_api->rsaapi.rsa_random_bit/8, DMA_BIDIRECTIONAL);
		rsaapi_ext->r9_phys = dma_map_single(csec_priv->dev, (unsigned char *)rsaapi_ext->r9, cry_api->rsaapi.rsa_random_bit/8, DMA_BIDIRECTIONAL);

#if 1
		inline_cnstr_jobdesc_rsa_genkey(desc, &(cry_api->rsaapi), capi_addr, rsaapi_ext);

		rsaapi_ext->desc_ext_phys = dma_map_single(csec_priv->dev,rsaapi_ext->desc_ext,MAX_CSEC_DESCSIZE, DMA_TO_DEVICE);
		rsaapi_ext->desc_ext2_phys = dma_map_single(csec_priv->dev,rsaapi_ext->desc_ext2,MAX_CSEC_DESCSIZE, DMA_TO_DEVICE);
		append_ptr(desc, change_addr_for_sec (rsaapi_ext->desc_ext_phys));
		append_ptr(rsaapi_ext->desc_ext, change_addr_for_sec (rsaapi_ext->desc_ext2_phys));

		if(cry_api->rsaapi.crt)
		{
			rsaapi_ext->desc_ext3_phys = dma_map_single(csec_priv->dev,rsaapi_ext->desc_ext3,MAX_CSEC_DESCSIZE, DMA_TO_DEVICE);
			append_ptr(rsaapi_ext->desc_ext2, change_addr_for_sec (rsaapi_ext->desc_ext3_phys));
		}
#else
		struct rsa_genkey_dma para;
		para.blen = cry_api->rsaapi.rsa_random_bit/8;
		para.elen = cry_api->rsaapi.fixed;
		para.crt = cry_api->rsaapi.crt; 
		para.sec_dma.p_dma = capi_addr+sizeof(struct rsa_api);
		para.sec_dma.q_dma = para.sec_dma.p_dma+para.blen;
		para.sec_dma.e_dma = para.sec_dma.q_dma+para.blen;
		para.sec_dma.n_dma = para.sec_dma.e_dma+para.blen;
		para.sec_dma.d_dma = para.sec_dma.n_dma+para.blen;
		para.sec_dma.dp_dma = para.sec_dma.d_dma+para.blen;
		para.sec_dma.dq_dma = para.sec_dma.dp_dma+para.blen;
		para.sec_dma.qInv_dma = para.sec_dma.dq_dma+para.blen;
		para.r_dma.r0_dma = rsaapi_ext->r0_phys;
		para.r_dma.r1_dma = rsaapi_ext->r1_phys;
		para.r_dma.r2_dma = rsaapi_ext->r2_phys;
		para.r_dma.r3_dma = rsaapi_ext->r3_phys;
		para.r_dma.r4_dma = rsaapi_ext->r4_phys;
		para.r_dma.r5_dma = rsaapi_ext->r5_phys;
		para.r_dma.r6_dma = rsaapi_ext->r6_phys;
		para.r_dma.r7_dma = rsaapi_ext->r7_phys;
		para.r_dma.r8_dma = rsaapi_ext->r8_phys;
		para.r_dma.r9_dma = rsaapi_ext->r9_phys;
		para.desc_dma = desc_phy_addr;

//		csec_error(KERN_INFO "############the value of elen is:%d\n", para.elen);
		
		inline_cnstr_jobdesc_rsa_genkey_simplified(desc, &para);
#endif
	}
		else if((cmd_nr == ACLASS_RSA_PUB) || (cmd_nr == ACLASS_RSA_PRIV))
	{	
#if 1
		inline_cnstr_jobdesc_pkha(desc,&(cry_api->papi),capi_addr);
#else
		struct rsa_pub_priv_dma para;
		para.blen = cry_api->papi.n_len;
	//	para.mode = cry_api->papi.mode;
		para.e_dma = capi_addr + sizeof(struct pkha_api);
		para.n_dma = capi_addr + sizeof(struct pkha_api) + para.blen;
		para.in_dma = capi_addr + sizeof(struct pkha_api) + 2*para.blen;
		para.out_dma = capi_addr + sizeof(struct pkha_api) + 3*para.blen;
		inline_cnstr_jobdesc_rsa_pub_priv_simplified(desc, &para);
#endif
	}
		else if((cmd_nr == ACLASS_RSA_PUB_BIG) || (cmd_nr == ACLASS_RSA_PRIV_BIG))
	{
		inline_cnstr_jobdesc_pkha_end_big(desc,&(cry_api->papi),capi_addr);
	}
		else if(cmd_nr == ACLASS_RSA_PRIV_CRT)
	{	
#if 1	
		inline_cnstr_jobdesc_rsa_priv_crt(desc,&(cry_api->papi),capi_addr);
#else
		struct rsa_priv_crt_dma para;
		para.blen = cry_api->papi.n_len;
		para.mode = cry_api->papi.mode;
		para.n = capi_addr + sizeof(struct pkha_api);
		para.a = capi_addr + sizeof(struct pkha_api) + para.blen;
		para.out = capi_addr + sizeof(struct pkha_api) + 2*para.blen;
		para.p = capi_addr + sizeof(struct pkha_api) + 3*para.blen;
		para.q = capi_addr + sizeof(struct pkha_api) + 4*para.blen;
		para.dp = capi_addr + sizeof(struct pkha_api) + 5*para.blen;
		para.dq = capi_addr + sizeof(struct pkha_api) + 6*para.blen;
		para.qInv= capi_addr + sizeof(struct pkha_api) + 7*para.blen;
		inline_cnstr_jobdesc_rsa_priv_crt_simplified(desc, &para);
#endif
	}	

	//desc_phy_addr = dma_map_single(csec_priv->dev,(void *)desc,MAX_CSEC_DESCSIZE, DMA_TO_DEVICE);	

	csec_debug(KERN_INFO "desc fill ok\n");
	
	init_completion(&done_op->op_done);
	
	do
	{
		status = cards_enqueue(csec_priv,  desc, desc_phy_addr,ioctl_desc_done,done_op);
		if(status)
		{
			if(CDEV_INVL)
			{
				//wait_event_timeout(csec_priv->ccore_cards->dq_done,0,CDEV_INVL);
				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(CDEV_INVL);
				
				csec_debug2(KERN_INFO "ce0\n");
			}
		}
	}while(status==-EBUSY);
		
	csec_debug(KERN_INFO "cdev_csec_ioctl is called s0\n");

	if (!wait_for_completion_timeout(&done_op->op_done, CDEV_INVL*20)){
		csec_error("wait_for_completion_timeout\n");
		return -EAGAIN;
	}
	csec_debug(KERN_INFO "cdev_csec_ioctl is called s1, over!\n!");

	if(smapi_ext)
		{
			if(smapi_ext->hashin_phys)
			{
				dma_unmap_single(csec_priv->dev,smapi_ext->hashin_phys,cry_api->smapi.plen*2+4,DMA_BIDIRECTIONAL);
				kfree(smapi_ext->hashin);
			}
			if(smapi_ext->hashout_phys)
			{
				if(cmd_nr>=ACLASS_SM2_KEY_AGREEMENTA && cmd_nr<=ACLASS_SM2_KEY_AGREEMENTB)
					dma_unmap_single(csec_priv->dev,smapi_ext->hashout_phys,cry_api->smapi.nlen,DMA_BIDIRECTIONAL);
				else
					dma_unmap_single(csec_priv->dev,smapi_ext->hashout_phys,(cry_api->smapi.klen+cry_api->smapi.nlen-1)/cry_api->smapi.nlen*cry_api->smapi.nlen,DMA_BIDIRECTIONAL);
				kfree(smapi_ext->hashout);
			}
			if(smapi_ext->k_phys)
			{
				if(cmd_nr>=ACLASS_SM2_KEY_AGREEMENTA && cmd_nr<=ACLASS_SM2_KEY_AGREEMENTB)
					dma_unmap_single(csec_priv->dev,smapi_ext->k_phys,cry_api->smapi.plen*2, DMA_BIDIRECTIONAL);
				else
					dma_unmap_single(csec_priv->dev,smapi_ext->k_phys,cry_api->smapi.plen, DMA_BIDIRECTIONAL);
				kfree(smapi_ext->k);
			}
			if(smapi_ext->desc_ext_phys)
			{
				dma_unmap_single(csec_priv->dev,smapi_ext->desc_ext_phys,MAX_CSEC_DESCSIZE, DMA_TO_DEVICE);
				kfree(smapi_ext->desc_ext);
			}
			if(smapi_ext->zain_phys)
			{
				if(cmd_nr>=ACLASS_SM2_KEY_AGREEMENTA && cmd_nr<=ACLASS_SM2_KEY_AGREEMENTB)
					dma_unmap_single(csec_priv->dev,smapi_ext->zain_phys,4+cry_api->smapi.entla+cry_api->smapi.entlb+cry_api->smapi.plen*12, DMA_TO_DEVICE);
				else
					dma_unmap_single(csec_priv->dev,smapi_ext->zain_phys,2+cry_api->smapi.entla+cry_api->smapi.plen*6, DMA_TO_DEVICE);
				kfree(smapi_ext->zain);
			}
			if(smapi_ext->zaout_phys)
			{
				if(cmd_nr>=ACLASS_SM2_KEY_AGREEMENTA && cmd_nr<=ACLASS_SM2_KEY_AGREEMENTB)
					dma_unmap_single(csec_priv->dev,smapi_ext->zaout_phys,cry_api->smapi.nlen*2, DMA_BIDIRECTIONAL);
				else
					dma_unmap_single(csec_priv->dev,smapi_ext->zaout_phys,cry_api->smapi.nlen, DMA_BIDIRECTIONAL);
				kfree(smapi_ext->zaout);
			}
			if(smapi_ext->one_phys)
			{
				if(cmd_nr>=ACLASS_SM2_KEY_AGREEMENTA && cmd_nr<=ACLASS_SM2_KEY_AGREEMENTB)
					dma_unmap_single(csec_priv->dev,smapi_ext->one_phys,2, DMA_TO_DEVICE);
				else
					dma_unmap_single(csec_priv->dev,smapi_ext->one_phys,cry_api->smapi.plen, DMA_TO_DEVICE);
				kfree(smapi_ext->one);
			}
			kfree(smapi_ext);
		}else if(rsaapi_ext) 
			{ 
				if(rsaapi_ext->r0_phys) 
					{
						dma_unmap_single(csec_priv->dev,rsaapi_ext->r0_phys,cry_api->rsaapi.rsa_random_bit/8,DMA_BIDIRECTIONAL );
						kfree(rsaapi_ext->r0); 
					}
				if(rsaapi_ext->r1_phys) 
					{
						dma_unmap_single(csec_priv->dev,rsaapi_ext->r1_phys,cry_api->rsaapi.rsa_random_bit/8,DMA_BIDIRECTIONAL );
						kfree(rsaapi_ext->r1); 
					}
				if(rsaapi_ext->r2_phys) 
					{
						dma_unmap_single(csec_priv->dev,rsaapi_ext->r2_phys,cry_api->rsaapi.rsa_random_bit/8,DMA_BIDIRECTIONAL );
						kfree(rsaapi_ext->r2); 
					}
				if(rsaapi_ext->r3_phys) 
					{ 	
						dma_unmap_single(csec_priv->dev,rsaapi_ext->r3_phys,cry_api->rsaapi.rsa_random_bit/8,DMA_BIDIRECTIONAL );
						kfree(rsaapi_ext->r3); 
					}
				if(rsaapi_ext->r4_phys) 
					{
						dma_unmap_single(csec_priv->dev,rsaapi_ext->r4_phys,cry_api->rsaapi.rsa_random_bit/8,DMA_BIDIRECTIONAL );
						kfree(rsaapi_ext->r4);
					}
				if(rsaapi_ext->r5_phys)
					{
						dma_unmap_single(csec_priv->dev,rsaapi_ext->r5_phys,cry_api->rsaapi.rsa_random_bit/8,DMA_BIDIRECTIONAL );
						kfree(rsaapi_ext->r5);
					}
				if(rsaapi_ext->r6_phys)
					{
						dma_unmap_single(csec_priv->dev,rsaapi_ext->r6_phys,cry_api->rsaapi.rsa_random_bit/8,DMA_BIDIRECTIONAL );
						kfree(rsaapi_ext->r6); 
					}
				if(rsaapi_ext->r7_phys)
					{
						dma_unmap_single(csec_priv->dev,rsaapi_ext->r7_phys,cry_api->rsaapi.rsa_random_bit/8,DMA_BIDIRECTIONAL );
						kfree(rsaapi_ext->r7); 
					}
				if(rsaapi_ext->r8_phys)
					{
						dma_unmap_single(csec_priv->dev,rsaapi_ext->r8_phys,cry_api->rsaapi.rsa_random_bit/8,DMA_BIDIRECTIONAL );
						kfree(rsaapi_ext->r8);
					}
				if(rsaapi_ext->r9_phys)
					{
						dma_unmap_single(csec_priv->dev,rsaapi_ext->r9_phys,cry_api->rsaapi.rsa_random_bit/8,DMA_BIDIRECTIONAL );
						kfree(rsaapi_ext->r9);
					}
				if(rsaapi_ext->desc_ext_phys)
					{
						dma_unmap_single(csec_priv->dev,rsaapi_ext->desc_ext_phys,MAX_CSEC_DESCSIZE,DMA_TO_DEVICE );	
					}
				if(rsaapi_ext->desc_ext2_phys)
					{
						dma_unmap_single(csec_priv->dev,rsaapi_ext->desc_ext2_phys,MAX_CSEC_DESCSIZE,DMA_TO_DEVICE );
					}
				if(rsaapi_ext->desc_ext3_phys)
					{
						dma_unmap_single(csec_priv->dev,rsaapi_ext->desc_ext3_phys,MAX_CSEC_DESCSIZE,DMA_TO_DEVICE );
					}

				kfree(rsaapi_ext->desc_ext);
				kfree(rsaapi_ext->desc_ext2);
				kfree(rsaapi_ext->desc_ext3);
				kfree(rsaapi_ext);
			}

//	dma_unmap_single(csec_priv->dev,desc_phy_addr,MAX_CSEC_DESCSIZE,DMA_TO_DEVICE);

//	kfree(desc);
	dma_free_coherent(csec_priv->dev, MAX_CSEC_DESCSIZE*4, desc, desc_phy_addr);

	return 0;
}
EXPORT_SYMBOL_GPL(cdev_csec_do);

/*
	for the application of key from internal card, add mask bit 0x80000000 of key_len.if this bit is 1,this means use internal card key,the key addr is place in key filed,and the space is 8byte.
*/

static long cdev_csec_ioctl2(struct file *filp, unsigned int cmd, unsigned long arg)
{
	unsigned char cmd_nr;
	unsigned char cmd_dir;
	int size,size2;
	struct csec_priv_t *csec_priv;
	struct ccore_cards_t *ccore_cards;
	struct crypto_api *cry_api = NULL,*cry_api_raw =NULL;
	dma_addr_t mem_phy_addr;
	struct fpd_st *fpd;
	struct result *done_op;

	unsigned char *cmpbuf;
	int status;

	int timeout;

	struct cipher_api *capi_class2;
	int ret;

	cmpbuf = kmalloc(CSEC_MAX_COMP,GFP_KERNEL);

	done_op = kzalloc(sizeof(struct result),GFP_KERNEL);
	if(!done_op)
	{
		csec_error(KERN_INFO "done_op kzalloc error\n");
		return -ENOMEM;
	}

	csec_debug(KERN_INFO "cdev_csec_ioctl is called\n");
	
	fpd = filp->private_data;
	if (_IOC_TYPE(cmd) != CCP903T_PCIE_MAGIC)
	{
		csec_error(KERN_ERR "error dev ioctl cmd\n");
		return -EINVAL;
	}
	cmd_nr = _IOC_NR(cmd);
	cmd_dir = _IOC_DIR(cmd);
	size = _IOC_SIZE(cmd);
	size2 = size;
	csec_debug(KERN_INFO "ioctl size is 0x%x\n",size);


	ccore_cards = fpd->ccore_cards;

	cry_api_raw =(struct crypto_api *) kmalloc(size+DATA_MARGIN,GFP_KERNEL|SYS_DMA);
	
	if(!cry_api_raw)
	{
		csec_error(KERN_INFO "cry_api_raw kmalloc error\n");
		return -ENOMEM;
	}
	
	cry_api =(struct crypto_api *) (((size_t)cry_api_raw+DATA_MARGIN)&(~(DATA_MARGIN-1)));
	//csec_debug(KERN_INFO "cry_api is %llx\n",(size_t )cry_api);
	
	if(!arg)
	{
		csec_error(KERN_INFO "no arg from app!\n");
		return -EINVAL;
	}
	
	copy_from_user((void *)cry_api, (void *)arg, size);   

	//sec_dump((void *)cry_api,size);
	//print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET, 32, 1, cry_api, size, false);
	csec_priv = cards_enqueue_pre(ccore_cards);

	if(cmd_nr == PCI_DMA_COMMUNICATE)
	{
		copy_from_user(csec_priv->cmd_buf, arg, size);  
		ret = host_to_cards_write(csec_priv, csec_priv->cmd_buf, size,
								csec_priv->cmd_buf, size);
		if(ret) {
			csec_error(KERN_INFO "host_to_cards_write function works incorrect!\n");
			return -EINVAL;
		}

		memset(csec_priv->cmd_buf, 0, size);

		ret = host_from_cards_read(csec_priv, csec_priv->cmd_buf, size,
								csec_priv->cmd_buf, size);
		if(ret) {
			csec_error(KERN_INFO "host_from_cards_read works incorrect!\n");
			return -EINVAL;
		}

		copy_to_user(arg, csec_priv->cmd_buf, size); 
			
		goto SM2_FT;
	}
	if(cmd_nr == ACLASS_CIPHER)
	{
		memcpy(cmpbuf,(u8 *)cry_api+size-cry_api->capi.iv_len,cry_api->capi.iv_len);
	}
	if(cmd_nr == ACLASS_HASH)
	{
		if(cry_api->capi.key_len & 0x80000000)
		{
			memcpy(cmpbuf,(u8 *)cry_api+ 8 + 16,cry_api->capi.iv_len);
		}else
		{
		 	memcpy(cmpbuf,(u8 *)cry_api+cry_api->capi.key_len + 16,cry_api->capi.iv_len);
		}
		
	}
	if(cmd_nr == ACLASS_SNOOP)
	{
		capi_class2 = (struct cipher_api *)( (u8 *)cry_api + 16 );
		memcpy(cmpbuf,(u8 *)cry_api+size-cry_api->capi.iv_len-get_icv_len(capi_class2->alg),cry_api->capi.iv_len);
	}
	
	mem_phy_addr = dma_map_single(csec_priv->dev,(void *)(&cry_api->capi),size, DMA_BIDIRECTIONAL);
	cdev_csec_do(csec_priv,cry_api,mem_phy_addr,size,cmd_nr,done_op);

	if(cmd_nr == ACLASS_CIPHER)
        {
		timeout=CMP_TOUT;
                do{
			dma_sync_single_for_cpu(csec_priv->dev,mem_phy_addr ,size,DMA_BIDIRECTIONAL);
                        status = memcmp(cmpbuf,(u8 *)cry_api+size-cry_api->capi.iv_len,cry_api->capi.iv_len);
			timeout--;
                }while((!status) && timeout);
		if(!timeout)
			csec_error(KERN_ERR "ioctl2: cipher maybe error!\n");
        }
        else if(cmd_nr == ACLASS_HASH)
        {
		timeout=CMP_TOUT;
                do{
			dma_sync_single_for_cpu(csec_priv->dev,mem_phy_addr ,size,DMA_BIDIRECTIONAL);
			if(cry_api->capi.key_len&0x80000000)
                     		status = memcmp(cmpbuf,(u8 *)cry_api + sizeof(struct cipher_api) + 8,cry_api->capi.iv_len);
                     	else	
				status = memcmp(cmpbuf,(u8 *)cry_api + sizeof(struct cipher_api) + cry_api->capi.key_len,cry_api->capi.iv_len);
			timeout--;
		  }
                while((!status) && timeout);
		if(!timeout)
			csec_error(KERN_ERR "ioctl2: hash maybe error!\n");
	}
	else if(cmd_nr == ACLASS_SNOOP)
        {
		timeout=CMP_TOUT;
                do{
			dma_sync_single_for_cpu(csec_priv->dev,mem_phy_addr ,size,DMA_BIDIRECTIONAL);
                        status = memcmp(cmpbuf,(u8 *)cry_api+size-cry_api->capi.iv_len-get_icv_len(capi_class2->alg),cry_api->capi.iv_len);
			timeout--;
                }while((!status) && timeout);
		if(!timeout)
			csec_error(KERN_ERR "ioctl2: cipher maybe error!\n");
	}else
	{
		dma_sync_single_for_cpu(csec_priv->dev,mem_phy_addr ,size,DMA_BIDIRECTIONAL);
	}
	
	if(cmd_nr == ACLASS_PKHA)
	{
		cry_api->papi.mode |= PKHA_DONE_MASK;

		if(done_op->rst !=0)
			cry_api->papi.mode |= PKHA_ERR_MASK;

		dma_sync_single_for_cpu(csec_priv->dev,mem_phy_addr ,size,DMA_BIDIRECTIONAL);
		copy_to_user((void *)arg,(void *)cry_api, size); 
	}
	else if((cmd_nr >= ACLASS_RSA_PUB) &&(cmd_nr <= ACLASS_RSA_PRIV_BIG))
	{
		cry_api->papi.mode |= PKHA_DONE_MASK;

		if(done_op->rst !=0)
			cry_api->papi.mode |= PKHA_ERR_MASK;

		dma_sync_single_for_cpu(csec_priv->dev,mem_phy_addr ,size,DMA_BIDIRECTIONAL);
		copy_to_user((void *)arg,(void *)cry_api, size); 
	}
	else if(cmd_nr == ACLASS_RSCP_CIPHER || cmd_nr == ACLASS_RSCP_HASH)
	{
		copy_to_user((void *)arg,(void *)cry_api, size); 
	}
	else if(cmd_nr>=ACLASS_SM2_ENCRYPT && cmd_nr<=ACLASS_SM2_SIGNATURE_NOID_SEED)
	{
		cry_api->smapi.field = 0;

		if(done_op->rst !=0)
			cry_api->smapi.field = done_op->rst;

		copy_to_user((void *)arg,(void *)cry_api, size); 
	}else if(cmd_nr==ACLASS_RSA_GENKEY )
	{
		cry_api->rsaapi.field = 0;

		if(done_op->rst !=0)
			cry_api->rsaapi.field = done_op->rst;

		dma_sync_single_for_cpu(csec_priv->dev,mem_phy_addr ,size,DMA_BIDIRECTIONAL);
		copy_to_user((void *)arg,(void *)cry_api, size); 
	}
	else
	{
	cry_api->capi.opt |= DONE_MASK;

	if(done_op->rst !=0)
		cry_api->capi.opt |= ST_ERR;
	
	if((cmd_nr & ACLASS_MASK) == ACLASS_HASH)
	{
		if(cry_api->capi.key_len&0x80000000)
			size = sizeof(struct cipher_api )+ 8 +cry_api->capi.iv_len;
		else	
			size = sizeof(struct cipher_api )+ cry_api->capi.key_len+cry_api->capi.iv_len;
	}
		
	if((cmd_nr & ACLASS_MASK) == ACLASS_SNOOP && done_op->rst !=0)
		copy_to_user((void *)arg,(void *)cry_api, 4); 
	else 
 		copy_to_user((void *)arg,(void *)cry_api, size); 
	}

	//sec_dump(cry_api,size);
	dma_unmap_single(csec_priv->dev,mem_phy_addr,size2,DMA_BIDIRECTIONAL);
	
SM2_FT:
	kfree(done_op);
	kfree(cry_api_raw);
	kfree(cmpbuf);

	csec_debug(KERN_INFO "cdev_csec_ioctl kfree desc and desc_ext here\n!");

	return 0;
}

struct file_operations cdev_csec_fops =
{
	.owner = THIS_MODULE,
	.read = cdev_csec_read,
	.open = cdev_csec_open,
	.release = cdev_csec_release,
	.write = cdev_csec_write,
	.llseek = cdev_csec_llseek,
	.unlocked_ioctl = cdev_csec_ioctl2,
};

static int __init cdev_csec_init(void)
{
	int ret;
	struct ccore_cards_t *ccore_cards;
	ccore_cards = get_ccore_cards();
	
	cdev_init(&(ccore_cards->cdev), &cdev_csec_fops);
	ccore_cards->cdev.owner = THIS_MODULE;

	if (!!(ret = alloc_chrdev_region(&(ccore_cards->dev_no), 0, 1, "csec's pcie devices"))) {
		csec_error(KERN_INFO "pci_csec_probe: failed to do alloc_chrdev_region\n");
		goto err_alloc_chrdev;
	}
	if (!!(ret = cdev_add(&(ccore_cards->cdev), ccore_cards->dev_no, 1))) {
		csec_error(KERN_INFO "pci_csec_probe: failed to do cdev_add\n");
		goto err_cdev_add;
	}

	ccore_cards->csec_classp = class_create(THIS_MODULE, CSEC_DEV_NAME);
	ccore_cards->csec_class_devp = device_create(ccore_cards->csec_classp, NULL, ccore_cards->dev_no, NULL, CSEC_DEV_NAME);  
	
	csec_debug(KERN_INFO "ccp903_cards_init: major = %u, minor = %u\n", (unsigned int) (MAJOR(ccore_cards->dev_no)), (unsigned int) (MINOR(ccore_cards->dev_no)));

	return 0;

err_cdev_add:

	unregister_chrdev_region(ccore_cards->dev_no, 1);

err_alloc_chrdev:
	return ret;
}

static void __exit cdev_csec_remove(void)
{
	struct ccore_cards_t *ccore_cards;
	ccore_cards = get_ccore_cards();	
	device_destroy(ccore_cards->csec_classp, ccore_cards->dev_no);
   	class_destroy(ccore_cards->csec_classp);
	cdev_del(&ccore_cards->cdev);
	unregister_chrdev_region(ccore_cards->dev_no, 1);
	return ;
}

module_init(cdev_csec_init);
module_exit(cdev_csec_remove);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ccore support for cdev API");
MODULE_AUTHOR("zjjin@ccore.com");

