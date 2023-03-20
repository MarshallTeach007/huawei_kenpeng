#include "../INCLUDE/compate.h"
#include "../INCLUDE/pci_csec.h"
#include "../INCLUDE/desc.h"
#include "../INCLUDE/desc_constr.h"

extern void inline_cnstr_jobdesc_cipher_core(uint32_t *desc,struct cipher_core *cipher);
extern void inline_cnstr_jobdesc_cipher_sg_core(struct csec_priv_t *csec_priv,uint32_t *desc,struct cipher_core *cipher);
extern void inline_cnstr_jobdesc_hash_core(uint32_t *desc,struct cipher_core *cipher);


void inline_cnstr_jobdesc_cipher(uint32_t *desc,struct cipher_api *capi,dma_addr_t mem_addr,dma_addr_t  extern_key_addr)
{

	struct cipher_core cipher;

	//csec_debug(KERN_INFO "inline_cnstr_jobdesc_cipher is called\n");

	cipher.alg = capi->alg;
	cipher.as = capi->as;
	cipher.opt = capi->opt;
	cipher.type = capi->type;
		
	if( (capi->key_len)&0x80000000)
	{
		cipher.key_addr = extern_key_addr;
		cipher.key_len = capi->key_len&0xffff;
		cipher.iv_addr = mem_addr+ sizeof(struct cipher_api ) + 8;
		cipher.iv_len = capi->iv_len;
	}else
	{

		cipher.key_addr = mem_addr+sizeof(struct cipher_api );
		cipher.key_len = capi->key_len&0xffff;
		cipher.iv_addr = cipher.key_addr + cipher.key_len;
		cipher.iv_len = capi->iv_len;
	}
	
	cipher.data_addr = cipher.iv_addr+cipher.iv_len;
	cipher.data_len = capi->data_len;

	 inline_cnstr_jobdesc_cipher_core(desc,&cipher);

}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_cipher);

void inline_cnstr_jobdesc_hash(uint32_t *desc,struct cipher_api *capi,dma_addr_t mem_addr,dma_addr_t extern_key_addr)
{
	struct cipher_core cipher;

	//csec_debug(KERN_INFO "inline_cnstr_jobdesc_cipher is called\n");
	cipher.alg = capi->alg;
	cipher.as = capi->as;
	cipher.opt = capi->opt;
	cipher.type = capi->type;
	if( (capi->key_len)&0x80000000)
	{
		cipher.key_addr = extern_key_addr;
		cipher.key_len = capi->key_len&0xffff;
		cipher.iv_addr = mem_addr+ sizeof(struct cipher_api ) + 8;
		cipher.iv_len = capi->iv_len;
	}else
	{

		cipher.key_addr = mem_addr+sizeof(struct cipher_api );
		cipher.key_len = capi->key_len&0xffff;
		cipher.iv_addr = cipher.key_addr + cipher.key_len;
		cipher.iv_len = capi->iv_len;
	}
	
	cipher.data_addr = cipher.iv_addr+cipher.iv_len;
	cipher.data_len = capi->data_len;

	inline_cnstr_jobdesc_hash_core(desc,&cipher);

	//sec_dump(desc,MAX_CSEC_DESCSIZE);

}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_hash);

int inline_cnstr_jobdesc_cipher_sg(struct csec_priv_t *csec_priv,uint32_t *desc,struct cipher_api *capi,dma_addr_t mem_addr,void **sg_raw,dma_addr_t *sg_phy_addr_p,dma_addr_t extern_key_addr)	//max sg nums is 16
{
	struct cipher_core cipher;

	//csec_debug(KERN_INFO "inline_cnstr_jobdesc_cipher is called\n");

	cipher.alg = capi->alg;
	cipher.as = capi->as;
	cipher.opt = capi->opt;
	cipher.type = capi->type;

	if( (capi->key_len)&0x80000000)
	{
		cipher.key_addr = extern_key_addr;
		cipher.key_len = capi->key_len&0xffff;
		cipher.iv_addr = mem_addr+ sizeof(struct cipher_api ) + 8;
		cipher.iv_len = capi->iv_len;
	}else
	{
		cipher.key_addr = mem_addr+sizeof(struct cipher_api );
		cipher.key_len = capi->key_len&0xffff;
		cipher.iv_addr = cipher.key_addr + cipher.key_len;
		cipher.iv_len = capi->iv_len;
	}
	
	cipher.data_addr = *sg_phy_addr_p;
	cipher.data_len = capi->data_len;

	inline_cnstr_jobdesc_cipher_sg_core(csec_priv,desc,&cipher);
	//sec_dump(desc,MAX_CSEC_DESCSIZE);
	return 0;

}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_cipher_sg);

int _inline_cnstr_jobdesc_cipher_sg(struct csec_priv_t *csec_priv,uint32_t *desc,struct cipher_api *capi,dma_addr_t mem_addr,void **sg_virt,dma_addr_t *sg_phy,dma_addr_t extern_key_addr)
{
	struct sg_entry *sg_table;
	int sg_len,fsg_maxlen;
	dma_addr_t sg_addr;
	int rev_len,i=0;
	dma_addr_t sgt_phy_addr;
	
	*sg_virt = (struct sg_entry *)kmalloc(SGMAX*16 + DATA_MARGIN,GFP_KERNEL|SYS_DMA);
	if (!sg_virt) {
		csec_error(KERN_INFO "inline_cnstr_jobdesc_cipher_sg: sg_raw mem error\n");
		return -ENOMEM;
	}
	sg_table = (struct sg_entry *) (((size_t)*sg_virt+DATA_MARGIN)&(~(DATA_MARGIN-1)));
	if(capi->key_len&0x80000000)
	{
		sg_addr = mem_addr + 16 +8 + capi->iv_len;
		fsg_maxlen = SIZE4KI-16-8-capi->iv_len;
	}else
	{
		sg_addr = mem_addr + 16 + capi->key_len + capi->iv_len;
		fsg_maxlen = SIZE4KI-16-capi->key_len-capi->iv_len;
	}
	fsg_maxlen &= 0xfffffff0;

	rev_len = capi->data_len;

	while(rev_len)
	{
		if(i==0)
		{
			sg_len = (rev_len < fsg_maxlen)?rev_len:(fsg_maxlen);
		}else
		{
			sg_len = (rev_len < SIZE4KI)?rev_len: SIZE4KI;
		}
		rev_len -= sg_len;
		sg_table[i].addr_hi = change_addr_for_sec(sg_addr) & 0xffffffff;
		sg_table[i].addr_lo= change_addr_for_sec(sg_addr) >> 32;
		sg_table[i].len_flag = sg_len & SG_ENTRY_LENGTH_MASK;
		sg_table[i].bpid_offset = 0;

		if(rev_len<=0)
		{
			sg_table[i].len_flag |= SG_ENTRY_FINAL_BIT;
		}
		sg_addr += sg_len;
		i++;
	}

	//sec_dump(sg_table,64);

	sgt_phy_addr = dma_map_single(csec_priv->dev,(void *)sg_table,SGMAX*16, DMA_TO_DEVICE);

	*sg_phy = sgt_phy_addr;

	inline_cnstr_jobdesc_cipher_sg(csec_priv,desc,capi,mem_addr,sg_virt,sg_phy,extern_key_addr);
	return 0;
}
EXPORT_SYMBOL_GPL(_inline_cnstr_jobdesc_cipher_sg);
