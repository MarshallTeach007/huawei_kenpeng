/***************************************************
 * job.c
 *
 * Created on: Mar 20, 2017
 * Author: zjjin@ccore.com
 ***************************************************/

#include "../INCLUDE/compate.h"
#include "../INCLUDE/pci_csec.h"
#include "../INCLUDE/jr.h"
#include "../INCLUDE/sec.h"
#include "../INCLUDE/desc.h"
#include "../INCLUDE/desc_constr.h"
#include "../INCLUDE/rsa_job.h"
#include "../INCLUDE/sm2_job.h"
#include "../INCLUDE/sm9.h"

void noprintk(const char *fmt,...)
{
}

EXPORT_SYMBOL_GPL(noprintk);

dma_addr_t change_addr_for_sec(dma_addr_t addr)
{
	return (addr+PCIE_AREA_OFF);
}
EXPORT_SYMBOL_GPL(change_addr_for_sec);

dma_addr_t change_addr_for_cpu(dma_addr_t addr)
{
	return (addr-PCIE_AREA_OFF);
}
EXPORT_SYMBOL_GPL(change_addr_for_cpu);


void inline_cnstr_jobdesc_cipher_core(uint32_t *desc,struct cipher_core *cipher)
{

	u32 options;
	u32 store_ops;

	//csec_debug(KERN_INFO "inline_cnstr_jobdesc_cipher is called\n");
	//csec_debug(KERN_INFO "mem_addr is %llx,key_addr is %llx,iv_addr is %llx,data_addr is %llx\n",mem_addr,key_addr ,iv_addr ,data_addr );

	init_job_desc(desc, START_INDEX);

	append_key(desc, change_addr_for_sec(cipher->key_addr), cipher->key_len, CLASS_1 |
			KEY_DEST_CLASS_REG);

	append_cmd_ptr(desc, change_addr_for_sec(cipher->iv_addr),cipher->iv_len,CMD_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_1_CCB );

	append_operation(desc, OP_TYPE_CLASS1_ALG |
			 ((cipher->type)<<4) | //OP_ALG_AAI
			 ((cipher->alg)<<16)|		//OP_ALG
			 ((cipher->as)<<2) |
			 (cipher->opt&DIR_MASK) |( (cipher->opt&AAI_SK_MASK)?AAI_SK_SEL:0) <<4);

	options = LDST_CLASS_1_CCB | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1;
	store_ops = FIFOST_TYPE_MESSAGE_DATA;

	if(cipher->data_len > 0xffff)
	{
		options |= FIFOLDST_EXT;
		store_ops |= FIFOLDST_EXT;
		append_fifo_load(desc, change_addr_for_sec(cipher->data_addr), 0, options);
		append_cmd(desc,cipher->data_len);
		append_fifo_store(desc, change_addr_for_sec(cipher->data_addr), 0, store_ops);
		append_cmd(desc,cipher->data_len);
	}else
	{
		append_fifo_load(desc, change_addr_for_sec(cipher->data_addr), cipher->data_len, options);
		append_fifo_store(desc, change_addr_for_sec(cipher->data_addr), cipher->data_len, store_ops);
	}
	
	append_store(desc, change_addr_for_sec(cipher->iv_addr), cipher->iv_len, LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);

	//sec_dump(desc,MAX_CSEC_DESCSIZE);

}

EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_cipher_core);


int inline_cnstr_jobdesc_cipher_sg_core(struct csec_priv_t *csec_priv,uint32_t *desc,struct cipher_core *cipher)	//max sg nums is 16
{

	u32 options;
	u32 store_ops;

	init_job_desc(desc, START_INDEX);

	append_key(desc, change_addr_for_sec(cipher->key_addr), cipher->key_len, CLASS_1 |
			KEY_DEST_CLASS_REG);

	append_cmd_ptr(desc, change_addr_for_sec(cipher->iv_addr),cipher->iv_len,CMD_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_1_CCB );

	append_operation(desc, OP_TYPE_CLASS1_ALG |
			 ((cipher->type)<<4) | //OP_ALG_AAI
			 ((cipher->alg)<<16)|		//OP_ALG
			 ((cipher->as)<<2) |
			 (cipher->opt&DIR_MASK) |( (cipher->opt&AAI_SK_MASK)?AAI_SK_SEL:0) <<4);

	options = LDST_CLASS_1_CCB | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1|FIFOLDST_SGF;
	store_ops = FIFOST_TYPE_MESSAGE_DATA|FIFOLDST_SGF;

	if(cipher->data_len > 0xffff)
	{
		options |= FIFOLDST_EXT;
		store_ops |= FIFOLDST_EXT;
		append_fifo_load(desc, change_addr_for_sec(cipher->data_addr), 0, options);
		append_cmd(desc,cipher->data_len);
		append_fifo_store(desc, change_addr_for_sec(cipher->data_addr), 0, store_ops);
		append_cmd(desc,cipher->data_len);
	}else
	{
		append_fifo_load(desc, change_addr_for_sec(cipher->data_addr), cipher->data_len, options);
		append_fifo_store(desc, change_addr_for_sec(cipher->data_addr), cipher->data_len, store_ops);
	}

	append_store(desc, change_addr_for_sec(cipher->iv_addr), cipher->iv_len, LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);
	
	//sec_dump(desc,MAX_CSEC_DESCSIZE);
	return 0;

}


EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_cipher_sg_core);

#if 0
void inline_cnstr_jobdesc_cipher_ccm(uint32_t *desc,struct cipher_ccm_api *ccapi,dma_addr_t mem_addr)
{

	u32 options;
	u32 store_ops;
	dma_addr_t data_addr;
	dma_addr_t iv_addr;
	dma_addr_t key_addr;
	dma_addr_t aad_addr;
	dma_addr_t icv_addr;

	//csec_debug(KERN_INFO "inline_cnstr_jobdesc_cipher is called\n");
		
	key_addr = mem_addr+sizeof(struct cipher_ccm_api );
	iv_addr = key_addr + ccapi->key_len;
	aad_addr = iv_addr+0x40;

	data_addr =  aad_addr + ccapi->aad_len;
	icv_addr = data_addr + 0x10;

	//csec_debug(KERN_INFO "mem_addr is %llx,key_addr is %llx,iv_addr is %llx,data_addr is %llx\n",mem_addr,key_addr ,iv_addr ,data_addr );

	init_job_desc(desc, START_INDEX);

	append_key(desc, change_addr_for_sec(key_addr), ccapi->key_len, CLASS_1 |
			KEY_DEST_CLASS_REG);

	append_cmd_ptr(desc, change_addr_for_sec(iv_addr),0x40,CMD_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_1_CCB );

	append_operation(desc, OP_TYPE_CLASS1_ALG |
			 ((0x80)<<4) | //OP_ALG_AAI	CCM
			 ((ccapi->alg)<<16)|		//OP_ALG
			 ((ccapi->as)<<2) |
			 ( (ccapi->opt) & DIR_MASK) |( ( ( (ccapi->opt) & DIR_MASK) == 0)?OP_ALG_ICV_ON:0)|
			 ( ( (ccapi->opt) & AAI_SK_MASK)?AAI_SK_SEL:0) <<4);


	options = LDST_CLASS_1_CCB | FIFOLD_TYPE_AAD;
	append_fifo_load(desc,change_addr_for_sec(aad_addr),ccapi->aad_len,options);

	options = LDST_CLASS_1_CCB | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1;
	store_ops = FIFOST_TYPE_MESSAGE_DATA;

	if(ccapi->data_len > 0xffff)
	{
		options |= FIFOLDST_EXT;
		store_ops |= FIFOLDST_EXT;
		append_fifo_load(desc, change_addr_for_sec(data_addr), 0, options);
		append_cmd(desc,ccapi->data_len);
		append_fifo_store(desc, change_addr_for_sec(data_addr), 0, store_ops);
		append_cmd(desc,ccapi->data_len);
	}else
	{
		append_fifo_load(desc, change_addr_for_sec(data_addr), ccapi->data_len, options);
		append_fifo_store(desc, change_addr_for_sec(data_addr), ccapi->data_len, store_ops);
	}
	

	if( ( (ccapi->opt) & DIR_MASK ) == 0)	//dec need load icv
	{
		append_cmd_ptr(desc,change_addr_for_sec(icv_addr),0x10,CMD_FIFO_LOAD|FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_LAST1 |FIFOLD_TYPE_ICV);
	}else
	{
		append_store(desc,change_addr_for_sec(icv_addr),0x10,LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);
	}

	append_store(desc, change_addr_for_sec(iv_addr), 0x40, LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);

	//sec_dump(desc,MAX_CSEC_DESCSIZE);

}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_cipher_ccm);
#endif
unsigned int hash_size(unsigned char alg)
{
	unsigned int hs;
	switch(alg)
	{
		case MD5:
			hs = 16;
			break;
		case SHA0:
		case SHA1:
			hs = 20;
			break;
		case SHA224:
			hs = 28;
			break;
		case SHA256:
		case SM3:
			hs = 32;
			break;
		case SHA384:
			hs = 48;
			break;
		case SHA512:
			hs = 64;
			break;
		default:
			hs = 16;
			break;
				
	}
	return hs;
}
EXPORT_SYMBOL_GPL(hash_size);

void inline_cnstr_jobdesc_hash_core(uint32_t *desc,struct cipher_core *cipher)
{
	u32 options;
	u32 store_ops;
	u32 clear_data;
	u32 store_len;

	//csec_debug(KERN_INFO "inline_cnstr_jobdesc_cipher is called\n");	

	clear_data = cpu_2_le32(0x01);

	init_job_desc(desc, START_INDEX);

	append_load_as_imm(desc,&clear_data,4,CMD_LOAD | LDST_SRCDST_WORD_CLRW | LDST_CLASS_IND_CCB);
	if(cipher->key_len)
	{
		append_key(desc, change_addr_for_sec(cipher->key_addr), cipher->key_len, CLASS_2 |
			KEY_DEST_CLASS_REG);
	}
	if(cipher->iv_len)
	{
		append_cmd_ptr(desc, change_addr_for_sec(cipher->iv_addr),cipher->iv_len,CMD_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_2_CCB );
	}

	append_operation(desc, OP_TYPE_CLASS2_ALG |
			 ((cipher->type)<<4) | //OP_ALG_AAI
			 ((cipher->alg)<<16)|		//OP_ALG
			 ((cipher->as)<<2) |
			 (cipher->opt&DIR_MASK) |( (cipher->opt&HSUB_MASK)?HSUB_SEL:0) << 4 );

	options = LDST_CLASS_2_CCB | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2;
	store_ops = FIFOST_TYPE_MESSAGE_DATA;

	if(cipher->data_len > 0xffff)
	{
		options |= FIFOLDST_EXT;
		append_fifo_load(desc, change_addr_for_sec(cipher->data_addr), 0, options);
		append_cmd(desc,cipher->data_len);
	}else{

		append_fifo_load(desc, change_addr_for_sec(cipher->data_addr), cipher->data_len, options);
	}

	store_len = cipher->iv_len;

	append_store(desc, change_addr_for_sec(cipher->iv_addr), store_len,
		     LDST_CLASS_2_CCB | LDST_SRCDST_BYTE_CONTEXT);

	//sec_dump(desc,MAX_CSEC_DESCSIZE);

}

EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_hash_core);

#if 0
int inline_cnstr_jobdesc_hash_sg(struct csec_priv_t *csec_priv,uint32_t *desc,struct cipher_api *capi,dma_addr_t mem_addr,void **sg_raw)
{

	u32 options;
	dma_addr_t data_addr;
	dma_addr_t iv_addr;
	dma_addr_t key_addr;
	u32 store_len;
	u32 clear_data;

	int rev_len,sg_len,fsg_maxlen,i=0;

	dma_addr_t sg_addr;
	dma_addr_t sgt_phy_addr;

	struct sg_entry *sg_table;

	clear_data = cpu_2_le32(0x01);
	*sg_raw = (struct sg_entry *)kmalloc(SGMAX*16 + DATA_MARGIN,GFP_KERNEL|SYS_DMA);
	if(!sg_raw)
	{
		csec_error(KERN_ERR "inline_cnstr_jobdesc_hash_sg: sg_raw mem err!\n");
		return -ENOMEM;
	}
	sg_table = (struct sg_entry *) (((size_t)*sg_raw+DATA_MARGIN)&(~(DATA_MARGIN-1)));

	//csec_debug(KERN_INFO "inline_cnstr_jobdesc_cipher is called\n");	
	
	key_addr = mem_addr+sizeof(struct cipher_api );
	iv_addr = key_addr + capi->key_len;
	data_addr = iv_addr+capi->iv_len;

	rev_len = capi->data_len;
	sg_addr = mem_addr + 16 + capi->key_len + capi->iv_len;
	fsg_maxlen = SIZE4KI-16-capi->key_len-capi->iv_len;
	fsg_maxlen &= 0xffffffc0;
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

	//csec_debug(KERN_INFO "mem_addr is %llx,key_addr is %llx,iv_addr is %llx,data_addr is %llx\n",mem_addr,key_addr ,iv_addr ,data_addr );

	sgt_phy_addr = dma_map_single(csec_priv->dev,(void *)sg_table,SGMAX*16, DMA_TO_DEVICE);

	init_job_desc(desc, START_INDEX);

	append_load_as_imm(desc,&clear_data,4,CMD_LOAD | LDST_SRCDST_WORD_CLRW | LDST_CLASS_IND_CCB);

	if(capi->key_len)
	{
		append_key(desc, change_addr_for_sec(key_addr), capi->key_len, CLASS_2 |
			KEY_DEST_CLASS_REG);
	}
	if(capi->iv_len)
	{
		append_cmd_ptr(desc, change_addr_for_sec(iv_addr),capi->iv_len,CMD_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_2_CCB );
	}

	append_operation(desc, OP_TYPE_CLASS2_ALG |
			 ((capi->type)<<4) | //OP_ALG_AAI
			 ((capi->alg)<<16)|		//OP_ALG
			 ((capi->as)<<2) |
			 (capi->opt&DIR_MASK)|( (capi->opt&HSUB_MASK)?HSUB_SEL:0) << 4 );

	options = LDST_CLASS_2_CCB | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2|FIFOLDST_SGF;

	if(capi->data_len > 0xffff)
	{
		options |= FIFOLDST_EXT;
		append_fifo_load(desc, change_addr_for_sec(sgt_phy_addr), 0, options);
		append_cmd(desc,capi->data_len);
	}else{

		append_fifo_load(desc, change_addr_for_sec(sgt_phy_addr), capi->data_len, options);
	}

	store_len = capi->iv_len;

	append_store(desc, change_addr_for_sec(iv_addr), store_len,
		     LDST_CLASS_2_CCB | LDST_SRCDST_BYTE_CONTEXT);

	dma_unmap_single(csec_priv->dev,sgt_phy_addr,SGMAX*16,DMA_TO_DEVICE);

	//sec_dump(desc,MAX_CSEC_DESCSIZE);
	return 0;

}
#else
int inline_cnstr_jobdesc_hash_sg(struct csec_priv_t *csec_priv,uint32_t *desc,struct cipher_api *capi,dma_addr_t mem_addr,void **sg_raw)
{
	return 0;
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_hash_sg);
#endif


u32 get_icv_len(u8 alg)
{
	switch(alg)
	{
		case 0x40:
			return 16;
		case 0x41:
			return 20;
		case 0x42:
			return 28;
		case 0x43:
			return 32;
		case 0x44:
			return 48;
		case 0x45:
			return 64;
		case 0x46:
			return 20;
		case 0x47:
			return 32;
		default:
			return 0;
		
	}
}
EXPORT_SYMBOL_GPL(get_icv_len);

void inline_cnstr_jobdesc_snoop_core(uint32_t *desc,struct cipher_core *ciphercore)
{
	u32 options;
	u32 store_ops;
	struct cipher_core *ciphercore_class1,*ciphercore_class2;
	u32 icv_len;

	//csec_debug(KERN_INFO "inline_cnstr_jobdesc_cipher is called\n");

	/////////////////////////////////////////////////////////////////////////////////////////
	// mem = cipher_api_class1 |-| cipher_api_class2 |-| key_class1 |-| key_class2 |-| iv |-| data |-| icv
	//
	//cipher_api_class1 has class1 alg,type,as,opt,key_len, and iv_len,data_len for both class1,2
	//cipher_api_class2 has class2 alg,type,as,opt,key_len
	//iv area is iv for class1 while input data for class2,like ipsec
	/////////////////////////////////////////////////////////////////////////////////////////
	

	ciphercore_class1 = ciphercore;
	ciphercore_class2 = (struct cipher_core *)&ciphercore[1];

	//csec_debug(KERN_INFO "mem_addr is %llx,key_addr is %llx,iv_addr is %llx,data_addr is %llx\n",mem_addr,key_addr ,iv_addr ,data_addr );

	init_job_desc(desc, START_INDEX);

	append_key(desc, change_addr_for_sec(ciphercore_class1->key_addr), ciphercore_class1->key_len , CLASS_1 |
			KEY_DEST_CLASS_REG);	

	append_key(desc, change_addr_for_sec(ciphercore_class2->key_addr), ciphercore_class2->key_len , CLASS_2 |
			KEY_DEST_CLASS_REG);	

	append_cmd_ptr(desc, change_addr_for_sec(ciphercore_class1->iv_addr),ciphercore_class1->iv_len,CMD_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_1_CCB );

	if(ciphercore_class2->opt&DIR_MASK)
	{
		append_operation(desc, OP_TYPE_CLASS2_ALG |
			 ((ciphercore_class2->type)<<4) | //OP_ALG_AAI
			 ((ciphercore_class2->alg)<<16)|		//OP_ALG
			 ((ciphercore_class2->as)<<2) |
			 (ciphercore_class2->opt&DIR_MASK)); 
	}else
	{
		append_operation(desc, OP_TYPE_CLASS2_ALG |
			 ((ciphercore_class2->type)<<4) | //OP_ALG_AAI
			 ((ciphercore_class2->alg)<<16)|		//OP_ALG
			 ((ciphercore_class2->as)<<2) |
			 (ciphercore_class2->opt&DIR_MASK)|OP_ALG_ICV_ON);
	}	

	append_operation(desc, OP_TYPE_CLASS1_ALG |
			 ((ciphercore_class1->type)<<4) | //OP_ALG_AAI
			 ((ciphercore_class1->alg)<<16)|		//OP_ALG
			 ((ciphercore_class1->as)<<2) |
			 (ciphercore_class1->opt&DIR_MASK) |( (ciphercore_class1->opt&AAI_SK_MASK)?AAI_SK_SEL:0) );

	//append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_CLASS2INFIFO | capi_class1->iv_len);	

	icv_len = get_icv_len(ciphercore_class2->alg);

	if(ciphercore_class2->opt&DIR_MASK)		//enc ,fifo load not include icv
	{
		options = FIFOLD_CLASS_BOTH | FIFOLD_TYPE_MSG1OUT2 | FIFOLD_TYPE_LASTBOTH;
		store_ops = FIFOST_TYPE_MESSAGE_DATA;
		if(ciphercore_class1->data_len > 0xffff)
		{
			options |= FIFOLDST_EXT;
			store_ops |= FIFOLDST_EXT;
			append_fifo_load(desc, change_addr_for_sec(ciphercore_class1->data_addr), 0, options);
			append_cmd(desc,ciphercore_class1->data_len);
			append_fifo_store(desc, change_addr_for_sec(ciphercore_class1->data_addr), 0, store_ops);
			append_cmd(desc,ciphercore_class1->data_len);
		}else
		{
			append_fifo_load(desc, change_addr_for_sec(ciphercore_class1->data_addr), ciphercore_class1->data_len, options);
			append_fifo_store(desc, change_addr_for_sec(ciphercore_class1->data_addr), ciphercore_class1->data_len, store_ops);
		}
		append_store(desc, change_addr_for_sec(ciphercore_class2->data_addr),icv_len,LDST_CLASS_2_CCB | LDST_SRCDST_BYTE_CONTEXT);
	}else
	{
		options = FIFOLD_CLASS_BOTH | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LASTBOTH;
		store_ops = FIFOST_TYPE_MESSAGE_DATA;
		if(ciphercore_class1->data_len > 0xffff)
		{
			options |= FIFOLDST_EXT;
			store_ops |= FIFOLDST_EXT;
			append_fifo_load(desc, change_addr_for_sec(ciphercore_class1->data_addr), 0, options);
			append_cmd(desc,ciphercore_class1->data_len);
			append_fifo_store(desc, change_addr_for_sec(ciphercore_class1->data_addr), 0, store_ops);
			append_cmd(desc,ciphercore_class1->data_len);
		}else
		{
			append_fifo_load(desc, change_addr_for_sec(ciphercore_class1->data_addr), ciphercore_class1->data_len, options);
			append_fifo_store(desc, change_addr_for_sec(ciphercore_class1->data_addr), ciphercore_class1->data_len, store_ops);
		}
		append_fifo_load(desc,change_addr_for_sec(ciphercore_class2->data_addr),icv_len, FIFOLD_CLASS_CLASS2 |
			     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_ICV);
	}
	//sec_dump(desc,MAX_CSEC_DESCSIZE);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_snoop_core);

void inline_cnstr_jobdesc_snoop_sp(uint32_t *desc,struct cipher_core *ciphercore)
{
	u32 options=0;
	u32 store_ops;
	struct cipher_core *ciphercore_class1,*ciphercore_class2;

	//csec_debug(KERN_INFO "inline_cnstr_jobdesc_cipher is called\n");

	/////////////////////////////////////////////////////////////////////////////////////////
	// mem = cipher_api_class1 |-| cipher_api_class2 |-| key_class1 |-| key_class2 |-| iv |-| data |-| icv
	//
	//cipher_api_class1 has class1 alg,type,as,opt,key_len, and iv_len,data_len for both class1,2
	//cipher_api_class2 has class2 alg,type,as,opt,key_len
	//iv area is iv for class1 while input data for class2,like ipsec
	/////////////////////////////////////////////////////////////////////////////////////////
	

	ciphercore_class1 = ciphercore;
	ciphercore_class2 = (struct cipher_core *)&ciphercore[1];

	//csec_debug(KERN_INFO "mem_addr is %llx,key_addr is %llx,iv_addr is %llx,data_addr is %llx\n",mem_addr,key_addr ,iv_addr ,data_addr );

	init_job_desc(desc, START_INDEX);

	if(ciphercore_class1->data_len > 0xffff)
	{
		options |= FIFOLDST_EXT;
		store_ops |= FIFOLDST_EXT;
		append_seq_in_ptr(desc,  change_addr_for_sec(ciphercore_class2->data_addr),0, options);
		append_cmd(desc,ciphercore_class2->data_len); 
		append_seq_out_ptr(desc, change_addr_for_sec(ciphercore_class1->data_addr), 0,store_ops);
		append_cmd(desc,ciphercore_class1->data_len);
	}else
	{
		append_seq_in_ptr(desc,  change_addr_for_sec(ciphercore_class2->data_addr),ciphercore_class2->data_len, options);
		append_seq_out_ptr(desc, change_addr_for_sec(ciphercore_class1->data_addr), ciphercore_class1->data_len,store_ops);
	}

	if(ciphercore_class1->key_len)
		append_key(desc, change_addr_for_sec(ciphercore_class1->key_addr), ciphercore_class1->key_len , CLASS_1 |
			KEY_DEST_CLASS_REG);	

	if(ciphercore_class2->key_len)
	append_key(desc, change_addr_for_sec(ciphercore_class2->key_addr), ciphercore_class2->key_len , CLASS_2 |
			KEY_DEST_CLASS_REG);	

	if(ciphercore_class1->iv_len)
		append_cmd_ptr(desc, change_addr_for_sec(ciphercore_class1->iv_addr),ciphercore_class1->iv_len,CMD_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_1_CCB );

	if(ciphercore_class2->iv_len)
		append_cmd_ptr(desc, change_addr_for_sec(ciphercore_class2->iv_addr),ciphercore_class2->iv_len,CMD_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_2_CCB );


	append_operation(desc, OP_TYPE_CLASS2_ALG |
			 ((ciphercore_class2->type)<<4) | //OP_ALG_AAI
			 ((ciphercore_class2->alg)<<16)|		//OP_ALG
			 ((ciphercore_class2->as)<<2) |
			 (ciphercore_class2->opt&DIR_MASK)); 


	append_operation(desc, OP_TYPE_CLASS1_ALG |
			 ((ciphercore_class1->type)<<4) | //OP_ALG_AAI
			 ((ciphercore_class1->alg)<<16)|		//OP_ALG
			 ((ciphercore_class1->as)<<2) |
			 (ciphercore_class1->opt&DIR_MASK) |( (ciphercore_class1->opt&AAI_SK_MASK)?AAI_SK_SEL:0) );

	append_math_sub(desc, REG0, REG3, REG3, CSEC_CMD_SZ);
	
	/* REG3 = cryptlen */	
	append_math_sub_imm_u32(desc, REG3, SEQOUTLEN, IMM,0);

	/* REG2 = assoclen + cryptlen*/
	append_math_sub_imm_u32(desc, REG2, SEQINLEN, IMM,0);
	
	/* assoclen = seqinlen - cryptlen */
	append_math_sub(desc, VARSEQINLEN, REG2, REG3, CSEC_CMD_SZ);

	//append_move(desc, MOVE_SRC_MATH0 | MOVE_DEST_MATH1 | 4 |MOVE_WAITCOMP);

	append_seq_fifo_load(desc, 0, FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG |
			     KEY_VLF);

	append_math_sub(desc, VARSEQINLEN, REG3, REG0, CSEC_CMD_SZ);
	append_math_sub(desc, VARSEQOUTLEN, REG3, REG0, CSEC_CMD_SZ);

	if(ciphercore_class2->opt&DIR_MASK)		//enc ,fifo load not include icv
	{
		options = FIFOLD_CLASS_BOTH | FIFOLD_TYPE_MSG1OUT2 | FIFOLD_TYPE_LASTBOTH | KEY_VLF;

	}else
	{
		options = FIFOLD_CLASS_BOTH | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LASTBOTH| KEY_VLF;
	}
	store_ops = FIFOST_TYPE_MESSAGE_DATA| KEY_VLF;

	append_seq_fifo_load(desc, 0, options);
	append_seq_fifo_store(desc, 0, store_ops);

	append_store(desc, change_addr_for_sec(ciphercore_class2->iv_addr),ciphercore_class2->iv_len,LDST_CLASS_2_CCB | LDST_SRCDST_BYTE_CONTEXT);

}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_snoop_sp);

void inline_cnstr_jobdesc_snoop(uint32_t *desc,struct cipher_api *capi,dma_addr_t mem_addr)
{
	u32 options;
	u32 store_ops;
	dma_addr_t data_addr;
	dma_addr_t iv_addr;
	dma_addr_t key_addr_class1;
	dma_addr_t key_addr_class2;
	dma_addr_t icv_addr;
	struct cipher_api *capi_class1,*capi_class2;
	u32 icv_len;

	//csec_debug(KERN_INFO "inline_cnstr_jobdesc_cipher is called\n");

	/////////////////////////////////////////////////////////////////////////////////////////
	// mem = cipher_api_class1 |-| cipher_api_class2 |-| key_class1 |-| key_class2 |-| iv |-| data |-| icv
	//
	//cipher_api_class1 has class1 alg,type,as,opt,key_len, and iv_len,data_len for both class1,2
	//cipher_api_class2 has class2 alg,type,as,opt,key_len
	//iv area is iv for class1 while input data for class2,like ipsec
	/////////////////////////////////////////////////////////////////////////////////////////
	

	capi_class1 = capi;
	capi_class2 = (struct cipher_api *)&capi[1];
	
	key_addr_class1 = mem_addr+sizeof(struct cipher_api )*2;
	key_addr_class2 = key_addr_class1  + capi_class1->key_len;
	iv_addr = key_addr_class2 + capi_class2->key_len;
	data_addr = iv_addr + capi_class1->iv_len;
	icv_addr = data_addr + capi_class1->data_len;

	//csec_debug(KERN_INFO "mem_addr is %llx,key_addr is %llx,iv_addr is %llx,data_addr is %llx\n",mem_addr,key_addr ,iv_addr ,data_addr );

	init_job_desc(desc, START_INDEX);

	append_key(desc, change_addr_for_sec(key_addr_class1), capi_class1->key_len , CLASS_1 |
			KEY_DEST_CLASS_REG);	

	append_key(desc, change_addr_for_sec(key_addr_class2), capi_class2->key_len , CLASS_2 |
			KEY_DEST_CLASS_REG);	

	append_cmd_ptr(desc, change_addr_for_sec(iv_addr),capi_class1->iv_len,CMD_LOAD | LDST_SRCDST_BYTE_CONTEXT |
		   LDST_CLASS_1_CCB );

	if(capi_class2->opt&DIR_MASK)
	{
		append_operation(desc, OP_TYPE_CLASS2_ALG |
			 ((capi_class2->type)<<4) | //OP_ALG_AAI
			 ((capi_class2->alg)<<16)|		//OP_ALG
			 ((capi_class2->as)<<2) |
			 (capi_class2->opt&DIR_MASK)); 
	}else
	{
		append_operation(desc, OP_TYPE_CLASS2_ALG |
			 ((capi_class2->type)<<4) | //OP_ALG_AAI
			 ((capi_class2->alg)<<16)|		//OP_ALG
			 ((capi_class2->as)<<2) |
			 (capi_class2->opt&DIR_MASK)|OP_ALG_ICV_ON);
	}	

	append_operation(desc, OP_TYPE_CLASS1_ALG |
			 ((capi_class1->type)<<4) | //OP_ALG_AAI
			 ((capi_class1->alg)<<16)|		//OP_ALG
			 ((capi_class1->as)<<2) |
			 (capi_class1->opt&DIR_MASK) |( (capi_class1->opt&AAI_SK_MASK)?AAI_SK_SEL:0) );

	//append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_CLASS2INFIFO | capi_class1->iv_len);	

	icv_len = get_icv_len(capi_class2->alg);

	if(capi_class2->opt&DIR_MASK)		//enc ,fifo load not include icv
	{
		options = FIFOLD_CLASS_BOTH | FIFOLD_TYPE_MSG1OUT2 | FIFOLD_TYPE_LASTBOTH;
		store_ops = FIFOST_TYPE_MESSAGE_DATA;
		append_fifo_load(desc, change_addr_for_sec(data_addr), capi_class1->data_len, options);
		append_fifo_store(desc, change_addr_for_sec(data_addr), capi->data_len, store_ops);
		append_store(desc, change_addr_for_sec(icv_addr),icv_len,LDST_CLASS_2_CCB | LDST_SRCDST_BYTE_CONTEXT);
	}else
	{
		options = FIFOLD_CLASS_BOTH | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LASTBOTH;
		store_ops = FIFOST_TYPE_MESSAGE_DATA;
		append_fifo_load(desc, change_addr_for_sec(data_addr), capi_class1->data_len, options);
		append_fifo_store(desc, change_addr_for_sec(data_addr), capi->data_len, store_ops);
		append_fifo_load(desc,change_addr_for_sec(icv_addr),icv_len, FIFOLD_CLASS_CLASS2 |
			     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_ICV);
	}
	//sec_dump(desc,MAX_CSEC_DESCSIZE);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_snoop);

void inline_cnstr_jobdesc_pkha(uint32_t *desc,struct pkha_api *papi,dma_addr_t mem_addr)
{
	dma_addr_t dma = mem_addr+sizeof(struct pkha_api);
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_pkha is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	if(papi->e_len)
	{
		append_load_as_imm(desc,&papi->e_len,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
		append_fifo_load(desc, change_addr_for_sec(dma), papi->e_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	}
	dma += papi->e_len;
	if(papi->n_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->n_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	}
	dma += papi->n_len;
	if(papi->a_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->a_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	}
	dma += papi->a_len;
	if(papi->b_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->b_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	}
	dma += papi->b_len;
	if(papi->a0_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->a0_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	}
	dma += papi->a0_len;
	if(papi->a1_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->a1_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	}
	dma += papi->a1_len;
	if(papi->a2_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->a2_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	}
	dma += papi->a2_len;
	if(papi->a3_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->a3_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	}
	dma += papi->a3_len;
	if(papi->b0_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->b0_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	}
	dma += papi->b0_len;
	if(papi->b1_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->b1_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	}
	dma += papi->b1_len;
	if(papi->b2_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->b2_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	}
	dma += papi->b2_len;
	if(papi->b3_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->b3_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
	}
	dma += papi->b3_len;

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | papi->mode);

	if((papi->mode & 0xf) > 0x8 && (papi->mode & 0xf) < 0xc)
	{
		append_fifo_store(desc, change_addr_for_sec(dma), papi->n_len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B1);
		dma+=papi->n_len;
		append_fifo_store(desc, change_addr_for_sec(dma), papi->n_len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B2);
	}
	else
	{
		append_fifo_store(desc, change_addr_for_sec(dma), papi->n_len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	}
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_pkha);

#if 0
void inline_cnstr_jobdesc_sm2_genkey(uint32_t *desc,struct sm2_api *smapi,dma_addr_t mem_addr, struct sm2_api_ext *smapi_ext)
{
	/* 
	  * in:head+p+a+b+G+n
	  * out:prikey+PUBKEY
	*/
	dma_addr_t dma_p = mem_addr+sizeof(struct sm2_api);
	dma_addr_t dma_a = mem_addr+sizeof(struct sm2_api)+smapi->plen;
	dma_addr_t dma_b= mem_addr+sizeof(struct sm2_api)+2*smapi->plen;
	dma_addr_t dma_gx = mem_addr+sizeof(struct sm2_api)+3*smapi->plen;
	dma_addr_t dma_gy = mem_addr+sizeof(struct sm2_api)+4*smapi->plen;
	dma_addr_t dma_n = mem_addr+sizeof(struct sm2_api)+5*smapi->plen;
	dma_addr_t dma_pri = mem_addr+sizeof(struct sm2_api)+6*smapi->plen;
	dma_addr_t dma_px = mem_addr+sizeof(struct sm2_api)+7*smapi->plen;
	dma_addr_t dma_py = mem_addr+sizeof(struct sm2_api)+8*smapi->plen;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_sm2_genkey is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//init rng
	//append_load(desc, change_addr_for_sec(smapi_ext->k_phys), 32, LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);
	//generate private key with random data
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
	append_cmd(desc, smapi->nlen);
	append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
	append_fifo_store(desc, change_addr_for_sec(dma_pri), smapi->nlen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGSTORE);

	append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);
	//private key mod order
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(dma_pri), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	if(smapi->plen%16)
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf0);
	else
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf2);
	append_fifo_store(desc, change_addr_for_sec(dma_pri), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	//load p
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_p), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load G
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gx), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gy), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	//load a
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_a), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	//copy k to e_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load b
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_b), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);
	//store pubkey
	append_fifo_store(desc, change_addr_for_sec(dma_px), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(dma_py), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_sm2_genkey);

void inline_cnstr_jobdesc_sm2_genkey_seed(uint32_t *desc,struct sm2_api *smapi,dma_addr_t mem_addr, struct sm2_api_ext *smapi_ext)
{
	/* 
	  * in:head+p+a+b+G+n+pri
	  * out:PUBKEY
	*/
	dma_addr_t dma_p = mem_addr+sizeof(struct sm2_api);
	dma_addr_t dma_a = mem_addr+sizeof(struct sm2_api)+smapi->plen;
	dma_addr_t dma_b= mem_addr+sizeof(struct sm2_api)+2*smapi->plen;
	dma_addr_t dma_gx = mem_addr+sizeof(struct sm2_api)+3*smapi->plen;
	dma_addr_t dma_gy = mem_addr+sizeof(struct sm2_api)+4*smapi->plen;
	dma_addr_t dma_n = mem_addr+sizeof(struct sm2_api)+5*smapi->plen;
	dma_addr_t dma_pri = mem_addr+sizeof(struct sm2_api)+6*smapi->plen;
	dma_addr_t dma_px = mem_addr+sizeof(struct sm2_api)+7*smapi->plen;
	dma_addr_t dma_py = mem_addr+sizeof(struct sm2_api)+8*smapi->plen;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_sm2_genkey_seed is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_pri), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0x2);

	//load p
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_p), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load G
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gx), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gy), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	//load a
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_a), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	//copy k to e_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load b
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_b), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);
	//store pubkey
	append_fifo_store(desc, change_addr_for_sec(dma_px), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(dma_py), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_sm2_genkey_seed);

void inline_cnstr_jobdesc_sm2_encrypt(uint32_t *desc,struct sm2_api *smapi,dma_addr_t mem_addr, struct sm2_api_ext *smapi_ext)
{
	/* 
	  * in:head+p+a+b+G+n+PUBKEY+message
	  * out:c1+c2+c3
	*/
	dma_addr_t dma_p = mem_addr+sizeof(struct sm2_api);
	dma_addr_t dma_a = mem_addr+sizeof(struct sm2_api)+smapi->plen;
	dma_addr_t dma_b= mem_addr+sizeof(struct sm2_api)+2*smapi->plen;
	dma_addr_t dma_gx = mem_addr+sizeof(struct sm2_api)+3*smapi->plen;
	dma_addr_t dma_gy = mem_addr+sizeof(struct sm2_api)+4*smapi->plen;
	dma_addr_t dma_n = mem_addr+sizeof(struct sm2_api)+5*smapi->plen;
	dma_addr_t dma_px = mem_addr+sizeof(struct sm2_api)+6*smapi->plen;
	dma_addr_t dma_py = mem_addr+sizeof(struct sm2_api)+7*smapi->plen;
	dma_addr_t dma_mes = mem_addr+sizeof(struct sm2_api)+8*smapi->plen;
//	dma_addr_t dma_c1 = mem_addr+sizeof(struct sm2_api)+8*smapi->plen+smapi->klen;
	dma_addr_t dma_c1x= mem_addr+sizeof(struct sm2_api)+8*smapi->plen+smapi->klen+1;
	dma_addr_t dma_c1y = mem_addr+sizeof(struct sm2_api)+9*smapi->plen+smapi->klen+1;
	dma_addr_t dma_c2 = mem_addr+sizeof(struct sm2_api)+10*smapi->plen+smapi->klen+1;
	dma_addr_t dma_c3 = mem_addr+sizeof(struct sm2_api)+10*smapi->plen+2*smapi->klen+1;
	unsigned int ct = (smapi->klen+smapi->nlen-1)/smapi->nlen, i;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_sm2_encrypt is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//generate k
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
	append_cmd(desc, smapi->nlen);
	append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->k_phys), smapi->nlen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGSTORE);
	append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);
	//k mod order
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->k_phys), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	if(smapi->plen%16)
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf0);
	else
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf2);
//	append_fifo_store(desc, virt_to_phys(rng), len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	//calculate c1
	//load p
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_p), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load G
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gx), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gy), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	//load a
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_a), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	//save a
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//copy k to e_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load b
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_b), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//save b
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B0 | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);
	//store c1
	append_fifo_store(desc, change_addr_for_sec(dma_c1x), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(dma_c1y), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);

	//calculate c2
	//load public key
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_px), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_py), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	//load a&b
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);
	//store x2,y2
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->hashin_phys), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->hashin_phys+smapi->plen), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
	//kdf
	//calc ct
	append_math_add(desc, REG0, ZERO, ONE, 4);
	append_math_swap(desc, REG1, REG0, ONE, 4);
	append_store(desc, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
	append_load(desc, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_MATH3 | 4);
	append_math_sub(desc, REG3, REG1, REG3, 4);
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfb);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	//extern descriptor
	init_job_desc(smapi_ext->desc_ext, START_INDEX);

	//do sm3
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), 2*smapi->plen+4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x10000);

	for(i=1; i<ct; i++)
	{
		//calc ct
		append_math_add(smapi_ext->desc_ext, REG0, REG0, ONE, 4);
		append_math_swap(smapi_ext->desc_ext, REG1, REG0, ONE, 4);
		append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		//append_move(smapi_ext->desc_ext, MOVE_SRC_MATH1 | MOVE_DEST_MATH2 | 4);
		//append_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH3);
		append_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);
		append_move(smapi_ext->desc_ext, MOVE_SRC_CLASS1CTX | MOVE_DEST_MATH3 | 4);
		append_math_sub(smapi_ext->desc_ext, REG3, REG1, REG3, 4);
		append_jump(smapi_ext->desc_ext, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfb);
		//do sm3
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(smapi_ext->desc_ext, 0x40000);
		append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), 2*smapi->plen+4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys+i*smapi->nlen), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(smapi_ext->desc_ext, 0x10000);
	}
	//sync
	append_jump(smapi_ext->desc_ext, JUMP_CLASS_CLASS2 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);
	//do t^mes
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_mes), smapi->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	//store c2
	append_fifo_store(smapi_ext->desc_ext, change_addr_for_sec(dma_c2), smapi->klen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);	

	//calculate c3
	//do sm3
	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x40000);
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	//load x2
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	//load mes
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_mes), smapi->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	//load y2
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+smapi->plen), smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	//store c3
	append_store(smapi_ext->desc_ext, change_addr_for_sec(dma_c3), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);

}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_sm2_encrypt);

void inline_cnstr_jobdesc_sm2_encrypt_seed(uint32_t *desc,struct sm2_api *smapi,dma_addr_t mem_addr, struct sm2_api_ext *smapi_ext)
{
	/* 
	  * in:head+p+a+b+G+n+PUBKEY+message+k
	  * out:c1+c2+c3
	*/
	dma_addr_t dma_p = mem_addr+sizeof(struct sm2_api);
	dma_addr_t dma_a = mem_addr+sizeof(struct sm2_api)+smapi->plen;
	dma_addr_t dma_b= mem_addr+sizeof(struct sm2_api)+2*smapi->plen;
	dma_addr_t dma_gx = mem_addr+sizeof(struct sm2_api)+3*smapi->plen;
	dma_addr_t dma_gy = mem_addr+sizeof(struct sm2_api)+4*smapi->plen;
	dma_addr_t dma_n = mem_addr+sizeof(struct sm2_api)+5*smapi->plen;
	dma_addr_t dma_px = mem_addr+sizeof(struct sm2_api)+6*smapi->plen;
	dma_addr_t dma_py = mem_addr+sizeof(struct sm2_api)+7*smapi->plen;
	dma_addr_t dma_mes = mem_addr+sizeof(struct sm2_api)+8*smapi->plen;
	dma_addr_t dma_k = mem_addr+sizeof(struct sm2_api)+8*smapi->plen+smapi->klen;
//	dma_addr_t dma_c1 = mem_addr+sizeof(struct sm2_api)+9*smapi->plen+smapi->klen;
	dma_addr_t dma_c1x= mem_addr+sizeof(struct sm2_api)+9*smapi->plen+smapi->klen+1;
	dma_addr_t dma_c1y = mem_addr+sizeof(struct sm2_api)+10*smapi->plen+smapi->klen+1;
	dma_addr_t dma_c2 = mem_addr+sizeof(struct sm2_api)+11*smapi->plen+smapi->klen+1;
	dma_addr_t dma_c3 = mem_addr+sizeof(struct sm2_api)+11*smapi->plen+2*smapi->klen+1;
	unsigned int ct = (smapi->klen+smapi->nlen-1)/smapi->nlen, i;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_sm2_encrypt_seed is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_k), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0x2);
	//calculate c1
	//load p
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_p), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load G
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gx), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gy), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	//load a
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_a), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	//save a
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//copy k to e_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load b
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_b), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//save b
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B0 | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);
	//store c1
	append_fifo_store(desc, change_addr_for_sec(dma_c1x), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(dma_c1y), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);

	//calculate c2
	//load public key
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_px), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_py), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	//load a&b
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);
	//store x2,y2
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->hashin_phys), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->hashin_phys+smapi->plen), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
	//kdf
	//calc ct
	append_math_add(desc, REG0, ZERO, ONE, 4);
	append_math_swap(desc, REG1, REG0, ONE, 4);
	append_store(desc, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
	//append_move(desc, MOVE_SRC_MATH1 | MOVE_DEST_MATH2 | 4);
	//append_load(desc, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH3);
	append_load(desc, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_MATH3 | 4);
	append_math_sub(desc, REG3, REG1, REG3, 4);
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfb);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	//extern descriptor
	init_job_desc(smapi_ext->desc_ext, START_INDEX);

	//do sm3
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), 2*smapi->plen+4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x10000);

	for(i=1; i<ct; i++)
	{
		//calc ct
		append_math_add(smapi_ext->desc_ext, REG0, REG0, ONE, 4);
		append_math_swap(smapi_ext->desc_ext, REG1, REG0, ONE, 4);
		append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		//append_move(smapi_ext->desc_ext, MOVE_SRC_MATH1 | MOVE_DEST_MATH2 | 4);
		//append_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH3);
		append_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);
		append_move(smapi_ext->desc_ext, MOVE_SRC_CLASS1CTX | MOVE_DEST_MATH3 | 4);
		append_math_sub(smapi_ext->desc_ext, REG3, REG1, REG3, 4);
		append_jump(smapi_ext->desc_ext, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfb);
		//do sm3
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(smapi_ext->desc_ext, 0x40000);
		append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), 2*smapi->plen+4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys+i*smapi->nlen), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(smapi_ext->desc_ext, 0x10000);
	}
	//sync
	append_jump(smapi_ext->desc_ext, JUMP_CLASS_CLASS2 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);
	//do t^mes
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_mes), smapi->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	//store c2
	append_fifo_store(smapi_ext->desc_ext, change_addr_for_sec(dma_c2), smapi->klen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);	

	//calculate c3
	//do sm3
	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x40000);
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	//load x2
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	//load mes
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_mes), smapi->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	//load y2
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+smapi->plen), smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	//store c3
	append_store(smapi_ext->desc_ext, change_addr_for_sec(dma_c3), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);

}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_sm2_encrypt_seed);

void inline_cnstr_jobdesc_sm2_decrypt(uint32_t *desc,struct sm2_api *smapi,dma_addr_t mem_addr, struct sm2_api_ext *smapi_ext)
{
	/* 
	  * in:head+p+a+b+G+n+prikey+c1+c2+c3
	  * out:mes
	*/
	dma_addr_t dma_p = mem_addr+sizeof(struct sm2_api);
	dma_addr_t dma_a = mem_addr+sizeof(struct sm2_api)+smapi->plen;
	dma_addr_t dma_b = mem_addr+sizeof(struct sm2_api)+2*smapi->plen;
//	dma_addr_t dma_gx = mem_addr+sizeof(struct sm2_api)+3*smapi->plen;
//	dma_addr_t dma_gy = mem_addr+sizeof(struct sm2_api)+4*smapi->plen;
	dma_addr_t dma_n = mem_addr+sizeof(struct sm2_api)+5*smapi->plen;
	dma_addr_t dma_pri = mem_addr+sizeof(struct sm2_api)+6*smapi->plen;
//	dma_addr_t dma_c1 = mem_addr+sizeof(struct sm2_api)+7*smapi->plen;
	dma_addr_t dma_c1x = mem_addr+sizeof(struct sm2_api)+7*smapi->plen+1;
	dma_addr_t dma_c1y = mem_addr+sizeof(struct sm2_api)+8*smapi->plen+1;
	dma_addr_t dma_c2 = mem_addr+sizeof(struct sm2_api)+9*smapi->plen+1;
	dma_addr_t dma_c3 = mem_addr+sizeof(struct sm2_api)+9*smapi->plen+smapi->klen+1;
	dma_addr_t dma_mes = mem_addr+sizeof(struct sm2_api)+9*smapi->plen+smapi->klen+smapi->nlen+1;
	unsigned int ct = (smapi->klen+smapi->nlen-1)/smapi->nlen, i;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_sm2_decrypt is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//calc x2,y2
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	//load p
	append_fifo_load(desc, change_addr_for_sec(dma_p), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	//load x1
	append_fifo_load(desc, change_addr_for_sec(dma_c1x), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLDST_SGF | FIFOLD_IMM | FIFOLD_TYPE_PK_A0);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	//load y1
	append_fifo_load(desc, change_addr_for_sec(dma_c1y), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLDST_SGF | FIFOLD_IMM | FIFOLD_TYPE_PK_A1);
	//load a
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_a), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	//load private key
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_pri), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//copy private key to e_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load b
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_b), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);
	//store x2,y2
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->hashin_phys), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->hashin_phys+smapi->plen), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);

	//do kdf
	//calc ct
	append_math_add(desc, REG0, ZERO, ONE, 4);
	append_math_swap(desc, REG1, REG0, ONE, 4);
	append_store(desc, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
	//append_move(desc, MOVE_SRC_MATH1 | MOVE_DEST_MATH2 | 4);
	//append_load(desc, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH3);
	append_load(desc, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_MATH3 | 4);
	append_math_sub(desc, REG3, REG1, REG3, 4);
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfb);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	//extern descriptor
	init_job_desc(smapi_ext->desc_ext, START_INDEX);

	//do sm3
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), 2*smapi->plen+4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x10000);
	
	for(i=1; i<ct; i++)
	{
		//calc ct
		append_math_add(smapi_ext->desc_ext, REG0, REG0, ONE, 4);
		append_math_swap(smapi_ext->desc_ext, REG1, REG0, ONE, 4);
		append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		//append_move(smapi_ext->desc_ext, MOVE_SRC_MATH1 | MOVE_DEST_MATH2 | 4);
		//append_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH3);
		append_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);
		append_move(smapi_ext->desc_ext, MOVE_SRC_CLASS1CTX | MOVE_DEST_MATH3 | 4);
		append_math_sub(smapi_ext->desc_ext, REG3, REG1, REG3, 4);
		append_jump(smapi_ext->desc_ext, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfb);
		//do sm3
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(smapi_ext->desc_ext, 0x40000);
		append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), 2*smapi->plen+4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys+i*smapi->nlen), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(smapi_ext->desc_ext, 0x10000);
	}
	//sync
	append_jump(smapi_ext->desc_ext, JUMP_CLASS_CLASS2 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);
	//do t^c2
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_c2), smapi->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_store(smapi_ext->desc_ext, change_addr_for_sec(dma_mes), smapi->klen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);

	//verify c3
	//do sm3
	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x40000);
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	//load x2
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	//load mes
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_mes), smapi->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	//load y2
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+smapi->plen), smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	//move hash to a_ram
	append_move(smapi_ext->desc_ext, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | smapi->nlen);
	//load n
//	if(smapi->plen != smapi->nlen)
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_n+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load c3
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_c3), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	//do mod sub
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	//is zero
	append_jump(smapi_ext->desc_ext, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x1);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_sm2_decrypt);

void inline_cnstr_jobdesc_sm2_signature(uint32_t *desc,struct sm2_api *smapi,dma_addr_t mem_addr, struct sm2_api_ext *smapi_ext)
{
	/* 
	  * in:head+p+a+b+G+n+PUBKEY+prikey+mes+ida
	  * out:r+s
	*/	
	dma_addr_t dma_p = mem_addr+sizeof(struct sm2_api);
	dma_addr_t dma_a = mem_addr+sizeof(struct sm2_api)+smapi->plen;
	dma_addr_t dma_b = mem_addr+sizeof(struct sm2_api)+2*smapi->plen;
	dma_addr_t dma_gx = mem_addr+sizeof(struct sm2_api)+3*smapi->plen;
	dma_addr_t dma_gy = mem_addr+sizeof(struct sm2_api)+4*smapi->plen;
	dma_addr_t dma_n = mem_addr+sizeof(struct sm2_api)+5*smapi->plen;
//	dma_addr_t dma_px = mem_addr+sizeof(struct sm2_api)+6*smapi->plen;
//	dma_addr_t dma_py = mem_addr+sizeof(struct sm2_api)+7*smapi->plen;
	dma_addr_t dma_pri = mem_addr+sizeof(struct sm2_api)+8*smapi->plen;
	dma_addr_t dma_mes = mem_addr+sizeof(struct sm2_api)+9*smapi->plen;
//	dma_addr_t dma_ida = mem_addr+sizeof(struct sm2_api)+9*smapi->plen+smapi->klen;
	dma_addr_t dma_r = mem_addr+sizeof(struct sm2_api)+9*smapi->plen+smapi->klen+smapi->entla;
	dma_addr_t dma_s = mem_addr+sizeof(struct sm2_api)+10*smapi->plen+smapi->klen+smapi->entla;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_sm2_signature is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//generate k
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
	append_cmd(desc, smapi->nlen);
	append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->k_phys), smapi->nlen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGSTORE);
	append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);
	//k mod order
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->k_phys), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	if(smapi->plen%16)
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf0);
	else
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//calculate za
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->zain_phys), 2+smapi->entla+6*smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	//append_store(desc, change_addr_for_sec(smapi_ext->zaout_phys), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	//calculate e
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_move(desc, MOVE_SRC_CLASS2CTX | MOVE_DEST_CLASS2INFIFO | smapi->nlen);
	//append_fifo_load(desc, change_addr_for_sec(smapi_ext->zaout_phys), smapi->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(dma_mes), smapi->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);

	//do e mod n
	//move e to a_ram
	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | MOVE_AUX_LS | smapi->nlen);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	//load n
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//do amodn
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	//save e mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	//extern descriptor
	init_job_desc(smapi_ext->desc_ext, START_INDEX);

	//(x1,y1) = [k]G
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	//load p
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_p), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load G
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_gx), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_gy), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	//load a
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_a), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	//load k to e_ram
//	if(smapi->plen%16)
//	{
		//pad to 128b-alignment
//		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
//		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
//	}
//	append_fifo_load(desc, change_addr_for_sec(smapi_ext->k_phys), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//save k
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load b
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_b), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//do ecc mod mult
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);

	//calculate r
	//load n
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//copy x1 to a_ram
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do x1 mod n
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	//load e mod n
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do e+x1 mod n
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//save r
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_store(smapi_ext->desc_ext, change_addr_for_sec(dma_r), smapi->plen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B|FIFOST_CLASS_SWAP);

	//calculate s
	if(smapi->plen == smapi->nlen)
	{
		append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_n), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		//load private key
		append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_pri), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	}
	else
	{
		append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_n+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		//load private key
		append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_pri+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	}
	//save private key
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N13 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//load 1
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->one_phys), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	//do 1+da mod n
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//copy to a_ram
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do (1+da)^-1 mod n
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
	//save result
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do r*da mod n
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N13 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	//do k-r*da mod n
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	//calc s
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	if(smapi->plen == smapi->nlen)
		append_fifo_store(smapi_ext->desc_ext, change_addr_for_sec(dma_s), smapi->nlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B|FIFOST_CLASS_SWAP);
	else
		append_fifo_store(smapi_ext->desc_ext, change_addr_for_sec(dma_s+smapi->plen-smapi->nlen), smapi->nlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B|FIFOST_CLASS_SWAP);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_sm2_signature);

void inline_cnstr_jobdesc_sm2_verify(uint32_t *desc,struct sm2_api *smapi,dma_addr_t mem_addr, struct sm2_api_ext *smapi_ext)
{
	/* 
	  * in:head+p+a+b+G+n+PUBKEY+mes+ida+r+s
	  * out:
	*/	
	dma_addr_t dma_p = mem_addr+sizeof(struct sm2_api);
	dma_addr_t dma_a = mem_addr+sizeof(struct sm2_api)+smapi->plen;
	dma_addr_t dma_b = mem_addr+sizeof(struct sm2_api)+2*smapi->plen;
	dma_addr_t dma_gx = mem_addr+sizeof(struct sm2_api)+3*smapi->plen;
	dma_addr_t dma_gy = mem_addr+sizeof(struct sm2_api)+4*smapi->plen;
	dma_addr_t dma_n = mem_addr+sizeof(struct sm2_api)+5*smapi->plen;
	dma_addr_t dma_px = mem_addr+sizeof(struct sm2_api)+6*smapi->plen;
	dma_addr_t dma_py = mem_addr+sizeof(struct sm2_api)+7*smapi->plen;
	dma_addr_t dma_mes = mem_addr+sizeof(struct sm2_api)+8*smapi->plen;
//	dma_addr_t dma_ida = mem_addr+sizeof(struct sm2_api)+8*smapi->plen+smapi->klen;
	dma_addr_t dma_r = mem_addr+sizeof(struct sm2_api)+8*smapi->plen+smapi->klen+smapi->entla;
	dma_addr_t dma_s = mem_addr+sizeof(struct sm2_api)+9*smapi->plen+smapi->klen+smapi->entla;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_sm2_verify is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//compare r and 1
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_r), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->one_phys), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x1);
	//compare r and n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_BORROW | 0x2);
	//compare s and n
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_s), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_BORROW | 0x3);
	//compare s and 1
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x4);
	
	//calculate za
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->zain_phys), 2+smapi->entla+6*smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	//append_store(desc, change_addr_for_sec(smapi_ext->zaout_phys), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	//calculate e
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_move(desc, MOVE_SRC_CLASS2CTX | MOVE_DEST_CLASS2INFIFO | smapi->nlen);
	//append_fifo_load(desc, change_addr_for_sec(smapi_ext->zaout_phys), smapi->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(dma_mes), smapi->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);

	//do e mod n
	//move e to a_ram
	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | MOVE_AUX_LS | smapi->nlen);

	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);

	//load n
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//do amodn
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	//save e mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N13 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//t = (r + s) mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	//extern descriptor
	init_job_desc(smapi_ext->desc_ext, START_INDEX);

	//calculate [t]Pa
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_p), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_px), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_py), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_a), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_b), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B0 | OP_ALG_PKMODE_DST_REG_N21 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_N22 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N23 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//calculate [s]G
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_gx), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_gy), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N21 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT |smapi->field);

	//(x1, y1) = [s]G + [t]Pa
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N21 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N22 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N23 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_ADD | smapi->field);

	//r' = (e + x1) mod n
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(smapi_ext->desc_ext, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N13 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);

	//compare r' and r
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(smapi_ext->desc_ext, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(smapi_ext->desc_ext, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x5);

}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_sm2_verify);

void inline_cnstr_jobdesc_sm2_signature_noid(uint32_t *desc,struct sm2_api *smapi,dma_addr_t mem_addr, struct sm2_api_ext *smapi_ext)
{
	/* 
	  * in:head+p+a+b+G+n+prikey+hash
	  * out:r+s
	*/	
	dma_addr_t dma_p = mem_addr+sizeof(struct sm2_api);
	dma_addr_t dma_a = mem_addr+sizeof(struct sm2_api)+smapi->plen;
	dma_addr_t dma_b = mem_addr+sizeof(struct sm2_api)+2*smapi->plen;
	dma_addr_t dma_gx = mem_addr+sizeof(struct sm2_api)+3*smapi->plen;
	dma_addr_t dma_gy = mem_addr+sizeof(struct sm2_api)+4*smapi->plen;
	dma_addr_t dma_n = mem_addr+sizeof(struct sm2_api)+5*smapi->plen;
	dma_addr_t dma_pri = mem_addr+sizeof(struct sm2_api)+6*smapi->plen;
	dma_addr_t dma_hash = mem_addr+sizeof(struct sm2_api)+7*smapi->plen;
	dma_addr_t dma_r = mem_addr+sizeof(struct sm2_api)+7*smapi->plen+smapi->nlen;
	dma_addr_t dma_s = mem_addr+sizeof(struct sm2_api)+8*smapi->plen+smapi->nlen;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_sm2_signature_noid is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//generate k
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
	append_cmd(desc, smapi->nlen);
	append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->k_phys), smapi->nlen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGSTORE);
	append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);
	//k mod order
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->k_phys), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	if(smapi->plen%16)
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf0);
	else
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//do e mod n
	//load n
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(dma_hash), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	//do amodn
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	//save e mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//(x1,y1) = [k]G
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	//load p
	append_fifo_load(desc, change_addr_for_sec(dma_p), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load G
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gx), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gy), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	//load a
	append_fifo_load(desc, change_addr_for_sec(dma_a), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	//load k to e_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load b
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_b), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);

	//calculate r
	//load n
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//copy x1 to a_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do x1 mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	//load e mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do e+x1 mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//save r
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_store(desc, change_addr_for_sec(dma_r), smapi->plen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B|FIFOST_CLASS_SWAP);

	//calculate s
	if(smapi->plen == smapi->nlen)
	{
		append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		//load private key
		append_fifo_load(desc, change_addr_for_sec(dma_pri), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	}
	else
	{
		append_fifo_load(desc, change_addr_for_sec(dma_n+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		//load private key
		append_fifo_load(desc, change_addr_for_sec(dma_pri+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	}
	//save private key
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N13 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//load 1
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->one_phys), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	//do 1+da mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//copy to a_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do (1+da)^-1 mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
	//save result
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do r*da mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N13 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	//do k-r*da mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	//calc s
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	if(smapi->plen == smapi->nlen)
		append_fifo_store(desc, change_addr_for_sec(dma_s), smapi->nlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B|FIFOST_CLASS_SWAP);
	else
		append_fifo_store(desc, change_addr_for_sec(dma_s+smapi->plen-smapi->nlen), smapi->nlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B|FIFOST_CLASS_SWAP);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_sm2_signature_noid);

void inline_cnstr_jobdesc_sm2_signature_noid_seed(uint32_t *desc,struct sm2_api *smapi,dma_addr_t mem_addr, struct sm2_api_ext *smapi_ext)
{
	/* 
	  * in:head+p+a+b+G+n+prikey+hash+k
	  * out:r+s
	*/	
	dma_addr_t dma_p = mem_addr+sizeof(struct sm2_api);
	dma_addr_t dma_a = mem_addr+sizeof(struct sm2_api)+smapi->plen;
	dma_addr_t dma_b = mem_addr+sizeof(struct sm2_api)+2*smapi->plen;
	dma_addr_t dma_gx = mem_addr+sizeof(struct sm2_api)+3*smapi->plen;
	dma_addr_t dma_gy = mem_addr+sizeof(struct sm2_api)+4*smapi->plen;
	dma_addr_t dma_n = mem_addr+sizeof(struct sm2_api)+5*smapi->plen;
	dma_addr_t dma_pri = mem_addr+sizeof(struct sm2_api)+6*smapi->plen;
	dma_addr_t dma_hash = mem_addr+sizeof(struct sm2_api)+7*smapi->plen;
	dma_addr_t dma_k = mem_addr+sizeof(struct sm2_api)+7*smapi->plen+smapi->nlen;
	dma_addr_t dma_r = mem_addr+sizeof(struct sm2_api)+8*smapi->plen+smapi->nlen;
	dma_addr_t dma_s = mem_addr+sizeof(struct sm2_api)+9*smapi->plen+smapi->nlen;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_sm2_signature_noid_seed is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_k), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0x2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//do e mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_fifo_load(desc, change_addr_for_sec(dma_hash), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	//do amodn
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	//save e mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//(x1,y1) = [k]G
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	//load p
	append_fifo_load(desc, change_addr_for_sec(dma_p), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load G
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gx), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gy), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	//load a
	append_fifo_load(desc, change_addr_for_sec(dma_a), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	//load k to e_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load b
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_b), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);

	//calculate r
	//load n
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//copy x1 to a_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do x1 mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	//load e mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do e+x1 mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//save r
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_store(desc, change_addr_for_sec(dma_r), smapi->plen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B|FIFOST_CLASS_SWAP);

	//calculate s
	if(smapi->plen == smapi->nlen)
	{
		append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		//load private key
		append_fifo_load(desc, change_addr_for_sec(dma_pri), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	}
	else
	{
		append_fifo_load(desc, change_addr_for_sec(dma_n+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		//load private key
		append_fifo_load(desc, change_addr_for_sec(dma_pri+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	}
	//save private key
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N13 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//load 1
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->one_phys), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	//do 1+da mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//copy to a_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do (1+da)^-1 mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
	//save result
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do r*da mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N13 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	//do k-r*da mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	//calc s
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	if(smapi->plen == smapi->nlen)
		append_fifo_store(desc, change_addr_for_sec(dma_s), smapi->nlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B|FIFOST_CLASS_SWAP);
	else
		append_fifo_store(desc, change_addr_for_sec(dma_s+smapi->plen-smapi->nlen), smapi->nlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B|FIFOST_CLASS_SWAP);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_sm2_signature_noid_seed);

void inline_cnstr_jobdesc_sm2_verify_noid(uint32_t *desc,struct sm2_api *smapi,dma_addr_t mem_addr, struct sm2_api_ext *smapi_ext)
{
	/* 
	  * in:head+p+a+b+G+n+PUBKEY+hash+r+s
	  * out:
	*/	
	dma_addr_t dma_p = mem_addr+sizeof(struct sm2_api);
	dma_addr_t dma_a = mem_addr+sizeof(struct sm2_api)+smapi->plen;
	dma_addr_t dma_b = mem_addr+sizeof(struct sm2_api)+2*smapi->plen;
	dma_addr_t dma_gx = mem_addr+sizeof(struct sm2_api)+3*smapi->plen;
	dma_addr_t dma_gy = mem_addr+sizeof(struct sm2_api)+4*smapi->plen;
	dma_addr_t dma_n = mem_addr+sizeof(struct sm2_api)+5*smapi->plen;
	dma_addr_t dma_px = mem_addr+sizeof(struct sm2_api)+6*smapi->plen;
	dma_addr_t dma_py = mem_addr+sizeof(struct sm2_api)+7*smapi->plen;
	dma_addr_t dma_hash = mem_addr+sizeof(struct sm2_api)+8*smapi->plen;
	dma_addr_t dma_r = mem_addr+sizeof(struct sm2_api)+8*smapi->plen+smapi->nlen;
	dma_addr_t dma_s = mem_addr+sizeof(struct sm2_api)+9*smapi->plen+smapi->nlen;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_sm2_verify_noid is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//compare r and 1
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_r), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->one_phys), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x1);
	//compare r and n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_BORROW | 0x2);
	//compare s and n
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_s), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_BORROW | 0x3);
	//compare s and 1
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x4);

	//do e mod n
	//load n
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(dma_hash), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	//do amodn
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	//save e mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N13 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//t = (r + s) mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);

	//calculate [t]Pa
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_p), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_px), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_py), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_a), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_b), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B0 | OP_ALG_PKMODE_DST_REG_N21 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_N22 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N23 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//calculate [s]G
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gx), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_gy), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N21 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT |smapi->field);

	//(x1, y1) = [s]G + [t]Pa
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N21 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N22 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N23 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_ADD | smapi->field);

	//r' = (e + x1) mod n
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_n), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N13 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);

	//compare r' and r
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x5);

}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_sm2_verify_noid);

void inline_cnstr_jobdesc_sm2_agreementA(uint32_t *desc,struct sm2_api *smapi,dma_addr_t mem_addr, struct sm2_api_ext *smapi_ext)
{
	/* 
	  * in:head+p+a+b+G+n+h+selfpub+selfpri+selfid+selftmppub+selftmppri+otherpub+otherid+othertmppub
	  * out:key+s1+sa
	*/	
	dma_addr_t dma_p = mem_addr+sizeof(struct sm2_api);
	dma_addr_t dma_a = mem_addr+sizeof(struct sm2_api)+smapi->plen;
	dma_addr_t dma_b = mem_addr+sizeof(struct sm2_api)+2*smapi->plen;
//	dma_addr_t dma_gx = mem_addr+sizeof(struct sm2_api)+3*smapi->plen;
//	dma_addr_t dma_gy = mem_addr+sizeof(struct sm2_api)+4*smapi->plen;
	dma_addr_t dma_n = mem_addr+sizeof(struct sm2_api)+5*smapi->plen;
	dma_addr_t dma_h = mem_addr+sizeof(struct sm2_api)+6*smapi->plen;
//	dma_addr_t dma_self_px = mem_addr+sizeof(struct sm2_api)+7*smapi->plen;
//	dma_addr_t dma_self_py = mem_addr+sizeof(struct sm2_api)+8*smapi->plen;
	dma_addr_t dma_self_pri = mem_addr+sizeof(struct sm2_api)+9*smapi->plen;
//	dma_addr_t dma_self_id = mem_addr+sizeof(struct sm2_api)+10*smapi->plen;
	dma_addr_t dma_self_tmp_px = mem_addr+sizeof(struct sm2_api)+10*smapi->plen+smapi->entla;
//	dma_addr_t dma_self_tmp_py = mem_addr+sizeof(struct sm2_api)+11*smapi->plen+smapi->entla;
	dma_addr_t dma_self_tmp_pri = mem_addr+sizeof(struct sm2_api)+12*smapi->plen+smapi->entla;
	dma_addr_t dma_other_px = mem_addr+sizeof(struct sm2_api)+13*smapi->plen+smapi->entla;
	dma_addr_t dma_other_py = mem_addr+sizeof(struct sm2_api)+14*smapi->plen+smapi->entla;
//	dma_addr_t dma_idb = mem_addr+sizeof(struct sm2_api)+15*smapi->plen+smapi->entla;
	dma_addr_t dma_other_tmp_px = mem_addr+sizeof(struct sm2_api)+15*smapi->plen+smapi->entla+smapi->entlb;
	dma_addr_t dma_other_tmp_py = mem_addr+sizeof(struct sm2_api)+16*smapi->plen+smapi->entla+smapi->entlb;
	dma_addr_t dma_key = mem_addr+sizeof(struct sm2_api)+17*smapi->plen+smapi->entla+smapi->entlb;
	dma_addr_t dma_s1 = mem_addr+sizeof(struct sm2_api)+17*smapi->plen+smapi->entla+smapi->entlb+smapi->klen;
	dma_addr_t dma_sa = mem_addr+sizeof(struct sm2_api)+17*smapi->plen+smapi->entla+smapi->entlb+smapi->klen+smapi->nlen;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_sm2_agreementA is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	append_fifo_load(desc, change_addr_for_sec(dma_n+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->k_phys+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(dma_self_tmp_pri+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);

	append_fifo_load(desc, change_addr_for_sec(dma_self_pri+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);

	append_fifo_load(desc, change_addr_for_sec(dma_h+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_p), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_other_tmp_px), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_other_tmp_py), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_a), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->k_phys+smapi->plen), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_b), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B0 | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_other_px), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_other_py), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_ADD| smapi->field);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->hashin_phys), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->hashin_phys+smapi->plen), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);

	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->zain_phys), 2+smapi->entla+6*smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(smapi_ext->zaout_phys), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->zain_phys+2+smapi->entla+6*smapi->plen), 2+smapi->entlb+6*smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(smapi_ext->zaout_phys+smapi->nlen), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);

	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);//85
	//extern descriptor
	init_job_desc(smapi_ext->desc_ext, START_INDEX);
	append_math_add(smapi_ext->desc_ext, REG0, ZERO, ONE, 4);
	append_math_swap(smapi_ext->desc_ext, REG1, REG0, ONE, 4);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);

	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x40000);
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), 2*smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->zaout_phys), 2*smapi->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(dma_key), smapi->klen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);	

	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x40000);
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->zaout_phys), 2*smapi->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_self_tmp_px), 2*smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_other_tmp_px), 2*smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x40000);
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->one_phys), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+smapi->plen), smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(dma_s1), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);

	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x40000);
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->one_phys+1), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+smapi->plen), smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(dma_sa), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_sm2_agreementA);

void inline_cnstr_jobdesc_sm2_agreementB(uint32_t *desc,struct sm2_api *smapi,dma_addr_t mem_addr, struct sm2_api_ext *smapi_ext)
{
	/* 
	  * in:head+p+a+b+G+n+h+selfpub+selfpri+selfid+selftmppub+selftmppri+otherpub+otherid+othertmppub
	  * out:key+s2+sb
	*/	
	dma_addr_t dma_p = mem_addr+sizeof(struct sm2_api);
	dma_addr_t dma_a = mem_addr+sizeof(struct sm2_api)+smapi->plen;
	dma_addr_t dma_b = mem_addr+sizeof(struct sm2_api)+2*smapi->plen;
//	dma_addr_t dma_gx = mem_addr+sizeof(struct sm2_api)+3*smapi->plen;
//	dma_addr_t dma_gy = mem_addr+sizeof(struct sm2_api)+4*smapi->plen;
	dma_addr_t dma_n = mem_addr+sizeof(struct sm2_api)+5*smapi->plen;
	dma_addr_t dma_h = mem_addr+sizeof(struct sm2_api)+6*smapi->plen;
//	dma_addr_t dma_self_px = mem_addr+sizeof(struct sm2_api)+7*smapi->plen;
//	dma_addr_t dma_self_py = mem_addr+sizeof(struct sm2_api)+8*smapi->plen;
	dma_addr_t dma_self_pri = mem_addr+sizeof(struct sm2_api)+9*smapi->plen;
//	dma_addr_t dma_self_id = mem_addr+sizeof(struct sm2_api)+10*smapi->plen;
	dma_addr_t dma_self_tmp_px = mem_addr+sizeof(struct sm2_api)+10*smapi->plen+smapi->entlb;
//	dma_addr_t dma_self_tmp_py = mem_addr+sizeof(struct sm2_api)+11*smapi->plen+smapi->entlb;
	dma_addr_t dma_self_tmp_pri = mem_addr+sizeof(struct sm2_api)+12*smapi->plen+smapi->entlb;
	dma_addr_t dma_other_px = mem_addr+sizeof(struct sm2_api)+13*smapi->plen+smapi->entlb;
	dma_addr_t dma_other_py = mem_addr+sizeof(struct sm2_api)+14*smapi->plen+smapi->entlb;
//	dma_addr_t dma_idb = mem_addr+sizeof(struct sm2_api)+15*smapi->plen+smapi->entlb;
	dma_addr_t dma_other_tmp_px = mem_addr+sizeof(struct sm2_api)+15*smapi->plen+smapi->entla+smapi->entlb;
	dma_addr_t dma_other_tmp_py = mem_addr+sizeof(struct sm2_api)+16*smapi->plen+smapi->entla+smapi->entlb;
	dma_addr_t dma_key = mem_addr+sizeof(struct sm2_api)+17*smapi->plen+smapi->entla+smapi->entlb;
	dma_addr_t dma_s2 = mem_addr+sizeof(struct sm2_api)+17*smapi->plen+smapi->entla+smapi->entlb+smapi->klen;
	dma_addr_t dma_sb = mem_addr+sizeof(struct sm2_api)+17*smapi->plen+smapi->entla+smapi->entlb+smapi->klen+smapi->nlen;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_sm2_agreementB is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc,&smapi->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	append_fifo_load(desc, change_addr_for_sec(dma_n+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->k_phys+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(dma_self_tmp_pri+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);

	append_fifo_load(desc, change_addr_for_sec(dma_self_pri+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);

	append_fifo_load(desc, change_addr_for_sec(dma_h+smapi->plen-smapi->nlen), smapi->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_p), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_other_tmp_px), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_other_tmp_py), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_a), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->k_phys+smapi->plen), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_b), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B0 | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_other_px), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(smapi->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-smapi->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(dma_other_py), smapi->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_ADD| smapi->field);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | smapi->field);
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->hashin_phys), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(smapi_ext->hashin_phys+smapi->plen), smapi->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);

	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->zain_phys), 2+smapi->entla+6*smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(smapi_ext->zaout_phys), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(smapi_ext->zain_phys+2+smapi->entla+6*smapi->plen), 2+smapi->entlb+6*smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(smapi_ext->zaout_phys+smapi->nlen), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);

	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);//85
	//extern descriptor
	init_job_desc(smapi_ext->desc_ext, START_INDEX);
	append_math_add(smapi_ext->desc_ext, REG0, ZERO, ONE, 4);
	append_math_swap(smapi_ext->desc_ext, REG1, REG0, ONE, 4);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);

	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x40000);
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), 2*smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->zaout_phys), 2*smapi->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+2*smapi->plen), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(dma_key), smapi->klen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);	

	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x40000);
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys), smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->zaout_phys), 2*smapi->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_other_tmp_px), 2*smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(dma_self_tmp_px), 2*smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x40000);
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->one_phys), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+smapi->plen), smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(dma_s2), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);

	append_cmd(smapi_ext->desc_ext, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(smapi_ext->desc_ext, 0x40000);
	append_operation(smapi_ext->desc_ext, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->one_phys+1), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashin_phys+smapi->plen), smapi->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(smapi_ext->desc_ext, change_addr_for_sec(smapi_ext->hashout_phys), smapi->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(smapi_ext->desc_ext, change_addr_for_sec(dma_sb), smapi->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_sm2_agreementB);
#endif

void inline_cnstr_jobdesc_rscp_cipher(uint32_t *desc,struct rscp_api *rapi,dma_addr_t mem_addr)
{
	dma_addr_t dma = mem_addr+sizeof(struct rscp_api);
//	unsigned int i;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_rscp_cipher is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	if(rapi->wk_len)
	{
//		for(i=0; i<(rapi->wk_len+15)/16; i++)
//			append_load(desc, change_addr_for_sec(dma+i*16), 1, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_RSCP | (i << LDST_OFFSET_SHIFT));
		append_load(desc, change_addr_for_sec(dma), (rapi->wk_len+15)/16, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_RSCP | LDST_OFFSET_RSCP_KEY);
		dma += rapi->wk_len;
	}
	if(rapi->iv_len)
	{
//		for(i=0; i<(rapi->iv_len+15)/16; i++)
//			append_load(desc, change_addr_for_sec(dma+i*16), 1, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_RSCP | ((0x40+i) << LDST_OFFSET_SHIFT));
		append_load(desc, change_addr_for_sec(dma), (rapi->iv_len+15)/16, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_RSCP | LDST_OFFSET_RSCP_IV);
		dma += rapi->iv_len;
	}
	if(rapi->udd_len)
	{
//		for(i=0; i<(rapi->udd_len+15)/16; i++)
//			append_load(desc, change_addr_for_sec(dma+i*16), 1, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_RSCP | ((0x48+i) << LDST_OFFSET_SHIFT));
		append_load(desc, change_addr_for_sec(dma), (rapi->udd_len+15)/16, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_RSCP | LDST_OFFSET_RSCP_UDD);
		dma += rapi->udd_len;
	}
	if(rapi->mk_len)
	{
//		for(i=0; i<(rapi->mk_len+15)/16; i++)
//			append_load(desc, change_addr_for_sec(dma+i*16), 1, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_RSCP | ((0x50+i) << LDST_OFFSET_SHIFT));
		append_load(desc, change_addr_for_sec(dma), (rapi->mk_len+15)/16, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_RSCP | LDST_OFFSET_RSCP_MK);
		dma += rapi->mk_len;
	}
	append_operation(desc, OP_TYPE_RSCP | OP_RSCP_CLASS_1 | OP_RSCP_BLOCKING | OP_RSCP_AS_UPDATE | OP_RSCP_NON_FILLING | (rapi->algo_type << OP_RSCP_ALGO_TYPE_SHIFT)  | OP_RSCP_MODE_KEY_EXPANSION);
	append_operation(desc, OP_TYPE_RSCP | OP_RSCP_CLASS_1 | OP_RSCP_NON_BLOCKING | OP_RSCP_AS_UPDATE  | OP_RSCP_NON_FILLING | (rapi->algo_type << OP_RSCP_ALGO_TYPE_SHIFT) | rapi->mode);

	append_fifo_load(desc, change_addr_for_sec(dma), rapi->in_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_RSCP_LAST);
	dma += rapi->in_len;

	append_fifo_store(desc, change_addr_for_sec(dma), rapi->out_len, FIFOST_TYPE_RSCP);
/*	
	if(rapi->iv_len)
	{
		append_store(desc, change_addr_for_sec(mem_addr+sizeof(struct rscp_api)+rapi->wk_len), (rapi->iv_len+15)/16, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_RSCP | LDST_OFFSET_RSCP_IV);
	}
	if(rapi->udd_len)
	{
		append_store(desc, change_addr_for_sec(mem_addr+sizeof(struct rscp_api)+rapi->wk_len+rapi->iv_len), (rapi->udd_len+15)/16, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_RSCP | LDST_OFFSET_RSCP_UDD);
	}
	
	sec_dump(desc,MAX_CSEC_DESCSIZE);
	*/
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_rscp_cipher);

void inline_cnstr_jobdesc_rscp_hash(uint32_t *desc,struct rscp_api *rapi,dma_addr_t mem_addr)
{
	dma_addr_t dma = mem_addr+sizeof(struct rscp_api);
	unsigned int fill = 0;
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_rscp_hash is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
	if(rapi->wk_len)
	{
		append_load(desc, change_addr_for_sec(dma), (rapi->wk_len+15)/16, LDST_CLASS_2_CCB | LDST_SRCDST_WORD_RSCP | LDST_OFFSET_RSCP_KEY);
		dma += rapi->wk_len;
	}
	if(rapi->iv_len)
	{
		append_load(desc, change_addr_for_sec(dma), (rapi->iv_len+15)/16, LDST_CLASS_2_CCB | LDST_SRCDST_WORD_RSCP | LDST_OFFSET_RSCP_IV);
		dma += rapi->iv_len;
	}
	if(rapi->udd_len)
	{
		append_load(desc, change_addr_for_sec(dma), (rapi->udd_len+15)/16, LDST_CLASS_2_CCB | LDST_SRCDST_WORD_RSCP | LDST_OFFSET_RSCP_UDD);
		dma += rapi->udd_len;
	}
	if(rapi->mk_len)
	{
		append_load(desc, change_addr_for_sec(dma), (rapi->mk_len+15)/16, LDST_CLASS_2_CCB | LDST_SRCDST_WORD_RSCP | LDST_OFFSET_RSCP_MK);
		dma += rapi->mk_len;
	}
	if((rapi->as & 0x1) == 0)
	{
		append_load(desc, change_addr_for_sec(mem_addr+16), 1, LDST_CLASS_2_CCB | LDST_SRCDST_WORD_RSCP | LDST_OFFSET_RSCP_HASH_LENGTH);
	}
	if(rapi->as & 0x2)
		fill = 1;
	append_operation(desc, OP_TYPE_RSCP | OP_RSCP_CLASS_2 | OP_RSCP_NON_BLOCKING | (rapi->as << OP_RSCP_AS_SHIFT) | (rapi->hash_db_size << OP_RSCP_DBS_SHIFT) | (fill << OP_RSCP_FB_SHIFT) | (rapi->algo_type << OP_RSCP_ALGO_TYPE_SHIFT) | (rapi->fill_length_size << OP_RSCP_LEN_SHIFT) | (rapi->output_buf_maxsize << OP_RSCP_VS_SHIFT) | rapi->mode);
	append_fifo_load(desc, change_addr_for_sec(dma), rapi->in_len, FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_RSCP_LAST);
	dma += rapi->in_len;
	append_store(desc, change_addr_for_sec(dma), rapi->out_len, LDST_CLASS_2_CCB | LDST_SRCDST_BYTE_CONTEXT);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_rscp_hash);

void inline_cnstr_jobdesc_rsa_genkey(uint32_t *desc, struct rsa_api *rapi,dma_addr_t mem_addr, struct rsa_api_ext *rapi_ext)
{

	/*
	  * in:head+p+q+e+n+d+r0~r9
	  * out:rsa_n, rsa_d
	*/
	unsigned int *jump_cmd_pri_p, *jump_cmd_pri_q, *jump_cmd_gcd, *jump_cmd_now; 
//	unsigned int *jump_cmd_cmp;
//	unsigned int input_rsa_bits = rapi->rsa_random_bit;
	unsigned int input_e_bits = rapi->fixed*8 ;		//rapi->fixed is byte, if rapi->fixed == 1,its fixed
	unsigned int blen = rapi->rsa_random_bit/8, blen_tmp = rapi->rsa_random_bit/16, crt = rapi->crt;
	uint32_t *desc_exp = rapi_ext->desc_ext;
	uint32_t *desc_exp2 = rapi_ext->desc_ext2;
	uint32_t *desc_crt = rapi_ext->desc_ext3;
	
	rapi_ext->rsa_p_phys = mem_addr+sizeof(struct rsa_api);
	rapi_ext->rsa_q_phys = mem_addr+sizeof(struct rsa_api)+blen;
	rapi_ext->rsa_e_phys = mem_addr+sizeof(struct rsa_api)+2*blen;
	rapi_ext->rsa_n_phys = mem_addr+sizeof(struct rsa_api)+3*blen;
	rapi_ext->rsa_d_phys = mem_addr+sizeof(struct rsa_api)+4*blen;
	rapi_ext->rsa_dp_phys= mem_addr+sizeof(struct rsa_api)+5*blen;
	rapi_ext->rsa_dq_phys = mem_addr+sizeof(struct rsa_api)+6*blen;
	rapi_ext->rsa_qInv_phys = mem_addr+sizeof(struct rsa_api)+7*blen;

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
//	append_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->r3_phys+blen-32), 32,  LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);

	append_cmd(desc, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM | LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
	append_cmd(desc, blen/4);
//	append_operation(desc, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI | OP_ALG_RNG4_NZB);
//	append_operation(desc, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
	append_operation(desc, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG );
	append_fifo_store(desc, change_addr_for_sec((dma_addr_t)rapi_ext->r0_phys+blen*3/4), blen/4, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGSTORE);
	jump_cmd_now = append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
	set_jump_tgt_here(desc, jump_cmd_now);

	jump_cmd_pri_p = desc_end(desc);
	if(blen != 0)
	{
		append_cmd(desc, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM | LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
		append_cmd(desc, blen/2);
//		append_operation(desc, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI | OP_ALG_RNG4_NZB);
//		append_operation(desc, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_operation(desc, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG);
 		append_fifo_store(desc, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_p_phys+blen/2), blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGSTORE | FIFOST_CLASS_SWAP);
		jump_cmd_now = append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
		set_jump_tgt_here(desc, jump_cmd_now);
	
		append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_p_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->r5_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_GCD);
		jump_cmd_now = append_jump(desc, JUMP_CLASS_NONE | JUMP_COND_PK_GCD_1 | JUMP_TEST_INVALL);
		set_jump_before(jump_cmd_pri_p, jump_cmd_now);
				
		append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->r2_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_p_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
		append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->r4_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
		jump_cmd_now = append_jump(desc, JUMP_CLASS_NONE | JUMP_COND_PK_BORROW| JUMP_TEST_ALL);
		set_jump_before(jump_cmd_pri_p, jump_cmd_now);
	}
					
	append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_p_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->r0_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->r1_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_PRIMALITY);
	jump_cmd_now = append_jump(desc, JUMP_CLASS_NONE | JUMP_COND_PK_PRIME | JUMP_TEST_INVALL);
	 set_jump_before(jump_cmd_pri_p, jump_cmd_now);
	
 	append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->r2_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
   	append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_p_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
   	append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->r6_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
   	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
   	append_fifo_store(desc, change_addr_for_sec((dma_addr_t)rapi_ext->r7_phys+blen/2), blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B | FIFOST_CLASS_SWAP);
//	jump_cmd_now = append_jump(desc,JUMP_CLASS_CLASS1|JUMP_TYPE_LOCAL|JUMP_TEST_ALL);
//	set_jump_tgt_here(desc, jump_cmd_now);
//store p-1 to N30
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N30 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	if(input_e_bits == 8)		//e is fixed
	{
		append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->r7_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_fifo_load(desc, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_e_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_GCD);
		jump_cmd_now = append_jump(desc, JUMP_CLASS_NONE | JUMP_COND_PK_GCD_1 | JUMP_TEST_INVALL);
		set_jump_before(jump_cmd_pri_p, jump_cmd_now);
	}

	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
//	append_ptr(desc, change_addr_for_sec (desc_exp));
	init_job_desc(desc_exp, START_INDEX);

	jump_cmd_pri_q = desc_end(desc_exp);

	if(blen != 0)
	{
		append_cmd(desc_exp, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM | LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
		append_cmd(desc_exp, blen/2);
//		append_operation(desc_exp, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI | OP_ALG_RNG4_NZB);
//		append_operation(desc_exp, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_operation(desc_exp, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG);
		append_fifo_store(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_q_phys+blen/2), blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGSTORE | FIFOST_CLASS_SWAP);
		jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
		set_jump_tgt_here(desc_exp, jump_cmd_now);
	
		append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_q_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->r5_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_GCD);
		jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_NONE | JUMP_COND_PK_GCD_1 | JUMP_TEST_INVALL);
		set_jump_before(jump_cmd_pri_q, jump_cmd_now);
				
		append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->r2_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_q_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
		append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->r4_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
		jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_NONE | JUMP_COND_PK_BORROW| JUMP_TEST_ALL);
		set_jump_before(jump_cmd_pri_q, jump_cmd_now);
	}

	append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_q_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->r0_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->r1_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_PRIMALITY);
	jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_NONE | JUMP_COND_PK_PRIME | JUMP_TEST_INVALL);
 	set_jump_before(jump_cmd_pri_q, jump_cmd_now);

 	append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->r2_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
   	append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_q_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
   	append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->r6_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
   	append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
   	append_fifo_store(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->r8_phys+blen/2), blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B | FIFOST_CLASS_SWAP);
//	jump_cmd_now = append_jump(desc_exp,JUMP_CLASS_CLASS1|JUMP_TYPE_LOCAL|JUMP_TEST_ALL);
//	set_jump_tgt_here(desc_exp, jump_cmd_now);
//store q-1 to N20
	append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	if(input_e_bits == 8)
	{
		append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->r8_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
   		append_fifo_load(desc_exp, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_e_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
   		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_GCD);
   		jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_NONE | JUMP_COND_PK_GCD_1 | JUMP_TEST_INVALL);
   		set_jump_before(jump_cmd_pri_q, jump_cmd_now);
	}

	append_jump(desc_exp, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
//	append_ptr(desc_exp, change_addr_for_sec (desc_exp2));
	init_job_desc(desc_exp2, START_INDEX);

   	jump_cmd_gcd = desc_end(desc_exp2);
   	if(input_e_bits != 8)
   	{
   		/* GCD : p-1 and e */
		append_cmd(desc_exp2, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM | LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
		append_cmd(desc_exp2, input_e_bits/8);
//		append_operation(desc_exp2, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI | OP_ALG_RNG4_NZB);
//		append_operation(desc_exp2, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_operation(desc_exp2, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG);
		append_fifo_store(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_e_phys+blen-input_e_bits/8), input_e_bits/8, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGSTORE | FIFOST_CLASS_SWAP);
		jump_cmd_now = append_jump(desc_exp2, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
		set_jump_tgt_here(desc_exp2, jump_cmd_now);

		/* GCD : p-1 and e */
   		append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->r7_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
   		append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_e_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
   		append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_GCD);
   		jump_cmd_now = append_jump(desc_exp2, JUMP_CLASS_NONE | JUMP_COND_PK_GCD_1 | JUMP_TEST_INVALL);
   		set_jump_before(jump_cmd_gcd, jump_cmd_now);

		/* GCD : q-1 and e */
   		append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->r8_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N| FIFOLDST_SGF | FIFOLD_IMM);
   		append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_e_phys+blen/2), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
   		append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_GCD);
   		jump_cmd_now = append_jump(desc_exp2, JUMP_CLASS_NONE | JUMP_COND_PK_GCD_1 | JUMP_TEST_INVALL);
   		set_jump_before(jump_cmd_gcd, jump_cmd_now);
   	}

	append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->r2_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_p_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_q_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_n_phys), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B | FIFOST_CLASS_SWAP);
//	jump_cmd_now = append_jump(desc_exp2,JUMP_CLASS_CLASS1|JUMP_TYPE_LOCAL|JUMP_TEST_ALL);
//	set_jump_tgt_here(desc_exp2, jump_cmd_now);

	/* calculate d, OP_ALG_PKMODE_MOD_MULT: r2 is N,  r0 is A, r1 is B, no E, r3 is OUT */
	append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->r2_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->r7_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->r8_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->r9_phys), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B | FIFOST_CLASS_SWAP);
	/* add to serial fifo_store and fifo_load r9*/
//	jump_cmd_now = append_jump(desc_exp2,JUMP_CLASS_CLASS1|JUMP_TYPE_LOCAL|JUMP_TEST_ALL);
//	set_jump_tgt_here(desc_exp2, jump_cmd_now);

	//P > Q
	append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->r2_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_p_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
       append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_q_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	jump_cmd_now = append_jump(desc_exp2, JUMP_CLASS_NONE | JUMP_COND_PK_BORROW | JUMP_TEST_INVALL | 0x0B);

   	append_fifo_store(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_p_phys), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B | FIFOST_CLASS_SWAP);
   	append_fifo_store(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_q_phys), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_A | FIFOST_CLASS_SWAP);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_B2 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N30 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N30 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	jump_cmd_now = append_jump(desc_exp2,JUMP_CLASS_CLASS1|JUMP_TYPE_LOCAL|JUMP_TEST_ALL);
	set_jump_tgt_here(desc_exp2, jump_cmd_now);

	/* OP_ALG_PKMODE_MOD_INV:  r3 is N,  rsa->e is A, no B, no E, rsa->d is OUT */
	append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->r9_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_e_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
	append_fifo_store(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_d_phys), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B | FIFOST_CLASS_SWAP);

	if(crt == 1)
	{
		append_jump(desc_exp2, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
//		append_ptr(desc_exp2, change_addr_for_sec (desc_crt));
		init_job_desc(desc_crt, START_INDEX);

//		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_CLEARMEM);
		append_load_as_imm(desc_crt, &blen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N30 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_N_SZ);
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);
//copy D to A-ram
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
//		append_fifo_load(desc_crt, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_d_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_fifo_store(desc_crt, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_dp_phys), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B | FIFOST_CLASS_SWAP);

		jump_cmd_now = append_jump(desc_crt,JUMP_CLASS_CLASS1|JUMP_TYPE_LOCAL|JUMP_TEST_ALL);
		set_jump_tgt_here(desc_crt, jump_cmd_now);

		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_N_SZ);
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);
		append_fifo_load(desc_crt, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_d_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);	
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_fifo_store(desc_crt, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_dq_phys), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B | FIFOST_CLASS_SWAP);

		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLEARMEM);
		append_load_as_imm(desc_crt, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
		append_load_as_imm(desc_crt, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
		append_load_as_imm(desc_crt, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);

		append_fifo_load(desc_crt, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_p_phys+blen/2), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_fifo_load(desc_crt, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_q_phys+blen/2), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
		append_fifo_store(desc_crt, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_qInv_phys+blen/2), blen_tmp, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B | FIFOST_CLASS_SWAP);
	}
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_rsa_genkey);

void inline_cnstr_jobdesc_pkha_end_big(uint32_t *desc,struct pkha_api *papi,dma_addr_t mem_addr)
{
	dma_addr_t dma = mem_addr+sizeof(struct pkha_api);
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_pkha is called, dma is 0x%p\n", desc);
	unsigned int e_len = papi->e_len;

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	if(papi->e_len)
	{
		append_load_as_imm(desc,&e_len,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
		append_fifo_load(desc, change_addr_for_sec(dma), papi->e_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	}
	dma += papi->e_len;
	if(papi->n_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->n_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	}
	dma += papi->n_len;
	if(papi->a_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->a_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	}
	dma += papi->a_len;
	if(papi->b_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->b_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	}
	dma += papi->b_len;
	if(papi->a0_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->a0_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	}
	dma += papi->a0_len;
	if(papi->a1_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->a1_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	}
	dma += papi->a1_len;
	if(papi->a2_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->a2_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2 | FIFOLDST_SGF | FIFOLD_IMM);
	}
	dma += papi->a2_len;
	if(papi->a3_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->a3_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	}
	dma += papi->a3_len;
	if(papi->b0_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->b0_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	}
	dma += papi->b0_len;
	if(papi->b1_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->b1_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1 | FIFOLDST_SGF | FIFOLD_IMM);
	}
	dma += papi->b1_len;
	if(papi->b2_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->b2_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2 | FIFOLDST_SGF | FIFOLD_IMM);
	}
	dma += papi->b2_len;
	if(papi->b3_len)
	{
		append_fifo_load(desc, change_addr_for_sec(dma), papi->b3_len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3 | FIFOLDST_SGF | FIFOLD_IMM);
	}
	dma += papi->b3_len;

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | papi->mode);

	if((papi->mode & 0xf) > 0x8 && (papi->mode & 0xf) < 0xc)
	{
		append_fifo_store(desc, change_addr_for_sec(dma), papi->n_len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B1 | FIFOST_CLASS_SWAP);
		dma+=papi->n_len;
		append_fifo_store(desc, change_addr_for_sec(dma), papi->n_len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B2 | FIFOST_CLASS_SWAP);
	}
	else
	{
		append_fifo_store(desc, change_addr_for_sec(dma), papi->n_len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B | FIFOST_CLASS_SWAP);
	}
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_pkha_end_big);

#if 1
//this crt swap, the data_in is big_end, but its not high-performance
void inline_cnstr_jobdesc_rsa_priv_crt(uint32_t *desc,struct pkha_api *papi,dma_addr_t mem_addr)
{
//	dma_addr_t dma = mem_addr+sizeof(struct pkha_api);
//	csec_debug(KERN_INFO "inline_cnstr_jobdesc_pkha is called, dma is 0x%p\n", desc);

	unsigned int *jump_cmd_now, blen = papi->n_len, blen_tmp = papi->n_len/2;

//	dma_addr_t dma_e = mem_addr+sizeof(struct pkha_api);
	dma_addr_t dma_n = mem_addr+sizeof(struct pkha_api);
	dma_addr_t dma_a= mem_addr+sizeof(struct pkha_api)+papi->n_len;
	dma_addr_t dma_out = mem_addr+sizeof(struct pkha_api)+2*papi->n_len;
	dma_addr_t dma_p = mem_addr+sizeof(struct pkha_api)+3*papi->n_len;
	dma_addr_t dma_q = mem_addr+sizeof(struct pkha_api)+4*papi->n_len;
	dma_addr_t dma_dp = mem_addr+sizeof(struct pkha_api)+5*papi->n_len;
	dma_addr_t dma_dq = mem_addr+sizeof(struct pkha_api)+6*papi->n_len;
	dma_addr_t dma_qInv = mem_addr+sizeof(struct pkha_api)+7*papi->n_len;

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);

	//c_Q = c mod Q;	store c_Q-->N22
	append_fifo_load(desc, change_addr_for_sec(dma_q), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(dma_a), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N22| OP_ALG_PKMODE_CPYMEM_N_SZ);

	//c_P = c mod P;	store c_P-->N21
	append_fifo_load(desc, change_addr_for_sec(dma_p), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(dma_a), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N21| OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	
	//m1 = c_P exp dP mod P;	m1 --> N31, store P-->N11
//	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(dma_p+blen_tmp), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_B2 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N21 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(dma_dp+blen_tmp), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N31 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//m2 = c_Q exp dQ mod Q; m2-->N32
	append_fifo_load(desc, change_addr_for_sec(dma_q+blen_tmp), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N22 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(dma_dq+blen_tmp), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N32 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//h = qInv * (m1 - m2) mod P; store (m1 - m2) mod P at B-mem
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_B2 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N31 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N32 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N33 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//h = qInv * N13 mod P; store h-->B-N12
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_B2 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_fifo_load(desc, change_addr_for_sec(dma_qInv+blen_tmp), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N33 | OP_ALG_PKMODE_DST_REG_B| OP_ALG_PKMODE_CPYMEM_N_SZ);
//	append_fifo_load(desc, change_addr_for_sec(dma_out), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc, &blen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);

	//m = m2 + h*q ---> mod P or N ?---->N
	append_fifo_load(desc, change_addr_for_sec(dma_n), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_fifo_load(desc, change_addr_for_sec(dma_q), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);	
	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N32 | OP_ALG_PKMODE_DST_REG_A| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);	
	append_fifo_store(desc, change_addr_for_sec(dma_out), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B | FIFOST_CLASS_SWAP);

}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_rsa_priv_crt);
#else
//this crt add swap, the data_in is big_end, and its high-performance, for test 
void inline_cnstr_jobdesc_rsa_priv_crt(uint32_t *desc,struct pkha_api *papi,dma_addr_t mem_addr)
{
//	dma_addr_t dma = mem_addr+sizeof(struct pkha_api);
//	csec_debug(KERN_INFO "inline_cnstr_jobdesc_pkha is called, dma is 0x%p\n", desc);

	unsigned int *jump_cmd_now, blen = papi->n_len, blen_tmp = papi->n_len/2;

//	dma_addr_t dma_e = mem_addr+sizeof(struct pkha_api);
	dma_addr_t dma_n = mem_addr+sizeof(struct pkha_api);
	dma_addr_t dma_a= mem_addr+sizeof(struct pkha_api)+papi->n_len;
	dma_addr_t dma_out = mem_addr+sizeof(struct pkha_api)+2*papi->n_len;
	dma_addr_t dma_p = mem_addr+sizeof(struct pkha_api)+3*papi->n_len;
	dma_addr_t dma_q = mem_addr+sizeof(struct pkha_api)+4*papi->n_len;
	dma_addr_t dma_dp = mem_addr+sizeof(struct pkha_api)+5*papi->n_len;
	dma_addr_t dma_dq = mem_addr+sizeof(struct pkha_api)+6*papi->n_len;
	dma_addr_t dma_qInv = mem_addr+sizeof(struct pkha_api)+7*papi->n_len;

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);

	//c_Q = c mod Q;	store c_Q-->N22
	append_fifo_load(desc, change_addr_for_sec(dma_q), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(dma_a), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N22| OP_ALG_PKMODE_CPYMEM_N_SZ);

	//c_P = c mod P;	store c_P-->N21
	append_fifo_load(desc, change_addr_for_sec(dma_p), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(dma_a), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N21| OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	
	//m1 = c_P exp dP mod P;	m1 --> N31, store P-->N11
//	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(dma_p), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_B2 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N21 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(dma_dp), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N31 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//m2 = c_Q exp dQ mod Q; m2-->N32
	append_fifo_load(desc, change_addr_for_sec(dma_q), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N22 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(dma_dq), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N32 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//h = qInv * (m1 - m2) mod P; store (m1 - m2) mod P at B-mem
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_B2 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N31 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N32 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N33 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	//h = qInv * N13 mod P; store h-->B-N12
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_B2 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_fifo_load(desc, change_addr_for_sec(dma_qInv+blen_tmp), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N33 | OP_ALG_PKMODE_DST_REG_B| OP_ALG_PKMODE_CPYMEM_N_SZ);
//	append_fifo_load(desc, change_addr_for_sec(dma_out), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc, &blen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);

	//m = m2 + h*q ---> mod P or N ?---->N
	append_fifo_load(desc, change_addr_for_sec(dma_n), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_fifo_load(desc, change_addr_for_sec(dma_q), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);	
	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N32 | OP_ALG_PKMODE_DST_REG_A| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);	
	append_fifo_store(desc, change_addr_for_sec(dma_out), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B | FIFOST_CLASS_SWAP);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_rsa_priv_crt);
#endif

#if 1
void inline_cnstr_jobdesc_rsa_priv_crt_simplified(unsigned int *desc, struct rsa_pub_priv_dma *para)
{
	unsigned int blen = para->blen, blen_tmp = para->blen/2;

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);

	//c_Q = c mod Q;	store c_Q-->B3
	append_fifo_load(desc, change_addr_for_sec(para->q_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->in_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A3| OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_B3| OP_ALG_PKMODE_CPYMEM_N_SZ);

	//c_P = c mod P;	store c_P-->B2
	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->in_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A3| OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_B2| OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	
	//m1 = c_P exp dP mod P;	m1 --> B1, store P-->A1
//	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->dp_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_B1 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//m2 = c_Q exp dQ mod Q; m2-->N11
	append_fifo_load(desc, change_addr_for_sec(para->q_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->dq_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N30 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//h = qInv * (m1 - m2) mod P; store (m1 - m2) mod P at B-mem
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A1 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N33 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//h = qInv * N13 mod P; store h-->A3
	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->qInv_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N33 | OP_ALG_PKMODE_DST_REG_B| OP_ALG_PKMODE_CPYMEM_N_SZ);
//	append_fifo_load(desc, change_addr_for_sec(dma_out), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc, &blen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);

	//m = m2 + h*q ---> mod P or N ?---->N
	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);

	append_fifo_load(desc, change_addr_for_sec(para->q_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);	
	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N30 | OP_ALG_PKMODE_DST_REG_A| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);	
	append_fifo_store(desc, change_addr_for_sec(para->out_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_rsa_priv_crt_simplified);
#else
void inline_cnstr_jobdesc_rsa_priv_crt_simplified(unsigned int *desc, struct rsa_pub_priv_dma *para)
{
	unsigned int *jump_cmd_now, blen = para->blen, blen_tmp = para->blen/2;

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);

	//m1 = c exp dP mod P
	//first step: c exp dP mod N --> N10
	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->in_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc, change_addr_for_sec(para->dp_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	
	//second step: N10 mod P :m1 --> A1
	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A1| OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//m2 = c exp dQ mod Q
	//first step: c exp dP mod N --> N20
	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->in_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc, change_addr_for_sec(para->dq_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//second step: N20 mod Q :m2 --> A2, and store m2 at dP temporarily for m2 + h*q
	append_fifo_load(desc, change_addr_for_sec(para->q_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_store(desc, change_addr_for_sec(para->out_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A2| OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//h = qInv * (m1 - m2) mod P; store (m1 - m2) mod P by A3; stpre h by N30
	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A1 | OP_ALG_PKMODE_DST_REG_B1| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A3| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
//	append_fifo_store(desc, change_addr_for_sec(dma_out), papi->n_len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);

	jump_cmd_now = append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
	set_jump_tgt_here(desc, jump_cmd_now);

	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);

	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->qInv_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_B| OP_ALG_PKMODE_CPYMEM_N_SZ);
//	append_fifo_load(desc, change_addr_for_sec(dma_out), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N30| OP_ALG_PKMODE_CPYMEM_N_SZ);

	jump_cmd_now = append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
	set_jump_tgt_here(desc, jump_cmd_now);

	//m = m2 + h*q
	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->q_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N30 | OP_ALG_PKMODE_DST_REG_B| OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_load_as_imm(desc, &blen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);	

	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B1| OP_ALG_PKMODE_CPYMEM_N_SZ);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A| OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->out_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);	
	append_fifo_store(desc, change_addr_for_sec(para->out_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_rsa_priv_crt_simplified);
#endif

#if 0
void inline_cnstr_jobdesc_rsa_priv_crt_simplified(unsigned int *desc, struct rsa_pub_priv_dma *para)
{
	unsigned int *jump_cmd_now, blen = para->blen, blen_tmp = para->blen/2;

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);

	//m1 = c exp dP mod P
	//first step: c exp dP mod N;		N-->B1、in-->B2、P-->A3、m1-->A1
	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_B1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	append_fifo_load(desc, change_addr_for_sec(para->in_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_B2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	append_fifo_load(desc, change_addr_for_sec(para->dp_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	
	//second step: N10 mod P :m1 --> A1
	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A1| OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//m2 = c exp dQ mod Q
	//first step: c exp dP mod N --> N20;		Q-->B3、m2-->A2
//	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

//	append_fifo_load(desc, change_addr_for_sec(para->in_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	append_fifo_load(desc, change_addr_for_sec(para->dq_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//second step: N20 mod Q :m2 --> A2, and store m2 at dP temporarily for m2 + h*q
	append_fifo_load(desc, change_addr_for_sec(para->q_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
//	append_fifo_store(desc, change_addr_for_sec(para->out_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A2| OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//h = qInv * (m1 - m2) mod P; store (m1 - m2) mod P -->N31
//	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N| OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A1 | OP_ALG_PKMODE_DST_REG_N21| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N21 | OP_ALG_PKMODE_DST_REG_A| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N31| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
//	append_fifo_store(desc, change_addr_for_sec(dma_out), papi->n_len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);

//	jump_cmd_now = append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
//	set_jump_tgt_here(desc, jump_cmd_now);
/*
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
//	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
*/
	//h = qInv * (m1 - m2) mod P; h-->N32
//	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);

//	append_fifo_load(desc, change_addr_for_sec(para->qInv_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc, change_addr_for_sec(para->qInv_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N31 | OP_ALG_PKMODE_DST_REG_B| OP_ALG_PKMODE_CPYMEM_N_SZ);
//	append_fifo_load(desc, change_addr_for_sec(dma_out), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);	


//add
	append_fifo_store(desc, change_addr_for_sec(para->dq_dma), blen_tmp, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);	//h



	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N32| OP_ALG_PKMODE_CPYMEM_N_SZ);

//	jump_cmd_now = append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
//	set_jump_tgt_here(desc, jump_cmd_now);

/*
	append_load_as_imm(desc, &blen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_load_as_imm(desc, &blen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
*/
	//m = m2 + h*q
//	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);

//	append_fifo_load(desc, change_addr_for_sec(para->q_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N32 | OP_ALG_PKMODE_DST_REG_B| OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);	

//	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);

//	append_fifo_load(desc, change_addr_for_sec(para->out_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_N11| OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A| OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);	
	append_fifo_store(desc, change_addr_for_sec(para->out_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
}
EXPORT_SYMBOL_GPL(inline_cnstr_jobdesc_rsa_priv_crt_simplified);
#endif

void inline_cnstr_jobdesc_rsa_genkey_simplified(unsigned int *desc, struct rsa_genkey_dma *para)
{

	/*
	  * in:head+p+q+e+n+d+r0~r9
	  * out:rsa_n, rsa_d
	*/
	unsigned int *jump_cmd_pri_p, *jump_cmd_pri_q, *jump_cmd_gcd, *jump_cmd_now, *jump_cmd_cmp;
	unsigned int input_elen = para->elen;		//rapi->fixed is byte, if rapi->fixed == 1,its fixed
	unsigned int blen = para->blen, blen_tmp = para->blen/2, crt = para->crt;
	uint32_t *desc_exp = desc + MAX_CSEC_DESCSIZE/4;
	uint32_t *desc_exp2 = desc_exp + MAX_CSEC_DESCSIZE/4;
	uint32_t *desc_crt = desc_exp2 + MAX_CSEC_DESCSIZE/4;
	
	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load(desc, change_addr_for_sec(para->r_dma.r3_dma), 32,  LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);

	append_cmd(desc, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM | LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
	append_cmd(desc, blen/4);
	append_operation(desc, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI | OP_ALG_RNG4_NZB);
	append_fifo_store(desc, change_addr_for_sec(para->r_dma.r0_dma), blen/4, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGSTORE);
	jump_cmd_now = append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
	set_jump_tgt_here(desc, jump_cmd_now);

	jump_cmd_pri_p = desc_end(desc);
	if(blen == 512)
	{
		append_cmd(desc, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM | LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
		append_cmd(desc, 255);
		append_operation(desc, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG);
		append_seq_fifo_store(desc, 255, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | 255);
		append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
		append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

		append_cmd(desc, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM | LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
		append_cmd(desc, 1);
		append_operation(desc, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI | OP_ALG_RNG4_NZB);
		append_seq_fifo_store(desc, 1, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | 1);

		append_fifo_load(desc, change_addr_for_sec(para->r_dma.r2_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	 	append_fifo_store(desc, change_addr_for_sec(para->sec_dma.p_dma), blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
		jump_cmd_now = append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
		set_jump_tgt_here(desc, jump_cmd_now);
	}
	else
	{
		append_cmd(desc, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM | LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
		append_cmd(desc, blen/2);
		append_operation(desc, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG);
		append_seq_fifo_store(desc,  blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | blen/2);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
 		append_fifo_store(desc, change_addr_for_sec(para->sec_dma.p_dma), blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
		jump_cmd_now = append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
		set_jump_tgt_here(desc, jump_cmd_now);
	}

	//new
//	append_fifo_store(desc, 0x80000000e034000UL, blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	
	jump_cmd_cmp = desc_end(desc);
//add compare
	append_fifo_load(desc, change_addr_for_sec(para->r_dma.r2_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->sec_dma.p_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	jump_cmd_now = append_jump(desc, JUMP_CLASS_NONE | JUMP_COND_PK_0 | JUMP_TEST_INVANY);
	set_jump_before(jump_cmd_cmp, jump_cmd_now);

	append_fifo_load(desc, change_addr_for_sec(para->sec_dma.p_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->r_dma.r5_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_GCD);
	jump_cmd_now = append_jump(desc, JUMP_CLASS_NONE | JUMP_COND_PK_GCD_1 | JUMP_TEST_INVALL);
	set_jump_before(jump_cmd_pri_p, jump_cmd_now);
			
	append_fifo_load(desc, change_addr_for_sec(para->r_dma.r2_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->sec_dma.p_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc, change_addr_for_sec(para->r_dma.r4_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	jump_cmd_now = append_jump(desc, JUMP_CLASS_NONE | JUMP_COND_PK_BORROW| JUMP_TEST_ALL);
	set_jump_before(jump_cmd_pri_p, jump_cmd_now);
			
	append_fifo_load(desc, change_addr_for_sec(para->sec_dma.p_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->r_dma.r0_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc, change_addr_for_sec(para->r_dma.r1_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_PRIMALITY);
//  append_jump(desc, JUMP_CLASS_NONE | JUMP_COND_PK_PRIME | JUMP_TEST_INVALL | 0xE9);
	jump_cmd_now = append_jump(desc, JUMP_CLASS_NONE | JUMP_COND_PK_PRIME | JUMP_TEST_INVALL);
 	set_jump_before(jump_cmd_pri_p, jump_cmd_now);

 	append_fifo_load(desc, change_addr_for_sec(para->r_dma.r2_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
   	append_fifo_load(desc, change_addr_for_sec(para->sec_dma.p_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
   	append_fifo_load(desc, change_addr_for_sec(para->r_dma.r6_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
   	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
   	append_fifo_store(desc, change_addr_for_sec(para->r_dma.r7_dma), blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);

	//new
//	append_fifo_store(desc, 0x80000000e034100UL, blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);

//	append_move(desc,MOVE_WAITCOMP|MOVE_SRC_MATH1|MOVE_DEST_MATH2|(8<<MOVE_LEN_SHIFT));
	jump_cmd_now = append_jump(desc,JUMP_CLASS_CLASS1|JUMP_TYPE_LOCAL|JUMP_TEST_ALL);
	set_jump_tgt_here(desc, jump_cmd_now);
//store p-1 to N30
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N30 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	if(input_elen == 1)		//e is fixed
	{
		jump_cmd_cmp = desc_end(desc);
		//add compare
		append_fifo_load(desc, change_addr_for_sec(para->r_dma.r2_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
		append_fifo_load(desc, change_addr_for_sec(para->r_dma.r7_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
		jump_cmd_now = append_jump(desc, JUMP_CLASS_NONE | JUMP_COND_PK_0 | JUMP_TEST_INVANY);
		set_jump_before(jump_cmd_cmp, jump_cmd_now);

		append_fifo_load(desc, change_addr_for_sec(para->r_dma.r7_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
		append_fifo_load(desc, change_addr_for_sec(para->sec_dma.e_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_GCD);
		jump_cmd_now = append_jump(desc, JUMP_CLASS_NONE | JUMP_COND_PK_GCD_1 | JUMP_TEST_INVALL);
		set_jump_before(jump_cmd_pri_p, jump_cmd_now);
	}

	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
//	append_ptr(desc, virt_to_phys (desc_exp));
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));

	init_job_desc(desc_exp, START_INDEX);
	jump_cmd_pri_q = desc_end(desc_exp);

	if(blen == 512)
	{
		append_cmd(desc_exp, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM | LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
		append_cmd(desc_exp, 255);
		append_operation(desc_exp, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG);
		append_seq_fifo_store(desc_exp, 255, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc_exp, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | 255);
		append_load_as_imm(desc_exp, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
		append_load_as_imm(desc_exp, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_LEFT_SHIFT_A);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

		append_cmd(desc_exp, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM | LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
		append_cmd(desc_exp, 1);
		append_operation(desc_exp, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI | OP_ALG_RNG4_NZB);
		append_seq_fifo_store(desc_exp, 1, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc_exp, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | 1);

		append_fifo_load(desc_exp, change_addr_for_sec(para->r_dma.r2_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	 	append_fifo_store(desc_exp, change_addr_for_sec(para->sec_dma.q_dma), blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
		jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
		set_jump_tgt_here(desc_exp, jump_cmd_now);
	}
	else
	{
		append_cmd(desc_exp, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM | LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
		append_cmd(desc_exp, blen/2);
		append_operation(desc_exp, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG);
		append_seq_fifo_store(desc_exp,  blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc_exp, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | blen/2);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
		append_fifo_store(desc_exp, change_addr_for_sec(para->sec_dma.q_dma), blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
		jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
		set_jump_tgt_here(desc_exp, jump_cmd_now);
	}

	jump_cmd_cmp = desc_end(desc_exp);
//add compare
	append_fifo_load(desc_exp, change_addr_for_sec(para->r_dma.r2_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc_exp, change_addr_for_sec(para->sec_dma.q_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_NONE | JUMP_COND_PK_0 | JUMP_TEST_INVANY);
	set_jump_before(jump_cmd_cmp, jump_cmd_now);

	append_fifo_load(desc_exp, change_addr_for_sec(para->sec_dma.q_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc_exp, change_addr_for_sec(para->r_dma.r5_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_GCD);
  	jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_NONE | JUMP_COND_PK_GCD_1 | JUMP_TEST_INVALL);
	set_jump_before(jump_cmd_pri_q, jump_cmd_now);
			
	append_fifo_load(desc_exp, change_addr_for_sec(para->r_dma.r2_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc_exp, change_addr_for_sec(para->sec_dma.q_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc_exp, change_addr_for_sec(para->r_dma.r4_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_NONE | JUMP_COND_PK_BORROW| JUMP_TEST_ALL);
	set_jump_before(jump_cmd_pri_q, jump_cmd_now);

	append_fifo_load(desc_exp, change_addr_for_sec(para->sec_dma.q_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc_exp, change_addr_for_sec(para->r_dma.r0_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc_exp, change_addr_for_sec(para->r_dma.r1_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_PRIMALITY);
	jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_NONE | JUMP_COND_PK_PRIME | JUMP_TEST_INVALL);
 	set_jump_before(jump_cmd_pri_q, jump_cmd_now);

 	append_fifo_load(desc_exp, change_addr_for_sec(para->r_dma.r2_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
   	append_fifo_load(desc_exp, change_addr_for_sec(para->sec_dma.q_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
   	append_fifo_load(desc_exp, change_addr_for_sec(para->r_dma.r6_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
   	append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
   	append_fifo_store(desc_exp, change_addr_for_sec(para->r_dma.r8_dma), blen/2, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	jump_cmd_now = append_jump(desc_exp,JUMP_CLASS_CLASS1|JUMP_TYPE_LOCAL|JUMP_TEST_ALL);
	set_jump_tgt_here(desc_exp, jump_cmd_now);
//store q-1 to N20
	append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	if(input_elen == 1)
	{
		jump_cmd_cmp = desc_end(desc_exp);
		//add compare
		append_fifo_load(desc_exp, change_addr_for_sec(para->r_dma.r2_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
		append_fifo_load(desc_exp, change_addr_for_sec(para->r_dma.r8_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
		jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_NONE | JUMP_COND_PK_0 | JUMP_TEST_INVANY);
		set_jump_before(jump_cmd_cmp, jump_cmd_now);

		append_fifo_load(desc_exp, change_addr_for_sec(para->r_dma.r8_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
   		append_fifo_load(desc_exp, change_addr_for_sec(para->sec_dma.e_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
   		append_operation(desc_exp, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_GCD);
   		jump_cmd_now = append_jump(desc_exp, JUMP_CLASS_NONE | JUMP_COND_PK_GCD_1 | JUMP_TEST_INVALL);
   		set_jump_before(jump_cmd_pri_q, jump_cmd_now);
	}

	append_jump(desc_exp, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
//	append_ptr(desc_exp, virt_to_phys (desc_exp2)); 
	append_ptr(desc_exp, change_addr_for_sec (para->desc_dma+2*MAX_CSEC_DESCSIZE));

	init_job_desc(desc_exp2, START_INDEX);

   	jump_cmd_gcd = desc_end(desc_exp2);
   	if(input_elen != 1)
   	{
   		/* GCD : p-1 and e */
		append_cmd(desc_exp2, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM | LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
		append_cmd(desc_exp2, input_elen);
		append_operation(desc_exp2, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI | OP_ALG_RNG4_NZB);
		append_seq_fifo_store(desc_exp2, input_elen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc_exp2, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | input_elen);
		append_fifo_store(desc_exp2, change_addr_for_sec(para->sec_dma.e_dma), input_elen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_A);

		jump_cmd_cmp = desc_end(desc_exp2);
		//add compare
		append_fifo_load(desc_exp2, change_addr_for_sec(para->r_dma.r2_dma), input_elen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
		append_fifo_load(desc_exp2, change_addr_for_sec(para->sec_dma.e_dma), input_elen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
		jump_cmd_now = append_jump(desc_exp2, JUMP_CLASS_NONE | JUMP_COND_PK_0 | JUMP_TEST_INVANY);
		set_jump_before(jump_cmd_cmp, jump_cmd_now);

		/* GCD : p-1 and e */
   		append_fifo_load(desc_exp2, change_addr_for_sec(para->r_dma.r7_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
   		append_fifo_load(desc_exp2, change_addr_for_sec(para->sec_dma.e_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
   		append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_GCD);
   		jump_cmd_now = append_jump(desc_exp2, JUMP_CLASS_NONE | JUMP_COND_PK_GCD_1 | JUMP_TEST_INVALL);
   		set_jump_before(jump_cmd_gcd, jump_cmd_now);
   		/* GCD : q-1 and e */
 //  		append_fifo_load(desc_exp2, change_addr_for_sec((dma_addr_t)rapi_ext->r8_phys), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
 		append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
 		append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
   		append_fifo_load(desc_exp2, change_addr_for_sec(para->sec_dma.e_dma), blen/2, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
   		append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_GCD);
   		jump_cmd_now = append_jump(desc_exp2, JUMP_CLASS_NONE | JUMP_COND_PK_GCD_1 | JUMP_TEST_INVALL);
   		set_jump_before(jump_cmd_gcd, jump_cmd_now);
   	}

	append_fifo_load(desc_exp2, change_addr_for_sec(para->r_dma.r2_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc_exp2, change_addr_for_sec(para->sec_dma.p_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc_exp2, change_addr_for_sec(para->sec_dma.q_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
//	append_fifo_store(desc_exp2, change_addr_for_sec((dma_addr_t)dma_rsa_n_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_store(desc_exp2, change_addr_for_sec(para->sec_dma.n_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	jump_cmd_now = append_jump(desc_exp2,JUMP_CLASS_CLASS1|JUMP_TYPE_LOCAL|JUMP_TEST_ALL);
	set_jump_tgt_here(desc_exp2, jump_cmd_now);


	//new, add for store E, D ,N at EVB
//	append_fifo_store(desc_exp2, 0x80000000E0340700UL, blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);	//N



	/* calculate d, OP_ALG_PKMODE_MOD_MULT: r2 is N,  r0 is A, r1 is B, no E, r3 is OUT */
	append_fifo_load(desc_exp2, change_addr_for_sec(para->r_dma.r2_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc_exp2, change_addr_for_sec(para->r_dma.r7_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc_exp2, change_addr_for_sec(para->r_dma.r8_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc_exp2, change_addr_for_sec(para->r_dma.r9_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	/* add to serial fifo_store and fifo_load r9*/
	jump_cmd_now = append_jump(desc_exp2,JUMP_CLASS_CLASS1|JUMP_TYPE_LOCAL|JUMP_TEST_ALL);
	set_jump_tgt_here(desc_exp2, jump_cmd_now);

	jump_cmd_cmp = desc_end(desc_exp2);
	//add compare
	append_fifo_load(desc_exp2, change_addr_for_sec(para->r_dma.r2_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc_exp2, change_addr_for_sec(para->r_dma.r9_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	jump_cmd_now = append_jump(desc_exp2, JUMP_CLASS_NONE | JUMP_COND_PK_0 | JUMP_TEST_INVANY);
	set_jump_before(jump_cmd_cmp, jump_cmd_now);

	//P > Q
	append_fifo_load(desc_exp2, change_addr_for_sec(para->r_dma.r2_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc_exp2, change_addr_for_sec(para->sec_dma.p_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
       append_fifo_load(desc_exp2, change_addr_for_sec(para->sec_dma.q_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	jump_cmd_now = append_jump(desc_exp2, JUMP_CLASS_NONE | JUMP_COND_PK_BORROW | JUMP_TEST_INVALL | 0x0B);

   	append_fifo_store(desc_exp2, change_addr_for_sec(para->sec_dma.p_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
   	append_fifo_store(desc_exp2, change_addr_for_sec(para->sec_dma.q_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_A);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_B2 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N30 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N30 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	jump_cmd_now = append_jump(desc_exp2,JUMP_CLASS_CLASS1|JUMP_TYPE_LOCAL|JUMP_TEST_ALL);
	set_jump_tgt_here(desc_exp2, jump_cmd_now);

	/* OP_ALG_PKMODE_MOD_INV:  r3 is N,  rsa->e is A, no B, no E, rsa->d is OUT */
	append_fifo_load(desc_exp2, change_addr_for_sec(para->r_dma.r9_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc_exp2, change_addr_for_sec(para->sec_dma.e_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc_exp2, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
	append_fifo_store(desc_exp2, change_addr_for_sec(para->sec_dma.d_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);


	//new, add for store E, D ,N at EVB
//	append_fifo_store(desc_exp2, 0x80000000E0340600UL, blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);	//D
//	append_fifo_store(desc_exp2, 0x80000000E0340500UL, blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_A);	//E

	if(crt == 1)
	{
		append_jump(desc_exp2, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
//		append_ptr(desc_exp2, virt_to_phys (desc_crt));
		append_ptr(desc_exp2, change_addr_for_sec (para->desc_dma+3*MAX_CSEC_DESCSIZE));

		init_job_desc(desc_crt, START_INDEX);
 
//		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_CLEARMEM);
		append_load_as_imm(desc_crt, &blen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N30 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_N_SZ);
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);
//copy D to A-ram
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
//		append_fifo_load(desc_crt, change_addr_for_sec((dma_addr_t)rapi_ext->rsa_d_phys), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_fifo_store(desc_crt, change_addr_for_sec(para->sec_dma.dp_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);


		//new
//		append_fifo_store(desc_crt, 0x80000000E0340a00UL, blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);	//dP  0xa00

		jump_cmd_now = append_jump(desc_crt,JUMP_CLASS_CLASS1|JUMP_TYPE_LOCAL|JUMP_TEST_ALL);
		set_jump_tgt_here(desc_crt, jump_cmd_now);

		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_N_SZ);
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_N_SZ);
		append_fifo_load(desc_crt, change_addr_for_sec(para->sec_dma.d_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);	
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_fifo_store(desc_crt, change_addr_for_sec(para->sec_dma.dq_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);


		//new
	//	append_fifo_store(desc_crt, 0x80000000E0340b00UL, blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);	//dQ  0xb00


		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLEARMEM);
		append_load_as_imm(desc_crt, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
		append_load_as_imm(desc_crt, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
		append_load_as_imm(desc_crt, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);

		append_fifo_load(desc_crt, change_addr_for_sec(para->sec_dma.p_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
		append_fifo_load(desc_crt, change_addr_for_sec(para->sec_dma.q_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
		append_operation(desc_crt, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
		append_fifo_store(desc_crt, change_addr_for_sec(para->sec_dma.qInv_dma), blen_tmp, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);

		//new
	//	append_fifo_store(desc_crt, 0x80000000E0340c00UL, blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);	//qInv  0xc00
		//new
	//	append_fifo_store(desc_crt, 0x80000000E0340800UL, blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_N);	//P  0x800
		//new
	//	append_fifo_store(desc_crt, 0x80000000E0340900UL, blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_A);	//Q  0x900

	}
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_rsa_genkey_simplified);

void inline_cnstr_jobdesc_rsa_pub_priv_simplified(unsigned int *desc, struct rsa_pub_priv_dma *para)
{
//	dma_addr_t dma = mem_addr+sizeof(struct pkha_api);
//	csec_debug(KERN_INFO "inline_cnstr_jobdesc_pkha is called, dma is 0x%p\n", desc);
	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);

	append_load_as_imm(desc, &para->blen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->e_dma), para->blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->n_dma), para->blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->in_dma), para->blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
	append_fifo_store(desc, change_addr_for_sec(para->out_dma), para->blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_rsa_pub_priv_simplified);

/*void inline_cnstr_jobdesc_rsa_priv_crt(unsigned int *desc, struct rsa_pub_priv_dma *para)
{
//	dma_addr_t dma = mem_addr+sizeof(struct pkha_api);
//	csec_debug(KERN_INFO "inline_cnstr_jobdesc_pkha is called, dma is 0x%p\n", desc);

	unsigned int *jump_cmd_now, blen = para->blen, blen_tmp = para->blen/2;

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);

	//m1 = c exp dP mod P
	//first step: c exp dP mod N --> N10
	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->a_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc, change_addr_for_sec(para->dp_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	
	//second step: N10 mod P :m1 --> A1
	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A1| OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//m2 = c exp dQ mod Q
	//first step: c exp dP mod N --> N20
	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->a_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc, change_addr_for_sec(para->dq_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_EXPO);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//second step: N20 mod Q :m2 --> A2, and store m2 at dP temporarily for m2 + h*q
	append_fifo_load(desc, change_addr_for_sec(para->q_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_store(desc, change_addr_for_sec(para->out_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A2| OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//h = qInv * (m1 - m2) mod P; store (m1 - m2) mod P by A3; stpre h by N30
	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A1 | OP_ALG_PKMODE_DST_REG_B1| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A3| OP_ALG_PKMODE_CPYMEM_SRC_SZ);
//	append_fifo_store(desc, change_addr_for_sec(dma_out), papi->n_len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);

	jump_cmd_now = append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
	set_jump_tgt_here(desc, jump_cmd_now);

	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &blen_tmp, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);

	append_fifo_load(desc, change_addr_for_sec(para->p_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->qInv_dma), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_B| OP_ALG_PKMODE_CPYMEM_N_SZ);
//	append_fifo_load(desc, change_addr_for_sec(dma_out), blen_tmp, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N30| OP_ALG_PKMODE_CPYMEM_N_SZ);

	jump_cmd_now = append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL);
	set_jump_tgt_here(desc, jump_cmd_now);

	//m = m2 + h*q
	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->q_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N30 | OP_ALG_PKMODE_DST_REG_B| OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_load_as_imm(desc, &blen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);	

	append_fifo_load(desc, change_addr_for_sec(para->n_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B1| OP_ALG_PKMODE_CPYMEM_N_SZ);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A| OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->out_dma), blen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);	
	append_fifo_store(desc, change_addr_for_sec(para->out_dma), blen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_rsa_priv_crt);
 */
void inline_cnstr_jobdesc_sm2_genkey(unsigned int *desc, struct sm2_genkey_private_dma *para)
{
	unsigned int ecc_op = (para->ecc_mode == FP) ? 0 : OP_ALG_PKMODE_MOD_F2M;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc,&para->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	if(para->rng_mode== HARDWARE)
	{
		//generate private key with random data
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->nlen);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->nlen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->nlen);

		//private key mod order
		if(para->plen%16)
		{
			//pad to 128b-alignment
			append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
			append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
		}
		append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.n), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);

		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);

		if(para->plen%16)
			append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf5);
		else
			append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
		append_fifo_store(desc, change_addr_for_sec(para->prikey_dma), para->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	else
	{
		if(para->plen%16)
		{
			//pad to 128b-alignment
			append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
			append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
		}
		append_fifo_load(desc, change_addr_for_sec(para->prikey_dma), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);		
	}
	//load p
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.p), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load G
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.gx), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.gy), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	//load a
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.a), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	//copy k to e_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load b
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.b), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | ecc_op);
	//store pubkey
	append_fifo_store(desc, change_addr_for_sec(para->pubkey_dma.x), para->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->pubkey_dma.y), para->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm2_genkey);

void inline_cnstr_jobdesc_sm2_encrypt(unsigned int *desc, struct sm2_enc_private_dma *para)
{
	unsigned int ecc_op = (para->ecc_mode == FP) ? 0 : OP_ALG_PKMODE_MOD_F2M;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc,&para->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_load_as_imm(desc,&para->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	if(para->rng_mode == HARDWARE)
	{
		//generate k
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->nlen);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->nlen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->nlen);
		//k mod order
		if(para->plen%16)
		{
			//pad to 128b-alignment
			append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
			append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
		}
		append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.n), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		if(para->plen%16)
			append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf5);
		else
			append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
	}
	else
	{
		if(para->plen%16)
		{
			//pad to 128b-alignment
			append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
			append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
		}
		append_fifo_load(desc, change_addr_for_sec(para->k_dma), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);		
	}		
	//calculate c1
	//load p
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.p), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load G
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.gx), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.gy), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	//load a
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.a), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	//save a
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load k
	//copy k to e_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load b
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.b), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//save b
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B0 | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | ecc_op);
	//store c1
	append_fifo_store(desc, change_addr_for_sec(para->ciphertext_dma.c1+1), para->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->ciphertext_dma.c1+1+para->plen), para->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);

	//calculate c2
	//load public key
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->pubkey_dma.x), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->pubkey_dma.y), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	//load a&b
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | ecc_op);
	//store x2,y2
	append_fifo_store(desc, change_addr_for_sec(para->hashin_dma), para->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->hashin_dma+para->plen), para->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
	//kdf
	//append_seq_out_ptr(desc, change_addr_for_sec(para->hashout_dma), para->ct * para->nlen, 0);
	append_seq_in_ptr(desc, change_addr_for_sec(para->msg_dma), para->klen, 0);
	append_seq_out_ptr(desc, change_addr_for_sec(para->ciphertext_dma.c2), para->klen, 0);
	append_load_as_imm(desc,&para->nlen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_load(desc, change_addr_for_sec(para->ct_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);
	if(para->endian_mode == BIG)
		append_math_swap(desc, REG0, REG0, ONE, 4);
	append_math_sub(desc, REG1, REG1, REG1, 4);
	append_math_add(desc, REG1, REG1, ONE, 4);
	if(para->endian_mode == LITTLE)
	{
		append_math_swap(desc, REG2, REG1, ONE, 4);
		append_store(desc, change_addr_for_sec(para->hashin_dma+para->plen*2), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH2);
		append_load(desc, change_addr_for_sec(para->hashin_dma+para->plen*2), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH3);
		append_math_sub(desc, REG3, REG2, REG3, 4);
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfc);
	}
	else
	{	
		append_store(desc, change_addr_for_sec(para->hashin_dma+para->plen*2), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		append_load(desc, change_addr_for_sec(para->hashin_dma+para->plen*2), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH3);
		append_math_sub(desc, REG3, REG1, REG3, 4);
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfc);
	}
/*
	append_load(desc, change_addr_for_sec(para->hashin_dma+para->plen*2), 4, LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_MATH3 | 4);
	if(para->endian_mode == BIG)
	{
		append_math_swap(desc, REG3, REG3, ONE, 4);
		append_math_sub(desc, REG3, REG1, REG3, 4);
	}
	else
		append_math_sub(desc, REG3, REG2, REG3, 4);
		
	if(para->endian_mode == LITTLE)
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfb);
	else
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfa);
*/
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);	
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 2*para->plen+4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	//append_seq_store(desc, para->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | para->nlen);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	append_math_sub(desc, REG3, REG0, REG1, 4);
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_MATH_Z | 0x5);
	append_seq_fifo_load(desc, para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_seq_fifo_store(desc, para->nlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);	
	if(para->endian_mode == LITTLE)
		append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 0xe8);//0xed);
	else
		append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 0xe9);//0xee);

	append_seq_fifo_load(desc, para->klen - (para->ct - 1) * para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_seq_fifo_store(desc, para->klen - (para->ct - 1) * para->nlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);	
	
	//add debug gsc	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_fifo_load(desc, change_addr_for_sec(para->ciphertext_dma.c2 + (para->ct - 1) * para->nlen), para->klen - (para->ct - 1) * para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0xfc);
/*
	//do t^mes
	//append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	//append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc,&para->klen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc, change_addr_for_sec(para->msg_dma), para->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	//store c2
	append_fifo_store(desc, change_addr_for_sec(para->ciphertext_dma.c2), para->klen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);	
*/
	//calculate c3
	//do sm3
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	//load x2
	append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	//load mes
	append_fifo_load(desc, change_addr_for_sec(para->msg_dma), para->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	//load y2
	append_fifo_load(desc, change_addr_for_sec(para->hashin_dma+para->plen), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	//store c3
	append_store(desc, change_addr_for_sec(para->ciphertext_dma.c3), para->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm2_encrypt);

void inline_cnstr_jobdesc_sm2_decrypt(unsigned int *desc, struct sm2_dec_private_dma *para)
{
	unsigned int ecc_op = (para->ecc_mode == FP) ? 0 : OP_ALG_PKMODE_MOD_F2M;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc,&para->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//calc x2,y2
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	//load p
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.p), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	//load x1
	append_fifo_load(desc, change_addr_for_sec(para->ciphertext_dma.c1+1), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLDST_SGF | FIFOLD_IMM | FIFOLD_TYPE_PK_A0);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	//load y1
	append_fifo_load(desc, change_addr_for_sec(para->ciphertext_dma.c1+1+para->plen), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLDST_SGF | FIFOLD_IMM | FIFOLD_TYPE_PK_A1);
	//load a
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.a), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	//load private key
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->prikey_dma), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//copy private key to e_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load b
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.b), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | ecc_op);
	//store x2,y2
	append_fifo_store(desc, change_addr_for_sec(para->hashin_dma), para->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->hashin_dma+para->plen), para->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);

	//do kdf
	//append_seq_out_ptr(desc, change_addr_for_sec(para->hashout_dma), para->ct * para->nlen, 0);
	append_seq_in_ptr(desc, change_addr_for_sec(para->ciphertext_dma.c2), para->klen, 0);
	append_seq_out_ptr(desc, change_addr_for_sec(para->msg_dma), para->klen, 0);
	append_load_as_imm(desc,&para->nlen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_load(desc, change_addr_for_sec(para->ct_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);
	if(para->endian_mode == BIG)
		append_math_swap(desc, REG0, REG0, ONE, 4);
	append_math_sub(desc, REG1, REG1, REG1, 4);
	append_math_add(desc, REG1, REG1, ONE, 4);
	if(para->endian_mode == LITTLE)
	{
		append_math_swap(desc, REG2, REG1, ONE, 4);
		append_store(desc, change_addr_for_sec(para->hashin_dma+para->plen*2), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH2);
		append_load(desc, change_addr_for_sec(para->hashin_dma+para->plen*2), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH3);
		append_math_sub(desc, REG3, REG2, REG3, 4);
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfc);
	}
	else
	{	
		append_store(desc, change_addr_for_sec(para->hashin_dma+para->plen*2), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		append_load(desc, change_addr_for_sec(para->hashin_dma+para->plen*2), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH3);
		append_math_sub(desc, REG3, REG1, REG3, 4);
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfc);
	}
/*
	append_load(desc, change_addr_for_sec(para->hashin_dma+para->plen*2), 4, LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_MATH3 | 4);
	if(para->endian_mode == BIG)
	{
		append_math_swap(desc, REG3, REG3, ONE, 4);
		append_math_sub(desc, REG3, REG1, REG3, 4);
	}
	else
		append_math_sub(desc, REG3, REG2, REG3, 4);
	if(para->endian_mode == LITTLE)
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfb);
	else
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_MATH_Z | 0xfa);
*/
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);	
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 2*para->plen+4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	//append_seq_store(desc, para->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | para->nlen);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	append_math_sub(desc, REG3, REG0, REG1, 4);
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_MATH_Z | 0x5);
	append_seq_fifo_load(desc, para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_seq_fifo_store(desc, para->nlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);	
	if(para->endian_mode == LITTLE)
		append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 0xe8);//0xed);
	else
		append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 0xe9);//0xee);

	append_seq_fifo_load(desc, para->klen - (para->ct - 1) * para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_seq_fifo_store(desc, para->klen - (para->ct - 1) * para->nlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);	

	//add debug gsc	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_fifo_load(desc, change_addr_for_sec(para->msg_dma+(para->ct - 1) * para->nlen), para->klen - (para->ct - 1) * para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0xfc);
	
	//do t^c2
/*
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc, change_addr_for_sec(para->ciphertext_dma.c2), para->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_store(desc, change_addr_for_sec(para->msg_dma), para->klen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);
*/

	//verify c3
	//do sm3
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	//load x2
	append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	//load mes
	append_fifo_load(desc, change_addr_for_sec(para->msg_dma), para->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	//load y2
	append_fifo_load(desc, change_addr_for_sec(para->hashin_dma+para->plen), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	//move hash to a_ram
	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | para->nlen);
	//load n
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.n+para->plen-para->nlen), para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load c3
	append_fifo_load(desc, change_addr_for_sec(para->ciphertext_dma.c3), para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
#if 0	
	//do mod sub	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	//is zero
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x1);
#else
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x1);
	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
		
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x1);
#endif	
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm2_decrypt);

void inline_cnstr_jobdesc_sm2_signature(unsigned int *desc, struct sm2_sig_private_dma *para)
{
	unsigned int ecc_op = (para->ecc_mode == FP) ? 0 : OP_ALG_PKMODE_MOD_F2M;

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc,&para->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_load_as_imm(desc,&para->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	if(para->rng_mode == HARDWARE)
	{
		//generate k
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->nlen);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->nlen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->nlen);
		//k mod order
		if(para->plen%16)
		{
			//pad to 128b-alignment
			append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
			append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
		}
		append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.n), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		if(para->plen%16)
			append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf5);
		else
			append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
	}
	else
	{
		if(para->plen%16)
		{
			//pad to 128b-alignment
			append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
			append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
		}
		append_fifo_load(desc, change_addr_for_sec(para->k_dma), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);		
	}	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(para->sig_mode == WITHID)
	{
		//calculate za
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->z_dma), para->zlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		//calculate e
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_move(desc, MOVE_SRC_CLASS2CTX | MOVE_DEST_CLASS2INFIFO | para->nlen);
		append_fifo_load(desc, change_addr_for_sec(para->msg_dma), para->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		//move e to a_ram
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | MOVE_AUX_LS | para->nlen);
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x10000);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->e_dma), para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	//do e mod n
	//load n
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.n), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//do amodn
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	//save e mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//(x1,y1) = [k]G
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	//load p
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.p), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load G
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.gx), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.gy), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	//load a
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.a), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	//load k to e_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//load b
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.b), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	//do ecc mod mult
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | ecc_op);

	//calculate r
	//load n
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.n), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//copy x1 to a_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do x1 mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	//load e mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do e+x1 mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//save r
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_store(desc, change_addr_for_sec(para->sig_dma.r), para->plen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B|FIFOST_CLASS_SWAP);

	//calculate s
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.n+para->plen-para->nlen), para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//load private key
	append_fifo_load(desc, change_addr_for_sec(para->prikey_dma+para->plen-para->nlen), para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);

	//save private key
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N13 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//load 1
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	//do 1+da mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//copy to a_ram
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do (1+da)^-1 mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
	//save result
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	//do r*da mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N13 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	//do k-r*da mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	//calc s
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	
	append_fifo_store(desc, change_addr_for_sec(para->sig_dma.s+para->plen-para->nlen), para->nlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B|FIFOST_CLASS_SWAP);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm2_signature);

void inline_cnstr_jobdesc_sm2_verify(unsigned int *desc, struct sm2_ver_private_dma *para)
{
	unsigned int ecc_op = (para->ecc_mode == FP) ? 0 : OP_ALG_PKMODE_MOD_F2M;

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc,&para->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//compare r and 1
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.n), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->sig_dma.r), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x1);
	//compare r and n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_BORROW | 0x2);
	//compare s and n
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->sig_dma.s), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_BORROW | 0x3);
	//compare s and 1
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x4);
	
	if(para->sig_mode == WITHID)
	{
		//calculate za
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->z_dma), para->zlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		//calculate e
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_move(desc, MOVE_SRC_CLASS2CTX | MOVE_DEST_CLASS2INFIFO | para->nlen);
		append_fifo_load(desc, change_addr_for_sec(para->msg_dma), para->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		//move e to a_ram
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | MOVE_AUX_LS | para->nlen);
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x10000);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->e_dma), para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);

	//do e mod n
	//load n
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.n), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	//do amodn
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	//save e mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N13 | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//t = (r + s) mod n
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);

	//calculate [t]Pa
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.p), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->pubkey_dma.x), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->pubkey_dma.y), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.a), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N20 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.b), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B0 | OP_ALG_PKMODE_DST_REG_N21 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | ecc_op);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_N22 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_N23 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//calculate [s]G
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.gx), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.gy), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N21 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT |ecc_op);

	//(x1, y1) = [s]G + [t]Pa
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N20 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N21 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N22 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N23 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_ADD | ecc_op);

	//r' = (e + x1) mod n
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.n), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N13 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//add debug
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N30 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//compare r' and r
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
#if 0	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x5);
#else
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x5);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N30 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB | OP_ALG_PKMODE_MOD_F2M);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x5);	
#endif		
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm2_verify);

void inline_cnstr_jobdesc_sm2_exchange(unsigned int *desc, struct sm2_exc_private_dma *para)
{
	unsigned int ecc_op = (para->ecc_mode == FP) ? 0 : OP_ALG_PKMODE_MOD_F2M;
	unsigned int *next_desc;

	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_load_as_imm(desc,&para->plen,4,LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.n+para->plen-para->nlen), para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->self_x_dma+para->plen-para->nlen), para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->self_tmp_prikey_dma+para->plen-para->nlen), para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);

	append_fifo_load(desc, change_addr_for_sec(para->self_prikey_dma+para->plen-para->nlen), para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);

	append_fifo_load(desc, change_addr_for_sec(para->h_dma+para->plen-para->nlen), para->nlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_N|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.p), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->other_tmp_pubkey_dma.x), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->other_tmp_pubkey_dma.y), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A3|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.a), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->other_x_dma), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->ecc_dma.b), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B0 | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | ecc_op);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A0|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->other_pubkey_dma.x), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	if(para->plen%16)
	{
		//pad to 128b-alignment
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
		append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_A1|NFIFOENTRY_PTYPE_ZEROS|(16-para->plen%16));
	}
	append_fifo_load(desc, change_addr_for_sec(para->other_pubkey_dma.y), para->plen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_ADD| ecc_op);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT | ecc_op);
	append_fifo_store(desc, change_addr_for_sec(para->u_dma.x), para->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->u_dma.y), para->plen, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);

	if(para->id_mode == WITHID)
	{
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->zain_dma), para->zain_len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->za_dma), para->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->zbin_dma), para->zbin_len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->zb_dma), para->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);

		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x10000);//94
	}

	append_math_add(desc, REG0, ZERO, ONE, 4);
	if(para->endian_mode == LITTLE)
	{
		append_math_swap(desc, REG1, REG0, ONE, 4);
		append_store(desc, change_addr_for_sec(para->ct_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
	}
	else
		append_store(desc, change_addr_for_sec(para->ct_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);
	
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));

	next_desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(next_desc, START_INDEX);

	append_cmd(next_desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(next_desc, 0x40000);
	append_operation(next_desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(next_desc, change_addr_for_sec(para->u_dma.x), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(next_desc, change_addr_for_sec(para->u_dma.y), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(next_desc, change_addr_for_sec(para->za_dma), para->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(next_desc, change_addr_for_sec(para->zb_dma), para->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(next_desc, change_addr_for_sec(para->ct_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(next_desc, change_addr_for_sec(para->key_dma), para->klen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);	

	append_cmd(next_desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(next_desc, 0x40000);
	append_operation(next_desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(next_desc, change_addr_for_sec(para->u_dma.x), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(next_desc, change_addr_for_sec(para->za_dma), para->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(next_desc, change_addr_for_sec(para->zb_dma), para->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	if(para->exc_mode == A)
	{
		append_fifo_load(next_desc, change_addr_for_sec(para->self_tmp_pubkey_dma.x), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(next_desc, change_addr_for_sec(para->self_tmp_pubkey_dma.y), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(next_desc, change_addr_for_sec(para->other_tmp_pubkey_dma.x), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(next_desc, change_addr_for_sec(para->other_tmp_pubkey_dma.y), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	}
	else
	{
		append_fifo_load(next_desc, change_addr_for_sec(para->other_tmp_pubkey_dma.x), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(next_desc, change_addr_for_sec(para->other_tmp_pubkey_dma.y), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(next_desc, change_addr_for_sec(para->self_tmp_pubkey_dma.x), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(next_desc, change_addr_for_sec(para->self_tmp_pubkey_dma.y), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);	
	}
	append_store(next_desc, change_addr_for_sec(para->hashout_dma), para->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(next_desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(next_desc, 0x40000);
	append_operation(next_desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(next_desc, change_addr_for_sec(para->s1_head_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(next_desc, change_addr_for_sec(para->u_dma.y), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(next_desc, change_addr_for_sec(para->hashout_dma), para->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(next_desc, change_addr_for_sec(para->s1_dma), para->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);

	append_cmd(next_desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(next_desc, 0x40000);
	append_operation(next_desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(next_desc, change_addr_for_sec(para->s2_head_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(next_desc, change_addr_for_sec(para->u_dma.y), para->plen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(next_desc, change_addr_for_sec(para->hashout_dma), para->nlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(next_desc, change_addr_for_sec(para->s2_dma), para->nlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm2_exchange);

void inline_cnstr_jobdesc_rng_simplified(uint32_t *desc, struct rng_para_dma*para)
{
	csec_debug(KERN_INFO "inline_cnstr_jobdesc_rng is called, dma is 0x%p\n", desc);

	init_job_desc(desc, START_INDEX);
//	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_N_RAM | OP_ALG_PKMODE_E_RAM | OP_ALG_PKMODE_CLEARMEM);

	append_cmd(desc, CMD_LOAD | LDST_CLASS_1_CCB | LDST_IMM |LDST_SRCDST_WORD_RNGDATASZ_REG | 4);
	append_cmd(desc, para->rng_size);

	append_operation(desc, OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG);

	append_fifo_store(desc, change_addr_for_sec(para->rng_dma), para->rng_size, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGSTORE);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_rng_simplified);

void inline_cnstr_jobdesc_sm9_genmastkey_for_enc(unsigned int *pdesc, struct sm9_genmastkey_for_enc_para *para)
{
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	if(para->rng_mode == HARDWARE)
	{
		//generate random number
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->cv.len);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->cv.len);
		//k mod order
		append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
		append_fifo_store(desc, change_addr_for_sec(para->ke_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->ke_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	//calc pub key
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_genmastkey_for_enc);

void inline_cnstr_jobdesc_sm9_genusekey_for_enc(unsigned int *pdesc, struct sm9_genusekey_for_enc_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	//calc t1
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->one_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hid_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_load(desc, change_addr_for_sec(para->ke_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);

	//calc t2
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);

	//calc deb
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_MOD_MUL);
	append_fifo_store(desc, change_addr_for_sec(para->deb.x), 2*para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->deb.y), 2*para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_genusekey_for_enc);

void inline_cnstr_jobdesc_sm9_genkey_for_enc(unsigned int *pdesc, struct sm9_genkey_for_enc_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	if(para->rng_mode == HARDWARE)
	{
		//generate random number
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->cv.len);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->cv.len);
		//k mod order
		append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
		append_fifo_store(desc, change_addr_for_sec(para->ke_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->ke_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//calc pub key
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
	//calc t1
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->one_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hid_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);

	//calc t2
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc deb
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_MOD_MUL);
	append_fifo_store(desc, change_addr_for_sec(para->deb.x), 2*para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->deb.y), 2*para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_genkey_for_enc);

void inline_cnstr_jobdesc_sm9_genmastkey_for_sig(unsigned int *pdesc, struct sm9_genmastkey_for_sig_para *para)
{
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	//calc pub key
	if(para->rng_mode == HARDWARE)
	{
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->cv.len);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->cv.len);
		//k mod order
		append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
		append_fifo_store(desc, change_addr_for_sec(para->ks_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->ks_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);

	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_MOD_MUL);
	append_fifo_store(desc, change_addr_for_sec(para->ppub_s.x), 2*para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->ppub_s.y), 2*para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_genmastkey_for_sig);

void inline_cnstr_jobdesc_sm9_genusekey_for_sig(unsigned int *pdesc, struct sm9_genusekey_for_sig_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	//calc t1
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->one_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hid_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_load(desc, change_addr_for_sec(para->ks_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//calc t2
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);

	//calc dsa
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsa.x), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->dsa.y), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_genusekey_for_sig);

void inline_cnstr_jobdesc_sm9_genkey_for_sig(unsigned int *pdesc, struct sm9_genkey_for_sig_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	//calc pub key
	if(para->rng_mode == HARDWARE)
	{
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->cv.len);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->cv.len);
		//k mod order
		append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
		append_fifo_store(desc, change_addr_for_sec(para->ks_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->ks_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_MOD_MUL);
	append_fifo_store(desc, change_addr_for_sec(para->ppub_s.x), 2*para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->ppub_s.y), 2*para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
	//calc t1
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->one_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hid_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//calc t2
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc dsa
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsa.x), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->dsa.y), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_genkey_for_sig);

void inline_cnstr_jobdesc_sm9_genkey_for_exc(unsigned int *pdesc, struct sm9_genkey_for_exc_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	//generate random number
	if(para->rng_mode == HARDWARE)
	{
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->cv.len);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->cv.len);
		//k mod order
		append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
		append_fifo_store(desc, change_addr_for_sec(para->ke_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->ke_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//calc pub key
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
	//calc private key a
	//calc t1
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->one_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hid_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//calc t2
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc deb
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_MOD_MUL);
	append_fifo_store(desc, change_addr_for_sec(para->dea.x), 2*para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->dea.y), 2*para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
	//calc private key b
	//calc t1
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->one_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hid_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	//calc t2
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_INV);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*2));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc deb
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_MOD_MUL);
	append_fifo_store(desc, change_addr_for_sec(para->deb.x), 2*para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->deb.y), 2*para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_genkey_for_exc);

void inline_cnstr_jobdesc_sm9_encapkey(unsigned int *pdesc, struct sm9_encapkey_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//H1(idb||hid, N)
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->one_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hid_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	//calc h1
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//calc Q
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_ADD);

	if(para->rng_mode == HARDWARE)
	{
		//gen r
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->cv.len);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->cv.len);
		//k mod order
		append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
		append_fifo_store(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);//124

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc C
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->c_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->c_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);//13
	//mont convert
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//71
	//calc g
	append_key(desc, change_addr_for_sec(para->key_dma), para->cv.len, KEY_DEST_CLASS_1 | KEY_NWB | KEY_DEST_PKHA_E);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*2));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	
	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		//jump to extern descriptor
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
		append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*(3+i)));
		desc = desc + MAX_CSEC_DESCSIZE/4;
		//extern descriptor
		init_job_desc(desc, START_INDEX);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->g_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*5));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);

	//calc w
	append_fifo_load(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->g_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_POW);
	append_sm9_store(desc, change_addr_for_sec(para->w_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	for(i=0; i<12; i++)
	{
		append_fifo_load(desc, change_addr_for_sec(para->w_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->w_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*6));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc kdf
	ct = (para->klen + para->cv.dlen - 1)/para->cv.dlen;
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{

		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->c_dma), 2*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->w_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->k_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//48
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_encapkey);

void inline_cnstr_jobdesc_sm9_decapkey(unsigned int *pdesc, struct sm9_decapkey_para *para)
{
	unsigned int i, ct ;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	//c is on curve
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->c_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->c_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_load(desc, change_addr_for_sec(para->ed.b), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->c_dma+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N13 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x1);
	//mont convert
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N13 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//88
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc w'
	append_key(desc, change_addr_for_sec(para->key_dma), para->cv.len, KEY_DEST_CLASS_1 | KEY_NWB | KEY_DEST_PKHA_E);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);
	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		//jump to extern descriptor
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
		append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*(2+i)));

		desc = desc + MAX_CSEC_DESCSIZE/4;
	
		//extern descriptor
		init_job_desc(desc, START_INDEX);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->w_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*4));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	for(i=0; i<12; i++)
	{
		append_fifo_load(desc, change_addr_for_sec(para->w_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->w_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}//91

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*5));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc kdf
	ct = (para->klen + para->cv.dlen - 1)/para->cv.dlen;
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{

		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->c_dma), 2*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->w_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->k_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//48
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLEARMEM);
	append_fifo_load(desc, change_addr_for_sec(para->k_dma), para->klen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0x2);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_decapkey);

void inline_cnstr_jobdesc_sm9_encrypt(unsigned int *pdesc, struct sm9_enc_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//H1(idb||hid, N)
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->one_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hid_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	//calc h1
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//calc Q
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_ADD);

	if(para->rng_mode == HARDWARE)
	{
		//gen r
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->cv.len);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->cv.len);
		//k mod order
		append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
		append_fifo_store(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);//124

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc c1
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->cd.c1), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->cd.c1+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);//13
	//mont convert
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//71
	//calc g
	append_key(desc, change_addr_for_sec(para->key_dma), para->cv.len, KEY_DEST_CLASS_1 | KEY_NWB | KEY_DEST_PKHA_E);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*2));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	
	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		//jump to extern descriptor
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
		append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*(3+i)));
		desc = desc + MAX_CSEC_DESCSIZE/4;
		//extern descriptor
		init_job_desc(desc, START_INDEX);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->g_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*5));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);

	//calc w
	append_fifo_load(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->g_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_POW);
	append_sm9_store(desc, change_addr_for_sec(para->w_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	for(i=0; i<12; i++)
	{
		append_fifo_load(desc, change_addr_for_sec(para->w_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->w_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*6));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	
	if(para->enc_type == SM9_SM3)
	{
	//calc kdf+c2+c3
	ct = (para->mlen + para->cv.dlen - 1)/para->cv.dlen;
	append_seq_in_ptr(desc, change_addr_for_sec(para->mes_dma), para->mlen, 0);
	append_seq_out_ptr(desc, change_addr_for_sec(para->cd.c2), para->mlen, 0);
	append_load_as_imm(desc, &para->cv.dlen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_load(desc, change_addr_for_sec(para->ct_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);
	if(para->endian_mode == BIG)	
		append_math_swap(desc, REG0, REG0, ONE, 4);
	append_math_sub(desc, REG1, REG1, REG1, 4);
	append_math_add(desc, REG1, REG1, ONE, 4);
	if(para->endian_mode == LITTLE)
	{
		append_math_swap(desc, REG2, REG1, ONE, 4);
		append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH2);
	}
	else
		append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c1), 2*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->w_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | para->cv.dlen);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	append_math_sub(desc, REG3, REG0, REG1, 4);
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_MATH_Z | 0x5);
	append_seq_fifo_load(desc, para->cv.dlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_seq_fifo_store(desc, para->cv.dlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);
	if(para->endian_mode == LITTLE)
		append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 0xe4);
	else
		append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 0xe5);
	append_seq_fifo_load(desc, para->mlen - (ct-1)*para->cv.dlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_seq_fifo_store(desc, para->mlen - (ct-1)*para->cv.dlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);
	append_fifo_store(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_A);

	append_math_add(desc, REG1, REG1, ONE, 4);
	if(para->endian_mode == LITTLE)
	{
		append_math_swap(desc, REG2, REG1, ONE, 4);
		append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH2);
	}
	else
		append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c1), 2*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->w_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->hashout_dma+para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c2), para->mlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma+para->mlen-(ct-1)*para->cv.dlen), para->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->cd.c3), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);

/*
	ct = (para->mlen + para->klen + para->cv.dlen - 1)/para->cv.dlen;
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{

		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->cd.c1), 2*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->w_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//48
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	//calc c2
	append_fifo_load(desc, change_addr_for_sec(para->mes_dma), para->mlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->mlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_load_as_imm(desc, &para->mlen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_store(desc, change_addr_for_sec(para->cd.c2), para->mlen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//60
	append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);
	//calc c3
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c2), para->mlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma+para->mlen), para->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->cd.c3), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);//72
*/
	}
	else
	{
	ct = (16 + para->klen + para->cv.dlen - 1)/para->cv.dlen;
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{

		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->cd.c1), 2*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->w_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//48
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10005);
	
	//calc c2
	append_key(desc, change_addr_for_sec(para->hashout_dma), 16, CLASS_1 | KEY_DEST_CLASS_REG);
	append_operation(desc, OP_TYPE_CLASS1_ALG |  OP_ALG_AAI_ECB | OP_ALG_ALGSEL_SM4 |	OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);
	append_fifo_load(desc, change_addr_for_sec(para->mes_dma), (para->mlen+15)/16*16, LDST_CLASS_1_CCB | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1);
	append_fifo_store(desc, change_addr_for_sec(para->cd.c2), (para->mlen+15)/16*16, FIFOST_TYPE_MESSAGE_DATA);
	append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);
	//calc c3
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c2), (para->mlen+15)/16*16, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma+16), para->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->cd.c3), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);//72
	}
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_encrypt);

void inline_cnstr_jobdesc_sm9_decrypt(unsigned int *pdesc, struct sm9_dec_para *para)
{
	unsigned int i, ct ;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	//c1 is on curve
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c1), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c1), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_load(desc, change_addr_for_sec(para->ed.b), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c1+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N13 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x1);
	//mont convert
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N13 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//88
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc w'
	append_key(desc, change_addr_for_sec(para->key_dma), para->cv.len, KEY_DEST_CLASS_1 | KEY_NWB | KEY_DEST_PKHA_E);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);
	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		//jump to extern descriptor
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
		append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*(2+i)));

		desc = desc + MAX_CSEC_DESCSIZE/4;
	
		//extern descriptor
		init_job_desc(desc, START_INDEX);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->w_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*4));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	for(i=0; i<12; i++)
	{
		append_fifo_load(desc, change_addr_for_sec(para->w_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->w_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}//91

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*5));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	if(para->enc_type == SM9_SM3)
	{
	//calc kdf+m'+c3
	ct = (para->mlen + para->cv.dlen - 1)/para->cv.dlen;
	append_seq_in_ptr(desc, change_addr_for_sec(para->cd.c2), para->mlen, 0);
	append_seq_out_ptr(desc, change_addr_for_sec(para->mes_dma), para->mlen, 0);
	append_load_as_imm(desc, &para->cv.dlen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_load(desc, change_addr_for_sec(para->ct_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);
	if(para->endian_mode == BIG)	
		append_math_swap(desc, REG0, REG0, ONE, 4);
	append_math_sub(desc, REG1, REG1, REG1, 4);
	append_math_add(desc, REG1, REG1, ONE, 4);
	if(para->endian_mode == LITTLE)
	{
		append_math_swap(desc, REG2, REG1, ONE, 4);
		append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH2);
	}
	else
		append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c1), 2*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->w_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | para->cv.dlen);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	append_math_sub(desc, REG3, REG0, REG1, 4);
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_MATH_Z | 0x5);
	append_seq_fifo_load(desc, para->cv.dlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_seq_fifo_store(desc, para->cv.dlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);
	if(para->endian_mode == LITTLE)
		append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 0xe4);
	else
		append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 0xe5);
	append_seq_fifo_load(desc, para->mlen - (ct-1)*para->cv.dlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_seq_fifo_store(desc, para->mlen - (ct-1)*para->cv.dlen, FIFOST_CLASS_NORMAL|FIFOLD_TYPE_PK_B);
	append_fifo_store(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_A);

	append_math_add(desc, REG1, REG1, ONE, 4);
	if(para->endian_mode == LITTLE)
	{
		append_math_swap(desc, REG2, REG1, ONE, 4);
		append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH2);
	}
	else
		append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c1), 2*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->w_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->hashout_dma+para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c2), para->mlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma+para->mlen-(ct-1)*para->cv.dlen), para->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
/*
	ct = (para->mlen + para->klen + para->cv.dlen - 1)/para->cv.dlen;
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{

		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->cd.c1), 2*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->w_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//48
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	//calc m'
	append_fifo_load(desc, change_addr_for_sec(para->cd.c2), para->mlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->mlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_load_as_imm(desc, &para->mlen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_store(desc, change_addr_for_sec(para->mes_dma), para->mlen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	//calc c3
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c2), para->mlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma+para->mlen), para->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
*/
	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | para->cv.dlen);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c3), para->cv.dlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_load_as_imm(desc, &para->cv.dlen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x2);
	}
	else
	{
	ct = (16 + para->klen + para->cv.dlen - 1)/para->cv.dlen;
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{

		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->cd.c1), 2*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->w_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//48
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10005);
	
	//calc m'
	append_key(desc, change_addr_for_sec(para->hashout_dma), 16, CLASS_1 | KEY_DEST_CLASS_REG);
	append_operation(desc, OP_TYPE_CLASS1_ALG |  OP_ALG_AAI_ECB | OP_ALG_ALGSEL_SM4 |	OP_ALG_AS_INITFINAL | OP_ALG_DECRYPT);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c2), (para->mlen+15)/16*16, LDST_CLASS_1_CCB | FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST1);
	append_fifo_store(desc, change_addr_for_sec(para->mes_dma), (para->mlen+15)/16*16, FIFOST_TYPE_MESSAGE_DATA);
	append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);

	//calc c3
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c2), (para->mlen+15)/16*16, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma+16), para->klen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);

	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | para->cv.dlen);
	append_fifo_load(desc, change_addr_for_sec(para->cd.c3), para->cv.dlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_load_as_imm(desc, &para->cv.dlen, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x2);	
	}
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_decrypt);

void inline_cnstr_jobdesc_sm9_signature(unsigned int *pdesc, struct sm9_sig_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_s.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_s.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_s.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_s.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//62
	//calc g
	append_key(desc, change_addr_for_sec(para->key_dma), para->cv.len, KEY_DEST_CLASS_1 | KEY_NWB | KEY_DEST_PKHA_E);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));

	desc = desc + MAX_CSEC_DESCSIZE/4;
	
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	
	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		//jump to extern descriptor
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
		append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*(i+2)));

		desc = desc + MAX_CSEC_DESCSIZE/4;
	
		//extern descriptor
		init_job_desc(desc, START_INDEX);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->g_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);//98
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*4));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	
	if(para->rng_mode == HARDWARE)
	{
		//gen r
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->cv.len);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->cv.len);
		//k mod order
		append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
		append_fifo_store(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	//calc w
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_sm9_load(desc, change_addr_for_sec(para->g_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_POW);
	append_sm9_store(desc, change_addr_for_sec(para->w_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);//31
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	for(i=0; i<12; i++)
	{
		append_fifo_load(desc, change_addr_for_sec(para->w_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->w_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}//121
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*5));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc h
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->two_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->mes_dma), para->mlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->w_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//48
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_store(desc, change_addr_for_sec(para->sd.h), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);

	append_fifo_load(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->dsa.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->dsa.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->sd.s+1), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->sd.s+1+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_signature);

void inline_cnstr_jobdesc_sm9_verify(unsigned int *pdesc, struct sm9_ver_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	//verify h
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_fifo_load(desc, change_addr_for_sec(para->sd.h), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_ALL | JUMP_COND_PK_BORROW | 0x1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_F2M | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_BORROW | 0x2);//15
	//s is on curve
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->sd.s+1), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_load(desc, change_addr_for_sec(para->ed.b), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->sd.s+1+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x3);//47
	//mont convert
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_s.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_s.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_s.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_s.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//105
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc g
	append_key(desc, change_addr_for_sec(para->key_dma), para->cv.len, KEY_DEST_CLASS_1 | KEY_NWB | KEY_DEST_PKHA_E);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);

	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		//jump to extern descriptor
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
		append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*(2+i)));
		desc = desc + MAX_CSEC_DESCSIZE/4;
		//extern descriptor
		init_job_desc(desc, START_INDEX);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->g_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);//98
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);

	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);

	//calc t
	append_fifo_load(desc, change_addr_for_sec(para->sd.h), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->g_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_POW);
	append_sm9_store(desc, change_addr_for_sec(para->t_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);//114
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*4));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);

	//calc h1
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->one_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hid_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//48
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);//72

	//calc p
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_MOD_MUL);

	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_s.x), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_s.y), 2*para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_MOD_ADD);
	append_fifo_store(desc, change_addr_for_sec(para->p.x), 2*para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->p.y), 2*para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
	append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);//113
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*5));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//mont convert
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->sd.s+1+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->sd.s+1), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->p.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->p.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->p.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->p.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//59
	//calc u
	append_fifo_load(desc, change_addr_for_sec(para->key_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*6));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		//jump to extern descriptor
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
		append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*(7+i)));
		desc = desc + MAX_CSEC_DESCSIZE/4;
		//extern descriptor
		init_job_desc(desc, START_INDEX);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);

	//calc w
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_sm9_load(desc, change_addr_for_sec(para->t_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
	append_sm9_store(desc, change_addr_for_sec(para->w_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);//105
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*9));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	for(i=0; i<12; i++)
	{
		append_fifo_load(desc, change_addr_for_sec(para->w_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->w_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}//91
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*10));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc h2
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->two_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->mes_dma), para->mlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->w_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//48
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_load(desc, change_addr_for_sec(para->sd.h), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x4);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_verify);

void inline_cnstr_jobdesc_sm9_exchange(unsigned int *pdesc, struct sm9_exc_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//calc Qb
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->one_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hid_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//50
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	//calc h1
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//calc Q
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_ADD);

	//calc Ra
	if(para->rng_mode == HARDWARE)
	{
		//gen r
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->cv.len);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->cv.len);
		//k mod order
		append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
		append_fifo_store(desc, change_addr_for_sec(para->k_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->k_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);//124
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
	//calc Qa
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->one_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hid_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//61
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	//calc h1
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//calc Q
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_ADD);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*2));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc Rb
	if(para->rng_mode == HARDWARE)
	{
		//gen r
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->cv.len);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->cv.len);
		//k mod order
		append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
		append_fifo_store(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);

	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);//124
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);//31
	//calc g1
	//mont convert
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//71

	append_fifo_load(desc, change_addr_for_sec(para->key_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*3));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);

	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
			//jump to extern descriptor
			append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
			append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*4));
			desc = desc + MAX_CSEC_DESCSIZE/4;
			//extern descriptor
			init_job_desc(desc, START_INDEX);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*5));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->g1b_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//calc g3
	append_fifo_load(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->g1b_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_POW);
	append_sm9_store(desc, change_addr_for_sec(para->g3b_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);//39
	//calc g2
	//mont convert
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//71
	
	append_fifo_load(desc, change_addr_for_sec(para->key_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*6));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);

	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
			//jump to extern descriptor
			append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
			append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*7));
			desc = desc + MAX_CSEC_DESCSIZE/4;
			//extern descriptor
			init_job_desc(desc, START_INDEX);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*8));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->g2b_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_fifo_load(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->g2b_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_POW);
	append_sm9_store(desc, change_addr_for_sec(para->g2b_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);//43
	for(i=0; i<12; i++)
	{
		append_fifo_load(desc, change_addr_for_sec(para->g1b_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->g1b_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
		append_fifo_load(desc, change_addr_for_sec(para->g2b_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->g2b_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
		append_fifo_load(desc, change_addr_for_sec(para->g3b_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->g3b_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
		if(i==2 || i==7)
		{
			//jump to extern descriptor
			append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
			if(i == 2)
				append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*9));
			else
				append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*10));
			desc = desc + MAX_CSEC_DESCSIZE/4;
			//extern descriptor
			init_job_desc(desc, START_INDEX);
		}
	}//85
	//calc SKb
	ct = (para->exklen + para->cv.dlen - 1)/para->cv.dlen;
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->g1b_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->g2b_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->g3b_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		//jump to extern descriptor
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
		append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*11));
		desc = desc + MAX_CSEC_DESCSIZE/4;
		//extern descriptor
		init_job_desc(desc, START_INDEX);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->exklen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_store(desc, change_addr_for_sec(para->skb_dma), para->exklen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_A);
	append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);//15
	//calc Sb
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->g2b_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g3b_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->msg_82_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g1b_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->sb_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);//59
	//calc S2
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->g2b_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g3b_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->msg_83_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g1b_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->s2_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);//104
	//calc g1'
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*12));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);

	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//71
	
	append_fifo_load(desc, change_addr_for_sec(para->key_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);//83

	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		}
		else
		{
			//jump to extern descriptor
			append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
			append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*13));
			desc = desc + MAX_CSEC_DESCSIZE/4;
			//extern descriptor
			init_job_desc(desc, START_INDEX);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	}
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*14));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->g1a_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_fifo_load(desc, change_addr_for_sec(para->k_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->g1a_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_POW);
	append_sm9_store(desc, change_addr_for_sec(para->g1a_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);//113
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*15));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc g2'
	//mont convert
	//append_fifo_load(desc, change_addr_for_sec(sm9->q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->dea.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->dea.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->dea.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->dea.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//71
	
	append_fifo_load(desc, change_addr_for_sec(para->key_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*16));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);

	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
			//jump to extern descriptor
			append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
			append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*17));
			desc = desc + MAX_CSEC_DESCSIZE/4;
			//extern descriptor
			init_job_desc(desc, START_INDEX);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*18));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->g2a_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//calc g3'
	append_fifo_load(desc, change_addr_for_sec(para->k_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->g2a_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_POW);
	append_sm9_store(desc, change_addr_for_sec(para->g3a_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);//43
	for(i=0; i<12; i++)
	{
		append_fifo_load(desc, change_addr_for_sec(para->g1a_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->g1a_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
		append_fifo_load(desc, change_addr_for_sec(para->g2a_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->g2a_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
		append_fifo_load(desc, change_addr_for_sec(para->g3a_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->g3a_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
		if(i==2 || i==7)
		{
			//jump to extern descriptor
			append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
			if(i == 2)
				append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*19));
			else
				append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*20));
			desc = desc + MAX_CSEC_DESCSIZE/4;
			//extern descriptor
			init_job_desc(desc, START_INDEX);
		}
	}
	//calc SKa
	ct = (para->exklen + para->cv.dlen - 1)/para->cv.dlen;
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->g1a_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->g2a_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->g3a_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		//jump to extern descriptor
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
		append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*21));
		desc = desc + MAX_CSEC_DESCSIZE/4;
		//extern descriptor
		init_job_desc(desc, START_INDEX);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//5
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->exklen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_store(desc, change_addr_for_sec(para->ska_dma), para->exklen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_A);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	//calc S1
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->g2a_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g3a_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->msg_82_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g1a_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->s1_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	//calc Sa
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->g2a_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g3a_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->msg_83_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g1a_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->sa_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	//cmp Sa and S2
	append_move(desc, MOVE_WAITCOMP | MOVE_SRC_CLASS2CTX | MOVE_DEST_PK_A | para->cv.dlen);
	append_fifo_load(desc, change_addr_for_sec(para->s2_dma), para->cv.dlen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x1);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_exchange);

void inline_cnstr_jobdesc_sm9_exchange_pre(unsigned int *pdesc, struct sm9_excpre_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		//calc ct
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->one_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->id_dma), para->entl, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hid_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//50
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	//calc h1
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_INFO_FIFO|4);
	append_cmd(desc, NFIFOENTRY_STYPE_PAD|NFIFOENTRY_DEST_CLASS1|NFIFOENTRY_DTYPE_PK_B0|NFIFOENTRY_PTYPE_ZEROS|(16-(para->cv.hlen/8)%16));
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.hlen/8, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
	append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_N_SZ);

	//calc Q
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p1.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A3 | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0 | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1 | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A3 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_ADD);

	//calc R
	if(para->rng_mode == HARDWARE)
	{
		//gen r
		append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_RNGDATASZ_REG|4);
		append_cmd(desc, para->cv.len);
		append_operation(desc,OP_TYPE_CLASS1_ALG | OP_ALG_ALGSEL_RNG | OP_ALG_RNG4_AI);
		append_seq_fifo_store(desc, para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_RNGFIFO);
		append_move(desc, MOVE_WAITCOMP | MOVE_SRC_OUTFIFO | MOVE_DEST_PK_A | para->cv.len);
		//k mod order
		append_fifo_load(desc, change_addr_for_sec(para->ed.n), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_REDUCT);
		append_jump(desc, JUMP_TYPE_LOCAL | JUMP_TEST_ALL | JUMP_COND_PK_0 | 0xf7);
		append_fifo_store(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
	}
	else
		append_fifo_load(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);//124
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ECC_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->r.x), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B1);
	append_fifo_store(desc, change_addr_for_sec(para->r.y), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B2);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_exchange_pre);

void inline_cnstr_jobdesc_sm9_exchange_maina(unsigned int *pdesc, struct sm9_excmaina_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);
	//check Rb is on curve
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_load(desc, change_addr_for_sec(para->ed.b), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N13 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x1);
	//calc g1'
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);

	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);

	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//71
	
	append_fifo_load(desc, change_addr_for_sec(para->key_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);//83

	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		}
		else
		{
			//jump to extern descriptor
			append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
			append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*2));
			desc = desc + MAX_CSEC_DESCSIZE/4;
			//extern descriptor
			init_job_desc(desc, START_INDEX);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	}
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*3));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->g1_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_fifo_load(desc, change_addr_for_sec(para->k_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->g1_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_POW);
	append_sm9_store(desc, change_addr_for_sec(para->g1_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);//113
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*4));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	//calc g2'
	//mont convert
	//append_fifo_load(desc, change_addr_for_sec(sm9->q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->dea.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->dea.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->dea.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->dea.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//71
	
	append_fifo_load(desc, change_addr_for_sec(para->key_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*5));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);

	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
			//jump to extern descriptor
			append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
			append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*6));
			desc = desc + MAX_CSEC_DESCSIZE/4;
			//extern descriptor
			init_job_desc(desc, START_INDEX);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*7));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->g2_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//calc g3'
	append_fifo_load(desc, change_addr_for_sec(para->k_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->g2_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_POW);
	append_sm9_store(desc, change_addr_for_sec(para->g3_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);//43
	for(i=0; i<12; i++)
	{
		append_fifo_load(desc, change_addr_for_sec(para->g1_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->g1_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
		append_fifo_load(desc, change_addr_for_sec(para->g2_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->g2_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
		append_fifo_load(desc, change_addr_for_sec(para->g3_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->g3_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
		if(i==2 || i==7)
		{
			//jump to extern descriptor
			append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
			if(i == 2)
				append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*8));
			else
				append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*9));
			desc = desc + MAX_CSEC_DESCSIZE/4;
			//extern descriptor
			init_job_desc(desc, START_INDEX);
		}
	}
	//calc SKa
	ct = (para->exklen + para->cv.dlen - 1)/para->cv.dlen;
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->g1_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->g2_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->g3_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		//jump to extern descriptor
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
		append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*10));
		desc = desc + MAX_CSEC_DESCSIZE/4;
		//extern descriptor
		init_job_desc(desc, START_INDEX);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}//5
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->exklen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_store(desc, change_addr_for_sec(para->sk_dma), para->exklen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_A);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_N_SZ);
	//calc S1
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->g2_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g3_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->msg_82_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g1_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->s1_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	//calc Sa
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->g2_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g3_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->msg_83_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g1_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->s2_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_exchange_maina);

void inline_cnstr_jobdesc_sm9_exchange_mainb(unsigned int *pdesc, struct sm9_excmainb_para *para)
{
	unsigned int i, ct = (para->cv.hlen+para->cv.v-1)/para->cv.v;
	unsigned int *desc = pdesc;

	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_E_SZ);

	//check Ra is on curve
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N12 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N10 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ed.a), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N12 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N10 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_fifo_load(desc, change_addr_for_sec(para->ed.b), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_ADD);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_N11 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_B | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A | OP_ALG_PKMODE_DST_REG_N13 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MULT);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N11 | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_SUB_AB);
	append_jump(desc, JUMP_TYPE_HALT_USER | JUMP_TEST_INVALL | JUMP_COND_PK_0 | 0x1);
	//calc g1
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->deb.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//71
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);

	append_fifo_load(desc, change_addr_for_sec(para->key_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*2));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);

	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
			//jump to extern descriptor
			append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
			append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*3));
			desc = desc + MAX_CSEC_DESCSIZE/4;
			//extern descriptor
			init_job_desc(desc, START_INDEX);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*4));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->g1_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//calc g3
	append_fifo_load(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->g1_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_POW);
	append_sm9_store(desc, change_addr_for_sec(para->g3_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);//39
	//calc g2
	//mont convert
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_MONT_CNST);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_N_SZ);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ppub_e.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->dsaa1_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.x), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_xs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y+para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->ed.p2.y), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_ys_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);
	append_fifo_load(desc, change_addr_for_sec(para->zero_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
	append_fifo_store(desc, change_addr_for_sec(para->t_zs_dma+para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_B);//71
	
	append_fifo_load(desc, change_addr_for_sec(para->key_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A3);
	append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
	append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B3 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_1_CCB|LDST_IMM|LDST_SRCDST_WORD_PKHA_B_SZ|4);
	append_cmd(desc, 2*para->cv.len);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B1 | OP_ALG_PKMODE_DST_REG_A0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B2 | OP_ALG_PKMODE_DST_REG_A1 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B3 | OP_ALG_PKMODE_DST_REG_A2 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*5));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_B_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_B_RAM | OP_ALG_PKMODE_CLR_SEG0 | OP_ALG_PKMODE_CLEARMEM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_A2 | OP_ALG_PKMODE_DST_REG_B0 | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_STEP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
	append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
	append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A1);
	append_sm9_store(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A2);

	append_fifo_load(desc, change_addr_for_sec(para->prev_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	for(i=0; i<2; i++)
	{
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_sm9_load(desc, change_addr_for_sec(para->p_inv_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FROBENIUS);
		append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
		append_sm9_store(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_A0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		if(i==1)
		{
			append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR_NEG);
			append_sm9_store(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B0);
			append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
			//jump to extern descriptor
			append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
			append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*6));
			desc = desc + MAX_CSEC_DESCSIZE/4;
			//extern descriptor
			init_job_desc(desc, START_INDEX);
		}
		append_sm9_load(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
		append_sm9_load(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B2);
		append_sm9_load(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B3);
		append_sm9_load(desc, change_addr_for_sec(para->q_xs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->q_ys_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
		append_sm9_load(desc, change_addr_for_sec(para->q_zs_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A2);
		append_sm9_load(desc, change_addr_for_sec(para->dsaa1_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_GTQ_P);
		append_sm9_store(desc, change_addr_for_sec(para->t_xs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B1);
		append_sm9_store(desc, change_addr_for_sec(para->t_ys_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B2);
		append_sm9_store(desc, change_addr_for_sec(para->t_zs_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR2_SZ | FIFOST_TYPE_PKHA_B3);
		append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
		append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
		append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_MUL0);
		append_sm9_store(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	}
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->p12r_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP1);
	append_sm9_store(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP2);
	append_sm9_store(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP3);
	append_sm9_store(desc, change_addr_for_sec(para->p12t1_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B1);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP4);
	append_sm9_store(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_sm9_store(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x4_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A1);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_sm9_load(desc, change_addr_for_sec(para->p_dma), para->cv.len, FIFOLDST_PKHA_PAR2_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP5);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	//jump to extern descriptor
	append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
	append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*7));
	desc = desc + MAX_CSEC_DESCSIZE/4;
	//extern descriptor
	init_job_desc(desc, START_INDEX);
	append_sm9_load(desc, change_addr_for_sec(para->x3_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_sm9_load(desc, change_addr_for_sec(para->x5_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x2_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP6);
	append_sm9_store(desc, change_addr_for_sec(para->p12t0_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_A0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_sm9_load(desc, change_addr_for_sec(para->x1_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B0);
	append_sm9_load(desc, change_addr_for_sec(para->x0_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B1);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_R_ATE_FINAL_EXP7);
	append_sm9_store(desc, change_addr_for_sec(para->g2_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_A_RAM | OP_ALG_PKMODE_CLR_SEG3 | OP_ALG_PKMODE_CLEARMEM);
	append_fifo_load(desc, change_addr_for_sec(para->r_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B | FIFOLDST_SGF | FIFOLD_IMM);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_B | OP_ALG_PKMODE_DST_REG_E | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_sm9_load(desc, change_addr_for_sec(para->g2_le_dma), para->cv.len, FIFOLDST_PKHA_PAR12_SZ | FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A0);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_PAR12_POW);
	append_sm9_store(desc, change_addr_for_sec(para->g2_le_dma), para->cv.len, FIFOST_CLASS_NORMAL| FIFOLDST_PKHA_PAR12_SZ | FIFOST_TYPE_PKHA_B0);
	//mont convert
	append_fifo_load(desc, change_addr_for_sec(para->ed.q), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N | FIFOLDST_SGF | FIFOLD_IMM);
	append_fifo_load(desc, change_addr_for_sec(para->one_dma), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_A);//43
	for(i=0; i<12; i++)
	{
		append_fifo_load(desc, change_addr_for_sec(para->g1_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->g1_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
		append_fifo_load(desc, change_addr_for_sec(para->g2_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->g2_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
		append_fifo_load(desc, change_addr_for_sec(para->g3_le_dma+(11-i)*para->cv.len), para->cv.len, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_B);
		append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_MOD_IN_MONTY | OP_ALG_PKMODE_MOD_OUT_MONTY | OP_ALG_PKMODE_MOD_MULT);
		append_fifo_store(desc, change_addr_for_sec(para->g3_dma+i*para->cv.len), para->cv.len, FIFOST_CLASS_NORMAL| FIFOST_CLASS_SWAP | FIFOST_TYPE_PKHA_B);
		if(i==2 || i==7)
		{
			//jump to extern descriptor
			append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
			if(i == 2)
				append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*8));
			else
				append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*9));
			desc = desc + MAX_CSEC_DESCSIZE/4;
			//extern descriptor
			init_job_desc(desc, START_INDEX);
		}
	}//85
	//calc SK
	ct = (para->exklen + para->cv.dlen - 1)/para->cv.dlen;
	append_math_add(desc, REG0, ZERO, ONE, 4);
	for(i=0; i<ct; i++)
	{
		if(para->endian_mode == LITTLE)
		{
			append_math_swap(desc, REG1, REG0, ONE, 4);
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH1);
		}
		else
			append_store(desc, change_addr_for_sec(para->hashin_dma), 4, LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH0);

		//do sm3
		append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
		append_cmd(desc, 0x40000);
		append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
		append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->g1_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->g2_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->g3_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
		append_fifo_load(desc, change_addr_for_sec(para->hashin_dma), 4, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
		//jump to extern descriptor
		append_jump(desc, JUMP_CLASS_NONE | JUMP_TYPE_NONLOCAL | JUMP_TEST_ALL | JUMP_DESC_EXP_128_DESC | 0);
		append_ptr(desc, change_addr_for_sec (para->desc_dma+MAX_CSEC_DESCSIZE*10));
		desc = desc + MAX_CSEC_DESCSIZE/4;
		//extern descriptor
		init_job_desc(desc, START_INDEX);
		append_store(desc, change_addr_for_sec(para->hashout_dma+i*para->cv.dlen), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
		append_math_add(desc, REG0, REG0, ONE, 4);
	}
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x10000);
	
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->exklen, FIFOLD_CLASS_CLASS1 | FIFOLD_TYPE_PK_N);
	append_operation(desc, OP_TYPE_PK | OP_ALG_PK | OP_ALG_PKMODE_SRC_REG_N | OP_ALG_PKMODE_DST_REG_A | OP_ALG_PKMODE_CPYMEM_SRC_SZ);
	append_fifo_store(desc, change_addr_for_sec(para->sk_dma), para->exklen, FIFOST_CLASS_NORMAL | FIFOST_TYPE_PKHA_A);
	append_jump(desc, JUMP_CLASS_CLASS1 | JUMP_TYPE_LOCAL | JUMP_TEST_ALL | 1);
	append_load_as_imm(desc, &para->cv.len, 4, LDST_CLASS_1_CCB | LDST_SRCDST_WORD_PKHA_A_SZ);//15
	//calc S1
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->g2_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g3_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->msg_82_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g1_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->s1_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);//59
	//calc S2
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->g2_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g3_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ida_dma), para->entla, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->idb_dma), para->entlb, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->ra.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.x), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->rb.y), para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);
	append_cmd(desc, CMD_LOAD|LDST_CLASS_IND_CCB|LDST_IMM|LDST_SRCDST_WORD_CLRW|4);
	append_cmd(desc, 0x40000);
	append_operation(desc, OP_TYPE_CLASS2_ALG|OP_ALG_ALGSEL_SM3|OP_ALG_AS_INITFINAL);
	append_fifo_load(desc, change_addr_for_sec(para->msg_83_dma), 1, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->g1_dma), 12*para->cv.len, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG);
	append_fifo_load(desc, change_addr_for_sec(para->hashout_dma), para->cv.dlen, FIFOLD_CLASS_CLASS2|FIFOLD_TYPE_MSG|FIFOLD_TYPE_LAST2);
	append_store(desc, change_addr_for_sec(para->s2_dma), para->cv.dlen, LDST_CLASS_2_CCB|LDST_SRCDST_BYTE_CONTEXT);//104	
}
EXPORT_SYMBOL(inline_cnstr_jobdesc_sm9_exchange_mainb);
