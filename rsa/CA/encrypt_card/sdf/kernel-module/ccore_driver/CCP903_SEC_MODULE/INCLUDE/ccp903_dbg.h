#ifndef __KERN_CSEC_DBG_H__
#define __KERN_CSEC_DBG_H__


#define CSEC_DEBUG_LV1	0x01
#define CSEC_DEBUG_LV2	0x02
#define CSEC_DEBUG_LV3	0x04
#define CSEC_DEBUG_LV4	0x08

#define CSEC_DBG1(fmt, args...)\
		do{\
				csec_info(CSEC_DEBUG_LV1, fmt, ##args);\
		}while(0)

#define CSEC_DBG2(fmt, args...)\
		do{\
				csec_info(CSEC_DEBUG_LV2, fmt, ##args);\
		}while(0)

#define CSEC_DBG3(fmt, args...)\
		do{\
				csec_info(CSEC_DEBUG_LV3, fmt, ##args);\
		}while(0)

#define CSEC_DBG4(fmt, args...)\
		do{\
				csec_info(CSEC_DEBUG_LV4, fmt, ##args);\
		}while(0)

void csec_info(unsigned int request_level,const char *format, ...);
		
#endif