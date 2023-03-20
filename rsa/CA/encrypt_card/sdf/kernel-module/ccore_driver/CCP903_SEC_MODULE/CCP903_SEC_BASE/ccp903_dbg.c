#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "../INCLUDE/ccp903_dbg.h"

unsigned int csec_debug_lvl = 0x00;
EXPORT_SYMBOL(csec_debug_lvl);

MODULE_PARM_DESC(debug, "Enable csec debug level output");

module_param_named(debug, csec_debug_lvl, int, 0600);


void csec_info(unsigned int request_level,const char *format, ...)
{
	va_list args;

	if (csec_debug_lvl & request_level) {
		//printk(KERN_INFO "[%d], ", request_level);
		va_start(args, format);
		vprintk(format, args);
		va_end(args);
	}	
}