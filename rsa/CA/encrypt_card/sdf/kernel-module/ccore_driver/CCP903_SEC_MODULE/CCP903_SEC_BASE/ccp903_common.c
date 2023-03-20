#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <linux/semaphore.h>
#include <linux/version.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>

#define VM_KERNEL

extern void get_random_bytes(void *buf, int nbytes);

void *cvf_kmalloc(size_t size, gfp_t flags)
{
	return kmalloc(size, flags);
}
EXPORT_SYMBOL_GPL(cvf_kmalloc);


void *cvf_kzalloc(size_t size, gfp_t flags)
{
	return kzalloc(size, flags);
}
EXPORT_SYMBOL_GPL(cvf_kzalloc);


void cvf_kfree(void *p)
{
	kfree(p);
}
EXPORT_SYMBOL_GPL(cvf_kfree);


void *cvf_vmalloc(unsigned long size)
{
#ifdef VM_KERNEL
	return kmalloc(size, GFP_KERNEL);
#else	
	return vmalloc(size);
#endif
}
EXPORT_SYMBOL_GPL(cvf_vmalloc);


void *cvf_vzalloc(unsigned long size)
{
#ifdef VM_KERNEL
	return kzalloc(size, GFP_KERNEL);
#else	
	return vzalloc(size);
#endif
}
EXPORT_SYMBOL_GPL(cvf_vzalloc);


void cvf_vfree(const void *addr)
{
#ifdef VM_KERNEL
	kfree(addr);
#else	
	vfree(addr);
#endif
}
EXPORT_SYMBOL_GPL(cvf_vfree);


void *cvf_memcpy(void *dest, const void *src, size_t n)
{
	return memcpy(dest, src, n);
}
EXPORT_SYMBOL_GPL(cvf_memcpy);


void *cvf_memset(void *s, int c, size_t n)
{
	return memset(s, c, n);
}
EXPORT_SYMBOL_GPL(cvf_memset);


char *cvf_strcpy(char *dst, const char *src)
{
	return strcpy(dst, src);
}
EXPORT_SYMBOL_GPL(cvf_strcpy);


size_t cvf_strlen(const char *s)
{
	return strlen(s);
}
EXPORT_SYMBOL_GPL(cvf_strlen);


size_t cvf_strnlen(const char * s, size_t n)
{
	return strnlen(s, n);
}
EXPORT_SYMBOL_GPL(cvf_strnlen);


int cvf_memcmp(const void *cs, const void *ct, size_t count)
{
	return memcmp(cs, ct, count);
}
EXPORT_SYMBOL_GPL(cvf_memcmp);


int cvf_strcmp(const char *cs, const char *ct)
{
	return strcmp(cs, ct);
}
EXPORT_SYMBOL_GPL(cvf_strcmp);


int cvf_strncmp(const char *cs, const char *ct, size_t count)
{
	return strncmp(cs, ct, count);
}
EXPORT_SYMBOL_GPL(cvf_strncmp);


void *cvf_memchr(const void *s, int c, size_t count)
{
	return memchr(s, c, count);
}
EXPORT_SYMBOL_GPL(cvf_memchr);


char *cvf_strchr(const char *s, int c)
{
	return strchr(s, c);
}
EXPORT_SYMBOL_GPL(cvf_strchr);


void *cvf_dma_alloc_coherent(struct device *hwdev, size_t size, dma_addr_t *dma_handle, gfp_t gfp)
{
	return dma_alloc_coherent(hwdev, size, dma_handle, gfp);
}
EXPORT_SYMBOL_GPL(cvf_dma_alloc_coherent);


void cvf_dma_free_coherent(struct device *hwdev, size_t size, void *vaddr, dma_addr_t dma_handle)
{
	dma_free_coherent(hwdev, size, vaddr, dma_handle);
}
EXPORT_SYMBOL_GPL(cvf_dma_free_coherent);

dma_addr_t cvf_dma_map_single(struct device *dev, void *ptr, size_t size,
							  		enum dma_data_direction direction)
{
	return dma_map_single(dev, ptr, size, direction);
}
EXPORT_SYMBOL_GPL(cvf_dma_map_single);


void cvf_dma_unmap_single(struct device *dev, dma_addr_t dma_addr, size_t size,
		     						 enum dma_data_direction direction)
{
	dma_unmap_single(dev, dma_addr, size, direction);
}
EXPORT_SYMBOL_GPL(cvf_dma_unmap_single);


void cvf_dma_sync_single_for_cpu(struct device *dev, dma_addr_t dma_handle,
			     							size_t size, enum dma_data_direction direction)
{
	dma_sync_single_for_cpu(dev, dma_handle, size, direction) ;
}
EXPORT_SYMBOL_GPL(cvf_dma_sync_single_for_cpu);


void cvf_dma_sync_single_for_device(struct device *dev, dma_addr_t dma_handle,
				size_t size, enum dma_data_direction direction)
{
	dma_sync_single_for_device(dev, dma_handle, size, direction);
}
EXPORT_SYMBOL_GPL(cvf_dma_sync_single_for_device);


int cvf_sock_create(int family, int type, int protocol, struct socket **res)
{
	return sock_create(family, type, protocol, res);
}
EXPORT_SYMBOL_GPL(cvf_sock_create);


void cvf_sock_release(struct socket *sock)
{
	return sock_release(sock);
}
EXPORT_SYMBOL_GPL(cvf_sock_release);

#if 0
int cvf_sock_sendmsg(struct socket *sock, struct msghdr *msg)
{
	return sock_sendmsg(sock, msg);
}
EXPORT_SYMBOL_GPL(cvf_sock_sendmsg);

int cvf_sock_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
		 int flags)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 15, 0)
	return sock_recvmsg(sock, msg, flags);
#else
	return sock_recvmsg(sock, msg, size, flags);
#endif
}
EXPORT_SYMBOL_GPL(cvf_sock_recvmsg);
#endif

struct sk_buff *cvf_nlmsg_new(size_t payload, gfp_t flags)
{
	return nlmsg_new(payload, flags);
}
EXPORT_SYMBOL_GPL(cvf_nlmsg_new);


struct nlmsghdr *cvf_nlmsg_put(struct sk_buff *skb, u32 portid, u32 seq,
					 int type, int payload, int flags)
{
	return nlmsg_put(skb, portid, seq, type, payload, flags);
}
EXPORT_SYMBOL_GPL(cvf_nlmsg_put);


void cvf_nlmsg_end(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	 nlmsg_end(skb, nlh);
}
EXPORT_SYMBOL_GPL(cvf_nlmsg_end);


void cvf_nlmsg_cancel(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	nlmsg_cancel(skb, nlh);
}
EXPORT_SYMBOL_GPL(cvf_nlmsg_cancel);


void cvf_nlmsg_free(struct sk_buff *skb)
{
	nlmsg_free(skb);
}
EXPORT_SYMBOL_GPL(cvf_nlmsg_free);


int cvf_nlmsg_unicast(struct sock *sk, struct sk_buff *skb, u32 portid)
{
	return nlmsg_unicast(sk, skb, portid);
}
EXPORT_SYMBOL_GPL(cvf_nlmsg_unicast);


int cvf_nlmsg_multicast(struct sock *sk, struct sk_buff *skb,
				  u32 portid, unsigned int group, gfp_t flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
	return nlmsg_multicast(sk, skb, portid, group, flags);
#else
	return nlmsg_multicast(sk, skb, portid, group);
#endif
}
EXPORT_SYMBOL_GPL(cvf_nlmsg_multicast);

void cvf_spin_lock_init(spinlock_t *lock)
{
		spin_lock_init(lock);
}
EXPORT_SYMBOL_GPL(cvf_spin_lock_init);

void cvf_spin_lock(spinlock_t *lock)
{
	spin_lock(lock);
}
EXPORT_SYMBOL_GPL(cvf_spin_lock);


void cvf_spin_unlock(spinlock_t *lock)
{
	spin_unlock(lock);
}
EXPORT_SYMBOL_GPL(cvf_spin_unlock);

void cvf_spin_lock_irqsave(spinlock_t *lock, unsigned long *pflags)
{
	unsigned long flags;
	spin_lock_irqsave(lock, flags);
	if(pflags)
		*pflags = flags;
}
EXPORT_SYMBOL_GPL(cvf_spin_lock_irqsave);

void cvf_spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
	spin_unlock_irqrestore(lock, flags);
}
EXPORT_SYMBOL_GPL(cvf_spin_unlock_irqrestore);

void cvf_mutex_init(void *lock)
{
	mutex_init(lock);
}
EXPORT_SYMBOL_GPL(cvf_mutex_init);

void cvf_mutex_lock(struct mutex *lock)
{
	mutex_lock(lock);
}
EXPORT_SYMBOL_GPL(cvf_mutex_lock);


void cvf_mutex_unlock(struct mutex *lock)
{
	mutex_unlock(lock);
}
EXPORT_SYMBOL_GPL(cvf_mutex_unlock);


void cvf_sema_init(struct semaphore *sem, int val)
{
	sema_init(sem, val);
}
EXPORT_SYMBOL_GPL(cvf_sema_init);

void cvf_up(struct semaphore *sem)
{
	up(sem);
}
EXPORT_SYMBOL_GPL(cvf_up);


void cvf_down(struct semaphore *sem)
{
	down(sem);
}
EXPORT_SYMBOL_GPL(cvf_down);

void cvf_get_random_bytes(void *buf, int nbytes)
{
	get_random_bytes(buf, nbytes);
}
EXPORT_SYMBOL_GPL(cvf_get_random_bytes);


void cvf_INIT_LIST_HEAD(struct list_head *list)
{
	INIT_LIST_HEAD(list);
}
EXPORT_SYMBOL_GPL(cvf_INIT_LIST_HEAD);

void cvf_list_add(struct list_head *new, struct list_head *head)
{
	list_add(new, head);
}
EXPORT_SYMBOL_GPL(cvf_list_add);

void cvf_list_del(struct list_head *entry)
{
	list_del(entry);
}
EXPORT_SYMBOL_GPL(cvf_list_del);


struct sock *cvf_netlink_kernel_create(struct net *net, int unit, void (*cvf_input)(struct sk_buff *skb))
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 7, 0)

	struct netlink_kernel_cfg cfg = {
		.input = cvf_input,
	};

#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 7, 0)
	return __netlink_kernel_create(net, unit, THIS_MODULE, &cfg);
#else
	return netlink_kernel_create(net, unit, 0, cvf_input, NULL, THIS_MODULE);
#endif
}
EXPORT_SYMBOL_GPL(cvf_netlink_kernel_create);

void cvf_netlink_kernel_release(struct sock *sk)
{
	netlink_kernel_release(sk);
}
EXPORT_SYMBOL_GPL(cvf_netlink_kernel_release);

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 10, 0)
int cvf_netlink_rcv_skb(struct sk_buff *skb, int (*cvf_cb)(struct sk_buff *,
						     struct nlmsghdr *, struct netlink_ext_ack *))
{
	return netlink_rcv_skb(skb, cvf_cb);
}	
#else
int cvf_netlink_rcv_skb(struct sk_buff *skb, int (*cvf_cb)(struct sk_buff *,
						     struct nlmsghdr *))
{
	return netlink_rcv_skb(skb, cvf_cb);
}	
#endif
EXPORT_SYMBOL_GPL(cvf_netlink_rcv_skb);