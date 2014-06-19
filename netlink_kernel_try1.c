#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <net/sock.h>

#define NETLINK_TEST 17
#define MSG_LEN NLMSG_SPACE(1024)


static struct sock *nl_sk;

static void nl_data_ready(struct sock *sk, int len)
{
	struct sk_buff *nl_skb;
	struct nlmsghdr *nl_hdr;
	int pid;
	printk ("Inside nl_data_ready\n");

	nl_skb = skb_dequeue (&sk->sk_receive_queue);
	if (nl_skb != NULL)
	{
		/* Copying data from userspace */

		nl_hdr = (struct nlmsghdr *)nl_skb->data;
		pid = nl_hdr->nlmsg_pid;
		printk ("Netlink user has message.....\n");
		printk ("PID       : %d\n", pid);
		printk ("Message   : %s\n", (char *)NLMSG_DATA(nl_hdr));
	}
	else
		printk ("Netlink has no message...........\n");
}

static void netlink_test (void)
{
	nl_sk = netlink_kernel_create(NETLINK_TEST, 0, nl_data_ready,
			NULL, THIS_MODULE);
	if (nl_sk == NULL)
	{
		printk ("Unable to create kernel socket\n");
	}
	printk ("Waiting for data\n");
}

static int __init register_link (void)
{
	printk ("Netlink module is registered\n");
	netlink_test ();
	return 0;
}

static void __exit unregister_link (void)
{
	printk ("netlink module is unregistered\n");
}

module_init (register_link);
module_exit (unregister_link);
