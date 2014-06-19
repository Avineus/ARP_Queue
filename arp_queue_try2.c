#ifndef __KERNEL__
#define __KERNEL__
#endif

#define __NO_VERSION__ /* don't define kernel_verion in module.h */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/sched.h>

#include <linux/kthread.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include <linux/netfilter.h>
#include <linux/netfilter_arp.h>
#include <linux/if_arp.h>

#define KNETLINK_UNIT 17

// Underscores at the end makes MSG to align in bytes
#define MSG_USR_PID_REG	    "NL_REG_USER_PID_"
#define MSG_USR_PID_ACK	    "NL_ACK_USER_PID_"
#define MSG_USR_PID_UREG	"NL_UREG_USER_PID"
#define MSG_USR_PID_SIZ     16

static struct sock * knetlink_sk = NULL;
static int arp_seq=0;
static pid_t pid=-1;

/** process a netlink message
 * @param skb socket buffer containing the netlink message
 *
 * The netlink message is in skb-> data
 * This function does some printout, modifies the bytes of the payload,
 * and send a reply message back to the sender user process.
 */
void knetlink_process( struct sk_buff * skb )
{
	struct nlmsghdr * nlh = NULL;
	u8 * payload = NULL;
	int   payload_size;
	int   length;
	int   seq;
	struct sk_buff * rskb = NULL;

	/* process netlink message pointed by skb->data */
	nlh = (struct nlmsghdr *)skb->data;
	pid = nlh->nlmsg_pid; /* Global User space PID variable */
	length = nlh->nlmsg_len;
	seq = nlh->nlmsg_seq;
	printk("knetlink_process: nlmsg len %d type %d pid %d seq %d\n",
			length, nlh->nlmsg_type, pid, seq );
	/* process the payload */
	payload_size = nlh->nlmsg_len - NLMSG_LENGTH(0);
	if ( payload_size > 0 ) {
		payload = NLMSG_DATA( nlh );

		printk("knetlink_process: User space PID registration ");
        // case 1:
        if (!strncmp (payload, MSG_USR_PID_REG, MSG_USR_PID_SIZ))
        {
            // Received message to register the User PID
            strncpy(payload, MSG_USR_PID_ACK ,MSG_USR_PID_SIZ );
        }
        // case 2:
        else if (!strncmp (payload, MSG_USR_PID_UREG, MSG_USR_PID_SIZ))
        {
            // Received message to UNregister the User PID
            pid = -1;
            return;
        }

		printk("...\n");
		/* ... */
	}
	// reply
	rskb = alloc_skb( nlh->nlmsg_len, GFP_KERNEL );
	if ( rskb ) {
	  memcpy( rskb->data, skb->data, length );
	  skb_put( rskb, length );
	  kfree_skb( skb );
	 }
        else {
	  printk("knetlink_process: replies with the same socket_buffer\n");
	  rskb = skb;
	 }
	 nlh = (struct nlmsghdr *) rskb->data;
	 nlh->nlmsg_len   = length;
	 nlh->nlmsg_pid   = 0;
	 nlh->nlmsg_flags = 0;
	 nlh->nlmsg_type  = 2;
	 nlh->nlmsg_seq   = arp_seq++;
	 NETLINK_CB( rskb ).pid    = 0;
	 payload = NLMSG_DATA( nlh );

	 printk("knetlink_process: reply nlmsg len %d type %d pid %d\n",
        	 nlh->nlmsg_len, nlh->nlmsg_type, nlh->nlmsg_pid );
	 printk("knetlink_process: reply payload ");
         printk("%s ", payload);
	 printk("...\n");

	 netlink_unicast( knetlink_sk, rskb, pid, MSG_DONTWAIT );

}

/** input function
 * @param sk sock (namely knetlink_sk)
 * @param len length of the data on the sock
 *
 * Either it calls the knetlink_process (no-thread model)
 * or it wakes the knetlink thread up.
 */
void knetlink_input( struct sock * sk, int len )
{

	struct sk_buff * skb = NULL;
	printk("knetlink_input: sock %p, len %d\n", (void*)sk, len);
	if ( knetlink_sk != sk ) {
		printk("knetlink_input: wrong sock %p instead of %p\n",
				(void *)sk, (void *)knetlink_sk );
		return;
	}
	while ( (skb = skb_dequeue( &sk->sk_receive_queue ) ) != NULL ) {
		knetlink_process( skb );
	}
}

/*static inline struct arphdr * arp_hdr(struct sk_buff *skb)
{
	//return (struct arphdr *)skb->head + skb->network_header;
	return skb->nh.arph;
}*/

static inline int arp_hdr_len(struct sk_buff *skb)
{
	/* ARP header, plus 2 device addresses, plus 2 IP addresses. */
	return sizeof(struct arphdr) + (skb->dev->addr_len + sizeof(u32)) * 2;
}

static void print_arp(unsigned char *payload)
{
    unsigned char *parse_arp=NULL;
    struct arphdr *arp=(struct arphdr *)payload;
    printk ("\nARP Payload : \n");
    arp = (struct arphdr *)payload;
    printk("ar_hrd=%u\n", arp->ar_hrd);
    printk("ar_pro=%u\n", arp->ar_pro);
    printk("ar_hln=%u\n", arp->ar_hln);
    printk("ar_pln=%u\n", arp->ar_pln);
    printk("ar_op =%u\n", arp->ar_op);
    parse_arp=(unsigned char *)arp + 8;
    printk("src addr= %0x:%0x:%0x:%0x:%0x:%0x\n",
                      parse_arp[0],
                      parse_arp[1],
                      parse_arp[2],
                      parse_arp[3],
                      parse_arp[4],
                      parse_arp[5]);
    parse_arp += 6;
    printk("sip addr= %u.%u.%u.%u\n",
                      parse_arp[0],
                      parse_arp[1],
                      parse_arp[2],
                      parse_arp[3]);
    parse_arp += 4;
    printk("dst addr= %0x:%0x:%0x:%0x:%0x:%0x\n",
                      parse_arp[0],
                      parse_arp[1],
                      parse_arp[2],
                      parse_arp[3],
                      parse_arp[4],
                      parse_arp[5]);
    parse_arp += 6;
    printk("dip addr= %u.%u.%u.%u\n",
                      parse_arp[0],
                      parse_arp[1],
                      parse_arp[2],
                      parse_arp[3]);


}

static unsigned int arp_hook (unsigned int hooknum,
		struct sk_buff **skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct sk_buff *sb = *skb;
	struct sk_buff *rskb = NULL;
	struct arphdr *arp;
	int slength;
        int arplength;
	struct nlmsghdr * nlh = NULL;
	u8 * payload = NULL;

	arp = arp_hdr (sb);
        arplength = arp_hdr_len(sb);
	printk ("Arp is %x", htons (arp->ar_op));
	//nlh = (struct nlmsghdr *)sb->data;
	nlh = (struct nlmsghdr *)arp;
	printk ("\nInside arp_hook\n");
	printk ("\nConnected PID is..... %d\n", pid);
	printk ("\n arp payload length is ....%d\n", arplength);

	slength = sizeof(struct nlmsghdr) + arplength;
	// reply
	rskb = alloc_skb( slength, GFP_KERNEL );
	if ( rskb ) {
		//skb_put( rskb, slength );
		//kfree_skb( sb );
		printk ("Allocation of rskb success\n");
	}
        else {
		printk ("Allocation of rskb is not success\n");
		//printk("knetlink_process: replies with the same socket_buffer\n");
		//rskb = sb;
                return NF_ACCEPT;
	}
	printk ("Memory allocated successfully...\n");
	rskb->len = slength;
	rskb->tail = rskb->data + rskb->len;
	rskb->truesize = rskb->len;

	nlh = (struct nlmsghdr *) rskb->data;
	nlh->nlmsg_len   = slength;
	nlh->nlmsg_pid   = 0; /* from kernel */
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type  = 2;
	nlh->nlmsg_seq   = arp_seq++;
	NETLINK_CB(rskb).pid      = 0;
        //NETLINK_CB(rskb).dst_group = 0;
        //NETLINK_CB(rskb).dst_pid   = pid;
	payload = NLMSG_DATA( nlh );

        memcpy (payload, arp, arplength);

	printk("knetlink_process: reply nlmsg len %d type %d pid %d\n",
			nlh->nlmsg_len, nlh->nlmsg_type, nlh->nlmsg_pid );
	printk("knetlink_process: payload ");
        print_arp(payload);
	printk("...\n");

	if (pid != 0)
	{
		printk ("\nknetlink: unicast send..... Queued %d packets\n", (arp_seq-1));
		netlink_unicast( knetlink_sk, rskb, pid, MSG_DONTWAIT );
	}
	else
	{
		printk ("\nInside no process to send ...\n");
	}


	//return NF_ACCEPT;
	return 1;
}


static struct nf_hook_ops arp_in_hook = {
	.hook = arp_hook,
	.owner = THIS_MODULE,
	.pf = NF_ARP,
	.hooknum = NF_ARP_IN
};


/** module init
 * @return 0 on success
 *
 * It creates the netlink, and (in the thread model) the
 * knetlink thread
 */
int knetlink_init( void )
{

	//nf_register_hook (&arp_in_hook);
	//printk ("Hook to arp is registerd\n");

	if ( knetlink_sk != NULL ) {
		printk("knetlink_init: sock already present\n");
		return 1;
	}

	knetlink_sk = netlink_kernel_create( KNETLINK_UNIT, 0, knetlink_input, NULL, THIS_MODULE);
	if ( knetlink_sk == NULL ) {
		printk("knetlink_init: sock fail\n");
		return 1;
	}

	printk("knetlink_init: sock %p\n", (void*)knetlink_sk );
	nf_register_hook (&arp_in_hook);
	printk ("Hook to arp is registerd\n");
	return 0;
}

/** module exit
 *
 * In the thread model it stops the thread,
 * then it releases the knetlink sock.
 */
void knetlink_exit( void )
{
	if ( knetlink_sk != NULL ) {
		printk("knetlink_exit: release sock %p\n", (void*)knetlink_sk);
		sock_release( knetlink_sk->sk_socket );
	} else {
		printk("knetlink_exit: warning sock is NULL\n");
	}
	nf_unregister_hook (&arp_in_hook);

}

module_init( knetlink_init );
module_exit( knetlink_exit );

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Avineus");
MODULE_DESCRIPTION("ARP Queue");


