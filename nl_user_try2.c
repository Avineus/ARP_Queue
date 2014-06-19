
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>   // socket, getpid, bind
#include <sys/socket.h>  // socket, bind
#include <unistd.h>      // getpid
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/if_arp.h>

// this value is not used in knetlink.c
#define KNETLINK 	17

#define PAYLOAD_SIZE 	1024
// Underscores at the end makes MSG to align in bytes
#define MSG_USR_PID_REG	    "NL_REG_USER_PID_"
#define MSG_USR_PID_ACK	    "NL_ACK_USER_PID_"
#define MSG_USR_PID_UREG	"NL_UREG_USER_PID"
#define MSG_USR_PID_SIZ     16

#define REGISTER            0
#define UNREGISTER          1


static void print_arp(unsigned char *payload)
{
    unsigned char *parse_arp=NULL;
    struct arphdr *arp=(struct arphdr *)payload;
    printf ("\nARP Payload : \n");
    arp = (struct arphdr *)payload;
    printf("ar_hrd=%u\n", arp->ar_hrd);
    printf("ar_pro=%u\n", arp->ar_pro);
    printf("ar_hln=%u\n", arp->ar_hln);
    printf("ar_pln=%u\n", arp->ar_pln);
    printf("ar_op =%u\n", arp->ar_op);
    parse_arp=(unsigned char *)arp + 8;
    printf("src addr= %0x:%0x:%0x:%0x:%0x:%0x\n",
                      parse_arp[0],
                      parse_arp[1],
                      parse_arp[2],
                      parse_arp[3],
                      parse_arp[4],
                      parse_arp[5]);
    parse_arp += 6;
    printf("sip addr= %u.%u.%u.%u\n",
                      parse_arp[0],
                      parse_arp[1],
                      parse_arp[2],
                      parse_arp[3]);
    parse_arp += 4;
    printf("dst addr= %0x:%0x:%0x:%0x:%0x:%0x\n",
                      parse_arp[0],
                      parse_arp[1],
                      parse_arp[2],
                      parse_arp[3],
                      parse_arp[4],
                      parse_arp[5]);
    parse_arp += 6;
    printf("dip addr= %u.%u.%u.%u\n",
                      parse_arp[0],
                      parse_arp[1],
                      parse_arp[2],
                      parse_arp[3]);


}

void receive_arp_packet(int sock)
{
    struct nlmsghdr nlh;     // netlink message header
    unsigned char rpayload[PAYLOAD_SIZE]; // payload
    struct iovec iov[2];     // iovec array
    struct msghdr msg;       // message-header
    struct sockaddr_nl peer; // peer address

    // receive PACKET from kernel
    memset( rpayload, 0, PAYLOAD_SIZE );
    memset( &nlh, 0, sizeof(nlh) );

    iov[0].iov_base = (void *)&nlh;
    iov[0].iov_len  = sizeof(nlh);
    iov[1].iov_base = (void *)rpayload;
    iov[1].iov_len  = PAYLOAD_SIZE;

    memset( &msg, 0, sizeof(msg) );
    msg.msg_name    = (void *)&peer;
    msg.msg_namelen = sizeof(peer);
    msg.msg_iov     = iov;
    msg.msg_iovlen  = 2;

    if ( recvmsg( sock, &msg, 0 ) < 0 ) {
        perror("Recvmsg error");
        exit(1);
    }

    printf ("Arp Payload : \n");
    print_arp(rpayload);
    printf ("... \n");

}

void register_arp_queue(int sock, int action)
{
  unsigned char payload[PAYLOAD_SIZE]; // payload
  unsigned char rpayload[PAYLOAD_SIZE]; // payload
  struct msghdr msg;       // message-header
  struct sockaddr_nl addr; // my netlink address
  struct sockaddr_nl peer; // peer address
  struct nlmsghdr nlh;     // netlink message header
  struct iovec iov[2];     // iovec array

  memset( &addr, 0, sizeof(addr) );
  addr.nl_family = AF_NETLINK;
  addr.nl_pad = 0;
  addr.nl_pid = getpid();
  addr.nl_groups = 0;

   //**************** sender *****************************
    printf("Sender: my pid %d\n", getpid() );
    memset( &peer, 0, sizeof(peer) );
    peer.nl_family = AF_NETLINK;
    peer.nl_pad = 0;
    peer.nl_pid = 0;      // peer is the kernel
    peer.nl_groups = 0;   // unicast
    printf("        server pid %d\n", peer.nl_pid);

    if (action == REGISTER)
    {
        // Message for Registering User PID to the Kernel
        strcpy(payload, MSG_USR_PID_REG);
    }
    else if (action == UNREGISTER)
        // Message for Unregistering User PID to the Kernel
        strcpy(payload, MSG_USR_PID_UREG);


    //nlh.nlmsg_len   = sizeof(nlh) + PAYLOAD_SIZE;
    nlh.nlmsg_len   = sizeof(nlh) + MSG_USR_PID_SIZ;
    nlh.nlmsg_type  = 5;
    nlh.nlmsg_flags = 0;
    nlh.nlmsg_seq   = 1;
    nlh.nlmsg_pid   = getpid();

    iov[0].iov_base = (void *)&nlh;
    iov[0].iov_len  = sizeof(nlh);
    iov[1].iov_base = (void *)payload;
    iov[1].iov_len  = PAYLOAD_SIZE;

    //for (i=0; i<PAYLOAD_SIZE; ++i) payload[i] = i % 0xff;

    msg.msg_name    = (void *)&(peer);
    msg.msg_namelen = sizeof(peer);
    msg.msg_iov     = iov;
    msg.msg_iovlen  = 2;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0; // flags are not used by sendmsg

    if ( sendmsg( sock, &msg, 0 ) < 0 ) {
      perror("Sendmsg error");
      exit(1);
    }

    if (action != REGISTER)
    {
        return;
    }

    // receive the kernel reply
    memset( rpayload, 0, PAYLOAD_SIZE );
    memset( &nlh, 0, sizeof(nlh) );

    iov[0].iov_base = (void *)&nlh;
    iov[0].iov_len  = sizeof(nlh);
    iov[1].iov_base = (void *)rpayload;
    iov[1].iov_len  = PAYLOAD_SIZE;

    memset( &msg, 0, sizeof(msg) );
    msg.msg_name    = (void *)&peer;
    msg.msg_namelen = sizeof(peer);
    msg.msg_iov     = iov;
    msg.msg_iovlen  = 2;

    // receive ACK reply
    if ( recvmsg( sock, &msg, 0 ) < 0 ) {
      perror("Recvmsg error");
      exit(1);
    }
    printf("recv iov %d %p\n", msg.msg_iovlen, (void *)&(msg.msg_iov) );
    printf("  peer:len %d, family %d, pid %d\n",
      msg.msg_namelen, peer.nl_family, peer.nl_pid );
    printf("  iov size [0] %d [1] %d\n", iov[0].iov_len, iov[1].iov_len);
    printf("  nl: len %d, type %d, flags %d, seq %d, pid %d\n",
      nlh.nlmsg_len, nlh.nlmsg_type, nlh.nlmsg_flags,
      nlh.nlmsg_seq, nlh.nlmsg_pid );

    printf ("\nACK from Kernel : %s\n", rpayload);

}

int open_nl_sock()
{
  int sock;
  sock = socket( AF_NETLINK, SOCK_DGRAM, KNETLINK /* NETLINK_ARPD */ );
  if ( sock < 0 ) {
    perror("Socket error");
    return -1;
  }
  return sock;
}

int main( int argc, char ** argv )
{
  int i, j;
  int sock;
//while (1) {
  sock = open_nl_sock();

  if ( -1 == sock)
  {
      return sock;
  }
  register_arp_queue(sock, REGISTER);
  receive_arp_packet(sock);
  register_arp_queue(sock, UNREGISTER);
  //}
  close(sock);
  return 0;
}
