#include <stdio.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/netlink.h>

#define NETLINK_TEST 17
#define MSG_LEN NLMSG_SPACE(1024)

int main (int argc, char *argv[])
{
	struct sockaddr_nl saddr;
	struct nlmsghdr *nlhdr;

	int sockfd;
	int bind_flag;
	int send_flag;

	char buffer[MSG_LEN];

	sockfd = socket (PF_NETLINK, SOCK_RAW, NETLINK_TEST);
	if (sockfd < 0)
	{
		fprintf (stderr, "\nUnable to create socket %s\n",
					strerror (errno));
		exit (1);
	}

	saddr.nl_family = PF_NETLINK;
	saddr.nl_pid = getpid ();
	saddr.nl_groups = 0;

	bind_flag = bind (sockfd, (struct sockaddr *)&saddr, sizeof (saddr));
	if (bind_flag < 0)
	{
		fprintf (stderr, "\nUnable to bind to socket %s\n", strerror (errno));
		exit (1);
	}

	nlhdr = (struct nlmsghdr *)buffer;
	nlhdr->nlmsg_len = MSG_LEN;
	nlhdr->nlmsg_pid = getpid ();
	nlhdr->nlmsg_flags = 0;
	strcpy (NLMSG_DATA(nlhdr), "Hello Kernel from user space\n");

	/* Send Message to the Kernel */

	send_flag = send (sockfd, buffer, MSG_LEN, 0);
	if (send_flag < 0)
	{
		fprintf (stderr, "\nUnable to send %s\n", strerror (errno));
		exit (1);
	}
	return 1;
}
