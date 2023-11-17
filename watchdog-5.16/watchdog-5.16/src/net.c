/* > net.c
 *
 * Code for checking network access. The open_netcheck() function is from set-up
 * code originally in watchdog.c
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <time.h>
#include <netinet/ip.h>
#include <linux/icmp.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>		/* for gethostname() etc */
#include <netdb.h>		/* for getprotobyname() */
#include <sys/param.h>	/* for MAXHOSTNAMELEN */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>		/* for ldiv() */

#ifndef FD_CLOEXEC
#define FD_CLOEXEC 1
#endif /*FD_CLOEXEC*/

#define PKBUF_SIZE (DATALEN + MAXIPLEN + MAXICMPLEN)

#include "extern.h"
#include "watch_err.h"
#include "gettime.h"

/*
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers (C Version)
 */
static int in_cksum(unsigned short *addr, int len)
{
	int nleft = len, sum = 0;
	unsigned short *w = addr, answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}			/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		sum += htons(*(unsigned char *) w << 8);
	}
	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);	/* add carry */
	answer = ~sum;		/* truncate to 16 bits */
	return (answer);
}

/*
 * Send out a ping packet of sequence count 'i' and ID from 'daemon_pid' value.
 *
 * Return value is the same as 'ecode' and non-zero on error case.
 */
static int send_ping(char *target, int sock_fp, struct sockaddr to, int i, int *ecode)
{
	unsigned char outpack[MAXPACKET];
	memset(outpack, 0, sizeof(outpack));
	struct icmphdr *icp = (struct icmphdr *)outpack;
	int err = ENOERR;

	/* setup a ping message */
	icp->type = ICMP_ECHO;
	icp->code = icp->checksum = 0;
	icp->un.echo.sequence = htons(i + 1);
	icp->un.echo.id = htons(daemon_pid);	/* ID */

	/* compute ICMP checksum here */
	icp->checksum = in_cksum((unsigned short *)icp, DATALEN + 8);

	/* and send it out */
	if (sendto(sock_fp, (char *)outpack, DATALEN + 8, 0, &to, sizeof(struct sockaddr)) < 0) {
		err = errno;

		/* if our kernel tells us the network is unreachable we are done */
		if (err == ENETUNREACH) {
			log_message(LOG_ERR, "network is unreachable (target: %s)", target);
		} else {
			log_message(LOG_ERR, "sendto gave error for target %s = %d = '%s'", target, err, strerror(err));
		}
	}

	*ecode = err;

return err;
}

/*
 * Look for a ping reply. We check it is our ping by comparing the ID and sequence
 * count to see if they match.
 *
 * Return value is non-zero on something significant: either an error or finding
 * one of our ping's response. The 'ecode' value shows which it was (0 if good).
 *
 */
static int found_ping(unsigned char *packet, int sock_fp, struct sockaddr to, int i,
					  int *ecode, fd_set *fdmask, struct timespec *dtimeout)
{
	struct sockaddr_in *to_in = (struct sockaddr_in *)&to;
	struct sockaddr_in from;
	socklen_t fromlen;

	if (pselect(sock_fp + 1, fdmask, NULL, NULL, dtimeout, NULL) >= 1) {
		/* read reply */
		fromlen = sizeof(from);
		if (recvfrom(sock_fp, packet, PKBUF_SIZE, 0, (struct sockaddr *)&from, &fromlen) < 0) {
			int err = errno;

			if (err != EINTR) {
				log_message(LOG_ERR, "recvfrom gave errno = %d = '%s'", err, strerror(err));
				*ecode = err;
				return 1;
			}
		} else {
			/* check if packet is our ECHO */
			struct icmphdr *icp = (struct icmphdr *)(packet + (((struct ip *)packet)->ip_hl << 2));

			if (icp->type == ICMP_ECHOREPLY) {
				int rcv_id  = ntohs(icp->un.echo.id);
				int rcv_seq = ntohs(icp->un.echo.sequence);

				/* Have ping reply, but is it the one we just sent? */
				if (rcv_id  == daemon_pid &&
					rcv_seq == (i + 1) &&
					from.sin_addr.s_addr == to_in->sin_addr.s_addr) {

					*ecode = ENOERR;
					return 1;
				}
			}
		}
	}

	return 0;
}

/*
 * Check network / machine is accessible via 'ping' packet.
 */

int check_net(char *target, int sock_fp, struct sockaddr to, unsigned char *packet, int time, int count)
{
	int i;
	int err = 0;
	struct timespec tmax;
	ldiv_t d;

	if (target == NULL)
		return (ENOERR);

	if (count < 1)
		return (EINVAL);

	/* set the timeout value */
	d = ldiv(time, count);
	tmax.tv_sec = d.quot;
	/* Compute nanoseconds, including the above remainder. */
	tmax.tv_nsec = (d.rem * NSEC) / count;

	/* try "ping-count" times */
	for (i = 0; i < count; i++) {
		fd_set fdmask;
		struct timespec tstart, timeout, dtimeout;

		if (send_ping(target, sock_fp, to, i, &err)) {
			return err;
		}

		clock_gettime(CLOCK_MONOTONIC, &tstart);
		/* set the timeout value */
		timespecadd(&tstart, &tmax, &timeout);

		/* wait for reply */
		FD_ZERO(&fdmask);
		FD_SET(sock_fp, &fdmask);
		while (1) {
			clock_gettime(CLOCK_MONOTONIC, &dtimeout);
			timespecsub(&timeout, &dtimeout, &dtimeout);
			/* Check if we have timed out waiting for a reply. */
			if ((long)dtimeout.tv_sec < 0)
				break;

			if (found_ping(packet, sock_fp, to, i, &err, &fdmask, &dtimeout)) {
				/* If successful and verbose, report this. */
				if (err == 0 && verbose && logtick && ticker == 1) {
					/* Report time since tstart in milliseconds (like 'ping' program). */
					double msec;
					clock_gettime(CLOCK_MONOTONIC, &dtimeout);
					timespecsub(&dtimeout, &tstart, &dtimeout);
					msec = 1.0e3 * (dtimeout.tv_sec + 1.0e-9 * dtimeout.tv_nsec);
					log_message(LOG_DEBUG, "got answer on ping=%d from target %-15s time=%.3fms", i+1, target, msec);
				}
				return err;
			}
		}
	}

	log_message(LOG_ERR, "no response from ping (target: %s)", target);

	return (ENETUNREACH);
}

/*
 * Close socket and free the packet buffer. As we zero this memory when originally
 * allocating it, a non-NULL packet buffer is an indicator it was opened.
 */

static int close_net(struct pingmode *net)
{
	int err = ENOERR;

	if (net->packet != NULL) {
		free(net->packet);
		net->packet = NULL;

		if (close(net->sock_fp) < 0) {
			err = errno;
			log_message(LOG_ERR, "error closing socket (err = %d = '%s')", err, strerror(err));
		}
		net->sock_fp = -1;
	}

	return err;
}

/*
 * Set up pinging if in ping mode
 */

int open_netcheck(struct list *tlist)
{
	struct list *act;
	int hold;
	struct icmp_filter filt;
	memset(&filt, 0, sizeof(filt));
	filt.data = ~(1<<ICMP_ECHOREPLY);

	if (tlist != NULL) {
		/* Have at least on ping target to configure, get ICMP settings. */
		struct protoent *proto;
		const char pname[] = "icmp";

		if (!(proto = getprotobyname(pname))) {
			fatal_error(EX_SYSERR, "unknown protocol %s", pname);
			return -1;
		}

		for (act = tlist; act != NULL; act = act->next) {
			struct pingmode *net = &act->parameter.net; /* 'net' is alias of act->parameter.net */
			struct sockaddr_in *to_in;

			close_net(net);

			/* setup the socket */
			memset(&(net->to), 0, sizeof(struct sockaddr));
			/*
			 * This pointer is an alias to same memory, an ugly but common
			 * method, for example http://www.retran.com/beej/sockaddr_inman.html
			 * Also we don't (yet) support IPv6 which needs a bigger structure
			 * anyway (e.g. the 'struct sockaddr_storage' type for all) and other
			 * changes around here.
			 */
			to_in = (struct sockaddr_in *)&(net->to);

			to_in->sin_family = AF_INET;
			to_in->sin_addr.s_addr = inet_addr(act->name);

			if (to_in->sin_addr.s_addr == INADDR_NONE) {
				fatal_error(EX_USAGE, "unknown host %s", act->name);
			}

			net->packet = (unsigned char *)xcalloc(PKBUF_SIZE, sizeof(char));

			if ((net->sock_fp = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0 ||
				fcntl(net->sock_fp, F_SETFD, FD_CLOEXEC)) {
				fatal_error(EX_SYSERR, "error opening socket (%s)", strerror(errno));
			}

			/* set filter for only ECOREPLY packet (configured in the filt.dat value above) */
			if (setsockopt(net->sock_fp, SOL_RAW, ICMP_FILTER, (char*)&filt, sizeof(filt)) < 0) {
				int err = errno;
				log_message(LOG_ERR, "set ICMP filter error for target %s err = %d = '%s'", act->name, err, strerror(err));
			}

			/* this is necessary for broadcast pings to work */
			hold = 0; /* value should not matter, but zero to be safe. */
			if (setsockopt(net->sock_fp, SOL_SOCKET, SO_BROADCAST, (char *)&hold, sizeof(hold)) < 0) {
				int err = errno;
				log_message(LOG_ERR, "set broadcast error for target %s err = %d = '%s'", act->name, err, strerror(err));
			}

			hold = 48 * 1024;
			if (setsockopt(net->sock_fp, SOL_SOCKET, SO_RCVBUF, (char *)&hold, sizeof(hold)) < 0) {
				int err = errno;
				log_message(LOG_ERR, "set revbuf error for target %s err = %d = '%s'", act->name, err, strerror(err));
			}
		}
	}

	return 0;
}

/*
 * Shut sockets and free memory as allocated by open_netcheck().
 */

int close_netcheck(struct list *tlist)
{
	int err = 0;
	struct list *act;

	if (tlist != NULL) {
		for (act = tlist; act != NULL; act = act->next) {
			err |= close_net(&act->parameter.net);
		}
	}

	return err;
}
