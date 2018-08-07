/*
 * pcap-dpdk-vpc.c
 *
 *      Author: anlang
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>


#include "pcap-int.h"

/*
 * Private data for capturing on Linux SOCK_PACKET or PF_PACKET sockets.
 */
struct pcap_dpdk_vpc {
	u_int	packets_read;	/* count of packets read with recvfrom() */
	long	proc_dropped;	/* packets reported dropped by /proc/net/dev */
	int	ifindex;	/* interface index of device we're bound to */
};



static int dpdk_vpc_pcap_cant_set_rfmon(pcap_t *p _U_) {
	/*Monitor mode

	 Sniffing the packets in the air without connecting (associating) with any access point.
	 Think of it like listening to people's conversations while you walk down the street.
	 */
	return (0);//直接返回0
}

#define DPDK_VPC_MAX_SNAPLEN 256
/*
 *  Linux uses the ARP hardware type to identify the type of an
 *  interface. pcap uses the DLT_xxx constants for this. This
 *  function takes a pointer to a "pcap_t", and an ARPHRD_xxx
 *  constant, as arguments, and sets "handle->linktype" to the
 *  appropriate DLT_XXX constant and sets "handle->offset" to
 *  the appropriate value (to make "handle->offset" plus link-layer
 *  header length be a multiple of 4, so that the link-layer payload
 *  will be aligned on a 4-byte boundary when capturing packets).
 *  (If the offset isn't set here, it'll be 0; add code as appropriate
 *  for cases where it shouldn't be 0.)
 *
 *  If "cooked_ok" is non-zero, we can use DLT_LINUX_SLL and capture
 *  in cooked mode; otherwise, we can't use cooked mode, so we have
 *  to pick some type that works in raw mode, or fail.
 *
 *  Sets the link type to -1 if unable to map the type.
 */
static void map_arphrd_to_dlt(pcap_t *handle, int sock_fd, int arptype,
			      const char *device, int cooked_ok)
{
	static const char cdma_rmnet[] = "cdma_rmnet";

	switch (arptype) {

	case ARPHRD_ETHER:
		/*
		 * For various annoying reasons having to do with DHCP
		 * software, some versions of Android give the mobile-
		 * phone-network interface an ARPHRD_ value of
		 * ARPHRD_ETHER, even though the packets supplied by
		 * that interface have no link-layer header, and begin
		 * with an IP header, so that the ARPHRD_ value should
		 * be ARPHRD_NONE.
		 *
		 * Detect those devices by checking the device name, and
		 * use DLT_RAW for them.
		 */
		if (strncmp(device, cdma_rmnet, sizeof cdma_rmnet - 1) == 0) {
			handle->linktype = DLT_RAW;
			return;
		}

		/*
		 * Is this a real Ethernet device?  If so, give it a
		 * link-layer-type list with DLT_EN10MB and DLT_DOCSIS, so
		 * that an application can let you choose it, in case you're
		 * capturing DOCSIS traffic that a Cisco Cable Modem
		 * Termination System is putting out onto an Ethernet (it
		 * doesn't put an Ethernet header onto the wire, it puts raw
		 * DOCSIS frames out on the wire inside the low-level
		 * Ethernet framing).
		 *
		 * XXX - are there any other sorts of "fake Ethernet" that
		 * have ARPHRD_ETHER but that shouldn't offer DLT_DOCSIS as
		 * a Cisco CMTS won't put traffic onto it or get traffic
		 * bridged onto it?  ISDN is handled in "activate_new()",
		 * as we fall back on cooked mode there, and we use
		 * is_wifi() to check for 802.11 devices; are there any
		 * others?
		 */
		handle->dlt_list = (u_int *) malloc(sizeof(u_int) * 2);
		/*
		 * If that fails, just leave the list empty.
		 */
		if (handle->dlt_list != NULL) {
			handle->dlt_list[0] = DLT_EN10MB;
			handle->dlt_list[1] = DLT_DOCSIS;
			handle->dlt_count = 2;
		}
		/* FALLTHROUGH */
	case ARPHRD_METRICOM:
	case ARPHRD_LOOPBACK:
		handle->linktype = DLT_EN10MB;
		handle->offset = 2;
		break;

	default:
		handle->linktype = -1;
		break;
	}
}

/*
 *  Return the index of the given device name. Fill ebuf and return
 *  -1 on failure.
 */
static int
iface_get_id(int fd, const char *device, char *ebuf)
{
	struct ifreq	ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		pcap_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
		    errno, "SIOCGIFINDEX");
		return -1;
	}

	return ifr.ifr_ifindex;
}

static int pcap_protocol(pcap_t *handle)
{
	int protocol;

	protocol = handle->opt.protocol;
	if (protocol == 0)
		protocol = ETH_P_ALL;

	return htons(protocol);
}

static int
iface_get_arptype(int fd, const char *device, char *ebuf)
{
	struct ifreq	ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		pcap_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
		    errno, "SIOCGIFHWADDR");
		if (errno == ENODEV) {
			/*
			 * No such device.
			 */
			return PCAP_ERROR_NO_SUCH_DEVICE;
		}
		return PCAP_ERROR;
	}

	return ifr.ifr_hwaddr.sa_family;
}

static int
iface_bind(int fd, int ifindex, char *ebuf, int protocol)
{
	struct sockaddr_ll	sll;
	int			err;
	socklen_t		errlen = sizeof(err);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family		= AF_PACKET;
	sll.sll_ifindex		= ifindex;
	sll.sll_protocol	= protocol;

	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
		if (errno == ENETDOWN) {
			/*
			 * Return a "network down" indication, so that
			 * the application can report that rather than
			 * saying we had a mysterious failure and
			 * suggest that they report a problem to the
			 * libpcap developers.
			 */
			return PCAP_ERROR_IFACE_NOT_UP;
		} else {
			pcap_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
			    errno, "bind");
			return PCAP_ERROR;
		}
	}

	/* Any pending errors, e.g., network is down? */

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
		pcap_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
		    errno, "getsockopt (SO_ERROR)");
		return 0;
	}

	if (err == ENETDOWN) {
		/*
		 * Return a "network down" indication, so that
		 * the application can report that rather than
		 * saying we had a mysterious failure and
		 * suggest that they report a problem to the
		 * libpcap developers.
		 */
		return PCAP_ERROR_IFACE_NOT_UP;
	} else if (err > 0) {
		pcap_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE,
		    err, "bind");
		return 0;
	}

	return 1;
}

//打开packet socket
static int
activate_new(pcap_t *handle)
{
	struct pcap_dpdk_vpc *handlep = handle->priv;
	const char		*device = handle->opt.device;
	int			is_any_device = (strcmp(device, "any") == 0);
	int			protocol = pcap_protocol(handle);
	int			sock_fd = -1, arptype;
	int			err = 0;
	struct packet_mreq	mr;

	if(is_any_device)
	{
		pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,"dpdk-vpc not support 'any' device");
		return PCAP_ERROR;
	}

	//raw socket情况下，对应非any设备
	sock_fd = socket(PF_PACKET, SOCK_RAW, protocol);
	if (sock_fd == -1) {
		//如果创建socket fd失败，则报错
		if (errno == EINVAL || errno == EAFNOSUPPORT) {
			/*
			 * We don't support PF_PACKET/SOCK_whatever
			 * sockets; try the old mechanism.
			 */
			return 0;
		}

		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "socket");
		if (errno == EPERM || errno == EACCES) {
			/*
			 * You don't have permission to open the
			 * socket.
			 */
			return PCAP_ERROR_PERM_DENIED;
		} else {
			/*
			 * Other error.
			 */
			return PCAP_ERROR;
		}
	}

	/*
	 * Default value for offset to align link-layer payload
	 * on a 4-byte boundary.
	 */
	handle->offset	 = 0;

	if(handle->opt.rfmon)
	{
		close(sock_fd);
		return PCAP_ERROR_RFMON_NOTSUP;
	}

	/*
	 * What kind of frames do we have to deal with? Fall back
	 * to cooked mode if we have an unknown interface type
	 * or a type we know doesn't work well in raw mode.
	 */

	arptype	= iface_get_arptype(sock_fd, device, handle->errbuf);
	if (arptype < 0) {
		close(sock_fd);
		return arptype;
	}

	map_arphrd_to_dlt(handle, sock_fd, arptype, device, 1);
	if (handle->linktype != DLT_EN10MB) {
		/*
		 * Unknown interface type (-1), or a
		 * device we explicitly chose to run
		 * in cooked mode (e.g., PPP devices),
		 * or an ISDN device (whose link-layer
		 * type we can only determine by using
		 * APIs that may be different on different
		 * kernels) - reopen in cooked mode.
		 */
		if (close(sock_fd) == -1) {
			pcap_fmt_errmsg_for_errno(handle->errbuf,
				PCAP_ERRBUF_SIZE, errno, "close");
		}
		return PCAP_ERROR;
	}

	handlep->ifindex = iface_get_id(sock_fd, device,
		handle->errbuf);
	if (handlep->ifindex == -1) {
		close(sock_fd);
		return PCAP_ERROR;
	}

	//将sock_fd绑定到ifindex上
	if ((err = iface_bind(sock_fd, handlep->ifindex,
		handle->errbuf, protocol)) != 1) {
			close(sock_fd);
		if (err < 0)
			return err;
		else
			return 0;	/* try old mechanism */
	}

	handle->bufsize = handle->snapshot;
	handle->fd = sock_fd;//记录要capture报文的fd

	return 1;
}

int	dpdk_vpc_pcap_inject(pcap_t *handle, const void *buf, size_t size)
{
	strlcpy(handle->errbuf,
				    "Sending packets isn't supported on the device",
				    PCAP_ERRBUF_SIZE);
	return (-1);
}

static int
dpdk_vpc_pcap_setdirection(pcap_t *handle, pcap_direction_t d)
{
	struct pcap_dpdk_vpc *handlep = handle->priv;

	handle->direction = d;
	return 0;
}

static int
dpdk_vpc_pcap_set_datalink(pcap_t *handle, int dlt)
{
	handle->linktype = dlt;
	return 0;
}

static int
dpdk_vpc_pcap_getnonblock_fd(pcap_t *p)
{
	return 0;
}

static int
dpdk_vpc_pcap_setnonblock_fd(pcap_t *p, int nonblock)
{
	return -1;
}

static void	dpdk_vpc_pcap_cleanup( pcap_t *handle )
{
	pcap_cleanup_live_common(handle);
}

/*
 *  Read a packet from the socket calling the handler provided by
 *  the user. Returns the number of packets received or -1 if an
 *  error occured.
 */
static int
dpdk_vpc_pcap_read_packet(pcap_t *handle, pcap_handler callback, u_char *userdata)
{
	struct pcap_dpdk_vpc*handlep = handle->priv;
	u_char			*bp;
	int			offset;
	struct sockaddr_ll	from;

	socklen_t		fromlen;
	int			packet_len, caplen;
	struct pcap_pkthdr	pcap_header;

    struct bpf_aux_data     aux_data;

	/*
	 * Receive a single packet from the kernel.
	 * We ignore EINTR, as that might just be due to a signal
	 * being delivered - if the signal should interrupt the
	 * loop, the signal handler should call pcap_breakloop()
	 * to set handle->break_loop (we ignore it on other
	 * platforms as well).
	 * We also ignore ENETDOWN, so that we can continue to
	 * capture traffic if the interface goes down and comes
	 * back up again; comments in the kernel indicate that
	 * we'll just block waiting for packets if we try to
	 * receive from a socket that delivered ENETDOWN, and,
	 * if we're using a memory-mapped buffer, we won't even
	 * get notified of "network down" events.
	 */
	bp = (u_char *)handle->buffer + handle->offset;

	do {
		/*
		 * Has "pcap_breakloop()" been called?
		 */
		if (handle->break_loop) {
			/*
			 * Yes - clear the flag that indicates that it has,
			 * and return PCAP_ERROR_BREAK as an indication that
			 * we were told to break out of the loop.
			 */
			handle->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}

		fromlen = sizeof(from);

		//自fd中读取报文，并将读取的报文内容填充到bp+offset指向的位置
		packet_len = recvfrom(
			handle->fd, bp + offset,
			handle->bufsize - offset, MSG_TRUNC,
			(struct sockaddr *) &from, &fromlen);
	} while (packet_len == -1 && errno == EINTR);

	/* Check if an error occured */
	if (packet_len == -1) {
		switch (errno) {

		case EAGAIN:
			return 0;	/* no packet there */

		case ENETDOWN:
			/*
			 * The device on which we're capturing went away.
			 *
			 * XXX - we should really return
			 * PCAP_ERROR_IFACE_NOT_UP, but pcap_dispatch()
			 * etc. aren't defined to return that.
			 */
			pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				"The interface went down");
			return PCAP_ERROR;

		default:
			pcap_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno, "recvfrom");
			return PCAP_ERROR;
		}
	}

	/*
	 * XXX: According to the kernel source we should get the real
	 * packet len if calling recvfrom with MSG_TRUNC set. It does
	 * not seem to work here :(, but it is supported by this code
	 * anyway.
	 * To be honest the code RELIES on that feature so this is really
	 * broken with 2.2.x kernels.
	 * I spend a day to figure out what's going on and I found out
	 * that the following is happening:
	 *
	 * The packet comes from a random interface and the packet_rcv
	 * hook is called with a clone of the packet. That code inserts
	 * the packet into the receive queue of the packet socket.
	 * If a filter is attached to that socket that filter is run
	 * first - and there lies the problem. The default filter always
	 * cuts the packet at the snaplen:
	 *
	 * # tcpdump -d
	 * (000) ret      #68
	 *
	 * So the packet filter cuts down the packet. The recvfrom call
	 * says "hey, it's only 68 bytes, it fits into the buffer" with
	 * the result that we don't get the real packet length. This
	 * is valid at least until kernel 2.2.17pre6.
	 *
	 * We currently handle this by making a copy of the filter
	 * program, fixing all "ret" instructions with non-zero
	 * operands to have an operand of MAXIMUM_SNAPLEN so that the
	 * filter doesn't truncate the packet, and supplying that modified
	 * filter to the kernel.
	 */

	caplen = packet_len;
	if (caplen > handle->snapshot)
		caplen = handle->snapshot;

	handlep->packets_read++;
	/* Run the packet filter if not using kernel filter */
	if (handle->fcode.bf_insns) {
		//在用户态执行bpf规则
		if (bpf_filter_with_aux_data(handle->fcode.bf_insns, bp,
		    packet_len, caplen, &aux_data) == 0) {
			/* rejected by filter */
			return 0;
		}
	}

	/* Fill in our own header data */
	if (ioctl(handle->fd, SIOCGSTAMP, &pcap_header.ts) == -1) {
		pcap_fmt_errmsg_for_errno(handle->errbuf,
			PCAP_ERRBUF_SIZE, errno, "SIOCGSTAMP");
		return PCAP_ERROR;
	}

	pcap_header.caplen	= caplen;
	pcap_header.len		= packet_len;

	/* Call the user supplied callback function */
	callback(userdata, &pcap_header, bp);

	return 1;
}

static int
dpdk_vpc_pcap_read(pcap_t *handle, int max_packets _U_, pcap_handler callback, u_char *user)
{
	return dpdk_vpc_pcap_read_packet(handle, callback, user);
}

/*
 * Return network statistics
 */
static int dpdk_vpc_pcap_stats (pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_dpdk_vpc *dpdk_vpc = p->priv;
  ps->ps_drop =0;//置为0，表示不支持
  ps->ps_ifdrop = 0;//ring入队时丢了多少包文
  ps->ps_recv = dpdk_vpc->packets_read;//由libpcap收到了多少报文
  return (0);
}

static int dpdk_vpc_pcap_activate_op(pcap_t *handle) {
	struct pcap_dpdk_vpc *dpdk_vpc = handle->priv;
	const char	*device;
	struct ifreq	ifr;
	int		status = 0;
	int		ret;

	device = handle->opt.device;

	/*
	 * Make sure the name we were handed will fit into the ioctls we
	 * might perform on the device; if not, return a "No such device"
	 * indication, as the Linux kernel shouldn't support creating
	 * a device whose name won't fit into those ioctls.
	 *
	 * "Will fit" means "will fit, complete with a null terminator",
	 * so if the length, which does *not* include the null terminator,
	 * is greater than *or equal to* the size of the field into which
	 * we'll be copying it, that won't fit.
	 */
	if (strlen(device) >= sizeof(ifr.ifr_name)) {
		status = PCAP_ERROR_NO_SUCH_DEVICE;
		goto fail;
	}

	/*
	 * Turn a negative snapshot value (invalid), a snapshot value of
	 * 0 (unspecified), or a value bigger than the normal maximum
	 * value, into the maximum allowed value.
	 *
	 * If some application really *needs* a bigger snapshot
	 * length, we should just increase MAXIMUM_SNAPLEN.
	 */
	if (handle->snapshot <= 0 || handle->snapshot > DPDK_VPC_MAX_SNAPLEN)
		handle->snapshot = DPDK_VPC_MAX_SNAPLEN;

	handle->inject_op = dpdk_vpc_pcap_inject;
	handle->setfilter_op = install_bpf_program;
	handle->setdirection_op = dpdk_vpc_pcap_setdirection;
	handle->set_datalink_op = dpdk_vpc_pcap_set_datalink;
	handle->getnonblock_op = dpdk_vpc_pcap_getnonblock_fd;
	handle->setnonblock_op = dpdk_vpc_pcap_setnonblock_fd;
	handle->cleanup_op = dpdk_vpc_pcap_cleanup;
	handle->read_op = dpdk_vpc_pcap_read;
	handle->stats_op = dpdk_vpc_pcap_stats;

	if (handle->opt.promisc) {
		handle->opt.promisc = 0;
		/* Just a warning. */
		pcap_snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				"Promiscuous mode not supported on the \"any\" device");
		status = PCAP_WARNING_PROMISC_NOTSUP;
	}

	/*
	 * Current Linux kernels use the protocol family PF_PACKET to
	 * allow direct access to all packets on the network while
	 * older kernels had a special socket type SOCK_PACKET to
	 * implement this feature.
	 * While this old implementation is kind of obsolete we need
	 * to be compatible with older kernels for a while so we are
	 * trying both methods with the newer method preferred.
	 */
	ret = activate_new(handle);
	if (ret != 1) {
		/*
		 * Fatal error with the new way; just fail.
		 * ret has the error return; if it's PCAP_ERROR,
		 * handle->errbuf has been set appropriately.
		 */
		status = ret;
		goto fail;
	}

	/*
	 * We set up the socket, but not with memory-mapped access.
	 */
	if (handle->opt.buffer_size != 0) {
		/*
		 * Set the socket buffer size to the specified value.
		 */
		if (setsockopt(handle->fd, SOL_SOCKET, SO_RCVBUF,
		    &handle->opt.buffer_size,
		    sizeof(handle->opt.buffer_size)) == -1) {
			pcap_fmt_errmsg_for_errno(handle->errbuf,
			    PCAP_ERRBUF_SIZE, errno, "SO_RCVBUF");
			status = PCAP_ERROR;
			goto fail;
		}
	}

	/* Allocate the buffer */
	handle->buffer	 = malloc(handle->bufsize + handle->offset);
	if (!handle->buffer) {
		pcap_fmt_errmsg_for_errno(handle->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		status = PCAP_ERROR;
		goto fail;
	}

	/*
	 * "handle->fd" is a socket, so "select()" and "poll()"
	 * should work on it.
	 */
	handle->selectable_fd = handle->fd;

fail:
	return status;
}

pcap_t *
pcap_create_interface(const char *device _U_, char *ebuf) {
	pcap_t *handle;

	handle = pcap_create_common(ebuf, sizeof (struct pcap_dpdk_vpc));
	if (handle == NULL)
		return NULL;

	handle->can_set_rfmon_op = dpdk_vpc_pcap_cant_set_rfmon;
	handle->activate_op = dpdk_vpc_pcap_activate_op;
	return handle;
}

int pcap_platform_finddevs(pcap_if_list_t *devlistp, char *errbuf) {
	/*
	 * There are no interfaces on which we can capture.
	 */
	static const char any_descr[] = "Pseudo-device that captures on all interfaces";
	if (add_dev(devlistp, "any",
		    PCAP_IF_UP|PCAP_IF_RUNNING|PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE,
		    any_descr, errbuf) == NULL)
			return (-1);
}

/*
 * Libpcap version string.
 */
const char *
pcap_lib_version(void) {
	return (PCAP_VERSION_STRING " (with linux raw socket,E-mail bug reports to anlaneg@126.com)");
}
