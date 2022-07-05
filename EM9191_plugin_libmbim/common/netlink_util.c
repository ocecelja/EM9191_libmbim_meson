#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <ifaddrs.h>

#include "netlink_util.h"
#include "proc_util.h"
#include "str_util.h"

// CPU=arm. These are not defined.
#ifndef IFLA_INFO_KIND
#define IFLA_INFO_KIND 1
#endif 
#ifndef IFLA_INFO_DATA
#define IFLA_INFO_DATA 2
#endif
#ifndef IFLA_VLAN_ID
#define IFLA_VLAN_ID 1
#endif
#ifndef IFLA_LINKINFO
#define IFLA_LINKINFO 18
#endif
// End of CPU=arm

// Normally we would also include net/if.h for the following declaration.
// However, for some compilers (arm64, rpi) there's a bug which causes iff_ constants
// to be declared twice, if net/if.h is included before linux/if.h.
// This workaround avoids this build issue.
extern unsigned int if_nametoindex (const char *__ifname) __THROW;

#define NL_SEND_BUF_SIZE	1024
#define NL_RECV_BUF_SIZE	4096

const char szNull[] = "null";

struct nlsock
{
	int fd;
	struct sockaddr_nl addr;
};

#ifdef DEBUG
// Output binary data for debugging purpose
void PrintNlmsgHdr(const char* szDesc, const struct nlmsghdr* pnh, bool bSend)
{
	if (szDesc)
		printf(" %s %s header %s\n", szDesc, bSend ? "request" : "received", bSend ? ">>>" : "<<<");

	printf("  Payload size    :\t%d (0x%08x)\n", pnh->nlmsg_len, pnh->nlmsg_len);
	printf("  Message type    :\t%d (0x%04x)\n", pnh->nlmsg_type, pnh->nlmsg_type);
	printf("  Additional flags:\t%04x\n", pnh->nlmsg_flags);
	printf("  Sequence number :\t%d (0x%08x)\n", pnh->nlmsg_seq, pnh->nlmsg_seq);
	printf("  Process port ID :\t%d (0x%08x)\n", pnh->nlmsg_pid, pnh->nlmsg_pid);
}

void DumpData(const char* szDesc, const char* pData, ssize_t nLen, bool bSend)
{
	printf(" %s %s data (%zd) %s", szDesc, bSend ? "request" : "received", nLen, bSend ? ">>>" : "<<<");

	ssize_t i = 0;
	while (i < nLen)
	{
		if (i % 16 == 0) printf("\n  ");
		else if (i % 8 == 0) printf(" ");
		printf("%02x", (unsigned char)pData[i]);
		if (++i % 16 != 0) printf(" ");
	}

	printf("\n\n");
}

void DumpDataExt(const char* szDesc, const char* pData, size_t nLen, bool bSend)
{
	struct nlmsghdr* pnh = (struct nlmsghdr*)pData;
	PrintNlmsgHdr(szDesc, pnh, bSend);

	pData = NLMSG_DATA(pData);
	nLen -= sizeof(struct nlmsghdr);

	switch (pnh->nlmsg_type)
	{
	case NLMSG_ERROR:
	{
		struct nlmsgerr* pErr = (struct nlmsgerr*) NLMSG_DATA(pnh);
		printf(" Error:\t%d (0x%08x)\n", pErr->error, pErr->error);
		printf(" Returned request header\n");
		PrintNlmsgHdr(0, &pErr->msg, bSend);
		pData += sizeof(struct nlmsgerr);
		nLen -= sizeof(struct nlmsgerr);
		printf("\n");
		break;
	}
	default:
		break;
	}

	DumpData(szDesc, pData, nLen, bSend);
}
#endif	// DEBUG

bool GetNetInterfaceName(const char* pDevPath, char* pIfName, size_t size)
{
	if (pDevPath == 0)
		return false;

	bool bPCIe = strncmp(pDevPath, "/dev/mhi_", 9) == 0;

	memset(pIfName, 0, size);

	struct ifaddrs* ifaddr = NULL;
	if (getifaddrs(&ifaddr) == -1)
		return false;

	struct ifaddrs* ifa = ifaddr;
	while (ifa != NULL && 
		(strncmp(ifa->ifa_name, "mhi_netdev", 10) != 0 || !bPCIe) &&
		((strncmp(ifa->ifa_name, "wwan", 4) != 0 &&
		  strncmp(ifa->ifa_name, "wwp", 3) != 0 &&
		  strncmp(ifa->ifa_name, "wws", 3) != 0) || bPCIe))
	{
		ifa = ifa->ifa_next;
	}

	if (ifa != NULL && strlen(ifa->ifa_name) < size)
		strcpy(pIfName, ifa->ifa_name);

	freeifaddrs(ifaddr);
	
	return strlen(pIfName) > 0;
}

bool CreateSocket(const char* szFunc, struct nlsock* s)
{
	s->fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (s->fd < 0)
		dlog(eLOG_ERROR, "%s - Create socket error %d: %s\n", szFunc, errno, strerror(errno));
	else
	{
		memset(&s->addr, 0, sizeof(s->addr));
		s->addr.nl_family = AF_NETLINK;
		s->addr.nl_pid = getpid();

#ifdef DEBUG
		//DumpData(__FUNCTION__, (const char*)&s->addr, sizeof(s->addr), true);
#endif

		if (bind(s->fd, (struct sockaddr *)&s->addr, sizeof(s->addr)) < 0)
		{
			close(s->fd);
			dlog(eLOG_ERROR, "%s - Bind socket error %d: %s\n", szFunc, errno, strerror(errno));
			s->fd = -1;
		}

#ifdef DEBUG
		//DumpData(__FUNCTION__, (const char*)&s->addr, sizeof(s->addr), false);
#endif
	}

	return s->fd != -1;
}

int SendToSocket(const char* szFunc, const char* szInterface, const char* szDesc,
	const struct nlsock* s, const void* pHeader, char* pBuf, ssize_t sizeBuf)
{
	struct nlmsghdr* nh = (struct nlmsghdr*)pHeader;
	nh->nlmsg_flags |= (NLM_F_REQUEST | NLM_F_ACK);
	if (nh->nlmsg_pid == 0)
		nh->nlmsg_pid = getpid();

#ifdef DEBUG
	DumpDataExt(szDesc, (const char*)nh, nh->nlmsg_len, true);
#endif

	if (send(s->fd, (const char*)pHeader, nh->nlmsg_len, 0) == -1)
	{
		dlog(eLOG_ERROR, "%s(%s) %s failed.  Error %d: %s\n", szFunc, szInterface ? szInterface : szNull, szDesc, errno, strerror(errno));
		return -1;
	}

	char intBuf[NL_RECV_BUF_SIZE];
	bool bUseIntBuf = pBuf == 0 || sizeBuf == 0;
	if (bUseIntBuf)
	{
		pBuf = intBuf;
		sizeBuf = NL_RECV_BUF_SIZE;
	}

	memset(pBuf, 0, sizeBuf);

	int nRecv = 0;

	do
	{
		int n = recv(s->fd, pBuf, sizeBuf, 0);
#ifdef DEBUG
		DumpDataExt(szDesc, pBuf, n, false);
#endif

		struct nlmsghdr* pnh = (struct nlmsghdr*)pBuf;
		if (pnh->nlmsg_type == NLMSG_DONE)
			break;

		if (pnh->nlmsg_type == NLMSG_ERROR)
		{
			struct nlmsgerr* pErr = (struct nlmsgerr*) NLMSG_DATA(pnh);
			if (pErr->error != 0)
			{
#ifdef DEBUG
				dlog(eLOG_DEBUG, "%s(%s) %s returns error %d, type %d\n", szFunc, szInterface ? szInterface : szNull, szDesc, pErr->error, pErr->msg.nlmsg_type);
#endif
				nRecv = -1;
			}

			break;
		}

		// Prepare buffer for next message
		nRecv += n;
		pBuf += n;
		sizeBuf -= n;
	} while (sizeBuf > 0 &&
		(s->addr.nl_groups & (RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE)) == 0);	// Logic from Mike's code.  Not sure what this is about

	return bUseIntBuf ? 0 : nRecv;
}

// Return IFF_UP | IFF_RUNNING if adapter is up, 0 is not, -1 is the device doesn't exist
int IsAdaptorUp(const char *szInterface)
{
#ifdef DEBUG
	dlog(eLOG_DEBUG, "%s: is adapter %s(%d) up?\n", __FUNCTION__, szInterface ? szInterface : szNull, szInterface ? if_nametoindex(szInterface) : 0);
#endif

	struct nlsock s;
	if (!CreateSocket(__FUNCTION__, &s))
		return -1;

	struct
	{
		struct nlmsghdr  nh;
		struct ifinfomsg ifi;
	} req;

	memset(&req, 0, sizeof(req));

	req.nh.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ifinfomsg)));
	req.nh.nlmsg_type = RTM_GETLINK;

	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = if_nametoindex(szInterface);

	char buf[NL_RECV_BUF_SIZE];

	int nRecv = SendToSocket(__FUNCTION__, szInterface, "RTM_GETLINK", &s, (void*)&req, buf, sizeof(buf));
	if (nRecv == -1)
	{
		close(s.fd);
		return 0;
	}

	int nFlags = -1;
	struct nlmsghdr *pnh = (struct nlmsghdr *)buf;

	while (NLMSG_OK(pnh, (uint32_t)nRecv))
	{
		if (nFlags != -1)
			dlog(eLOG_WARN, "%s warning: more than one interface found\n", __FUNCTION__);

		struct ifinfomsg *pifi = NLMSG_DATA(pnh);
		nFlags = pifi->ifi_flags & (IFF_UP | IFF_RUNNING);

		dlog(eLOG_INFO, "%s - Adaptor %s is %s\n", __FUNCTION__, szInterface, nFlags == 0 ? "down" : "up");

		pnh = NLMSG_NEXT(pnh, nRecv);
	}

	close(s.fd);

	return nFlags;
}

void UpDownAdaptor(const struct nlsock* s, bool bUp, const char *szInterface)
{
	dlog(eLOG_INFO, "%s adaptor %s(%d)\n", bUp ? "Up" : "Down", szInterface ? szInterface : szNull, szInterface ? if_nametoindex(szInterface) : 0);

	struct
	{
		struct nlmsghdr  nh;
		struct ifinfomsg ifi;
	} req;

	memset(&req, 0, sizeof(req));

	req.nh.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ifinfomsg)));
	req.nh.nlmsg_type = RTM_SETLINK;

	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = if_nametoindex(szInterface);
	req.ifi.ifi_flags = bUp ? (IFF_UP | IFF_RUNNING) : 0;
	req.ifi.ifi_change = IFF_UP | IFF_RUNNING;

	SendToSocket(__FUNCTION__, szInterface, "Set IFF", s, (void*)&req, 0, 0);
}

const char* UpAdaptorAddresses(const struct nlsock* s, const char* szInterface)
{
	char *parentAdaptorName = strstr(szInterface, ":");
	if (parentAdaptorName != NULL)
	{
		char sztempEthName[255] = "";
		StrNCpy(sztempEthName, szInterface, parentAdaptorName - szInterface);
	
		szInterface = parentAdaptorName + 1;

		UpDownAdaptor(s, true, sztempEthName);
	}

	UpDownAdaptor(s, true, szInterface);

	return szInterface;
}

void UpDownAdaptorInterface(bool bUp, const char *szInterface)
{
	struct nlsock s;
	if (CreateSocket(__FUNCTION__, &s))
	{
		UpDownAdaptor(&s, bUp, szInterface);
		close(s.fd);
	}
}

void UpAdaptorInterface(const char *szInterface)
{
	UpDownAdaptorInterface(true, szInterface);
}

void DownAdaptorInterface(const char *szInterface)
{
	UpDownAdaptorInterface(false, szInterface);
}

void DownAdaptorInterfaces(const char *szInterface, int nType)
{
	struct nlsock s;
	if (CreateSocket(__FUNCTION__, &s))
	{
		if (nType == 1)
		{
			UpDownAdaptor(&s, false, VLAN_0_NAME);
			UpDownAdaptor(&s, false, VLAN_1_NAME);
		}
		else if (nType == 2)
		{
			UpDownAdaptor(&s, false, QMIMUX_0_NAME);
			UpDownAdaptor(&s, false, QMIMUX_1_NAME);
		}

		UpDownAdaptor(&s, false, szInterface);
		close(s.fd);
	}
}

// Add data to rtattr
int rtattr_add(struct nlmsghdr *nh, int maxlen, int type, const void *data, int alen)
{
	int len = RTA_LENGTH(alen);

	if (nh->nlmsg_len + RTA_ALIGN(len) > (unsigned int)maxlen)
	{
		dlog(eLOG_ERROR, "rtattr_add error: message exceeded bound of %d\n", maxlen);
		return -1;
	}

	struct rtattr *rta = ((struct rtattr *)(((void *)(nh)) + NLMSG_ALIGN((nh)->nlmsg_len)));
	rta->rta_type = type;
	rta->rta_len = len;

	if (alen > 0)
	{
		memcpy(RTA_DATA(rta), data, alen);
		nh->nlmsg_len += RTA_ALIGN(len);
	}

	return 0;
}

// Add address to rtattr
int rtattr_addaddr(struct nlmsghdr *nh, int maxlen, int type, const char* addr, int domain)
{
	if (addr == 0 || strlen(addr) == 0)
		return 0;

	unsigned char buf[sizeof(struct in6_addr)];
	return inet_pton(domain, addr, buf) != 0 && rtattr_add(nh, maxlen, type, buf, domain == AF_INET6 ? 16 : 4);
}

void SetRoute(int domain, const char *szInterface, bool bAdd, const char* dst, int dstprefixlen, const char* gw)
{
	if (dstprefixlen == 0)
		dstprefixlen = domain == AF_INET6 ? 128 : 32;

	const char* szDef = "default";
	dlog(eLOG_INFO, "%s(family %d): route %s %s:%d dev %s(%d) gw %s\n", __FUNCTION__, domain,
		bAdd ? "add" : "del",
		dst ? dst : szDef,
		dstprefixlen,
		szInterface ? szInterface : szDef,
		szInterface ? if_nametoindex(szInterface) : 0,
		gw ? gw : szDef);

	struct nlsock s;
	if (!CreateSocket(__FUNCTION__, &s))
		return;

	struct
	{
		struct nlmsghdr nh;
		struct rtmsg rm;
		char buf[NL_SEND_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));

	// Initialize request structure
	req.nh.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct rtmsg)));
	req.nh.nlmsg_flags = bAdd ? NLM_F_CREATE : 0;
	req.nh.nlmsg_type = bAdd ? RTM_NEWROUTE : RTM_DELROUTE;

	req.rm.rtm_family = domain;
	req.rm.rtm_dst_len = dstprefixlen;
	req.rm.rtm_table = RT_TABLE_MAIN;
	req.rm.rtm_protocol = RTPROT_STATIC;
	req.rm.rtm_scope = RT_SCOPE_UNIVERSE;
	req.rm.rtm_type = RTN_UNICAST;

	rtattr_addaddr(&req.nh, sizeof(req), RTA_DST, dst, domain);	// Set destination network
	rtattr_addaddr(&req.nh, sizeof(req), RTA_GATEWAY, gw, domain); // Set gateway

	if (szInterface)
	{
		// Set interface
		int idx = if_nametoindex(szInterface);
		rtattr_add(&req.nh, sizeof(req), RTA_OIF, &idx, sizeof(int));
	}

	// Send message to the netlink
	SendToSocket(__FUNCTION__, szInterface, "Set Route", &s, (void*)&req, 0, 0);

	close(s.fd);
}

void SetAdaptorAddress(int domain, const char *szInterface, bool bAdd, const char *szIPAddress, int dstprefixlen)
{
	if (dstprefixlen == 0)
		dstprefixlen = domain == AF_INET6 ? 128 : 32;

	struct nlsock s;
	if (!CreateSocket(__FUNCTION__, &s))
		return;

	if (bAdd)
		szInterface = UpAdaptorAddresses(&s, szInterface);

	dlog(eLOG_INFO, "%s(family %d): ip addr %s %s:%d dev %s(%d)\n", __FUNCTION__, domain, bAdd ? "add" : "del",
		szIPAddress, dstprefixlen,
		szInterface ? szInterface : szNull, szInterface ? if_nametoindex(szInterface) : 0);

	struct
	{
		struct nlmsghdr  nh;
		struct ifaddrmsg ifa;
		char             buf[NL_SEND_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));

	req.nh.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ifaddrmsg)));
	req.nh.nlmsg_type = bAdd ? RTM_NEWADDR : RTM_DELADDR;
	req.nh.nlmsg_flags = bAdd ? (NLM_F_CREATE | NLM_F_REPLACE) : 0;

	req.ifa.ifa_family = domain;
	req.ifa.ifa_prefixlen = dstprefixlen;
	req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;// 0;
	req.ifa.ifa_index = szInterface ? if_nametoindex(szInterface) : 0;

	rtattr_addaddr(&req.nh, sizeof(req), IFA_LOCAL, szIPAddress, domain);
	rtattr_addaddr(&req.nh, sizeof(req), IFA_ADDRESS, szIPAddress, domain);

	// Send message to the netlink
	SendToSocket(__FUNCTION__, szInterface, "Set Adaptor Address", &s, (void*)&req, 0, 0);

	close(s.fd);
}

void SetAdaptorMtu(const char *szInterface, int mtu)
{
	dlog(eLOG_INFO, "%s(%s:%d) mtu %d\n", __FUNCTION__, szInterface ? szInterface : szNull, szInterface ? if_nametoindex(szInterface) : 0, mtu);

	struct nlsock s;
	if (!CreateSocket(__FUNCTION__, &s))
		return;

	struct
	{
		struct nlmsghdr  nh;
		struct ifinfomsg ifi;
		char             attrbuf[NL_SEND_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));

	req.nh.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ifinfomsg)));
	req.nh.nlmsg_type = RTM_NEWLINK;

	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = if_nametoindex(szInterface);

	rtattr_add(&req.nh, sizeof(req), IFLA_MTU, &mtu, sizeof(mtu));

	SendToSocket(__FUNCTION__, szInterface, "Set MTU", &s, (void*)&req, 0, 0);

	close(s.fd);
}

int AddVlan(const char* szInterface, const char* szVlanInterface, int nVlandId)
{
	dlog(eLOG_INFO, "%s(%s:%d) add VLAN %s:%d\n", __FUNCTION__,
		szInterface ? szInterface : szNull, szInterface ? if_nametoindex(szInterface) : 0, szVlanInterface, nVlandId);

	if (if_nametoindex(szVlanInterface) != 0)
	{
		printf("%s VLAN %s already exist\n", __FUNCTION__, szVlanInterface);
		return -1;
	}

	struct nlsock s;
	if (!CreateSocket(__FUNCTION__, &s))
		return -1;

	struct
	{
		struct nlmsghdr  nh;
		struct ifinfomsg ifi;
		char             attrbuf[NL_SEND_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));

	req.nh.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ifinfomsg)));
	req.nh.nlmsg_type = RTM_NEWLINK;
	req.nh.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;

	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_type = ARPHRD_NETROM;

	int ifcn = if_nametoindex(szInterface);
	rtattr_add(&req.nh, sizeof(req), IFLA_LINK, &ifcn, sizeof(ifcn));
	rtattr_add(&req.nh, sizeof(req), IFLA_IFNAME, szVlanInterface, strlen(szVlanInterface) + 1);

	struct
	{
		struct rtattr attrinfokind;	// First nested attribute
		char infokindbuf[NLMSG_ALIGN(5)];	// Next nested attribute
		struct rtattr attrinfodata;
		struct
		{
			// Note: this attribute contains a nested attribute (2 levels of nesting)
			struct rtattr attrvlanid;
			int id;
		} vlanid;
	} vlanattr = 
	{
		{ RTA_LENGTH(sizeof(vlanattr.infokindbuf)), IFLA_INFO_KIND },
		"vlan",
		{ RTA_LENGTH(sizeof(vlanattr.vlanid)), IFLA_INFO_DATA },
		{ { RTA_LENGTH(sizeof(vlanattr.vlanid.id)), IFLA_VLAN_ID }, nVlandId }
	};
	rtattr_add(&req.nh, sizeof(req), IFLA_LINKINFO, &vlanattr, sizeof(vlanattr));

	int ret = SendToSocket(__FUNCTION__, szInterface, "Add VLAN", &s, (void*)&req, 0, 0);

	close(s.fd);

	return ret;
}

int DeleteVlan(const char* szVlanInterface)
{
	dlog(eLOG_INFO, "%s delete VLAN %s\n", __FUNCTION__, szVlanInterface);

	if (if_nametoindex(szVlanInterface) == 0)
	{
		dlog(eLOG_WARN, "%s VLAN %s does not exist\n", __FUNCTION__, szVlanInterface);
		return -1;
	}

	struct nlsock s;
	if (!CreateSocket(__FUNCTION__, &s))
		return -1;

	struct
	{
		struct nlmsghdr  nh;
		struct ifinfomsg ifi;
		char             attrbuf[NL_SEND_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));

	req.nh.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ifinfomsg)));
	req.nh.nlmsg_type = RTM_DELLINK;

	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_type = ARPHRD_NETROM;
	req.ifi.ifi_index = if_nametoindex(szVlanInterface);  // According to strace

	int ret = SendToSocket(__FUNCTION__, szVlanInterface, "Remove VLAN", &s, (void*)&req, 0, 0);

	close(s.fd);

	return ret;
}

int AddQmiMuxIf(const char* szInterface, int nQmiMuxId)
{
	char buf[64];
	sprintf(buf, "/sys/class/net/%s/qmi/add_mux", szInterface);

	FILE* pf = fopen(buf, "a");
	if (pf == NULL)
		return 0;

	sprintf(buf, "0x%02x\n", nQmiMuxId);

	fwrite(buf, 1, strlen(buf), pf);

	fclose(pf);
	return 1;
}

int EnableQmiMuxRawIp(const char* szInterface)
{
	char buf[64];
	sprintf(buf, "/sys/class/net/%s/qmi/raw_ip", szInterface);

	FILE* pf = fopen(buf, "w");
	if (pf == NULL)
		return 0;

	buf[0] = 'Y';
	fwrite(buf, 1, 1, pf);

	fclose(pf);
	return 1;
}

int Mask2PrefixLenV4(unsigned int n)
{
	int len = 0;

	while (n != 0)
	{
		n <<= 1;
		len++;
	}

	return len;
}

struct in6_addr* htonl6(uint16_t* h, struct in6_addr* nl)
{
	int i = 0;
	int j = 0;
	for (; i < 8; i++)
	{
		nl->s6_addr[j++] = (u_int8_t)(h[i] >> 8);
		nl->s6_addr[j++] = (u_int8_t)(h[i] & 0xff);
	}

	return nl;
}
