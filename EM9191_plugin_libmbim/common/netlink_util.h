#ifndef __NETLINK_UTIL_H__
#define __NETLINK_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdbool.h>

#define VLAN_0_NAME "vlan.0"
#define VLAN_1_NAME "vlan.1"
#define VLAN_0_ID	4094
#define VLAN_1_ID	1

#define QMIMUX_0_NAME "qmimux0"
#define QMIMUX_1_NAME "qmimux1"
#define QMIMUX_0_ID	1
#define QMIMUX_1_ID	2

bool GetNetInterfaceName(const char* pDevPath, char* pIfName, size_t size);
void UpAdaptorInterface(const char *szInterface);
void DownAdaptorInterface(const char *szInterface);
void DownAdaptorInterfaces(const char *szInterface, int nType);
void SetRoute(int domain, const char *szInterface, bool bAdd, const char* dst, int dstprefixlen, const char* gw);
void SetAdaptorAddress(int domain, const char *szInterface, bool bAdd, const char *szIPAddress, int dstprefixlen);
int IsAdaptorUp(const char *szInterface);
void SetAdaptorMtu(const char *szInterface, int mtu);
int AddVlan(const char* szInterface, const char* szVlanInterface, int nVlandId);
int DeleteVlan(const char* szVlanInterface);
int AddQmiMuxIf(const char* szInterface, int nQmiMuxId);
int EnableQmiMuxRawIp(const char* szInterface);
int Mask2PrefixLenV4(unsigned int n);
struct in6_addr* htonl6(uint16_t* h, struct in6_addr* nl);

#ifdef __cplusplus
} /* extern "C" { */
#endif

#endif // __NETLINK_UTIL_H__

