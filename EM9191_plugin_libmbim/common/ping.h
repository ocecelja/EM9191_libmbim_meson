#ifndef __PING_H__
#define __PING_H__

#ifdef __cplusplus
extern "C" {
#endif

	int ping(int ipFamily, const char *szAddress, unsigned int cnt, unsigned int delay);

#ifdef __cplusplus
} /* extern "C" { */
#endif

#endif	// __PING_H__
