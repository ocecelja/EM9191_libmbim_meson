#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <errno.h>
#include <sys/time.h>

#define PACKET_SIZE     4096
#define MAX_DELAY		10
#define MAX_NO_PACKETS	10
#define MAX_RECV_RETRY  5
#define DATA_LEN		56

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

void statistics(int nsent, int nreceived)
{
    printf("\n--------------------PING statistics-------------------\n");
    printf("%d packets transmitted, %d received , %%%d lost\n",
        nsent, nreceived, (nsent - nreceived) / nsent * 100);
}

unsigned short cal_chksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

int pack(int ipFamily, char* sendpacket, pid_t pid, int pack_no)
{
    struct icmp *icmp = (struct icmp*)sendpacket;
    icmp->icmp_type = ipFamily == 4 ? ICMP_ECHO : ICMP6_ECHO_REQUEST;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = pid;
    icmp->icmp_seq = pack_no;

	int packsize = 8 + DATA_LEN;

	struct timeval *tval = (struct timeval*)icmp->icmp_data;
    gettimeofday(tval, NULL);

	if (ipFamily == 4)	// Kernel calculate checksum for IPv6
	    icmp->icmp_cksum = cal_chksum((unsigned short*)icmp, packsize);

    return packsize;
}

// Returns -1 on error, number of packet sent on success.
int send_packet(int ipFamily, int sockfd, pid_t pid, struct sockaddr* addr, size_t size, int cnt)
{
    int nsent = 0;

    while (nsent < cnt)
    {
		char sendpacket[PACKET_SIZE];
		memset(sendpacket, 0, PACKET_SIZE);

		int packetsize = pack(ipFamily, sendpacket, pid, ++nsent);

        if (sendto(sockfd, sendpacket, packetsize, 0, addr, size) < 0)
        {
            perror("sendto error");
            return -1;
        }

        sleep(1);
    }

    return nsent;
}

void tv_sub(struct timeval *out, struct timeval *in)
{
    if ((out->tv_usec -= in->tv_usec) < 0)
    {
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    
    out->tv_sec -= in->tv_sec;
}

double rtt(struct timeval* tvsend)
{
	struct timeval tvrecv;
	gettimeofday(&tvrecv, NULL);
	tv_sub(&tvrecv, tvsend);

	return tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000;
}

int unpack(pid_t pid, struct sockaddr_in* from, char *buf, int len)
{
	struct ip* ip = (struct ip*)buf;
    int iphdrlen = ip->ip_hl << 2;
	struct icmp* icmp = (struct icmp*)(buf + iphdrlen);
    
	len -= iphdrlen;
    if (len < 8)
    {
        printf("ICMP packets\'s length is less than 8\n");
        return -1;
    }

    if (icmp->icmp_type != ICMP_ECHOREPLY || icmp->icmp_id != pid)
	    return -1;

	printf("%d bytes from %s icmp_seq=%u ttl=%d rtt=%.3f ms\n", len,
		inet_ntoa(from->sin_addr), icmp->icmp_seq, ip->ip_ttl, rtt((struct timeval*)icmp->icmp_data));
	
	return 0;
}

int unpack6(pid_t pid, struct sockaddr_in6* from, char *buf, int len)
{
	struct icmp6_hdr *icmp = (struct icmp6_hdr*)buf;
	if (len < (int)sizeof(struct icmp6_hdr))
	{
		printf("ICMP6 packet length is less than it should be\n");
		return  -1;
	}

    if (icmp->icmp6_type != ICMP6_ECHO_REPLY || icmp->icmp6_id != pid)
	    return -1;

	if (len < (int)sizeof(struct icmp6_hdr) + (int)sizeof(struct timeval))
	{
		printf("ICMP6 packet data length is less than it should be\n");
		return  -1;
	}

	char szFrom[INET6_ADDRSTRLEN] = { '\0' };
	inet_ntop(AF_INET6, from->sin6_addr.s6_addr, szFrom, INET6_ADDRSTRLEN);

	printf("%d byte from %s: icmp_seq=%u rtt=%.3f ms\n", len,
		szFrom, icmp->icmp6_seq, rtt((struct timeval*)(icmp + 1)));

	return 0;
}

int recv_packet(int ipFamily, int sockfd, pid_t pid, int nsent)
{
	int nreceived = 0;
	int retry = 0;
    extern int errno;

    //signal(SIGALRM, statistics);
    while (nreceived < nsent && retry < MAX_RECV_RETRY)
    {
		char recvpacket[PACKET_SIZE];
		memset(recvpacket, 0, PACKET_SIZE);

		struct sockaddr_in6 from;
		memset(&from, 0, sizeof(struct sockaddr_in6));

		socklen_t fromlen = (socklen_t)(ipFamily == 4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
		int n = recvfrom(sockfd, recvpacket, PACKET_SIZE, 0, (void*)&from, &fromlen);
		if (n < 0)
        {
			if (errno == EAGAIN)
				sleep(1);
            else if (errno != EINTR)
	            perror("recvfrom error");

            retry++;
            continue;
        }
        
		int result = ipFamily == 4 ? unpack(pid, (struct sockaddr_in*)&from, recvpacket, n) : unpack6(pid, &from, recvpacket, n);
		if (result == -1)
			retry++;
		else
	        nreceived++;
    }

	return nreceived;
}

int ping(int ipFamily, const char *szaddress, unsigned int cnt, unsigned int delay)
{
	int sockfd = ipFamily == 4 ? socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) : socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (sockfd < 0)
    {
        perror("socket error");
        return -1;
    }
        
	if (delay > 0)
		sleep(MIN(delay, MAX_DELAY));

    int size = 50 * 1024;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) < 0)
		printf("Failed setsockopt(SOL_SOCKET, SO_RCVBUF\n");
	
	int timestamp = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMP, &timestamp, sizeof(timestamp)) < 0)
		printf("Failed setsockopt(SOL_SOCKET, SO_TIMESTAMP)\n");

	struct timeval sndTimeo;
	sndTimeo.tv_sec = 1;
	sndTimeo.tv_usec = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &sndTimeo, sizeof(sndTimeo)) < 0)
		printf("Failed setsockopt(SOL_SOCKET, SO_SNDTIMEO)\n");

	struct timeval rcvTimeo;
	rcvTimeo.tv_sec = 1;
	rcvTimeo.tv_usec = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &rcvTimeo, sizeof(rcvTimeo)) < 0)
		printf("Failed setsockopt(SOL_SOCKET, SO_RCVTIMEO)\n");

	struct sockaddr_in6 dest;
	memset(&dest, 0, sizeof(dest));

	struct sockaddr_in* pdest = (struct sockaddr_in*)&dest;
	size_t sizeDest = sizeof(struct sockaddr_in);

	if (ipFamily == 4)
	{
		pdest->sin_family = AF_INET;
		pdest->sin_addr.s_addr = inet_addr(szaddress);
	}
	else // if (ipFamily == 6)
	{
		sizeDest = sizeof(struct sockaddr_in6);

		int receiveError = 1;
		if (setsockopt(sockfd, SOL_IPV6, IPV6_RECVERR, &receiveError, sizeof(receiveError)) < 0)
			printf("Failed setsockopt(SOL_IPV6, IPV6_RECVERR)\n");

		int sndBuf = 344;
		if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndBuf, sizeof(sndBuf)) < 0)
			printf("Failed setsockopt(SOL_SOCKET, SO_SNDBUF)\n");

		// Let kernel calculate checksum.
		struct icmp6_hdr* pHdr = NULL;
		int checksumOffset = (int)((uint8_t*)&pHdr->icmp6_cksum - (uint8_t*)pHdr);
		if (setsockopt(sockfd, SOL_RAW, IPV6_CHECKSUM, &checksumOffset, sizeof(checksumOffset)) < 0)
			printf("Failed setsockopt(SOL_RAW, IPV6_CHECKSUM)\n");

		struct icmp6_filter filter;
		ICMP6_FILTER_SETBLOCKALL(&filter);
		ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
		if (setsockopt(sockfd, SOL_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0)
			printf("Failed setsockopt(SOL_ICMPV6, ICMP6_FILTER)\n");

		int recvHopLimit = 1;
		if (setsockopt(sockfd, SOL_IPV6, IPV6_RECVHOPLIMIT, &recvHopLimit, sizeof(recvHopLimit)) < 0)
			printf("Failed setsockopt(SOL_IPV6, IPV6_RECVHOPLIMIT)\n");

        dest.sin6_family = AF_INET6;
        dest.sin6_port = htons(IPPROTO_ICMPV6);
        if (inet_pton(AF_INET6, szaddress, &dest.sin6_addr) != 1)
            perror("inet_pton error");
    }
	
	printf("PING %s %d bytes data in %s packets.\n", szaddress, DATA_LEN, ipFamily == 4 ? "ICMP" : "ICMP6");

	pid_t pid = getpid();
	int nsent = send_packet(ipFamily, sockfd, pid, (struct sockaddr*)pdest, sizeDest, MIN(cnt, MAX_NO_PACKETS));
	if (nsent > 0)
		statistics(nsent, recv_packet(ipFamily, sockfd, pid, nsent));

	close(sockfd);

    return nsent > 0 ? 0 : -1;
}

