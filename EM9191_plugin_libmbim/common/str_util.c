#include "str_util.h"

int strncpy_s(char* pDest, size_t dest_size, const char* pSrc, size_t n)
{
	if (pDest == NULL || dest_size == 0 || pSrc == NULL)
		return -1;

	if (n >= dest_size)
		n = dest_size - 1;

	strncpy(pDest, pSrc, n);
	pDest[n] = 0;

	return n;
}

int strcpy_s(char* pDest, size_t dest_size, const char* pSrc)
{
	return strncpy_s(pDest, dest_size, pSrc, strlen(pSrc));
}

char* strcat_s(char* pDest, size_t dest_size, const char* pSrc)
{
	if (pDest && dest_size > 0 && pSrc &&
		strlen(pSrc) + strlen(pDest) < dest_size)
		strcat(pDest, pSrc);

	return pDest;
}
