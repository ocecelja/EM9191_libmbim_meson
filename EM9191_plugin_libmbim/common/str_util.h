#ifndef __STR_UTIL_H__
#define __STR_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

#define StrCpy(d, s) strcpy_s((d), sizeof((d)), (s))
#define StrNCpy(d, s, n) strncpy_s((d), sizeof((d)), (s), (n))
#define StrCat(d, s) strcat_s((d), sizeof((d)), (s))

// If successful, returns the number of characters copied.
// The number might be less then the size of the source string,
// if the destination buffer is not large enough.
// Destination string is NULL terminated upon successful copying.
// Returns -1 if source or destination pointers are NULL, or destination size is 0
int strcpy_s(char* pDest, size_t dest_size, const char* pSrc);
int strncpy_s(char* pDest, size_t dest_size, const char* pSrc, size_t n);

// Returns pDest.  The concatenation is only done if source and destination
// string buffers are valid and the destination buffer size is large enough
char* strcat_s(char* pDest, size_t dest_size, const char* pSrc);

#ifdef __cplusplus
} /* extern "C" { */
#endif

#endif // __STR_UTIL_H__

