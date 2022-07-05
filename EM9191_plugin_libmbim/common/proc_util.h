#ifndef __PROC_UTIL_H__
#define __PROC_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include "common.h"

typedef void(*FNTERMHANDLER)(int signo, void* pTermContext);

#define DEFAULT_TERMHANDLER	((FNTERMHANDLER)-1)

void SetTermHandler(FNTERMHANDLER pfnTermHandler, void* pTermContext);

void runas_daemon();
void dlog(int lvl, const char* fmt, ...);

#ifdef __cplusplus
} /* extern "C" { */
#endif

#endif // __PROC_UTIL_H__

