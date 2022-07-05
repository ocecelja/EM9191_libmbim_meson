#ifndef __SYSINFO_H__
#define __SYSINFO_H__

#define SH_RESP_BUF_LEN 512
#define CMD_BUF_LEN     128

#define eLOG_DEBUG      1

typedef void (*LOG_FUNC)(__uint8_t lvl, const char *buff, ...);

void set_log_func(LOG_FUNC pLogFunc);

void log_kernel();
void log_mods_info();

#endif
