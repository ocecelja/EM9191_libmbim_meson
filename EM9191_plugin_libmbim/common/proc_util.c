#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>

#ifdef DEBUG
#include <time.h>		/* timeval, time_t */
#include <sys/timeb.h>
#include <sys/syscall.h>
#endif

#include "proc_util.h"

FNTERMHANDLER gfnTermHandler = NULL;
void* gpTermContext = NULL;

bool bSysLog = false;

void sig_handler(int signo)
{
	if (signo == SIGINT)
		alarm(1);	// Unblock fgets in main thread

	if (gfnTermHandler)
		gfnTermHandler(signo, gpTermContext);
}

void SetSigHandler(int sig, const char* desc, bool bReset)
{
	if (signal(sig, bReset ? SIG_IGN : sig_handler) == SIG_ERR)
		dlog(eLOG_WARN, "\nUnable to %s %s\n", bReset ? "reset" : "catch", desc);
}

void SetTermHandler(FNTERMHANDLER pfnTermHandler, void* pTermContext)
{
	SetSigHandler(SIGINT, "SIGINT", pfnTermHandler == NULL);
	SetSigHandler(SIGTERM, "SIGTERM", pfnTermHandler == NULL);

	gfnTermHandler = pfnTermHandler == DEFAULT_TERMHANDLER ? NULL : pfnTermHandler;
	gpTermContext = pTermContext;
}

void runas_daemon()
{
	pid_t pid = fork();	// Fork off the parent process

	if (pid < 0)
		exit(EXIT_FAILURE);	// error occurred

	if (pid > 0)
	{
		dlog(eLOG_INFO, "Daemon process ID: %d\n", pid);
		exit(EXIT_SUCCESS);	// Success: terminate parent
	}

	bSysLog = true;

	umask(0);	// Set new file permissions

	// Child process is now session leader
	if (setsid() < 0)
		exit(EXIT_FAILURE);

	dlog(eLOG_INFO, "Daemon process started\n");

	// Ignore signals
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	if (chdir("/") != 0)	// Change the working directory to root
		dlog(eLOG_ERROR, "Failed to change working directory to root (%d)\n", errno);

	// Close all open file descriptors
	int x = sysconf(_SC_OPEN_MAX);
	for (; x >= 0; x--)
		close(x);
}

#define DEFAULT_SYSLOG_LEVEL 7
void dlog(int lvl, const char* fmt, ...)
{
#ifndef DEBUG
	if (lvl == eLOG_DEBUG)
		return;
#endif

	char buff[255];
	va_list arg;

	va_start(arg, fmt);
	vsnprintf(buff, 254, fmt, arg);
	va_end(arg);

#ifndef DEBUG
	if (bSysLog)
		syslog(DEFAULT_SYSLOG_LEVEL, "%s", buff);
	else
		printf("%s", buff);
#else
	if (bSysLog)
		syslog(DEFAULT_SYSLOG_LEVEL, "%ld [%d] %s", syscall(SYS_gettid), lvl, buff);
	else
	{
		struct timeb ft;
		ftime(&ft);
		
		struct tm lt = *localtime(&ft.time);

		printf("%04d/%02d/%02d %02d:%02d:%02d.%03d %ld [%d] %s",
			lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday, lt.tm_hour, lt.tm_min, lt.tm_sec, ft.millitm,
			syscall(SYS_gettid), lvl, buff);
	}
#endif
}

