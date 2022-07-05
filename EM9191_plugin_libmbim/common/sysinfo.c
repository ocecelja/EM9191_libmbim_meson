#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "sysinfo.h"

LOG_FUNC log_func = NULL;

void set_log_func(LOG_FUNC pLogFunc)
{
    log_func = pLogFunc;
}

void log_mod_info(char * mod)
{
    if (log_func == NULL)
    {
        return;
    }

    char cmd[CMD_BUF_LEN] = "";
    snprintf(cmd, CMD_BUF_LEN, "modinfo %s 2>/dev/null", mod);

    FILE * fp = popen(cmd, "r");
    if (!fp)
    {
        char temp[CMD_BUF_LEN * 2] = "";
        sprintf(temp, "Failed to popen for command '%s', errno: %d", cmd, errno);
        log_func(eLOG_DEBUG, temp);
        return;
    }

    char resp[SH_RESP_BUF_LEN] = "";
    bool found = false;

    while (fgets(resp, SH_RESP_BUF_LEN, fp))
    {
        if (strstr(resp, "version:"))
        {
            char temp[SH_RESP_BUF_LEN + 16] = "";
            sprintf(temp, "%s %s", mod, resp);
            log_func(eLOG_DEBUG, temp);
            found = true;
            break;
        }
    }

    if (!found)
    {
        char temp[CMD_BUF_LEN] = "";
        sprintf(temp, "Unable to log %s version info. Drivers from MBPL R17 or newer are required.", mod);
        log_func(eLOG_DEBUG, temp);
    }

    pclose(fp);
}

void log_kernel()
{
    if (log_func == NULL)
    {
        return;
    }

    FILE * fp = popen("uname -a", "r");
    if (!fp)
    {
        char temp[CMD_BUF_LEN] = "";
        sprintf(temp, "Failed to popen for command 'uname -a', errno: %d", errno);
        log_func(eLOG_DEBUG, temp);
        return;
    }

    char resp[SH_RESP_BUF_LEN] = "";

    while (fgets(resp, SH_RESP_BUF_LEN, fp))
    {
        char temp[SH_RESP_BUF_LEN + 16] = "";
        sprintf(temp, "Kernel: %s", resp);
        log_func(eLOG_DEBUG, temp);
    }

    pclose(fp);
}

void log_mods_info()
{
    log_kernel();
    log_mod_info("qcserial");
    log_mod_info("usb_wwan");
    log_mod_info("cdc_mbim");
    log_mod_info("qmi_wwan");
    log_mod_info("mhictrl");
    log_mod_info("mhinet");
    log_mod_info("mhitty");
}
