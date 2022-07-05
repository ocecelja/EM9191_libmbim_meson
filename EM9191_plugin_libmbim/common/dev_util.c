#include <string.h>
#include "dev_util.h"

bool locate_usb_adapter_path(usb_dev_loc_info* pusb_dev_loc, char* dev_path, int dev_path_size)
{
	char cmd[128] = "";

	if (pusb_dev_loc->hub_num == 0)
		snprintf(cmd, 128, "ls /sys/bus/usb/devices/%d-%d:%d.%d/usbmisc 2>&1",
			pusb_dev_loc->bus_num, pusb_dev_loc->port_num,
			pusb_dev_loc->dev_num, pusb_dev_loc->if_adapter);
	else
		snprintf(cmd, 128, "ls /sys/bus/usb/devices/%d-%d.%d:%d.%d/usbmisc 2>&1",
			pusb_dev_loc->bus_num, pusb_dev_loc->hub_num, pusb_dev_loc->port_num,
			pusb_dev_loc->dev_num, pusb_dev_loc->if_adapter);

	FILE* fp = popen(cmd, "r");
	if (!fp)
		return false;

	char resp[32] = "";
	bool ret = fgets(resp, 32, fp) && strstr(resp, "cdc");
	if (ret)
	{
		snprintf(dev_path, dev_path_size, "/dev/%s", resp);

		size_t len = strlen(dev_path);
		if (len > 0 && dev_path[len - 1] == '\n')
			dev_path[len - 1] = 0;
	}

	pclose(fp);

	return ret;
}

bool locate_usb_dev_bus_num(int* pbus_num)
{
	FILE * fp = popen("lsusb -d 1199:", "r");
	if (!fp)
		return false;

	char resp[SH_RESP_BUF_LEN] = "";
	bool found = false;

	while (fgets(resp, SH_RESP_BUF_LEN, fp))
	{
		if (sscanf(resp, "Bus %d Device %*s ID %*s %*s", pbus_num) == 1)
		{
			if (found)
			{
				// More than one device found
				found = false;
				printf("\nMultiple USB devices are found. Unable to determine the device to use.\n");
				break;
			}

			found = true;
		}
	}

	pclose(fp);

	return found;
}

bool locate_usb_qdl(usb_dev_loc_info * pusb_dev_loc)
{
	if (pusb_dev_loc->bus_num == 0)
		return false;

	FILE * fp = popen("lsusb -t", "r");
	if (!fp)
		return false;

	char resp[SH_RESP_BUF_LEN] = "";
	bool found_bus = false;
	bool found_port = false;

	while (fgets(resp, SH_RESP_BUF_LEN, fp))
	{
		if (strstr(resp, "Class=root_hub"))
		{
			int bus_num = 0;
			if (sscanf(resp, "/:  Bus %d.Port %*s Dev %d, %*s %*s %*s", &bus_num, &pusb_dev_loc->dev_num) == 2 &&
				bus_num == pusb_dev_loc->bus_num)
			{
				pusb_dev_loc->hub_num = 0;
				found_bus = true;
			}

			continue;
		}

		if (!found_bus)
			continue;

		if (strstr(resp, "Class=Hub, Driver=hub"))
		{
			sscanf(resp, "%*s Port %d: %*s", &pusb_dev_loc->hub_num);
			continue;
		}

		found_port = strstr(resp, "Class=Vendor Specific Class, Driver=qcserial") &&
			sscanf(resp, "%*s Port %d: Dev %*s If %d, %*s", &pusb_dev_loc->port_num, &pusb_dev_loc->if_qdl) == 2;

		if (found_port)
		{
			if (strncmp(resp, "        ", 8) != 0)
				pusb_dev_loc->hub_num = 0;	// In case what we found here is not under "Hub" node

			break;
		}
	}

	pclose(fp);

	return found_port;
}

bool locate_usb_adapter(usb_dev_loc_info* pusb_dev_loc, int* pmode, bool find_match)
{
	if (pusb_dev_loc->bus_num == 0)
		return false;

	usb_dev_loc_info cached_dev_loc;
	if (find_match)
	{
		// Cache the USB device location info, if we need to find a matching USB device.
		memcpy(&cached_dev_loc, pusb_dev_loc, sizeof(usb_dev_loc_info));
	}

	FILE * fp = popen("lsusb -t", "r");
	if (!fp)
		return false;

	char resp[SH_RESP_BUF_LEN] = "";
	bool found_bus = false;
	bool found_port = false;

	while (fgets(resp, SH_RESP_BUF_LEN, fp))
	{
		if (strstr(resp, "Class=root_hub"))
		{
			int bus_num = 0;
			if (sscanf(resp, "/:  Bus %d.Port %*s Dev %d, %*s %*s %*s", &bus_num, &pusb_dev_loc->dev_num) == 2 &&
				bus_num == pusb_dev_loc->bus_num)
			{
				pusb_dev_loc->hub_num = 0;
				found_bus = true;
			}

			continue;
		}

		if (!found_bus)
			continue;

		if (strstr(resp, "Class=Hub, Driver=hub"))
		{
			sscanf(resp, "%*s Port %d: %*s", &pusb_dev_loc->hub_num);
			continue;
		}

		found_port = 
			(((*pmode == QMUX_INTERFACE_UNKNOWN || *pmode == QMUX_INTERFACE_DIRECT) &&
			  strstr(resp, "Class=Vendor Specific Class, Driver=qmi_wwan")) ||
			((*pmode == QMUX_INTERFACE_UNKNOWN || *pmode == QMUX_INTERFACE_MBIM) &&
			  strstr(resp, "Class=Communications, Driver=cdc_mbim"))) &&
			sscanf(resp, "%*s Port %d: Dev %*s If %d, %*s", &pusb_dev_loc->port_num, &pusb_dev_loc->if_adapter) == 2;

		if (found_port)
		{
			if (strncmp(resp, "        ", 8) != 0)
				pusb_dev_loc->hub_num = 0;	// In case what we found here is not under "Hub" node

			*pmode =
				strstr(resp, "Driver=qmi_wwan") ? QMUX_INTERFACE_DIRECT :
				strstr(resp, "Driver=cdc_mbim") ? QMUX_INTERFACE_MBIM : QMUX_INTERFACE_UNKNOWN;

			if (!find_match)
			{
				// If we do not need to find a matching device, we just find one. So, we are done here.
				break;
			}
			else
			{
				// Check if the found one is the one we are searching for
				if (pusb_dev_loc->bus_num == cached_dev_loc.bus_num &&
					pusb_dev_loc->hub_num == cached_dev_loc.hub_num &&
					pusb_dev_loc->port_num == cached_dev_loc.port_num)
				{
					// We have found the matching device.  We are done here.
					break;
				}
				else
				{
					// We have not found the matching device, continue searching.
					found_port = false;
				}
			}
		}
	}

	pclose(fp);

	return found_port;
}

//
// Find USB device
//
// 1. lsusb - d 1199:
// 2.; extract bus_num and id in format "Bus <bus_num> Device sss ID <id> sss"
// 3. lsusb - t
// 4.; find line with "Class=root_hub", and bus_num in "/:  Bus <bus_num>.Port sss Dev <dev_id>, sss" is the same as that found in previous step
// 5.; if "Class=Hub, Driver=hub" is found, extract hub_num from "sss, Port <hum_num>: sss"
// 6.; find following line with "Class=Communications, Driver=cdc_mbim" or "Class=Communications, Driver=qmi_wwan"
// 7.; extract port_num and if_adapter from format "sss Port <port_num>: Dev sss If <if_adapter>, sss"
// 8.; determine if the device found is under USB Hub
// 9.; device mode is QMI if "Driver=qmi_wwan", MBIM if "Driver=cdc_mbim"
// 10.; if under USB Hub, "ls /sys/bus/usb/devices/<bus_num>-<hub_num>.<port_num>:<dev_num>.<if_adapter>/usbmisc"
//      otherwiese "ls /sys/bus/usb/devices/<bus_num>-<port_num>:<dev_num>.<if_adapter>/usbmisc"
// 11.; the device name is found in the output of step 11 that starts with "cdc"

bool find_usb_adapter_path(char* dev_path, int dev_path_size, int* pmode, int* pif_adapter)
{
	usb_dev_loc_info usb_dev_loc;
	memset(&usb_dev_loc, 0, sizeof(usb_dev_loc_info));

	if (locate_usb_dev_bus_num(&usb_dev_loc.bus_num) &&
		locate_usb_adapter(&usb_dev_loc, pmode, false) &&
		locate_usb_adapter_path(&usb_dev_loc, dev_path, dev_path_size))
	{
		if (pif_adapter)
			*pif_adapter = usb_dev_loc.if_adapter;

		return true;
	}

	return false;
}

bool locate_pcie_dev(pcie_dev_loc_info* ppcie_dev_loc)
{
	FILE * fp = popen("lspci -v 2>&1", "r");
	if (!fp)
		return false;

	bool found = false;
	bool found_qc = false;

	char resp[SH_RESP_BUF_LEN] = "";
	while (!found && fgets(resp, SH_RESP_BUF_LEN, fp))
	{
		if (strstr(resp, "Qualcomm Device 0306"))
		{
			if (sscanf(resp, "%d:%d.%*d %*s Qualcomm Device 0306",
				&ppcie_dev_loc->bus_num, &ppcie_dev_loc->slot_num) == 2)
				found_qc = true;
		}
		else
			found = found_qc && strstr(resp, "Subsystem: Device 18d7");
	}

	pclose(fp);

	return found;
}

//
// Find PCIe device
//
// 1. lspci - v
// 2.; find line with "Qualcomm Device 0306"
// 3.; extract bus_num and slot_num in format "<bus_num>:<slot_num>.x sss Qualcomm Device 0306"
// 4.; find line with "Subsystem: Device 18d7" to confirm PCIe device found
// 5. ls / dev / mhi *
// 6.; find mbim device in the format of "mhi_0306_<domain_num:2>.<bus_num:2>.<slot_num:2>_pipe_12
// 7.; find qmi device in the format of "mhi_0306_<domain_num:2>.<bus_num:2>.<slot_num:2>_pipe_14

bool find_pcie_dev(char* dev_path, int dev_path_size, int* pmode, char * qdl_path, int qdl_path_size)
{
	pcie_dev_loc_info pcie_dev_loc;
	memset(&pcie_dev_loc, 0, sizeof(pcie_dev_loc_info));

	if (!locate_pcie_dev(&pcie_dev_loc))
		return false;

	FILE* fp = popen("ls /dev/mhi* 2>&1", "r");
	if (!fp)
		return false;

	char path_mbim[64] = "";
	sprintf(path_mbim, "/dev/mhi_0306_%02d.%02d.%02d_pipe_12", pcie_dev_loc.domain_num,
		pcie_dev_loc.bus_num, pcie_dev_loc.slot_num);
	char path_qmi[64] = "";
	sprintf(path_qmi, "/dev/mhi_0306_%02d.%02d.%02d_pipe_14", pcie_dev_loc.domain_num,
		pcie_dev_loc.bus_num, pcie_dev_loc.slot_num);
	char path_qdl[] = "/dev/mhiqdl0";

	bool found = false;
	char resp[SH_RESP_BUF_LEN] = "";

	while (!found && fgets(resp, SH_RESP_BUF_LEN, fp))
	{
		if ((*pmode == QMUX_INTERFACE_UNKNOWN || *pmode == QMUX_INTERFACE_DIRECT) && strstr(resp, path_qmi))
		{
			strncpy(dev_path, path_qmi, dev_path_size);
			*pmode = QMUX_INTERFACE_DIRECT;
			if (qdl_path)
			{
				memset(qdl_path, 0, qdl_path_size);
				strncpy(qdl_path, path_qdl, qdl_path_size);
			}
			found = true;
		}
		else if ((*pmode == QMUX_INTERFACE_UNKNOWN || *pmode == QMUX_INTERFACE_MBIM) && strstr(resp, path_mbim))
		{
			strncpy(dev_path, path_mbim, dev_path_size);
			*pmode = QMUX_INTERFACE_MBIM;
			if (qdl_path)
			{
				memset(qdl_path, 0, qdl_path_size);
				strncpy(qdl_path, path_qdl, qdl_path_size);
			}
			found = true;
		}
		else if (strstr(resp, path_qdl))
		{
			if (qdl_path)
			{
				memset(qdl_path, 0, qdl_path_size);
				strncpy(qdl_path, path_qdl, qdl_path_size);
			}

			if (*pmode == QMUX_INTERFACE_UNKNOWN || *pmode == QMUX_INTERFACE_MBIM)
			{
				strncpy(dev_path, path_mbim, dev_path_size);
				*pmode = QMUX_INTERFACE_MBIM;
			}
			else if (*pmode == QMUX_INTERFACE_DIRECT)
			{
				strncpy(dev_path, path_qmi, dev_path_size);
				*pmode = QMUX_INTERFACE_DIRECT;
			}
			found = true;
		}
	}

	pclose(fp);

	return found;
}

const char* GetModeDesc(int mode)
{
	switch (mode)
	{
	case QMUX_INTERFACE_DIRECT:
		return "QMI";
	case QMUX_INTERFACE_MBIM:
		return "MBIM";
	case QMUX_INTERFACE_ROUTER:
		return "router";
	// case QMUX_INTERFACE_UNKNOWN:
	default:
		return "unknown";
	}
}

int InitDevMode(const char* dev_path)
{
	if (dev_path == NULL)
		return QMUX_INTERFACE_UNKNOWN;;

	const char* dev_name = strrchr(dev_path, '/');

	if (dev_name == NULL)
		return QMUX_INTERFACE_UNKNOWN;
	
	int mode = QMUX_INTERFACE_UNKNOWN;

	dev_name++;

	if (strstr(dev_name, "mhi_"))
	{
		// PCIe
		if (strstr(dev_name, "_12"))
			mode = QMUX_INTERFACE_MBIM;
		else if (strstr(dev_name, "_14"))
			mode = QMUX_INTERFACE_DIRECT;
	}
	else
	{
		// USB
		char cmd_part1[] = "udevadm info -x -a -p $(find /sys/bus/usb/devices/usb*/ -name ";
		char cmd[MAX_PATH_LEN] = "";
		snprintf(cmd, MAX_PATH_LEN, "%s%s) | grep DRIVERS", cmd_part1, dev_name);

		FILE * fp = popen(cmd, "r");
		if (fp)
		{
			char resp[128] = "";

			while (mode == QMUX_INTERFACE_UNKNOWN && fgets(resp, 128, fp))
			{
				if (strstr(resp, "cdc_mbim"))
					mode = QMUX_INTERFACE_MBIM;
				else if (strstr(resp, "qmi_wwan"))
					mode = QMUX_INTERFACE_DIRECT;
			}

			pclose(fp);
		}
	}

	return mode;
}

bool InitDevPaths(char* dev_path, int dev_path_size, int* pmode, int* pif_adapter)
{
	// Return true if only one device is found
	if (dev_path == NULL || dev_path_size == 0 || pmode == NULL)
		return false;

	int pcie_mode = *pmode;
	int usb_mode = *pmode;
	bool pcie = find_pcie_dev(dev_path, dev_path_size, &pcie_mode, NULL, 0);
	bool usb = find_usb_adapter_path(dev_path, dev_path_size, &usb_mode, pif_adapter);

	if (pcie && usb)
	{
		printf("\nBoth PCIe and USB devices are found. Unable to determine the device to use.\n\n");
		return false;
	}

	if (!pcie && !usb)
	{
		printf("\nNeither PCIe nor USB device can be identified.\n\n");
		return false;
	}

	*pmode = pcie ? pcie_mode : usb_mode;

	return true;
}

bool GetDeviceInfo(char* dev_path, size_t dev_path_size, int* pmode, int* pif_adapter,
	bool valid, FNSHOWHELP pfnsh, const char* pProcName, bool showhelp)
{
	if (dev_path == NULL || pmode == NULL || strlen(dev_path) >= dev_path_size)
		return false;

	valid = valid &&
		(dev_path[0] == 0 /* empty path */ ||
		(*pmode != QMUX_INTERFACE_ROUTER && strstr(dev_path, "/dev/") == dev_path && strstr(dev_path, " ") == NULL));

	if (valid)
	{
		if (strlen(dev_path) > 0)
		{
			if (*pmode == QMUX_INTERFACE_UNKNOWN)
				*pmode = InitDevMode(dev_path);
		}
		else if (*pmode != QMUX_INTERFACE_ROUTER)
			valid = InitDevPaths(dev_path, dev_path_size, pmode, pif_adapter);

		if (valid && *pmode == QMUX_INTERFACE_UNKNOWN)
		{
			printf("\nUnable to identify mode of device %s\n\n", dev_path);
			valid = false;
		}
	}

	if ((!valid || showhelp) && pfnsh)
	{
		pfnsh(pProcName);

		if (!valid)
			return false;
	}

	return true;
}

