/*
 * Copyright, AnyWi Technologies BV, 2020,2021,2022
 */

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>
#include <errno.h>

#include <glib-unix.h>
#include <gio/gio.h>

#include <libmbim-glib.h>

#include <linkmanager/api/modules.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "common/netlink_util.h"
#include "common/str_util.h"
#include "common/ping.h"
#include "helper.h"

namespace {
// ********************************************************************************************************************************
class test_device: public linkmanager::api::modules::device {
public:
	inline explicit test_device(DeviceContext *pDeviceContext) {
		device_ctx = pDeviceContext;
		m_device_name = device_ctx->vlan_name;
		m_state = false;

		g_print("Created device: %s\n", m_device_name.c_str());
	}

	virtual ~test_device() {
		g_print("Device: %s destructor called!\n", m_device_name.c_str());
		if (is_up()) {
			set_updown(false);
		} else {
			g_print("Device: %s alredy set to DOWN\n", m_device_name.c_str());
		}
	}

	virtual std::string name() const final {
		return m_device_name;
	}

	virtual bool is_up() const final {
		return m_state;
	}

	virtual void set_updown(bool new_state) {
		g_print(
				"\n------------------Set device: %s to state: %s------------------\n\n",
				m_device_name.c_str(), new_state ? "UP" : "DOWN");

		int ret = EXIT_FAILURE;

		if (new_state == true)
		{
			// Create VLAN
			ret = AddVlan(device_ctx->interface_name, device_ctx->vlan_name, device_ctx->vlan_id);
			if (ret < 0)
			{
				g_print("AddVlan:%s id:%d failed with ret:%d ignoring!\n", device_ctx->vlan_name, device_ctx->vlan_id, ret);
				return;
			}

			// Find the max MTU
			uint32_t maxMTU = findMaxMTU();

			// Set base device MTU accordingly. Otherwise we'll get a ERANGE error if we try to set a vlan MTU greater than this.
			g_print("Setting %s MTU = %d\n", device_ctx->interface_name, maxMTU);
			SetAdaptorMtu(device_ctx->interface_name, maxMTU);

			// Let OS know about established IP addresses
			UpdateRuntimeSettings();  // <-- add m_network.push_back(liberate::net::network{"IP ADDR/PREFIX LEN"});

			// Let OS know about established IP addresses
			if (RunPingCheckForSession() == SUCCESS) {
				// Set state to UP
				m_state = true;
				g_print("Device: %s set to UP\n", m_device_name.c_str());
			} else {
				// Set state to DOWN
				ClearRuntimeSettings();

				DownAdaptorInterface(device_ctx->interface_name);

				g_print("Removing vlan %s\n", device_ctx->vlan_name);
				ret = DeleteVlan(device_ctx->vlan_name);
				if (ret < 0)
				{
					g_print("DeleteVlan failed with ret %d ignoring\n",ret);
				}

				//
				m_network.clear();

				m_state = false;
				g_print("Couldn't set device: %s to UP\n", m_device_name.c_str());
			}
		} else {
			ClearRuntimeSettings();

			DownAdaptorInterface(device_ctx->interface_name);

			g_print("Removing vlan %s\n", device_ctx->vlan_name);
			ret = DeleteVlan(device_ctx->vlan_name);
			if (ret < 0)
			{
				g_print("DeleteVlan failed with ret %d ignoring\n",ret);
			}

			//
			m_network.clear();

			m_state = false;
			g_print("Device: %s set to DOWN\n", m_device_name.c_str());
		}

		return;
	}

	virtual network_list get_networks() const final {
		return m_network;
	}

	std::string m_device_name;
	bool m_state;
	network_list m_network = { };

	// *****************************************************CUSTOM*****************************************************************
	uint32_t findMaxMTU()
	{
		uint32_t maxMtu = 0;

		if (device_ctx->iPv4ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_MTU)
		{
			if (device_ctx->iPv4Mtu > maxMtu)
			{
				maxMtu = device_ctx->iPv4Mtu;
			}
		}
		if (device_ctx->iPv6ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_MTU)
		{
			if (device_ctx->iPv6Mtu > maxMtu)
			{
				maxMtu = device_ctx->iPv6Mtu;
			}
		}

		return maxMtu;
	}

	void UpdateRuntimeSettings()
	{
		bool updatingIPv4 = false;
		bool updatingIPv6 = false;

		// Hardware constraint. We have to set interface MTU to minimum MTU of all availabe in session.
		uint32_t minMtu = UINT32_MAX;

		if (device_ctx->iPv4ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_MTU)
		{
			if (device_ctx->iPv4Mtu < minMtu)
			{
				minMtu = device_ctx->iPv4Mtu;
			}
			updatingIPv4 = true;
		}

		if (device_ctx->iPv6ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_MTU)
		{
			if (device_ctx->iPv6Mtu < minMtu)
			{
				minMtu = device_ctx->iPv6Mtu;
			}
			updatingIPv6 = true;
		}

		if (minMtu != UINT32_MAX)
		{
			g_print("Setting %s MTU = %" PRIu32 "\n", device_ctx->vlan_name, minMtu);
			SetAdaptorMtu(device_ctx->vlan_name, minMtu);
		}

		if (device_ctx->iPv4ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_ADDRESS)
		{
			// Note: MBIM can return multiple IP addresses.
			// For the purposes of this program, we'll only use the first.
			uint32_t i;
			for (i = 0; i < MIN(device_ctx->iPv4AddressCount, 1); i++)
			{
				SetAdapterIPv4Address(true, device_ctx->vlan_name, device_ctx->iPv4Addresses[i]);
				updatingIPv4 = true;
			}
		}

		if (device_ctx->iPv6ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_ADDRESS)
		{
			// Note: MBIM can return multiple IP addresses.
			// For the purposes of this program, we'll only use the first.
			uint32_t i;
			for (i = 0; i < MIN(device_ctx->iPv6AddressCount, 1); i++)
			{
				SetAdapterIPv6Address(true, device_ctx->vlan_name, device_ctx->iPv6Addresses[i]);
				updatingIPv6 = true;
			}
		}

		// After setting the ip address, network adapter needs some time to become ready.
		int timeout = 0;
		if (updatingIPv4 || updatingIPv6)
		{
			UpAdaptorInterface(device_ctx->interface_name);

			while (!IsAdaptorUp(device_ctx->interface_name) && timeout++ < 6)
			{
				sleep(1);
			}

			UpAdaptorInterface(device_ctx->vlan_name);

			while (!IsAdaptorUp(device_ctx->vlan_name) && timeout++ < 6)
			{
				sleep(1);
			}
		}

		// Now set up routes.
		if (updatingIPv4)
		{
			for (uint32_t i = 0; i < device_ctx->iPv4RouteCount; i++)
			{
				// TBD: check gateway
				char szGateway[INET_ADDRSTRLEN] = {'\0'};
				inet_ntop(AF_INET, device_ctx->iPv4Gateway->addr, szGateway, INET_ADDRSTRLEN);
				ModifyIPv4RouteEntry(&device_ctx->iPv4Routes[i], device_ctx->vlan_name, NULL, NULL, szGateway);
				SetRoute(AF_INET, device_ctx->iPv4Routes[i].szInterface, true, device_ctx->iPv4Routes[i].szDst, device_ctx->iPv4Routes[i].dstPrefixLength, device_ctx->iPv4Routes[i].szGateway);
			}
		}

		if (updatingIPv6)
		{
			for (uint32_t i = 0; i < device_ctx->iPv6RouteCount; i++)
			{
				char szGateway[INET6_ADDRSTRLEN] = {'\0'};
				inet_ntop(AF_INET6, device_ctx->iPv6Gateway->addr, szGateway, INET6_ADDRSTRLEN);
				ModifyIPv6RouteEntry(&device_ctx->iPv6Routes[i], device_ctx->vlan_name, NULL, NULL, szGateway);
				SetRoute(AF_INET6, device_ctx->iPv6Routes[i].szInterface, true, device_ctx->iPv6Routes[i].szDst, device_ctx->iPv6Routes[i].dstPrefixLength, device_ctx->iPv6Routes[i].szGateway);
			}
		}
	}

	int SetAdapterIPv4Address(bool bAdd, const char *szInterface, MbimIPv4ElementArray pElement)
	{
		char szIpAddress[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, pElement->ipv4_address.addr, szIpAddress, INET_ADDRSTRLEN);

		g_print("%s %s address = %s\n", bAdd ? "Adding" : "Removing", szInterface, szIpAddress);
		SetAdaptorAddress(AF_INET, szInterface, bAdd, szIpAddress, pElement->on_link_prefix_length);

		return 0;
	}

	int SetAdapterIPv6Address(bool bAdd, const char *szInterface, MbimIPv6ElementArray pElement)
	{
		char szIpAddress[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, pElement->ipv6_address.addr, szIpAddress, INET6_ADDRSTRLEN);

		g_print("%s %s address = %s\n", bAdd ? "Adding" : "Removing", szInterface, szIpAddress);
		SetAdaptorAddress(AF_INET6, szInterface, bAdd, szIpAddress, pElement->on_link_prefix_length);

		return 0;
	}

	void ModifyIPv4RouteEntry(
			IPv4RouteTableEntry* pEntry,
			char* szInterface,
			char* szDst,
			uint32_t* pDstPrefixLength,
			char* szGateway)
	{
		// Modifies only non-NULL parameters, other members are left unchanged

		if (szInterface)
		{
			StrCpy(pEntry->szInterface, szInterface);
		}
		if (szDst)
		{
			StrCpy(pEntry->szDst, szDst);
		}
		if (pDstPrefixLength)
		{
			pEntry->dstPrefixLength = *pDstPrefixLength;
		}
		if (szGateway)
		{
			StrCpy(pEntry->szGateway, szGateway);
		}
	}

	void ModifyIPv6RouteEntry(
			IPv6RouteTableEntry* pEntry,
			char* szInterface,
			char* szDst,
			uint32_t* pDstPrefixLength,
			char* szGateway)
	{
		// Modifies only non-NULL parameters, other members are left unchanged

		if (szInterface)
		{
			StrCpy(pEntry->szInterface, szInterface);
		}
		if (szDst)
		{
			StrCpy(pEntry->szDst, szDst);
		}
		if (pDstPrefixLength)
		{
			pEntry->dstPrefixLength = *pDstPrefixLength;
		}
		if (szGateway)
		{
			StrCpy(pEntry->szGateway, szGateway);
		}
	}

	int RunPingCheckForSession()
	{
		// Ping tests
		uint32_t pingDstIdx;
		int ret = 0;

		if (device_ctx->iPv4ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_ADDRESS)
		{
			// IPv4

			for (pingDstIdx = 0; pingDstIdx < device_ctx->iPv4PingDestinationCount; pingDstIdx++)
			{
				char szGateway[INET_ADDRSTRLEN] = {'\0'};
				ret = 0;
				const char* szInterface =NULL;

				szInterface = device_ctx->vlan_name;

				inet_ntop(AF_INET, device_ctx->iPv4Gateway->addr, szGateway, INET_ADDRSTRLEN);
				g_print("ping (IPv4) dst=%s gateway=%s -I=%s\n", device_ctx->iPv4PingDestinations[pingDstIdx], szGateway, szInterface);

				ret = ping(4, device_ctx->iPv4PingDestinations[pingDstIdx], PING_COUNT, PING_DELAY);

				g_print("%s\n", ret == SUCCESS ? "success" : "failure");
			}
		}

		if (device_ctx->iPv6ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_ADDRESS)
		{
			sleep(3);	// TODO: This is ugly but a delay is needed when we only have IPV6 or the intial ping
						//       recvfrom returns EAGIN continuously

			// IPv6
			for (pingDstIdx = 0; pingDstIdx < device_ctx->iPv6PingDestinationCount; pingDstIdx++)
			{
				char szGateway[INET6_ADDRSTRLEN] = {'\0'};
				ret = 0;
				const char* szInterface =NULL;

				szInterface = device_ctx->vlan_name;

				inet_ntop(AF_INET6, device_ctx->iPv6Gateway->addr, szGateway, INET6_ADDRSTRLEN);
				g_print("ping (IPv6) dst=%s gateway=%s -I=%s\n", device_ctx->iPv6PingDestinations[pingDstIdx], szGateway, szInterface);

				ret = ping(6, device_ctx->iPv6PingDestinations[pingDstIdx], PING_COUNT, PING_DELAY);

				g_print("%s\n", ret == SUCCESS ? "success" : "failure");
			}
		}

		g_print("\n");
		return ret;
	}

	void ClearRuntimeSettings()
	{
		uint32_t i;
		char tmp[] = "";

		if (device_ctx->iPv4ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_ADDRESS)
		{
			for (i = 0; i < device_ctx->iPv4RouteCount; i++)
			{
				SetRoute(AF_INET, device_ctx->iPv4Routes[i].szInterface, false, device_ctx->iPv4Routes[i].szDst, device_ctx->iPv4Routes[i].dstPrefixLength, device_ctx->iPv4Routes[i].szGateway);
				ModifyIPv4RouteEntry(&device_ctx->iPv4Routes[i], tmp, NULL, NULL, tmp);
			}

			for (i = 0; i < MIN(device_ctx->iPv4AddressCount, 1); i++)
			{
				// Clear adapter address.
				SetAdapterIPv4Address(false, device_ctx->vlan_name, device_ctx->iPv4Addresses[i]);
			}
		}

		if (device_ctx->iPv6ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_ADDRESS)
		{
			for (i = 0; i < device_ctx->iPv6RouteCount; i++)
			{
				SetRoute(AF_INET6, device_ctx->iPv6Routes[i].szInterface, false, device_ctx->iPv6Routes[i].szDst, device_ctx->iPv6Routes[i].dstPrefixLength, device_ctx->iPv6Routes[i].szGateway);
				ModifyIPv6RouteEntry(&device_ctx->iPv6Routes[i], tmp, NULL, NULL, tmp);
			}

			for (i = 0; i < MIN(device_ctx->iPv6AddressCount, 1); i++)
			{
				// Clear adapter address.
				SetAdapterIPv6Address(false, device_ctx->vlan_name, device_ctx->iPv6Addresses[i]);
			}
		}

		DownAdaptorInterface(device_ctx->vlan_name);
	}

	// Globals
	GMainLoop *loop;
	GCancellable *cancellable;
	MbimDevice *mbim_device;
	gboolean operation_status;
	DeviceContext *device_ctx;
};

// ********************************************************************************************************************************
class test_link: public linkmanager::api::modules::link {
public:
	inline explicit test_link(const std::string &pName, MbimDevice *dev) {
		m_link_name = pName;
		m_active = false;
		mbim_device = dev;

		link_ctx = NULL;
		device_ctx = NULL;
		link_user_connect_data = NULL;

		g_print("Created link: %s\n", m_link_name.c_str());
	}

	virtual ~test_link() {
		g_print("Link destructor called %s!\n", m_link_name.c_str());

		// Clear device list
		cleanup(ALL);
	}

	virtual std::string name() const final {
		return m_link_name;
	}

	virtual bool is_active() const final {
		return m_active;
	}

	virtual void set_active(bool new_status, activation_callback test_cb) {
		g_print("\n------------------Set link: %s to state: %s------------------\n\n",
				m_link_name.c_str(), new_status ? "ACTIVE" : "INACTIVE");

		if (new_status == TRUE && new_status == m_active) {
			g_print("Link: %s already activated\n", m_link_name.c_str());
			test_cb(*this, m_active);
			return;
		}

//		if (new_status == m_active) {
//			g_print("Link: %s already deactivated\n", m_link_name.c_str());
//			test_cb(*this, m_active);
//			return;
//		}

			/* Applications that want to start one or more operations that should be cancellable
			 * should create a GCancellable object and pass it to the operations
			 */
			cancellable = g_cancellable_new();

			/* Create main event loop for application */
			loop = g_main_loop_new(NULL, FALSE);

			/* Setup signals for safe exit
			 * A convenience function for g_unix_signal_source_new(), which attaches to the default GMainContext
			 */
			g_unix_signal_add(SIGINT, (GSourceFunc) signals_handler, this);
			g_unix_signal_add(SIGHUP, (GSourceFunc) signals_handler, this);
			g_unix_signal_add(SIGTERM, (GSourceFunc) signals_handler, this);

			GTask *task;
			task = g_task_new(mbim_device, cancellable, NULL, NULL);
			g_task_set_task_data(task, link_ctx, NULL);
			link_user_connect_data = g_slice_new0(LinkUserData);
			link_user_connect_data->link = this;
			link_user_connect_data->task = task;
			if (new_status == true) {
				link_user_connect_data->step = LINK_CONNECT_STEP_FIRST;
				link_user_connect_data->connect_type = CONNECT;
			} else {
				link_user_connect_data->step = LINK_DISCONNECT_CONNECT_DEACTIVATE;
				link_user_connect_data->connect_type = DISCONNECT;
			}
			link_user_connect_data->query_subscriber_ready_status_ready_cnt = 0;
			link_user_connect_data->set_register_state_cnt = 0;
			link_context_step(task);

			g_main_loop_run(loop);

			// Clear context
			if (cancellable)
				g_object_unref(cancellable);
			g_main_loop_unref(loop);

			if (new_status == true) {
				/* Delete user data */
				context_free(LINK_USER_DATA_ONLY);

				/* Call CB */
				if (operation_status == EXIT_SUCCESS) {
					m_active = true;
					test_cb(*this, m_active);
				} else {
					m_active = false;
					test_cb(*this, m_active);
				}
			} else {
				/* Call CB */
				if (operation_status == EXIT_SUCCESS) {
					cleanup(LINK_USER_DATA_ONLY);
					m_active = false;
					test_cb(*this, m_active);
				} else {
					context_free(LINK_USER_DATA_ONLY);
					test_cb(*this, m_active);
				}
			}

			g_printerr("NOTE: Operation status: %s!\n",
			operation_status ? "EXIT_FAILURE" : "EXIT_SUCCESS");
	}

	virtual bool configure(nlohmann::json const &config) final {
		g_print("\n----------------Configure link: %s ----------------\n\n",
				m_link_name.c_str());

		/* Link context */
		link_ctx = g_slice_new0(LinkContext);
		operation_status = EXIT_FAILURE;
		/* Subscriber Ready Status */
		link_ctx->ready_state = MBIM_SUBSCRIBER_READY_STATE_NOT_INITIALIZED;
		/* SSIM credentials */
		link_ctx->remaining_attempts = 0;
		link_ctx->pin_type = MBIM_PIN_TYPE_UNKNOWN;
		/* Parse config file */
		if (config.contains("simPin")) {
			auto key = config["simPin"].get<std::string>();
			link_ctx->pin = g_strdup((gchar*) key.c_str());
			g_print("SIM PIN: %s\n", link_ctx->pin);
		} else {
			g_printerr("ERROR: Missing SIM PIN!\n");
			context_free(ALL);
			return EXIT_FAILURE;
		}
		/* Register State */
		link_ctx->register_state = MBIM_REGISTER_STATE_UNKNOWN;
		/* Packet Service State */
		link_ctx->packet_service_state = MBIM_PACKET_SERVICE_STATE_UNKNOWN;
		/* Connect cmd */
		if (config.contains("userName")) {
			auto tmp = config["userName"].get<std::string>();
			link_ctx->user_name = g_strdup((gchar*) tmp.c_str());
			g_print("userName: %s\n", link_ctx->user_name);
		} else {
			g_printerr("ERROR: Missing userName!\n");
			context_free(ALL);
			return EXIT_FAILURE;
		}
		if (config.contains("password")) {
			auto tmp = config["password"].get<std::string>();
			link_ctx->password = g_strdup((gchar*) tmp.c_str());
			g_print("password: %s\n", link_ctx->password);
		} else {
			g_printerr("ERROR: Missing password!\n");
			context_free(ALL);
			return EXIT_FAILURE;
		}
		if (config.contains("accessString")) {
			auto tmp = config["accessString"].get<std::string>();
			link_ctx->access_string = g_strdup((gchar*) tmp.c_str());
			g_print("accessString: %s\n", link_ctx->access_string);
		} else {
			g_printerr("ERROR: Missing accessString!\n");
			context_free(ALL);
			return EXIT_FAILURE;
		}
		if (config.contains("MbimCompression")) {
			auto tmp = config["MbimCompression"].get<int>();
			link_ctx->compression = tmp;
			g_print("MbimCompression: %d\n", link_ctx->compression);
		} else {
			g_printerr("ERROR: Missing MbimCompression!\n");
			context_free(ALL);
			return EXIT_FAILURE;
		}
		if (config.contains("MbimAuthProtocol")) {
			auto tmp = config["MbimAuthProtocol"].get<int>();
			link_ctx->auth_protocol = tmp;
			g_print("MbimAuthProtocol: %d\n", link_ctx->auth_protocol);
		} else {
			g_printerr("ERROR: Missing MbimAuthProtocol!\n");
			context_free(ALL);
			return EXIT_FAILURE;
		}
		if (config.contains("MbimContextIpType")) {
			auto tmp = config["MbimContextIpType"].get<int>();
			link_ctx->ip_type = tmp;
			g_print("MbimContextIpType: %d\n", link_ctx->ip_type);
		} else {
			g_printerr("ERROR: Missing MbimContextIpType!\n");
			context_free(ALL);
			return EXIT_FAILURE;
		}
		if (config.contains("sessionId")) {
			auto tmp = config["sessionId"].get<int>();
			link_ctx->session_id = tmp;
			g_print("sessionId: %d\n", link_ctx->session_id);
		} else {
			g_printerr("ERROR: Missing sessionId!\n");
			context_free(ALL);
			return EXIT_FAILURE;
		}

		/* Device context */
		device_ctx = g_slice_new0(DeviceContext);
		if (config.contains("interfaceName")) {
			auto tmp = config["interfaceName"].get<std::string>();
			device_ctx->interface_name = g_strdup((gchar*) tmp.c_str());
			g_print("interface_name: %s\n", device_ctx->interface_name);
		} else {
			g_printerr("ERROR: Missing interfaceName!\n");
			context_free(ALL);
			return EXIT_FAILURE;
		}
		if (config.contains("vlanName")) {
			auto tmp = config["vlanName"].get<std::string>();
			device_ctx->vlan_name = g_strdup((gchar*) tmp.c_str());
			g_print("vlan_name: %s\n", device_ctx->vlan_name);
		} else {
			g_printerr("ERROR: Missing vlanName!\n");
			context_free(ALL);
			return EXIT_FAILURE;
		}
		if (config.contains("vlanId")) {
			auto tmp = config["vlanId"].get<int>();
			device_ctx->vlan_id = tmp;
			g_print("vlan_id: %d\n", device_ctx->vlan_id);
		} else {
			g_printerr("ERROR: Missing vlanId!\n");
			context_free(ALL);
			return EXIT_FAILURE;
		}

		/* Routes */
		char sesssionRouteDst[64] {0};
		uint32_t sessionRouteDstPrefixLength = 0;
		for (auto& [route_name, _] : config["route"].items())
		{
			if (config["route"][route_name].contains("routeDst")) {
				auto tmp = config["route"][route_name]["routeDst"].get<std::string>();
				strcpy(sesssionRouteDst, tmp.c_str());
				g_print("Route Destination: %s\n", sesssionRouteDst);
			} else {
				g_printerr("ERROR: Missing Route Destination!\n");
				context_free(ALL);
				return EXIT_FAILURE;
			}
			if (config["route"][route_name].contains("routeDstPrefixLength")) {
				auto tmp = config["route"][route_name]["routeDstPrefixLength"].get<uint32_t>();
				sessionRouteDstPrefixLength = tmp;
				g_print("Route Destination Prefix Length: %d\n", sessionRouteDstPrefixLength);
			} else {
				g_printerr("ERROR: Missing Route Destination Prefix Length!\n");
				context_free(ALL);
				return EXIT_FAILURE;
			}
			// Create route entry
			if (AddRouteEntry(sesssionRouteDst, sessionRouteDstPrefixLength) == -1)
			{
				g_print("Failed to parse route %s\n", sesssionRouteDst);
				context_free(ALL);
				return EXIT_FAILURE;
			}
		}

		/* Ping destinations */
		char sessionPingDst[64] {0};
		for (auto& [ping_name, _] : config["ping"].items())
		{
			if (config["ping"][ping_name].contains("pingDst")) {
				auto tmp = config["ping"][ping_name]["pingDst"].get<std::string>();
				strcpy(sessionPingDst, tmp.c_str());
				g_print("Ping Destination: %s\n", sessionPingDst);
			} else {
				g_printerr("ERROR: Missing Ping Destination!\n");
				context_free(ALL);
				return EXIT_FAILURE;
			}
			// Create ping entry
			if (AddPingDestination(sessionPingDst) == -1)
			{
				g_print("ERROR: Failed to parse ping destination: %s\n", sessionPingDst);
				context_free(ALL);
				return EXIT_FAILURE;
			}
		}

		return EXIT_SUCCESS;
	}

	virtual device_list devices() const {
		return m_devices;
	}

//	virtual std::shared_ptr<metrics_base> metrics() {
//		g_print("\n------------------Get link's: %s QoS data\n\n", m_link_name.c_str());
//
//		/* Applications that want to start one or more operations that should be cancellable
//		 * should create a GCancellable object and pass it to the operations
//		 */
//		cancellable = g_cancellable_new();
//
//		/* Create main event loop for application */
//		loop = g_main_loop_new(NULL, FALSE);
//
//		GTask *task;
//		task = g_task_new(mbim_device, cancellable, NULL, NULL);
//		g_task_set_task_data(task, link_ctx, NULL);
//		link_user_connect_data = g_slice_new0(LinkUserData);
//		link_user_connect_data->link = this;
//		link_user_connect_data->task = task;
//
//		link_user_connect_data->query_subscriber_ready_status_ready_cnt = 0;
//		link_user_connect_data->set_register_state_cnt = 0;
//		link_context_step(task);
//
//		g_main_loop_run(loop);
//
//		// Clear context
//		if (cancellable)
//			g_object_unref(cancellable);
//		g_main_loop_unref(loop);
//
//	}

	std::string m_link_name;
	bool m_active;
	device_list m_devices = { };

	// *****************************************************CUSTOM*****************************************************************
	typedef struct {
		test_link *link;
		GTask *task;
		LinkStep step;
		guint query_subscriber_ready_status_ready_cnt;
		guint set_register_state_cnt;
		guint set_packet_service_ready_cnt;
		MbimConnectType connect_type;
	} LinkUserData;

	typedef struct {
		test_link *link;
		GTask *task;
	} LinkUserDataDisonnect;

	inline void create_device() {
		m_devices.push_back(std::make_shared<test_device>(device_ctx));
	}

	inline void context_free(LinkUserDataCtxFreeType type) {
		if (link_ctx && type == ALL) {
			g_print("Free link_ctx...\n");
			g_free(link_ctx->pin);
			g_free(link_ctx->user_name);
			g_free(link_ctx->password);
			g_free(link_ctx->access_string);
			g_slice_free(LinkContext, link_ctx);
			link_ctx = NULL;
		}

		if (device_ctx && type == ALL) {
			g_print("Free device_ctx...\n");
			g_free(device_ctx->interface_name);
			g_free(device_ctx->vlan_name);
			g_slice_free(DeviceContext, device_ctx);
			device_ctx = NULL;
		}

		if (link_user_connect_data && (type == ALL || type == LINK_USER_DATA_ONLY)) {
			g_print("Free link_user_connect_data...\n");
			g_slice_free(LinkUserData, link_user_connect_data);
			link_user_connect_data = NULL;
		}
	}

	inline void mbimcli_async_operation_done(
			gboolean reported_operation_status) {
		/* Keep the result of the operation */
		operation_status = reported_operation_status;

		/* Cleanup cancellation */
		g_clear_object(&cancellable);

		g_main_loop_quit(loop);
	}

	inline void cleanup(LinkUserDataCtxFreeType type) {
		// Clear links list
		if (!m_devices.empty()) {
			m_devices.clear();
		}

		context_free(type);
	}

	int AddRouteEntry(char* szDst, uint32_t dstPrefixLength)
	{
		// Determine if IP4 or IPv6.
		char tmp[] = "";

		struct in_addr iPv4;
		memset(&iPv4, 0, sizeof(iPv4));
		if (inet_pton(AF_INET, szDst, (void *)&iPv4) == 1)
		{
			// IPv4
			if (device_ctx->iPv4RouteCount < ARRAYSIZE(device_ctx->iPv4Routes))
			{
				// Gateway and interface names will be filled in on successful connection.
				ModifyIPv4RouteEntry(&device_ctx->iPv4Routes[device_ctx->iPv4RouteCount], tmp, szDst, &dstPrefixLength, tmp);
				device_ctx->iPv4RouteCount++;
				return 0;
			}
			else
			{
				g_print("Too many IPv4 routes defined. Ignoring\n");
			}
			return 0;
		}

		struct in6_addr iPv6;
		memset(&iPv6, 0, sizeof(iPv6));
		if (inet_pton(AF_INET6, szDst, (void *)&iPv6) == 1)
		{
			// IPv6
			if (device_ctx->iPv6RouteCount < ARRAYSIZE(device_ctx->iPv6Routes))
			{
				// Gateway and interface names will be filled in on successful connection.
				ModifyIPv6RouteEntry(&device_ctx->iPv6Routes[device_ctx->iPv6RouteCount], tmp, szDst, &dstPrefixLength, tmp);
				device_ctx->iPv6RouteCount++;
				return 0;
			}
			else
			{
				g_print("Too many IPv6 routes defined. Ignoring\n");
			}
			return 0;
		}

		return -1;
	}

	int AddPingDestination(char* szDst)
	{
		// Determine if IP4 or IPv6.

		struct in_addr iPv4;
		memset(&iPv4, 0, sizeof(iPv4));
		if (inet_pton(AF_INET, szDst, (void *)&iPv4) == 1)
		{
			// IPv4
			if (device_ctx->iPv4PingDestinationCount < ARRAYSIZE(device_ctx->iPv4PingDestinations))
			{
				// Gateway and interface names will be filled in on successful connection.
				StrCpy(device_ctx->iPv4PingDestinations[device_ctx->iPv4PingDestinationCount], szDst);
				device_ctx->iPv4PingDestinationCount++;
				return 0;
			}
			else
			{
				g_print("Too many IPv4 ping destinations defined. Ignoring\n");
			}
			return 0;
		}

		struct in6_addr iPv6;
		memset(&iPv6, 0, sizeof(iPv6));
		if (inet_pton(AF_INET6, szDst, (void *)&iPv6) == 1)
		{
			// IPv6
			if (device_ctx->iPv6PingDestinationCount < ARRAYSIZE(device_ctx->iPv6PingDestinations))
			{
				// Gateway and interface names will be filled in on successful connection.
				StrCpy(device_ctx->iPv6PingDestinations[device_ctx->iPv6PingDestinationCount], szDst);
				device_ctx->iPv6PingDestinationCount++;
				return 0;
			}
			else
			{
				g_print("Too many IPv6 ping destinations defined. Ignoring\n");
			}
			return 0;
		}

		return -1;
	}

	void ModifyIPv4RouteEntry(
			IPv4RouteTableEntry* pEntry,
			char* szInterface,
			char* szDst,
			uint32_t* pDstPrefixLength,
			char* szGateway)
	{
		// Modifies only non-NULL parameters, other members are left unchanged

		if (szInterface)
		{
			StrCpy(pEntry->szInterface, szInterface);
		}
		if (szDst)
		{
			StrCpy(pEntry->szDst, szDst);
		}
		if (pDstPrefixLength)
		{
			pEntry->dstPrefixLength = *pDstPrefixLength;
		}
		if (szGateway)
		{
			StrCpy(pEntry->szGateway, szGateway);
		}
	}

	void ModifyIPv6RouteEntry(
			IPv6RouteTableEntry* pEntry,
			char* szInterface,
			char* szDst,
			uint32_t* pDstPrefixLength,
			char* szGateway)
	{
		// Modifies only non-NULL parameters, other members are left unchanged

		if (szInterface)
		{
			StrCpy(pEntry->szInterface, szInterface);
		}
		if (szDst)
		{
			StrCpy(pEntry->szDst, szDst);
		}
		if (pDstPrefixLength)
		{
			pEntry->dstPrefixLength = *pDstPrefixLength;
		}
		if (szGateway)
		{
			StrCpy(pEntry->szGateway, szGateway);
		}
	}

	inline void link_context_step(GTask *task) {

		MbimDevice *self;
		LinkContext *link_ctx;
		g_autoptr(MbimMessage) message = NULL;
		g_autoptr(GError) error = NULL;

		/* If cancelled, complete */
		if (g_task_return_error_if_cancelled(task)) {
			g_object_unref(task);
			return;
		}

		self = (MbimDevice*) g_task_get_source_object(task);
		link_ctx = (LinkContext*) g_task_get_task_data(task);

		switch (link_user_connect_data->step) {

		case LINK_CONNECT_STEP_FIRST:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			link_user_connect_data->step = LINK_CONNECT_STEP_QUERY_SUBSCRIBER_READY_STATUS;
			/* Fall through */

		case LINK_CONNECT_STEP_QUERY_SUBSCRIBER_READY_STATUS:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			/* Protection against infinite loop needed */
			if (link_user_connect_data->query_subscriber_ready_status_ready_cnt > 3) {
				g_print("ERROR: Could not get Subscriber Ready Status\n");
				g_object_unref(task);
				mbimcli_async_operation_done(EXIT_FAILURE);
				return;
			}

			if (!(link_ctx->ready_state
					== MBIM_SUBSCRIBER_READY_STATE_INITIALIZED
					|| link_ctx->ready_state
							== MBIM_SUBSCRIBER_READY_STATE_DEVICE_LOCKED)) {
				g_print("Asynchronously querying Subscriber Ready Status...\n");
				message =
						(mbim_message_subscriber_ready_status_query_new(NULL));
				link_user_connect_data->query_subscriber_ready_status_ready_cnt++;
				mbim_device_command(self, message, 10,
						g_task_get_cancellable(task),
						(GAsyncReadyCallback) query_subscriber_ready_status_ready,
						link_user_connect_data);

				return;
			}

			link_user_connect_data->step = LINK_CONNECT_STEP_QUERY_PIN_STATE;

		case LINK_CONNECT_STEP_QUERY_PIN_STATE:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			g_print("Asynchronously querying PIN state...\n");
			message = mbim_message_pin_query_new(&error);
			if (!message) {
				g_printerr("error: couldn't create request: %s\n",
						error->message);
				g_object_unref(task);
				mbimcli_async_operation_done(EXIT_FAILURE);
				return;
			}
			mbim_device_command(self, message, 10, g_task_get_cancellable(task),
					(GAsyncReadyCallback) pin_ready, link_user_connect_data);

			return;

		case LINK_CONNECT_STEP_SET_PIN:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			if (link_ctx->pin_type == MBIM_PIN_TYPE_UNKNOWN) {
				g_print("ERROR: MBIM_PIN_TYPE_UNKNOWN\n");
				g_object_unref(task);
				mbimcli_async_operation_done(EXIT_FAILURE);
				return;
			}

			/* Prevent SIM lock due multiple false SIM PIN entries */
			if (link_ctx->remaining_attempts == 1) {
				g_print("ERROR: Could not set SIM credentials\n");
				g_object_unref(task);
				mbimcli_async_operation_done(EXIT_FAILURE);
				return;
			}

			if (link_ctx->pin_type != MBIM_PIN_TYPE_PIN2
					&& link_ctx->pin_state == MBIM_PIN_STATE_LOCKED) {
				g_print("Asynchronously entering SIM credentials...\n");
				link_ctx->pin_operation = MBIM_PIN_OPERATION_ENTER;
				message = (mbim_message_pin_set_new(link_ctx->pin_type,
						link_ctx->pin_operation, link_ctx->pin,
						NULL, &error));
				if (!message) {
					g_printerr("error: couldn't create request: %s\n",
							error->message);
					g_object_unref(task);
					mbimcli_async_operation_done(EXIT_FAILURE);
					return;
				}
				mbim_device_command(self, message, 10,
						g_task_get_cancellable(task),
						(GAsyncReadyCallback) pin_ready, link_user_connect_data);

				return;
			}

			link_user_connect_data->step = LINK_CONNECT_STEP_QUERY_REGISTER_STATE;

		case LINK_CONNECT_STEP_QUERY_REGISTER_STATE:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			g_print("Asynchronously querying Register State...\n");
			message = mbim_message_register_state_query_new(NULL);
			mbim_device_command(self, message, 10, g_task_get_cancellable(task),
					(GAsyncReadyCallback) register_state_ready, link_user_connect_data);

			return;

		case LINK_CONNECT_STEP_SET_REGISTER_STATE_AUTOMATIC:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			/* Protection against infinite loop needed */
			if (link_user_connect_data->set_register_state_cnt > 3) {
				g_print("ERROR: Could not set Register State\n");
				g_object_unref(task);
				mbimcli_async_operation_done(EXIT_FAILURE);
				return;
			}

			if (!(link_ctx->register_state == MBIM_REGISTER_STATE_HOME
					|| link_ctx->register_state == MBIM_REGISTER_STATE_ROAMING
					|| link_ctx->register_state == MBIM_REGISTER_STATE_PARTNER)) {
				g_print(
						"Asynchronously setting Register State to automatic...\n");
				message = mbim_message_register_state_set_new(NULL,
						MBIM_REGISTER_ACTION_AUTOMATIC, (MbimDataClass) 0,
						&error);
				if (!message) {
					g_printerr("error: couldn't create request: %s\n",
							error->message);
					g_object_unref(task);
					mbimcli_async_operation_done(EXIT_FAILURE);
					return;
				}
				link_user_connect_data->set_register_state_cnt++;
				mbim_device_command(self, message, 120,
						g_task_get_cancellable(task),
						(GAsyncReadyCallback) register_state_ready,
						link_user_connect_data);

				return;
			}

			link_user_connect_data->step = LINK_CONNECT_STEP_QUERY_PACKET_SERVICE_READY;

		case LINK_CONNECT_STEP_QUERY_PACKET_SERVICE_READY:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			g_print("Asynchronously querying Packet Service Ready...\n");
			message = mbim_message_register_state_query_new(NULL);
			mbim_device_command(self, message, 10, g_task_get_cancellable(task),
					(GAsyncReadyCallback) packet_service_ready, link_user_connect_data);

			return;

		case LINK_CONNECT_STEP_SET_PACKET_SERVICE_ATTACH_FLAG:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			/* Protection against infinite loop needed */
			if (link_user_connect_data->set_packet_service_ready_cnt > 3) {
				g_print("ERROR: Could not set Packet Service to attached\n");
				g_object_unref(task);
				mbimcli_async_operation_done(EXIT_FAILURE);
				return;
			}

			if (link_ctx->packet_service_state
					!= MBIM_PACKET_SERVICE_STATE_ATTACHED) {
				g_print(
						"Asynchronously setting Packet Service to attached...\n");
				link_ctx->packet_service_action =
						MBIM_PACKET_SERVICE_ACTION_ATTACH;
				message = mbim_message_packet_service_set_new(
						link_ctx->packet_service_action, &error);
				if (!message) {
					g_printerr("error: couldn't create request: %s\n",
							error->message);
					g_object_unref(task);
					mbimcli_async_operation_done(EXIT_FAILURE);
					return;
				}
				link_user_connect_data->query_subscriber_ready_status_ready_cnt++;
				mbim_device_command(self, message, 120,
						g_task_get_cancellable(task),
						(GAsyncReadyCallback) packet_service_ready,
						link_user_connect_data);

				return;
			}

			link_user_connect_data->step = LINK_CONNECT_STEP_CONNECT_ACTIVATE;

		case LINK_CONNECT_STEP_CONNECT_ACTIVATE:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			message = mbim_message_connect_set_new (link_ctx->session_id,
													MBIM_ACTIVATION_COMMAND_ACTIVATE,
													link_ctx->access_string,
													link_ctx->user_name,
													link_ctx->password,
													(MbimCompression) link_ctx->compression,
													(MbimAuthProtocol) link_ctx->auth_protocol,
													(MbimContextIpType) link_ctx->ip_type,
													mbim_uuid_from_context_type (MBIM_CONTEXT_TYPE_INTERNET),
													&error);

			if (!message) {
				g_printerr ("error: couldn't create request: %s\n", error->message);
				g_object_unref(task);
				mbimcli_async_operation_done(EXIT_FAILURE);
				return;
			}

			mbim_device_command(self, message, 120,
					g_task_get_cancellable(task), (GAsyncReadyCallback)connect_ready,
					link_user_connect_data);

			return;

		case LINK_CONNECT_STEP_IP_QUERY:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			message = (mbim_message_ip_configuration_query_new (
						link_ctx->session_id,
						MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_NONE, /* ipv4configurationavailable */
						MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_NONE, /* ipv6configurationavailable */
						0, /* ipv4addresscount */
						NULL, /* ipv4address */
						0, /* ipv6addresscount */
						NULL, /* ipv6address */
						NULL, /* ipv4gateway */
						NULL, /* ipv6gateway */
						0, /* ipv4dnsservercount */
						NULL, /* ipv4dnsserver */
						0, /* ipv6dnsservercount */
						NULL, /* ipv6dnsserver */
						0, /* ipv4mtu */
						0, /* ipv6mtu */
						&error));
			if (!message) {
				g_printerr ("error: couldn't create IP config request: %s\n", error->message);
				g_object_unref(task);
				mbimcli_async_operation_done(EXIT_FAILURE);
				return;
			}

			mbim_device_command (self, message,
								 60,
								 g_task_get_cancellable(task),
								 (GAsyncReadyCallback)ip_configuration_query_ready,
								 link_user_connect_data);

			return;

		case LINK_CONNECT_STEP_CREATE_DEVICES:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			create_device();

			link_user_connect_data->step = LINK_CONNECT_STEP_LAST;

		case LINK_CONNECT_STEP_LAST:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			g_object_unref(task);
			mbimcli_async_operation_done(EXIT_SUCCESS);
			return;

		case LINK_DISCONNECT_CONNECT_DEACTIVATE:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			message = mbim_message_connect_set_new (link_ctx->session_id,
													MBIM_ACTIVATION_COMMAND_DEACTIVATE,
													NULL,
													NULL,
													NULL,
													MBIM_COMPRESSION_NONE,
													MBIM_AUTH_PROTOCOL_NONE,
													MBIM_CONTEXT_IP_TYPE_DEFAULT,
													mbim_uuid_from_context_type (MBIM_CONTEXT_TYPE_INTERNET),
													&error);

			if (!message) {
				g_printerr ("error: couldn't create request: %s\n", error->message);
				g_object_unref(task);
				mbimcli_async_operation_done(EXIT_FAILURE);
				return;
			}

			mbim_device_command(self, message, 60,
					g_task_get_cancellable(task), (GAsyncReadyCallback)connect_ready,
					link_user_connect_data);

			return;

		case LINK_DISCONNECT_STEP_LAST:
			g_print("link_context_step: %d\n", link_user_connect_data->step);

			g_object_unref(task);
			mbimcli_async_operation_done(EXIT_SUCCESS);
			return;

		default:
			g_print("DEFAULT...\n");
			break;
		}

		g_print("This state shouldn't be reached! Error in task\n");
		g_object_unref(task);
		mbimcli_async_operation_done(EXIT_FAILURE);

		return;
	}

	static void query_subscriber_ready_status_ready(MbimDevice *device,
			GAsyncResult *res, LinkUserData *tmp) {
		LinkUserData *link_user_connect_data = (LinkUserData*) tmp;
		LinkContext *link_ctx;
		link_ctx = (LinkContext*) g_task_get_task_data(link_user_connect_data->task);

		g_autoptr (MbimMessage) response = NULL;
		g_autoptr (GError) error = NULL;
		MbimSubscriberReadyState ready_state;
		const gchar *ready_state_str;
		g_autofree gchar *subscriber_id = NULL;
		g_autofree gchar *sim_iccid = NULL;
		MbimReadyInfoFlag ready_info;
		g_autofree gchar *ready_info_str = NULL;
		guint32 telephone_numbers_count;
		g_auto(GStrv) telephone_numbers = NULL;
		g_autofree gchar *telephone_numbers_str = NULL;

		response = mbim_device_command_finish(device, res, &error);
		if (!response
				|| !mbim_message_response_get_result(response,
						MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
			g_printerr("error: operation failed: %s\n", error->message);
			/* All errors are fatal */
			g_object_unref(link_user_connect_data->task);
			link_user_connect_data->link->mbimcli_async_operation_done(EXIT_FAILURE);
			return;
		}

		/* MBIM 1.0 support */
		if (!mbim_message_subscriber_ready_status_response_parse(response,
				&ready_state, &subscriber_id, &sim_iccid, &ready_info,
				&telephone_numbers_count, &telephone_numbers, &error)) {

			g_printerr("error: couldn't parse response message: %s\n",
					error->message);
			/* All errors are fatal */
			g_object_unref(link_user_connect_data->task);
			link_user_connect_data->link->mbimcli_async_operation_done(EXIT_FAILURE);
			return;
		}
		g_print("Successfully parsed response as MBIM 1.0 Subscriber State");

		telephone_numbers_str = (
				telephone_numbers ? g_strjoinv(", ", telephone_numbers) : NULL);
		ready_state_str = mbim_subscriber_ready_state_get_string(ready_state);
		ready_info_str = mbim_ready_info_flag_build_string_from_mask(
				ready_info);

		g_print("[%s] Subscriber ready status retrieved:\n"
				"\t      Ready state: '%s'\n"
				"\t    Subscriber ID: '%s'\n"
				"\t        SIM ICCID: '%s'\n"
				"\t       Ready info: '%s'\n"
				"\tTelephone numbers: (%u) '%s'\n",
				mbim_device_get_path_display(device),
				VALIDATE_UNKNOWN(ready_state_str),
				VALIDATE_UNKNOWN(subscriber_id), VALIDATE_UNKNOWN(sim_iccid),
				VALIDATE_UNKNOWN(ready_info_str), telephone_numbers_count,
				VALIDATE_UNKNOWN(telephone_numbers_str));

		/* Keep on */
		link_ctx->ready_state = ready_state;
		link_user_connect_data->step = LINK_CONNECT_STEP_QUERY_SUBSCRIBER_READY_STATUS;
		link_user_connect_data->link->link_context_step(link_user_connect_data->task);
	}

	static void pin_ready(MbimDevice *device, GAsyncResult *res,
			LinkUserData *tmp) {
		LinkUserData *link_user_connect_data = (LinkUserData*) tmp;
		LinkContext *link_ctx;
		link_ctx = (LinkContext*) g_task_get_task_data(link_user_connect_data->task);

		g_autoptr(MbimMessage) response = NULL;
		g_autoptr(GError) error = NULL;
		MbimPinType pin_type;
		MbimPinState pin_state;
		const gchar *pin_state_str;
		guint32 remaining_attempts;

		response = mbim_device_command_finish(device, res, &error);
		if (!response
				|| !mbim_message_response_get_result(response,
						MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
			g_printerr("error: operation failed: %s\n", error->message);
			/* All errors are fatal */
			g_object_unref(link_user_connect_data->task);
			link_user_connect_data->link->mbimcli_async_operation_done(EXIT_FAILURE);
			return;
		}

		if (!mbim_message_pin_response_parse(response, &pin_type, &pin_state,
				&remaining_attempts, &error)) {
			g_printerr("error: couldn't parse response message: %s\n",
					error->message);
			g_object_unref(link_user_connect_data->task);
			link_user_connect_data->link->mbimcli_async_operation_done(EXIT_FAILURE);
			return;
		}

		pin_state_str = mbim_pin_state_get_string(pin_state);

		g_print("[%s] PIN info:\n"
				"\t         PIN state: '%s'\n",
				mbim_device_get_path_display(device),
				VALIDATE_UNKNOWN(pin_state_str));
		if (pin_type != MBIM_PIN_TYPE_UNKNOWN) {
			const gchar *pin_type_str;

			pin_type_str = mbim_pin_type_get_string(pin_type);
			g_print("\t          PIN type: '%s'\n"
					"\tRemaining attempts: '%u'\n",
					VALIDATE_UNKNOWN(pin_type_str), remaining_attempts);
		}

		/* Keep on */
		link_ctx->pin_type = pin_type;
		link_ctx->pin_state = pin_state;
		link_ctx->remaining_attempts = remaining_attempts;
		link_user_connect_data->step = LINK_CONNECT_STEP_SET_PIN;
		link_user_connect_data->link->link_context_step(link_user_connect_data->task);
	}

	static void register_state_ready(MbimDevice *device, GAsyncResult *res,
			LinkUserData *tmp) {
		LinkUserData *link_user_connect_data = (LinkUserData*) tmp;
		LinkContext *link_ctx;
		link_ctx = (LinkContext*) g_task_get_task_data(link_user_connect_data->task);

		g_autoptr(MbimMessage) response = NULL;
		g_autoptr(GError) error = NULL;
		MbimNwError nw_error;
		MbimRegisterState register_state;
		MbimRegisterMode register_mode;
		MbimDataClass available_data_classes;
		g_autofree gchar *available_data_classes_str = NULL;
		MbimCellularClass cellular_class;
		g_autofree gchar *cellular_class_str = NULL;
		g_autofree gchar *provider_id = NULL;
		g_autofree gchar *provider_name = NULL;
		g_autofree gchar *roaming_text = NULL;
		MbimRegistrationFlag registration_flag;
		g_autofree gchar *registration_flag_str = NULL;

		response = mbim_device_command_finish(device, res, &error);
		if (!response
				|| !mbim_message_response_get_result(response,
						MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
			g_printerr("error: operation failed: %s\n", error->message);
			g_object_unref(link_user_connect_data->task);
			link_user_connect_data->link->mbimcli_async_operation_done(EXIT_FAILURE);
			return;
		}

		if (!mbim_message_register_state_response_parse(response, &nw_error,
				&register_state, &register_mode, &available_data_classes,
				&cellular_class, &provider_id, &provider_name, &roaming_text,
				&registration_flag, &error)) {
			g_printerr("error: couldn't parse response message: %s\n",
					error->message);
			g_object_unref(link_user_connect_data->task);
			link_user_connect_data->link->mbimcli_async_operation_done(EXIT_FAILURE);
			return;
		}

		available_data_classes_str = mbim_data_class_build_string_from_mask(
				available_data_classes);
		cellular_class_str = mbim_cellular_class_build_string_from_mask(
				cellular_class);
		registration_flag_str = mbim_registration_flag_build_string_from_mask(
				registration_flag);

		g_print("[%s] Registration status:\n"
				"\t         Network error: '%s'\n"
				"\t        Register state: '%s'\n"
				"\t         Register mode: '%s'\n"
				"\tAvailable data classes: '%s'\n"
				"\tCurrent cellular class: '%s'\n"
				"\t           Provider ID: '%s'\n"
				"\t         Provider name: '%s'\n"
				"\t          Roaming text: '%s'\n"
				"\t    Registration flags: '%s'\n",
				mbim_device_get_path_display(device),
				VALIDATE_UNKNOWN(mbim_nw_error_get_string(nw_error)),
				VALIDATE_UNKNOWN(
						mbim_register_state_get_string(register_state)),
				VALIDATE_UNKNOWN(mbim_register_mode_get_string(register_mode)),
				VALIDATE_UNKNOWN(available_data_classes_str),
				VALIDATE_UNKNOWN(cellular_class_str),
				VALIDATE_UNKNOWN(provider_id), VALIDATE_UNKNOWN(provider_name),
				VALIDATE_UNKNOWN(roaming_text),
				VALIDATE_UNKNOWN(registration_flag_str));

		/* Keep on */
		link_ctx->register_state = register_state;
		link_user_connect_data->step = LINK_CONNECT_STEP_SET_REGISTER_STATE_AUTOMATIC;
		link_user_connect_data->link->link_context_step(link_user_connect_data->task);
	}

	static void packet_service_ready(MbimDevice *device, GAsyncResult *res,
			LinkUserData *tmp) {
		LinkUserData *link_user_connect_data = (LinkUserData*) tmp;
		LinkContext *link_ctx;
		link_ctx = (LinkContext*) g_task_get_task_data(link_user_connect_data->task);

		g_autoptr(MbimMessage) response = NULL;
		g_autoptr(GError) error = NULL;
		guint32 nw_error;
		MbimPacketServiceState packet_service_state;
		MbimDataClass highest_available_data_class;
		g_autofree gchar *highest_available_data_class_str = NULL;
		guint64 uplink_speed;
		guint64 downlink_speed;

		response = mbim_device_command_finish(device, res, &error);
		if (!response
				|| !mbim_message_response_get_result(response,
						MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
			g_printerr("error: operation failed: %s\n", error->message);
			g_object_unref(link_user_connect_data->task);
			link_user_connect_data->link->mbimcli_async_operation_done(EXIT_FAILURE);
			return;
		}

		if (!mbim_message_packet_service_response_parse(response, &nw_error,
				&packet_service_state, &highest_available_data_class,
				&uplink_speed, &downlink_speed, &error)) {
			g_printerr("error: couldn't parse response message: %s\n",
					error->message);
			g_object_unref(link_user_connect_data->task);
			link_user_connect_data->link->mbimcli_async_operation_done(EXIT_FAILURE);
			return;
		}

		highest_available_data_class_str =
				mbim_data_class_build_string_from_mask(
						highest_available_data_class);

		g_print("[%s] Packet service status:\n"
				"\t         Network error: '%s'\n"
				"\t  Packet service state: '%s'\n"
				"\tAvailable data classes: '%s'\n"
				"\t          Uplink speed: '%" G_GUINT64_FORMAT " bps'\n"
		"\t        Downlink speed: '%" G_GUINT64_FORMAT " bps'\n",
				mbim_device_get_path_display(device),
				VALIDATE_UNKNOWN(
						mbim_nw_error_get_string((MbimNwError ) nw_error)),
				VALIDATE_UNKNOWN(
						mbim_packet_service_state_get_string(
								packet_service_state)),
				VALIDATE_UNKNOWN(highest_available_data_class_str),
				uplink_speed, downlink_speed);

		/* Keep on */
		link_ctx->packet_service_state = packet_service_state;
		link_user_connect_data->step = LINK_CONNECT_STEP_SET_PACKET_SERVICE_ATTACH_FLAG;
		link_user_connect_data->link->link_context_step(link_user_connect_data->task);
	}

	static void
	connect_ready (MbimDevice   *device,
	               GAsyncResult *res,
				   LinkUserData *tmp) {
		LinkUserData *link_user_connect_data = (LinkUserData*) tmp;

	    g_autoptr(MbimMessage)  response = NULL;
	    g_autoptr(GError)       error = NULL;
	    guint32                 session_id;
	    MbimActivationState     activation_state;
	    MbimVoiceCallState      voice_call_state;
	    MbimContextIpType       ip_type;
	    const MbimUuid         *context_type;
	    guint32                 nw_error;

	    response = mbim_device_command_finish (device, res, &error);
	    if (!response || !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
	        g_printerr ("error: operation failed: %s\n", error->message);
	        g_object_unref(link_user_connect_data->task);
			link_user_connect_data->link->mbimcli_async_operation_done(EXIT_FAILURE);
	        return;
	    }

	    if (!mbim_message_connect_response_parse (
	            response,
	            &session_id,
	            &activation_state,
	            &voice_call_state,
	            &ip_type,
	            &context_type,
	            &nw_error,
	            &error)) {
	        g_printerr ("error: couldn't parse response message: %s\n", error->message);
	        g_object_unref(link_user_connect_data->task);
			link_user_connect_data->link->mbimcli_async_operation_done(EXIT_FAILURE);
	        return;
	    }

	    g_print ("[%s] Connection status:\n"
	             "\t      Session ID: '%u'\n"
	             "\tActivation state: '%s'\n"
	             "\tVoice call state: '%s'\n"
	             "\t         IP type: '%s'\n"
	             "\t    Context type: '%s'\n"
	             "\t   Network error: '%s'\n",
	             mbim_device_get_path_display (device),
	             session_id,
	             VALIDATE_UNKNOWN (mbim_activation_state_get_string (activation_state)),
	             VALIDATE_UNKNOWN (mbim_voice_call_state_get_string (voice_call_state)),
	             VALIDATE_UNKNOWN (mbim_context_ip_type_get_string (ip_type)),
	             VALIDATE_UNKNOWN (mbim_context_type_get_string (mbim_uuid_to_context_type (context_type))),
	             VALIDATE_UNKNOWN (mbim_nw_error_get_string ((MbimNwError) nw_error)));


	    switch (link_user_connect_data->connect_type) {
	    case CONNECT:
	        g_print ("[%s] Successfully connected\n",
	                 mbim_device_get_path_display (device));
	        		link_user_connect_data->step = LINK_CONNECT_STEP_IP_QUERY;
	        break;
	    case DISCONNECT:
	        g_print ("[%s] Successfully disconnected\n\n",
	                 mbim_device_get_path_display (device));
	        		link_user_connect_data->step = LINK_DISCONNECT_STEP_LAST;
	        break;
	    default:
	        break;
	    }

	    link_user_connect_data->link->link_context_step(link_user_connect_data->task);
	}

	static void
	ip_configuration_query_ready (MbimDevice   *device,
	                              GAsyncResult *res,
								  LinkUserData *tmp) {
		LinkUserData *link_user_connect_data = (LinkUserData*) tmp;

		g_autoptr(GError)      error = NULL;
	    g_autoptr(MbimMessage) response;
	    gboolean               success = FALSE;

	    response = mbim_device_command_finish (device, res, &error);
	    if (!response ||
	        !mbim_message_response_get_result (response, MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)) {
	        g_printerr ("error: couldn't get IP configuration response message: %s\n", error->message);
	    } else {

	        g_autofree gchar                 *ipv4configurationavailable_str = NULL;
	        g_autofree gchar                 *ipv6configurationavailable_str = NULL;
	        link_user_connect_data->link->device_ctx->iPv4Addresses = NULL;
	        link_user_connect_data->link->device_ctx->iPv6Addresses = NULL;
	        link_user_connect_data->link->device_ctx->iPv4DnsServers = NULL;
	        link_user_connect_data->link->device_ctx->iPv6DnsServers = NULL;

	        if (!mbim_message_ip_configuration_response_parse (
	                response,
	                NULL, /* sessionid */
	                &link_user_connect_data->link->device_ctx->iPv4ConfigurationAvailable,
	                &link_user_connect_data->link->device_ctx->iPv6ConfigurationAvailable,
	                &link_user_connect_data->link->device_ctx->iPv4AddressCount,
	                &link_user_connect_data->link->device_ctx->iPv4Addresses,
	                &link_user_connect_data->link->device_ctx->iPv6AddressCount,
	                &link_user_connect_data->link->device_ctx->iPv6Addresses,
	                &link_user_connect_data->link->device_ctx->iPv4Gateway,
	                &link_user_connect_data->link->device_ctx->iPv6Gateway,
	                &link_user_connect_data->link->device_ctx->iPv4DnsServerCount,
	                &link_user_connect_data->link->device_ctx->iPv4DnsServers,
	                &link_user_connect_data->link->device_ctx->iPv6DnsServerCount,
	                &link_user_connect_data->link->device_ctx->iPv6DnsServers,
	                &link_user_connect_data->link->device_ctx->iPv4Mtu,
	                &link_user_connect_data->link->device_ctx->iPv6Mtu,
	                &error)) {
	        	success = FALSE;
	        } else {

				/* IPv4 info */

				ipv4configurationavailable_str = mbim_ip_configuration_available_flag_build_string_from_mask (link_user_connect_data->link->device_ctx->iPv4ConfigurationAvailable);
				g_print ("[%s] IPv4 configuration available: '%s'\n", mbim_device_get_path_display (device), ipv4configurationavailable_str);

				if (link_user_connect_data->link->device_ctx->iPv4ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_ADDRESS) {
					guint i;

					for (i = 0; i < link_user_connect_data->link->device_ctx->iPv4AddressCount; i++) {
						g_autoptr(GInetAddress)  addr = NULL;
						g_autofree gchar        *addr_str = NULL;

						addr = g_inet_address_new_from_bytes ((guint8 *)&link_user_connect_data->link->device_ctx->iPv4Addresses[i]->ipv4_address, G_SOCKET_FAMILY_IPV4);
						addr_str = g_inet_address_to_string (addr);
						g_print ("     IP [%u]: '%s/%u'\n", i, addr_str, link_user_connect_data->link->device_ctx->iPv4Addresses[i]->on_link_prefix_length);
					}
				}

				if (link_user_connect_data->link->device_ctx->iPv4ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_GATEWAY) {
					g_autoptr(GInetAddress)  addr = NULL;
					g_autofree gchar        *addr_str = NULL;

					addr = g_inet_address_new_from_bytes ((guint8 *)link_user_connect_data->link->device_ctx->iPv4Gateway, G_SOCKET_FAMILY_IPV4);
					addr_str = g_inet_address_to_string (addr);
					g_print ("    Gateway: '%s'\n", addr_str);
				}

				if (link_user_connect_data->link->device_ctx->iPv4ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_DNS) {
					guint i;

					for (i = 0; i < link_user_connect_data->link->device_ctx->iPv4DnsServerCount; i++) {
						g_autoptr(GInetAddress) addr = NULL;

						addr = g_inet_address_new_from_bytes ((guint8 *)&link_user_connect_data->link->device_ctx->iPv4DnsServers[i], G_SOCKET_FAMILY_IPV4);
						if (!g_inet_address_get_is_any (addr)) {
							g_autofree gchar *addr_str = NULL;

							addr_str = g_inet_address_to_string (addr);
							g_print ("    DNS [%u]: '%s'\n", i, addr_str);
						}
					}
				}

				if (link_user_connect_data->link->device_ctx->iPv4ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_MTU)
					g_print ("        MTU: '%u'\n", link_user_connect_data->link->device_ctx->iPv4Mtu);

				/* IPv6 info */
				ipv6configurationavailable_str = mbim_ip_configuration_available_flag_build_string_from_mask (link_user_connect_data->link->device_ctx->iPv6ConfigurationAvailable);
				g_print ("[%s] IPv6 configuration available: '%s'\n", mbim_device_get_path_display (device), ipv6configurationavailable_str);

				if (link_user_connect_data->link->device_ctx->iPv6ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_ADDRESS) {
					guint i;

					for (i = 0; i < link_user_connect_data->link->device_ctx->iPv6AddressCount; i++) {
						g_autoptr(GInetAddress)  addr = NULL;
						g_autofree gchar        *addr_str = NULL;

						addr = g_inet_address_new_from_bytes ((guint8 *)&link_user_connect_data->link->device_ctx->iPv6Addresses[i]->ipv6_address, G_SOCKET_FAMILY_IPV6);
						addr_str = g_inet_address_to_string (addr);
						g_print ("     IP [%u]: '%s/%u'\n", i, addr_str, link_user_connect_data->link->device_ctx->iPv6Addresses[i]->on_link_prefix_length);
					}
				}

				if (link_user_connect_data->link->device_ctx->iPv6ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_GATEWAY) {
					g_autoptr(GInetAddress)  addr = NULL;
					g_autofree gchar        *addr_str = NULL;

					addr = g_inet_address_new_from_bytes ((guint8 *)link_user_connect_data->link->device_ctx->iPv6Gateway, G_SOCKET_FAMILY_IPV6);
					addr_str = g_inet_address_to_string (addr);
					g_print ("    Gateway: '%s'\n", addr_str);
				}

				if (link_user_connect_data->link->device_ctx->iPv6ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_DNS) {
					guint i;

					for (i = 0; i < link_user_connect_data->link->device_ctx->iPv6DnsServerCount; i++) {
						g_autoptr(GInetAddress) addr = NULL;

						addr = g_inet_address_new_from_bytes ((guint8 *)&link_user_connect_data->link->device_ctx->iPv6DnsServers[i], G_SOCKET_FAMILY_IPV6);
						if (!g_inet_address_get_is_any (addr)) {
							g_autofree gchar *addr_str = NULL;

							addr_str = g_inet_address_to_string (addr);
							g_print ("    DNS [%u]: '%s'\n", i, addr_str);
						}
					}
				}

				if (link_user_connect_data->link->device_ctx->iPv6ConfigurationAvailable & MBIM_IP_CONFIGURATION_AVAILABLE_FLAG_MTU)
					g_print ("        MTU: '%u'\n", link_user_connect_data->link->device_ctx->iPv6Mtu);


				success = TRUE;
	        }

	        if (!success)
	            g_printerr ("error: couldn't parse IP configuration response message: %s\n", error->message);
	    }

	    link_user_connect_data->step = LINK_CONNECT_STEP_CREATE_DEVICES;
		link_user_connect_data->link->link_context_step(link_user_connect_data->task);
	}

	static gboolean signals_handler(gpointer psignum) {
		test_link *tmp_link = (test_link*) psignum;
		if (tmp_link->cancellable) {
			/* Ignore consecutive requests of cancellation */
			if (!g_cancellable_is_cancelled(tmp_link->cancellable)) {
				g_print("Canceling the operation...\n");
				g_cancellable_cancel(tmp_link->cancellable);
			}
		}

		if (tmp_link->loop && g_main_loop_is_running(tmp_link->loop)) {
			g_print("Canceling the main loop...\n");
			g_idle_add((GSourceFunc) g_main_loop_quit, tmp_link->loop);
		}

		return FALSE;
	}

	// Globals
	GMainLoop *loop;
	GCancellable *cancellable;
	MbimDevice *mbim_device;
	gboolean operation_status;
	LinkContext *link_ctx;
	DeviceContext *device_ctx;
	LinkUserData *link_user_connect_data;
};

// ********************************************************************************************************************************

class test_module: public linkmanager::api::modules::link_module {
public:
	inline explicit test_module() {
		// Set defaults
		mbim_device = NULL;
		link_module_ctx = NULL;
		link_module_user_data = NULL;

		m_link_module_name = "EM919x Sierra Wireless LTE Module";
	}

	virtual ~test_module() {
		g_print("Link Module destructor called %s!\n", name().c_str());

		cleanup();
	}

	virtual std::string name() const final {
		return m_link_module_name;
	}

	virtual bool is_powered_on() const final {
		// future with future HW component that controls module power supply
		// e.g. bool isPowerOn() as member function of psControl
		// psControl.isPowerOn();
		return false;
	}

	virtual bool set_powered_on(bool new_state [[maybe_unused]]) final {
		if (new_state) {
			// return (bool powerOn())
		} else {
			cleanup();
			// return (bool powerOff())
		}
		// Temporary
		return true;
	}

	virtual link_list links() const final {
		return m_links;
	}

	virtual bool configure(nlohmann::json const &config) {
		g_print("\n----Configure module: %s -----\n\n", name().c_str());

		GError *error = NULL;
		g_autoptr(GFile) file = NULL;

		/* Link Device Context */
		link_module_ctx = g_slice_new0(LinkModuleContext);
		link_module_ctx->step = MODULE_STEP_FIRST;
		/* Transaction_id value FIXED to 3
		 * since the message is expected to be sent only
		 * after the reception of the response from previous
		 * message or timeout
		 */
		link_module_ctx->transaction_id = 3;
		/* Use proxy feature */
		link_module_ctx->open_flags = MBIM_DEVICE_OPEN_FLAGS_PROXY;
		/* Radio State */
		link_module_ctx->radioState_cnt = 0;

		/* Parse config file and fill in context content */
		// Get module path
		if (config.contains("modulePath")) {
			auto key = config["modulePath"].get<std::string>();
			link_module_ctx->device_path = g_strdup((gchar*) key.c_str());
			g_print("device_path: %s\n", link_module_ctx->device_path);
		} else {
			g_printerr("ERROR: Missing device (module) path!\n");
			context_free();
			return EXIT_FAILURE;
		}

		// Create link array according to sessions in configuration file
		if (config.contains("links")) {
			int link_cnt = 0;
			for (auto& [link_name, value] : config["links"].items()) {
				link_module_ctx->link[link_cnt] = g_strdup(
						(gchar*) link_name.c_str());
				g_print("Found link: %s\n", link_module_ctx->link[link_cnt]);
				link_cnt++;
			}
			if (link_cnt != NUMBER_OF_SIM_CARD_SLOTS) {
				g_printerr(
						"ERROR: Number of links in config file does not match number of SIM card slots!\n");
				context_free();
				return EXIT_FAILURE;
			}
		} else {
			g_printerr("ERROR: Missing session configuration!\n");
			context_free();
			return EXIT_FAILURE;
		}

		link_module_user_data = g_slice_new0(LinkModuleUserData);
		link_module_user_data->link_module = this;

		/* Build new GFile */
		file = g_file_new_for_path(link_module_ctx->device_path);
		if (!file) {
			g_printerr("error: couldn't get bus: %s\n",
					error ? error->message : "unknown error");
			context_free();
			return EXIT_FAILURE;
		}

		/* Applications that want to start one or more operations that should be cancellable
		 * should create a GCancellable object and pass it to the operations
		 */
		cancellable = g_cancellable_new();

		/* Create main event loop for application */
		loop = g_main_loop_new(NULL, FALSE);

		/* Setup signals for safe exit
		 * A convenience function for g_unix_signal_source_new(), which attaches to the default GMainContext
		 */
		g_unix_signal_add(SIGINT, (GSourceFunc) signals_handler, this);
		g_unix_signal_add(SIGHUP, (GSourceFunc) signals_handler, this);
		g_unix_signal_add(SIGTERM, (GSourceFunc) signals_handler, this);

		/* Launch MbimDevice creation */
		mbim_device_new(file, cancellable,
				(GAsyncReadyCallback) device_new_ready, this);
		g_main_loop_run(loop);

		// Clear context
		if (cancellable)
			g_object_unref(cancellable);
		g_main_loop_unref(loop);

		if (operation_status == EXIT_FAILURE) {
			cleanup();
		}

		g_printerr("NOTE: Operation status: %s!\n",
				operation_status ? "EXIT_FAILURE" : "EXIT_SUCCESS");
		return (operation_status ? EXIT_FAILURE : EXIT_SUCCESS);
	}

	std::string m_link_module_name;
	inline static link_list m_links = { };

	//************************************CUSTOM*************************************************
	typedef struct {
		test_module *link_module;
		GTask *task;
	} LinkModuleUserData;

	inline void create_link(const std::string &link_name) {
		m_links.push_back(std::make_shared<test_link>(link_name, mbim_device));
	}

	inline void context_free() {
		if (link_module_ctx) {
			g_print("Free link_module_ctx...\n");
			g_free(link_module_ctx->device_path);
			for (int i = 0; i < NUMBER_OF_SIM_CARD_SLOTS; i++) {
				g_free(link_module_ctx->link[i]);
			}
			g_slice_free(LinkModuleContext, link_module_ctx);
			link_module_ctx = NULL;
		}

		if (link_module_user_data) {
			g_print("Free link_module_user_data...\n");
			g_slice_free(LinkModuleUserData, link_module_user_data);
			link_module_user_data = NULL;
		}
	}

	inline void mbimcli_async_operation_done(
			gboolean reported_operation_status) {
		/* Keep the result of the operation */
		operation_status = reported_operation_status;

		/* Cleanup cancellation */
		g_clear_object(&cancellable);

		g_main_loop_quit(loop);
	}

	inline void shutdown(gboolean operation_status) {
		/* Cleanup context and finish async operation */
		context_free();
		mbimcli_async_operation_done(operation_status);
	}

	inline void cleanup() {
		// Clear links list
		if (!m_links.empty()) {
			m_links.clear();
		}

		if (mbim_device) {
			/* Close the device */
			if (mbim_device_is_open(mbim_device)) {
				/* Create main event loop for application */
				loop = g_main_loop_new(NULL, FALSE);
				mbim_device_close(mbim_device, 15, NULL,
						(GAsyncReadyCallback) device_close_ready, this);
				g_main_loop_run(loop);
				g_main_loop_unref(loop);
			}

			g_object_unref(mbim_device);
			mbim_device = NULL;
		}
	}

	inline void link_module_context_step(GTask *task) {

		MbimDevice *self;
		LinkModuleContext *link_module_ctx;
		g_autoptr(MbimMessage) message = NULL;

		/* If cancelled, complete */
		if (g_task_return_error_if_cancelled(task)) {
			g_object_unref(task);
			return;
		}

		self = (MbimDevice*) g_task_get_source_object(task);
		link_module_ctx = (LinkModuleContext*) g_task_get_task_data(task);

		switch (link_module_ctx->step) {

		case MODULE_STEP_FIRST:
			g_print("link_module_context_step: %d\n", link_module_ctx->step);

			link_module_ctx->step = MODULE_STEP_QUERY_DEV_CAPS;
			/* Fall through */

		case MODULE_STEP_QUERY_DEV_CAPS:
			g_print("link_module_context_step: %d\n", link_module_ctx->step);

			g_print("Asynchronously querying device capabilities...\n");
			message = (mbim_message_device_caps_query_new(NULL));
			mbim_device_command(self, message, 30, g_task_get_cancellable(task),
					(GAsyncReadyCallback) query_device_caps_ready,
					link_module_user_data);
			return;

		case MODULE_STEP_QUERY_RADIO_STATE:
			g_print("link_module_context_step: %d\n", link_module_ctx->step);

			g_print("Asynchronously querying radio state...\n");
			message = (mbim_message_radio_state_query_new(NULL));
			mbim_device_command(self, message, 10, g_task_get_cancellable(task),
					(GAsyncReadyCallback) query_radio_state_ready,
					link_module_user_data);
			return;

		case MODULE_STEP_SET_RADIO_STATE:
			g_print("link_module_context_step: %d\n", link_module_ctx->step);

			/* Protection against infinite loop needed */
			if (link_module_ctx->radioState_cnt > 3) {
				g_print("ERROR: Could not set Radio State\n");
				g_object_unref(task);
				shutdown(EXIT_FAILURE);

				return;
			}

			if (link_module_ctx->s_HwRadioState == MBIM_RADIO_SWITCH_STATE_OFF
					|| link_module_ctx->s_SwRadioState
							== MBIM_RADIO_SWITCH_STATE_OFF) {
				g_print("Asynchronously setting radio state to ON...\n");
				message = mbim_message_radio_state_set_new(
						MBIM_RADIO_SWITCH_STATE_ON, NULL);
				link_module_ctx->radioState_cnt++;
				mbim_device_command(self, message, 10,
						g_task_get_cancellable(task),
						(GAsyncReadyCallback) query_radio_state_ready, link_module_user_data);
				return;
			}

			link_module_ctx->step = MODULE_STEP_CREATE_LINKS;

		case MODULE_STEP_CREATE_LINKS:
			g_print("link_module_context_step: %d\n", link_module_ctx->step);

			for (int i = 0; i < NUMBER_OF_SIM_CARD_SLOTS; i++) {
				create_link(link_module_ctx->link[i]);
			}

			link_module_ctx->step = MODULE_STEP_LAST;

		case MODULE_STEP_LAST:
			g_print("link_module_context_step: %d\n", link_module_ctx->step);

			g_object_unref(task);
			shutdown(EXIT_SUCCESS);
			return;

		default:
			g_print("DEFAULT...\n");
			break;
		}

		g_print("This state shouldn't be reached! Error in task\n");
		g_object_unref(task);
		shutdown(EXIT_FAILURE);

		return;
	}

	static gboolean signals_handler(gpointer psignum) {
		test_link *tmp_link = (test_link*) psignum;
		if (tmp_link->cancellable) {
			/* Ignore consecutive requests of cancellation */
			if (!g_cancellable_is_cancelled(tmp_link->cancellable)) {
				g_print("Canceling the operation...\n");
				g_cancellable_cancel(tmp_link->cancellable);
			}
		}

		if (tmp_link->loop && g_main_loop_is_running(tmp_link->loop)) {
			g_print("Canceling the main loop...\n");
			g_idle_add((GSourceFunc) g_main_loop_quit, tmp_link->loop);
		}

		return FALSE;
	}

	static void device_new_ready(GObject *unused, GAsyncResult *res,
			test_module *tmp) {
		test_module *link_device = (test_module*) tmp;
		GError *error = NULL;

		/* Finishes an operation started with mbim_device_new() */
		link_device->mbim_device = mbim_device_new_finish(res, &error);
		if (!link_device->mbim_device) {
			g_print("error: couldn't create MbimDevice: %s\n", error->message);
			link_device->shutdown(EXIT_FAILURE);
		}

		g_object_set(link_device->mbim_device,
		MBIM_DEVICE_IN_SESSION, TRUE,
		MBIM_DEVICE_TRANSACTION_ID,
				link_device->link_module_ctx->transaction_id,
				NULL);

		/* Open the mbim_device allows launching the MbimDevice */
		mbim_device_open_full(link_device->mbim_device,
				link_device->link_module_ctx->open_flags, 30,
				link_device->cancellable,
				(GAsyncReadyCallback) device_open_ready, link_device);
	}

	static void device_open_ready(MbimDevice *dev, GAsyncResult *res,
			test_module *tmp) {
		test_module *link_device = (test_module*) tmp;
		g_autoptr(GError) error = NULL;
		GTask *task;

		if (!mbim_device_open_finish(dev, res, &error)) {
			g_print("error: couldn't open the MbimDevice: %s\n",
					error->message);
			link_device->shutdown(EXIT_FAILURE);
		}

		g_print("MBIM device at '%s' ready\n",
				mbim_device_get_path_display(dev));

		/* Task set-up */
		// TBD: callback - think if callback is needed; indicates creation of the task
		task = g_task_new(dev, link_device->cancellable, NULL, NULL);
		// TBD: last argument NULL because context free should happen outside task control, maybe in configure() or !test_link()
		g_task_set_task_data(task, link_device->link_module_ctx, NULL);

		link_device->link_module_user_data->task = task;

		/* Connecting procedure */
		link_device->link_module_context_step(task);
	}

	static void query_device_caps_ready(MbimDevice *dev, GAsyncResult *res,
			LinkModuleUserData *tmp) {
		LinkModuleUserData *link_module_user_data = (LinkModuleUserData*) tmp;
		LinkModuleContext *link_module_ctx;
		link_module_ctx = (LinkModuleContext*) g_task_get_task_data(
				link_module_user_data->task);

		g_autoptr(GError) error = NULL;
		g_autoptr(MbimMessage) response = NULL;
		MbimDeviceType device_type;
		const gchar *device_type_str;
		MbimVoiceClass voice_class;
		const gchar *voice_class_str;
		MbimCellularClass cellular_class;
		g_autofree gchar *cellular_class_str = NULL;
		MbimSimClass sim_class;
		g_autofree gchar *sim_class_str = NULL;
		MbimDataClass data_class;
		g_autofree gchar *data_class_str = NULL;
		MbimSmsCaps sms_caps;
		g_autofree gchar *sms_caps_str = NULL;
		MbimCtrlCaps ctrl_caps;
		g_autofree gchar *ctrl_caps_str = NULL;
		guint32 max_sessions;
		g_autofree gchar *custom_data_class = NULL;
		g_autofree gchar *device_id = NULL;
		g_autofree gchar *firmware_info = NULL;
		g_autofree gchar *hardware_info = NULL;

		response = mbim_device_command_finish(dev, res, &error);
		if (!(response
				&& (mbim_message_response_get_result(response,
						MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)
						|| error->code == MBIM_STATUS_ERROR_FAILURE))) {
			g_print("error: operation failed: %s\n", error->message);
			/* All errors are fatal */
			g_object_unref(link_module_user_data->task);
			link_module_user_data->link_module->shutdown(EXIT_FAILURE);
			return;
		}

		if (!mbim_message_device_caps_response_parse(response, &device_type,
				&cellular_class, &voice_class, &sim_class, &data_class,
				&sms_caps, &ctrl_caps, &max_sessions, &custom_data_class,
				&device_id, &firmware_info, &hardware_info, &error)) {
			g_print("error: couldn't parse response message: %s\n",
					error->message);
			g_object_unref(link_module_user_data->task);
			link_module_user_data->link_module->shutdown(EXIT_FAILURE);
			return;
		}

		device_type_str = mbim_device_type_get_string(device_type);
		cellular_class_str = mbim_cellular_class_build_string_from_mask(
				cellular_class);
		voice_class_str = mbim_voice_class_get_string(voice_class);
		sim_class_str = mbim_sim_class_build_string_from_mask(sim_class);
		data_class_str = mbim_data_class_build_string_from_mask(data_class);
		sms_caps_str = mbim_sms_caps_build_string_from_mask(sms_caps);
		ctrl_caps_str = mbim_ctrl_caps_build_string_from_mask(ctrl_caps);

		g_print("[%s] Device capabilities retrieved:\n"
				"\t      Device type: '%s'\n"
				"\t   Cellular class: '%s'\n"
				"\t      Voice class: '%s'\n"
				"\t        SIM class: '%s'\n"
				"\t       Data class: '%s'\n"
				"\t         SMS caps: '%s'\n"
				"\t        Ctrl caps: '%s'\n"
				"\t     Max sessions: '%u'\n"
				"\tCustom data class: '%s'\n"
				"\t        Device ID: '%s'\n"
				"\t    Firmware info: '%s'\n"
				"\t    Hardware info: '%s'\n",
				mbim_device_get_path_display(
						link_module_user_data->link_module->mbim_device),
				VALIDATE_UNKNOWN(device_type_str),
				VALIDATE_UNKNOWN(cellular_class_str),
				VALIDATE_UNKNOWN(voice_class_str),
				VALIDATE_UNKNOWN(sim_class_str),
				VALIDATE_UNKNOWN(data_class_str),
				VALIDATE_UNKNOWN(sms_caps_str), VALIDATE_UNKNOWN(ctrl_caps_str),
				max_sessions, VALIDATE_UNKNOWN(custom_data_class),
				VALIDATE_UNKNOWN(device_id), VALIDATE_UNKNOWN(firmware_info),
				VALIDATE_UNKNOWN(hardware_info));

		/* Keep on */
		link_module_ctx->step = MODULE_STEP_QUERY_RADIO_STATE;
		link_module_user_data->link_module->link_module_context_step(
				link_module_user_data->task);
	}

	static void query_radio_state_ready(MbimDevice *dev, GAsyncResult *res,
			LinkModuleUserData *tmp) {
		LinkModuleUserData *link_module_user_data = (LinkModuleUserData*) tmp;
		LinkModuleContext *link_module_ctx;
		link_module_ctx = (LinkModuleContext*) g_task_get_task_data(
				link_module_user_data->task);

		g_autoptr(MbimMessage) response = NULL;
		g_autoptr(GError) error = NULL;
		MbimRadioSwitchState hardware_radio_state;
		const gchar *hardware_radio_state_str;
		MbimRadioSwitchState software_radio_state;
		const gchar *software_radio_state_str;

		response = mbim_device_command_finish(dev, res, &error);
		if (!(response
				&& (mbim_message_response_get_result(response,
						MBIM_MESSAGE_TYPE_COMMAND_DONE, &error)
						|| error->code == MBIM_STATUS_ERROR_FAILURE))) {
			g_print("error: operation failed: %s\n", error->message);
			/* All errors are fatal */
			g_object_unref(link_module_user_data->task);
			link_module_user_data->link_module->shutdown(EXIT_FAILURE);
			return;
		}

		if (!mbim_message_radio_state_response_parse(response,
				&hardware_radio_state, &software_radio_state, &error)) {
			g_printerr("error: couldn't parse response message: %s\n",
					error->message);
			g_object_unref(link_module_user_data->task);
			link_module_user_data->link_module->shutdown(EXIT_FAILURE);
			return;
		}

		hardware_radio_state_str = mbim_radio_switch_state_get_string(
				hardware_radio_state);
		software_radio_state_str = mbim_radio_switch_state_get_string(
				software_radio_state);

		g_print("[%s] Radio state retrieved:\n"
				"\t     Hardware radio state: '%s'\n"
				"\t     Software radio state: '%s'\n",
				mbim_device_get_path_display(dev),
				VALIDATE_UNKNOWN(hardware_radio_state_str),
				VALIDATE_UNKNOWN(software_radio_state_str));

		/* Keep on */
		link_module_ctx->s_HwRadioState = hardware_radio_state;
		link_module_ctx->s_SwRadioState = software_radio_state;
		link_module_ctx->step = MODULE_STEP_SET_RADIO_STATE;
		link_module_user_data->link_module->link_module_context_step(
				link_module_user_data->task);
	}

	static void device_close_ready(MbimDevice *dev, GAsyncResult *res,
			test_module *tmp) {
		test_module *link_device = (test_module*) tmp;
		GError *error = NULL;

		if (!mbim_device_close_finish(dev, res, &error)) {
			g_printerr("error: couldn't close device: %s\n", error->message);
			g_error_free(error);
		} else
			g_print("MBIM device closed\n");

		/* Cancel main loop */
		g_main_loop_quit(link_device->loop);
	}

	// Globals
	GMainLoop *loop;
	GCancellable *cancellable;
	MbimDevice *mbim_device;
	gboolean operation_status;
	LinkModuleContext *link_module_ctx;
	LinkModuleUserData *link_module_user_data;
};

}
