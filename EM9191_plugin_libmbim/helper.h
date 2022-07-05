/* DEFINE */
#define VALIDATE_UNKNOWN(str) ((str) ? (str) : "unknown")
// Depends on number of SIM slots
#define NUMBER_OF_SIM_CARD_SLOTS 2

#ifndef ARRAYSIZE
#define ARRAYSIZE(a)                (sizeof(a)/sizeof(a[0]))
#endif

#define MAX_SESSIONS 4			// Arbitrary. May be changed by developer.
#define MAX_IP_ADDRESSES 4		// Arbitrary. May be changed by developer.
#define MAX_DNS_SERVERS 4		// Arbitrary. May be changed by developer.
#define MAX_ROUTES 4			// Arbitrary. May be changed by developer.
#define MAX_PING_DESTINATIONS 4	// Arbitrary. May be changed by developer.

#define PING_COUNT    10
#define PING_DELAY    3

#define SUCCESS 0
#define FAILURE -1

/* ENUM*/
typedef enum {
	MODULE_STEP_FIRST,									// 0
	MODULE_STEP_QUERY_DEV_CAPS,							// 1
	MODULE_STEP_QUERY_RADIO_STATE,						// 2
	MODULE_STEP_SET_RADIO_STATE,						// 3
	MODULE_STEP_CREATE_LINKS,							// 4
	MODULE_STEP_LAST									// 5
} LinkModuleStep;

typedef enum {
	LINK_CONNECT_STEP_FIRST,										// 0
	LINK_CONNECT_STEP_QUERY_SUBSCRIBER_READY_STATUS,				// 1
	LINK_CONNECT_STEP_QUERY_PIN_STATE,								// 2
	LINK_CONNECT_STEP_SET_PIN,							    		// 3
	LINK_CONNECT_STEP_QUERY_REGISTER_STATE,							// 4
	LINK_CONNECT_STEP_SET_REGISTER_STATE_AUTOMATIC,					// 5
	LINK_CONNECT_STEP_QUERY_PACKET_SERVICE_READY,					// 6
	LINK_CONNECT_STEP_SET_PACKET_SERVICE_ATTACH_FLAG,				// 7
	LINK_CONNECT_STEP_CONNECT_ACTIVATE,								// 8
	LINK_CONNECT_STEP_IP_QUERY,										// 9
	LINK_CONNECT_STEP_CREATE_DEVICES,								// 10
	LINK_CONNECT_STEP_LAST,											// 11
	LINK_DISCONNECT_CONNECT_DEACTIVATE,								// 12
	LINK_DISCONNECT_STEP_LAST										// 13
} LinkStep;

typedef enum {
	CONNECT,								// 0
	DISCONNECT								// 1
} MbimConnectType;

typedef enum {
	ALL,
	LINK_USER_DATA_ONLY,
	NONE
} LinkUserDataCtxFreeType;

/* STRUCT */
typedef struct {
	char szInterface[IF_NAMESIZE];
	char szDst[INET_ADDRSTRLEN];
	uint32_t dstPrefixLength;    // This is the number of leftmost bits that make up the network mask.
	char szGateway[INET_ADDRSTRLEN];
} IPv4RouteTableEntry;

typedef struct
{
	char szInterface[IF_NAMESIZE];
	char szDst[INET6_ADDRSTRLEN];
	uint32_t dstPrefixLength;	// This is the number of leftmost bits that make up the network mask.
	char szGateway[INET6_ADDRSTRLEN];
} IPv6RouteTableEntry;
typedef struct {
	MbimDeviceOpenFlags open_flags;
	char *link[NUMBER_OF_SIM_CARD_SLOTS];
	char *device_path;
	LinkModuleStep step;
	guint radioState_cnt;
	MbimRadioSwitchState s_HwRadioState;
	MbimRadioSwitchState s_SwRadioState;
	guint transaction_id;
} LinkModuleContext;

typedef struct {
	MbimSubscriberReadyState ready_state;
	guint32 remaining_attempts;
	MbimPinType pin_type;
	MbimPinState pin_state;
	MbimPinOperation pin_operation;
	gchar *pin;

	MbimRegisterState register_state;

	MbimPacketServiceAction packet_service_action;
	MbimPacketServiceState packet_service_state;
	gchar *user_name;
	gchar *password;
	gchar *access_string;
	guint compression;
	guint auth_protocol;
	guint ip_type;
	guint session_id;
} LinkContext;

typedef struct {
	gchar *interface_name;
	gchar *vlan_name;
	guint vlan_id;

	// Routing tables.
	guint32 iPv4RouteCount;
	IPv4RouteTableEntry iPv4Routes[MAX_ROUTES];
	guint32 iPv6RouteCount;
	IPv6RouteTableEntry iPv6Routes[MAX_ROUTES];

	// Ping destinations. Should align with routing table entries.
	guint32 iPv4PingDestinationCount;
	char iPv4PingDestinations[MAX_PING_DESTINATIONS][INET_ADDRSTRLEN];
	guint32 iPv6PingDestinationCount;
	char iPv6PingDestinations[MAX_PING_DESTINATIONS][INET6_ADDRSTRLEN];

	/*  */
    MbimIPConfigurationAvailableFlag  iPv4ConfigurationAvailable;
    MbimIPConfigurationAvailableFlag  iPv6ConfigurationAvailable;
    guint32                           iPv4AddressCount;
    MbimIPv4ElementArray			 *iPv4Addresses;
    guint32                           iPv6AddressCount;
    MbimIPv6ElementArray   			 *iPv6Addresses;
    const MbimIPv4                   *iPv4Gateway;
    const MbimIPv6                   *iPv6Gateway;
    guint32                           iPv4DnsServerCount;
    MbimIPv4              			 *iPv4DnsServers;
    guint32                           iPv6DnsServerCount;
    MbimIPv6                         *iPv6DnsServers;
    guint32                           iPv4Mtu;
    guint32                           iPv6Mtu;
} DeviceContext;

