/**
 * \ingroup liteqmi
 * \ingroup swi
 * \file common.h
 */
#ifndef __COMMON_H
#define __COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "switype_256bit.h"
#define SDU_HDR_LEN (3)
#define MINREQBKLEN (2048)
#define MSGID_AND_LEN    (4)
#define MSGID_DONT_CARE (0xffff)

#ifndef UNUSEDPARAM
#define UNUSEDPARAM( x ) (void)x
#endif 

#define DEAULT_LOC_TIMEOUT_IN_SEC 2
#define SDK_VALIDATE_INPUT_PACK_PARAM(pCtx, pBuf, pLen ) \
    if ((pCtx == NULL) || (pBuf == NULL) || (pLen == NULL) ) \
        {\
        liteqmi_log(eLOG_DEBUG,"[  pack] %s parameter NULL\n",__func__); \
        return eQCWWAN_ERR_INVALID_ARG; \
        }

#define SDK_VALIDATE_INPUT_PACK_PARAM_AND_FILL_XID(pCtx, pBuf, pLen ) \
    if ((pCtx == NULL) || (pBuf == NULL) || (pLen == NULL) ) \
        {\
        liteqmi_log(eLOG_DEBUG,"[  pack] %s parameter NULL\n",__func__); \
        return eQCWWAN_ERR_INVALID_ARG; \
        } \
    if (pCtx->xid == 0) \
       return eQCWWAN_ERR_INVALID_XID; \
    pBuf[0] = eREQ; \
    pBuf[1] = pCtx->xid & 0xff; \
    pBuf[2] = pCtx->xid >> 8;

#define SDK_VALIDATE_INPUT_UNPACK_PARAM(pResp, respLen, pOutput ) \
    if ((pResp == NULL) || (respLen == 0) || (pOutput == NULL) ) \
        {\
        liteqmi_log(eLOG_DEBUG,"[ unpack] %s parameter NULL or invalid\n",__func__); \
        return eQCWWAN_ERR_INVALID_ARG; \
        }

#ifdef SIERRA_ANDROID_RIL
/* We have to rename the "logger" because it clashes with Android's logger name. */
#define logger swilogger
#endif

typedef void (* logger)(uint8_t lvl, const char* buff, ...);

extern logger glog;
extern uint8_t gloglvl;

/**
 * \ingroup swi
 * 
 * log levels
 */
enum eLOG_LEVEL{
    eLOG_INFO,
    eLOG_DEBUG,
    eLOG_WARN,
    eLOG_ERROR,
    eLOG_FATAL
};

/**
 *  eTimeout
 **/
enum eTimeout
{
    eTIMEOUT_2_S        = 2000,
    eTIMEOUT_5_S        = 5000,
    eTIMEOUT_8_S        = 8000,
    eTIMEOUT_10_S       = 10000,
    eTIMEOUT_20_S       = 20000,
    eTIMEOUT_30_S       = 30000,
    eTIMEOUT_60_S       = 60000,
    eTIMEOUT_300_S      = 300000,
    eTIMEOUT_DEFAULT    = eTIMEOUT_8_S
};

/**
 * \ingroup swi
 * 
 * qmi service
 */
enum eQMI_SVC{
    eCTL=0,
    eWDS=0x01,
    eDMS=0x02,
    eNAS=0x03,
    eQOS=0x04,
    eSMS=0x05,
    eCAT=0x0A,
    eUIM=0x0B,
    eLOC=0x10,
    eSAR=0x11,
    eIMS=0x12,    // 012 IMS Service
	eTS=0x17,
    eTMD=0x18,
	eWDA=0x1A,
    eIMSA=0x21,
    eDSD=0x2A,    //DSD is assigned QMI service type 0x2A
    eRMS=225,
    eSWILOC=246,
    eSWINAS=252,    // 0xFC
    eSWIDMS=254
};

/**
 * \ingroup swi
 * 
 * qmi message type
 */
enum msgtype{
    eREQ=0,
    eRSP=2,
    eIND=4
};

/**
 * \ingroup swi
 * 
 * qmi request context
 * @param[in] xid transaction id
 * @param[out] timeout timeout recommended in seconds
 * @param[out] msgid message id
 * @param[out] svc qmi service
 */
typedef struct{
    uint16_t    xid;
    int         timeout;
    uint16_t    msgid;
    uint8_t     svc;
} pack_qmi_t;

/**
 * \ingroup swi
 * 
 * qmi response context
 * @param[out] type message type
 * @param[out] msgid message id
 * @param[out] xid transaction id
 */
typedef struct{
    enum msgtype    type;
    uint16_t        msgid;
    uint16_t        xid;
} unpack_qmi_t;

/**
 * \ingroup swi
 * 
 * Helper function to get transaction ID
 * 
 * @param[in] qmi_resp: QMI response message
 * 
 * @return Transaction ID in uint16_t
 */
uint16_t helper_get_xid(uint8_t *qmi_resp);

/**
 * \ingroup swi
 *
 * Helper function to get message ID
 *
 * @param[in] qmi_resp: QMI response message
 *
 * @return Message ID in uint16_t
 */
uint16_t helper_get_msgid(uint8_t *qmi_resp);

/**
 * \ingroup swi
 * 
 * Helper function to get SDK error code based on 
 * device error code in QMI response
 * 
 * @param[in] qmi_resp: QMI response message
 * 
 * @return SDK error code
 */
uint16_t helper_get_error_code(uint8_t *qmi_resp);

/**
 * \ingroup swi
 * 
 * Helper function to get error reason string
 * 
 * @param[in] retVal: Return code value
 * 
 * @return Error message based on the return code
 */
char* helper_get_error_reason(uint16_t retVal);

/**
 * \ingroup swi
 * 
 * extract msgid/xid/type from modem reply
 * @param[in] svc qmi service
 * @param[in] pbuf qmi response/indication
 * @param[in] len response/indication length
 * @param[out] pCtx unpacked context
 * @return qmi message string
 */
const char* helper_get_resp_ctx(
    uint8_t svc,
    uint8_t *pbuf,
    uint16_t len,
    unpack_qmi_t *pCtx
);

/**
 * \ingroup swi
 * 
 * extract msgid string from modem req
 * @param[in] svc qmi service
 * @param[in] req qmi request
 * @param[in] len request length
 * @return qmi message string
 */
const char* helper_get_req_str(
    uint8_t svc,
    uint8_t *req,
    uint32_t len
);

/**
 * \ingroup swi
 * 
 * common handler for unpacking response with TLV type 0x02 only
 */
unsigned unpack_result_code_only(uint8_t *pMdmResp);

/**
 * \ingroup swi
 * 
 * Set external log function for lite-qmi messages.
 * If no external log function is used, lite-qmi messages
 * go to syslog.
 * 
 * @param[in] func: External logger function
 * 
 * @return 0: indicates operation successful
 */
int helper_set_log_func(logger func);

/**
 * \ingroup swi
 * 
 * lite-qmi logging function.
 * If external log function is used, logging goes to external log function.
 * Otherwise, logging goes to syslog.
 * 
 * @param[in] lvl: Logging level
 * @param[in] fmt: Format of the logging message
 * 
 * @return None
 */
void liteqmi_log(
    uint8_t lvl,
    const char* fmt, ...
);

/**
 * \ingroup swi
 * 
 * set log level
 */
int helper_set_log_lvl(uint8_t lvl);

/* Internal helper for pack/unpack function */
void fill_sdu_hdr(
    pack_qmi_t *pCtx,
    uint8_t *pReqBuf
);

/* Internal helper for packing context */
void fill_pack_ctx(
    pack_qmi_t *pCtx,
    uint8_t *pReqBuf,
    uint16_t *pLen,
    uint8_t svc,
    int timeout
);

/**
 * \ingroup swi
 * 
 * @return version string
 */
char* get_version();

/**
 * \ingroup swi
 * 
 * @return version string
 */
char* liteqmi_GetVersion();

/**
 * \ingroup swi
 * 
 * decode 7bit encoded string
 * @param[in] encoded_str 7 bit encoded ASCII
 * @param[in] encoded_len encoded length
 * @param[out] decoded_str decoded ASCII string
 */
void liteqmi_helper_decode7bitAsciiEncString(
    uint8_t *encoded_str,
    uint8_t encoded_len,
    uint8_t *decoded_str
);

/**
 * \ingroup swi
 * 
 * @param[in] szPath the full path of the provided bootloader or firmware file
 * @param[in] pQsn the QSN of a specific module user wants to check, it is a 
 *            4 bytes hex value without the prefix 0X. It can be retrieved by 
 *            AT command AT!ENTERCND="<password>", AT!SECBOOTCFG?, the first 
 *            parameter of the response of AT!SECBOOTCFG?.
 * @return values listed below
 *          - -1 bootloader is not debug enabled
 *          -  0 unbale to retrieve the bootloader debug info
 *          -  1 bootloader is debug enabled for the provided QSN
 *          -  4 either szPath or pQsn is invalid (NULL)
 *          - 18 invalid file
 */
int helper_isBootLoader_DebugEnabled(const char* szPath, const char* pQsn );

#define SWI_INIT_UNPACK_RESULT_VALUE {0, SWI_UINT256_INT_VALUE}

/**
 * \ingroup swi
 * 
 * unpack result struct
 * @param[out] Tlvresult
 * @param[out] ParamPresenceMask Parameter presence bit mask
 */
typedef struct
{
    uint16_t        Tlvresult;
    swi_uint256_t   ParamPresenceMask;
} unpack_result_t;

#ifdef __cplusplus
} /* extern "C" { */
#endif

#endif
