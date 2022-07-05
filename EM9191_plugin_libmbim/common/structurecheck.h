#ifndef __LITEQMI_STRUCT_CHECK_H__
#define __LITEQMI_STRUCT_CHECK_H__


#include <stdint.h>
#include <stdio.h> 
#include <stddef.h>
#include <assert.h>

#include "msgid.h"
#include "qaGobiApiFms.h"
#include "qaGobiApiWds.h"
#include "qaGobiApiUim.h"
#include "qaGobiApiNas.h"
#include "qaGobiApiSwiDms.h"
#include "qaCbkDmsSwiEventReportInd.h"
#include "qaGobiApiCbk.h"

#include "../lite-qmi/fms.h"
#include "../lite-qmi/wds.h"
#include "../lite-qmi/uim.h"
#include "../lite-qmi/nas.h"
#include "../lite-qmi/swidms.h"
#include "../lite-qmi/dms.h"
#include "../lite-fw/lite-fw.h"
#include "../lite-qmi/loc.h"


//FIRMWARE_INFO_STRING_SIZE+NULL_TERMINATOR_CHAR_SIZE+FIRMWARE_INFO_STRING_SIZE+NULL_TERMINATOR_CHAR_SIZE
#if LITE_TOTAL_IMAGE_ID_STRING_SIZE != TOTAL_IMAGE_ID_STRING_SIZE
#error "LITE_TOTAL_IMAGE_ID_STRING_SIZE must be identical to TOTAL_IMAGE_ID_STRING_SIZE"
#endif
#if TOTAL_IMAGE_ID_STRING_SIZE < FIRMWARE_INFO_STRING_SIZE + NULL_TERMINATOR_CHAR_SIZE + 1 + FIRMWARE_INFO_STRING_SIZE + NULL_TERMINATOR_CHAR_SIZE
#error  "TOTAL_IMAGE_ID_STRING_SIZE too small"
#endif

#pragma once
#if ( ((__GNUC__==4)&&(__GNUC_MINOR__>=6)) || (__GNUC__>4))
#ifndef static_assert
#define static_assert _Static_assert
#endif

#define CHECK_STRUCT_SIZE(x,y) \
static_assert(sizeof(x) == sizeof(y), "Code relies on structure size being exactly");

#define CHECK_STRUCT_MEMBER_OFFSET(x,xx,y,yy) \
static_assert(offsetof(x,xx) == offsetof(y,yy), "Code relies on structure member offset being exactly");

#define CHECK_STRUCT_MEMBER_SIZE(x,xx,y,yy) \
static_assert(sizeof(((x *)NULL)->xx) == sizeof(((y *)NULL)->yy), "Code relies on member size being exactly");

#define CHECK_STRUCT_MEMBER(x,xx,y,yy) \
    CHECK_STRUCT_MEMBER_OFFSET(x,xx,y,yy) \
    CHECK_STRUCT_MEMBER_SIZE(x,xx,y,yy)


/**********
typedef struct
{
    uint32_t     m_nCarrierId;
    uint32_t     m_nFolderId;
    uint32_t     m_nStorage;
    uint8_t      m_FwImageId[FMS_GOBI_MBN_IMG_ID_STR_LEN];
    uint8_t      m_FwBuildId[FMS_GOBI_MBN_BUILD_ID_STR_LEN];
    uint8_t      m_PriImageId[FMS_GOBI_MBN_IMG_ID_STR_LEN];
    uint8_t      m_PriBuildId[FMS_GOBI_MBN_BUILD_ID_STR_LEN];
}CarrierImage_t;
struct SWI_STRUCT_CarrierImage
{
    ULONG     m_nCarrierId;
    ULONG     m_nFolderId;
    ULONG     m_nStorage;
    BYTE      m_FwImageId[IMG_ID_LEN];
    BYTE      m_FwBuildId[BUILD_ID_LEN];
    BYTE      m_PriImageId[IMG_ID_LEN];
    BYTE      m_PriBuildId[BUILD_ID_LEN];
};
***********/
/**
Check CarrierImage all struct members Lite vs SDK.
**/
#define CHECK_FMS_CARRIER_IMAGE_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,m_nCarrierId,y,m_nCarrierId) \
    CHECK_STRUCT_MEMBER(x,m_nFolderId,y,m_nFolderId) \
    CHECK_STRUCT_MEMBER(x,m_nStorage,y,m_nStorage) \
    CHECK_STRUCT_MEMBER(x,m_FwImageId,y,m_FwImageId) \
    CHECK_STRUCT_MEMBER(x,m_FwBuildId,y,m_FwBuildId) \
    CHECK_STRUCT_MEMBER(x,m_PriImageId,y,m_PriImageId) \
    CHECK_STRUCT_MEMBER(x,m_PriBuildId,y,m_PriBuildId)
CHECK_FMS_CARRIER_IMAGE_STRUCT(CarrierImage_t, struct SWI_STRUCT_CarrierImage)

/*****************
FMSImageList
typedef struct
{
    uint8_t                  listSize;
    FMSImageIDEntries imageIDEntries[FMS_IMAGE_ID_MAX_ENTRIES];
}FMSImageList;

struct ImageList
{
    BYTE                  listSize;
    struct ImageIDEntries imageIDEntries[2];
};
*****************/
/**
Check FMSImageList all struct members Lite vs SDK.
**/
#define CHECK_FMS_IMAGE_LIST_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,listSize,y,listSize) \
    CHECK_STRUCT_MEMBER(x,imageIDEntries,y,imageIDEntries)
CHECK_FMS_IMAGE_LIST_STRUCT(FMSImageList, struct ImageList)
/*****************
struct CreateProfileOut
{
    BYTE   *pProfileType;
    BYTE   *pProfileIndex;
    USHORT *pExtErrorCode;
};

typedef struct 
{
    uint8_t   ProfileType;
    uint8_t   ProfileIndex;
    uint16_t  ExtErrorCode;
}PackCreateProfileOut;
*****************/
#define CHECK_CREATE_PROFILE_OUT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
CHECK_CREATE_PROFILE_OUT(PackCreateProfileOut, struct CreateProfileOut)

/*****************
UIMSlotsStatus
typedef struct
{
    UIMSlotStatus uimSlotStatus[MAX_SLOTS_STATUS];
}UIMSlotsStatus;

typedef struct
{
    slot_t uimSlotStatus[MAX_SLOTS_STATUS];
}slots_t;
*****************/
/**
Check UIMSlotsStatus all struct members Lite vs SDK.
**/
#define CHECK_UIM_SLOT_STATUS_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,uimSlotStatus,y,uimSlotStatus)
CHECK_UIM_SLOT_STATUS_STRUCT(UIMSlotsStatus, slots_t)

/*****************
UIM File Info
typedef struct {
    WORD  fileID;
    BYTE  pathLen;
    WORD  path[MAX_PATH_LENGTH];
} fileInfo;

typedef struct {
    uint16_t  fileID;
    uint8_t  pathLen;
    uint16_t  path[UIM_UINT8_MAX_STRING_SZ];
} uim_fileInfo;
*****************/
/**
Check fileInfo all struct members Lite vs SDK.
**/
#define CHECK_UIM_FILE_INFO_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,fileID,y,fileID) \
    CHECK_STRUCT_MEMBER(x,pathLen,y,pathLen) \
    CHECK_STRUCT_MEMBER(x,path,y,path)
CHECK_UIM_FILE_INFO_STRUCT(fileInfo, uim_fileInfo)

/*********************
struct SlqsNasPCIInfo
{
BYTE PCICellInfoLen;
struct SlqsNasPCICellInfo PCICellInfo[NAS_MAX_SLQS_NAS_PCI_INFO_LENGTH];
WORD rsrp;
WORD rsrpRx0;
WORD rsrpRx1;
WORD rsrq;
WORD rsrqRx0;
WORD rsrqRx1;
}

typedef struct
{
    uint8_t PCICellInfoLen;
    nas_QmisNasSlqsNasPCICellInfo nasQmisNasSlqsNasPCICellInfo[NAS_MAX_SLQS_NAS_PCI_INFO_LENGTH];
    uint16_t rsrp;
    uint16_t rsrpRx0;
    uint16_t rsrpRx1;
    uint16_t rsrq;
    uint16_t rsrqRx0;
    uint16_t rsrqRx1;
}nas_QmisNasSlqsNasPCIInfo;

***********************/
/**
Check PCI Cell Info all struct members Lite vs SDK.
**/
#define CHECK_NAS_PCI_INFO_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,PCICellInfoLen,y,PCICellInfoLen) \
    CHECK_STRUCT_MEMBER(x,PCICellInfo,y,nasQmisNasSlqsNasPCICellInfo) \
    CHECK_STRUCT_MEMBER(x,rsrp,y,rsrp) \
    CHECK_STRUCT_MEMBER(x,rsrpRx0,y,rsrpRx0) \
    CHECK_STRUCT_MEMBER(x,rsrpRx1,y,rsrpRx1) \
    CHECK_STRUCT_MEMBER(x,rsrq,y,rsrq) \
    CHECK_STRUCT_MEMBER(x,rsrqRx0,y,rsrqRx0) \
    CHECK_STRUCT_MEMBER(x,rsrqRx1,y,rsrqRx1)
CHECK_NAS_PCI_INFO_STRUCT(struct SlqsNasPCIInfo,nas_QmisNasSlqsNasPCIInfo)

/*****************
SWIDMS Get Interface Config TLV

typedef struct
{
    ULONG CurrentCfgType;
    ULONG CfgValue;
} intfaceCfgTlv;

typedef struct
{
    uint32_t CurrentCfgType;
    uint32_t CfgValue;
} swidms_intfaceCfgTlv;

*****************/
/**
Check array call info  all struct members Lite vs SDK.
**/
#define CHECK_INTERFACE_CONFIG_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,CurrentCfgType,y,CurrentCfgType) \
    CHECK_STRUCT_MEMBER(x,CfgValue,y,CfgValue)
CHECK_INTERFACE_CONFIG_STRUCT(intfaceCfgTlv, swidms_intfaceCfgTlv)

/*****************
SWIDMS Get Supported Bitmasks TLV

typedef struct
{
    ULONG ValidBitmasks;
} supportedIntBitmaskTlv;


typedef struct
{
    uint32_t ValidBitmasks;
} swidms_supportedIntBitmaskTlv;

*****************/
/**
Check array call info  all struct members Lite vs SDK.
**/
#define CHECK_SUPPORTED_BITMASKS_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,ValidBitmasks,y,ValidBitmasks)
CHECK_SUPPORTED_BITMASKS_STRUCT(supportedIntBitmaskTlv, swidms_supportedIntBitmaskTlv)

/*****************
SWIDMS SwiEventReportCallBack_ind UIM Status Tlv

struct UIMStatusTlv
{
    BYTE intf;
    BYTE event;
}
struct TemperatureTlv
{
    BYTE TempState;
    WORD Temperature;
};
struct VoltageTlv
{
    BYTE VoltState;
    WORD Voltage;
}

typedef struct
{
    uint8_t intf;
    uint8_t event;
} dms_UimStatusTlv;

typedef struct
{
    uint8_t TempStat;
    uint16_t Temperature;
} dms_TemperatureTlv;

typedef struct
{
    uint8_t VoltStat;
    uint16_t Voltage;
} dms_VoltageTlv;

*****************/
/**
Check array call info  all struct members Lite vs SDK.
**/
#define CHECK_SWIDMS_EVENT_REPORT_STRUCT_UIMSSTATUS(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,intf,y,intf) \
    CHECK_STRUCT_MEMBER(x,event,y,event)

#define CHECK_SWIDMS_EVENT_REPORT_STRUCT_TEMPSTATUS(x,y) \
        CHECK_STRUCT_SIZE(x,y) \
        CHECK_STRUCT_MEMBER(x,TempStat,y,TempState) \
        CHECK_STRUCT_MEMBER(x,Temperature,y,Temperature)

#define CHECK_SWIDMS_EVENT_REPORT_STRUCT_VOLTATE(x,y) \
        CHECK_STRUCT_SIZE(x,y) \
        CHECK_STRUCT_MEMBER(x,VoltStat,y,VoltState) \
        CHECK_STRUCT_MEMBER(x,Voltage,y,Voltage)

CHECK_SWIDMS_EVENT_REPORT_STRUCT_UIMSSTATUS(dms_UimStatusTlv, struct UIMStatusTlv)
CHECK_SWIDMS_EVENT_REPORT_STRUCT_TEMPSTATUS(dms_TemperatureTlv, struct TemperatureTlv)
CHECK_SWIDMS_EVENT_REPORT_STRUCT_VOLTATE(dms_VoltageTlv, struct VoltageTlv)

/*****************
NAS eDRX Change Info

typedef struct{
    BYTE edrxEnabled;
}EdrxEnableType;

typedef struct{
    uint8_t edrxEnabled;
}nas_EdrxEnableType;

typedef struct{
    BYTE cycleLength;
}EdrxCycleLength;

typedef struct{
    uint8_t cycleLength;
}nas_EdrxCycleLength;

typedef struct{
    BYTE edrxPtw;
}EdrxPagingTimeWindow;

typedef struct{
    uint8_t edrxPtw;
}nas_EdrxPagingTimeWindow;

typedef struct{
    BYTE edrxRatType;
}EdrxRatType;

typedef struct{
    uint8_t edrxRatType;
}nas_EdrxRatType;

typedef struct{
    ULONG lteOpMode;
}EdrxCiotLteMode;

typedef struct{
    uint32_t lteOpMode;
}nas_EdrxCiotLteMode;

*****************/
/**
Check eDRX Enable Type all struct members Lite vs SDK.
**/
#define CHECK_NAS_EDRX_ENABLE_TYPE_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,edrxEnabled,y,edrxEnabled)

#define CHECK_NAS_EDRX_CYCLE_LENGTH_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,cycleLength,y,cycleLength)

#define CHECK_NAS_EDRX_PTW_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,edrxPtw,y,edrxPtw)

#define CHECK_NAS_EDRX_RAT_TYPE_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,edrxRatType,y,edrxRatType)

#define CHECK_NAS_EDRX_CIOT_LTE_MODE_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,lteOpMode,y,lteOpMode)

CHECK_NAS_EDRX_ENABLE_TYPE_STRUCT(EdrxEnableType, nas_EdrxEnableType)
CHECK_NAS_EDRX_CYCLE_LENGTH_STRUCT(EdrxCycleLength, nas_EdrxCycleLength)
CHECK_NAS_EDRX_PTW_STRUCT(EdrxPagingTimeWindow, nas_EdrxPagingTimeWindow)
CHECK_NAS_EDRX_RAT_TYPE_STRUCT(EdrxRatType, nas_EdrxRatType)
CHECK_NAS_EDRX_CIOT_LTE_MODE_STRUCT(EdrxCiotLteMode, nas_EdrxCiotLteMode)

/*****************
NAS Get Forbidden Networks TLV

typedef struct{
    WORD      forbiddenNwInstLen;
    WORD      MCC[SLQS_NAS_MCC_MNC_INST_LENGTH];
    WORD      MNC[SLQS_NAS_MCC_MNC_INST_LENGTH];
}ForbiddenNetworks3GPP;

typedef struct{
    uint16_t      forbiddenNwInstLen;
    uint16_t      MCC[NAS_MCC_MNC_INST_LENGTH];
    uint16_t      MNC[NAS_MCC_MNC_INST_LENGTH];
}nas_ForbiddenNetworks3GPP;

*****************/
/**
Check array call info  all struct members Lite vs SDK.
**/
#define CHECK_FORBIDDEN_NETWORKS_STRUCT(x,y) \
    CHECK_STRUCT_SIZE(x,y) \
    CHECK_STRUCT_MEMBER(x,forbiddenNwInstLen,y,forbiddenNwInstLen) \
    CHECK_STRUCT_MEMBER(x,MCC,y,MCC) \
    CHECK_STRUCT_MEMBER(x,MNC,y,MNC)
CHECK_FORBIDDEN_NETWORKS_STRUCT(ForbiddenNetworks3GPP, nas_ForbiddenNetworks3GPP)

/***
typedef struct {
     uint32_t    PDOP;
     uint32_t    HDOP;
     uint32_t    VDOP;
}loc_precisionDilution;
typedef struct precisionDilution_s{
     ULONG    PDOP;
     ULONG    HDOP;
     ULONG    VDOP;
}precisionDilution;
***/
#define CHECK_LOC_IND_BEST_AVAIL_POSITION_PRECISION_DILUTION_STRUCT(x,y) \
        CHECK_STRUCT_SIZE(x,y) \
        CHECK_STRUCT_MEMBER(x,PDOP,y,PDOP) \
        CHECK_STRUCT_MEMBER(x,HDOP,y,HDOP) \
        CHECK_STRUCT_MEMBER(x,VDOP,y,VDOP) 

CHECK_LOC_IND_BEST_AVAIL_POSITION_PRECISION_DILUTION_STRUCT(precisionDilution,loc_precisionDilution)
/***
typedef struct {
     uint16_t     gpsWeek;
     uint32_t    gpsTimeOfWeekMs;
}loc_gpsTime;
typedef struct gpsTime_s{
     WORD     gpsWeek;
     ULONG    gpsTimeOfWeekMs;
}gpsTime;
***/
#define CHECK_LOC_IND_BEST_AVAIL_POSITION_GPS_TIME_STRUCT(x,y) \
            CHECK_STRUCT_SIZE(x,y) \
            CHECK_STRUCT_MEMBER(x,gpsWeek,y,gpsWeek) \
            CHECK_STRUCT_MEMBER(x,gpsTimeOfWeekMs,y,gpsTimeOfWeekMs)
    
CHECK_LOC_IND_BEST_AVAIL_POSITION_GPS_TIME_STRUCT(gpsTime,loc_gpsTime)

/***
typedef struct {
     uint32_t     usageMask;
     uint32_t     aidingIndicatorMask;
}loc_sensorDataUsage;

typedef struct sensorDataUsage_s{
     ULONG     usageMask;
     ULONG     aidingIndicatorMask;
}sensorDataUsage;
***/
#define CHECK_LOC_IND_BEST_AVAIL_POSITION_SENSOR_DATA_USAGE_STRUCT(x,y) \
                CHECK_STRUCT_SIZE(x,y) \
                CHECK_STRUCT_MEMBER(x,usageMask,y,usageMask) \
                CHECK_STRUCT_MEMBER(x,aidingIndicatorMask,y,aidingIndicatorMask)
CHECK_LOC_IND_BEST_AVAIL_POSITION_SENSOR_DATA_USAGE_STRUCT(sensorDataUsage,loc_sensorDataUsage)

/***
typedef struct {
     uint8_t     gnssSvUsedList_len ;
     uint16_t     gnssSvUsedList[LOC_UINT8_MAX_STRING_SZ];
}loc_svUsedforFix;
typedef struct svUsedforFix_s{
     BYTE     gnssSvUsedList_len ;
     WORD     gnssSvUsedList[255];
}svUsedforFix;
***/
#define CHECK_LOC_IND_BEST_AVAIL_POSITION_SV_USED_FOR_FIX_STRUCT(x,y) \
                    CHECK_STRUCT_SIZE(x,y) \
                    CHECK_STRUCT_MEMBER(x,gnssSvUsedList_len,y,gnssSvUsedList_len) \
                    CHECK_STRUCT_MEMBER(x,gnssSvUsedList,y,gnssSvUsedList)
CHECK_LOC_IND_BEST_AVAIL_POSITION_SV_USED_FOR_FIX_STRUCT(svUsedforFix,loc_svUsedforFix)

#endif //#if ( ((__GNUC__==4)&&(__GNUC_MINOR__>=6)) || (__GNUC__>4))

#endif //__LITEQMI_STRUCT_CHECK_H__
