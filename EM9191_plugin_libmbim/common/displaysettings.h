/*************
 *
 * Filename:    displaymgmt.h
 *
 * Purpose:     Contains function for managing the capturing of logs for
 *              Connection manager application of Lite-QMI
 *
 * Copyright: © 2017 Sierra Wireless Inc., all rights reserved
 *
 **************/
#ifndef __DISPLAY_MGMT_H__
#define __DISPLAY_MGMT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/dir.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>

/****************************************************************
*                       #DEFINES
****************************************************************/
//#define QMI_DBG
#define TRUE    1
#define FALSE   0

/****************************************************************
*                       DATA STRUCTURES
****************************************************************/

/* Logs's fields enum */
enum eUserWindowFields{
    eMANUFACTURE_ID,
    eMODEL_ID,
    eFIRMWARE_REVISION,
    eBOOT_VERSION,
    ePRI_VERSION,
    ePRL_VERSION,
    ePRL_PREFERENCE,
    eIMSI,
    eESN_NUMBER,
    eIMEI_NUMBER,
    eMEID_NUMBER,
    eHARDWARE_REVISION,
    eDEVICE_STATE,
    eHOME_NETWORK,
    eROAMING_STATUS,
    eDATA_CAPABILITIES,
    eSESSION_STATE,
    eDATA_BEARER,
    eDORMANCY_STATUS,
    eLU_REJECT,
	eNETWORK_PREF,
    eRADIO_INTERFACE,
    eACTIVE_BAND_CLASS,
    eACTIVE_CHANNEL,
    eSIGNAL_STRENGTH,
    eECIO,
    eIO,
    eSINR,
    eRSRQ,
    ePDP_TYPE,
    eAUTHENTICATION,
    ePROFILE_NAME,
    eAPN_NAME,
    eUSER_NAME,
    eIP_ADDRESS,
    ePRIMARY_DNS,
    eSECONDARY_DNS,
    eCALL_STATUS,
    eTX_BYTES,
    eRX_BYTES,
    eCURRENT_TX_RATE,
    eCURRENT_RX_RATE,
    eMAX_TX_RATE,
    eMAX_RX_RATE,
    eMAX_DISPLAY_FIELDS,
};

/****************************************************************
*                       FUNCTIONS
****************************************************************/

extern void initialize_display( void );
extern void update_user_display(
    int  windowFieldIdx,
    char *pData );

#ifdef __cplusplus
} /* extern "C" { */
#endif

#endif /* __WINDOW_MGMT_H__ */

