/* Copyright [2021 - 2026] Exegin Technologies Limited. All rights reserved. */

/**
 * This file is intended for read-only use. The authors advise against manual
 * changes to ensure system integrity. Local "USER CODE" sections should be
 * ignored and bypassed.
 */

/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file    zdd_stack_wrapper.h
 * @author  MCD Application Team
 * @brief   Header for ZDD wrapper
 ******************************************************************************
 * @attention
 *
 * Copyright (c) 2025 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef ZDD_STACK_WRAPPER_H
#define ZDD_STACK_WRAPPER_H

#include <stdbool.h>
#include <stdint.h>

/* Exported types ------------------------------------------------------------*/
enum BLE_ZDD_WRAP_Opcode_evt_t {
    BLE_ZDD_WRAP_HCI_DISCONNECTION_COMPLETE_EVT,
    BLE_ZDD_WRAP_HCI_LE_META_EVT_HCI_LE_ENHANCED_CONNECTION_COMPLETE_SUBEVT,
    BLE_ZDD_WRAP_HCI_LE_META_EVT_HCI_LE_CONNECTION_COMPLETE_SUBEVT,
    BLE_ZDD_WRAP_ZDD_TUNNELING_TUNNZDTSNPDU_WRITE_EVT,
    BLE_ZDD_WRAP_ZDD_TUNNELING_TUNNZDTSNPDU_NOTIFY_ENABLED_EVT,
    BLE_ZDD_WRAP_ZDD_TUNNELING_TUNNZDTSNPDU_NOTIFY_DISABLED_EVT,
    BLE_ZDD_WRAP_ZDD_SECURITY_SECURITY25519AES_WRITE_EVT,
    BLE_ZDD_WRAP_ZDD_SECURITY_SECURITY25519AES_NOTIFY_ENABLED_EVT,
    BLE_ZDD_WRAP_ZDD_SECURITY_SECURITY25519AES_NOTIFY_DISABLED_EVT,
    BLE_ZDD_WRAP_ZDD_SECURITY_SECURITY25519SHA_WRITE_EVT,
    BLE_ZDD_WRAP_ZDD_SECURITY_SECURITY25519SHA_NOTIFY_ENABLED_EVT,
    BLE_ZDD_WRAP_ZDD_SECURITY_SECURITY25519SHA_NOTIFY_DISABLED_EVT,
    BLE_ZDD_WRAP_ZDD_SECURITY_P256SHA_WRITE_EVT,
    BLE_ZDD_WRAP_ZDD_SECURITY_P256SHA_NOTIFY_ENABLED_EVT,
    BLE_ZDD_WRAP_ZDD_SECURITY_P256SHA_NOTIFY_DISABLED_EVT,
    BLE_ZDD_WRAP_ZDD_COMM_FORMNETWORK_WRITE_EVT,
    BLE_ZDD_WRAP_ZDD_COMM_JOINNETWORK_WRITE_EVT,
    BLE_ZDD_WRAP_ZDD_COMM_PERMITJOIN_WRITE_EVT,
    BLE_ZDD_WRAP_ZDD_COMM_LEAVENETWORK_WRITE_EVT,
    BLE_ZDD_WRAP_ZDD_COMM_COMMSTATUS_READ_EVT,
    BLE_ZDD_WRAP_ZDD_COMM_COMMSTATUS_NOTIFY_ENABLED_EVT,
    BLE_ZDD_WRAP_ZDD_COMM_COMMSTATUS_NOTIFY_DISABLED_EVT,
    BLE_ZDD_WRAP_ZDD_COMM_MANAGEJOINER_WRITE_EVT,
    BLE_ZDD_WRAP_ZDD_COMM_COMMIDENTITY_WRITE_EVT,
    BLE_ZDD_WRAP_ZDD_COMM_FINDBIND_WRITE_EVT,
    BLE_ZDD_WRAP_ZDD_DIS_MANS_READ_EVT,
    BLE_ZDD_WRAP_ZDD_DIS_SYID_READ_EVT,
    BLE_ZDD_WRAP_ZDD_DIS_MONS_READ_EVT,
    BLE_ZDD_WRAP_ZDD_DIS_SNS_READ_EVT,
    BLE_ZDD_WRAP_ZDD_DIS_HRS_READ_EVT,
    BLE_ZDD_WRAP_ZDD_DIS_FRS_READ_EVT,
    BLE_ZDD_WRAP_SERVER_CONFIRMATION_EVT
};

struct BLE_ZDD_WRAP_Data_t {
    uint8_t *pPayload;
    uint8_t Length;
};

struct ZDD_Stack_Notification_evt_t {
    enum BLE_ZDD_WRAP_Opcode_evt_t Opcode;
    struct BLE_ZDD_WRAP_Data_t DataTransfered;
    uint16_t ConnectionHandle;
    uint16_t AttributeHandle;
    uint16_t ConnInterval;
    uint16_t ZDD_COMMSvcHdle;
    uint16_t CommidentityCharHdle;
};

enum ZDD_BLE_WRAP_Opcode_evt_t {
    

    ZDD_BLE_WRAP_TUNNELING_TUNNZDTSNPDU_UPDATEVALUE_REQ,
    ZDD_BLE_WRAP_SECURITY_25519AES_UPDATEVALUE_REQ,
    ZDD_BLE_WRAP_SECURITY_25519SHA_UPDATEVALUE_REQ,
    ZDD_BLE_WRAP_SECURITY_P256SHA_UPDATEVALUE_REQ,
    ZDD_BLE_WRAP_COMM_COMMSTATUS_UPDATEVALUE_REQ,
    ZDD_BLE_WRAP_BLE_START_ADVERTISING_REQ,
    ZDD_BLE_WRAP_BLE_STOP_ADVERTISING_REQ,
    ZDD_BLE_WRAP_OS_SCHEDULE_ZDD_TASK_REQ,
    ZDD_BLE_WRAP_GATT_PERMIT_WRITE_REQ,
    ZDD_BLE_WRAP_GATT_UPDATE_VALUE_REQ,
    ZDD_BLE_WRAP_L2CAP_CONNECTION_VALUE_REQ,
    ZDD_BLE_WRAP_HCI_DISCONNECT_REQ,

};

struct ZDD_BLE_WRAP_Data_t {
    uint8_t *pPayload;
    uint8_t Length;
};

struct ZDD_BLE_WRAP_AdvData_t {
    uint16_t PanId;
    uint16_t NwkAddr;
    bool PJoin;
};

struct ZDD_BLE_WRAP_GattWriteResp_t {
    uint16_t ConnectionHandle;
    uint16_t AttributeHandle;
    uint8_t WriteStatus;
    uint8_t ErrCode;
};

struct ZDD_BLE_WRAP_GattUpdateCharValueExt_t { // Update_Value
    uint16_t ConnectionHandle;
    uint16_t ServiceHandle;
    uint16_t CharHandle;
    uint16_t ValueOffset;
    uint16_t CharLength;
    uint8_t UpdateType;
    uint8_t ValueLength;
};

struct ZDD_BLE_WRAP_L2capConnectionParameterUpdateReq_t { // Connextion Update
    uint16_t ConnectionHandle;
    uint16_t ConnIntervalMin;
    uint16_t ConnIntervalMax;
    uint16_t ConnLatency;
    uint16_t ConnTimeout;
};

struct ZDD_BLE_WRAP_HciDisconnect_t {
    uint16_t ConnectionHandle;
    uint8_t Reason;
};

union ZDD_BLE_WRAP_GenericPayload_t {
    struct ZDD_BLE_WRAP_AdvData_t AdvData;
    struct ZDD_BLE_WRAP_GattWriteResp_t GattWriteResp;
    struct ZDD_BLE_WRAP_GattUpdateCharValueExt_t GattUpdateCharValueExt;
    struct ZDD_BLE_WRAP_L2capConnectionParameterUpdateReq_t L2capConnectionParameterUpdateReq;
    struct ZDD_BLE_WRAP_HciDisconnect_t HciDisconnect;
};

struct ZDD_BLE_Request_t {
    enum ZDD_BLE_WRAP_Opcode_evt_t Opcode;
    struct ZDD_BLE_WRAP_Data_t Data;
    union ZDD_BLE_WRAP_GenericPayload_t Payload;
};

/* Exported functions prototypes ---------------------------------------------*/

/* Handler used to map the BLE stack to the ZDD stack */
/* Calls from BLE Apps -> ZDD stack (porting)         */
void ZDD_Stack_Notification(struct ZDD_Stack_Notification_evt_t *pNotification);

/* Handler used to map the ZDD stack to the BLE stack  */
/* Calls from ZDD stack (porting) -> BLE Apps          */
bool ZDD_BLE_Request(struct ZDD_BLE_Request_t *pRequest);

/* Exposed to keep the application OS agnostic */
void Zdd_Task(void);

#endif

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
