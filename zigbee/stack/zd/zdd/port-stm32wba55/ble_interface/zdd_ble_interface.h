/* Copyright [2021 - 2026] Exegin Technologies Limited. All rights reserved. */

/**
 * This file is intended for read-only use. The authors advise against manual
 * changes to ensure system integrity. Local "USER CODE" sections should be
 * ignored and bypassed.
 */

/**
 ******************************************************************************
 * @file    zdd_ble_interface.h
 * @author  MCD Application Team
 * @brief   Defines and structure used for ZigbeeDirect to be shared between
 *          the application and the ZigbeeDirect stack library.
 *
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
#ifndef ZDD_BLE_INTERFACE_H
#define ZDD_BLE_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Device information service */
enum DIS_CharOpcode_t {
    DIS_MANS,
    DIS_CHAROPCODE_LAST
};

struct DIS_Data_t {
    uint8_t *p_Payload;
    uint8_t Length;
};

/* tunneling service */
enum TUNNELING_CharOpcode_t {
    TUNNELING_TUNNZDTSNPDU,
    TUNNELING_CHAROPCODE_LAST
};

struct TUNNELING_Data_t {
    uint8_t *p_Payload;
    uint8_t Length;
};

/* security service */
enum ZDD_SECURITY_CharOpcode_t {
    ZDD_SECURITY_SECURITY25519AES,
    ZDD_SECURITY_SECURITY25519SHA,
    ZDD_SECURITY_P256SHA,
    ZDD_SECURITY_CHAROPCODE_LAST
};

struct ZDD_SECURITY_Data_t {
    uint8_t *p_Payload;
    uint8_t Length;
};

/* Commissioning service */
enum ZDD_COMM_CharOpcode_t {
    ZDD_COMM_FORMNETWORK,
    ZDD_COMM_JOINNETWORK,
    ZDD_COMM_PERMITJOIN,
    ZDD_COMM_LEAVENETWORK,
    ZDD_COMM_COMMSTATUS,
    ZDD_COMM_MANAGEJOINER,
    ZDD_COMM_COMMIDENTITY,
    ZDD_COMM_FINDBIND,
    ZDD_COMM_CHAROPCODE_LAST
};

struct ZDD_COMM_Data_t {
    uint8_t *p_Payload;
    uint8_t Length;

    /* USER CODE BEGIN Service2_Data_t */

    /* USER CODE END Service2_Data_t */
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZDD_BLE_INTERFACE_H */
