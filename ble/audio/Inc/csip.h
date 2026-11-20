/**
  ******************************************************************************
  * @file    csip.h
  * @author  MCD Application Team
  * @brief   This file contains definitions used for Coordinated Set
  *          Identification Profile
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2022 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Define to prevent recursive inclusion -------------------------------------*/

#ifndef __CSIP_H
#define __CSIP_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/

#include "csip_types.h"

/* Defines -------------------------------------------------------------------*/

/* Types ---------------------------------------------------------------------*/

/* Exported functions --------------------------------------------------------*/

/**
  * @brief  Register Coordinated Set Identification Service Instance
  * @param  Instance_ID: Coordinated Set Identification Service Instance Identifier
  * @param  pServiceInfo: CSIP settings
  * @retval status of the operation
  */
tBleStatus CSIP_SET_MEMBER_RegisterServiceInstance(uint8_t Instance_ID, CSIS_ServiceInit_t *pServiceInfo);

/**
  * @brief Remove every CSIP services record for CSIP Set Member and/or CSIP Set Coordinator role
  *        related to a peer address stored in NVM
  * @param Peer_Address_Type: Peer Address type
  * @param Peer_Address: Peer Address
  * @retval status of the operation
  */
tBleStatus CSIP_RemoveServiceRecord(uint8_t Peer_Address_Type, const uint8_t Peer_Address[6]);

/**
  * @brief  Read the Coordinated Set Name characteristic on a linked Set Member
  *
  *         The linkup for the target ConnHandle must already be complete and the Coordinated
  *         Set Name characteristic must have been discovered during linkup.
  *         The result is delivered asynchronously via CSIP_COO_SET_NAME_NOTIFIED_EVT.
  *
  * @param  ConnHandle: connection handle of the linked Set Member
  * @retval BLE_STATUS_SUCCESS if the ATT read was submitted
  * @retval HCI_UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE_ERR_CODE if the characteristic was
  *         not discovered (peer does not expose Coordinated Set Name)
  * @retval BLE_STATUS_INVALID_OPERATION if no linked instance is found or linkup is not complete
  */
tBleStatus CSIP_COO_Read_Coordinated_Set_Name(uint16_t ConnHandle);

#ifdef __cplusplus
}
#endif

#endif /* __CSIP_H */
