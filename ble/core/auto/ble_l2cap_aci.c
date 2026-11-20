/*****************************************************************************
 * @file    ble_l2cap_aci.c
 * @brief   STM32WB BLE API (l2cap_aci)
 *          Auto-generated file: do not edit!
 *****************************************************************************
 * @attention
 *
 * Copyright (c) 2018-2026 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 *****************************************************************************
 */

#include "auto/ble_l2cap_aci.h"

tBleStatus aci_l2cap_connection_parameter_update_req( uint16_t Connection_Handle,
                                                      uint16_t Conn_Interval_Min,
                                                      uint16_t Conn_Interval_Max,
                                                      uint16_t Latency,
                                                      uint16_t Timeout_Multiplier )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_l2cap_connection_parameter_update_req_cp0 *cp0 = (aci_l2cap_connection_parameter_update_req_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Conn_Interval_Min = Conn_Interval_Min;
  in_offset += 2;
  cp0->Conn_Interval_Max = Conn_Interval_Max;
  in_offset += 2;
  cp0->Latency = Latency;
  in_offset += 2;
  cp0->Timeout_Multiplier = Timeout_Multiplier;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x181;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_l2cap_connection_parameter_update_resp( uint16_t Connection_Handle,
                                                       uint16_t Conn_Interval_Min,
                                                       uint16_t Conn_Interval_Max,
                                                       uint16_t Latency,
                                                       uint16_t Timeout_Multiplier,
                                                       uint16_t Minimum_CE_Length,
                                                       uint16_t Maximum_CE_Length,
                                                       uint8_t Identifier,
                                                       uint8_t Accept )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_l2cap_connection_parameter_update_resp_cp0 *cp0 = (aci_l2cap_connection_parameter_update_resp_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Conn_Interval_Min = Conn_Interval_Min;
  in_offset += 2;
  cp0->Conn_Interval_Max = Conn_Interval_Max;
  in_offset += 2;
  cp0->Latency = Latency;
  in_offset += 2;
  cp0->Timeout_Multiplier = Timeout_Multiplier;
  in_offset += 2;
  cp0->Minimum_CE_Length = Minimum_CE_Length;
  in_offset += 2;
  cp0->Maximum_CE_Length = Maximum_CE_Length;
  in_offset += 2;
  cp0->Identifier = Identifier;
  in_offset += 1;
  cp0->Accept = Accept;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x182;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_l2cap_coc_connect( uint16_t Connection_Handle,
                                  uint16_t SPSM,
                                  uint16_t MTU,
                                  uint16_t MPS,
                                  uint16_t Initial_Credits,
                                  uint8_t Channel_Number )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_l2cap_coc_connect_cp0 *cp0 = (aci_l2cap_coc_connect_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->SPSM = SPSM;
  in_offset += 2;
  cp0->MTU = MTU;
  in_offset += 2;
  cp0->MPS = MPS;
  in_offset += 2;
  cp0->Initial_Credits = Initial_Credits;
  in_offset += 2;
  cp0->Channel_Number = Channel_Number;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x188;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_l2cap_coc_connect_confirm( uint16_t Connection_Handle,
                                          uint16_t MTU,
                                          uint16_t MPS,
                                          uint16_t Initial_Credits,
                                          uint16_t Result,
                                          uint8_t Max_Channel_Number,
                                          uint8_t* Channel_Number,
                                          uint8_t* Channel_Index_List )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_l2cap_coc_connect_confirm_cp0 *cp0 = (aci_l2cap_coc_connect_confirm_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->MTU = MTU;
  in_offset += 2;
  cp0->MPS = MPS;
  in_offset += 2;
  cp0->Initial_Credits = Initial_Credits;
  in_offset += 2;
  cp0->Result = Result;
  in_offset += 2;
  cp0->Max_Channel_Number = Max_Channel_Number;
  in_offset += 1;
  aci_l2cap_coc_connect_confirm_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x189;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Channel_Number = resp.Channel_Number;
  Osal_MemCpy( (void*)Channel_Index_List, (const void*)resp.Channel_Index_List, *Channel_Number );
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_l2cap_coc_reconf( uint16_t Connection_Handle,
                                 uint16_t MTU,
                                 uint16_t MPS,
                                 uint8_t Channel_Number,
                                 const uint8_t* Channel_Index_List )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_l2cap_coc_reconf_cp0 *cp0 = (aci_l2cap_coc_reconf_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->MTU = MTU;
  in_offset += 2;
  cp0->MPS = MPS;
  in_offset += 2;
  cp0->Channel_Number = Channel_Number;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Channel_Index_List, (const void*)Channel_Index_List, Channel_Number );
  in_offset += Channel_Number;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x18a;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_l2cap_coc_reconf_confirm( uint16_t Connection_Handle,
                                         uint16_t Result )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_l2cap_coc_reconf_confirm_cp0 *cp0 = (aci_l2cap_coc_reconf_confirm_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Result = Result;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x18b;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_l2cap_coc_disconnect( uint8_t Channel_Index )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_l2cap_coc_disconnect_cp0 *cp0 = (aci_l2cap_coc_disconnect_cp0*)(cmd_buffer + in_offset);
  cp0->Channel_Index = Channel_Index;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x18c;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_l2cap_coc_flow_control( uint8_t Channel_Index,
                                       uint16_t Credits )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_l2cap_coc_flow_control_cp0 *cp0 = (aci_l2cap_coc_flow_control_cp0*)(cmd_buffer + in_offset);
  cp0->Channel_Index = Channel_Index;
  in_offset += 1;
  cp0->Credits = Credits;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x18d;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_l2cap_coc_tx_data( uint8_t Channel_Index,
                                  uint16_t Length,
                                  const uint8_t* Data )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_l2cap_coc_tx_data_cp0 *cp0 = (aci_l2cap_coc_tx_data_cp0*)(cmd_buffer + in_offset);
  cp0->Channel_Index = Channel_Index;
  in_offset += 1;
  cp0->Length = Length;
  in_offset += 2;
  Osal_MemCpy( (void*)&cp0->Data, (const void*)Data, Length );
  in_offset += Length;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x18e;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

