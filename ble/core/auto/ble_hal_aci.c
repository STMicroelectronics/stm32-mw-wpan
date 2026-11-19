/*****************************************************************************
 * @file    ble_hal_aci.c
 * @brief   STM32WB BLE API (hal_aci)
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

#include "auto/ble_hal_aci.h"

tBleStatus aci_hal_write_config_data( uint8_t Offset,
                                      uint8_t Length,
                                      const uint8_t* Value )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_write_config_data_cp0 *cp0 = (aci_hal_write_config_data_cp0*)(cmd_buffer + in_offset);
  cp0->Offset = Offset;
  in_offset += 1;
  cp0->Length = Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Value, (const void*)Value, Length );
  in_offset += Length;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x00c;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_hal_read_config_data( uint8_t Offset,
                                     uint8_t* Data_Length,
                                     uint8_t* Data )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_read_config_data_cp0 *cp0 = (aci_hal_read_config_data_cp0*)(cmd_buffer + in_offset);
  cp0->Offset = Offset;
  in_offset += 1;
  aci_hal_read_config_data_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x00d;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Data_Length = resp.Data_Length;
  Osal_MemCpy( (void*)Data, (const void*)resp.Data, *Data_Length );
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_hal_set_tx_power_level( uint8_t En_High_Power,
                                       uint8_t PA_Level )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_set_tx_power_level_cp0 *cp0 = (aci_hal_set_tx_power_level_cp0*)(cmd_buffer + in_offset);
  cp0->En_High_Power = En_High_Power;
  in_offset += 1;
  cp0->PA_Level = PA_Level;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x00f;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_hal_le_tx_test_packet_number( uint32_t* Number_Of_Packets )
{
  struct hci_request rq;
  aci_hal_le_tx_test_packet_number_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x014;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Number_Of_Packets = resp.Number_Of_Packets;
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_hal_tone_start( uint8_t RF_Channel,
                               uint8_t Freq_offset )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_tone_start_cp0 *cp0 = (aci_hal_tone_start_cp0*)(cmd_buffer + in_offset);
  cp0->RF_Channel = RF_Channel;
  in_offset += 1;
  cp0->Freq_offset = Freq_offset;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x015;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_hal_tone_stop( void )
{
  struct hci_request rq;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x016;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_hal_get_link_status( uint8_t* Link_Status,
                                    uint16_t* Link_Connection_Handle )
{
  struct hci_request rq;
  aci_hal_get_link_status_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x017;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  Osal_MemCpy( (void*)Link_Status, (const void*)resp.Link_Status, 8 );
  Osal_MemCpy( (void*)Link_Connection_Handle, (const void*)resp.Link_Connection_Handle, 16 );
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_hal_set_radio_activity_mask( uint16_t Radio_Activity_Mask )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_set_radio_activity_mask_cp0 *cp0 = (aci_hal_set_radio_activity_mask_cp0*)(cmd_buffer + in_offset);
  cp0->Radio_Activity_Mask = Radio_Activity_Mask;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x018;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_hal_get_anchor_period( uint32_t* Anchor_Period,
                                      uint32_t* Max_Free_Slot )
{
  struct hci_request rq;
  aci_hal_get_anchor_period_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x019;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Anchor_Period = resp.Anchor_Period;
  *Max_Free_Slot = resp.Max_Free_Slot;
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_hal_set_event_mask( uint32_t Event_Mask )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_set_event_mask_cp0 *cp0 = (aci_hal_set_event_mask_cp0*)(cmd_buffer + in_offset);
  cp0->Event_Mask = Event_Mask;
  in_offset += 4;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x01a;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_hal_set_peripheral_latency( uint8_t Enable )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_set_peripheral_latency_cp0 *cp0 = (aci_hal_set_peripheral_latency_cp0*)(cmd_buffer + in_offset);
  cp0->Enable = Enable;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x020;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_hal_read_rssi( uint8_t* RSSI )
{
  struct hci_request rq;
  aci_hal_read_rssi_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x022;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *RSSI = resp.RSSI;
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_hal_ead_encrypt_decrypt( uint8_t Mode,
                                        const uint8_t* Key,
                                        const uint8_t* IV,
                                        uint16_t In_Data_Length,
                                        const uint8_t* In_Data,
                                        uint16_t* Out_Data_Length,
                                        uint8_t* Out_Data )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_ead_encrypt_decrypt_cp0 *cp0 = (aci_hal_ead_encrypt_decrypt_cp0*)(cmd_buffer + in_offset);
  cp0->Mode = Mode;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Key, (const void*)Key, 16 );
  in_offset += 16;
  Osal_MemCpy( (void*)&cp0->IV, (const void*)IV, 8 );
  in_offset += 8;
  cp0->In_Data_Length = In_Data_Length;
  in_offset += 2;
  Osal_MemCpy( (void*)&cp0->In_Data, (const void*)In_Data, In_Data_Length );
  in_offset += In_Data_Length;
  aci_hal_ead_encrypt_decrypt_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x02f;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Out_Data_Length = resp.Out_Data_Length;
  Osal_MemCpy( (void*)Out_Data, (const void*)resp.Out_Data, *Out_Data_Length );
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_hal_read_radio_reg( uint8_t Register_Address,
                                   uint8_t* reg_val )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_read_radio_reg_cp0 *cp0 = (aci_hal_read_radio_reg_cp0*)(cmd_buffer + in_offset);
  cp0->Register_Address = Register_Address;
  in_offset += 1;
  aci_hal_read_radio_reg_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x030;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *reg_val = resp.reg_val;
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_hal_write_radio_reg( uint8_t Register_Address,
                                    uint8_t Register_Value )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_write_radio_reg_cp0 *cp0 = (aci_hal_write_radio_reg_cp0*)(cmd_buffer + in_offset);
  cp0->Register_Address = Register_Address;
  in_offset += 1;
  cp0->Register_Value = Register_Value;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x031;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_hal_read_raw_rssi( uint8_t* Value )
{
  struct hci_request rq;
  aci_hal_read_raw_rssi_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x032;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  Osal_MemCpy( (void*)Value, (const void*)resp.Value, 3 );
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_hal_rx_start( uint8_t RF_Channel )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_rx_start_cp0 *cp0 = (aci_hal_rx_start_cp0*)(cmd_buffer + in_offset);
  cp0->RF_Channel = RF_Channel;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x033;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_hal_rx_stop( void )
{
  struct hci_request rq;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x034;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_hal_additional_beacon_start( uint16_t Adv_Interval_Min,
                                            uint16_t Adv_Interval_Max,
                                            uint8_t Adv_Channel_Map,
                                            uint8_t Own_Address_Type,
                                            const uint8_t* Own_Address,
                                            uint8_t PA_Level )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_additional_beacon_start_cp0 *cp0 = (aci_hal_additional_beacon_start_cp0*)(cmd_buffer + in_offset);
  cp0->Adv_Interval_Min = Adv_Interval_Min;
  in_offset += 2;
  cp0->Adv_Interval_Max = Adv_Interval_Max;
  in_offset += 2;
  cp0->Adv_Channel_Map = Adv_Channel_Map;
  in_offset += 1;
  cp0->Own_Address_Type = Own_Address_Type;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Own_Address, (const void*)Own_Address, 6 );
  in_offset += 6;
  cp0->PA_Level = PA_Level;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x0b0;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_hal_additional_beacon_stop( void )
{
  struct hci_request rq;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x0b1;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_hal_additional_beacon_set_data( uint8_t Adv_Data_Length,
                                               const uint8_t* Adv_Data )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_hal_additional_beacon_set_data_cp0 *cp0 = (aci_hal_additional_beacon_set_data_cp0*)(cmd_buffer + in_offset);
  cp0->Adv_Data_Length = Adv_Data_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Adv_Data, (const void*)Adv_Data, Adv_Data_Length );
  in_offset += Adv_Data_Length;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x0b2;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

