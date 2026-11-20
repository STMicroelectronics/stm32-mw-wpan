/*****************************************************************************
 * @file    ble_hci_le.c
 * @brief   STM32WB BLE API (hci_le)
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

#include "auto/ble_hci_le.h"

tBleStatus hci_disconnect( uint16_t Connection_Handle,
                           uint8_t Reason )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_disconnect_cp0 *cp0 = (hci_disconnect_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Reason = Reason;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x01;
  rq.ocf = 0x006;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_read_remote_version_information( uint16_t Connection_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_read_remote_version_information_cp0 *cp0 = (hci_read_remote_version_information_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x01;
  rq.ocf = 0x01d;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_set_event_mask( const uint8_t* Event_Mask )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_set_event_mask_cp0 *cp0 = (hci_set_event_mask_cp0*)(cmd_buffer + in_offset);
  Osal_MemCpy( (void*)&cp0->Event_Mask, (const void*)Event_Mask, 8 );
  in_offset += 8;
  tBleStatus status = 0;
  rq.ogf = 0x03;
  rq.ocf = 0x001;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_reset( void )
{
  struct hci_request rq;
  tBleStatus status = 0;
  rq.ogf = 0x03;
  rq.ocf = 0x003;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_read_transmit_power_level( uint16_t Connection_Handle,
                                          uint8_t Type,
                                          uint8_t* TX_Power_Level )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_read_transmit_power_level_cp0 *cp0 = (hci_read_transmit_power_level_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Type = Type;
  in_offset += 1;
  hci_read_transmit_power_level_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x03;
  rq.ocf = 0x02d;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *TX_Power_Level = resp.TX_Power_Level;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_set_controller_to_host_flow_control( uint8_t Flow_Control_Enable )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_set_controller_to_host_flow_control_cp0 *cp0 = (hci_set_controller_to_host_flow_control_cp0*)(cmd_buffer + in_offset);
  cp0->Flow_Control_Enable = Flow_Control_Enable;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x03;
  rq.ocf = 0x031;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_host_buffer_size( uint16_t Host_ACL_Data_Packet_Length,
                                 uint8_t Host_Synchronous_Data_Packet_Length,
                                 uint16_t Host_Total_Num_ACL_Data_Packets,
                                 uint16_t Host_Total_Num_Synchronous_Data_Packets )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_host_buffer_size_cp0 *cp0 = (hci_host_buffer_size_cp0*)(cmd_buffer + in_offset);
  cp0->Host_ACL_Data_Packet_Length = Host_ACL_Data_Packet_Length;
  in_offset += 2;
  cp0->Host_Synchronous_Data_Packet_Length = Host_Synchronous_Data_Packet_Length;
  in_offset += 1;
  cp0->Host_Total_Num_ACL_Data_Packets = Host_Total_Num_ACL_Data_Packets;
  in_offset += 2;
  cp0->Host_Total_Num_Synchronous_Data_Packets = Host_Total_Num_Synchronous_Data_Packets;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x03;
  rq.ocf = 0x033;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_host_number_of_completed_packets( uint8_t Num_Handles,
                                                 const Host_Nb_Of_Completed_Pkt_Pair_t* Host_Nb_Of_Completed_Pkt_Pair )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_host_number_of_completed_packets_cp0 *cp0 = (hci_host_number_of_completed_packets_cp0*)(cmd_buffer + in_offset);
  cp0->Num_Handles = Num_Handles;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Host_Nb_Of_Completed_Pkt_Pair, (const void*)Host_Nb_Of_Completed_Pkt_Pair, Num_Handles * (sizeof(Host_Nb_Of_Completed_Pkt_Pair_t)) );
  in_offset += Num_Handles * (sizeof(Host_Nb_Of_Completed_Pkt_Pair_t));
  tBleStatus status = 0;
  rq.ogf = 0x03;
  rq.ocf = 0x035;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_read_local_version_information( uint8_t* HCI_Version,
                                               uint16_t* HCI_Subversion,
                                               uint8_t* LMP_Version,
                                               uint16_t* Company_Identifier,
                                               uint16_t* LMP_Subversion )
{
  struct hci_request rq;
  hci_read_local_version_information_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x04;
  rq.ocf = 0x001;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *HCI_Version = resp.HCI_Version;
  *HCI_Subversion = resp.HCI_Subversion;
  *LMP_Version = resp.LMP_Version;
  *Company_Identifier = resp.Company_Identifier;
  *LMP_Subversion = resp.LMP_Subversion;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_read_local_supported_commands( uint8_t* Supported_Commands )
{
  struct hci_request rq;
  hci_read_local_supported_commands_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x04;
  rq.ocf = 0x002;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  Osal_MemCpy( (void*)Supported_Commands, (const void*)resp.Supported_Commands, 64 );
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_read_local_supported_features( uint8_t* LMP_Features )
{
  struct hci_request rq;
  hci_read_local_supported_features_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x04;
  rq.ocf = 0x003;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  Osal_MemCpy( (void*)LMP_Features, (const void*)resp.LMP_Features, 8 );
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_read_bd_addr( uint8_t* BD_ADDR )
{
  struct hci_request rq;
  hci_read_bd_addr_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x04;
  rq.ocf = 0x009;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  Osal_MemCpy( (void*)BD_ADDR, (const void*)resp.BD_ADDR, 6 );
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_read_rssi( uint16_t Handle,
                          uint8_t* RSSI )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_read_rssi_cp0 *cp0 = (hci_read_rssi_cp0*)(cmd_buffer + in_offset);
  cp0->Handle = Handle;
  in_offset += 2;
  hci_read_rssi_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x05;
  rq.ocf = 0x005;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *RSSI = resp.RSSI;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_set_event_mask( const uint8_t* LE_Event_Mask )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_event_mask_cp0 *cp0 = (hci_le_set_event_mask_cp0*)(cmd_buffer + in_offset);
  Osal_MemCpy( (void*)&cp0->LE_Event_Mask, (const void*)LE_Event_Mask, 8 );
  in_offset += 8;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x001;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_read_buffer_size( uint16_t* LE_ACL_Data_Packet_Length,
                                    uint8_t* Total_Num_LE_ACL_Data_Packets )
{
  struct hci_request rq;
  hci_le_read_buffer_size_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x002;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *LE_ACL_Data_Packet_Length = resp.LE_ACL_Data_Packet_Length;
  *Total_Num_LE_ACL_Data_Packets = resp.Total_Num_LE_ACL_Data_Packets;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_read_local_supported_features_page_0( uint8_t* LE_Features )
{
  struct hci_request rq;
  hci_le_read_local_supported_features_page_0_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x003;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  Osal_MemCpy( (void*)LE_Features, (const void*)resp.LE_Features, 8 );
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_set_random_address( const uint8_t* Random_Address )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_random_address_cp0 *cp0 = (hci_le_set_random_address_cp0*)(cmd_buffer + in_offset);
  Osal_MemCpy( (void*)&cp0->Random_Address, (const void*)Random_Address, 6 );
  in_offset += 6;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x005;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_advertising_parameters( uint16_t Advertising_Interval_Min,
                                              uint16_t Advertising_Interval_Max,
                                              uint8_t Advertising_Type,
                                              uint8_t Own_Address_Type,
                                              uint8_t Peer_Address_Type,
                                              const uint8_t* Peer_Address,
                                              uint8_t Advertising_Channel_Map,
                                              uint8_t Advertising_Filter_Policy )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_advertising_parameters_cp0 *cp0 = (hci_le_set_advertising_parameters_cp0*)(cmd_buffer + in_offset);
  cp0->Advertising_Interval_Min = Advertising_Interval_Min;
  in_offset += 2;
  cp0->Advertising_Interval_Max = Advertising_Interval_Max;
  in_offset += 2;
  cp0->Advertising_Type = Advertising_Type;
  in_offset += 1;
  cp0->Own_Address_Type = Own_Address_Type;
  in_offset += 1;
  cp0->Peer_Address_Type = Peer_Address_Type;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Peer_Address, (const void*)Peer_Address, 6 );
  in_offset += 6;
  cp0->Advertising_Channel_Map = Advertising_Channel_Map;
  in_offset += 1;
  cp0->Advertising_Filter_Policy = Advertising_Filter_Policy;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x006;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_read_advertising_physical_channel_tx_power( uint8_t* TX_Power_Level )
{
  struct hci_request rq;
  hci_le_read_advertising_physical_channel_tx_power_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x007;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *TX_Power_Level = resp.TX_Power_Level;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_set_advertising_data( uint8_t Advertising_Data_Length,
                                        const uint8_t* Advertising_Data )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_advertising_data_cp0 *cp0 = (hci_le_set_advertising_data_cp0*)(cmd_buffer + in_offset);
  cp0->Advertising_Data_Length = Advertising_Data_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Advertising_Data, (const void*)Advertising_Data, 31 );
  in_offset += 31;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x008;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_scan_response_data( uint8_t Scan_Response_Data_Length,
                                          const uint8_t* Scan_Response_Data )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_scan_response_data_cp0 *cp0 = (hci_le_set_scan_response_data_cp0*)(cmd_buffer + in_offset);
  cp0->Scan_Response_Data_Length = Scan_Response_Data_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Scan_Response_Data, (const void*)Scan_Response_Data, 31 );
  in_offset += 31;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x009;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_advertising_enable( uint8_t Advertising_Enable )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_advertising_enable_cp0 *cp0 = (hci_le_set_advertising_enable_cp0*)(cmd_buffer + in_offset);
  cp0->Advertising_Enable = Advertising_Enable;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x00a;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_scan_parameters( uint8_t LE_Scan_Type,
                                       uint16_t LE_Scan_Interval,
                                       uint16_t LE_Scan_Window,
                                       uint8_t Own_Address_Type,
                                       uint8_t Scanning_Filter_Policy )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_scan_parameters_cp0 *cp0 = (hci_le_set_scan_parameters_cp0*)(cmd_buffer + in_offset);
  cp0->LE_Scan_Type = LE_Scan_Type;
  in_offset += 1;
  cp0->LE_Scan_Interval = LE_Scan_Interval;
  in_offset += 2;
  cp0->LE_Scan_Window = LE_Scan_Window;
  in_offset += 2;
  cp0->Own_Address_Type = Own_Address_Type;
  in_offset += 1;
  cp0->Scanning_Filter_Policy = Scanning_Filter_Policy;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x00b;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_scan_enable( uint8_t LE_Scan_Enable,
                                   uint8_t Filter_Duplicates )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_scan_enable_cp0 *cp0 = (hci_le_set_scan_enable_cp0*)(cmd_buffer + in_offset);
  cp0->LE_Scan_Enable = LE_Scan_Enable;
  in_offset += 1;
  cp0->Filter_Duplicates = Filter_Duplicates;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x00c;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_create_connection( uint16_t LE_Scan_Interval,
                                     uint16_t LE_Scan_Window,
                                     uint8_t Initiator_Filter_Policy,
                                     uint8_t Peer_Address_Type,
                                     const uint8_t* Peer_Address,
                                     uint8_t Own_Address_Type,
                                     uint16_t Connection_Interval_Min,
                                     uint16_t Connection_Interval_Max,
                                     uint16_t Max_Latency,
                                     uint16_t Supervision_Timeout,
                                     uint16_t Min_CE_Length,
                                     uint16_t Max_CE_Length )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_create_connection_cp0 *cp0 = (hci_le_create_connection_cp0*)(cmd_buffer + in_offset);
  cp0->LE_Scan_Interval = LE_Scan_Interval;
  in_offset += 2;
  cp0->LE_Scan_Window = LE_Scan_Window;
  in_offset += 2;
  cp0->Initiator_Filter_Policy = Initiator_Filter_Policy;
  in_offset += 1;
  cp0->Peer_Address_Type = Peer_Address_Type;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Peer_Address, (const void*)Peer_Address, 6 );
  in_offset += 6;
  cp0->Own_Address_Type = Own_Address_Type;
  in_offset += 1;
  cp0->Connection_Interval_Min = Connection_Interval_Min;
  in_offset += 2;
  cp0->Connection_Interval_Max = Connection_Interval_Max;
  in_offset += 2;
  cp0->Max_Latency = Max_Latency;
  in_offset += 2;
  cp0->Supervision_Timeout = Supervision_Timeout;
  in_offset += 2;
  cp0->Min_CE_Length = Min_CE_Length;
  in_offset += 2;
  cp0->Max_CE_Length = Max_CE_Length;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x00d;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_create_connection_cancel( void )
{
  struct hci_request rq;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x00e;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_read_filter_accept_list_size( uint8_t* Filter_Accept_List_Size )
{
  struct hci_request rq;
  hci_le_read_filter_accept_list_size_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x00f;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Filter_Accept_List_Size = resp.Filter_Accept_List_Size;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_clear_filter_accept_list( void )
{
  struct hci_request rq;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x010;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_add_device_to_filter_accept_list( uint8_t Address_Type,
                                                    const uint8_t* Address )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_add_device_to_filter_accept_list_cp0 *cp0 = (hci_le_add_device_to_filter_accept_list_cp0*)(cmd_buffer + in_offset);
  cp0->Address_Type = Address_Type;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Address, (const void*)Address, 6 );
  in_offset += 6;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x011;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_remove_device_from_filter_accept_list( uint8_t Address_Type,
                                                         const uint8_t* Address )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_remove_device_from_filter_accept_list_cp0 *cp0 = (hci_le_remove_device_from_filter_accept_list_cp0*)(cmd_buffer + in_offset);
  cp0->Address_Type = Address_Type;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Address, (const void*)Address, 6 );
  in_offset += 6;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x012;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_connection_update( uint16_t Connection_Handle,
                                     uint16_t Connection_Interval_Min,
                                     uint16_t Connection_Interval_Max,
                                     uint16_t Max_Latency,
                                     uint16_t Supervision_Timeout,
                                     uint16_t Min_CE_Length,
                                     uint16_t Max_CE_Length )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_connection_update_cp0 *cp0 = (hci_le_connection_update_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Connection_Interval_Min = Connection_Interval_Min;
  in_offset += 2;
  cp0->Connection_Interval_Max = Connection_Interval_Max;
  in_offset += 2;
  cp0->Max_Latency = Max_Latency;
  in_offset += 2;
  cp0->Supervision_Timeout = Supervision_Timeout;
  in_offset += 2;
  cp0->Min_CE_Length = Min_CE_Length;
  in_offset += 2;
  cp0->Max_CE_Length = Max_CE_Length;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x013;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_host_channel_classification( const uint8_t* Channel_Map )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_host_channel_classification_cp0 *cp0 = (hci_le_set_host_channel_classification_cp0*)(cmd_buffer + in_offset);
  Osal_MemCpy( (void*)&cp0->Channel_Map, (const void*)Channel_Map, 5 );
  in_offset += 5;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x014;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_read_channel_map( uint16_t Connection_Handle,
                                    uint8_t* Channel_Map )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_read_channel_map_cp0 *cp0 = (hci_le_read_channel_map_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  hci_le_read_channel_map_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x015;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  Osal_MemCpy( (void*)Channel_Map, (const void*)resp.Channel_Map, 5 );
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_read_remote_features_page_0( uint16_t Connection_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_read_remote_features_page_0_cp0 *cp0 = (hci_le_read_remote_features_page_0_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x016;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_encrypt( const uint8_t* Key,
                           const uint8_t* Plaintext_Data,
                           uint8_t* Encrypted_Data )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_encrypt_cp0 *cp0 = (hci_le_encrypt_cp0*)(cmd_buffer + in_offset);
  Osal_MemCpy( (void*)&cp0->Key, (const void*)Key, 16 );
  in_offset += 16;
  Osal_MemCpy( (void*)&cp0->Plaintext_Data, (const void*)Plaintext_Data, 16 );
  in_offset += 16;
  hci_le_encrypt_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x017;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  Osal_MemCpy( (void*)Encrypted_Data, (const void*)resp.Encrypted_Data, 16 );
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_rand( uint8_t* Random_Number )
{
  struct hci_request rq;
  hci_le_rand_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x018;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  Osal_MemCpy( (void*)Random_Number, (const void*)resp.Random_Number, 8 );
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_enable_encryption( uint16_t Connection_Handle,
                                     const uint8_t* Random_Number,
                                     uint16_t Encrypted_Diversifier,
                                     const uint8_t* Long_Term_Key )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_enable_encryption_cp0 *cp0 = (hci_le_enable_encryption_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  Osal_MemCpy( (void*)&cp0->Random_Number, (const void*)Random_Number, 8 );
  in_offset += 8;
  cp0->Encrypted_Diversifier = Encrypted_Diversifier;
  in_offset += 2;
  Osal_MemCpy( (void*)&cp0->Long_Term_Key, (const void*)Long_Term_Key, 16 );
  in_offset += 16;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x019;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_long_term_key_request_reply( uint16_t Connection_Handle,
                                               const uint8_t* Long_Term_Key )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_long_term_key_request_reply_cp0 *cp0 = (hci_le_long_term_key_request_reply_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  Osal_MemCpy( (void*)&cp0->Long_Term_Key, (const void*)Long_Term_Key, 16 );
  in_offset += 16;
  hci_le_long_term_key_request_reply_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x01a;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_long_term_key_request_negative_reply( uint16_t Connection_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_long_term_key_request_negative_reply_cp0 *cp0 = (hci_le_long_term_key_request_negative_reply_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  hci_le_long_term_key_request_negative_reply_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x01b;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_read_supported_states( uint8_t* LE_States )
{
  struct hci_request rq;
  hci_le_read_supported_states_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x01c;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  Osal_MemCpy( (void*)LE_States, (const void*)resp.LE_States, 8 );
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_receiver_test( uint8_t RX_Channel )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_receiver_test_cp0 *cp0 = (hci_le_receiver_test_cp0*)(cmd_buffer + in_offset);
  cp0->RX_Channel = RX_Channel;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x01d;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_transmitter_test( uint8_t TX_Channel,
                                    uint8_t Test_Data_Length,
                                    uint8_t Packet_Payload )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_transmitter_test_cp0 *cp0 = (hci_le_transmitter_test_cp0*)(cmd_buffer + in_offset);
  cp0->TX_Channel = TX_Channel;
  in_offset += 1;
  cp0->Test_Data_Length = Test_Data_Length;
  in_offset += 1;
  cp0->Packet_Payload = Packet_Payload;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x01e;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_test_end( uint16_t* Num_Packets )
{
  struct hci_request rq;
  hci_le_test_end_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x01f;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Num_Packets = resp.Num_Packets;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_set_data_length( uint16_t Connection_Handle,
                                   uint16_t TX_Octets,
                                   uint16_t TX_Time )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_data_length_cp0 *cp0 = (hci_le_set_data_length_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->TX_Octets = TX_Octets;
  in_offset += 2;
  cp0->TX_Time = TX_Time;
  in_offset += 2;
  hci_le_set_data_length_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x022;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_read_suggested_default_data_length( uint16_t* Suggested_Max_TX_Octets,
                                                      uint16_t* Suggested_Max_TX_Time )
{
  struct hci_request rq;
  hci_le_read_suggested_default_data_length_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x023;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Suggested_Max_TX_Octets = resp.Suggested_Max_TX_Octets;
  *Suggested_Max_TX_Time = resp.Suggested_Max_TX_Time;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_write_suggested_default_data_length( uint16_t Suggested_Max_TX_Octets,
                                                       uint16_t Suggested_Max_TX_Time )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_write_suggested_default_data_length_cp0 *cp0 = (hci_le_write_suggested_default_data_length_cp0*)(cmd_buffer + in_offset);
  cp0->Suggested_Max_TX_Octets = Suggested_Max_TX_Octets;
  in_offset += 2;
  cp0->Suggested_Max_TX_Time = Suggested_Max_TX_Time;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x024;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_read_local_p256_public_key( void )
{
  struct hci_request rq;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x025;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_generate_dhkey( const uint8_t* Remote_P256_Public_Key )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_generate_dhkey_cp0 *cp0 = (hci_le_generate_dhkey_cp0*)(cmd_buffer + in_offset);
  Osal_MemCpy( (void*)&cp0->Remote_P256_Public_Key, (const void*)Remote_P256_Public_Key, 64 );
  in_offset += 64;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x026;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_add_device_to_resolving_list( uint8_t Peer_Identity_Address_Type,
                                                const uint8_t* Peer_Identity_Address,
                                                const uint8_t* Peer_IRK,
                                                const uint8_t* Local_IRK )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_add_device_to_resolving_list_cp0 *cp0 = (hci_le_add_device_to_resolving_list_cp0*)(cmd_buffer + in_offset);
  cp0->Peer_Identity_Address_Type = Peer_Identity_Address_Type;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Peer_Identity_Address, (const void*)Peer_Identity_Address, 6 );
  in_offset += 6;
  Osal_MemCpy( (void*)&cp0->Peer_IRK, (const void*)Peer_IRK, 16 );
  in_offset += 16;
  Osal_MemCpy( (void*)&cp0->Local_IRK, (const void*)Local_IRK, 16 );
  in_offset += 16;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x027;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_remove_device_from_resolving_list( uint8_t Peer_Identity_Address_Type,
                                                     const uint8_t* Peer_Identity_Address )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_remove_device_from_resolving_list_cp0 *cp0 = (hci_le_remove_device_from_resolving_list_cp0*)(cmd_buffer + in_offset);
  cp0->Peer_Identity_Address_Type = Peer_Identity_Address_Type;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Peer_Identity_Address, (const void*)Peer_Identity_Address, 6 );
  in_offset += 6;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x028;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_clear_resolving_list( void )
{
  struct hci_request rq;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x029;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_read_resolving_list_size( uint8_t* Resolving_List_Size )
{
  struct hci_request rq;
  hci_le_read_resolving_list_size_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x02a;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Resolving_List_Size = resp.Resolving_List_Size;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_read_peer_resolvable_address( uint8_t Peer_Identity_Address_Type,
                                                const uint8_t* Peer_Identity_Address,
                                                uint8_t* Peer_Resolvable_Address )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_read_peer_resolvable_address_cp0 *cp0 = (hci_le_read_peer_resolvable_address_cp0*)(cmd_buffer + in_offset);
  cp0->Peer_Identity_Address_Type = Peer_Identity_Address_Type;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Peer_Identity_Address, (const void*)Peer_Identity_Address, 6 );
  in_offset += 6;
  hci_le_read_peer_resolvable_address_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x02b;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  Osal_MemCpy( (void*)Peer_Resolvable_Address, (const void*)resp.Peer_Resolvable_Address, 6 );
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_read_local_resolvable_address( uint8_t Peer_Identity_Address_Type,
                                                 const uint8_t* Peer_Identity_Address,
                                                 uint8_t* Local_Resolvable_Address )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_read_local_resolvable_address_cp0 *cp0 = (hci_le_read_local_resolvable_address_cp0*)(cmd_buffer + in_offset);
  cp0->Peer_Identity_Address_Type = Peer_Identity_Address_Type;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Peer_Identity_Address, (const void*)Peer_Identity_Address, 6 );
  in_offset += 6;
  hci_le_read_local_resolvable_address_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x02c;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  Osal_MemCpy( (void*)Local_Resolvable_Address, (const void*)resp.Local_Resolvable_Address, 6 );
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_set_address_resolution_enable( uint8_t Address_Resolution_Enable )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_address_resolution_enable_cp0 *cp0 = (hci_le_set_address_resolution_enable_cp0*)(cmd_buffer + in_offset);
  cp0->Address_Resolution_Enable = Address_Resolution_Enable;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x02d;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_resolvable_private_address_timeout( uint16_t RPA_Timeout )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_resolvable_private_address_timeout_cp0 *cp0 = (hci_le_set_resolvable_private_address_timeout_cp0*)(cmd_buffer + in_offset);
  cp0->RPA_Timeout = RPA_Timeout;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x02e;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_read_maximum_data_length( uint16_t* Supported_Max_TX_Octets,
                                            uint16_t* Supported_Max_TX_Time,
                                            uint16_t* Supported_Max_RX_Octets,
                                            uint16_t* Supported_Max_RX_Time )
{
  struct hci_request rq;
  hci_le_read_maximum_data_length_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x02f;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Supported_Max_TX_Octets = resp.Supported_Max_TX_Octets;
  *Supported_Max_TX_Time = resp.Supported_Max_TX_Time;
  *Supported_Max_RX_Octets = resp.Supported_Max_RX_Octets;
  *Supported_Max_RX_Time = resp.Supported_Max_RX_Time;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_read_phy( uint16_t Connection_Handle,
                            uint8_t* TX_PHY,
                            uint8_t* RX_PHY )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_read_phy_cp0 *cp0 = (hci_le_read_phy_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  hci_le_read_phy_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x030;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *TX_PHY = resp.TX_PHY;
  *RX_PHY = resp.RX_PHY;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_set_default_phy( uint8_t All_PHYs,
                                   uint8_t TX_PHYs,
                                   uint8_t RX_PHYs )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_default_phy_cp0 *cp0 = (hci_le_set_default_phy_cp0*)(cmd_buffer + in_offset);
  cp0->All_PHYs = All_PHYs;
  in_offset += 1;
  cp0->TX_PHYs = TX_PHYs;
  in_offset += 1;
  cp0->RX_PHYs = RX_PHYs;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x031;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_phy( uint16_t Connection_Handle,
                           uint8_t All_PHYs,
                           uint8_t TX_PHYs,
                           uint8_t RX_PHYs,
                           uint16_t PHY_Options )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_phy_cp0 *cp0 = (hci_le_set_phy_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->All_PHYs = All_PHYs;
  in_offset += 1;
  cp0->TX_PHYs = TX_PHYs;
  in_offset += 1;
  cp0->RX_PHYs = RX_PHYs;
  in_offset += 1;
  cp0->PHY_Options = PHY_Options;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x032;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_receiver_test_v2( uint8_t RX_Channel,
                                    uint8_t PHY,
                                    uint8_t Modulation_Index )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_receiver_test_v2_cp0 *cp0 = (hci_le_receiver_test_v2_cp0*)(cmd_buffer + in_offset);
  cp0->RX_Channel = RX_Channel;
  in_offset += 1;
  cp0->PHY = PHY;
  in_offset += 1;
  cp0->Modulation_Index = Modulation_Index;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x033;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_transmitter_test_v2( uint8_t TX_Channel,
                                       uint8_t Test_Data_Length,
                                       uint8_t Packet_Payload,
                                       uint8_t PHY )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_transmitter_test_v2_cp0 *cp0 = (hci_le_transmitter_test_v2_cp0*)(cmd_buffer + in_offset);
  cp0->TX_Channel = TX_Channel;
  in_offset += 1;
  cp0->Test_Data_Length = Test_Data_Length;
  in_offset += 1;
  cp0->Packet_Payload = Packet_Payload;
  in_offset += 1;
  cp0->PHY = PHY;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x034;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_advertising_set_random_address( uint8_t Advertising_Handle,
                                                      const uint8_t* Random_Address )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_advertising_set_random_address_cp0 *cp0 = (hci_le_set_advertising_set_random_address_cp0*)(cmd_buffer + in_offset);
  cp0->Advertising_Handle = Advertising_Handle;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Random_Address, (const void*)Random_Address, 6 );
  in_offset += 6;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x035;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_extended_advertising_parameters( uint8_t Advertising_Handle,
                                                       uint16_t Advertising_Event_Properties,
                                                       const uint8_t* Primary_Advertising_Interval_Min,
                                                       const uint8_t* Primary_Advertising_Interval_Max,
                                                       uint8_t Primary_Advertising_Channel_Map,
                                                       uint8_t Own_Address_Type,
                                                       uint8_t Peer_Address_Type,
                                                       const uint8_t* Peer_Address,
                                                       uint8_t Advertising_Filter_Policy,
                                                       uint8_t Advertising_TX_Power,
                                                       uint8_t Primary_Advertising_PHY,
                                                       uint8_t Secondary_Advertising_Max_Skip,
                                                       uint8_t Secondary_Advertising_PHY,
                                                       uint8_t Advertising_SID,
                                                       uint8_t Scan_Req_Notification_Enable,
                                                       uint8_t* Selected_TX_Power )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_extended_advertising_parameters_cp0 *cp0 = (hci_le_set_extended_advertising_parameters_cp0*)(cmd_buffer + in_offset);
  cp0->Advertising_Handle = Advertising_Handle;
  in_offset += 1;
  cp0->Advertising_Event_Properties = Advertising_Event_Properties;
  in_offset += 2;
  Osal_MemCpy( (void*)&cp0->Primary_Advertising_Interval_Min, (const void*)Primary_Advertising_Interval_Min, 3 );
  in_offset += 3;
  Osal_MemCpy( (void*)&cp0->Primary_Advertising_Interval_Max, (const void*)Primary_Advertising_Interval_Max, 3 );
  in_offset += 3;
  cp0->Primary_Advertising_Channel_Map = Primary_Advertising_Channel_Map;
  in_offset += 1;
  cp0->Own_Address_Type = Own_Address_Type;
  in_offset += 1;
  cp0->Peer_Address_Type = Peer_Address_Type;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Peer_Address, (const void*)Peer_Address, 6 );
  in_offset += 6;
  cp0->Advertising_Filter_Policy = Advertising_Filter_Policy;
  in_offset += 1;
  cp0->Advertising_TX_Power = Advertising_TX_Power;
  in_offset += 1;
  cp0->Primary_Advertising_PHY = Primary_Advertising_PHY;
  in_offset += 1;
  cp0->Secondary_Advertising_Max_Skip = Secondary_Advertising_Max_Skip;
  in_offset += 1;
  cp0->Secondary_Advertising_PHY = Secondary_Advertising_PHY;
  in_offset += 1;
  cp0->Advertising_SID = Advertising_SID;
  in_offset += 1;
  cp0->Scan_Req_Notification_Enable = Scan_Req_Notification_Enable;
  in_offset += 1;
  hci_le_set_extended_advertising_parameters_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x036;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Selected_TX_Power = resp.Selected_TX_Power;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_set_extended_advertising_data( uint8_t Advertising_Handle,
                                                 uint8_t Operation,
                                                 uint8_t Fragment_Preference,
                                                 uint8_t Advertising_Data_Length,
                                                 const uint8_t* Advertising_Data )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_extended_advertising_data_cp0 *cp0 = (hci_le_set_extended_advertising_data_cp0*)(cmd_buffer + in_offset);
  cp0->Advertising_Handle = Advertising_Handle;
  in_offset += 1;
  cp0->Operation = Operation;
  in_offset += 1;
  cp0->Fragment_Preference = Fragment_Preference;
  in_offset += 1;
  cp0->Advertising_Data_Length = Advertising_Data_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Advertising_Data, (const void*)Advertising_Data, Advertising_Data_Length );
  in_offset += Advertising_Data_Length;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x037;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_extended_scan_response_data( uint8_t Advertising_Handle,
                                                   uint8_t Operation,
                                                   uint8_t Fragment_Preference,
                                                   uint8_t Scan_Response_Data_Length,
                                                   const uint8_t* Scan_Response_Data )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_extended_scan_response_data_cp0 *cp0 = (hci_le_set_extended_scan_response_data_cp0*)(cmd_buffer + in_offset);
  cp0->Advertising_Handle = Advertising_Handle;
  in_offset += 1;
  cp0->Operation = Operation;
  in_offset += 1;
  cp0->Fragment_Preference = Fragment_Preference;
  in_offset += 1;
  cp0->Scan_Response_Data_Length = Scan_Response_Data_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Scan_Response_Data, (const void*)Scan_Response_Data, Scan_Response_Data_Length );
  in_offset += Scan_Response_Data_Length;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x038;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_extended_advertising_enable( uint8_t Enable,
                                                   uint8_t Num_Sets,
                                                   const Adv_Set_t* Adv_Set )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_extended_advertising_enable_cp0 *cp0 = (hci_le_set_extended_advertising_enable_cp0*)(cmd_buffer + in_offset);
  cp0->Enable = Enable;
  in_offset += 1;
  cp0->Num_Sets = Num_Sets;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Adv_Set, (const void*)Adv_Set, Num_Sets * (sizeof(Adv_Set_t)) );
  in_offset += Num_Sets * (sizeof(Adv_Set_t));
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x039;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_read_maximum_advertising_data_length( uint16_t* Max_Advertising_Data_Length )
{
  struct hci_request rq;
  hci_le_read_maximum_advertising_data_length_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x03a;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Max_Advertising_Data_Length = resp.Max_Advertising_Data_Length;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_read_number_of_supported_advertising_sets( uint8_t* Num_Supported_Advertising_Sets )
{
  struct hci_request rq;
  hci_le_read_number_of_supported_advertising_sets_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x03b;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Num_Supported_Advertising_Sets = resp.Num_Supported_Advertising_Sets;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_remove_advertising_set( uint8_t Advertising_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_remove_advertising_set_cp0 *cp0 = (hci_le_remove_advertising_set_cp0*)(cmd_buffer + in_offset);
  cp0->Advertising_Handle = Advertising_Handle;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x03c;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_clear_advertising_sets( void )
{
  struct hci_request rq;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x03d;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_extended_scan_parameters( uint8_t Own_Address_Type,
                                                uint8_t Scanning_Filter_Policy,
                                                uint8_t Scanning_PHYs,
                                                const Scan_Param_Phy_t* Scan_Param_Phy )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_extended_scan_parameters_cp0 *cp0 = (hci_le_set_extended_scan_parameters_cp0*)(cmd_buffer + in_offset);
  cp0->Own_Address_Type = Own_Address_Type;
  in_offset += 1;
  cp0->Scanning_Filter_Policy = Scanning_Filter_Policy;
  in_offset += 1;
  cp0->Scanning_PHYs = Scanning_PHYs;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Scan_Param_Phy, (const void*)Scan_Param_Phy, 10 );
  in_offset += 10;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x041;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_extended_scan_enable( uint8_t Enable,
                                            uint8_t Filter_Duplicates,
                                            uint16_t Duration,
                                            uint16_t Period )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_extended_scan_enable_cp0 *cp0 = (hci_le_set_extended_scan_enable_cp0*)(cmd_buffer + in_offset);
  cp0->Enable = Enable;
  in_offset += 1;
  cp0->Filter_Duplicates = Filter_Duplicates;
  in_offset += 1;
  cp0->Duration = Duration;
  in_offset += 2;
  cp0->Period = Period;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x042;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_extended_create_connection( uint8_t Initiator_Filter_Policy,
                                              uint8_t Own_Address_Type,
                                              uint8_t Peer_Address_Type,
                                              const uint8_t* Peer_Address,
                                              uint8_t Initiating_PHYs,
                                              const Init_Param_Phy_t* Init_Param_Phy )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_extended_create_connection_cp0 *cp0 = (hci_le_extended_create_connection_cp0*)(cmd_buffer + in_offset);
  cp0->Initiator_Filter_Policy = Initiator_Filter_Policy;
  in_offset += 1;
  cp0->Own_Address_Type = Own_Address_Type;
  in_offset += 1;
  cp0->Peer_Address_Type = Peer_Address_Type;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Peer_Address, (const void*)Peer_Address, 6 );
  in_offset += 6;
  cp0->Initiating_PHYs = Initiating_PHYs;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Init_Param_Phy, (const void*)Init_Param_Phy, 48 );
  in_offset += 48;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x043;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_read_transmit_power( uint8_t* Min_TX_Power,
                                       uint8_t* Max_TX_Power )
{
  struct hci_request rq;
  hci_le_read_transmit_power_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x04b;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Min_TX_Power = resp.Min_TX_Power;
  *Max_TX_Power = resp.Max_TX_Power;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_read_rf_path_compensation( uint16_t* RF_TX_Path_Compensation_Value,
                                             uint16_t* RF_RX_Path_Compensation_Value )
{
  struct hci_request rq;
  hci_le_read_rf_path_compensation_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x08;
  rq.ocf = 0x04c;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *RF_TX_Path_Compensation_Value = resp.RF_TX_Path_Compensation_Value;
  *RF_RX_Path_Compensation_Value = resp.RF_RX_Path_Compensation_Value;
  return BLE_STATUS_SUCCESS;
}

tBleStatus hci_le_write_rf_path_compensation( uint16_t RF_TX_Path_Compensation_Value,
                                              uint16_t RF_RX_Path_Compensation_Value )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_write_rf_path_compensation_cp0 *cp0 = (hci_le_write_rf_path_compensation_cp0*)(cmd_buffer + in_offset);
  cp0->RF_TX_Path_Compensation_Value = RF_TX_Path_Compensation_Value;
  in_offset += 2;
  cp0->RF_RX_Path_Compensation_Value = RF_RX_Path_Compensation_Value;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x04d;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_privacy_mode( uint8_t Peer_Identity_Address_Type,
                                    const uint8_t* Peer_Identity_Address,
                                    uint8_t Privacy_Mode )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_privacy_mode_cp0 *cp0 = (hci_le_set_privacy_mode_cp0*)(cmd_buffer + in_offset);
  cp0->Peer_Identity_Address_Type = Peer_Identity_Address_Type;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Peer_Identity_Address, (const void*)Peer_Identity_Address, 6 );
  in_offset += 6;
  cp0->Privacy_Mode = Privacy_Mode;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x04e;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_generate_dhkey_v2( const uint8_t* Remote_P256_Public_Key,
                                     uint8_t Key_Type )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_generate_dhkey_v2_cp0 *cp0 = (hci_le_generate_dhkey_v2_cp0*)(cmd_buffer + in_offset);
  Osal_MemCpy( (void*)&cp0->Remote_P256_Public_Key, (const void*)Remote_P256_Public_Key, 64 );
  in_offset += 64;
  cp0->Key_Type = Key_Type;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x05e;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus hci_le_set_resolvable_private_address_timeout_v2( uint16_t RPA_Timeout_Min,
                                                             uint16_t RPA_Timeout_Max )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  hci_le_set_resolvable_private_address_timeout_v2_cp0 *cp0 = (hci_le_set_resolvable_private_address_timeout_v2_cp0*)(cmd_buffer + in_offset);
  cp0->RPA_Timeout_Min = RPA_Timeout_Min;
  in_offset += 2;
  cp0->RPA_Timeout_Max = RPA_Timeout_Max;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x08;
  rq.ocf = 0x09e;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

