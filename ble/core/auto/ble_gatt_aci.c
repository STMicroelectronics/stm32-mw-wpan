/*****************************************************************************
 * @file    ble_gatt_aci.c
 * @brief   STM32WB BLE API (gatt_aci)
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

#include "auto/ble_gatt_aci.h"

tBleStatus aci_gatt_init( void )
{
  struct hci_request rq;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x101;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_add_service( uint8_t Service_UUID_Type,
                                 const Service_UUID_t* Service_UUID,
                                 uint8_t Service_Type,
                                 uint8_t Max_Attribute_Records,
                                 uint16_t* Service_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_add_service_cp0 *cp0 = (aci_gatt_add_service_cp0*)(cmd_buffer + in_offset);
  cp0->Service_UUID_Type = Service_UUID_Type;
  in_offset += 1;
  int service_uuid_size = (Service_UUID_Type == 2 ? 16 : 2);
  Osal_MemCpy( (void*)&cp0->Service_UUID, (const void*)Service_UUID, service_uuid_size );
  in_offset += service_uuid_size;
  aci_gatt_add_service_cp1 *cp1 = (aci_gatt_add_service_cp1*)(cmd_buffer + in_offset);
  cp1->Service_Type = Service_Type;
  in_offset += 1;
  cp1->Max_Attribute_Records = Max_Attribute_Records;
  in_offset += 1;
  aci_gatt_add_service_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x102;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Service_Handle = resp.Service_Handle;
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_gatt_include_service( uint16_t Service_Handle,
                                     uint16_t Include_Start_Handle,
                                     uint16_t Include_End_Handle,
                                     uint8_t Include_UUID_Type,
                                     const Include_UUID_t* Include_UUID,
                                     uint16_t* Include_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_include_service_cp0 *cp0 = (aci_gatt_include_service_cp0*)(cmd_buffer + in_offset);
  cp0->Service_Handle = Service_Handle;
  in_offset += 2;
  cp0->Include_Start_Handle = Include_Start_Handle;
  in_offset += 2;
  cp0->Include_End_Handle = Include_End_Handle;
  in_offset += 2;
  cp0->Include_UUID_Type = Include_UUID_Type;
  in_offset += 1;
  int include_uuid_size = (Include_UUID_Type == 2 ? 16 : 2);
  Osal_MemCpy( (void*)&cp0->Include_UUID, (const void*)Include_UUID, include_uuid_size );
  in_offset += include_uuid_size;
  aci_gatt_include_service_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x103;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Include_Handle = resp.Include_Handle;
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_gatt_add_char( uint16_t Service_Handle,
                              uint8_t Char_UUID_Type,
                              const Char_UUID_t* Char_UUID,
                              uint16_t Char_Value_Length,
                              uint8_t Char_Properties,
                              uint8_t Security_Permissions,
                              uint8_t GATT_Evt_Mask,
                              uint8_t Enc_Key_Size,
                              uint8_t Is_Variable,
                              uint16_t* Char_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_add_char_cp0 *cp0 = (aci_gatt_add_char_cp0*)(cmd_buffer + in_offset);
  cp0->Service_Handle = Service_Handle;
  in_offset += 2;
  cp0->Char_UUID_Type = Char_UUID_Type;
  in_offset += 1;
  int char_uuid_size = (Char_UUID_Type == 2 ? 16 : 2);
  Osal_MemCpy( (void*)&cp0->Char_UUID, (const void*)Char_UUID, char_uuid_size );
  in_offset += char_uuid_size;
  aci_gatt_add_char_cp1 *cp1 = (aci_gatt_add_char_cp1*)(cmd_buffer + in_offset);
  cp1->Char_Value_Length = Char_Value_Length;
  in_offset += 2;
  cp1->Char_Properties = Char_Properties;
  in_offset += 1;
  cp1->Security_Permissions = Security_Permissions;
  in_offset += 1;
  cp1->GATT_Evt_Mask = GATT_Evt_Mask;
  in_offset += 1;
  cp1->Enc_Key_Size = Enc_Key_Size;
  in_offset += 1;
  cp1->Is_Variable = Is_Variable;
  in_offset += 1;
  aci_gatt_add_char_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x104;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Char_Handle = resp.Char_Handle;
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_gatt_add_char_desc( uint16_t Service_Handle,
                                   uint16_t Char_Handle,
                                   uint8_t Char_Desc_Uuid_Type,
                                   const Char_Desc_Uuid_t* Char_Desc_Uuid,
                                   uint8_t Char_Desc_Value_Max_Len,
                                   uint8_t Char_Desc_Value_Length,
                                   const uint8_t* Char_Desc_Value,
                                   uint8_t Security_Permissions,
                                   uint8_t Access_Permissions,
                                   uint8_t GATT_Evt_Mask,
                                   uint8_t Enc_Key_Size,
                                   uint8_t Is_Variable,
                                   uint16_t* Char_Desc_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_add_char_desc_cp0 *cp0 = (aci_gatt_add_char_desc_cp0*)(cmd_buffer + in_offset);
  cp0->Service_Handle = Service_Handle;
  in_offset += 2;
  cp0->Char_Handle = Char_Handle;
  in_offset += 2;
  cp0->Char_Desc_Uuid_Type = Char_Desc_Uuid_Type;
  in_offset += 1;
  int char_desc_uuid_size = (Char_Desc_Uuid_Type == 2 ? 16 : 2);
  Osal_MemCpy( (void*)&cp0->Char_Desc_Uuid, (const void*)Char_Desc_Uuid, char_desc_uuid_size );
  in_offset += char_desc_uuid_size;
  aci_gatt_add_char_desc_cp1 *cp1 = (aci_gatt_add_char_desc_cp1*)(cmd_buffer + in_offset);
  cp1->Char_Desc_Value_Max_Len = Char_Desc_Value_Max_Len;
  in_offset += 1;
  cp1->Char_Desc_Value_Length = Char_Desc_Value_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp1->Char_Desc_Value, (const void*)Char_Desc_Value, Char_Desc_Value_Length );
  in_offset += Char_Desc_Value_Length;
  aci_gatt_add_char_desc_cp2 *cp2 = (aci_gatt_add_char_desc_cp2*)(cmd_buffer + in_offset);
  cp2->Security_Permissions = Security_Permissions;
  in_offset += 1;
  cp2->Access_Permissions = Access_Permissions;
  in_offset += 1;
  cp2->GATT_Evt_Mask = GATT_Evt_Mask;
  in_offset += 1;
  cp2->Enc_Key_Size = Enc_Key_Size;
  in_offset += 1;
  cp2->Is_Variable = Is_Variable;
  in_offset += 1;
  aci_gatt_add_char_desc_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x105;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Char_Desc_Handle = resp.Char_Desc_Handle;
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_gatt_update_char_value( uint16_t Service_Handle,
                                       uint16_t Char_Handle,
                                       uint8_t Val_Offset,
                                       uint8_t Char_Value_Length,
                                       const uint8_t* Char_Value )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_update_char_value_cp0 *cp0 = (aci_gatt_update_char_value_cp0*)(cmd_buffer + in_offset);
  cp0->Service_Handle = Service_Handle;
  in_offset += 2;
  cp0->Char_Handle = Char_Handle;
  in_offset += 2;
  cp0->Val_Offset = Val_Offset;
  in_offset += 1;
  cp0->Char_Value_Length = Char_Value_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Char_Value, (const void*)Char_Value, Char_Value_Length );
  in_offset += Char_Value_Length;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x106;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_del_char( uint16_t Serv_Handle,
                              uint16_t Char_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_del_char_cp0 *cp0 = (aci_gatt_del_char_cp0*)(cmd_buffer + in_offset);
  cp0->Serv_Handle = Serv_Handle;
  in_offset += 2;
  cp0->Char_Handle = Char_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x107;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_del_service( uint16_t Serv_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_del_service_cp0 *cp0 = (aci_gatt_del_service_cp0*)(cmd_buffer + in_offset);
  cp0->Serv_Handle = Serv_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x108;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_del_include_service( uint16_t Serv_Handle,
                                         uint16_t Include_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_del_include_service_cp0 *cp0 = (aci_gatt_del_include_service_cp0*)(cmd_buffer + in_offset);
  cp0->Serv_Handle = Serv_Handle;
  in_offset += 2;
  cp0->Include_Handle = Include_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x109;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_set_event_mask( uint32_t GATT_Evt_Mask )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_set_event_mask_cp0 *cp0 = (aci_gatt_set_event_mask_cp0*)(cmd_buffer + in_offset);
  cp0->GATT_Evt_Mask = GATT_Evt_Mask;
  in_offset += 4;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x10a;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_exchange_config( uint16_t Connection_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_exchange_config_cp0 *cp0 = (aci_gatt_exchange_config_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x10b;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_att_find_info_req( uint16_t Connection_Handle,
                                  uint16_t Start_Handle,
                                  uint16_t End_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_att_find_info_req_cp0 *cp0 = (aci_att_find_info_req_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Start_Handle = Start_Handle;
  in_offset += 2;
  cp0->End_Handle = End_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x10c;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_att_find_by_type_value_req( uint16_t Connection_Handle,
                                           uint16_t Start_Handle,
                                           uint16_t End_Handle,
                                           uint16_t UUID,
                                           uint8_t Attribute_Val_Length,
                                           const uint8_t* Attribute_Val )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_att_find_by_type_value_req_cp0 *cp0 = (aci_att_find_by_type_value_req_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Start_Handle = Start_Handle;
  in_offset += 2;
  cp0->End_Handle = End_Handle;
  in_offset += 2;
  cp0->UUID = UUID;
  in_offset += 2;
  cp0->Attribute_Val_Length = Attribute_Val_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Attribute_Val, (const void*)Attribute_Val, Attribute_Val_Length );
  in_offset += Attribute_Val_Length;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x10d;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_att_read_by_type_req( uint16_t Connection_Handle,
                                     uint16_t Start_Handle,
                                     uint16_t End_Handle,
                                     uint8_t UUID_Type,
                                     const UUID_t* UUID )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_att_read_by_type_req_cp0 *cp0 = (aci_att_read_by_type_req_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Start_Handle = Start_Handle;
  in_offset += 2;
  cp0->End_Handle = End_Handle;
  in_offset += 2;
  cp0->UUID_Type = UUID_Type;
  in_offset += 1;
  int uuid_size = (UUID_Type == 2 ? 16 : 2);
  Osal_MemCpy( (void*)&cp0->UUID, (const void*)UUID, uuid_size );
  in_offset += uuid_size;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x10e;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_att_read_by_group_type_req( uint16_t Connection_Handle,
                                           uint16_t Start_Handle,
                                           uint16_t End_Handle,
                                           uint8_t UUID_Type,
                                           const UUID_t* UUID )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_att_read_by_group_type_req_cp0 *cp0 = (aci_att_read_by_group_type_req_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Start_Handle = Start_Handle;
  in_offset += 2;
  cp0->End_Handle = End_Handle;
  in_offset += 2;
  cp0->UUID_Type = UUID_Type;
  in_offset += 1;
  int uuid_size = (UUID_Type == 2 ? 16 : 2);
  Osal_MemCpy( (void*)&cp0->UUID, (const void*)UUID, uuid_size );
  in_offset += uuid_size;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x10f;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_att_prepare_write_req( uint16_t Connection_Handle,
                                      uint16_t Attr_Handle,
                                      uint16_t Val_Offset,
                                      uint8_t Attribute_Val_Length,
                                      const uint8_t* Attribute_Val )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_att_prepare_write_req_cp0 *cp0 = (aci_att_prepare_write_req_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Val_Offset = Val_Offset;
  in_offset += 2;
  cp0->Attribute_Val_Length = Attribute_Val_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Attribute_Val, (const void*)Attribute_Val, Attribute_Val_Length );
  in_offset += Attribute_Val_Length;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x110;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_att_execute_write_req( uint16_t Connection_Handle,
                                      uint8_t Execute )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_att_execute_write_req_cp0 *cp0 = (aci_att_execute_write_req_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Execute = Execute;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x111;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_disc_all_primary_services( uint16_t Connection_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_disc_all_primary_services_cp0 *cp0 = (aci_gatt_disc_all_primary_services_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x112;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_disc_primary_service_by_uuid( uint16_t Connection_Handle,
                                                  uint8_t UUID_Type,
                                                  const UUID_t* UUID )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_disc_primary_service_by_uuid_cp0 *cp0 = (aci_gatt_disc_primary_service_by_uuid_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->UUID_Type = UUID_Type;
  in_offset += 1;
  int uuid_size = (UUID_Type == 2 ? 16 : 2);
  Osal_MemCpy( (void*)&cp0->UUID, (const void*)UUID, uuid_size );
  in_offset += uuid_size;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x113;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_find_included_services( uint16_t Connection_Handle,
                                            uint16_t Start_Handle,
                                            uint16_t End_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_find_included_services_cp0 *cp0 = (aci_gatt_find_included_services_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Start_Handle = Start_Handle;
  in_offset += 2;
  cp0->End_Handle = End_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x114;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_disc_all_char_of_service( uint16_t Connection_Handle,
                                              uint16_t Start_Handle,
                                              uint16_t End_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_disc_all_char_of_service_cp0 *cp0 = (aci_gatt_disc_all_char_of_service_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Start_Handle = Start_Handle;
  in_offset += 2;
  cp0->End_Handle = End_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x115;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_disc_char_by_uuid( uint16_t Connection_Handle,
                                       uint16_t Start_Handle,
                                       uint16_t End_Handle,
                                       uint8_t UUID_Type,
                                       const UUID_t* UUID )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_disc_char_by_uuid_cp0 *cp0 = (aci_gatt_disc_char_by_uuid_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Start_Handle = Start_Handle;
  in_offset += 2;
  cp0->End_Handle = End_Handle;
  in_offset += 2;
  cp0->UUID_Type = UUID_Type;
  in_offset += 1;
  int uuid_size = (UUID_Type == 2 ? 16 : 2);
  Osal_MemCpy( (void*)&cp0->UUID, (const void*)UUID, uuid_size );
  in_offset += uuid_size;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x116;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_disc_all_char_desc( uint16_t Connection_Handle,
                                        uint16_t Char_Handle,
                                        uint16_t End_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_disc_all_char_desc_cp0 *cp0 = (aci_gatt_disc_all_char_desc_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Char_Handle = Char_Handle;
  in_offset += 2;
  cp0->End_Handle = End_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x117;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_read_char_value( uint16_t Connection_Handle,
                                     uint16_t Attr_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_read_char_value_cp0 *cp0 = (aci_gatt_read_char_value_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x118;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_read_using_char_uuid( uint16_t Connection_Handle,
                                          uint16_t Start_Handle,
                                          uint16_t End_Handle,
                                          uint8_t UUID_Type,
                                          const UUID_t* UUID )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_read_using_char_uuid_cp0 *cp0 = (aci_gatt_read_using_char_uuid_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Start_Handle = Start_Handle;
  in_offset += 2;
  cp0->End_Handle = End_Handle;
  in_offset += 2;
  cp0->UUID_Type = UUID_Type;
  in_offset += 1;
  int uuid_size = (UUID_Type == 2 ? 16 : 2);
  Osal_MemCpy( (void*)&cp0->UUID, (const void*)UUID, uuid_size );
  in_offset += uuid_size;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x119;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_read_long_char_value( uint16_t Connection_Handle,
                                          uint16_t Attr_Handle,
                                          uint16_t Val_Offset )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_read_long_char_value_cp0 *cp0 = (aci_gatt_read_long_char_value_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Val_Offset = Val_Offset;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x11a;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_read_multiple_char_value( uint16_t Connection_Handle,
                                              uint8_t Number_of_Handles,
                                              const Handle_Entry_t* Handle_Entry )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_read_multiple_char_value_cp0 *cp0 = (aci_gatt_read_multiple_char_value_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Number_of_Handles = Number_of_Handles;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Handle_Entry, (const void*)Handle_Entry, Number_of_Handles * (sizeof(Handle_Entry_t)) );
  in_offset += Number_of_Handles * (sizeof(Handle_Entry_t));
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x11b;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_write_char_value( uint16_t Connection_Handle,
                                      uint16_t Attr_Handle,
                                      uint8_t Attribute_Val_Length,
                                      const uint8_t* Attribute_Val )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_write_char_value_cp0 *cp0 = (aci_gatt_write_char_value_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Attribute_Val_Length = Attribute_Val_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Attribute_Val, (const void*)Attribute_Val, Attribute_Val_Length );
  in_offset += Attribute_Val_Length;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x11c;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_write_long_char_value( uint16_t Connection_Handle,
                                           uint16_t Attr_Handle,
                                           uint16_t Val_Offset,
                                           uint8_t Attribute_Val_Length,
                                           const uint8_t* Attribute_Val )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_write_long_char_value_cp0 *cp0 = (aci_gatt_write_long_char_value_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Val_Offset = Val_Offset;
  in_offset += 2;
  cp0->Attribute_Val_Length = Attribute_Val_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Attribute_Val, (const void*)Attribute_Val, Attribute_Val_Length );
  in_offset += Attribute_Val_Length;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x11d;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_write_char_reliable( uint16_t Connection_Handle,
                                         uint16_t Attr_Handle,
                                         uint16_t Val_Offset,
                                         uint8_t Attribute_Val_Length,
                                         const uint8_t* Attribute_Val )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_write_char_reliable_cp0 *cp0 = (aci_gatt_write_char_reliable_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Val_Offset = Val_Offset;
  in_offset += 2;
  cp0->Attribute_Val_Length = Attribute_Val_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Attribute_Val, (const void*)Attribute_Val, Attribute_Val_Length );
  in_offset += Attribute_Val_Length;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x11e;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_write_without_resp( uint16_t Connection_Handle,
                                        uint16_t Attr_Handle,
                                        uint8_t Attribute_Val_Length,
                                        const uint8_t* Attribute_Val )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_write_without_resp_cp0 *cp0 = (aci_gatt_write_without_resp_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Attribute_Val_Length = Attribute_Val_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Attribute_Val, (const void*)Attribute_Val, Attribute_Val_Length );
  in_offset += Attribute_Val_Length;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x123;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_confirm_indication( uint16_t Connection_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_confirm_indication_cp0 *cp0 = (aci_gatt_confirm_indication_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x125;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_permit_write( uint16_t Connection_Handle,
                                  uint16_t Attr_Handle,
                                  uint8_t Write_status,
                                  uint8_t Error_Code,
                                  uint8_t Attribute_Val_Length,
                                  const uint8_t* Attribute_Val )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_permit_write_cp0 *cp0 = (aci_gatt_permit_write_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Write_status = Write_status;
  in_offset += 1;
  cp0->Error_Code = Error_Code;
  in_offset += 1;
  cp0->Attribute_Val_Length = 0;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x126;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_permit_read( uint16_t Connection_Handle,
                                 uint8_t Read_status,
                                 uint8_t Error_Code,
                                 uint16_t Attr_Handle )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_permit_read_cp0 *cp0 = (aci_gatt_permit_read_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Read_status = Read_status;
  in_offset += 1;
  cp0->Error_Code = Error_Code;
  in_offset += 1;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x127;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_set_security_permission( uint16_t Serv_Handle,
                                             uint16_t Attr_Handle,
                                             uint8_t Security_Permissions )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_set_security_permission_cp0 *cp0 = (aci_gatt_set_security_permission_cp0*)(cmd_buffer + in_offset);
  cp0->Serv_Handle = Serv_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Security_Permissions = Security_Permissions;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x128;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_set_desc_value( uint16_t Serv_Handle,
                                    uint16_t Char_Handle,
                                    uint16_t Char_Desc_Handle,
                                    uint16_t Val_Offset,
                                    uint8_t Char_Desc_Value_Length,
                                    const uint8_t* Char_Desc_Value )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_set_desc_value_cp0 *cp0 = (aci_gatt_set_desc_value_cp0*)(cmd_buffer + in_offset);
  cp0->Serv_Handle = Serv_Handle;
  in_offset += 2;
  cp0->Char_Handle = Char_Handle;
  in_offset += 2;
  cp0->Char_Desc_Handle = Char_Desc_Handle;
  in_offset += 2;
  cp0->Val_Offset = Val_Offset;
  in_offset += 2;
  cp0->Char_Desc_Value_Length = Char_Desc_Value_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Char_Desc_Value, (const void*)Char_Desc_Value, Char_Desc_Value_Length );
  in_offset += Char_Desc_Value_Length;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x129;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_read_handle_value( uint16_t Attr_Handle,
                                       uint16_t Offset,
                                       uint16_t Value_Length_Requested,
                                       uint16_t* Length,
                                       uint16_t* Value_Length,
                                       uint8_t* Value )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_read_handle_value_cp0 *cp0 = (aci_gatt_read_handle_value_cp0*)(cmd_buffer + in_offset);
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Offset = Offset;
  in_offset += 2;
  cp0->Value_Length_Requested = Value_Length_Requested;
  in_offset += 2;
  aci_gatt_read_handle_value_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x12a;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Length = resp.Length;
  *Value_Length = resp.Value_Length;
  Osal_MemCpy( (void*)Value, (const void*)resp.Value, *Value_Length );
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_gatt_get_attribute_value( uint16_t Connection_Handle,
                                         uint16_t Attr_Handle,
                                         uint16_t Offset,
                                         uint16_t Value_Length_Requested,
                                         uint16_t* Length,
                                         uint16_t* Value_Length,
                                         uint8_t* Value )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_get_attribute_value_cp0 *cp0 = (aci_gatt_get_attribute_value_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Offset = Offset;
  in_offset += 2;
  cp0->Value_Length_Requested = Value_Length_Requested;
  in_offset += 2;
  aci_gatt_get_attribute_value_rp0 resp;
  Osal_MemSet( &resp, 0, sizeof(resp) );
  rq.ogf = 0x3f;
  rq.ocf = 0x12b;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &resp;
  rq.rlen = sizeof(resp);
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  if ( resp.Status )
    return resp.Status;
  *Length = resp.Length;
  *Value_Length = resp.Value_Length;
  Osal_MemCpy( (void*)Value, (const void*)resp.Value, *Value_Length );
  return BLE_STATUS_SUCCESS;
}

tBleStatus aci_gatt_update_char_value_ext( uint16_t Conn_Handle_To_Notify,
                                           uint16_t Service_Handle,
                                           uint16_t Char_Handle,
                                           uint8_t Update_Type,
                                           uint16_t Char_Length,
                                           uint16_t Value_Offset,
                                           uint8_t Value_Length,
                                           const uint8_t* Value )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_update_char_value_ext_cp0 *cp0 = (aci_gatt_update_char_value_ext_cp0*)(cmd_buffer + in_offset);
  cp0->Conn_Handle_To_Notify = Conn_Handle_To_Notify;
  in_offset += 2;
  cp0->Service_Handle = Service_Handle;
  in_offset += 2;
  cp0->Char_Handle = Char_Handle;
  in_offset += 2;
  cp0->Update_Type = Update_Type;
  in_offset += 1;
  cp0->Char_Length = Char_Length;
  in_offset += 2;
  cp0->Value_Offset = Value_Offset;
  in_offset += 2;
  cp0->Value_Length = Value_Length;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Value, (const void*)Value, Value_Length );
  in_offset += Value_Length;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x12c;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_set_access_permission( uint16_t Serv_Handle,
                                           uint16_t Attr_Handle,
                                           uint8_t Access_Permissions )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_set_access_permission_cp0 *cp0 = (aci_gatt_set_access_permission_cp0*)(cmd_buffer + in_offset);
  cp0->Serv_Handle = Serv_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Access_Permissions = Access_Permissions;
  in_offset += 1;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x12e;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_store_db( void )
{
  struct hci_request rq;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x130;
  rq.cparam = 0;
  rq.clen = 0;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_send_mult_notification( uint16_t Connection_Handle,
                                            uint8_t Number_of_Handles,
                                            const Handle_Entry_t* Handle_Entry )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_send_mult_notification_cp0 *cp0 = (aci_gatt_send_mult_notification_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Number_of_Handles = Number_of_Handles;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Handle_Entry, (const void*)Handle_Entry, Number_of_Handles * (sizeof(Handle_Entry_t)) );
  in_offset += Number_of_Handles * (sizeof(Handle_Entry_t));
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x131;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_read_multiple_var_char_value( uint16_t Connection_Handle,
                                                  uint8_t Number_of_Handles,
                                                  const Handle_Entry_t* Handle_Entry )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_read_multiple_var_char_value_cp0 *cp0 = (aci_gatt_read_multiple_var_char_value_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Number_of_Handles = Number_of_Handles;
  in_offset += 1;
  Osal_MemCpy( (void*)&cp0->Handle_Entry, (const void*)Handle_Entry, Number_of_Handles * (sizeof(Handle_Entry_t)) );
  in_offset += Number_of_Handles * (sizeof(Handle_Entry_t));
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x132;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_write_without_resp_ext( uint16_t Connection_Handle,
                                            uint16_t Attr_Handle,
                                            uint8_t Signed_Mode,
                                            uint16_t Data_Length,
                                            uint32_t Data_Pointer )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_write_without_resp_ext_cp0 *cp0 = (aci_gatt_write_without_resp_ext_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Signed_Mode = Signed_Mode;
  in_offset += 1;
  cp0->Data_Length = Data_Length;
  in_offset += 2;
  cp0->Data_Pointer = Data_Pointer;
  in_offset += 4;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x140;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

tBleStatus aci_gatt_write_with_resp_ext( uint16_t Connection_Handle,
                                         uint16_t Attr_Handle,
                                         uint8_t Write_Mode,
                                         uint16_t Val_Offset,
                                         uint16_t Data_Length,
                                         uint32_t Data_Pointer )
{
  struct hci_request rq;
  uint8_t cmd_buffer[BLE_CMD_MAX_PARAM_LEN];
  int in_offset = 0;
  aci_gatt_write_with_resp_ext_cp0 *cp0 = (aci_gatt_write_with_resp_ext_cp0*)(cmd_buffer + in_offset);
  cp0->Connection_Handle = Connection_Handle;
  in_offset += 2;
  cp0->Attr_Handle = Attr_Handle;
  in_offset += 2;
  cp0->Write_Mode = Write_Mode;
  in_offset += 1;
  cp0->Val_Offset = Val_Offset;
  in_offset += 2;
  cp0->Data_Length = Data_Length;
  in_offset += 2;
  cp0->Data_Pointer = Data_Pointer;
  in_offset += 4;
  tBleStatus status = 0;
  rq.ogf = 0x3f;
  rq.ocf = 0x141;
  rq.cparam = cmd_buffer;
  rq.clen = in_offset;
  rq.rparam = &status;
  rq.rlen = 1;
  if ( hci_send_req(&rq, FALSE) < 0 )
    return BLE_STATUS_TIMEOUT;
  return status;
}

