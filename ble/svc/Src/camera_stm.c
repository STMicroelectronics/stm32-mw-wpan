/**
  ******************************************************************************
  * @file    camera_stm.c
  * @author  MCD Application Team
  * @brief   Camera Service (Custom STM)
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2018-2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */


/* Includes ------------------------------------------------------------------*/
#include "common_blesvc.h"
#include "camera_stm.h"

/* Private typedef -----------------------------------------------------------*/
typedef struct{
  uint16_t	CameraSvcHdle;				        /**< Service handle */
  uint16_t	CAMWriteClientToServerCharHdle;	  /**< Characteristic handle */
  uint16_t	CAMNotifyServerToClientCharHdle;	/**< Characteristic handle */
}CameraContext_t;

/* Private defines -----------------------------------------------------------*/
#define UUID_128_SUPPORTED  1

#if (UUID_128_SUPPORTED == 1)
#define BM_UUID_LENGTH  UUID_TYPE_128
#else
#define BM_UUID_LENGTH  UUID_TYPE_16
#endif

#define BM_REQ_CHAR_SIZE    (3)


/* Private macros ------------------------------------------------------------*/

/* Private variables ---------------------------------------------------------*/
/**
 * Reboot Characteristic UUID
 * 0000fe11-8e22-4541-9d4c-21edae82ed19
 */
#if (UUID_128_SUPPORTED == 1)
const uint8_t BM_REQ_CHAR_UUID[16] = {0x19, 0xed, 0x82, 0xae,
                                       0xed, 0x21, 0x4c, 0x9d,
                                       0x41, 0x45, 0x22, 0x8e,
                                       0x11, 0xFE, 0x00, 0x00};
#else
const uint8_t BM_REQ_CHAR_UUID[2] = {0x11, 0xFE};
#endif

/**
 * START of Section BLE_DRIVER_CONTEXT
 */
#pragma default_variable_attributes = @"BLE_DRIVER_CONTEXT"
static CameraContext_t aCameraContext;
#pragma default_variable_attributes =
/**
 * END of Section BLE_DRIVER_CONTEXT
 */
/* Private function prototypes -----------------------------------------------*/
static SVCCTL_EvtAckStatus_t Camera_Event_Handler(void *Event);


/* Functions Definition ------------------------------------------------------*/
/* Private functions ----------------------------------------------------------*/

#define COPY_UUID_128(uuid_struct, uuid_15, uuid_14, uuid_13, uuid_12, uuid_11, uuid_10, uuid_9, uuid_8, uuid_7, uuid_6, uuid_5, uuid_4, uuid_3, uuid_2, uuid_1, uuid_0) \
do {\
    uuid_struct[0] = uuid_0; uuid_struct[1] = uuid_1; uuid_struct[2] = uuid_2; uuid_struct[3] = uuid_3; \
        uuid_struct[4] = uuid_4; uuid_struct[5] = uuid_5; uuid_struct[6] = uuid_6; uuid_struct[7] = uuid_7; \
            uuid_struct[8] = uuid_8; uuid_struct[9] = uuid_9; uuid_struct[10] = uuid_10; uuid_struct[11] = uuid_11; \
                uuid_struct[12] = uuid_12; uuid_struct[13] = uuid_13; uuid_struct[14] = uuid_14; uuid_struct[15] = uuid_15; \
}while(0)

/* Hardware Characteristics Service */
/*
 The following 128bits UUIDs have been generated from the random UUID
 generator:
 D973F2E0-B19E-11E2-9E96-0800200C9A66: Service 128bits UUID
 D973F2E1-B19E-11E2-9E96-0800200C9A66: Characteristic_1 128bits UUID
 D973F2E2-B19E-11E2-9E96-0800200C9A66: Characteristic_2 128bits UUID
 */
#define COPY_CAM_SERVICE_UUID(uuid_struct)       COPY_UUID_128(uuid_struct,0x00,0x00,0xfe,0xa0,0xcc,0x7a,0x48,0x2a,0x98,0x4a,0x7f,0x2e,0xd5,0xb3,0xe5,0x8f)
#define COPY_CAM_WRITE_CHAR_UUID(uuid_struct)    COPY_UUID_128(uuid_struct,0x00,0x00,0xfe,0xa1,0x8e,0x22,0x45,0x41,0x9d,0x4c,0x21,0xed,0xae,0x82,0xed,0x19)
#define COPY_CAM_NOTIFY_UUID(uuid_struct)        COPY_UUID_128(uuid_struct,0x00,0x00,0xfe,0xa2,0x8e,0x22,0x45,0x41,0x9d,0x4c,0x21,0xed,0xae,0x82,0xed,0x19)



/**
 * @brief  Event handler
 * @param  Event: Address of the buffer holding the Event
 * @retval Ack: Return whether the Event has been managed or not
 */
static SVCCTL_EvtAckStatus_t Camera_Event_Handler(void *Event)
{
  SVCCTL_EvtAckStatus_t return_value;
  hci_event_pckt *event_pckt;
  evt_blecore_aci *blecore_evt;
  aci_gatt_attribute_modified_event_rp0    * attribute_modified;
  CAMS_STM_App_Notification_evt_t Notification;

  return_value = SVCCTL_EvtNotAck;
  event_pckt = (hci_event_pckt *)(((hci_uart_pckt*)Event)->data);

  switch(event_pckt->evt)
  {
    case HCI_VENDOR_SPECIFIC_DEBUG_EVT_CODE:
    {
      blecore_evt = (evt_blecore_aci*)event_pckt->data;
      switch(blecore_evt->ecode)
      {
        case ACI_GATT_ATTRIBUTE_MODIFIED_VSEVT_CODE:
       {
          attribute_modified = (aci_gatt_attribute_modified_event_rp0*)blecore_evt->data;
            if(attribute_modified->Attr_Handle == (aCameraContext.CAMNotifyServerToClientCharHdle + 2))
            {
              /**
               * Descriptor handle
               */
              return_value = SVCCTL_EvtAckFlowEnable;
              /**
               * Notify to application
               */
              if(attribute_modified->Attr_Data[0] & COMSVC_Notification)
              {
                Notification.CAM_Evt_Opcode = CAMS_STM_NOTIFY_ENABLED_EVT;
                Camera_STM_App_Notification(&Notification);

              }
              else
              {
                Notification.CAM_Evt_Opcode = CAMS_STM_NOTIFY_DISABLED_EVT;

                Camera_STM_App_Notification(&Notification);

              }
            }            
            else if(attribute_modified->Attr_Handle == (aCameraContext.CAMWriteClientToServerCharHdle + 1))
            {
              BLE_DBG_P2P_STM_MSG("-- GATT : LED CONFIGURATION RECEIVED\n");
              Notification.CAM_Evt_Opcode = CAMS_STM_WRITE_EVT;
              Notification.DataTransfered.Length=attribute_modified->Attr_Data_Length;
              Notification.DataTransfered.pPayload=attribute_modified->Attr_Data;
              Camera_STM_App_Notification(&Notification);  
            }          
     
        }
        break;

        case ACI_GATT_TX_POOL_AVAILABLE_VSEVT_CODE:
          Notification.CAM_Evt_Opcode = CAMS_STM_BLE_TX_READY;
          Camera_STM_App_Notification(&Notification);  
          break; 
          
        default:
          break;
      }
    }
    break; /* HCI_HCI_VENDOR_SPECIFIC_DEBUG_EVT_CODE_SPECIFIC */

    default:
      break;
  }

  return(return_value);
}/* end SVCCTL_EvtAckStatus_t */


/* Public functions ----------------------------------------------------------*/

/**
 * @brief  Service initialization
 * @param  None
 * @retval None
 */
void SVCCTL_InitCustomSvc(void)
{
 
  Char_UUID_t  uuid16;

  /**
   *	Register the event handler to the BLE controller
   */
  SVCCTL_RegisterSvcHandler(Camera_Event_Handler);
  
    /**
     *  Peer To Peer Service
     *
     * Max_Attribute_Records = 2*no_of_char + 1
     * service_max_attribute_record = 1 for Peer To Peer service +
     *                                2 for P2P Write characteristic +
     *                                2 for P2P Notify characteristic +
     *                                1 for client char configuration descriptor +
     *                                
     */
    COPY_CAM_SERVICE_UUID(uuid16.Char_UUID_128);
    aci_gatt_add_service(UUID_TYPE_128,
                      (Service_UUID_t *) &uuid16,
                      PRIMARY_SERVICE,
                      8,
                      &(aCameraContext.CameraSvcHdle));

    /**
     *  Add LED Characteristic
     */
    COPY_CAM_WRITE_CHAR_UUID(uuid16.Char_UUID_128);
    aci_gatt_add_char(aCameraContext.CameraSvcHdle,
                      UUID_TYPE_128, &uuid16,
                      1,                                   
                      CHAR_PROP_WRITE|CHAR_PROP_READ,
                      ATTR_PERMISSION_NONE,
                      GATT_NOTIFY_ATTRIBUTE_WRITE, /* gattEvtMask */
                      10, /* encryKeySize */
                      1, /* isVariable */
                      &(aCameraContext.CAMWriteClientToServerCharHdle));

    /**
     *   Add Button Characteristic
     */
    COPY_CAM_NOTIFY_UUID(uuid16.Char_UUID_128);
    aci_gatt_add_char(aCameraContext.CameraSvcHdle,
                      UUID_TYPE_128, &uuid16,
                      CFG_PACKET_SIZE_CAMERA_DATA,
                      CHAR_PROP_NOTIFY,
                      ATTR_PERMISSION_NONE,
                      GATT_NOTIFY_ATTRIBUTE_WRITE, /* gattEvtMask */
                      10, /* encryKeySize */
                      1, /* isVariable: 1 */
                      &(aCameraContext.CAMNotifyServerToClientCharHdle));


    
  return;
}

/**
 * @brief  Characteristic update
 * @param  UUID: UUID of the characteristic
 * @param  Service_Instance: Instance of the service to which the characteristic belongs
 * 
 */
tBleStatus Camera_STM_App_Update_Char(uint16_t UUID, uint8_t *pPayload, uint8_t len) 
{
  tBleStatus result = BLE_STATUS_INVALID_PARAMS;
  switch(UUID)
  {
    case CAM_NOTIFY_CHAR_UUID:
      
     result = aci_gatt_update_char_value(aCameraContext.CameraSvcHdle,
                             aCameraContext.CAMNotifyServerToClientCharHdle,
                              0, /* charValOffset */
                             len,/* charValueLen */
                             (uint8_t *)  pPayload);
    
      break;

    default:
      break;
  }

  return result;
}


