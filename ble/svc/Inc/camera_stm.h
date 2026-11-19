/**
  ******************************************************************************
  *  @file   camera_stm.h
  * @author  MCD Application Team
  * @brief   Header for camera_stm.c module
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


/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __CAMS_STM_H
#define __CAMS_STM_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/

 
  
/* Exported types ------------------------------------------------------------*/
typedef enum
{
  CAMS_STM_NOTIFY_ENABLED_EVT,
  CAMS_STM_NOTIFY_DISABLED_EVT,
  CAMS_STM_READ_EVT,
  CAMS_STM_WRITE_EVT,
  CAMS_STM_BOOT_REQUEST_EVT,
  CAMS_STM_BLE_TX_READY,
} CAMS_STM_Opcode_evt_t;

typedef struct
{
  uint8_t * pPayload;
  uint8_t     Length;
}CAMS_STM_Data_t;  

typedef struct
{
  CAMS_STM_Opcode_evt_t     CAM_Evt_Opcode;
  CAMS_STM_Data_t           DataTransfered;
  uint16_t                  ConnectionHandle;
  uint8_t                   ServiceInstance;
}CAMS_STM_App_Notification_evt_t;


/* Exported constants --------------------------------------------------------*/
/* External variables --------------------------------------------------------*/
/* Exported macros -----------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
void SVCCTL_InitCustomSvc( void );
void Camera_STM_App_Notification(CAMS_STM_App_Notification_evt_t *pNotification);
tBleStatus Camera_STM_App_Update_Char(uint16_t UUID,  uint8_t *pPayload, uint8_t len);


#ifdef __cplusplus
}
#endif

#endif /*__CAMS_STM_H */


