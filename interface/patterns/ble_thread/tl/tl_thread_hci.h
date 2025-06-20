/**
 ******************************************************************************
 * @file    tl_thread_hci.h
 * @author  MCD Application Team
 * @brief   Constants and functions for managing Thread TL
 ******************************************************************************
 * @attention
 *
 * <h2><center>&copy; Copyright (c) 2019 STMicroelectronics.
 * All rights reserved.</center></h2>
 *
 * This software component is licensed by ST under Ultimate Liberty license
 * SLA0044, the "License"; You may not use this file except in compliance with
 * the License. You may obtain a copy of the License at:
 *                             www.st.com/SLA0044
 *
 ******************************************************************************
 */


#ifndef __TL_THREAD_HCI_H_
#define __TL_THREAD_HCI_H_

/* Includes ------------------------------------------------------------------*/
#include "stm32wbxx_hal_def.h"
#include "stm32wbxx_core_interface_def.h"
#include <string.h>


/* Exported functions  ------------------------------------------------------------*/
void Pre_OtCmdProcessing(void);
void Ot_Cmd_Transfer(void);
Thread_OT_Cmd_Request_t* THREAD_Get_OTCmdPayloadBuffer(void);
Thread_OT_Cmd_Request_t* THREAD_Get_OTCmdRspPayloadBuffer(void);
Thread_OT_Cmd_Request_t* THREAD_Get_NotificationPayloadBuffer(void);

/* Exported defines -----------------------------------------------------------*/


#endif /* __TL_THREAD_HCI_H_ */
