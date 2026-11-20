/**
  ******************************************************************************
  * @file    threading_alt.h
  * @author  MCD Application Team
  * @brief   mbedTLS threading alternate backend type definition
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
#ifndef THREADING_ALT_H
#define THREADING_ALT_H

#include <stdint.h>

typedef struct mbedtls_threading_mutex_t
{
  /* Indicates if the mutex is valid */
  uint32_t is_valid;
  /* Pointer to the actual mutex object */
  void * mutex;
} mbedtls_threading_mutex_t;

#endif /* THREADING_ALT_H */
