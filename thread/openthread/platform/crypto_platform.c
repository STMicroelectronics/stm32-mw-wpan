/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    crypto_platform.c
  * @author  MCD Application Team
  * @brief   This file implements part of the OpenThread crypto platform abstraction
  * Functions replace weak function of crypto_platform.cpp file
  *          UART communication.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2023 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

#include "openthread-core-config.h"
#include "stm32wba-mbedtls-config.h"
#include <string.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "error.h"
#include "platform/misc.h"
#include "platform/entropy.h"
#include "platform/crypto.h"


#if (OPENTHREAD_CONFIG_CRYPTO_LIB == OPENTHREAD_CONFIG_CRYPTO_LIB_PSA)
#include <psa/crypto.h>
#endif

#if OPENTHREAD_CONFIG_CRYPTO_LIB == OPENTHREAD_CONFIG_CRYPTO_LIB_MBEDTLS

#if (!defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES) && \
     (!defined(MBEDTLS_NO_PLATFORM_ENTROPY) || defined(MBEDTLS_HAVEGE_C) || defined(MBEDTLS_ENTROPY_HARDWARE_ALT)))
#define OT_MBEDTLS_STRONG_DEFAULT_ENTROPY_PRESENT
#endif

#if !OPENTHREAD_RADIO
/**
 * Below context structures depend of mbedtls config they cannot be integrated in openthread lib 
 * For example matter has capability MBEDTLS_THREADING_C where as OT hasn't by default
 *
 */
static mbedtls_ctr_drbg_context sCtrDrbgContext;
static mbedtls_entropy_context  sEntropyContext;
#ifndef OT_MBEDTLS_STRONG_DEFAULT_ENTROPY_PRESENT
static uint16_t kEntropyMinThreshold = 16;
#endif
#endif

#ifndef OT_MBEDTLS_STRONG_DEFAULT_ENTROPY_PRESENT

static int handleMbedtlsEntropyPoll(void *aData, unsigned char *aOutput, size_t aInLen, size_t *aOutLen)
{
    int rval = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;

    if (otPlatEntropyGet((uint8_t *)(aOutput), (uint16_t)(aInLen)) == 0)
    {
      rval = 0;
    }
    
    if (aOutLen != NULL)
    {
      *aOutLen = aInLen;
    }

    OT_UNUSED_VARIABLE(aData);
    return rval;
}

#endif // OT_MBEDTLS_STRONG_DEFAULT_ENTROPY_PRESENT

void otPlatCryptoRandomInit(void)
{
    mbedtls_entropy_init(&sEntropyContext);

#ifndef OT_MBEDTLS_STRONG_DEFAULT_ENTROPY_PRESENT
    mbedtls_entropy_add_source(&sEntropyContext, handleMbedtlsEntropyPoll, NULL, kEntropyMinThreshold,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);
#endif

    mbedtls_ctr_drbg_init(&sCtrDrbgContext);

    int rval = mbedtls_ctr_drbg_seed(&sCtrDrbgContext, mbedtls_entropy_func, &sEntropyContext, NULL, 0);
    if (rval != 0)
    {
      otPlatAssertFail(NULL,0);
    }
}

void otPlatCryptoRandomDeinit(void)
{
    mbedtls_entropy_free(&sEntropyContext);
    mbedtls_ctr_drbg_free(&sCtrDrbgContext);
}

otError otPlatCryptoRandomGet(uint8_t *aBuffer, uint16_t aSize)
{
  otError error = OT_ERROR_NONE;

  if (mbedtls_ctr_drbg_random(&sCtrDrbgContext, aBuffer, (size_t)(aSize)) != 0)
  {
    error = OT_ERROR_FAILED;
  }

  return error;
}
#elif OPENTHREAD_CONFIG_CRYPTO_LIB == OPENTHREAD_CONFIG_CRYPTO_LIB_PSA

#include "mbedtls/asn1.h"

#if !defined(PSA_USE_ITS_ALT)
extern void psa_its_init(void);
#endif /*#if !defined(PSA_USE_ITS_ALT)*/

static otError PsaToOtError(psa_status_t aStatus)
{
    otError error;

    switch (aStatus)
    {
    case PSA_SUCCESS:
        error = OT_ERROR_NONE;
        break;
    case PSA_ERROR_INVALID_ARGUMENT:
        error = OT_ERROR_INVALID_ARGS;
        break;
    case PSA_ERROR_BUFFER_TOO_SMALL:
        error = OT_ERROR_NO_BUFS;
        break;
    default:
        error = OT_ERROR_FAILED;
        break;
    }

    return error;
}

static psa_key_type_t ToPsaKeyType(otCryptoKeyType aType)
{
    psa_key_type_t type;

    switch (aType)
    {
    case OT_CRYPTO_KEY_TYPE_RAW:
        type = PSA_KEY_TYPE_RAW_DATA;
        break;
    case OT_CRYPTO_KEY_TYPE_AES:
        type = PSA_KEY_TYPE_AES;
        break;
    case OT_CRYPTO_KEY_TYPE_HMAC:
        type = PSA_KEY_TYPE_HMAC;
        break;
    case OT_CRYPTO_KEY_TYPE_ECDSA:
        type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        break;
    case OT_CRYPTO_KEY_TYPE_DERIVE:
        type = PSA_KEY_TYPE_DERIVE;
        break;
    default:
        type = PSA_KEY_TYPE_NONE;
        break;
    }

    return type;
}

static psa_algorithm_t ToPsaAlgorithm(otCryptoKeyAlgorithm aAlgorithm)
{
    psa_algorithm_t algorithm;

    switch (aAlgorithm)
    {
    case OT_CRYPTO_KEY_ALG_AES_ECB:
        algorithm = PSA_ALG_ECB_NO_PADDING;
        break;
    case OT_CRYPTO_KEY_ALG_HMAC_SHA_256:
        algorithm = PSA_ALG_HMAC(PSA_ALG_SHA_256);
        break;
    case OT_CRYPTO_KEY_ALG_ECDSA:
        algorithm = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
        break;
    case OT_CRYPTO_KEY_ALG_HKDF_SHA256:
        algorithm = PSA_ALG_HKDF(PSA_ALG_SHA_256);
        break;
    default:
        algorithm = PSA_ALG_NONE;
        break;
    }

    return algorithm;
}

static psa_key_usage_t ToPsaKeyUsage(int aUsage)
{
    psa_key_usage_t usage = 0;

    if (aUsage & OT_CRYPTO_KEY_USAGE_EXPORT)
    {
        usage |= PSA_KEY_USAGE_EXPORT;
    }

    if (aUsage & OT_CRYPTO_KEY_USAGE_ENCRYPT)
    {
        usage |= PSA_KEY_USAGE_ENCRYPT;
    }

    if (aUsage & OT_CRYPTO_KEY_USAGE_DECRYPT)
    {
        usage |= PSA_KEY_USAGE_DECRYPT;
    }

    if (aUsage & OT_CRYPTO_KEY_USAGE_SIGN_HASH)
    {
        usage |= PSA_KEY_USAGE_SIGN_HASH;
    }

    if (aUsage & OT_CRYPTO_KEY_USAGE_VERIFY_HASH)
    {
        usage |= PSA_KEY_USAGE_VERIFY_HASH;
    }

    if (aUsage & OT_CRYPTO_KEY_USAGE_DERIVE)
    {
        usage |= PSA_KEY_USAGE_DERIVE;
    }

    return usage;
}

static otError ValidateKeyUsage(int aUsage)
{
    otError error = OT_ERROR_NONE;

    // Check if only supported flags have been passed
    static int supportedFlags = OT_CRYPTO_KEY_USAGE_EXPORT | OT_CRYPTO_KEY_USAGE_ENCRYPT |
                                OT_CRYPTO_KEY_USAGE_DECRYPT | OT_CRYPTO_KEY_USAGE_SIGN_HASH |
                                OT_CRYPTO_KEY_USAGE_VERIFY_HASH | OT_CRYPTO_KEY_USAGE_DERIVE;

    if ((aUsage & ~supportedFlags) != 0)
    {
      error = OT_ERROR_INVALID_ARGS;
    }

    return error;
}

static otError ExtractPrivateKeyInfo(const uint8_t *aAsn1KeyPair,
                                     size_t         aAsn1KeyPairLen,
                                     size_t        *aKeyOffset,
                                     size_t        *aKeyLen)
{
    int                  ret;
    otError              error = OT_ERROR_NONE;
    unsigned char       *p     = (unsigned char *)aAsn1KeyPair;
    const unsigned char *end   = p + aAsn1KeyPairLen;
    size_t               len;

    // Parse the ASN.1 SEQUENCE headers
    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    
    if (ret != 0)
    {
      error = OT_ERROR_INVALID_ARGS;
    }
    else
    {
      // Parse the version (INTEGER)
      ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER);
      
      if (ret != 0)
      {
        error = OT_ERROR_INVALID_ARGS;
      }
      else
      {
        // Skip the version.
        p += len;

        // Parse the private key (OCTET STRING)
        ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
        
        if (ret != 0)
        {
          error = OT_ERROR_INVALID_ARGS;
        }
        else
        {
          // Check if the private key includes a padding byte (0x00)
          if (*p == 0x00)
          {
              p++;
              len--; // Skip the padding byte and reduce length by 1
          }

          *aKeyOffset = (p - aAsn1KeyPair);
          *aKeyLen    = len;
        }
      }
    }

    return error;
}

void otPlatCryptoInit(void)
{
#if !defined(PSA_USE_ITS_ALT)
  psa_its_init();
#endif /*#if !defined(PSA_USE_ITS_ALT)*/
  psa_crypto_init();
  //otPlatLog(OT_LOG_LEVEL_INFO, OT_LOG_REGION_PLATFORM, "psa_crypto initialized");
}

otError otPlatCryptoImportKey(otCryptoKeyRef      *aKeyRef,
                              otCryptoKeyType      aKeyType,
                              otCryptoKeyAlgorithm aKeyAlgorithm,
                              int                  aKeyUsage,
                              otCryptoKeyStorage   aKeyPersistence,
                              const uint8_t       *aKey,
                              size_t               aKeyLen)
{
    otError                error      = OT_ERROR_NONE;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    error = ValidateKeyUsage(aKeyUsage);
    
    if (OT_ERROR_NONE == error)
    {
      if ((aKeyRef == NULL) ||
          (aKey == NULL))
      {
        error = OT_ERROR_INVALID_ARGS;
      }
      else
      {
        // PSA Crypto API expects the private key to be provided, not the full ASN1 buffer.
        if (aKeyType == OT_CRYPTO_KEY_TYPE_ECDSA)
        {
          size_t pkOffset;
          size_t pkLength;

          error = ExtractPrivateKeyInfo(aKey, aKeyLen, &pkOffset, &pkLength);
          
          if (OT_ERROR_NONE == error)
          {
            // Overwrite the content of the key.
            aKey += pkOffset;
            aKeyLen = pkLength;

            psa_set_key_bits(&attributes, 256);            
          }
          else
          {
            /* Do nothing, error is already set */
          }
        }
        
        if (OT_ERROR_NONE == error)
        {
          psa_set_key_type(&attributes, ToPsaKeyType(aKeyType));
          psa_set_key_algorithm(&attributes, ToPsaAlgorithm(aKeyAlgorithm));
          psa_set_key_usage_flags(&attributes, ToPsaKeyUsage(aKeyUsage));

          switch (aKeyPersistence)
          {
          case OT_CRYPTO_KEY_STORAGE_PERSISTENT:
              psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
              psa_set_key_id(&attributes, *aKeyRef);
              break;
          case OT_CRYPTO_KEY_STORAGE_VOLATILE:
              psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
              break;
          default:
              otPlatAssertFail(NULL,0);
          }

          if (OT_ERROR_NONE == error)
          {
            error = PsaToOtError(psa_import_key(&attributes, aKey, aKeyLen, aKeyRef));
          }
        }
      }
    }

    psa_reset_key_attributes(&attributes);

    return error;
}

otError otPlatCryptoExportKey(otCryptoKeyRef aKeyRef, uint8_t *aBuffer, size_t aBufferLen, size_t *aKeyLen)
{
    otError error = OT_ERROR_NONE;
    
    if ((aBuffer == NULL) || 
        (aKeyLen == NULL))
    {
      error = OT_ERROR_INVALID_ARGS;
    }
    else
    {
      error = PsaToOtError(psa_export_key(aKeyRef, aBuffer, aBufferLen, aKeyLen));
    }
    
    return error;
}

#endif // #if OPENTHREAD_CONFIG_CRYPTO_LIB == OPENTHREAD_CONFIG_CRYPTO_LIB_MBEDTLS