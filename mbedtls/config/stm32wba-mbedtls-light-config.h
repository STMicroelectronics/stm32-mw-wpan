#ifndef STM32WBA_MBEDTLS_CONFIG_H
#define STM32WBA_MBEDTLS_CONFIG_H

#include "stm32wbaxx.h"

/* -------------------------------------------------------------------------- */
/* System support and platform constraints                                    */
/* -------------------------------------------------------------------------- */

/**
 * \def MBEDTLS_HAVE_ASM
 *
 * The compiler has support for asm().
 *
 * Requires support for asm() in compiler.
 *
 * Comment to disable the use of assembly code.
 */
#define MBEDTLS_HAVE_ASM

/**
 * \def MBEDTLS_NO_PLATFORM_ENTROPY
 *
 * Do not use built-in platform entropy functions.
 * This is useful if your platform does not support
 * standards like the /dev/urandom or Windows CryptoAPI.
 *
 * Uncomment this macro to disable the built-in platform entropy functions.
 */
#define MBEDTLS_NO_PLATFORM_ENTROPY

/**
 * \def MBEDTLS_PLATFORM_MEMORY
 *
 * Enable the memory allocation layer.
 *
 * By default mbed TLS uses the system-provided calloc() and free().
 * This allows different allocators (self-implemented or provided) to be
 * provided to the platform abstraction layer.
 *
 * Enabling MBEDTLS_PLATFORM_MEMORY without the
 * MBEDTLS_PLATFORM_{FREE,CALLOC}_MACROs will provide
 * "mbedtls_platform_set_calloc_free()" allowing you to set an alternative calloc() and
 * free() function pointer at runtime.
 *
 * Enabling MBEDTLS_PLATFORM_MEMORY and specifying
 * MBEDTLS_PLATFORM_{CALLOC,FREE}_MACROs will allow you to specify the
 * alternate function at compile time.
 *
 * Requires: MBEDTLS_PLATFORM_C
 *
 * Enable this layer to allow use of alternative memory allocators.
 */
#define MBEDTLS_PLATFORM_MEMORY

/* -------------------------------------------------------------------------- */
/* PSA and core Mbed TLS behavior                                             */
/* -------------------------------------------------------------------------- */

/**
 * \def MBEDTLS_USE_PSA_CRYPTO
 *
 * Make the X.509 and TLS libraries use PSA for cryptographic operations as
 * much as possible, and enable new APIs for using keys handled by PSA Crypto.
 *
 * \note Development of this option is currently in progress, and parts of Mbed
 * TLS's X.509 and TLS modules are not ported to PSA yet. However, these parts
 * will still continue to work as usual, so enabling this option should not
 * break backwards compatibility.
 *
 * \warning If you enable this option, you need to call `psa_crypto_init()`
 * before calling any function from the SSL/TLS, X.509 or PK modules, except
 * for the various mbedtls_xxx_init() functions which can be called at any time.
 *
 * \warning In multithreaded applications, you must also enable
 * #MBEDTLS_THREADING_C, unless only one thread ever calls PSA functions
 * (`psa_xxx()`), including indirect calls through SSL/TLS, X.509 or PK.
 *
 * \note An important and desirable effect of this option is that it allows
 * PK, X.509 and TLS to take advantage of PSA drivers. For example, enabling
 * this option is what allows use of drivers for ECDSA, ECDH and EC J-PAKE in
 * those modules. However, note that even with this option disabled, some code
 * in PK, X.509, TLS or the crypto library might still use PSA drivers, if it
 * can determine it's safe to do so; currently that's the case for hashes.
 *
 * \note See docs/use-psa-crypto.md for a complete description this option.
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C.
 *
 * Uncomment this to enable internal use of PSA Crypto and new associated APIs.
 */
#define MBEDTLS_USE_PSA_CRYPTO

/** \def MBEDTLS_PSA_CRYPTO_CLIENT
 *
 * Enable support for PSA crypto client.
 *
 * \note This option allows to include the code necessary for a PSA
 *       crypto client when the PSA crypto implementation is not included in
 *       the library (MBEDTLS_PSA_CRYPTO_C disabled). The code included is the
 *       code to set and get PSA key attributes.
 *       The development of PSA drivers partially relying on the library to
 *       fulfill the hardware gaps is another possible usage of this option.
 *
 * \warning This interface is experimental and may change or be removed
 * without notice.
 */
#define MBEDTLS_PSA_CRYPTO_CLIENT

/**
 * \def MBEDTLS_PSA_CRYPTO_CONFIG
 *
 * This setting allows support for cryptographic mechanisms through the PSA
 * API to be configured separately from support through the mbedtls API.
 *
 * When this option is disabled, the PSA API exposes the cryptographic
 * mechanisms that can be implemented on top of the `mbedtls_xxx` API
 * configured with `MBEDTLS_XXX` symbols.
 *
 * When this option is enabled, the PSA API exposes the cryptographic
 * mechanisms requested by the `PSA_WANT_XXX` symbols defined in
 * include/psa/crypto_config.h. The corresponding `MBEDTLS_XXX` settings are
 * automatically enabled if required (i.e. if no PSA driver provides the
 * mechanism). You may still freely enable additional `MBEDTLS_XXX` symbols
 * in mbedtls_config.h.
 *
 * If the symbol #MBEDTLS_PSA_CRYPTO_CONFIG_FILE is defined, it specifies
 * an alternative header to include instead of include/psa/crypto_config.h.
 *
 * \warning This option is experimental, in that the set of `PSA_WANT_XXX`
 *          symbols is not completely finalized yet, and the configuration
 *          tooling is not ideally adapted to having two separate configuration
 *          files.
 *          Future minor releases of Mbed TLS may make minor changes to those
 *          symbols, but we will endeavor to provide a transition path.
 *          Nonetheless, this option is considered mature enough to use in
 *          production, as long as you accept that you may need to make
 *          minor changes to psa/crypto_config.h when upgrading Mbed TLS.
 */
#define MBEDTLS_PSA_CRYPTO_CONFIG

/**
 * \def MBEDTLS_MD_SOME_PSA
 *
 * Enable partial use of PSA drivers in the message-digest layer when available.
 */
#define MBEDTLS_MD_SOME_PSA

#if !defined(MBEDTLS_RSA_GEN_KEY_MIN_BITS)
#define MBEDTLS_RSA_GEN_KEY_MIN_BITS 1024
#endif /*!defined(MBEDTLS_RSA_GEN_KEY_MIN_BITS)*/

/* -------------------------------------------------------------------------- */
/* Threading                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * \def MBEDTLS_THREADING_C
 *
 * Enable the threading abstraction layer.
 *
 * Traditionally, Mbed TLS assumes it is used in a non-threaded environment or
 * that contexts are not shared between threads. If you do intend to use contexts
 * between threads, you will need to enable this layer to prevent race
 * conditions.
 *
 * The PSA subsystem has an implicit shared context. Therefore, you must
 * enable this option if more than one thread may use any part of
 * Mbed TLS that is implemented on top of the PSA subsystem.
 *
 * See also our Knowledge Base article about threading:
 * https://mbed-tls.readthedocs.io/en/latest/kb/development/thread-safety-and-multi-threading
 *
 * Module:  library/threading.c
 *
 * You will have to enable either MBEDTLS_THREADING_ALT or
 * MBEDTLS_THREADING_PTHREAD.
 */
#define MBEDTLS_THREADING_C

/**
 * \def MBEDTLS_THREADING_ALT
 *
 * Provide your own alternate implementation of threading primitives
 * for mutexes. If you enable this option:
 *
 * - Provide a header file "threading_alt.h", defining the
 *   type mbedtls_threading_mutex_t of mutex objects.
 *
 * - Call mbedtls_threading_set_alt() in your application
 *   before calling any other library function.
 *
 * Requires: MBEDTLS_THREADING_C
 */
#define MBEDTLS_THREADING_ALT

/* -------------------------------------------------------------------------- */
/* Cipher layer options                                                        */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* ECC curves and key exchange options                                         */
/* -------------------------------------------------------------------------- */

/**
 * \def MBEDTLS_ECP_DP_SECP192R1_ENABLED
 *
 * MBEDTLS_ECP_XXXX_ENABLED: Enables specific curves within the Elliptic Curve
 * module.  By default all supported curves are enabled.
 *
 * Comment macros to disable the curve and functions for it
 */
/* Short Weierstrass curves (supporting ECP, ECDH, ECDSA) */
//#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
//#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
//#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
//#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
//#define MBEDTLS_ECP_DP_SECP192K1_ENABLED
//#define MBEDTLS_ECP_DP_SECP224K1_ENABLED
//#define MBEDTLS_ECP_DP_SECP256K1_ENABLED
//#define MBEDTLS_ECP_DP_BP256R1_ENABLED
//#define MBEDTLS_ECP_DP_BP384R1_ENABLED
//#define MBEDTLS_ECP_DP_BP512R1_ENABLED
/* Montgomery curves (supporting ECP) */
//#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
//#define MBEDTLS_ECP_DP_CURVE448_ENABLED

/**
 * \def MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
 *
 * Enable the ECJPAKE based ciphersuite modes in SSL / TLS.
 *
 * \warning This is currently experimental. EC J-PAKE support is based on the
 * Thread v1.0.0 specification; incompatible changes to the specification
 * might still happen. For this reason, this is disabled by default.
 *
 * Requires: MBEDTLS_ECJPAKE_C or (MBEDTLS_USE_PSA_CRYPTO and PSA_WANT_ALG_JPAKE)
 *           SHA-256 (via MBEDTLS_SHA256_C or a PSA driver)
 *           MBEDTLS_ECP_DP_SECP256R1_ENABLED
 *
 * \warning If SHA-256 is provided only by a PSA driver, you must call
 * psa_crypto_init() before the first handshake (even if
 * MBEDTLS_USE_PSA_CRYPTO is disabled).
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8
 */
#define MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/* Mirrored enabled options from mbedtls_config.h                              */
/* -------------------------------------------------------------------------- */

/**
 * \def MBEDTLS_AES_C
 *
 * Enable the AES block cipher.
 *
 * Module:  library/aes.c
 * Caller:  library/cipher.c
 *          library/pem.c
 *          library/ctr_drbg.c
 *
 * This module enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256
 *      MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA
 *
 * PEM_PARSE uses AES for decrypting encrypted keys.
 */
#define MBEDTLS_AES_C

/**
 * \def MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
 *
 * Use only 128-bit keys in AES operations to save ROM.
 *
 * Uncomment this macro to remove support for AES operations that use 192-
 * or 256-bit keys.
 *
 * Uncommenting this macro reduces the size of AES code by ~300 bytes
 * on v8-M/Thumb2.
 *
 * Module:  library/aes.c
 *
 * Requires: MBEDTLS_AES_C
 */
#define MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH

/**
 * \def MBEDTLS_AESCE_C
 *
 * Enable AES cryptographic extension support on Armv8.
 *
 * Module:  library/aesce.c
 * Caller:  library/aes.c
 *
 * Requires: MBEDTLS_AES_C
 *
 * \warning Runtime detection only works on Linux. For non-Linux operating
 *          system, Armv8-A Cryptographic Extensions must be supported by
 *          the CPU when this option is enabled.
 *
 * \note    Minimum compiler versions for this feature when targeting aarch64
 *          are Clang 4.0; armclang 6.6; GCC 6.0; or MSVC 2019 version 16.11.2.
 *          Minimum compiler versions for this feature when targeting 32-bit
 *          Arm or Thumb are Clang 11.0; armclang 6.20; or GCC 6.0.
 *
 * \note \c CFLAGS must be set to a minimum of \c -march=armv8-a+crypto for
 * armclang <= 6.9
 *
 * This module adds support for the AES Armv8-A Cryptographic Extensions on Armv8 systems.
 */
#define MBEDTLS_AESCE_C

/**
 * \def MBEDTLS_ASN1_PARSE_C
 *
 * Enable the generic ASN1 parser.
 *
 * Module:  library/asn1.c
 * Caller:  library/x509.c
 *          library/dhm.c
 *          library/pkcs12.c
 *          library/pkcs5.c
 *          library/pkparse.c
 */
#define MBEDTLS_ASN1_PARSE_C

/**
 * \def MBEDTLS_ASN1_WRITE_C
 *
 * Enable the generic ASN1 writer.
 *
 * Module:  library/asn1write.c
 * Caller:  library/ecdsa.c
 *          library/pkwrite.c
 *          library/x509_create.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 */
#define MBEDTLS_ASN1_WRITE_C

/**
 * \def MBEDTLS_BASE64_C
 *
 * Enable the Base64 module.
 *
 * Module:  library/base64.c
 * Caller:  library/pem.c
 *
 * This module is required for PEM support (required by X.509).
 */
#define MBEDTLS_BASE64_C

/**
 * \def MBEDTLS_BIGNUM_C
 *
 * Enable the multi-precision integer library.
 *
 * Module:  library/bignum.c
 *          library/bignum_core.c
 *          library/bignum_mod.c
 *          library/bignum_mod_raw.c
 * Caller:  library/dhm.c
 *          library/ecp.c
 *          library/ecdsa.c
 *          library/rsa.c
 *          library/rsa_alt_helpers.c
 *          library/ssl_tls.c
 *
 * This module is required for RSA, DHM and ECC (ECDH, ECDSA) support.
 */
#define MBEDTLS_BIGNUM_C

/**
 * \def MBEDTLS_CCM_C
 *
 * Enable the Counter with CBC-MAC (CCM) mode for 128-bit block cipher.
 *
 * Module:  library/ccm.c
 *
 * Requires: MBEDTLS_CIPHER_C, MBEDTLS_AES_C or MBEDTLS_CAMELLIA_C or
 *                             MBEDTLS_ARIA_C
 *
 * This module enables the AES-CCM ciphersuites, if other requisites are
 * enabled as well.
 */
#define MBEDTLS_CCM_C

/**
 * \def MBEDTLS_CIPHER_C
 *
 * Enable the generic cipher layer.
 *
 * Module:  library/cipher.c
 * Caller:  library/ccm.c
 *          library/cmac.c
 *          library/gcm.c
 *          library/nist_kw.c
 *          library/pkcs12.c
 *          library/pkcs5.c
 *          library/psa_crypto_aead.c
 *          library/psa_crypto_mac.c
 *          library/ssl_ciphersuites.c
 *          library/ssl_msg.c
 *          library/ssl_ticket.c (unless MBEDTLS_USE_PSA_CRYPTO is enabled)
 * Auto-enabled by: MBEDTLS_PSA_CRYPTO_C depending on which ciphers are enabled
 *                  (see the documentation of that option for details).
 *
 * Uncomment to enable generic cipher wrappers.
 */
#define MBEDTLS_CIPHER_C

/**
 * \def MBEDTLS_CMAC_C
 *
 * Enable the CMAC (Cipher-based Message Authentication Code) mode for block
 * ciphers.
 *
 * \note When #MBEDTLS_CMAC_ALT is active, meaning that the underlying
 *       implementation of the CMAC algorithm is provided by an alternate
 *       implementation, that alternate implementation may opt to not support
 *       AES-192 or 3DES as underlying block ciphers for the CMAC operation.
 *
 * Module:  library/cmac.c
 *
 * Requires: MBEDTLS_CIPHER_C, MBEDTLS_AES_C or MBEDTLS_DES_C
 *
 */
#define MBEDTLS_CMAC_C


/** \def MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
 *
 * Make the PSA Crypto module use an external random generator provided
 * by a driver, instead of Mbed TLS's entropy and DRBG modules.
 *
 * \note This random generator must deliver random numbers with cryptographic
 *       quality and high performance. It must supply unpredictable numbers
 *       with a uniform distribution. The implementation of this function
 *       is responsible for ensuring that the random generator is seeded
 *       with sufficient entropy. If you have a hardware TRNG which is slow
 *       or delivers non-uniform output, declare it as an entropy source
 *       with mbedtls_entropy_add_source() instead of enabling this option.
 *
 * If you enable this option, you must configure the type
 * ::mbedtls_psa_external_random_context_t in psa/crypto_platform.h
 * and define a function called mbedtls_psa_external_get_random()
 * with the following prototype:
 * ```
 * psa_status_t mbedtls_psa_external_get_random(
 *     mbedtls_psa_external_random_context_t *context,
 *     uint8_t *output, size_t output_size, size_t *output_length);
 * );
 * ```
 * The \c context value is initialized to 0 before the first call.
 * The function must fill the \c output buffer with \c output_size bytes
 * of random data and set \c *output_length to \c output_size.
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C
 *
 * \warning If you enable this option, code that uses the PSA cryptography
 *          interface will not use any of the entropy sources set up for
 *          the entropy module, nor the NV seed that MBEDTLS_ENTROPY_NV_SEED
 *          enables.
 *
 * \note This option is experimental and may be removed without notice.
 */
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG

/**
 * \def MBEDTLS_ECDH_C
 *
 * Enable the elliptic curve Diffie-Hellman library.
 *
 * Module:  library/ecdh.c
 * Caller:  library/psa_crypto.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * This module is used by the following key exchanges:
 *      ECDHE-ECDSA, ECDHE-RSA, DHE-PSK
 *
 * Requires: MBEDTLS_ECP_C
 */
#define MBEDTLS_ECDH_C

/**
 * \def MBEDTLS_ECDSA_C
 *
 * Enable the elliptic curve DSA library.
 *
 * Module:  library/ecdsa.c
 * Caller:
 *
 * This module is used by the following key exchanges:
 *      ECDHE-ECDSA
 *
 * Requires: MBEDTLS_ECP_C, MBEDTLS_ASN1_WRITE_C, MBEDTLS_ASN1_PARSE_C,
 *           and at least one MBEDTLS_ECP_DP_XXX_ENABLED for a
 *           short Weierstrass curve.
 */
#define MBEDTLS_ECDSA_C

/**
 * \def MBEDTLS_ECDSA_DETERMINISTIC
 *
 * Enable deterministic ECDSA (RFC 6979).
 * Standard ECDSA is "fragile" in the sense that lack of entropy when signing
 * may result in a compromise of the long-term signing key. This is avoided by
 * the deterministic variant.
 *
 * Requires: MBEDTLS_HMAC_DRBG_C, MBEDTLS_ECDSA_C
 *
 * Comment this macro to disable deterministic ECDSA.
 */
#define MBEDTLS_ECDSA_DETERMINISTIC

/**
 * \def MBEDTLS_ECJPAKE_C
 *
 * Enable the elliptic curve J-PAKE library.
 *
 * \note EC J-PAKE support is based on the Thread v1.0.0 specification.
 *       It has not been reviewed for compliance with newer standards such as
 *       Thread v1.1 or RFC 8236.
 *
 * Module:  library/ecjpake.c
 * Caller:
 *
 * This module is used by the following key exchanges:
 *      ECJPAKE
 *
 * Requires: MBEDTLS_ECP_C and either MBEDTLS_MD_C or MBEDTLS_PSA_CRYPTO_C
 *
 * \warning If using a hash that is only provided by PSA drivers, you must
 * call psa_crypto_init() before doing any EC J-PAKE operations.
 */
#define MBEDTLS_ECJPAKE_C

/**
 * \def MBEDTLS_ECP_C
 *
 * Enable the elliptic curve over GF(p) library.
 *
 * Module:  library/ecp.c
 * Caller:  library/ecdh.c
 *          library/ecdsa.c
 *          library/ecjpake.c
 *
 * Requires: MBEDTLS_BIGNUM_C and at least one MBEDTLS_ECP_DP_XXX_ENABLED
 */
#define MBEDTLS_ECP_C

/**
 * \def MBEDTLS_ERROR_C
 *
 * Enable error code to error string conversion.
 *
 * Module:  library/error.c
 * Caller:
 *
 * This module enables mbedtls_strerror().
 */
//#define MBEDTLS_ERROR_C

/**
 * \def MBEDTLS_ERROR_STRERROR_DUMMY
 *
 * Enable a dummy error function to make use of mbedtls_strerror() in
 * third party libraries easier when MBEDTLS_ERROR_C is disabled
 * (no effect when MBEDTLS_ERROR_C is enabled).
 *
 * You can safely disable this if MBEDTLS_ERROR_C is enabled, or if you're
 * not using mbedtls_strerror() or error_strerror() in your application.
 *
 * Disable if you run into name conflicts and want to really remove the
 * mbedtls_strerror()
 */
//#define MBEDTLS_ERROR_STRERROR_DUMMY

/**
 * \def MBEDTLS_GCM_C
 *
 * Enable the Galois/Counter Mode (GCM).
 *
 * Module:  library/gcm.c
 *
 * Requires: MBEDTLS_CIPHER_C, MBEDTLS_AES_C or MBEDTLS_CAMELLIA_C or
 *                             MBEDTLS_ARIA_C
 *
 * This module enables the AES-GCM and CAMELLIA-GCM ciphersuites, if other
 * requisites are enabled as well.
 */
#define MBEDTLS_GCM_C

/**
 * \def MBEDTLS_HMAC_DRBG_C
 *
 * Enable the HMAC_DRBG random generator.
 *
 * Module:  library/hmac_drbg.c
 * Caller:
 *
 * Requires: MBEDTLS_MD_C
 *
 * Uncomment to enable the HMAC_DRBG random number generator.
 */
#define MBEDTLS_HMAC_DRBG_C


/**
 * \def MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
 *
 * Enable the ECDHE-ECDSA based ciphersuite modes in SSL / TLS.
 *
 * Requires: MBEDTLS_ECDH_C or (MBEDTLS_USE_PSA_CRYPTO and PSA_WANT_ALG_ECDH)
 *           MBEDTLS_ECDSA_C or (MBEDTLS_USE_PSA_CRYPTO and PSA_WANT_ALG_ECDSA)
 *           MBEDTLS_X509_CRT_PARSE_C
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
 *      MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
 */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/**
 * \def MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
 *
 * Enable the PSK based ciphersuite modes in SSL / TLS.
 *
 * This enables the following ciphersuites (if other requisites are
 * enabled as well):
 *      MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384
 *      MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384
 *      MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA
 *      MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384
 *      MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
 *      MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256
 *      MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256
 *      MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA
 *      MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256
 *      MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
 */
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED

/**
 * \def MBEDTLS_MD_C
 *
 * Enable the generic layer for message digest (hashing) and HMAC.
 *
 * Requires: one of: MBEDTLS_MD5_C, MBEDTLS_RIPEMD160_C, MBEDTLS_SHA1_C,
 *                   MBEDTLS_SHA224_C, MBEDTLS_SHA256_C, MBEDTLS_SHA384_C,
 *                   MBEDTLS_SHA512_C, or MBEDTLS_PSA_CRYPTO_C with at least
 *                   one hash.
 * Module:  library/md.c
 * Caller:  library/constant_time.c
 *          library/ecdsa.c
 *          library/ecjpake.c
 *          library/hkdf.c
 *          library/hmac_drbg.c
 *          library/pk.c
 *          library/pkcs5.c
 *          library/pkcs12.c
 *          library/psa_crypto_ecp.c
 *          library/psa_crypto_rsa.c
 *          library/rsa.c
 *          library/ssl_cookie.c
 *          library/ssl_msg.c
 *          library/ssl_tls.c
 *          library/x509.c
 *          library/x509_crt.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 *
 * Uncomment to enable generic message digest wrappers.
 */
#define MBEDTLS_MD_C

/**
 * \def MBEDTLS_OID_C
 *
 * Enable the OID database.
 *
 * Module:  library/oid.c
 * Caller:  library/asn1write.c
 *          library/pkcs5.c
 *          library/pkparse.c
 *          library/pkwrite.c
 *          library/rsa.c
 *          library/x509.c
 *          library/x509_create.c
 *          library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *          library/x509write_crt.c
 *          library/x509write_csr.c
 *
 * This modules translates between OIDs and internal values.
 */
#define MBEDTLS_OID_C

/**
 * \def MBEDTLS_PEM_PARSE_C
 *
 * Enable PEM decoding / parsing.
 *
 * Module:  library/pem.c
 * Caller:  library/dhm.c
 *          library/pkparse.c
 *          library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: MBEDTLS_BASE64_C
 *           optionally MBEDTLS_MD5_C, or PSA Crypto with MD5 (see below)
 *
 * \warning When parsing password-protected files, if MD5 is provided only by
 * a PSA driver, you must call psa_crypto_init() before the first file.
 *
 * This modules adds support for decoding / parsing PEM files.
 */
#define MBEDTLS_PEM_PARSE_C

/**
 * \def MBEDTLS_PK_C
 *
 * Enable the generic public (asymmetric) key layer.
 *
 * Module:  library/pk.c
 * Caller:  library/psa_crypto_rsa.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *          library/x509.c
 *
 * Requires: MBEDTLS_MD_C, MBEDTLS_RSA_C or MBEDTLS_ECP_C
 *
 * Uncomment to enable generic public key wrappers.
 */
#define MBEDTLS_PK_C

/**
 * \def MBEDTLS_PK_PARSE_C
 *
 * Enable the generic public (asymmetric) key parser.
 *
 * Module:  library/pkparse.c
 * Caller:  library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: MBEDTLS_ASN1_PARSE_C, MBEDTLS_OID_C, MBEDTLS_PK_C
 *
 * Uncomment to enable generic public key parse functions.
 */
#define MBEDTLS_PK_PARSE_C

/**
 * \def MBEDTLS_PK_WRITE_C
 *
 * Enable the generic public (asymmetric) key writer.
 *
 * Module:  library/pkwrite.c
 * Caller:  library/x509write.c
 *
 * Requires: MBEDTLS_ASN1_WRITE_C, MBEDTLS_OID_C, MBEDTLS_PK_C
 *
 * Uncomment to enable generic public key write functions.
 */
#define MBEDTLS_PK_WRITE_C

/**
 * \def MBEDTLS_PLATFORM_C
 *
 * Enable the platform abstraction layer that allows you to re-assign
 * functions like calloc(), free(), snprintf(), printf(), fprintf(), exit().
 *
 * Enabling MBEDTLS_PLATFORM_C enables to use of MBEDTLS_PLATFORM_XXX_ALT
 * or MBEDTLS_PLATFORM_XXX_MACRO directives, allowing the functions mentioned
 * above to be specified at runtime or compile time respectively.
 *
 * \note This abstraction layer must be enabled on Windows (including MSYS2)
 * as other modules rely on it for a fixed snprintf implementation.
 *
 * Module:  library/platform.c
 * Caller:  Most other .c files
 *
 * This module enables abstraction of common (libc) functions.
 */
#define MBEDTLS_PLATFORM_C

/**
 * \def MBEDTLS_PSA_CRYPTO_C
 *
 * Enable the Platform Security Architecture (PSA) cryptography API.
 *
 * \note In multithreaded applications, you must enable #MBEDTLS_THREADING_C,
 *       unless only one thread ever calls `psa_xxx()` functions.
 *       That includes indirect calls, such as:
 *       - performing a TLS handshake if support for TLS 1.3 is enabled;
 *       - using a TLS 1.3 connection;
 *       - indirect calls from PK, X.509 or SSL functions when
 *         #MBEDTLS_USE_PSA_CRYPTO is enabled;
 *       - indirect calls to calculate a hash when #MBEDTLS_MD_C is disabled;
 *       - any other call to a function that requires calling psa_crypto_init()
 *         beforehand.
 *
 * Module:  library/psa_crypto.c
 *
 * Requires: either MBEDTLS_CTR_DRBG_C and MBEDTLS_ENTROPY_C,
 *           or MBEDTLS_HMAC_DRBG_C and MBEDTLS_ENTROPY_C,
 *           or MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG.
 * Auto-enables: MBEDTLS_CIPHER_C if any unauthenticated (ie, non-AEAD) cipher
 *               is enabled in PSA (unless it's fully accelerated, see
 *               docs/driver-only-builds.md about that).
 */
#define MBEDTLS_PSA_CRYPTO_C

/**
 * \def MBEDTLS_PSA_CRYPTO_STORAGE_C
 *
 * Enable the Platform Security Architecture persistent key storage.
 *
 * Module:  library/psa_crypto_storage.c
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C,
 *           either MBEDTLS_PSA_ITS_FILE_C or a native implementation of
 *           the PSA ITS interface
 */
#define MBEDTLS_PSA_CRYPTO_STORAGE_C

/**
 * \def MBEDTLS_PSA_KEY_STORE_DYNAMIC
 *
 * Dynamically resize the PSA key store to accommodate any number of
 * volatile keys (until the heap memory is exhausted).
 *
 * If this option is disabled, the key store has a fixed size
 * #MBEDTLS_PSA_KEY_SLOT_COUNT for volatile keys and loaded persistent keys
 * together.
 *
 * This option has no effect when #MBEDTLS_PSA_CRYPTO_C is disabled.
 *
 * Module:  library/psa_crypto.c
 * Requires: MBEDTLS_PSA_CRYPTO_C
 */
//#define MBEDTLS_PSA_KEY_STORE_DYNAMIC

/**
 * \def MBEDTLS_SHA224_C
 *
 * Enable the SHA-224 cryptographic hash algorithm.
 *
 * Module:  library/sha256.c
 * Caller:  library/md.c
 *          library/ssl_cookie.c
 *
 * This module adds support for SHA-224.
 */
#define MBEDTLS_SHA224_C

/**
 * \def MBEDTLS_SHA256_C
 *
 * Enable the SHA-256 cryptographic hash algorithm.
 *
 * Module:  library/sha256.c
 * Caller:  library/entropy.c
 *          library/md.c
 *          library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * This module adds support for SHA-256.
 * This module is required for the SSL/TLS 1.2 PRF function.
 */
#define MBEDTLS_SHA256_C


/**
 * \def MBEDTLS_SSL_CACHE_C
 *
 * Enable simple SSL cache implementation.
 *
 * Module:  library/ssl_cache.c
 * Caller:
 *
 * Requires: MBEDTLS_SSL_CACHE_C
 */
#define MBEDTLS_SSL_CACHE_C

/**
 * \def MBEDTLS_SSL_CLI_C
 *
 * Enable the SSL/TLS client code.
 *
 * Module:  library/ssl*_client.c
 * Caller:
 *
 * Requires: MBEDTLS_SSL_TLS_C
 *
 * This module is required for SSL/TLS client support.
 */
#define MBEDTLS_SSL_CLI_C

/**
 * \def MBEDTLS_SSL_COOKIE_C
 *
 * Enable basic implementation of DTLS cookies for hello verification.
 *
 * Module:  library/ssl_cookie.c
 * Caller:
 */
#define MBEDTLS_SSL_COOKIE_C

/**
 * \def MBEDTLS_SSL_DTLS_ANTI_REPLAY
 *
 * Enable support for the anti-replay mechanism in DTLS.
 *
 * Requires: MBEDTLS_SSL_TLS_C
 *           MBEDTLS_SSL_PROTO_DTLS
 *
 * \warning Disabling this is often a security risk!
 * See mbedtls_ssl_conf_dtls_anti_replay() for details.
 *
 * Comment this to disable anti-replay in DTLS.
 */
#define MBEDTLS_SSL_DTLS_ANTI_REPLAY

/**
 * \def MBEDTLS_SSL_DTLS_CONNECTION_ID
 *
 * Enable support for the DTLS Connection ID (CID) extension,
 * which allows to identify DTLS connections across changes
 * in the underlying transport. The CID functionality is described
 * in RFC 9146.
 *
 * Setting this option enables the SSL APIs `mbedtls_ssl_set_cid()`,
 * mbedtls_ssl_get_own_cid()`, `mbedtls_ssl_get_peer_cid()` and
 * `mbedtls_ssl_conf_cid()`. See the corresponding documentation for
 * more information.
 *
 * The maximum lengths of outgoing and incoming CIDs can be configured
 * through the options
 * - MBEDTLS_SSL_CID_OUT_LEN_MAX
 * - MBEDTLS_SSL_CID_IN_LEN_MAX.
 *
 * Requires: MBEDTLS_SSL_PROTO_DTLS
 *
 * Uncomment to enable the Connection ID extension.
 */
#define MBEDTLS_SSL_DTLS_CONNECTION_ID

/**
 * \def MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT
 *
 * Defines whether RFC 9146 (default) or the legacy version
 * (version draft-ietf-tls-dtls-connection-id-05,
 * https://tools.ietf.org/html/draft-ietf-tls-dtls-connection-id-05)
 * is used.
 *
 * Set the value to 0 for the standard version, and
 * 1 for the legacy draft version.
 *
 * \deprecated Support for the legacy version of the DTLS
 *             Connection ID feature is deprecated. Please
 *             switch to the standardized version defined
 *             in RFC 9146 enabled by utilizing
 *             MBEDTLS_SSL_DTLS_CONNECTION_ID without use
 *             of MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT.
 *
 * Requires: MBEDTLS_SSL_DTLS_CONNECTION_ID
 */
#define MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT 0

/**
 * \def MBEDTLS_SSL_DTLS_HELLO_VERIFY
 *
 * Enable support for HelloVerifyRequest on DTLS servers.
 *
 * This feature is highly recommended to prevent DTLS servers being used as
 * amplifiers in DoS attacks against other hosts. It should always be enabled
 * unless you know for sure amplification cannot be a problem in the
 * environment in which your server operates.
 *
 * \warning Disabling this can be a security risk! (see above)
 *
 * Requires: MBEDTLS_SSL_PROTO_DTLS
 *
 * Comment this to disable support for HelloVerifyRequest.
 */
#define MBEDTLS_SSL_DTLS_HELLO_VERIFY

/** \def MBEDTLS_SSL_EXTENDED_MASTER_SECRET
 *
 * Enable support for RFC 7627: Session Hash and Extended Master Secret
 * Extension.
 *
 * This was introduced as "the proper fix" to the Triple Handshake family of
 * attacks, but it is recommended to always use it (even if you disable
 * renegotiation), since it actually fixes a more fundamental issue in the
 * original SSL/TLS design, and has implications beyond Triple Handshake.
 *
 * Requires: MBEDTLS_SSL_PROTO_TLS1_2
 *
 * Comment this macro to disable support for Extended Master Secret.
 */
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET

/**
 * \def MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
 *
 * This option controls the availability of the API mbedtls_ssl_get_peer_cert()
 * giving access to the peer's certificate after completion of the handshake.
 *
 * Unless you need mbedtls_ssl_peer_cert() in your application, it is
 * recommended to disable this option for reduced RAM usage.
 *
 * \note If this option is disabled, mbedtls_ssl_get_peer_cert() is still
 *       defined, but always returns \c NULL.
 *
 * \note This option has no influence on the protection against the
 *       triple handshake attack. Even if it is disabled, Mbed TLS will
 *       still ensure that certificates do not change during renegotiation,
 *       for example by keeping a hash of the peer's certificate.
 *
 * \note This option is required if MBEDTLS_SSL_PROTO_TLS1_3 is set.
 *
 * Comment this macro to disable storing the peer's certificate
 * after the handshake.
 */
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

/**
 * \def MBEDTLS_SSL_KEYING_MATERIAL_EXPORT
 *
 * When this option is enabled, the client and server can extract additional
 * shared symmetric keys after an SSL handshake using the function
 * mbedtls_ssl_export_keying_material().
 *
 * The process for deriving the keys is specified in RFC 5705 for TLS 1.2 and
 * in RFC 8446, Section 7.5, for TLS 1.3.
 *
 * Comment this macro to disable mbedtls_ssl_export_keying_material().
 */
#define MBEDTLS_SSL_KEYING_MATERIAL_EXPORT

/**
 * \def MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
 *
 * Enable support for RFC 6066 max_fragment_length extension in SSL.
 *
 * Comment this macro to disable support for the max_fragment_length extension
 */
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH

/**
 * \def MBEDTLS_SSL_PROTO_DTLS
 *
 * Enable support for DTLS (all available versions).
 *
 * Enable this and MBEDTLS_SSL_PROTO_TLS1_2 to enable DTLS 1.2.
 *
 * Requires: MBEDTLS_SSL_PROTO_TLS1_2
 *
 * Comment this macro to disable support for DTLS
 */
#define MBEDTLS_SSL_PROTO_DTLS

/**
 * \def MBEDTLS_SSL_PROTO_TLS1_2
 *
 * Enable support for TLS 1.2 (and DTLS 1.2 if DTLS is enabled).
 *
 * Requires: Without MBEDTLS_USE_PSA_CRYPTO: MBEDTLS_MD_C and
 *              (MBEDTLS_SHA256_C or MBEDTLS_SHA384_C or
 *               SHA-256 or SHA-512 provided by a PSA driver)
 *           With MBEDTLS_USE_PSA_CRYPTO:
 *              PSA_WANT_ALG_SHA_256 or PSA_WANT_ALG_SHA_384
 *
 * \warning If building with MBEDTLS_USE_PSA_CRYPTO, or if the hash(es) used
 * are only provided by PSA drivers, you must call psa_crypto_init() before
 * doing any TLS operations.
 *
 * Comment this macro to disable support for TLS 1.2 / DTLS 1.2
 */
#define MBEDTLS_SSL_PROTO_TLS1_2

/**
 * \def MBEDTLS_SSL_PROTO_TLS1_3
 *
 * Enable support for TLS 1.3.
 *
 * \note See docs/architecture/tls13-support.md for a description of the TLS
 *       1.3 support that this option enables.
 *
 * Requires: MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
 * Requires: MBEDTLS_PSA_CRYPTO_C
 *
 * \note TLS 1.3 uses PSA crypto for cryptographic operations that are
 *       directly performed by TLS 1.3 code. As a consequence, when TLS 1.3
 *       is enabled, a TLS handshake may call psa_crypto_init(), even
 *       if it ends up negotiating a different TLS version.
 *
 * \note Cryptographic operations performed indirectly via another module
 *       (X.509, PK) or by code shared with TLS 1.2 (record protection,
 *       running handshake hash) only use PSA crypto if
 *       #MBEDTLS_USE_PSA_CRYPTO is enabled.
 *
 * \note In multithreaded applications, you must also enable
 *       #MBEDTLS_THREADING_C, even if individual TLS contexts are not
 *       shared between threads, unless only one thread ever calls
 *       TLS functions.
 *
 * Uncomment this macro to enable the support for TLS 1.3.
 */
//#define MBEDTLS_SSL_PROTO_TLS1_3

/**
 * \def MBEDTLS_SSL_RENEGOTIATION
 *
 * Enable support for TLS renegotiation.
 *
 * The two main uses of renegotiation are (1) refresh keys on long-lived
 * connections and (2) client authentication after the initial handshake.
 * If you don't need renegotiation, it's probably better to disable it, since
 * it has been associated with security issues in the past and is easy to
 * misuse/misunderstand.
 *
 * Requires: MBEDTLS_SSL_PROTO_TLS1_2
 *
 * Comment this to disable support for renegotiation.
 *
 * \note   Even if this option is disabled, both client and server are aware
 *         of the Renegotiation Indication Extension (RFC 5746) used to
 *         prevent the SSL renegotiation attack (see RFC 5746 Sect. 1).
 *         (See \c mbedtls_ssl_conf_legacy_renegotiation for the
 *          configuration of this extension).
 *
 */
#define MBEDTLS_SSL_RENEGOTIATION

/**
 * \def MBEDTLS_SSL_SRV_C
 *
 * Enable the SSL/TLS server code.
 *
 * Module:  library/ssl*_server.c
 * Caller:
 *
 * Requires: MBEDTLS_SSL_TLS_C
 *
 * This module is required for SSL/TLS server support.
 */
#define MBEDTLS_SSL_SRV_C

/**
 * \def MBEDTLS_SSL_TLS_C
 *
 * Enable the generic SSL/TLS code.
 *
 * Module:  library/ssl_tls.c
 * Caller:  library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * Requires: MBEDTLS_CIPHER_C, MBEDTLS_MD_C
 *           and at least one of the MBEDTLS_SSL_PROTO_XXX defines
 *
 * This module is required for SSL/TLS.
 */
#define MBEDTLS_SSL_TLS_C

/**
 * \def MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
 *
 * Enable TLS 1.3 middlebox compatibility mode.
 *
 * As specified in Section D.4 of RFC 8446, TLS 1.3 offers a compatibility
 * mode to make a TLS 1.3 connection more likely to pass through middle boxes
 * expecting TLS 1.2 traffic.
 *
 * Turning on the compatibility mode comes at the cost of a few added bytes
 * on the wire, but it doesn't affect compatibility with TLS 1.3 implementations
 * that don't use it. Therefore, unless transmission bandwidth is critical and
 * you know that middlebox compatibility issues won't occur, it is therefore
 * recommended to set this option.
 *
 * Comment to disable compatibility mode for TLS 1.3. If
 * MBEDTLS_SSL_PROTO_TLS1_3 is not enabled, this option does not have any
 * effect on the build.
 *
 */
#define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE

/**
 * \def MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
 *
 * Enable TLS 1.3 ephemeral key exchange mode.
 *
 * Requires: PSA_WANT_ALG_ECDH or PSA_WANT_ALG_FFDH
 *           MBEDTLS_X509_CRT_PARSE_C
 *           and at least one of:
 *               MBEDTLS_ECDSA_C or (MBEDTLS_USE_PSA_CRYPTO and PSA_WANT_ALG_ECDSA)
 *               MBEDTLS_PKCS1_V21
 *
 * Comment to disable support for the ephemeral key exchange mode in TLS 1.3.
 * If MBEDTLS_SSL_PROTO_TLS1_3 is not enabled, this option does not have any
 * effect on the build.
 *
 */
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED

/**
 * \def MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
 *
 * Enable TLS 1.3 PSK key exchange mode.
 *
 * Comment to disable support for the PSK key exchange mode in TLS 1.3. If
 * MBEDTLS_SSL_PROTO_TLS1_3 is not enabled, this option does not have any
 * effect on the build.
 *
 */
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED

/**
 * \def MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
 *
 * Enable TLS 1.3 PSK ephemeral key exchange mode.
 *
 * Requires: PSA_WANT_ALG_ECDH or PSA_WANT_ALG_FFDH
 *
 * Comment to disable support for the PSK ephemeral key exchange mode in
 * TLS 1.3. If MBEDTLS_SSL_PROTO_TLS1_3 is not enabled, this option does not
 * have any effect on the build.
 *
 */
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED

/** 
 * \def MBEDTLS_SSL_IN_CONTENT_LEN
 *
 * Maximum length (in bytes) of incoming plaintext fragments.
 *
 * This determines the size of the incoming TLS I/O buffer in such a way
 * that it is capable of holding the specified amount of plaintext data,
 * regardless of the protection mechanism used.
 *
 * \note When using a value less than the default of 16KB on the client, it is
 *       recommended to use the Maximum Fragment Length (MFL) extension to
 *       inform the server about this limitation. On the server, there
 *       is no supported, standardized way of informing the client about
 *       restriction on the maximum size of incoming messages, and unless
 *       the limitation has been communicated by other means, it is recommended
 *       to only change the outgoing buffer size #MBEDTLS_SSL_OUT_CONTENT_LEN
 *       while keeping the default value of 16KB for the incoming buffer.
 *
 * Uncomment to set the maximum plaintext size of the incoming I/O buffer.
 */
#define MBEDTLS_SSL_IN_CONTENT_LEN 2048

/** 
 * \def MBEDTLS_SSL_OUT_CONTENT_LEN
 *
 * Maximum length (in bytes) of outgoing plaintext fragments.
 *
 * This determines the size of the outgoing TLS I/O buffer in such a way
 * that it is capable of holding the specified amount of plaintext data,
 * regardless of the protection mechanism used.
 *
 * It is possible to save RAM by setting a smaller outward buffer, while keeping
 * the default inward 16384 byte buffer to conform to the TLS specification.
 *
 * The minimum required outward buffer size is determined by the handshake
 * protocol's usage. Handshaking will fail if the outward buffer is too small.
 * The specific size requirement depends on the configured ciphers and any
 * certificate data which is sent during the handshake.
 *
 * Uncomment to set the maximum plaintext size of the outgoing I/O buffer.
 */
#define MBEDTLS_SSL_OUT_CONTENT_LEN 2048

/** 
 * \def MBEDTLS_SSL_DTLS_MAX_BUFFERING
 *
 * Maximum number of heap-allocated bytes for the purpose of
 * DTLS handshake message reassembly and future message buffering.
 *
 * This should be at least 9/8 * MBEDTLS_SSL_IN_CONTENT_LEN
 * to account for a reassembled handshake message of maximum size,
 * together with its reassembly bitmap.
 *
 * A value of 2 * MBEDTLS_SSL_IN_CONTENT_LEN (32768 by default)
 * should be sufficient for all practical situations as it allows
 * to reassembly a large handshake message (such as a certificate)
 * while buffering multiple smaller handshake messages.
 *
 */
#define MBEDTLS_SSL_DTLS_MAX_BUFFERING             4096

/**
 * \def MBEDTLS_SSL_EXPORT_KEYS
 *
 * Enable support for exporting key block and master secret.
 * This is required for certain users of TLS, e.g. EAP-TLS.
 *
 * Comment this macro to disable support for key export
 */
#define MBEDTLS_SSL_EXPORT_KEYS


/* MPI / BIGNUM options */
#define MBEDTLS_MPI_WINDOW_SIZE            1 /**< Maximum windows size used. */
#define MBEDTLS_MPI_MAX_SIZE              32 /**< Maximum number of bytes for usable MPIs. */

/* ECP options */
#define MBEDTLS_ECP_WINDOW_SIZE            2 /**< Maximum window size used */
#define MBEDTLS_ECP_FIXED_POINT_OPTIM      0 /**< Enable fixed-point speed-up */

/**
 * \def MBEDTLS_VERSION_C
 *
 * Enable run-time version information.
 *
 * Module:  library/version.c
 *
 * This module provides run-time version information.
 */
#define MBEDTLS_VERSION_C

/**
 * \def MBEDTLS_VERSION_FEATURES
 *
 * Allow run-time checking of compile-time enabled features. Thus allowing users
 * to check at run-time if the library is for instance compiled with threading
 * support via mbedtls_version_check_feature().
 *
 * Requires: MBEDTLS_VERSION_C
 *
 * Comment this to disable run-time checking and save ROM space
 */
#define MBEDTLS_VERSION_FEATURES

/**
 * \def MBEDTLS_X509_CRT_PARSE_C
 *
 * Enable X.509 certificate parsing.
 *
 * Module:  library/x509_crt.c
 * Caller:  library/ssl_tls.c
 *          library/ssl*_client.c
 *          library/ssl*_server.c
 *
 * Requires: MBEDTLS_X509_USE_C
 *
 * This module is required for X.509 certificate parsing.
 */
#define MBEDTLS_X509_CRT_PARSE_C

/**
 * \def MBEDTLS_X509_USE_C
 *
 * Enable X.509 core for using certificates.
 *
 * Module:  library/x509.c
 * Caller:  library/x509_crl.c
 *          library/x509_crt.c
 *          library/x509_csr.c
 *
 * Requires: MBEDTLS_ASN1_PARSE_C, MBEDTLS_BIGNUM_C, MBEDTLS_OID_C, MBEDTLS_PK_PARSE_C,
 *           (MBEDTLS_MD_C or MBEDTLS_USE_PSA_CRYPTO)
 *
 * \warning If building with MBEDTLS_USE_PSA_CRYPTO, you must call
 * psa_crypto_init() before doing any X.509 operation.
 *
 * This module is required for the X.509 parsing modules.
 */
#define MBEDTLS_X509_USE_C

/* -------------------------------------------------------------------------- */
/* STM32 hardware context and alternative implementations                      */
/* -------------------------------------------------------------------------- */

/**
  * @brief ST_HW_CONTEXT_SAVING Enables ST HASH save context
  *        The HASH context of the interrupted task can be saved from the HASH
  *        registers to memory, and then be restored from memory to the HASH
  *        registers.
  *
  *        Shall be activated if mbedtls_sha256_clone() is used => Y for OT comissionning
  *
  *        Uncomment a macro to enable ST HASH save context.
  *        Requires: MBEDTLS_SHA256_ALT.
  */
#define ST_HW_CONTEXT_SAVING

/**
  * @brief USE_HAL_HASH_SUSPEND_RESUME Use the HAL Hash suspend/resume mechanism
  */
#define USE_HAL_HASH_SUSPEND_RESUME 1U

#if defined(ST_HW_CONTEXT_SAVING) && (USE_HAL_HASH_SUSPEND_RESUME != 1U)
#error "Enable USE_HAL_HASH_SUSPEND_RESUME flag to save HASH context"
#endif /* ST_HW_CONTEXT_SAVING && USE_HAL_HASH_SUSPEND_RESUME */

#ifdef MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
#include "stm32wbaxx_hal_rng.h"
#endif /*MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG*/

/**
  * @brief MBEDTLS_HAL_AES_ALT Enables ST AES alternative module to replace mbed
  *        TLS AES module by ST AES alternative implementation based on STM32
  *        AES hardware accelerator.
  *
  *        Uncomment a macro to enable ST AES hardware alternative module.
  *        Requires: MBEDTLS_AES_C, MBEDTLS_AES_ALT.
  */
#define MBEDTLS_AES_ALT
#define MBEDTLS_HAL_AES_ALT

/**
  * @brief HW_CRYPTO_DPA_AES Allows DPA resistance for AES modes by using secure
  *        crypto processor (SAES), when this option is enabled,
  *        AES-ECB/CBC modes become DPA-protected.
  *
  * @note Using DPA resistance degrades the performance.
  *
  *       Comment this option if your system can run cryptographic services
  *       without DPA resistance for the highest performance benefit.
  *       Requires: MBEDTLS_HAL_AES_ALT
  */
//#define HW_CRYPTO_DPA_AES

#ifdef MBEDTLS_HAL_AES_ALT
#include "stm32wbaxx_hal_dma.h"
#include "stm32wbaxx_hal_cryp.h"
#endif /*MBEDTLS_HAL_AES_ALT*/

/**
  * @brief MBEDTLS_HAL_GCM_ALT Enables ST GCM alternative module to replace mbed
  *        TLS GCM module by ST GCM alternative implementation based on STM32
  *        AES hardware accelerator.
  *
  *        Uncomment a macro to enable ST GCM hardware alternative module.
  *        Requires: MBEDTLS_AES_C, MBEDTLS_GCM_C, MBEDTLS_GCM_ALT.
  */
#define MBEDTLS_GCM_ALT
#define MBEDTLS_HAL_GCM_ALT

/**
  * @brief HW_CRYPTO_DPA_GCM Allows DPA resistance for GCM by using secure crypto
  *        processor (SAES) when this option is enabled, GCM becomes DPA-protected.
  *
  * @note Using DPA resistance degrades the performance.
  *
  *       Comment this option if your system can run cryptographic services
  *       without DPA resistance for the highest performance benefit.
  *       Requires: MBEDTLS_HAL_GCM_ALT.
  */
//#define HW_CRYPTO_DPA_GCM

/**
  * @brief HW_CRYPTO_DPA_CTR_FOR_GCM Allows DPA resistance for GCM through CTR by
  *        using secure crypto processor (SAES) when this option is enabled,
  *        CTR becomes DPA-protected.
  *        CTR protected mode is mixed with software to create GCM protected mode.
  *        This option can be enabled when the hardware don't support protected GCM.
  *
  * @note Using DPA resistance degrades the performance.
  *
  *       Comment this option if your system can run cryptographic services
  *       without DPA resistance for the highest performance benefit.
  *       Requires: MBEDTLS_HAL_GCM_ALT, HW_CRYPTO_DPA_GCM.
  */
//#define HW_CRYPTO_DPA_CTR_FOR_GCM

#if defined(HW_CRYPTO_DPA_GCM) && defined(HW_CRYPTO_DPA_CTR_FOR_GCM)
#error "HW_CRYPTO_DPA_GCM and HW_CRYPTO_DPA_CTR_FOR_GCM cannot be defined simultaneously"
#endif /* HW_CRYPTO_DPA_GCM && HW_CRYPTO_DPA_CTR_FOR_GCM */

#ifdef MBEDTLS_HAL_GCM_ALT
#include "stm32wbaxx_hal_dma.h"
#include "stm32wbaxx_hal_cryp.h"
#endif /*MBEDTLS_HAL_GCM_ALT*/

/**
  * @brief MBEDTLS_HAL_ECP_ALT Enables ST ECP alternative modules to replace
  *        mbed TLS ECP module by ST ECP alternative implementation based on
  *        STM32 PKA hardware accelerator.
  *
  *        Uncomment a macro to enable ST ECP hardware alternative module.
  *        Requires: MBEDTLS_ECP_C, MBEDTLS_ECP_ALT.
  */
#define MBEDTLS_ECP_ALT
#define MBEDTLS_HAL_ECP_ALT

#ifdef MBEDTLS_HAL_ECP_ALT
#include "stm32wbaxx_hal_pka.h"
#endif /*MBEDTLS_HAL_ECP_ALT*/

/**
  * @brief MBEDTLS_HAL_ECDSA_ALT Enables ST ECDSA alternative module to replace
  *        mbed TLS ECDSA sign and  verify modules by ST ECDSA alternative
  *        implementation based on STM32 PKA hardware accelerator.
  *
  *        Uncomment a macro to enable ST ECDSA hardware alternative module.
  *        Requires: MBEDTLS_ECDSA_C, MBEDTLS_ECDSA_SIGN_ALT,
  *                  MBEDTLS_ECDSA_VERIFY_ALT, MBEDTLS_ECP_ALT.
  */
#define MBEDTLS_ECDSA_ALT
#define MBEDTLS_HAL_ECDSA_ALT

#ifdef MBEDTLS_HAL_ECDSA_ALT
#include "stm32wbaxx_hal_pka.h"
#endif /*MBEDTLS_HAL_ECDSA_ALT*/

/**
  * @brief MBEDTLS_HAL_ECDH_ALT Enables ST ECDH alternative module to replace
  *        mbed TLS Compute shared secret module by ST Compute shared secret
  *        alternative implementation based on STM32 PKA hardware accelerator.
  *
  *        Uncomment a macro to enable ST ECDH hardware alternative module.
  *        Requires: MBEDTLS_ECDH_C, MBEDTLS_ECDH_COMPUTE_SHARED_ALT,
  *                  MBEDTLS_ECP_ALT!!!!!.
  */
#define MBEDTLS_ECDH_ALT
#define MBEDTLS_HAL_ECDH_ALT

#ifdef MBEDTLS_HAL_ECDH_ALT
#include "stm32wbaxx_hal_pka.h"
#endif /*MBEDTLS_HAL_ECDH_ALT*/

/**
  * @brief MBEDTLS_HAL_RSA_ALT Enables ST RSA alternative modules to replace
  *        mbed TLS RSA module by ST RSA alternative implementation based on
  *        STM32 PKA hardware accelerator.
  *
  *        Uncomment a macro to enable ST RSA hardware alternative module.
  *        Requires: MBEDTLS_RSA_C, MBEDTLS_RSA_ALT.
  */
/* #define MBEDTLS_RSA_ALT */
/* #define MBEDTLS_HAL_RSA_ALT */

#ifdef MBEDTLS_HAL_RSA_ALT
#include "stm32wbaxx_hal_pka.h"
#endif /*MBEDTLS_HAL_RSA_ALT*/

/**
  * @brief MBEDTLS_HAL_SHA256_ALT Enables ST SHA-224 and SHA-256 alternative
  *        modules to replace mbed TLS SHA-224 and SHA-256 modules by ST SHA-224
  *        and SHA-256 alternative implementation based on STM32 HASH hardware
  *        accelerator.
  *
  *        Uncomment a macro to enable ST SHA256 hardware alternative module.
  *        Requires: MBEDTLS_SHA256_C, MBEDTLS_SHA256_ALT.
  */
#if defined(ST_HW_CONTEXT_SAVING)
#define MBEDTLS_SHA256_ALT
#define MBEDTLS_HAL_SHA256_ALT

#ifdef MBEDTLS_HAL_SHA256_ALT
#include "stm32wbaxx_hal_hash.h"
#endif /*MBEDTLS_HAL_SHA256_ALT*/
#endif /* ST_HW_CONTEXT_SAVING*/

#endif /* STM32WBA_MBEDTLS_CONFIG_H */
