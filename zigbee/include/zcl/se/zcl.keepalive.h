/**
 * @file zcl.keepalive.h
 * @copyright Copyright [2009 - 2025] Exegin Technologies Limited. All rights reserved.
 * @heading Keep Alive
 * @brief ZCL Keep Alive cluster header
 *
 * The Keep Alive clusters are typically used in Smart Energy applications. However, with BDB 3.1
 * Keep-Alive clusters are recommended to be used to ensure connectivity with the TC.
 *
 * The Keep Alive server and client clusters are allocated by the stack if the application
 * enables and configures information in the ZbStartup configuration (struct ZbStartupKeepAliveT).
 * If enabled, the Keep Alive server is allocated if the server_enable flag is set
 * to true, otherwise the Keep Alive client is allocated. Typically, the Keep Alive server is allocated
 * on the Trust Center, and the Keep Alive client is allocated on devices joining the network.
 *
 * If the Keep Alive client determines there's a problem communicating with the Trust Center,
 * it will call the application callback 'tcso_callback' configured in the ZbStartup configuration.
 * At which point, the stack will perform the necessary Trust Center Swap Out (TCSO) routines
 * to attempt to find a newly swapped-out Trust Center, or if the current Trust Center has moved
 * to a different channel or other configuration.
 *
 * *ZbStartupKeepAliveT*
 *
 * |===
 *
 * |bool *enabled* | If set to true, the Keep-Alive clusters are allocated and keep-alive mechanism
 * started on the devices. Default is false.
 *
 * |uint8_t *endpoint* | Endpoint to assign Keep-Alive cluster. Default is
 * `ZB_ENDPOINT_CBKE_DEFAULT` (240)
 *
 * |uint16_t *profileId* | Profile Id to assign to the endpoint created for the Keep-Alive cluster.
 * Default is `ZCL_PROFILE_SMART_ENERGY`.
 *
 * |uint16_t *deviceId* | Device Id to assign to the endpoint created for the Keep-Alive cluster.
 * Default is `ZCL_DEVICE_METER`.
 *
 * |bool *server_enable* | Determines whether to allocate the Keep Alive Server
 * or Client cluster.
 *
 * |uint8_t *server_base* | Trust Center Keep Alive Server 'Base' attribute value in minutes.
 * If zero, let the stack choose a default value.
 *
 * |uint8_t *server_jitter* | Trust Center Keep Alive Server 'Jitter' attribute value in seconds.
 * If zero, let the stack choose a default value.
 *
 * |void (*tcso_callback)(enum ZbTcsoStatusT status, void *arg) | Application callback
 * which is called for any Trust Center Swap Out (TCSO) process initiated by the Keep Alive
 * Client cluster. This includes when a TCSO has been started and the final outcome of a TCSO
 * process.
 *
 * |void *+++*+++tcso_arg* | Application callback argument for `tcso_callback`.
 *
 * |===
 */

/*--------------------------------------------------------------------------
 *  DESCRIPTION
 *      Interface definition for the ZCL Keep Alive cluster.
 *--------------------------------------------------------------------------
 */
#ifndef ZCL_KEEPALIVE_H
# define ZCL_KEEPALIVE_H

#include "zcl/zcl.h"

/** Keep Alive Server Attribute IDs */
enum ZbZclKeepAliveSvrAttrT {
    ZCL_KEEPALIVE_SVR_ATTR_BASE = 0x0000,
    /**< TC Keep-Alive Base - minutes (valid range is from 0x01 to 0xff,
     * but not enforced by cluster, for testing) */

    ZCL_KEEPALIVE_SVR_ATTR_JITTER = 0x0001
        /**< TC Keep-Alive Jitter - seconds (valid range is from 0x0000 to 0x0200) */
};

#define ZCL_KEEPALIVE_BASE_MIN                  0x01U
#define ZCL_KEEPALIVE_BASE_MAX                  0xffU

#define ZCL_KEEPALIVE_JITTER_MIN                0x0000U
#define ZCL_KEEPALIVE_JITTER_MAX                0x0200U

/* Keep Alive Server Defaults */
#define ZCL_KEEPALIVE_SERVER_BASE_DEFAULT       10U /* minutes */
#define ZCL_KEEPALIVE_SERVER_JITTER_DEFAULT     300U /* seconds */

/* Keep Alive Client Defaults */
/* The client will poll the server at a faster rate until it is able to read
 * the real attribute values from the Keep Alive Server. */
#define ZCL_KEEPALIVE_CLIENT_BASE_DEFAULT       0U /* minutes */
#define ZCL_KEEPALIVE_CLIENT_JITTER_DEFAULT     30U /* seconds */

/**
 * Write a Keep Alive Server attribute
 * @note Use this API only if Keep-Alive is enabled and Keep-Alive server cluster allocated using the
 * startup configuration.
 * @param zb Zigbee instance
 * @param attrId The attribute Id to write
 * @param value Attribute data to be writen.
 * @return ZCL Status Code
 */
enum ZclStatusCodeT ZbZclKeepAliveServerWriteDirect(struct ZigBeeT *zb, uint16_t attrId, uint16_t value);

/**
 * Start the Keep Alive process. This is ignored if the cluster has not been allocated.
 * The Keep Alive cluster is allocated based on the ZbStartupT configuration given to ZbStartup.
 * @param zb Zigbee stack instance
 * @return Void
 */
void ZbZclKeepAliveClientStart(struct ZigBeeT *zb);

/**
 * Stop the Keep Alive process and abort the TCSO if running. This is ignored if the cluster
 * has not been allocated. The Keep Alive cluster is allocated based on the ZbStartupT
 * configuration given to ZbStartup.
 * @param zb Zigbee stack instance
 * @return Void
 */
void ZbZclKeepAliveClientStop(struct ZigBeeT *zb);

#endif
