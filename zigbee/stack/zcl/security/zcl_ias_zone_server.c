/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

/*-------------------------------------------------
 *  DESCRIPTION
 *      HA IAS devices Implementation.
 *-------------------------------------------------
 */

#include "zcl/security/zcl.ias_zone.h"
#include "../zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */

struct cluster_priv_t {
    struct ZbZclClusterT cluster;

    bool is_init;
    uint16_t manuf_code;

    /* Keep a local copy of ZCL_IAS_ZONE_SVR_ATTR_CIE_ADDR, because
     * we need it when ZCL_IAS_ZONE_SVR_ATTR_ZONE_STATUS and we can't
     * read an attribute while we're in the middle of writing one.  */
    uint64_t ias_cie_addr;
    uint8_t ias_cie_endpoint;

    struct ZbTimerT *enroll_req_timer;
    bool enroll_active;
    bool use_trip_pair;

    struct ZbTimerT *test_mode_timer;

    /* Application callbacks */
    struct ZbZclIasZoneServerCallbacksT callbacks;
};

static void zcl_ias_zone_server_enroll_success(struct ZbZclClusterT *cluster, uint8_t zone_id);

static void zcl_ias_zone_server_test_mode_timeout(struct ZigBeeT *zb, void *arg);

static uint8_t zcl_ias_zone_server_status_change_notify(struct ZbZclClusterT *cluster,
    struct ZbZclIasZoneServerStatusChangeNotifyT *notify);

static enum ZclStatusCodeT zcl_ias_zone_server_command(struct ZbZclClusterT *,
    struct ZbZclHeaderT *, struct ZbApsdeDataIndT *);
static void zcl_ias_zone_server_cleanup(struct ZbZclClusterT *cluster);

static enum ZclStatusCodeT zcl_attr_read_cb(struct ZbZclClusterT *cluster, uint16_t attributeId,
    uint8_t *data, unsigned int maxlen, void *app_cb_arg);

static enum ZclStatusCodeT zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src,
    uint16_t attributeId, const uint8_t *inputData, unsigned int inputMaxLen,
    void *attrData, ZclWriteModeT mode, void *app_cb_arg);

static enum ZclStatusCodeT
zcl_attr_cb(struct ZbZclClusterT *cluster, struct ZbZclAttrCbInfoT *cb)
{
    if (cb->type == ZCL_ATTR_CB_TYPE_READ) {
        return zcl_attr_read_cb(cluster, cb->info->attributeId, cb->zcl_data, cb->zcl_len, cb->app_cb_arg);
    }
    else if (cb->type == ZCL_ATTR_CB_TYPE_WRITE) {
        return zcl_attr_write_cb(cluster, cb->src, cb->info->attributeId, cb->zcl_data, cb->zcl_len,
            cb->attr_data, cb->write_mode, cb->app_cb_arg);
    }
    else {
        return ZCL_STATUS_FAILURE;
    }
}

/* Attributes */
static const struct ZbZclAttrT zcl_ias_zone_server_attr_list[] = {
    /* Zone Information */
    {
        ZCL_IAS_ZONE_SVR_ATTR_ZONE_STATE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_PERSISTABLE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_IAS_ZONE_SVR_ATTR_ZONE_TYPE, ZCL_DATATYPE_ENUMERATION_16BIT,
        ZCL_ATTR_FLAG_PERSISTABLE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_IAS_ZONE_SVR_ATTR_ZONE_STATUS, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_CB_WRITE /* ZCL_ATTR_FLAG_PERSISTABLE? */, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },

    /* Zone Settings */
    {
        ZCL_IAS_ZONE_SVR_ATTR_CIE_ADDR, ZCL_DATATYPE_EUI64,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_PERSISTABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_IAS_ZONE_SVR_ATTR_ZONE_ID, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_PERSISTABLE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },

    /* Exegin add-on to persist endpoint of CIE */
    {
        ZCL_IAS_ZONE_SVR_ATTR_CIE_ENDPOINT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_INTERNAL | ZCL_ATTR_FLAG_PERSISTABLE | ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
};

struct ZbZclClusterT *
ZbZclIasZoneServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, uint16_t zone_type,
    uint16_t manuf_code, bool use_trip_pair,
    struct ZbZclIasZoneServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *cluster;

    cluster = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t),
            ZCL_CLUSTER_SECURITY_IAS_ZONE, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (cluster == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "CCB 2352"
     * (need to investigate these changes) */
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    cluster->is_init = true;
    cluster->cluster.command = zcl_ias_zone_server_command;
    cluster->cluster.cleanup = zcl_ias_zone_server_cleanup;
    cluster->use_trip_pair = use_trip_pair;
    cluster->ias_cie_endpoint = ZB_ENDPOINT_BCAST;

    cluster->test_mode_timer = ZbTimerAlloc(zb, zcl_ias_zone_server_test_mode_timeout, cluster);
    if (!cluster->test_mode_timer) {
        ZbZclClusterFree(&cluster->cluster);
        return NULL;
    }

    if (ZbZclAttrAppendList(&cluster->cluster, zcl_ias_zone_server_attr_list,
            ZCL_ATTR_LIST_LEN(zcl_ias_zone_server_attr_list))) {
        ZbZclClusterFree(&cluster->cluster);
        return NULL;
    }

    ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_IAS_ZONE_SVR_ATTR_ZONE_TYPE, zone_type);
    cluster->manuf_code = manuf_code;

    ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_IAS_ZONE_SVR_ATTR_ZONE_STATE, ZCL_IAS_ZONE_SVR_STATE_NOT_ENROLLED);
    ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_IAS_ZONE_SVR_ATTR_ZONE_STATUS, 0x0000);
    ZbZclAttrEuiWrite(&cluster->cluster, ZCL_IAS_ZONE_SVR_ATTR_CIE_ADDR, 0);
    ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_IAS_ZONE_SVR_ATTR_ZONE_ID, 0xff);

    ZbZclClusterSetCallbackArg(&cluster->cluster, arg);
    if (callbacks != NULL) {
        (void)memcpy(&cluster->callbacks, callbacks, sizeof(struct ZbZclIasZoneServerCallbacksT));
    }
    else {
        (void)memset(&cluster->callbacks, 0, sizeof(struct ZbZclIasZoneServerCallbacksT));
    }

    (void)ZbZclClusterAttach(&cluster->cluster);

    cluster->is_init = false;
    return &cluster->cluster;
}

static enum ZclStatusCodeT
zcl_attr_read_cb(struct ZbZclClusterT *cluster, uint16_t attributeId, uint8_t *data,
    unsigned int maxlen, void *app_cb_arg)
{
    struct cluster_priv_t *iasCluster = (void *)cluster;

    switch (attributeId) {
        case ZCL_IAS_ZONE_SVR_ATTR_CIE_ENDPOINT:
            /* This attribute is for persistence */
            if (maxlen < 1) {
                return ZCL_STATUS_INSUFFICIENT_SPACE;
            }
            data[0] = iasCluster->ias_cie_endpoint;
            break;

        default:
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
    return ZCL_STATUS_SUCCESS;
}

static void
zcl_zone_enroll_req_timer(struct ZigBeeT *zb, void *arg)
{
    struct ZbZclClusterT *cluster = arg;
    struct cluster_priv_t *iasCluster = (struct cluster_priv_t *)cluster;
    enum ZclStatusCodeT status;

    ZbTimerFree(iasCluster->enroll_req_timer);
    iasCluster->enroll_req_timer = NULL;

    ZCL_LOG_PRINTF(cluster->zb, __func__, "Attempting enrollment request");
    status = ZbZclIasZoneServerEnrollRequest(cluster, NULL, NULL);
    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Warning, failed to perform auto-enroll-request");
    }
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src,
    uint16_t attributeId, const uint8_t *inputData, unsigned int inputMaxLen,
    void *attrData, ZclWriteModeT mode, void *app_cb_arg)
{
    struct cluster_priv_t *iasCluster = (void *)cluster;

    switch (attributeId) {
        case ZCL_IAS_ZONE_SVR_ATTR_ZONE_STATUS:
        {
            uint16_t current_zone_status, new_zone_status;
            struct ZbZclIasZoneServerStatusChangeNotifyT notify;
            uint8_t zone_id;
            enum ZclStatusCodeT status;

            /* Get and check incoming status */
            new_zone_status = pletoh16(inputData);
            if ((new_zone_status & ~(ZCL_IAS_ZONE_SVR_ZONE_STATUS_MASK)) != 0U) {
                return ZCL_STATUS_INVALID_VALUE;
            }

            /* Compare if different than current */
            current_zone_status = pletoh16(attrData);
            if (new_zone_status == current_zone_status) {
                return ZCL_STATUS_SUCCESS;
            }

            if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) {
                (void)memcpy(attrData, inputData, 2);

                if (iasCluster->is_init) {
                    /* We're initializing the cluster and attributes, we're done. */
                    return ZCL_STATUS_SUCCESS;
                }

                /* Send a Status Change Notification */
                (void)memset(&notify, 0, sizeof(notify));
                notify.zone_status = (enum ZbZclIasZoneServerZoneStatusT)new_zone_status;
                notify.ext_status = 0x00;

                zone_id = ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_IAS_ZONE_SVR_ATTR_ZONE_ID, NULL, &status);
                if (status != 0x00) {
                    return ZCL_STATUS_FAILURE;
                }
                notify.zone_id = zone_id;
                /* EXEGIN - support the 'Delay Parameter'? */
                notify.delay = 0x0000;

                (void)zcl_ias_zone_server_status_change_notify(cluster, &notify);
            }
            break;
        }

        case ZCL_IAS_ZONE_SVR_ATTR_CIE_ADDR:
        {
            uint64_t eui;
            enum ZclStatusCodeT status;
            enum ZbZclIasZoneServerZoneStateT state;

            eui = pletoh64(inputData);

            if (iasCluster->is_init) {
                /* We're initializing the cluster and attributes, we're done. */
                iasCluster->ias_cie_addr = eui;
                (void)memcpy(attrData, inputData, 8);
                return ZCL_STATUS_SUCCESS;
            }

            /* Check if we are already enrolled */
            state = (enum ZbZclIasZoneServerZoneStateT)ZbZclAttrIntegerRead(cluster, ZCL_IAS_ZONE_SVR_ATTR_ZONE_STATE, NULL, &status);
            if (status != ZCL_STATUS_SUCCESS) {
                return ZCL_STATUS_FAILURE;
            }
            if (state == ZCL_IAS_ZONE_SVR_STATE_ENROLLED) {
                /* We're already enrolled. Don't change CIE Address, but still return SUCCESS. */
                ZCL_LOG_PRINTF(cluster->zb, __func__, "Dropping write to CIE_ADDR attribute, already enrolled.");
                return ZCL_STATUS_SUCCESS;
            }

            if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) {
                ZCL_LOG_PRINTF(cluster->zb, __func__, "Writing IAS_CIE_ADDR = " LOGFMTx64, LOGVALx64(eui));

                iasCluster->ias_cie_addr = eui;
                iasCluster->ias_cie_endpoint = src->endpoint;

                (void)memcpy(attrData, inputData, 8);

                if (((mode & ZCL_ATTR_WRITE_FLAG_PERSIST) == 0U) && !iasCluster->use_trip_pair) {
                    /* Perform Auto-Enroll Request */
                    if (iasCluster->enroll_req_timer != NULL) {
                        ZCL_LOG_PRINTF(cluster->zb, __func__, "Enrollment already queued, ignoring.");
                        break;
                    }
                    iasCluster->enroll_req_timer = ZbTimerAlloc(cluster->zb, zcl_zone_enroll_req_timer, cluster);
                    if (iasCluster->enroll_req_timer == NULL) {
                        break;
                    }
                    ZCL_LOG_PRINTF(cluster->zb, __func__, "Enroll attempt in %d mS", ZB_NWK_RSP_DELAY_DEFAULT);
                    ZbTimerReset(iasCluster->enroll_req_timer, ZB_NWK_RSP_DELAY_DEFAULT);
                }
            }
            break;
        }

        case ZCL_IAS_ZONE_SVR_ATTR_CIE_ENDPOINT:
            /* This attribute is for persistence */
            if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) {
                iasCluster->ias_cie_endpoint = inputData[0];
            }
            break;

        default:
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
    return ZCL_STATUS_SUCCESS;
}

static void
zcl_ias_zone_server_cleanup(struct ZbZclClusterT *cluster)
{
    struct cluster_priv_t *iasCluster = (void *)cluster;

    if (iasCluster->test_mode_timer != NULL) {
        ZbTimerFree(iasCluster->test_mode_timer);
        iasCluster->test_mode_timer = NULL;
    }
}

enum ZclStatusCodeT
zcl_ias_zone_server_initiate_test_mode(struct ZbZclClusterT *cluster, struct ZbZclIasZoneClientTestModeReqT *req)
{
    struct cluster_priv_t *iasCluster = (void *)cluster;
    enum ZclStatusCodeT status;
    uint16_t zone_status;

    if (req->test_duration == 0) {
        return ZCL_STATUS_INVALID_VALUE;
    }

    zone_status = ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_IAS_ZONE_SVR_ATTR_ZONE_STATUS, NULL, &status);
    if (status != 0x00) {
        /* Shouldn't get here */
        /* EXEGIN - status code? */
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    if (zone_status & ZCL_IAS_ZONE_SVR_ZONE_STATUS_TEST) {
        /* No change. Spec doesn't say what to do.
         * We send a Default Response with INVALID_VALUE */
        return ZCL_STATUS_INVALID_VALUE;
    }

    ZCL_LOG_PRINTF(cluster->zb, __func__, "Initiating Test Operating Mode (duration = %d", req->test_duration);

    /* Enable the TEST status bit */
    zone_status |= ZCL_IAS_ZONE_SVR_ZONE_STATUS_TEST;
    ZbZclAttrIntegerWrite(cluster, ZCL_IAS_ZONE_SVR_ATTR_ZONE_STATUS, zone_status);

    ZbTimerReset(iasCluster->test_mode_timer, req->test_duration * 1000);

    if (iasCluster->callbacks.mode_change) {
        iasCluster->callbacks.mode_change(cluster, cluster->app_cb_arg, ZCL_IAS_ZONE_SVR_MODE_TEST, req);
    }
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
zcl_ias_zone_server_initiate_normal_mode(struct ZbZclClusterT *cluster)
{
    struct cluster_priv_t *iasCluster = (void *)cluster;
    enum ZclStatusCodeT status;
    uint16_t zone_status;

    zone_status = ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_IAS_ZONE_SVR_ATTR_ZONE_STATUS, NULL, &status);
    if (status != 0x00) {
        /* Shouldn't get here */
        /* EXEGIN - status code? */
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    if (!(zone_status & ZCL_IAS_ZONE_SVR_ZONE_STATUS_TEST)) {
        /* No change. Spec doesn't say what to do.
         * We send a Default Response with INVALID_VALUE */
        return ZCL_STATUS_INVALID_VALUE;
    }

    ZCL_LOG_PRINTF(cluster->zb, __func__, "Initiating Normal Operating Mode");

    /* Disable the TEST status bit */
    zone_status &= ~(ZCL_IAS_ZONE_SVR_ZONE_STATUS_TEST);
    ZbZclAttrIntegerWrite(cluster, ZCL_IAS_ZONE_SVR_ATTR_ZONE_STATUS, zone_status);

    ZbTimerStop(iasCluster->test_mode_timer);

    if (iasCluster->callbacks.mode_change != NULL) {
        status = iasCluster->callbacks.mode_change(cluster, cluster->app_cb_arg, ZCL_IAS_ZONE_SVR_MODE_NORMAL, NULL);
        if (status != 0x00) {
            return status;
        }
    }
    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
zcl_ias_zone_server_command(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *iasCluster = (void *)cluster;
    uint64_t src_addr;
    unsigned int i = 0;

    if (zclHdrPtr->frameCtrl.manufacturer) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    /* Incoming message must have an extended source address */
    if (dataIndPtr->src.mode == ZB_APSDE_ADDRMODE_EXT) {
        src_addr = dataIndPtr->src.extAddr;
    }
    else if (dataIndPtr->src.mode == ZB_APSDE_ADDRMODE_SHORT) {
        /* If SHORT, do address lookup */
        src_addr = ZbNwkAddrLookupExt(cluster->zb, dataIndPtr->src.nwkAddr);
        if (src_addr == 0) {
            /* Drop, don't send response */
            ZCL_LOG_PRINTF(cluster->zb, __func__, "Dropping command, no addressing mapping short to ext.");
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
        }
    }
    else {
        /* Drop, don't send response */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    /* Commands can only come from the IAS_CIE_Address */
    if (iasCluster->ias_cie_addr == 0) {
        /* Drop, don't send response */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }
    if (iasCluster->ias_cie_addr != src_addr) {
        /* Drop, don't send response */
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Dropping command, not from IAS_CIE_ADDR");
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    switch (zclHdrPtr->cmdId) {
        case ZCL_IAS_ZONE_CLI_CMD_ZONE_ENROLL_RESPONSE:
        {
            uint8_t enroll_status;
            uint8_t zone_id;

            if (iasCluster->enroll_active) {
                /* Ignore this message, we're in the middle of an enrollment
                 * request, which should be handled by zcl_ias_zone_server_enroll_callback. */
                return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            }
            /* If not doing request, this is an Auto-Enroll-Response */
            if (dataIndPtr->asduLength < 2) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            enroll_status = dataIndPtr->asdu[i++];
            zone_id = dataIndPtr->asdu[i++];
            if (enroll_status != ZCL_IAS_ZONE_CLI_RESP_SUCCESS) {
                /* Pretty strange if we get an unsolicited enroll response
                 * with an error status. */
                return ZCL_STATUS_SUCCESS;
            }
            /* EXEGIN - check if we're already enrolled? */
            zcl_ias_zone_server_enroll_success(cluster, zone_id);
            return ZCL_STATUS_SUCCESS;
        }

        case ZCL_IAS_ZONE_CLI_CMD_INITIATE_NORMAL_MODE:
            return zcl_ias_zone_server_initiate_normal_mode(cluster);

        case ZCL_IAS_ZONE_CLI_CMD_INITIATE_TEST_MODE:
        {
            struct ZbZclIasZoneClientTestModeReqT req;

            if (dataIndPtr->asduLength < 2) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            req.test_duration = dataIndPtr->asdu[i++];
            req.current_zone_sensitivity = dataIndPtr->asdu[i++];

            return zcl_ias_zone_server_initiate_test_mode(cluster, &req);
        }

        default:
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
}

static void
zcl_ias_zone_server_test_mode_timeout(struct ZigBeeT *zb, void *arg)
{
    struct ZbZclClusterT *cluster = arg;

    /* Go back to NORMAL operating mode */
    ZCL_LOG_PRINTF(cluster->zb, __func__, "Test mode has timed-out.");
    zcl_ias_zone_server_initiate_normal_mode(cluster);
}

static uint8_t
zcl_ias_zone_server_status_change_notify(struct ZbZclClusterT *cluster,
    struct ZbZclIasZoneServerStatusChangeNotifyT *notify)
{
    struct cluster_priv_t *iasCluster = (void *)cluster;
    uint8_t payload[6];
    unsigned int i = 0;
    struct ZbZclClusterCommandReqT req;

    if (iasCluster->ias_cie_addr == 0) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, ZCL_IAS_ZONE_SVR_ATTR_CIE_ADDR == 0");
        return ZCL_STATUS_FAILURE;
    }
    if (iasCluster->ias_cie_endpoint == ZB_ENDPOINT_BCAST) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, Zone CIE endpoint is unconfigured");
        return ZCL_STATUS_FAILURE;
    }

    putle16(&payload[i], notify->zone_status);
    i += 2;
    payload[i++] = notify->ext_status;
    payload[i++] = notify->zone_id;
    putle16(&payload[i], notify->delay);
    i += 2;

    (void)memset(&req, 0, sizeof(req));
    req.dst.mode = ZB_APSDE_ADDRMODE_EXT;
    req.dst.extAddr = iasCluster->ias_cie_addr;
    req.dst.endpoint = iasCluster->ias_cie_endpoint;
    req.cmdId = ZCL_IAS_ZONE_SVR_CMD_ZONE_STATUS_CHANGE_NOTIFY;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = i;

    ZCL_LOG_PRINTF(cluster->zb, __func__, "Sending notify to " LOGFMTx64 " (ZoneStatus = 0x%04x)",
        LOGVALx64(iasCluster->ias_cie_addr), notify->zone_status);

    return ZbZclClusterCommandReq(cluster, &req, NULL, NULL);
}

struct enroll_cb_t {
    struct ZbZclClusterT *cluster;
    void (*callback)(struct ZbZclIasZoneClientEnrollResponseT *enrl_rsp, void *arg);
    void *arg;
};

static void
zcl_ias_zone_server_enroll_success(struct ZbZclClusterT *cluster, uint8_t zone_id)
{
    /* If successful, save the ZoneID and update the ZoneState (enrolled) */
    ZbZclAttrIntegerWrite(cluster, ZCL_IAS_ZONE_SVR_ATTR_ZONE_ID, zone_id);
    ZbZclAttrIntegerWrite(cluster, ZCL_IAS_ZONE_SVR_ATTR_ZONE_STATE, ZCL_IAS_ZONE_SVR_STATE_ENROLLED);
}

static void
zcl_ias_zone_server_enroll_callback(struct ZbZclCommandRspT *zcl_rsp, void *arg)
{
    struct enroll_cb_t *cb = arg;
    struct cluster_priv_t *iasCluster = (void *)cb->cluster;
    uint8_t enroll_status = 0xff;
    uint8_t zone_id = 0x00;

    do {
        if (zcl_rsp->status) {
            break;
        }
        if (zcl_rsp->length < 2) {
            /* EXEGIN - Do we also need to send a Default Response back to
             * the sender that it was malformed? */
            break;
        }
        enroll_status = zcl_rsp->payload[0];
        zone_id = zcl_rsp->payload[1];
    } while (false);

    if (enroll_status == ZCL_IAS_ZONE_CLI_RESP_SUCCESS) {
        ZCL_LOG_PRINTF(cb->cluster->zb, __func__,
            "Success, IAS Zone Server Enroll Response (enroll_status = 0x%02x, zone_id = 0x%02x)",
            enroll_status, zone_id);
        zcl_ias_zone_server_enroll_success(cb->cluster, zone_id);
    }
    else {
        ZCL_LOG_PRINTF(cb->cluster->zb, __func__,
            "Error, IAS Zone Server Enroll Response (zcl_status = 0x%02x, enroll_status = 0x%02x)",
            zcl_rsp->status, enroll_status);
    }

    if (cb->callback) {
        struct ZbZclIasZoneClientEnrollResponseT enrl_rsp;

        enrl_rsp.zcl_status = zcl_rsp->status;
        enrl_rsp.enroll_status = (enum ZbZclIasZoneClientResponseCodeT)enroll_status;
        enrl_rsp.zone_id = zone_id;
        cb->callback(&enrl_rsp, cb->arg);
    }
    ZbHeapFree(cb->cluster->zb, cb);
    iasCluster->enroll_active = false;
}

enum ZclStatusCodeT
ZbZclIasZoneServerEnrollRequest(struct ZbZclClusterT *cluster,
    void (*callback)(struct ZbZclIasZoneClientEnrollResponseT *enrl_rsp, void *arg), void *arg)
{
    struct cluster_priv_t *iasCluster = (void *)cluster;
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[4];
    unsigned int i = 0;
    struct enroll_cb_t *cb;
    uint64_t cie_addr;
    enum ZclStatusCodeT status;
    uint16_t zone_type;

    if (iasCluster->enroll_active) {
        return ZCL_STATUS_FAILURE;
    }
    /* EXEGIN - check if we're already enrolled? */

    cie_addr = ZbZclAttrEuiRead(cluster, ZCL_IAS_ZONE_SVR_ATTR_CIE_ADDR, &status);
    if (status != 0x00) {
        ZCL_LOG_PRINTF(cluster->zb, __func__,
            "Error, cannot read ZCL_IAS_ZONE_SVR_ATTR_CIE_ADDR (status = 0x%02x)", status);
        return ZCL_STATUS_FAILURE;
    }
    if (cie_addr == 0) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, ZCL_IAS_ZONE_SVR_ATTR_CIE_ADDR is not configured");
        return ZCL_STATUS_FAILURE;
    }
    if (iasCluster->ias_cie_endpoint == ZB_ENDPOINT_BCAST) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, Zone CIE endpoint is unconfigured");
        return ZCL_STATUS_FAILURE;
    }

    zone_type = ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_IAS_ZONE_SVR_ATTR_ZONE_TYPE, NULL, &status);
    if (status != 0x00) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, cannot read ZCL_IAS_ZONE_SVR_ATTR_ZONE_TYPE");
        return ZCL_STATUS_FAILURE;
    }

    cb = ZbHeapAlloc(cluster->zb, sizeof(struct enroll_cb_t));
    if (cb == NULL) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
    cb->cluster = cluster;
    cb->callback = callback;
    cb->arg = arg;

    (void)memset(&req, 0, sizeof(req));
    req.dst.mode = ZB_APSDE_ADDRMODE_EXT;
    req.dst.extAddr = cie_addr;
    req.dst.endpoint = iasCluster->ias_cie_endpoint;
    req.cmdId = ZCL_IAS_ZONE_SVR_CMD_ZONE_ENROLL_REQUEST;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;

    putle16(&payload[i], zone_type);
    i += 2;
    putle16(&payload[i], iasCluster->manuf_code);
    i += 2;

    req.payload = payload;
    req.length = sizeof(payload);

    iasCluster->enroll_active = true;
    return ZbZclClusterCommandReq(cluster, &req, zcl_ias_zone_server_enroll_callback, cb);
}
