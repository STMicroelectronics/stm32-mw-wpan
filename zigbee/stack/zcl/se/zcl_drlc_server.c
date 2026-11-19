/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

/*-------------------------------------------------
 *  DESCRIPTION
 *      The Smart Energy Demand Response and Load Control
 *  server cluster.
 *-------------------------------------------------
 */

#include "zcl/se/zcl.drlc.h"
#include "zcl/general/zcl.time.h"
#include "zcl/zcl.payload.h"

/*lint -e826 "suspicious ptr-to-ptr conversion [LINT]" */
/*lint -e9087 "cluster_priv_t* <- ZbZclClusterT* [MISRA Rule 11.3 (REQUIRED)]" */

/* The DRLC Client Server struct - allocated by ZbZclDrlcServer */
struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct ZbZclDrlcServerCallbacksT callbacks;
};

static enum ZclStatusCodeT zcl_drlc_server_handle_command(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclDrlcServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclDrlcServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_DRLC, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.command = zcl_drlc_server_handle_command;

    /* Assume this is for SE */
    ZbZclClusterSetProfileId(&clusterPtr->cluster, ZCL_PROFILE_SMART_ENERGY);

    if (!ZbZclClusterSetMinSecurity(&clusterPtr->cluster, ZB_APS_STATUS_SECURED_LINK_KEY)) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }
    if (!ZbZclClusterSetMaxAsduLength(&clusterPtr->cluster, ZCL_ASDU_LENGTH_SMART_ENERGY)) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Set the callback argument and attach callbacks */
    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);
    if (callbacks != NULL) {
        (void)memcpy(&clusterPtr->callbacks, callbacks, sizeof(struct ZbZclDrlcServerCallbacksT));
    }
    else {
        (void)memset(&clusterPtr->callbacks, 0, sizeof(struct ZbZclDrlcServerCallbacksT));
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_drlc_server_handle_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    unsigned int i = 0;
    enum ZclStatusCodeT status = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    struct ZbZclAddrInfoT srcInfo;

    (void)memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zclHdrPtr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Processing command 0x%02x", zclHdrPtr->cmdId);

    switch (zclHdrPtr->cmdId) {
        case (uint8_t)ZCL_DRLC_COMMAND_REPORT_EVENT_STATUS:
        {
            struct ZbZclDrlcStatusT eventStatus;

            /* Sanity-check the length of the DRLC event status. */
            if (dataIndPtr->asduLength < 18U) {
                status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            /* Parse the report event status command. */
            eventStatus.issuer_id = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            eventStatus.status = dataIndPtr->asdu[i++];
            eventStatus.status_time = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            eventStatus.crit_level_applied = dataIndPtr->asdu[i++];
            eventStatus.cool_setpoint_applied = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            eventStatus.heat_setpoint_applied = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            eventStatus.avg_load_adj_applied = (int8_t)dataIndPtr->asdu[i++];
            eventStatus.dutycycle_applied = dataIndPtr->asdu[i++];
            eventStatus.event_control = dataIndPtr->asdu[i++];
            /*lint -e{9034} "ZbZclDrlcSignatureT* <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
            eventStatus.sig_type = (enum ZbZclDrlcSignatureT)dataIndPtr->asdu[i++];
            if (eventStatus.sig_type != ZCL_DRLC_SIGNATURE_TYPE_NONE) {
                if ((i + ZCL_DRLC_SIGNATURE_LENGTH) > dataIndPtr->asduLength) {
                    status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                (void)memcpy(eventStatus.sig_data, &dataIndPtr->asdu[i], ZCL_DRLC_SIGNATURE_LENGTH);
                /* Last entry, don't increment 'i' */
            }

            /* If a callback was specified for the report event status command, handle it now. */
            if (serverPtr->callbacks.report_status != NULL) {
                serverPtr->callbacks.report_status(clusterPtr, &srcInfo, &eventStatus, serverPtr->cluster.app_cb_arg);
            }
            status = ZCL_STATUS_SUCCESS;
            break;
        }

        case (uint8_t)ZCL_DRLC_COMMAND_GET_SCHEDULED_EVENTS:
        {
            struct ZbZclDrlcGetEventsReqT get_events;

            (void)memset(&get_events, 0, sizeof(get_events));
            get_events.issuer_id = ZCL_DRLC_ISSUER_ID_INVALID;

            /* Parse the get scheduled events command. */
            if ((i + 5U) > dataIndPtr->asduLength) {
                status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            get_events.start_time = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            get_events.num_events = dataIndPtr->asdu[i++];
            if ((i + 4U) <= dataIndPtr->asduLength) {
                get_events.issuer_id = pletoh32(&dataIndPtr->asdu[i]);
                /* Last entry, don't increment 'i' */
            }
            if (serverPtr->callbacks.get_events == NULL) {
                status = ZCL_STATUS_NOT_FOUND;
            }
            else {
                status = serverPtr->callbacks.get_events(clusterPtr, &srcInfo, &get_events, serverPtr->cluster.app_cb_arg);
            }
            break;
        }

        default:
            status = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return status;
}

static int
ZbZclDrlcServerEventBuild(struct ZbZclDrlcEventT *eventPtr, uint8_t *payload, unsigned int max_len)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint32(payload, max_len, &index, eventPtr->issuer_id) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, max_len, &index, eventPtr->device_class) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, eventPtr->util_enrol_group) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint32(payload, max_len, &index, eventPtr->start_time) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, max_len, &index, eventPtr->duration) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, (uint8_t)eventPtr->criticality) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, eventPtr->cool_offset) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, eventPtr->heat_offset) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, max_len, &index, (uint16_t)eventPtr->cool_setpoint) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, max_len, &index, (uint16_t)eventPtr->heat_setpoint) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, (uint8_t)eventPtr->avg_load_adj) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, eventPtr->dutycycle) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, eventPtr->event_control) < 0) {
        return -1;
    }
    return (int)index;
}

enum ZclStatusCodeT
ZbZclDrlcServerCommandEventReq(struct ZbZclClusterT *cluster, struct ZbZclDrlcEventT *eventPtr, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    int length;
    struct ZbZclClusterCommandReqT req;

    length = ZbZclDrlcServerEventBuild(eventPtr, payload, sizeof(payload));
    if (length < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLC_COMMAND_EVENT;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = (unsigned int)length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

static int
ZbZclDrlcServerCancelBuild(struct ZbZclDrlcCancelT *cancelInfoPtr, uint8_t *payload, unsigned int max_len)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint32(payload, max_len, &index, cancelInfoPtr->issuer_id) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, max_len, &index, cancelInfoPtr->device_class) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, cancelInfoPtr->util_enrol_group) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, cancelInfoPtr->cancel_control) < 0) {
        return -1;
    }
    /* Effective time is deprecated and must zero. */
    if (zb_zcl_append_uint32(payload, max_len, &index, 0) < 0) {
        return -1;
    }
    return (int)index;
}

enum ZclStatusCodeT
ZbZclDrlcServerCommandCancelReq(struct ZbZclClusterT *cluster, struct ZbZclDrlcCancelT *cancelInfoPtr, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    int length;
    struct ZbZclClusterCommandReqT req;

    length = ZbZclDrlcServerCancelBuild(cancelInfoPtr, payload, sizeof(payload));
    if (length < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLC_COMMAND_CANCEL_EVENT;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = (unsigned int)length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

static int
ZbZclDrlcServerCancelAllBuild(uint8_t ctrl, uint8_t *payload, unsigned int max_len)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, max_len, &index, ctrl) < 0) {
        return -1;
    }
    return (int)index;
}

enum ZclStatusCodeT
ZbZclDrlcServerCommandCancelAllReq(struct ZbZclClusterT *cluster, uint8_t ctrl, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    int length;
    struct ZbZclClusterCommandReqT req;

    length = ZbZclDrlcServerCancelAllBuild(ctrl, payload, sizeof(payload));
    if (length < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLC_COMMAND_CANCEL_ALL;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = (unsigned int)length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}
