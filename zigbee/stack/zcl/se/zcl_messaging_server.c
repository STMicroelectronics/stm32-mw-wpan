/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

/*-------------------------------------------------
 *  DESCRIPTION
 *      The source code implementing the Smart
 *      Energy messaging cluster.
 *-------------------------------------------------
 */

#include "zcl/se/zcl.message.h"
#include "zcl/zcl.payload.h"

/*lint -e826 "suspicious ptr-to-ptr conversion [LINT]" */
/*lint -e9087 "cast *A <- *B [MISRA Rule 11.3 (REQUIRED)]" */

/* Message state. */
#define ZCL_MESSAGE_STATE_EMPTY                     0x00 /* No Messages present. */
#define ZCL_MESSAGE_STATE_ACTIVE                    0x01 /* Message is being displayed */
#define ZCL_MESSAGE_STATE_PENDING                   0x02 /* Message is waiting for the start time to elapse. */

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclMsgServerCallbacksT callbacks;
};

/* Command callback functions. */
static enum ZclStatusCodeT msg_server_command(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclMsgServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclMsgServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    /* must implement mandatory commands, optional ones not checked */
    if (callbacks == NULL) {
        return NULL;
    }
    if ((callbacks->get_last_message == NULL) || (callbacks->message_confirmation == NULL)) {
        return NULL;
    }

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_MESSAGING, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.command = msg_server_command;

    if (callbacks != NULL) {
        (void)memcpy(&clusterPtr->callbacks, callbacks, sizeof(struct ZbZclMsgServerCallbacksT));
    }
    else {
        (void)memset(&clusterPtr->callbacks, 0, sizeof(struct ZbZclMsgServerCallbacksT));
    }

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

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static int
display_message_build(uint8_t *payload, unsigned int max_len, struct ZbZclMsgMessageT *msg)
{
    unsigned int index = 0;
    unsigned int str_len;

    str_len = strlen(msg->message_str);
    if (str_len > ZCL_MESSAGE_MAX_LENGTH) {
        return -1;
    }

    if (zb_zcl_append_uint32(payload, max_len, &index, msg->message_id) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, msg->message_control) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint32(payload, max_len, &index, msg->start_time) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, max_len, &index, msg->duration) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, (uint8_t)str_len) < 0) {
        return -1;
    }
    if (str_len > 0U) {
        if ((str_len + index) > max_len) {
            return -1;
        }
        (void)memcpy(&payload[index], msg->message_str, str_len);
        index += str_len;
    }
    /* optional but we always send it */
    payload[index++] = msg->extended_control;
    return (int)index;
}

enum ZclStatusCodeT
ZbZclMsgServerDisplayMessageReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst, struct ZbZclMsgMessageT *msg,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    int length;
    struct ZbZclClusterCommandReqT req;

    /* EXEGIN - Do we adjust startime and duration like we do for GET_LAST_MESSAGE? */

    length = display_message_build(payload, sizeof(payload), msg);
    if (length < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_MESSAGE_SVR_CMD_DISPLAY_MESSAGE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = (unsigned int)length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclMsgServerDisplayProtectedMsgReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst, struct ZbZclMsgMessageT *msg,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    int length;
    struct ZbZclClusterCommandReqT req;

    /* EXEGIN - Do we adjust startime and duration like we do for ZCL_MESSAGE_GET_LAST_MESSAGE? */

    length = display_message_build(payload, sizeof(payload), msg);
    if (length < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_MESSAGE_SVR_CMD_DISPLAY_PROTECTED_MESSAGE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = (unsigned int)length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

static int
cancel_message_build(uint8_t *payload, unsigned int max_len, struct ZbZclMsgMessageCancelT *cancel)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint32(payload, max_len, &index, cancel->message_id) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, cancel->control) < 0) {
        return -1;
    }
    return (int)index;
}

enum ZclStatusCodeT
ZbZclMsgServerCancelMessageReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclMsgMessageCancelT *cancel,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    int length;
    struct ZbZclClusterCommandReqT req;

    length = cancel_message_build(payload, sizeof(payload), cancel);
    if (length < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_MESSAGE_SVR_CMD_CANCEL_MESSAGE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = (unsigned int)length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclMsgServerCancelAllReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclMsgMessageCancelAllT *cancel_all,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    if (zb_zcl_append_uint32(payload, ZCL_PAYLOAD_UNFRAG_SAFE_SIZE, &length, cancel_all->implementation_time) < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_MESSAGE_SVR_CMD_CANCEL_ALL_MESSAGES;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = (unsigned int)length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

static enum ZclStatusCodeT
msg_server_command(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *msg_server = (struct cluster_priv_t *)cluster;
    struct ZbZclAddrInfoT source;
    enum ZclStatusCodeT rc = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

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

    (void)memset(&source, 0, sizeof(struct ZbZclAddrInfoT));
    source.addr = dataIndPtr->src;
    source.seqnum = zclHdrPtr->seqNum;
    source.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    switch (zclHdrPtr->cmdId) {
        case (uint8_t)ZCL_MESSAGE_CLI_CMD_GET_LAST_MESSAGE:
            if (msg_server->callbacks.get_last_message == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            rc = msg_server->callbacks.get_last_message(cluster, msg_server->cluster.app_cb_arg, &source);
            break;

        case (uint8_t)ZCL_MESSAGE_CLI_CMD_MESSAGE_CONFIRM:
        {
            struct ZbZclMsgMessageConfT confirm;
            unsigned int i = 0;
            uint8_t str_len;

            if (msg_server->callbacks.message_confirmation == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            if (dataIndPtr->asduLength < 8) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            (void)memset(&confirm, 0, sizeof(struct ZbZclMsgMessageConfT));
            confirm.message_id = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            confirm.confirm_time = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            if (dataIndPtr->asduLength > i) {
                confirm.has_confirm_control = true;
                confirm.confirm_control = dataIndPtr->asdu[i++];
                if (dataIndPtr->asduLength > i) {
                    confirm.has_confirm_response = true;
                    str_len = dataIndPtr->asdu[i++];
                    if (str_len > ZCL_MESSAGE_CONF_RSP_LEN) {
                        return ZCL_STATUS_MALFORMED_COMMAND;
                    }
                    confirm.confirm_response[0] = str_len;
                    (void)memcpy(&confirm.confirm_response[1], &dataIndPtr->asdu[i], str_len);
                }
                else {
                    confirm.has_confirm_response = false;
                }
            }
            else {
                confirm.has_confirm_control = false;
            }
            rc = msg_server->callbacks.message_confirmation(cluster, msg_server->cluster.app_cb_arg, &confirm, &source);
            break;
        }

        case (uint8_t)ZCL_MESSAGE_CLI_CMD_GET_MESSAGE_CANCELLATION:
        {
            struct ZbZclMsgGetMsgCancellationT msg_cancel;

            if (msg_server->callbacks.get_message_cancellation == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            msg_cancel.earliest_impl_time = pletoh32(&dataIndPtr->asdu[0]);
            rc = msg_server->callbacks.get_message_cancellation(cluster, msg_server->cluster.app_cb_arg, &msg_cancel, &source);
            break;
        }

        default:
            rc = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return rc;
}
