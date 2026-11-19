/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

/*----------------------------------------------------------------------------
 *    Smart Energy Messaging Cluster
 *----------------------------------------------------------------------------
 */

#include "zcl/se/zcl.message.h"
#include "zcl/zcl.payload.h"

/* #define COND_ZCL_MESSAGE_ENHANCED_ALLOW */

/*lint -e9087 "ZbZclMessageClientT*<- ZbZclClusterT* [MISRA Rule 11.3 (REQUIRED)]" */

#define TIME_STR_LEN_MAX                            128U

/* Size of Message commands. */
#define ZCL_MESSAGE_DISPLAY_MIN_SIZE                12U
#define ZCL_MESSAGE_CANCEL_MIN_SIZE                 5U
#define ZCL_MESSAGE_CANCEL_ALL_MIN_SIZE             4U

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclMsgClientCallbacksT callbacks;
};

static enum ZclStatusCodeT ZbZclMessageClientCommand(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

/*----------------------------------------------------------------------------
 *  NAME
 *      ZbZclMessageClientAlloc
 *  DESCRIPTION
 *      Initializes an instance of the ZCL message client on a given endpoint.
 *  PARAMETERS
 *      zb              ZigBee stack.
 *      callback        Callback function to start/stop displaying messages.
 *      arg             Argument to the callback functions.
 *  RETURNS
 *      ZbZclClusterT * ZCL cluster struct.
 *----------------------------------------------------------------------------
 */
struct ZbZclClusterT *
ZbZclMsgClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclMsgClientCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *client;

    client = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_MESSAGING, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (client == NULL) {
        return NULL;
    }
    client->cluster.command = ZbZclMessageClientCommand;

    if (callbacks != NULL) {
        (void)memcpy(&client->callbacks, callbacks, sizeof(struct ZbZclMsgClientCallbacksT));
    }
    else {
        (void)memset(&client->callbacks, 0, sizeof(struct ZbZclMsgClientCallbacksT));
    }

    /* Assume this is for SE */
    ZbZclClusterSetProfileId(&client->cluster, ZCL_PROFILE_SMART_ENERGY);

    if (!ZbZclClusterSetMinSecurity(&client->cluster, ZB_APS_STATUS_SECURED_LINK_KEY)) {
        ZbZclClusterFree(&client->cluster);
        return NULL;
    }
    if (!ZbZclClusterSetMaxAsduLength(&client->cluster, ZCL_ASDU_LENGTH_SMART_ENERGY)) {
        ZbZclClusterFree(&client->cluster);
        return NULL;
    }

    ZbZclClusterSetCallbackArg(&client->cluster, arg);

    (void)ZbZclClusterAttach(&client->cluster);
    return &client->cluster;
}

static enum ZclStatusCodeT
ZbZclMessageClientCommand(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclAddrInfoT src_info;
    enum ZclStatusCodeT rc;
    unsigned int i = 0;

    if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    (void)memset(&src_info, 0, sizeof(src_info));
    src_info.addr = dataIndPtr->src;
    src_info.seqnum = zclHdrPtr->seqNum;
    src_info.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    switch (zclHdrPtr->cmdId) {
        case (uint8_t)ZCL_MESSAGE_SVR_CMD_DISPLAY_MESSAGE:
        case (uint8_t)ZCL_MESSAGE_SVR_CMD_DISPLAY_PROTECTED_MESSAGE:
        {
            struct ZbZclMsgMessageT msg;
            uint8_t msg_len;

            memset(&msg, 0, sizeof(msg));
            if (client->callbacks.display_message == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            if (dataIndPtr->asduLength < ZCL_MESSAGE_DISPLAY_MIN_SIZE) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            msg.message_id = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            msg.message_control = dataIndPtr->asdu[i++];
            msg.start_time = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            msg.duration = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            msg_len = dataIndPtr->asdu[i++];
            if (((msg_len + i) > dataIndPtr->asduLength) || (msg_len > ZCL_MESSAGE_MAX_LENGTH)) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            memcpy(msg.message_str, &dataIndPtr->asdu[i], msg_len);
            i += msg_len;
            if (i < dataIndPtr->asduLength) {
                msg.extended_control = dataIndPtr->asdu[i];
            }

            if (zclHdrPtr->cmdId == ZCL_MESSAGE_SVR_CMD_DISPLAY_MESSAGE) {
                rc = client->callbacks.display_message(clusterPtr, client->cluster.app_cb_arg, &msg, &src_info);
            }
            else {
                rc = client->callbacks.display_protected_message(clusterPtr, client->cluster.app_cb_arg, &msg, &src_info);
            }
            break;
        }

        case (uint8_t)ZCL_MESSAGE_SVR_CMD_CANCEL_MESSAGE:
        {
            struct ZbZclMsgMessageCancelT cancel;

            memset(&cancel, 0, sizeof(cancel));
            if (client->callbacks.cancel_message == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            if (dataIndPtr->asduLength < ZCL_MESSAGE_CANCEL_MIN_SIZE) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            cancel.message_id = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            cancel.control = dataIndPtr->asdu[i];

            rc = client->callbacks.cancel_message(clusterPtr, client->cluster.app_cb_arg, &cancel, &src_info);
            break;
        }

        case (uint8_t)ZCL_MESSAGE_SVR_CMD_CANCEL_ALL_MESSAGES:
        {
            struct ZbZclMsgMessageCancelAllT cancel_all;

            memset(&cancel_all, 0, sizeof(cancel_all));
            if (client->callbacks.cancel_all_messages == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            if (dataIndPtr->asduLength < ZCL_MESSAGE_CANCEL_ALL_MIN_SIZE) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            cancel_all.implementation_time = pletoh32(&dataIndPtr->asdu[i]);

            rc = client->callbacks.cancel_all_messages(clusterPtr, client->cluster.app_cb_arg, &cancel_all, &src_info);
            break;
        }

        default:
            rc = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }

    return rc;
}

enum ZclStatusCodeT
ZbZclMsgClientGetLastReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_MESSAGE_CLI_CMD_GET_LAST_MESSAGE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

/*----------------------------------------------------------------------------
 *  NAME
 *      ZbZclMsgClientConfReq
 *  DESCRIPTION
 *      none
 *  PARAMETERS
 *      cluster                  client instance from which to send ZCL command
 *      dst                      destination (server) address
 *      msg_conf                 data to include in confirmation message
 *      callback                 callback to be invoked for reply
 *      arg                      data to pass back to callback when invoked
 *  RETURNS
 *      enum ZclStatusCodeT      status of request on sending
 *----------------------------------------------------------------------------
 */
enum ZclStatusCodeT
ZbZclMsgClientConfReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclMsgConfirmT *msg_conf, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    if (zb_zcl_append_uint32(payload, sizeof(payload), &length, msg_conf->message_id) < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
    if (zb_zcl_append_uint32(payload, sizeof(payload), &length, msg_conf->confirm_time) < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_MESSAGE_CLI_CMD_MESSAGE_CONFIRM;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = (uint32_t)length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

#ifdef COND_ZCL_MESSAGE_ENHANCED_ALLOW
static int
ZbZclMessageClientConfEnhBuild(uint8_t *payload, unsigned int max_len, struct ZbZclMsgConfirmEnhT *msg_conf_enh)
{
    unsigned int index = 0;
    unsigned int str_len;

    if (zb_zcl_append_uint32(payload, max_len, &index, msg_conf_enh->message_id) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint32(payload, max_len, &index, msg_conf_enh->confirm_time) < 0) {
        return -1;
    }

    /* Message Confirmation Control */
    if (zb_zcl_append_uint8(payload, max_len, &index, msg_conf_enh->confirm_control) < 0) {
        return -1;
    }

    /* Message Confirmation Response (Octet String) */
    str_len = strlen(msg_conf_enh->confirm_response);
    if (str_len > ZCL_MESSAGE_CONFIRM_ENH_RSP_MAX_LEN) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, max_len, &index, (uint8_t)str_len) < 0) {
        return -1;
    }

    if (str_len != 0U) {
        if ((str_len + index) > max_len) {
            return -1;
        }
        (void)memcpy(&payload[index], msg_conf_enh->confirm_response, str_len);
        index += str_len;
    }
    return ((int)index);
}

/*----------------------------------------------------------------------------
 *  NAME
 *      ZbZclMsgClientConfReq
 *  DESCRIPTION
 *      send a Message Confirmation ZCL message to the server
 *  PARAMETERS
 *      cluster                  client instance from which to send ZCL command
 *      dst                      destination (server) address
 *      msg_conf_enh             data to include in enhanced confirmation message
 *      callback                 callback to be invoked for reply
 *      arg                      data to pass back to callback when invoked
 *  RETURNS
 *      enum ZclStatusCodeT      status of request on sending
 *----------------------------------------------------------------------------
 */
enum ZclStatusCodeT
ZbZclMsgClientConfExtReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclMsgConfirmEnhT *msg_conf_enh,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    int length = 0;
    struct ZbZclClusterCommandReqT req;

    length = ZbZclMessageClientConfEnhBuild(&payload[length], sizeof(payload), msg_conf_enh);
    if (length < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_MESSAGE_CLI_CMD_MESSAGE_CONFIRM;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = (uint32_t)length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

#endif

/*----------------------------------------------------------------------------
 *  NAME
 *      ZbZclMsgClientGetMsgCancelReq
 *  DESCRIPTION
 *      send a Get Message Cancellation ZCL message to the server
 *  PARAMETERS
 *      cluster                  client instance from which to send ZCL command
 *      dst                      destination (server) address
 *      earliest_time            earliest time for requested cancellation messages
 *      callback                 callback to be invoked for reply
 *      arg                      data to pass back to callback when invoked
 *  RETURNS
 *      enum ZclStatusCodeT      status of request on sending
 *----------------------------------------------------------------------------
 */
enum ZclStatusCodeT
ZbZclMsgClientGetMsgCancelReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    uint32_t earliest_time, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    if (zb_zcl_append_uint32(payload, sizeof(payload), &length, earliest_time) < 0) {
        return ((int)ZCL_STATUS_INSUFFICIENT_SPACE);
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_MESSAGE_CLI_CMD_GET_MESSAGE_CANCELLATION;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = (uint32_t)length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}
