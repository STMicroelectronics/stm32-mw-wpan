/* Copyright [2019 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.voice.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct zcl_voice_client_callbacks_t callbacks;
};

static enum ZclStatusCodeT voice_client_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclVoiceClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct zcl_voice_client_callbacks_t *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_VOICE_OVER_ZIGBEE, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    memset(&clusterPtr->callbacks, 0, sizeof(clusterPtr->callbacks));
    if (callbacks != NULL) {
        memcpy(&clusterPtr->callbacks, callbacks, sizeof(clusterPtr->callbacks));
    }

    clusterPtr->cluster.command = voice_client_command;

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

enum ZclStatusCodeT
ZbZclVoiceClientEstabReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct voice_estab_req_t *estab_req, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[10];
    unsigned int length = 0;

    payload[length++] = estab_req->flag;
    payload[length++] = estab_req->codec_type;
    payload[length++] = estab_req->samp_freq;
    payload[length++] = estab_req->codec_rate;
    payload[length++] = estab_req->service_type;
    if (estab_req->flag & ZCL_VOICE_FLAG_CODEC_TYPE_SUB_1) {
        payload[length++] = estab_req->codec_type_s1;
    }
    if (estab_req->flag & ZCL_VOICE_FLAG_CODEC_TYPE_SUB_2) {
        payload[length++] = estab_req->codec_type_s2;
    }
    if (estab_req->flag & ZCL_VOICE_FLAG_CODEC_TYPE_SUB_3) {
        payload[length++] = estab_req->codec_type_s3;
    }
    if (estab_req->flag & ZCL_VOICE_FLAG_COMPRESSION) {
        payload[length++] = estab_req->comp_type;
        payload[length++] = estab_req->comp_rate;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_VOICE_CLI_ESTAB_REQ;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclVoiceVoiceTxReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct voice_voice_tx_t *voice_tx, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;

    if ((voice_tx->voice_data == NULL) || (voice_tx->voice_data_len == 0U)) {
        return ZCL_STATUS_INVALID_VALUE;
    }

    (void)memcpy(&payload[length], voice_tx->voice_data, voice_tx->voice_data_len);
    length += voice_tx->voice_data_len;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_VOICE_CLI_VOICE_TX;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclVoiceTxCompletedReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_VOICE_CLI_TX_COMPLETE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = NULL;
    req.length = 0U;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclVoiceClientSendControlRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst_info, struct voice_control_rsp_t *rsp)
{
    uint8_t rsp_payload[1];
    unsigned int length = 0;
    struct ZbApsBufT bufv[1];

    /* Form the payload */
    rsp_payload[length++] = rsp->ack_nak;

    bufv[0].data = rsp_payload;
    bufv[0].len = length;

    return ZbZclClusterCommandRsp(clusterPtr, dst_info, (uint8_t)ZCL_VOICE_CLI_CONTROL_RSP, bufv, 1U);
}

static enum ZclStatusCodeT
voice_client_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *voice_cluster = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclAddrInfoT src_info;
    uint8_t cmd_id = zclHdrPtr->cmdId;
    enum ZclStatusCodeT return_status = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

    (void)memset(&src_info, 0, sizeof(src_info));
    src_info.addr = dataIndPtr->src;
    src_info.seqnum = zclHdrPtr->seqNum;
    src_info.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    switch (cmd_id) {
        case ZCL_VOICE_SVR_CONTROL:
        {
            struct voice_control_t req;

            if (dataIndPtr->asduLength < 1U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            if (voice_cluster->callbacks.control == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));
            req.control_type = dataIndPtr->asdu[0];
            return_status = voice_cluster->callbacks.control(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        default:
            return_status = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return return_status;
}
