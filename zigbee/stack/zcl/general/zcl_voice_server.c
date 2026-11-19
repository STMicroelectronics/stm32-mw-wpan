/* Copyright [2019 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.voice.h"

static const struct ZbZclAttrT zcl_voice_server_attr_list[] = {
    /* Establishment Information Attribute Set */
    {
        ZCL_VOICE_ATTR_CODEC_TYPE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x01, 0x04}, {0, 0}
    },
    {
        ZCL_VOICE_ATTR_SAMP_FREQ, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x01, 0x03}, {0, 0}
    },
    {
        ZCL_VOICE_ATTR_CODECRATE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x01, 0x0a}, {0, 0}
    },
    {
        ZCL_VOICE_ATTR_ESTAB_TIMEOUT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0x01, 0xff}, {0, 0}
    },
#if 0
    {
        ZCL_VOICE_ATTR_CODEC_TYPE_SUB_1, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x01, 0x04}, {0, 0}
    },
    {
        ZCL_VOICE_ATTR_CODEC_TYPE_SUB_2, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x01, 0x04}, {0, 0}
    },
    {
        ZCL_VOICE_ATTR_CODEC_TYPE_SUB_3, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x01, 0x04}, {0, 0}
    },
    {
        ZCL_VOICE_ATTR_COMPRESSION_TYPE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0x01, 0x02}, {0, 0}
    },
    {
        ZCL_VOICE_ATTR_COMPRESSION_RATE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_VOICE_ATTR_OPTION_FLAGS, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x00, 0xff}, {0, 0}
    },
    {
        ZCL_VOICE_ATTR_COMPRESSION_RATE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x00, 0xff}, {0, 0}
    },
#endif
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct zcl_voice_server_callbacks_t callbacks;
};

static enum ZclStatusCodeT voice_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclVoiceServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct zcl_voice_server_callbacks_t *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_VOICE_OVER_ZIGBEE, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    memset(&clusterPtr->callbacks, 0, sizeof(clusterPtr->callbacks));
    if (callbacks != NULL) {
        memcpy(&clusterPtr->callbacks, callbacks, sizeof(clusterPtr->callbacks));
    }

    clusterPtr->cluster.command = voice_command;

    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_voice_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_voice_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
voice_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *voice_cluster = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclAddrInfoT src_info;
    uint8_t cmd_id = zclHdrPtr->cmdId;
    unsigned int length = 0;
    enum ZclStatusCodeT return_status = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

    (void)memset(&src_info, 0, sizeof(src_info));
    src_info.addr = dataIndPtr->src;
    src_info.seqnum = zclHdrPtr->seqNum;
    src_info.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    switch (cmd_id) {
        case ZCL_VOICE_CLI_ESTAB_REQ:
        {
            struct voice_estab_req_t req;

            if (dataIndPtr->asduLength < 5U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            if (voice_cluster->callbacks.estab_req == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.flag = dataIndPtr->asdu[length++];
            req.codec_type = dataIndPtr->asdu[length++];
            req.samp_freq = dataIndPtr->asdu[length++];
            req.codec_rate = dataIndPtr->asdu[length++];
            req.service_type = dataIndPtr->asdu[length++];
            if ((req.flag & ZCL_VOICE_FLAG_CODEC_TYPE_SUB_1) != 0U) {
                if (dataIndPtr->asduLength < length + 1U) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                req.codec_type_s1 = dataIndPtr->asdu[length++];
            }
            if ((req.flag & ZCL_VOICE_FLAG_CODEC_TYPE_SUB_2) != 0U) {
                if (dataIndPtr->asduLength < length + 1U) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                req.codec_type_s2 = dataIndPtr->asdu[length++];
            }
            if ((req.flag & ZCL_VOICE_FLAG_CODEC_TYPE_SUB_3) != 0U) {
                if (dataIndPtr->asduLength < length + 1U) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                req.codec_type_s3 = dataIndPtr->asdu[length++];
            }
            if ((req.flag & ZCL_VOICE_FLAG_COMPRESSION) != 0U) {
                if (dataIndPtr->asduLength < length + 2U) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                req.comp_type = dataIndPtr->asdu[length++];
                req.comp_rate = dataIndPtr->asdu[length++];
            }

            return_status = voice_cluster->callbacks.estab_req(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_VOICE_CLI_VOICE_TX:
        {
            struct voice_voice_tx_t req;

            if (voice_cluster->callbacks.voice_tx == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.voice_data = &dataIndPtr->asdu[0];
            req.voice_data_len = dataIndPtr->asduLength;

            return_status = voice_cluster->callbacks.voice_tx(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_VOICE_CLI_TX_COMPLETE:
            if (voice_cluster->callbacks.tx_complete == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            return_status = voice_cluster->callbacks.tx_complete(clusterPtr, &src_info, clusterPtr->app_cb_arg);
            break;

        default:
            return_status = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return return_status;
}

enum ZclStatusCodeT
ZbZclVoiceServerSendEstabRsp(struct ZbZclClusterT *clusterPtr,
    struct ZbZclAddrInfoT *dst, struct voice_estab_rsp_t *rsp)
{
    struct ZbApsBufT bufv[1];
    uint8_t rsp_payload[2];
    unsigned int length = 0;

    /* Form the payload */
    rsp_payload[length++] = rsp->ack_nak;
    if (rsp->codec_type) {
        rsp_payload[length++] = rsp->codec_type;
    }

    bufv[0].data = rsp_payload;
    bufv[0].len = length;

    return ZbZclClusterCommandRsp(clusterPtr, dst, (uint8_t)ZCL_VOICE_SVR_ESTAB_RSP, bufv, 1U);
}

enum ZclStatusCodeT
ZbZclVoiceServerSendVoiceTxRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct voice_voice_tx_rsp_t *rsp)
{
    struct ZbApsBufT bufv[1];
    uint8_t rsp_payload[2];
    unsigned int length = 0;

    /* Form the payload */
    rsp_payload[length++] = rsp->error_flag;

    bufv[0].data = rsp_payload;
    bufv[0].len = length;
    return ZbZclClusterCommandRsp(clusterPtr, dst, (uint8_t)ZCL_VOICE_SVR_VOICE_TX_RSP, bufv, 1U);
}

enum ZclStatusCodeT
ZbZclVoiceServerControlReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct voice_control_t *control_cmd, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[1];

    payload[0] = control_cmd->control_type;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_VOICE_SVR_CONTROL;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 1;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}
