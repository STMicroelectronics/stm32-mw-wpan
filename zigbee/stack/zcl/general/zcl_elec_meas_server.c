/* Copyright [2019 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.elec.meas.h"

static const struct ZbZclAttrT zcl_elec_meas_server_attr_list[] = {
    /* Basic Information */
    {
        ZCL_ELEC_MEAS_ATTR_MEAS_TYPE, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0x00000000, 0xffffffff}, {0, 0}
    },
    {
        ZCL_ELEC_MEAS_ATTR_DC_VOLT, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {ZCL_ELEC_MEAS_MIN_DC_MEAS, ZCL_ELEC_MEAS_MAX_DC_MEAS}, {0, 0}
    },
    {
        ZCL_ELEC_MEAS_ATTR_DC_VOLT_MIN, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {ZCL_ELEC_MEAS_MIN_DC_MEAS, ZCL_ELEC_MEAS_MAX_DC_MEAS}, {0, 0}
    },
    {
        ZCL_ELEC_MEAS_ATTR_DC_VOLT_MAX, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {ZCL_ELEC_MEAS_MIN_DC_MEAS, ZCL_ELEC_MEAS_MAX_DC_MEAS}, {0, 0}
    },
    {
        ZCL_ELEC_MEAS_ATTR_DC_VOLT_MULTIPLIER, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {ZCL_ELEC_MEAS_MIN_DC_FORMATTING, ZCL_ELEC_MEAS_MAX_DC_FORMATTING}, {0, 0}
    },
    {
        ZCL_ELEC_MEAS_ATTR_DC_VOLT_DIVISOR, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {ZCL_ELEC_MEAS_MIN_DC_FORMATTING, ZCL_ELEC_MEAS_MAX_DC_FORMATTING}, {0, 0}
    },
    {
        ZCL_ELEC_MEAS_ATTR_DC_OL_ALARMS_MASK, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {ZCL_ELEC_MEAS_MIN_OL_ALARMS_MASK, ZCL_ELEC_MEAS_MAX_OL_ALARMS_MASK}, {0, 0}
    },
    {
        ZCL_ELEC_MEAS_ATTR_DC_VOLT_OL, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct ZbZclElecMeasSvrCallbacksT callbacks;
};

static enum ZclStatusCodeT elec_command(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclElecMeasServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclElecMeasSvrCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_MEAS_ELECTRICAL, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "CCB 2236" (need to investigate what these changes are) */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    memset(&clusterPtr->callbacks, 0, sizeof(clusterPtr->callbacks));
    if (callbacks != NULL) {
        memcpy(&clusterPtr->callbacks, callbacks, sizeof(clusterPtr->callbacks));
    }

    clusterPtr->cluster.command = elec_command;

    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_elec_meas_server_attr_list,
            ZCL_ATTR_LIST_LEN(zcl_elec_meas_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ELEC_MEAS_ATTR_MEAS_TYPE, ZCL_ELEC_MEAS_DEFAULT_MEAS_TYPE);

    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ELEC_MEAS_ATTR_DC_VOLT, ZCL_ELEC_MEAS_DEFAULT_DC_MEAS);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ELEC_MEAS_ATTR_DC_VOLT_MIN, ZCL_ELEC_MEAS_DEFAULT_DC_MEAS);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ELEC_MEAS_ATTR_DC_VOLT_MAX, ZCL_ELEC_MEAS_DEFAULT_DC_MEAS);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ELEC_MEAS_ATTR_DC_VOLT_MULTIPLIER, ZCL_ELEC_MEAS_DEFAULT_DC_FORMATTING);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ELEC_MEAS_ATTR_DC_VOLT_DIVISOR, ZCL_ELEC_MEAS_DEFAULT_DC_FORMATTING);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ELEC_MEAS_ATTR_DC_OL_ALARMS_MASK, ZCL_ELEC_MEAS_DEFAULT_DC_OL_ALARMS_MASK);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ELEC_MEAS_ATTR_DC_VOLT_OL, ZCL_ELEC_MEAS_DEFAULT_DC_VOLT_OL);

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
elec_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *elec_meas_cluster = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclAddrInfoT src_info;
    uint8_t cmd_id = zclHdrPtr->cmdId;
    enum ZclStatusCodeT return_status = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

    (void)memset(&src_info, 0, sizeof(src_info));
    src_info.addr = dataIndPtr->src;
    src_info.seqnum = zclHdrPtr->seqNum;
    src_info.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    switch (cmd_id) {
        case ZCL_ELEC_MEAS_CLI_GET_PROFILE_INFO:
        {
            if (elec_meas_cluster->callbacks.get_profile_info == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            return_status = elec_meas_cluster->callbacks.get_profile_info(clusterPtr, &src_info, clusterPtr->app_cb_arg);
            break;
        }
        case ZCL_ELEC_MEAS_CLI_GET_MEAS_PROFILE:
        {
            struct ZbZclElecMeasClientGetMeasProfileReqT req;
            memset(&req, 0, sizeof(req));

            if (elec_meas_cluster->callbacks.get_meas_profile == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            req.attr_id = pletoh16(dataIndPtr->asdu);
            req.start_time = pletoh32(&dataIndPtr->asdu[2]);
            req.num_intervals = dataIndPtr->asdu[6];

            return_status = elec_meas_cluster->callbacks.get_meas_profile(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }
        default:
            return_status = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return return_status;
}

enum ZclStatusCodeT
ZbZclElecMeasServerSendProfileInfoRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst_info,
    struct ZbZclElecMeasSvrGetProfileInfoRspT *rsp)
{
    uint8_t rsp_payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbApsBufT bufv[1];
    uint8_t i;

    /* Form the payload */
    rsp_payload[length++] = rsp->profile_count;
    rsp_payload[length++] = rsp->profile_interval_period;
    rsp_payload[length++] = rsp->max_num_intervals;
    for (i = 0U; i < rsp->profile_count; i++) {
        if ((length + 2U) > sizeof(rsp_payload)) {
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }
        putle16(&rsp_payload[length], rsp->attr_list[i]);
        length += 2U;
    }

    bufv[0].data = rsp_payload;
    bufv[0].len = length;

    return ZbZclClusterCommandRsp(clusterPtr, dst_info, (uint8_t)ZCL_ELEC_MEAS_SVR_GET_PROFILE_INFO_RSP, bufv, 1U);
}

enum ZclStatusCodeT
ZbZclElecMeasServerSendMeasProfileRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst_info,
    struct ZbZclElecMeasSvrGetMeasProfileRspT *rsp)
{
    uint8_t rsp_payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbApsBufT bufv[1];

    /* Form the payload */
    putle32(&rsp_payload[length], rsp->start_time);
    length += 4U;
    rsp_payload[length++] = rsp->status;
    rsp_payload[length++] = rsp->profile_interval_period;
    rsp_payload[length++] = rsp->num_intervals_delivered;
    putle16(&rsp_payload[length], rsp->attr_id);
    length += 2U;
    (void)memcpy(&rsp_payload[length], rsp->interval_data, rsp->interval_len);
    length += rsp->interval_len;

    bufv[0].data = rsp_payload;
    bufv[0].len = length;

    return ZbZclClusterCommandRsp(clusterPtr, dst_info, (uint8_t)ZCL_ELEC_MEAS_SVR_GET_MEAS_PROFILE_RSP, bufv, 1U);
}
