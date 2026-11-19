/* Copyright [2019 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.rssi.loc.h"

static enum ZclStatusCodeT zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attributeId,
    const uint8_t *inputData, unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg);

static enum ZclStatusCodeT
zcl_attr_cb(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrCbInfoT *cb)
{
    if (cb->type == ZCL_ATTR_CB_TYPE_WRITE) {
        return zcl_attr_write_cb(clusterPtr, cb->src, cb->info->attributeId, cb->zcl_data, cb->zcl_len,
            cb->attr_data, cb->write_mode, cb->app_cb_arg);
    }
    else {
        return ZCL_STATUS_FAILURE;
    }
}

static const struct ZbZclAttrT zcl_rssi_loc_server_attr_list[] = {
    /* Location Information Attribute Set */
    {
        ZCL_RSSI_LOC_SVR_ATTR_LOCATION_TYPE, ZCL_DATATYPE_GENERAL_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x00, 0x0f}, {0, 0}
    },
    {
        ZCL_RSSI_LOC_SVR_ATTR_LOCATION_METHOD, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_RSSI_LOC_SVR_ATTR_LOCATION_AGE, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_RSSI_LOC_SVR_ATTR_QUALITY_MEAS, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0x00, 0x64}, {0, 0}
    },
    {
        ZCL_RSSI_LOC_SVR_ATTR_NUM_DEVICES, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    /* Location Settings Attribute Set */
    {
        ZCL_RSSI_LOC_SVR_ATTR_COORD1, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_RSSI_LOC_SVR_ATTR_COORD2, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_RSSI_LOC_SVR_ATTR_COORD3, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_RSSI_LOC_SVR_ATTR_POWER, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_RSSI_LOC_SVR_ATTR_PATH_LOSS_EXP, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_RSSI_LOC_SVR_ATTR_REPORT_PERIOD, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_RSSI_LOC_SVR_ATTR_CALC_PERIOD, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_RSSI_LOC_SVR_ATTR_NUM_RSSI_MEAS, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x01, 0xFF}, {0, 0}
    }
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct zcl_rssi_loc_server_callbacks_t callbacks;
};

static enum ZclStatusCodeT rssi_loc_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclRssiLocServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct zcl_rssi_loc_server_callbacks_t *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_RSSI_LOCATION, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    memset(&clusterPtr->callbacks, 0, sizeof(clusterPtr->callbacks));
    if (callbacks != NULL) {
        memcpy(&clusterPtr->callbacks, callbacks, sizeof(clusterPtr->callbacks));
    }

    clusterPtr->cluster.command = rssi_loc_command;

    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_rssi_loc_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_rssi_loc_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_RSSI_LOC_SVR_ATTR_LOCATION_TYPE, 0);

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src,
    uint16_t attributeId, const uint8_t *inputData, unsigned int inputMaxLen,
    void *attrData, ZclWriteModeT mode, void *app_cb_arg)
{
    enum ZclStatusCodeT rc = ZCL_STATUS_SUCCESS;

    switch (attributeId) {
        case ZCL_RSSI_LOC_SVR_ATTR_LOCATION_METHOD:
        {
            uint8_t method;

            if (inputMaxLen < 1U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            method = inputData[0];
            if ((method > ZCL_RSSI_LOC_METHOD_CENTRALIZED) && (method < ZCL_RSSI_LOC_METHOD_MANUF_SPEC_MIN)) {
                rc = ZCL_STATUS_INVALID_VALUE;
                break;
            }
            /* If just testing, return SUCCESS now. */
            if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) != 0U) {
                break;
            }
            (void)memcpy(attrData, inputData, 1);
            break;
        }

        default:
            /* Unknown attribute identifier. */
            rc = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            break;
    }
    return rc;
}

static enum ZclStatusCodeT
rssi_loc_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *rssi_loc_cluster = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclAddrInfoT src_info;
    uint8_t cmd_id = zclHdrPtr->cmdId;
    enum ZclStatusCodeT return_status = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

    (void)memset(&src_info, 0, sizeof(src_info));
    src_info.addr = dataIndPtr->src;
    src_info.seqnum = zclHdrPtr->seqNum;
    src_info.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    switch (cmd_id) {
        case ZCL_RSSI_LOC_CLI_CMD_SET_ABS_LOC:
        {
            if (dataIndPtr->asduLength < 10U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_RSSI_LOC_SVR_ATTR_COORD1, (int16_t)pletoh16(&dataIndPtr->asdu[0]));
            (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_RSSI_LOC_SVR_ATTR_COORD2, (int16_t)pletoh16(&dataIndPtr->asdu[2]));
            (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_RSSI_LOC_SVR_ATTR_COORD3, (int16_t)pletoh16(&dataIndPtr->asdu[4]));
            (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_RSSI_LOC_SVR_ATTR_POWER, (int16_t)pletoh16(&dataIndPtr->asdu[6]));
            (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_RSSI_LOC_SVR_ATTR_PATH_LOSS_EXP, pletoh16(&dataIndPtr->asdu[8]));

            return_status = ZCL_STATUS_SUCCESS;
            break;
        }

        case ZCL_RSSI_LOC_CLI_CMD_SET_DEV_CONFIG:
        {
            uint8_t location_type;

            if (dataIndPtr->asduLength < 9U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            ZbZclAttrRead(clusterPtr, ZCL_RSSI_LOC_SVR_ATTR_LOCATION_TYPE, NULL, &location_type, sizeof(location_type), false);
            if ((location_type & ZCL_RSSI_LOC_LOC_TYPE_ABSOLUTE) == 0U) {
                (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_RSSI_LOC_SVR_ATTR_POWER, (int16_t)pletoh16(&dataIndPtr->asdu[0]));
                (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_RSSI_LOC_SVR_ATTR_PATH_LOSS_EXP, pletoh16(&dataIndPtr->asdu[2]));
                (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_RSSI_LOC_SVR_ATTR_CALC_PERIOD, pletoh16(&dataIndPtr->asdu[4]));
                (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_RSSI_LOC_SVR_ATTR_NUM_RSSI_MEAS, dataIndPtr->asdu[6]);
                (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_RSSI_LOC_SVR_ATTR_REPORT_PERIOD, pletoh16(&dataIndPtr->asdu[7]));
            }
            else {
                return_status = ZCL_STATUS_FAILURE;
                break;
            }

            return_status = ZCL_STATUS_SUCCESS;
            break;
        }

        case ZCL_RSSI_LOC_CLI_CMD_GET_DEV_CONFIG:
        {
            struct rssi_loc_get_dev_config req;

            if (dataIndPtr->asduLength < 8U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            if (rssi_loc_cluster->callbacks.get_dev_config == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.target_addr = pletoh64(&dataIndPtr->asdu[0]);

            return_status = rssi_loc_cluster->callbacks.get_dev_config(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_RSSI_LOC_CLI_CMD_GET_LOC_DATA:
        {
            struct rssi_loc_get_loc_data req;

            if (dataIndPtr->asduLength < 2U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            if (rssi_loc_cluster->callbacks.get_loc_data == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.bitmap = dataIndPtr->asdu[0];
            req.num_responses = dataIndPtr->asdu[1];
            if ((req.bitmap & ZCL_RSSI_LOC_LOC_DATA_BROAD_IND) == 0U) {
                if (dataIndPtr->asduLength < 10U) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                req.target_addr = pletoh64(&dataIndPtr->asdu[2]);
            }

            return_status = rssi_loc_cluster->callbacks.get_loc_data(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_RSSI_LOC_CLI_CMD_SEND_PINGS:
        {
            struct rssi_loc_send_pings req;

            if (dataIndPtr->asduLength < 11U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            if (rssi_loc_cluster->callbacks.send_pings == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.target_addr = pletoh64(&dataIndPtr->asdu[0]);
            req.num_rssi_meas = dataIndPtr->asdu[8];
            req.calc_period = pletoh16(&dataIndPtr->asdu[9]);

            return_status = rssi_loc_cluster->callbacks.send_pings(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_RSSI_LOC_CLI_CMD_ANCHOR_NODE_ANNC:
        {
            struct rssi_loc_anchor_node_annc req;

            if (dataIndPtr->asduLength < 14U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            if (rssi_loc_cluster->callbacks.anchor_node_annc == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.addr = pletoh64(&dataIndPtr->asdu[0]);
            req.x = (int16_t)pletoh16(&dataIndPtr->asdu[8]);
            req.y = (int16_t)pletoh16(&dataIndPtr->asdu[10]);
            req.z = (int16_t)pletoh16(&dataIndPtr->asdu[12]);

            return_status = rssi_loc_cluster->callbacks.anchor_node_annc(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        default:
            return_status = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return return_status;
}

enum ZclStatusCodeT
ZbZclRssiLocServerSendDevConfigRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst_info,
    struct rssi_loc_dev_config_rsp *rsp)
{
    uint8_t rsp_payload[10];
    unsigned int length = 0U;
    struct ZbApsBufT bufv[1];

    /* Form the payload */
    rsp_payload[length++] = rsp->status;
    if (rsp->status == 0U) {
        putle16(&rsp_payload[length], rsp->power);
        length += 2U;
        putle16(&rsp_payload[length], rsp->path_loss_exp);
        length += 2U;
        putle16(&rsp_payload[length], rsp->calc_period);
        length += 2U;
        rsp_payload[length++] = rsp->num_rssi_meas;
        putle16(&rsp_payload[length], rsp->report_period);
        length += 2U;
    }

    bufv[0].data = rsp_payload;
    bufv[0].len = length;

    return ZbZclClusterCommandRsp(clusterPtr, dst_info, ZCL_RSSI_LOC_CLI_CMD_DEV_CONFIG_RSP, bufv, 1U);
}

enum ZclStatusCodeT
ZbZclRssiLocServerSendLocDataRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst_info,
    struct rssi_loc_loc_data_rsp *rsp)
{
    uint8_t rsp_payload[16];
    unsigned int length = 0U;
    struct ZbApsBufT bufv[1];

    /* Form the payload */
    rsp_payload[length++] = rsp->status;
    if (rsp->status == 0U) {
        rsp_payload[length++] = rsp->loc_type;
        putle16(&rsp_payload[length], rsp->coord1);
        length += 2U;
        putle16(&rsp_payload[length], rsp->coord2);
        length += 2U;
        putle16(&rsp_payload[length], rsp->coord3);
        length += 2U;
        putle16(&rsp_payload[length], rsp->power);
        length += 2U;
        putle16(&rsp_payload[length], rsp->path_loss_exp);
        length += 2U;
        rsp_payload[length++] = rsp->loc_method;
        rsp_payload[length++] = rsp->quality_meas;
        putle16(&rsp_payload[length], rsp->loc_age);
        length += 2U;
    }

    bufv[0].data = rsp_payload;
    bufv[0].len = length;

    return ZbZclClusterCommandRsp(clusterPtr, dst_info, ZCL_RSSI_LOC_CLI_CMD_LOC_DATA_RSP, bufv, 1U);
}

enum ZclStatusCodeT
ZbZclRssiLocServerLocDataNotif(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    struct rssi_loc_loc_data_notif loc_data_notif;
    uint8_t payload[15];
    unsigned int length = 0U;

    (void)memset(&loc_data_notif, 0, sizeof(loc_data_notif));
    loc_data_notif.loc_type = (uint8_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_LOCATION_TYPE, NULL, NULL);
    loc_data_notif.coord1 = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_COORD1, NULL, NULL);
    loc_data_notif.coord2 = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_COORD2, NULL, NULL);
    loc_data_notif.coord3 = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_COORD3, NULL, NULL);
    loc_data_notif.power = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_POWER, NULL, NULL);
    loc_data_notif.path_loss_exp = (uint16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_PATH_LOSS_EXP, NULL, NULL);
    loc_data_notif.loc_method = (uint8_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_LOCATION_METHOD, NULL, NULL);
    loc_data_notif.quality_meas = (uint8_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_QUALITY_MEAS, NULL, NULL);
    loc_data_notif.loc_age = (uint16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_LOCATION_AGE, NULL, NULL);

    payload[length++] = loc_data_notif.loc_type;
    putle16(&payload[length], loc_data_notif.coord1);
    length += 2U;
    putle16(&payload[length], loc_data_notif.coord2);
    length += 2U;
    if ((loc_data_notif.loc_type & ZCL_RSSI_LOC_LOC_TYPE_2D) == 0U) {
        putle16(&payload[length], loc_data_notif.coord3);
        length += 2U;
    }
    putle16(&payload[length], loc_data_notif.power);
    length += 2U;
    putle16(&payload[length], loc_data_notif.path_loss_exp);
    length += 2U;
    if ((loc_data_notif.loc_type & ZCL_RSSI_LOC_LOC_TYPE_ABSOLUTE) == 0U) {
        payload[length++] = loc_data_notif.loc_method;
        payload[length++] = loc_data_notif.quality_meas;
        putle16(&payload[length], loc_data_notif.loc_age);
        length += 2U;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_RSSI_LOC_CLI_CMD_LOC_DATA_NOTIF;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    ZbZclClusterCommandReq(cluster, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclRssiLocServerCompDataNotif(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    struct rssi_loc_comp_data_notif comp_data_notif;
    uint8_t payload[10];
    unsigned int length = 0U;

    (void)memset(&comp_data_notif, 0, sizeof(comp_data_notif));
    comp_data_notif.loc_type = (uint8_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_LOCATION_TYPE, NULL, NULL);
    comp_data_notif.coord1 = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_COORD1, NULL, NULL);
    comp_data_notif.coord2 = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_COORD2, NULL, NULL);
    comp_data_notif.coord3 = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_COORD3, NULL, NULL);
    comp_data_notif.quality_meas = (uint8_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_QUALITY_MEAS, NULL, NULL);
    comp_data_notif.loc_age = (uint16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_LOCATION_AGE, NULL, NULL);

    payload[length++] = comp_data_notif.loc_type;
    putle16(&payload[length], comp_data_notif.coord1);
    length += 2U;
    putle16(&payload[length], comp_data_notif.coord2);
    length += 2U;
    if ((comp_data_notif.loc_type & ZCL_RSSI_LOC_LOC_TYPE_2D) == 0U) {
        putle16(&payload[length], comp_data_notif.coord3);
        length += 2U;
    }
    if ((comp_data_notif.loc_type & ZCL_RSSI_LOC_LOC_TYPE_ABSOLUTE) == 0U) {
        payload[length++] = comp_data_notif.quality_meas;
        putle16(&payload[length], comp_data_notif.loc_age);
        length += 2U;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_RSSI_LOC_CLI_CMD_COMP_DATA_NOTIF;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    ZbZclClusterCommandReq(cluster, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclRssiLocServerRssiPing(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[1];
    unsigned int length = 0U;

    payload[length++] = (uint8_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_RSSI_LOC_SVR_ATTR_LOCATION_TYPE, NULL, NULL);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_RSSI_LOC_CLI_CMD_RSSI_PING;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    ZbZclClusterCommandReq(cluster, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclRssiLocServerRssiReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_RSSI_LOC_CLI_CMD_RSSI_REQUEST;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = NULL;
    req.length = 0U;
    ZbZclClusterCommandReq(cluster, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclRssiLocServerReportRssi(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct rssi_loc_report_rssi *report_rssi, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0U;
    unsigned int i;

    putle64(&payload[length], report_rssi->measuring_dev);
    length += 8U;
    payload[length++] = report_rssi->n_neighbours;
    for (i = 0; i < report_rssi->n_neighbours; i++) {
        putle64(&payload[length], report_rssi->neighbours_info[i].neighbour);
        length += 8U;
        putle16(&payload[length], report_rssi->neighbours_info[i].x);
        length += 2U;
        putle16(&payload[length], report_rssi->neighbours_info[i].y);
        length += 2U;
        putle16(&payload[length], report_rssi->neighbours_info[i].z);
        length += 2U;
        payload[length++] = report_rssi->neighbours_info[i].rssi;
        payload[length++] = report_rssi->neighbours_info[i].num_rssi_meas;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_RSSI_LOC_CLI_CMD_REPORT_RSSI;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    ZbZclClusterCommandReq(cluster, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclRssiLocServerReqOwnLoc(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct rssi_loc_req_own_loc *req_own_loc, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[8];
    unsigned int length = 0U;

    putle64(&payload[length], req_own_loc->addr);
    length += 8U;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_RSSI_LOC_CLI_CMD_REQ_OWN_LOC;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    ZbZclClusterCommandReq(cluster, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}
