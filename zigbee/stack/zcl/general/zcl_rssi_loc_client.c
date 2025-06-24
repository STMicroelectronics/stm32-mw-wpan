/* Copyright [2019 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.rssi.loc.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct zcl_rssi_loc_client_callbacks_t callbacks;
};

static enum ZclStatusCodeT rssi_loc_client_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclRssiLocClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct zcl_rssi_loc_client_callbacks_t *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_RSSI_LOCATION, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    memset(&clusterPtr->callbacks, 0, sizeof(clusterPtr->callbacks));
    if (callbacks != NULL) {
        memcpy(&clusterPtr->callbacks, callbacks, sizeof(clusterPtr->callbacks));
    }

    clusterPtr->cluster.command = rssi_loc_client_command;

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

enum ZclStatusCodeT
ZbZclRssiLocClientSetAbsLocation(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct rssi_loc_set_abs_loc *set_abs_loc, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[10];
    unsigned int length = 0U;

    putle16(&payload[length], set_abs_loc->coord1);
    length += 2U;
    putle16(&payload[length], set_abs_loc->coord2);
    length += 2U;
    putle16(&payload[length], set_abs_loc->coord3);
    length += 2U;
    putle16(&payload[length], set_abs_loc->power);
    length += 2U;
    putle16(&payload[length], set_abs_loc->path_loss_exp);
    length += 2U;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_RSSI_LOC_CLI_CMD_SET_ABS_LOC;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    ZbZclClusterCommandReq(cluster, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclRssiLocClientSetDevConfig(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct rssi_loc_set_dev_config *set_dev_config, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[9];
    unsigned int length = 0U;

    putle16(&payload[length], set_dev_config->power);
    length += 2U;
    putle16(&payload[length], set_dev_config->path_loss_exp);
    length += 2U;
    putle16(&payload[length], set_dev_config->calc_period);
    length += 2U;
    payload[length++] = set_dev_config->num_rssi_meas;
    putle16(&payload[length], set_dev_config->report_period);
    length += 2U;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_RSSI_LOC_CLI_CMD_SET_DEV_CONFIG;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    ZbZclClusterCommandReq(cluster, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclRssiLocClientGetDevConfig(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct rssi_loc_get_dev_config *get_dev_config, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[8];
    unsigned int length = 0U;

    putle64(&payload[length], get_dev_config->target_addr);
    length += 8U;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_RSSI_LOC_CLI_CMD_GET_DEV_CONFIG;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    ZbZclClusterCommandReq(cluster, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclRssiLocClientGetLocData(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct rssi_loc_get_loc_data *get_loc_data, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[10];
    unsigned int length = 0U;

    payload[length++] = get_loc_data->bitmap;
    payload[length++] = get_loc_data->num_responses;
    if ((get_loc_data->bitmap & ZCL_RSSI_LOC_LOC_DATA_BROAD_IND) == 0U) {
        putle64(&payload[length], get_loc_data->target_addr);
        length += 8U;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_RSSI_LOC_CLI_CMD_GET_LOC_DATA;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    ZbZclClusterCommandReq(cluster, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclRssiLocClientSendPings(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct rssi_loc_send_pings *send_pings, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[11];
    unsigned int length = 0U;

    putle64(&payload[length], send_pings->target_addr);
    length += 8U;
    payload[length++] = send_pings->num_rssi_meas;
    putle16(&payload[length], send_pings->calc_period);
    length += 2U;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_RSSI_LOC_CLI_CMD_SEND_PINGS;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    ZbZclClusterCommandReq(cluster, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclRssiLocClientAnchorNodeAnnc(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct rssi_loc_anchor_node_annc *anchor_node_annc, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[14];
    unsigned int length = 0U;

    putle64(&payload[length], anchor_node_annc->addr);
    length += 8U;
    putle16(&payload[length], anchor_node_annc->x);
    length += 2U;
    putle16(&payload[length], anchor_node_annc->y);
    length += 2U;
    putle16(&payload[length], anchor_node_annc->z);
    length += 2U;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_RSSI_LOC_CLI_CMD_ANCHOR_NODE_ANNC;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    ZbZclClusterCommandReq(cluster, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclRssiLocClientSendRssiRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst_info,
    struct rssi_loc_rssi_rsp *rsp)
{
    uint8_t rsp_payload[16];
    unsigned int length = 0U;
    struct ZbApsBufT bufv[1];

    /* Form the payload */
    putle64(&rsp_payload[length], rsp->replying_dev);
    length += 8U;
    putle16(&rsp_payload[length], (uint16_t)rsp->x);
    length += 2U;
    putle16(&rsp_payload[length], (uint16_t)rsp->y);
    length += 2U;
    putle16(&rsp_payload[length], (uint16_t)rsp->z);
    length += 2U;
    rsp_payload[length++] = (uint8_t)rsp->rssi;
    rsp_payload[length++] = rsp->num_rssi_meas;

    bufv[0].data = rsp_payload;
    bufv[0].len = length;

    return ZbZclClusterCommandRsp(clusterPtr, dst_info, ZCL_RSSI_LOC_CLI_CMD_RSSI_RSP, bufv, 1U);
}

static enum ZclStatusCodeT
rssi_loc_client_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
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
        case ZCL_RSSI_LOC_CLI_CMD_LOC_DATA_NOTIF:
        {
            struct rssi_loc_loc_data_notif req;
            unsigned int length = 0;

            if (dataIndPtr->asduLength < 9U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            if (rssi_loc_cluster->callbacks.loc_data_notif == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.loc_type = dataIndPtr->asdu[length++];
            req.coord1 = (int16_t)pletoh16(&dataIndPtr->asdu[length]);
            length += 2U;
            req.coord2 = (int16_t)pletoh16(&dataIndPtr->asdu[length]);
            length += 2U;
            if ((req.loc_type & ZCL_RSSI_LOC_LOC_TYPE_2D) == 0U) {
                if (dataIndPtr->asduLength < 11U) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                req.coord3 = (int16_t)pletoh16(&dataIndPtr->asdu[length]);
                length += 2U;
            }
            req.power = (int16_t)pletoh16(&dataIndPtr->asdu[length]);
            length += 2U;
            req.path_loss_exp = pletoh16(&dataIndPtr->asdu[length]);
            length += 2U;
            if ((req.loc_type & ZCL_RSSI_LOC_LOC_TYPE_ABSOLUTE) == 0U) {
                if (dataIndPtr->asduLength < 13U) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                req.loc_method = dataIndPtr->asdu[length++];
                req.quality_meas = dataIndPtr->asdu[length++];
                req.loc_age = pletoh16(&dataIndPtr->asdu[length]);
                length += 2U;
            }

            return_status = rssi_loc_cluster->callbacks.loc_data_notif(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_RSSI_LOC_CLI_CMD_COMP_DATA_NOTIF:
        {
            struct rssi_loc_comp_data_notif req;
            unsigned int length = 0;

            if (dataIndPtr->asduLength < 5U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            if (rssi_loc_cluster->callbacks.comp_data_notif == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.loc_type = dataIndPtr->asdu[length++];
            req.coord1 = (int16_t)pletoh16(&dataIndPtr->asdu[length]);
            length += 2U;
            req.coord2 = (int16_t)pletoh16(&dataIndPtr->asdu[length]);
            length += 2U;
            if ((req.loc_type & ZCL_RSSI_LOC_LOC_TYPE_2D) == 0U) {
                if (dataIndPtr->asduLength < 7U) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                req.coord3 = (int16_t)pletoh16(&dataIndPtr->asdu[length]);
                length += 2U;
            }
            if ((req.loc_type & ZCL_RSSI_LOC_LOC_TYPE_ABSOLUTE) == 0U) {
                if (dataIndPtr->asduLength < 8U) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                req.quality_meas = dataIndPtr->asdu[length++];
                req.loc_age = pletoh16(&dataIndPtr->asdu[length]);
                length += 2U;
            }

            return_status = rssi_loc_cluster->callbacks.comp_data_notif(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_RSSI_LOC_CLI_CMD_RSSI_PING:
        {
            struct rssi_loc_rssi_ping req;

            if (dataIndPtr->asduLength < 1U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            if (rssi_loc_cluster->callbacks.rssi_ping == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.loc_type = dataIndPtr->asdu[0];

            return_status = rssi_loc_cluster->callbacks.rssi_ping(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_RSSI_LOC_CLI_CMD_RSSI_REQUEST:
        {
            struct rssi_loc_rssi_req req;

            if (rssi_loc_cluster->callbacks.rssi_req == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.rssi = dataIndPtr->rssi;

            return_status = rssi_loc_cluster->callbacks.rssi_req(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_RSSI_LOC_CLI_CMD_REPORT_RSSI:
        {
            struct rssi_loc_report_rssi req;
            unsigned int length = 0;
            unsigned int i;

            if (dataIndPtr->asduLength < 9U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            if (rssi_loc_cluster->callbacks.report_rssi == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.measuring_dev = pletoh64(&dataIndPtr->asdu[length]);
            length += 8U;
            req.n_neighbours = dataIndPtr->asdu[length++];
            if (dataIndPtr->asduLength < (9 + (req.n_neighbours * 16))) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            for (i = 0; i < req.n_neighbours; i++) {
                req.neighbours_info[i].neighbour = pletoh64(&dataIndPtr->asdu[length]);
                length += 8U;
                req.neighbours_info[i].x = (int16_t)pletoh16(&dataIndPtr->asdu[length]);
                length += 2U;
                req.neighbours_info[i].y = (int16_t)pletoh16(&dataIndPtr->asdu[length]);
                length += 2U;
                req.neighbours_info[i].z = (int16_t)pletoh16(&dataIndPtr->asdu[length]);
                length += 2U;
                req.neighbours_info[i].rssi = (int16_t)dataIndPtr->asdu[length++];
                req.neighbours_info[i].num_rssi_meas = dataIndPtr->asdu[length++];
            }

            return_status = rssi_loc_cluster->callbacks.report_rssi(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_RSSI_LOC_CLI_CMD_REQ_OWN_LOC:
        {
            struct rssi_loc_req_own_loc req;

            if (dataIndPtr->asduLength < 8U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            if (rssi_loc_cluster->callbacks.req_own_loc == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.addr = pletoh64(&dataIndPtr->asdu[0]);

            return_status = rssi_loc_cluster->callbacks.req_own_loc(clusterPtr, &req, &src_info, clusterPtr->app_cb_arg);
            break;
        }

        default:
            return_status = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return return_status;
}
