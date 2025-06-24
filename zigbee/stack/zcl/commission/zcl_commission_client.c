/**
 * @file zcl_commission_client.c
 * @brief ZCL Commissioning Client cluster
 * @author Exegin Technologies Limited
 * @copyright Copyright [2019 - 2021] Exegin Technologies Limited. All rights reserved.
 */

#include "zcl/general/zcl.commission.h"
#include "../zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */

struct cluster_priv_t {
    struct ZbZclClusterT cluster;
};

struct ZbZclClusterT *
ZbZclCommissionClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, uint16_t profile, bool aps_secured)
{
    struct cluster_priv_t *clientPtr;

    clientPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_COMMISSIONING,
            endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clientPtr == NULL) {
        return NULL;
    }

    ZbZclClusterSetProfileId(&clientPtr->cluster, profile);

    if (aps_secured) {
        /* Packets are sent and received with APS security */
        ZbZclClusterSetTxOptions(&clientPtr->cluster, ZCL_COMMISSION_TXOPTIONS_SECURE);
        (void)ZbZclClusterSetMinSecurity(&clientPtr->cluster, ZB_APS_STATUS_SECURED_LINK_KEY);
    }
    else {
        /* Packets are sent and received completely unsecured */
        ZbZclClusterSetTxOptions(&clientPtr->cluster, ZCL_COMMISSION_TXOPTIONS_UNSECURE);
        (void)ZbZclClusterSetMinSecurity(&clientPtr->cluster, ZB_APS_STATUS_UNSECURED);
    }

    if (endpoint == ZB_ENDPOINT_BCAST) {
        /* For Interpan to work, we need to bind to the bcast endpoint */
        /* Remove any existing filter */
        ZbZclClusterUnbind(&clientPtr->cluster);
        ZbZclClusterBind(&clientPtr->cluster, ZB_ENDPOINT_BCAST, profile, ZCL_DIRECTION_TO_CLIENT);
        /* Don't call ZbZclClusterAttach. It will remove our filter. */
    }
    else {
        (void)ZbZclClusterAttach(&clientPtr->cluster);
    }

    return &clientPtr->cluster;
}

enum ZclStatusCodeT
ZbZclCommissionClientEnable(struct ZbZclClusterT *cluster, struct ZbZclCommissionClientEnableInfoT *info)
{
    struct ZbNwkCommissioningInfo *commission_info;

    /* For the client, there's no need to disable the commissioning cluster.
     * The info parameter must always be non-NULL. */
    if (info == NULL) {
        return ZCL_STATUS_FAILURE;
    }

    commission_info = ZbHeapAlloc(cluster->zb, sizeof(struct ZbNwkCommissioningInfo));
    if (commission_info == NULL) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
    memset(commission_info, 0, sizeof(struct ZbNwkCommissioningInfo));
    commission_info->ifc_index = 0U;
    commission_info->nwk_addr = ZB_NWK_ADDR_UNDEFINED;
    commission_info->pan_id = ZB_NWK_ADDR_UNDEFINED;
    commission_info->rx_on = 1U;
    commission_info->page = info->page;
    commission_info->channel = info->channel;
    if (!ZbNwkCommissioningConfig(cluster->zb, commission_info)) {
        ZbHeapFree(cluster->zb, commission_info);
        return ZCL_STATUS_FAILURE;
    }
    ZbHeapFree(cluster->zb, commission_info);
    return ZCL_STATUS_SUCCESS;
}

static void
zcl_commission_req_init(struct ZbZclClusterT *cluster, struct ZbZclCommandReqT *req,
    enum ZbZclCommissionClientCommandsT cmd, uint64_t dst_ext, uint8_t dst_ep)
{
    /* Source Information and TX Options */
    ZbZclClusterInitCommandReq(cluster, req);

    /* Destination */
    req->dst.mode = ZB_APSDE_ADDRMODE_EXT;
    req->dst.extAddr = dst_ext;

    /* If the cluster has been initialized to use Inter-PAN, then send using Inter-PAN */
    if (cluster->endpoint == ZB_ENDPOINT_BCAST) {
        req->dst.endpoint = ZB_ENDPOINT_INTERPAN;
        req->dst.panId = ZB_NWK_ADDR_BCAST_ALL;
    }
    else {
        req->dst.endpoint = dst_ep;
    }

    /* ZCL Header Info */
    req->hdr.frameCtrl.frameType = ZCL_FRAMETYPE_CLUSTER;
    req->hdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
    req->hdr.seqNum = ZbZclGetNextSeqnum();
    req->hdr.cmdId = cmd;
}

enum ZclStatusCodeT
ZbZclCommissionClientSendRestart(struct ZbZclClusterT *cluster, uint64_t dst_ext, uint8_t dst_ep,
    struct ZbZclCommissionClientRestartDev *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclCommandReqT cmd;
    uint8_t payload[3];

    /* Destination and ZCL Header */
    zcl_commission_req_init(cluster, &cmd, ZCL_COMMISSION_CLI_CMD_RESTART_DEVICE, dst_ext, dst_ep);

    /* ZCL Payload */
    payload[0] = req->options;
    payload[1] = req->delay;
    payload[2] = req->jitter;
    cmd.payload = payload;
    cmd.length = sizeof(payload);

    return ZbZclCommandReq(cluster->zb, &cmd, callback, arg);
}

enum ZclStatusCodeT
ZbZclCommissionClientSendSaveStartup(struct ZbZclClusterT *cluster, uint64_t dst_ext, uint8_t dst_ep,
    struct ZbZclCommissionClientSaveStartup *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclCommandReqT cmd;
    uint8_t payload[2];

    /* Destination and ZCL Header */
    zcl_commission_req_init(cluster, &cmd, ZCL_COMMISSION_CLI_CMD_SAVE_STARTUP, dst_ext, dst_ep);

    /* ZCL Payload */
    payload[0] = req->options;
    payload[1] = req->index;
    cmd.payload = payload;
    cmd.length = sizeof(payload);

    return ZbZclCommandReq(cluster->zb, &cmd, callback, arg);
}

enum ZclStatusCodeT
ZbZclCommissionClientSendRestoreStartup(struct ZbZclClusterT *cluster, uint64_t dst_ext, uint8_t dst_ep,
    struct ZbZclCommissionClientRestoreStartup *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclCommandReqT cmd;
    uint8_t payload[2];

    /* Destination and ZCL Header */
    zcl_commission_req_init(cluster, &cmd, ZCL_COMMISSION_CLI_CMD_RESTORE_STARTUP, dst_ext, dst_ep);

    /* ZCL Payload */
    payload[0] = req->options;
    payload[1] = req->index;
    cmd.payload = payload;
    cmd.length = sizeof(payload);

    return ZbZclCommandReq(cluster->zb, &cmd, callback, arg);
}

enum ZclStatusCodeT
ZbZclCommissionClientSendResetStartup(struct ZbZclClusterT *cluster, uint64_t dst_ext, uint8_t dst_ep,
    struct ZbZclCommissionClientResetStartup *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclCommandReqT cmd;
    uint8_t payload[2];

    /* Destination and ZCL Header */
    zcl_commission_req_init(cluster, &cmd, ZCL_COMMISSION_CLI_CMD_RESET_STARTUP, dst_ext, dst_ep);

    /* ZCL Payload */
    payload[0] = req->options;
    payload[1] = req->index;
    cmd.payload = payload;
    cmd.length = sizeof(payload);

    return ZbZclCommandReq(cluster->zb, &cmd, callback, arg);
}
