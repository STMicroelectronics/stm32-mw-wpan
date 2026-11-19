/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.basic.h"
#include "zcl/general/zcl.alarm.h"

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
};

static enum ZclStatusCodeT zcl_basic_client_handle_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr,
    struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclBasicClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_BASIC, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.command = zcl_basic_client_handle_command;

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_basic_client_handle_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_CLIENT) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    return ZCL_STATUS_UNSUPP_COMMAND;
}

static void
zcl_basic_client_reset_rsp_cb(struct ZbZclCommandRspT *zcl_rsp, void *arg)
{
    struct ZbZclClusterT *clusterPtr = arg;

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Response (status = 0x%02x)", zcl_rsp->status);
    (void)clusterPtr; /* in case logging is not enabled */
}

enum ZclStatusCodeT
ZbZclBasicClientResetReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_BASIC_RESET_FACTORY;
    /* No cluster-specific response, so set Disable Default Response to False */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, zcl_basic_client_reset_rsp_cb, cluster);
}
