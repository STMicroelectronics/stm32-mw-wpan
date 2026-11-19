/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.onoff.h"

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
};

struct ZbZclClusterT *
ZbZclOnOffClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_ONOFF, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

/*
 * Client Cluster Commands
 */

static enum ZclStatusCodeT
onoff_send_req(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    enum ZbZclOnOffCmdT cmd,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = cmd;
#if 1
    /* Not described in ZCL Spec, but don't enable Default Response if we are sending to broadcast.
     * It otherwise generates unnecessary traffic that we don't actually care about receiving. */
    req.noDefaultResp = ZbApsAddrIsBcast(dst) ? ZCL_NO_DEFAULT_RESPONSE_TRUE : ZCL_NO_DEFAULT_RESPONSE_FALSE;
#else
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
#endif
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclOnOffClientOnReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    return onoff_send_req(cluster, dst, ZCL_ONOFF_COMMAND_ON, callback, arg);
}

enum ZclStatusCodeT
ZbZclOnOffClientOffReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    return onoff_send_req(cluster, dst, ZCL_ONOFF_COMMAND_OFF, callback, arg);
}

enum ZclStatusCodeT
ZbZclOnOffClientToggleReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    return onoff_send_req(cluster, dst, ZCL_ONOFF_COMMAND_TOGGLE, callback, arg);
}
