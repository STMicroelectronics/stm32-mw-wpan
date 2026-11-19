/* Copyright [2017 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.identify.h"
#include "zcl/zcl.payload.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

struct ZbZclClusterT *
ZbZclIdentifyClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_IDENTIFY, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    if (ZbZclClusterAttach(&clusterPtr->cluster) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }
    return &clusterPtr->cluster;
}

enum ZclStatusCodeT
zcl_identify_identify_request(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst, uint16_t identify_time,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{

    struct ZbZclClusterCommandReqT req;
    int length = 0;
    unsigned int index = 0;
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];

    length = zb_zcl_append_uint16(payload, sizeof(payload), &index, identify_time);
    if (length < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IDENTIFY_COMMAND_IDENTIFY;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
zcl_identify_query_request(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IDENTIFY_COMMAND_QUERY;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}
