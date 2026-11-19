/* Copyright [2019 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.elec.meas.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

struct ZbZclClusterT *
ZbZclElecMeasClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_MEAS_ELECTRICAL, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

enum ZclStatusCodeT
ZbZclElecMeasClientGetProfileInfoReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_ELEC_MEAS_CLI_GET_PROFILE_INFO;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclElecMeasClientGetMeasProfileReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclElecMeasClientGetMeasProfileReqT *get_meas_profile_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[7];
    unsigned int length = 0;

    putle16(&payload[length], get_meas_profile_req->attr_id);
    length += 2;
    putle32(&payload[length], get_meas_profile_req->start_time);
    length += 4;
    payload[length++] = get_meas_profile_req->num_intervals;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_ELEC_MEAS_CLI_GET_MEAS_PROFILE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 7;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}
