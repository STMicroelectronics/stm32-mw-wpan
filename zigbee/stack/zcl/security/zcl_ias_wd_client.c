/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

/*-------------------------------------------------
 *  DESCRIPTION
 *      HA IAS devices Implementation.
 *-------------------------------------------------
 */

#include "zcl/security/zcl.ias_wd.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster;
};

static enum ZclStatusCodeT zcl_ias_wd_client_command(struct ZbZclClusterT *, struct ZbZclHeaderT *, struct ZbApsdeDataIndT *);

struct ZbZclClusterT *
ZbZclIasWdClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_SECURITY_IAS_WARNING, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.command = zcl_ias_wd_client_command;

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_ias_wd_client_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    if (zclHdrPtr->frameCtrl.manufacturer) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    switch (zclHdrPtr->cmdId) {
        default:
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
}

uint8_t
ZbZclIasWdClientStartWarningReq(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *dst,
    struct ZbZclIasWdClientStartWarningReqT *warning_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[5];
    unsigned int i = 0;

    payload[i] = 0;
    payload[i] |= (warning_req->warning_mode & 0x0f) << 4;
    payload[i] |= (warning_req->strobe & 0x03) << 2;
    payload[i] |= (warning_req->siren_level & 0x03);
    i++;

    putle16(&payload[i], warning_req->warning_duration);
    i += 2;
    payload[i++] = warning_req->strobe_dutycycle;
    payload[i++] = warning_req->strobe_level;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_WD_CLI_CMD_START_WARNING;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = sizeof(payload);
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

uint8_t
ZbZclIasWdClientSquawkReq(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *dst,
    struct ZbZclIasWdClientSquawkReqT *squawk_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[1];

    payload[0] = 0;
    payload[0] |= (squawk_req->squawk_mode & 0x0f) << 4;
    payload[0] |= (squawk_req->strobe & 0x01) << 3;
    payload[0] |= (squawk_req->squawk_level & 0x03);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_WD_CLI_CMD_SQUAWK;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = sizeof(payload);
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}
