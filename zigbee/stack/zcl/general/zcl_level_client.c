/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.level.h"
#include "zcl/zcl.payload.h"

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
};

struct ZbZclClusterT *
ZbZclLevelClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_LEVEL_CONTROL,
            endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

enum ZclStatusCodeT
ZbZclLevelClientMoveToLevelReq(struct ZbZclClusterT *clusterPtr,
    const struct ZbApsAddrT *dst, struct ZbZclLevelClientMoveToLevelReqT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT cmd_req;

    /* Payload */
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->level) < 0) {
        return ZCL_STATUS_FAILURE;
    }
    if (zb_zcl_append_uint16(payload, sizeof(payload), &length, req->transition_time) < 0) {
        return ZCL_STATUS_FAILURE;
    }
    /* CCB 2814 - OptionsMask and OptionsOverride in commands are mandatory */
    /* ZCL 8 3.10.2.3.6 "The Move to Level (with On/Off), Move (with On/Off) and Step (with On/Off) commands
     * have identical payloads to the Move to Level, Move and Step commands respectively" (CCB 2818) */
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->mask) < 0) {
        return ZCL_STATUS_FAILURE;
    }
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->override) < 0) {
        return ZCL_STATUS_FAILURE;
    }

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = req->with_onoff ? ZCL_LEVEL_COMMAND_MOVELEVEL_ONOFF : ZCL_LEVEL_COMMAND_MOVELEVEL;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd_req.payload = payload;
    cmd_req.length = length;
    return ZbZclClusterCommandReq(clusterPtr, &cmd_req, callback, arg);
}

enum ZclStatusCodeT
ZbZclLevelClientMoveReq(struct ZbZclClusterT *clusterPtr,
    const struct ZbApsAddrT *dst, struct ZbZclLevelClientMoveReqT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT cmd_req;

    /* Payload */
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->mode) < 0) {
        return ZCL_STATUS_FAILURE;
    }
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->rate) < 0) {
        return ZCL_STATUS_FAILURE;
    }
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->mask) < 0) {
        return ZCL_STATUS_FAILURE;
    }
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->override) < 0) {
        return ZCL_STATUS_FAILURE;
    }

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = req->with_onoff ? ZCL_LEVEL_COMMAND_MOVE_ONOFF : ZCL_LEVEL_COMMAND_MOVE;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd_req.payload = payload;
    cmd_req.length = length;
    return ZbZclClusterCommandReq(clusterPtr, &cmd_req, callback, arg);
}

enum ZclStatusCodeT
ZbZclLevelClientStepReq(struct ZbZclClusterT *clusterPtr,
    const struct ZbApsAddrT *dst, struct ZbZclLevelClientStepReqT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT cmd_req;

    /* Payload */
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->mode) < 0) {
        return ZCL_STATUS_FAILURE;
    }
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->size) < 0) {
        return ZCL_STATUS_FAILURE;
    }
    if (zb_zcl_append_uint16(payload, sizeof(payload), &length, req->transition_time) < 0) {
        return ZCL_STATUS_FAILURE;
    }
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->mask) < 0) {
        return ZCL_STATUS_FAILURE;
    }
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->override) < 0) {
        return ZCL_STATUS_FAILURE;
    }

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = req->with_onoff ? ZCL_LEVEL_COMMAND_STEP_ONOFF : ZCL_LEVEL_COMMAND_STEP;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd_req.payload = payload;
    cmd_req.length = length;
    return ZbZclClusterCommandReq(clusterPtr, &cmd_req, callback, arg);
}

enum ZclStatusCodeT
ZbZclLevelClientStopReq(struct ZbZclClusterT *clusterPtr,
    const struct ZbApsAddrT *dst, struct ZbZclLevelClientStopReqT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT cmd_req;

    /* Payload */
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->mask) < 0) {
        return ZCL_STATUS_FAILURE;
    }
    if (zb_zcl_append_uint8(payload, sizeof(payload), &length, req->override) < 0) {
        return ZCL_STATUS_FAILURE;
    }

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = req->with_onoff ? ZCL_LEVEL_COMMAND_STOP_ONOFF : ZCL_LEVEL_COMMAND_STOP;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    if (length > 0) {
        cmd_req.payload = payload;
        cmd_req.length = length;
    }
    return ZbZclClusterCommandReq(clusterPtr, &cmd_req, callback, arg);
}
