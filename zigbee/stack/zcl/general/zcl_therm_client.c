/* Copyright [2017 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl/general/zcl.therm.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

struct ZbZclClusterT *
ZbZclThermClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_HVAC_THERMOSTAT,
            endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

enum ZclStatusCodeT
ZbZclThermClientSetpointRaiseLower(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *dst,
    struct ZbZclThermCliSetpointT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[2];
    uint16_t len = 0;
    struct ZbZclClusterCommandReqT cmd_req;

    /* Command payload */
    payload[len++] = req->mode;
    payload[len++] = (uint8_t)req->amount;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = (uint8_t)ZCL_THERM_CLI_SETPOINT_RAISE_LOWER;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd_req.payload = payload;
    cmd_req.length = len;
    return ZbZclClusterCommandReq(clusterPtr, &cmd_req, callback, arg);
}

enum ZclStatusCodeT
ZbZclThermClientSetWeeklySched(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *dst,
    struct ZbZclThermWeeklySchedT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[3 + (ZCL_THERM_NUM_TRANSITIONS_MAX * 6)];
    uint16_t len = 0;
    struct ZbZclClusterCommandReqT cmd_req;
    unsigned int i;

    if (req->num_transitions > ZCL_THERM_NUM_TRANSITIONS_MAX) {
        return ZCL_STATUS_FAILURE;
    }

    /* Command payload */
    payload[len++] = req->num_transitions;
    payload[len++] = req->day_of_week_seq;
    payload[len++] = req->mode_for_seq;
    /* transitions */
    for (i = 0; i < req->num_transitions; i++) {
        putle16(&payload[len], req->transitions[i].transition_time);
        len += 2U;
        if ((req->mode_for_seq & ZCL_THERM_MODE_HEAT_SETPOINT_PRESENT) != 0U) {
            putle16(&payload[len], (uint16_t)req->transitions[i].heat_set_point);
            len += 2U;
        }
        if ((req->mode_for_seq & ZCL_THERM_MODE_COOL_SETPOINT_PRESENT) != 0U) {
            putle16(&payload[len], (uint16_t)req->transitions[i].cool_set_point);
            len += 2U;
        }
    }

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = (uint8_t)ZCL_THERM_CLI_SET_WEEK_SCHED;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd_req.payload = payload;
    cmd_req.length = len;
    return ZbZclClusterCommandReq(clusterPtr, &cmd_req, callback, arg);
}

enum ZclStatusCodeT
ZbZclThermClientGetWeeklySched(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *dst,
    struct ZbZclThermCliGetWeeklyT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[2];
    uint16_t len = 0;
    struct ZbZclClusterCommandReqT cmd_req;

    /* Command payload */
    payload[len++] = req->days_to_return;
    payload[len++] = req->mode_to_return;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = (uint8_t)ZCL_THERM_CLI_GET_WEEK_SCHED;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE; /* ZCL_THERM_SVR_GET_WEEK_RSP */
    cmd_req.payload = payload;
    cmd_req.length = len;
    return ZbZclClusterCommandReq(clusterPtr, &cmd_req, callback, arg);
}

enum ZclStatusCodeT
ZbZclThermClientClearWeeklySched(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd_req;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = (uint8_t)ZCL_THERM_CLI_CLEAR_WEEK_SCHED;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd_req.payload = NULL;
    cmd_req.length = 0;
    return ZbZclClusterCommandReq(clusterPtr, &cmd_req, callback, arg);
}

enum ZclStatusCodeT
ZbZclThermClientGetRelayStatusLog(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd_req;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = (uint8_t)ZCL_THERM_CLI_GET_RELAY_LOG;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE; /* ZCL_THERM_SVR_GET_RELAY_LOG_RSP */
    cmd_req.payload = NULL;
    cmd_req.length = 0;
    return ZbZclClusterCommandReq(clusterPtr, &cmd_req, callback, arg);
}
