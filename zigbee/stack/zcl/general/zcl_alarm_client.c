/* Copyright [2017 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.alarm.h"
#include "zcl/zcl.payload.h"

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
    ZbZclAlarmClientCallbackT callback;
    void *arg;
};

static enum ZclStatusCodeT alarm_command(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *aps_data_ind);

struct ZbZclClusterT *
ZbZclAlarmClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, ZbZclAlarmClientCallbackT callback, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    /* EXEGIN - don't allow Alarms Client on same endpoint as
     * Alarms Server, which is setup to receive loopback commands sent
     * to the Alarms Client to be forwarded over-the-air to Alarms Client
     * bindings. */

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_ALARMS, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.command = alarm_command;
    clusterPtr->callback = callback;
    clusterPtr->arg = arg;

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
alarm_command(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *aps_data_ind)
{
    struct cluster_priv_t *alarm_cluster = (struct cluster_priv_t *)cluster;

    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_CLIENT) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (zclHdrPtr->frameCtrl.manufacturer) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    if (zclHdrPtr->cmdId == ZCL_ALARM_COMMAND_ALARM) {
        uint8_t alarm_code;
        uint16_t cluster_id;

        /* parse alarm */
        if (aps_data_ind->asduLength < 3) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }
        alarm_code = aps_data_ind->asdu[0];
        cluster_id = pletoh16(&aps_data_ind->asdu[1]);

        if (aps_data_ind->src.mode != ZB_APSDE_ADDRMODE_SHORT) {
            ZCL_LOG_PRINTF(cluster->zb, __func__, "received alarm with invalid addressing");
            return ZCL_STATUS_INVALID_FIELD;
        }
        alarm_cluster->callback(alarm_cluster->arg, aps_data_ind->src.nwkAddr, (uint8_t)aps_data_ind->src.endpoint, alarm_code, cluster_id);
        return ZCL_STATUS_SUCCESS;
    }

    /* Note, ZCL_ALARM_COMMAND_GET_RESPONSE is handled by the ZbZclAlarmClientGetAlarmReq
     * callback handler. */

    return ZCL_STATUS_UNSUPP_COMMAND;
}

static int
reset_alarm_build(uint8_t *payload, unsigned int length, uint8_t alarm_code, uint16_t cluster_id)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, alarm_code) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, cluster_id) < 0) {
        return -1;
    }
    return index;
}

enum ZclStatusCodeT
ZbZclAlarmClientResetAlarmReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst, uint8_t alarm_code,
    uint16_t cluster_id, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[3];
    int length = 0;
    struct ZbZclClusterCommandReqT req;

    length = reset_alarm_build(payload, sizeof(payload), alarm_code, cluster_id);
    if (length < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_ALARM_COMMAND_RESET;
    /* No cluster-specific response, so set Disable Default Response to False */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclAlarmClientResetAllAlarmsReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_ALARM_COMMAND_RESET_ALL;
    /* No cluster-specific response, so set Disable Default Response to False */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclAlarmClientGetAlarmReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_ALARM_COMMAND_GET;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclAlarmClientResetAlarmLogReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_ALARM_COMMAND_RESET_LOG;
    /* No cluster-specific response, so set Disable Default Response to False */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}
