/* Copyright [2017 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl/general/zcl.therm.h"

/* Thermostat cluster */
struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct ZbZclThermServerCallbacksT callbacks;
};

static enum ZclStatusCodeT therm_svr_command_cb(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *zcl_hdr, struct ZbApsdeDataIndT *dataIndPtr);

static uint8_t therm_svr_get_scene_cb(struct ZbZclClusterT *clusterPtr,
    uint8_t *extBuf, uint8_t extMaxLen);

static enum ZclStatusCodeT therm_svr_set_scene_cb(struct ZbZclClusterT *clusterPtr,
    uint8_t *extData, uint8_t extLen, uint16_t transition_tenths);

/* Attributes */
static const struct ZbZclAttrT thermAttrList[] = {
    {
        ZCL_THERM_SVR_ATTR_LOCAL_TEMP, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {ZCL_THERM_TEMP_MIN, ZCL_THERM_TEMP_MAX}, {0, 0}
    },
    {
        ZCL_THERM_SVR_ATTR_OUTDOOR_TEMP, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {ZCL_THERM_TEMP_MIN, ZCL_THERM_TEMP_MAX}, {0, 0}
    },
    {
        ZCL_THERM_SVR_ATTR_OCCUP_COOL_SETPOINT, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {ZCL_THERM_TEMP_MIN, ZCL_THERM_TEMP_MAX}, {0, 0}
    },
    {
        ZCL_THERM_SVR_ATTR_OCCUP_HEAT_SETPOINT, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {ZCL_THERM_TEMP_MIN, ZCL_THERM_TEMP_MAX}, {0, 0}
    },
    {
        ZCL_THERM_SVR_ATTR_CONTROL_SEQ_OPER, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, ZCL_THERM_CONTROL_OPERCOOL_HEAT_REHEAT}, {0, 0}
    },
    {
        ZCL_THERM_SVR_ATTR_SYSTEM_MODE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, ZCL_THERM_SYSMODE_SLEEP}, {0, 0}
    },
};

struct ZbZclClusterT *
ZbZclThermServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclThermServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *server;

    server = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_HVAC_THERMOSTAT, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (server == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "CCB 1981 2186 2249 2250 2251; NFR Thermostat Setback"
     * (need to investigate these changes) */
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    server->cluster.command = therm_svr_command_cb;
    server->cluster.get_scene_data = therm_svr_get_scene_cb;
    server->cluster.set_scene_data = therm_svr_set_scene_cb;

    if (callbacks != NULL) {
        memcpy(&server->callbacks, callbacks, sizeof(struct ZbZclThermServerCallbacksT));
    }
    else {
        memset(&server->callbacks, 0, sizeof(struct ZbZclThermServerCallbacksT));
    }
    ZbZclClusterSetCallbackArg(&server->cluster, arg);

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&server->cluster, thermAttrList, ZCL_ATTR_LIST_LEN(thermAttrList))) {
        ZbZclClusterFree(&server->cluster);
        return NULL;
    }

    ZbZclAttrIntegerWrite(&server->cluster, ZCL_THERM_SVR_ATTR_LOCAL_TEMP, ZCL_THERM_TEMP_LOCAL_DEFAULT);
    /* Set default to 26 deg C (0x0a28 = 2600) */
    ZbZclAttrIntegerWrite(&server->cluster, ZCL_THERM_SVR_ATTR_OCCUP_COOL_SETPOINT, 2600);
    /* Set default to 20 deg C (0x07d0 = 2000) */
    ZbZclAttrIntegerWrite(&server->cluster, ZCL_THERM_SVR_ATTR_OCCUP_HEAT_SETPOINT, 2000);
    /* Set the default to Heat */
    ZbZclAttrIntegerWrite(&server->cluster, ZCL_THERM_SVR_ATTR_CONTROL_SEQ_OPER, ZCL_THERM_CONTROL_OPERCOOL_HEAT);
    /* Set default to Auto */
    ZbZclAttrIntegerWrite(&server->cluster, ZCL_THERM_SVR_ATTR_SYSTEM_MODE, ZCL_THERM_SYSMODE_AUTO);

    (void)ZbZclClusterAttach(&server->cluster);
    return &server->cluster;
}

static enum ZclStatusCodeT
therm_svr_command_cb(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zcl_hdr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)clusterPtr;
    unsigned int i = 0;
    enum ZclStatusCodeT rc;
    struct ZbZclAddrInfoT srcInfo;

    memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zcl_hdr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    if (zcl_hdr->frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    switch (zcl_hdr->cmdId) {
        case ZCL_THERM_CLI_SETPOINT_RAISE_LOWER:
        {
            struct ZbZclThermCliSetpointT req;

            if (server->callbacks.setpoint_raise_lower == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            if (dataIndPtr->asduLength < 2) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            /* Parse the request */
            memset(&req, 0, sizeof(req));
            req.mode = dataIndPtr->asdu[i++];
            req.amount = (int8_t)dataIndPtr->asdu[i++];
            /* Callback */
            rc = server->callbacks.setpoint_raise_lower(clusterPtr, clusterPtr->app_cb_arg, &req, &srcInfo);
            break;
        }

        case ZCL_THERM_CLI_SET_WEEK_SCHED:
        {
            struct ZbZclThermWeeklySchedT req;
            unsigned int j;

            if (server->callbacks.set_weekly == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            if (dataIndPtr->asduLength < 3) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            /* Parse the request */
            memset(&req, 0, sizeof(req));
            req.num_transitions = dataIndPtr->asdu[i++];
            req.day_of_week_seq = (int8_t)dataIndPtr->asdu[i++];
            req.mode_for_seq = (int8_t)dataIndPtr->asdu[i++];

            if (req.num_transitions > ZCL_THERM_NUM_TRANSITIONS_MAX) {
                /* or return ZCL_STATUS_INSUFFICIENT_SPACE? */
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            /* transitions */
            for (j = 0; j < req.num_transitions; j++) {
                req.transitions[j].transition_time = pletoh16(&dataIndPtr->asdu[i]);
                i += 2U;
                if ((req.mode_for_seq & ZCL_THERM_MODE_HEAT_SETPOINT_PRESENT) != 0U) {
                    req.transitions[j].heat_set_point = pletoh16(&dataIndPtr->asdu[i]);
                    i += 2U;
                }
                if ((req.mode_for_seq & ZCL_THERM_MODE_COOL_SETPOINT_PRESENT) != 0U) {
                    req.transitions[j].cool_set_point = pletoh16(&dataIndPtr->asdu[i]);
                    i += 2U;
                }
            }

            /* Callback */
            rc = server->callbacks.set_weekly(clusterPtr, clusterPtr->app_cb_arg, &req, &srcInfo);
            break;
        }

        case ZCL_THERM_CLI_GET_WEEK_SCHED:
        {
            struct ZbZclThermCliGetWeeklyT req;

            if (server->callbacks.get_weekly == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            if (dataIndPtr->asduLength < 2) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            /* Parse the request */
            memset(&req, 0, sizeof(req));
            req.days_to_return = dataIndPtr->asdu[i++];
            req.mode_to_return = (int8_t)dataIndPtr->asdu[i++];

            /* Callback */
            rc = server->callbacks.get_weekly(clusterPtr, clusterPtr->app_cb_arg, &req, &srcInfo);
            break;
        }

        case ZCL_THERM_CLI_CLEAR_WEEK_SCHED:
            if (server->callbacks.clear_weekly == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            /* No payload */
            /* Callback */
            rc = server->callbacks.clear_weekly(clusterPtr, clusterPtr->app_cb_arg, &srcInfo);
            break;

        case ZCL_THERM_CLI_GET_RELAY_LOG:
            if (server->callbacks.get_relay_status_log == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            /* No payload */
            /* Callback */
            rc = server->callbacks.get_relay_status_log(clusterPtr, clusterPtr->app_cb_arg, &srcInfo);
            break;

        default:
            rc = ZCL_STATUS_UNSUPP_COMMAND;
    }
    return rc;
}

static uint8_t
therm_svr_get_scene_cb(struct ZbZclClusterT *clusterPtr, uint8_t *extBuf, uint8_t extMaxLen)
{
    uint8_t len = 0;
    int16_t setpoint;
    uint8_t mode;

    /* Cluster ID [0:1] */
    putle16(&extBuf[len], clusterPtr->clusterId);
    len += 2;
    /* Extension Length [2] */
    extBuf[len++] = 0; /* filled in later */

    /* Scene Table Extensions:
     * 1) OccupiedCoolingSetpoint (2 bytes)
     * 2) OccupiedHeatingSetpoint (2 bytes)
     * 3) SystemMode (1 byte)
     */

    /* OccupiedCoolingSetpoint */
    if (ZbZclAttrRead(clusterPtr, ZCL_THERM_SVR_ATTR_OCCUP_COOL_SETPOINT, NULL, &setpoint, sizeof(setpoint), false) != ZCL_STATUS_SUCCESS) {
        return 0;
    }
    putle16(&extBuf[len], setpoint);
    len += 2;

    /* OccupiedHeatingSetpoint */
    if (ZbZclAttrRead(clusterPtr, ZCL_THERM_SVR_ATTR_OCCUP_HEAT_SETPOINT, NULL, &setpoint, sizeof(setpoint), false) != ZCL_STATUS_SUCCESS) {
        return 0;
    }
    putle16(&extBuf[len], setpoint);
    len += 2;

    /* SystemMode */
    if (ZbZclAttrRead(clusterPtr, ZCL_THERM_SVR_ATTR_SYSTEM_MODE, NULL, &mode, sizeof(mode), false) != ZCL_STATUS_SUCCESS) {
        return 0;
    }
    extBuf[len++] = mode;

    /* Extension Length [2] */
    extBuf[2] = len - 3;
    return len;
}

static enum ZclStatusCodeT
therm_svr_set_scene_cb(struct ZbZclClusterT *clusterPtr, uint8_t *extData, uint8_t extLen, uint16_t transition_tenths)
{
    uint8_t len = 0;
    int16_t setpoint;
    uint8_t mode;

    if (extLen < 5) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, invalid scene data length (%d)", extLen);
        return ZCL_STATUS_INVALID_VALUE;
    }

    /* OccupiedCoolingSetpoint */
    setpoint = pletoh16(&extData[len]);
    len += 2;
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_THERM_SVR_ATTR_OCCUP_COOL_SETPOINT, setpoint);

    /* OccupiedHeatingSetpoint */
    setpoint = pletoh16(&extData[len]);
    len += 2;
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_THERM_SVR_ATTR_OCCUP_HEAT_SETPOINT, setpoint);

    /* SystemMode */
    mode = extData[len];
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_THERM_SVR_ATTR_SYSTEM_MODE, mode);

    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclThermServerGetWeeklySchedRsp(struct ZbZclClusterT *clusterPtr,
    struct ZbZclAddrInfoT *dstInfo, struct ZbZclThermWeeklySchedT *rsp)
{
    uint8_t rsp_payload[3 + (ZCL_THERM_NUM_TRANSITIONS_MAX * 6)];
    unsigned int len = 0;
    struct ZbApsBufT bufv[1];
    unsigned int i;

    if (rsp->num_transitions > ZCL_THERM_NUM_TRANSITIONS_MAX) {
        return ZCL_STATUS_FAILURE;
    }

    /* Form the payload */
    rsp_payload[len++] = rsp->num_transitions;
    rsp_payload[len++] = rsp->day_of_week_seq;
    rsp_payload[len++] = rsp->mode_for_seq;
    /* transitions */
    for (i = 0; i < rsp->num_transitions; i++) {
        putle16(&rsp_payload[len], rsp->transitions[i].transition_time);
        len += 2U;
        if ((rsp->mode_for_seq & ZCL_THERM_MODE_HEAT_SETPOINT_PRESENT) != 0U) {
            putle16(&rsp_payload[len], (uint16_t)rsp->transitions[i].heat_set_point);
            len += 2U;
        }
        if ((rsp->mode_for_seq & ZCL_THERM_MODE_COOL_SETPOINT_PRESENT) != 0U) {
            putle16(&rsp_payload[len], (uint16_t)rsp->transitions[i].cool_set_point);
            len += 2U;
        }
    }

    bufv[0].data = rsp_payload;
    bufv[0].len = len;

    return ZbZclClusterCommandRsp(clusterPtr, dstInfo, (uint8_t)ZCL_THERM_SVR_GET_WEEK_RSP, bufv, 1U);
}

/* ZCL_THERM_SVR_GET_RELAY_LOG_RSP */
enum ZclStatusCodeT
ZbZclThermServerGetRelayStatusLogRsp(struct ZbZclClusterT *clusterPtr,
    struct ZbZclAddrInfoT *dstInfo, struct ZbZclThermSvrGetRelayStatusLogRspT *rsp)
{
    uint8_t rsp_payload[11];
    unsigned int len = 0;
    struct ZbApsBufT bufv[1];

    /* Form the payload */
    putle16(&rsp_payload[len], rsp->time_of_day);
    len += 2;
    putle16(&rsp_payload[len], rsp->relay_status);
    len += 2;
    putle16(&rsp_payload[len], (uint16_t)rsp->local_temp);
    len += 2;
    rsp_payload[len++] = rsp->humidity_percent;
    putle16(&rsp_payload[len], (uint16_t)rsp->set_point);
    len += 2;
    putle16(&rsp_payload[len], rsp->unread_entries);
    len += 2;

    bufv[0].data = rsp_payload;
    bufv[0].len = len;

    return ZbZclClusterCommandRsp(clusterPtr, dstInfo, (uint8_t)ZCL_THERM_SVR_GET_RELAY_LOG_RSP, bufv, 1U);
}
