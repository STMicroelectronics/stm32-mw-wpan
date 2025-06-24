/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

/*-------------------------------------------------
 *  DESCRIPTION
 *      HA IAS devices Implementation.
 *-------------------------------------------------
 */

#include "zcl/security/zcl.ias_ace.h"

struct cluster_priv_t {
    /* The ZCL Cluster struct must go first for inheritance. */
    struct ZbZclClusterT cluster;
};

static enum ZclStatusCodeT zcl_ias_ace_client_command(struct ZbZclClusterT *,
    struct ZbZclHeaderT *, struct ZbApsdeDataIndT *);

struct ZbZclClusterT *
ZbZclIasAceClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t),
            ZCL_CLUSTER_SECURITY_IAS_ANCILLARY, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.command = zcl_ias_ace_client_command;

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_ias_ace_client_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    if (zclHdrPtr->frameCtrl.manufacturer) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    switch (zclHdrPtr->cmdId) {
        case ZCL_IAS_ACE_SVR_CMD_ARM_RSP:
        case ZCL_IAS_ACE_SVR_CMD_GET_ZONE_ID_MAP_RSP:
        case ZCL_IAS_ACE_SVR_CMD_GET_ZONE_INFO_RSP:
        case ZCL_IAS_ACE_SVR_CMD_ZONE_STATUS_CHANGED:
        case ZCL_IAS_ACE_SVR_CMD_PANEL_STATUS_CHANGED:
        case ZCL_IAS_ACE_SVR_CMD_GET_PANEL_STATUS_RSP:
        case ZCL_IAS_ACE_SVR_CMD_SET_BYPASSED_ZONE_LIST:
        case ZCL_IAS_ACE_SVR_CMD_BYPASS_RSP:
        case ZCL_IAS_ACE_SVR_CMD_GET_ZONE_STATUS_RSP:
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

        default:
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
}

uint8_t
ZbZclIasAceClientCommandArmReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclIasAceClientCommandArmT *cmd_req, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int len = 0, arm_code_len;
    struct ZbZclClusterCommandReqT req;

    arm_code_len = strlen(cmd_req->arm_code);
    if (arm_code_len > ZCL_IAS_ACE_ARM_CODE_STRING_MAX_LEN) {
        return ZCL_STATUS_INVALID_VALUE;
    }

    /* Command payload */
    payload[len++] = cmd_req->arm_mode;
    payload[len++] = arm_code_len;
    if (arm_code_len) {
        (void)memcpy(&payload[len], cmd_req->arm_code, arm_code_len);
        len += arm_code_len;
    }
    payload[len++] = cmd_req->zone_id;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ACE_CLI_CMD_ARM;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = len;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

uint8_t
ZbZclIasAceClientCommandBypassReq(struct ZbZclClusterT *cluster,
    const struct ZbApsAddrT *dst, struct ZbZclIasAceClientCommandBypassT *cmd_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int len = 0, arm_code_len, i;
    struct ZbZclClusterCommandReqT req;

    arm_code_len = strlen(cmd_req->arm_code);
    if (arm_code_len > ZCL_IAS_ACE_ARM_CODE_STRING_MAX_LEN) {
        return ZCL_STATUS_INVALID_VALUE;
    }
    if (cmd_req->num_zones > ZCL_IAS_ACE_BYPASS_MAX_ZONES) {
        return ZCL_STATUS_INVALID_VALUE;
    }

    /* Command payload */
    payload[len++] = cmd_req->num_zones;
    for (i = 0; i < cmd_req->num_zones; i++) {
        payload[len++] = cmd_req->zone_id_list[i];
    }
    payload[len++] = arm_code_len;
    if (arm_code_len) {
        (void)memcpy(&payload[len], cmd_req->arm_code, arm_code_len);
        len += arm_code_len;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ACE_CLI_CMD_BYPASS;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = len;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

uint8_t
ZbZclIasAceClientCommandEmergencyReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ACE_CLI_CMD_EMERGENCY;
    /* No cluster-specific response, so set no-default-response to false. */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

uint8_t
ZbZclIasAceClientCommandFireReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ACE_CLI_CMD_FIRE;
    /* No cluster-specific response, so set no-default-response to false. */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

uint8_t
ZbZclIasAceClientCommandPanicReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ACE_CLI_CMD_PANIC;
    /* No cluster-specific response, so set no-default-response to false. */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

uint8_t
ZbZclIasAceClientCommandGetZoneIdMapReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ACE_CLI_CMD_GET_ZONE_ID_MAP;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

uint8_t
ZbZclIasAceClientCommandGetZoneInfoReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclIasAceClientCommandGetZoneInfoT *cmd_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int len = 0;
    struct ZbZclClusterCommandReqT req;

    /* Command payload */
    payload[len++] = cmd_req->zone_id;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ACE_CLI_CMD_GET_ZONE_INFO;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = len;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

uint8_t
ZbZclIasAceClientCommandGetPanelStatusReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ACE_CLI_CMD_GET_PANEL_STATUS;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

uint8_t
ZbZclIasAceClientCommandGetBypassedZoneListReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ACE_CLI_CMD_GET_BYPASSED_ZONE_LIST;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

uint8_t
ZbZclIasAceClientCommandGetZoneStatusReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclIasAceClientCommandGetZoneStatusT *cmd_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int len = 0;
    struct ZbZclClusterCommandReqT req;

    /* Command payload */
    payload[len++] = cmd_req->starting_zone_id;
    payload[len++] = cmd_req->max_zone_ids;
    payload[len++] = cmd_req->zone_status_mask_flag;
    putle16(&payload[len], cmd_req->zone_status_mask);
    len += 2;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ACE_CLI_CMD_GET_ZONE_STATUS;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = len;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

bool
ZbZclIasAceClientParseArmRsp(const uint8_t *buf, unsigned int len, struct ZbZclIasAceServerCommandArmRspT *rsp)
{
    unsigned int i = 0;

    if ((i + 1) > len) {
        return false;
    }
    rsp->arm_notify = (enum ZbZclIasAceArmNotifyT)buf[i++];
    return true;
}

bool
ZbZclIasAceClientParseGetZoneIdMapRsp(const uint8_t *buf, unsigned int len, struct ZbZclIasAceServerCommandGetZoneIdMapRspT *rsp)
{
    unsigned int i = 0, j;

    if ((i + (ZCL_IAS_ACE_ZONE_ID_MAP_NUM_SECTIONS * 2)) > len) {
        return false;
    }
    for (j = 0; j < ZCL_IAS_ACE_ZONE_ID_MAP_NUM_SECTIONS; j++) {
        rsp->zond_id_map_list[j] = pletoh16(&buf[i]);
        i += 2;
    }
    return true;
}

bool
ZbZclIasAceClientParseGetZoneInfoRsp(const uint8_t *buf, unsigned int len, struct ZbZclIasAceServerCommandGetZoneInfoRspT *rsp)
{
    unsigned int i = 0, zone_label_len;

    if ((i + 12) > len) {
        return false;
    }
    (void)memset(rsp, 0, sizeof(struct ZbZclIasAceServerCommandGetZoneInfoRspT));
    rsp->zone_id = buf[i++];
    rsp->zone_type = (enum ZbZclIasZoneServerZoneTypeT)pletoh16(&buf[i]);
    i += 2;
    rsp->zone_addr = pletoh64(&buf[i]);
    i += 8;
    zone_label_len = buf[i++];
    if (zone_label_len > 0) {
        if (zone_label_len > ZCL_IAS_ACE_ZONE_LABEL_STRING_MAX_LEN) {
            return false;
        }
        if ((i + zone_label_len) > len) {
            return false;
        }
        (void)memcpy(rsp->zone_label, &buf[i], zone_label_len);
        i += zone_label_len;
    }
    return true;
}

bool
ZbZclIasAceClientParseZoneStatusChanged(const uint8_t *buf, unsigned int len, struct ZbZclIasAceServerCommandZoneStatusChangedT *rsp)
{
    unsigned int i = 0, zone_label_len;

    if ((i + 5) > len) {
        return false;
    }
    (void)memset(rsp, 0, sizeof(struct ZbZclIasAceServerCommandZoneStatusChangedT));
    rsp->zone_id = buf[i++];
    rsp->zone_status = (enum ZbZclIasZoneServerZoneStatusT)pletoh16(&buf[i]);
    i += 2;
    rsp->audible_notify = (enum ZbZclIasAceAudibleNotifyT)buf[i++];
    zone_label_len = buf[i++];
    if (zone_label_len > 0) {
        if (zone_label_len > ZCL_IAS_ACE_ZONE_LABEL_STRING_MAX_LEN) {
            return false;
        }
        if ((i + zone_label_len) > len) {
            return false;
        }
        (void)memcpy(rsp->zone_label, &buf[i], zone_label_len);
        i += zone_label_len;
    }
    return true;
}

bool
ZbZclIasAceClientParseGetPanelStatusRsp(const uint8_t *buf, unsigned int len, struct ZbZclIasAceServerCommandGetPanelStatusRspT *rsp)
{
    unsigned int i = 0;

    if ((i + 4) > len) {
        return false;
    }
    rsp->panel_status = (enum ZbZclIasAcePanelStatusT)buf[i++];
    rsp->seconds_remain = buf[i++];
    rsp->audible_notify = (enum ZbZclIasAceAudibleNotifyT)buf[i++];
    rsp->alarm_status = (enum ZbZclIasAceAlarmStatusT)buf[i++];
    return true;
}

bool
ZbZclIasAceClientParseSetBypassedZoneList(const uint8_t *buf, unsigned int len, struct ZbZclIasAceServerCommandSetBypassedZoneListT *rsp)
{
    unsigned int i = 0, j;

    if ((i + 1) > len) {
        return false;
    }
    rsp->num_zones = buf[i++];
    if (rsp->num_zones > 0) {
        if (rsp->num_zones > ZCL_IAS_ACE_BYPASS_MAX_ZONES) {
            return false;
        }
        if ((i + rsp->num_zones) > len) {
            return false;
        }
        for (j = 0; j < rsp->num_zones; j++) {
            rsp->zone_id_list[j] = buf[i++];
        }
    }
    return true;
}

bool
ZbZclIasAceClientParseBypassRsp(const uint8_t *buf, unsigned int len, struct ZbZclIasAceServerCommandBypassRspT *rsp)
{
    unsigned int i = 0, j;

    if ((i + 1) > len) {
        return false;
    }
    rsp->num_zones = buf[i++];
    if (rsp->num_zones > 0) {
        if (rsp->num_zones > ZCL_IAS_ACE_BYPASS_MAX_ZONES) {
            return false;
        }
        if ((i + rsp->num_zones) > len) {
            return false;
        }
        for (j = 0; j < rsp->num_zones; j++) {
            rsp->bypass_result_list[j] = (enum ZbZclIasAceBypassResultT)buf[i++];
        }
    }
    return true;
}

bool
ZbZclIasAceClientParseGetZoneStatusRsp(const uint8_t *buf, unsigned int len, struct ZbZclIasAceServerCommandGetZoneStatusRspT *rsp)
{
    unsigned int i = 0, j;

    if ((i + 2) > len) {
        return false;
    }
    rsp->zone_status_complete = buf[i++];
    rsp->num_zones = buf[i++];
    if (rsp->num_zones > 0) {
        if (rsp->num_zones > ZCL_IAS_ACE_ZONE_STATUS_MAX_ZONES) {
            return false;
        }
        if ((i + (rsp->num_zones * 3)) > len) {
            return false;
        }
        for (j = 0; j < rsp->num_zones; j++) {
            rsp->zone_list[j].zone_id = buf[i++];
            rsp->zone_list[j].zone_status = (enum ZbZclIasZoneServerZoneStatusT)pletoh16(&buf[i]);
            i += 2U;
        }
    }
    return true;
}
