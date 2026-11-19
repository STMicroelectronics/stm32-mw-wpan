/* Copyright [2017 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.power.profile.h"

/*lint -e9087 "cluster_priv_t* <- ZbZclClusterT* [MISRA Rule 11.3 (REQUIRED)]" */

/* Power Profile cluster */
struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct ZbZclPowerProfServerCallbacks callbacks;
};

static enum ZclStatusCodeT power_profile_server_cmd(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

/* Attributes */
static const struct ZbZclAttrT attr_list[] = {
    {
        ZCL_POWER_PROF_SVR_ATTR_TOTAL_PROFILENUM, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE,
        0, NULL, {0, 0xFE}, {0, 0}
    },
    {
        ZCL_POWER_PROF_SVR_ATTR_MULTIPLE_SCHED, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_NONE,
        0, NULL, {0, 0x01}, {0, 0}
    },
    {
        ZCL_POWER_PROF_SVR_ATTR_ENERGY_FORMAT, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_NONE,
        0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_PROF_SVR_ATTR_ENERGY_REMOTE, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_NONE,
        0, NULL, {0, 0x01}, {0, 0}
    },
    {
        ZCL_POWER_PROF_SVR_ATTR_SCHEDULE_MODE, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE,
        0, NULL, {0, 0xFF}, {0, 0}
    }
};

struct ZbZclClusterT *
ZbZclPowerProfServerAlloc(struct ZigBeeT *zb, uint8_t endpoint,
    struct ZbZclPowerProfServerCallbacks *callbacks, void *arg)
{
    struct cluster_priv_t *server;

    server = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_POWER_PROFILE,
            endpoint, ZCL_DIRECTION_TO_SERVER);
    if (server == NULL) {
        return NULL;
    }

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&server->cluster, attr_list, ZCL_ATTR_LIST_LEN(attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&server->cluster);
        return NULL;
    }
    server->cluster.command = power_profile_server_cmd;

    /* Set some default values */
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_POWER_PROF_SVR_ATTR_TOTAL_PROFILENUM, 1);
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_POWER_PROF_SVR_ATTR_MULTIPLE_SCHED, 0);
    /* Energy format: 1 trailing digit, no leading digits (i.e. 1/10 of Watt Hours) */
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_POWER_PROF_SVR_ATTR_ENERGY_FORMAT, 0x01);
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_POWER_PROF_SVR_ATTR_ENERGY_REMOTE, 0);
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_POWER_PROF_SVR_ATTR_SCHEDULE_MODE, 0);

    /* Configure callbacks */
    if (callbacks != NULL) {
        (void)memcpy(&server->callbacks, callbacks, sizeof(struct ZbZclPowerProfServerCallbacks));
    }
    else {
        (void)memset(&server->callbacks, 0, sizeof(struct ZbZclPowerProfServerCallbacks));
    }
    ZbZclClusterSetCallbackArg(&server->cluster, arg);

    (void)ZbZclClusterAttach(&server->cluster);
    return &server->cluster;
}

static enum ZclStatusCodeT
power_profile_server_cmd(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr,
    struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)clusterPtr;
    uint8_t cmdId = zclHdrPtr->cmdId;
    enum ZclStatusCodeT rc;
    struct ZbZclAddrInfoT srcInfo;
    unsigned int i = 0;

    (void)memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zclHdrPtr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    switch (cmdId) {
        case ZCL_PWR_PROF_CLI_PROFILE_REQ:
        {
            struct ZbZclPowerProfCliProfileReq req;

            if (server->callbacks.profile_req == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            /* PowerProfileRequest has length of 1 */
            if (dataIndPtr->asduLength < 1U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            memset(&req, 0, sizeof(req));
            req.profile_id = dataIndPtr->asdu[0];
            rc = server->callbacks.profile_req(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_PWR_PROF_CLI_STATE_REQ:
            if (server->callbacks.state_req == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            /* No Payload */
            rc = server->callbacks.state_req(clusterPtr, &srcInfo, clusterPtr->app_cb_arg);
            break;

        case ZCL_PWR_PROF_CLI_PHASES_NOTIFY:
        {
            struct ZbZclPowerProfCliPhasesNotify notify;
            unsigned int j;

            if (server->callbacks.phases_notify == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            memset(&notify, 0, sizeof(notify));
            if (dataIndPtr->asduLength < 1U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            notify.profile_id = dataIndPtr->asdu[i++];
            notify.num_phases = dataIndPtr->asdu[i++];
            if (notify.num_phases > ZCL_PWR_PROF_MAX_ENERGY_PHASES) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            if ((i + (3 * notify.num_phases)) > dataIndPtr->asduLength) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            for (j = 0; j < notify.num_phases; j++) {
                notify.sched_list[j].energy_phase_id = dataIndPtr->asdu[i++];
                notify.sched_list[j].sched_time = pletoh16(&dataIndPtr->asdu[i]);
                i += 2;
            }
            rc = server->callbacks.phases_notify(clusterPtr, &notify, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_PWR_PROF_CLI_SCHED_CONS_REQ:
        {
            struct ZbZclPowerProfCliProfileReq req;

            if (server->callbacks.sched_contraints_req == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            if (dataIndPtr->asduLength < 1U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            memset(&req, 0, sizeof(req));
            req.profile_id = dataIndPtr->asdu[0];
            rc = server->callbacks.sched_contraints_req(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_PWR_PROF_CLI_PHASES_SCHED_STATE_REQ:
        {
            struct ZbZclPowerProfCliProfileReq req;

            if (server->callbacks.phases_sched_state_req == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            if (dataIndPtr->asduLength < 1U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            memset(&req, 0, sizeof(req));
            req.profile_id = dataIndPtr->asdu[0];
            rc = server->callbacks.phases_sched_state_req(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        default:
            rc = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return rc;
}

static enum ZclStatusCodeT
power_profile_server_build_profile(struct ZbZclPowerProfSvrProfileRsp *rsp,
    uint8_t *payload, uint16_t *plen)
{
    /* uint16_t max_len = *plen; */
    uint16_t len = 0;
    unsigned int i;

    /* Check input parameters */
    if (rsp->num_transferred_phases > ZCL_PWR_PROF_MAX_ENERGY_PHASES) {
        return ZCL_STATUS_FAILURE;
    }

    /* Command payload */
    payload[len++] = rsp->total_profile_num;
    payload[len++] = rsp->profile_id;
    payload[len++] = rsp->num_transferred_phases;
    for (i = 0; i < rsp->num_transferred_phases; i++) {
        payload[len++] = rsp->phase_list[i].energy_phase_id;
        payload[len++] = rsp->phase_list[i].macro_phase_id;
        putle16(&payload[len], rsp->phase_list[i].expect_duration);
        len += 2;
        putle16(&payload[len], rsp->phase_list[i].peak_power);
        len += 2;
        putle16(&payload[len], rsp->phase_list[i].energy);
        len += 2;
        putle16(&payload[len], rsp->phase_list[i].max_activation_delay);
        len += 2;
    }
    *plen = len;
    return ZCL_STATUS_SUCCESS;
}

/* ZCL_PWR_PROF_SVR_PROFILE_NOTIFY */
enum ZclStatusCodeT
ZbZclPowerProfServerProfileNotify(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPowerProfSvrProfileRsp *notify,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    uint8_t payload[3 + (ZCL_PWR_PROF_MAX_ENERGY_PHASES * 10)]; /* EXEGIN - magic nums */
    uint16_t len;
    struct ZbZclClusterCommandReqT req;

    len = sizeof(payload);
    power_profile_server_build_profile(notify, payload, &len);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_PWR_PROF_SVR_PROFILE_NOTIFY;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = len;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

/* ZCL_PWR_PROF_SVR_PROFILE_RSP */
enum ZclStatusCodeT
ZbZclPowerProfServerProfileRsp(struct ZbZclClusterT *cluster,
    struct ZbZclAddrInfoT *dst, struct ZbZclPowerProfSvrProfileRsp *rsp,
    void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[3 + (ZCL_PWR_PROF_MAX_ENERGY_PHASES * 10)]; /* EXEGIN - magic nums */
    uint16_t len;
    struct ZbApsBufT bufv;

    len = sizeof(payload);
    power_profile_server_build_profile(rsp, payload, &len);

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(cluster, dst, ZCL_PWR_PROF_SVR_PROFILE_RSP, &bufv, 1U, callback, arg);
}

/* ZCL_PWR_PROF_SVR_STATE_RSP */
enum ZclStatusCodeT
ZbZclPowerProfServerStateRsp(struct ZbZclClusterT *cluster,
    struct ZbZclAddrInfoT *dst, struct ZbZclPowerProfSvrStateRsp *rsp,
    void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1U + (ZCL_PWR_PROF_MAX_PROFILES * 4U)];
    uint16_t len = 0;
    struct ZbApsBufT bufv;
    unsigned int i;

    /* Check input parameters */
    if (rsp->profile_count > ZCL_PWR_PROF_MAX_PROFILES) {
        return ZCL_STATUS_FAILURE;
    }

    /* Command payload */
    payload[len++] = rsp->profile_count;
    for (i = 0; i < rsp->profile_count; i++) {
        payload[len++] = rsp->record_list[i].profile_id;
        payload[len++] = rsp->record_list[i].energy_phase_id;
        payload[len++] = rsp->record_list[i].remote_control;
        payload[len++] = rsp->record_list[i].state;
    }

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(cluster, dst, ZCL_PWR_PROF_SVR_STATE_RSP, &bufv, 1U, callback, arg);
}

/* ZCL_PWR_PROF_SVR_STATE_NOTIFY */
enum ZclStatusCodeT
ZbZclPowerProfServerStateNotify(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPowerProfSvrStateRsp *notify,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd_req;
    uint8_t payload[1U + (ZCL_PWR_PROF_MAX_PROFILES * 4U)];
    uint16_t len = 0;
    unsigned int i;

    /* Check input parameters */
    if (notify->profile_count > ZCL_PWR_PROF_MAX_PROFILES) {
        return ZCL_STATUS_FAILURE;
    }

    /* Command payload */
    payload[len++] = notify->profile_count;
    for (i = 0; i < notify->profile_count; i++) {
        payload[len++] = notify->record_list[i].profile_id;
        payload[len++] = notify->record_list[i].energy_phase_id;
        payload[len++] = notify->record_list[i].remote_control;
        payload[len++] = notify->record_list[i].state;
    }

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = ZCL_PWR_PROF_SVR_STATE_NOTIFY;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd_req.payload = payload;
    cmd_req.length = len;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

/* ZCL_PWR_PROF_SVR_GET_PRICE */
enum ZclStatusCodeT
ZbZclPowerProfServerGetPriceReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPowerProfCliProfileReq *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd_req;
    uint8_t payload[1];
    uint16_t len = 0;

    /* Command payload */
    payload[len++] = req->profile_id;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = ZCL_PWR_PROF_SVR_GET_PRICE;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    cmd_req.payload = payload;
    cmd_req.length = len;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

/* ZCL_PWR_PROF_SVR_GET_SCHED_PRICE */
enum ZclStatusCodeT
ZbZclPowerProfServerGetSchedPriceReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd_req;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = ZCL_PWR_PROF_SVR_GET_SCHED_PRICE;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    cmd_req.payload = NULL;
    cmd_req.length = 0U;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

/* ZCL_PWR_PROF_SVR_PHASES_REQ */
enum ZclStatusCodeT
ZbZclPowerProfServerPhasesReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPowerProfCliProfileReq *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd_req;
    uint8_t payload[1];
    uint16_t len = 0;

    /* Command payload */
    payload[len++] = req->profile_id;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = ZCL_PWR_PROF_SVR_PHASES_REQ;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    cmd_req.payload = payload;
    cmd_req.length = len;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

/* ZCL_PWR_PROF_SVR_PHASES_RSP */
enum ZclStatusCodeT
ZbZclPowerProfServerPhasesRsp(struct ZbZclClusterT *cluster,
    struct ZbZclAddrInfoT *dst, struct ZbZclPowerProfSvrPhasesRsp *rsp,
    void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[2U];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    /* Command payload */
    payload[len++] = rsp->profile_id;
    payload[len++] = rsp->num_sched_energy_phases;
    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(cluster, dst, ZCL_PWR_PROF_SVR_PHASES_RSP, &bufv, 1U, callback, arg);
}

/* ZCL_PWR_PROF_SVR_PHASES_NOTIFY */
enum ZclStatusCodeT
ZbZclPowerProfServerPhasesNotify(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPowerProfSvrPhasesRsp *notify,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd_req;
    uint8_t payload[2U];
    uint16_t len = 0;

    /* Command payload */
    payload[len++] = notify->profile_id;
    payload[len++] = notify->num_sched_energy_phases;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = ZCL_PWR_PROF_SVR_PHASES_NOTIFY;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd_req.payload = payload;
    cmd_req.length = len;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

/* ZCL_PWR_PROF_SVR_CONSTRAINTS_RSP */
enum ZclStatusCodeT
ZbZclPowerProfServerConstraintsRsp(struct ZbZclClusterT *cluster,
    struct ZbZclAddrInfoT *dst, struct ZbZclPowerProfSvrConstraintsNotify *rsp,
    void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[5U];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    /* Command payload */
    payload[len++] = rsp->profile_id;
    putle16(&payload[len], rsp->start_after);
    len += 2;
    putle16(&payload[len], rsp->stop_before);
    len += 2;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(cluster, dst, ZCL_PWR_PROF_SVR_CONSTRAINTS_RSP, &bufv, 1U, callback, arg);
}

/* ZCL_PWR_PROF_SVR_CONSTRAINTS_NOTIFY */
enum ZclStatusCodeT
ZbZclPowerProfServerConstraintsNotify(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPowerProfSvrConstraintsNotify *notify,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd_req;
    uint8_t payload[5U];
    uint16_t len = 0;

    /* Command payload */
    payload[len++] = notify->profile_id;
    putle16(&payload[len], notify->start_after);
    len += 2;
    putle16(&payload[len], notify->stop_before);
    len += 2;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = ZCL_PWR_PROF_SVR_CONSTRAINTS_NOTIFY;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd_req.payload = payload;
    cmd_req.length = len;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

/* ZCL_PWR_PROF_SVR_GET_PRICE_EXT */
enum ZclStatusCodeT
ZbZclPowerProfServerGetPriceReqExtReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPowerProfSvrGetPriceExtReq *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd_req;
    uint8_t payload[4];
    uint16_t len = 0;

    /* Command payload */
    payload[len++] = req->options;
    payload[len++] = req->profile_id;
    if ((req->options & ZCL_PWR_PROF_PRICE_EXT_OPT_START_TIME_PRESENT) != 0U) {
        putle16(&payload[len], req->start_time);
        len += 2;
    }

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = ZCL_PWR_PROF_SVR_GET_PRICE_EXT;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    cmd_req.payload = payload;
    cmd_req.length = len;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}
