/* Copyright [2017 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.power.profile.h"

/*lint -save -e9087 "cluster_priv_t* <- ZbZclClusterT* [MISRA Rule 11.3 (REQUIRED)]" */

/* Power Profile cluster */
struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct ZbZclPowerProfClientCallbacks callbacks;
};

static enum ZclStatusCodeT power_profile_client_cmd_cb(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclPowerProfClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclPowerProfClientCallbacks *callbacks, void *arg)
{
    struct cluster_priv_t *client;

    client = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_POWER_PROFILE, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (client == NULL) {
        return NULL;
    }

    client->cluster.command = power_profile_client_cmd_cb;

    /* Configure callbacks */
    if (callbacks != NULL) {
        (void)memcpy(&client->callbacks, callbacks, sizeof(struct ZbZclPowerProfClientCallbacks));
    }
    else {
        (void)memset(&client->callbacks, 0, sizeof(struct ZbZclPowerProfClientCallbacks));
    }
    ZbZclClusterSetCallbackArg(&client->cluster, arg);

    (void)ZbZclClusterAttach(&client->cluster);
    return &client->cluster;
}

static enum ZclStatusCodeT
power_profile_client_cmd_cb(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)clusterPtr;
    uint8_t cmdId = zclHdrPtr->cmdId;
    enum ZclStatusCodeT rc;
    struct ZbZclAddrInfoT srcInfo;
    unsigned int i = 0;

    (void)memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zclHdrPtr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    switch (cmdId) {
        case ZCL_PWR_PROF_SVR_PROFILE_NOTIFY:
        {
            struct ZbZclPowerProfSvrProfileRsp notify;
            unsigned int j;

            if (client->callbacks.profile_notify == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            memset(&notify, 0, sizeof(notify));
            if (dataIndPtr->asduLength < 3) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            notify.total_profile_num = dataIndPtr->asdu[i++];
            notify.profile_id = dataIndPtr->asdu[i++];
            notify.num_transferred_phases = dataIndPtr->asdu[i++];
            if (notify.num_transferred_phases > ZCL_PWR_PROF_MAX_ENERGY_PHASES) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            /* EXEGIN - magic num */
            if ((i + (10 * notify.num_transferred_phases)) > dataIndPtr->asduLength) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            for (j = 0; j < notify.num_transferred_phases; j++) {
                notify.phase_list[j].energy_phase_id = dataIndPtr->asdu[i++];
                notify.phase_list[j].macro_phase_id = dataIndPtr->asdu[i++];
                notify.phase_list[j].expect_duration = pletoh16(&dataIndPtr->asdu[i]);
                i += 2;
                notify.phase_list[j].peak_power = pletoh16(&dataIndPtr->asdu[i]);
                i += 2;
                notify.phase_list[j].energy = pletoh16(&dataIndPtr->asdu[i]);
                i += 2;
                notify.phase_list[j].max_activation_delay = pletoh16(&dataIndPtr->asdu[i]);
                i += 2;
            }
            rc = client->callbacks.profile_notify(clusterPtr, &notify, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_PWR_PROF_SVR_GET_PRICE:
        {
            struct ZbZclPowerProfCliProfileReq req;

            if (client->callbacks.get_price == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            memset(&req, 0, sizeof(req));
            if (dataIndPtr->asduLength < 1) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            req.profile_id = dataIndPtr->asdu[i++];
            rc = client->callbacks.get_price(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_PWR_PROF_SVR_STATE_NOTIFY:
        {
            struct ZbZclPowerProfSvrStateRsp notify;
            unsigned int j;

            if (client->callbacks.state_notify == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            memset(&notify, 0, sizeof(notify));
            if (dataIndPtr->asduLength < 1) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            notify.profile_count = dataIndPtr->asdu[i++];
            if (notify.profile_count > ZCL_PWR_PROF_MAX_PROFILES) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            /* EXEGIN - magic num */
            if ((i + (4 * notify.profile_count)) > dataIndPtr->asduLength) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            for (j = 0; j < notify.profile_count; j++) {
                notify.record_list[j].profile_id = dataIndPtr->asdu[i++];
                notify.record_list[j].energy_phase_id = dataIndPtr->asdu[i++];
                notify.record_list[j].remote_control = dataIndPtr->asdu[i++];
                notify.record_list[j].state = (enum ZbZclPowerProfState)dataIndPtr->asdu[i++];
            }
            rc = client->callbacks.state_notify(clusterPtr, &notify, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_PWR_PROF_SVR_GET_SCHED_PRICE:
            /* No payload */
            rc = client->callbacks.get_sched_price(clusterPtr, &srcInfo, clusterPtr->app_cb_arg);
            break;

        case ZCL_PWR_PROF_SVR_PHASES_REQ:
        {
            struct ZbZclPowerProfCliProfileReq req;

            if (client->callbacks.phases_req == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            memset(&req, 0, sizeof(req));
            if (dataIndPtr->asduLength < 1) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            req.profile_id = dataIndPtr->asdu[i++];
            rc = client->callbacks.phases_req(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_PWR_PROF_SVR_PHASES_NOTIFY:
        {
            struct ZbZclPowerProfSvrPhasesRsp notify;

            if (client->callbacks.phases_notify == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            memset(&notify, 0, sizeof(notify));
            if (dataIndPtr->asduLength < 2) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            notify.profile_id = dataIndPtr->asdu[i++];
            notify.num_sched_energy_phases = dataIndPtr->asdu[i++];
            rc = client->callbacks.phases_notify(clusterPtr, &notify, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_PWR_PROF_SVR_CONSTRAINTS_NOTIFY:
        {
            struct ZbZclPowerProfSvrConstraintsNotify notify;

            if (client->callbacks.constraints_notify == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            memset(&notify, 0, sizeof(notify));
            if (dataIndPtr->asduLength < 5) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            notify.profile_id = dataIndPtr->asdu[i++];
            notify.start_after = pletoh16(&dataIndPtr->asdu[i]);
            i += 2;
            notify.stop_before = pletoh16(&dataIndPtr->asdu[i]);
            i += 2;
            rc = client->callbacks.constraints_notify(clusterPtr, &notify, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_PWR_PROF_SVR_GET_PRICE_EXT:
        {
            struct ZbZclPowerProfSvrGetPriceExtReq req;

            if (client->callbacks.get_price_ext == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            memset(&req, 0, sizeof(req));
            if (dataIndPtr->asduLength < 2) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            req.options = dataIndPtr->asdu[i++];
            req.profile_id = dataIndPtr->asdu[i++];
            if ((req.options & ZCL_PWR_PROF_PRICE_EXT_OPT_START_TIME_PRESENT) != 0U) {
                if ((i + 1) > dataIndPtr->asduLength) {
                    rc = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                req.start_time = pletoh16(&dataIndPtr->asdu[i]);
                i += 2;
            }
            rc = client->callbacks.get_price_ext(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        default:
            rc = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }

    return rc;
}

static enum ZclStatusCodeT
power_profile_client_profile_req(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPowerProfCliProfileReq *req, uint8_t cmd_id,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd_req;
    uint8_t payload[1];
    uint16_t len = 0;

    /* Command payload */
    payload[len++] = req->profile_id;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = cmd_id;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    cmd_req.payload = payload;
    cmd_req.length = len;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

/* ZCL_PWR_PROF_CLI_PROFILE_REQ */
enum ZclStatusCodeT
ZbZclPowerProfClientProfileReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPowerProfCliProfileReq *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    return power_profile_client_profile_req(cluster, dst, req, ZCL_PWR_PROF_CLI_PROFILE_REQ,
        callback, arg);
}

/* ZCL_PWR_PROF_CLI_STATE_REQ */
enum ZclStatusCodeT
ZbZclPowerProfClientStateReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd_req;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = (uint8_t)ZCL_PWR_PROF_CLI_STATE_REQ;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    cmd_req.payload = NULL;
    cmd_req.length = 0;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

static enum ZclStatusCodeT
power_profile_client_price_rsp(struct ZbZclClusterT *cluster,
    struct ZbZclAddrInfoT *dst, struct ZbZclPowerProfCliPriceRsp *rsp, uint8_t cmd_id,
    void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[8];
    unsigned int len = 0;
    struct ZbApsBufT bufv;

    /* Form the payload */
    payload[len++] = rsp->profile_id;
    putle16(&payload[len], rsp->currency);
    len += 2;
    putle32(&payload[len], rsp->price);
    len += 4;
    payload[len++] = rsp->trailing_digit;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(cluster, dst, cmd_id, &bufv, 1U, callback, arg);
}

/* ZCL_PWR_PROF_CLI_PRICE_RSP */
enum ZclStatusCodeT
ZbZclPowerProfClientPriceRsp(struct ZbZclClusterT *cluster,
    struct ZbZclAddrInfoT *dst, struct ZbZclPowerProfCliPriceRsp *rsp,
    void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    return power_profile_client_price_rsp(cluster, dst, rsp, ZCL_PWR_PROF_CLI_PRICE_RSP, callback, arg);
}

/* ZCL_PWR_PROF_CLI_SCHED_PRICE_RSP */
enum ZclStatusCodeT
ZbZclPowerProfClientSchedPriceRsp(struct ZbZclClusterT *cluster,
    struct ZbZclAddrInfoT *dst, struct ZbZclPowerProfCliSchedPriceRsp *rsp,
    void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[7];
    unsigned int len = 0;
    struct ZbApsBufT bufv;

    /* Form the payload */
    putle16(&payload[len], rsp->currency);
    len += 2;
    putle32(&payload[len], rsp->price);
    len += 4;
    payload[len++] = rsp->trailing_digit;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(cluster, dst, ZCL_PWR_PROF_CLI_SCHED_PRICE_RSP, &bufv, 1U, callback, arg);
}

/* ZCL_PWR_PROF_CLI_PHASES_NOTIFY */
enum ZclStatusCodeT
ZbZclPowerProfClientPhasesNotify(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPowerProfCliPhasesNotify *notify,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[2 + (ZCL_PWR_PROF_MAX_ENERGY_PHASES * 3)];
    uint16_t len = 0;
    unsigned int i;
    struct ZbZclClusterCommandReqT cmd_req;

    /* Check input parameters */
    if (notify->num_phases > ZCL_PWR_PROF_MAX_ENERGY_PHASES) {
        return ZCL_STATUS_FAILURE;
    }

    /* Command payload */
    payload[len++] = notify->profile_id;
    payload[len++] = notify->num_phases;
    for (i = 0; i < notify->num_phases; i++) {
        payload[len++] = notify->sched_list[i].energy_phase_id;
        putle16(&payload[len], notify->sched_list[i].sched_time);
        len += 2;
    }

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = (uint8_t)ZCL_PWR_PROF_CLI_PHASES_NOTIFY;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd_req.payload = payload;
    cmd_req.length = len;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

/* ZCL_PWR_PROF_CLI_PHASES_RSP */
enum ZclStatusCodeT
ZbZclPowerProfClientPhasesResponse(struct ZbZclClusterT *cluster, struct ZbZclAddrInfoT *dst,
    struct ZbZclPowerProfCliPhasesNotify *notify,
    void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[2 + (ZCL_PWR_PROF_MAX_ENERGY_PHASES * 3)];
    uint16_t len = 0;
    struct ZbApsBufT bufv;
    unsigned int i;

    /* Check input parameters */
    if (notify->num_phases > ZCL_PWR_PROF_MAX_ENERGY_PHASES) {
        return ZCL_STATUS_FAILURE;
    }

    /* Command payload */
    payload[len++] = notify->profile_id;
    payload[len++] = notify->num_phases;
    for (i = 0; i < notify->num_phases; i++) {
        payload[len++] = notify->sched_list[i].energy_phase_id;
        putle16(&payload[len], notify->sched_list[i].sched_time);
        len += 2;
    }
    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(cluster, dst, ZCL_PWR_PROF_CLI_PHASES_RSP, &bufv, 1U, callback, arg);
}

/* ZCL_PWR_PROF_CLI_SCHED_CONS_REQ */
enum ZclStatusCodeT
ZbZclPowerProfClientSchedConsReq(struct ZbZclClusterT *cluster,
    const struct ZbApsAddrT *dst, struct ZbZclPowerProfCliProfileReq *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    return power_profile_client_profile_req(cluster, dst, req, ZCL_PWR_PROF_CLI_SCHED_CONS_REQ,
        callback, arg);
}

/* ZCL_PWR_PROF_CLI_PHASES_SCHED_STATE_REQ */
enum ZclStatusCodeT
ZbZclPowerProfClientPhasesSchedStateReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPowerProfCliProfileReq *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    return power_profile_client_profile_req(cluster, dst, req, ZCL_PWR_PROF_CLI_PHASES_SCHED_STATE_REQ,
        callback, arg);
}

/* ZCL_PWR_PROF_CLI_PRICE_EXT_RSP */
enum ZclStatusCodeT
ZbZclPowerProfClientPriceExtRsp(struct ZbZclClusterT *cluster,
    struct ZbZclAddrInfoT *dst, struct ZbZclPowerProfCliPriceRsp *rsp,
    void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    return power_profile_client_price_rsp(cluster, dst, rsp, ZCL_PWR_PROF_CLI_PRICE_EXT_RSP, callback, arg);
}
