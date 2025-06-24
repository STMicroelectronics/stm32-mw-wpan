/* Copyright [2019 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.poll.control.h"
#include "zcl/zcl.payload.h"
#include "../zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */

struct server_list_t {
    struct LinkListT link;
    struct ZbApsAddrT dst;
    bool start_fast_poll;
    uint16_t fast_poll_timeout;
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct ZbZclPollControlClientCallbackT callbacks;
    struct LinkListT server_list; /* struct server_list_t */
};

struct callback_info_t {
    struct cluster_priv_t *client;
    struct server_list_t *entry;
};

static enum ZclStatusCodeT zcl_poll_client_command_handler(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);
static void zcl_poll_client_cleanup(struct ZbZclClusterT *cluster);

static enum ZclStatusCodeT zcl_poll_handle_checkin_req(struct ZbZclClusterT *clusterPtr,
    struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
zcl_poll_client_alloc(struct ZigBeeT *zb, uint8_t endpoint,
    struct ZbZclPollControlClientCallbackT *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t),
            ZCL_CLUSTER_POLL_CONTROL, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.command = zcl_poll_client_command_handler;
    clusterPtr->cluster.cleanup = zcl_poll_client_cleanup;

    LINK_LIST_INIT(&clusterPtr->server_list);

    /* Configure callbacks */
    if (callbacks != NULL) {
        (void)memcpy(&clusterPtr->callbacks, callbacks, sizeof(struct ZbZclPollControlClientCallbackT));
    }
    else {
        (void)memset(&clusterPtr->callbacks, 0, sizeof(struct ZbZclPollControlClientCallbackT));
    }
    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static void
zcl_poll_client_cleanup(struct ZbZclClusterT *cluster)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;
    struct LinkListT *p;
    struct server_list_t *entry;

    /* Free any possible outstanding check-in responses */
    while (true) {
        p = LINK_LIST_HEAD(&client->server_list);
        if (p == NULL) {
            break;
        }
        entry = LINK_LIST_ITEM(p, struct server_list_t, link);
        LINK_LIST_UNLINK(&entry->link);
        ZbHeapFree(cluster->zb, entry);
    }
}

static enum ZclStatusCodeT
zcl_poll_client_command_handler(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr,
    struct ZbApsdeDataIndT *dataIndPtr)
{
    enum ZclStatusCodeT rc;

    switch (zclHdrPtr->cmdId) {
        case ZCL_POLL_CTRL_SVR_CHECK_IN:
            rc = zcl_poll_handle_checkin_req(clusterPtr, dataIndPtr);
            break;

        default:
            rc = ZCL_STATUS_UNSUPP_COMMAND;
    }
    return rc;
}

static void
zcl_poll_checkin_rsp_cb(struct ZbZclCommandRspT *rsp, void *arg)
{
    struct callback_info_t *info = arg;
    struct ZigBeeT *zb = info->client->cluster.zb;
    struct zcl_poll_checkin_rsp_t rsp_info;
    struct ZbZclAddrInfoT srcInfo;

    (void)memset(&rsp_info, 0, sizeof(struct zcl_poll_checkin_rsp_t));
    rsp_info.status = rsp->status;
    if (info->entry != NULL) {
        rsp_info.start_fast_poll = info->entry->start_fast_poll;
        rsp_info.fast_poll_timeout = info->entry->fast_poll_timeout;
    }

    (void)memset(&srcInfo, 0, sizeof(struct ZbZclAddrInfoT));
    srcInfo.addr = rsp->src;

    if (rsp->status == ZCL_STATUS_SUCCESS) {
        /* If success, then free this info from the server_list */
        if (info->entry != NULL) {
            LINK_LIST_UNLINK(&info->entry->link);
            ZbHeapFree(zb, info->entry);
        }
    }

    /* Call the application callback if set */
    if (info->client->callbacks.checkin_rsp_callback != NULL) {
        info->client->callbacks.checkin_rsp_callback(&info->client->cluster,
            &rsp_info, &srcInfo, info->client->cluster.app_cb_arg);
    }

    ZbHeapFree(zb, info);
}

static struct server_list_t *
zcl_poll_find_server(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;
    struct LinkListT *p;
    struct server_list_t *entry;

    for (p = LINK_LIST_HEAD(&client->server_list); p; p = LINK_LIST_NEXT(p, &client->server_list)) {
        entry = LINK_LIST_ITEM(p, struct server_list_t, link);

        if (entry->dst.mode != dst->mode) {
            if ((entry->dst.mode == ZB_APSDE_ADDRMODE_EXT) && (dst->mode == ZB_APSDE_ADDRMODE_SHORT)) {
                uint16_t nwkAddr;

                nwkAddr = ZbNwkAddrLookupNwk(cluster->zb, entry->dst.extAddr);
                if ((nwkAddr != ZB_NWK_ADDR_UNDEFINED) && (nwkAddr == dst->nwkAddr)) {
                    return entry;
                }
            }
            continue;
        }
        if (entry->dst.mode == ZB_APSDE_ADDRMODE_EXT) {
            if (entry->dst.extAddr == dst->extAddr) {
                return entry;
            }
        }
        if (entry->dst.mode == ZB_APSDE_ADDRMODE_SHORT) {
            if (entry->dst.nwkAddr == dst->nwkAddr) {
                return entry;
            }
        }
    }
    return NULL;
}

static enum ZclStatusCodeT
zcl_poll_handle_checkin_req(struct ZbZclClusterT *cluster, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;
    struct callback_info_t *info;
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[3U];
    enum ZclStatusCodeT status;

    info = ZbHeapAlloc(cluster->zb, sizeof(struct callback_info_t));
    if (info == NULL) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
    memset(info, 0, sizeof(struct callback_info_t));
    info->client = client;
    /* Find a response, if it exists */
    info->entry = zcl_poll_find_server(cluster, &dataIndPtr->src);
    /* Form the payload */
    memset(payload, 0, sizeof(payload));
    if (info->entry != NULL) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Sending check-in response (fast = %d, timeout = %d)",
            info->entry->start_fast_poll, info->entry->fast_poll_timeout);
        payload[0] = info->entry->start_fast_poll;
        putle16(&payload[1], info->entry->fast_poll_timeout);
    }
    else {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Sending empty check-in response (fast = 0, timeout = 0)");
    }

    /* Send out Check in response as a request, which will generate a default response.*/
    (void)memset(&req, 0, sizeof(req));
    req.dst = dataIndPtr->src;
    req.cmdId = ZCL_POLL_CTRL_CLI_CHECK_IN_RSP;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = sizeof(payload);
    status = ZbZclClusterCommandReq(cluster, &req, zcl_poll_checkin_rsp_cb, info);
    if (status != ZCL_STATUS_SUCCESS) {
        ZbHeapFree(cluster->zb, info);
    }
    return status;
}

enum ZclStatusCodeT
zcl_poll_client_set_checkin_rsp(struct ZbZclClusterT *cluster, struct ZbZclPollControlClientCheckinInfo *info)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;
    struct server_list_t *entry;

    entry = zcl_poll_find_server(cluster, &info->dst);
    if (entry != NULL) {
        entry->start_fast_poll = info->start_fast_poll;
        entry->fast_poll_timeout = info->fast_poll_timeout;
    }
    else {
        /* Create a new entry */
        entry = ZbHeapAlloc(cluster->zb, sizeof(struct server_list_t));
        if (entry == NULL) {
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }
        memset(entry, 0, sizeof(struct server_list_t));
        LINK_LIST_INIT(&entry->link);
        entry->dst = info->dst;
        entry->start_fast_poll = info->start_fast_poll;
        entry->fast_poll_timeout = info->fast_poll_timeout;
        LINK_LIST_INSERT_TAIL(&client->server_list, &entry->link);
    }
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
zcl_poll_client_stop_fastpoll_req(struct ZbZclClusterT *cluster,
    struct ZbZclPollControlClientStopReq *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd;

    (void)memset(&cmd, 0, sizeof(cmd));
    cmd.dst = req->dst;
    cmd.cmdId = ZCL_POLL_CTRL_CLI_FAST_POLL_STOP;
    cmd.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd.payload = NULL;
    cmd.length = 0;
    return ZbZclClusterCommandReq(cluster, &cmd, callback, arg);
}

enum ZclStatusCodeT
zcl_poll_client_set_long_intvl_req(struct ZbZclClusterT *cluster,
    struct ZbZclPollControlClientSetLongReq *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd;
    unsigned int index = 0;
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];

    if (zb_zcl_append_uint32(payload, sizeof(payload), &index, req->interval) < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    (void)memset(&cmd, 0, sizeof(cmd));
    cmd.dst = req->dst;
    cmd.cmdId = ZCL_POLL_CTRL_CLI_SET_LONG_POLL_INTERVAL;
    cmd.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd.payload = payload;
    cmd.length = index;
    return ZbZclClusterCommandReq(cluster, &cmd, callback, arg);
}

enum ZclStatusCodeT
zcl_poll_client_set_short_intvl_req(struct ZbZclClusterT *cluster,
    struct ZbZclPollControlClientSetShortReq *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd;
    unsigned int index = 0;
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];

    if (zb_zcl_append_uint16(payload, sizeof(payload), &index, req->interval) < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    (void)memset(&cmd, 0, sizeof(cmd));
    cmd.dst = req->dst;
    cmd.cmdId = ZCL_POLL_CTRL_CLI_SET_SHOR_POLL_INTERVAL;
    cmd.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd.payload = payload;
    cmd.length = index;
    return ZbZclClusterCommandReq(cluster, &cmd, callback, arg);
}
