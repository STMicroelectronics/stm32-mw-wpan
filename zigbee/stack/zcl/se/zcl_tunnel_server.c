/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/se/zcl.tunnel.h"
#include "local_zcl_tunnel.h"
#include "../zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */

/*lint -save -e9087 "cluster_priv_t* <- ZbZclClusterT* [MISRA Rule 11.3 (REQUIRED)]" */

/* Same as ZCL_INVALID_UNSIGNED_16BIT, but 0xffff seems to be a valid value for this attribute. */
#define ZCL_TUNNEL_SVR_TIMEOUT_DEFAULT      0xffff

/* Attributes */
#define  ZCL_TUNNEL_SVR_PERSIST_LEN         16U
#define  ZCL_TUNNEL_SVR_PERSIST_NUM_MAX     32U
#define  ZCL_TUNNEL_SVR_PERSIST_BUF_MAX     (1U + (ZCL_TUNNEL_SVR_PERSIST_NUM_MAX * ZCL_TUNNEL_SVR_PERSIST_LEN))

enum {
    ZCL_TUNNEL_ATTR_PERSIST = 0x7fff
};

static enum ZclStatusCodeT zcl_attr_read_cb(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, uint8_t *attr_ptr,
    unsigned int maxlen, void *app_cb_arg);

static enum ZclStatusCodeT zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr,
    const struct ZbApsAddrT *src, uint16_t attributeId, const uint8_t *inputData,
    unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg);

static enum ZclStatusCodeT
zcl_attr_cb(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrCbInfoT *cb)
{
    if (cb->type == ZCL_ATTR_CB_TYPE_READ) {
        return zcl_attr_read_cb(clusterPtr, cb->info->attributeId, cb->zcl_data, cb->zcl_len, cb->app_cb_arg);
    }
    else if (cb->type == ZCL_ATTR_CB_TYPE_WRITE) {
        return zcl_attr_write_cb(clusterPtr, cb->src, cb->info->attributeId, cb->zcl_data, cb->zcl_len,
            cb->attr_data, cb->write_mode, cb->app_cb_arg);
    }
    else {
        return ZCL_STATUS_FAILURE;
    }
}

static const struct ZbZclAttrT zcl_tunnel_server_attr_list[] = {
    {ZCL_TUNNEL_ATTR_TIMEOUT, ZCL_DATATYPE_UNSIGNED_16BIT,
     ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}},

    {ZCL_TUNNEL_ATTR_PERSIST, ZCL_DATATYPE_STRING_LONG_OCTET,
     ZCL_ATTR_FLAG_INTERNAL | ZCL_ATTR_FLAG_PERSISTABLE | ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, ZCL_TUNNEL_SVR_PERSIST_BUF_MAX,
     zcl_attr_cb, {0, 0}, {0, 0}},
};

/* Tunnel server information struct. */
struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
    /* Message Information */
    struct LinkListT protolist;
    struct LinkListT tunlist;
    uint16_t nextid;
    uint8_t num_tunnels; /* max is ZCL_TUNNEL_SVR_PERSIST_NUM_MAX */
};

static void zcl_tunnel_server_cleanup(struct ZbZclClusterT *clusterPtr);
static enum ZclStatusCodeT zcl_tunnel_server_handle_command(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *hdr, struct ZbApsdeDataIndT *dataIndPtr);
static void zcl_tunnel_server_close(struct ZigBeeT *zb, struct ZbZclTunnelStateT *state);
static void zcl_tunnel_server_timeout(struct ZigBeeT *zb, void *arg);

static struct ZbZclTunnelProtoT * zcl_tunnel_server_find_proto(struct cluster_priv_t *tun,
    enum ZbZclTunnelProtocolT id, uint16_t mfr);

static enum ZbZclTunnelStatusT zcl_tunnel_server_add_tunnel(struct ZbZclClusterT *clusterPtr, struct ZbZclTunnelProtoT *proto,
    uint64_t rmt_addr, uint8_t rmt_endpoint, uint16_t rmt_mtu, uint16_t tunnel_id,
    struct ZbZclTunnelStateT **ret_state);

static struct ZbZclTunnelStateT * zcl_tunnel_server_find_by_source(struct ZbZclClusterT *clusterPtr,
    uint64_t rmt_addr, uint8_t rmt_endpoint, enum ZbZclTunnelProtocolT protocol, uint16_t mfr);
static void zcl_tunnel_server_close_all_by_source(struct ZbZclClusterT *clusterPtr, uint64_t rmt_addr);

static void zcl_tunnel_server_reset_timeout(struct ZbZclClusterT *clusterPtr, struct ZbZclTunnelStateT *state);

static void zcl_tunnel_server_response(struct ZigBeeT *zb, uint16_t id, enum ZbZclTunnelStatusT status,
    uint16_t mtu, uint8_t zcl_seqnum, struct ZbApsdeDataReqT *dataReq);

static struct ZbZclTunnelProtoT *
zcl_tunnel_server_find_proto(struct cluster_priv_t *tun, enum ZbZclTunnelProtocolT id, uint16_t mfr)
{
    struct LinkListT *p;
    struct ZbZclTunnelProtoT *proto;

    LINK_LIST_FOREACH(p, &tun->protolist) {
        proto = LINK_LIST_ITEM(p, struct ZbZclTunnelProtoT, link);
        if (proto->protocol != id) {
            continue;
        }
        if (proto->mfr != mfr) {
            continue;
        }
        return proto;
    } /* LINK_LIST_FOREACH */
    return NULL;
}

static void
zcl_tunnel_server_response(struct ZigBeeT *zb, uint16_t id, enum ZbZclTunnelStatusT status, uint16_t mtu,
    uint8_t zcl_seqnum, struct ZbApsdeDataReqT *dataReq)
{
    struct ZbZclHeaderT hdr;
    int hdr_len;
    struct ZbApsBufT bufv[2];
    uint8_t hbuf[ZCL_HEADER_MAX_SIZE];
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;

    /* ZCL Header */
    (void)memset(&hdr, 0, sizeof(struct ZbZclHeaderT));
    hdr.frameCtrl.frameType = ZCL_FRAMETYPE_CLUSTER;
    hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    hdr.frameCtrl.direction = ZCL_DIRECTION_TO_CLIENT;
    hdr.frameCtrl.manufacturer = 0U;
    hdr.cmdId = ZCL_TUNNEL_CLI_CMD_RESPONSE;
    hdr.seqNum = zcl_seqnum;

    putle16(&payload[length], id);
    length += 2U;
    payload[length++] = (uint8_t)status;
    putle16(&payload[length], mtu);
    length += 2U;

    hdr_len = ZbZclAppendHeader(&hdr, hbuf, sizeof(hbuf));
    if (hdr_len <= 0) {
        return;
    }

    /* Build the command. */
    bufv[0].data = hbuf;
    bufv[0].len = (unsigned int)hdr_len;
    bufv[1].data = payload;
    bufv[1].len = length;

    dataReq->asdu = bufv;
    dataReq->asduLength = (uint16_t)(sizeof(bufv) / sizeof(bufv[0]));
    dataReq->txOptions |= ZB_APSDE_DATAREQ_TXOPTIONS_VECTOR;
    if (ZbApsdeDataReqCallback(zb, dataReq, NULL, NULL) != ZB_APS_STATUS_SUCCESS) {
        /* Ignored */
    }
}

void
zcl_tunnel_send_error(struct ZbZclClusterT *clusterPtr, struct ZbApsdeDataIndT *dataIndPtr,
    uint16_t id, enum ZbZclTunnelXferStatusT status)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;

    putle16(&payload[length], id);
    length += 2U;
    payload[length++] = (uint8_t)status;

    (void)memset(&req, 0, sizeof(req));
    req.dst = dataIndPtr->src;
    /* If we're the server, send a client command error, and vice versa. */
    req.cmdId = (ZbZclClusterGetDirection(clusterPtr) == ZCL_DIRECTION_TO_SERVER) ? \
        (uint8_t)ZCL_TUNNEL_CLI_CMD_ERROR : (uint8_t)ZCL_TUNNEL_SVR_CMD_ERROR;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;

    ZbZclClusterCommandReqDelayed(clusterPtr, &req, 100U, NULL, NULL);
}

#if 0 /* currently not used - flow control only */
void
zcl_tunnel_send_ack(struct ZbZclClusterT *clusterPtr, struct ZbApsdeDataIndT *dataIndPtr,
    uint16_t id, uint16_t numbytes)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;

    putle16(&payload[length], id);
    length += 2U;
    putle16(&payload[length], numbytes);
    length += 2U;

    (void)memset(&req, 0, sizeof(req));
    req.dst = dataIndPtr->src;
    /* If we're the server, send a client command error, and vice versa. */
    req.cmdId = (ZbZclClusterGetDirection(clusterPtr) == ZCL_DIRECTION_TO_SERVER) ? \
        (uint8_t)ZCL_TUNNEL_CLI_CMD_ACK : (uint8_t)ZCL_TUNNEL_SVR_CMD_ACK;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;

    ZbZclClusterCommandReqDelayed(clusterPtr, &req, 100U, NULL, NULL);
}

#endif

enum ZclStatusCodeT
zcl_tunnel_handle_data(struct ZbZclClusterT *clusterPtr, struct ZbZclTunnelStateT *state,
    struct ZbZclHeaderT *zcl_hdr, struct ZbApsdeDataIndT *aps_ind)
{
    unsigned int datalen;
    const uint8_t *data;

    if (aps_ind->src.extAddr == 0U) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, extended source address is not known");
        zcl_tunnel_send_error(clusterPtr, aps_ind, state->id, ZCL_TUNNEL_XFER_STATUS_WRONG_DEVICE);
        return ZCL_STATUS_FAILURE;
    }

    /* Ensure the datagram originated from the tunnel's address. */
    if ((state->addr != aps_ind->src.extAddr) || (state->endpoint != aps_ind->src.endpoint)) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, invalid address");
        zcl_tunnel_send_error(clusterPtr, aps_ind, state->id, ZCL_TUNNEL_XFER_STATUS_WRONG_DEVICE);
        return ZCL_STATUS_FAILURE;
    }

    if (aps_ind->asduLength < ZCL_TUNNEL_DATA_HDR_SIZE) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, too short");
        zcl_tunnel_send_error(clusterPtr, aps_ind, state->id, ZCL_TUNNEL_XFER_STATUS_OVERFLOW);
        return ZCL_STATUS_FAILURE;
    }
    datalen = (unsigned int)aps_ind->asduLength - ZCL_TUNNEL_DATA_HDR_SIZE;
    data = &aps_ind->asdu[ZCL_TUNNEL_DATA_HDR_SIZE];

    /* Check for MTU violation. */
    if (datalen > state->mtu) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, MTU exceeded");
        zcl_tunnel_send_error(clusterPtr, aps_ind, state->id, ZCL_TUNNEL_XFER_STATUS_OVERFLOW);
        return ZCL_STATUS_FAILURE;
    }

    if (state->flow != 0U) {
#if 0 /* EXEGIN - flow not supported */
      /* Check for overflows. */
        if ((state->length + datalen) > state->mtu) {
            zcl_tunnel_send_error(clusterPtr, aps_ind, state->id, ZCL_TUNNEL_XFER_STATUS_OVERFLOW);
            return ZCL_STATUS_FAILURE;
        }
        /* Buffer the input data. */
        (void)memcpy(state->data + state->length, data, datalen);
        state->length += datalen;
        state->proto->input(clusterPtr, state, state->proto->priv);

        zcl_tunnel_send_ack(clusterPtr->zb, ZCL_DIRECTION_TO_SERVER, client->state.id,
            (client->state.mtu - client->state.length), hdr->seqNum, &dataReq);
        return ZCL_TUNNEL_STATUS_SUCCESS;
#else
        zcl_tunnel_send_error(clusterPtr, aps_ind, state->id, ZCL_TUNNEL_XFER_STATUS_OVERFLOW);
        return ZCL_STATUS_FAILURE;
#endif
    }
    else {
        /* Drop packets if the tunnel is overloaded. */
        if (state->length != 0U) {
            /* ZSDK-2142: Send Default Response (ZCL_STATUS_INSUFFICIENT_SPACE) */
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }
        state->length = datalen;
        (void)memcpy(state->data, data, datalen);

        state->proto->callbacks.input(clusterPtr, state, state->proto->callbacks.priv);

        /* ZSDK-2142: Send Default Response (ZCL_STATUS_SUCCESS) */
        return ZCL_STATUS_SUCCESS;
    }
}

struct ZbZclClusterT *
ZbZclTunnelServerAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    /* Allocate the tunnel cluster struct. */
    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_TUNNELING, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.command = zcl_tunnel_server_handle_command;
    clusterPtr->cluster.cleanup = zcl_tunnel_server_cleanup;
    LINK_LIST_INIT(&clusterPtr->protolist);
    LINK_LIST_INIT(&clusterPtr->tunlist);

    /* Assume this is for SE */
    ZbZclClusterSetProfileId(&clusterPtr->cluster, ZCL_PROFILE_SMART_ENERGY);

    if (!ZbZclClusterSetMinSecurity(&clusterPtr->cluster, ZB_APS_STATUS_SECURED_LINK_KEY)) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    if (!ZbZclClusterSetMaxAsduLength(&clusterPtr->cluster, ZCL_ASDU_LENGTH_SMART_ENERGY)) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_tunnel_server_attr_list,
            ZCL_ATTR_LIST_LEN(zcl_tunnel_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_TUNNEL_ATTR_TIMEOUT, ZCL_TUNNEL_SVR_TIMEOUT_DEFAULT);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static void
zcl_tunnel_server_cleanup(struct ZbZclClusterT *clusterPtr)
{
    struct cluster_priv_t *tun = (struct cluster_priv_t *)clusterPtr;
    struct LinkListT *p;

    /* Close all tunnels. */
    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Cluster cleanup, closing all tunnel connections");
    while (true) {
        struct ZbZclTunnelStateT *state;

        p = LINK_LIST_HEAD(&tun->tunlist);
        if (p == NULL) {
            break;
        }
        state = LINK_LIST_ITEM(p, struct ZbZclTunnelStateT, link);
        zcl_tunnel_server_close(clusterPtr->zb, state);
    }

    /* Remove all protocols. */
    while (true) {
        struct ZbZclTunnelProtoT *proto_ptr;

        p = LINK_LIST_HEAD(&tun->protolist);
        if (p == NULL) {
            break;
        }
        proto_ptr = LINK_LIST_ITEM(p, struct ZbZclTunnelProtoT, link);
        LINK_LIST_UNLINK(p);
        ZbHeapFree(clusterPtr->zb, proto_ptr);
    } /* while */
}

enum ZclStatusCodeT
ZbZclTunnelServerAddProto(struct ZbZclClusterT *clusterPtr, enum ZbZclTunnelProtocolT protocol,
    uint16_t mfr, uint16_t mtu, struct ZbZclTunnelProtoCbT *callbacks)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclTunnelProtoT *proto_ptr;

    if (callbacks == NULL) {
        return ZCL_STATUS_FAILURE;
    }
    if (callbacks->request == NULL) {
        return ZCL_STATUS_FAILURE;
    }
    if (callbacks->input == NULL) {
        return ZCL_STATUS_FAILURE;
    }

    /* EXEGIN: Check for duplicates. */

    proto_ptr = ZbHeapAlloc(clusterPtr->zb, sizeof(struct ZbZclTunnelProtoT));
    if (proto_ptr == NULL) {
        return ZCL_STATUS_FAILURE;
    }
    (void)memset(proto_ptr, 0, sizeof(struct ZbZclTunnelProtoT));
    proto_ptr->protocol = protocol;
    proto_ptr->mfr = mfr;
    proto_ptr->mtu = mtu;
    memcpy(&proto_ptr->callbacks, callbacks, sizeof(struct ZbZclTunnelProtoCbT));
    LINK_LIST_INIT(&proto_ptr->link);
    LINK_LIST_INSERT_TAIL(&serverPtr->protolist, &proto_ptr->link);
    return ZCL_STATUS_SUCCESS;
}

static enum ZbZclTunnelStatusT
zcl_tunnel_server_add_tunnel(struct ZbZclClusterT *clusterPtr, struct ZbZclTunnelProtoT *proto,
    uint64_t rmt_addr, uint8_t rmt_endpoint, uint16_t rmt_mtu, uint16_t tunnel_id,
    struct ZbZclTunnelStateT **ret_state)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclTunnelStateT *state;
    enum ZbZclTunnelStatusT status;

    if (ret_state != NULL) {
        *ret_state = NULL;
    }

    if (serverPtr->num_tunnels >= ZCL_TUNNEL_SVR_PERSIST_NUM_MAX) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, can't add tunnel, at maximum (%d)", (ZCL_TUNNEL_SVR_PERSIST_NUM_MAX));
        return ZCL_TUNNEL_STATUS_NO_RESOURCES;
    }

    state = zcl_tunnel_server_find_by_source(clusterPtr, rmt_addr, rmt_endpoint, proto->protocol, proto->mfr);
    if (state != NULL) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, tunnel already exists with this client");
        return ZCL_TUNNEL_STATUS_NO_RESOURCES;
    }

    state = ZbZclTunnelServerStateFindById(clusterPtr, tunnel_id);
    if (state != NULL) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, tunnel ID already exists");
        return ZCL_TUNNEL_STATUS_NO_RESOURCES;
    }

    /* Allocate the tunnel state. */
    state = ZbHeapAlloc(clusterPtr->zb, sizeof(struct ZbZclTunnelStateT));
    if (state == NULL) {
        return ZCL_TUNNEL_STATUS_NO_RESOURCES;
    }
    (void)memset(state, 0, sizeof(struct ZbZclTunnelStateT));
    state->data = ZbHeapAlloc(clusterPtr->zb, proto->mtu);
    if (state->data == NULL) {
        ZbHeapFree(clusterPtr->zb, state);
        return ZCL_TUNNEL_STATUS_NO_RESOURCES;
    }

    /* Initialize the tunnel. */
    LINK_LIST_INIT(&state->link);
    state->timer = ZbTimerAlloc(clusterPtr->zb, zcl_tunnel_server_timeout, state);
    if (state->timer == NULL) {
        ZbHeapFree(clusterPtr->zb, state);
        return ZCL_TUNNEL_STATUS_NO_RESOURCES;
    }
    state->cluster = clusterPtr;
    state->proto = proto;
    state->id = tunnel_id;
    state->endpoint = rmt_endpoint;
    state->addr = rmt_addr;
    state->flow = 0; /* Disable flow control for now. */
    state->mtu = (proto->mtu > rmt_mtu) ? rmt_mtu : proto->mtu;
    state->length = 0U;

    status = proto->callbacks.request(clusterPtr, state, proto->callbacks.priv);
    if (status != ZCL_TUNNEL_STATUS_SUCCESS) {
        /* Tunnel creation failed. */
        ZbHeapFree(clusterPtr->zb, state->data);
        ZbHeapFree(clusterPtr->zb, state);
        return status;
    }

    /* Insert the tunnel into the list. */
    LINK_LIST_INSERT_TAIL(&serverPtr->tunlist, &state->link);
    serverPtr->num_tunnels++;

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Added tunnel to list (id = 0x%04x)", state->id);

    if (ret_state != NULL) {
        *ret_state = state;
    }

    (void)ZbZclAttrPersist(clusterPtr, ZCL_TUNNEL_ATTR_PERSIST);
    return ZCL_TUNNEL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
zcl_attr_read_cb(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, uint8_t *attr_ptr,
    unsigned int maxlen, void *app_cb_arg)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclTunnelStateT *state;
    struct LinkListT *p;
    uint8_t num_tunnels = 0;
    uint16_t len = 3U;

    /* EXEGIN - mutex lock? */
    LINK_LIST_FOREACH(p, &serverPtr->tunlist)
    {
        state = LINK_LIST_ITEM(p, struct ZbZclTunnelStateT, link);

        /* Check for overflow */
        if (((unsigned int)len + ZCL_TUNNEL_SVR_PERSIST_LEN) > maxlen) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__,
                "Error, saving tunnel to persistence will exceed buffer length, skipping", __func__);
            break;
        }

        /* Tunnel Persistence Data Format:
         * protocol (1 octets)
         * mfr (2 octets)
         * rmt_addr (8 octets)
         * rmt_endpoint (1 octets)
         * rmt_mtu (2 octets)
         * tunnel_id (2 octets)
         */
        attr_ptr[len++] = (uint8_t)state->proto->protocol;
        putle16(&attr_ptr[len], state->proto->mfr);
        len += 2U;
        putle64(&attr_ptr[len], state->addr);
        len += 8U;
        attr_ptr[len++] = state->endpoint;
        putle16(&attr_ptr[len], state->mtu);
        len += 2U;
        putle16(&attr_ptr[len], state->id);
        len += 2U;

        num_tunnels++;
    }

    /* Number of Tunnels saved (1 octet) */
    attr_ptr[2] = num_tunnels;

    /* string-long-octet length */
    putle16(&attr_ptr[0], len - 2U);
    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attributeId,
    const uint8_t *inputData, unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    const uint8_t *attr_ptr = inputData;
    uint16_t strlong_len;
    unsigned int i = 0, j;
    uint8_t num_tunnels;
    enum ZclStatusCodeT status = ZCL_STATUS_SUCCESS;

    if ((mode & ZCL_ATTR_WRITE_FLAG_PERSIST) == 0U) {
        return ZCL_STATUS_READ_ONLY;
    }

    /* ZCL_DATATYPE_STRING_LONG_OCTET */
    strlong_len = pletoh16(&attr_ptr[i]);
    i += 2U;

    /* For inputData buffer underflow checking, add 2 octets for the
     * ZCL_DATATYPE_STRING_LONG_OCTET length field. */
    strlong_len += 2U;

    if (strlong_len > inputMaxLen) {
        /* Should never get here */
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    if ((i + 1U) > strlong_len) {
        /* Shouldn't get here, even for an empty tunnel table. */
        return ZCL_STATUS_SUCCESS;
    }

    /* Number of Tunnels saved (1 octet) */
    num_tunnels = attr_ptr[i++];

#if 0 /* required? */
      /* Remove all tunnels (there shouldn't be any yet) */
    zcl_scenes_server_remove_all_scenes(serverPtr);
#endif

    for (j = 0; j < num_tunnels; j++) {
        uint8_t protocol;
        uint16_t mfr;
        uint64_t rmt_addr;
        uint8_t rmt_endpoint;
        uint16_t rmt_mtu;
        uint16_t tunnel_id;
        struct ZbZclTunnelProtoT *proto;
        struct ZbZclTunnelStateT *state;
        enum ZbZclTunnelStatusT tun_status;

        if ((i + ZCL_TUNNEL_SVR_PERSIST_LEN) > strlong_len) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        /* Tunnel Persistence Data Format:
         * protocol (1 octets)
         * mfr (2 octets)
         * rmt_addr (8 octets)
         * rmt_endpoint (1 octets)
         * rmt_mtu (2 octets)
         * tunnel_id (2 octets)
         */
        protocol = attr_ptr[i++];
        mfr = pletoh16(&attr_ptr[i]);
        i += 2U;
        rmt_addr = pletoh64(&attr_ptr[i]);
        i += 8U;
        rmt_endpoint = attr_ptr[i++];
        rmt_mtu = pletoh16(&attr_ptr[i]);
        i += 2U;
        tunnel_id = pletoh16(&attr_ptr[i]);
        i += 2U;

        /*lint -e{9034} "ZbZclTunnelProtocolT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
        proto = zcl_tunnel_server_find_proto(serverPtr, (enum ZbZclTunnelProtocolT)protocol, mfr);
        if (proto == NULL) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, not supported (proto = 0x%02x, mfr = 0x%04x, i = %d)",
                protocol, mfr, i);
            status = ZCL_STATUS_INVALID_VALUE;
            continue;
        }

        tun_status = zcl_tunnel_server_add_tunnel(clusterPtr, proto, rmt_addr, rmt_endpoint, rmt_mtu, tunnel_id, &state);
        if (tun_status != ZCL_TUNNEL_STATUS_SUCCESS) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, unable to add tunnel (no resources?)");
            status = ZCL_STATUS_INSUFFICIENT_SPACE;
            continue;
        }
        zcl_tunnel_server_reset_timeout(clusterPtr, state);
    }

    return status;
}

struct ZbZclTunnelStateT *
ZbZclTunnelServerStateFindById(struct ZbZclClusterT *clusterPtr, uint16_t tunnel_id)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclTunnelStateT *state;
    struct LinkListT *p;

    /* EXEGIN - mutex lock? */
    LINK_LIST_FOREACH(p, &serverPtr->tunlist)
    {
        state = LINK_LIST_ITEM(p, struct ZbZclTunnelStateT, link);
        if (state->id != tunnel_id) {
            continue;
        }
        return state;
    }
    return NULL;
}

static struct ZbZclTunnelStateT *
zcl_tunnel_server_find_by_source(struct ZbZclClusterT *clusterPtr, uint64_t rmt_addr, uint8_t rmt_endpoint,
    enum ZbZclTunnelProtocolT protocol, uint16_t mfr)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclTunnelStateT *state;
    struct LinkListT *p;

    if (rmt_addr == 0U) {
        return NULL;
    }

    /* EXEGIN - mutex lock? */
    LINK_LIST_FOREACH(p, &serverPtr->tunlist) {
        state = LINK_LIST_ITEM(p, struct ZbZclTunnelStateT, link);
        if (state->addr != rmt_addr) {
            continue;
        }
        if (state->endpoint != rmt_endpoint) {
            continue;
        }
        if (state->proto->protocol != protocol) {
            continue;
        }
        if (state->proto->mfr != mfr) {
            continue;
        }
        return state;
    }
    return NULL;
}

static void
zcl_tunnel_server_close_all_by_source(struct ZbZclClusterT *clusterPtr, uint64_t rmt_addr)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclTunnelStateT *state;
    struct LinkListT *p, *next;

    if (rmt_addr == 0U) {
        return;
    }

    /* EXEGIN - mutex lock? */
    for (p = LINK_LIST_HEAD(&serverPtr->tunlist); p != NULL; p = next) {
        next = LINK_LIST_NEXT(p, &serverPtr->tunlist);
        state = LINK_LIST_ITEM(p, struct ZbZclTunnelStateT, link);
        if (state->addr != rmt_addr) {
            continue;
        }
        zcl_tunnel_server_close(clusterPtr->zb, state);
    }
}

static void
zcl_tunnel_server_reset_timeout(struct ZbZclClusterT *clusterPtr, struct ZbZclTunnelStateT *state)
{
    unsigned int timeout;
    enum ZclStatusCodeT status;

    timeout = (unsigned int)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_TUNNEL_ATTR_TIMEOUT, NULL, &status);
    if ((status != ZCL_STATUS_SUCCESS) || (timeout == 0U)) {
        timeout = ZCL_TUNNEL_SVR_TIMEOUT_DEFAULT;
    }
    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "resetting timeout for tunnel id = 0x%04x (%d seconds)", state->id, timeout);
    ZbTimerReset(state->timer, timeout * 1000U);
}

static uint16_t
zcl_tunnel_server_get_next_id(struct ZbZclClusterT *clusterPtr)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    unsigned int i;

    for (i = 0; i < 0xffffU; i++) {
        if (ZbZclTunnelServerStateFindById(clusterPtr, serverPtr->nextid) == NULL) {
            break;
        }
        serverPtr->nextid++;
    }
    return serverPtr->nextid;
}

static enum ZclStatusCodeT
zcl_tunnel_server_handle_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *hdr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclTunnelProtoT *proto;
    struct ZbApsdeDataReqT dataReq;
    unsigned int i = 0;
    enum ZclStatusCodeT rc = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

    /* Sanity. */
    if (hdr->frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (hdr->frameCtrl.manufacturer != 0U) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

#if 0
    ZCL_LOG_PRINTF(c->zb, __func__, "From: " LOGFMTx64 ", Command: 0x%04x, Len: %d",
        LOGVALx64(ind->src.extAddr), hdr->cmdId, ind->asduLength);
#endif

    /* Form an APSDE-DATA.request for the response. */
    ZbZclClusterInitApsdeReq(clusterPtr, &dataReq, dataIndPtr);
    dataReq.dst = dataIndPtr->src;
    /* No APS ACK */
    dataReq.txOptions = (uint16_t)(ZB_APSDE_DATAREQ_TXOPTIONS_SECURITY | ZB_APSDE_DATAREQ_TXOPTIONS_FRAG);

    switch (hdr->cmdId) {
        case ZCL_TUNNEL_SVR_CMD_REQUEST:
        {
            struct ZbZclTunnelStateT *state;
            enum ZbZclTunnelProtocolT protocol;
            uint16_t mfr;
            uint8_t flow;
            uint16_t mtu;
            enum ZbZclTunnelStatusT status;

            /* Sanity-check the length. */
            if (dataIndPtr->asduLength < 6U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            /* Parse the request tunnel command. */
            /*lint -e{9034} "ZbZclTunnelProtocolT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
            protocol = (enum ZbZclTunnelProtocolT)dataIndPtr->asdu[i++];
            mfr = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            flow = dataIndPtr->asdu[i++];
            mtu = pletoh16(&dataIndPtr->asdu[i]);

            /* Check if we support the protocol. */
            proto = zcl_tunnel_server_find_proto(serverPtr, protocol, mfr);
            if (proto == NULL) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, protocol not supported");
                zcl_tunnel_server_response(clusterPtr->zb, 0xffff, ZCL_TUNNEL_STATUS_PROTO_UNSUPPORTED, 0, hdr->seqNum, &dataReq);
                break;
            }
            /* Check if we support flow control. */
            if (flow != 0U) {
                /* EXEGIN: Flow control support. */
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, flow not supported");
                zcl_tunnel_server_response(clusterPtr->zb, 0xffff, ZCL_TUNNEL_STATUS_FLOW_UNSUPPORTED, 0, hdr->seqNum, &dataReq);
                break;
            }

            /* Check if this tunnel already exists */
            state = zcl_tunnel_server_find_by_source(clusterPtr, dataIndPtr->src.extAddr,
                    (uint8_t)dataIndPtr->src.endpoint, protocol, mfr);
            if (state == NULL) {
                status = zcl_tunnel_server_add_tunnel(clusterPtr, proto, dataIndPtr->src.extAddr,
                        (uint8_t)dataIndPtr->src.endpoint, mtu, zcl_tunnel_server_get_next_id(clusterPtr), &state);
                if (status != ZCL_TUNNEL_STATUS_SUCCESS) {
                    zcl_tunnel_server_response(clusterPtr->zb, 0xffff, status, 0, hdr->seqNum, &dataReq);
                    break;
                }
                serverPtr->nextid++;
            }

            zcl_tunnel_server_response(clusterPtr->zb, state->id, ZCL_TUNNEL_STATUS_SUCCESS, state->mtu, hdr->seqNum, &dataReq);

            zcl_tunnel_server_reset_timeout(clusterPtr, state);
            break;
        }

        case ZCL_TUNNEL_SVR_CMD_CLOSE:
        {
            struct ZbZclTunnelStateT *state;
            uint16_t tunnel_id;

            if (dataIndPtr->asduLength < 2U) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, incoming CLOSE command is too short");
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            tunnel_id = pletoh16(&dataIndPtr->asdu[i]);

            state = ZbZclTunnelServerStateFindById(clusterPtr, tunnel_id);
            if (state == NULL) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, no tunnel found");
                rc = ZCL_STATUS_NOT_FOUND;
                break;
            }

            zcl_tunnel_server_close(clusterPtr->zb, state);
            rc = ZCL_STATUS_SUCCESS;
            break;
        }

        case ZCL_TUNNEL_SVR_CMD_DATA:
        {
            struct ZbZclTunnelStateT *state;
            uint16_t tunnel_id;

            /* Parse the tunnel ID. */
            if (dataIndPtr->asduLength < ZCL_TUNNEL_DATA_HDR_SIZE) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, incoming CLIENT_DATA is too short");
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            tunnel_id = pletoh16(&dataIndPtr->asdu[i]);

            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "client data (id = 0x%04x)", tunnel_id);

            /* Lookup the tunnel state by its ID. */
            state = ZbZclTunnelServerStateFindById(clusterPtr, tunnel_id);
            if (state == NULL) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, no tunnel found (src = " LOGFMTx64 ", id = %d)",
                    LOGVALx64(dataIndPtr->src.extAddr), tunnel_id);
                zcl_tunnel_send_error(clusterPtr, dataIndPtr, tunnel_id, ZCL_TUNNEL_XFER_STATUS_NO_TUNNEL);

                /* We're out of sync with this client. Close all other tunnels for this client.
                 * This is a GBCS requirement.
                 * EXEGIN - make this behaviour configurable? */
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Closing all tunnels for src = " LOGFMTx64,
                    LOGVALx64(dataIndPtr->src.extAddr));
                zcl_tunnel_server_close_all_by_source(clusterPtr, dataIndPtr->src.extAddr);
                rc = ZCL_STATUS_FAILURE;
                break;
            }

            zcl_tunnel_server_reset_timeout(clusterPtr, state);

            /* Handle the tunnel data. */
            rc = zcl_tunnel_handle_data(clusterPtr, state, hdr, dataIndPtr);
            break;
        }

        case ZCL_TUNNEL_SVR_CMD_ERROR:
        {
            struct ZbZclTunnelStateT *state;
            uint16_t tunnel_id;
            enum ZbZclTunnelXferStatusT tunnel_status;

            if (dataIndPtr->asduLength < 3U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            tunnel_id = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            /*lint -e{9034} "ZbZclTunnelXferStatusT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
            tunnel_status = (enum ZbZclTunnelXferStatusT)dataIndPtr->asdu[i];

            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Processing Tunnel Error (id = 0x%04x, status = 0x%02x)",
                tunnel_id, tunnel_status);

            state = ZbZclTunnelServerStateFindById(clusterPtr, tunnel_id);
            if (state == NULL) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, no matching tunnel found");
#if 0 /* EXEGIN - send an error response? */
                zcl_tunnel_send_error(clusterPtr, dataIndPtr, tunnel_id, ZCL_TUNNEL_XFER_STATUS_NO_TUNNEL);
#endif
                break;
            }
            if (state->proto->callbacks.error != NULL) {
                if (!state->proto->callbacks.error(clusterPtr, state, state->proto->callbacks.priv, tunnel_status)) {
                    /* EXEGIN - send ZCL_TUNNEL_CLI_CMD_CLOSE_NOTIFY? */
                    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Closing tunnel (%d) after processing ERROR command.", state->id);
                    zcl_tunnel_server_close(clusterPtr->zb, state);
                }
            }
            rc = ZCL_STATUS_SUCCESS;
            break;
        }

        case ZCL_TUNNEL_SVR_CMD_ACK:
        case ZCL_TUNNEL_SVR_CMD_READY:
            /* only required for flow control */
            rc = ZCL_STATUS_UNSUPP_COMMAND;
            break;

        case ZCL_TUNNEL_SVR_CMD_SUPPORTED_REQ:
            /* EXEGIN - this is optional and currently not supported */
            rc = ZCL_STATUS_UNSUPP_COMMAND;
            break;

        default:
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, unsupported command 0x%02x", hdr->cmdId);
            rc = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return rc;
}

static void
zcl_tunnel_server_close(struct ZigBeeT *zb, struct ZbZclTunnelStateT *state)
{
    struct ZbZclClusterT *clusterPtr = state->cluster;
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Closing tunnel (id = 0x%04x)", state->id);

    LINK_LIST_UNLINK(&state->link);
    serverPtr->num_tunnels--;
    if (state->timer != NULL) {
        ZbTimerFree(state->timer);
        state->timer = NULL;
    }
    if (state->proto->callbacks.close != NULL) {
        state->proto->callbacks.close(state->cluster, state, state->proto->callbacks.priv);
    }
    if (state->data != NULL) {
        ZbHeapFree(zb, state->data);
    }
    ZbHeapFree(zb, state);
    (void)ZbZclAttrPersist(clusterPtr, ZCL_TUNNEL_ATTR_PERSIST);
}

static void
zcl_tunnel_server_timeout(struct ZigBeeT *zb, void *arg)
{
    struct ZbZclTunnelStateT *state = (struct ZbZclTunnelStateT *)arg;

    /* The tunnel state has timed out, remove it and clean up. */
    ZCL_LOG_PRINTF(zb, __func__, "Tunnel has timed-out (id = 0x%04x)", state->id);
    zcl_tunnel_server_close(zb, state);
}

enum ZclStatusCodeT
ZbZclTunnelServerSendto(struct ZbZclClusterT *clusterPtr, struct ZbZclTunnelStateT *state, const uint8_t *data, unsigned int len,
    enum ZbZclDirectionT direction, void (*callback)(struct ZbZclCommandRspT *rspPtr, void *arg), void *arg)
{
    struct ZbZclCommandReqT req;
    uint8_t tunnel_hdr_buf[2];
    struct ZbApsBufT bufv[2];

    /* EXEGIN: Buffer the packet and stream it out via flow control? */

    /* Tunnel Client Data command payload.
     * Use a Vector Buffer so we don't have to allocate the payload twice. */
    /* Tunnel Header */
    putle16(tunnel_hdr_buf, state->id);
    bufv[0].data = tunnel_hdr_buf;
    bufv[0].len = sizeof(tunnel_hdr_buf);
    /* Tunnel Payload */
    bufv[1].data = data;
    bufv[1].len = len;

    ZbZclClusterInitCommandReq(clusterPtr, &req);
    req.dst.mode = ZB_APSDE_ADDRMODE_EXT;
    req.dst.extAddr = state->addr;
    req.dst.endpoint = state->endpoint;
    req.txOptions |= ZB_APSDE_DATAREQ_TXOPTIONS_VECTOR;
    /* ZCL Header */
    req.hdr.cmdId = (direction == ZCL_DIRECTION_TO_CLIENT) ? (uint8_t)ZCL_TUNNEL_CLI_CMD_DATA : (uint8_t)ZCL_TUNNEL_SVR_CMD_DATA;
    req.hdr.frameCtrl.frameType = ZCL_FRAMETYPE_CLUSTER;
    req.hdr.frameCtrl.manufacturer = 0;
    req.hdr.frameCtrl.direction = direction;
    req.hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.hdr.seqNum = ZbZclGetNextSeqnum();
    /* Payload */
    req.payload = bufv;
    req.length = (unsigned int)(sizeof(bufv) / sizeof(bufv[0]));

    if (clusterPtr->direction == ZCL_DIRECTION_TO_SERVER) {
        /* Reset the inactivity timer before sending. */
        zcl_tunnel_server_reset_timeout(clusterPtr, state);
    }

    ZbZclCommandReq(clusterPtr->zb, &req, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

void
ZbZclTunnelServerSendAllMatch(struct ZbZclClusterT *clusterPtr, uint64_t eui, void *data, unsigned int len)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    struct LinkListT *p;
    struct ZbZclTunnelStateT *state;

    LINK_LIST_FOREACH(p, &serverPtr->tunlist)
    {
        state = LINK_LIST_ITEM(p, struct ZbZclTunnelStateT, link);
        if (state->addr != eui) {
            continue;
        }
        /* Found a matching tunnel. */
        (void)ZbZclTunnelServerSendto(clusterPtr, state, data, len, ZCL_DIRECTION_TO_CLIENT, NULL, NULL);
    }
}

/*lint -restore */
