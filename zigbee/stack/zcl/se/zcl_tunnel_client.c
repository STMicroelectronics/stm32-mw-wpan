/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/se/zcl.tunnel.h"
#include "local_zcl_tunnel.h"
#include "../zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */

/*lint -e9087 "ZbZclTunnelClient* <- ZbZclClusterT* [MISRA Rule 11.3 (REQUIRED)]" */

#define ZCL_TUNNEL_CLIENT_RSP_WAIT_TIMEOUT          3000U /* APS ACK timeout is 1.5 seconds */

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
    struct {
        struct ZbTimerT *timer;
        bool isActive;
        void (*callback)(struct ZbZclClusterT *clusterPtr, struct ZbZclTunnelStateT *s, enum ZbZclTunnelStatusT status, void *arg);
        void *cbarg;
        enum ZbZclTunnelStatusT status;
    } connect;
    struct ZbZclTunnelProtoT proto;
    struct ZbZclTunnelStateT state;
    bool valid_state;
};

static enum ZclStatusCodeT zcl_tuncli_handle_command(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *hdr, struct ZbApsdeDataIndT *dataIndPtr);
static void zcl_tuncli_cleanup(struct ZbZclClusterT *clusterPtr);
static bool zcl_tuncli_is_valid_id(struct ZbZclClusterT *clusterPtr, uint16_t tunnel_id);
static void zcl_tuncli_connect_timeout(struct ZigBeeT *zb, void *arg);
static void zcl_tuncli_connect_response_delay(struct ZigBeeT *zb, void *arg);

struct ZbZclClusterT *
ZbZclTunnelClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_TUNNELING, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.command = zcl_tuncli_handle_command;
    clusterPtr->cluster.cleanup = zcl_tuncli_cleanup;

    clusterPtr->connect.timer = ZbTimerAlloc(zb, NULL, NULL);
    if (clusterPtr->connect.timer == NULL) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Assume this is for SE */
    ZbZclClusterSetProfileId(&clusterPtr->cluster, ZCL_PROFILE_SMART_ENERGY);

    if (!ZbZclClusterSetMinSecurity(&clusterPtr->cluster, ZB_APS_STATUS_SECURED_LINK_KEY)) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    clusterPtr->proto.protocol = ZCL_TUNNEL_PROTO_RESERVED;

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

enum ZclStatusCodeT
ZbZclTunnelClientAddProto(struct ZbZclClusterT *clusterPtr, enum ZbZclTunnelProtocolT protocol,
    uint16_t mfr, uint16_t mtu, struct ZbZclTunnelProtoCbT *callbacks)
{
    struct cluster_priv_t *clientPtr = (struct cluster_priv_t *)clusterPtr;

    if (callbacks == NULL) {
        return ZCL_STATUS_FAILURE;
    }
    if (callbacks->input == NULL) {
        return ZCL_STATUS_FAILURE;
    }
    if (protocol == ZCL_TUNNEL_PROTO_RESERVED) {
        return ZCL_STATUS_FAILURE;
    }
    if (clientPtr->proto.protocol != ZCL_TUNNEL_PROTO_RESERVED) {
        /* We've already configured the protocol */
        /* EXEGIN - allow more than one tunnel protocol and connection? */
        return ZCL_STATUS_FAILURE;
    }
    if (!ZbZclClusterSetMaxAsduLength(clusterPtr, mtu + ZCL_TUNNEL_DATA_HDR_SIZE + ZCL_HEADER_MAX_SIZE)) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    clientPtr->state.data = ZbHeapAlloc(clusterPtr->zb, mtu);
    if (clientPtr->state.data == NULL) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    clientPtr->proto.protocol = protocol;
    clientPtr->proto.mfr = mfr;
    clientPtr->proto.mtu = mtu;
    memcpy(&clientPtr->proto.callbacks, callbacks, sizeof(struct ZbZclTunnelProtoCbT));
    LINK_LIST_INIT(&clientPtr->proto.link);
    return ZCL_STATUS_SUCCESS;
}

static void
zcl_tuncli_cleanup(struct ZbZclClusterT *clusterPtr)
{
    struct cluster_priv_t *clientPtr = (struct cluster_priv_t *)clusterPtr;

    if (clientPtr->connect.timer != NULL) {
        ZbTimerFree(clientPtr->connect.timer);
        clientPtr->connect.timer = NULL;
    }
    if (clientPtr->state.data != NULL) {
        ZbHeapFree(clusterPtr->zb, clientPtr->state.data);
    }
}

uint16_t
ZbZclTunnelStateGetId(struct ZbZclTunnelStateT *state)
{
    return state->id;
}

enum ZbZclTunnelProtocolT
ZbZclTunnelStateGetProtocol(struct ZbZclTunnelStateT *state)
{
    return state->proto->protocol;
}

uint8_t *
ZbZclTunnelStateGetDataPtr(struct ZbZclTunnelStateT *state)
{
    return state->data;
}

uint32_t
ZbZclTunnelStateGetDataLen(struct ZbZclTunnelStateT *state, bool clear_data)
{
    uint32_t length = state->length;

    if (clear_data) {
        state->length = 0;
    }
    return length;
}

enum ZclStatusCodeT
ZbZclTunnelClientConnectReq(struct ZbZclClusterT *clusterPtr, uint64_t dst_addr, uint8_t dst_ep,
    void (*callback)(struct ZbZclClusterT *clusterPtr, struct ZbZclTunnelStateT *state, enum ZbZclTunnelStatusT status, void *arg),
    void *arg)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)clusterPtr;
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    if (client->proto.protocol == ZCL_TUNNEL_PROTO_RESERVED) {
        /* We haven't configured a protocol yet */
        return ZCL_STATUS_FAILURE;
    }

    if (client->connect.isActive) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, connect still active?");
        return ZCL_STATUS_FAILURE;
    }

    if (zcl_tuncli_is_valid_id(clusterPtr, client->state.id)) {
        /* If already have connection with server, close it */
        (void)ZbZclTunnelClientCloseQuietReq(clusterPtr);
    }

    client->connect.isActive = true;

    /* Build Command Payload */
    payload[length++] = (uint8_t)client->proto.protocol;
    putle16(&payload[length], client->proto.mfr);
    length += 2U;
    payload[length++] = 0; /* flow */
    putle16(&payload[length], client->proto.mtu);
    length += 2U;

    client->state.cluster = clusterPtr;
    client->state.proto = &client->proto;
    client->state.id = 0; /* TBD by the server. */
    client->state.addr = dst_addr;
    client->state.endpoint = dst_ep;
    client->state.flow = 0; /* EXEGIN: Support flow control. */
    client->state.mtu = client->proto.mtu; /* TBD by the server. */
    client->state.length = 0;

    /* Set the state as valid, but the status as error until we receive the response. */
    client->connect.status = ZCL_TUNNEL_STATUS_BUSY;
    client->valid_state = true;

    /* Save the callback. */
    client->connect.callback = callback;
    client->connect.cbarg = arg;

    /* Start the timer in case we don't get a response. */
    ZbTimerChangeCallback(client->connect.timer, zcl_tuncli_connect_timeout, clusterPtr);
    ZbTimerReset(client->connect.timer, ZCL_TUNNEL_CLIENT_RSP_WAIT_TIMEOUT);

    (void)memset(&req, 0, sizeof(req));
    req.dst.mode = ZB_APSDE_ADDRMODE_EXT;
    req.dst.extAddr = dst_addr;
    req.dst.endpoint = dst_ep;
    req.cmdId = ZCL_TUNNEL_SVR_CMD_REQUEST;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    /* EXEGIN - add calback to catch error so we don't have to wait for timer */
    return ZbZclClusterCommandReq(clusterPtr, &req, NULL, NULL);
    /* Followed up by ZCL_TUNNEL_CLI_CMD_RESPONSE handler, or timeout */
}

enum ZclStatusCodeT
ZbZclTunnelClientCloseQuietReq(struct ZbZclClusterT *clusterPtr)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)clusterPtr;

    if (client->connect.isActive) {
        /* A Tunnel Connect is active */
        return ZCL_STATUS_FAILURE;
    }

    if (!zcl_tuncli_is_valid_id(clusterPtr, client->state.id)) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, not connected");
        return ZCL_STATUS_FAILURE;
    }

    client->connect.status = ZCL_TUNNEL_STATUS_BUSY;
    if (client->proto.callbacks.close != NULL) {
        client->proto.callbacks.close(&client->cluster, &client->state, client->proto.callbacks.priv);
    }
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclTunnelClientCloseReq(struct ZbZclClusterT *clusterPtr, void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)clusterPtr;
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;
    enum ZclStatusCodeT status;

    status = ZbZclTunnelClientCloseQuietReq(clusterPtr);
    if (status != ZCL_STATUS_SUCCESS) {
        return status;
    }

    /* Build Command Payload */
    putle16(&payload[length], client->state.id);
    length += 2U;

    (void)memset(&req, 0, sizeof(req));
    req.dst.mode = ZB_APSDE_ADDRMODE_EXT;
    req.dst.extAddr = client->state.addr;
    req.dst.endpoint = client->state.endpoint;
    req.cmdId = ZCL_TUNNEL_SVR_CMD_CLOSE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclTunnelClientSendReq(struct ZbZclClusterT *clusterPtr, const uint8_t *data, uint16_t len,
    void (*callback)(struct ZbZclCommandRspT *rspPtr, void *arg), void *arg)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)clusterPtr;

    if (!client->valid_state || (client->connect.status != ZCL_TUNNEL_STATUS_SUCCESS)) {
        return ZCL_STATUS_INVALID_VALUE;
    }
    return ZbZclTunnelServerSendto(clusterPtr, &client->state, data, len, ZCL_DIRECTION_TO_SERVER, callback, arg);
}

static bool
zcl_tuncli_is_valid_id(struct ZbZclClusterT *clusterPtr, uint16_t tunnel_id)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)clusterPtr;

    if (!client->valid_state) {
        return false;
    }
    if (client->connect.status != ZCL_TUNNEL_STATUS_SUCCESS) {
        return false;
    }
    return tunnel_id == client->state.id;
}

/* For testing only! */
bool
zcl_tuncli_test_change_id(struct ZbZclClusterT *clusterPtr, uint16_t tunnel_id)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)clusterPtr;

    if (!client->valid_state) {
        return false;
    }
    if (client->connect.status != ZCL_TUNNEL_STATUS_SUCCESS) {
        return false;
    }
    client->state.id = tunnel_id;
    return true;
}

static void
zcl_tuncli_nhle_error(struct ZbZclClusterT *clusterPtr, enum ZbZclTunnelXferStatusT status)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)clusterPtr;

    if (client->state.proto->callbacks.error == NULL) {
        return;
    }
    if (!client->state.proto->callbacks.error(clusterPtr, &client->state, client->state.proto->callbacks.priv, status)) {
        /* App is indicating that we should close the tunnel.
         * All errors are pretty much fatal. */
        (void)ZbZclTunnelClientCloseReq(clusterPtr, NULL, NULL);
    }
}

static enum ZclStatusCodeT
zcl_tuncli_handle_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *hdr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclTunnelProtoT *proto = &client->proto;
    uint16_t tunnel_id;
    unsigned int i = 0;
    enum ZclStatusCodeT rc = ZCL_STATUS_SUCCESS;

    /* Sanity. */
    if (hdr->frameCtrl.direction != ZCL_DIRECTION_TO_CLIENT) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (hdr->frameCtrl.manufacturer != 0U) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    switch (hdr->cmdId) {
        case ZCL_TUNNEL_CLI_CMD_RESPONSE:
        {
            enum ZbZclTunnelStatusT status;
            uint16_t mtu;

            /* Sanity-check the length. */
            if (dataIndPtr->asduLength < ZCL_TUNNEL_RESPONSE_SIZE) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            if (!client->valid_state) {
                rc = ZCL_STATUS_FAILURE;
                break;
            }

            /* Parse the request tunnel response command. */
            tunnel_id = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            /*lint -e{9034} "ZbZclTunnelStatusT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
            status = (enum ZbZclTunnelStatusT)dataIndPtr->asdu[i++];
            mtu = pletoh16(&dataIndPtr->asdu[i]);

            /* We can stop the timeout handler. */
            ZbTimerStop(client->connect.timer);

            /* Tunnel creation has been completed. */
            if (status != ZCL_TUNNEL_STATUS_SUCCESS) {
                if (proto->callbacks.close != NULL) {
                    proto->callbacks.close(clusterPtr, &client->state, proto->callbacks.priv);
                }
                (void)memset(&client->state, 0, sizeof(struct ZbZclTunnelStateT));
            }
            client->state.id = tunnel_id;
            client->state.mtu = (proto->mtu < mtu) ? proto->mtu : mtu;
            client->connect.status = status;

            if (client->connect.isActive) {
                /* Delay before notifying application requester to allow
                 * APS ACK to be processed. Otherwise, if the application
                 * is allowed to start sending data right away it can
                 * clobber the APS ACK and we get into a MAC ACK RF
                 * deadlock / stand-off. */
                ZbTimerChangeCallback(client->connect.timer, zcl_tuncli_connect_response_delay, client);
                ZbTimerReset(client->connect.timer, ZB_NWK_RSP_DELAY_DEFAULT);
            }
            break;
        }

        case ZCL_TUNNEL_CLI_CMD_DATA:
            /* Parse the tunnel ID. */
            if (dataIndPtr->asduLength < ZCL_TUNNEL_DATA_HDR_SIZE) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            tunnel_id = pletoh16(&dataIndPtr->asdu[i]);

            /* Ensure the tunnel state matches. */
            if (!zcl_tuncli_is_valid_id(clusterPtr, tunnel_id)) {
                zcl_tunnel_send_error(clusterPtr, dataIndPtr, tunnel_id, ZCL_TUNNEL_XFER_STATUS_NO_TUNNEL);
                /* Inform the application a server is trying to communicate with us on the wrong tunnel. */
                zcl_tuncli_nhle_error(clusterPtr, ZCL_TUNNEL_XFER_STATUS_NO_TUNNEL);
                rc = ZCL_STATUS_FAILURE;
                break;
            }
            /* Handle the tunneled data. */
            rc = zcl_tunnel_handle_data(clusterPtr, &client->state, hdr, dataIndPtr);
            break;

        case ZCL_TUNNEL_CLI_CMD_ERROR:
        {
            enum ZbZclTunnelXferStatusT status;

            if (dataIndPtr->asduLength < 3U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            tunnel_id = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            /*lint -e{9034} "ZbZclTunnelXferStatusT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
            status = (enum ZbZclTunnelXferStatusT)dataIndPtr->asdu[i];

            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Processing Tunnel Error (id = 0x%04x, status = 0x%02x)", tunnel_id, status);

            if (!zcl_tuncli_is_valid_id(clusterPtr, tunnel_id)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, no matching tunnel found");
                /* EXEGIN - send an error response? */
                rc = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
                break;
            }
            zcl_tuncli_nhle_error(clusterPtr, status);
            break;
        }

        case ZCL_TUNNEL_CLI_CMD_ACK:
        case ZCL_TUNNEL_CLI_CMD_READY:
            /* only required for flow control */
            rc = ZCL_STATUS_UNSUPP_COMMAND;
            break;

        case ZCL_TUNNEL_CLI_CMD_SUPPORTED_RSP:
            /* EXEGIN - this is optional and currently not supported */
            rc = ZCL_STATUS_UNSUPP_COMMAND;
            break;

        case ZCL_TUNNEL_CLI_CMD_CLOSE_NOTIFY:
            if (dataIndPtr->asduLength < 2U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            tunnel_id = pletoh16(&dataIndPtr->asdu[i]);

            if (!zcl_tuncli_is_valid_id(clusterPtr, tunnel_id)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, no matching tunnel found");
                /* EXEGIN - send an error response? */
                rc = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
                break;
            }

            client->connect.status = ZCL_TUNNEL_STATUS_BUSY;
            if (proto->callbacks.close != NULL) {
                proto->callbacks.close(&client->cluster, &client->state, proto->callbacks.priv);
            }
            break;

        default:
            rc = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return rc;
}

static void
zcl_tuncli_connect_timeout(struct ZigBeeT *zb, void *arg)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)arg;
    struct ZbZclTunnelProtoT *proto = &client->proto;

    /* If we got here, then the connection attempt has failed. */
    client->connect.status = ZCL_TUNNEL_STATUS_BUSY;
    if (proto->callbacks.close != NULL) {
        proto->callbacks.close(&client->cluster, &client->state, proto->callbacks.priv);
    }
    if (client->connect.callback != NULL) {
        client->connect.callback(&client->cluster, &client->state, client->connect.status, client->connect.cbarg);
    }
    client->valid_state = false;
    client->connect.isActive = false;
}

static void
zcl_tuncli_connect_response_delay(struct ZigBeeT *zb, void *arg)
{
    struct cluster_priv_t *client = arg;

    if (client->connect.callback != NULL) {
        client->connect.callback(&client->cluster, &client->state, client->connect.status, client->connect.cbarg);
    }
    client->connect.isActive = false;
}
