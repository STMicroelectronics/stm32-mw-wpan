/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/se/zcl.keepalive.h"
/* The KeepAlive Cluster is embedded within the stack */
#include "../local.zigbee.h"

/* Let the join process complete (incl. Device Annce and End Device Keep Alive) */
#define ZCL_KEEPALIVE_START_DELAY_MS                3000U

/* Minimum delay before restarting keep alive after a TCSO failure.
 * Don't want to continually hammer the network with rejoin attempts */
#define ZCL_KEEPALIVE_FAIL_RESTART_DELAY_MIN_MS    (5U * 60U * 1000U) /* 5 minutes (aribtrary) */

/* The spec states that after 3 failed keepalive read requests, we shall start TCSO. */
#define ZCL_KEEPALIVE_FAIL_MAX                      3U

#define ZCL_KEEPALIVE_TC_ENDPOINT_INVALID           0xffU

enum ZclKeepaliveStateT {
    KEEPALIVE_CLI_STATE_IDLE, /* Idle, inactive */
    KEEPALIVE_CLI_STATE_MATCH_WAIT, /* Waiting to perform ZDO Match Desc Request to TC */
    KEEPALIVE_CLI_STATE_MATCH_ACTIVE, /* ZDO Match Desc Request is active, waiting for response callback */
    KEEPALIVE_CLI_STATE_READ_WAIT, /* Waiting to perform ZCL Read Request to TC */
    KEEPALIVE_CLI_STATE_READ_ACTIVE, /* ZCL Read Request is active, waiting for response callback */
    KEEPALIVE_CLI_STATE_TCSO_ACTIVE, /* TCSO is active */
    KEEPALIVE_CLI_STATE_TCSO_FAILED
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    enum ZclKeepaliveStateT state;

    bool reset_state_machine;
    enum ZclKeepaliveStateT next_state;

    struct ZbTimerT *timer;
    uint8_t tc_endpoint;
    uint8_t failures;
    uint8_t read_interval_base;
    uint16_t read_interval_jitter;

    void (*tcso_callback)(enum ZbTcsoStatusT status, void *arg);
    void *tcso_arg;
};

static void zcl_ka_client_cleanup(struct ZbZclClusterT *clusterPtr);

static bool zcl_ka_client_change_state(struct cluster_priv_t *clientPtr, enum ZclKeepaliveStateT state, bool check_joined, int delay_ms);
static void zcl_ka_client_timer_callback(struct ZigBeeT *zb, void *arg);
static uint32_t zcl_ka_client_get_next_timeout(struct cluster_priv_t *clientPtr);
static bool zcl_ka_client_incr_failure(struct cluster_priv_t *clientPtr);
static void zcl_ka_client_start_match_req(struct cluster_priv_t *clientPtr);
static void zcl_ka_client_start_match_rsp(struct ZbZdoMatchDescRspT *matchRsp, void *arg);
static void zcl_ka_client_read_callback(const struct ZbZclReadRspT *readRsp, void *arg);
static void zcl_ka_client_read_req(struct cluster_priv_t *clientPtr);
static void zcl_ka_client_tcso_callback(enum ZbTcsoStatusT status, void *arg);

struct ZbZclClusterT *
ZbZclKeepAliveClientAlloc(struct ZigBeeT *zb, uint8_t endpoint,
    void (*tcso_callback)(enum ZbTcsoStatusT status, void *arg), void *tcso_arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_KEEP_ALIVE, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.cleanup = zcl_ka_client_cleanup;

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

    clusterPtr->timer = ZbTimerAlloc(zb, zcl_ka_client_timer_callback, clusterPtr);
    clusterPtr->tc_endpoint = ZCL_KEEPALIVE_TC_ENDPOINT_INVALID; /* do a match descriptor to find endpoint */
    clusterPtr->failures = 0;

    clusterPtr->read_interval_base = ZCL_KEEPALIVE_BASE_DEFAULT;
    clusterPtr->read_interval_jitter = ZCL_KEEPALIVE_JITTER_DEFAULT;

    clusterPtr->state = KEEPALIVE_CLI_STATE_IDLE;

    clusterPtr->tcso_callback = tcso_callback;
    clusterPtr->tcso_arg = tcso_arg;

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static void
zcl_ka_client_cleanup(struct ZbZclClusterT *clusterPtr)
{
    /*lint -save -e9087 [ cluster_priv_t* <- ZbZclClusterT* <Rule 11.3, REQUIRED> ] */
    struct cluster_priv_t *client = (struct cluster_priv_t *)clusterPtr;
    /*lint -restore */

#if 0
    /* EXEGIN - what if a request is active (e.g. KEEPALIVE_CLI_STATE_READ_ACTIVE),
     * or a TCSO attempt is active (e.g. KEEPALIVE_CLI_STATE_TCSO_ACTIVE_OTHER). Need to safely
     * take down this cluster. On the other hand, this is usually called as the stack is being
     * torn down, so freeing everything here is probably fine. */
    ZbZclKeepAliveClientStop(clusterPtr->zb);
#endif
    ZbTimerFree(client->timer);
}

void
zcl_ka_client_start_state_machine(struct ZbZclClusterT *clusterPtr, bool tc_verified)
{
    /*lint -save -e9087 [ cluster_priv_t* <- ZbZclClusterT* <Rule 11.3, REQUIRED> ] */
    struct cluster_priv_t *clientPtr = (struct cluster_priv_t *)clusterPtr;
    /*lint -restore */

    if (clusterPtr->zb->zcl_ke.keCluster == NULL) {
        /* No CBKE, so nothing for Keep Alive to do. */
        return;
    }
    if ((clientPtr->state == KEEPALIVE_CLI_STATE_TCSO_FAILED) && !tc_verified) {
        /* If we failed TCSO and we're not sure we can communicate with the TC, then don't
         * restart Keep Alive until this timeout expires. */
        return;
    }

    clientPtr->failures = 0;

    if (clientPtr->state != KEEPALIVE_CLI_STATE_IDLE) {
        /* Keep Alive is active, but assume we restarted the stack.
         * Set the flag to reset the state machine the next time there's a state change. */
        ZCL_LOG_PRINTF(clientPtr->cluster.zb, __func__, "Keep Alive is active, setting flag to restart state machine.");
        clientPtr->next_state = KEEPALIVE_CLI_STATE_MATCH_WAIT;
        clientPtr->reset_state_machine = true;
        return;
    }

    /* Start in the Match_Desc_req state */
    (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_MATCH_WAIT, true, (int)ZCL_KEEPALIVE_START_DELAY_MS);
}

void
ZbZclKeepAliveClientStart(struct ZigBeeT *zb)
{
    if (zb->zcl_ke.keepaliveClient == NULL) {
        return;
    }
    zcl_ka_client_start_state_machine(zb->zcl_ke.keepaliveClient, true);
}

void
ZbZclKeepAliveClientStop(struct ZigBeeT *zb)
{
    struct cluster_priv_t *clientPtr;

    if (zb->zcl_ke.keepaliveClient == NULL) {
        return;
    }
/*lint -save -e9087 [ cluster_priv_t* <- ZbZclClusterT* <Rule 11.3, REQUIRED> ] */
    clientPtr = (struct cluster_priv_t *)zb->zcl_ke.keepaliveClient;
/*lint -restore */

    (void)ZbStartupTcsoAbort(zb);

    clientPtr->reset_state_machine = false;
    ZbTimerStop(clientPtr->timer);
    (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_IDLE, false, -1);
    clientPtr->failures = 0;
}

static bool
zcl_ka_client_change_state(struct cluster_priv_t *clientPtr,
    enum ZclKeepaliveStateT state, bool check_joined, int delay_ms)
{
    if (check_joined) {
        uint64_t epid = 0U;

        (void)ZbNwkGet(clientPtr->cluster.zb, ZB_NWK_NIB_ID_ExtendedPanId, &epid, sizeof(epid));
        if (epid == 0ULL) {
            /* We're no longer joined to a network */
            clientPtr->reset_state_machine = false;
            ZCL_LOG_PRINTF(clientPtr->cluster.zb, __func__, "Warning, not joined to network. Can't set state = %d", state);
            ZCL_LOG_PRINTF(clientPtr->cluster.zb, __func__, "Disabling state machine.");
            clientPtr->state = KEEPALIVE_CLI_STATE_IDLE;
            return false;
        }
    }

    if (state == KEEPALIVE_CLI_STATE_TCSO_FAILED) {
        /* Clear the reset flag, if set. If ZbZclKeepAliveClientStart() was called at the end
         * of a failed TCSO (e.g. during persistence reset after a failure), just ignore it. */
        clientPtr->reset_state_machine = false;
    }

    if (clientPtr->reset_state_machine == true) {
        /* The stack has been restarted, so go back to the MATCH_WAIT state. */
        clientPtr->reset_state_machine = false;
        ZCL_LOG_PRINTF(clientPtr->cluster.zb, __func__, "Restarting state machine");
        clientPtr->state = clientPtr->next_state;
        if (clientPtr->next_state != KEEPALIVE_CLI_STATE_IDLE) {
            ZbTimerReset(clientPtr->timer, 0);
        }
        return false;
    }

    /* We're allowed to change states. */
    ZCL_LOG_PRINTF(clientPtr->cluster.zb, __func__, "Keep Alive State Change = %d (delay = %d)", state, delay_ms);
    clientPtr->state = state;
    if (delay_ms >= 0) {
        ZbTimerReset(clientPtr->timer, (unsigned int)delay_ms);
    }
    return true;
}

static void
zcl_ka_client_timer_callback(struct ZigBeeT *zb, void *arg)
{
    struct cluster_priv_t *clientPtr = arg;

    switch (clientPtr->state) {
        case KEEPALIVE_CLI_STATE_IDLE:
            break;

        case KEEPALIVE_CLI_STATE_MATCH_WAIT:
            zcl_ka_client_start_match_req(clientPtr);
            break;

        case KEEPALIVE_CLI_STATE_MATCH_ACTIVE:
            /* Will never get here */
            break;

        case KEEPALIVE_CLI_STATE_READ_WAIT:
            zcl_ka_client_read_req(clientPtr);
            break;

        case KEEPALIVE_CLI_STATE_READ_ACTIVE:
            /* Will never get here */
            break;

        case KEEPALIVE_CLI_STATE_TCSO_ACTIVE:
            /* nothing to do, waiting for callback */
            break;

        case KEEPALIVE_CLI_STATE_TCSO_FAILED:
            if (clientPtr->tc_endpoint == ZCL_KEEPALIVE_TC_ENDPOINT_INVALID) {
                zcl_ka_client_start_match_req(clientPtr);
            }
            else {
                zcl_ka_client_read_req(clientPtr);
            }
            break;

        default:
            /* empty */
            break;
    }
}

/* Returns a value in milliseconds */
static uint32_t
zcl_ka_client_get_next_timeout(struct cluster_priv_t *clientPtr)
{
    struct ZigBeeT *zb = clientPtr->cluster.zb;
    uint32_t timeout = 0U;

    if (clientPtr->read_interval_base == 0U) {
        if (clientPtr->read_interval_jitter > 0) {
            /* Valid base range is from 0x01 to 0xff. If the base is set to 0, then assume we're testing.
             * Use the jitter as an absolute timeout, and not a random range. */
            timeout = (uint32_t)clientPtr->read_interval_jitter * 1000U;
        }
        else {
            ZCL_LOG_PRINTF(zb, __func__, "Error, no timeout specified. Using default base timeout.");
            /* Interval base is in minutes */
            timeout = ZCL_KEEPALIVE_BASE_DEFAULT * 60000U;
        }
    }
    else {
        uint32_t rand_val;

        /* Get a random value to use with jitter */
        if (ZbRngBytes(zb->prng, &rand_val, sizeof(rand_val)) == NULL) {
            ZCL_LOG_PRINTF(zb, __func__, "entropy failure falling back to PRNG");
            rand_val = ZbPortGetRand(zb);
        }
        /* Interval base is in minutes */
        timeout = (uint32_t)clientPtr->read_interval_base * 60000U;
        /* Jitter is in seconds */
        timeout += rand_val % ((uint32_t)clientPtr->read_interval_jitter * 1000U);
    }
    return timeout;
}

static bool
zcl_ka_client_incr_failure(struct cluster_priv_t *clientPtr)
{
    struct ZigBeeT *zb = clientPtr->cluster.zb;

    clientPtr->failures++;

    ZCL_LOG_PRINTF(zb, __func__, "ZCL Keep Alive failed (%d of %d, base = %d, jitter = %d)",
        clientPtr->failures, ZCL_KEEPALIVE_FAIL_MAX, clientPtr->read_interval_base, clientPtr->read_interval_jitter);

    if (clientPtr->failures < ZCL_KEEPALIVE_FAIL_MAX) {
        return false;
    }

    /* Start TCSO */
    clientPtr->failures = 0;
    if (zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_TCSO_ACTIVE, true, -1)) {
        /* Inform application we are performing TCSO */
        if (clientPtr->tcso_callback != NULL) {
            clientPtr->tcso_callback(ZB_TCSO_STATUS_DISCOVERY_UNDERWAY, clientPtr->tcso_arg);
        }
        if (ZbStartupTcsoStart(zb, zcl_ka_client_tcso_callback, clientPtr)) {
            /* After this process, one of several things will have happened, either we found the new trust center
             * and have switched to it and resume keepalive there, or we found the old trust center (possibly on
             * a new channel) or we didn't find a trust center (new or old) on a new channel and will resume
             * trying to contact the old trust center on the old channel */
            return true;
        }
        /* Inform application we are performing TCSO */
        if (clientPtr->tcso_callback != NULL) {
            clientPtr->tcso_callback(ZB_TCSO_STATUS_NOT_FOUND, clientPtr->tcso_arg);
        }
    }
    return false;
}

static void
zcl_ka_client_start_match_req(struct cluster_priv_t *clientPtr)
{
    struct ZbZdoMatchDescReqT matchReq;

    /* Invalidate the endpoint before starting the Match Descriptor. */
    clientPtr->tc_endpoint = ZCL_KEEPALIVE_TC_ENDPOINT_INVALID;

    if (zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_MATCH_ACTIVE, true, -1)) {
        (void)ZbMemSet(&matchReq, 0x00, sizeof(matchReq));
        matchReq.nwkAddrOfInterest = ZB_NWK_ADDR_COORDINATOR;
        matchReq.dstNwkAddr = matchReq.nwkAddrOfInterest;
        matchReq.profileId = ZCL_PROFILE_SMART_ENERGY;
        matchReq.numInClusters = 1U;
        matchReq.inClusterList[0] = (uint16_t)ZCL_CLUSTER_KEEP_ALIVE;
        matchReq.numOutClusters = 0U;
        if (ZbZdoMatchDescReq(clientPtr->cluster.zb, &matchReq, zcl_ka_client_start_match_rsp, clientPtr) != ZB_ZDP_STATUS_SUCCESS) {
            struct ZbZdoMatchDescRspT matchRsp;

            (void)ZbMemSet(&matchRsp, 0, sizeof(matchRsp));
            matchRsp.status = ZB_ZDP_STATUS_INV_REQTYPE;
            zcl_ka_client_start_match_rsp(&matchRsp, clientPtr);
            return;
        }
    }
}

static void
zcl_ka_client_start_match_rsp(struct ZbZdoMatchDescRspT *matchRsp, void *arg)
{
    struct cluster_priv_t *clientPtr = arg;
    uint8_t remote_endpoint;

    if (clientPtr->state != KEEPALIVE_CLI_STATE_MATCH_ACTIVE) {
        return;
    }

    if (matchRsp->status != ZB_STATUS_SUCCESS) {
        uint32_t timeout;

        /* Assume we timed-out. Try again in a bit. */
        timeout = zcl_ka_client_get_next_timeout(clientPtr);

        ZCL_LOG_PRINTF(clientPtr->cluster.zb, __func__,
            "Warning, match descriptor result status: 0x%02x. Trying again in %d seconds.",
            matchRsp->status, timeout / 1000U);

        (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_MATCH_WAIT, true, (int)timeout);
        (void)zcl_ka_client_incr_failure(clientPtr);
        return;
    }

    /* We got a successful response, clear the failures. */
    clientPtr->failures = 0;

    if (matchRsp->matchLength == 0U) {
        ZCL_LOG_PRINTF(clientPtr->cluster.zb, __func__,
            "Warning, match descriptor returned no endpoints for keep-alive cluster.\n");
        (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_IDLE, false, -1);
        return;
    }
    remote_endpoint = matchRsp->matchList[0];
    if (matchRsp->matchLength > 1U) {
        ZCL_LOG_PRINTF(clientPtr->cluster.zb, __func__,
            "Warning, match descriptor returned multiple endpoints. Using first one at %d.",
            remote_endpoint);
    }
    if (remote_endpoint == ZCL_KEEPALIVE_TC_ENDPOINT_INVALID) {
        ZCL_LOG_PRINTF(clientPtr->cluster.zb, __func__,
            "Warning, match descriptor returned invalid endpoint: 0x%02x\n", remote_endpoint);
        (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_IDLE, false, -1);
        return;
    }

    ZCL_LOG_PRINTF(clientPtr->cluster.zb, __func__,
        "Start reading KeepAlive attributes from remote endpoint 0x%02x "
        "(match descriptor)", remote_endpoint);

    clientPtr->tc_endpoint = remote_endpoint;
    (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_READ_WAIT, true, 0);
}

static void
zcl_ka_client_read_req(struct cluster_priv_t *clientPtr)
{
    struct ZbZclReadReqT readReq;

    if (clientPtr->tc_endpoint == ZCL_KEEPALIVE_TC_ENDPOINT_INVALID) {
        /* Shouldn't get here */
        (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_IDLE, false, -1);
        return;
    }

    if (!zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_READ_ACTIVE, true, -1)) {
        return;
    }

    (void)ZbMemSet(&readReq, 0, sizeof(readReq));
    readReq.dst.mode = ZB_APSDE_ADDRMODE_SHORT;
    readReq.dst.nwkAddr = ZB_NWK_ADDR_COORDINATOR;
    readReq.dst.endpoint = clientPtr->tc_endpoint;
    readReq.count = 2U;
    readReq.attr[0] = ZCL_KEEPALIVE_SVR_ATTR_BASE;
    readReq.attr[1] = ZCL_KEEPALIVE_SVR_ATTR_JITTER;
    ZbZclReadReq(&clientPtr->cluster, &readReq, zcl_ka_client_read_callback, clientPtr);
}

static void
zcl_ka_client_read_callback(const struct ZbZclReadRspT *readRsp, void *arg)
{
    struct cluster_priv_t *clientPtr = arg;
    struct ZigBeeT *zb = clientPtr->cluster.zb;
    uint32_t keepAliveNext;
    bool found_error = false;
    bool found_base = false, found_jitter = false;
    uint8_t read_interval_base = 0;
    uint16_t read_interval_jitter = 0;
    unsigned int i;

    if (clientPtr->state != KEEPALIVE_CLI_STATE_READ_ACTIVE) {
        return;
    }

    do {
        if (readRsp->status != ZCL_STATUS_SUCCESS) {
            found_error = true;
            break;
        }
        if (readRsp->count != 2U) {
            found_error = true;
            break;
        }
        for (i = 0; i < 2U; i++) {
            if (readRsp->attr[i].status != ZCL_STATUS_SUCCESS) {
                found_error = true;
                ZCL_LOG_PRINTF(zb, __func__, "ZCL Keep Alive read attribute failure: attr=0x%04x, status=0x%02x",
                    readRsp->attr[i].attrId, readRsp->attr[i].status);
                break;
            }
            if (readRsp->attr[i].attrId == (uint16_t)ZCL_KEEPALIVE_SVR_ATTR_BASE) {
                read_interval_base = readRsp->attr[i].value[0];
                found_base = true;
            }
            else if (readRsp->attr[i].attrId == (uint16_t)ZCL_KEEPALIVE_SVR_ATTR_JITTER) {
                read_interval_jitter = pletoh16(readRsp->attr[i].value);
                found_jitter = true;
            }
            else {
                found_error = true;
                break;
            }
        }
        if (found_error) {
            break;
        }
        if (!found_base || !found_jitter) {
            found_error = true;
            break;
        }

        clientPtr->read_interval_base = read_interval_base;
        clientPtr->read_interval_jitter = read_interval_jitter;

        /* Success */
        clientPtr->failures = 0;

        ZCL_LOG_PRINTF(zb, __func__, "ZCL Keep Alive Read Response: Base Interval = %d minutes, Jitter = %d",
            clientPtr->read_interval_base, clientPtr->read_interval_jitter);
        break;
    } while (false);

    if (found_error) {
        if (zcl_ka_client_incr_failure(clientPtr)) {
            return;
        }
    }

    /* Schedule the next read request */
    keepAliveNext = zcl_ka_client_get_next_timeout(clientPtr);

    ZCL_LOG_PRINTF(zb, __func__,
        "ZCL Keep Alive next read attributes request in %d seconds", keepAliveNext / 1000U);

    (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_READ_WAIT, true, (int)keepAliveNext);
}

static void
zcl_ka_client_tcso_callback(enum ZbTcsoStatusT status, void *arg)
{
    struct cluster_priv_t *clientPtr = arg;
    uint32_t timeout = zcl_ka_client_get_next_timeout(clientPtr);

    ZCL_LOG_PRINTF(clientPtr->cluster.zb, __func__, "TCSO callback status = %d", status);

    switch (status) {
        case ZB_TCSO_STATUS_SUCCESS:
            /* Successful TCSO, go back to the Match Descriptor state to find the remote endpoint. */
            (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_MATCH_WAIT, true, (int)ZCL_KEEPALIVE_START_DELAY_MS);
            break;

        case ZB_TCSO_STATUS_REJOIN_PREV:
            (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_READ_WAIT, true, (int)timeout);
            break;

        case ZB_TCSO_STATUS_NOT_FOUND:
            if (timeout < ZCL_KEEPALIVE_FAIL_RESTART_DELAY_MIN_MS) {
                timeout = ZCL_KEEPALIVE_FAIL_RESTART_DELAY_MIN_MS;
            }
            ZCL_LOG_PRINTF(clientPtr->cluster.zb, __func__,
                "TCSO failed, starting Keep Alive again in %d seconds", timeout / 1000U);
            (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_TCSO_FAILED, true, (int)timeout);
            break;

        case ZB_TCSO_STATUS_FATAL:
            (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_IDLE, false, -1);
            break;

        default:
            (void)zcl_ka_client_change_state(clientPtr, KEEPALIVE_CLI_STATE_IDLE, false, -1);
            break;
    }
    if (clientPtr->tcso_callback != NULL) {
        clientPtr->tcso_callback(status, clientPtr->tcso_arg);
    }
}
