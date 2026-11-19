/* Copyright [2019 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.poll.control.h"
#include "zcl/zcl.payload.h"

#define POLL_CHECK_IN_INTERVAL_DEFAULT      0x00003840 /* (14,400 qs), 1 hour */
#define POLL_CHECK_IN_INTERVAL_MIN          0x00000014 /* 5 seconds */
#define POLL_CHECK_IN_INTERVAL_MAX          0x006E0000U
#define POLL_CHECK_IN_START_DELAY_SEC       3U
#define POLL_CHECK_IN_RESPONSE_WAIT_POLLS   8U /* Number of fast polls to wait to receive check-in responses */
#define POLL_CHECK_IN_RESPONSE_WAIT_MIN     3000U /* Minimum time to fast-poll to receive check-in responses */

#define POLL_LONG_POLL_INTERVAL_MIN         0x04 /* 1 second */
#define POLL_LONG_POLL_INTERVAL_MAX         0x6E0000U
/* According to ZCL 7 Spec, the default long polling interval is 20 (5 seconds).
 * However, we want to let the application dictate this. */
#define POLL_LONG_POLL_INTERVAL_DEFAULT     ZCL_INVALID_UNSIGNED_32BIT /* Disabled */

#define POLL_SHORT_POLL_INTERVAL_DEFAULT    0x0002U /* 500 mS */

#define POLL_FAST_POLL_TIMEOUT_MIN          0x0001U /* 250 mS */
#define POLL_FAST_POLL_TIMEOUT_MAX          0xffffU
#define POLL_FAST_POLL_TIMEOUT_DEFAULT      0x0028U /* 10 seconds */

/* Convert milliseconds to quarter seconds, and vice versa */
#define POLL_CONVERT_MS_TO_QS(ms)           (ms / 250U)
#define POLL_CONVERT_QS_TO_MS(qs)           (qs * 250U)

#define MAX_CLIENTS                         10U

struct client_list_info {
    bool valid;
    uint16_t client_address;
    bool start_fast_poll;
    unsigned int fast_poll_timeout; /* in mS */
    unsigned int end_time; /**< When should the fast polling stop. */
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct ZbZclPollControlServerCallbackT callbacks;
    struct ZbTimerT *checkin_timer;
    struct ZbTimerT *fast_poll_timer; /* When to stop fast polling */
    struct ZbTimerT *long_poll_timer;
    struct ZbTimerT *checkin_rsp_timer;
    struct nwk_fastpoll_entry_t *checkin_fast_poll;
    bool long_poll_active;
    struct client_list_info client_list[MAX_CLIENTS];
    unsigned int num_clients;
    struct ZbMsgFilterT *msg_filter;
    struct nwk_fastpoll_entry_t *fast_poll_entry;
};

static enum ZclStatusCodeT zcl_poll_server_command_handler(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);
static enum ZclStatusCodeT zcl_attr_write_cb(struct ZbZclClusterT *cluster,
    const struct ZbApsAddrT *src, uint16_t attribute_id, const uint8_t *input_data,
    unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg);
static enum ZclStatusCodeT zcl_attr_read_cb(struct ZbZclClusterT *cluster,
    uint16_t attributeId, uint8_t *data, unsigned int maxlen, void *app_cb_arg);

static void zcl_poll_checkin_timeout(struct ZigBeeT *zb, void *arg);
static void zcl_poll_fast_poll_finish(struct ZigBeeT *zb, void *arg);
static void zcl_poll_long_poll_timeout(struct ZigBeeT *zb, void *arg);
static void zcl_poll_checkin_rsp_timeout(struct ZigBeeT *zb, void *arg);

static enum ZclStatusCodeT zcl_poll_handle_checkin_rsp(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);
static enum ZclStatusCodeT zcl_poll_handle_fast_stop(struct ZbZclClusterT *cluster, struct ZbApsdeDataIndT *dataIndPtr);
static enum ZclStatusCodeT zcl_poll_handle_set_long_poll(struct ZbZclClusterT *cluster, struct ZbApsdeDataIndT *dataIndPtr);
static enum ZclStatusCodeT zcl_poll_handle_set_short_poll(struct ZbZclClusterT *cluster, struct ZbApsdeDataIndT *dataIndPtr);

static enum zb_msg_filter_rc zcl_poll_server_msg_filter(struct ZigBeeT *zb, uint32_t id, void *msg, void *cbarg);

static void zcl_poll_server_cleanup(struct ZbZclClusterT *cluster);

static enum ZclStatusCodeT
zcl_attr_cb(struct ZbZclClusterT *cluster, struct ZbZclAttrCbInfoT *cb)
{
    if (cb->type == ZCL_ATTR_CB_TYPE_WRITE) {
        return zcl_attr_write_cb(cluster, cb->src, cb->info->attributeId, cb->zcl_data, cb->zcl_len,
            cb->attr_data, cb->write_mode, cb->app_cb_arg);
    }
    else if (cb->type == ZCL_ATTR_CB_TYPE_READ) {
        return zcl_attr_read_cb(cluster, cb->info->attributeId, cb->zcl_data, cb->zcl_len, cb->app_cb_arg);
    }
    else {
        return ZCL_STATUS_FAILURE;
    }
}

/* Attributes */
static const struct ZbZclAttrT zcl_poll_server_attr_list[] = {
    {
        ZCL_POLL_CHECK_IN_INTERVAL, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb,
        {0, POLL_CHECK_IN_INTERVAL_MAX}, {0, 0}
    },
    {
        ZCL_POLL_LONG_POLL_INTERVAL, ZCL_DATATYPE_UNSIGNED_32BIT,
        /* Not remotely writable, but need callback for local writes. */
        ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb,
        {POLL_LONG_POLL_INTERVAL_MIN, POLL_LONG_POLL_INTERVAL_MAX}, {0, 0}
    },
    {
        ZCL_POLL_SHORT_POLL_INTERVAL, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_POLL_FAST_POLL_TIMEOUT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb,
        {POLL_FAST_POLL_TIMEOUT_MIN, POLL_FAST_POLL_TIMEOUT_MAX}, {0, 0}
    },
    {
        ZCL_POLL_CHECK_IN_INTERVAL_MIN, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0x0, POLL_CHECK_IN_INTERVAL_MAX}, {0, 0}
    },
    {
        ZCL_POLL_LONG_POLL_INTERVAL_MIN, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0x4, POLL_LONG_POLL_INTERVAL_MAX}, {0, 0}
    },
    {
        ZCL_POLL_FAST_POLL_TIMEOUT_MAX, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0x2, 0xffff}, {0, 0}
    },
};

struct ZbZclClusterT *
zcl_poll_server_alloc(struct ZigBeeT *zb, uint8_t endpoint,
    struct ZbZclPollControlServerCallbackT *callbacks, void *arg)
{
    struct cluster_priv_t *server;

    server = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_POLL_CONTROL,
            endpoint, ZCL_DIRECTION_TO_SERVER);
    if (server == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "CCB 2319 2329" (need to investigate what these changes are) */
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    server->cluster.command = zcl_poll_server_command_handler;
    server->cluster.cleanup = zcl_poll_server_cleanup;

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&server->cluster, zcl_poll_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_poll_server_attr_list))) {
        ZbZclClusterFree(&server->cluster);
        return NULL;
    }
    /* Allocate the timers */
    server->checkin_timer = ZbTimerAlloc(zb, zcl_poll_checkin_timeout, server);
    if (server->checkin_timer == NULL) {
        return NULL;
    }
    server->fast_poll_timer = ZbTimerAlloc(zb, zcl_poll_fast_poll_finish, server);
    if (server->fast_poll_timer == NULL) {
        return NULL;
    }
    server->long_poll_timer = ZbTimerAlloc(zb, zcl_poll_long_poll_timeout, server);
    if (server->long_poll_timer == NULL) {
        return NULL;
    }

    server->checkin_rsp_timer = ZbTimerAlloc(zb, zcl_poll_checkin_rsp_timeout, server);
    if (server->checkin_rsp_timer == NULL) {
        return NULL;
    }

    /* Configure callbacks */
    if (callbacks != NULL) {
        (void)memcpy(&server->callbacks, callbacks, sizeof(struct ZbZclPollControlServerCallbackT));
    }
    else {
        (void)memset(&server->callbacks, 0, sizeof(struct ZbZclPollControlServerCallbackT));
    }
    ZbZclClusterSetCallbackArg(&server->cluster, arg);

    (void)ZbZclClusterAttach(&server->cluster);

    /* Set long poll interval min to the absolute minumum in the allowable range for long poll interval */
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_POLL_LONG_POLL_INTERVAL_MIN, POLL_LONG_POLL_INTERVAL_MIN);
    /* Set fast poll timeout max to the absolute maximum in the allowable range for fast poll timeout */
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_POLL_FAST_POLL_TIMEOUT_MAX, POLL_FAST_POLL_TIMEOUT_MAX);
    /* Note, writing to this attribute doesn't start fast polling. */
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_POLL_LONG_POLL_INTERVAL, POLL_LONG_POLL_INTERVAL_DEFAULT);
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_POLL_SHORT_POLL_INTERVAL, POLL_SHORT_POLL_INTERVAL_DEFAULT);

    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_POLL_FAST_POLL_TIMEOUT, POLL_FAST_POLL_TIMEOUT_DEFAULT);
    /* Check-in min interval needs to be >= the Long Poll Interval */
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_POLL_CHECK_IN_INTERVAL_MIN, POLL_CHECK_IN_INTERVAL_MIN);
    /* Writing to the check-in interval attribute will reset the timer. */
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_POLL_CHECK_IN_INTERVAL, POLL_CHECK_IN_INTERVAL_DEFAULT);

    /* Create a filter, so we are informed whenever we join or rejoin */
    server->msg_filter = ZbMsgFilterRegister(zb, ZB_MSG_FILTER_STARTUP_IND,
            ZB_MSG_DEFAULT_PRIO, zcl_poll_server_msg_filter, server);

    return &server->cluster;
}

static void
zcl_poll_server_cleanup(struct ZbZclClusterT *cluster)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)cluster;

    /* Free up all the timers */
    if (server->checkin_timer != NULL) {
        ZbTimerFree(server->checkin_timer);
        server->checkin_timer = NULL;
    }
    if (server->fast_poll_timer != NULL) {
        ZbTimerFree(server->fast_poll_timer);
        server->fast_poll_timer = NULL;
    }
    if (server->long_poll_timer != NULL) {
        ZbTimerFree(server->long_poll_timer);
        server->long_poll_timer = NULL;
    }
    if (server->checkin_rsp_timer != NULL) {
        ZbTimerFree(server->checkin_rsp_timer);
        server->checkin_rsp_timer = NULL;
    }
    if (server->msg_filter != NULL) {
        ZbMsgFilterRemove(cluster->zb, server->msg_filter);
        server->msg_filter = NULL;
    }
    /* client_list is allocated along with base cluster, so will be
     * freed when base cluster is freed. */
}

static enum zb_msg_filter_rc
zcl_poll_server_msg_filter(struct ZigBeeT *zb, uint32_t id, void *msg, void *cbarg)
{
    struct cluster_priv_t *server = cbarg;
    struct ZbMsgStartupInd *startup_ind = msg;
    enum ZclStatusCodeT zcl_status;
    uint32_t checkin_time;

    /* Sanity check */
    if (id != ZB_MSG_FILTER_STARTUP_IND) {
        return ZB_MSG_CONTINUE;
    }
    /* Only care if we successfully joined or rejoined */
    if (startup_ind->status != ZB_STATUS_SUCCESS) {
        return ZB_MSG_CONTINUE;
    }
    checkin_time = (uint32_t)ZbZclAttrIntegerRead(&server->cluster, (uint16_t)ZCL_POLL_CHECK_IN_INTERVAL, NULL, &zcl_status);
    if (zcl_status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(zb, __func__, "Warning, failed to read ZCL_POLL_CHECK_IN_INTERVAL attribute");
        return ZB_MSG_CONTINUE;
    }
    if (checkin_time == 0U) {
        ZCL_LOG_PRINTF(zb, __func__, "Warning, check-in interval is disabled");
        return ZB_MSG_CONTINUE;
    }
    /* Reset the timer to fire soon after joining. */
    ZCL_LOG_PRINTF(zb, __func__, "Successfully joined or rejoined, sending check-in request in %d seconds",
        POLL_CHECK_IN_START_DELAY_SEC);
    ZbTimerReset(server->checkin_timer, POLL_CHECK_IN_START_DELAY_SEC * 1000U);
    return ZB_MSG_CONTINUE;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src, uint16_t attribute_id,
    const uint8_t *input_data, unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)cluster;
    unsigned int len = 0;
    enum ZclStatusCodeT status;
    uint32_t input, min_value;
    uint16_t max_value;

    switch (attribute_id) {
        case ZCL_POLL_CHECK_IN_INTERVAL:
        {
            uint32_t short_poll_intvl, long_poll_intvl;

            if (input_max_len < 4U) {
                status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            input = pletoh32(input_data);

            /* Handle zero separately */
            if (input == 0U) {
                ZCL_LOG_PRINTF(cluster->zb, __func__, "Stopping check-in timer");
                ZbTimerStop(server->checkin_timer);

                len = 4;
                status = ZCL_STATUS_SUCCESS;
                break;
            }

            min_value = (uint32_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_POLL_CHECK_IN_INTERVAL_MIN, NULL, &status);
            if (status != ZCL_STATUS_SUCCESS) {
                break;
            }
            if ((input < min_value) || (input < POLL_CHECK_IN_INTERVAL_MIN) || (input > POLL_CHECK_IN_INTERVAL_MAX)) {
                ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, check-in interval value out of range");
                status = ZCL_STATUS_INVALID_VALUE;
                break;
            }

            /* The Check-inInterval, LongPollInterval and ShortPollInterval SHOULD be set such that:
             * Check-in Interval >= Long Poll Interval >= Short Poll Interval */
            long_poll_intvl = (uint32_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_POLL_LONG_POLL_INTERVAL, NULL, &status);
            if (status != ZCL_STATUS_SUCCESS) {
                break;
            }
            if (long_poll_intvl == ZCL_INVALID_UNSIGNED_32BIT) {
                /* If long polling is disabled, make sure check-in is >= Short Poll Interval */
                short_poll_intvl = (uint32_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_POLL_SHORT_POLL_INTERVAL, NULL, &status);
                if (status != ZCL_STATUS_SUCCESS) {
                    break;
                }
                /* Return ZCL_STATUS_INVALID_VALUE if check-in interval is less than short poll interval
                 * ZCL_POLL_SHORT_POLL_INTERVAL is of type uint16 with no special values (0x0-0xffff is valid) */
                if (input < short_poll_intvl) {
                    ZCL_LOG_PRINTF(cluster->zb, __func__,
                        "Error, check-in interval is less than short polling interval (%d)", short_poll_intvl);
                    status = ZCL_STATUS_INVALID_VALUE;
                    break;
                }
            }
            else {
                if (input < long_poll_intvl) {
                    /* Return ZCL_STATUS_INVALID_VALUE if check-in interval is less than long poll interval */
                    ZCL_LOG_PRINTF(cluster->zb, __func__,
                        "Error, check-in interval is less than long polling interval (%d)", long_poll_intvl);
                    status = ZCL_STATUS_INVALID_VALUE;
                    break;
                }
            }

            /* Check-in is valid since it's more than the check-in min and the long poll interval.
             * Update checkin_timer with new check in interval */
            ZCL_LOG_PRINTF(cluster->zb, __func__,
                "Setting check-in timer to %d seconds", POLL_CONVERT_QS_TO_MS(input) / 1000U);
            ZbTimerReset(server->checkin_timer, POLL_CONVERT_QS_TO_MS(input));

            len = 4;
            status = ZCL_STATUS_SUCCESS;
            break;
        }

        case ZCL_POLL_LONG_POLL_INTERVAL:
            input = (uint32_t)pletoh32(input_data);

            /* ZCL_INVALID_UNSIGNED_32BIT disables the long poll timer */
            if (input == ZCL_INVALID_UNSIGNED_32BIT) {
                ZbTimerStop(server->long_poll_timer);
                server->long_poll_active = false;
            }

            min_value = (uint32_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_POLL_LONG_POLL_INTERVAL_MIN, NULL, &status);
            if (status != ZCL_STATUS_SUCCESS) {
                break;
            }
            if (input < min_value) {
                status = ZCL_STATUS_INVALID_VALUE;
                break;
            }
            if (input != ZCL_INVALID_UNSIGNED_32BIT) {
                ZbTimerReset(server->long_poll_timer, POLL_CONVERT_QS_TO_MS(input));
            }
            len = 4;
            status = ZCL_STATUS_SUCCESS;
            break;

        case ZCL_POLL_SHORT_POLL_INTERVAL:
        {
            uint16_t short_poll_intvl;
            uint32_t long_poll_intvl;
            uint16_t short_ms;

            short_poll_intvl = pletoh16(input_data);

            long_poll_intvl = (uint32_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_POLL_LONG_POLL_INTERVAL, NULL, &status);
            if (status != ZCL_STATUS_SUCCESS) {
                break;
            }
            if (short_poll_intvl > long_poll_intvl) {
                status = ZCL_STATUS_INVALID_VALUE;
                break;
            }
            /* Besides not exceeding the long poll interval, we only need to check for 0 here.
            * The NLME-SET handler for ZB_NWK_NIB_ID_FastPollPeriod will perform range checking
            * to ensure we don't exceed a value that breaks stack functionality. */
            if (short_poll_intvl == 0) {
                status = ZCL_STATUS_INVALID_VALUE;
                break;
            }
            /* convert quarterseconds to ms and set new value to the NIB also */
            short_ms = POLL_CONVERT_QS_TO_MS(short_poll_intvl);
            if (ZbNwkSet(cluster->zb, ZB_NWK_NIB_ID_FastPollPeriod, &short_ms, sizeof(short_ms)) != ZB_STATUS_SUCCESS) {
                status = ZCL_STATUS_INVALID_VALUE;
                break;
            }
            status = ZCL_STATUS_SUCCESS;
            break;
        }

        case ZCL_POLL_FAST_POLL_TIMEOUT:
            input = (uint16_t)pletoh16(input_data);
            max_value = (uint16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_POLL_FAST_POLL_TIMEOUT_MAX, NULL, &status);
            if (status != ZCL_STATUS_SUCCESS) {
                break;
            }
            if (input > max_value) {
                status = ZCL_STATUS_INVALID_VALUE;
                break;
            }
            len = 2;
            status = ZCL_STATUS_SUCCESS;
            break;

        default:
            status = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            break;
    }

    if (((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) && (status == ZCL_STATUS_SUCCESS)) {
        (void)memcpy(attr_data, input_data, len);
    }
    return status;
}

static enum ZclStatusCodeT
zcl_attr_read_cb(struct ZbZclClusterT *cluster, uint16_t attributeId, uint8_t *data, unsigned int maxlen, void *app_cb_arg)
{
    switch (attributeId) {
        case ZCL_POLL_SHORT_POLL_INTERVAL:
        {
            uint16_t val;

            if (maxlen < 2) {
                return ZCL_STATUS_INSUFFICIENT_SPACE;
            }
            val = 0U;
            (void)ZbNwkGet(cluster->zb, ZB_NWK_NIB_ID_FastPollPeriod, &val, sizeof(uint16_t));
            /* convert ms to quarterseconds */
            val = POLL_CONVERT_MS_TO_QS(val);
            putle16(data, val);
            return ZCL_STATUS_SUCCESS;
        }

        default:
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
}

static enum ZclStatusCodeT
zcl_poll_server_command_handler(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    enum ZclStatusCodeT zcl_status;

    switch (zclHdrPtr->cmdId) {
        case ZCL_POLL_CTRL_CLI_CHECK_IN_RSP:
            zcl_status = zcl_poll_handle_checkin_rsp(cluster, zclHdrPtr, dataIndPtr);
            break;

        case ZCL_POLL_CTRL_CLI_FAST_POLL_STOP:
            zcl_status = zcl_poll_handle_fast_stop(cluster, dataIndPtr);
            break;

        case ZCL_POLL_CTRL_CLI_SET_LONG_POLL_INTERVAL:
            zcl_status = zcl_poll_handle_set_long_poll(cluster, dataIndPtr);
            break;

        case ZCL_POLL_CTRL_CLI_SET_SHOR_POLL_INTERVAL:
            zcl_status = zcl_poll_handle_set_short_poll(cluster, dataIndPtr);
            break;

        default:
            zcl_status = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return zcl_status;
}

static void
zcl_poll_checkin_timeout(struct ZigBeeT *zb, void *arg)
{
    struct cluster_priv_t *server = arg;
    struct ZbZclClusterCommandReqT req;
    uint16_t fastPollPeriod;
    uint32_t checkin_time, timeout;
    enum ZclStatusCodeT zcl_status;

    /* Reset timer with check in interval */
    checkin_time = (uint32_t)ZbZclAttrIntegerRead(&server->cluster,
            (uint16_t)ZCL_POLL_CHECK_IN_INTERVAL, NULL, &zcl_status);
    if ((zcl_status == ZCL_STATUS_SUCCESS) && (checkin_time > 0U)) {
        timeout = POLL_CONVERT_QS_TO_MS(checkin_time);
        ZCL_LOG_PRINTF(zb, __func__, "Resetting check-in timer (%d seconds)", timeout / 1000U);
        ZbTimerReset(server->checkin_timer, timeout);
    }

    if (ZbTimerRunning(server->checkin_rsp_timer)) {
        /* Shouldn't get here. If we do, the check-in time must be really
         * fast. Let's just skip this one and wait for the next. */
        ZCL_LOG_PRINTF(zb, __func__, "Error, still waiting for response from previous request.");
        return;
    }

    if (server->checkin_fast_poll != NULL) {
        /* Calling ZbNwkFastPollRelease should be redundant because we're using a
         * timeout with ZbNwkFastPollRequest. It should have timed-out long before
         * we need to perform another check-in. */
        (void)ZbNwkFastPollRelease(zb, server->checkin_fast_poll);
        server->checkin_fast_poll = NULL;
    }

    (void)ZbNwkGet(zb, ZB_NWK_NIB_ID_FastPollPeriod, &fastPollPeriod, sizeof(uint16_t));
    timeout = (uint32_t)fastPollPeriod * POLL_CHECK_IN_RESPONSE_WAIT_POLLS;
    if (timeout < POLL_CHECK_IN_RESPONSE_WAIT_MIN) {
        timeout = POLL_CHECK_IN_RESPONSE_WAIT_MIN;
    }

    ZCL_LOG_PRINTF(zb, __func__, "Sending check-in via binding (response timeout = %d mS)", timeout);
    ZbTimerReset(server->checkin_rsp_timer, timeout);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *ZbApsAddrBinding;
    req.cmdId = ZCL_POLL_CTRL_SVR_CHECK_IN;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = NULL;
    req.length = 0U;
    zcl_status = ZbZclClusterCommandReq(&server->cluster, &req, NULL, NULL);
    if (zcl_status == ZCL_STATUS_SUCCESS) {
        /* Since we didn't define a callback to ZbZclClusterCommandReq, yet we
         * still want to receive the response, enable fast polling here. */
        server->checkin_fast_poll = ZbNwkFastPollRequest(zb, ZB_NWK_SYNC_DEFAULT_DELAY_MS, timeout);
    }
}

static void
zcl_poll_fast_poll_finish(struct ZigBeeT *zb, void *arg)
{
    struct cluster_priv_t *server = arg;
    unsigned int i;
    uint32_t long_poll_intvl;
    uint64_t epid = 0;

    /* This function may be called from outside a timer callback, so stop
     * the timer if it's running. */
    if (ZbTimerRunning(server->fast_poll_timer)) {
        ZbTimerStop(server->fast_poll_timer);
    }

    /* Fast polling for all clients is done. Clean up the whole client list */
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (!server->client_list[i].valid) {
            continue;
        }
        server->client_list[i].valid = false;
        server->num_clients--;
    }

    if (server->fast_poll_entry != NULL) {
        ZCL_LOG_PRINTF(zb, __func__, "Releasing fast polling");
        ZbNwkFastPollRelease(zb, server->fast_poll_entry);
        server->fast_poll_entry = NULL;
    }

    (void)ZbNwkGet(zb, ZB_NWK_NIB_ID_ExtendedPanId, &epid, sizeof(uint64_t));
    if (epid == 0) {
        /* Timers may be restarted after receiving ZB_MSG_FILTER_STACK_EVENT */
        return;
    }

    /* Start slow poll timer (if applicable) */
    long_poll_intvl = ZbZclAttrIntegerRead(&server->cluster, (uint16_t)ZCL_POLL_LONG_POLL_INTERVAL, NULL, NULL);
    if ((long_poll_intvl != 0U) && (long_poll_intvl != ZCL_INVALID_UNSIGNED_32BIT)) {
        ZbTimerReset(server->long_poll_timer, POLL_CONVERT_QS_TO_MS(long_poll_intvl));
    }
}

static void
zcl_poll_slow_poll_sync_conf(struct ZbNlmeSyncConfT *syncConfPtr, void *arg)
{
    struct cluster_priv_t *server = arg;

    /* EXEGIN handle polling errors? Not much we can do. The stack will already be sending
     * us PARENT_LINK_FAILURE codes. */
    server->long_poll_active = false;
}

static void
zcl_poll_long_poll_timeout(struct ZigBeeT *zb, void *arg)
{
    struct cluster_priv_t *server = arg;
    struct ZbNlmeSyncReqT req;
    uint32_t long_poll_intvl;
    enum ZbStatusCodeT zb_status;
    enum ZclStatusCodeT zcl_status;
    uint64_t epid = 0;

    (void)ZbNwkGet(zb, ZB_NWK_NIB_ID_ExtendedPanId, &epid, sizeof(uint64_t));
    if (epid == 0) {
        /* Timers may be restarted after receiving ZB_MSG_FILTER_STACK_EVENT */
        return;
    }

    long_poll_intvl = ZbZclAttrIntegerRead(&server->cluster, (uint16_t)ZCL_POLL_LONG_POLL_INTERVAL, NULL, &zcl_status);
    if (long_poll_intvl == 0U) {
        /* Long polling disabled */
        return;
    }

    if (ZbTimerRunning(server->fast_poll_timer)) {
        /* Fast polling is active, so skip this long poll. If log polling is enabled,
         * this timer will be restarted after fast polling is done. */
        return;
    }

    if (server->long_poll_active) {
        /* Shouldn't get here, but don't start another NLME-SYNC until the current one is finished. */
        ZbTimerReset(server->long_poll_timer, 100);
        return;
    }

    /* Reset the long poll timer */
    ZbTimerReset(server->long_poll_timer, POLL_CONVERT_QS_TO_MS(long_poll_intvl));

    /* Perform an NLME-SYNC.request */
    (void)memset(&req, 0, sizeof(req));
    server->long_poll_active = true;
    zb_status = ZbNlmeSyncReq(zb, &req, zcl_poll_slow_poll_sync_conf, server);
    if (zb_status != ZB_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(zb, __func__, "Warning, NLME-SYNC.request failed (an MLME-POLL.request may already be active)");
        server->long_poll_active = false;
    }
}

static void *
zcl_poll_find_polling_client(struct cluster_priv_t *server, uint16_t client_addr)
{
    unsigned int i;

    for (i = 0; i < MAX_CLIENTS; i++) {
        if (!server->client_list[i].valid) {
            continue;
        }
        if (server->client_list[i].client_address != client_addr) {
            continue;
        }
        return &server->client_list[i];
    }
    return NULL;
}

static bool
zcl_poll_check_bind_exists(struct ZigBeeT *zb, struct ZbApsdeDataIndT *dataIndPtr)
{
    unsigned int bind_index;
    struct ZbApsmeBindT current_bind;
    enum ZbStatusCodeT status;
    uint64_t src_ext;
    uint8_t src_ep;

    /* Translate the source short address to an extended address, which is used in binding. */
    src_ext = ZbNwkAddrLookupExt(zb, dataIndPtr->src.nwkAddr);
    if (src_ext == 0U) {
        return false;
    }
    src_ep = dataIndPtr->src.endpoint;

    for (bind_index = 0;; bind_index++) {
        /* Get the next entry in the binding table. */
        status = ZbApsGetIndex(zb, ZB_APS_IB_ID_BINDING_TABLE, &current_bind, sizeof(struct ZbApsmeBindT), bind_index);
        if (status != ZB_APS_STATUS_SUCCESS) {
            /* Reached the end of the table */
            return false;
        }
        if (current_bind.dst.mode != ZB_APSDE_ADDRMODE_EXT) {
            /* Only check for bindings through EUI for now */
            continue;
        }
        if (current_bind.clusterId != ZCL_CLUSTER_POLL_CONTROL) {
            continue;
        }
        if (current_bind.dst.endpoint != src_ep) {
            continue;
        }
        if (current_bind.dst.extAddr != src_ext) {
            continue;
        }
        /* Found a match */
        return true;
    }
}

static unsigned int
zcl_poll_timers_check(struct cluster_priv_t *server)
{
    struct ZigBeeT *zb = server->cluster.zb;
    unsigned int i, timeout = 0, client_timeout;
    struct client_list_info *client_info;
    ZbUptimeT uptime;

    /* Check if any of our clients have asked us to perform fast polling. */
    uptime = ZbZclUptime(zb);
    for (i = 0; i < MAX_CLIENTS; i++) {
        client_info = &server->client_list[i];

        if (!client_info->valid) {
            continue;
        }
        /* Timeout check comes before 'start_fast_poll' check, because
         * we can have a client that isn't fast polling. Question might be,
         * should we immediately remove a client from the list if it isn't
         * allowed to fast poll? */
        client_timeout = ZbTimeoutRemaining(uptime, client_info->end_time);
        if (client_timeout == 0U) {
            /* Fast polling timed-out. Remove it from the list. */
            client_info->valid = false;
            continue;
        }
        if (!client_info->start_fast_poll) {
            continue;
        }
        if (client_timeout > timeout) {
            timeout = client_timeout;
        }
    }
    /* If fast-polling is running, stop it. */
    if (server->fast_poll_entry != NULL) {
        ZbNwkFastPollRelease(zb, server->fast_poll_entry);
        server->fast_poll_entry = NULL;
    }
    if (ZbTimerRunning(server->fast_poll_timer)) {
        ZbTimerStop(server->fast_poll_timer);
    }
    if (timeout > 0U) {
        /* (Re)start fast polling */
        ZCL_LOG_PRINTF(zb, __func__, "Fast polling for %d ms", timeout);
        server->fast_poll_entry = ZbNwkFastPollRequest(zb, 0, 0);
        if (server->fast_poll_entry == NULL) {
            ZCL_LOG_PRINTF(zb, __func__, "Failed to start fast poll");
            return 0;
        }
        ZbTimerReset(server->fast_poll_timer, timeout);
    }
    return timeout;
}

static void
zcl_poll_checkin_rsp_timeout(struct ZigBeeT *zb, void *arg)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)arg;

    /* Waiting for check-in responses has expired. Stop fast polling for them. */
    if (server->checkin_fast_poll != NULL) {
        (void)ZbNwkFastPollRelease(zb, server->checkin_fast_poll);
        server->checkin_fast_poll = NULL;
    }
    (void)zcl_poll_timers_check(server);
}

static enum ZclStatusCodeT
zcl_poll_handle_checkin_rsp(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr,
    struct ZbApsdeDataIndT *dataIndPtr)
{
    struct ZigBeeT *zb = cluster->zb;
    struct cluster_priv_t *server = (struct cluster_priv_t *)cluster;
    struct zcl_poll_checkin_rsp_t rsp_info;
    struct ZbZclAddrInfoT srcInfo;
    uint16_t max_value;
    struct client_list_info *client_info;
    enum ZclStatusCodeT zcl_status;

    /* Sanity check */
    if (dataIndPtr->asduLength < 3U) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    /* Must be from a bound device */
    if (!zcl_poll_check_bind_exists(zb, dataIndPtr)) {
        return ZCL_STATUS_FAILURE;
    }
    if (!ZbTimerRunning(server->checkin_rsp_timer)) {
        /* From ZCL8:
        * If the Poll Control Server receives a Check-In Response from a bound client
        * AFTER the temporary fast poll mode is completed it SHOULD respond with a
        * Default Response with a status value indicating FAILURE.
        */
        return ZCL_STATUS_FAILURE;
    }

    (void)memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zclHdrPtr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    /* Parse the command */
    memset(&rsp_info, 0, sizeof(rsp_info));
    rsp_info.status = ZCL_STATUS_SUCCESS;
    rsp_info.start_fast_poll = (dataIndPtr->asdu[0] != 0x00) ? true : false;
    rsp_info.fast_poll_timeout = pletoh16(&dataIndPtr->asdu[1]);

    /* Make sure fast poll timeout is valid */
    /* From ZCL7:
        * If the Poll Control Server receives a Check-In Response from a client for which
        * there is a binding (bound) with an invalid fast poll timeout, it SHOULD respond
        * with a Default Response with status INVALID_VALUE.
        *
        * If the Poll Control Server receives a Check-In Response from a bound client after
        * temporary fast poll mode is completed it SHOULD respond with a Default Response
        * with a status value indicating TIMEOUT.
        *
        * If the Fast Poll Timeout value is 0, the device is EXPECTED to continue fast polling
        * until the amount of time indicated in the FastPollTimeout attribute has elapsed or
        * it receives a Fast Poll Stop command.
        *
        * The Fast Poll Timeout argument temporarily overrides the FastPollTimeout attribute
        * on the Poll Control Cluster Server for the fast poll mode induced by the Check-in
        * Response command. This value is not EXPECTED to overwrite the stored value in the
        * FastPollTimeout attribute.
        */

    /* Get the max value for the fast poll timeout */
    max_value = (uint16_t)ZbZclAttrIntegerRead(cluster,
            (uint16_t)ZCL_POLL_FAST_POLL_TIMEOUT_MAX, NULL, &zcl_status);
    if (zcl_status == ZCL_STATUS_SUCCESS) {
        if (rsp_info.fast_poll_timeout > max_value) {
            return ZCL_STATUS_INVALID_VALUE;
        }
    }

    if (rsp_info.fast_poll_timeout == 0U) {
        /* If the fast poll timeout is zero, then use what we already have configured. */
        rsp_info.fast_poll_timeout = (uint16_t)ZbZclAttrIntegerRead(cluster,
                (uint16_t)ZCL_POLL_FAST_POLL_TIMEOUT, NULL, &zcl_status);
        if (zcl_status != ZCL_STATUS_SUCCESS) {
            return zcl_status;
        }
    }

    /* Add this client to the list */
    client_info = zcl_poll_find_polling_client(server, dataIndPtr->src.nwkAddr);
    if (client_info != NULL) {
        /* 'start_fast_poll' may be ignored and set by checkin_rsp() callback. */
        client_info->start_fast_poll = rsp_info.start_fast_poll;
        client_info->fast_poll_timeout = POLL_CONVERT_QS_TO_MS(rsp_info.fast_poll_timeout);
        client_info->end_time = ZbZclUptime(zb) + POLL_CONVERT_QS_TO_MS(rsp_info.fast_poll_timeout);
    }
    else {
        unsigned int i;
        ZbUptimeT uptime;

        /* Add client to list of active clients */
        uptime = ZbZclUptime(zb);
        for (i = 0; i < MAX_CLIENTS; i++) {
            client_info = &server->client_list[i];
            if (client_info->valid) {
                /* Valid, but has it expired? */
                if (ZbTimeoutRemaining(uptime, client_info->end_time) > 0U) {
                    continue;
                }
            }
            /* Found an empty entry, add it to the list. */
            (void)memset(client_info, 0, sizeof(struct client_list_info));
            client_info->client_address = dataIndPtr->src.nwkAddr;
            /* 'start_fast_poll' may be ignored and set by checkin_rsp() callback. */
            client_info->start_fast_poll = rsp_info.start_fast_poll;
            client_info->fast_poll_timeout = POLL_CONVERT_QS_TO_MS(rsp_info.fast_poll_timeout);
            client_info->end_time = ZbZclUptime(zb) + POLL_CONVERT_QS_TO_MS(rsp_info.fast_poll_timeout);
            client_info->valid = true;
            server->num_clients++;
            ZCL_LOG_PRINTF(zb, __func__, "Add client 0x%04x to list", client_info->client_address);
            break;
        }
        if (i == MAX_CLIENTS) {
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }
    }

    if (server->callbacks.checkin_rsp != NULL) {
        client_info->start_fast_poll = server->callbacks.checkin_rsp(cluster, &rsp_info, &srcInfo, cluster->app_cb_arg);
    }
    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
zcl_poll_handle_fast_stop(struct ZbZclClusterT *cluster, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct ZigBeeT *zb = cluster->zb;
    struct cluster_priv_t *server = (struct cluster_priv_t *)cluster;
    unsigned int timeout;
    struct client_list_info *client_list_info;

    /* Must be from a bound device */
    if (!zcl_poll_check_bind_exists(zb, dataIndPtr)) {
        return ZCL_STATUS_FAILURE;
    }

    client_list_info = zcl_poll_find_polling_client(server, dataIndPtr->src.nwkAddr);
    if (client_list_info == NULL) {
        /* Cannot find this client in the list of clients. */
        ZCL_LOG_PRINTF(zb, __func__, "Client not in list of polling clients. Command denied.");
        return ZCL_STATUS_FAILURE;
    }

    /* Client found. We should remove this client from list of clients. */
    ZCL_LOG_PRINTF(zb, __func__, "Removing 0x%04x from list of fast poll clients.", dataIndPtr->src.nwkAddr);
    client_list_info->valid = false;
    server->num_clients--;

    if (server->num_clients == 0U) {
        /* List is empty. Release fast poll and stop fast poll timer. */
        ZCL_LOG_PRINTF(zb, __func__, "Client list now empty. Clean up the fast poll timer and release polling.");
        zcl_poll_fast_poll_finish(zb, server);
        return ZCL_STATUS_SUCCESS;
    }

    timeout = zcl_poll_timers_check(server);
    if (timeout > 0) {
        /* From ZCL 8 Section 3.16.5.4:
        * "If the Poll Control Server receives a Fast Poll Stop command from a bound
        * client but it is unable to stop fast polling due to the fact that there is
        * another bound client which has requested that polling continue it SHOULD
        * respond with a Default Response with a status of FAILURE" */
        return ZCL_STATUS_FAILURE;
    }
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
zcl_poll_server_write_long_poll_intvl(struct ZbZclClusterT *cluster, uint32_t long_poll_intvl)
{
    uint16_t short_poll_intvl;
    uint32_t check_in_intvl;
    enum ZclStatusCodeT zcl_status;

    /* 3.16.4.2 Attribute Settings and Battery Life Considerations
     * Check-in Interval >= Long Poll Interval >= Short Poll Interval
     * Note that for the Check-in Interval, 0 is a special value and does not apply to this equation.
     */
    check_in_intvl = (uint32_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_POLL_CHECK_IN_INTERVAL, NULL, &zcl_status);
    if (zcl_status != ZCL_STATUS_SUCCESS) {
        return zcl_status;
    }
    /* Long poll interval can be invalid uint32 to turn off slow polling */
    if ((check_in_intvl != 0U) && (check_in_intvl < long_poll_intvl) && (long_poll_intvl != ZCL_INVALID_UNSIGNED_32BIT)) {
        return ZCL_STATUS_INVALID_VALUE;
    }

    short_poll_intvl = (uint16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_POLL_SHORT_POLL_INTERVAL, NULL, &zcl_status);
    if (zcl_status != ZCL_STATUS_SUCCESS) {
        return zcl_status;
    }
    if (long_poll_intvl < short_poll_intvl) {
        return ZCL_STATUS_INVALID_VALUE;
    }

    /* Writing to the attribute may restart the long polling timer */
    if (ZbZclAttrIntegerWrite(cluster, ZCL_POLL_LONG_POLL_INTERVAL, long_poll_intvl)) {
        return ZCL_STATUS_INVALID_VALUE;
    }
    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
zcl_poll_handle_set_long_poll(struct ZbZclClusterT *cluster, struct ZbApsdeDataIndT *dataIndPtr)
{
    uint32_t long_poll_intvl;

    if (dataIndPtr->asduLength < 4U) {
        /* Return the default ZCL response indicating a malformed command. */
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    long_poll_intvl = pletoh32(dataIndPtr->asdu);
    return zcl_poll_server_write_long_poll_intvl(cluster, long_poll_intvl);
}

static enum ZclStatusCodeT
zcl_poll_handle_set_short_poll(struct ZbZclClusterT *cluster, struct ZbApsdeDataIndT *dataIndPtr)
{
    uint16_t short_poll_intvl;

    /* Sanity-check the length of the command payload */
    if (dataIndPtr->asduLength < 2U) {
        /* Return the default ZCL response indicating a malformed command. */
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    short_poll_intvl = pletoh16(dataIndPtr->asdu);
    if (ZbZclAttrIntegerWrite(cluster, ZCL_POLL_SHORT_POLL_INTERVAL, short_poll_intvl)) {
        return ZCL_STATUS_INVALID_VALUE;
    }
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
zcl_poll_server_send_checkin(struct ZbZclClusterT *cluster)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)cluster;

    /* Reset timer to 10ms to send force a checkin command */
    ZbTimerReset(server->checkin_timer, 10U);
    return ZCL_STATUS_SUCCESS;
}
