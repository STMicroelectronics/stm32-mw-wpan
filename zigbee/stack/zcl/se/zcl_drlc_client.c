/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

/*-------------------------------------------------
 *  DESCRIPTION
 *      The Smart Energy Demand Response and Load Control
 *  client cluster.
 *-------------------------------------------------
 */

#include "zcl/se/zcl.drlc.h"
#include "zcl/general/zcl.time.h"

/* EXEGIN - add mutex? */
#define ZbEnterCritical(_zb_)
#define ZbExitCritical(_zb_)

/*lint -e9087 "struct cluster_priv_t* <- ZbZclClusterT* [MISRA Rule 11.3 (REQUIRED)]" */

#define ZCL_DRLC_EVENT_MIN_SIZE             23U
#define ZCL_DRLC_CANCEL_MIN_SIZE            12U

#define ZCL_DRLC_NUM_EVENTS_MAX             16U

/* DRLC event list element struct */
struct ZbZclDrlcEventListElT {
    bool valid;
    /* Event Information */
    struct ZbZclDrlcEventT event;
    uint32_t endTime;
    uint8_t doCancel;
    struct ZbApsAddrT src;
};

/* The DRLC Client Cluster struct - allocated by ZbZclDrlcClient */
struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
    struct ZbTimerT *timer;
    struct ZbZclClusterT *time_server;
    /* DRLC Event List */
    struct ZbZclDrlcEventListElT eventList[ZCL_DRLC_NUM_EVENTS_MAX];
    /* Callbacks */
    struct ZbZclDrlcClientCallbacksT callbacks;
};

/* Attributes */
static const struct ZbZclAttrT drlc_default_attr_list[] = {
    {
        ZCL_DRLC_CLI_ATTR_UTILITY_ENROL_GRP, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLC_CLI_ATTR_START_RAND_MINS, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x00, 0x3c}, {0, 0}
    },
    {
        ZCL_DRLC_CLI_ATTR_DURATION_RAND_MINS, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x00, 0x3c}, {0, 0}
    },
    {
        ZCL_DRLC_CLI_ATTR_DEVICE_CLASS, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
};

/*---------------------------------------------------------
 * Function Declarations
 *---------------------------------------------------------
 */
static void zcl_drlc_client_tick(struct ZigBeeT *zb, void *arg);

static enum ZclStatusCodeT zcl_drlc_client_handle_command(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);
static void zcl_drlc_client_cleanup(struct ZbZclClusterT *clusterPtr);

/* Static functions */
static bool zcl_drlc_client_event_append(struct cluster_priv_t *clientPtr, struct ZbZclDrlcEventT *eventp, unsigned short seqNum,
    struct ZbApsdeDataIndT *dataIndPtr);

static bool zcl_drlc_client_event_delete(struct cluster_priv_t *clientPtr, unsigned int issuer_id);

static struct ZbZclDrlcEventListElT * zcl_drlc_client_event_find(struct cluster_priv_t *clientPtr, unsigned int issuer_id);

static void zcl_drlc_client_event_send_status(struct ZbZclClusterT *clusterPtr, unsigned int issuer_id,
    enum ZbZclDrlcEventStatusT event_status, enum ZbZclDrlcCriticalityLevelT criticality,
    const struct ZbApsAddrT *dst);

static unsigned int zcl_drlc_client_report_status_build(struct ZbZclDrlcStatusT *statusPtr, uint8_t *payload, unsigned int maxlen);

struct ZbZclClusterT *
ZbZclDrlcClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclClusterT *time_server,
    struct ZbZclDrlcClientCallbacksT *callbacks, void *cb_arg)
{
    struct cluster_priv_t *clusterPtr;

    if (time_server == NULL) {
        return NULL;
    }

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_DRLC, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.command = zcl_drlc_client_handle_command;
    clusterPtr->cluster.cleanup = zcl_drlc_client_cleanup;

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
    if (ZbZclAttrAppendList(&clusterPtr->cluster, drlc_default_attr_list,
            ZCL_ATTR_LIST_LEN(drlc_default_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLC_CLI_ATTR_UTILITY_ENROL_GRP, 0);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLC_CLI_ATTR_START_RAND_MINS, 0x1e);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLC_CLI_ATTR_DURATION_RAND_MINS, 0);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLC_CLI_ATTR_DEVICE_CLASS, 0);

    clusterPtr->time_server = time_server;

    /* Callbacks */
    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, cb_arg);
    if (callbacks != NULL) {
        (void)memcpy(&clusterPtr->callbacks, callbacks, sizeof(struct ZbZclDrlcClientCallbacksT));
    }
    else {
        (void)memset(&clusterPtr->callbacks, 0, sizeof(struct ZbZclDrlcClientCallbacksT));
    }

    /* Start a timer to handle cluster ticking. */
    clusterPtr->timer = ZbTimerAlloc(zb, zcl_drlc_client_tick, clusterPtr);
    if (clusterPtr->timer == NULL) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }
    ZbTimerReset(clusterPtr->timer, 1000);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static void
zcl_drlc_client_cleanup(struct ZbZclClusterT *clusterPtr)
{
    struct cluster_priv_t *clientPtr = (struct cluster_priv_t *)clusterPtr;

    if (clientPtr->timer != NULL) {
        ZbTimerFree(clientPtr->timer);
        clientPtr->timer = NULL;
    }
}

static void
zcl_drlc_client_tick(struct ZigBeeT *zb, void *arg)
{
    struct cluster_priv_t *clientPtr = arg;
    struct ZbZclDrlcEventListElT *entryp;
    unsigned int currentTime = ZbZclTimeServerCurrentTime(clientPtr->time_server);
    unsigned char status;
    unsigned int i;

    ZbEnterCritical(zb);
    for (i = 0; i < ZCL_DRLC_NUM_EVENTS_MAX; i++) {
        entryp = &clientPtr->eventList[i];
        if (!entryp->valid) {
            continue;
        }

        if (entryp->endTime != 0U) {
            if (currentTime >= entryp->endTime) {
                /* Add random delay? */
                if (clientPtr->callbacks.stop != NULL) {
                    clientPtr->callbacks.stop(clientPtr->cluster.app_cb_arg, &entryp->event);
                }

                /* Send the event status */
                if (entryp->doCancel != 0U) {
                    status = ZCL_DRLC_STATUS_EVENT_CANCELLED;
                }
                else {
                    status = ZCL_DRLC_STATUS_EVENT_COMPLETED;
                }

                zcl_drlc_client_event_send_status(&clientPtr->cluster, entryp->event.issuer_id, status,
                    entryp->event.criticality, &entryp->src);

                /* Remove the event, now that it's done. */
                (void)zcl_drlc_client_event_delete(clientPtr, entryp->event.issuer_id);
            }
            continue;
        }
        if ((entryp->event.start_time == 0U) || (currentTime >= entryp->event.start_time)) {
            /* ! Add random delay? */
            /* Send event-started to DRLC server */
            zcl_drlc_client_event_send_status(&clientPtr->cluster, entryp->event.issuer_id, ZCL_DRLC_STATUS_EVENT_STARTED,
                entryp->event.criticality, &entryp->src);

            /* Start event */
            if (clientPtr->callbacks.start != NULL) {
                if (clientPtr->callbacks.start(clientPtr->cluster.app_cb_arg, &entryp->event)) {
                    /*
                     * Set the end time.  Also lets us know that this
                     * event has been started and also needs to be stopped.
                     */
                    entryp->endTime = currentTime + ((uint32_t)entryp->event.duration * 60U);
                }
            }
        }
    }
    ZbExitCritical(zb);

    /* Check again in one second. */
    ZbTimerReset(clientPtr->timer, 1000);
}

static bool
zcl_drlc_client_event_append(struct cluster_priv_t *clientPtr, struct ZbZclDrlcEventT *eventp,
    unsigned short seqNum, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct ZbZclDrlcEventListElT *entryp;
    struct ZbZclDrlcEventListElT *free_entry = NULL;
    unsigned int i;

    ZbEnterCritical(clientPtr->cluster.zb);

    /* Check for duplicate ID */
    for (i = 0; i < ZCL_DRLC_NUM_EVENTS_MAX; i++) {
        entryp = &clientPtr->eventList[i];
        if (!entryp->valid) {
            if (free_entry == NULL) {
                free_entry = entryp;
            }
            continue;
        }
        if (entryp->event.issuer_id == eventp->issuer_id) {
            ZbExitCritical(clientPtr->cluster.zb);
            /*
             * NOTE: returning true. We may have requested the latest
             * event from the server, so it could be our fault that
             * we're trying to save it again. I.e. instead of the
             * server pushing it on us.
             */
            return true;
        }
    }
    if (free_entry == NULL) {
        ZbExitCritical(clientPtr->cluster.zb);
        return false;
    }
    (void)memcpy(&free_entry->event, eventp, sizeof(struct ZbZclDrlcEventT));
    (void)memcpy(&free_entry->src, &dataIndPtr->src, sizeof(const struct ZbApsAddrT));
    free_entry->valid = true;

    ZbExitCritical(clientPtr->cluster.zb);
    return true;
}

static bool
zcl_drlc_client_event_delete(struct cluster_priv_t *clientPtr, unsigned int issuer_id)
{
    struct ZbZclDrlcEventListElT *entryp;
    unsigned int i;

    ZbEnterCritical(clientPtr->cluster.zb);
    for (i = 0; i < ZCL_DRLC_NUM_EVENTS_MAX; i++) {
        entryp = &clientPtr->eventList[i];
        if (!entryp->valid) {
            continue;
        }
        if (entryp->event.issuer_id == issuer_id) {
            entryp->valid = false;
            ZbExitCritical(clientPtr->cluster.zb);
            return true;
        }
    }
    ZbExitCritical(clientPtr->cluster.zb);
    return false;
}

static struct ZbZclDrlcEventListElT *
zcl_drlc_client_event_find(struct cluster_priv_t *clientPtr, unsigned int issuer_id)
{
    struct ZbZclDrlcEventListElT *entryp;
    unsigned int i;

    ZbEnterCritical(clientPtr->cluster.zb);
    for (i = 0; i < ZCL_DRLC_NUM_EVENTS_MAX; i++) {
        entryp = &clientPtr->eventList[i];
        if (!entryp->valid) {
            continue;
        }
        if (entryp->event.issuer_id == issuer_id) {
            ZbExitCritical(clientPtr->cluster.zb);
            return &clientPtr->eventList[i];
        }
    }
    ZbExitCritical(clientPtr->cluster.zb);
    return NULL;
}

static void
zcl_drlc_client_event_send_status(struct ZbZclClusterT *clusterPtr, unsigned int issuer_id,
    enum ZbZclDrlcEventStatusT event_status, enum ZbZclDrlcCriticalityLevelT criticality,
    const struct ZbApsAddrT *dst)
{
    struct cluster_priv_t *clientPtr = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclDrlcStatusT eventStatus;

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__,
        "Sending REPORT_EVENT_STATUS (id = %d, status = 0x%02x)", issuer_id, event_status);

    /* Build the Load Control Event Status command and send it. */
    (void)memset(&eventStatus, 0, sizeof(struct ZbZclDrlcStatusT));
    eventStatus.issuer_id = issuer_id;
    eventStatus.status = event_status;
    eventStatus.status_time = ZbZclTimeServerCurrentTime(clientPtr->time_server);
    eventStatus.crit_level_applied = criticality;
    eventStatus.cool_setpoint_applied = ZCL_DRLC_COOL_SETPOINT_IGNORED;
    eventStatus.heat_setpoint_applied = ZCL_DRLC_HEAT_SETPOINT_IGNORED;
    eventStatus.avg_load_adj_applied = ZCL_DRLC_AVG_LOAD_ADJ_IGNORED;
    eventStatus.dutycycle_applied = ZCL_DRLC_DUTYCYCLE_IGNORED;
    eventStatus.event_control = 0x00;

    /* Generate the signature */
    /* EXEGIN - signature won't fit in an unfragmented packet. */
    eventStatus.sig_type = ZCL_DRLC_SIGNATURE_TYPE_NONE;
    /* eventStatus.signature[ZCL_DRLC_SIGNATURE_LENGTH]; */

    (void)ZbZclDrlcClientCommandReportStatusReq(&clientPtr->cluster, dst, &eventStatus, NULL, NULL);
}

static enum ZclStatusCodeT
zcl_drlc_client_handle_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *clientPtr = (struct cluster_priv_t *)clusterPtr;
    unsigned int i = 0;
    enum ZclStatusCodeT rc;

    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_CLIENT) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    switch (zclHdrPtr->cmdId) {
        case ZCL_DRLC_COMMAND_EVENT:
        {
            struct ZbZclDrlcEventT event;

            /* Sanity-check the length of the DRLC event */
            if (dataIndPtr->asduLength < ZCL_DRLC_EVENT_MIN_SIZE) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            (void)memset(&event, 0, sizeof(struct ZbZclDrlcEventT));
            event.issuer_id = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            event.device_class = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            event.util_enrol_group = dataIndPtr->asdu[i++];
            event.start_time = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            event.duration = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            /*lint -e{64} -e{9034} "ZbZclDrlcCriticalityLevelT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
            event.criticality = dataIndPtr->asdu[i++];

            /* Optional (fields are still present) */
            event.cool_offset = dataIndPtr->asdu[i++];
            event.heat_offset = dataIndPtr->asdu[i++];
            event.cool_setpoint = (int16_t)pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            event.heat_setpoint = (int16_t)pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            event.avg_load_adj = (int8_t)dataIndPtr->asdu[i++];
            event.dutycycle = dataIndPtr->asdu[i++];
            event.event_control = dataIndPtr->asdu[i++];

            /* Append the new event.  Also include some info about where the
             * request came from so we know where to respond. */
            if (zcl_drlc_client_event_append(clientPtr, &event, zclHdrPtr->seqNum, dataIndPtr) == false) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }

            /* Send the event status */
            /* ! Do this after sending Default Response? */
            zcl_drlc_client_event_send_status(clusterPtr, event.issuer_id, ZCL_DRLC_STATUS_EVENT_RECEIVED,
                event.criticality, &dataIndPtr->src);
            ZbTimerReset(clientPtr->timer, 0);

            rc = ZCL_STATUS_SUCCESS;
            break;
        }

        case ZCL_DRLC_COMMAND_CANCEL_EVENT:
        {
            struct ZbZclDrlcEventListElT *entry;
            struct ZbZclDrlcCancelT cancel;
            enum ZbZclDrlcEventStatusT event_status;
            enum ZbZclDrlcCriticalityLevelT criticality = ZCL_DRLC_CRITICALITY_INVALID;
            uint32_t effectiveTime;

            /* Sanity-check the length of the DRLC cancel */
            if (dataIndPtr->asduLength < ZCL_DRLC_CANCEL_MIN_SIZE) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }

            (void)memset(&cancel, 0, sizeof(struct ZbZclDrlcCancelT));
            cancel.issuer_id = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            cancel.device_class = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            cancel.util_enrol_group = dataIndPtr->asdu[i++];
            cancel.cancel_control = dataIndPtr->asdu[i++];
            effectiveTime = pletoh32(&dataIndPtr->asdu[i]);

            if (effectiveTime != 0U) {
                /* Effective Time is deprecated, and only 'now' is supported */
                return ZCL_STATUS_UNSUPP_ATTRIBUTE;
            }

            entry = zcl_drlc_client_event_find(clientPtr, cancel.issuer_id);
            if (entry == NULL) {
                event_status = ZCL_DRLC_STATUS_RJCTD;
            }
            else {
                /* Save the criticality level */
                criticality = entry->event.criticality;
                if (entry->endTime != 0U) {
                    /* Set the stop time to now. */
                    entry->doCancel = 1;
                    entry->endTime = ZbZclTimeServerCurrentTime(clientPtr->time_server);
                    /* The thread will send the event, so we're done. */
                    return ZCL_STATUS_SUCCESS;
                }
                else {
                    /* The event has not started, so just remove it. */
                    if (zcl_drlc_client_event_delete(clientPtr, entry->event.issuer_id)) {
                        event_status = ZCL_DRLC_STATUS_EVENT_CANCELLED;
                    }
                    else {
                        event_status = ZCL_DRLC_STATUS_RJCTD;
                    }
                }
            }

            /* ! Do this after sending Default Response? */
            zcl_drlc_client_event_send_status(clusterPtr, cancel.issuer_id, event_status,
                criticality, &dataIndPtr->src);

            rc = ZCL_STATUS_SUCCESS;
            break;
        }

        case ZCL_DRLC_COMMAND_CANCEL_ALL:
        {
            unsigned char cancelControl;

            /* Sanity-check the length of the DRLC cancel all */
            if (dataIndPtr->asduLength < 1U) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }

            cancelControl = dataIndPtr->asdu[i++];
            if ((cancelControl & ZCL_DRLC_CANCEL_CONTROL_GRACEFUL) != 0U) {
                /* ignored */
            }

            ZbEnterCritical(clientPtr->cluster.zb);
            for (i = 0; i < ZCL_DRLC_NUM_EVENTS_MAX; i++) {
                uint32_t issuer_id;
                enum ZbZclDrlcEventStatusT event_status;
                enum ZbZclDrlcCriticalityLevelT criticality = ZCL_DRLC_CRITICALITY_INVALID;
                struct ZbZclDrlcEventListElT *entryp = &clientPtr->eventList[i];

                if (!entryp->valid) {
                    continue;
                }

                /* Check if the event has been started */
                issuer_id = entryp->event.issuer_id;
                if (entryp->endTime != 0U) {
                    /* Set the stop time to now. */
                    entryp->doCancel = 1;
                    entryp->endTime = ZbZclTimeServerCurrentTime(clientPtr->time_server);
                    /* Thread will send the event. */
                    continue;
                }

                /* The event has not started, so just remove it off the list. */
                criticality = entryp->event.criticality;
                if (zcl_drlc_client_event_delete(clientPtr, issuer_id)) {
                    event_status = ZCL_DRLC_STATUS_EVENT_CANCELLED;
                }
                else {
                    event_status = ZCL_DRLC_STATUS_RJCTD;
                }

                /* Send the event status */
                /* ! Do this after sending Default Response? */
                zcl_drlc_client_event_send_status(clusterPtr, issuer_id, event_status,
                    criticality, &dataIndPtr->src);
            }
            ZbExitCritical(clusterPtr->zb);

            rc = ZCL_STATUS_SUCCESS;
            break;
        }

        default:
            rc = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return rc;
}

static unsigned int
zcl_drlc_client_report_status_build(struct ZbZclDrlcStatusT *statusPtr, uint8_t *payload, unsigned int maxlen)
{
    unsigned int length = 0;

    if ((length + 18U) > maxlen) {
        return 0;
    }
    putle32(&payload[length], statusPtr->issuer_id);
    length += 4U;
    payload[length++] = (uint8_t)statusPtr->status;
    putle32(&payload[length], statusPtr->status_time);
    length += 4U;
    payload[length++] = (uint8_t)statusPtr->crit_level_applied;
    putle16(&payload[length], statusPtr->cool_setpoint_applied);
    length += 2U;
    putle16(&payload[length], statusPtr->heat_setpoint_applied);
    length += 2U;
    payload[length++] = (uint8_t)statusPtr->avg_load_adj_applied;
    payload[length++] = statusPtr->dutycycle_applied;
    payload[length++] = (uint8_t)statusPtr->sig_type;
    payload[length++] = statusPtr->event_control;
    if (statusPtr->sig_type != ZCL_DRLC_SIGNATURE_TYPE_NONE) {
        if ((length + ZCL_DRLC_SIGNATURE_LENGTH) > maxlen) {
            return 0;
        }
        (void)memcpy(&payload[length], statusPtr->sig_data, ZCL_DRLC_SIGNATURE_LENGTH);
        length += ZCL_DRLC_SIGNATURE_LENGTH;
    }
    return length;
}

enum ZclStatusCodeT
ZbZclDrlcClientCommandReportStatusReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDrlcStatusT *statusPtr, void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length;
    struct ZbZclClusterCommandReqT req;

    /* EXEGIN - signature won't fit in an unfragmented packet.
     * Must increase size of payload. */
    if (statusPtr->sig_type != ZCL_DRLC_SIGNATURE_TYPE_NONE) {
        return ZCL_STATUS_FAILURE;
    }

    /* Build the payload */
    length = zcl_drlc_client_report_status_build(statusPtr, payload, sizeof(payload));

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLC_COMMAND_REPORT_EVENT_STATUS;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReqDelayed(cluster, &req, ZB_NWK_RSP_DELAY_DEFAULT, callback, arg);
}

enum ZclStatusCodeT
ZbZclDrlcClientCommandGetEventsReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDrlcGetEventsReqT *cmd_req, void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    putle32(&payload[length], cmd_req->start_time);
    length += 4U;
    payload[length++] = cmd_req->num_events;
    if (cmd_req->issuer_id != ZCL_DRLC_ISSUER_ID_INVALID) {
        putle32(&payload[length], cmd_req->issuer_id);
        length += 4U;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLC_COMMAND_GET_SCHEDULED_EVENTS;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

unsigned int
ZbZclDrlcClientGetEventList(struct ZbZclClusterT *cluster, struct ZbZclDrlcEventT *eventList, unsigned int maxEntries)
{
    struct cluster_priv_t *clientPtr = (struct cluster_priv_t *)cluster;
    struct ZbZclDrlcEventListElT *entryp;
    unsigned int i, eventListSz = 0;

    ZbEnterCritical(clientPtr->cluster.zb);
    for (i = 0; i < ZCL_DRLC_NUM_EVENTS_MAX; i++) {
        entryp = &clientPtr->eventList[i];
        if (!entryp->valid) {
            continue;
        }
        if (eventListSz == maxEntries) {
            break;
        }
        (void)memcpy(&eventList[eventListSz], &entryp->event, sizeof(struct ZbZclDrlcEventT));
        eventListSz++;
    }
    ZbExitCritical(cluster->zb);
    return eventListSz;
}
