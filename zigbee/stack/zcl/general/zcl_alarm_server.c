/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.alarm.h"
#include "zcl/general/zcl.time.h"

/* Alarm log entry. */
struct ZbZclAlarmLogT {
    uint8_t alarmCode;
    uint16_t clusterId;
    uint32_t timeStamp;
};

struct ZbZclAlarmT {
    /* Internal - for linking. */
    struct ZbZclAlarmT *next;
    struct ZbZclAlarmT *prev;
    /* Alarm information. */
    uint8_t masked;
    uint8_t alarmCode;
    uint16_t clusterId;
    /* Callback functions for manual-reset. */
    int (*reset)(void *);
    void *arg;
};

/* Alarm cluster */
struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
    struct ZbZclClusterT *time_server;
    struct ZbApsFilterT *loopback_filter;

    /* Alarm Log */
    unsigned int logSize;
    unsigned int logEntries;
    unsigned int logStart;
    struct ZbZclAlarmLogT *logList;
    /* logList memory follows directly after this struct */
};

static enum ZclStatusCodeT zcl_attr_read_cb(struct ZbZclClusterT *clusterPtr, uint16_t attributeId,
    uint8_t *data, unsigned int maxlen, void *app_cb_arg);

static enum ZclStatusCodeT
zcl_attr_cb(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrCbInfoT *cb)
{
    if (cb->type == ZCL_ATTR_CB_TYPE_READ) {
        return zcl_attr_read_cb(clusterPtr, cb->info->attributeId, cb->zcl_data, cb->zcl_len, cb->app_cb_arg);
    }
    else {
        return ZCL_STATUS_FAILURE;
    }
}

/* Attributes */
static const struct ZbZclAttrT zcl_alarm_server_attr_list[] = {
    /* Alarm Attributes */
    /* ZCL 8 Section 3.11.2.2.1 Table 3-65 is uint16 but only has the range of a uint8, this may be an editorial error */
    {
        ZCL_ALARM_ATTR_COUNT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_CB_READ, 0, zcl_attr_cb, {0, 0xFF}, {0, 0}
    },
};

static enum ZclStatusCodeT alarm_command(struct ZbZclClusterT *, struct ZbZclHeaderT *, struct ZbApsdeDataIndT *);
static void alarm_server_cleanup(struct ZbZclClusterT *clusterPtr);

/* Alarm helper functions. */
static void alarm_log_insert(struct cluster_priv_t *, uint8_t, uint16_t, uint32_t);

/* Allocates an alarm cluster.
 *      IMPORTANT NOTE: the alarm server cluster must be on both the endpoint in and out lists
 *      because it receives alarms loopback from other clusters on the same endpoint */
struct ZbZclClusterT *
ZbZclAlarmServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, uint16_t logSize, struct ZbZclClusterT *time_server)
{
    struct cluster_priv_t *alarm_server;
    uint16_t profile_id;

    if (time_server == NULL) {
        return NULL;
    }

    /* Allocate enough memory for the cluster and the logList table */
    alarm_server = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t) + (logSize * sizeof(struct ZbZclAlarmLogT)),
            ZCL_CLUSTER_ALARMS, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (alarm_server == NULL) {
        return NULL;
    }
    alarm_server->cluster.command = alarm_command;
    alarm_server->cluster.cleanup = alarm_server_cleanup;

    alarm_server->time_server = time_server;
    alarm_server->logSize = logSize;
    alarm_server->logEntries = 0;
    alarm_server->logStart = 0;
    /* Assign the logList table memory to be immediately after the cluster memory. */
    alarm_server->logList = (struct ZbZclAlarmLogT *)(alarm_server + 1U);

    profile_id = ZbApsEndpointProfile(zb, endpoint);
    if (profile_id == ZCL_PROFILE_WILDCARD) {
        profile_id = ZCL_PROFILE_HOME_AUTOMATION;
    }

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&alarm_server->cluster, zcl_alarm_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_alarm_server_attr_list))) {
        ZbZclClusterFree(&alarm_server->cluster);
        return NULL;
    }

    ZbZclAttrIntegerWrite(&alarm_server->cluster, ZCL_ALARM_ATTR_COUNT, 0);

    /* Binds the cluster to the endpoint and creates a filter to receive APS messages
     * from the stack. */
    (void)ZbZclClusterAttach(&alarm_server->cluster);

    /* Create a loopback binding so we can receive ZCL_ALARM_COMMAND_ALARM commands sent
     * from Server to Client (ZbZclClusterSendAlarm). Commands are also processed by alarm_command() */
    alarm_server->loopback_filter = ZbZclClusterReverseBind(&alarm_server->cluster);
    return &alarm_server->cluster;
}

static void
alarm_server_cleanup(struct ZbZclClusterT *clusterPtr)
{
    struct cluster_priv_t *alarm_server = (struct cluster_priv_t *)clusterPtr;

    if (alarm_server->loopback_filter != NULL) {
        ZbZclClusterReverseUnbind(clusterPtr, alarm_server->loopback_filter);
        alarm_server->loopback_filter = NULL;
    }
    /* NOTE: logList memory is allocated with cluster, so isn't freed here. */
}

static enum ZclStatusCodeT
zcl_attr_read_cb(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, uint8_t *data, unsigned int maxlen, void *app_cb_arg)
{
    struct cluster_priv_t *alarm_server = (struct cluster_priv_t *)clusterPtr;

    switch (attributeId) {
        case ZCL_ALARM_ATTR_COUNT:
            if (maxlen < 2) {
                return ZCL_STATUS_INSUFFICIENT_SPACE;
            }
            putle16(data, alarm_server->logEntries);
            return ZCL_STATUS_SUCCESS;

        default:
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
}

static void
alarm_log_insert(struct cluster_priv_t *alarm_server, uint8_t code, uint16_t clusterId, uint32_t timestamp)
{
    unsigned int i;
    uint16_t alarm_count;
    enum ZclDataTypeT attr_type;
    enum ZclStatusCodeT attr_status;

    /* Check if logging is enabled. */
    if (alarm_server->logSize == 0) {
        return;
    }

    /* Write the new log entry (overwrite the oldest entry if the table is full). */
    i = (alarm_server->logStart + alarm_server->logEntries) % alarm_server->logSize;
    alarm_server->logList[i].alarmCode = code;
    alarm_server->logList[i].clusterId = clusterId;
    alarm_server->logList[i].timeStamp = timestamp;

    /* Increment the number of alarms if there is space in the table. */
    if (alarm_server->logEntries < alarm_server->logSize) {
        alarm_server->logEntries++;
    }
    /* Or just advance the head index if there wasn't space. */
    else if (++(alarm_server->logStart) >= alarm_server->logSize) {
        alarm_server->logStart = 0;
    }

    attr_type = ZCL_DATATYPE_UNSIGNED_16BIT;
    alarm_count = (uint16_t)ZbZclAttrIntegerRead(&alarm_server->cluster, (uint16_t)ZCL_ALARM_ATTR_COUNT, &attr_type, &attr_status);

    if (attr_status) {
        ZCL_LOG_PRINTF(alarm_server->cluster.zb, __func__, "internal read alarm count failed: 0x%02x", attr_status);
    }
    alarm_count++;
    ZbZclAttrIntegerWrite(&alarm_server->cluster, ZCL_ALARM_ATTR_COUNT, alarm_count);
}

static enum ZclStatusCodeT
alarm_command(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zcl_hdr, struct ZbApsdeDataIndT *data_ind)
{
    struct cluster_priv_t *alarm_server = (struct cluster_priv_t *)cluster;
    enum ZclStatusCodeT status;

    if (ZbApsAddrIsBcast(&data_ind->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    if (zcl_hdr->frameCtrl.direction == ZCL_DIRECTION_TO_CLIENT) {
        /* Only handle locally reflected alarm commands (i.e. from
         * ZbZclClusterSendAlarm). We are not going to process actual
         * Alarms Commands sent to an Alarms Client here. */

        if (!ZbApsAddrIsLocal(cluster->zb, &data_ind->src)) {
            ZCL_LOG_PRINTF(cluster->zb, __func__, "Dropping client command 0x%02x, not from us", zcl_hdr->cmdId);
            return ZCL_STATUS_UNSUPP_COMMAND;
        }

        ZCL_LOG_PRINTF(cluster->zb, __func__, "Handling reflected command 0x%02x", zcl_hdr->cmdId);

        switch (zcl_hdr->cmdId) {
            case ZCL_ALARM_COMMAND_ALARM:
            {
                uint8_t alarm_code;
                uint16_t cluster_id;
                struct ZbZclClusterCommandReqT req;
                uint32_t timestamp;

                if (data_ind->asduLength < 3) {
                    status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }

                timestamp = ZbZclTimeServerCurrentTime(alarm_server->time_server);

                /* Add to alarm log table */
                alarm_code = data_ind->asdu[0];
                cluster_id = pletoh16(&data_ind->asdu[1]);
                alarm_log_insert(alarm_server, alarm_code, cluster_id, timestamp);

                /* Reflect Alarm Command to binding with same payload */
                (void)memset(&req, 0, sizeof(req));
                req.dst = *ZbApsAddrBinding;
                req.cmdId = ZCL_ALARM_COMMAND_ALARM;
                req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
                req.payload = data_ind->asdu;
                req.length = data_ind->asduLength;
                ZCL_LOG_PRINTF(cluster->zb, __func__, "Sending ALARM command to any bindings");
                (void)ZbZclClusterCommandReq(cluster, &req, NULL, NULL);
                status = ZCL_STATUS_SUCCESS;
                break;
            }

            default:
                status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
        }
    }
    else {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Received server command 0x%02x", zcl_hdr->cmdId);

        switch (zcl_hdr->cmdId) {
            case ZCL_ALARM_COMMAND_RESET:
                /* We will get here only if no clusters have registered to receive this command
                 * (ZbZclClusterRegisterAlarmResetHandler and zcl_cluster_alarm_data_ind).
                 * Just return SUCCESS. */
                status = ZCL_STATUS_SUCCESS;
                break;

            case ZCL_ALARM_COMMAND_RESET_ALL:
                /* We will get here only if no clusters have registered to receive this command
                 * (ZbZclClusterRegisterAlarmResetHandler and zcl_cluster_alarm_data_ind).
                 * Just return SUCCESS. */
                status = ZCL_STATUS_SUCCESS;
                break;

            case ZCL_ALARM_COMMAND_GET:
            {
                uint16_t alarm_count;
                enum ZclDataTypeT attr_type;
                enum ZclStatusCodeT attr_status;
                uint8_t rawbuf[ZCL_HEADER_MAX_SIZE + 8];
                int i = 0;

                /* Build the get alarms response command. */
                if (alarm_server->logEntries) {
                    struct ZbZclAlarmLogT *log = &alarm_server->logList[alarm_server->logStart];
                    /* An alarm exist in the log. */
                    rawbuf[i++] = ZCL_STATUS_SUCCESS;
                    rawbuf[i++] = log->alarmCode;
                    putle16(&rawbuf[i], log->clusterId);
                    i += 2;
                    putle32(&rawbuf[i], log->timeStamp);
                    i += 4;

                    /* Remove this alarm from the log. */
                    alarm_server->logEntries--;
                    if (++(alarm_server->logStart) >= alarm_server->logSize) {
                        alarm_server->logStart = 0;
                    }
                }
                else {
                    /* The alarm log is empty. */
                    rawbuf[i++] = ZCL_STATUS_NOT_FOUND;
                }

                /* Send the response */
                ZbZclSendClusterStatusResponse(cluster, data_ind, zcl_hdr, ZCL_ALARM_COMMAND_GET_RESPONSE, rawbuf, i, false);

                /* Update the alarm count */
                attr_type = ZCL_DATATYPE_UNSIGNED_16BIT;
                alarm_count = (uint16_t)ZbZclAttrIntegerRead(&alarm_server->cluster, (uint16_t)ZCL_ALARM_ATTR_COUNT, &attr_type, &attr_status);

                if (!attr_status) {
                    ZCL_LOG_PRINTF(cluster->zb, __func__, "internal read alarm count failed: 0x%02x", attr_status);
                }
                alarm_count--;
                ZbZclAttrIntegerWrite(&alarm_server->cluster, ZCL_ALARM_ATTR_COUNT, alarm_count);

                /* We sent a response already */
                status = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
                break;
            }

            case ZCL_ALARM_COMMAND_RESET_LOG:
                /* Clear the alarms table. */
                alarm_server->logEntries = 0;
                alarm_server->logStart = 0;

                /* reset the count attribute */
                ZbZclAttrIntegerWrite(&alarm_server->cluster, ZCL_ALARM_ATTR_COUNT, 0);

                /* Return a Default Response with SUCCESS */
                status = ZCL_STATUS_SUCCESS;
                break;

            default:
                status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
        }
    }
    return status;
}
