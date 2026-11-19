/* Copyright [2009 - 2023] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl_attr.h"
#include "zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */
#include "ieee802154_crc.h"

/* EXEGIN - add log levels/mask to ZCL_LOG_PRINTF? */
/* #define COND_ZCL_REPORT_VERBOSE_LOGGING */

/* Attribute ID (2) + Data Type (1) */
#define ZCL_ATTR_REPORT_HDR_LEN             3U

/* Maximum time for the timer to sleep. This time is based on that the most a
 * sleepy device that's doing reporting should go to sleep for is on the order
 * of 30-60 minutes typically.  */
#define ZCL_ATTR_REPORT_MAX_TIMEOUT         3600000U /* 1 hour */

/* The time range to use to group multiple reports into a single ZCL report command.
 * If an attribute report will timeout within this time of another attribute report,
 * then group both of them into a single report that is sent at the earlier of the
 * two times. */
#define ZCL_ATTR_REPORT_SLACK_TIME          1000U /* 1 second */

/* This time serves two purposes:
 *  1. To add some delay after an attribute is modified from an over-the-air write,
 *     to prevent creating contention and packet collisions (usually with an APS ACK).
 *  2. To group attribute reports if a bunch are modified at the same time or close
 *     to one another. */
#define ZCL_ATTR_REPORT_CHANGE_DELAY        200U /* 200 mS, e.g. ZB_NWK_RSP_DELAY_DEFAULT */

/* A 32-bit attribute value requires 7 octets in the report payload.
 * Best case unfragmented APS payload is ZB_APS_CONST_MAX_PAYLOAD_SIZE (82).
 * Worst case payload size is ZCL_PAYLOAD_UNFRAG_SAFE_SIZE (54)
 * ZCL Report Command header is 3 bytes.
 * Assuming if all attributes are 32-bit values, this gives a best case of
 * (82 - 3) / 7 = 11 entries */
#define ZCL_ATTR_REPORT_MAX_ATTRS           12U /* Actual number may be less based on attribute value lengths */

/* Let's just be safe and use ZCL_PAYLOAD_UNFRAG_SAFE_SIZE. */
#define ZCL_ATTR_REPORT_MAX_PAYLOAD         ZCL_PAYLOAD_UNFRAG_SAFE_SIZE /* 54 */

struct ZbZclReportT {
    struct LinkListT link;
    struct ZbZclClusterT *cluster;
    uint16_t attributeId;
    enum ZclDataTypeT dataType;
    ZbUptimeT last_report_time;

    /* Reporting Information */
    union {
        long long integer;
        double floating;
        uint16_t hash;
    } last_value;

    /* Reporting Intervals */
    uint16_t min_interval; /* in seconds. */
    uint16_t max_interval; /* in seconds. */
    uint16_t default_min_interval; /* in seconds. */
    uint16_t default_max_interval; /* in seconds. */

    /* Reportable Change */
    double change;
    double default_change;
};

/* Attribute report info entry for sending reports. Contains the
 * attribute information and current value to be included in the report. */
struct zcl_report_attr_info_t {
    uint16_t attr_id;
    uint8_t *attr_data;
    uint8_t attr_len;
    uint8_t hdr_buf[ZCL_ATTR_REPORT_HDR_LEN];
};

static struct ZbZclReportT * zcl_reporting_find(struct ZbZclClusterT *cluster,
    uint16_t attributeId, enum ZbZclReportDirectionT direction);

static struct ZbZclReportT * zcl_reporting_create_new(struct ZbZclClusterT *cluster, struct ZbZclReportT *info);
static void zcl_reporting_delete(struct ZbZclReportT *report);
static void zcl_reporting_disable(struct ZbZclReportT *report);
static void zcl_reporting_reset_defaults(struct ZigBeeT *zb, struct ZbZclReportT *report, bool reset_timer);

static int zcl_append_report_config_record(struct ZbZclAttrReportConfigRecordT *record,
    uint8_t *payload, unsigned int max_len);

static void zcl_reporting_send_report(struct ZbZclClusterT *cluster, struct zcl_report_attr_info_t *info_list);

/* For debugging */
static void
zcl_reporting_send_conf(struct ZbApsdeDataConfT *conf, void *arg)
{
    struct ZigBeeT *zb = arg;

    if (conf->status != ZB_STATUS_SUCCESS) {
        if (conf->status == ZB_APS_STATUS_INVALID_BINDING) {
            /* ZCL_LOG_PRINTF(zb, __func__, "Error, send failed (no APS binding)"); */
        }
        else if (conf->status == ZB_APS_STATUS_ILLEGAL_REQUEST) {
            /* ZCL_LOG_PRINTF(zb, __func__, "Error, send failed (not started?)"); */
        }
        else {
            ZCL_LOG_PRINTF(zb, __func__, "Error, send failed (status = 0x%02x)", conf->status);
        }
    }
}

struct report_command_delay_t {
    struct ZbZclClusterT *cluster;
    struct ZbTimerT *timer;
    struct zcl_report_attr_info_t info_list[ZCL_ATTR_REPORT_MAX_ATTRS];
};

static void
report_command_timer(struct ZigBeeT *zb, void *arg)
{
    struct report_command_delay_t *info = arg;

    zcl_reporting_send_report(info->cluster, info->info_list);
    ZbTimerFree(info->timer);
    ZbHeapFree(info->cluster->zb, info);
}

static bool
zcl_reporting_queue_report(struct ZbZclClusterT *cluster, struct zcl_report_attr_info_t *info_list, unsigned int delay)
{
    if (delay == 0U) {
        zcl_reporting_send_report(cluster, info_list);
    }
    else {
        struct report_command_delay_t *info;

        info = ZbHeapAlloc(cluster->zb, sizeof(struct report_command_delay_t));
        if (info == NULL) {
            return false;
        }
        (void)memset(info, 0, sizeof(struct report_command_delay_t));
        info->timer = ZbTimerAlloc(cluster->zb, report_command_timer, info);
        if (info->timer == NULL) {
            ZbHeapFree(cluster->zb, info);
            return false;
        }
        info->cluster = cluster;
        (void)memcpy(&info->info_list, info_list, sizeof(struct zcl_report_attr_info_t) * ZCL_ATTR_REPORT_MAX_ATTRS);
        ZbTimerReset(info->timer, delay);
    }
    return true;
}

static void
zcl_reporting_send_report(struct ZbZclClusterT *cluster, struct zcl_report_attr_info_t *info_list)
{
    struct ZbZclHeaderT hdr;
    struct ZbApsdeDataReqT dataReq;
    struct ZbApsBufT bufv[1 + (2 * ZCL_ATTR_REPORT_MAX_ATTRS)]; /* ZCL Header | [Report Header | Report Payload] ... */
    uint8_t num_bufv = 0;
    uint8_t zclHdrBuf[ZCL_HEADER_MAX_SIZE];
    int zclHdrLen;
    enum ZbStatusCodeT status;
    unsigned int i;

    /* Build the report attributes command. */
    hdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    hdr.frameCtrl.manufacturer = (cluster->mfrCode != 0U) ? 1U : 0U;
    hdr.manufacturerCode = cluster->mfrCode;
    if (cluster->direction == ZCL_DIRECTION_TO_SERVER) {
        hdr.frameCtrl.direction = ZCL_DIRECTION_TO_CLIENT;
    }
    else {
        hdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
    }

    hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    hdr.seqNum = ZbZclGetNextSeqnum();
    hdr.cmdId = ZCL_COMMAND_REPORT;
    zclHdrLen = ZbZclAppendHeader(&hdr, zclHdrBuf, ZCL_HEADER_MAX_SIZE);
    if (zclHdrLen <= 0) {
        goto EXIT_FUNC;
    }

    /* Configure the APS buffers */
    bufv[num_bufv].data = zclHdrBuf;
    bufv[num_bufv].len = (uint8_t)zclHdrLen;
    num_bufv++;

    for (i = 0; i < ZCL_ATTR_REPORT_MAX_ATTRS; i++) {
        if (info_list[i].attr_len == 0) {
            break;
        }
        bufv[num_bufv].data = info_list[i].hdr_buf;
        bufv[num_bufv].len = ZCL_ATTR_REPORT_HDR_LEN;
        num_bufv++;
        bufv[num_bufv].data = info_list[i].attr_data;
        bufv[num_bufv].len = info_list[i].attr_len;
        num_bufv++;
    }

    /* Transmit the report attributes command. */
    ZbZclClusterInitApsdeReq(cluster, &dataReq, NULL);
    dataReq.dst = *ZbApsAddrBinding;
    dataReq.txOptions |= ZB_APSDE_DATAREQ_TXOPTIONS_VECTOR;
    dataReq.discoverRoute = true;
    dataReq.radius = 0;
    dataReq.asdu = bufv;
    dataReq.asduLength = num_bufv;

    status = ZbApsdeDataReqCallback(cluster->zb, &dataReq, zcl_reporting_send_conf, cluster->zb);
    if (status != ZB_APS_STATUS_SUCCESS) {
        struct ZbApsdeDataConfT dataConf;

        (void)memset(&dataConf, 0, sizeof(dataConf));
        dataConf.status = status;
        zcl_reporting_send_conf(&dataConf, cluster->zb);
        goto EXIT_FUNC;
    }

EXIT_FUNC:
    /* Free the attribute data values */
    for (i = 0; i < ZCL_ATTR_REPORT_MAX_ATTRS; i++) {
        if (info_list[i].attr_data == NULL) {
            break;
        }
        ZbHeapFree(cluster->zb, info_list[i].attr_data);
        info_list[i].attr_data = NULL;
        info_list[i].attr_len = 0;
    }
}

/* Returns the lesser of either next_timeout or check_time */
static unsigned int
zcl_report_check_time(unsigned int next_timeout, unsigned int check_time)
{
    return (check_time < next_timeout) ? check_time : next_timeout;
}

static bool
zcl_report_kick(struct ZbZclClusterT *cluster, unsigned int delay)
{
    if (cluster->reports.timer == NULL) {
        return false;
    }
    if (cluster->reports.kicked) {
        /* Already kicked. Don't keep kicking, otherwise report timer may never run
         * if an attribute is constantly changing. */
        return true;
    }
    cluster->reports.kicked = true;
    ZbTimerReset(cluster->reports.timer, delay);
    return true;
}

enum ZclStatusCodeT
ZbZclAttrReportKick(struct ZbZclClusterT *cluster, bool send_all,
    void (*callback)(struct ZbZclClusterT *cluster, unsigned int next_timeout, void *arg), void *arg)
{
    if (cluster->reports.callback != NULL) {
        /* Already active */
        return ZCL_STATUS_FAILURE;
    }
    cluster->reports.send_all = send_all;
    cluster->reports.callback = callback;
    cluster->reports.arg = arg;
    if (!zcl_report_kick(cluster, 0U)) {
        cluster->reports.callback = NULL;
        cluster->reports.arg = NULL;
        return ZCL_STATUS_FAILURE;
    }
    return ZCL_STATUS_SUCCESS;
}

static bool
zcl_report_append_attr(struct ZigBeeT *zb, struct zcl_report_attr_info_t *entry,
    uint16_t attr_id, uint8_t attr_type, uint8_t *attr_data, int attr_len)
{
    /* Make a copy of the attribute data to include in the report.
     * NOTE: this memory is freed in zcl_reporting_send_report */
    entry->attr_data = ZbHeapAlloc(zb, attr_len);
    if (entry->attr_data == NULL) {
        return false;
    }
    (void)memcpy(entry->attr_data, attr_data, attr_len);
    entry->attr_len = attr_len;
    entry->attr_id = attr_id;

    /* Report Header */
    putle16(&entry->hdr_buf[0], attr_id);
    entry->hdr_buf[2] = attr_type;
    return true;
}

static bool
zcl_cluster_report_check_timeout(struct ZbZclClusterT *cluster, unsigned int uptime)
{
    struct LinkListT *p;
    struct ZbZclReportT *report;
    unsigned int check_time;

    if (LINK_LIST_HEAD(&cluster->reports.list) == NULL) {
        return false;
    }

    LINK_LIST_FOREACH(p, &cluster->reports.list) {
        report = LINK_LIST_ITEM(p, struct ZbZclReportT, link);
        if (report->max_interval == ZCL_ATTR_REPORT_MAX_INTVL_DISABLE) {
            /* This report is disabled */
            continue;
        }
        /* Check if minimum reporting interval has been reached.
         * Don't send report until then. */
        if (report->min_interval != ZCL_ATTR_REPORT_MIN_INTVL_DISABLE) {
            check_time = report->last_report_time + (report->min_interval * 1000U);
            check_time = ZbTimeoutRemaining(uptime, check_time);
            if (check_time > 0) {
                /* Hasn't timed-out yet */
                continue;
            }
        }

        if (report->max_interval == ZCL_ATTR_REPORT_MAX_INTVL_CHANGE) {
            continue;
        }
        check_time = report->last_report_time + (report->max_interval * 1000U);
        check_time = ZbTimeoutRemaining(uptime, check_time);
        if (check_time > 0) {
            /* Hasn't timed-out yet */
            continue;
        }
        /* This report has timed-out */
        return true;
    }
    return false;
}

/* The reporting ZbTimer callback */
void
zcl_cluster_reports_timer(struct ZigBeeT *zb, void *arg)
{
    struct ZbZclClusterT *cluster = arg;
    struct LinkListT *p;
    struct ZbZclReportT *report;
    uint8_t *attr_data = NULL;
    int attr_len = 0;
    enum ZclDataTypeT attr_type;
    unsigned int next_timeout = ZCL_ATTR_REPORT_MAX_TIMEOUT, check_time;
    unsigned int up_time, compare_time;
    unsigned int max_intvl_timeout;
    struct zcl_report_attr_info_t info_list[ZCL_ATTR_REPORT_MAX_ATTRS];
    uint8_t num_attrs, total_rpt_len;
    uint8_t total_attrs = 0U;
    unsigned int send_delay = 0U;
    bool send_all = cluster->reports.send_all;
    uint8_t disable_periodic_timers = 0U;

    cluster->reports.kicked = false;
    cluster->reports.send_all = false;

    if (LINK_LIST_HEAD(&cluster->reports.list) == NULL) {
        /* No reports. */
        goto EXIT_FUNC;
    }

    up_time = ZbZclUptime(zb);

    /* Check if we should try to group reports that are about to timeout close together.
     * This is allowed by the ZCL Spec, and encouraged to save on traffic. */
    if (zcl_cluster_report_check_timeout(cluster, up_time)) {
        /* A report has timed-out. Adjust the timeout time to include others that are
         * close to timing out. */
        compare_time = up_time + ZCL_ATTR_REPORT_SLACK_TIME;
    }
    else {
        compare_time = up_time;
    }

    (void)memset(info_list, 0, sizeof(info_list));
    num_attrs = 0;
    total_rpt_len = 0;

    /* Loop through all the reports on this cluster */
    LINK_LIST_FOREACH(p, &cluster->reports.list) {
        bool send_report = send_all;

        max_intvl_timeout = ZCL_ATTR_REPORT_MAX_TIMEOUT;

        report = LINK_LIST_ITEM(p, struct ZbZclReportT, link);
        if (report->max_interval == ZCL_ATTR_REPORT_MAX_INTVL_DISABLE) {
            /* This report is disabled */
            continue;
        }

        /* Check if minimum reporting interval has been reached. Don't send report until then. */
        if (!send_all && (report->min_interval != ZCL_ATTR_REPORT_MIN_INTVL_DISABLE)) {
            check_time = report->last_report_time + (report->min_interval * 1000U);
            check_time = ZbTimeoutRemaining(compare_time, check_time);
            if (check_time > 0) {
                /* Hasn't timed-out yet */
                next_timeout = zcl_report_check_time(next_timeout, check_time);
                continue;
            }
        }

        /* Check if maximum reporting interval has been reached.
         * If using maximum reporting interval, then even if no change, send a report */
        if (!send_all && (report->max_interval != ZCL_ATTR_REPORT_MAX_INTVL_CHANGE)) {
            max_intvl_timeout = report->last_report_time + (report->max_interval * 1000U);
            max_intvl_timeout = ZbTimeoutRemaining(compare_time, max_intvl_timeout);
            if (max_intvl_timeout == 0) {
                send_report = true;
                /* Save the last reporting time */
                report->last_report_time = up_time;
            }
        }

        /* Check if a binding exists. If not, there's no point in checking if the attribute changed. */
        if (!ZbApsBindSrcExists(zb, cluster->endpoint, cluster->clusterId)) {
            /* ZCL_LOG_PRINTF(zb, __func__, "Skipping report, no binding (cl = 0x%04x (%s), attr = 0x%04x)",
                ZbZclClusterGetClusterId(cluster), ZbZclClusterGetDirectionStr(cluster), report->attributeId); */
            next_timeout = zcl_report_check_time(next_timeout, max_intvl_timeout);
            continue;
        }

        /* We can get here if the attribute has timed-out or we want to check if
         * it has changed. Either way, we need to read the attribute value. */
        do {
            /* Allocate a buffer for the read data. Only do this once.
             * Freed at the end of this function. */
            if (attr_data == NULL) {
                attr_data = ZbHeapAlloc(zb, ZCL_ATTRIBUTE_BUFFER_SIZE_MAX);
                if (attr_data == NULL) {
                    /* Memory exhausted. */
                    goto EXIT_FUNC;
                }
            }

            /* Read the current attribute value. */
            if (ZbZclAttrRead(cluster, report->attributeId, &attr_type, attr_data,
                    ZCL_ATTRIBUTE_BUFFER_SIZE_MAX, false) != ZCL_STATUS_SUCCESS) {
                ZCL_LOG_PRINTF(zb, __func__, "Error trying to read attribute value (cl = 0x%04x (%s), attr = 0x%04x)",
                    ZbZclClusterGetClusterId(cluster), ZbZclClusterGetDirectionStr(cluster), report->attributeId);
                zcl_reporting_disable(report);
                break;
            }

            attr_len = ZbZclAttrParseLength(attr_type, attr_data, ZCL_ATTRIBUTE_BUFFER_SIZE_MAX, 0);
            if (attr_len < 0) {
                ZCL_LOG_PRINTF(zb, __func__, "Error trying to parse attribute length (cl = 0x%04x (%s), attr = 0x%04x)",
                    ZbZclClusterGetClusterId(cluster), ZbZclClusterGetDirectionStr(cluster), report->attributeId);
                zcl_reporting_disable(report);
                break;
            }
            if (attr_len == 0) {
                break;
            }

            /* Compare minimum change in floating point values. */
            if ((report->dataType >= ZCL_DATATYPE_FLOATING_SEMI)
                && (report->dataType <= ZCL_DATATYPE_FLOATING_DOUBLE)) {
                enum ZclStatusCodeT status;
                double val, delta;

                val = ZbZclParseFloat(report->dataType, attr_data, &status);
                if (status != ZCL_STATUS_SUCCESS) {
                    zcl_reporting_disable(report);
                    break;
                }
                delta = val - report->last_value.floating;

                if (delta < 0.0) {
                    delta = -delta;
                }
                /* Check if the attribute has changed enough to be reported. */
                if (!send_report && (delta < report->change)) {
                    break;
                }

#ifdef COND_ZCL_REPORT_VERBOSE_LOGGING
                ZCL_LOG_PRINTF(zb, __func__, "Sending report for 0x%04x (%s), attr = 0x%04x, "
                    "val = %f, delta = %f, epsilon = %f, FLOAT",
                    ZbZclClusterGetClusterId(cluster), ZbZclClusterGetDirectionStr(cluster),
                    report->attributeId, val, delta, report->change);
#endif

                /* Update the last reported value. */
                report->last_value.floating = val;
            }
            /* Compare minimum change in integer values. */
            else if (ZbZclAttrIsAnalog(report->dataType)) {
                enum ZclStatusCodeT status;
                long long val;
                long long delta;

#if 0 /* Allow a Reportable Change of 0, even though this may not make sense. */
                if (report->change == 0) {
                    ZCL_LOG_PRINTF(zb, __func__, "Error, epsilon is 0. (cl = 0x%04x (%s), attr = 0x%04x) ANALOG",
                        ZbZclClusterGetClusterId(cluster), ZbZclClusterGetDirectionStr(cluster), report->attributeId);
                    zcl_reporting_disable(report);
                    break;
                }
#endif

                val = ZbZclParseInteger(report->dataType, attr_data, &status);
                if (status != ZCL_STATUS_SUCCESS) {
                    zcl_reporting_disable(report);
                    break;
                }

                delta = val - report->last_value.integer;
                if (delta < 0) {
                    delta = -delta;
                }
                /* Check if the attribute has changed enough to be reported. */
                if (!send_report && (delta < report->change)) {
                    break;
                }

#ifdef COND_ZCL_REPORT_VERBOSE_LOGGING
                ZCL_LOG_PRINTF(zb, __func__, "Sending report for 0x%04x (%s), attr = 0x%04x, "
                    "val = %lld, delta = %d, epsilon = %d, ANALOG",
                    ZbZclClusterGetClusterId(cluster), ZbZclClusterGetDirectionStr(cluster),
                    report->attributeId, val, delta, report->change);
#endif

                /* Update the last reported value. */
                report->last_value.integer = val;
            }
            /* Compare changes in digital attributes with hashes (CRC). */
            else {
                uint16_t hash = WpanCrc(WPAN_CRC_INITIAL, attr_data, (uint32_t)attr_len);

                if (!send_report && (report->last_value.hash == hash)) {
                    break;
                }

#ifdef COND_ZCL_REPORT_VERBOSE_LOGGING
                ZCL_LOG_PRINTF(zb, __func__, "Sending report for 0x%04x (%s), attr = 0x%04x, "
                    "hash = 0x%04x, DIGITAL",
                    ZbZclClusterGetClusterId(cluster), ZbZclClusterGetDirectionStr(cluster),
                    report->attributeId, hash);
#endif

                report->last_value.hash = hash;
            }

            /* If we get here, there was a reportable change */
            send_report = true;
            /* Save the last reporting time */
            report->last_report_time = up_time;
        } while (false);

        if (send_report && (attr_len != 0)) {
            total_attrs++;

            /* Check if this attribute will fit in the report */
            if ((num_attrs == ZCL_ATTR_REPORT_MAX_ATTRS)
                || (total_rpt_len + ZCL_ATTR_REPORT_HDR_LEN + attr_len) > ZCL_ATTR_REPORT_MAX_PAYLOAD) {
                /* Send the report command now */
                (void)zcl_reporting_queue_report(cluster, info_list, send_delay);
                send_delay += ZCL_ATTR_REPORT_CHANGE_DELAY;

                /* Reset the attribute info */
                (void)memset(info_list, 0, sizeof(info_list));
                num_attrs = 0;
                total_rpt_len = 0;
            }

            if (!zcl_report_append_attr(zb, &info_list[num_attrs], report->attributeId,
                    (uint8_t)report->dataType, attr_data, attr_len)) {
                continue;
            }
            num_attrs++;
            total_rpt_len += ZCL_ATTR_REPORT_HDR_LEN + attr_len;

            /* Check the next timeout for this report, since we adjusted last_report_time */
            if (report->min_interval != ZCL_ATTR_REPORT_MIN_INTVL_DISABLE) {
                check_time = (report->min_interval * 1000U);
            }
            else if (report->max_interval != ZCL_ATTR_REPORT_MAX_INTVL_CHANGE) {
                check_time = (report->max_interval * 1000U);
            }
            else {
                check_time = ZCL_ATTR_REPORT_MAX_TIMEOUT;
            }
            next_timeout = zcl_report_check_time(next_timeout, check_time);
        }
        else {
            /* No change, and haven't reached max_interval time yet (if any). */
            next_timeout = zcl_report_check_time(next_timeout, max_intvl_timeout);
        }
    }

    if (attr_data != NULL) {
        if (total_attrs != 0U) {
            /* Add the AttributeReportingStatus attribute as the last attribute with
             * reporting status set to complete. */
            attr_len = 1;
            attr_data[0] = ZCL_ATTR_REPORTING_STATUS_COMPLETE;

            /* Check if this attribute will fit in the report */
            if ((num_attrs == ZCL_ATTR_REPORT_MAX_ATTRS)
                || (total_rpt_len + ZCL_ATTR_REPORT_HDR_LEN + attr_len) > ZCL_ATTR_REPORT_MAX_PAYLOAD) {
                /* Send the report command now */
                (void)zcl_reporting_queue_report(cluster, info_list, send_delay);
                send_delay += ZCL_ATTR_REPORT_CHANGE_DELAY;

                /* Reset the attribute info */
                (void)memset(info_list, 0, sizeof(info_list));
                num_attrs = 0;
                total_rpt_len = 0;
            }

            if (zcl_report_append_attr(zb, &info_list[num_attrs], ZCL_GLOBAL_ATTR_REPORTING_STATUS,
                    (uint8_t)ZCL_DATATYPE_ENUMERATION_8BIT, attr_data, attr_len)) {
                num_attrs++;
            }

            if (num_attrs != 0U) {
                /* Send the (final) report */
                (void)zcl_reporting_queue_report(cluster, info_list, send_delay);
                /* send_delay += ZCL_ATTR_REPORT_CHANGE_DELAY; */
            }
        }

        ZbHeapFree(zb, attr_data);
    }

EXIT_FUNC:
    if (next_timeout < ZCL_ATTR_REPORT_CHANGE_DELAY) {
        next_timeout = ZCL_ATTR_REPORT_CHANGE_DELAY;
    }
    if (cluster->reports.callback != NULL) {
        cluster->reports.callback(cluster, next_timeout, cluster->reports.arg);
        cluster->reports.callback = NULL;
        cluster->reports.arg = NULL;
    }
    if (ZbNwkGet(zb, ZB_NWK_NIB_ID_DisablePeriodicTimers, &disable_periodic_timers, 1)) {
        disable_periodic_timers = 0U;
    }
    if (!disable_periodic_timers) {
        /* Only restart timer if we have reports configured. */
        if (LINK_LIST_HEAD(&cluster->reports.list) != NULL) {
            ZbTimerReset(cluster->reports.timer, next_timeout);
        }
    }
}

void
zcl_attr_reporting_check(struct ZbZclClusterT *cluster, uint16_t attributeId, enum ZbZclReportDirectionT direction)
{
    uint8_t disable_periodic_timers = 0U;

    if (ZbNwkGet(cluster->zb, ZB_NWK_NIB_ID_DisablePeriodicTimers, &disable_periodic_timers, 1)) {
        disable_periodic_timers = 0U;
    }
    if (!disable_periodic_timers) {
        struct ZbZclReportT *report;

        report = zcl_reporting_find(cluster, attributeId, direction);
        if (report != NULL) {
            /* Since we can get here from an OTA ZCL Write, delay sending the report
             * so we don't cause an OTA collission.  */
            zcl_report_kick(cluster, ZCL_ATTR_REPORT_CHANGE_DELAY);
        }
    }
}

void
ZbZclReportCleanup(struct ZbZclClusterT *cluster)
{
    struct LinkListT *p;
    struct ZbZclReportT *report;

    while (true) {
        p = LINK_LIST_HEAD(&cluster->reports.list);
        if (p == NULL) {
            break;
        }
        report = LINK_LIST_ITEM(p, struct ZbZclReportT, link);
        zcl_reporting_delete(report);
    }
}

static struct ZbZclReportT *
zcl_reporting_find(struct ZbZclClusterT *cluster, uint16_t attributeId, enum ZbZclReportDirectionT direction)
{
    struct LinkListT *p;
    struct ZbZclReportT *report;

    /* We only support the generation of reporting for now. */
    if (direction == (uint8_t)ZCL_REPORT_DIRECTION_REVERSE) {
        return NULL;
    }

    /*
     * Search the report list for a matching cluster and attribute identifier
     */
    LINK_LIST_FOREACH(p, &cluster->reports.list) {
        report = LINK_LIST_ITEM(p, struct ZbZclReportT, link);
        /* Ensure the attribute identifiers match. */
        if (report->attributeId != attributeId) {
            continue;
        }
        /* If we get this far, we found a match. */
        return report;
    }

    /* If we get this far, then we found no match. */
    return NULL;
}

/* Only reset if the ZbApsReset is called (i.e. During a nwk leave)
 * A ZCL basic factory reset should not reset the reporting interval as per the ZCL7 */
enum zb_msg_filter_rc
zcl_reporting_stack_event(struct ZigBeeT *zb, uint32_t id, void *msg, void *cbarg)
{
    struct ZbZclClusterT *cluster = cbarg;
    struct LinkListT *p;
    struct ZbZclReportT *report;

    if (id != ZB_MSG_FILTER_RESET_REPORTS) {
        return ZB_MSG_CONTINUE;
    }
    /* Loop through all the reports on this cluster */
    LINK_LIST_FOREACH(p, &cluster->reports.list) {
        report = LINK_LIST_ITEM(p, struct ZbZclReportT, link);
        zcl_reporting_reset_defaults(zb, report, true);
    }

    return ZB_MSG_CONTINUE;
}

static enum ZclStatusCodeT
zcl_reporting_save_curr_val(struct ZbZclClusterT *cluster, struct ZbZclReportT *info)
{
    struct ZigBeeT *zb = cluster->zb;
    uint8_t *read_rsp;
    enum ZclDataTypeT attr_type;
    int attr_len;
    enum ZclStatusCodeT status;

    read_rsp = ZbHeapAlloc(zb, ZCL_ATTRIBUTE_BUFFER_SIZE_MAX);
    if (read_rsp == NULL) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    /* Read the current attribute value. */
    status = ZbZclAttrRead(cluster, info->attributeId, &attr_type, read_rsp, ZCL_ATTRIBUTE_BUFFER_SIZE_MAX, true);
    if (status != ZCL_STATUS_SUCCESS) {
        return status;
    }
    /* Sanity check (Should be redundant, since we already checked this above) */
    if (info->dataType != attr_type) {
        return ZCL_STATUS_INVALID_DATA_TYPE;
    }

    attr_len = ZbZclAttrParseLength(attr_type, read_rsp, ZCL_ATTRIBUTE_BUFFER_SIZE_MAX, 0);
    if (attr_len < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    if (!ZbZclAttrIsAnalog(info->dataType)) {
        info->last_value.hash = WpanCrc(WPAN_CRC_INITIAL, read_rsp, (uint32_t)attr_len);
    }
    else if (ZbZclAttrIsFloat(info->dataType)) {
        info->last_value.floating = ZbZclParseFloat(info->dataType, read_rsp, &status);
        if (status != ZCL_STATUS_SUCCESS) {
            return status;
        }
    }
    else {
        info->last_value.integer = ZbZclParseInteger(info->dataType, read_rsp, &status);
        if (status != ZCL_STATUS_SUCCESS) {
            return status;
        }
    }
    ZbHeapFree(zb, read_rsp);
    return ZCL_STATUS_SUCCESS;
}

/* Allocates and attaches a reporting configuration to the cluster */
static struct ZbZclReportT *
zcl_reporting_create_new(struct ZbZclClusterT *cluster, struct ZbZclReportT *info)
{
    struct ZigBeeT *zb = cluster->zb;
    struct ZbZclReportT *report;

    /* Check for duplicate */
    report = zcl_reporting_find(cluster, info->attributeId, ZCL_REPORT_DIRECTION_NORMAL);
    if (report != NULL) {
        /* Shouldn't get here, because callers are currently checking if reporting
         * already exists. */
        /* EXEGIN - free this one and use the new info? */
        return report;
    }

    /* Allocate memory for a new outgoing reporting record. */
    report = ZbHeapAlloc(zb, sizeof(struct ZbZclReportT));
    if (report == NULL) {
        return NULL;
    }
    (void)memcpy(report, info, sizeof(struct ZbZclReportT));

    /* Insert this record into the endpoint descriptor's reporting list. */
    LINK_LIST_INIT(&report->link);
    LINK_LIST_INSERT_TAIL(&cluster->reports.list, &report->link);

    zcl_reporting_reset_defaults(zb, report, true);
    return report;
}

/* Remove and free a reporting entry */
static void
zcl_reporting_delete(struct ZbZclReportT *report)
{
    struct ZbZclClusterT *cluster = report->cluster;
    struct ZigBeeT *zb = cluster->zb;
    uint8_t disable_periodic_timers = 0U;

    ZCL_LOG_PRINTF(zb, __func__, "Removing reporting config for cl = 0x%04x (%s), attr = 0x%04x",
        ZbZclClusterGetClusterId(cluster), ZbZclClusterGetDirectionStr(cluster), report->attributeId);
    LINK_LIST_UNLINK(&report->link);
    ZbHeapFree(zb, report);
    if (ZbNwkGet(zb, ZB_NWK_NIB_ID_DisablePeriodicTimers, &disable_periodic_timers, 1)) {
        disable_periodic_timers = 0U;
    }
    if (!disable_periodic_timers) {
        /* Kick the timer to compute the next timeout */
        zcl_report_kick(cluster, ZCL_ATTR_REPORT_CHANGE_DELAY);
    }
}

/* Remove and free reporting for a specific attribute (e.g. if an attribute is deleted) */
bool
zcl_cluster_attr_report_delete(struct ZbZclClusterT *cluster, uint16_t attributeId,
    enum ZbZclReportDirectionT direction)
{
    struct ZbZclReportT *report;

    report = zcl_reporting_find(cluster, attributeId, direction);
    if (report == NULL) {
        return false;
    }
    zcl_reporting_delete(report);
    return true;
}

static void
zcl_reporting_disable(struct ZbZclReportT *report)
{
    struct ZigBeeT *zb = report->cluster->zb;
    uint8_t disable_periodic_timers = 0U;

    report->max_interval = ZCL_ATTR_REPORT_MAX_INTVL_DISABLE;
    report->min_interval = ZCL_ATTR_REPORT_MIN_INTVL_DISABLE;
    if (ZbNwkGet(zb, ZB_NWK_NIB_ID_DisablePeriodicTimers, &disable_periodic_timers, 1)) {
        disable_periodic_timers = 0U;
    }
    if (!disable_periodic_timers) {
        /* Kick the timer to compute the next timeout */
        zcl_report_kick(report->cluster, ZCL_ATTR_REPORT_CHANGE_DELAY);
    }
}

static void
zcl_reporting_check_default_intvl(uint16_t *min, uint16_t *max)
{

    /* Is reporting interval disabled? (0xffff) */
    if (*max == ZCL_ATTR_REPORT_MAX_INTVL_DISABLE) {
        /* Leave as-is */
    }
    /* Is reporting interval on change only? (0x0000) */
    else if (*max == ZCL_ATTR_REPORT_MAX_INTVL_CHANGE) {
        /* Leave as-is */
    }
    else {
        if (*max > ZCL_ATTR_REPORT_MAX_INTVL_MAXIMUM) {
            /* Won't get here, since the only value larger is ZCL_ATTR_REPORT_MAX_INTVL_DISABLE. */
            *max = ZCL_ATTR_REPORT_MAX_INTVL_MAXIMUM;
        }
#if 0 /* This is the BDB limit. */
      /* Is max reporting interval within range? */
        else if (*max < ZCL_ATTR_REPORT_MAX_INTVL_MINIMUM) {
            *max = ZCL_ATTR_REPORT_MAX_INTVL_MINIMUM;
        }
#endif
        else {
            /* Leave as-is */
        }

        if (*min > *max) {
            /* Disable min and only use max */
            *min = ZCL_ATTR_REPORT_MIN_INTVL_DISABLE;
        }
    }
}

/* Configure the default reporting intervals from the attribute's pre-defined
 * default values. */
static void
zcl_reporting_config_attr_defaults(struct ZigBeeT *zb, struct ZbZclAttrListEntryT *attr, struct ZbZclReportT *report)
{
    uint16_t min, max;

    /* Get the attribute's min and max reporting invervals and make sure they are sane. */
    min = attr->reporting.interval_secs_min;
    max = attr->reporting.interval_secs_max;
    zcl_reporting_check_default_intvl(&min, &max);
    /* Set the defaults to these values */
    report->default_min_interval = min;
    report->default_max_interval = max;

    /* Reset the report configuration back to defaults now,
     * but don't reset the report timer. */
    zcl_reporting_reset_defaults(zb, report, false);
}

/* Reset the reporting configuration back to defaults. */
static void
zcl_reporting_reset_defaults(struct ZigBeeT *zb, struct ZbZclReportT *report, bool reset_timer)
{
    /* Reset the intervals back to defaults */
    report->min_interval = report->default_min_interval;
    report->max_interval = report->default_max_interval;

    /* Sanity check the default intervals */
    if ((report->min_interval == ZCL_ATTR_REPORT_MIN_INTVL_DEFAULT)
        && (report->max_interval == ZCL_ATTR_REPORT_MAX_INTVL_DEFAULT)) {
        /* The default reporting configuration for this attribute is set to
         * the special value to reset to defaults. BDB states the reporting
         * can either be disabled or between 0x003d to 0xfffe (61 to 65534
         * seconds). Since the user didn't select disabled (max = 0ffff),
         * let's choose the max to be 61 seconds and ignore the min, so we
         * enable reports for at least every 61 seconds. */
        report->max_interval = ZCL_ATTR_REPORT_MAX_INTVL_MINIMUM; /* 61 seconds */
        report->min_interval = ZCL_ATTR_REPORT_MIN_INTVL_DISABLE; /* ignored */
    }

    /* Reset the change amount required to send a report back to defaults */
    report->change = report->default_change;

    /* For reporting timing, set the last reporting time to now. */
    report->last_report_time = ZbZclUptime(zb);

    /* EXEGIN - save current value? */
    /* zcl_reporting_save_curr_val(); */

    if (reset_timer) {
        uint8_t disable_periodic_timers;

        if (ZbNwkGet(zb, ZB_NWK_NIB_ID_DisablePeriodicTimers, &disable_periodic_timers, 1)) {
            disable_periodic_timers = 0U;
        }
        if (!disable_periodic_timers) {
            /* Kick the timer to compute the next timeout */
            zcl_report_kick(report->cluster, ZCL_ATTR_REPORT_CHANGE_DELAY);
        }
    }
}

static void
zcl_reporting_epsilon_default(struct ZbZclReportT *info, enum ZclDataTypeT dataType)
{
    /* Configure value change required to trigger report */
    if ((dataType >= ZCL_DATATYPE_FLOATING_SEMI) && (dataType <= ZCL_DATATYPE_FLOATING_DOUBLE)) {
        info->change = 1.0;
    }
    else if (ZbZclAttrIsAnalog(dataType)) {
        info->change = 1;
    }
    else {
        /* No epsilon for this data type */
        info->change = 0;
    }
}

static bool
zcl_reporting_epsilon_check(struct ZbZclReportT *info)
{
    if (info->max_interval == ZCL_ATTR_REPORT_MAX_INTVL_DISABLE) {
        /* Reportable Change is ignored in this case */
        return true;
    }
    if ((info->min_interval == ZCL_ATTR_REPORT_MIN_INTVL_DEFAULT)
        && (info->max_interval == ZCL_ATTR_REPORT_MAX_INTVL_DEFAULT)) {
        /* Reportable Change is ignored in this case */
        return true;
    }

    if ((info->dataType >= ZCL_DATATYPE_FLOATING_SEMI)
        && (info->dataType <= ZCL_DATATYPE_FLOATING_DOUBLE)) {
        /* If no minimum interval and no reportable change, then this is invalid */
        if ((info->min_interval == 0x0000) && (info->change == 0.0)) {
            return false;
        }
        /* Fix the sign, if negative */
        if (info->change < 0.0) {
            info->change = -info->change;
        }
        return true;
    }
    else if (ZbZclAttrIsAnalog(info->dataType)) {
        /* If no minimum interval and no reportable change, then this is invalid */
        if ((info->min_interval == 0x0000) && (info->change == 0)) {
            return false;
        }
        /* Fix the sign, if negative */
        if (info->change < 0) {
            info->change = -info->change;
        }
        return true;
    }
    else {
        /* Reportable Change is ignored in this case */
        return true;
    }
}

/* Create all default attribute reporting, if supported by the attribute. */
enum ZclStatusCodeT
zcl_reporting_create_default_reports(struct ZbZclClusterT *cluster)
{
    struct ZbZclReportT *report, info;
    struct LinkListT *p;
    struct ZbZclAttrListEntryT *attr;
    enum ZclStatusCodeT status;

    LINK_LIST_FOREACH(p, &cluster->attributeList) {
        attr = LINK_LIST_ITEM(p, struct ZbZclAttrListEntryT, link);
        if ((attr->info->flags & ZCL_ATTR_FLAG_REPORTABLE) == 0U) {
            continue;
        }

        report = zcl_reporting_find(cluster, attr->info->attributeId, ZCL_REPORT_DIRECTION_NORMAL);
        if (report != NULL) {
            /* A report already exists. Don't create another one. */
            /* ! reset it back to defaults? */
            continue;
        }

        (void)memset(&info, 0, sizeof(struct ZbZclReportT));
        info.attributeId = attr->info->attributeId;
        info.cluster = cluster;
        info.dataType = attr->info->dataType;

        /* Configure the default reportable change value */
        zcl_reporting_epsilon_default(&info, attr->info->dataType);
        memcpy(&info.default_change, &info.change, sizeof(info.change));

        /* Set the reporting intervals from the attribute's original
         * configuration. This will also set the current settings to
         * these default values, including the reportable change value
         * configured above. */
        zcl_reporting_config_attr_defaults(cluster->zb, attr, &info);

        status = zcl_reporting_save_curr_val(cluster, &info);
        if (status != ZCL_STATUS_SUCCESS) {
            ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, can't read current value of attribute = 0x%04x",
                attr->info->attributeId);
            return status;
        }

        ZCL_LOG_PRINTF(cluster->zb, __func__,
            "Creating report: cluster = 0x%04x, attr = 0x%04x, min_time = 0x%04x, max_time = 0x%04x, change = %0.3f",
            ZbZclClusterGetClusterId(cluster), attr->info->attributeId, info.default_min_interval,
            info.default_max_interval, info.change);
        if (zcl_reporting_create_new(cluster, &info) == NULL) {
            ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, failed to create new report for attribute = 0x%04x",
                attr->info->attributeId);
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }
    }

    return ZCL_STATUS_SUCCESS;
}

/* Handles ZCL_COMMAND_CONFIG_REPORTING */
void
ZbZclHandleConfigReport(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr,
    struct ZbApsdeDataIndT *ind)
{
    struct ZigBeeT *zb = cluster->zb;
    struct ZbApsdeDataReqT dataReq;
    struct ZbZclHeaderT hdr;
    struct ZbApsBufT bufv[2];
    uint8_t hbuf[ZCL_HEADER_MAX_SIZE];
    int hlen;
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int len = 0;
    enum ZclStatusCodeT status, all_status = ZCL_STATUS_SUCCESS;
    int attr_len;
    unsigned int i = 0;
    bool reset_timer = false;

    /* Build the ZCL header. */
    memset(&hdr, 0, sizeof(hdr));
    hdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    hdr.frameCtrl.manufacturer = zclHdrPtr->frameCtrl.manufacturer;
    if (zclHdrPtr->frameCtrl.direction > ZCL_DIRECTION_TO_SERVER) {
        hdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
    }
    else {
        hdr.frameCtrl.direction = ZCL_DIRECTION_TO_CLIENT;
    }

    hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    hdr.manufacturerCode = zclHdrPtr->manufacturerCode;
    hdr.seqNum = zclHdrPtr->seqNum;
    hdr.cmdId = ZCL_COMMAND_CONFIG_REPORTING_RESPONSE;
    hlen = ZbZclAppendHeader(&hdr, hbuf, ZCL_HEADER_MAX_SIZE);
    if (hlen < 0) {
        ZbZclSendDefaultResponse(cluster, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    /* Parse reporting configuration records until out of data. */
    while (i < ind->asduLength) {
        struct ZbZclReportT reportInfo;
        bool have_reportable_change = false;
        enum ZbZclReportDirectionT direction;

        (void)memset(&reportInfo, 0, sizeof(struct ZbZclReportT));
        if ((i + 3U) > ind->asduLength) {
            ZbZclSendDefaultResponse(cluster, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
            return;
        }
        /*lint -e{9034} "ZbZclReportDirectionT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
        direction = (enum ZbZclReportDirectionT)ind->asdu[i++];
        reportInfo.attributeId = pletoh16(&ind->asdu[i]);
        i += 2U;

        if (direction == ZCL_REPORT_DIRECTION_NORMAL) {
            struct ZbZclAttrListEntryT *attrPtr;
            struct ZbZclReportT *report;

            /* This direction indicates that we should send reports. */
            if ((i + 2U) > ind->asduLength) {
                ZCL_LOG_PRINTF(zb, __func__, "Malformed Configure Reporting Command");
                ZbZclSendDefaultResponse(cluster, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
                return;
            }

            /* The following are optional */
            do {
                /* Attribute type */
                if ((i + 1U) > ind->asduLength) {
                    break;
                }
                /*lint -e{9034} "ZclDataTypeT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
                reportInfo.dataType = (enum ZclDataTypeT)ind->asdu[i++];

                /* Minimum reporting interval */
                if ((i + 2U) > ind->asduLength) {
                    break;
                }
                reportInfo.min_interval = pletoh16(&ind->asdu[i]);
                i += 2U;

                /* Maximum reporting interval */
                if ((i + 2U) > ind->asduLength) {
                    break;
                }
                reportInfo.max_interval = pletoh16(&ind->asdu[i]);
                i += 2U;

                /* Reportable change */
                if ((i + 1U) > ind->asduLength) {
                    break;
                }
                if (reportInfo.dataType == ZCL_DATATYPE_ARRAY || reportInfo.dataType == ZCL_DATATYPE_STRUCT
                    || reportInfo.dataType == ZCL_DATATYPE_SET || reportInfo.dataType == ZCL_DATATYPE_BAG) {
                    status = ZCL_STATUS_UNREPORTABLE_ATTRIBUTE;
                    goto APPEND_ERROR;
                }
                /* If the data type is analog, parse the reportable change. */
                if ((reportInfo.dataType >= ZCL_DATATYPE_FLOATING_SEMI)
                    && (reportInfo.dataType <= ZCL_DATATYPE_FLOATING_DOUBLE)) {
                    attr_len = ZbZclAttrParseLength(reportInfo.dataType, &ind->asdu[i], ind->asduLength - i, 0);
                    if (attr_len < 0) {
                        status = ZCL_STATUS_INVALID_FIELD;
                        goto APPEND_ERROR;
                    }
                    reportInfo.change = ZbZclParseFloat(reportInfo.dataType, &ind->asdu[i], &status);
                    if (status != ZCL_STATUS_SUCCESS) {
                        goto APPEND_ERROR;
                    }
                    i += (uint32_t)attr_len;
                    have_reportable_change = true;
                }
                else if (ZbZclAttrIsAnalog(reportInfo.dataType)) {
                    attr_len = ZbZclAttrParseLength(reportInfo.dataType, &ind->asdu[i], ind->asduLength - i, 0);
                    if (attr_len < 0) {
                        status = ZCL_STATUS_INVALID_FIELD;
                        goto APPEND_ERROR;
                    }
                    reportInfo.change = ZbZclParseInteger(reportInfo.dataType, &ind->asdu[i], &status);
                    if (status != ZCL_STATUS_SUCCESS) {
                        goto APPEND_ERROR;
                    }
                    i += (uint32_t)attr_len;
                    have_reportable_change = true;
                }
                else {
                    /* No reportable change value for this type (e.g. type = bitmask) */
                }
            } while (false);

            attrPtr = ZbZclAttrFind(cluster, reportInfo.attributeId);
            if (attrPtr == NULL) {
                ZCL_LOG_PRINTF(zb, __func__, "Error, can't find attribute for cl = 0x%04x (%s), attr = 0x%04x",
                    ZbZclClusterGetClusterId(cluster), ZbZclClusterGetDirectionStr(cluster), reportInfo.attributeId);
                status = ZCL_STATUS_UNSUPP_ATTRIBUTE;
                goto APPEND_ERROR;
            }

            if ((attrPtr->info->flags & ZCL_ATTR_FLAG_INTERNAL) != 0U) {
                status = ZCL_STATUS_UNSUPP_ATTRIBUTE;
                goto APPEND_ERROR;
            }

            if ((attrPtr->info->flags & ZCL_ATTR_FLAG_REPORTABLE) == 0U) {
                ZCL_LOG_PRINTF(zb, __func__, "Error, attribute 0x%04x is not reportable", reportInfo.attributeId);
                status = ZCL_STATUS_UNREPORTABLE_ATTRIBUTE;
                goto APPEND_ERROR;
            }

            if (reportInfo.max_interval == ZCL_ATTR_REPORT_MAX_INTVL_DISABLE) {
                /* Ignore the Reportable Change Field, if provided, in this case. */
                have_reportable_change = false;
            }

            /* Check for an existing report here. The following will depend on whether
             * the report already exists and if we preseve some info from it. */
            report = zcl_reporting_find(cluster, reportInfo.attributeId, direction);

            /* Check if we should use the attribute's reporting defaults */
            if ((reportInfo.min_interval == ZCL_ATTR_REPORT_MIN_INTVL_DEFAULT)
                && (reportInfo.max_interval == ZCL_ATTR_REPORT_MAX_INTVL_DEFAULT)) {

                /* Ignore the Reportable Change Field, if provided, in this case. */
                have_reportable_change = false;

                if (report != NULL) {
                    /* Keep the default min and max values from the existing report configuration */
                    reportInfo.default_min_interval = report->default_min_interval;
                    reportInfo.default_max_interval = report->default_max_interval;
                    /* Reset the rest back to defaults */
                    zcl_reporting_reset_defaults(zb, &reportInfo, false);
                }
                else {
                    /* Use default min and max values from attribute entry instead */
                    zcl_reporting_config_attr_defaults(zb, attrPtr, &reportInfo);
                }
            }

            /* Sanity-Check the data type. */
            if (reportInfo.dataType != attrPtr->info->dataType) {
                status = ZCL_STATUS_INVALID_DATA_TYPE;
                goto APPEND_ERROR;
            }

            if (report != NULL) {
                /* Update the outgoing reporting info. */
                report->min_interval = reportInfo.min_interval;
                report->max_interval = reportInfo.max_interval;
                if (have_reportable_change) {
                    if (!zcl_reporting_epsilon_check(&reportInfo)) {
                        status = ZCL_STATUS_INVALID_FIELD;
                        goto APPEND_ERROR;
                    }
                    report->change = reportInfo.change;
                }
                /* Since the reporting has been enabled or changed, set the timeout
                 * from this point. */
                report->last_report_time = ZbZclUptime(zb);
                reset_timer = true;
                continue;
            }

            if (reportInfo.max_interval == ZCL_ATTR_REPORT_MAX_INTVL_DISABLE) {
                continue;
            }

            reportInfo.cluster = cluster;

            if (have_reportable_change) {
                if (!zcl_reporting_epsilon_check(&reportInfo)) {
                    status = ZCL_STATUS_INVALID_FIELD;
                    goto APPEND_ERROR;
                }
            }
            else {
                zcl_reporting_epsilon_default(&reportInfo, reportInfo.dataType);
            }
            memcpy(&reportInfo.default_change, &reportInfo.change, sizeof(reportInfo.change));

            status = zcl_reporting_save_curr_val(cluster, &reportInfo);
            if (status != ZCL_STATUS_SUCCESS) {
                goto APPEND_ERROR;
            }

            /* Allocate the reporting configuration */
            report = zcl_reporting_create_new(cluster, &reportInfo);
            if (report == NULL) {
                status = ZCL_STATUS_INSUFFICIENT_SPACE;
                goto APPEND_ERROR;
            }
            reset_timer = true;
        }
        else if (direction == ZCL_REPORT_DIRECTION_REVERSE) {
            /* Direction indicates that we should receive reports. */
            if ((i + 2U) > ind->asduLength) {
                ZbZclSendDefaultResponse(cluster, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
                return;
            }
            /* Note, we don't support configuration for receiving reports only sending.
             * At the very least, the concept needs some serious re-think about
             * how to do anything useful with the incoming reports. */
            status = ZCL_STATUS_UNREPORTABLE_ATTRIBUTE;
            goto APPEND_ERROR;
        }
        else {
            ZCL_LOG_PRINTF(zb, __func__, "Unsupported direction: 0x%02x", direction);
            ZbZclSendDefaultResponse(cluster, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
            return;
        }
        continue;

APPEND_ERROR:
        all_status = status;

        if ((unsigned int)(len + 4U) > sizeof(payload)) {
            break;
        }
        payload[len++] = (uint8_t)status;
        payload[len++] = (uint8_t)direction;
        putle16(&payload[len], reportInfo.attributeId);
        len += 2U;
    }

    if (all_status == ZCL_STATUS_SUCCESS) {
        /* If all were successful, then we return a single status byte (SUCCESS) */
        len = 0;
        payload[len++] = (uint8_t)ZCL_STATUS_SUCCESS;
    }

    /* A struct ZbApsmeBindT needs to be created so that the reports
     * will know where they are to be sent. */
    if (all_status == ZCL_STATUS_SUCCESS) {
        struct ZbApsmeBindReqT bindReq;
        struct ZbApsmeBindConfT conf;

        (void)memset(&bindReq, 0, sizeof(bindReq));
        bindReq.srcExtAddr = ZbExtendedAddress(zb);
        bindReq.srcEndpt = (uint8_t)ind->dst.endpoint;
        bindReq.clusterId = (uint16_t)cluster->clusterId;
        bindReq.dst.mode = ZB_APSDE_ADDRMODE_EXT;
        bindReq.dst.endpoint = ind->src.endpoint;
        bindReq.dst.nwkAddr = ind->src.nwkAddr;
        bindReq.dst.extAddr = ind->src.extAddr;
        ZbApsmeBindReq(zb, &bindReq, &conf);
    }

    /* Fill in the APSDE-DATA.request. */
    ZbZclClusterInitApsdeReq(cluster, &dataReq, NULL);
    dataReq.dst = ind->src;
    dataReq.txOptions = ZbZclTxOptsFromSecurityStatus(ind->securityStatus);
    dataReq.txOptions |= ZB_APSDE_DATAREQ_TXOPTIONS_VECTOR;
    dataReq.discoverRoute = true;
    dataReq.radius = 0; /* Use defaults. */

    bufv[0].data = hbuf;
    bufv[0].len = (uint32_t)hlen;
    bufv[1].data = payload;
    bufv[1].len = len;
    dataReq.asdu = bufv;
    dataReq.asduLength = (uint16_t)(sizeof(bufv) / sizeof(bufv[0]));

    /* Send the APSDE-DATA.request without blocking. */
    if (ZbApsdeDataReqCallback(zb, &dataReq, NULL, NULL) != ZB_APS_STATUS_SUCCESS) {
        /* Ignored */
    }

    if (reset_timer) {
        uint8_t disable_periodic_timers;

        if (ZbNwkGet(zb, ZB_NWK_NIB_ID_DisablePeriodicTimers, &disable_periodic_timers, 1)) {
            disable_periodic_timers = 0U;
        }
        if (!disable_periodic_timers) {
            /* Kick the timer to compute the next timeout */
            zcl_report_kick(cluster, ZCL_ATTR_REPORT_CHANGE_DELAY);
        }
    }
}

void
ZbZclHandleReadReport(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind)
{
    struct ZbApsdeDataReqT dataReq;
    struct ZbZclHeaderT hdr;
    uint8_t *payload;
    int len;
    int err;
    unsigned int i = 0;
    uint16_t attributeId;
    enum ZbZclReportDirectionT direction;

    /* Allocate a buffer for the read reporting response. */
    payload = ZbHeapAlloc(cluster->zb, cluster->maxAsduLength);
    if (payload == NULL) {
        /* Out of memory. */
        ZbZclSendDefaultResponse(cluster, ind, zclHdrPtr, ZCL_STATUS_INSUFFICIENT_SPACE);
        return;
    }

    /* Construct the ZCL header. */
    memset(&hdr, 0, sizeof(hdr));
    hdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    hdr.frameCtrl.manufacturer = zclHdrPtr->frameCtrl.manufacturer;
    if (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_SERVER) {
        hdr.frameCtrl.direction = ZCL_DIRECTION_TO_CLIENT;
    }
    else {
        hdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
    }

    hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    hdr.manufacturerCode = zclHdrPtr->manufacturerCode;
    hdr.seqNum = zclHdrPtr->seqNum;
    hdr.cmdId = ZCL_COMMAND_READ_REPORTING_RESPONSE;
    len = ZbZclAppendHeader(&hdr, payload, ZCL_HEADER_MAX_SIZE);
    if (len < 0) {
        ZbZclSendDefaultResponse(cluster, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    /* Parse the attribute status record list and return the reporting configuration. */
    while (i < ind->asduLength) {
        struct ZbZclReportT *report;
        struct ZbZclAttrListEntryT *attrPtr;
        struct ZbZclAttrReportConfigRecordT config;
        enum ZclStatusCodeT error_status;

        if ((i + 3U) > ind->asduLength) {
            ZbZclSendDefaultResponse(cluster, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
            return;
        }
        if (ind->asdu[i++] != 0U) {
            direction = ZCL_REPORT_DIRECTION_REVERSE;
        }
        else {
            direction = ZCL_REPORT_DIRECTION_NORMAL;
        }
        attributeId = pletoh16(&ind->asdu[i]);
        i += 2U;

        /* Verify that we support the requested attribute */
        attrPtr = ZbZclAttrFind(cluster, attributeId);
        if (attrPtr == NULL) {
            error_status = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            goto APPEND_ERROR;
        }
        if ((attrPtr->info->flags & ZCL_ATTR_FLAG_REPORTABLE) == 0U) {
            ZCL_LOG_PRINTF(cluster->zb, __func__, "Warning, attribute 0x%04x is not reportable", attributeId);
            error_status = ZCL_STATUS_UNREPORTABLE_ATTRIBUTE;
            goto APPEND_ERROR;
        }

        /* Lookup the matching reporting configuration. */
        report = zcl_reporting_find(cluster, attributeId, direction);
        if (report == NULL) {
            error_status = ZCL_STATUS_NOT_FOUND;
            goto APPEND_ERROR;
        }
        if (report->max_interval == ZCL_ATTR_REPORT_MAX_INTVL_DISABLE) {
            error_status = ZCL_STATUS_NOT_FOUND;
            goto APPEND_ERROR;
        }

        /* Otherwise, write the reporting configuration to the frame buffer. */
        memset(&config, 0, sizeof(config));
        if (direction > 0U) {
            config.direction = ZCL_REPORT_DIRECTION_REVERSE;
        }
        else {
            config.direction = ZCL_REPORT_DIRECTION_NORMAL;
        }
        config.attr_id = report->attributeId;
        config.attr_type = report->dataType;
        config.min = report->min_interval;
        config.max = report->max_interval;
        config.change = report->change;
        /* Timeout Period Field: If this value is set to 0x0000, reports of the
         * attribute are not subject to timeout. */
        config.timeout_period = 0x0000U;

        payload[len++] = 0x00; /* SUCCESS */
        err = zcl_append_report_config_record(&config, &payload[len], (uint32_t)cluster->maxAsduLength - (uint16_t)len);
        if (err < 0) {
            /* Remove SUCCESS status code */
            len--;
            error_status = ZCL_STATUS_FAILURE;
            goto APPEND_ERROR;
        }
        len += err;
        continue;

APPEND_ERROR:
        if (((uint32_t)len + 3U) > cluster->maxAsduLength) {
            break;
        }
        payload[len++] = (uint8_t)error_status;
        payload[len++] = direction;
        putle16(&payload[len], attributeId);
        len += 2;
    }

    /* Fill in the APSDE-DATA.request. */
    ZbZclClusterInitApsdeReq(cluster, &dataReq, ind);
    dataReq.dst = ind->src;
    dataReq.txOptions = ZbZclTxOptsFromSecurityStatus(ind->securityStatus);
    dataReq.discoverRoute = true;
    dataReq.radius = 0; /* Use defaults. */
    dataReq.asdu = payload;
    dataReq.asduLength = (uint16_t)len;

    /* Send the APSDE-DATA.request without blocking. */
    if (ZbApsdeDataReqCallback(cluster->zb, &dataReq, NULL, NULL) != ZB_APS_STATUS_SUCCESS) {
        /* Ignored */
    }
    ZbHeapFree(cluster->zb, payload);
}

void
ZbZclHandleReportAttr(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind)
{
    uint16_t attributeId;
    enum ZclDataTypeT dataType;
    int attr_len;
    uint16_t offset = 0;

    /* Ensure this cluster supports reported attributes. */
    if (cluster->report == NULL) {
        /* This cluster doesn't support reported attributes. */
        return;
    }

    /* Parse the attribute report list until out of data. */
    while (true) {
        /* Parse the attribute ID and type. */
        if ((offset + 3U) > ind->asduLength) {
            break;
        }
        attributeId = pletoh16(&ind->asdu[offset]);
        /*lint -e{9034} "ZclDataTypeT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
        dataType = (enum ZclDataTypeT)ind->asdu[offset + 2U];
        offset += 3U;

        /* Parse the attribute length and value. */
        attr_len = ZbZclAttrParseLength(dataType, &ind->asdu[offset], (uint32_t)ind->asduLength - offset, 0);
        if (attr_len < 0) {
            break;
        }

        /* Report the attribute value. */
        cluster->report(cluster, ind, attributeId, dataType, &ind->asdu[offset], ind->asduLength - offset);
        offset += (uint16_t)attr_len;
    }
}

static int
zcl_append_report_config_record(struct ZbZclAttrReportConfigRecordT *record, uint8_t *payload, unsigned int max_len)
{
    unsigned int i = 0;
    bool incl_change;

    switch (record->direction) {
        case ZCL_REPORT_DIRECTION_NORMAL:
            if (ZbZclAttrIsFloat(record->attr_type)) {
                incl_change = true;
            }
            else if (ZbZclAttrIsAnalog(record->attr_type)) {
                incl_change = true;
            }
            else {
                /* For attributes of 'discrete' data type (see 2.6.2), this field is omitted. */
                incl_change = false;
            }

            if (max_len < 8U) {
                return -1;
            }
            payload[i++] = (uint8_t)record->direction;
            putle16(&payload[i], record->attr_id);
            i += 2U;
            payload[i++] = record->attr_type;
            putle16(&payload[i], record->min);
            i += 2U;
            putle16(&payload[i], record->max);
            i += 2U;

            /* Reportable Change Field (Optional) */
            if (incl_change) {
                unsigned int attr_len;

                attr_len = ZbZclAttrTypeLength(record->attr_type);
                if (attr_len == 0) {
                    return ZCL_STATUS_FAILURE;
                }

                switch (attr_len) {
                    case 1:
                        if (record->change > 0xff) {
                            return ZCL_STATUS_FAILURE;
                        }
                        payload[i++] = (uint8_t)record->change;
                        break;

                    case 2:
                        if (record->change > 0xffff) {
                            return ZCL_STATUS_FAILURE;
                        }
                        putle16(&payload[i], (uint16_t)record->change);
                        i += 2;
                        break;

                    case 3:
                        if (record->change > 0xffffff) {
                            return ZCL_STATUS_FAILURE;
                        }
                        putle24(&payload[i], (uint32_t)record->change);
                        i += 3;
                        break;

                    case 4:
                        if (record->change > 0xffffffff) {
                            return ZCL_STATUS_FAILURE;
                        }
                        putle32(&payload[i], (uint32_t)record->change);
                        i += 4;
                        break;

                    case 5:
                        if (record->change > 0xffffffffffULL) {
                            return ZCL_STATUS_FAILURE;
                        }
                        putle40(&payload[i], (uint64_t)record->change);
                        i += 5;
                        break;

                    case 6:
                        if (record->change > 0xffffffffffffULL) {
                            return ZCL_STATUS_FAILURE;
                        }
                        putle48(&payload[i], (uint64_t)record->change);
                        i += 6;
                        break;

                    case 7:
                        if (record->change > 0xffffffffffffffULL) {
                            return ZCL_STATUS_FAILURE;
                        }
                        putle56(&payload[i], (uint64_t)record->change);
                        i += 7;
                        break;

                    case 8:
                        if (record->change > 0xffffffffffffffffULL) {
                            return ZCL_STATUS_FAILURE;
                        }
                        putle64(&payload[i], (uint64_t)record->change);
                        i += 8;
                        break;

                    default:
                        return ZCL_STATUS_FAILURE;
                }
            }
            break;

        case ZCL_REPORT_DIRECTION_REVERSE:
            if (max_len < 8U) {
                return -1;
            }
            payload[i++] = (uint8_t)record->direction;
            putle16(&payload[i], record->attr_id);
            i += 2U;
            putle16(&payload[i], record->timeout_period);
            i += 2U;
            break;

        default:
            return ZCL_STATUS_FAILURE; /* EXEGIN status code? */
    }
    return (int)i;
}

enum ZclStatusCodeT
ZbZclAttrReportConfigReq(struct ZbZclClusterT *cluster, struct ZbZclAttrReportConfigT *config,
    void (*callback)(struct ZbZclCommandRspT *cmd_rsp, void *arg), void *arg)
{
    struct ZbZclCommandReqT req;
    uint8_t payload[ZB_APS_CONST_SAFE_APSSEC_PAYLOAD_SIZE];
    unsigned int i = 0, j;

    if ((config->num_records == 0) || (config->num_records > ZCL_ATTR_REPORT_CONFIG_NUM_MAX)) {
        return ZCL_STATUS_FAILURE; /* EXEGIN status code? */
    }

    /* Form the payload. List of Attribute reporting configuration records */
    for (j = 0; j < config->num_records; j++) {
        struct ZbZclAttrReportConfigRecordT *record;
        int err;

        record = &config->record_list[j];
        err = zcl_append_report_config_record(record, &payload[i], ZB_APS_CONST_SAFE_APSSEC_PAYLOAD_SIZE - i);
        if (err <= 0) {
            return ZCL_STATUS_FAILURE; /* EXEGIN status code? */
        }
        i += err;
    }

    /* Request */
    (void)memset(&req, 0, sizeof(struct ZbZclCommandReqT));
    req.hdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    req.hdr.frameCtrl.manufacturer = (cluster->mfrCode != 0U) ? 1U : 0U;
    req.hdr.manufacturerCode = cluster->mfrCode;
    req.hdr.cmdId = ZCL_COMMAND_CONFIG_REPORTING;
    req.hdr.seqNum = ZbZclGetNextSeqnum();
    req.dst = config->dst;
    req.profileId = cluster->profileId;
    req.clusterId = cluster->clusterId;
    req.srcEndpt = cluster->endpoint;
    req.txOptions = cluster->txOptions;
    req.discoverRoute = cluster->discoverRoute;
    req.radius = cluster->radius;
    req.payload = payload;
    req.length = (uint32_t)i;
    return ZbZclCommandReq(cluster->zb, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclAttrReportReadReq(struct ZbZclClusterT *cluster, struct ZbZclAttrReportReadT *read,
    void (*callback)(struct ZbZclCommandRspT *cmd_rsp, void *arg), void *arg)
{
    struct ZbZclCommandReqT req;
    uint8_t payload[ZB_APS_CONST_SAFE_APSSEC_PAYLOAD_SIZE]; /* 57 */
    unsigned int i = 0, j;

    if ((read->num_records == 0) || (read->num_records > ZCL_ATTR_REPORT_READ_NUM_MAX)) {
        return ZCL_STATUS_FAILURE; /* EXEGIN status code? */
    }

    /* Payload */
    for (j = 0; j < read->num_records; j++) {
        if ((i + 3U) > ZB_APS_CONST_SAFE_APSSEC_PAYLOAD_SIZE) {
            return ZCL_STATUS_FAILURE; /* EXEGIN status code? */
        }
        payload[i++] = read->record_list[j].direction;
        putle16(&payload[i], read->record_list[j].attr_id);
        i += 2U;
    }

    /* Request */
    (void)memset(&req, 0, sizeof(struct ZbZclCommandReqT));
    req.hdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    req.hdr.cmdId = ZCL_COMMAND_READ_REPORTING;
    req.hdr.seqNum = ZbZclGetNextSeqnum();
    req.dst = read->dst;
    req.profileId = cluster->profileId;
    req.clusterId = cluster->clusterId;
    req.srcEndpt = cluster->endpoint;
    req.txOptions = cluster->txOptions;
    req.discoverRoute = cluster->discoverRoute;
    req.radius = cluster->radius;
    req.payload = payload;
    req.length = i;
    return ZbZclCommandReq(cluster->zb, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclAttrReportConfigDefault(struct ZbZclClusterT *cluster, uint16_t attrId,
    uint16_t default_min, uint16_t default_max, double *default_change)
{
    struct ZbZclAttrListEntryT *attr;
    struct ZbZclReportT *report;
    uint16_t min, max;

    attr = ZbZclAttrFind(cluster, attrId);
    if (attr == NULL) {
        return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
    if ((attr->info->flags & ZCL_ATTR_FLAG_REPORTABLE) == 0U) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, attribute 0x%04x is not reportable", attrId);
        return ZCL_STATUS_UNREPORTABLE_ATTRIBUTE;
    }
    report = zcl_reporting_find(cluster, attrId, ZCL_REPORT_DIRECTION_NORMAL);
    if (report == NULL) {
        return ZCL_STATUS_NOT_FOUND;
    }

    /* Check the min and max values */
    min = default_min;
    max = default_max;
    zcl_reporting_check_default_intvl(&min, &max);

    /* Update the default reporting intervals */
    report->default_min_interval = min;
    report->default_max_interval = max;

    if (default_change != NULL) {
        /* Update the default reportable change */
        report->default_change = *default_change;
    }

    /* Update the current reporting info from these new default values,
     * and reset the report timer. */
    zcl_reporting_reset_defaults(cluster->zb, report, true);

    return ZCL_STATUS_SUCCESS;
}

void
ZbZclClusterReportCallbackAttach(struct ZbZclClusterT *cluster,
    void (*callback)(struct ZbZclClusterT *cluster, struct ZbApsdeDataIndT *dataIndPtr,
        uint16_t attr_id, enum ZclDataTypeT data_type, const uint8_t *in_payload, uint16_t in_len))
{
    cluster->report = callback;
    /* EXEGIN - update stack (e.g. ZbZclClusterAttach, but without binding again) */
}
