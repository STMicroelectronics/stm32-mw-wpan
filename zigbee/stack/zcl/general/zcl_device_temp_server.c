/* Copyright [2017 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.device.temp.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster;
    struct ZbTimerT *dwell_timer;
    int alarm_state;
};

/* Forward declarations */
static void dwell_timer_callback(struct ZigBeeT *zb, void *arg);
static void dev_temp_server_cleanup(struct ZbZclClusterT *);

static enum ZclStatusCodeT zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attributeId,
    const uint8_t *inputData, unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg);

static enum ZclStatusCodeT alarm_reset_cb(struct ZbZclClusterT *clusterPtr, uint8_t alarm_code,
    uint16_t cluster_id, struct ZbApsdeDataIndT *data_ind, struct ZbZclHeaderT *hdr);

static enum ZclStatusCodeT
zcl_attr_cb(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrCbInfoT *cb)
{
    if (cb->type == ZCL_ATTR_CB_TYPE_WRITE) {
        return zcl_attr_write_cb(clusterPtr, cb->src, cb->info->attributeId, cb->zcl_data, cb->zcl_len,
            cb->attr_data, cb->write_mode, cb->app_cb_arg);
    }
    else {
        return ZCL_STATUS_FAILURE;
    }
}

const struct ZbZclAttrT device_temp_attr_list[] = {
    {
        ZCL_DEV_TEMP_CURRENT, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_DEV_TEMP_MIN_TEMP, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {ZCL_DEVICE_TEMP_MIN, ZCL_DEVICE_TEMP_MAX}, {0, 0}
    },
    {
        ZCL_DEV_TEMP_MAX_TEMP, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {ZCL_DEVICE_TEMP_MIN, ZCL_DEVICE_TEMP_MAX}, {0, 0}
    },
    {
        ZCL_DEV_TEMP_ALARM_MASK, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_DEV_TEMP_LOW_THRESHOLD, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_DEV_TEMP_HIGH_THRESHOLD, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_DEV_TEMP_LOW_DWELL_TRIP, ZCL_DATATYPE_UNSIGNED_24BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DEV_TEMP_HIGH_DWELL_TRIP, ZCL_DATATYPE_UNSIGNED_24BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
};

static void
dwell_timer_callback(struct ZigBeeT *zb, void *arg)
{
    struct cluster_priv_t *dev_temp_cluster = (struct cluster_priv_t *)arg;

    ZCL_LOG_PRINTF(zb, __func__, "dwell timer expired sending alarm");
    if (dev_temp_cluster->alarm_state == ZCL_DEV_TEMP_ALARM_MASK_LOW) {
        ZbZclClusterSendAlarm(&dev_temp_cluster->cluster, ZbZclClusterGetEndpoint(&dev_temp_cluster->cluster), ZCL_DEV_TEMP_ALARM_CODE_LOW);
    }
    if (dev_temp_cluster->alarm_state == ZCL_DEV_TEMP_ALARM_MASK_HIGH) {
        ZbZclClusterSendAlarm(&dev_temp_cluster->cluster, ZbZclClusterGetEndpoint(&dev_temp_cluster->cluster), ZCL_DEV_TEMP_ALARM_CODE_HIGH);
    }
    dev_temp_cluster->alarm_state = ZCL_DEV_TEMP_ALARM_MASK_CLEAR;
}

struct ZbZclClusterT *
ZbZclDevTempServerAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_DEVICE_TEMPERATURE, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    clusterPtr->cluster.cleanup = dev_temp_server_cleanup;

    clusterPtr->dwell_timer = ZbTimerAlloc(zb, dwell_timer_callback, clusterPtr);
    if (clusterPtr->dwell_timer == NULL) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }
    clusterPtr->alarm_state = ZCL_DEV_TEMP_ALARM_MASK_CLEAR;

    /* configure basic requirements */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, device_temp_attr_list, ZCL_ATTR_LIST_LEN(device_temp_attr_list))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DEV_TEMP_CURRENT, ZCL_DEVICE_TEMP_INVALID);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DEV_TEMP_MIN_TEMP, ZCL_DEVICE_TEMP_INVALID);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DEV_TEMP_MAX_TEMP, ZCL_DEVICE_TEMP_INVALID);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DEV_TEMP_ALARM_MASK, 0x00); /* both disabled */
    /* Setting thresholds to the min and max, respectively, effectively
     * disables the alarm. The alarm is triggered if the temp exceeds
     * the threshold, which cannot occur if the threshold is at the
     * attribute's limit. */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DEV_TEMP_LOW_THRESHOLD, ZCL_DEVICE_TEMP_INVALID);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DEV_TEMP_HIGH_THRESHOLD, ZCL_DEVICE_TEMP_INVALID);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DEV_TEMP_LOW_DWELL_TRIP, ZCL_INVALID_UNSIGNED_24BIT);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DEV_TEMP_HIGH_DWELL_TRIP, ZCL_INVALID_UNSIGNED_24BIT);

    ZbZclClusterRegisterAlarmResetHandler(&clusterPtr->cluster, alarm_reset_cb);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static void
zcl_device_temp_server_handle_temp_change(struct ZbZclClusterT *cluster)
{
    int16_t temp_current;
    int16_t temp_min;
    int16_t raw_reading;
    uint8_t alarm_mask;
    int16_t low_temp_threshold;
    int16_t high_temp_threshold;
    uint32_t dwell_time;
    struct cluster_priv_t *dev_temp_cluster = (struct cluster_priv_t *)cluster;

    temp_current = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_DEV_TEMP_CURRENT, NULL, NULL);

    /* update minimum attribute */
    raw_reading = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_DEV_TEMP_MIN_TEMP, NULL, NULL);
    temp_min = raw_reading;

    /* attributes are initialized to invalid as there is no history and must be initialized
    * to first valid value. Must check for INVALID with unsigned to prevent sign extension issues */
    if ((raw_reading == ZCL_DEVICE_TEMP_INVALID) || (temp_current < temp_min)) {
        (void)ZbZclAttrIntegerWrite(cluster, ZCL_DEV_TEMP_MIN_TEMP, temp_current);
        ZCL_LOG_PRINTF(cluster->zb, __func__, "updating min to 0x%04x", temp_current);
    }

    /* update maximum attribute */
    raw_reading = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_DEV_TEMP_MAX_TEMP, NULL, NULL);
    if ((raw_reading == ZCL_DEVICE_TEMP_INVALID) || (temp_current > raw_reading)) {
        (void)ZbZclAttrIntegerWrite(cluster, ZCL_DEV_TEMP_MAX_TEMP, temp_current);
        ZCL_LOG_PRINTF(cluster->zb, __func__, "updating max to 0x%04x", temp_current);
    }

    alarm_mask = (uint8_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_DEV_TEMP_ALARM_MASK, NULL, NULL);
    ZCL_LOG_PRINTF(cluster->zb, __func__, "current temp 0x%04x alarm mask 0x%02x", temp_current, alarm_mask);

    /* check low threshold */
    low_temp_threshold = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_DEV_TEMP_LOW_THRESHOLD, NULL, NULL);
    if (temp_current < low_temp_threshold) { /* must be a signed comparison */

        dwell_time = (uint32_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_DEV_TEMP_LOW_DWELL_TRIP, NULL, NULL);
        if ((alarm_mask & ZCL_DEV_TEMP_ALARM_MASK_LOW)
            && (low_temp_threshold != ZCL_DEVICE_TEMP_INVALID)
            && (dwell_time != ZCL_INVALID_UNSIGNED_24BIT)) {
            if (dwell_time == 0) {
                ZbZclClusterSendAlarm(&dev_temp_cluster->cluster, ZbZclClusterGetEndpoint(&dev_temp_cluster->cluster),
                    ZCL_DEV_TEMP_ALARM_CODE_LOW);
            }
            else {
                dev_temp_cluster->alarm_state = ZCL_DEV_TEMP_ALARM_MASK_LOW;
                ZbTimerReset(dev_temp_cluster->dwell_timer, dwell_time * 1000);
                ZCL_LOG_PRINTF(cluster->zb, __func__, "below low threshold starting dwell %d ms for alarm", dwell_time * 1000);
            }
        }
    }
    else { /* above low threshold */
           /* if low threshold dwell period active */
        if (dev_temp_cluster->alarm_state == ZCL_DEV_TEMP_ALARM_MASK_LOW) {
            ZbTimerStop(dev_temp_cluster->dwell_timer);
            dev_temp_cluster->alarm_state = ZCL_DEV_TEMP_ALARM_MASK_CLEAR;
            ZCL_LOG_PRINTF(cluster->zb, __func__, "rose above low threshold during dwell, stopped alarm timer");
        }
    }

    /* check high threshold */
    high_temp_threshold = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_DEV_TEMP_HIGH_THRESHOLD, NULL, NULL);
    if (temp_current > high_temp_threshold) { /* must be a signed comparison */

        dwell_time = (uint32_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_DEV_TEMP_HIGH_DWELL_TRIP, NULL, NULL);
        if ((alarm_mask & ZCL_DEV_TEMP_ALARM_MASK_HIGH)
            && (high_temp_threshold != ZCL_DEVICE_TEMP_INVALID)
            && (dwell_time != ZCL_INVALID_UNSIGNED_24BIT)) {
            if (dwell_time == 0) {
                ZbZclClusterSendAlarm(&dev_temp_cluster->cluster, ZbZclClusterGetEndpoint(&dev_temp_cluster->cluster),
                    ZCL_DEV_TEMP_ALARM_CODE_HIGH);
            }
            else {
                dev_temp_cluster->alarm_state = ZCL_DEV_TEMP_ALARM_MASK_HIGH;
                ZbTimerReset(dev_temp_cluster->dwell_timer, dwell_time * 1000);
                ZCL_LOG_PRINTF(cluster->zb, __func__, "above high threshold, starting %d ms dwell for alarm", dwell_time * 1000);
            }
        }
    }
    else { /* below high threshold */
           /* if high threshold dwell period active */
        if (dev_temp_cluster->alarm_state == ZCL_DEV_TEMP_ALARM_MASK_HIGH) {
            ZbTimerStop(dev_temp_cluster->dwell_timer);
            dev_temp_cluster->alarm_state = ZCL_DEV_TEMP_ALARM_MASK_CLEAR;
            ZCL_LOG_PRINTF(cluster->zb, __func__, "dropped below high threshold during dwell, stopped alarm timer");
        }
    }
}

static bool
zcl_device_temp_server_range_check(int16_t temperature)
{
    if (temperature == ZCL_DEVICE_TEMP_INVALID) {
        return true;
    }
    if (temperature < ZCL_DEVICE_TEMP_MIN) {
        return false;
    }
    if (temperature > ZCL_DEVICE_TEMP_MAX) {
        return false;
    }
    return true;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attributeId,
    const uint8_t *inputData, unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg)
{
    enum ZclStatusCodeT status;
    unsigned int len = 0;

    switch (attributeId) {
        case ZCL_DEV_TEMP_CURRENT:
        {
            int16_t val;

            val = pletoh16(inputData);
            if (!zcl_device_temp_server_range_check(val)) {
                /* Out of range */
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Range check failed (attr = 0x%04x, value = 0x%04x)", attributeId, val);
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 2;
            if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) {
                (void)memcpy(attrData, inputData, len);
                zcl_device_temp_server_handle_temp_change(clusterPtr);
            }
            /* Special case. Already written to attrData. */
            return ZCL_STATUS_SUCCESS;
        }

        case ZCL_DEV_TEMP_ALARM_MASK:
        {
            uint8_t val;

            val = inputData[0];
            if ((val & ~(ZCL_DEVICE_TEMP_ALARM_MASK_ALL)) != 0) {
                status = ZCL_STATUS_INVALID_VALUE;
                break;
            }
            len = 1;
            break;

        }
        case ZCL_DEV_TEMP_LOW_THRESHOLD:
        {
            int16_t val, compare;

            val = pletoh16(inputData);
            len = 2;

            /* Range check */
            if (val == ZCL_DEVICE_TEMP_INVALID) {
                break;
            }
            if ((val < ZCL_DEVICE_TEMP_MIN) || (val > ZCL_DEVICE_TEMP_MAX)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            if ((mode & ZCL_ATTR_WRITE_FLAG_FORCE) == 0U) {
                compare = (int16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_DEV_TEMP_HIGH_THRESHOLD, NULL, &status);
                if ((status == ZCL_STATUS_SUCCESS) && (compare != ZCL_DEVICE_TEMP_INVALID) && (val > compare)) {
                    return ZCL_STATUS_INVALID_VALUE;
                }
            }
            break;
        }

        case ZCL_DEV_TEMP_HIGH_THRESHOLD:
        {
            int16_t val, compare;

            val = pletoh16(inputData);
            len = 2;

            /* Range check */
            if (val == ZCL_DEVICE_TEMP_INVALID) {
                break;
            }
            if ((val < ZCL_DEVICE_TEMP_MIN) || (val > ZCL_DEVICE_TEMP_MAX)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            if ((mode & ZCL_ATTR_WRITE_FLAG_FORCE) == 0U) {
                compare = (int16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_DEV_TEMP_LOW_THRESHOLD, NULL, &status);
                if ((status == ZCL_STATUS_SUCCESS) && (compare != ZCL_DEVICE_TEMP_INVALID)) {
                    if (val < compare) {
                        return ZCL_STATUS_INVALID_VALUE;
                    }
                }
            }
            break;
        }

        default:
            /* Can't get here */
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }

    if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) {
        (void)memcpy(attrData, inputData, len);
    }
    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
alarm_reset_cb(struct ZbZclClusterT *clusterPtr, uint8_t alarm_code, uint16_t cluster_id,
    struct ZbApsdeDataIndT *data_ind, struct ZbZclHeaderT *hdr)
{
    int16_t temp_current;
    uint8_t alarms = 0;

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Device Temp Server - Reset Alarm (code = 0x%02x)", alarm_code);

    /* reuse the alarm mask to keep track of which alarms are to be reset */
    if (alarm_code == 0xffU) {
        alarms = ZCL_DEV_TEMP_ALARM_MASK_LOW | ZCL_DEV_TEMP_ALARM_MASK_HIGH;
    }
    else if (alarm_code == ZCL_DEV_TEMP_ALARM_CODE_LOW) {
        alarms = ZCL_DEV_TEMP_ALARM_MASK_LOW;
    }
    else if (alarm_code == ZCL_DEV_TEMP_ALARM_CODE_HIGH) {
        alarms = ZCL_DEV_TEMP_ALARM_MASK_HIGH;
    }
    else {
        return ZCL_STATUS_INVALID_VALUE;
    }

    temp_current = (int16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_DEV_TEMP_CURRENT, NULL, NULL);

    if ((alarms & ZCL_DEV_TEMP_ALARM_MASK_LOW) != 0U) {
        int16_t low_temp_threshold;
        int16_t raw_reading;
        uint32_t low_dwell_time;

        raw_reading = (int16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_DEV_TEMP_LOW_THRESHOLD, NULL, NULL);
        low_temp_threshold = raw_reading;
        /* dwell time is only used to check for the special value */
        low_dwell_time = (uint32_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_DEV_TEMP_LOW_DWELL_TRIP, NULL, NULL);
        if (low_dwell_time != ZCL_INVALID_UNSIGNED_24BIT) {
            if (temp_current < low_temp_threshold) {
                /* on reset neither check nor set the low_alarm_state since we must send anyway */
                ZbZclClusterSendAlarm(clusterPtr, ZbZclClusterGetEndpoint(clusterPtr), ZCL_DEV_TEMP_ALARM_CODE_LOW);
            }
        }
    }

    if ((alarms & ZCL_DEV_TEMP_ALARM_MASK_HIGH) != 0U) {
        int16_t high_temp_threshold;
        uint16_t raw_reading;
        uint32_t high_dwell_time;

        raw_reading = (uint16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_DEV_TEMP_HIGH_THRESHOLD, NULL, NULL);
        high_temp_threshold = raw_reading;
        /* dwell time is only used to check for the special value */
        high_dwell_time = (uint32_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_DEV_TEMP_HIGH_DWELL_TRIP, NULL, NULL);
        if (high_dwell_time != ZCL_INVALID_UNSIGNED_24BIT) {
            if (temp_current > high_temp_threshold) {
                /* on reset neither check nor set the low_alarm_state since we must send anyway */
                ZbZclClusterSendAlarm(clusterPtr, ZbZclClusterGetEndpoint(clusterPtr), ZCL_DEV_TEMP_ALARM_CODE_HIGH);
            }
        }
    }

    return ZCL_STATUS_SUCCESS;
}

static void
dev_temp_server_cleanup(struct ZbZclClusterT *clusterPtr)
{
    struct cluster_priv_t *dev_temp_cluster = (struct cluster_priv_t *)clusterPtr;

    if (dev_temp_cluster->dwell_timer != NULL) {
        ZbTimerFree(dev_temp_cluster->dwell_timer);
        dev_temp_cluster->dwell_timer = NULL;
    }
}
