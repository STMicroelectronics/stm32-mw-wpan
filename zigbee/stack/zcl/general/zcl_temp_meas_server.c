/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl/general/zcl.temp.meas.h"

/*lint -e9087 "struct cluster_priv_t <- void [MISRA Rule 11.3 (REQUIRED)]" */

#define ZCL_TEMP_MEAS_MIN_TEMPERATURE               (-27315)

static enum ZclStatusCodeT zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attributeId,
    const uint8_t *inputData, unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg);

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

/* Attributes */
static const struct ZbZclAttrT zcl_temp_meas_server_attr_list[] =
{
    /* Temperature Attributes */
    {
        ZCL_TEMP_MEAS_ATTR_MEAS_VAL, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_TEMP_MEAS_ATTR_MIN_MEAS_VAL, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        zcl_attr_cb, {ZCL_TEMP_MEAS_MIN_MEAS_VAL_MIN, ZCL_TEMP_MEAS_MIN_MEAS_VAL_MAX}, {0, 0}
    },
    {
        ZCL_TEMP_MEAS_ATTR_MAX_MEAS_VAL, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        zcl_attr_cb, {ZCL_TEMP_MEAS_MAX_MEAS_VAL_MIN, ZCL_TEMP_MEAS_MAX_MEAS_VAL_MAX}, {0, 0}
    },
    {
        ZCL_TEMP_MEAS_ATTR_TOLERANCE, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        zcl_attr_cb, {ZCL_TEMP_MEAS_TOLERANCE_MIN, ZCL_TEMP_MEAS_TOLERANCE_MAX}, {0, 0}
    },
};

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;

    /* Application specific defaults */
    int64_t defaultMin;
    int16_t defaultMax;
    uint16_t defaultTolerance;
};

struct ZbZclClusterT *
ZbZclTempMeasServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, int16_t min, int16_t max, uint16_t tolerance)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_MEAS_TEMPERATURE, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "CCB 2241 2370" (need to investigate what these changes are) */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    clusterPtr->defaultMin = min;
    clusterPtr->defaultMax = max;
    clusterPtr->defaultTolerance = tolerance;

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_temp_meas_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_temp_meas_server_attr_list))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* ZCL_TEMP_MEAS_ATTR_MEAS_VAL may not have taken, depending on the order
     * the default values were written to the attributes. */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_TEMP_MEAS_ATTR_MEAS_VAL, ZCL_TEMP_MEAS_UNKNOWN);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_TEMP_MEAS_ATTR_MIN_MEAS_VAL, clusterPtr->defaultMin);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_TEMP_MEAS_ATTR_MAX_MEAS_VAL, clusterPtr->defaultMax);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_TEMP_MEAS_ATTR_TOLERANCE, clusterPtr->defaultTolerance);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static bool
zcl_meas_temp_server_range_check(int16_t temperature, int16_t min_val, int16_t max_val)
{
    if (temperature == (int16_t)ZCL_TEMP_MEAS_UNKNOWN) {
        return true;
    }
    if ((temperature < min_val) && (min_val != (int16_t)ZCL_TEMP_MEAS_UNKNOWN)) {
        return false;
    }
    if ((temperature > max_val) && (max_val != (int16_t)ZCL_TEMP_MEAS_UNKNOWN)) {
        return false;
    }
    return true;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attributeId,
    const uint8_t *inputData, unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg)
{
    unsigned int len;
    switch (attributeId) {
        case ZCL_TEMP_MEAS_ATTR_MEAS_VAL:
        {
            int16_t minValue, maxValue;
            int16_t val = pletoh16(inputData);
            minValue = (int16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_TEMP_MEAS_ATTR_MIN_MEAS_VAL, NULL, NULL);
            maxValue = (int16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_TEMP_MEAS_ATTR_MAX_MEAS_VAL, NULL, NULL);
            if (!zcl_meas_temp_server_range_check(val, minValue, maxValue)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 2;
            break;
        }

        default:
            /* Unsupported Attribute */
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }

    if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) {
        (void)memcpy(attrData, inputData, len);
    }
    return ZCL_STATUS_SUCCESS;
}
