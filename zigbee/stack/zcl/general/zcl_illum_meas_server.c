/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.illum.meas.h"

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
static const struct ZbZclAttrT zcl_illuminance_server_attr_list[] =
{
    /* Illuminance Attributes */
    {
        ZCL_ILLUM_MEAS_ATTR_MEAS_VAL, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_ILLUM_MEAS_ATTR_MIN_MEAS_VAL, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        zcl_attr_cb, {ZCL_ILLUM_MEAS_MIN_MEAS_VAL_MIN, ZCL_ILLUM_MEAS_MIN_MEAS_VAL_MAX}, {0, 0}
    },
    {
        ZCL_ILLUM_MEAS_ATTR_MAX_MEAS_VAL, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        zcl_attr_cb, {ZCL_ILLUM_MEAS_MAX_MEAS_VAL_MIN, ZCL_ILLUM_MEAS_MAX_MEAS_VAL_MAX}, {0, 0}
    },
#if 0 /* Optional attributes */
    {
        ZCL_ILLUM_MEAS_ATTR_TOLERANCE, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        zcl_attr_cb, {ZCL_ILLUM_MEAS_TOLERANCE_MIN, ZCL_ILLUM_MEAS_TOLERANCE_MAX}, {0, 0}
    },
    {
        ZCL_ILLUM_MEAS_ATTR_LIGHT_SENSOR_TYPE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        zcl_attr_cb, {ZCL_ILLUM_MEAS_LIGHT_SENS_TYPE_PHOTODIODE, ZCL_ILLUM_MEAS_LIGHT_SENS_TYPE_UNKNOWN}, {0, 0}
    },
#endif
};

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;

    /* Application specific defaults */
    uint16_t defaultMin;
    uint16_t defaultMax;
#if 0 /* Optional */
    uint16_t defaultTolerance;
    uint8_t defaultLightSensorType;
#endif
};

struct ZbZclClusterT *
ZbZclIllumMeasServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, uint16_t min, uint16_t max)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_MEAS_ILLUMINANCE, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "CCB 2167" (need to investigate what these changes are) */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    /* set the cluster defaults here. These will be used to set the cluster attribute defaults. */
    clusterPtr->defaultMin = min;
    clusterPtr->defaultMax = max;
#if 0 /* Optional */
    clusterPtr->defaultTolerance = tolerance;
    clusterPtr->defaultLightSensorType = sensorType;
#endif

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_illuminance_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_illuminance_server_attr_list))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Write default values to attributes */
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ILLUM_MEAS_ATTR_MEAS_VAL, ZCL_ILLUM_MEAS_MEASURED_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ILLUM_MEAS_ATTR_MIN_MEAS_VAL, clusterPtr->defaultMin);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ILLUM_MEAS_ATTR_MAX_MEAS_VAL, clusterPtr->defaultMax);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attributeId,
    const uint8_t *inputData, unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg)
{
    unsigned int len;
    uint16_t uint16, minValue, maxValue;
    switch (attributeId) {
        case ZCL_ILLUM_MEAS_ATTR_MEAS_VAL:
            uint16 = pletoh16(inputData);
            minValue = (uint16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_ILLUM_MEAS_ATTR_MIN_MEAS_VAL, NULL, NULL);
            maxValue = (uint16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_ILLUM_MEAS_ATTR_MAX_MEAS_VAL, NULL, NULL);
            if ((minValue == ZCL_ILLUM_MEAS_MIN_MEAS_VAL_UNKNOWN)
                || (maxValue == ZCL_ILLUM_MEAS_MAX_MEAS_VAL_UNKNOWN)) {
                /* There is no need to do range checking in this case. */
            }
            else {
                if (((uint16 < minValue) || (uint16 > maxValue))
                    && ((uint16 != ZCL_ILLUM_MEAS_MEASURED_DEFAULT)
                        && (uint16 != ZCL_ILLUM_MEAS_UNKNOWN))) {
                    return ZCL_STATUS_INVALID_VALUE;
                }
            }
            len = 2;
            break;

        default:
            /* Unsupported Attribute */
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }

    if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) {
        (void)memcpy(attrData, inputData, len);
    }
    return ZCL_STATUS_SUCCESS;
}
