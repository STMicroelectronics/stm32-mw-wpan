/* Copyright [2019 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/zcl.h"
#include "zcl/general/zcl.press.meas.h"

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
static const struct ZbZclAttrT zcl_press_meas_server_attr_list[] = {
    /* Pressure Measurement Information. */
    {
        ZCL_PRESS_MEAS_ATTR_MEAS_VAL, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_PRESS_MEAS_ATTR_MIN_MEAS_VAL, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        zcl_attr_cb, {ZCL_PRESS_MEAS_MIN_VAL_MIN, ZCL_PRESS_MEAS_MIN_VAL_MAX}, {0, 0}
    },
    {
        ZCL_PRESS_MEAS_ATTR_MAX_MEAS_VAL, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        zcl_attr_cb, {ZCL_PRESS_MEAS_MAX_VAL_MIN, ZCL_PRESS_MEAS_MAX_VAL_MAX}, {0, 0}
    },
#if 0 /* Optional attributes */
    {
        ZCL_PRESS_MEAS_ATTR_TOLERANCE, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0}, {0, 0x0800}
    },
    /* Extended Pressure Measurement Information. */
    {
        ZCL_PRESS_MEAS_ATTR_SCALED_VAL, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_PRESS_MEAS_ATTR_MIN_SCALED_VAL, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0,
        zcl_attr_cb, {ZCL_PRESS_MEAS_MIN_VAL_MIN, ZCL_PRESS_MEAS_MIN_VAL_MAX}, {0, 0}
    },
    {
        ZCL_PRESS_MEAS_ATTR_MAX_SCALED_VAL, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        zcl_attr_cb, {ZCL_PRESS_MEAS_MAX_VAL_MIN, ZCL_PRESS_MEAS_MAX_VAL_MAX}, {0, 0}
    },
    {
        ZCL_PRESS_MEAS_ATTR_SCALED_TOL, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0x0800}, {0, 0}
    },
    {
        ZCL_PRESS_MEAS_ATTR_SCALE, ZCL_DATATYPE_SIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {ZCL_PRESS_MEAS_SCALE_MIN, ZCL_PRESS_MEAS_SCALE_MAX}, {0, 0}
    },
#endif
};

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;

    /* application specific defaults */
    int16_t default_min;
    int16_t default_max;
};

struct ZbZclClusterT *
ZbZclPressMeasServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, int16_t min, int16_t max)
{
    struct cluster_priv_t *clusterPtr;

    /* Allocate. */
    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_MEAS_PRESSURE, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "CCB 2241 2370" (need to investigate what these changes are) */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    /* set the cluster defaults here. These will be used to set the
     * cluster attribute defaults. */
    clusterPtr->default_min = min;
    clusterPtr->default_max = max;

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_press_meas_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_press_meas_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Write default values to attributes */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_PRESS_MEAS_ATTR_MEAS_VAL, ZCL_PRESS_MEAS_UNKNOWN);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_PRESS_MEAS_ATTR_MIN_MEAS_VAL, clusterPtr->default_min);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_PRESS_MEAS_ATTR_MAX_MEAS_VAL, clusterPtr->default_max);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static bool
zcl_press_meas_server_range_check(int16_t value, int16_t min_val, int16_t max_val)
{
    if (value == (int16_t)ZCL_PRESS_MEAS_UNKNOWN) {
        return true;
    }
    if ((value < min_val) && (min_val != (int16_t)ZCL_PRESS_MEAS_UNKNOWN)) {
        return false;
    }
    if ((value > max_val) && (max_val != (int16_t)ZCL_PRESS_MEAS_UNKNOWN)) {
        return false;
    }
    return true;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src, uint16_t attribute_id,
    const uint8_t *input_data, unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg)
{
    unsigned int len = 0;
    enum ZclStatusCodeT status = ZCL_STATUS_SUCCESS;

    switch (attribute_id) {
        case ZCL_PRESS_MEAS_ATTR_MEAS_VAL:
        {
            int16_t input, min_value, max_value;

            input = (int16_t)pletoh16(input_data);
            min_value = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_PRESS_MEAS_ATTR_MIN_MEAS_VAL, NULL, NULL);
            max_value = (int16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_PRESS_MEAS_ATTR_MAX_MEAS_VAL, NULL, NULL);
            if (!zcl_press_meas_server_range_check(input, min_value, max_value)) {
                status = ZCL_STATUS_INVALID_VALUE;
                break;
            }
            len = 2;
            break;
        }

        default:
            /* Unsupported Attribute */
            status = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            break;
    }

    if (((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) && (status == ZCL_STATUS_SUCCESS)) {
        (void)memcpy(attr_data, input_data, len);
    }
    return status;
}
