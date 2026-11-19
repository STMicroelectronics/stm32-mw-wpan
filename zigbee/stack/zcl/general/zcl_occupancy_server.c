/* Copyright [2017 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.occupancy.h"

/* Alarm cluster */
struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

/* Attributes */
static const struct ZbZclAttrT zcl_occupancy_server_attr_list[] = {
    {
        ZCL_OCC_ATTR_OCCUPANCY, ZCL_DATATYPE_BITMAP_8BIT, ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0x1}, {0, 0}
    },
    {
        ZCL_OCC_ATTR_SENSORTYPE, ZCL_DATATYPE_ENUMERATION_8BIT, ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0, 0xFE}, {0, 0}
    },
    {
        ZCL_OCC_ATTR_SENSORTYPE_BITMAP, ZCL_DATATYPE_BITMAP_8BIT, ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0x1, 0x7}, {0, 0}
    },
    /* Optional attributes */
    /* PIR Config. */
    {
        ZCL_OCC_ATTR_PIR_OU_DELAY, ZCL_DATATYPE_UNSIGNED_16BIT, ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0, 0xFFFE}, {0, 0}
    },
    {
        ZCL_OCC_ATTR_PIR_UO_DELAY, ZCL_DATATYPE_UNSIGNED_16BIT, ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0, 0xFFFE}, {0, 0}
    },
    {
        ZCL_OCC_ATTR_PIR_UO_THRESHOLD, ZCL_DATATYPE_UNSIGNED_8BIT, ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {1, 0xFE}, {0, 0}
    },
    /* Ultrasonic config. */
    {
        ZCL_OCC_ATTR_US_OU_DELAY, ZCL_DATATYPE_UNSIGNED_16BIT, ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0, 0xFFFE}, {0, 0}
    },
    {
        ZCL_OCC_ATTR_US_UO_DELAY, ZCL_DATATYPE_UNSIGNED_16BIT, ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0, 0xFFFE}, {0, 0}
    },
    {
        ZCL_OCC_ATTR_US_UO_THRESHOLD, ZCL_DATATYPE_UNSIGNED_8BIT, ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {1, 0xFE}, {0, 0}
    },
#if 0
    /* Physical Contact config. */
    {
        ZCL_OCC_ATTR_PHY_OU_DELAY, ZCL_DATATYPE_UNSIGNED_16BIT, ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0, 0xFFFE}, {0, 0}
    },
    {
        ZCL_OCC_ATTR_PHY_UO_DELAY, ZCL_DATATYPE_UNSIGNED_16BIT, ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0, 0xFFFE}, {0, 0}
    },
    {
        ZCL_OCC_ATTR_PHY_UO_THRESHOLD, ZCL_DATATYPE_UNSIGNED_8BIT, ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {1, 0xFE}, {0, 0}
    }
#endif
};

struct ZbZclClusterT *
ZbZclOccupancyServerAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_MEAS_OCCUPANCY, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_occupancy_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_occupancy_server_attr_list))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Revision 2 implements: "Physical Contact Occupancy feature with mandatory OccupancySensorTypeBitmap"
     * (need to investigate what these changes are) */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_OCC_ATTR_PIR_OU_DELAY, 0x00);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_OCC_ATTR_PIR_UO_DELAY, 0x00);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_OCC_ATTR_PIR_UO_THRESHOLD, 0x01);

    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_OCC_ATTR_US_OU_DELAY, 0x00);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_OCC_ATTR_US_UO_DELAY, 0x00);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_OCC_ATTR_US_UO_THRESHOLD, 0x01);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}
