/* Copyright [2019 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.illum.level.h"

static const struct ZbZclAttrT zcl_illum_level_server_attr_list[] = {
    /* Illuminance Level Sensing Information. */
    {
        ZCL_ILLUM_LEVEL_ATTR_LEVEL_STATUS, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {ZCL_ILLUM_LEVEL_STATUS_MIN, ZCL_ILLUM_LEVEL_STATUS_MAX}, {0, 0}
    },
#if 0 /* Optional attributes */
    {
        ZCL_ILLUM_LEVEL_ATTR_LIGHT_SENSOR_TYPE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {ZCL_ILLUM_LEVEL_SEN_TYPE_MIN, ZCL_ILLUM_LEVEL_SEN_TYPE_MAX}, {0, 0}
    },
#endif
    /* Illuminance Level Sensing Settings. */
    {
        ZCL_ILLUM_LEVEL_ATTR_ILLUM_TARGET_LEVEL, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {ZCL_ILLUM_LEVEL_TARGET_MIN, ZCL_ILLUM_LEVEL_TARGET_MAX}, {0, 0}
    },
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

struct ZbZclClusterT *
ZbZclIllumLevelServerAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_MEAS_ILLUMINANCE_LEVEL, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_illum_level_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_illum_level_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}
