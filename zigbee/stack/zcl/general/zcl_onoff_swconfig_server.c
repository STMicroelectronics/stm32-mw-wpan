/* Copyright [2019 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.onoff.swconfig.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

static const struct ZbZclAttrT zcl_onoff_swconfig_server_attr_list[] = {
    /* Switch Information. */
    {
        ZCL_ONOFF_SWCONFIG_ATTR_TYPE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0x00, 0x02}, {0, 0}
    },
    /* Switch Settings */
    {
        ZCL_ONOFF_SWCONFIG_ATTR_ACTIONS, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0x00, 0x02}, {0, 0}
    },
};

struct ZbZclClusterT *
ZbZclOnOffSwConfigServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, uint8_t switch_type)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_ONOFF_CONFIG, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_onoff_swconfig_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_onoff_swconfig_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ONOFF_SWCONFIG_ATTR_TYPE, (long long)switch_type);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_ONOFF_SWCONFIG_ATTR_ACTIONS, ZCL_ONOFF_SWCONFIG_ON_OFF);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}
