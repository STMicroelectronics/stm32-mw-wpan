/* Copyright [2019 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.nearest.gw.h"

static const struct ZbZclAttrT zcl_nearest_gw_server_attr_list[] = {
    {
        ZCL_NEAREST_GW_SVR_ATTR_NEAREST_GW, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x0000, 0xFFF8}, {0, 0}
    },
    {
        ZCL_NEAREST_GW_SVR_ATTR_NEW_MOBILE_NODE, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0x0000, 0xFFF8}, {0, 0}
    },
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

struct ZbZclClusterT *
ZbZclNearestGwServerAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_NEAREST_GATEWAY, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_nearest_gw_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_nearest_gw_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_NEAREST_GW_SVR_ATTR_NEAREST_GW, ZCL_NEAREST_GW_DEFAULT_NEAREST_GW);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_NEAREST_GW_SVR_ATTR_NEW_MOBILE_NODE, ZCL_NEAREST_GW_DEFAULT_NEW_MOBILE_NODE);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}
