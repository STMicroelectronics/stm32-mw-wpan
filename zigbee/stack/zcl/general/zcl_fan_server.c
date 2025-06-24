/* Copyright [2017 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.fan.h"

/* Alarm cluster */
struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

/* Attributes */
static const struct ZbZclAttrT fanAttrList[] = {
    {
        ZCL_FAN_ATTR_MODE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, ZCL_FAN_MODE_SMART}, {0, 0}
    },
    {
        ZCL_FAN_ATTR_SEQUENCE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, ZCL_FAN_SEQ_OA}, {0, 0}
    },
};

struct ZbZclClusterT *
ZbZclFanServerAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_HVAC_FAN, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, fanAttrList, ZCL_ATTR_LIST_LEN(fanAttrList))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Set some initial default attribute values */
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_FAN_ATTR_MODE, ZCL_FAN_MODE_AUTO);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_FAN_ATTR_SEQUENCE, ZCL_FAN_SEQ_LMHA);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}
