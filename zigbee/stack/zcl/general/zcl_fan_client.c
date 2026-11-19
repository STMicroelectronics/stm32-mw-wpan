/* Copyright [2017 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.fan.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

struct ZbZclClusterT *
ZbZclFanClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_HVAC_FAN, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}
