/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/zcl.h"
#include "zcl/general/zcl.wcm.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

struct ZbZclClusterT *
ZbZclWaterContentMeasClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, enum ZbZclClusterIdT clusterID)
{
    struct cluster_priv_t *clusterPtr;

    if ((clusterID != ZCL_CLUSTER_MEAS_HUMIDITY)
        && (clusterID != ZCL_CLUSTER_MEAS_LEAF_WETNESS)
        && (clusterID != ZCL_CLUSTER_MEAS_SOIL_MOISTURE)) {
        return NULL;
    }

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), clusterID, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Write default values to attributes */

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}
