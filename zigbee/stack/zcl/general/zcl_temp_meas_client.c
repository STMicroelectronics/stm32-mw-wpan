/* Copyright [2019 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl/general/zcl.temp.meas.h"

/*lint -e9087 "struct cluster_priv_t <- void [MISRA Rule 11.3 (REQUIRED)]" */

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
};

struct ZbZclClusterT *
ZbZclTempMeasClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_MEAS_TEMPERATURE, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}
