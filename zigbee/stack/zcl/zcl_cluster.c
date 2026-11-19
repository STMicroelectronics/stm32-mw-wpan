/* Copyright [2009 - 2025] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl_attr.h"

#define ZCL_OTA_COMMAND_IMAGE_NOTIFY       0x00
#define ZCL_METER_SVR_ATTR_DEVICE_TYPE     0x0306

uint8_t
ZbZclClusterGetEndpoint(struct ZbZclClusterT *cluster)
{
    return cluster->endpoint;
}

void
ZbZclClusterSetCallbackArg(struct ZbZclClusterT *cluster, void *app_cb_arg)
{
    cluster->app_cb_arg = app_cb_arg;
}

void
ZbZclClusterSetMfrCode(struct ZbZclClusterT *cluster, uint16_t mfrCode)
{
    cluster->mfrCode = mfrCode;
}

enum ZbZclClusterIdT
ZbZclClusterGetClusterId(struct ZbZclClusterT *cluster)
{
    return cluster->clusterId;
}

void
ZbZclClusterSetProfileId(struct ZbZclClusterT *cluster, uint16_t profileId)
{
    cluster->profileId = profileId;

    /* EXEGIN - can we remove this check? */
    if (cluster->endpoint != ZB_ENDPOINT_BCAST) {
        /* Update the binding for the new profile ID */
        /* EXEGIN - if previous binding was to the bcast endpoint to receive InterPAN messages,
         * then this filter change will lose that behaviour. Need to check or track if cluster
         * should use bcast endpoint for filter, and not endpoint the cluster has been allocated
         * to. Currently, there should be no application facing clusters that need to use
         * InterPAN (i.e. Touchlink), so this should never be an issue. */
        ZbZclClusterUnbind(cluster);
        (void)ZbZclClusterBind(cluster, cluster->endpoint, cluster->profileId, cluster->direction);
    }
}

uint16_t
ZbZclClusterGetProfileId(struct ZbZclClusterT *cluster)
{
    return cluster->profileId;
}

bool
ZbZclClusterSetMinSecurity(struct ZbZclClusterT *cluster, enum ZbStatusCodeT minSecurity)
{
    bool retval = true;
    bool was_aps_secured;

    was_aps_secured = ((cluster->txOptions & ZB_APSDE_DATAREQ_TXOPTIONS_SECURITY) != 0U)
        && ((cluster->txOptions & ZB_APSDE_DATAREQ_TXOPTIONS_NWKKEY) == 0U);

    switch (minSecurity) {
        case ZB_APS_STATUS_UNSECURED:
            cluster->txOptions &= ~(uint16_t)(ZB_APSDE_DATAREQ_TXOPTIONS_NWKKEY);
            cluster->txOptions &= ~(uint16_t)(ZB_APSDE_DATAREQ_TXOPTIONS_SECURITY);
            if (was_aps_secured) {
                ZCL_LOG_PRINTF(cluster->zb, __func__,
                    "Warning, changing cluster (0x%04x on %d) default security level from APS to NONE",
                    cluster->clusterId, cluster->endpoint);
            }
            break;

        case ZB_APS_STATUS_SECURED_NWK_KEY:
            cluster->txOptions |= (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_NWKKEY;
            cluster->txOptions |= (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_SECURITY;
            if (was_aps_secured) {
                ZCL_LOG_PRINTF(cluster->zb, __func__,
                    "Warning, changing cluster (0x%04x on %d) default security level from APS to NWK",
                    cluster->clusterId, cluster->endpoint);
            }
            break;

        case ZB_APS_STATUS_SECURED_LINK_KEY:
            cluster->txOptions &= ~(uint16_t)(ZB_APSDE_DATAREQ_TXOPTIONS_NWKKEY);
            cluster->txOptions |= (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_SECURITY;
            break;

        default:
            retval = false;
            break;
    }
    if (retval) {
        cluster->minSecurity = minSecurity;
    }
    return retval;
}

bool
ZbZclClusterCheckMinSecurity(struct ZbZclClusterT *cluster,
    struct ZbApsdeDataIndT *dataIndPtr, struct ZbZclHeaderT *zclHdrPtr)
{
    bool retval = false;

    do {
        if (cluster->minSecurity == ZB_APS_STATUS_UNSECURED) {
            retval = true;
            break;
        }

        if (cluster->minSecurity == ZB_APS_STATUS_SECURED_NWK_KEY) {
            if ((dataIndPtr->securityStatus == ZB_APS_STATUS_SECURED_NWK_KEY)
                || (dataIndPtr->securityStatus == ZB_APS_STATUS_SECURED_LINK_KEY)) {
                retval = true;
            }
            break;
        }

        if (cluster->minSecurity == ZB_APS_STATUS_SECURED_LINK_KEY) {
            if (dataIndPtr->securityStatus == ZB_APS_STATUS_SECURED_LINK_KEY) {
                /* If it's APS secured, let it through. */
                retval = true;
                break;
            }
            if (dataIndPtr->securityStatus != ZB_APS_STATUS_SECURED_NWK_KEY) {
                /* If it's not at least NWK secured, then drop it. */
                break;
            }

            /* The OTA Client is allowed to receive an Image Notify network broadcast using only NWK security. */
            if ((cluster->clusterId == ZCL_CLUSTER_OTA_UPGRADE) && (cluster->direction == ZCL_DIRECTION_TO_CLIENT)) {
                /* Check if it's a broadcast Image Notify */
                if (ZbApsAddrIsBcast(&dataIndPtr->dst) && (zclHdrPtr->frameCtrl.frameType == ZCL_FRAMETYPE_CLUSTER)
                    && (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_CLIENT)
                    && (zclHdrPtr->cmdId == (uint8_t)ZCL_OTA_COMMAND_IMAGE_NOTIFY)) {
                    /* Let it through */
                    retval = true;
                    break;
                }
                break;
            }

            /* ZSDK-4540 MeteringDeviceType attribute in the Metering Server Cluster is exempt from APS security */
            if ((cluster->clusterId == ZCL_CLUSTER_SIMPLE_METERING) && (cluster->direction == ZCL_DIRECTION_TO_SERVER)) {
                /* Check for a Read Request. Note, the ASDU is pointing to immediately after the ZCL Command ID byte. */
                if ((zclHdrPtr->frameCtrl.frameType == ZCL_FRAMETYPE_PROFILE) && (zclHdrPtr->cmdId == (uint8_t)ZCL_COMMAND_READ)
                    && (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_SERVER) && (dataIndPtr->asduLength >= 2U)) {
                    uint16_t attributeId = pletoh16(dataIndPtr->asdu);

                    /* Note, can only be 1 attribute in the Read request, and must be MeteringDeviceType. */
                    if (attributeId == (uint16_t)ZCL_METER_SVR_ATTR_DEVICE_TYPE) {
                        /* Let it through */
                        retval = true;
                        break;
                    }
                }
            }
            if ((cluster->clusterId == ZCL_CLUSTER_SIMPLE_METERING) && (cluster->direction == ZCL_DIRECTION_TO_CLIENT)) {
                /* Check for a Read Response. Note, the ASDU is pointing to immediately after the ZCL Command ID byte. */
                if ((zclHdrPtr->frameCtrl.frameType == ZCL_FRAMETYPE_PROFILE)
                    && (zclHdrPtr->cmdId == (uint8_t)ZCL_COMMAND_READ_RESPONSE)
                    && (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_CLIENT)
                    && (dataIndPtr->asduLength >= 2U)) {
                    uint16_t attributeId = pletoh16(dataIndPtr->asdu);

                    /* Note, can only be 1 attribute in the Read request, and must be MeteringDeviceType. */
                    if (attributeId == (uint16_t)ZCL_METER_SVR_ATTR_DEVICE_TYPE) {
                        /* Let it through */
                        retval = true;
                        break;
                    }
                }
                break;
            }

            /* No other checks */
            break;
        }
    } while (false);

    return retval;
}

void
ZbZclClusterSetTxOptions(struct ZbZclClusterT *cluster, uint16_t txOptions)
{
    if ((txOptions & ZB_APSDE_DATAREQ_TXOPTIONS_VECTOR) != 0U) {
        /* Vector Buffer not supported by the ZbZclClusterCommandxxx APIs. */
        return;
    }
    cluster->txOptions = txOptions;
}

uint16_t
ZbZclClusterGetTxOptions(struct ZbZclClusterT *cluster)
{
    /* ZB_APSDE_DATAREQ_TXOPTIONS_VECTOR should never be set here, but
     * make sure we don't return this bit set. */
    return cluster->txOptions & ~(uint16_t)(ZB_APSDE_DATAREQ_TXOPTIONS_VECTOR);
}

uint16_t
ZbZclTxOptsFromSecurityStatus(enum ZbStatusCodeT security_status)
{
    uint16_t tx_opts = 0;

    tx_opts |= (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_ACK;
    tx_opts |= (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_FRAG;
    if (security_status == ZB_APS_STATUS_SECURED_LINK_KEY) {
        tx_opts |= (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_SECURITY;
    }
    else if (security_status == ZB_APS_STATUS_SECURED_NWK_KEY) {
        tx_opts |= (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_SECURITY;
        tx_opts |= (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_NWKKEY;
    }
    else {
        /* empty */
    }
    return tx_opts;
}

enum ZbZclDirectionT
ZbZclClusterGetDirection(struct ZbZclClusterT *cluster)
{
    return cluster->direction;
}

const char *
ZbZclClusterGetDirectionStr(struct ZbZclClusterT *cluster)
{
    const char *retstr;

    switch (cluster->direction) {
        case ZCL_DIRECTION_TO_SERVER:
            retstr = "server";
            break;

        case ZCL_DIRECTION_TO_CLIENT:
            retstr = "client";
            break;

        case ZCL_DIRECTION_ANY:
            retstr = "both";
            break;

        default:
            retstr = "unknown";
            break;
    }
    return retstr;
}

void
ZbZclClusterSetDiscoverRoute(struct ZbZclClusterT *cluster, bool discoverRoute)
{
    cluster->discoverRoute = discoverRoute;
}

void
ZbZclClusterSetRadius(struct ZbZclClusterT *cluster, uint8_t radius)
{
    cluster->radius = radius;
}

uint8_t
ZbZclClusterGetRadius(struct ZbZclClusterT *cluster)
{
    return cluster->radius;
}

bool
ZbZclClusterSetMaxAsduLength(struct ZbZclClusterT *cluster, uint16_t maxAsduLength)
{
    uint16_t max = maxAsduLength;

    if (max > ZB_HEAP_MAX_ALLOC) {
        return false;
    }
    /* Ensure a sane minimum value. */
    if (max < ZB_APS_CONST_SAFE_APSSEC_PAYLOAD_SIZE) {
        max = (uint16_t)ZB_APS_CONST_SAFE_APSSEC_PAYLOAD_SIZE;
    }
    cluster->maxAsduLength = max;
    return true;
}

unsigned int
ZbZclClusterGetMaxAsduLength(struct ZbZclClusterT *cluster)
{
    return cluster->maxAsduLength;
}

void
ZbZclClusterInitCommandReq(struct ZbZclClusterT *cluster, struct ZbZclCommandReqT *cmdReq)
{
    (void)memset(cmdReq, 0, sizeof(struct ZbZclCommandReqT));
    cmdReq->profileId = cluster->profileId;
    cmdReq->clusterId = cluster->clusterId;
    cmdReq->srcEndpt = cluster->endpoint;
    cmdReq->txOptions = cluster->txOptions;
    cmdReq->discoverRoute = cluster->discoverRoute;
    cmdReq->radius = cluster->radius;
    /* Fill in some of the ZCL header struct? */
}

void
ZbZclClusterInitApsdeReq(struct ZbZclClusterT *cluster, struct ZbApsdeDataReqT *apsReq, struct ZbApsdeDataIndT *dataIndPtr)
{
    (void)memset(apsReq, 0, sizeof(struct ZbApsdeDataReqT));
    apsReq->profileId = cluster->profileId;
    apsReq->clusterId = (uint16_t)cluster->clusterId;
    apsReq->srcEndpt = cluster->endpoint;
    apsReq->txOptions = cluster->txOptions;
    apsReq->discoverRoute = cluster->discoverRoute;
    apsReq->radius = cluster->radius;

    if (dataIndPtr != NULL) {
        if (apsReq->srcEndpt == ZB_ENDPOINT_BCAST) {
            apsReq->srcEndpt = dataIndPtr->dst.endpoint;
            /* EXEGIN - what if srcEndpt is still == ZB_ENDPOINT_BCAST.
             * This will happen with the Basic and Time clusters that have
             * global (singleton) clusters when the destination for this
             * request was to ZB_ENDPOINT_BCAST endpoint.
             * Can we get the endpoint from the message filter? */
        }
        if (dataIndPtr->profileId != (uint16_t)ZCL_PROFILE_WILDCARD) {
            apsReq->profileId = dataIndPtr->profileId;
        }
    }
}
