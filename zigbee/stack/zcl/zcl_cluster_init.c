/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/zcl.h"
#include "zcl_attr.h"
#include "zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */

/* Default cluster TX Options (NWK layer security, APS ACK, fragmentation allowed) */
#define ZCL_CLUSTER_TXOPTIONS_DEFAULT \
    (ZB_APSDE_DATAREQ_TXOPTIONS_SECURITY | \
     ZB_APSDE_DATAREQ_TXOPTIONS_NWKKEY | \
     ZB_APSDE_DATAREQ_TXOPTIONS_ACK | \
     ZB_APSDE_DATAREQ_TXOPTIONS_FRAG)

static const struct ZbZclAttrT zcl_attr_cluster_mandatory_revision = {
    ZCL_GLOBAL_ATTR_CLUSTER_REV, ZCL_DATATYPE_UNSIGNED_16BIT,
    ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
};

#ifndef CONFIG_ZB_ZCL_NO_PERSIST
static void zcl_cluster_persist_timer(struct ZigBeeT *zb, void *arg);
static uint8_t * zcl_persist_read_attrs(struct ZbZclClusterT *clusterPtr, uint16_t *len);
enum ZclStatusCodeT zcl_persist_send_cache(struct ZigBeeT *zb, uint16_t src_cluster_id,
    uint8_t src_direction, uint16_t endpoint, const uint8_t *payload, uint16_t len);
#endif

/*
 *      ZSDK-2228: If command callback is NULL, any input command will
 *      generate a Default Response.
 *
 *      All clusters should define a command callback to at least determine
 *      whether the incoming command is valid or not. If it's an unsupported
 *      command ID, return ZCL_STATUS_UNSUPP_COMMAND.
 *      Otherwise return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE.
 *
 *      The command may be handled by a separate filter created to receive
 *      a response to a request, for instance.
 */
static enum ZclStatusCodeT
zcl_cluster_command_dummy(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
}

void *
ZbZclClusterAlloc(struct ZigBeeT *zb, unsigned int alloc_sz, enum ZbZclClusterIdT cluster_id,
    uint8_t endpoint, enum ZbZclDirectionT direction)
{
    struct ZbZclClusterT *cluster;

    if (alloc_sz < sizeof(struct ZbZclClusterT)) {
        return NULL;
    }
    cluster = ZbHeapAlloc(zb, alloc_sz);
    if (cluster == NULL) {
        return NULL;
    }
    (void)memset(cluster, 0, alloc_sz);
    LINK_LIST_INIT(&cluster->link);

    cluster->zb = zb;
    cluster->clusterId = cluster_id;
    cluster->endpoint = endpoint;
    cluster->mfrCode = 0x0000U;
    cluster->profileId = ZCL_PROFILE_HOME_AUTOMATION;
    cluster->txOptions = (uint16_t)ZCL_CLUSTER_TXOPTIONS_DEFAULT;
    cluster->discoverRoute = true;
    cluster->radius = 0U;
    cluster->maxAsduLength = (uint16_t)ZB_APS_CONST_SAFE_APSSEC_PAYLOAD_SIZE;
    cluster->direction = direction;
    LINK_LIST_INIT(&cluster->attributeList);
    LINK_LIST_INIT(&cluster->reports.list);

    cluster->reports.reset_filter = ZbMsgFilterRegister(zb, ZB_MSG_FILTER_RESET_REPORTS,
            ZB_MSG_INTERNAL_PRIO + 1, zcl_reporting_stack_event, cluster);
    if (cluster->reports.reset_filter == NULL) {
        ZbZclClusterFree(cluster);
        return NULL;
    }

    /* Allocate the timers */
    cluster->reports.timer = ZbTimerAlloc(zb, zcl_cluster_reports_timer, cluster);
    if (cluster->reports.timer == NULL) {
        ZbZclClusterFree(cluster);
        return NULL;
    }

#ifndef CONFIG_ZB_ZCL_NO_PERSIST
    cluster->persist_timer = ZbTimerAlloc(zb, zcl_cluster_persist_timer, cluster);
    if (cluster->persist_timer == NULL) {
        ZbZclClusterFree(cluster);
        return NULL;
    }
#endif

    (void)ZbZclClusterSetMinSecurity(cluster, ZB_APS_STATUS_SECURED_NWK_KEY);

    /* Allocate the mandatory attributes */
    if (ZbZclAttrAppendList(cluster, &zcl_attr_cluster_mandatory_revision, 1U) != ZCL_STATUS_SUCCESS) {
        ZbHeapFree(zb, cluster);
        return NULL;
    }

    /* Assume that all of our clusters are up to ZCL Revision 6, and start at version 1. */
    (void)ZbZclAttrIntegerWrite(cluster, (uint16_t)ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    return cluster;
}

enum ZclStatusCodeT
ZbZclClusterAttach(struct ZbZclClusterT *cluster)
{
    if ((cluster->endpoint == ZB_ENDPOINT_BCAST) && (cluster->clusterId != ZCL_CLUSTER_BASIC) && (cluster->clusterId != ZCL_CLUSTER_TIME)) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Warning, cluster 0x%04x with broadcast endpoint (not creating APS filter).", cluster->clusterId);
    }

    if (cluster->endpoint != ZB_ENDPOINT_BCAST) {
        enum ZclStatusCodeT status;

        /* Create a binding for this cluster to receive APS messages */
        status = ZbZclClusterBind(cluster, cluster->endpoint, cluster->profileId, cluster->direction);
        if (status != ZCL_STATUS_SUCCESS) {
            return status;
        }
    }

    if (cluster->command == NULL) {
        cluster->command = zcl_cluster_command_dummy;
    }
    return ZCL_STATUS_SUCCESS;
}

static void
ZbZclClusterDetach(struct ZbZclClusterT *cluster)
{
    if (cluster->zb == NULL) {
        return;
    }

    /* Remove the APS packet filter (if set) */
    ZbZclClusterUnbind(cluster);

    /* Remove the Alarms APS packet filter (if set) */
    ZbZclClusterRemoveAlarmResetHandler(cluster);

    if (cluster->endpoint != ZB_ENDPOINT_BCAST) {
        /* Remove this cluster from the endpoint's cluster list, if it was added. */
        (void)ZbZclClusterEndpointRemove(cluster);
    }
}

void
ZbZclClusterFree(struct ZbZclClusterT *cluster)
{
    struct ZigBeeT *zb = cluster->zb;

    if (zb == NULL) {
        return;
    }

#ifndef CONFIG_ZB_ZCL_NO_PERSIST
    if (cluster->persist_timer != NULL) {
        ZbTimerFree(cluster->persist_timer);
        cluster->persist_timer = NULL;
    }
#endif
    if (cluster->reports.timer != NULL) {
        ZbTimerFree(cluster->reports.timer);
        cluster->reports.timer = NULL;
    }
    if (cluster->reports.reset_filter != NULL) {
        ZbMsgFilterRemove(zb, cluster->reports.reset_filter);
        cluster->reports.reset_filter = NULL;
    }

    /* Cleanup any reporting handlers. */
    ZbZclReportCleanup(cluster);

    ZbZclClusterDetach(cluster);

    /* Free the attributes */
    ZbZclAttrFreeList(cluster);

    /* Use the callback to cleanup/free the cluster. */
    if (cluster->cleanup != NULL) {
        cluster->cleanup(cluster);
    }

    ZbHeapFree(zb, cluster);
}

/* NOTE: The following code is located here instead of zcl_cluster_persist.c, because
 * of how the stack is split on multi-core platforms. zcl_cluster_persist.c is
 * co-located with the stack and this file is co-located with the application clusters. */
#ifndef CONFIG_ZB_ZCL_NO_PERSIST
/* This is a cluster specific timer that is only run when we want
 * to save a cluster's attributes (ZCL_ATTR_FLAG_PERSISTABLE). */
static void
zcl_cluster_persist_timer(struct ZigBeeT *zb, void *arg)
{
    struct ZbZclClusterT *cluster = arg;
    uint8_t *attrBuf;
    uint16_t bufLen;

    attrBuf = zcl_persist_read_attrs(cluster, &bufLen);
    if (attrBuf != NULL) {
        (void)zcl_persist_send_cache(cluster->zb, (uint16_t)cluster->clusterId,
            (uint8_t)cluster->direction, cluster->endpoint, attrBuf, bufLen);
        ZbHeapFree(cluster->zb, attrBuf);
    }
}

/* The format of the return buffer is:
 *  |  (2 octets)   |     (2 octets)   |    N octets    |
 *  | Attribute ID  | Attribute Length | Attribute Data | ...
 */
static uint8_t *
zcl_persist_read_attrs(struct ZbZclClusterT *cluster, uint16_t *len)
{
    uint8_t *bufPtr;
    struct LinkListT *p;
    struct ZbZclAttrListEntryT *attrPtr;
    uint16_t i = 0, allocLen = 0;
    int ret;

    /* Get the size of the attribute data */
    for (p = LINK_LIST_HEAD(&cluster->attributeList); p != NULL; p = LINK_LIST_NEXT(p, &cluster->attributeList)) {
        attrPtr = LINK_LIST_ITEM(p, struct ZbZclAttrListEntryT, link);
        if ((attrPtr->info->flags & ZCL_ATTR_FLAG_PERSISTABLE) == 0U) {
            continue;
        }
        /* Note, just use the attribute's valSz. If it uses a custom read functionm,
         * then valSz represents the maximum size the attribute value can take. */
        if ((attrPtr->valSz == 0U) || (attrPtr->valSz > 0xffffU)) {
            continue;
        }
        /* Attribute ID (2) and Attribute Length (2) */
        allocLen += 4U;
        /* Attribute Data */
        allocLen += (uint16_t)attrPtr->valSz;
    }

    if (allocLen == 0U) {
        return NULL;
    }

    bufPtr = ZbHeapAlloc(cluster->zb, allocLen);
    if (bufPtr == NULL) {
        return NULL;
    }

    /* Read the attribute data */
    for (p = LINK_LIST_HEAD(&cluster->attributeList); p != NULL;
         p = LINK_LIST_NEXT(p, &cluster->attributeList)) {
        attrPtr = LINK_LIST_ITEM(p, struct ZbZclAttrListEntryT, link);

        /* Check if the attribute should be persisted */
        if ((attrPtr->info->flags & ZCL_ATTR_FLAG_PERSISTABLE) == 0U) {
            continue;
        }

        /* If the attribute has a custom read function, use it. */
        if ((attrPtr->info->flags & ZCL_ATTR_FLAG_CB_READ) != 0U) {
            uint8_t *attrData;
            uint16_t attrMaxLen;
            struct ZbZclAttrCbInfoT cb;
            enum ZclStatusCodeT status;

            attrData = &bufPtr[i + 4U];
            attrMaxLen = allocLen - i - 4U;

            (void)memset(&cb, 0, sizeof(struct ZbZclAttrCbInfoT));
            cb.info = attrPtr->info;
            cb.type = ZCL_ATTR_CB_TYPE_READ;
            cb.zcl_data = attrData;
            cb.zcl_len = attrMaxLen;
            cb.app_cb_arg = cluster->app_cb_arg;
            status = ZbZclAttrCallbackExec(cluster, attrPtr, &cb);
            if (status != ZCL_STATUS_SUCCESS) {
                /* EXEGIN - print error message */
                continue;
            }
            /* Get the actual length */
            ret = ZbZclAttrParseLength(attrPtr->info->dataType, attrData, attrMaxLen, 0);
            if ((ret <= 0) || (ret > 0xffff)) {
                /* EXEGIN - print error message */
                continue;
            }
            if ((i + 4U + (uint16_t)ret) > allocLen) {
                ZbHeapFree(cluster->zb, bufPtr);
                return NULL;
            }
            /* Attribute ID */
            putle16(&bufPtr[i], attrPtr->info->attributeId);
            i += 2U;
            /* Attribute Length */
            putle16(&bufPtr[i], (uint16_t)ret);
            i += 2U;
            /* Attribute Data (already in the buffer) */
            i += (uint16_t)ret;
        }
        /* Otherwise, the attribute data is in attrPtr->valBuf */
        else {
            ret = ZbZclAttrParseLength(attrPtr->info->dataType, attrPtr->valBuf, attrPtr->valSz, 0);
            if ((ret <= 0) || (ret > 0xffff)) {
                /* EXEGIN - print error message */
                continue;
            }
            if ((i + 4U + (uint16_t)ret) > allocLen) {
                ZbHeapFree(cluster->zb, bufPtr);
                return NULL;
            }
            /* Attribute ID */
            putle16(&bufPtr[i], attrPtr->info->attributeId);
            i += 2U;
            /* Attribute Length */
            putle16(&bufPtr[i], (uint16_t)ret);
            i += 2U;
            /* Attribute Data */
            (void)memcpy(&bufPtr[i], attrPtr->valBuf, (uint32_t)ret);
            i += (uint16_t)ret;
        }
    }

    *len = i;
    return bufPtr;
}

/* Called by a cluster to push the attribute data it wants to save.
 * The destination for these frames is the local ZCL Persistence Cluster
 * (ZCL_CLUSTER_PERSIST), which is part of the ZigBee Stack itself.
 *
 * The format of the payload is:
 *  |  (2 octets)   |     (2 octets)   |    N octets    |
 *  | Attribute ID  | Attribute Length | Attribute Data | ...
*/
enum ZclStatusCodeT
zcl_persist_send_cache(struct ZigBeeT *zb, uint16_t src_cluster_id, uint8_t src_direction, uint16_t endpoint,
    const uint8_t *payload, uint16_t len)
{
    struct ZbApsdeDataReqT apsData;
    struct ZbZclHeaderT zclHdr;
    uint8_t zclHdrBuf[ZCL_HEADER_MAX_SIZE];
    int zclHdrLen;
    struct ZbApsBufT bufv[3]; /* ZCL Header | SrcCluster | Payload */
    unsigned int bufIdx = 0;
    uint8_t clusterBuf[3];

    if (endpoint == ZB_ENDPOINT_BCAST) {
        return ZCL_STATUS_INVALID_FIELD;
    }

    /* EXEGIN - max size? */
    if (len > (0xffffU - ZCL_HEADER_MAX_SIZE)) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    /* Construct the ZCL header. */
    (void)memset(&zclHdr, 0, sizeof(struct ZbZclHeaderT));
    zclHdr.frameCtrl.frameType = ZCL_FRAMETYPE_CLUSTER;
    /* The persistence cluster is a manufacturer-specific cluster,
     * so set the manufacturer bit and code in the header. */
    zclHdr.frameCtrl.manufacturer = 1;
    zclHdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
    zclHdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    zclHdr.manufacturerCode = ZCL_MANUF_CODE_INTERNAL;
    zclHdr.seqNum = ZbZclGetNextSeqnum();
    zclHdr.cmdId = ZCL_PERSIST_SVR_CMD_PUSH;
    zclHdrLen = ZbZclAppendHeader(&zclHdr, zclHdrBuf, sizeof(zclHdrBuf));
    if (zclHdrLen < 0) {
        return ZCL_STATUS_INVALID_FIELD;
    }
    bufv[bufIdx].data = zclHdrBuf;
    bufv[bufIdx].len = (uint32_t)zclHdrLen;
    bufIdx++;

    /* ZCL payload: Source Cluster ID (2 octets) and Direction (1 octet) */
    putle16(clusterBuf, src_cluster_id);
    clusterBuf[2] = src_direction;
    bufv[bufIdx].data = clusterBuf;
    bufv[bufIdx].len = sizeof(clusterBuf);
    bufIdx++;

    /* ZCL payload (Data) */
    bufv[bufIdx].data = payload;
    bufv[bufIdx].len = len;
    bufIdx++;

    /* Fill in the APSDE-DATA.request. */
    (void)memset(&apsData, 0, sizeof(struct ZbApsdeDataReqT));
    /* Loopback */
    apsData.dst.mode = ZB_APSDE_ADDRMODE_EXT;
    apsData.dst.extAddr = ZbExtendedAddress(zb);
    apsData.dst.endpoint = ZB_ENDPOINT_BCAST;
    apsData.profileId = ZCL_PROFILE_WILDCARD;
    apsData.clusterId = (uint16_t)ZCL_CLUSTER_PERSIST;
    apsData.srcEndpt = endpoint;
    apsData.asdu = bufv;
    apsData.asduLength = (uint16_t)bufIdx;
    apsData.discoverRoute = false;
    apsData.radius = 0;
    apsData.txOptions = ZB_APSDE_DATAREQ_TXOPTIONS_VECTOR;
    apsData.txOptions |= ZB_APSDE_DATAREQ_TXOPTIONS_FRAG;
    apsData.txOptions |= ZB_APSDE_DATAREQ_TXOPTIONS_ACK;

    ZCL_LOG_PRINTF(zb, __func__, "Sending persist PUSH (ep = %d, cl = 0x%04x, len = %d)", endpoint, src_cluster_id, len);

    /* Send the APSDE-DATA.request to the ZCL Persistence Server via local loopback. */
    if (ZbApsdeDataReqCallback(zb, &apsData, NULL, NULL) != ZB_APS_STATUS_SUCCESS) {
        return ZCL_STATUS_FAILURE;
    }
    return ZCL_STATUS_SUCCESS;
}

#endif
