/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.groups.h"
#include "zcl/general/zcl.identify.h"
#include "../zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */

#define DEF_NAME_SUPPORT                    0

struct ZbZclGroupsServerClusterT {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
};

struct cluster_priv_t {
    struct ZbZclClusterT *clusterPtr;
    uint16_t group_id;
    struct ZbZclHeaderT zclHdr;
    struct ZbApsdeDataIndT dataInd;
};

static enum ZclStatusCodeT ZbZclGroupsServerCommand(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);
static enum ZclStatusCodeT zcl_attr_cb(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrCbInfoT *cb);
static enum ZclStatusCodeT zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src, uint16_t attribute_id,
    const uint8_t *input_data, unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg);

/* Attributes */
static const struct ZbZclAttrT zcl_groups_server_attr_list[] = {
    /* Groups Attributes */
    {
        ZCL_GROUPS_ATTR_NAME_SUPPORT, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
};

struct ZbZclClusterT *
ZbZclGroupsServerAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct ZbZclGroupsServerClusterT *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct ZbZclGroupsServerClusterT), ZCL_CLUSTER_GROUPS, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    clusterPtr->cluster.command = ZbZclGroupsServerCommand;

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_groups_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_groups_server_attr_list))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GROUPS_ATTR_NAME_SUPPORT, DEF_NAME_SUPPORT);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static void
zcl_groups_identify_read_callback(const struct ZbZclReadRspT *readRsp, void *arg)
{
    struct cluster_priv_t *cb = arg;
    struct ZbZclClusterT *clusterPtr = cb->clusterPtr;
    uint16_t idTime;
    struct ZbApsmeAddGroupReqT req;
    struct ZbApsmeAddGroupConfT conf;

    do {
        if (readRsp->status != ZCL_STATUS_SUCCESS) {
            break;
        }
        if (readRsp->attr[0].length != 2) {
            break;
        }
        idTime = pletoh16(readRsp->attr[0].value);

        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "ZCL_GROUPS_COMMAND_ADD_IDENTIFYING: identifying= %d secs", idTime);

        /* Only ADD group if it is IDENTIFYING */
        if ((idTime == 0U) || (idTime == ZCL_INVALID_UNSIGNED_16BIT)) {
            break;
        }
        req.groupAddr = cb->group_id;
        req.endpt = ZbZclClusterGetEndpoint(clusterPtr);
        ZbApsmeAddGroupReq(clusterPtr->zb, &req, &conf);
    } while (false);

    /* Send the Default Response. We always return SUCCESS. This request
     * should be broadcast, so we should never return a response anyway. */
    ZbZclSendDefaultResponse(clusterPtr, &cb->dataInd, &cb->zclHdr, ZCL_STATUS_SUCCESS);
    /* Free the callback info */
    ZbHeapFree(clusterPtr->zb, cb);
}

static enum ZclStatusCodeT
ZbZclGroupsServerCommand(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct ZigBeeT *zb = clusterPtr->zb;
    uint8_t resp[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    uint8_t respLen = 0;
    uint8_t local_endpoint = ZbZclClusterGetEndpoint(clusterPtr);

    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    switch (zclHdrPtr->cmdId) {
        case ZCL_GROUPS_COMMAND_ADD:
        {
            struct ZbApsmeAddGroupReqT req;
            struct ZbApsmeAddGroupConfT conf;

            if (dataIndPtr->asduLength < 2U) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }

            (void)memset(&req, 0, sizeof(req));
            /* Group ID */
            req.groupAddr = pletoh16(dataIndPtr->asdu);
            req.endpt = local_endpoint;
            ZbApsmeAddGroupReq(zb, &req, &conf);

            ZCL_LOG_PRINTF(zb, __func__, "APSME-ADD-GROUP (0x%04x, 0x%02x): Status = 0x%02x\n",
                req.groupAddr, req.endpt, conf.status);

            if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
                return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            }

            /* Form the response */
            switch (conf.status) {
                case ZB_APS_STATUS_SUCCESS:
                    resp[respLen++] = 0x00U;
                    break;

                case ZB_APS_STATUS_TABLE_FULL:
                    resp[respLen++] = (uint8_t)ZCL_STATUS_INSUFFICIENT_SPACE;
                    break;

                default:
                    resp[respLen++] = (uint8_t)ZCL_STATUS_INVALID_FIELD;
                    break;
            }
            /* Overwrite status if we're out of bounds */
            if (req.groupAddr > ZCL_GROUPS_ID_MAX) {
                resp[0] = (uint8_t)ZCL_STATUS_INVALID_VALUE;
            }

            putle16(&resp[respLen], req.groupAddr);
            respLen += 2;

            ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_GROUPS_COMMAND_ADD, resp, respLen, false);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
        }

        case ZCL_GROUPS_COMMAND_VIEW:
        {
            uint16_t group_id;

            if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
                return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            }
            if (dataIndPtr->asduLength < 2U) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }

            /* Group ID */
            group_id = pletoh16(dataIndPtr->asdu);

            /* Form the response */
            if (group_id > ZCL_GROUPS_ID_MAX) {
                resp[respLen++] = (uint8_t)ZCL_STATUS_INVALID_VALUE;
            }
            else {
                resp[respLen++] = ZCL_STATUS_SUCCESS;
            }
            putle16(&resp[respLen], group_id);
            respLen += 2;
            /* VIEW can carry name, which we don't currently support. */
            resp[respLen++] = 0;

            if (!ZbApsGroupIsMember(zb, group_id, local_endpoint)) {
                resp[0] = ZCL_STATUS_NOT_FOUND;
            }
            ZCL_LOG_PRINTF(zb, __func__, "APSME-VIEW-GROUP (0x%04x, 0x%02x): Status = 0x%02x\n",
                group_id, local_endpoint, resp[0]);
            ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_GROUPS_COMMAND_VIEW, resp,
                respLen, false);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
        }

        case ZCL_GROUPS_COMMAND_GET_MEMBERSHIP:
        {
            uint8_t group_count;
            unsigned int max_groups;
            uint16_t group_id, *group_list;
            unsigned int i = 0, num_groups = 0;
            struct ZbApsBufT bufv;
            struct ZbZclAddrInfoT dstInfo;

            if (dataIndPtr->asduLength < 1) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }

            max_groups = (sizeof(resp) - 2) / 2;
            group_list = ZbHeapAlloc(zb, sizeof(uint16_t) * max_groups);
            if (group_list == NULL) {
                return ZCL_STATUS_INSUFFICIENT_SPACE;
            }

            group_count = dataIndPtr->asdu[i++];
            if (group_count == 0) {
                /* If the group count field of the command frame has a value of
                 * 0 indicating that the group list field is empty, the entity
                 * SHALL respond with all group identifiers of which the entity
                 * is a member. */
                num_groups = ZbApsGroupsGetMembership(zb, local_endpoint, group_list, max_groups);
            }
            else {
                /* If the group list field of the command frame contains at
                 * least one group of which the entity is a member, the
                 * entity SHALL respond with each entity group identifier
                 * that match a group in the group list field.
                 *
                 * If the group count is non-zero, and the group list field
                 * of the command frame does not contain any group of which
                 * the entity is a member, the entity SHALL only respond if
                 * the command is unicast. The response SHALL return a group
                 * count of zero. */
                while (group_count && ((i + 2) <= dataIndPtr->asduLength)) {
                    group_id = pletoh16(&dataIndPtr->asdu[i]);
                    i += 2;

                    if (ZbApsGroupIsMember(zb, group_id, local_endpoint)) {
                        group_list[num_groups++] = group_id;
                    }
                    group_count--;
                } /* while */
                if (group_count) {
                    ZCL_LOG_PRINTF(zb, __func__, "Error, get_membership command malformed (remaining group_count to parse = %d)",
                        group_count);
                    ZbHeapFree(zb, group_list);
                    return ZCL_STATUS_MALFORMED_COMMAND;
                }
            }

            resp[respLen++] = ZbApsGroupsGetCapacity(zb);
            resp[respLen++] = num_groups;
            for (i = 0; i < num_groups; i++) {
                putle16(&resp[respLen], group_list[i]);
                respLen += 2;
            }
            ZbHeapFree(zb, group_list);

            /* ZCL_LOG_PRINTF(zb, __func__, "APSME-MEMBERSHIP-GROUP: count= %d, gID= 0x%x\n", num_groups, grpAddr); */

            /* "If the group count is non-zero, and the group list field of the command frame does not
             * contain any group of which the entity is a member, the entity SHALL only respond if
             * the command is unicast." */
            if (ZbApsAddrIsBcast(&dataIndPtr->dst) && (group_count != 0) && (num_groups == 0)) {
                /* Drop bcast messages */
                return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            }

            /* EXEGIN - this check has been present for a long time, but is it correct? */
            /* resp[0] is not status, so can't use ZbZclSendClusterStatusResponse */
            if ((ZbApsAddrIsBcast(&dataIndPtr->dst)) || (dataIndPtr->dst.endpoint == ZB_ENDPOINT_BCAST)) {
                /* request was broadcast, so don't send response. */
                return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            }

            bufv.data = resp;
            bufv.len = respLen;

            /* Send */
            (void)memset(&dstInfo, 0, sizeof(dstInfo));
            dstInfo.addr = dataIndPtr->src;
            dstInfo.seqnum = zclHdrPtr->seqNum;
            dstInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);
            (void)ZbZclClusterCommandRsp(clusterPtr, &dstInfo, ZCL_GROUPS_COMMAND_GET_MEMBERSHIP, &bufv, 1U);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
        }

        case ZCL_GROUPS_COMMAND_REMOVE:
        {
            uint16_t group_id;
            struct ZbApsmeRemoveGroupReqT req;
            struct ZbApsmeRemoveGroupConfT conf;
            enum ZclStatusCodeT status;

            if (dataIndPtr->asduLength < 2) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            /* Group ID */
            group_id = pletoh16(dataIndPtr->asdu);

            /* Form the response */
            resp[respLen++] = ZCL_STATUS_SUCCESS;
            putle16(&resp[respLen], group_id);
            respLen += 2;

            /* APSME-REMOVE-GROUP.request / .confirm */
            req.groupAddr = group_id;
            req.endpt = local_endpoint;
            ZbApsmeRemoveGroupReq(zb, &req, &conf);
            if (conf.status != ZB_STATUS_SUCCESS) {
                status = ZCL_STATUS_NOT_FOUND;
            }
            else {
                status = ZCL_STATUS_SUCCESS;
            }

            ZCL_LOG_PRINTF(zb, __func__, "APSME-REMOVE-GROUP (0x%04x, 0x%02x): Status = 0x%02x\n",
                group_id, local_endpoint, status);

            if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
                return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            }

            if (group_id > ZCL_GROUPS_ID_MAX) {
                resp[0] = (uint8_t)ZCL_STATUS_INVALID_VALUE;
            }
            else {
                resp[0] = status;
            }

            ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_GROUPS_COMMAND_REMOVE, resp,
                respLen, false);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
        }

        case ZCL_GROUPS_COMMAND_REMOVE_ALL:
        {
            struct ZbApsmeRemoveAllGroupsReqT req;
            struct ZbApsmeRemoveAllGroupsConfT conf;

            req.endpt = local_endpoint;
            ZbApsmeRemoveAllGroupsReq(zb, &req, &conf);
            ZCL_LOG_PRINTF(zb, __func__, "APSME-REMOVEALL-GROUP(0x%x): Status = 0x%02x\n",
                req.endpt, conf.status);
            /* NOTE - REMOVE_ALL doesn't send a SPECIFIC response! */
            if (conf.status != ZB_STATUS_SUCCESS) {
                return ZCL_STATUS_FAILURE;
            }
            return ZCL_STATUS_SUCCESS;
        }

        case ZCL_GROUPS_COMMAND_ADD_IDENTIFYING:
        {
            struct cluster_priv_t *cb;
            struct ZbZclReadReqT readReq;
            uint16_t group_id, nwkAddr;
            struct ZbZclClusterT *identify_client;
            enum ZclStatusCodeT status;

            if (dataIndPtr->asduLength < 2) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            /* Group ID */
            group_id = pletoh16(dataIndPtr->asdu);
            if (group_id > ZCL_GROUPS_ID_MAX) {
                return ZCL_STATUS_INVALID_VALUE;
            }

            cb = ZbHeapAlloc(zb, sizeof(struct cluster_priv_t));
            if (cb == NULL) {
                return ZCL_STATUS_FAILURE;
            }
            (void)memset(cb, 0, sizeof(struct cluster_priv_t));
            cb->clusterPtr = clusterPtr;
            cb->group_id = group_id;
            (void)memcpy(&cb->zclHdr, zclHdrPtr, sizeof(struct ZbZclHeaderT));
            (void)memcpy(&cb->dataInd, dataIndPtr, sizeof(struct ZbApsdeDataIndT));

            (void)ZbNwkGet(zb, ZB_NWK_NIB_ID_NetworkAddress, &nwkAddr, sizeof(nwkAddr));
            readReq.dst.mode = ZB_APSDE_ADDRMODE_SHORT;
            readReq.dst.nwkAddr = nwkAddr;
            readReq.dst.endpoint = ZbZclClusterGetEndpoint(clusterPtr);
            readReq.count = 1;
            readReq.attr[0] = ZCL_IDENTIFY_ATTR_TIME;

            /* We need an Identify Client to do the read. Create a mocked version. */
            identify_client = ZbHeapAlloc(zb, sizeof(struct ZbZclClusterT));
            if (identify_client == NULL) {
                return ZCL_STATUS_INSUFFICIENT_SPACE;
            }
            (void)memset(identify_client, 0, sizeof(struct ZbZclClusterT));
            identify_client->zb = zb;
            identify_client->clusterId = ZCL_CLUSTER_IDENTIFY;
            identify_client->endpoint = ZbZclClusterGetEndpoint(clusterPtr);
            identify_client->minSecurity = ZB_APS_STATUS_SECURED_NWK_KEY;
            identify_client->profileId = clusterPtr->profileId;
            identify_client->txOptions = 0U;
            identify_client->discoverRoute = false;
            identify_client->radius = 1U;
            identify_client->maxAsduLength = (uint16_t)ZB_APS_CONST_SAFE_APSSEC_PAYLOAD_SIZE;
            identify_client->direction = ZCL_DIRECTION_TO_CLIENT;
            (void)ZbZclClusterSetMinSecurity(identify_client, clusterPtr->minSecurity);
            status = ZbZclReadReq(identify_client, &readReq, zcl_groups_identify_read_callback, cb);
            ZbHeapFree(zb, identify_client);
            if (status != ZCL_STATUS_SUCCESS) {
                return status;
            }
            /* Response is sent from zcl_groups_identify_read_callback */
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
        }

        default:
            /* Unsupported command*/
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
}

static enum ZclStatusCodeT
zcl_attr_cb(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrCbInfoT *cb)
{
    if (cb->type == ZCL_ATTR_CB_TYPE_WRITE) {
        return zcl_attr_write_cb(clusterPtr, cb->src, cb->info->attributeId, cb->zcl_data, cb->zcl_len,
            cb->attr_data, cb->write_mode, cb->app_cb_arg);
    }
    else {
        return ZCL_STATUS_FAILURE;
    }
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src, uint16_t attribute_id,
    const uint8_t *input_data, unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg)
{
    enum ZclStatusCodeT status = ZCL_STATUS_SUCCESS;
    unsigned int len = 0;

    switch (attribute_id) {
        case ZCL_GROUPS_ATTR_NAME_SUPPORT:
        {
            uint8_t val;

            val = input_data[0];
            if ((val & ~(ZCL_GROUPS_NAME_SUPPORT_MASK)) != 0U) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;
        }

        default:
            status = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            break;
    }

    if (((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) && (status == ZCL_STATUS_SUCCESS)) {
        (void)memcpy(attr_data, input_data, len);
    }
    return status;
}
