/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

/*-------------------------------------------------
 *  DESCRIPTION
 *      HA IAS devices Implementation.
 *-------------------------------------------------
 */

#include "zcl/security/zcl.ias_zone.h"

struct cluster_priv_t {
    /* The ZCL Cluster struct must go first for inheritance. */
    struct ZbZclClusterT cluster;

    /* Application callbacks */
    struct ZbZclIasZoneClientCallbacksT callbacks;
};

static enum ZclStatusCodeT zcl_ias_zone_client_command(struct ZbZclClusterT *, struct ZbZclHeaderT *, struct ZbApsdeDataIndT *);

struct ZbZclClusterT *
ZbZclIasZoneClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclIasZoneClientCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_SECURITY_IAS_ZONE, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.command = zcl_ias_zone_client_command;

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);
    if (callbacks != NULL) {
        (void)memcpy(&clusterPtr->callbacks, callbacks, sizeof(struct ZbZclIasZoneClientCallbacksT));
    }
    else {
        (void)memset(&clusterPtr->callbacks, 0, sizeof(struct ZbZclIasZoneClientCallbacksT));
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static uint64_t
aps_addr_get_ext(struct ZigBeeT *zb, const struct ZbApsAddrT *addr)
{
    if (addr->mode == ZB_APSDE_ADDRMODE_EXT) {
        return addr->extAddr;
    }
    else if (addr->mode == ZB_APSDE_ADDRMODE_SHORT) {
        return ZbNwkAddrLookupExt(zb, addr->nwkAddr);
    }
    else {
        return 0;
    }
}

static enum ZclStatusCodeT
zcl_ias_zone_client_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *iasCluster = (struct cluster_priv_t *)clusterPtr;
    unsigned int i = 0;

    if (zclHdrPtr->frameCtrl.manufacturer) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    switch (zclHdrPtr->cmdId) {
        case ZCL_IAS_ZONE_SVR_CMD_ZONE_STATUS_CHANGE_NOTIFY:
        {
            struct ZbZclIasZoneServerStatusChangeNotifyT req;

            if (dataIndPtr->asduLength < 6) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (!iasCluster->callbacks.zone_status_change) {
                /* EXEGIN - or just return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE */
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            /* Parse the request */
            req.zone_status = (enum ZbZclIasZoneServerZoneStatusT)pletoh16(&dataIndPtr->asdu[i]);
            i += 2;
            req.ext_status = dataIndPtr->asdu[i++];
            req.zone_id = dataIndPtr->asdu[i++];
            req.delay = pletoh16(&dataIndPtr->asdu[i]);
            i += 2;

            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Zone ID = 0x%02x, Zone Status (0x%04x).", req.zone_id, req.zone_status);

            iasCluster->callbacks.zone_status_change(clusterPtr, clusterPtr->app_cb_arg, &req, &dataIndPtr->src);

            /* EXEGIN - review whether we send a Default Response or not.
             * Return ZCL_STATUS_SUCCESS or ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE */
            return ZCL_STATUS_SUCCESS;
        }

        case ZCL_IAS_ZONE_SVR_CMD_ZONE_ENROLL_REQUEST:
        {
            struct ZbZclIasZoneServerEnrollRequestT req;
            enum ZbZclIasZoneClientResponseCodeT enrRspCode;
            uint8_t zone_id;
            uint8_t payload[2];
            enum ZclStatusCodeT status;
            uint64_t ext_src_addr;

            ext_src_addr = aps_addr_get_ext(clusterPtr->zb, &dataIndPtr->src);
            if (ext_src_addr == 0) {
                return ZCL_STATUS_FAILURE;
            }

            if (dataIndPtr->asduLength < 4) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (!iasCluster->callbacks.zone_enroll_req) {
                payload[0] = ZCL_IAS_ZONE_CLI_RESP_NOT_SUPPORTED;
                payload[1] = 0x00; /* Zone ID */
                if (ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr,
                        ZCL_IAS_ZONE_CLI_CMD_ZONE_ENROLL_RESPONSE, payload, 2, false) != ZCL_STATUS_SUCCESS) {
                    return ZCL_STATUS_INSUFFICIENT_SPACE;
                }
                return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            }

            /* Parse the request */
            req.zone_type = (enum ZbZclIasZoneServerZoneTypeT)pletoh16(&dataIndPtr->asdu[i]);
            i += 2;
            req.manuf_code = pletoh16(&dataIndPtr->asdu[i]);
            i += 2;

            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Zone Type = 0x%04x, Manufacture Code = 0x%04x.", req.zone_type, req.manuf_code);

            /* Call the application callback */
            status = iasCluster->callbacks.zone_enroll_req(clusterPtr, clusterPtr->app_cb_arg, &req, ext_src_addr, &enrRspCode, &zone_id);
            if (status != ZCL_STATUS_SUCCESS) {
                return status;
            }

            payload[0] = enrRspCode;
            if (enrRspCode == ZCL_IAS_ZONE_CLI_RESP_SUCCESS) {
                payload[1] = zone_id;
            }
            else {
                payload[1] = 0x00;
            }

            if (ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr,
                    ZCL_IAS_ZONE_CLI_CMD_ZONE_ENROLL_RESPONSE, payload, 2, false) != ZCL_STATUS_SUCCESS) {
                return ZCL_STATUS_INSUFFICIENT_SPACE;
            }
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
        }

        default:
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
}

uint8_t
ZbZclIasZoneClientInitiateAutoEnroll(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *dst,
    void (*callback)(const struct ZbZclWriteRspT *, void *), void *arg)
{
    struct ZbZclWriteReqT writeReq;
    uint8_t buf[8];

    if (dst->mode != ZB_APSDE_ADDRMODE_EXT) {
        return ZCL_STATUS_INVALID_VALUE;
    }
    putle64(buf, ZbExtendedAddress(clusterPtr->zb));

    (void)memset(&writeReq, 0, sizeof(writeReq));
    writeReq.dst = *dst;
    writeReq.count = 1;
    writeReq.attr[0].attrId = ZCL_IAS_ZONE_SVR_ATTR_CIE_ADDR;
    writeReq.attr[0].type = ZCL_DATATYPE_EUI64;
    writeReq.attr[0].value = buf;
    writeReq.attr[0].length = sizeof(buf);
    ZbZclWriteReq(clusterPtr, &writeReq, callback, arg);
    return ZCL_STATUS_SUCCESS;
}

uint8_t
ZbZclIasZoneClientSendAutoEnrollResponse(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *dst, uint8_t zone_id,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[2];

    payload[0] = ZCL_IAS_ZONE_CLI_RESP_SUCCESS;
    payload[1] = zone_id;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ZONE_CLI_CMD_ZONE_ENROLL_RESPONSE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = sizeof(payload);
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

uint8_t
ZbZclIasZoneClientInitiateNormalMode(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ZONE_CLI_CMD_INITIATE_NORMAL_MODE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = NULL;
    req.length = 0;
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

uint8_t
ZbZclIasZoneClientInitiateTestMode(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *dst,
    struct ZbZclIasZoneClientTestModeReqT *test_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    uint8_t payload[2];
    struct ZbZclClusterCommandReqT req;

    payload[0] = test_req->test_duration;
    payload[1] = test_req->current_zone_sensitivity;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_IAS_ZONE_CLI_CMD_INITIATE_TEST_MODE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = sizeof(payload);
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}
