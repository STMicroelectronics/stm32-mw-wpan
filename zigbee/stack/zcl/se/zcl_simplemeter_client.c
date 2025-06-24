/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

/*--------------------------------------------------------------------------
 *  DESCRIPTION
 *      The source code implementing the Smart Energy simple metering
 *  cluster.
 *--------------------------------------------------------------------------
 */

#include "zcl/se/zcl.meter.h"

#define ZCL_METER_READ_ATTR_NUM_PER         5U
#define ZCL_METER_SVR_ATTRID_DELIV_MIN      0x0100U
#define ZCL_METER_SVR_ATTRID_RECV_MIN       0x0101U

#define ZCL_METER_MIRROR_RESP_SIZE          (ZCL_HEADER_MAX_SIZE + 2U /* endpoint */)

static const struct ZbZclAttrT zcl_metering_client_mirror_attr_list[] = {
    {
        ZCL_METER_CLI_ATTR_FUNC_NOTIF_FLAGS, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_CLI_ATTR_NOTIF_FLAGS_2, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_CLI_ATTR_NOTIF_FLAGS_3, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_CLI_ATTR_NOTIF_FLAGS_4, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_CLI_ATTR_NOTIF_FLAGS_5, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_CLI_ATTR_NOTIF_FLAGS_6, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_CLI_ATTR_NOTIF_FLAGS_7, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_CLI_ATTR_NOTIF_FLAGS_8, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    }
};

/* Metering data structure */
struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
    struct ZbZclMeterClientCallbacksT callbacks;

    /* Optional Mirrored Server */
    struct {
        struct ZbZclClusterT *server;
        uint64_t rmt_addr;
        uint8_t rmt_endpoint;

        bool notif_reporting; /* MirrorReporting attribute? */
        enum ZbZclMeterNotifSchemesT notif_scheme;
    } mirror;
};

static enum ZclStatusCodeT zcl_metering_client_command(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

static void zcl_metering_client_report(struct ZbZclClusterT *cluster, struct ZbApsdeDataIndT *dataIndPtr,
    uint16_t attributeId, enum ZclDataTypeT dataType, const uint8_t *in_payload, uint16_t in_len);

static void zcl_metering_client_send_mirror_report_attr_rsp(struct ZbZclClusterT *cluster,
    const struct ZbApsAddrT *dst);

struct ZbZclClusterT *
ZbZclMeterClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclMeterClientCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *cluster;

    cluster = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_SIMPLE_METERING,
            endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (cluster == NULL) {
        return NULL;
    }
    cluster->cluster.command = zcl_metering_client_command;

    /* Assume this is for SE */
    ZbZclClusterSetProfileId(&cluster->cluster, ZCL_PROFILE_SMART_ENERGY);

    if (!ZbZclClusterSetMinSecurity(&cluster->cluster, ZB_APS_STATUS_SECURED_LINK_KEY)) {
        ZbZclClusterFree(&cluster->cluster);
        return NULL;
    }
    if (!ZbZclClusterSetMaxAsduLength(&cluster->cluster, ZCL_ASDU_LENGTH_SMART_ENERGY)) {
        ZbZclClusterFree(&cluster->cluster);
        return NULL;
    }

    if (callbacks->request_mirror != NULL) {
        /* If Mirror callbacks defined, then allocate the Mirror attributes. */
        if (ZbZclAttrAppendList(&cluster->cluster, zcl_metering_client_mirror_attr_list,
                ZCL_ATTR_LIST_LEN(zcl_metering_client_mirror_attr_list)) != ZCL_STATUS_SUCCESS) {
            ZbZclClusterFree(&cluster->cluster);
            return false;
        }
    }

    ZbZclClusterSetCallbackArg(&cluster->cluster, arg); /* Set this even if callbacks is NULL */
    if (callbacks != NULL) {
        (void)memcpy(&cluster->callbacks, callbacks, sizeof(struct ZbZclMeterClientCallbacksT));
    }

    ZCL_LOG_PRINTF(zb, __func__, "ZbZclMeterClientAlloc endpoint = %d txOptions 0x%02x minSecurity 0x%02x profileId 0x%04x",
        cluster->cluster.endpoint, cluster->cluster.txOptions, cluster->cluster.minSecurity,
        cluster->cluster.profileId);

    (void)ZbZclClusterAttach(&cluster->cluster);
    return &cluster->cluster;
}

void
ZbZclMeterClientMirrorRegister(struct ZbZclClusterT *cluster, struct ZbZclClusterT *server,
    uint64_t rmt_addr, uint8_t rmt_endpoint)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;

    /* NOTE: if a mirror is already registered, its info will be overwritten */
    client->mirror.server = server;
    client->mirror.rmt_addr = rmt_addr;
    client->mirror.rmt_endpoint = rmt_endpoint;

    if (server != NULL) {
        /* Configure the report callback so we can receive reports from the meter
         * and update our mirror. */
        ZbZclClusterReportCallbackAttach(cluster, zcl_metering_client_report);
    }
    else {
        ZbZclClusterReportCallbackAttach(cluster, NULL);
    }
}

static void
zcl_metering_client_send_mirror_report_attr_rsp(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;
    uint8_t payload[1U + (4U * ZCL_METER_NOTIF_FLAGS_MAX)];
    uint8_t i = 0, j;
    struct ZbZclClusterCommandReqT cmd;
    uint8_t num_flags = 0;

    if (!client->mirror.notif_reporting) {
        /* MirrorReporting not set. Don't send this message automatically.
         * The Meter can manually read the flags using a ZCL Read Request. */
        return;
    }

    switch (client->mirror.notif_scheme) {
        case ZCL_METER_NOTIF_SCHEME_PREDEF_A:
            num_flags = 1; /* Only Functional Flags */
            break;

        case ZCL_METER_NOTIF_SCHEME_PREDEF_B:
            num_flags = 5; /* Functional Flags and Flags2..5 */
            break;

        default:
            ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, unsupported scheme = %d", client->mirror.notif_scheme);
            return;
    }

    payload[i++] = (uint8_t)client->mirror.notif_scheme;

    /* Read all the flags attributes */
    for (j = 0; j < num_flags; j++) {
        enum ZclStatusCodeT status;
        uint32_t flagmask;

        flagmask = ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_METER_CLI_ATTR_FUNC_NOTIF_FLAGS + j, NULL, &status);
        if (status != ZCL_STATUS_SUCCESS) {
            ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, failed to read attribute");
            return;
        }
        putle32(&payload[i], flagmask);
        i += 4U;
    }

    /* NOTE: sending message even if no flags are set. Can't find anything in the SE Spec
     * that goes against this. */

    (void)memset(&cmd, 0, sizeof(cmd));
    cmd.dst = *dst;
    cmd.cmdId = (uint8_t)ZCL_METER_CLI_CMD_MIRROR_REPORT_ATTRIBUTE_RESPONSE;
    cmd.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd.payload = payload;
    cmd.length = i;
    /* Although this is labelled a response, it's sent as a request. It's more of a
     * notification. */
    /* It also needs to be sent delayed, so the potential APS ACK for the ZCL Report
     * from the Meter can be sent first and prevent any collision.
     * Any delay should be fine, because it should cause the packet to be queued
     * in the indirect packet queue AFTER the APS ACK.  */
    /* ZCL_LOG_PRINTF(cluster->zb, __func__, "Sending mirror response"); */
    (void)ZbZclClusterCommandReqDelayed(cluster, &cmd, ZB_NWK_RSP_DELAY_DEFAULT, NULL, NULL);
}

/* This function receives reports from the Meter Server (real meter) and updates
 * the local Meter Server mirror. */
static void
zcl_metering_client_report(struct ZbZclClusterT *cluster, struct ZbApsdeDataIndT *dataIndPtr,
    uint16_t attributeId, enum ZclDataTypeT dataType, const uint8_t *in_payload, uint16_t in_len)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;
    int attrLen;

    /* Are we mirroring a Meter Server? */
    if (client->mirror.server == NULL) {
        /* This callback is only for updating our local mirror. If no mirror cluster, then drop it. */
        return;
    }
    /* Verify the source of the reported attribute. */
    if (client->mirror.rmt_addr != dataIndPtr->src.extAddr) {
        return;
    }
    if (client->mirror.rmt_endpoint != dataIndPtr->src.endpoint) {
        return;
    }
    /* Parse the attribute data */
    attrLen = ZbZclAttrParseLength(dataType, in_payload, dataIndPtr->asduLength, 0);
    if (attrLen < 0) {
        return;
    }
    if (attrLen > (int)in_len) {
        return;
    }

    switch (attributeId) {
        case ZCL_GLOBAL_ATTR_REPORTING_STATUS:
        {
            long long val;
            enum ZclStatusCodeT status;

            if (dataType != ZCL_DATATYPE_ENUMERATION_8BIT) {
                ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, invalid data type");
                return;
            }
            if (attrLen < 1) {
                ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, length too short");
                return;
            }
            val = ZbZclParseInteger(dataType, in_payload, &status);
            if (status != ZCL_STATUS_SUCCESS) {
                return;
            }
            if (val != ZCL_ATTR_REPORTING_STATUS_COMPLETE) {
                ZCL_LOG_PRINTF(cluster->zb, __func__, "Skipping, status = 0x%02x", val);
                return;
            }
            zcl_metering_client_send_mirror_report_attr_rsp(cluster, &dataIndPtr->src);
            /* We're done (not a writable attribute) */
            return;
        }

        case ZCL_METER_SVR_ATTR_DEVICE_TYPE:
        {
            long long val;
            enum ZclStatusCodeT status;
            enum ZbZclMeterTypeT mirror_type;

            /* Data type from spec is 8-bit BitMap, but let's also allow the 8-bit Enum */
            if ((dataType != ZCL_DATATYPE_BITMAP_8BIT) && (dataType != ZCL_DATATYPE_ENUMERATION_8BIT)) {
                ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, invalid data type");
                return;
            }
            if (attrLen < 1) {
                ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, length too short");
                return;
            }
            val = ZbZclParseInteger(dataType, in_payload, &status);
            if (status != ZCL_STATUS_SUCCESS) {
                return;
            }
            switch (val) {
                case ZCL_METER_TYPE_ELECTRIC:
                    mirror_type = ZCL_METER_TYPE_MIRROR_ELECTRIC;
                    break;

                case ZCL_METER_TYPE_GAS:
                    mirror_type = ZCL_METER_TYPE_MIRROR_GAS;
                    break;

                default:
                    /* Unknown */
                    return;
            }
            ZCL_LOG_PRINTF(cluster->zb, __func__, "Configuring ZCL_METER_SVR_ATTR_DEVICE_TYPE (0x%04x) = 0x%02x",
                ZCL_METER_SVR_ATTR_DEVICE_TYPE, mirror_type);
            (void)ZbZclAttrIntegerWrite(client->mirror.server, ZCL_METER_SVR_ATTR_DEVICE_TYPE, mirror_type);
            /* We're done */
            return;
        }

        default:
            break;
    }

    /* EXEGIN - print value as well? */
    ZCL_LOG_PRINTF(cluster->zb, __func__, "Writing attr = 0x%04x", attributeId);

    /* Write the attribute value to the Meter Server mirror */
    (void)ZbZclAttrWrite(client->mirror.server, NULL, attributeId, in_payload,
        (unsigned int)attrLen, ZCL_ATTR_WRITE_FLAG_FORCE);
}

static void
zcl_metering_client_aps_conf(struct ZbApsdeDataConfT *conf, void *arg)
{
    struct ZbZclClusterT *cluster = arg;

    ZCL_LOG_PRINTF(cluster->zb, __func__, "APSDE-DATA.confirm (status = 0x%02x)", conf->status);
}

static enum ZclStatusCodeT
zcl_metering_client_command(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr,
    struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;
    enum ZclStatusCodeT rc;
    struct ZbZclAddrInfoT srcInfo;

    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_CLIENT) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    (void)memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zclHdrPtr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    switch ((enum ZbZclMeterServerCommandsT)zclHdrPtr->cmdId) {
        case ZCL_METER_SVR_CMD_GET_PROFILE_RESPONSE:
        case ZCL_METER_SVR_CMD_FAST_POLL_RESPONSE:
        case ZCL_METER_SVR_CMD_SCHEDULE_SNAPSHOT_RESPONSE:
        case ZCL_METER_SVR_CMD_TAKE_SNAPSHOT_RESPONSE:
        case ZCL_METER_SVR_CMD_GET_SAMPLED_DATA_RESPONSE:
            /* Handled by the request callback handler. Don't send a response */
            rc = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            break;

        case ZCL_METER_SVR_CMD_REQUEST_MIRROR:
        {
            struct ZbApsdeDataReqT dataReq;
            struct ZbZclHeaderT hdr;
            uint8_t buf[ZCL_METER_MIRROR_RESP_SIZE];
            int hdr_len;
            uint16_t len;
            uint16_t endpointId;
            enum ZbStatusCodeT status;

            if (client->callbacks.request_mirror == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            /* Ensure that we know the extended source address. */
            if (dataIndPtr->src.extAddr == 0ULL) {
                endpointId = 0xffffU;
            }
            else {
                endpointId = client->callbacks.request_mirror(cluster, &srcInfo, cluster->app_cb_arg);

                /* Range check: [0x0001:0x00F0] || 0xFFFF */
                if ((endpointId != 0xffffU) && ((endpointId < 0x0001) || (endpointId > 0x00F0))) {
                    rc = ZCL_STATUS_FAILURE;
                    break;
                }
            }

            /* Form the ZCL Header */
            (void)memset(&hdr, 0, sizeof(hdr));
            hdr.frameCtrl.frameType = ZCL_FRAMETYPE_CLUSTER;
            hdr.frameCtrl.manufacturer = 0U;
            hdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
            hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
            hdr.seqNum = zclHdrPtr->seqNum;
            hdr.cmdId = (uint8_t)ZCL_METER_CLI_CMD_REQUEST_MIRROR_RESPONSE;
            hdr_len = ZbZclAppendHeader(&hdr, buf, sizeof(buf));
            if (hdr_len < 0) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            len = (uint16_t)hdr_len;

            /* Append the mirror response command. */
            putle16(&buf[len], endpointId);
            len += 2;

            /* Form the APSDE-DATA.request. */
            ZbZclClusterInitApsdeReq(cluster, &dataReq, dataIndPtr);
            dataReq.dst = dataIndPtr->src;
            dataReq.txOptions = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);
            dataReq.asdu = buf;
            dataReq.asduLength = len;

            /* Send the response. */
            ZCL_LOG_PRINTF(cluster->zb, __func__, "Sending Request Mirror Response");
            status = ZbApsdeDataReqCallback(cluster->zb, &dataReq, zcl_metering_client_aps_conf, cluster);
            if (status != ZB_APS_STATUS_SUCCESS) {
                /* Ignored */
                ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, failed to send APS packet (status = 0x%02x)", status);
            }
            rc = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            break;
        }

        case ZCL_METER_SVR_CMD_REMOVE_MIRROR:
        {
            struct ZbApsdeDataReqT dataReq;
            struct ZbZclHeaderT hdr;
            uint8_t buf[ZCL_METER_MIRROR_RESP_SIZE];
            int hdr_len;
            uint16_t len;
            uint16_t endpointId;

            if (client->callbacks.remove_mirror == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            /* Execute the remove mirror callback.
             * If successful, the NHLE will have freed the corresponding Meter Server
             * it was using to mirror. */
            endpointId = client->callbacks.remove_mirror(cluster, &srcInfo, cluster->app_cb_arg);

            if (endpointId != ZCL_METER_MIRROR_INVALID_ENDPOINT) {
                /* Deregister the Meter Server so we don't end up using an invalid pointer */
                ZbZclMeterClientMirrorRegister(cluster, NULL, 0, 0);
            }

            /* Form the ZCL Header */
            hdr.frameCtrl.frameType = ZCL_FRAMETYPE_CLUSTER;
            hdr.frameCtrl.manufacturer = 0U;
            hdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
            hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
            hdr.seqNum = zclHdrPtr->seqNum;
            hdr.cmdId = (uint8_t)ZCL_METER_CLI_CMD_MIRROR_REMOVED;
            hdr_len = ZbZclAppendHeader(&hdr, buf, sizeof(buf));
            if (hdr_len < 0) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            len = (uint16_t)hdr_len;

            /* Append the mirror removed command. */
            putle16(&buf[len], endpointId);
            len += 2U;

            /* Form the APSDE-DATA.request. */
            ZbZclClusterInitApsdeReq(cluster, &dataReq, dataIndPtr);
            dataReq.dst = dataIndPtr->src;
            dataReq.txOptions = (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_SECURITY;
            dataReq.txOptions |= (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_ACK;
            dataReq.txOptions |= (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_FRAG;
            dataReq.asdu = buf;
            dataReq.asduLength = len;
            if (ZbApsdeDataReqCallback(cluster->zb, &dataReq, NULL, NULL) != ZB_APS_STATUS_SUCCESS) {
                /* Ignored */
            }
            rc = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            break;
        }

        case ZCL_METER_SVR_CMD_CONFIGURE_MIRROR:
        {
            struct ZbZclMeterServerConfigMirrorT req;
            unsigned int i = 0;

            if (dataIndPtr->asduLength < 9U) {
                rc = ZCL_STATUS_FAILURE;
                break;
            }
            if (client->callbacks.config_mirror == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.issuer_event_id = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            req.reporting_interval = pletoh24(&dataIndPtr->asdu[i]);
            i += 3U;
            req.mirror_notif_reporting = (dataIndPtr->asdu[i++] == 0x00) ? false : true;
            req.notif_scheme = dataIndPtr->asdu[i];

            rc = client->callbacks.config_mirror(cluster, &req, &srcInfo, cluster->app_cb_arg);
            if (rc == ZCL_STATUS_SUCCESS) {
                /* Save the notification scheme */
                client->mirror.notif_reporting = req.mirror_notif_reporting;
                client->mirror.notif_scheme = req.notif_scheme;
            }
            break;
        }

#if 0 /* Not certifiable (and not supported) */
        case ZCL_METER_SVR_CMD_CONFIGURE_NOTIFICATION_SCHEME:
        {
            struct ZbZclMeterServerConfigNotifSchemeT req;
            unsigned int i = 0;
            uint8_t j, shift;
            uint32_t notif_flag_order;

            if (dataIndPtr->asduLength < 9U) {
                rc = ZCL_STATUS_FAILURE;
                break;
            }
            if (client->callbacks.config_notif_scheme == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.issuer_event_id = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            req.notif_scheme = dataIndPtr->asdu[i++];
            /*  notif_flag_order */
            notif_flag_order = pletoh32(&dataIndPtr->asdu[i]);
            /* i += 4U; */
            for (j = 0; j < 8U; j++) {
                shift = 32U - (j + 1U) * 4U;
                req.notif_flag_order[j] = (notif_flag_order >> shift) & 0x0fU;
            }

            rc = client->callbacks.config_notif_scheme(cluster, &req, &srcInfo, cluster->app_cb_arg);
            break;
        }

        case ZCL_METER_SVR_CMD_CONFIGURE_NOTIFICATION_FLAG:
        {
            struct ZbZclMeterServerConfigNotifFlagsT req;
            unsigned int i = 0;
            uint8_t j;

            if (dataIndPtr->asduLength < 12U) {
                rc = ZCL_STATUS_FAILURE;
                break;
            }
            if (client->callbacks.config_notif_flags == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.issuer_event_id = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            req.notif_scheme = dataIndPtr->asdu[i++];
            req.notif_flag_attrid = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            /* Bit Field Allocation */
            req.bit_field_alloc.cluster_id = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            req.bit_field_alloc.manuf_id = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            req.bit_field_alloc.num_commands = dataIndPtr->asdu[i++];
            if (req.bit_field_alloc.num_commands > ZCL_METER_BIT_FIELD_ALLOC_MAX_COMMANDS) {
                rc = ZCL_STATUS_FAILURE;
                break;
            }
            if ((i + req.bit_field_alloc.num_commands) > dataIndPtr->asduLength) {
                rc = ZCL_STATUS_FAILURE;
                break;
            }
            for (j = 0; j < req.bit_field_alloc.num_commands; j++) {
                req.bit_field_alloc.command_ids[j] = dataIndPtr->asdu[i++];
            }

            rc = client->callbacks.config_notif_flags(cluster, &req, &srcInfo, cluster->app_cb_arg);
            break;
        }
#endif

        default:
            /* For all other commands, check if the application can handle them. */
            if (client->callbacks.optional == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            rc = client->callbacks.optional(cluster, zclHdrPtr, dataIndPtr);
            break;
    }
    return rc;
}

enum ZclStatusCodeT
ZbZclMeterClientCommandGetProfileReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclMeterClientGetProfileReqT *cmd_req, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    uint16_t length = 0;
    struct ZbZclClusterCommandReqT req;

    payload[length++] = (uint8_t)cmd_req->interval_channel;
    putle32(&payload[length], cmd_req->end_time);
    length += 4U;
    payload[length++] = cmd_req->number_of_periods;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_METER_CLI_CMD_GET_PROFILE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
    /* Should receive ZCL_METER_SVR_CMD_GET_PROFILE_RESPONSE command via callback */
}

enum ZclStatusCodeT
ZbZclMeterClientCommandGetSampledDataReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclMeterClientGetSampledDataReqT *cmd_req, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    uint8_t length = 0;
    struct ZbZclClusterCommandReqT req;

    /* Sample ID */
    putle16(&payload[length], cmd_req->sample_id);
    length += 2U;
    /* Earliest Sample Time */
    putle32(&payload[length], cmd_req->earliest_sample_time);
    length += 4U;
    /* Sample Type */
    payload[length++] = (uint8_t)cmd_req->sample_type;
    /* Number of Samples */
    putle16(&payload[length], cmd_req->number_of_samples);
    length += 2U;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_METER_CLI_CMD_GET_SAMPLED_DATA;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
    /* ZCL_METER_SVR_CMD_GET_SAMPLED_DATA_RESPONSE via callback */
}

enum ZclStatusCodeT
ZbZclMeterClientCommandLocalChangeSupplyReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclMeterClientLocalChangeSupplyReqT *cmd_req, void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    uint8_t length = 0;
    struct ZbZclClusterCommandReqT req;

    /* Sample Type */
    payload[length++] = (uint8_t)cmd_req->prop_supply_status;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_METER_CLI_CMD_LOCAL_CHANGE_SUPPLY;
    /* Note: "No Supply Status Response command shall be returned to the originator."
     * Disable noDefaultResponse, so we always get a response in this case. */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}
