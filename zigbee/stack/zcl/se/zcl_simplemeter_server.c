/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

/*--------------------------------------------------------------------------
 *  DESCRIPTION
 *      The source code implementing the Smart Energy simple metering
 *  cluster.
 *--------------------------------------------------------------------------
 */

#include "zcl/se/zcl.meter.h"

/*lint -e9087 "cluster_priv_t* <- ZbZclClusterT* [MISRA Rule 11.3 (REQUIRED)]" */

/* Command size macros. */
#define ZCL_METER_PRFL_RESP_SIZE(x)   (ZCL_HEADER_MAX_SIZE + 7U + (3U * (x)))

/*---------------------------------------------------------
 * Structures
 *---------------------------------------------------------
 */
/* Metering data structure */
struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;

    /* Callback functions. */
    struct ZbZclMeterServerCallbacksT callbacks;
};

/* Mandatory Metering Server Attributes.
 * The application can override these attributes with its own list. */
static const struct ZbZclAttrT zcl_metering_server_mandatory_attr_list[] = {
    /* Reading Information Attribute Set */
    {
        ZCL_METER_SVR_ATTR_CURSUM_DELIV, ZCL_DATATYPE_UNSIGNED_48BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL,
        {0, 0}, {0, 0}
    },

    /* Meter Status Attribute Set */
    {
        ZCL_METER_SVR_ATTR_METER_STATUS, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL,
        {0, 0}, {0, 0}
    },

    /* Formatting Attribute Set */
    {
        ZCL_METER_SVR_ATTR_UNIT_OF_MEASURE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL,
        {0, 0}, {0, 0}
    },
    {
        ZCL_METER_SVR_ATTR_SUMMATION_FORMAT, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL,
        {0, 0}, {0, 0}
    },
    {
        /* NOTE: not ZCL_DATATYPE_ENUMERATION_8BIT as one would expect. Zero-day bug in Spec. */
        ZCL_METER_SVR_ATTR_DEVICE_TYPE, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL,
        {0, 0}, {0, 0}
    },
};

static enum ZclStatusCodeT zcl_metering_server_command(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

static bool
ZbZclMeterServerInit(struct ZigBeeT *zb, struct cluster_priv_t *cluster, uint8_t endpoint)
{
    /* Initialize the simple metering cluster. */

    cluster->cluster.command = zcl_metering_server_command;

    /* Assume this is for SE */
    ZbZclClusterSetProfileId(&cluster->cluster, ZCL_PROFILE_SMART_ENERGY);

    cluster->cluster.txOptions = (uint16_t)(ZB_APSDE_DATAREQ_TXOPTIONS_SECURITY | \
                                            ZB_APSDE_DATAREQ_TXOPTIONS_ACK | ZB_APSDE_DATAREQ_TXOPTIONS_FRAG);
    if (!ZbZclClusterSetMinSecurity(&cluster->cluster, ZB_APS_STATUS_SECURED_LINK_KEY)) {
        ZbZclClusterFree(&cluster->cluster);
        return false;
    }
    if (!ZbZclClusterSetMaxAsduLength(&cluster->cluster, ZCL_ASDU_LENGTH_SMART_ENERGY)) {
        ZbZclClusterFree(&cluster->cluster);
        return false;
    }

    if (ZbZclAttrAppendList(&cluster->cluster, zcl_metering_server_mandatory_attr_list,
            ZCL_ATTR_LIST_LEN(zcl_metering_server_mandatory_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&cluster->cluster);
        return false;
    }

    /* Set Defaults */
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_CURSUM_DELIV, (long long)ZCL_INVALID_UNSIGNED_48BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_CURSUM_RECV, (long long)ZCL_INVALID_UNSIGNED_48BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_MAX_DMND_DELIV, (long long)ZCL_INVALID_UNSIGNED_48BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_MAX_DMND_RECV, (long long)ZCL_INVALID_UNSIGNED_48BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_DFT_SUM, (long long)ZCL_INVALID_UNSIGNED_48BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_DAILY_FREEZE_TIME, 0);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_POWER_FACTOR, 0);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_READ_SNAPSHOT_TIME, 0);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_MAX_DMND_DELIV_TIME, (long long)ZCL_INVALID_TIME_UTC);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_MAX_DMND_RECV_TIME, (long long)ZCL_INVALID_TIME_UTC);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_CURBLOCK, 0x00);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_SUPPLY_STATUS, 0x02); /* supply on */
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_METER_STATUS, 0x00);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_UNIT_OF_MEASURE, 0x80); /* BCD kWh */
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_MULTIPLIER, 1);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_DIVISOR, 100);
    /* ? ZCL_METER_FORMAT_SUPPRESS_LEADING_ZERO | ZCL_METER_FORMAT_INTEGER */
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_SUMMATION_FORMAT, 0xaa);
    /* ? ZCL_METER_FORMAT_SUPPRESS_LEADING_ZERO | ZCL_METER_FORMAT_INTEGER */
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_DEMAND_FORMAT, 0xaa);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_HISTORICAL_CONSUMPTION_FORMAT,
        (long long)(ZCL_METER_FORMAT_SUPPRESS_LEADING_ZERO | ZCL_METER_FORMAT_INTEGER));
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_DEVICE_TYPE, ZCL_METER_TYPE_ELECTRIC);
    /* BCD or ZCL_INVALID_SIGNED_24BIT ? */
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_INSTANTANEOUS_DEMAND, 0x0253);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_CURDAY_DM_DELIV, (long long)ZCL_INVALID_UNSIGNED_24BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_CURDAY_DM_RECV, (long long)ZCL_INVALID_UNSIGNED_24BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_PRVDAY_DM_DELIV, (long long)ZCL_INVALID_UNSIGNED_24BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_PRVDAY_DM_RECV, (long long)ZCL_INVALID_UNSIGNED_24BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_CURPRTL_DELIV_START, (long long)ZCL_INVALID_TIME_UTC);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_CURPRTL_RECV_START, (long long)ZCL_INVALID_TIME_UTC);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_CURPRTL_DELIV, (long long)ZCL_INVALID_UNSIGNED_24BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_CURPRTL_RECV, (long long)ZCL_INVALID_UNSIGNED_24BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_MAX_PERIODS_DELIV, 0x18);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_CURDEMAND_DELIV, (long long)ZCL_INVALID_UNSIGNED_24BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_DEMAND_LIMIT, (long long)ZCL_INVALID_UNSIGNED_24BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_DEMAND_INTEGRATION_PERIOD, (long long)ZCL_INVALID_UNSIGNED_8BIT);
    (void)ZbZclAttrIntegerWrite(&cluster->cluster, ZCL_METER_SVR_ATTR_DEMAND_SUBINTERVALS, (long long)ZCL_INVALID_UNSIGNED_8BIT);

    /* Attach this cluster to the endpoint so we can receive commands */
    (void)ZbZclClusterAttach(&cluster->cluster);
    return true;
}

struct ZbZclClusterT *
ZbZclMeterServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclMeterServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *meterPtr;

    /* Allocate a metering data structure. */
    meterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t),
            ZCL_CLUSTER_SIMPLE_METERING, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (meterPtr == NULL) {
        return NULL;
    }
    /* Initialize the simple metering cluster. */
    if (!ZbZclMeterServerInit(zb, meterPtr, endpoint)) {
        /* If ZbZclMeterServerInit fails, it frees the cluster. */
        return NULL;
    }
    ZbZclClusterSetCallbackArg(&meterPtr->cluster, arg); /* Set this even if callbacks is NULL */
    if (callbacks != NULL) {
        (void)memcpy(&meterPtr->callbacks, callbacks, sizeof(struct ZbZclMeterServerCallbacksT));
    }
    return &meterPtr->cluster;
}

int
ZbZclMeterGetProfileIntervalPeriod(uint8_t profile_interval_id)
{
    int rc;

    switch (profile_interval_id) {
        case 0U:
            /* Daily */
            rc = 86400; /* 24 * 60 * 60 */
            break;

        case 1U:
            /* 60 minutes */
            rc = 3600; /* 60 * 60 */
            break;

        case 2U:
            /* 30 minutes */
            rc = 1800; /* 30 * 60 */
            break;

        case 3U:
            /* 15 minutes */
            rc = 900; /* 15 * 60 */
            break;

        case 4U:
            /* 10 minutes */
            rc = 600; /* 10 * 60 */
            break;

        case 5U:
            /* 7.5 minutes */
            rc = 450; /* 7.5 * 60 */
            break;

        case 6U:
            /* 5 minutes */
            rc = 300; /* 5 * 60 */
            break;

        case 7U:
            /* 2.5 minutes */
            rc = 150; /* 2.5 * 60 */
            break;

        case 8U:
            /* 1 minute */
            rc = 60; /* 1 * 60 */
            break;

        default:
            rc = -1;
            break;
    }
    return rc;
}

enum ZclStatusCodeT
ZbZclMeterServerSendGetProfileRsp(struct ZbZclClusterT *cluster, struct ZbZclAddrInfoT *dstInfo,
    struct ZbZclMeterServerGetProfileRspT *rsp)
{
    uint8_t rsp_hdr_buf[11];
    unsigned int rsp_len;
    struct ZbApsBufT bufv[2];
    uint8_t i = 0U;

    /* Form the response payload */
    rsp_len = 0U;
    putle32(&rsp_hdr_buf[rsp_len], rsp->end_time);
    rsp_len += 4U;
    rsp_hdr_buf[rsp_len++] = (uint8_t)rsp->status;
    rsp_hdr_buf[rsp_len++] = rsp->profile_interval_period;
    rsp_hdr_buf[rsp_len++] = rsp->number_of_periods;

    bufv[i].data = rsp_hdr_buf;
    bufv[i].len = rsp_len;
    i++;

    if ((rsp->profile_data != NULL) && (rsp->profile_length > 0U)) {
        bufv[i].data = rsp->profile_data;
        bufv[i].len = rsp->profile_length;
        i++;
    }

    return ZbZclClusterCommandRsp(cluster, dstInfo, (uint8_t)ZCL_METER_SVR_CMD_GET_PROFILE_RESPONSE, bufv, i);
}

int
ZbZclMeterFormSampledData(uint8_t *sample_data, unsigned int max_len, uint32_t *samples, uint16_t num_samples)
{
    unsigned int i, len = 0;

    for (i = 0U; i < num_samples; i++) {
        if ((len + 3U) > max_len) {
            return -1;
        }
        putle24(&sample_data[len], samples[i]);
        len += 3U;
    }
    return (int)len;
}

enum ZclStatusCodeT
ZbZclMeterServerSendGetSampledDataRsp(struct ZbZclClusterT *cluster, struct ZbZclAddrInfoT *dstInfo,
    struct ZbZclMeterServerGetSampledDataRspT *rsp)
{
    uint8_t rsp_hdr_buf[11];
    unsigned int rsp_len;
    struct ZbApsBufT bufv[2];
    uint8_t i = 0U;

    /* Form the response payload */
    rsp_len = 0U;
    putle16(&rsp_hdr_buf[rsp_len], rsp->sample_id);
    rsp_len += 2U;
    putle32(&rsp_hdr_buf[rsp_len], rsp->sample_start_time);
    rsp_len += 4U;
    rsp_hdr_buf[rsp_len++] = (uint8_t)rsp->sample_type;
    putle16(&rsp_hdr_buf[rsp_len], rsp->sample_request_interval);
    rsp_len += 2U;
    putle16(&rsp_hdr_buf[rsp_len], rsp->number_of_samples);
    rsp_len += 2U;

    /* Form the vectored APS payload */
    bufv[i].data = rsp_hdr_buf;
    bufv[i++].len = rsp_len;
    if ((rsp->sample_data != NULL) && (rsp->sample_length > 0U)) {
        bufv[i].data = rsp->sample_data;
        bufv[i++].len = rsp->sample_length;
    }

    return ZbZclClusterCommandRsp(cluster, dstInfo, (uint8_t)ZCL_METER_SVR_CMD_GET_SAMPLED_DATA_RESPONSE, bufv, i);
}

static enum ZclStatusCodeT
zcl_metering_server_command(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *meterPtr = (struct cluster_priv_t *)cluster;
    unsigned int i = 0U;
    enum ZclStatusCodeT rc = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    struct ZbZclAddrInfoT srcInfo;

    (void)memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zclHdrPtr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    switch ((enum ZbZclMeterClientCommandsT)zclHdrPtr->cmdId) {
        case ZCL_METER_CLI_CMD_GET_PROFILE:
        {
            struct ZbZclMeterClientGetProfileReqT req;

            if (!meterPtr->callbacks.get_profile) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            /* Parse the start time and price count. */
            if (dataIndPtr->asduLength < 6U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            req.interval_channel = (enum ZbZclMeterSampleTypeT)dataIndPtr->asdu[i++];
            req.end_time = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            req.number_of_periods = dataIndPtr->asdu[i];

            rc = meterPtr->callbacks.get_profile(cluster, meterPtr->cluster.app_cb_arg, &req, &srcInfo);
            /* If success, application should have called ZbZclMeterServerSendGetProfileRsp
                * to send the response. We're done. */
            break;
        }

        case ZCL_METER_CLI_CMD_GET_SAMPLED_DATA:
        {
            struct ZbZclMeterClientGetSampledDataReqT req;

            if (meterPtr->callbacks.get_sampled_data == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            /* Parse the message */
            if (dataIndPtr->asduLength < 9U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            req.sample_id = pletoh16(&dataIndPtr->asdu[i]);
            i += 2U;
            req.earliest_sample_time = pletoh32(&dataIndPtr->asdu[i]);
            i += 4U;
            req.sample_type = (enum ZbZclMeterSampleTypeT)dataIndPtr->asdu[i++];
            req.number_of_samples = pletoh16(&dataIndPtr->asdu[i]);

            /* Call the application callback */
            rc = meterPtr->callbacks.get_sampled_data(cluster, meterPtr->cluster.app_cb_arg, &req, &srcInfo);
            /* If success, Application should have called ZbZclMeterServerSendGetSampledDataRsp
                * to send the response. We're done. */
            break;
        }

        case ZCL_METER_CLI_CMD_LOCAL_CHANGE_SUPPLY:
        {
            struct ZbZclMeterClientLocalChangeSupplyReqT req;

            if (meterPtr->callbacks.local_change_supply == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            /* Parse the message */
            if (dataIndPtr->asduLength < 1U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            req.prop_supply_status = (enum ZbZclMeterSupplyStatusT)dataIndPtr->asdu[i++];
            if ((req.prop_supply_status != ZCL_METER_SUPPLY_STATUS_OFF_ARMED)
                && (req.prop_supply_status != ZCL_METER_SUPPLY_STATUS_ON)) {
                rc = ZCL_STATUS_INVALID_FIELD;
                break;
            }
            rc = meterPtr->callbacks.local_change_supply(cluster, meterPtr->cluster.app_cb_arg, &req, &srcInfo);
            break;
        }

        case ZCL_METER_CLI_CMD_REQUEST_MIRROR_RESPONSE:
        case ZCL_METER_CLI_CMD_MIRROR_REMOVED:
            /* Handled by the request callback handler. Don't send a response */
            rc = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            break;

        case ZCL_METER_CLI_CMD_MIRROR_REPORT_ATTRIBUTE_RESPONSE:
        {
            struct ZbZclMeterClientMirrorReportAttrRspT notify;
            uint8_t j;

            if (meterPtr->callbacks.mirror_report_attr_rsp == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            /* Parse the message */
            if (dataIndPtr->asduLength < 5U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&notify, 0, sizeof(notify));
            notify.notif_scheme = dataIndPtr->asdu[i++];
            for (j = 0; j < ZCL_METER_NOTIF_FLAGS_MAX; j++) {
                if ((i + 4U) > dataIndPtr->asduLength) {
                    break;
                }
                notify.notif_flags[j] = pletoh32(&dataIndPtr->asdu[i]);
                i += 4U;
                notify.num_flags++;
            }

            rc = meterPtr->callbacks.mirror_report_attr_rsp(cluster, meterPtr->cluster.app_cb_arg, &notify, &srcInfo);
            break;
        }

        default:
            /* For all other commands, check if the application can handle them. */
            if (meterPtr->callbacks.optional == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            rc = meterPtr->callbacks.optional(cluster, zclHdrPtr, dataIndPtr);
            break;
    }
    return rc;
}

enum ZclStatusCodeT
ZbZclMeterServerSendRequestMirror(struct ZbZclClusterT *cluster, struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_METER_SVR_CMD_REQUEST_MIRROR;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = NULL;
    req.length = 0U;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
    /* Should receive ZCL_METER_CLI_CMD_REQUEST_MIRROR_RESPONSE command via callback */
}

enum ZclStatusCodeT
ZbZclMeterServerSendRemoveMirror(struct ZbZclClusterT *cluster, struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_METER_SVR_CMD_REMOVE_MIRROR;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = NULL;
    req.length = 0U;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
    /* Should receive ZCL_METER_CLI_CMD_MIRROR_REMOVED command via callback */
}

enum ZclStatusCodeT
ZbZclMeterServerSendConfigMirror(struct ZbZclClusterT *cluster, struct ZbApsAddrT *dst,
    struct ZbZclMeterServerConfigMirrorT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd;
    uint8_t payload[9U];
    unsigned int i = 0;

    putle32(&payload[i], req->issuer_event_id);
    i += 4;
    putle24(&payload[i], req->reporting_interval);
    i += 3;
    payload[i++] = req->mirror_notif_reporting ? 0x01 : 0x00;
    payload[i++] = (uint8_t)req->notif_scheme;

    (void)memset(&cmd, 0, sizeof(cmd));
    cmd.dst = *dst;
    cmd.cmdId = (uint8_t)ZCL_METER_SVR_CMD_CONFIGURE_MIRROR;
    cmd.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd.payload = payload;
    cmd.length = i;
    return ZbZclClusterCommandReq(cluster, &cmd, callback, arg);
}

#if 0 /* Not certifiable (and not supported) */
enum ZclStatusCodeT
ZbZclMeterServerSendConfigNotifScheme(struct ZbZclClusterT *cluster, struct ZbApsAddrT *dst,
    struct ZbZclMeterServerConfigNotifSchemeT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd;
    uint8_t payload[9U];
    unsigned int i = 0;
    uint8_t j, shift;
    uint32_t notif_flag_order = 0U;

    putle32(&payload[i], req->issuer_event_id);
    i += 4U;
    payload[i++] = (uint8_t)req->notif_scheme;
    /*  notif_flag_order */
    for (j = 0; j < 8; j++) {
        shift = 32U - (j + 1U) * 4U;
        notif_flag_order |= (req->notif_flag_order[j] & 0x0fU) << shift;
    }
    putle32(&payload[i], notif_flag_order);
    i += 4U;

    (void)memset(&cmd, 0, sizeof(cmd));
    cmd.dst = *dst;
    cmd.cmdId = (uint8_t)ZCL_METER_SVR_CMD_CONFIGURE_NOTIFICATION_SCHEME;
    cmd.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd.payload = payload;
    cmd.length = i;
    return ZbZclClusterCommandReq(cluster, &cmd, callback, arg);
}

enum ZclStatusCodeT
ZbZclMeterServerSendConfigNotifFlags(struct ZbZclClusterT *cluster, struct ZbApsAddrT *dst,
    struct ZbZclMeterServerConfigNotifFlagsT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd;
    uint8_t payload[12U + ZCL_METER_BIT_FIELD_ALLOC_MAX_COMMANDS];
    unsigned int i = 0;
    uint8_t j;

    if (req->bit_field_alloc.num_commands > ZCL_METER_BIT_FIELD_ALLOC_MAX_COMMANDS) {
        return ZCL_STATUS_FAILURE;
    }

    putle32(&payload[i], req->issuer_event_id);
    i += 4U;
    payload[i++] = (uint8_t)req->notif_scheme;
    putle16(&payload[i], req->notif_flag_attrid);
    i += 2U;
    /* Bit Field Allocation */
    putle16(&payload[i], req->bit_field_alloc.cluster_id);
    i += 2U;
    putle16(&payload[i], req->bit_field_alloc.manuf_id);
    i += 2U;
    payload[i++] = req->bit_field_alloc.num_commands;
    for (j = 0; j < req->bit_field_alloc.num_commands; j++) {
        payload[i++] = req->bit_field_alloc.command_ids[j];
    }

    (void)memset(&cmd, 0, sizeof(cmd));
    cmd.dst = *dst;
    cmd.cmdId = (uint8_t)ZCL_METER_SVR_CMD_CONFIGURE_NOTIFICATION_FLAG;
    cmd.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmd.payload = payload;
    cmd.length = i;
    return ZbZclClusterCommandReq(cluster, &cmd, callback, arg);
}

#endif
