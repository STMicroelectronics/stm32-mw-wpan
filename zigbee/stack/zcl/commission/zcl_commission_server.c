/**
 * @file zcl_commission_server.c
 * @brief ZCL Commissioning Server cluster
 * @author Exegin Technologies Limited
 * @copyright Copyright [2019 - 2022] Exegin Technologies Limited. All rights reserved.
 */

#include "zcl/general/zcl.commission.h"
#include "../zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */

/* Null (all zeroes)
 * 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00 */
extern const uint8_t sec_key_null[ZB_SEC_KEYSIZE];

/* "ZigBeeAlliance09"
 * 5a:69:67:42:65:65:41:6c:6c:69:61:6e:63:65:30:39 */
extern const uint8_t sec_key_ha[ZB_SEC_KEYSIZE];

struct cluster_priv_t {
    struct ZbZclClusterT cluster;
    struct ZbZclCommissionServerCallbacksT callbacks;
    bool enable;
    uint8_t page;
};

/* EXEGIN - use ZCL_ATTR_FLAG_PERSISTABLE? */

static const struct ZbZclAttrT zcl_commission_server_attr_list[] = {
    /* Startup Parameters */
    {
        ZCL_COMMISSION_SVR_ATTR_SHORT_ADDR, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x0000, 0xfff7}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_EPID, ZCL_DATATYPE_EUI64,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_PANID, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_CHANNELMASK, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, WPAN_PAGE_CHANNELMASK_ALL}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_PROTOCOLVER, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x02, 0x02}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_STACKPROFILE, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x01, 0x02}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_STARTUPCONTROL, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x00, 0x03}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_TCADDR, ZCL_DATATYPE_EUI64,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
#if 0 /* Optional, not supported */
    {
        ZCL_COMMISSION_SVR_ATTR_TCMASTER, ZCL_DATATYPE_SECURITY_KEY128,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
#endif
    {
        ZCL_COMMISSION_SVR_ATTR_NWKKEY, ZCL_DATATYPE_SECURITY_KEY128,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_USEINSECJOIN, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_PRECONFLINKKEY, ZCL_DATATYPE_SECURITY_KEY128,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_NWKKEYSEQNUM, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_NWKKEYTYPE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_NWKMGRADDR, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x0000, 0xfff7}, {0, 0}
    },

    /* Join Parameters */
    {
        ZCL_COMMISSION_SVR_ATTR_SCANATTEMPTS, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x01, 0xff}, {0, 0}
    },
#if 0 /* Optional, not supported */
    {
        ZCL_COMMISSION_SVR_ATTR_TIMEBTWSCANS, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_REJOININTERVAL, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_MAXREJOININTERVAL, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
#endif

#if 0 /* Optional, not supported */
      /* End Device Parameters */
    {
        ZCL_COMMISSION_SVR_ATTR_POLLRATE, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_PARENTRETRYTHRESH, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
#endif

#if 0 /* Optional, not supported */
      /* Concentrator Parameters */
    {
        ZCL_COMMISSION_SVR_ATTR_CONCFLAG, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_CONCRADIUS, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COMMISSION_SVR_ATTR_CONCDISCTIME, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
#endif
};

static enum ZclStatusCodeT zcl_commission_server_command(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *zcl_hdr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclCommissionServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, uint16_t profile, bool aps_secured,
    struct ZbZclCommissionServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *serverPtr;

    serverPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_COMMISSIONING,
            endpoint, ZCL_DIRECTION_TO_SERVER);
    if (serverPtr == NULL) {
        return NULL;
    }
    serverPtr->cluster.command = zcl_commission_server_command;

    ZbZclClusterSetCallbackArg(&serverPtr->cluster, arg);

    if (callbacks != NULL) {
        memcpy(&serverPtr->callbacks, callbacks, sizeof(struct ZbZclCommissionServerCallbacksT));
    }
    else {
        memset(&serverPtr->callbacks, 0, sizeof(struct ZbZclCommissionServerCallbacksT));
    }

    if (ZbZclAttrAppendList(&serverPtr->cluster, zcl_commission_server_attr_list,
            ZCL_ATTR_LIST_LEN(zcl_commission_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&serverPtr->cluster);
        return NULL;
    }

    ZbZclClusterSetProfileId(&serverPtr->cluster, profile);

    if (aps_secured) {
        /* Packets are sent and received with APS security */
        ZbZclClusterSetTxOptions(&serverPtr->cluster, ZCL_COMMISSION_TXOPTIONS_SECURE);
        (void)ZbZclClusterSetMinSecurity(&serverPtr->cluster, ZB_APS_STATUS_SECURED_LINK_KEY);
    }
    else {
        /* Packets are sent and received completely unsecured */
        ZbZclClusterSetTxOptions(&serverPtr->cluster, ZCL_COMMISSION_TXOPTIONS_UNSECURE);
        (void)ZbZclClusterSetMinSecurity(&serverPtr->cluster, ZB_APS_STATUS_UNSECURED);
    }

    if (endpoint == ZB_ENDPOINT_BCAST) {
        /* For Interpan to work, we need to bind to the bcast endpoint */
        /* Remove any existing filter */
        ZbZclClusterUnbind(&serverPtr->cluster);
        ZbZclClusterBind(&serverPtr->cluster, ZB_ENDPOINT_BCAST, profile, ZCL_DIRECTION_TO_SERVER);
        /* Don't call ZbZclClusterAttach. It will remove our filter. */
    }
    else {
        (void)ZbZclClusterAttach(&serverPtr->cluster);
    }

    (void)ZbZclCommissionServerResetStartup(&serverPtr->cluster);

    return &serverPtr->cluster;
}

enum ZclStatusCodeT
ZbZclCommissionServerResetStartup(struct ZbZclClusterT *clusterPtr)
{
    /* Startup Parameters */
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_SHORT_ADDR, ZB_NWK_ADDR_UNDEFINED);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_EPID, 0U);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_PANID, ZB_NWK_ADDR_UNDEFINED);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_CHANNELMASK, WPAN_CHANNELMASK_2400MHZ);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_PROTOCOLVER, ZB_PROTOCOL_VERSION_2007);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_STACKPROFILE, ZB_NWK_STACK_PROFILE_PRO);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_STARTUPCONTROL, ZbStartTypeJoin);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_TCADDR, 0U);
    ZbZclAttrWrite(clusterPtr, NULL, ZCL_COMMISSION_SVR_ATTR_NWKKEY,
        sec_key_null, ZB_SEC_KEYSIZE, ZCL_ATTR_WRITE_FLAG_FORCE);
    ZbZclAttrWrite(clusterPtr, NULL, ZCL_COMMISSION_SVR_ATTR_PRECONFLINKKEY,
        sec_key_ha, ZB_SEC_KEYSIZE, ZCL_ATTR_WRITE_FLAG_FORCE);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_USEINSECJOIN, 1U);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_NWKKEYSEQNUM, 0U);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_NWKKEYTYPE, ZB_SEC_KEYTYPE_STANDARD_NWK);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_NWKMGRADDR, 0x0000U);

    /* Join Parameters */
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_SCANATTEMPTS, 1U);
#if 0 /* Optional, not supported */
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_TIMEBTWSCANS, 0U);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_REJOININTERVAL, 0U);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_MAXREJOININTERVAL, 0U);
#endif

    /* End Device Parameters */
#if 0 /* Optional, not supported */
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_POLLRATE, 0U);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_PARENTRETRYTHRESH, 0U);
#endif

    /* Concentrator Parameters */
#if 0 /* Optional, not supported */
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_CONCFLAG, 0U);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_CONCRADIUS, 0U);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_COMMISSION_SVR_ATTR_CONCDISCTIME, 0U);
#endif

    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclCommissionServerGetStartup(struct ZbZclClusterT *clusterPtr, struct ZbStartupT *config)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    enum ZclStatusCodeT status;
    long long val;

    ZbStartupConfigGetProDefaults(config);

    /* ZCL_COMMISSION_SVR_ATTR_SHORT_ADDR */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_SHORT_ADDR, NULL, &status);
    if ((status != ZCL_STATUS_SUCCESS) || (val > 0xffffU)) {
        return ZCL_STATUS_FAILURE;
    }
    config->shortAddress = (uint16_t)val;

    /* ZCL_COMMISSION_SVR_ATTR_EPID */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_EPID, NULL, &status);
    if (status != ZCL_STATUS_SUCCESS) {
        return ZCL_STATUS_FAILURE;
    }
    config->extendedPanId = (uint64_t)val;

    /* ZCL_COMMISSION_SVR_ATTR_PANID */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_PANID, NULL, &status);
    if ((status != ZCL_STATUS_SUCCESS) || (val > 0xffffU)) {
        return ZCL_STATUS_FAILURE;
    }
    config->panId = (uint16_t)val;

    /* ZCL_COMMISSION_SVR_ATTR_CHANNELMASK */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_CHANNELMASK, NULL, &status);
    if ((status != ZCL_STATUS_SUCCESS) || (val > 0xffffffffU)) {
        return ZCL_STATUS_FAILURE;
    }
    config->channelList.count = 1;
    /* Use the page we're currently operating on */
    config->channelList.list[0].page = serverPtr->page;
    config->channelList.list[0].channelMask = (val & WPAN_PAGE_CHANNELMASK_ALL);

#if 0
    /* ZCL_COMMISSION_SVR_ATTR_PROTOCOLVER */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_PROTOCOLVER, NULL, &status);
    if ((status != ZCL_STATUS_SUCCESS) || (val > 0xffU)) {
        return ZCL_STATUS_FAILURE;
    }
    config->protocolVersion = val;
#endif

    /* ZCL_COMMISSION_SVR_ATTR_STACKPROFILE */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_STACKPROFILE, NULL, &status);
    if ((status != ZCL_STATUS_SUCCESS) || (val > 0xffU)) {
        return ZCL_STATUS_FAILURE;
    }
    config->stackProfile = (uint8_t)val;

    /* ZCL_COMMISSION_SVR_ATTR_TCADDR */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_TCADDR, NULL, &status);
    if (status != ZCL_STATUS_SUCCESS) {
        return ZCL_STATUS_FAILURE;
    }
    config->security.trustCenterAddress = (uint64_t)val;

    /* ZCL_COMMISSION_SVR_ATTR_STARTUPCONTROL */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_STARTUPCONTROL, NULL, &status);
    if (status != ZCL_STATUS_SUCCESS) {
        return ZCL_STATUS_FAILURE;
    }

    switch (val) {
        case ZbStartTypePreconfigured:
            break;

        case ZbStartTypeForm:
        /*lint -fallthrough */
        case ZbStartTypeJoin:
            if (config->security.trustCenterAddress != 0U) {
                return ZCL_STATUS_FAILURE;
            }
            break;

        case ZbStartTypeRejoin:
            break;

        default:
            return ZCL_STATUS_FAILURE;
    }
    config->startupControl = (enum ZbStartType)val;

    /* ZCL_COMMISSION_SVR_ATTR_NWKKEY */
    status = ZbZclAttrRead(clusterPtr, ZCL_COMMISSION_SVR_ATTR_NWKKEY, NULL,
            config->security.networkKey, ZB_SEC_KEYSIZE, false);
    if (status != ZCL_STATUS_SUCCESS) {
        return ZCL_STATUS_FAILURE;
    }

    /* ZCL_COMMISSION_SVR_ATTR_USEINSECJOIN */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_USEINSECJOIN, NULL, &status);
    if ((status != ZCL_STATUS_SUCCESS) || (val > 1U)) {
        return ZCL_STATUS_FAILURE;
    }
    config->security.useInsecureRejoin = (val == 1U) ? true : false;

    /* ZCL_COMMISSION_SVR_ATTR_PRECONFLINKKEY */
    status = ZbZclAttrRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_PRECONFLINKKEY, NULL,
            config->security.preconfiguredLinkKey, ZB_SEC_KEYSIZE, false);
    if (status != ZCL_STATUS_SUCCESS) {
        return ZCL_STATUS_FAILURE;
    }

    /* ZCL_COMMISSION_SVR_ATTR_NWKKEYSEQNUM */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_NWKKEYSEQNUM, NULL, &status);
    if ((status != ZCL_STATUS_SUCCESS) || (val > 0xffU)) {
        return ZCL_STATUS_FAILURE;
    }
    config->security.networkKeySeqNum = (uint8_t)val;

    /* ZCL_COMMISSION_SVR_ATTR_NWKKEYTYPE */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_NWKKEYTYPE, NULL, &status);
    if ((status != ZCL_STATUS_SUCCESS) || (val != ZB_SEC_KEYTYPE_STANDARD_NWK)) {
        return ZCL_STATUS_FAILURE;
    }
    config->security.networkKeyType = (enum ZbSecKeyTypeT)val;

    /* ZCL_COMMISSION_SVR_ATTR_NWKMGRADDR */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_NWKMGRADDR, NULL, &status);
    if ((status != ZCL_STATUS_SUCCESS) || (val > 0xffffU)) {
        return ZCL_STATUS_FAILURE;
    }
    config->networkManagerAddress = (uint16_t)val;

    /* ZCL_COMMISSION_SVR_ATTR_SCANATTEMPTS */
    val = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_COMMISSION_SVR_ATTR_SCANATTEMPTS, NULL, &status);
    if ((status != ZCL_STATUS_SUCCESS) || (val > 0xffU) || (val == 0x00U)) {
        return ZCL_STATUS_FAILURE;
    }
    else {
        uint8_t scan_count = val;

        (void)ZbApsSet(clusterPtr->zb, ZB_APS_IB_ID_SCAN_COUNT, &scan_count, sizeof(scan_count));
    }

    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
zcl_commission_server_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zcl_hdr,
    struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    enum ZclStatusCodeT rc = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    struct ZbZclAddrInfoT srcInfo;
    enum ZbZclCommissionClientCommandsT cmd_id;

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Processing command 0x%02x", zcl_hdr->cmdId);

    memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zcl_hdr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    if (!serverPtr->enable) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Dropping command 0x%02x, cluster is disabled", zcl_hdr->cmdId);
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (zcl_hdr->frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (zcl_hdr->frameCtrl.manufacturer != 0U) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    cmd_id = (enum ZbZclCommissionClientCommandsT)zcl_hdr->cmdId;
    switch (cmd_id) {
        case ZCL_COMMISSION_CLI_CMD_RESTART_DEVICE:
        {
            struct ZbZclCommissionClientRestartDev req;

            if (serverPtr->callbacks.restart_device == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            if (dataIndPtr->asduLength < 3U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            memset(&req, 0, sizeof(req));
            req.options = dataIndPtr->asdu[0];
            req.delay = dataIndPtr->asdu[1];
            req.jitter = dataIndPtr->asdu[2];
            rc = serverPtr->callbacks.restart_device(&serverPtr->cluster, &req, &srcInfo, serverPtr->cluster.app_cb_arg);
            break;
        }

        case ZCL_COMMISSION_CLI_CMD_SAVE_STARTUP:
        {
            struct ZbZclCommissionClientSaveStartup req;

            if (serverPtr->callbacks.save_startup == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 2U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.options = dataIndPtr->asdu[0];
            req.index = dataIndPtr->asdu[1];
            rc = serverPtr->callbacks.save_startup(&serverPtr->cluster, &req, &srcInfo, serverPtr->cluster.app_cb_arg);
            break;
        }

        case ZCL_COMMISSION_CLI_CMD_RESTORE_STARTUP:
        {
            struct ZbZclCommissionClientRestoreStartup req;

            if (serverPtr->callbacks.restore_startup == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 2U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.options = dataIndPtr->asdu[0];
            req.index = dataIndPtr->asdu[1];
            rc = serverPtr->callbacks.restore_startup(&serverPtr->cluster, &req, &srcInfo, serverPtr->cluster.app_cb_arg);
            break;
        }

        case ZCL_COMMISSION_CLI_CMD_RESET_STARTUP:
        {
            struct ZbZclCommissionClientResetStartup req;

            if (serverPtr->callbacks.reset_startup == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 2U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.options = dataIndPtr->asdu[0];
            req.index = dataIndPtr->asdu[1];
            rc = serverPtr->callbacks.reset_startup(&serverPtr->cluster, &req, &srcInfo, serverPtr->cluster.app_cb_arg);
            break;
        }

        default:
            rc = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return rc;
}

enum ZclStatusCodeT
ZbZclCommissionServerEnable(struct ZbZclClusterT *clusterPtr, bool enable,
    struct ZbZclCommissionServerEnableInfoT *info)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)clusterPtr;
    uint64_t epid = 0U;

    /* Get current EPID. Don't muck around with the MAC settings if we're currently
     * operating on a network. */
    (void)ZbNwkGet(clusterPtr->zb, ZB_NWK_NIB_ID_ExtendedPanId, &epid, sizeof(uint64_t));
    if (enable) {
        if (epid == 0U) {
            struct ZbNwkCommissioningInfo *commission_info;

            if (info == NULL) {
                return ZCL_STATUS_FAILURE;
            }
            commission_info = ZbHeapAlloc(clusterPtr->zb, sizeof(struct ZbNwkCommissioningInfo));
            if (commission_info == NULL) {
                return ZCL_STATUS_FAILURE;
            }
            memset(commission_info, 0, sizeof(struct ZbNwkCommissioningInfo));
            commission_info->ifc_index = 0U;
            commission_info->nwk_addr = ZB_NWK_ADDR_UNDEFINED;
            commission_info->pan_id = ZB_NWK_ADDR_UNDEFINED;
            commission_info->rx_on = 1U;
            commission_info->page = info->page;
            commission_info->channel = info->channel;
            if (!ZbNwkCommissioningConfig(clusterPtr->zb, commission_info)) {
                ZbHeapFree(clusterPtr->zb, commission_info);
                return ZCL_STATUS_FAILURE;
            }
            ZbHeapFree(clusterPtr->zb, commission_info);
            serverPtr->page = info->page;
        }
        else {
            struct ZbChannelListT channelList;

            (void)ZbNwkGet(clusterPtr->zb, ZB_NWK_NIB_ID_ActiveChannelList, &channelList, sizeof(struct ZbChannelListT));
            serverPtr->page = channelList.list[0].page;
        }
    }

    serverPtr->enable = enable;
    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
zcl_commission_server_send_rsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dstInfo,
    enum ZbZclCommissionServerCommandsT cmd_id, enum ZclStatusCodeT status)
{
    struct ZbZclCommandReqT cmd_req;
    uint8_t payload[1];

    /* Source Information and TX Options */
    ZbZclClusterInitCommandReq(clusterPtr, &cmd_req);

    /* Destination */
    cmd_req.dst = dstInfo->addr;

    /* ZCL Header Info */
    cmd_req.hdr.frameCtrl.frameType = ZCL_FRAMETYPE_CLUSTER;
    cmd_req.hdr.frameCtrl.direction = ZCL_DIRECTION_TO_CLIENT;
    cmd_req.hdr.seqNum = dstInfo->seqnum;
    cmd_req.hdr.cmdId = cmd_id;

    /* ZCL Payload */
    payload[0] = status;
    cmd_req.payload = payload;
    cmd_req.length = sizeof(payload);

    return ZbZclCommandReq(clusterPtr->zb, &cmd_req, NULL, NULL);
}

enum ZclStatusCodeT
ZbZclCommissionServerSendRestartRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dstInfo,
    struct ZbZclCommissionServerRestartDevRsp *rsp)
{
    return zcl_commission_server_send_rsp(clusterPtr, dstInfo, ZCL_COMMISSION_SVR_CMD_RESTART_DEVICE_RSP, rsp->status);
}

enum ZclStatusCodeT
ZbZclCommissionServerSendSaveStartupRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dstInfo,
    struct ZbZclCommissionServerSaveStartupRsp *rsp)
{
    return zcl_commission_server_send_rsp(clusterPtr, dstInfo, ZCL_COMMISSION_SVR_CMD_SAVE_STARTUP_RSP, rsp->status);
}

enum ZclStatusCodeT
ZbZclCommissionServerSendRestoreStartupRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dstInfo,
    struct ZbZclCommissionServerRestoreStartupRsp *rsp)
{
    return zcl_commission_server_send_rsp(clusterPtr, dstInfo, ZCL_COMMISSION_SVR_CMD_RESTORE_STARTUP_RSP, rsp->status);
}

enum ZclStatusCodeT
ZbZclCommissionServerSendResetStartupRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dstInfo,
    struct ZbZclCommissionServerResetStartupRsp *rsp)
{
    return zcl_commission_server_send_rsp(clusterPtr, dstInfo, ZCL_COMMISSION_SVR_CMD_RESET_STARTUP_RSP, rsp->status);
}
