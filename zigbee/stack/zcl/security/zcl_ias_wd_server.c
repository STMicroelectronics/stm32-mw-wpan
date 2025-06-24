/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

/*-------------------------------------------------
 *  DESCRIPTION
 *      HA IAS devices Implementation.
 *-------------------------------------------------
 */

#include "zcl/security/zcl.ias_wd.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster;

    /* Application callbacks */
    struct ZbZclIasWdServerCallbacksT callbacks;
};

static enum ZclStatusCodeT zcl_ias_wd_server_command(struct ZbZclClusterT *, struct ZbZclHeaderT *, struct ZbApsdeDataIndT *);

/* Attributes */
static const struct ZbZclAttrT zcl_ias_wd_server_attr_list[] = {
    {
        ZCL_IAS_WD_SVR_ATTR_MAX_DURATION, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_PERSISTABLE, 0, NULL, {0, 0}, {0, 0}
    },
};

struct ZbZclClusterT *
ZbZclIasWdServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclIasWdServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_SECURITY_IAS_WARNING, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "CCB 2350 2341"
     * (need to investigate these changes) */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    clusterPtr->cluster.command = zcl_ias_wd_server_command;

    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_ias_wd_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_ias_wd_server_attr_list))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_IAS_WD_SVR_ATTR_MAX_DURATION, 240);

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);
    if (callbacks != NULL) {
        (void)memcpy(&clusterPtr->callbacks, callbacks, sizeof(struct ZbZclIasWdServerCallbacksT));
    }
    else {
        (void)memset(&clusterPtr->callbacks, 0, sizeof(struct ZbZclIasWdServerCallbacksT));
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_ias_wd_server_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *serverPtr = (void *)clusterPtr;
    unsigned int i = 0;

    if (zclHdrPtr->frameCtrl.manufacturer) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    switch (zclHdrPtr->cmdId) {
        case ZCL_IAS_WD_CLI_CMD_START_WARNING:
            if (serverPtr->callbacks.start_warning) {
                struct ZbZclIasWdClientStartWarningReqT start_warning_req;
                uint8_t bitmap8;
                uint16_t max_duration;
                enum ZclStatusCodeT status;

                if (dataIndPtr->asduLength < 5) {
                    return ZCL_STATUS_MALFORMED_COMMAND;
                }
                (void)memset(&start_warning_req, 0, sizeof(start_warning_req));
                bitmap8 = dataIndPtr->asdu[i++];
                start_warning_req.warning_mode = (enum ZbZclIasWdWarningModeT)((bitmap8 >> 4) & 0x0f);
                start_warning_req.strobe = (enum ZbZclIasWdStrobeT)((bitmap8 >> 2) & 0x03);
                start_warning_req.siren_level = (enum ZbZclIasWdLevelT)(bitmap8 & 0x03);

                start_warning_req.warning_duration = pletoh16(&dataIndPtr->asdu[i]);
                i += 2;
                start_warning_req.strobe_dutycycle = dataIndPtr->asdu[i++];
                start_warning_req.strobe_level = (enum ZbZclIasWdLevelT)dataIndPtr->asdu[i++];

                max_duration = ZbZclAttrIntegerRead(clusterPtr, ZCL_IAS_WD_SVR_ATTR_MAX_DURATION, NULL, &status);
                if (status != 0x00) {
                    return ZCL_STATUS_FAILURE;
                }
                if (start_warning_req.warning_duration > max_duration) {
                    start_warning_req.warning_duration = max_duration;
                }

                return serverPtr->callbacks.start_warning(clusterPtr, clusterPtr->app_cb_arg, &start_warning_req);
            }
            return ZCL_STATUS_UNSUPP_COMMAND;

        case ZCL_IAS_WD_CLI_CMD_SQUAWK:
            if (serverPtr->callbacks.squawk) {
                struct ZbZclIasWdClientSquawkReqT squawk_req;
                uint8_t bitmap8;

                if (dataIndPtr->asduLength < 1) {
                    return ZCL_STATUS_MALFORMED_COMMAND;
                }
                (void)memset(&squawk_req, 0, sizeof(squawk_req));
                bitmap8 = dataIndPtr->asdu[i++];
                squawk_req.squawk_mode = (enum ZbZclIasWdSquawkModeT)((bitmap8 >> 4) & 0x0f);
                squawk_req.strobe = (enum ZbZclIasWdStrobeT)((bitmap8 >> 3) & 0x01);
                squawk_req.squawk_level = (enum ZbZclIasWdLevelT)(bitmap8 & 0x03);

                return serverPtr->callbacks.squawk(clusterPtr, clusterPtr->app_cb_arg, &squawk_req);
            }
            return ZCL_STATUS_UNSUPP_COMMAND;

        default:
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
}
