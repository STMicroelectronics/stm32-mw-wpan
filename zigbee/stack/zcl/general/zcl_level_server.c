/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.level.h"
#include "zcl/general/zcl.onoff.h"

#define ZCL_LEVEL_OPTIONS_DENY_STATUS       ZCL_STATUS_REQUEST_DENIED /* was ZCL_STATUS_SUCCESS */

struct cluster_priv_t {
    struct ZbZclClusterT cluster;
    struct ZbZclClusterT *onoff_server;
    struct ZbZclLevelServerCallbacksT callbacks;
};

/* Attributes */
static const struct ZbZclAttrT zcl_level_server_attr_list[] = {
    {
        ZCL_LEVEL_ATTR_CURRLEVEL, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0xfe}, {0, 0}
    },
#if 0
    {
        ZCL_LEVEL_ATTR_REMAINTIME, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_LEVEL_ATTR_MINLEVEL, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_LEVEL_ATTR_MAXLEVEL, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_LEVEL_ATTR_CURRFREQ, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_LEVEL_ATTR_MINFREQ, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_LEVEL_ATTR_MAXFREQ, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_LEVEL_ATTR_ONOFF_TRANS_TIME, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_LEVEL_ATTR_ONLEVEL, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_LEVEL_ATTR_ON_TRANS_TIME, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xfffe}, {0, 0}
    },
    {
        ZCL_LEVEL_ATTR_OFF_TRANS_TIME, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xfffe}, {0, 0}
    },
    {
        ZCL_LEVEL_ATTR_DEFAULT_MOVE_RATE, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xfe}, {0, 0}
    },
#endif
    {
        ZCL_LEVEL_ATTR_OPTIONS, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xfe}, {0, 0}
    },
#if 0
    {
        ZCL_LEVEL_ATTR_STARTUP_CURRLEVEL, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xff}, {0, 0}
    }
#endif
};

static uint8_t zcl_level_server_get_scene_data(struct ZbZclClusterT *clusterPtr, uint8_t *extBuf, uint8_t extMaxLen);
static enum ZclStatusCodeT zcl_level_server_set_scene_data(struct ZbZclClusterT *clusterPtr, uint8_t *extData, uint8_t extLen, uint16_t transition_tenths);
static enum ZclStatusCodeT zcl_level_server_handle_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclLevelServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclClusterT *onoff_server,
    struct ZbZclLevelServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    if (onoff_server != NULL) {
        /* If an OnOff Server is provided, make sure it's correct and on the same endpoint */
        if (ZbZclClusterGetClusterId(onoff_server) != ZCL_CLUSTER_ONOFF) {
            return NULL;
        }
        if (ZbZclClusterGetDirection(onoff_server) != ZCL_DIRECTION_TO_SERVER) {
            return NULL;
        }
        if (ZbZclClusterGetEndpoint(onoff_server) != endpoint) {
            return NULL;
        }
    }

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_LEVEL_CONTROL, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "added Options attribute, state change table; ZLO 1.0" */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 2);

    clusterPtr->cluster.get_scene_data = zcl_level_server_get_scene_data;
    clusterPtr->cluster.set_scene_data = zcl_level_server_set_scene_data;
    clusterPtr->cluster.command = zcl_level_server_handle_command;

    /* Configure callbacks */
    if (callbacks != NULL) {
        (void)memcpy(&clusterPtr->callbacks, callbacks, sizeof(struct ZbZclLevelServerCallbacksT));
    }
    else {
        (void)memset(&clusterPtr->callbacks, 0, sizeof(struct ZbZclLevelServerCallbacksT));
    }
    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    /* Set the Linked On/Off Cluster */
    clusterPtr->onoff_server = onoff_server;

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_level_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_level_server_attr_list))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static uint8_t
zcl_level_server_get_scene_data(struct ZbZclClusterT *clusterPtr, uint8_t *extBuf, uint8_t extMaxLen)
{
    uint8_t len = 3; /* Attribute data starts at the third byte. */
    uint8_t attrVal;

    /* Write attributes first, before Cluster ID and Length */

    /* Current Level attribute */
    if (ZbZclAttrRead(clusterPtr, ZCL_LEVEL_ATTR_CURRLEVEL, NULL, &attrVal, sizeof(attrVal), false) != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "failed to read CurrentLevel attribute");
        return 0;
    }

    extBuf[len] = attrVal;
    len++;

    /* Cluster ID [0:1] */
    putle16(&extBuf[0], clusterPtr->clusterId);
    /* Extension Length [2] */
    extBuf[2] = len - 3;
    return len;
}

static enum ZclStatusCodeT
zcl_level_server_set_scene_data(struct ZbZclClusterT *clusterPtr, uint8_t *extData, uint8_t extLen, uint16_t transition_tenths)
{
    struct cluster_priv_t *levelClusterPtr = (struct cluster_priv_t *)clusterPtr;
    uint8_t level;

    if (extLen != 1) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, invalid scene data length (%d)", extLen);
        return ZCL_STATUS_INVALID_VALUE;
    }

    level = extData[0];

    if (levelClusterPtr->callbacks.move_to_level != NULL) {
        struct ZbZclLevelClientMoveToLevelReqT req;

        memset(&req, 0, sizeof(req));
        req.with_onoff = false;
        req.level = level;
        if (ZbZclAttrRead(clusterPtr, ZCL_LEVEL_ATTR_ONOFF_TRANS_TIME, NULL,
                &req.transition_time, sizeof(req.transition_time), false) != ZCL_STATUS_SUCCESS) {
            req.transition_time = ZCL_LEVEL_MINIMUM_TRANS_TIME;
        }
        levelClusterPtr->callbacks.move_to_level(clusterPtr, &req, NULL, clusterPtr->app_cb_arg);
    }
    else {
        /* no callback, just set the attribute value */
        ZbZclAttrIntegerWrite(clusterPtr, ZCL_LEVEL_ATTR_CURRLEVEL, level);
    }

    return ZCL_STATUS_SUCCESS;
}

/**
 * Command execution SHALL NOT continue beyond the Options processing if all of
 * these criteria are true:
 *  a. The command is one of the ‘without On/Off’ commands: Move, Move to Level, Stop, or Step.
 *  b. The On/Off cluster exists on the same endpoint as this cluster.
 *  c. The OnOff attribute of the On/Off cluster, on this endpoint, is 0x00 (FALSE).
 *  d. The value of the ExecuteIfOff bit is 0.
 * @param
 * @return
 */
static bool
zcl_level_options_cmd_allow(struct ZbZclClusterT *clusterPtr, uint8_t options_mask, uint8_t options_override)
{
    struct cluster_priv_t *levelClusterPtr = (struct cluster_priv_t *)clusterPtr;
    uint8_t i, mask, options, onoff_val;

    /* Read the options field */
    if (ZbZclAttrRead(clusterPtr, ZCL_LEVEL_ATTR_OPTIONS, NULL,
            &options, sizeof(options), false) != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, failed to read from OPTIONS attribute");
        return false; /* Drop it */
    }

    /* ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "options = 0x%02x, options_mask = 0x%02x", options, options_mask); */

    /* Check all bits in the OptionsMask */
    for (i = 0; i < 8; i++) {
        mask = (1U << i);
        if ((options_mask & mask) == 0U) {
            continue;
        }
        /* Mask bit is set, so use override bit instead */
        if ((options_override & mask) == 0U) {
            /* Clear bit in options */
            options &= ~mask;
        }
        else {
            /* Set bit in options */
            options |= mask;
        }
    }

    if ((options & ZCL_LEVEL_OPTIONS_EXECUTE_IF_OFF) == 0) {
        if (levelClusterPtr->onoff_server != NULL) {
            /* Read the OnOff state */
            if (ZbZclAttrRead(levelClusterPtr->onoff_server, ZCL_ONOFF_ATTR_ONOFF,
                    NULL, &onoff_val, sizeof(onoff_val), false) != ZCL_STATUS_SUCCESS) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, failed to read from ONOFF attribute");
                return false; /* Drop it */
            }
            if (onoff_val == 0x00) {
                /* ExecuteIfOff == false, and OnOff is OFF, so drop this command */
                return false; /* Drop it */
            }
        }
    }

    return true;
}

static enum ZclStatusCodeT
zcl_level_server_handle_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr,
    struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *levelClusterPtr = (struct cluster_priv_t *)clusterPtr;
    uint16_t asdu_length = dataIndPtr->asduLength;
    struct ZbZclAddrInfoT srcInfo;

    (void)memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zclHdrPtr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    switch (zclHdrPtr->cmdId) {
        case ZCL_LEVEL_COMMAND_MOVELEVEL:
        case ZCL_LEVEL_COMMAND_MOVELEVEL_ONOFF:
        {
            struct ZbZclLevelClientMoveToLevelReqT req;

            /* Sanity-check the length of the command payload */
            if (asdu_length < 3) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "malformed command, asduLength is %d", asdu_length);
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (levelClusterPtr->callbacks.move_to_level == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));
            if (zclHdrPtr->cmdId == ZCL_LEVEL_COMMAND_MOVELEVEL_ONOFF) {
                req.with_onoff = true;
            }
            req.level = dataIndPtr->asdu[0];
            req.transition_time = pletoh16(&dataIndPtr->asdu[1]);

            if (zclHdrPtr->cmdId == ZCL_LEVEL_COMMAND_MOVELEVEL) {
                /* Options */
                if (asdu_length >= 5) {
                    req.mask = dataIndPtr->asdu[3];
                    req.override = dataIndPtr->asdu[4];
                }
                /* Check if command should be dropped */
                if (!zcl_level_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                    return ZCL_LEVEL_OPTIONS_DENY_STATUS;
                }
            }
            return levelClusterPtr->callbacks.move_to_level(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_LEVEL_COMMAND_MOVE:
        case ZCL_LEVEL_COMMAND_MOVE_ONOFF:
        {
            struct ZbZclLevelClientMoveReqT req;

            /* Sanity-check the length of the command payload */
            if (asdu_length < 2) {
                /* Return the default ZCL response indicating a malformed command. */
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "malformed command, asduLength is %d", asdu_length);
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (levelClusterPtr->callbacks.move == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));
            if (zclHdrPtr->cmdId == ZCL_LEVEL_COMMAND_MOVE_ONOFF) {
                req.with_onoff = true;
            }
            req.mode = dataIndPtr->asdu[0];
            req.rate = dataIndPtr->asdu[1];

            if (zclHdrPtr->cmdId == ZCL_LEVEL_COMMAND_MOVE) {
                /* Options */
                if (asdu_length >= 4) {
                    req.mask = dataIndPtr->asdu[2];
                    req.override = dataIndPtr->asdu[3];
                }
                /* Check if command should be dropped */
                if (!zcl_level_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                    return ZCL_LEVEL_OPTIONS_DENY_STATUS;
                }
            }
            return levelClusterPtr->callbacks.move(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_LEVEL_COMMAND_STEP:
        case ZCL_LEVEL_COMMAND_STEP_ONOFF:
        {
            struct ZbZclLevelClientStepReqT req;

            if (asdu_length < 4) { /* check the length of the command payload */
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "malformed command, asduLength is %d", asdu_length);
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (levelClusterPtr->callbacks.step == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));
            if (zclHdrPtr->cmdId == ZCL_LEVEL_COMMAND_STEP_ONOFF) {
                req.with_onoff = true;
            }
            req.mode = dataIndPtr->asdu[0];
            req.size = dataIndPtr->asdu[1];
            req.transition_time = pletoh16(&dataIndPtr->asdu[2]);

            if (zclHdrPtr->cmdId == ZCL_LEVEL_COMMAND_STEP) {
                /* Options */
                if (asdu_length >= 6) {
                    req.mask = dataIndPtr->asdu[4];
                    req.override = dataIndPtr->asdu[5];
                }
                /* Check if command should be dropped */
                if (!zcl_level_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                    return ZCL_LEVEL_OPTIONS_DENY_STATUS;
                }
            }
            return levelClusterPtr->callbacks.step(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);

        }

        case ZCL_LEVEL_COMMAND_STOP:
        case ZCL_LEVEL_COMMAND_STOP_ONOFF:
        {
            struct ZbZclLevelClientStopReqT req;

            if (levelClusterPtr->callbacks.stop == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));
            if (zclHdrPtr->cmdId == ZCL_LEVEL_COMMAND_STOP_ONOFF) {
                req.with_onoff = true;
            }

            if (zclHdrPtr->cmdId == ZCL_LEVEL_COMMAND_STOP) {
                /* Options */
                if (asdu_length >= 2) {
                    req.mask = dataIndPtr->asdu[0];
                    req.override = dataIndPtr->asdu[1];
                }
                /* Check if command should be dropped */
                if (!zcl_level_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                    return ZCL_LEVEL_OPTIONS_DENY_STATUS;
                }
            }
            return levelClusterPtr->callbacks.stop(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        default:
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
}
