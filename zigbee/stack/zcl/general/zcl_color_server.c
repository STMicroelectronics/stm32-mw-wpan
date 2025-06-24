/* Copyright [2016 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.onoff.h"
#include "zcl/general/zcl.level.h"
#include "zcl/general/zcl.color.h"

#define ZCL_COLOR_OPTIONS_DENY_STATUS       ZCL_STATUS_REQUEST_DENIED /* was ZCL_STATUS_SUCCESS */

struct cluster_priv_t {
    struct ZbZclClusterT cluster;
    struct ZbZclClusterT *onoff_server;
    struct ZbColorClusterConfig config;
};

/* Forward declarations */
static enum ZclStatusCodeT zcl_color_server_handle_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);
static uint8_t zcl_color_server_get_scene_data(struct ZbZclClusterT *clusterPtr, uint8_t *extBuf, uint8_t extMaxLen);
static enum ZclStatusCodeT zcl_color_server_set_scene_data(struct ZbZclClusterT *clusterPtr, uint8_t *extData, uint8_t extLen, uint16_t transition_tenths);
static enum ZclStatusCodeT zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src, uint16_t attribute_id,
    const uint8_t *input_data, unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg);

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

const struct ZbZclAttrT zcl_attr_primaries_mandatory_list[] = {
    {
        ZCL_COLOR_ATTR_COLOR_MODE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COLOR_ATTR_OPTIONS, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0, 0x1}, {0, 0}
    },
    {
        ZCL_COLOR_ATTR_ENH_COLOR_MODE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COLOR_ATTR_COLOR_CAPABILITIES, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COLOR_ATTR_NUM_PRIMARIES, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0, 0}, {0, 0}
    },
};

const struct ZbZclAttrT zcl_attr_hs_mandatory_list[] = {
    {
        ZCL_COLOR_ATTR_CURRENT_HUE, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, ZCL_COLOR_MAX_HUE_SAT},
        {ZCL_ATTR_REPORT_MIN_INTVL_DEFAULT, ZCL_ATTR_REPORT_MAX_INTVL_DEFAULT}
    },
    {
        ZCL_COLOR_ATTR_CURRENT_SAT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, ZCL_COLOR_MAX_HUE_SAT},
        {ZCL_ATTR_REPORT_MIN_INTVL_DEFAULT, ZCL_ATTR_REPORT_MAX_INTVL_DEFAULT}
    },
};

const struct ZbZclAttrT zcl_attr_hue_enh_mandatory_list[] = {
    {
        ZCL_COLOR_ATTR_ENH_CURR_HUE, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0},
        {ZCL_ATTR_REPORT_MIN_INTVL_DEFAULT, ZCL_ATTR_REPORT_MAX_INTVL_DEFAULT}
    },
};

const struct ZbZclAttrT zcl_attr_xy_mandatory_list[] = {
    {
        ZCL_COLOR_ATTR_CURRENT_X, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, ZCL_COLOR_X_MAX},
        {ZCL_ATTR_REPORT_MIN_INTVL_DEFAULT, ZCL_ATTR_REPORT_MAX_INTVL_DEFAULT}
    },
    {
        ZCL_COLOR_ATTR_CURRENT_Y, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, ZCL_COLOR_Y_MAX},
        {ZCL_ATTR_REPORT_MIN_INTVL_DEFAULT, ZCL_ATTR_REPORT_MAX_INTVL_DEFAULT}
    },
};

const struct ZbZclAttrT zcl_attr_temp_mandatory_list[] = {
    {
        ZCL_COLOR_ATTR_COLOR_TEMP_MIREDS, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, ZCL_COLOR_TEMP_MAX},
        {ZCL_ATTR_REPORT_MIN_INTVL_DEFAULT, ZCL_ATTR_REPORT_MAX_INTVL_DEFAULT}
    },
    {
        ZCL_COLOR_ATTR_COLOR_TEMP_MIN, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, ZCL_COLOR_TEMP_MAX}, {0, 0}
    },
    {
        ZCL_COLOR_ATTR_COLOR_TEMP_MAX, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, ZCL_COLOR_TEMP_MAX}, {0, 0}
    },
    {
        ZCL_COLOR_ATTR_COUPLE_COLOR_TL_MIN, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_COLOR_ATTR_STARTUP_COLOR_TEMP, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, zcl_attr_cb, {0, ZCL_COLOR_STARTUP_COLOR_TEMP_MAX}, {0, 0}
    },
};

const struct ZbZclAttrT zcl_attr_loop_mandatory_list[] = {
    {
        ZCL_COLOR_ATTR_COLOR_LOOP_ACTIVE, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COLOR_ATTR_COLOR_LOOP_DIR, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COLOR_ATTR_COLOR_LOOP_TIME, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COLOR_ATTR_COLOR_LOOP_START_HUE, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_COLOR_ATTR_COLOR_LOOP_STORE_HUE, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
};

struct ZbZclClusterT *
ZbZclColorServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclClusterT *onoff_server,
    const struct ZbZclAttrT *attribute_list, unsigned int num_attrs,
    struct ZbColorClusterConfig *config, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    if (config == NULL) {
        return NULL;
    }

    /* Check mandatory capabalities */
    if ((config->capabilities & ZCL_COLOR_CAP_ENH_HUE) != 0U) {
        if ((config->capabilities & ZCL_COLOR_CAP_HS) == 0U) {
            return NULL;
        }
    }
    if ((config->capabilities & ZCL_COLOR_CAP_XY) == 0U) {
        return NULL;
    }

    /* make sure we are only linking to an On/Off cluster if available and on same endpoint*/
    if (onoff_server != NULL) {
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

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_COLOR_CONTROL, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "added Options attribute, CCB 2085 2104 2124 2230; ZLO 1.0" */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 2);

    clusterPtr->cluster.get_scene_data = zcl_color_server_get_scene_data;
    clusterPtr->cluster.set_scene_data = zcl_color_server_set_scene_data;
    clusterPtr->cluster.command = zcl_color_server_handle_command;

    /* Save the configuration */
    memcpy(&clusterPtr->config, config, sizeof(struct ZbColorClusterConfig));

    /* Set the Linked On/Off Cluster */
    clusterPtr->onoff_server = onoff_server;

    /* configure basic requirements */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_attr_primaries_mandatory_list,
            ZCL_ATTR_LIST_LEN(zcl_attr_primaries_mandatory_list))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    if ((config->capabilities & ZCL_COLOR_CAP_HS) != 0U) {
        if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_attr_hs_mandatory_list,
                ZCL_ATTR_LIST_LEN(zcl_attr_hs_mandatory_list))) {
            ZbZclClusterFree(&clusterPtr->cluster);
            return NULL;
        }
    }
    if ((config->capabilities & ZCL_COLOR_CAP_ENH_HUE) != 0U) {
        if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_attr_hue_enh_mandatory_list,
                ZCL_ATTR_LIST_LEN(zcl_attr_hue_enh_mandatory_list))) {
            ZbZclClusterFree(&clusterPtr->cluster);
            return NULL;
        }
    }
    if ((config->capabilities & ZCL_COLOR_CAP_XY) != 0U) {
        if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_attr_xy_mandatory_list,
                ZCL_ATTR_LIST_LEN(zcl_attr_xy_mandatory_list))) {
            ZbZclClusterFree(&clusterPtr->cluster);
            return NULL;
        }
    }
    if ((config->capabilities & ZCL_COLOR_CAP_COLOR_TEMP) != 0U) {
        if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_attr_temp_mandatory_list,
                ZCL_ATTR_LIST_LEN(zcl_attr_temp_mandatory_list))) {
            ZbZclClusterFree(&clusterPtr->cluster);
            return NULL;
        }
    }
    if ((config->capabilities & ZCL_COLOR_CAP_COLOR_LOOP) != 0U) {
        if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_attr_loop_mandatory_list,
                ZCL_ATTR_LIST_LEN(zcl_attr_loop_mandatory_list))) {
            ZbZclClusterFree(&clusterPtr->cluster);
            return NULL;
        }
    }

    /* Application Defined Attributes */
    if (attribute_list != NULL) {
        if (ZbZclAttrAppendList(&clusterPtr->cluster, attribute_list, num_attrs)) {
            ZbZclClusterFree(&clusterPtr->cluster);
            return NULL;
        }
    }

    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_OPTIONS, ZCL_COLOR_OPTIONS_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_COLOR_MODE, ZCL_COLOR_MODE_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_COLOR_CAPABILITIES, 0);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_ENH_COLOR_MODE, 1);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_NUM_PRIMARIES, 0);

    if ((config->capabilities & ZCL_COLOR_CAP_HS) != 0U) {
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_CURRENT_HUE, 0);
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_CURRENT_SAT, 0);
    }
    if ((config->capabilities & ZCL_COLOR_CAP_XY) != 0U) {
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_CURRENT_X, ZCL_COLOR_X_DEFAULT);
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_CURRENT_Y, ZCL_COLOR_Y_DEFAULT);
    }
    if ((config->capabilities & ZCL_COLOR_CAP_COLOR_TEMP) != 0U) {
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_COLOR_TEMP_MIREDS, ZCL_COLOR_TEMP_DEFAULT);
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_COLOR_TEMP_MIN, 0);
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_COLOR_TEMP_MAX, ZCL_COLOR_TEMP_MAX);
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_COUPLE_COLOR_TL_MIN, 0);
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_STARTUP_COLOR_TEMP, ZCL_COLOR_STARTUP_COLOR_TEMP_MAX);
    }
    if ((config->capabilities & ZCL_COLOR_CAP_COLOR_LOOP) != 0U) {
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_COLOR_LOOP_ACTIVE, 0);
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_COLOR_LOOP_TIME, ZCL_COLOR_LOOP_TIME_DEFAULT);
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_COLOR_LOOP_START_HUE, ZCL_COLOR_LOOP_START_HUE_DEFAULT);
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_COLOR_LOOP_DIR, 0);
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_COLOR_LOOP_STORE_HUE, 0);
    }
    if ((config->capabilities & ZCL_COLOR_CAP_ENH_HUE) != 0U) {
        ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_ENH_CURR_HUE, 0);
    }

    clusterPtr->cluster.app_cb_arg = arg;

    /* set the color capabilites to the attribute */
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_COLOR_ATTR_COLOR_CAPABILITIES, config->capabilities);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static uint8_t
zcl_color_server_get_scene_data(struct ZbZclClusterT *clusterPtr, uint8_t *extBuf, uint8_t extMaxLen)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)clusterPtr;
    uint8_t len = 3; /* Attribute data starts at the third byte. */
    uint8_t attrVal8;
    uint16_t attrVal16;

    /* Write attributes first, before Cluster ID and Length */

    /* 1. CurrentX */
    if (ZbZclAttrRead(clusterPtr, ZCL_COLOR_ATTR_CURRENT_X, NULL, &attrVal16, sizeof(attrVal16), false) != ZCL_STATUS_SUCCESS) {
        return 0;
    }
    putle16(&extBuf[len], attrVal16);
    len += 2;

    /* 2. CurrentY */
    if (ZbZclAttrRead(clusterPtr, ZCL_COLOR_ATTR_CURRENT_Y, NULL, &attrVal16, sizeof(attrVal16), false) != ZCL_STATUS_SUCCESS) {
        return 0;
    }
    putle16(&extBuf[len], attrVal16);
    len += 2;

    /* 3. EnhancedCurrentHue */
    if ((server->config.capabilities & ZCL_COLOR_CAP_ENH_HUE) != 0U) {
        if (ZbZclAttrRead(clusterPtr, ZCL_COLOR_ATTR_ENH_CURR_HUE, NULL, &attrVal16, sizeof(attrVal16), false) != ZCL_STATUS_SUCCESS) {
            return 0;
        }
    }
    else {
        attrVal16 = 0U;
    }
    putle16(&extBuf[len], attrVal16);
    len += 2;

    /* 4. CurrentSaturation */
    if (ZbZclAttrRead(clusterPtr, ZCL_COLOR_ATTR_CURRENT_SAT, NULL, &attrVal8, sizeof(attrVal8), false) != ZCL_STATUS_SUCCESS) {
        return 0;
    }
    extBuf[len] = attrVal8;
    len++;

    /* 5. ColorLoopActive */
    /* 6. ColorLoopDirection */
    /* 7. ColorLoopTime */
    if ((server->config.capabilities & ZCL_COLOR_CAP_COLOR_LOOP) != 0U) {
        if (ZbZclAttrRead(clusterPtr, ZCL_COLOR_ATTR_COLOR_LOOP_ACTIVE, NULL, &attrVal8, sizeof(attrVal8), false) != ZCL_STATUS_SUCCESS) {
            return 0;
        }
        extBuf[len++] = attrVal8;
        if (ZbZclAttrRead(clusterPtr, ZCL_COLOR_ATTR_COLOR_LOOP_DIR, NULL, &attrVal8, sizeof(attrVal8), false) != ZCL_STATUS_SUCCESS) {
            return 0;
        }
        extBuf[len++] = attrVal8;
        if (ZbZclAttrRead(clusterPtr, ZCL_COLOR_ATTR_COLOR_LOOP_TIME, NULL, &attrVal16, sizeof(attrVal16), false) != ZCL_STATUS_SUCCESS) {
            return 0;
        }
        putle16(&extBuf[len], attrVal16);
        len += 2;
    }
    else {
        extBuf[len++] = 0x00U;
        extBuf[len++] = 0x00U;
        putle16(&extBuf[len], 0x0000U);
        len += 2;
    }

    /* 8. ColorTemperatureMireds */
    if ((server->config.capabilities & ZCL_COLOR_CAP_COLOR_TEMP) != 0U) {
        if (ZbZclAttrRead(clusterPtr, ZCL_COLOR_ATTR_COLOR_TEMP_MIREDS, NULL, &attrVal16, sizeof(attrVal16), false) != ZCL_STATUS_SUCCESS) {
            return 0;
        }
    }
    else {
        attrVal16 = 0U;
    }
    putle16(&extBuf[len], attrVal16);
    len += 2;

    /* Cluster ID [0:1] */
    putle16(&extBuf[0], clusterPtr->clusterId);
    /* Extension Length [2] */
    extBuf[2] = len - 3;
    return len;
}

static enum ZclStatusCodeT
zcl_color_server_set_scene_data(struct ZbZclClusterT *clusterPtr, uint8_t *extData, uint8_t extLen, uint16_t transition_tenths)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)clusterPtr;
    uint16_t current_x;
    uint16_t current_y;
    uint16_t current_hue_enh;
    uint8_t current_sat;
    uint8_t loop_active;
    uint8_t loop_direction;
    uint16_t loop_time;
    uint16_t color_temp;

    if (extLen != 13) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, invalid scene data length (%d)", extLen);
        return ZCL_STATUS_INVALID_VALUE;
    }

    current_x = pletoh16(extData); /* 1. CurrentX */
    current_y = pletoh16(&extData[2]); /* 2. CurrentY */
    current_hue_enh = pletoh16(&extData[4]); /* 3. EnhancedCurrentHue */
    current_sat = extData[6]; /* 4. CurrentSaturation */
    loop_active = extData[7]; /* 5. ColorLoopActive */
    loop_direction = extData[8]; /* 6. ColorLoopDirection */
    loop_time = pletoh16(&extData[9]); /* 7. ColorLoopTime */
    color_temp = pletoh16(&extData[11]); /* 8. ColorTemperatureMireds */

    if ((server->config.capabilities & ZCL_COLOR_CAP_XY) != 0U) {
        if (server->config.callbacks.move_to_color_xy != NULL) {
            struct ZbZclColorClientMoveToColorXYReqT req;

            memset(&req, 0, sizeof(req));
            req.color_x = current_x;
            req.color_y = current_y;
            req.transition_time = transition_tenths;
            server->config.callbacks.move_to_color_xy(clusterPtr, &req, NULL, clusterPtr->app_cb_arg);
        }
        else {
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_CURRENT_X, (uint8_t *)&extData[0], 2, ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_CURRENT_Y, (uint8_t *)&extData[2], 2, ZCL_ATTR_WRITE_FLAG_FORCE);
        }
    }

    if ((server->config.capabilities & ZCL_COLOR_CAP_ENH_HUE) != 0U) {
        if (server->config.callbacks.move_to_hue_sat_enh != NULL) {
            struct ZbZclColorClientMoveToHueSatEnhReqT req;

            memset(&req, 0, sizeof(req));
            req.enh_hue = current_hue_enh;
            req.sat = current_sat;
            req.transition_time = transition_tenths;
            server->config.callbacks.move_to_hue_sat_enh(clusterPtr, &req, NULL, clusterPtr->app_cb_arg);
        }
        else {
            (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_COLOR_ATTR_ENH_CURR_HUE, current_hue_enh);
        }
    }

    if ((server->config.capabilities & ZCL_COLOR_CAP_COLOR_LOOP) != 0U) {
        if (server->config.callbacks.color_loop_set != NULL) {
            struct ZbZclColorClientColorLoopSetReqT req;

            memset(&req, 0, sizeof(req));
            req.update_flags |= ZCL_COLOR_LOOP_FLAG_UPDATE_ACTION;
            req.update_flags |= ZCL_COLOR_LOOP_FLAG_UPDATE_DIRECTION;
            req.update_flags |= ZCL_COLOR_LOOP_FLAG_UPDATE_TIME;
            req.update_flags |= ZCL_COLOR_LOOP_FLAG_UPDATE_START_HUE;
            req.action = loop_active; /* EXEGIN - verify */
            req.direction = loop_direction;
            req.transition_time = loop_time;
            req.start_hue = current_hue_enh; /* EXEGIN - verify */
            server->config.callbacks.color_loop_set(clusterPtr, &req, NULL, clusterPtr->app_cb_arg);
        }
        else {
            (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_COLOR_ATTR_COLOR_LOOP_ACTIVE, loop_active);
            (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_COLOR_ATTR_COLOR_LOOP_DIR, loop_direction);
            (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_COLOR_ATTR_COLOR_LOOP_TIME, loop_time);
        }
    }

    if ((server->config.capabilities & ZCL_COLOR_CAP_COLOR_TEMP) != 0U) {
        if (server->config.callbacks.move_to_color_temp != NULL) {
            struct ZbZclColorClientMoveToColorTempReqT req;

            memset(&req, 0, sizeof(req));
            req.color_temp = color_temp;
            req.transition_time = transition_tenths;
            server->config.callbacks.move_to_color_temp(clusterPtr, &req, NULL, clusterPtr->app_cb_arg);
        }
        else {
            (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_COLOR_ATTR_COLOR_TEMP_MIREDS, color_temp);
        }
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
zcl_color_options_cmd_allow(struct ZbZclClusterT *clusterPtr, uint8_t options_mask, uint8_t options_override)
{
    struct cluster_priv_t *color_server = (struct cluster_priv_t *)clusterPtr;
    uint8_t i, mask, options, onoff_val;

    /* Read the options field */
    if (ZbZclAttrRead(clusterPtr, ZCL_COLOR_ATTR_OPTIONS, NULL,
            &options, sizeof(options), false) != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, failed to read from OPTIONS attribute");
        return false; /* Drop it */
    }

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

    if ((options & ZCL_COLOR_OPTIONS_EXECUTE_IF_OFF) == 0) {
        if (color_server->onoff_server != NULL) {
            /* Read the OnOff state */
            if (ZbZclAttrRead(color_server->onoff_server, ZCL_ONOFF_ATTR_ONOFF,
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
zcl_color_server_handle_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *color_server = (struct cluster_priv_t *)clusterPtr;
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
        case ZCL_COLOR_COMMAND_MOVE_TO_HUE:
        {
            struct ZbZclColorClientMoveToHueReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_HS;

            if (dataIndPtr->asduLength < 4) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.move_to_hue == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 6) {
                req.mask = dataIndPtr->asdu[4];
                req.override = dataIndPtr->asdu[5];
            }

            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.hue = dataIndPtr->asdu[0];
            req.direction = dataIndPtr->asdu[1];
            req.transition_time = pletoh16(&dataIndPtr->asdu[2]);
            return color_server->config.callbacks.move_to_hue(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_MOVE_HUE:
        {
            struct ZbZclColorClientMoveHueReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_HS;

            if (dataIndPtr->asduLength < 2) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.move_hue == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 4) {
                req.mask = dataIndPtr->asdu[2];
                req.override = dataIndPtr->asdu[3];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            req.move_mode = dataIndPtr->asdu[0];
            req.rate = dataIndPtr->asdu[1];

            if (((req.move_mode == ZCL_COLOR_MOVE_MODE_UP) || (req.move_mode == ZCL_COLOR_MOVE_MODE_DOWN)) && (req.rate == 0U)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "illegal move rate");
                return ZCL_STATUS_INVALID_FIELD;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            return color_server->config.callbacks.move_hue(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_STEP_HUE:
        {
            struct ZbZclColorClientStepHueReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_HS;

            if (dataIndPtr->asduLength < 4) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }

            if (color_server->config.callbacks.step_hue == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 6) {
                req.mask = dataIndPtr->asdu[4];
                req.override = dataIndPtr->asdu[5];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.step_mode = dataIndPtr->asdu[0];
            req.step_size = dataIndPtr->asdu[1];
            req.transition_time = pletoh16(&dataIndPtr->asdu[2]);
            return color_server->config.callbacks.step_hue(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_MOVE_TO_SAT:
        {
            struct ZbZclColorClientMoveToSatReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_HS;

            if (dataIndPtr->asduLength < 3) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.move_to_sat == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 5) {
                req.mask = dataIndPtr->asdu[3];
                req.override = dataIndPtr->asdu[4];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.sat = dataIndPtr->asdu[0];
            req.transition_time = pletoh16(&dataIndPtr->asdu[1]);
            return color_server->config.callbacks.move_to_sat(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_MOVE_SAT:
        {
            struct ZbZclColorClientMoveSatReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_HS;

            if (dataIndPtr->asduLength < 2) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.move_sat == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 4) {
                req.mask = dataIndPtr->asdu[2];
                req.override = dataIndPtr->asdu[3];
            }

            req.move_mode = dataIndPtr->asdu[0];
            req.rate = dataIndPtr->asdu[1];

            if (((req.move_mode == ZCL_COLOR_MOVE_MODE_UP) || (req.move_mode == ZCL_COLOR_MOVE_MODE_DOWN)) && (req.rate == 0U)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "illegal move rate");
                return ZCL_STATUS_INVALID_FIELD;
            }

            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            return color_server->config.callbacks.move_sat(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_STEP_SAT:
        {
            struct ZbZclColorClientStepSatReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_HS;

            if (dataIndPtr->asduLength < 4) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.step_sat == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 6) {
                req.mask = dataIndPtr->asdu[4];
                req.override = dataIndPtr->asdu[5];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.step_mode = dataIndPtr->asdu[0];
            req.step_size = dataIndPtr->asdu[1];
            req.transition_time = pletoh16(&dataIndPtr->asdu[2]);
            return color_server->config.callbacks.step_sat(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_MOVE_TO_HS:
        {
            struct ZbZclColorClientMoveToHueSatReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_HS;

            if (dataIndPtr->asduLength < 4) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.move_to_hue_sat == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 6) {
                req.mask = dataIndPtr->asdu[4];
                req.override = dataIndPtr->asdu[5];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.hue = dataIndPtr->asdu[0];
            req.sat = dataIndPtr->asdu[1];
            req.transition_time = pletoh16(&dataIndPtr->asdu[2]);
            return color_server->config.callbacks.move_to_hue_sat(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_MOVE_TO_COLOR:
        {
            struct ZbZclColorClientMoveToColorXYReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_XY;

            if (dataIndPtr->asduLength < 6) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.move_to_color_xy == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 8) {
                req.mask = dataIndPtr->asdu[6];
                req.override = dataIndPtr->asdu[7];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.color_x = pletoh16(&dataIndPtr->asdu[0]);
            req.color_y = pletoh16(&dataIndPtr->asdu[2]);
            req.transition_time = pletoh16(&dataIndPtr->asdu[4]);
            return color_server->config.callbacks.move_to_color_xy(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_MOVE_COLOR:
        {
            struct ZbZclColorClientMoveColorXYReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_XY;

            if (dataIndPtr->asduLength < 4) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.move_color_xy == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 6) {
                req.mask = dataIndPtr->asdu[4];
                req.override = dataIndPtr->asdu[5];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            req.rate_x = pletoh16(&dataIndPtr->asdu[0]);
            req.rate_y = pletoh16(&dataIndPtr->asdu[2]);

            if ((req.rate_x == 0U) && (req.rate_y == 0U)) {
                /* EXEGIN - Need to stop all previously received cluster commands */
                return ZCL_STATUS_SUCCESS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            return color_server->config.callbacks.move_color_xy(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_STEP_COLOR:
        {
            struct ZbZclColorClientStepColorXYReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_XY;

            if (dataIndPtr->asduLength < 6) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.step_color_xy == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 8) {
                req.mask = dataIndPtr->asdu[6];
                req.override = dataIndPtr->asdu[7];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.step_x = pletoh16(&dataIndPtr->asdu[0]);
            req.step_y = pletoh16(&dataIndPtr->asdu[2]);
            req.transition_time = pletoh16(&dataIndPtr->asdu[4]);
            return color_server->config.callbacks.step_color_xy(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_MOVE_TO_COLOR_TEMP:
        {
            struct ZbZclColorClientMoveToColorTempReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_TEMP;

            if (color_server->config.callbacks.move_to_color_temp == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 6) {
                req.mask = dataIndPtr->asdu[4];
                req.override = dataIndPtr->asdu[5];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.color_temp = pletoh16(&dataIndPtr->asdu[0]);
            /* As per section 5.2.2.3.1 of ZCL8, not mentioned in command details but in generic usage notes instead */
            if (req.color_temp > ZCL_COLOR_TEMP_MAX) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Clipping requested temperature to 0xFEFF");
                req.color_temp = ZCL_COLOR_TEMP_MAX;
            }

            req.transition_time = pletoh16(&dataIndPtr->asdu[2]);
            return color_server->config.callbacks.move_to_color_temp(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_ENH_MOVE_TO_HUE:
        {
            struct ZbZclColorClientMoveToHueEnhReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_HS;
            uint8_t enh_color_mode = ZCL_COLOR_ENH_MODE_ENH_HUE_SAT;

            if (dataIndPtr->asduLength < 5) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.move_to_hue_enh == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 7) {
                req.mask = dataIndPtr->asdu[5];
                req.override = dataIndPtr->asdu[6];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&enh_color_mode, sizeof(enh_color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.enh_hue = pletoh16(&dataIndPtr->asdu[0]);
            req.direction = dataIndPtr->asdu[2];
            req.transition_time = pletoh16(&dataIndPtr->asdu[3]);
            return color_server->config.callbacks.move_to_hue_enh(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_ENH_MOVE_HUE:
        {
            struct ZbZclColorClientMoveHueEnhReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_HS;
            uint8_t enh_color_mode = ZCL_COLOR_ENH_MODE_ENH_HUE_SAT;

            if (dataIndPtr->asduLength < 3) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }

            if (color_server->config.callbacks.move_hue_enh == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 5) {
                req.mask = dataIndPtr->asdu[3];
                req.override = dataIndPtr->asdu[4];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            req.move_mode = dataIndPtr->asdu[0];
            req.rate = pletoh16(&dataIndPtr->asdu[1]);

            if (((req.move_mode == ZCL_COLOR_MOVE_MODE_UP) || (req.move_mode == ZCL_COLOR_MOVE_MODE_DOWN)) && (req.rate == 0U)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "illegal move rate");
                return ZCL_STATUS_INVALID_FIELD;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&enh_color_mode, sizeof(enh_color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            return color_server->config.callbacks.move_hue_enh(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_ENH_STEP_HUE:
        {
            struct ZbZclColorClientStepHueEnhReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_HS;
            uint8_t enh_color_mode = ZCL_COLOR_ENH_MODE_ENH_HUE_SAT;

            if (dataIndPtr->asduLength < 5) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.step_hue_enh == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 7) {
                req.mask = dataIndPtr->asdu[5];
                req.override = dataIndPtr->asdu[6];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&enh_color_mode, sizeof(enh_color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.step_mode = dataIndPtr->asdu[0];
            req.step_size = pletoh16(&dataIndPtr->asdu[1]);
            req.transition_time = pletoh16(&dataIndPtr->asdu[3]);
            return color_server->config.callbacks.step_hue_enh(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_ENH_MOVE_TO_HS:
        {
            struct ZbZclColorClientMoveToHueSatEnhReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_HS;
            uint8_t enh_color_mode = ZCL_COLOR_ENH_MODE_ENH_HUE_SAT;

            if (dataIndPtr->asduLength < 5) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.move_to_hue_sat_enh == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 7) {
                req.mask = dataIndPtr->asdu[5];
                req.override = dataIndPtr->asdu[6];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&enh_color_mode, sizeof(enh_color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.enh_hue = pletoh16(&dataIndPtr->asdu[0]);
            req.sat = dataIndPtr->asdu[2];
            req.transition_time = pletoh16(&dataIndPtr->asdu[3]);
            return color_server->config.callbacks.move_to_hue_sat_enh(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_COLOR_LOOP_SET:
        {
            struct ZbZclColorClientColorLoopSetReqT req;

            if (dataIndPtr->asduLength < 7) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.color_loop_set == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 9) {
                req.mask = dataIndPtr->asdu[7];
                req.override = dataIndPtr->asdu[8];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            req.update_flags = dataIndPtr->asdu[0];
            req.action = dataIndPtr->asdu[1];
            req.direction = dataIndPtr->asdu[2];
            req.transition_time = pletoh16(&dataIndPtr->asdu[3]);
            req.start_hue = pletoh16(&dataIndPtr->asdu[5]);
            return color_server->config.callbacks.color_loop_set(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_STOP_MOVE_STEP:
        {
            struct ZbZclColorClientStopMoveStepReqT req;

            if (color_server->config.callbacks.stop_move_step == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 2) {
                req.mask = dataIndPtr->asdu[0];
                req.override = dataIndPtr->asdu[1];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }
            return color_server->config.callbacks.stop_move_step(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        case ZCL_COLOR_COMMAND_MOVE_COLOR_TEMP:
        {
            struct ZbZclColorClientMoveColorTempReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_TEMP;

            if (dataIndPtr->asduLength < 7) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.move_color_temp == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 9) {
                req.mask = dataIndPtr->asdu[7];
                req.override = dataIndPtr->asdu[8];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            req.move_mode = dataIndPtr->asdu[0];
            req.rate = pletoh16(&dataIndPtr->asdu[1]);

            if (((req.move_mode == ZCL_COLOR_MOVE_MODE_UP) || (req.move_mode == ZCL_COLOR_MOVE_MODE_DOWN)) && (req.rate == 0U)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "illegal move rate");
                return ZCL_STATUS_INVALID_FIELD;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.color_temp_min = pletoh16(&dataIndPtr->asdu[3]);
            req.color_temp_max = pletoh16(&dataIndPtr->asdu[5]);
            return color_server->config.callbacks.move_color_temp(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }
        /*
         * Step Color Temperature
         */
        case ZCL_COLOR_COMMAND_STEP_COLOR_TEMP:
        {
            struct ZbZclColorClientStepColorTempReqT req;
            uint8_t color_mode = ZCL_COLOR_MODE_TEMP;

            if (dataIndPtr->asduLength < 9) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            if (color_server->config.callbacks.step_color_temp == NULL) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }

            memset(&req, 0, sizeof(req));

            /* Options */
            if (asdu_length >= 11) {
                req.mask = dataIndPtr->asdu[9];
                req.override = dataIndPtr->asdu[10];
            }
            /* Check if command should be dropped */
            if (!zcl_color_options_cmd_allow(clusterPtr, req.mask, req.override)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "dropping command due to options processing");
                return ZCL_COLOR_OPTIONS_DENY_STATUS;
            }

            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);
            ZbZclAttrWrite(clusterPtr, NULL, ZCL_COLOR_ATTR_ENH_COLOR_MODE, (uint8_t *)&color_mode, sizeof(color_mode), ZCL_ATTR_WRITE_FLAG_FORCE);

            req.step_mode = dataIndPtr->asdu[0];
            req.step_size = pletoh16(&dataIndPtr->asdu[1]);
            req.transition_time = pletoh16(&dataIndPtr->asdu[3]);
            req.color_temp_min = pletoh16(&dataIndPtr->asdu[5]);
            req.color_temp_max = pletoh16(&dataIndPtr->asdu[7]);
            return color_server->config.callbacks.step_color_temp(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
        }

        default:
            return ZCL_STATUS_UNSUPP_COMMAND;
    }

}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src, uint16_t attribute_id,
    const uint8_t *input_data, unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg)
{
    unsigned int len = 0;
    enum ZclStatusCodeT status;
    uint16_t input, min_value, max_value;

    switch (attribute_id) {
        case ZCL_COLOR_ATTR_COUPLE_COLOR_TL_MIN:
            input = (uint16_t)pletoh16(input_data);
            min_value = (uint16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_COLOR_ATTR_COLOR_TEMP_MIN, NULL, NULL);
            max_value = (uint16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_COLOR_ATTR_COLOR_TEMP_MIREDS, NULL, NULL);
            if ((input < min_value) || (input > max_value)) {
                status = ZCL_STATUS_INVALID_VALUE;
                break;
            }
            len = 2;
            status = ZCL_STATUS_SUCCESS;
            break;

        default:
            status = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            break;
    }

    if (((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) && (status == ZCL_STATUS_SUCCESS)) {
        (void)memcpy(attr_data, input_data, len);
    }
    return status;
}
