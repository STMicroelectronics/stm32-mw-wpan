/* Copyright [2017 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.window.h"

/* Alarm cluster */
struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct ZbZclWindowServerCallbacksT callbacks;
};

static enum ZclStatusCodeT zcl_window_closure_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);
static uint8_t window_server_get_scene_data(struct ZbZclClusterT *clusterPtr, uint8_t *extBuf, uint8_t extMaxLen);
static enum ZclStatusCodeT window_server_set_scene_data(struct ZbZclClusterT *clusterPtr, uint8_t *extData, uint8_t extLen, uint16_t transition_tenths);

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

/* Attributes */
static const struct ZbZclAttrT windowAttrList[5] = {
    /* Information Attribute Set */
    {
        ZCL_WNCV_SVR_ATTR_COVERING_TYPE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0x9}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_CONFIG_STATUS, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    /* Lift and Tilt Percent aren't mandatory if we use open loop control
     * but in ZCL 7, sec. 7.4.2.4, these are to be added into scene tables
     * "If the Window Covering server cluster is implemented" */
    {
        ZCL_WNCV_SVR_ATTR_CURR_POS_LIFT_PERCENT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0x64}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_CURR_POS_TILT_PERCENT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0x64}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_MODE, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
#if 0
    {
        ZCL_WNCV_SVR_ATTR_PHY_CLOSE_LIMIT_LIFT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_PHY_CLOSE_LIMIT_TILT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_CURR_POSITION_LIFT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_CURR_POSITION_TILT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_ACTUATION_NUMBER_LIFT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_ACCUATION_NUMBER_TILT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    /* Settings Attribute Set */
    {
        ZCL_WNCV_SVR_ATTR_INSTALLED_OPENED_LIMIT_LIFT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_INSTALLED_CLOSED_LIMIT_LIFT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_INSTALLED_OPENED_LIMIT_TILT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_INSTALLED_CLOSED_LIMIT_TILT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_VELOCITY_LIFT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_ACCELERATION_TIME_LIFT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_DECELERATION_TIME_LIFT, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xffff}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_INTERMEDIATE_SETPOINTS_LIFT, ZCL_DATATYPE_STRING_OCTET,
        ZCL_ATTR_FLAG_WRITABLE, 32, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_WNCV_SVR_ATTR_INTERMEDIATE_SETPOINTS_TILT, ZCL_DATATYPE_STRING_OCTET,
        ZCL_ATTR_FLAG_WRITABLE, 32, NULL, {0, 0}, {0, 0}
    },
#endif
};

struct ZbZclClusterT *
ZbZclWindowServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclWindowServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_WINDOW_COVERING, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "CCB 2328"
     * (need to investigate these changes) */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    clusterPtr->cluster.command = zcl_window_closure_command;
    clusterPtr->cluster.get_scene_data = window_server_get_scene_data;
    clusterPtr->cluster.set_scene_data = window_server_set_scene_data;

    /* set cluster callbacks */
    if (callbacks != NULL) {
        (void)memcpy(&clusterPtr->callbacks, callbacks, sizeof(struct ZbZclWindowServerCallbacksT));
    }
    else {
        (void)memset(&clusterPtr->callbacks, 0, sizeof(struct ZbZclWindowServerCallbacksT));
    }

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, windowAttrList, ZCL_ATTR_LIST_LEN(windowAttrList))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Set some initial default attribute values */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_WNCV_SVR_ATTR_COVERING_TYPE, ZCL_WNCV_TYPE_ROLLERSHADE);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_WNCV_SVR_ATTR_CONFIG_STATUS, (ZCL_WNCV_STATUS_OPERATIONAL | ZCL_WNCV_STATUS_ONLINE));
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_WNCV_SVR_ATTR_MODE, 0);

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src, uint16_t attribute_id,
    const uint8_t *input_data, unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg)
{
    enum ZclStatusCodeT status = ZCL_STATUS_SUCCESS;
    unsigned int len = 0;

    switch (attribute_id) {
        case ZCL_WNCV_SVR_ATTR_CONFIG_STATUS:
        {
            uint8_t mask;

            mask = input_data[0];
            if ((mask & ~(ZCL_WNCV_STATUS_MASK)) != 0U) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;
        }

        case ZCL_WNCV_SVR_ATTR_MODE:
        {
            uint8_t mask;

            mask = input_data[0];
            if ((mask & ~(ZCL_WNCV_MODE_MASK)) != 0U) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;
        }

        default:
            /* Can't get here */
            status = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            break;
    }

    if (((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) && (status == ZCL_STATUS_SUCCESS)) {
        (void)memcpy(attr_data, input_data, len);
    }
    return status;
}

static uint8_t
window_server_get_scene_data(struct ZbZclClusterT *clusterPtr, uint8_t *extBuf, uint8_t extMaxLen)
{
    uint8_t len = 3; /* Attribute data starts at the third byte. */
    uint8_t attrVal;

    /* Write attributes first, before Cluster ID and Length */

    /* Lift attribute */
    if (ZbZclAttrRead(clusterPtr, ZCL_WNCV_SVR_ATTR_CURR_POS_LIFT_PERCENT, NULL, &attrVal, sizeof(attrVal), false) != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Failed to read Current Position Lift Percentage attribute");
        return 0;
    }
    extBuf[len++] = attrVal;

    /* Tilt Percentage */
    if (ZbZclAttrRead(clusterPtr, ZCL_WNCV_SVR_ATTR_CURR_POS_TILT_PERCENT, NULL, &attrVal, sizeof(attrVal), false) != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Failed to read Current Position Tilt Percentage attribute");
        return 0;
    }
    extBuf[len++] = attrVal;

    /* Cluster ID [0:1] */
    putle16(&extBuf[0], clusterPtr->clusterId);
    /* Extension Length [2] */
    extBuf[2] = len - 3;
    return len;
}

static enum ZclStatusCodeT
window_server_set_scene_data(struct ZbZclClusterT *clusterPtr, uint8_t *extData, uint8_t extLen, uint16_t transition_tenths)
{
    struct cluster_priv_t *window_server = (void *)clusterPtr;
    uint8_t tiltPercentage, liftPercentage;

    if (extLen != 2) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, invalid scene data length (%d)", extLen);
        return ZCL_STATUS_INVALID_VALUE;
    }

    /* Unpack Scene external data */
    tiltPercentage = extData[0];
    liftPercentage = extData[1];

    /* Invoke a callback function in application layer to write to attributes */
    (void)window_server->callbacks.set_lift_and_tilt_command(clusterPtr, clusterPtr->app_cb_arg,
        liftPercentage, tiltPercentage);
    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
zcl_window_closure_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *window_server = (void *)clusterPtr;
    uint8_t cmdId = zclHdrPtr->cmdId;
    enum ZclStatusCodeT rc;

    /* this req must be headed to server. */
    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (zclHdrPtr->frameCtrl.manufacturer) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    switch (cmdId) {
        case ZCL_WNCV_COMMAND_UP:
            rc = window_server->callbacks.up_command(clusterPtr, zclHdrPtr, dataIndPtr, clusterPtr->app_cb_arg);
            break;

        case ZCL_WNCV_COMMAND_DOWN:
            rc = window_server->callbacks.down_command(clusterPtr, zclHdrPtr, dataIndPtr, clusterPtr->app_cb_arg);
            break;

        case ZCL_WNCV_COMMAND_STOP:
            rc = window_server->callbacks.stop_command(clusterPtr, zclHdrPtr, dataIndPtr, clusterPtr->app_cb_arg);
            break;

        default:
            rc = ZCL_STATUS_UNSUPP_COMMAND;

    }
    return rc;
}

enum ZclStatusCodeT
ZbZclWindowClosureServerMode(struct ZbZclClusterT *clusterPtr, uint8_t mode)
{
    uint8_t config_status;

    config_status = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_WNCV_SVR_ATTR_CONFIG_STATUS, NULL, NULL);

    if ((mode & ZCL_WNCV_MODE_REVERSED) != 0U) {
        config_status |= ZCL_WNCV_STATUS_UP_REVERSED;
    }
    else {
        config_status &= ~(ZCL_WNCV_STATUS_UP_REVERSED);
    }

    if ((mode & ZCL_WNCV_MODE_MAINTENANCE) != 0U) {
        config_status &= ~(ZCL_WNCV_STATUS_ONLINE);
    }
    else {
        config_status |= ZCL_WNCV_STATUS_ONLINE;
    }

#if 0 /* these don't update CONFIG_STATUS */
    if ((mode & ZCL_WNCV_MODE_CALIBRATION) != 0U) {
        /* toggle HW normal/calibration mode */
    }
    if (mode & ZCL_WNCV_MODE_LED_FEEDBACK) {
        /* toggle HW LED on/off */
    }
#endif

    (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_WNCV_SVR_ATTR_MODE, mode);
    (void)ZbZclAttrIntegerWrite(clusterPtr, ZCL_WNCV_SVR_ATTR_CONFIG_STATUS, config_status);
    return ZCL_STATUS_SUCCESS;
}
