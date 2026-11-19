/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.ballast.config.h"

#if 0 /* Optional */
static void ballastconfig_server_send_alarm(struct ZbZclClusterT *clusterPtr);
#endif

static enum ZclStatusCodeT zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src,
    uint16_t attributeId, const uint8_t *inputData, unsigned int inputMaxLen, void *attrData,
    ZclWriteModeT mode, void *app_cb_arg);

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

/* Ballast Configuration Cluster Server Attributes */
static const struct ZbZclAttrT zcl_ballastconfig_server_attr_list[] =
{
    /* Ballast Information Attribute Set */
    {
        ZCL_BALLAST_CONFIG_ATTR_PHY_MIN_LEVEL, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_BALLAST_CONFIG_ATTR_PHY_MAX_LEVEL, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    /* Ballast Settings Attribute Set */
    {
        ZCL_BALLAST_CONFIG_ATTR_MIN_LEVEL, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_BALLAST_CONFIG_ATTR_MAX_LEVEL, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_BALLAST_CONFIG_ATTR_BALLAST_STATUS, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
#if 0 /* example */
    {
        ZCL_BALLAST_CONFIG_ATTR_INTRINSIC_BALLAST_FACTOR, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_BALLAST_CONFIG_ATTR_BALLAST_FACTOR_ADJUSTMENT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    /* Lamp Information Attribute Set */
    {
        ZCL_BALLAST_CONFIG_ATTR_LAMP_QUANTITY, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    /* Lamp Settings Attribute Set */
    {
        ZCL_BALLAST_CONFIG_ATTR_LAMP_TYPE, ZCL_DATATYPE_STRING_CHARACTER,
        ZCL_ATTR_FLAG_WRITABLE, ZCL_BALLAST_CONFIG_LAMP_TYPE_NAME_LENGTH,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_BALLAST_CONFIG_ATTR_LAMP_MANUFACTURER, ZCL_DATATYPE_STRING_CHARACTER,
        ZCL_ATTR_FLAG_WRITABLE, ZCL_BALLAST_CONFIG_LAMP_MANUFACTURER_NAME_LENGTH,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_BALLAST_CONFIG_ATTR_LAMP_RATED_HOURS, ZCL_DATATYPE_UNSIGNED_24BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_BALLAST_CONFIG_ATTR_LAMP_BURN_HOURS, ZCL_DATATYPE_UNSIGNED_24BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_BALLAST_CONFIG_ATTR_LAMP_ALARM_MODE, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_BALLAST_CONFIG_ATTR_LAMP_BURN_HOURS_TRIP_POINT, ZCL_DATATYPE_UNSIGNED_24BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
#endif

};

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
};

struct ZbZclClusterT *
ZbZclBallastConfigServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, uint8_t phyMin, uint8_t phyMax)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_BALLAST_CONTROL, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "CCB 2104 2193 2230 2393 Deprecated some attributes"
     * (need to investigate changes) */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

#if 0 /* Optional attribute, not implemented */
    clusterPtr->defaultBallastFactorAdjMax = ballastFactorAdjMax;
#endif

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_ballastconfig_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_ballastconfig_server_attr_list))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Write default values to attributes */
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_PHY_MIN_LEVEL, phyMin);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_PHY_MAX_LEVEL, phyMax);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_MIN_LEVEL, phyMin);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_MAX_LEVEL, phyMax);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_BALLAST_STATUS, ZCL_BALLAST_CONFIG_BALLAST_STATUS_DEFAULT);
#if 0
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_INTRINSIC_BALLAST_FACTOR, ZCL_BALLAST_CONFIG_INTRINSIC_BALLAST_FACTOR_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_BALLAST_FACTOR_ADJUSTMENT, ZCL_BALLAST_CONFIG_BALLAST_FACTOR_ADJ_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_LAMP_QUANTITY, ZCL_BALLAST_CONFIG_LAMP_QUANTITY_DEFAULT);
    ZbZclAttrStringWriteShort(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_LAMP_TYPE, );
    ZbZclAttrStringWriteShort(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_LAMP_MANUFACTURER, );
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_LAMP_RATED_HOURS, ZCL_BALLAST_CONFIG_LAMP_RATED_HOURS_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_LAMP_BURN_HOURS, ZCL_BALLAST_CONFIG_LAMP_BURN_HOURS_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_LAMP_ALARM_MODE, ZCL_BALLAST_CONFIG_LAMP_ALARM_MODE_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_BALLAST_CONFIG_ATTR_LAMP_BURN_HOURS_TRIP_POINT, ZCL_BALLAST_CONFIG_LAMP_BURN_HOURS_TRIP_POINT_DEFAULT);
#endif

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attributeId,
    const uint8_t *inputData, unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg)
{
    unsigned int len;
    uint8_t uint8, minValue, maxValue;

    switch (attributeId) {
        case ZCL_BALLAST_CONFIG_ATTR_PHY_MIN_LEVEL:
            uint8 = *inputData;
            minValue = ZCL_BALLAST_CONFIG_PHY_MIN_LEVEL_MIN;
            maxValue = ZCL_BALLAST_CONFIG_PHY_MIN_LEVEL_MAX;
            if ((uint8 < minValue) || (uint8 > maxValue)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;

        case ZCL_BALLAST_CONFIG_ATTR_PHY_MAX_LEVEL:
            uint8 = *inputData;
            minValue = ZCL_BALLAST_CONFIG_PHY_MAX_LEVEL_MIN;
            maxValue = ZCL_BALLAST_CONFIG_PHY_MAX_LEVEL_MAX;
            if ((uint8 < minValue) || (uint8 > maxValue)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;

        case ZCL_BALLAST_CONFIG_ATTR_MIN_LEVEL:
            uint8 = *inputData;
            minValue = (uint8_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_BALLAST_CONFIG_ATTR_PHY_MIN_LEVEL, NULL, NULL);
            maxValue = (uint8_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_BALLAST_CONFIG_ATTR_MAX_LEVEL, NULL, NULL);
            if (maxValue == ZCL_INVALID_UNSIGNED_8BIT) {
                maxValue = (uint8_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_BALLAST_CONFIG_ATTR_PHY_MAX_LEVEL, NULL, NULL);
            }
            if ((uint8 < minValue) || (uint8 > maxValue)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;

        case ZCL_BALLAST_CONFIG_ATTR_MAX_LEVEL:
            uint8 = *inputData;
            minValue = (uint8_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_BALLAST_CONFIG_ATTR_MIN_LEVEL, NULL, NULL);
            if (minValue == ZCL_INVALID_UNSIGNED_8BIT) {
                minValue = (uint8_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_BALLAST_CONFIG_ATTR_PHY_MIN_LEVEL, NULL, NULL);
            }
            maxValue = (uint8_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_BALLAST_CONFIG_ATTR_PHY_MAX_LEVEL, NULL, NULL);
            if ((uint8 < minValue) || (uint8 > maxValue)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;

        case ZCL_BALLAST_CONFIG_ATTR_BALLAST_STATUS:
            uint8 = *inputData;
            maxValue = ZCL_BALLAST_CONFIG_BALLAST_STATUS_MAX;
            if (uint8 > maxValue) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;

#if 0
        case ZCL_BALLAST_CONFIG_ATTR_INTRINSIC_BALLAST_FACTOR:
            uint8 = *inputData;
            /* No need to do range checking here. Because valid
             * functional range is 0x00-0xfe. But, 0xff is a
             * special value. */
            len = 1;
            break;

        case ZCL_BALLAST_CONFIG_ATTR_BALLAST_FACTOR_ADJUSTMENT:
            uint8 = *inputData;
            minValue = ZCL_BALLAST_CONFIG_BALLAST_FACTOR_ADJ_MIN;
            maxValue = serverPtr->defaultBallastFactorAdjMax;
            if (((uint8 < minValue) || (uint8 > maxValue))
                && (uint8 != ZCL_BALLAST_CONFIG_BALLAST_FACTOR_ADJ_DEFAULT)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;

        case ZCL_BALLAST_CONFIG_ATTR_LAMP_QUANTITY:
            uint8 = *inputData;
            minValue = ZCL_BALLAST_CONFIG_LAMP_QUANTITY_MIN;
            maxValue = ZCL_BALLAST_CONFIG_LAMP_QUANTITY_MAX;
            if ((uint8 < minValue) || (uint8 > maxValue)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;

        case ZCL_BALLAST_CONFIG_ATTR_LAMP_RATED_HOURS:
            /* No need to do range checking here. Because valid
             * functional range is 0x000000-0xfffffe. But,
             * 0xffffff is a special value. */
            len = 3;
            break;

        case ZCL_BALLAST_CONFIG_ATTR_LAMP_BURN_HOURS:
            /* No need to do range checking here. Because valid
             * functional range is 0x000000-0xfffffe. But,
             * 0xffffff is a special value. */
            len = 3;
            break;

        case ZCL_BALLAST_CONFIG_ATTR_LAMP_ALARM_MODE:
            uint8 = *inputData;
            if (uint8 > ((uint8_t)ZCL_BALLAST_CONFIG_LAMP_ALARM_MODE_BIT_MASK)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;

        case ZCL_BALLAST_CONFIG_ATTR_LAMP_BURN_HOURS_TRIP_POINT:
            /* No need to do range checking here. Because valid
             * functional range is 0x000000-0xfffffe. But,
             * 0xffffff is a special value. */
            len = 3;
            break;
#endif

        default:
            /* Unsupported Attribute */
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }

    if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) {
        (void)memcpy(attrData, inputData, len);
    }

#if 0 /* Optional attribute, not implemented */
    if ((ZCL_BALLAST_CONFIG_ATTR_LAMP_BURN_HOURS == attributeId)
        || (ZCL_BALLAST_CONFIG_ATTR_LAMP_ALARM_MODE == attributeId)
        || (ZCL_BALLAST_CONFIG_ATTR_LAMP_BURN_HOURS_TRIP_POINT == attributeId)) {
        /* if any one of these attributes have been updated. Check if we have
         * to send and alarm.
         */
        ballastconfig_server_send_alarm(clusterPtr);
    }
#endif

    return ZCL_STATUS_SUCCESS;
}

#if 0 /* Optional */
static void
ballastconfig_server_send_alarm(struct ZbZclClusterT *clusterPtr)
{
    /* read alarm mode attribute if ballast configuration cluster
     * to check if Alarm mode is true */
    uint8_t alarmMode;
    uint32_t lampBurnHours;
    uint32_t lampBurnHoursTripPoint;
    alarmMode = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_BALLAST_CONFIG_ATTR_LAMP_ALARM_MODE, NULL, NULL);

    if (alarmMode & ZCL_BALLAST_CONFIG_LAMP_ALARM_MODE_BIT_MASK) {
        /* alarm for LampBurnHours attribute is TRUE, read trip point & burn hours */
        lampBurnHours = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_BALLAST_CONFIG_ATTR_LAMP_BURN_HOURS, NULL, NULL);
        lampBurnHoursTripPoint = ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_BALLAST_CONFIG_ATTR_LAMP_BURN_HOURS_TRIP_POINT, NULL, NULL);
        if ((ZCL_BALLAST_CONFIG_LAMP_BURN_HOURS_TRIP_POINT_DEFAULT != lampBurnHoursTripPoint)
            && (ZCL_BALLAST_CONFIG_LAMP_BURN_HOURS_UNKNOWN != lampBurnHours)) {
            if (lampBurnHours >= lampBurnHoursTripPoint) {
                /* Send alarm command. */
                ZbZclClusterSendAlarm(clusterPtr, ZbZclClusterGetEndpoint(clusterPtr), ZCL_BALLAST_CONFIG_LAMP_BURN_HOUR_ALARM_CODE);
            }
        }
    }
}

#endif
