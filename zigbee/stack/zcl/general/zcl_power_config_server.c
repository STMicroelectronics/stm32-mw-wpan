/* Copyright [2017 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl/general/zcl.power.config.h"

/* Alarm cluster */
struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

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
static const struct ZbZclAttrT zcl_power_server_attr_list[] = {
    {
        ZCL_POWER_CONFIG_ATTR_MAINS_VOLTAGE, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xFFFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_MAINS_FREQ, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_MAINS_ALARM_MASK, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_MAINS_VOLT_MIN, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0xFFFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_MAINS_VOLT_MAX, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0xFFFF}, {0, 0}
    },
#if 0
    {
        ZCL_POWER_CONFIG_ATTR_MAINS_VOLT_DWELL, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFFFF}, {0, 0}
    },
#endif

    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_VOLTAGE, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_PCT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_MFR_NAME, ZCL_DATATYPE_STRING_CHARACTER,
        ZCL_ATTR_FLAG_WRITABLE, ZCL_DATATYPE_STRING_CHARACTER, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_SIZE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_AHRRATING, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFFFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_QUANTITY, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_RATED_VOLT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_ALARM_MASK, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_VOLT_MIN, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_PCT_MIN, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_ALARM_STATE, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_REPORTABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },

    /* Battery 2 */
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_SIZE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    /* Battery 3 */
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_SIZE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },

#if 0
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_VTHRESHOLD1, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_VTHRESHOLD2, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_VTHRESHOLD3, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_PTHRESHOLD1, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_PTHRESHOLD2, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY_PTHRESHOLD3, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_VOLTAGE, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_PCT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_MFR_NAME, ZCL_DATATYPE_STRING_CHARACTER,
        ZCL_ATTR_FLAG_WRITABLE, ZCL_DATATYPE_STRING_CHARACTER, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_AHRRATING, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFFFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_QUANTITY, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_RATED_VOLT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_ALARM_MASK, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0x1}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_VOLT_MIN, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_VTHRESHOLD1, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_VTHRESHOLD2, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_VTHRESHOLD3, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_PCT_MIN, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_PTHRESHOLD1, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_PTHRESHOLD2, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_PTHRESHOLD3, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY2_ALARM_STATE, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_VOLTAGE, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_PCT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_MFR_NAME, ZCL_DATATYPE_STRING_CHARACTER,
        ZCL_ATTR_FLAG_WRITABLE, ZCL_DATATYPE_STRING_CHARACTER, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_AHRRATING, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFFFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_QUANTITY, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_RATED_VOLT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_ALARM_MASK, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0x1}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_VOLT_MIN, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_VTHRESHOLD1, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_VTHRESHOLD2, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_VTHRESHOLD3, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_PCT_MIN, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_PTHRESHOLD1, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_PTHRESHOLD2, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_PTHRESHOLD3, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_POWER_CONFIG_ATTR_BATTERY3_ALARM_STATE, ZCL_DATATYPE_BITMAP_32BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0}, {0, 0}
    },
#endif
};

struct ZbZclClusterT *
ZbZclPowerConfigServerAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t),
            ZCL_CLUSTER_POWER_CONFIG, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_power_server_attr_list,
            ZCL_ATTR_LIST_LEN(zcl_power_server_attr_list))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Set some initial attribute values */
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_POWER_CONFIG_ATTR_MAINS_VOLT_MIN,
        ZCL_POWER_CONFIG_MAINS_VOLT_MIN_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_POWER_CONFIG_ATTR_MAINS_VOLT_MAX,
        ZCL_POWER_CONFIG_MAINS_VOLT_MAX_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_POWER_CONFIG_ATTR_BATTERY_SIZE,
        ZCL_POWER_CONFIG_BATTERY_SIZE_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_POWER_CONFIG_ATTR_BATTERY2_SIZE,
        ZCL_POWER_CONFIG_BATTERY2_SIZE_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_POWER_CONFIG_ATTR_BATTERY3_SIZE,
        ZCL_POWER_CONFIG_BATTERY3_SIZE_DEFAULT);

    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_POWER_CONFIG_ATTR_MAINS_ALARM_MASK,
        ZCL_POWER_CONFIG_MAINS_ALARM_MASK_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_POWER_CONFIG_ATTR_BATTERY_PCT,
        ZCL_POWER_CONFIG_BATTERY_PCT_DEFAULT);
    ZbZclAttrStringWriteShort(&clusterPtr->cluster, ZCL_POWER_CONFIG_ATTR_BATTERY_MFR_NAME,
        zcl_attr_str_short_zero);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_POWER_CONFIG_ATTR_BATTERY_ALARM_MASK,
        ZCL_POWER_CONFIG_BATTERY_ALARM_MASK_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_POWER_CONFIG_ATTR_BATTERY_VOLT_MIN,
        ZCL_POWER_CONFIG_BATTERY_VOLT_MIN_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_POWER_CONFIG_ATTR_BATTERY_PCT_MIN,
        ZCL_POWER_CONFIG_BATTERY_PCT_MIN_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_POWER_CONFIG_ATTR_BATTERY_ALARM_STATE,
        ZCL_POWER_CONFIG_BATTERY_ALARM_STATE_DEFAULT);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src, uint16_t attribute_id,
    const uint8_t *input_data, unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg)
{
    /* struct cluster_priv_t *server = (struct cluster_priv_t *)cluster; */
    enum ZclStatusCodeT status = ZCL_STATUS_SUCCESS;
    unsigned int len = 0;
    enum ZclStatusCodeT zcl_status;

    switch (attribute_id) {
        case ZCL_POWER_CONFIG_ATTR_MAINS_ALARM_MASK:
        {
            uint8_t val;

            val = input_data[0];
            if ((val & ~(ZCL_POWER_CONFIG_MAINS_ALARM_MASK_MAINS_MASK)) != 0U) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;
        }

        case ZCL_POWER_CONFIG_ATTR_MAINS_VOLT_MIN:
        {
            uint16_t val, max_value;

            val = pletoh16(input_data);
            max_value = (uint16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_POWER_CONFIG_ATTR_MAINS_VOLT_MAX, NULL, &zcl_status);
            if (zcl_status != ZCL_STATUS_SUCCESS) {
                return zcl_status;
            }
            if ((max_value != ZCL_INVALID_UNSIGNED_16BIT) && (val > max_value)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 2;
            break;
        }

        case ZCL_POWER_CONFIG_ATTR_MAINS_VOLT_MAX:
        {
            uint16_t val, min_value;

            val = pletoh16(input_data);
            min_value = (uint16_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_POWER_CONFIG_ATTR_MAINS_VOLT_MIN, NULL, &zcl_status);
            if (zcl_status != ZCL_STATUS_SUCCESS) {
                return zcl_status;
            }
            if ((min_value != ZCL_INVALID_UNSIGNED_16BIT) && (val < min_value)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 2;
            break;
        }

        case ZCL_POWER_CONFIG_ATTR_BATTERY_SIZE:
        case ZCL_POWER_CONFIG_ATTR_BATTERY2_SIZE:
        case ZCL_POWER_CONFIG_ATTR_BATTERY3_SIZE:
        {
            uint8_t val;

            val = input_data[0];
            if ((val > ZCL_POWER_CONFIG_BATTERY_SIZE_CR123A) && (val != ZCL_POWER_CONFIG_BATTERY_SIZE_UNKNOWN)) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;
        }

        case ZCL_POWER_CONFIG_ATTR_BATTERY_ALARM_MASK:
        {
            uint8_t val;

            val = input_data[0];
            if ((val & ~(ZCL_POWER_CONFIG_BATTERY_ALARM_MASK_MASK)) != 0U) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 1;
            break;
        }
        /* ZCL_POWER_CONFIG_ATTR_BATTERY_ALARM_STATE is an read/reportable attribute, but this is still required here for local writes */
        case ZCL_POWER_CONFIG_ATTR_BATTERY_ALARM_STATE:
        {
            uint32_t val;

            val = pletoh32(input_data);
            if ((val & ~(ZCL_POWER_CONFIG_BATTERY_ALARM_STATE_MASK)) != 0U) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 4;
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
