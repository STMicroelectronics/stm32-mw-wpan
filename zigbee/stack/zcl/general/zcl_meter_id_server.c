/* Copyright [2019 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.meter.id.h"

static const struct ZbZclAttrT zcl_meter_id_server_attr_list[] = {
    /* Meter Identification */
    {
        ZCL_METER_ID_ATTR_COMPANY_NAME, ZCL_DATATYPE_STRING_CHARACTER,
        ZCL_ATTR_FLAG_NONE, ZCL_METER_ID_COMPANY_NAME_LEN_MAX,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_ID_ATTR_METER_TYPE_ID, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_ID_ATTR_DATA_QUAL_ID, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0, 0}, {0, 0}
    },
#if 0 /* Optional attributes */
    {
        ZCL_METER_ID_ATTR_CUSTOMER_NAME, ZCL_DATATYPE_STRING_CHARACTER,
        ZCL_ATTR_FLAG_WRITABLE, ZCL_METER_ID_CUSTOMER_NAME_LEN_MAX,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_ID_ATTR_MODEL, ZCL_DATATYPE_STRING_OCTET,
        ZCL_ATTR_FLAG_NONE, ZCL_METER_ID_MODEL_LEN_MAX,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_ID_ATTR_PART_NUMBER, ZCL_DATATYPE_STRING_OCTET,
        ZCL_ATTR_FLAG_NONE, ZCL_METER_ID_PART_NUMBER_LEN_MAX,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_ID_ATTR_PRODUCT_REV, ZCL_DATATYPE_STRING_OCTET,
        ZCL_ATTR_FLAG_NONE, ZCL_METER_ID_PRODUCT_REV_LEN_MAX,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_ID_ATTR_SOFTWARE_REV, ZCL_DATATYPE_STRING_OCTET,
        ZCL_ATTR_FLAG_NONE, ZCL_METER_ID_SOFTWARE_REV_LEN_MAX,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_ID_ATTR_UTILITY_NAME, ZCL_DATATYPE_STRING_CHARACTER,
        ZCL_ATTR_FLAG_WRITABLE, ZCL_METER_ID_UTILITY_NAME_LEN_MAX,
        NULL, {0, 0}, {0, 0}
    },
#endif
    {
        ZCL_METER_ID_ATTR_POD, ZCL_DATATYPE_STRING_CHARACTER,
        ZCL_ATTR_FLAG_NONE, ZCL_METER_ID_POD_LEN_MAX,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_ID_ATTR_AVAILABLE_POWER, ZCL_DATATYPE_SIGNED_24BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_METER_ID_ATTR_POWER_THRESH, ZCL_DATATYPE_SIGNED_24BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0, 0}, {0, 0}
    }
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

struct ZbZclClusterT *
ZbZclMeterIdServerAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_METER_ID, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_meter_id_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_meter_id_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    (void)ZbZclAttrStringWriteShort(&clusterPtr->cluster, ZCL_METER_ID_ATTR_COMPANY_NAME, zcl_attr_str_short_zero);
    (void)ZbZclAttrStringWriteShort(&clusterPtr->cluster, ZCL_METER_ID_ATTR_POD, zcl_attr_str_short_zero);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}
