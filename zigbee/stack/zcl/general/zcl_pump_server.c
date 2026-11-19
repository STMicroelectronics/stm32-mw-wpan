/* Copyright [2019 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/zcl.h"
#include "zcl/general/zcl.pump.h"

static const struct ZbZclAttrT zcl_pump_server_attr_list[] = {
    /* Pump Information. */
    {
        ZCL_PUMP_SVR_ATTR_MAX_PRESSURE, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {ZCL_PUMP_PRESSURE_MIN, ZCL_PUMP_PRESSURE_MAX}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_MAX_SPEED, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0x0000, 0xfffe}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_MAX_FLOW, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0x0000, 0xfffe}, {0, 0}
    },
#if 0 /* Optional attributes */
    {
        ZCL_PUMP_SVR_ATTR_MIN_CONST_PRESSURE, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {ZCL_PUMP_PRESSURE_MIN, ZCL_PUMP_PRESSURE_MAX}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_MAX_CONST_PRESSURE, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {ZCL_PUMP_PRESSURE_MIN, ZCL_PUMP_PRESSURE_MAX}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_MIN_COMP_PRESSURE, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {ZCL_PUMP_PRESSURE_MIN, ZCL_PUMP_PRESSURE_MAX}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_MAX_COMP_PRESSURE, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {ZCL_PUMP_PRESSURE_MIN, ZCL_PUMP_PRESSURE_MAX}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_MIN_CONST_SPEED, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0x0000, 0xfffe}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_MAX_CONST_SPEED, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0x0000, 0xfffe}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_MIN_CONST_FLOW, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0x0000, 0xfffe}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_MAX_CONST_FLOW, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0x0000, 0xfffe}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_MIN_CONST_TEMP, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {ZCL_PUMP_TEMP_MIN, ZCL_PUMP_TEMP_MAX}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_MAX_CONST_TEMP, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {ZCL_PUMP_TEMP_MIN, ZCL_PUMP_TEMP_MAX}, {0, 0}
    },
    /* Pump Dynamic Information. */
    {
        ZCL_PUMP_SVR_ATTR_PUMP_STATUS, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0}, {0, 0}
    },
#endif
    {
        ZCL_PUMP_SVR_ATTR_EFF_OP_MODE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0x00, 0xfe}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_EFF_CTRL_MODE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0x00, 0xfe}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_CAPACITY, ZCL_DATATYPE_SIGNED_16BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {ZCL_PUMP_CAPACITY_MIN, ZCL_PUMP_CAPACITY_MAX}, {0, 0}
    },
#if 0
    {
        ZCL_PUMP_SVR_ATTR_SPEED, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0x0000, 0xffff}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_RUNNING_HOURS, ZCL_DATATYPE_UNSIGNED_24BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0x000000, 0xffffff}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_POWER, ZCL_DATATYPE_UNSIGNED_24BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0x000000, 0xffffff}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_ENERGY_CONSUMED, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0x00000000U, 0xffffffffU}, {0, 0}
    },
#endif
    {
        ZCL_PUMP_SVR_ATTR_OP_MODE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0x00, 0xfe}, {0, 0}
    },
#if 0
    {
        ZCL_PUMP_SVR_ATTR_CTRL_MODE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0x00, 0xfe}, {0, 0}
    },
    {
        ZCL_PUMP_SVR_ATTR_ALARM_MASK, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0, 0}, {0, 0}
    },
#endif
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

struct ZbZclClusterT *
ZbZclPumpServerAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_HVAC_PUMP, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_pump_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_pump_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_PUMP_SVR_ATTR_OP_MODE, ZCL_PUMP_OP_MODE_DEFAULT);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}
