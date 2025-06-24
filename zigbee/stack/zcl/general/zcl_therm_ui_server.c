/* Copyright [2019 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/zcl.h"
#include "zcl/general/zcl.therm.ui.h"

static const struct ZbZclAttrT zcl_therm_ui_server_attr_list[] = {
    {
        ZCL_THERM_UI_SVR_ATTR_DISPLAY_MODE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0x00, 0x01}, {0, 0}
    },
    {
        ZCL_THERM_UI_SVR_ATTR_KEYPAD_LOCKOUT, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0x00, 0x05}, {0, 0}
    },
#if 0 /* Optional attributes */
    {
        ZCL_THERM_UI_SVR_ATTR_SCHEDULE_PROG_VIS, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0,
        NULL, {0x00, 0x01}, {0, 0}
    }
#endif
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

struct ZbZclClusterT *
ZbZclThermUiServerAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_HVAC_THERMOSTAT_UI, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_therm_ui_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_therm_ui_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_THERM_UI_SVR_ATTR_DISPLAY_MODE, 0x00);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_THERM_UI_SVR_ATTR_KEYPAD_LOCKOUT, 0x00);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}
