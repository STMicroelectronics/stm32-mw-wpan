/* Copyright [2019 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.dehum.ctrl.h"

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
static const struct ZbZclAttrT zcl_dehum_ctrl_server_attr_list[] = {
    /* Dehumidification Information. */
#if 0 /* Optional attributes */
    {
        ZCL_DEHUM_CTRL_SVR_ATTR_REL_HUM, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0,
        NULL, {0x00U, 0x64U}, {0, 0}
    },
#endif
    {
        ZCL_DEHUM_CTRL_SVR_ATTR_DEHUM_COOLING, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    /* Dehumidification Settings. */
    {
        ZCL_DEHUM_CTRL_SVR_ATTR_RHDH_SETPT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x1E, 0x64}, {0, 0}
    },
#if 0
    {
        ZCL_DEHUM_CTRL_SVR_ATTR_RH_MODE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x00U, 0x01}, {0, 0}
    },
    {
        ZCL_DEHUM_CTRL_SVR_ATTR_DH_LOCKOUT, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x00U, 0x01}, {0, 0}
    },
#endif
    {
        ZCL_DEHUM_CTRL_SVR_ATTR_DH_HYS, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x02, 0x14}, {0, 0}
    },
    {
        ZCL_DEHUM_CTRL_SVR_ATTR_DH_MAX_COOL, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x14, 0x64}, {0, 0}
    },
#if 0
    {
        ZCL_DEHUM_CTRL_SVR_ATTR_RH_DISPLAY, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0x00, 0x01}, {0, 0}
    },
#endif
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

struct ZbZclClusterT *
ZbZclDehumCtrlServerAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    /* Allocate. */
    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_HVAC_DEHUMIDIFIER, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_dehum_ctrl_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_dehum_ctrl_server_attr_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Write default values to attributes */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DEHUM_CTRL_SVR_ATTR_DEHUM_COOLING, ZCL_DEHUM_CTRL_UNKNOWN);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DEHUM_CTRL_SVR_ATTR_RHDH_SETPT, ZCL_DEHUM_CTRL_RHDH_SETPT_DEFAULT);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DEHUM_CTRL_SVR_ATTR_DH_HYS, ZCL_DEHUM_CTRL_DH_HYS_DEFAULT);
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DEHUM_CTRL_SVR_ATTR_DH_MAX_COOL, ZCL_DEHUM_CTRL_DH_MAX_COOL_DEFAULT);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src, uint16_t attribute_id,
    const uint8_t *input_data, unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg)
{
    unsigned int len = 0;
    enum ZclStatusCodeT status;
    uint8_t value, maxValue;
    switch (attribute_id) {
        case ZCL_DEHUM_CTRL_SVR_ATTR_DEHUM_COOLING:
            value = *input_data;
            maxValue = (uint8_t)ZbZclAttrIntegerRead(cluster, (uint16_t)ZCL_DEHUM_CTRL_SVR_ATTR_DH_MAX_COOL, NULL, NULL);
            if ((value > maxValue) && (value != ZCL_INVALID_UNSIGNED_8BIT)) {
                status = ZCL_STATUS_INVALID_VALUE;
                break;
            }
            len = 1;
            status = ZCL_STATUS_SUCCESS;
            break;

        default:
            /* Unsupported Attribute */
            status = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            break;
    }

    if (((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) && (status == ZCL_STATUS_SUCCESS)) {
        (void)memcpy(attr_data, input_data, len);
    }
    return status;
}
