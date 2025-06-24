/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

/*-------------------------------------------------
 *  DESCRIPTION
 *      Implements ZCL helper functions.
 *-------------------------------------------------
 */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl_attr.h"

const uint8_t zcl_attr_str_short_zero[] = {
    0x00
};

const uint8_t zcl_attr_str_long_zero[] = {
    0x00, 0x00
};

static enum ZclStatusCodeT
zcl_attr_string_write(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrListEntryT *attrPtr, const uint8_t *zcl_str)
{
    uint16_t length;
    enum ZclStatusCodeT status = ZCL_STATUS_SUCCESS;

    switch (attrPtr->info->dataType) {
        case ZCL_DATATYPE_STRING_OCTET:
        case ZCL_DATATYPE_STRING_CHARACTER:
            length = (uint16_t)zcl_str[0] + 1;
            break;

        case ZCL_DATATYPE_STRING_LONG_OCTET:
        case ZCL_DATATYPE_STRING_LONG_CHARACTER:
            length = pletoh16(&zcl_str[0]) + 2;
            break;

        default:
            status = ZCL_STATUS_INVALID_DATA_TYPE;
            break;
    }

    if (status != ZCL_STATUS_SUCCESS) {
        /* unknow type, bail! */
        return status;
    }

    /* Write the attribute. */
    if ((attrPtr->info->flags & ZCL_ATTR_FLAG_CB_WRITE) != 0U) {
        struct ZbZclAttrCbInfoT cb;

        /* Write or test the attribute value depending on the mode. */
        (void)memset(&cb, 0, sizeof(struct ZbZclAttrCbInfoT));
        cb.info = attrPtr->info;
        cb.type = ZCL_ATTR_CB_TYPE_WRITE;
        cb.zcl_data = (uint8_t *)zcl_str;
        cb.zcl_len = length;
        cb.write_mode = ZCL_ATTR_WRITE_FLAG_FORCE;
        cb.attr_data = attrPtr->valBuf;
        cb.app_cb_arg = clusterPtr->app_cb_arg;
        status = ZbZclAttrCallbackExec(clusterPtr, attrPtr, &cb);
    }
    else {
        status = ZbZclAttrDefaultWrite(clusterPtr, attrPtr, zcl_str, ZCL_ATTR_WRITE_FLAG_FORCE);
        if ((status == ZCL_STATUS_SUCCESS) && ((attrPtr->info->flags & ZCL_ATTR_FLAG_CB_NOTIFY) != 0U)) {
            struct ZbZclAttrCbInfoT cb;

            /* Notify the application that this attribute has been modified internally by the stack. */
            (void)memset(&cb, 0, sizeof(struct ZbZclAttrCbInfoT));
            cb.info = attrPtr->info;
            cb.type = ZCL_ATTR_CB_TYPE_NOTIFY;
            cb.app_cb_arg = clusterPtr->app_cb_arg;
            (void)ZbZclAttrCallbackExec(clusterPtr, attrPtr, &cb);
        }
    }

    if (status == ZCL_STATUS_SUCCESS) {
        ZbZclAttrPostWrite(clusterPtr, attrPtr);
    }
    return status;
}

enum ZclStatusCodeT
ZbZclAttrStringWriteShort(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, const uint8_t *zcl_str)
{
    struct ZbZclAttrListEntryT *attrPtr;

    attrPtr = ZbZclAttrFind(clusterPtr, attributeId);
    if (attrPtr == NULL) {
        return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
    if ((attrPtr->info->dataType != ZCL_DATATYPE_STRING_OCTET)
        && (attrPtr->info->dataType != ZCL_DATATYPE_STRING_CHARACTER)) {
        return ZCL_STATUS_INVALID_DATA_TYPE;
    }
    return zcl_attr_string_write(clusterPtr, attrPtr, zcl_str);
}

enum ZclStatusCodeT
ZbZclAttrStringWriteLong(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, const uint8_t *zcl_str)
{
    struct ZbZclAttrListEntryT *attrPtr;

    attrPtr = ZbZclAttrFind(clusterPtr, attributeId);
    if (attrPtr == NULL) {
        return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
    if ((attrPtr->info->dataType != ZCL_DATATYPE_STRING_LONG_OCTET)
        && (attrPtr->info->dataType != ZCL_DATATYPE_STRING_LONG_CHARACTER)) {
        return ZCL_STATUS_INVALID_DATA_TYPE;
    }
    return zcl_attr_string_write(clusterPtr, attrPtr, zcl_str);
}
