/* Copyright [2009 - 2025] Exegin Technologies Limited. All rights reserved. */

/*-------------------------------------------------
 *  DESCRIPTION
 *      Implements ZCL helper functions.
 *-------------------------------------------------
 */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl_attr.h"

/*lint -e9070 "ZbZclAttrParseLength() recursive [MISRA Rule 17.2 (REQUIRED)]" */

enum ZclStatusCodeT ZbZclAttrDefaultWrite(struct ZbZclClusterT *clusterPtr,
    struct ZbZclAttrListEntryT *attrPtr, const uint8_t *data, ZclWriteModeT mode);

void ZbZclAttrPostWrite(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrListEntryT *attrPtr);

static enum ZclStatusCodeT ZbZclAttrDefaultRead(struct ZbZclClusterT *clusterPtr,
    struct ZbZclAttrListEntryT *attrPtr, uint8_t *data, unsigned int data_len);

void
ZbZclAttrAddSorted(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrListEntryT *new_entry)
{
    struct LinkListT *p;
    struct ZbZclAttrListEntryT *entry;

    LINK_LIST_FOREACH(p, &clusterPtr->attributeList) {
        entry = LINK_LIST_ITEM(p, struct ZbZclAttrListEntryT, link);
        if (new_entry->info->attributeId < entry->info->attributeId) {
            LINK_LIST_INSERT_BEFORE(&entry->link, &new_entry->link);
            return;
        }
    }
    LINK_LIST_INSERT_TAIL(&clusterPtr->attributeList, &new_entry->link);
}

struct ZbZclAttrListEntryT *
ZbZclAttrFind(struct ZbZclClusterT *clusterPtr, uint16_t attrId)
{
    struct LinkListT *p;
    struct ZbZclAttrListEntryT *attrPtr;

    for (p = LINK_LIST_HEAD(&clusterPtr->attributeList); p != NULL; p = LINK_LIST_NEXT(p, &clusterPtr->attributeList)) {
        attrPtr = LINK_LIST_ITEM(p, struct ZbZclAttrListEntryT, link);
        if (attrPtr->info->attributeId != attrId) {
            continue;
        }
        return attrPtr;
    }
    return NULL;
}

void
ZbZclAttrHandleDiscover(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr,
    struct ZbApsdeDataIndT *ind)
{
    struct ZbApsdeDataReqT dataReq;
    uint8_t buf[ZB_APS_CONST_SAFE_APSSEC_PAYLOAD_SIZE];
    struct ZbZclHeaderT respHeader;
    uint16_t start_attr;
    int len;
    uint8_t num_attr, i;

    memset(&respHeader, 0, sizeof(struct ZbZclHeaderT));

    /* Parse the start attribute ID and the maximum attribute count. */
    if (ind->asduLength < 3U) {
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    i = 0;
    start_attr = pletoh16(&ind->asdu[i]);
    i += 2U;
    num_attr = ind->asdu[i++];
    (void)i; /* keep MISRA happy. */

    /* Construct the ZCL header for the response. */
    respHeader.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    respHeader.frameCtrl.manufacturer = zclHdrPtr->frameCtrl.manufacturer;
    respHeader.frameCtrl.direction = (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_SERVER) ?
        ZCL_DIRECTION_TO_CLIENT : ZCL_DIRECTION_TO_SERVER;
    respHeader.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    respHeader.manufacturerCode = zclHdrPtr->manufacturerCode;
    respHeader.seqNum = zclHdrPtr->seqNum;
    respHeader.cmdId = ZCL_COMMAND_DISCOVER_ATTR_RSP;
    len = ZbZclAppendHeader(&respHeader, buf, sizeof(buf));
    if (len < 0) {
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    /* Get the ZCL payload (attribute list) */
    len += (int)ZbZclAttrDiscoverGetList(clusterPtr, start_attr, &num_attr, &buf[len], ((uint32_t)sizeof(buf)) - (uint32_t)len);
    if (num_attr == 0U) {
        if (ZbApsAddrIsBcast(&ind->dst)) {
            /* If the request was broadcast or group addressed, and we found no
             * attributes, then don't generate a discover response command. */
            return;
        }
    }

    /* Fill in the APSDE-DATA.request. */
    ZbZclClusterInitApsdeReq(clusterPtr, &dataReq, ind);
    dataReq.dst = ind->src;
    dataReq.txOptions = ZbZclTxOptsFromSecurityStatus(ind->securityStatus);
    dataReq.asdu = buf;
    dataReq.asduLength = (uint16_t)len;

    /* Send the APSDE-DATA.request without blocking. */
    if (ZbApsdeDataReqCallback(clusterPtr->zb, &dataReq, NULL, NULL) != ZB_APS_STATUS_SUCCESS) {
        /* Ignored */
    }
}

unsigned int
ZbZclAttrDiscoverGetList(struct ZbZclClusterT *clusterPtr, uint16_t start_attr, uint8_t *max_num_attr,
    uint8_t *buf, unsigned int max_len)
{
    struct LinkListT *p;
    struct ZbZclAttrListEntryT *attrPtr;
    uint8_t num_attr = 0;
    unsigned int len = 0;

    /* Set the complete flag to false. */
    buf[len++] = 0;

    /* Iterate through the attribute list and append the attribute info fields. */
    for (p = LINK_LIST_HEAD(&clusterPtr->attributeList); p != NULL; p = LINK_LIST_NEXT(p, &clusterPtr->attributeList)) {
        attrPtr = LINK_LIST_ITEM(p, struct ZbZclAttrListEntryT, link);
        /* Skip this attribute if it's lower than the start. */
        if (attrPtr->info->attributeId < start_attr) {
            continue;
        }
        if ((attrPtr->info->flags & ZCL_ATTR_FLAG_INTERNAL) != 0U) {
            /* Internal use only, not discoverable. */
            continue;
        }

        /* Get out if we've already reached the maximum number of attributes. */
        if (num_attr >= *max_num_attr) {
            break;
        }
        if ((len + 3U) > max_len) {
            break;
        }

        /* Add this attribute */
        putle16(&buf[len], attrPtr->info->attributeId);
        len += 2U;
        buf[len++] = (uint8_t)attrPtr->info->dataType;
        num_attr++;
    }

    if (p == NULL) {
        /* If we reached the end of the attribute list, set the complete
         * flag to true. */
        *buf = 1U;
    }

    *max_num_attr = num_attr;
    return len;
}

enum ZclStatusCodeT
ZbZclAttrRead(struct ZbZclClusterT *clusterPtr, uint16_t attrId, enum ZclDataTypeT *attrType, void *outputBuf,
    unsigned int max_len, bool isReporting)
{
    struct ZbZclAttrListEntryT *attrPtr;

    attrPtr = ZbZclAttrFind(clusterPtr, attrId);
    if (attrPtr == NULL) {
        return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }

    if (isReporting && ((attrPtr->info->flags & ZCL_ATTR_FLAG_REPORTABLE) == 0U)) {
        return ZCL_STATUS_UNREPORTABLE_ATTRIBUTE;
    }

    if (attrType != NULL) {
        *attrType = attrPtr->info->dataType;
    }

    if ((outputBuf == NULL) || (max_len == 0U)) {
        if (attrType != NULL) {
            /* Caller just wanted to get the attribute's type */
            return ZCL_STATUS_SUCCESS;
        }
        else {
            /* Caller doesn't know what they're doing */
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }
    }

    if ((attrPtr->info->flags & ZCL_ATTR_FLAG_CB_READ) != 0U) {
        struct ZbZclAttrCbInfoT cb;

        (void)memset(&cb, 0, sizeof(struct ZbZclAttrCbInfoT));
        cb.info = attrPtr->info;
        cb.type = ZCL_ATTR_CB_TYPE_READ;
        cb.zcl_data = outputBuf;
        cb.zcl_len = max_len;
        cb.app_cb_arg = clusterPtr->app_cb_arg;
        return ZbZclAttrCallbackExec(clusterPtr, attrPtr, &cb);
    }
    else {
        return ZbZclAttrDefaultRead(clusterPtr, attrPtr, outputBuf, max_len);
    }
}

static enum ZclStatusCodeT
ZbZclAttrDefaultRead(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrListEntryT *attrPtr,
    uint8_t *data, unsigned int data_len)
{
    unsigned int copy_len = 0U;
    enum ZclStatusCodeT rc = ZCL_STATUS_SUCCESS;

    switch (attrPtr->info->dataType) {
        /* 8-bit data */
        case ZCL_DATATYPE_GENERAL_8BIT:
        case ZCL_DATATYPE_BOOLEAN:
        case ZCL_DATATYPE_BITMAP_8BIT:
        case ZCL_DATATYPE_UNSIGNED_8BIT:
        case ZCL_DATATYPE_SIGNED_8BIT:
        case ZCL_DATATYPE_ENUMERATION_8BIT:
            if (data_len < 1U) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            copy_len = 1U;
            break;

        /* 16-bit data */
        case ZCL_DATATYPE_GENERAL_16BIT:
        case ZCL_DATATYPE_BITMAP_16BIT:
        case ZCL_DATATYPE_UNSIGNED_16BIT:
        case ZCL_DATATYPE_SIGNED_16BIT:
        case ZCL_DATATYPE_ENUMERATION_16BIT:
        case ZCL_DATATYPE_FLOATING_SEMI:
        case ZCL_DATATYPE_CLUSTER_ID:
        case ZCL_DATATYPE_ATTRIBUTE_ID:
            if (data_len < 2U) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            copy_len = 2U;
            break;

        /* 24-bit data */
        case ZCL_DATATYPE_GENERAL_24BIT:
        case ZCL_DATATYPE_BITMAP_24BIT:
        case ZCL_DATATYPE_UNSIGNED_24BIT:
        case ZCL_DATATYPE_SIGNED_24BIT:
            if (data_len < 3U) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            copy_len = 3U;
            break;

        /* 32-bit data */
        case ZCL_DATATYPE_GENERAL_32BIT:
        case ZCL_DATATYPE_BITMAP_32BIT:
        case ZCL_DATATYPE_UNSIGNED_32BIT:
        case ZCL_DATATYPE_SIGNED_32BIT:
        case ZCL_DATATYPE_FLOATING_SINGLE:
        case ZCL_DATATYPE_TIME_OF_DAY:
        case ZCL_DATATYPE_DATE:
        case ZCL_DATATYPE_TIME_UTC:
        case ZCL_DATATYPE_BACNET_OID:
            if (data_len < 4U) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            copy_len = 4U;
            break;

        /* 40-bit data */
        case ZCL_DATATYPE_GENERAL_40BIT:
        case ZCL_DATATYPE_BITMAP_40BIT:
        case ZCL_DATATYPE_UNSIGNED_40BIT:
        case ZCL_DATATYPE_SIGNED_40BIT:
            if (data_len < 5U) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            copy_len = 5U;
            break;

        /* 48-bit data */
        case ZCL_DATATYPE_GENERAL_48BIT:
        case ZCL_DATATYPE_BITMAP_48BIT:
        case ZCL_DATATYPE_UNSIGNED_48BIT:
        case ZCL_DATATYPE_SIGNED_48BIT:
            if (data_len < 6U) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            copy_len = 6U;
            break;

        /* 56-bit data */
        case ZCL_DATATYPE_GENERAL_56BIT:
        case ZCL_DATATYPE_BITMAP_56BIT:
        case ZCL_DATATYPE_UNSIGNED_56BIT:
        case ZCL_DATATYPE_SIGNED_56BIT:
            if (data_len < 7U) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            copy_len = 7U;
            break;

        /* 64-bit data */
        case ZCL_DATATYPE_GENERAL_64BIT:
        case ZCL_DATATYPE_BITMAP_64BIT:
        case ZCL_DATATYPE_UNSIGNED_64BIT:
        case ZCL_DATATYPE_SIGNED_64BIT:
        case ZCL_DATATYPE_FLOATING_DOUBLE:
        case ZCL_DATATYPE_EUI64:
            if (data_len < 8U) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            copy_len = 8U;
            break;

        /* 128-bit data */
        case ZCL_DATATYPE_SECURITY_KEY128:
            if (data_len < ZB_SEC_KEYSIZE) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            copy_len = ZB_SEC_KEYSIZE;
            break;

        /* Strings */
        case ZCL_DATATYPE_STRING_OCTET:
        case ZCL_DATATYPE_STRING_CHARACTER:
        {
            uint8_t str_len;

            if (data_len < 1U) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }

            str_len = attrPtr->valBuf[0];
            if (str_len == 0xffU) {
                str_len = 0U;
            }
            copy_len = (unsigned int)str_len + 1U;
            if (copy_len > data_len) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            break;
        }

        case ZCL_DATATYPE_STRING_LONG_OCTET:
        case ZCL_DATATYPE_STRING_LONG_CHARACTER:
        {
            uint16_t str_len;

            if (data_len < 1U) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            str_len = pletoh16(&attrPtr->valBuf[0]);
            if (str_len == 0xffffU) {
                str_len = 0U;
            }
            copy_len = (unsigned int)str_len + 2U;
            if (copy_len > data_len) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            break;
        }

        case ZCL_DATATYPE_ARRAY:
        case ZCL_DATATYPE_STRUCT:
        case ZCL_DATATYPE_SET:
        case ZCL_DATATYPE_BAG:
        case ZCL_DATATYPE_NULL:
        case ZCL_DATATYPE_UNKNOWN:
        default:
            rc = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            break;
    }
    if (rc == ZCL_STATUS_SUCCESS) {
        (void)memcpy(data, attrPtr->valBuf, copy_len);
    }
    return rc;
}

/* Locally write an attribute. */
enum ZclStatusCodeT
ZbZclAttrWrite(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attr_id,
    const uint8_t *attr_data, unsigned int max_len, ZclWriteModeT mode)
{
    struct ZbZclAttrListEntryT *attrPtr;
    enum ZclStatusCodeT status;
    int attr_len;

    attrPtr = ZbZclAttrFind(clusterPtr, attr_id);
    if (attrPtr == NULL) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Failed to write cl = 0x%04x, attr = 0x%04x (cannot find attribute)",
            clusterPtr->clusterId, attr_id);
        return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
    if (((attrPtr->info->flags & ZCL_ATTR_FLAG_WRITABLE) == 0U) && ((mode & ZCL_ATTR_WRITE_FLAG_FORCE) == 0U)) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Failed to write cl = 0x%04x, attr = 0x%04x (read-only)",
            clusterPtr->clusterId, attr_id);
        return ZCL_STATUS_READ_ONLY;
    }

    /* Sanity-check the attribute before writing it. */
    attr_len = ZbZclAttrParseLength(attrPtr->info->dataType, attr_data, max_len, 0);
    if (attr_len < 0) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, failed to write cl = 0x%04x, attr = 0x%04x (invalid length)",
            clusterPtr->clusterId, attr_id);
        return ZCL_STATUS_INVALID_VALUE;
    }

    if (ZbZclAttrIsInteger(attrPtr->info->dataType)) {
        long long value;

        value = ZbZclParseInteger(attrPtr->info->dataType, attr_data, &status);
        if (status != ZCL_STATUS_SUCCESS) {
            return status;
        }
        /* ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Range checking attribute (0x%04x) value = %lld", attr_id, value); */
        if (!ZbZclAttrIntegerRangeCheck(value, attrPtr->info->dataType,
                (long long)attrPtr->info->range.min, (long long)attrPtr->info->range.max)) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Failed to write cl = 0x%04x, attr = 0x%04x (out of range)",
                clusterPtr->clusterId, attr_id);
            return ZCL_STATUS_INVALID_VALUE;
        }
    }

    if ((attrPtr->info->flags & ZCL_ATTR_FLAG_CB_WRITE) != 0U) {
        struct ZbZclAttrCbInfoT cb;

        /* Write or test the attribute value depending on the mode. */
        (void)memset(&cb, 0, sizeof(struct ZbZclAttrCbInfoT));
        cb.info = attrPtr->info;
        cb.type = ZCL_ATTR_CB_TYPE_WRITE;
        cb.src = src;
        cb.zcl_data = (uint8_t *)attr_data;
        cb.zcl_len = max_len;
        cb.write_mode = mode;
        cb.attr_data = attrPtr->valBuf;
        cb.app_cb_arg = clusterPtr->app_cb_arg;
        status = ZbZclAttrCallbackExec(clusterPtr, attrPtr, &cb);
    }
    else {
        status = ZbZclAttrDefaultWrite(clusterPtr, attrPtr, attr_data, mode);
        if ((status == ZCL_STATUS_SUCCESS) && ((attrPtr->info->flags & ZCL_ATTR_FLAG_CB_NOTIFY) != 0U)) {
            struct ZbZclAttrCbInfoT cb;

            /* Notify the application that this attribute has been modified internally by the stack. */
            (void)memset(&cb, 0, sizeof(struct ZbZclAttrCbInfoT));
            cb.info = attrPtr->info;
            cb.type = ZCL_ATTR_CB_TYPE_NOTIFY;
            cb.src = src;
            cb.app_cb_arg = clusterPtr->app_cb_arg;
            (void)ZbZclAttrCallbackExec(clusterPtr, attrPtr, &cb);
        }
    }

    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Failed to write cl = 0x%04x, attr = 0x%04x (status = 0x%02x)",
            clusterPtr->clusterId, attr_id, status);
        return status;
    }

    ZbZclAttrPostWrite(clusterPtr, attrPtr);
    return ZCL_STATUS_SUCCESS;
}

void
ZbZclAttrPostWrite(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrListEntryT *attrPtr)
{
    /* sanity. */
    if (attrPtr == NULL) {
        return;
    }

#ifndef CONFIG_ZB_ZCL_NO_PERSIST
    /* Kick the persistence timer for this cluster if the attribute has the PERSIST flag set.
     * NOTE: Even if zb->persist.notify_enable is disabled, we still want to cache the ZCL
     * persistence data in case persistence gets enabled later. */
    if (((attrPtr->info->flags & ZCL_ATTR_FLAG_PERSISTABLE) != 0U) && (clusterPtr->persist_timer != NULL)) {
        if (!ZbTimerRunning(clusterPtr->persist_timer)) {
            ZbTimerReset(clusterPtr->persist_timer, 0);
            /* Followed up in zcl_cluster_persist_timer */
        }
    }
#endif

    /* Check if reports are affected by the attribute change. */
    zcl_attr_reporting_check(clusterPtr, attrPtr->info->attributeId, ZCL_REPORT_DIRECTION_NORMAL);
}

bool
ZbZclAttrPersist(struct ZbZclClusterT *clusterPtr, uint16_t attr_id)
{
    struct ZbZclAttrListEntryT *attrPtr;

    attrPtr = ZbZclAttrFind(clusterPtr, attr_id);
    if (attrPtr == NULL) {
        return false;
    }
    if ((attrPtr->info->flags & ZCL_ATTR_FLAG_PERSISTABLE) == 0U) {
        return false;
    }
    ZbZclAttrPostWrite(clusterPtr, attrPtr);
    return true;
}

enum ZclStatusCodeT
ZbZclAttrDefaultWrite(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrListEntryT *attrPtr,
    const uint8_t *data, ZclWriteModeT mode)
{
    unsigned int data_len = 0U;
    enum ZclStatusCodeT rc = ZCL_STATUS_SUCCESS;

    if (data == NULL) {
        return ZCL_STATUS_FAILURE;
    }

    switch (attrPtr->info->dataType) {
        /* 8-bit data */
        case ZCL_DATATYPE_GENERAL_8BIT:
        case ZCL_DATATYPE_BOOLEAN:
        case ZCL_DATATYPE_BITMAP_8BIT:
        case ZCL_DATATYPE_UNSIGNED_8BIT:
        case ZCL_DATATYPE_SIGNED_8BIT:
        case ZCL_DATATYPE_ENUMERATION_8BIT:
            data_len = 1U;
            break;

        /* 16-bit data */
        case ZCL_DATATYPE_GENERAL_16BIT:
        case ZCL_DATATYPE_BITMAP_16BIT:
        case ZCL_DATATYPE_UNSIGNED_16BIT:
        case ZCL_DATATYPE_SIGNED_16BIT:
        case ZCL_DATATYPE_ENUMERATION_16BIT:
        case ZCL_DATATYPE_FLOATING_SEMI:
        case ZCL_DATATYPE_CLUSTER_ID:
        case ZCL_DATATYPE_ATTRIBUTE_ID:
            data_len = 2U;
            break;

        /* 24-bit data */
        case ZCL_DATATYPE_GENERAL_24BIT:
        case ZCL_DATATYPE_BITMAP_24BIT:
        case ZCL_DATATYPE_UNSIGNED_24BIT:
        case ZCL_DATATYPE_SIGNED_24BIT:
            data_len = 3U;
            break;

        /* 32-bit data */
        case ZCL_DATATYPE_GENERAL_32BIT:
        case ZCL_DATATYPE_BITMAP_32BIT:
        case ZCL_DATATYPE_UNSIGNED_32BIT:
        case ZCL_DATATYPE_SIGNED_32BIT:
        case ZCL_DATATYPE_FLOATING_SINGLE:
        case ZCL_DATATYPE_TIME_OF_DAY:
        case ZCL_DATATYPE_DATE:
        case ZCL_DATATYPE_TIME_UTC:
        case ZCL_DATATYPE_BACNET_OID:
            data_len = 4U;
            break;

        /* 40-bit data */
        case ZCL_DATATYPE_GENERAL_40BIT:
        case ZCL_DATATYPE_BITMAP_40BIT:
        case ZCL_DATATYPE_UNSIGNED_40BIT:
        case ZCL_DATATYPE_SIGNED_40BIT:
            data_len = 5U;
            break;

        /* 48-bit data */
        case ZCL_DATATYPE_GENERAL_48BIT:
        case ZCL_DATATYPE_BITMAP_48BIT:
        case ZCL_DATATYPE_UNSIGNED_48BIT:
        case ZCL_DATATYPE_SIGNED_48BIT:
            data_len = 6U;
            break;

        /* 56-bit data */
        case ZCL_DATATYPE_GENERAL_56BIT:
        case ZCL_DATATYPE_BITMAP_56BIT:
        case ZCL_DATATYPE_UNSIGNED_56BIT:
        case ZCL_DATATYPE_SIGNED_56BIT:
            data_len = 7U;
            break;

        /* 64-bit data */
        case ZCL_DATATYPE_GENERAL_64BIT:
        case ZCL_DATATYPE_BITMAP_64BIT:
        case ZCL_DATATYPE_UNSIGNED_64BIT:
        case ZCL_DATATYPE_SIGNED_64BIT:
        case ZCL_DATATYPE_FLOATING_DOUBLE:
        case ZCL_DATATYPE_EUI64:
            data_len = 8U;
            break;

        /* 128-bit data */
        case ZCL_DATATYPE_SECURITY_KEY128:
            data_len = ZB_SEC_KEYSIZE;
            break;

        /* Strings */
        case ZCL_DATATYPE_STRING_OCTET:
        case ZCL_DATATYPE_STRING_CHARACTER:
        {
            uint8_t str_len;

            if (attrPtr->valSz < 1U) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }

            str_len = *data;
            if (str_len == 0xffU) {
                attrPtr->valBuf[0] = 0xffU;
                data_len = 0U; /* value already written to buffer */
                break;
            }
            data_len = (unsigned int)str_len + 1U;
            if (data_len > attrPtr->valSz) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            break;
        }

        case ZCL_DATATYPE_STRING_LONG_OCTET:
        case ZCL_DATATYPE_STRING_LONG_CHARACTER:
        {
            uint16_t str_len;

            if (attrPtr->valSz < 2U) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }

            str_len = pletoh16(data);
            if (str_len == 0xffffU) {
                putle16(attrPtr->valBuf, 0xffffU);
                data_len = 0U; /* value already written to buffer */
                break;
            }
            data_len = (unsigned int)str_len + 2U;
            if (data_len > attrPtr->valSz) {
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            break;
        }

        case ZCL_DATATYPE_ARRAY:
        case ZCL_DATATYPE_STRUCT:
        case ZCL_DATATYPE_SET:
        case ZCL_DATATYPE_BAG:
        case ZCL_DATATYPE_NULL:
        case ZCL_DATATYPE_UNKNOWN:
        default:
            rc = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            break;
    }
    if ((rc == ZCL_STATUS_SUCCESS) && ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) && (data_len > 0U)) {
        (void)memcpy(attrPtr->valBuf, data, data_len);
    }
    return rc;
}

/* Writes the default (i.e. invalid) value of a ZCL data type to the buffer provided. */
int
ZbZclAttrDefaultValue(enum ZclDataTypeT type, uint8_t *buf, unsigned int max_len)
{
    unsigned int len = 0;
    int rc = -1;

    /*lint -save -e9090 "switch w fallthrough [MISRA Rule 16.3 (REQUIRED)]" */
    switch (type) {
        /* Attributes that have no data. */
        case ZCL_DATATYPE_NULL:
        case ZCL_DATATYPE_UNKNOWN:
            rc = 0;
            break;

        /* Invalid integer values are all ones (e.g. ZCL_INVALID_UNSIGNED_8BIT) */
        case ZCL_DATATYPE_GENERAL_64BIT:
        case ZCL_DATATYPE_UNSIGNED_64BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0xff;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_GENERAL_56BIT:
        case ZCL_DATATYPE_UNSIGNED_56BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0xff;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_GENERAL_48BIT:
        case ZCL_DATATYPE_UNSIGNED_48BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0xff;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_GENERAL_40BIT:
        case ZCL_DATATYPE_UNSIGNED_40BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0xff;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_GENERAL_32BIT:
        case ZCL_DATATYPE_UNSIGNED_32BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0xff;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_GENERAL_24BIT:
        case ZCL_DATATYPE_UNSIGNED_24BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0xff;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_GENERAL_16BIT:
        case ZCL_DATATYPE_UNSIGNED_16BIT:
        case ZCL_DATATYPE_ENUMERATION_16BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0xff;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_GENERAL_8BIT:
        case ZCL_DATATYPE_UNSIGNED_8BIT:
        case ZCL_DATATYPE_ENUMERATION_8BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0xff;
            len++;
            rc = (int)len;
            break;

        case ZCL_DATATYPE_BOOLEAN:
            *buf++ = 0;
            rc = 1;
            break;

        /* Set bit fields to zero */
        case ZCL_DATATYPE_BITMAP_64BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_BITMAP_56BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_BITMAP_48BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_BITMAP_40BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_BITMAP_32BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_BITMAP_24BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_BITMAP_16BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_BITMAP_8BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
            rc = (int)len;
            break;

        /* For signed attributes, the invalid value is MSB is 0x80, the rest are all zeros. */
        case ZCL_DATATYPE_SIGNED_64BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_56BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_48BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_40BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_32BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_24BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_16BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0;
            len++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_8BIT:
            if ((len + 1U) > max_len) {
                break;
            }
            *buf++ = 0x80;
            len++;
            rc = (int)len;
            break;

        case ZCL_DATATYPE_FLOATING_SEMI:
            if (max_len < 2U) {
                break;
            }
            putle16(buf, (uint16_t)ZCL_INVALID_FLOATING_SEMI);
            rc = 2;
            break;

        case ZCL_DATATYPE_FLOATING_SINGLE:
            if (max_len < 4U) {
                break;
            }
            putle32(buf, (uint32_t)ZCL_INVALID_FLOATING_SINGLE);
            rc = 4;
            break;

        case ZCL_DATATYPE_FLOATING_DOUBLE:
            if (max_len < 8U) {
                break;
            }
            putle64(buf, (uint64_t)ZCL_INVALID_FLOATING_DOUBLE);
            rc = 8;
            break;

        case ZCL_DATATYPE_STRING_OCTET:
            if (max_len < 2U) {
                break;
            }
            putle16(buf, ZCL_INVALID_STRING_OCTET);
            rc = 2;
            break;

        case ZCL_DATATYPE_STRING_CHARACTER:
            if (max_len < 2U) {
                break;
            }
            putle16(buf, ZCL_INVALID_STRING_CHARACTER);
            rc = 2;
            break;

        case ZCL_DATATYPE_STRING_LONG_OCTET:
            if (max_len < 4U) {
                break;
            }
            putle32(buf, ZCL_INVALID_STRING_LONG_OCTET);
            rc = 4;
            break;

        case ZCL_DATATYPE_STRING_LONG_CHARACTER:
            if (max_len < 4U) {
                break;
            }
            putle32(buf, ZCL_INVALID_STRING_LONG_CHARACTER);
            rc = 4;
            break;

        case ZCL_DATATYPE_EUI64:
            if (max_len < 8U) {
                break;
            }
            putle64(buf, ZCL_INVALID_EUI64);
            rc = 8;
            break;

        case ZCL_DATATYPE_SECURITY_KEY128:
            if (max_len < ZB_SEC_KEYSIZE) {
                break;
            }
            (void)memset(buf, 0, ZB_SEC_KEYSIZE);
            rc = (int)ZB_SEC_KEYSIZE;
            break;

        case ZCL_DATATYPE_ARRAY:
            if (max_len < 2U) {
                break;
            }
            putle16(buf, ZCL_INVALID_ARRAY);
            rc = 2;
            break;

        case ZCL_DATATYPE_STRUCT:
            if (max_len < 2U) {
                break;
            }
            putle16(buf, ZCL_INVALID_STRUCT);
            rc = 2;
            break;

        case ZCL_DATATYPE_SET:
            if (max_len < 2U) {
                break;
            }
            putle16(buf, ZCL_INVALID_SET);
            rc = 2;
            break;

        case ZCL_DATATYPE_BAG:
            if (max_len < 2U) {
                break;
            }
            putle16(buf, ZCL_INVALID_BAG);
            rc = 2;
            break;

        case ZCL_DATATYPE_TIME_OF_DAY:
            if (max_len < 4U) {
                break;
            }
            putle32(buf, ZCL_INVALID_TIME_OF_DAY);
            rc = 4;
            break;

        case ZCL_DATATYPE_DATE:
            if (max_len < 4U) {
                break;
            }
            putle32(buf, ZCL_INVALID_DATE);
            rc = 4;
            break;

        case ZCL_DATATYPE_TIME_UTC:
            if (max_len < 4U) {
                break;
            }
            putle32(buf, ZCL_INVALID_TIME_UTC);
            rc = 4;
            break;

        case ZCL_DATATYPE_CLUSTER_ID:
            if (max_len < 2U) {
                break;
            }
            putle16(buf, ZCL_INVALID_CLUSTER_ID);
            rc = 2;
            break;

        case ZCL_DATATYPE_ATTRIBUTE_ID:
            if (max_len < 2U) {
                break;
            }
            putle16(buf, ZCL_INVALID_ATTRIBUTE_ID);
            rc = 2;
            break;

        case ZCL_DATATYPE_BACNET_OID:
            if (max_len < 4U) {
                break;
            }
            putle32(buf, ZCL_INVALID_BACNET_OID);
            rc = 4;
            break;

        default:
            /* Unknown attribute type. */
            break;
    }
    /*lint -restore */
    return rc;
}

#if 0 /* not used */
enum ZclDataTypeT
ZbZclAttrType(struct ZbZclClusterT *clusterPtr, uint16_t attrId)
{
    struct ZbZclAttrListEntryT *attrPtr;

    attrPtr = ZbZclAttrFind(clusterPtr, attrId);
    if (attrPtr == NULL) {
        return ZCL_DATATYPE_NULL;
    }
    return attrPtr->info->dataType;
}

#endif

/* Returns the length of an attribute, solely based on type.
 *      For variable length attribute types (i.e. string, array, struct)
 *      and unknown attribute types, this function returns 0. */
unsigned int
ZbZclAttrTypeLength(enum ZclDataTypeT type)
{
    unsigned int rc;

    switch (type) {
        /* 8-bit data */
        case ZCL_DATATYPE_GENERAL_8BIT:
        case ZCL_DATATYPE_BOOLEAN:
        case ZCL_DATATYPE_BITMAP_8BIT:
        case ZCL_DATATYPE_UNSIGNED_8BIT:
        case ZCL_DATATYPE_SIGNED_8BIT:
        case ZCL_DATATYPE_ENUMERATION_8BIT:
            rc = 1;
            break;

        /* 16-bit data */
        case ZCL_DATATYPE_GENERAL_16BIT:
        case ZCL_DATATYPE_BITMAP_16BIT:
        case ZCL_DATATYPE_UNSIGNED_16BIT:
        case ZCL_DATATYPE_SIGNED_16BIT:
        case ZCL_DATATYPE_ENUMERATION_16BIT:
        case ZCL_DATATYPE_FLOATING_SEMI:
        case ZCL_DATATYPE_CLUSTER_ID:
        case ZCL_DATATYPE_ATTRIBUTE_ID:
            rc = 2;
            break;

        /* 24-bit data */
        case ZCL_DATATYPE_GENERAL_24BIT:
        case ZCL_DATATYPE_BITMAP_24BIT:
        case ZCL_DATATYPE_UNSIGNED_24BIT:
        case ZCL_DATATYPE_SIGNED_24BIT:
            rc = 3;
            break;

        /* 32-bit data */
        case ZCL_DATATYPE_GENERAL_32BIT:
        case ZCL_DATATYPE_BITMAP_32BIT:
        case ZCL_DATATYPE_UNSIGNED_32BIT:
        case ZCL_DATATYPE_SIGNED_32BIT:
        case ZCL_DATATYPE_FLOATING_SINGLE:
        case ZCL_DATATYPE_TIME_OF_DAY:
        case ZCL_DATATYPE_DATE:
        case ZCL_DATATYPE_TIME_UTC:
        case ZCL_DATATYPE_BACNET_OID:
            rc = 4;
            break;

        /* 40-bit data */
        case ZCL_DATATYPE_GENERAL_40BIT:
        case ZCL_DATATYPE_BITMAP_40BIT:
        case ZCL_DATATYPE_UNSIGNED_40BIT:
        case ZCL_DATATYPE_SIGNED_40BIT:
            rc = 5;
            break;

        /* 48-bit data */
        case ZCL_DATATYPE_GENERAL_48BIT:
        case ZCL_DATATYPE_BITMAP_48BIT:
        case ZCL_DATATYPE_UNSIGNED_48BIT:
        case ZCL_DATATYPE_SIGNED_48BIT:
            rc = 6;
            break;

        /* 56-bit data */
        case ZCL_DATATYPE_GENERAL_56BIT:
        case ZCL_DATATYPE_BITMAP_56BIT:
        case ZCL_DATATYPE_UNSIGNED_56BIT:
        case ZCL_DATATYPE_SIGNED_56BIT:
            rc = 7;
            break;

        /* 64-bit data */
        case ZCL_DATATYPE_GENERAL_64BIT:
        case ZCL_DATATYPE_BITMAP_64BIT:
        case ZCL_DATATYPE_UNSIGNED_64BIT:
        case ZCL_DATATYPE_SIGNED_64BIT:
        case ZCL_DATATYPE_FLOATING_DOUBLE:
        case ZCL_DATATYPE_EUI64:
            rc = 8;
            break;

        /* 128-bit data */
        case ZCL_DATATYPE_SECURITY_KEY128:
            rc = 16;
            break;

        /* Variable or Null Length Attributes */
        case ZCL_DATATYPE_NULL:
        case ZCL_DATATYPE_STRING_OCTET:
        case ZCL_DATATYPE_STRING_CHARACTER:
        case ZCL_DATATYPE_STRING_LONG_OCTET:
        case ZCL_DATATYPE_STRING_LONG_CHARACTER:
        case ZCL_DATATYPE_ARRAY:
        case ZCL_DATATYPE_STRUCT:
        case ZCL_DATATYPE_SET:
        case ZCL_DATATYPE_BAG:
        case ZCL_DATATYPE_UNKNOWN:
            rc = 0;
            break;

        default:
            rc = 0;
            break;
    }
    return rc;
}

/* Determines the length of an attribute for a given data
 *      type. In case the type has a variable length, the buffer
 *      should also be provided. */
int
ZbZclAttrParseLength(enum ZclDataTypeT type, const uint8_t *ptr, unsigned int max_len, uint8_t recurs_depth)
{
    enum ZclDataTypeT sub_type;
    uint16_t dblVal;
    int length;

    /* The recursive depth (i.e. array, set, bag, struct) may not exceed 15. */
    if (recurs_depth >= 15U) {
        return -1;
    }

    /* Most attributes have a fixed length, so look that up first. */
    length = (int)ZbZclAttrTypeLength(type);
    if (length > 0) {
        if ((unsigned int)length > max_len) {
            return -1;
        }
        return length;
    }

    if (ptr == NULL) {
        /* If the attribute data buffer is NULL, then return the max length. */
        return (int)max_len;
    }

    /* For non-fixed-length attributes, compute the length. */
    length = -1;
    switch (type) {
        /* Length defined in the first octet. */
        case ZCL_DATATYPE_STRING_OCTET:
        case ZCL_DATATYPE_STRING_CHARACTER:
            /* Parse the length field. */
            if (max_len < 1U) {
                break;
            }
            /* Ensure the string exists. */
            length = (ptr[0] == 0xffU) ? 1 : ((int)ptr[0] + 1);
            break;

        /* Length defined in the first two octets. */
        case ZCL_DATATYPE_STRING_LONG_OCTET:
        case ZCL_DATATYPE_STRING_LONG_CHARACTER:
            if (max_len < 2U) {
                break;
            }
            dblVal = pletoh16(ptr);
            /* Ensure the string exists. */
            length = (dblVal == 0xffffU) ? 2 : ((int)dblVal + 2);
            break;

        /* List of elements with the same type. */
        case ZCL_DATATYPE_ARRAY:
        case ZCL_DATATYPE_SET:
        case ZCL_DATATYPE_BAG:
            /* Parse the type and quantity of elements. */
            if (max_len < 3U) {
                break;
            }
            /*lint -e{9034} "ZclDataTypeT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
            sub_type = (enum ZclDataTypeT)ptr[0];

            dblVal = pletoh16(&ptr[1]);
            /* Iterate through the list, summing up the element sizes. */
            length = 3;
            for (; (dblVal > 0U) && (dblVal != 0xffffU); dblVal--) {
                int temp;

                /* Get the length of the next element (recursive). */
                temp = ZbZclAttrParseLength(sub_type, &ptr[length], max_len - (unsigned int)length, recurs_depth + 1U);
                if (temp < 0) {
                    return temp;
                }

                /* Add the length. */
                length += temp;
            }
            break;

        /* List of elements with varying type. */
        case ZCL_DATATYPE_STRUCT:
            /* Parse the quantity of elements. */
            if (max_len < 2U) {
                break;
            }
            dblVal = pletoh16(ptr);

            /* Iterate through the list, summing up the element sizes. */
            length = 2;
            for (; (dblVal > 0U) && (dblVal != 0xffffU); dblVal--) {
                int temp;

                /* Ensure the element type exists. */
                if (((unsigned int)length + 1U) > max_len) {
                    break;
                }
                /*lint -e{9034} "ZclDataTypeT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
                sub_type = (enum ZclDataTypeT)ptr[length++];

                /* Get the length of the next element (recursive). */
                temp = ZbZclAttrParseLength(sub_type, &ptr[length], max_len - (unsigned int)length, recurs_depth + 1U);
                if (temp < 0) {
                    break;
                }

                /* Add the length. */
                length += temp;
            }
            break;

        default:
            /* Unknown data type */
            break;
    }
    if ((length < 0) || ((unsigned int)length > max_len)) {
        return -1;
    }
    return length;
}

bool
ZbZclAttrIsAnalog(enum ZclDataTypeT dataType)
{
    if ((dataType >= ZCL_DATATYPE_UNSIGNED_8BIT)
        && (dataType <= ZCL_DATATYPE_UNSIGNED_64BIT)) {
        /* Unsigned integers are analog. */
        return true;
    }
    if ((dataType >= ZCL_DATATYPE_SIGNED_8BIT)
        && (dataType <= ZCL_DATATYPE_SIGNED_64BIT)) {
        /* Signed integers are analog. */
        return true;
    }
    if ((dataType == ZCL_DATATYPE_FLOATING_SEMI)
        || (dataType == ZCL_DATATYPE_FLOATING_SINGLE)
        || (dataType == ZCL_DATATYPE_FLOATING_DOUBLE)) {
        /* Floating point are analog. */
        return true;
    }
    if ((dataType == ZCL_DATATYPE_TIME_OF_DAY)
        || (dataType == ZCL_DATATYPE_DATE)
        || (dataType == ZCL_DATATYPE_TIME_UTC)) {
        /* Time is analog...  unless you happen to be Max Planck. */
        return true;
    }
    /* Everything else is digital. */
    return false;
}
