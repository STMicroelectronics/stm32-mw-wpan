/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl_attr.h"
#include "zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */

static void ZbZclAttrFreeAttr(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrListEntryT *attrPtr);

enum ZclStatusCodeT
ZbZclAttrAppendList(struct ZbZclClusterT *clusterPtr, const struct ZbZclAttrT *attrList, unsigned int num_attrs)
{
    struct ZigBeeT *zb = clusterPtr->zb;
    unsigned int i;
    struct ZbZclAttrListEntryT new_attr, *attrPtr;
    unsigned int val_buf_sz;

    /* The caller shouldn't be calling with a NULL attribute list, but
     * allow it anyway. */
    if ((attrList == NULL) || (num_attrs == 0U)) {
        return ZCL_STATUS_SUCCESS;
    }

    for (i = 0; i < num_attrs; i++) {
        if ((attrList[i].flags & ZCL_ATTR_FLAG_CB_MASK) != 0U) {
            if (attrList[i].callback == NULL) {
                ZCL_LOG_PRINTF(zb, __func__, "Error, callback flags detected but callback "
                    "function pointer is NULL for attribute %x", attrList[i].attributeId);
                return ZCL_STATUS_FAILURE;
            }
        }

        attrPtr = ZbZclAttrFind(clusterPtr, attrList[i].attributeId);
        if (attrPtr != NULL) {
            /* Replace any duplicate attributes we find. The cluster might
             * have some default attribute definitions that the application
             * wants to override with its own. */
            ZbZclAttrFreeAttr(clusterPtr, attrPtr);
        }

        (void)memset(&new_attr, 0, sizeof(struct ZbZclAttrListEntryT));
        LINK_LIST_INIT(&new_attr.link);
        new_attr.info = &attrList[i];
        if ((attrList[i].flags & ZCL_ATTR_FLAG_REPORTABLE) != 0U) {
            new_attr.reporting.interval_secs_max = attrList[i].reporting.interval_max;
            new_attr.reporting.interval_secs_min = attrList[i].reporting.interval_min;
        }

        /* How much memory to allocate for attribute data? */
        if (((attrList[i].flags & ZCL_ATTR_FLAG_CB_READ) != 0U)
            && ((attrList[i].flags & ZCL_ATTR_FLAG_CB_WRITE) != 0U)) {
            /* If defining a custom value size and also both custom read and write functions,
             * then don't allocate the attribute data buffer. The cluster will maintain this
             * information separately. */
            val_buf_sz = 0U;

            /* However, assign new_attr.valSz for persistence to work proplery.  */
            new_attr.valSz = attrList[i].customValSz;
        }
        else if (attrList[i].customValSz > 0U) {
            new_attr.valSz = attrList[i].customValSz;

            /* Allow for leading string length header, to keep these details
             * from user. */
            if ((new_attr.info->dataType == ZCL_DATATYPE_STRING_OCTET)
                || (new_attr.info->dataType == ZCL_DATATYPE_STRING_CHARACTER)) {
                new_attr.valSz += 1U;
            }
            else if ((new_attr.info->dataType == ZCL_DATATYPE_STRING_LONG_OCTET)
                     || (new_attr.info->dataType == ZCL_DATATYPE_STRING_LONG_CHARACTER)) {
                new_attr.valSz += 2U;
            }
            else {
                /* no change to valSz */
            }
            val_buf_sz = new_attr.valSz;
        }
        else {
            new_attr.valSz = ZbZclAttrTypeLength(attrList[i].dataType);
            if (new_attr.valSz == 0U) {
                ZCL_LOG_PRINTF(zb, __func__, "Error, attr = 0x%04x, type = %d, len = 0",
                    attrList[i].attributeId, attrList[i].dataType);
                return ZCL_STATUS_INVALID_DATA_TYPE;
            }
            val_buf_sz = new_attr.valSz;
        }

        ZCL_LOG_PRINTF(zb, __func__, "Allocating attribute (cl=0x%04x, attr=0x%04x) = %d",
            clusterPtr->clusterId, attrList[i].attributeId,
            sizeof(struct ZbZclAttrListEntryT) + val_buf_sz);

        attrPtr = ZbHeapAlloc(zb, sizeof(struct ZbZclAttrListEntryT) + val_buf_sz);
        if (attrPtr == NULL) {
            ZCL_LOG_PRINTF(zb, __func__, "Error, memory exhausted (len = %d)", sizeof(struct ZbZclAttrListEntryT) + val_buf_sz);
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }
        (void)memcpy(attrPtr, &new_attr, sizeof(struct ZbZclAttrListEntryT));

        if (val_buf_sz > 0U) {
            /* Set the valBuf memory pointer */
            attrPtr->valBuf = (uint8_t *)(&attrPtr[1]);
            (void)memset(attrPtr->valBuf, 0, val_buf_sz);
        }

        /* Append it to the list */
        ZbZclAttrAddSorted(clusterPtr, attrPtr);

        /* Give the attribute a default value */
        if (attrPtr->valBuf != NULL) {
            (void)ZbZclAttrDefaultValue(attrPtr->info->dataType, attrPtr->valBuf, attrPtr->valSz);
        }
        else {
            /* managed by app */
        }
    }

    (void)zcl_reporting_create_default_reports(clusterPtr);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclAttrCallbackExec(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrListEntryT *attrPtr,
    struct ZbZclAttrCbInfoT *cb)
{
    if (attrPtr->info->callback != NULL) {
        return attrPtr->info->callback(clusterPtr, cb);
    }
    return ZCL_STATUS_FAILURE;
}

static void
ZbZclAttrFreeAttr(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrListEntryT *attrPtr)
{
    if ((attrPtr->info->flags & ZCL_ATTR_FLAG_REPORTABLE) != 0U) {
        (void)zcl_cluster_attr_report_delete(clusterPtr, attrPtr->info->attributeId, ZCL_REPORT_DIRECTION_NORMAL);
        (void)zcl_cluster_attr_report_delete(clusterPtr, attrPtr->info->attributeId, ZCL_REPORT_DIRECTION_REVERSE);
    }
    LINK_LIST_UNLINK(&attrPtr->link);
    ZbHeapFree(clusterPtr->zb, attrPtr);
}

void
ZbZclAttrFreeList(struct ZbZclClusterT *clusterPtr)
{
    struct LinkListT *p;
    struct ZbZclAttrListEntryT *attrPtr;

    while (true) {
        p = LINK_LIST_HEAD(&clusterPtr->attributeList);
        if (p == NULL) {
            break;
        }
        attrPtr = LINK_LIST_ITEM(p, struct ZbZclAttrListEntryT, link);
        ZbZclAttrFreeAttr(clusterPtr, attrPtr);
    }
}
