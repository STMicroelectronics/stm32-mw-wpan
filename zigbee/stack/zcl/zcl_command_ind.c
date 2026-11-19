/* Copyright [2009 - 2024] Exegin Technologies Limited. All rights reserved. */

#include "zcl/zcl.h"
#include "zcl/general/zcl.alarm.h"
#include "zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */
#include "zcl_attr.h"

#ifndef CONFIG_ZB_ZCL_NO_PERSIST
static enum ZclStatusCodeT zcl_persist_handle_set(struct ZbZclClusterT *clusterPtr, uint8_t *buf, uint16_t len);
#endif

#ifndef CONFIG_ZB_ZCL_NO_PERSIST
/*FUNCTION:-------------------------------------------------------------------
 *  NAME
 *      zcl_persist_handle_set
 *  DESCRIPTION
 *      Called for receipt of local ZCL_CMD_MANUF_INTERNAL_ATTR_PERSIST_SET
 *      (i.e. from zcl_persist_restore)
 *  PARAMETERS
 *      clusterPtr ; the cluster we're restoring persistence to.
 *      buf ; Attribute data
 *      len ; Length of buf
 *  RETURNS
 *      ZigBee status code
 *----------------------------------------------------------------------------
 */
static enum ZclStatusCodeT
zcl_persist_handle_set(struct ZbZclClusterT *clusterPtr, uint8_t *buf, uint16_t len)
{
    uint16_t i, attrId, attrLen;
    uint8_t *attrData;
    enum ZclStatusCodeT status;

    for (i = 0; i < len; ) {
        if ((i + 4U) > len) {
            return ZCL_STATUS_INVALID_VALUE;
        }
        attrId = pletoh16(&buf[i]);
        i += 2U;
        attrLen = pletoh16(&buf[i]);
        i += 2U;
        if ((i + attrLen) > len) {
            return ZCL_STATUS_INVALID_VALUE;
        }
        attrData = &buf[i];
        i += attrLen;

        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Restoring cluster persistence (cl = 0x%04x, attr = 0x%04x, len = %d)",
            clusterPtr->clusterId, attrId, attrLen);

        /* Assumes that we called ZbPersistNotifyControl(zb, false); to disable
         * saving of persistence, so we don't trigger saving persistence
         * while we restore persistence. */
        status = ZbZclAttrWrite(clusterPtr, NULL, attrId, attrData, attrLen,
                ZCL_ATTR_WRITE_FLAG_FORCE | ZCL_ATTR_WRITE_FLAG_PERSIST);
        if (status != ZCL_STATUS_SUCCESS) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Warning, failed to write persistence data to attribute (status = 0x%02x)", status);
            return status;
        }
    }
    return ZCL_STATUS_SUCCESS;
}

#endif

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      ZbZclHandleReadAttr
 *  DESCRIPTION
 *      Handles the ZCL Read Attribute global command.
 *  PARAMETERS
 *      clusterPtr      ; ZCL Cluster structure.
 *      zclHdrPtr       ; ZCL Header structure.
 *      dataIndPtr      ; APSDE-DATA.indication.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
ZbZclHandleReadAttr(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind)
{
    struct ZbApsdeDataReqT dataReq;
    struct ZbZclHeaderT respHeader;
    uint16_t attributeId;
    unsigned int offset;
    int len;
    uint8_t *buf;

    /* Allocate a temporary buffer for the read attribute response. */
    buf = ZbHeapAlloc(clusterPtr->zb, clusterPtr->maxAsduLength);
    if (buf == NULL) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Sending default response (INSUFFICIENT_SPACE).");
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_INSUFFICIENT_SPACE);
        return;
    }

    /* Construct the ZCL header. */
    (void)memset(&respHeader, 0, sizeof(struct ZbZclHeaderT));
    respHeader.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    respHeader.frameCtrl.manufacturer = zclHdrPtr->frameCtrl.manufacturer;
    respHeader.frameCtrl.direction = (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_SERVER) ?
        ZCL_DIRECTION_TO_CLIENT : ZCL_DIRECTION_TO_SERVER;
    respHeader.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    respHeader.manufacturerCode = zclHdrPtr->manufacturerCode;
    respHeader.seqNum = zclHdrPtr->seqNum;
    respHeader.cmdId = ZCL_COMMAND_READ_RESPONSE;
    len = ZbZclAppendHeader(&respHeader, buf, clusterPtr->maxAsduLength);
    if (len < 0) {
        ZbHeapFree(clusterPtr->zb, buf);
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }
    offset = (unsigned int)len;

    /* Parse the attribute list and perform reads until out of data. */
    while (true) {
        enum ZclStatusCodeT status;
        enum ZclDataTypeT attrType;

        /* Parse the next attribute ID. */
        if (ind->asduLength < 2U) {
            /* Got to the end */
            break;
        }
        attributeId = pletoh16(ind->asdu);
        /*lint -e{9016} "ptr arithmetic used [MISRA Rule 18.4 (ADVISORY)]" */
        ind->asdu += 2U;
        ind->asduLength -= 2U;

        /* Attempt to read the attribute value into the buffer. */
        if ((offset + 4U) >= clusterPtr->maxAsduLength) {
            /* Out of space for more attributes. */
            break;
        }

        /* Attribute ID field */
        putle16(&buf[offset], attributeId);
        offset += 2U;

        /* EXEGIN - print value as well? */
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Handling ZCL Read of cl = 0x%04x, attr = 0x%04x",
            ZbZclClusterGetClusterId(clusterPtr), attributeId);

        /* Perform the read (start buffer after the STATUS and TYPE fields. */
        status = ZbZclAttrRead(clusterPtr, attributeId, &attrType, &buf[offset + 2U],
                clusterPtr->maxAsduLength - offset - 2U, false);

        /* Fill in status field */
        buf[offset++] = (uint8_t)status;

        /* ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "attr = 0x%04x, status = 0x%02x", attributeId, status); */

        if (status == ZCL_STATUS_INSUFFICIENT_SPACE) {
            /* Don't try reading any more if we ran out of buffer space. */
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Unable to read attribute (buffer too small).");
            break;
        }
        if (status != ZCL_STATUS_SUCCESS) {
            /* Just return the error status */
            continue;
        }

        buf[offset++] = (uint8_t)attrType;

        /* Get length */
        len = ZbZclAttrParseLength(attrType, &buf[offset], clusterPtr->maxAsduLength - offset, 0);
        if (len < 0) {
            /* An error occurred, and the attribute value is broken. */
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Cluster returned malformed attribute.");
            offset--; /* remove attribute type */
            buf[offset - 1U] = (uint8_t)ZCL_STATUS_INVALID_VALUE;
            continue;
        }
        offset += (unsigned int)len;
    }

    /* Fill in the APSDE-DATA.request. */
    ZbZclClusterInitApsdeReq(clusterPtr, &dataReq, ind);
    dataReq.dst = ind->src;
    dataReq.txOptions = ZbZclTxOptsFromSecurityStatus(ind->securityStatus);
    if ((clusterPtr->txOptions & ZB_APSDE_DATAREQ_TXOPTIONS_FRAG) == 0U) {
        /* If cluster doesn't support frag, then disable it here.
         * This came about from Green Power, but seems reasonable
         * in the general case. Clusters by default allow fragmentation. */
        dataReq.txOptions &= ~(ZB_APSDE_DATAREQ_TXOPTIONS_FRAG);
    }
    dataReq.asdu = buf;
    dataReq.asduLength = (uint16_t)offset;

    /* ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Sending ZCL Read Response (len = %d)", dataReq.asduLength); */

    /* Send the APSDE-DATA.request without blocking. */
    if (ZbApsdeDataReqCallback(clusterPtr->zb, &dataReq, NULL, NULL) != ZB_APS_STATUS_SUCCESS) {
        /* Ignored */
    }

    /* Done with the heap buffer. */
    ZbHeapFree(clusterPtr->zb, buf);
}

/**
 * Handles the ZCL Write Attribute global commands. This
 * function implements the Write, Write No-Response, and
 * Write Undivided commands.
 * @param clusterPtr
 * @param zclHdrPtr
 * @param ind
 * @return None
 */
static void
ZbZclHandleWriteAttr(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind)
{
    struct ZbApsdeDataReqT dataReq;
    struct ZbZclHeaderT hdr;
    uint8_t buf[ZB_APS_CONST_SAFE_APSSEC_PAYLOAD_SIZE];
    enum ZclStatusCodeT status = ZCL_STATUS_FAILURE;
    uint16_t attr_id;
    enum ZclDataTypeT attr_type;
    int attr_len;
    unsigned int offset;
    int len = 0;
    unsigned int num_write_errors = 0;
    bool send_default_rsp;
    ZclWriteModeT mode;
    enum ZclStatusCodeT dft_rsp_status = ZCL_STATUS_SUCCESS;
    uint8_t cmd_id = (uint8_t)zclHdrPtr->cmdId;

    /* Handle the command. */
    mode = ZCL_ATTR_WRITE_FLAG_NORMAL;

    /*lint -save -e9090 "switch with fallthrough [MISRA Rule 16.3 (REQUIRED)]" */
    switch (cmd_id) {
        case ZCL_COMMAND_WRITE_UNDIVIDED:
            /* Change the write mode to prevent modifying any attributes
             * during the first pass. If we didn't encounter any errors,
             * then proceed to write all the attributes. */
            mode |= ZCL_ATTR_WRITE_FLAG_TEST;
        /*lint -fallthrough */

        case ZCL_COMMAND_WRITE:
            /* Construct the ZCL header for the write response command. */
            (void)memset(&hdr, 0, sizeof(struct ZbZclHeaderT));
            hdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
            hdr.frameCtrl.manufacturer = zclHdrPtr->frameCtrl.manufacturer;
            hdr.frameCtrl.direction = (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_SERVER) ?
                ZCL_DIRECTION_TO_CLIENT : ZCL_DIRECTION_TO_SERVER;
            hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
            hdr.manufacturerCode = zclHdrPtr->manufacturerCode;
            hdr.seqNum = zclHdrPtr->seqNum;
            hdr.cmdId = ZCL_COMMAND_WRITE_RESPONSE;
            len = ZbZclAppendHeader(&hdr, buf, sizeof(buf));
            if (len < 0) {
                dft_rsp_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            /* Fill in the APSDE-DATA.request. */
            ZbZclClusterInitApsdeReq(clusterPtr, &dataReq, ind);
            dataReq.dst = ind->src;
            dataReq.txOptions = ZbZclTxOptsFromSecurityStatus(ind->securityStatus);

            /* Parse the attribute list and test each write. */
            offset = 0;
            /* Set an error status for the default response if we need to
             * send one before parsing any attributes. */
            status = ZCL_STATUS_MALFORMED_COMMAND;
            send_default_rsp = true;
            num_write_errors = 0;
            while (true) {
                /* Parse the attribute ID and type. */
                if ((offset + 3U) >= ind->asduLength) {
                    status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }

                /* Make sure there is room for an error status, just in case. */
                if (((unsigned int)len + 3U) > sizeof(buf)) {
                    /* Shouldn't get here */
                    send_default_rsp = true;
                    status = ZCL_STATUS_INSUFFICIENT_SPACE;
                    break;
                }

                /* If we get this far, we can generate a proper write response */
                send_default_rsp = false;

                /* Parse write attribute record */
                attr_id = pletoh16(&ind->asdu[offset]);
                offset += 2U;

                /*lint -e{9034} "ZclDataTypeT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
                attr_type = (enum ZclDataTypeT)ind->asdu[offset++];

                /* Parse the attribute length and value. */
                attr_len = ZbZclAttrParseLength(attr_type, &ind->asdu[offset], ind->asduLength - offset, 0);
                if (attr_len < 0) {
                    num_write_errors++;

                    /* Append the write attribute status record. */
                    buf[len++] = (uint8_t)ZCL_STATUS_INVALID_VALUE;
                    putle16(&buf[len], attr_id);
                    len += 2;

                    /* Since we don't know the attribute's length, we have to stop
                     * processing this message. */
                    break;
                }

                /* Attempt to write this attribute */
                status = ZbZclAttrWrite(clusterPtr, &ind->src, attr_id, &ind->asdu[offset], ind->asduLength - offset, mode);
                offset += (unsigned int)attr_len;

                if (status != ZCL_STATUS_SUCCESS) {
                    num_write_errors++;

                    /* Only errors are appending to the write response */
                    buf[len++] = (uint8_t)status;
                    putle16(&buf[len], attr_id);
                    len += 2;
                }
            } /* while */

            if (send_default_rsp) {
                dft_rsp_status = status;
                break;
            }

            /* If this is a normal (!undivided) write, or if we encountered
             * an error and cannot do an undivided write, then get out now
             * and send the response. */
            if ((cmd_id == ZCL_COMMAND_WRITE) || (num_write_errors > 0U)) {
                break;
            }
        /*lint -fallthrough */

        case ZCL_COMMAND_WRITE_NO_RESPONSE:
            /* Parse the attribute list and perform writes until out of data. */
            offset = 0;
            num_write_errors = 0;
            while (true) {
                /* Parse the attribute ID and type. */
                if ((offset + 3U) >= ind->asduLength) {
                    num_write_errors++;
                    break;
                }
                attr_id = pletoh16(&ind->asdu[offset]);
                offset += 2U;
                /*lint -e{9034} "ZclDataTypeT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
                attr_type = (enum ZclDataTypeT)ind->asdu[offset++];

                /* Parse the attribute length and value. */
                attr_len = ZbZclAttrParseLength(attr_type, &ind->asdu[offset], ind->asduLength - offset, 0);
                if (attr_len < 0) {
                    num_write_errors++;
                    break;
                }

                status = ZbZclAttrWrite(clusterPtr, &ind->src, attr_id, &ind->asdu[offset],
                        ind->asduLength - offset, ZCL_ATTR_WRITE_FLAG_NORMAL);
                if (status != ZCL_STATUS_SUCCESS) {
                    num_write_errors++;
                }

                offset += (unsigned int)attr_len;
            } /* while */

            if (cmd_id == ZCL_COMMAND_WRITE_UNDIVIDED) {
                if (num_write_errors > 0U) {
                    /* Oh no! We did a dry-run and everything was fine, but when
                     * we went to actually write the attributes, we got an error.
                     * This means the write was not undivided. */
                    dft_rsp_status = ZCL_STATUS_FAILURE;
                    break;
                }
                break;
            }
            /* Otherwise, no response */
            dft_rsp_status = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            break;

        default:
            /* Can't get here, since this function is only called for
             * ZCL_COMMAND_WRITE[_xxx] commands. */
            dft_rsp_status = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    /*lint -restore */

    if (dft_rsp_status != ZCL_STATUS_SUCCESS) {
        if (dft_rsp_status != ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE) {
            ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, dft_rsp_status);
        }
        return;
    }

    if (num_write_errors == 0U) {
        if (len == 0) {
            /* The ZCL Header hasn't been written to the buffer. Should never get here. */
            ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_FAILURE);
            return;
        }
        /* If no errors, then nothing has been written to the payload yet. */
        buf[len++] = (uint8_t)ZCL_STATUS_SUCCESS;
    }

    /* Send the write response command. */
    dataReq.asdu = buf;
    dataReq.asduLength = (uint16_t)len;
    if (ZbApsdeDataReqCallback(clusterPtr->zb, &dataReq, NULL, NULL) != ZB_APS_STATUS_SUCCESS) {
        /* Ignored */
    }
}

#ifdef CONFIG_ZB_ZCL_STRUCT
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      ZbZclHandleReadStruct
 *  DESCRIPTION
 *      Handles the ZCL Read Structured global command.
 *  PARAMETERS
 *      clusterPtr      ; ZCL Cluster structure.
 *      zclHdrPtr       ; ZCL Header structure.
 *      dataIndPtr      ; APSDE-DATA.indication
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
ZbZclHandleReadStruct(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind)
{
    struct ZbApsdeDataReqT dataReq;
    uint8_t *buf;
    struct ZbZclHeaderT hdr;
    int hdr_len, attr_len;
    unsigned int len;
    unsigned offset = 0;
    enum ZclStatusCodeT status;
    enum ZclDataTypeT attrType;
    uint8_t indicator, stop;
    uint16_t index[15];
    uint16_t attr_id;
    uint8_t *attrBuf;
    uint8_t *elemPtr;

    (void)memset(index, 0, sizeof(uint16_t) * 15U);
    /* Allocate a buffer for the structured read response. */
    buf = ZbHeapAlloc(clusterPtr->zb, clusterPtr->maxAsduLength);
    if (buf == NULL) {
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_INSUFFICIENT_SPACE);
        return;
    }

    /* Construct the ZCL header. */
    hdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    hdr.frameCtrl.manufacturer = zclHdrPtr->frameCtrl.manufacturer;
    if (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_SERVER) {
        hdr.frameCtrl.direction = ZCL_DIRECTION_TO_CLIENT;
    }
    else {
        hdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
    }
    hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;

    hdr.manufacturerCode = zclHdrPtr->manufacturerCode;
    hdr.seqNum = zclHdrPtr->seqNum;
    hdr.cmdId = ZCL_COMMAND_READ_RESPONSE;
    hdr_len = ZbZclAppendHeader(&hdr, buf, sizeof(clusterPtr->maxAsduLength));
    if (hdr_len < 0) {
        ZbHeapFree(clusterPtr->zb, buf);
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }
    len = (unsigned int)hdr_len;

    /* Allocate a temporary buffer for caching the attribute value. */
    attrBuf = ZbHeapAlloc(clusterPtr->zb, ZCL_ATTRIBUTE_BUFFER_SIZE_MAX);
    if (attrBuf == NULL) {
        /* Out of memory. */
        ZbHeapFree(clusterPtr->zb, buf);
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_INSUFFICIENT_SPACE);
        return;
    }

    /* Parse the attribute and selector lists and perform reads until out of data. */
    while (true) {
        unsigned int i;

        /* Parse the attribute ID and indicator. */
        if ((offset + 3U) > ind->asduLength) {
            break;
        }
        attr_id = pletoh16(&ind->asdu[offset]);
        offset += 2U;
        indicator = ind->asdu[offset];
        offset++;

        /* Parse the selector list. */
        stop = indicator & ZCL_INDICATOR_DEPTH;
        for (i = 0; i < stop; i++) {
            if ((offset + 2U) > ind->asduLength) {
                break;
            }
            index[i] = pletoh16(&ind->asdu[offset]);
            offset += 2U;
        }
        if (i < stop) {
            break;
        }

        /* Read the attribute. */
        status = ZbZclAttrRead(clusterPtr, attr_id, &attrType, attrBuf, ZCL_ATTRIBUTE_BUFFER_SIZE_MAX, false);
        if (status != ZCL_STATUS_SUCCESS) {
            goto read_struct_error;
        }

        /* Parse the attribute for the desired element. */
        elemPtr = ZbZclFindElement(&attrType, attrBuf, ZCL_ATTRIBUTE_BUFFER_SIZE_MAX, indicator, index, &status);
        if (elemPtr == NULL) {
            goto read_struct_error;
        }
        /* Sanity-check the element length and make sure it fits. */
        /*lint -e{9016} "ptr arithmetic [MISRA Rule 18.4 (ADVISORY)]" */
        /*lint -e{946} -e{947} "ptr subtract [MISRA Rule 18.3 (REQUIRED)]" */
        /*lint -e{732} -e{9034} "arg3: uint <- int [MISRA Rule 10.3 (REQUIRED)]" */
        attr_len = ZbZclAttrParseLength(attrType, elemPtr, (uint16_t)ZCL_ATTRIBUTE_BUFFER_SIZE_MAX - (elemPtr - attrBuf), 0);
        if (attr_len < 0) {
            status = ZCL_STATUS_INVALID_VALUE;
            goto read_struct_error;
        }
        if ((len + 4U + (uint32_t)attr_len) > clusterPtr->maxAsduLength) {
            break;
        }

        /* Read was successful, append the element value. */
        putle16(&buf[len], attr_id);
        len += 2U;
        buf[len++] = (uint8_t)ZCL_STATUS_SUCCESS;
        buf[len++] = (uint8_t)attrType;
        (void)memcpy(&buf[len], elemPtr, (uint32_t)attr_len);
        len += (uint32_t)attr_len;
        /* Read more elements. */
        continue;

read_struct_error:
        if ((len + 3U) > clusterPtr->maxAsduLength) {
            break;
        }
        putle16(&buf[len], attr_id);
        len += 2U;
        buf[len++] = (uint8_t)status;
        /* Try more elements. */
    } /* while */

    /* Done with the temporary attribute buffer. */
    ZbHeapFree(clusterPtr->zb, attrBuf);

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
    ZbHeapFree(clusterPtr->zb, buf);
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      ZbZclHandleWriteStruct
 *  DESCRIPTION
 *      Handles the ZCL Write Structured Attribute global command.
 *
 *      Works by first reading the attribute from the application,
 *      overwriting the specified element with the one from the
 *      command, and then writing the whole attribute back to the
 *      application.
 *  PARAMETERS
 *      clusterPtr      ; ZCL Cluster structure.
 *      zclHdrPtr       ; ZCL Header structure.
 *      dataIndPtr      ; APSDE-DATA.indication
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
ZbZclHandleWriteStruct(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct ZbApsdeDataReqT dataReq;
    struct ZbZclHeaderT hdr;
    uint8_t buf[ZB_APS_CONST_SAFE_APSSEC_PAYLOAD_SIZE];
    enum ZclStatusCodeT status;
    uint8_t i, indicator, stop;
    uint16_t index[15];
    bool rc = true;
    int len;
    uint16_t offset = 0;
    void *attr;
    enum ZclDataTypeT attrType;
    uint16_t attr_id;
    void *elem;
    enum ZclDataTypeT elem_type;
    int elem_size;

    (void)memset(index, 0, sizeof(uint16_t) * 15U);
    /* Construct the ZCL header. */
    hdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    hdr.frameCtrl.manufacturer = zclHdrPtr->frameCtrl.manufacturer;
    if (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_SERVER) {
        hdr.frameCtrl.direction = ZCL_DIRECTION_TO_CLIENT;
    }
    else {
        hdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
    }
    hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;

    hdr.manufacturerCode = zclHdrPtr->manufacturerCode;
    hdr.seqNum = zclHdrPtr->seqNum;
    hdr.cmdId = ZCL_COMMAND_WRITE_STRUCTURED_RESPONSE;
    len = ZbZclAppendHeader(&hdr, buf, sizeof(buf));
    if (len < 0) {
        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    /* Fill in the APSDE-DATA.request. */
    ZbZclClusterInitApsdeReq(clusterPtr, &dataReq, dataIndPtr);
    dataReq.dst = dataIndPtr->src;
    dataReq.txOptions = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    /* Allocate a temporary buffer to cache the attribute value in. */
    attr = ZbHeapAlloc(clusterPtr->zb, ZCL_ATTRIBUTE_BUFFER_SIZE_MAX);
    if (attr == NULL) {
        /* Out of memory. */
        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_INSUFFICIENT_SPACE);
        return;
    }

    /* Parse the attribute list and perform writes until out of data. */
    while (true) {
        /* Parse the attribute ID and indicator. */
        if ((offset + 3U) > dataIndPtr->asduLength) {
            break;
        }
        attr_id = pletoh16(&dataIndPtr->asdu[offset]);
        offset += 2U;
        indicator = dataIndPtr->asdu[offset];
        offset++;

        /* Parse the selector list. */
        stop = indicator & 0xfU;
        for (i = 0; i < stop; i++) {
            if ((offset + 2U) > dataIndPtr->asduLength) {
                break;
            }
            index[i] = pletoh16(&dataIndPtr->asdu[offset]);
            offset += 2U;
        }
        if (i < stop) {
            break;
        }

        /* Parse the attribute type. */
        if ((offset + 1U) > dataIndPtr->asduLength) {
            break;
        }
        /*lint -e{9034} "ZclDataTypeT <- uint8_t [MISRA Rule 10.3 (REQUIRED)]" */
        elem_type = (enum ZclDataTypeT )dataIndPtr->asdu[offset];
        offset++;

        /* Ensure we have enough space for the write response record before continuing. */
        if (((uint32_t)len + 4U) > sizeof(buf)) {
            break;
        }

        /* Parse the element length and value. */
        elem = &dataIndPtr->asdu[offset];
        elem_size = ZbZclAttrParseLength(elem_type, elem, (uint32_t)dataIndPtr->asduLength - offset, 0);
        if (elem_size < 0) {
            break;
        }
        offset += (uint16_t)elem_size;

        /* Read the current value of the attribute. */
        status = ZbZclAttrRead(clusterPtr, attr_id, &attrType, attr, ZCL_ATTRIBUTE_BUFFER_SIZE_MAX, false);

        if (status != ZCL_STATUS_SUCCESS) {
            rc = false;
            buf[len++] = (uint8_t)status;
            putle16(&buf[len], attr_id);
            len += 2;
            buf[len++] = 0; /* selector field. */
            continue;
        }

        /* If the read was successful, attempt to replace the selected element. */
        status = ZbZclWriteElement(attr, attrType, (int)ZCL_ATTRIBUTE_BUFFER_SIZE_MAX, elem,
                (uint8_t)elem_type, elem_size, indicator, index);
        if (status == ZCL_STATUS_SUCCESS) {
            /* Successfully replaced the selected element, now try to write the attribute. */
            status = ZbZclAttrWrite(clusterPtr, &dataIndPtr->src, attr_id, attr,
                    ZCL_ATTRIBUTE_BUFFER_SIZE_MAX, ZCL_ATTR_WRITE_FLAG_NORMAL);
        }

        /* Check if the write succeeded. */
        if (status != ZCL_STATUS_SUCCESS) {
            rc = false;
            buf[len++] = (uint8_t)status;
            putle16(&buf[len], attr_id);
            len += 2;
            buf[len++] = 0; /* selector field. */
            continue;
        }
    } /* while */

    /* Done with the write buffer. */
    ZbHeapFree(clusterPtr->zb, attr);

    /* If all the writes were successful, then append a single status of SUCCESS. */
    if (rc) {
        buf[len++] = (uint8_t)ZCL_STATUS_SUCCESS;
    }

    /* Send the APSDE-DATA.request without blocking */
    dataReq.asdu = buf;
    dataReq.asduLength = (uint16_t)len;
    if (ZbApsdeDataReqCallback(clusterPtr->zb, &dataReq, NULL, NULL) != ZB_APS_STATUS_SUCCESS) {
        /* Ignored */
    }
}

#endif

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zcl_handle_command
 *  DESCRIPTION
 *      Handles a general ZCL command frame.
 *  PARAMETERS
 *      clusterPtr ;
 *      dataIndPtr ; APSDE-DATA.indication.
 *      zclHdrPtr ; ZCL Header structure.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
static int
zcl_handle_command(struct ZbZclClusterT *clusterPtr, struct ZbApsdeDataIndT *dataIndPtr, struct ZbZclHeaderT *zclHdrPtr)
{
    uint8_t cmd_id = (uint8_t)zclHdrPtr->cmdId;
    int rc;

    /* NOTE: If command sent to a groupcast (ZB_APSDE_ADDRMODE_GROUP), then the 'ind->dst.endpoint'
     * is set to each matching endpoint for that group (see aps_ind_check_filters), before executing
     * the filter. However, broadcast is treated the same as unicast, so we need to return
     * ZB_APS_FILTER_CONTINUE to check if the broadcast command matches any other endpoints. */
    if (dataIndPtr->dst.endpoint == ZB_ENDPOINT_BCAST) {
        rc = ZB_APS_FILTER_CONTINUE;
    }
    else {
        rc = ZB_APS_FILTER_DISCARD;
    }

    /* Check for minimum security if not an internal loop-back packet. */
    do {
        if (ZbApsAddrIsLocal(clusterPtr->zb, &dataIndPtr->src)) {
            /* It's a locally (this device) generated packet. Always let through. */
            break;
        }
        if (clusterPtr->clusterId == ZCL_CLUSTER_TOUCHLINK) {
            /* TOUCHLINK is a very special cluster, so just let them through! */
            break;
        }
        /* Check minimum security level */
        if (!ZbZclClusterCheckMinSecurity(clusterPtr, dataIndPtr, zclHdrPtr)) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__,
                "Error, cluster=0x%04x command=0x%02x, security=0x%02x doesn't meet minimum (0x%02x)",
                clusterPtr->clusterId, cmd_id, dataIndPtr->securityStatus, clusterPtr->minSecurity);
            ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_FAILURE);
            return rc;
        }
        /* Check Device Log */
        if (!ZbZclDeviceLogCheckAllow(clusterPtr->zb, dataIndPtr, zclHdrPtr)) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, " LOGFMTx64 " is not in the white-list",
                LOGVALx64(dataIndPtr->src.extAddr));
            /* EXEGIN - drop silently without sending a Default Response? */
            ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_FAILURE);
            return rc;
        }
    } while (false);

    /* EXEGIN - Check clusterPtr->maxAsduLength? */

    /* If the scope of this command is cluster-specific, then execute the cluster's
     * callback function. */
    if (zclHdrPtr->frameCtrl.frameType == ZCL_FRAMETYPE_CLUSTER) {
        enum ZclStatusCodeT status;

        /* Ensure that this cluster supports cluster-specific commands. */
        if (clusterPtr->command == NULL) {
            /* Cluster command not supported. */
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, cluster does not support asynchronous commands.");
            ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_UNSUPP_COMMAND);
            return rc;
        }

        /* Check manufacturer code, if present */
        if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
            if ((clusterPtr->mfrCode == 0x0000U) || (clusterPtr->mfrCode != zclHdrPtr->manufacturerCode)) {
                /* Incoming command is manufacturer-specific, but cluster is not
                 * manufacturer-specific or the code doesn't match, return error. */
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, dropping manuf cluster command (cl = 0x%04x)", clusterPtr->clusterId);
                ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_UNSUPP_COMMAND);
                return rc;
            }
        }
        else {
            if (clusterPtr->mfrCode != 0x0000U) {
                /* Incoming command is not manufacturer-specific, but cluster is
                 * manufacturer-specific, return error. */
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, dropping cluster command (cl = 0x%04x, mfr = 0x%04x)",
                    clusterPtr->clusterId, clusterPtr->mfrCode);
                ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_UNSUPP_COMMAND);
                return rc;
            }
        }

        status = clusterPtr->command(clusterPtr, zclHdrPtr, dataIndPtr);

        /* ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "cluster 'command' handler (%p) returned status = 0x%02x",
            clusterPtr->command, status); */

        if (status != ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE) {
            ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, status);
        }
        return rc;
    }

    /* Otherwise, the only valid scope for this command is the global scope.
     * If the frame type indicates anything else, return a default response
     * command. */
    if (zclHdrPtr->frameCtrl.frameType != ZCL_FRAMETYPE_PROFILE) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Sending default response (INVALID_FIELD).");
        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_INVALID_FIELD);
        return rc;
    }

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "ZCL Command: cluster=0x%04x, dst=0x%02x, fc_manuf=%d, fc_dir=%d, cmd=0x%02x",
        clusterPtr->clusterId, dataIndPtr->dst.endpoint, zclHdrPtr->frameCtrl.manufacturer, zclHdrPtr->frameCtrl.direction, cmd_id);

    /* Handle the command. */
    switch (cmd_id) {
        case ZCL_COMMAND_READ:
            ZbZclHandleReadAttr(clusterPtr, zclHdrPtr, dataIndPtr);
            break;

        case ZCL_COMMAND_WRITE:
        case ZCL_COMMAND_WRITE_NO_RESPONSE:
        case ZCL_COMMAND_WRITE_UNDIVIDED:
            ZbZclHandleWriteAttr(clusterPtr, zclHdrPtr, dataIndPtr);
            break;

        case ZCL_COMMAND_CONFIG_REPORTING:
            ZbZclHandleConfigReport(clusterPtr, zclHdrPtr, dataIndPtr);
            break;

        case ZCL_COMMAND_READ_REPORTING:
            ZbZclHandleReadReport(clusterPtr, zclHdrPtr, dataIndPtr);
            break;

        case ZCL_COMMAND_REPORT:
            ZbZclHandleReportAttr(clusterPtr, zclHdrPtr, dataIndPtr);
            break;

        case ZCL_COMMAND_DISCOVER_ATTR:
            ZbZclAttrHandleDiscover(clusterPtr, zclHdrPtr, dataIndPtr);
            break;

#ifdef CONFIG_ZB_ZCL_STRUCT
        case ZCL_COMMAND_READ_STRUCTURED:
            ZbZclHandleReadStruct(clusterPtr, zclHdrPtr, dataIndPtr);
            break;

        case ZCL_COMMAND_WRITE_STRUCTURED:
            ZbZclHandleWriteStruct(clusterPtr, zclHdrPtr, dataIndPtr);
            break;
#endif

        case ZCL_COMMAND_DEFAULT_RESPONSE:
#if 0
            /* Not required. For one, we don't want to process unsolicited
             * Default Response commands. Secondly, the request/response handler
             * (ZbZclCommandReq/zcl_command_data_ind) will receive and
             * process a Default Response if received. */
            if (clusterPtr->command) {
                clusterPtr->command(clusterPtr, zclHdrPtr, dataIndPtr);
            }
#endif
            break;

        case ZCL_COMMAND_READ_RESPONSE:
        case ZCL_COMMAND_WRITE_RESPONSE:
        case ZCL_COMMAND_WRITE_STRUCTURED_RESPONSE:
        case ZCL_COMMAND_CONFIG_REPORTING_RESPONSE:
        case ZCL_COMMAND_DISCOVER_ATTR_RSP:
        case ZCL_COMMAND_READ_REPORTING_RESPONSE:
            /* Solicited responses, not handled here */
            break;

        default:
            if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
                if (zclHdrPtr->manufacturerCode == (uint16_t)ZCL_MANUF_CODE_INTERNAL) {
                    if (!ZbApsAddrIsLocal(clusterPtr->zb, &dataIndPtr->src)) {
                        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Unsupported manufacturer id: 0x%04x", zclHdrPtr->manufacturerCode);
                        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_UNSUPP_COMMAND);
                        return rc;
                    }

                    if (cmd_id == (uint8_t)ZCL_CMD_MANUF_INTERNAL_GET_SCENE_EXTDATA) {
                        if (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_SERVER) {
                            ZbZclHandleGetSceneData(clusterPtr, zclHdrPtr, dataIndPtr);
                        }
                        /* TO_CLIENT responses are handled by a filter from ZbZclCommandReq */
                    }
                    else if (cmd_id == (uint8_t)ZCL_CMD_MANUF_INTERNAL_SET_SCENE_EXTDATA) {
                        if (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_SERVER) {
                            ZbZclHandleSetSceneData(clusterPtr, zclHdrPtr, dataIndPtr);
                        }
                        /* TO_CLIENT responses are handled by a filter from ZbZclCommandReq */
                    }
                    else if (cmd_id == (uint8_t)ZCL_CMD_MANUF_INTERNAL_ATTR_PERSIST_SET) {
#ifndef CONFIG_ZB_ZCL_NO_PERSIST
                        enum ZclStatusCodeT status;

                        status = zcl_persist_handle_set(clusterPtr, dataIndPtr->asdu, dataIndPtr->asduLength);
                        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, status);
#endif
                    }
                    else {
                        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Unsupported manufacturer command id: 0x%02x", cmd_id);
                        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_UNSUPP_COMMAND);
                    }
                }
                else {
                    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Unsupported manufacturer id: 0x%04x", zclHdrPtr->manufacturerCode);
                    ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_UNSUPP_COMMAND);
                }
                return rc;
            }

            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Unsupported command id: 0x%02x", cmd_id);
            ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_UNSUPP_COMMAND);
            break;
    }
    return rc;
}

/* Internal APSDE-DATA.indication handler for bound clusters. */
int
zcl_cluster_data_ind(struct ZbApsdeDataIndT *dataIndPtr, void *arg)
{
    struct ZbZclClusterT *clusterPtr = arg;
    struct ZbZclHeaderT hdr;
    int len;

    /* ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "APS Message: cl = 0x%04x, src = 0x%04x:%d, dst = %d",
        clusterPtr->clusterId, dataIndPtr->src.nwkAddr, dataIndPtr->src.endpoint, dataIndPtr->dst.endpoint); */

    /* Parse the ZCL header before passing it to the clusters. */
    len = ZbZclParseHeader(&hdr, dataIndPtr->asdu, dataIndPtr->asduLength);
    if (len < 0) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, failed to parse ZCL header");
        return ZB_APS_FILTER_CONTINUE;
    }
    dataIndPtr->asdu = &dataIndPtr->asdu[len];
    dataIndPtr->asduLength -= (uint16_t)len;
    return zcl_handle_command(clusterPtr, dataIndPtr, &hdr);
}

/* Internal APSDE-DATA.indication handler for alarms */
int
zcl_cluster_alarm_data_ind(struct ZbApsdeDataIndT *data_ind, void *arg)
{
    struct ZbZclClusterT *cluster = arg; /* originating cluster not alarms */
    struct ZbZclHeaderT zcl_hdr;
    int len;
    uint8_t alarm_code;
    uint16_t cluster_id;
    enum ZclStatusCodeT defrsp_status = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    int rc = ZB_APS_FILTER_CONTINUE;

    ZCL_LOG_PRINTF(cluster->zb, __func__, "APS message for Alarms: srcEp=0x%02x dstEp=0x%02x",
        data_ind->src.endpoint, data_ind->dst.endpoint);

    /* Parse the ZCL header before passing it to the clusters. */
    len = ZbZclParseHeader(&zcl_hdr, data_ind->asdu, data_ind->asduLength);
    if (len < 0) {
        return ZB_APS_FILTER_CONTINUE;
    }
    data_ind->asduLength -= (uint16_t)len;

    /* We only care about Alarm Server Cluster Specific Commands */
    if (data_ind->clusterId != (uint16_t)ZCL_CLUSTER_ALARMS) {
        /* Shouldn't get here (bad filter?) */
        return ZB_APS_FILTER_CONTINUE;
    }
    if (zcl_hdr.frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        /* Ignore here */
        return ZB_APS_FILTER_CONTINUE;
    }
    if (zcl_hdr.frameCtrl.frameType != ZCL_FRAMETYPE_CLUSTER) {
        /* Ignore here */
        return ZB_APS_FILTER_CONTINUE;
    }

    switch (zcl_hdr.cmdId) {
        case ZCL_ALARM_COMMAND_RESET:
        {
            alarm_code = data_ind->asdu[len];
            cluster_id = pletoh16(&data_ind->asdu[len + 1]);
            if (cluster_id != ZbZclClusterGetClusterId(cluster)) {
                /* Ignored. Not for this cluster. */
                break;
            }
            /* Does the application have a callback */
            if (cluster->alarm.reset_callback == NULL) {
                /* Shouldn't get here. Callback must be provided to ZbZclClusterRegisterAlarmResetHandler. */
                defrsp_status = ZCL_STATUS_UNSUPP_COMMAND;
                rc = ZB_APS_FILTER_DISCARD; /* command handled */
                break;
            }
            defrsp_status = cluster->alarm.reset_callback(cluster, alarm_code, cluster_id, data_ind, &zcl_hdr);
            rc = ZB_APS_FILTER_DISCARD; /* command handled */
            break;
        }

        case ZCL_ALARM_COMMAND_RESET_ALL:
            /* Does the application have a callback */
            if (cluster->alarm.reset_callback == NULL) {
                /* Shouldn't get here. Callback must be provided to ZbZclClusterRegisterAlarmResetHandler. */
                defrsp_status = ZCL_STATUS_UNSUPP_COMMAND;
                rc = ZB_APS_FILTER_DISCARD; /* command handled */
                break;
            }
            defrsp_status = cluster->alarm.reset_callback(cluster, 0xffU, 0xffffU, data_ind, &zcl_hdr);
            rc = ZB_APS_FILTER_DISCARD; /* command handled */
            break;

        default:
            /* Ignore any other commands in this handler */
            break;
    }

    /* Check if we need to send a Default Response */
    if (defrsp_status != ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE) {
        uint8_t zcl_seq;
        uint8_t zcl_hdr_buf[ZCL_HEADER_MAX_SIZE];
        int zcl_hdr_len;
        uint8_t payload[2];
        struct ZbApsBufT bufv[2];
        struct ZbApsdeDataReqT dataReq;

        zcl_seq = zcl_hdr.seqNum;

        /* Form the default response payload. */
        payload[0] = zcl_hdr.cmdId;
        payload[1] = (uint8_t)defrsp_status;

        /* Form the ZCL Header */
        memset(&zcl_hdr, 0, sizeof(zcl_hdr));
        zcl_hdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
        zcl_hdr.frameCtrl.manufacturer = 0U;
        zcl_hdr.frameCtrl.direction = ZCL_DIRECTION_TO_CLIENT;
        zcl_hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
        zcl_hdr.manufacturerCode = 0x0000U;
        zcl_hdr.seqNum = zcl_seq;
        zcl_hdr.cmdId = ZCL_COMMAND_DEFAULT_RESPONSE;
        zcl_hdr_len = ZbZclAppendHeader(&zcl_hdr, zcl_hdr_buf, sizeof(zcl_hdr_buf));
        if (zcl_hdr_len < 0) {
            /* should never get here */
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }

        /* Form the vectored APS payload */
        bufv[0].data = zcl_hdr_buf;
        bufv[0].len = (unsigned int)zcl_hdr_len;
        bufv[1].data = payload;
        bufv[1].len = sizeof(payload);

        /* Fill in the APSDE-DATA.request. */
        (void)memset(&dataReq, 0, sizeof(dataReq));
        dataReq.dst = data_ind->src;
        dataReq.profileId = cluster->profileId;
        dataReq.clusterId = (uint16_t)ZCL_CLUSTER_ALARMS;
        dataReq.srcEndpt = cluster->endpoint;
        dataReq.asdu = bufv;
        dataReq.asduLength = 2;
        dataReq.txOptions = ZbZclTxOptsFromSecurityStatus(data_ind->securityStatus);
        dataReq.txOptions |= (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_VECTOR;
        dataReq.discoverRoute = 0;
        dataReq.radius = 0;

        ZCL_LOG_PRINTF(cluster->zb, __func__,
            "Sending Default Response, ep = %d to %d, cl = 0x%04x, dst = 0x%04x, cmd = 0x%02x, status = 0x%02x",
            dataReq.srcEndpt, dataReq.dst.endpoint, dataReq.clusterId, dataReq.dst.nwkAddr,
            payload[0], payload[1]);

        if (ZbApsdeDataReqCallback(cluster->zb, &dataReq, NULL, NULL) != ZB_STATUS_SUCCESS) {
            /* Ignored */
        }
    }
    return rc;
}
