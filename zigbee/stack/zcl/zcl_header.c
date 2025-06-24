/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"

int
ZbZclParseHeader(struct ZbZclHeaderT *zclHdrPtr, const uint8_t *buf, unsigned int len)
{
    unsigned int hdrLen = 0;

    /* Check the input length */
    if (len < ZCL_HEADER_MIN_SIZE) {
        return -1;
    }

    /* Initialize the frame header. */
    (void)memset(zclHdrPtr, 0, sizeof(struct ZbZclHeaderT));

    /* Parse the frame control field. */
    zclHdrPtr->frameCtrl.frameType = buf[hdrLen] & ZCL_FRAMECTRL_TYPE;
    zclHdrPtr->frameCtrl.manufacturer = ((buf[hdrLen] & ZCL_FRAMECTRL_MANUFACTURER) != 0U) ? 1U : 0U;
    zclHdrPtr->frameCtrl.direction = ((buf[hdrLen] & ZCL_FRAMECTRL_DIRECTION) != 0U) ? ZCL_DIRECTION_TO_CLIENT : ZCL_DIRECTION_TO_SERVER;
    zclHdrPtr->frameCtrl.noDefaultResp = ((buf[hdrLen] & ZCL_FRAMECTRL_DISABLE_DEFAULT_RESP) != 0U) ? ZCL_NO_DEFAULT_RESPONSE_TRUE : ZCL_NO_DEFAULT_RESPONSE_FALSE;
    hdrLen++;

    /* Parse the rest of the ZCL header. */
    if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
        if (len < ZCL_HEADER_MAX_SIZE) {
            return -1;
        }
        zclHdrPtr->manufacturerCode = pletoh16(&buf[hdrLen]);
        hdrLen += 2U;
    }
    zclHdrPtr->seqNum = buf[hdrLen++];
    zclHdrPtr->cmdId = buf[hdrLen++];

    /* EXEGIN: Any sanity checks? */
    return (int)hdrLen;
}

int
ZbZclPrependHeader(struct ZbZclHeaderT *zclHdrPtr, uint8_t *data, unsigned int len)
{
    uint8_t frameControl = 0x00;
    int i = (int)len, j = 0; /* j is for MISRA */

    /* Sanity-check the buffer space. */
    if ((zclHdrPtr->frameCtrl.manufacturer != 0U) && (len < ZCL_HEADER_MAX_SIZE)) {
        return -1;
    }
    else if (len < ZCL_HEADER_MIN_SIZE) {
        return -1;
    }
    else {
        /* empty */
    }

    /* Append the command ID and transaction sequence number. */
    data[--i] = zclHdrPtr->cmdId;
    j++;
    data[--i] = zclHdrPtr->seqNum;
    j++;

    /* If this is a manufacturer-specific command, append the manufacturer code. */
    if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
        data[--i] = (uint8_t)(zclHdrPtr->manufacturerCode >> 8U) & 0xffU;
        j++;
        data[--i] = (uint8_t)(zclHdrPtr->manufacturerCode >> 0) & 0xffU;
        j++;
    }

    /* Build the frame control field. */
    frameControl |= (zclHdrPtr->frameCtrl.frameType & ZCL_FRAMECTRL_TYPE);
    if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
        frameControl |= ZCL_FRAMECTRL_MANUFACTURER;
    }
    if (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_CLIENT) {
        frameControl |= ZCL_FRAMECTRL_DIRECTION;
    }
    if (zclHdrPtr->frameCtrl.noDefaultResp == ZCL_NO_DEFAULT_RESPONSE_TRUE) {
        frameControl |= ZCL_FRAMECTRL_DISABLE_DEFAULT_RESP;
    }
    data[--i] = frameControl;
    (void)i; /* keep MISRA happy! */
    j++;

    return j;
}

int
ZbZclAppendHeader(struct ZbZclHeaderT *zclHdrPtr, uint8_t *data, unsigned int max_len)
{
    uint8_t frameControl = 0x00;
    int i = 0;

    /* Sanity-check the buffer space. */
    if ((zclHdrPtr->frameCtrl.manufacturer != 0U) && (max_len < ZCL_HEADER_MAX_SIZE)) {
        return -1;
    }
    else if (max_len < ZCL_HEADER_MIN_SIZE) {
        return -1;
    }
    else {
        /* empty */
    }

    /* Build the frame control field. */
    frameControl |= (zclHdrPtr->frameCtrl.frameType & ZCL_FRAMECTRL_TYPE);
    if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
        frameControl |= ZCL_FRAMECTRL_MANUFACTURER;
    }
    if (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_CLIENT) {
        frameControl |= ZCL_FRAMECTRL_DIRECTION;
    }
    if (zclHdrPtr->frameCtrl.noDefaultResp == ZCL_NO_DEFAULT_RESPONSE_TRUE) {
        frameControl |= ZCL_FRAMECTRL_DISABLE_DEFAULT_RESP;
    }
    data[i++] = frameControl;

    /* If this is a manufacturer-specific command, append the manufacturer code. */
    if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
        data[i++] = (uint8_t)zclHdrPtr->manufacturerCode & 0xffU;
        data[i++] = (uint8_t)(zclHdrPtr->manufacturerCode >> 8U) & 0xffU;
    }

    /* Append the command ID and transaction sequence number. */
    data[i++] = zclHdrPtr->seqNum;
    data[i++] = zclHdrPtr->cmdId;

    /* Done. */
    return i;
}
