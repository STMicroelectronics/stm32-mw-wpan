/* Copyright [2020 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/zcl.h"
#include "zcl_attr.h"

void
ZbZclHandleGetSceneData(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind)
{
    uint8_t extLen;
    uint8_t buf[ZB_APS_CONST_MAX_PAYLOAD_SIZE - ZCL_HEADER_MAX_SIZE];
    struct ZbApsdeDataReqT dataReq;
    struct ZbZclHeaderT zclRspHdr;
    int len;
    uint32_t offset;

    if (!clusterPtr->get_scene_data) {
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_UNSUPP_COMMAND);
        return;
    }

    /* Construct the ZCL header. */
    (void)memset(&zclRspHdr, 0, sizeof(struct ZbZclHeaderT));
    zclRspHdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    zclRspHdr.frameCtrl.manufacturer = 1;
    if (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_SERVER) {
        zclRspHdr.frameCtrl.direction = ZCL_DIRECTION_TO_CLIENT;
    }
    else {
        zclRspHdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
    }
    zclRspHdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;

    zclRspHdr.manufacturerCode = ZCL_MANUF_CODE_INTERNAL;
    zclRspHdr.seqNum = zclHdrPtr->seqNum;
    zclRspHdr.cmdId = ZCL_CMD_MANUF_INTERNAL_GET_SCENE_EXTDATA;
    len = ZbZclAppendHeader(&zclRspHdr, buf, clusterPtr->maxAsduLength);
    if (len < 0) {
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }
    offset = (uint32_t)len;

    /* ZCL payload */
    extLen = clusterPtr->get_scene_data(clusterPtr, &buf[offset], (uint8_t)(sizeof(buf) - offset));
    if (extLen == 0U) {
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_UNSUPP_COMMAND);
        return;
    }
    offset += extLen;

    /* Fill in the APSDE-DATA.request. */
    ZbZclClusterInitApsdeReq(clusterPtr, &dataReq, ind);
    dataReq.dst = ind->src;
    dataReq.txOptions = 0x00;
    dataReq.discoverRoute = false;
    dataReq.radius = 0;
    dataReq.asdu = buf;
    dataReq.asduLength = (uint16_t)offset;

    /* Send the APSDE-DATA.request without blocking. */
    if (ZbApsdeDataReqCallback(clusterPtr->zb, &dataReq, NULL, NULL) != ZB_APS_STATUS_SUCCESS) {
        /* Ignored */
    }
}

void
ZbZclHandleSetSceneData(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind)
{
    enum ZclStatusCodeT status;
    uint8_t extLen;
    uint8_t buf[ZB_APS_CONST_MAX_PAYLOAD_SIZE - ZCL_HEADER_MAX_SIZE];
    struct ZbApsdeDataReqT dataReq;
    struct ZbZclHeaderT zclRspHdr;
    int len;
    uint32_t offset;
    uint32_t transition_tenths;

    if (clusterPtr->set_scene_data == NULL) {
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_UNSUPP_COMMAND);
        return;
    }

    if (ind->asduLength < (uint16_t)SET_SCENE_EXTDATA_HEADER_LEN) {
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    transition_tenths = pletoh32(&ind->asdu[0]);

    extLen = ind->asdu[SET_SCENE_EXTDATA_OFFSET_EXT_LEN];

    if ((SET_SCENE_EXTDATA_HEADER_LEN + extLen) < ind->asduLength) {
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    status = clusterPtr->set_scene_data(clusterPtr, &ind->asdu[SET_SCENE_EXTDATA_OFFSET_EXT_FIELD], extLen, (uint16_t)transition_tenths);

    /* Construct the ZCL Response Header. */
    (void)memset(&zclRspHdr, 0, sizeof(struct ZbZclHeaderT));
    zclRspHdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    zclRspHdr.frameCtrl.manufacturer = 1;
    if (zclHdrPtr->frameCtrl.direction == ZCL_DIRECTION_TO_SERVER) {
        zclRspHdr.frameCtrl.direction = ZCL_DIRECTION_TO_CLIENT;
    }
    else {
        zclRspHdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
    }
    zclRspHdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;

    zclRspHdr.manufacturerCode = ZCL_MANUF_CODE_INTERNAL;
    zclRspHdr.seqNum = zclHdrPtr->seqNum;
    zclRspHdr.cmdId = ZCL_CMD_MANUF_INTERNAL_SET_SCENE_EXTDATA;
    len = ZbZclAppendHeader(&zclRspHdr, buf, clusterPtr->maxAsduLength);
    if (len < 0) {
        ZbZclSendDefaultResponse(clusterPtr, ind, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }
    offset = (uint32_t)len;

    /* ZCL Payload (status code) */
    buf[offset++] = (uint8_t)status;

    /* Fill in the APSDE-DATA.request. */
    ZbZclClusterInitApsdeReq(clusterPtr, &dataReq, ind);
    dataReq.dst = ind->src;
    dataReq.txOptions = 0x00;
    dataReq.discoverRoute = false;
    dataReq.radius = 0;
    dataReq.asdu = buf;
    dataReq.asduLength = (uint16_t)offset;

    /* Send the APSDE-DATA.request without blocking. */
    if (ZbApsdeDataReqCallback(clusterPtr->zb, &dataReq, NULL, NULL) != ZB_APS_STATUS_SUCCESS) {
        /* Ignored */
    }
}
