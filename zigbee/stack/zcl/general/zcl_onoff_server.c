/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.onoff.h"

struct cluster_priv_t {
    struct ZbZclClusterT onoff_cluster;
    struct ZbZclOnOffServerCallbacksT onoff_callbacks;
    struct ZbZclClusterT *level_cluster;
    ZbZclLevelControlCallbackT level_callback;
};

/* Attributes */
static const struct ZbZclAttrT zcl_onoff_server_attr_list[] = {
    {
        ZCL_ONOFF_ATTR_ONOFF, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
};

static uint8_t onOffServerGetSceneData(struct ZbZclClusterT *clusterPtr, uint8_t *extBuf, uint8_t extMaxLen);
static enum ZclStatusCodeT onOffServerSetSceneData(struct ZbZclClusterT *clusterPtr, uint8_t *extData, uint8_t extLen, uint16_t transition_tenths);
static enum ZclStatusCodeT onOffServerCommand(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclOnOffServerAlloc(struct ZigBeeT *zb, uint8_t endpoint,
    struct ZbZclOnOffServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_ONOFF, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    if (callbacks != NULL) {
        memcpy(&clusterPtr->onoff_callbacks, callbacks, sizeof(struct ZbZclOnOffServerCallbacksT));
    }
    else {
        memset(&clusterPtr->onoff_callbacks, 0, sizeof(struct ZbZclOnOffServerCallbacksT));
    }

    /* Revision 2 implements: "ZLO 1.0: StartUpOnOff" (currently not supported) */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->onoff_cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    clusterPtr->onoff_cluster.get_scene_data = onOffServerGetSceneData;
    clusterPtr->onoff_cluster.set_scene_data = onOffServerSetSceneData;
    clusterPtr->onoff_cluster.command = onOffServerCommand;

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->onoff_cluster, zcl_onoff_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_onoff_server_attr_list))) {
        ZbZclClusterFree(&clusterPtr->onoff_cluster);
        return NULL;
    }

    (void)ZbZclAttrIntegerWrite(&clusterPtr->onoff_cluster, ZCL_ONOFF_ATTR_ONOFF, 0);

    ZbZclClusterSetCallbackArg(&clusterPtr->onoff_cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->onoff_cluster);
    return &clusterPtr->onoff_cluster;
}

static uint8_t
onOffServerGetSceneData(struct ZbZclClusterT *clusterPtr, uint8_t *extBuf, uint8_t extMaxLen)
{
    uint8_t len = 3; /* Attribute data starts at the third byte. */
    uint8_t attrVal;

    /* Write attributes first, before Cluster ID and Length */

    /* OnOff attribute */
    if (ZbZclAttrRead(clusterPtr, ZCL_ONOFF_ATTR_ONOFF, NULL, &attrVal, sizeof(attrVal), false) != ZCL_STATUS_SUCCESS) {
        return 0;
    }
    extBuf[len++] = attrVal;

    /* Cluster ID [0:1] */
    putle16(&extBuf[0], clusterPtr->clusterId);
    /* Extension Length [2] */
    extBuf[2] = len - 3;
    return len;
}

static enum ZclStatusCodeT
onOffServerSetSceneData(struct ZbZclClusterT *clusterPtr, uint8_t *extData, uint8_t extLen, uint16_t transition_tenths)
{
    uint8_t onOffVal;

    if (extLen != 1) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, invalid scene data length (%d)", extLen);
        return ZCL_STATUS_INVALID_VALUE;
    }

    onOffVal = extData[0] ? 1 : 0;

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "OnOff = %d, Transition (tenths) = %d", onOffVal, transition_tenths);

    /* Save the attribute value, and will call the application callback
     * if there was a change in state. */
    /* EXEGIN - use transition_tenths? */
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_ONOFF_ATTR_ONOFF, onOffVal);
    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
onOffServerCommand(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclAddrInfoT srcInfo;
    enum ZclStatusCodeT return_status = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

    (void)memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zclHdrPtr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    switch (zclHdrPtr->cmdId) {
        case ZCL_ONOFF_COMMAND_OFF:
            if (server->onoff_callbacks.off != NULL) {
                return_status = server->onoff_callbacks.off(clusterPtr, &srcInfo, clusterPtr->app_cb_arg);
            }
            else {
                ZbZclAttrIntegerWrite(clusterPtr, ZCL_ONOFF_ATTR_ONOFF, 0);
            }
            break;

        case ZCL_ONOFF_COMMAND_ON:
            if (server->onoff_callbacks.on != NULL) {
                return_status = server->onoff_callbacks.on(clusterPtr, &srcInfo, clusterPtr->app_cb_arg);
            }
            else {
                ZbZclAttrIntegerWrite(clusterPtr, ZCL_ONOFF_ATTR_ONOFF, 1);
            }
            break;

        case ZCL_ONOFF_COMMAND_TOGGLE:
            if (server->onoff_callbacks.toggle != NULL) {
                return_status = server->onoff_callbacks.toggle(clusterPtr, &srcInfo, clusterPtr->app_cb_arg);
            }
            else {
                uint8_t attrVal;

                if (ZbZclAttrRead(clusterPtr, ZCL_ONOFF_ATTR_ONOFF, NULL, &attrVal, sizeof(attrVal), false) != ZCL_STATUS_SUCCESS) {
                    /* Should never get here */
                    return_status = ZCL_STATUS_UNSUPP_ATTRIBUTE;
                    break;
                }

                /* Toggle the value */
                attrVal = attrVal ? 0 : 1;
                ZbZclAttrIntegerWrite(clusterPtr, ZCL_ONOFF_ATTR_ONOFF, attrVal);
            }
            break;

        default:
            return_status = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }

    if ((return_status == ZCL_STATUS_SUCCESS) && (server->level_callback != NULL)) {
        server->level_callback(server->level_cluster, zclHdrPtr->cmdId);
    }
    return return_status;
}

void
ZbZclOnOffServerSetLevelControlCallback(struct ZbZclClusterT *on_off_cluster, struct ZbZclClusterT *level_cluster,
    ZbZclLevelControlCallbackT levelControlCallback)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)on_off_cluster;

    server->level_cluster = level_cluster;
    server->level_callback = levelControlCallback;
}
