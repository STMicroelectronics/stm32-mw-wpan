/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.identify.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster;

    /* Identify Information */
    struct ZbTimerT *timer;
    ZbZclIdentifyCallbackT callback;
};

static enum ZclStatusCodeT zcl_attr_read_cb(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, uint8_t *data,
    unsigned int maxlen, void *app_cb_arg);

static enum ZclStatusCodeT zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attributeId,
    const uint8_t *inputData, unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg);

static enum ZclStatusCodeT
zcl_attr_cb(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrCbInfoT *cb)
{
    if (cb->type == ZCL_ATTR_CB_TYPE_READ) {
        return zcl_attr_read_cb(clusterPtr, cb->info->attributeId, cb->zcl_data, cb->zcl_len, cb->app_cb_arg);
    }
    else if (cb->type == ZCL_ATTR_CB_TYPE_WRITE) {
        return zcl_attr_write_cb(clusterPtr, cb->src, cb->info->attributeId, cb->zcl_data, cb->zcl_len,
            cb->attr_data, cb->write_mode, cb->app_cb_arg);
    }
    else {
        return ZCL_STATUS_FAILURE;
    }
}

/* Identify attribute list. The application can override these with
 * their own implementation. */
static const struct ZbZclAttrT zcl_identify_server_default_list[] =
{
    /* Identify Attributes */
    {
        ZCL_IDENTIFY_ATTR_TIME, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
};

static void zcl_identify_server_timeout(struct ZigBeeT *zb, void *arg);

static enum ZclStatusCodeT zcl_identify_server_handle_command(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

static void zcl_identify_server_cleanup(struct ZbZclClusterT *clusterPtr);

struct ZbZclClusterT *
ZbZclIdentifyServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_IDENTIFY, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    clusterPtr->cluster.command = zcl_identify_server_handle_command;
    clusterPtr->cluster.cleanup = zcl_identify_server_cleanup;

    /* Initialize the identify cluster attributes. */
    clusterPtr->callback = NULL;

    clusterPtr->timer = ZbTimerAlloc(zb, zcl_identify_server_timeout, clusterPtr);
    if (clusterPtr->timer == NULL) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_identify_server_default_list, ZCL_ATTR_LIST_LEN(zcl_identify_server_default_list))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static void
zcl_identify_server_cleanup(struct ZbZclClusterT *clusterPtr)
{
    struct cluster_priv_t *identifyPtr = (struct cluster_priv_t *)clusterPtr;

    if (identifyPtr->timer != NULL) {
        ZbTimerFree(identifyPtr->timer);
        identifyPtr->timer = NULL;
    }
}

void
ZbZclIdentifyServerSetCallback(struct ZbZclClusterT *cluster, ZbZclIdentifyCallbackT callback)
{
    struct cluster_priv_t *identifyPtr = (struct cluster_priv_t *)cluster;

    identifyPtr->callback = callback;
}

uint16_t
ZbZclIdentifyServerGetTime(struct ZbZclClusterT *cluster)
{
    struct cluster_priv_t *identifyPtr = (void *)cluster;
    unsigned int remain;

    remain = ZbTimerRemaining(identifyPtr->timer);
    if (remain > 0U) {
        /* Convert to seconds, but round up. */
        remain = ((remain - 1) / 1000) + 1;
    }
    if (remain > 0xffffU) {
        /* Should never get here */
        remain = ZCL_INVALID_UNSIGNED_16BIT;
    }
    return remain;
}

void
ZbZclIdentifyServerSetTime(struct ZbZclClusterT *cluster, uint16_t seconds)
{
    enum ZbZclIdentifyServerStateT state;
    struct cluster_priv_t *identifyPtr = (struct cluster_priv_t *)cluster;
    uint8_t mode;
    enum ZbBdbCommissioningStatusT bdbStatus;

    (void)ZbBdbGet(cluster->zb, ZB_BDB_CommissioningMode, &mode, sizeof(mode));
    if ((seconds > 0U) && ((mode & BDB_COMMISSION_MODE_FIND_BIND) != 0U)) {
        uint8_t bdbMinTime = 0;

        /* If using finding & binding, identify time must be at least
         * ZB_BDBC_MinCommissioningTime, unless explicitly zero (disabled). */
        (void)ZbBdbGet(cluster->zb, ZB_BDBC_MinCommissioningTime, &bdbMinTime, sizeof(uint8_t));
        if (seconds < bdbMinTime) {
            ZCL_LOG_PRINTF(cluster->zb, __func__, "Finding & Binding overriding Identify Time to be %d seconds", bdbMinTime);
            seconds = bdbMinTime;
        }
    }

    /* Update the identify time counter. */
    if (seconds > 0U) {
        ZbTimerReset(identifyPtr->timer, seconds * 1000);
        state = ZCL_IDENTIFY_START;
        bdbStatus = ZB_BDB_COMMISS_STATUS_IN_PROGRESS;
    }
    else {
        ZbTimerStop(identifyPtr->timer);
        state = ZCL_IDENTIFY_STOP;
        bdbStatus = ZB_BDB_COMMISS_STATUS_SUCCESS;
    }

    if ((mode & BDB_COMMISSION_MODE_FIND_BIND) != 0U) {
        ZbBdbSetEndpointStatus(cluster->zb, bdbStatus, cluster->endpoint);
    }

    /* Execute the callback to start or stop identifying. */
    if (identifyPtr->callback) {
        identifyPtr->callback(cluster, state, cluster->app_cb_arg);
    }
}

static enum ZclStatusCodeT
zcl_attr_read_cb(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, uint8_t *data, unsigned int maxlen, void *app_cb_arg)
{
    switch (attributeId) {
        case ZCL_IDENTIFY_ATTR_TIME:
        {
            uint16_t identifyTime;

            if (maxlen < 2) {
                return ZCL_STATUS_INSUFFICIENT_SPACE;
            }

            /* Compute how many seconds are left to identify. */
            identifyTime = ZbZclIdentifyServerGetTime(clusterPtr);
            putle16(data, identifyTime);
            return ZCL_STATUS_SUCCESS;
        }

        default:
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attributeId,
    const uint8_t *inputData, unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg)
{
    switch (attributeId) {
        case ZCL_IDENTIFY_ATTR_TIME:
            if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) {
                uint16_t identifyTime;

                /* Parse the attribute value. */
                identifyTime = pletoh16(inputData);
                /* Don't need to write to attrData. Handled in zcl_attr_read_cb. */
                ZbZclIdentifyServerSetTime(clusterPtr, identifyTime);
            }
            return ZCL_STATUS_SUCCESS;

        default:
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
}

static enum ZclStatusCodeT
zcl_identify_server_handle_command(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *identifyPtr = (struct cluster_priv_t *)clusterPtr;
    uint16_t dblVal;

    switch (zclHdrPtr->cmdId) {
        case ZCL_IDENTIFY_COMMAND_IDENTIFY:
            /* Parse the payload (identify time). */
            if (dataIndPtr->asduLength < 2) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            /* Overwrite the identifyTime attribute. Let the write callback do all the work. */
            dblVal = pletoh16(dataIndPtr->asdu);
            return ZbZclAttrIntegerWrite(&identifyPtr->cluster, ZCL_IDENTIFY_ATTR_TIME, dblVal);

        case ZCL_IDENTIFY_COMMAND_QUERY:
        {
            uint8_t rawbuf[ZCL_HEADER_MAX_SIZE + sizeof(uint16_t)];
            uint16_t seconds = ZbZclIdentifyServerGetTime(clusterPtr);
            struct ZbZclAddrInfoT dst_info;
            struct ZbApsBufT bufv[1];
            unsigned int i = 0;

            /* The identify query command only generates a response if we are currently identifying ourself.
             * If the remaining seconds are greater, than zero, then we are identifying and should respond. */
            if (seconds == 0) {
                /* We're not identifying, just reply with Default Response. */
                if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
                    return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
                }
                else {
                    return ZCL_STATUS_SUCCESS;
                }
            }

            /* Payload: Timeout (2) */
            putle16(&rawbuf[i], seconds);
            i += 2;

            dst_info.addr = dataIndPtr->src;
            dst_info.seqnum = zclHdrPtr->seqNum;
            dst_info.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

            /* ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Sending Identify Query Response (dst = 0x%04x, opts = 0x%04x)",
                dst_info.addr.nwkAddr, dst_info.tx_options); */

            bufv[0].data = rawbuf;
            bufv[0].len = i;

            /* Send the Query response command. */
            (void)ZbZclClusterCommandRsp(clusterPtr, &dst_info, ZCL_IDENTIFY_COMMAND_QUERY_RESP, bufv, 1);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
        }

        default:
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
}

static void
zcl_identify_server_timeout(struct ZigBeeT *zb, void *arg)
{
    struct cluster_priv_t *identifyPtr = (struct cluster_priv_t *)arg;
    uint8_t mode = 0;

    (void)ZbBdbGet(identifyPtr->cluster.zb, ZB_BDB_CommissioningMode, &mode, sizeof(mode));
    if ((mode & BDB_COMMISSION_MODE_FIND_BIND) != 0U) {
        ZbBdbSetEndpointStatus(identifyPtr->cluster.zb, ZB_BDB_COMMISS_STATUS_SUCCESS, identifyPtr->cluster.endpoint);
    }

    if (identifyPtr->callback) {
        identifyPtr->callback(&identifyPtr->cluster, ZCL_IDENTIFY_STOP, identifyPtr->cluster.app_cb_arg);
    }
}
