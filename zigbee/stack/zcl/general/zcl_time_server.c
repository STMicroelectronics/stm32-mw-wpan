/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/zcl.h"
#include "zcl/general/zcl.time.h"

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

/* The only way to suppress the following Flexelint exemption is to cast to uin16_t after each bitwise OR */
/*lint -save -e9027 -e9029 "unpermitted operand to '|' [MISRA Rule 10.4 (REQUIRED)]" */
static const struct ZbZclAttrT time_attr_default_list[] = {
    /* EXEGIN - add persist flag to some of these writable attributes? ZCL_ATTR_FLAG_PERSISTABLE */
    {
        ZCL_TIME_ATTR_TIME, ZCL_DATATYPE_TIME_UTC,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_TIME_ATTR_STATUS, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_TIME_ATTR_TIME_ZONE, ZCL_DATATYPE_SIGNED_32BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_TIME_ATTR_DST_START, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_TIME_ATTR_DST_END, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_TIME_ATTR_DST_SHIFT, ZCL_DATATYPE_SIGNED_32BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_TIME_ATTR_STANDARD_TIME, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_TIME_ATTR_LOCAL_TIME, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_TIME_ATTR_LAST_SET_TIME, ZCL_DATATYPE_TIME_UTC,
        ZCL_ATTR_FLAG_NONE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_TIME_ATTR_VALID_UNTIL_TIME, ZCL_DATATYPE_TIME_UTC,
        ZCL_ATTR_FLAG_WRITABLE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
};
/*lint -restore */

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* must be first for inheritence */

    struct ZbZclTimeServerCallbacks callbacks;

    /* Clock status */
    bool isSynchronized;
    bool isMaster;
    bool isLocalMaster;
    bool isSuperseding;

    /* Local time information. */
    int32_t timeZone;
    int32_t dstShift;
    uint32_t dstStart;
    uint32_t dstEnd;
    uint32_t lastSetTime;
};

struct ZbZclClusterT *
ZbZclTimeServerAlloc(struct ZigBeeT *zb, uint8_t endpoint,
    struct ZbZclTimeServerCallbacks *callbacks, void *arg)
{
    struct cluster_priv_t *server;

    /* Must provide set and get callbacks */
    if ((callbacks == NULL) || (callbacks->get_time == NULL) || (callbacks->set_time == NULL)) {
        return NULL;
    }
    server = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_TIME, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (server == NULL) {
        return NULL;
    }

    memcpy(&server->callbacks, callbacks, sizeof(struct ZbZclTimeServerCallbacks));
    ZbZclClusterSetCallbackArg(&server->cluster, arg);

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&server->cluster, time_attr_default_list,
            ZCL_ATTR_LIST_LEN(time_attr_default_list)) != ZCL_STATUS_SUCCESS) {
        ZbZclClusterFree(&server->cluster);
        return NULL;
    }

    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_TIME_ATTR_STATUS, 0x00);
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_TIME_ATTR_TIME_ZONE, 0);
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_TIME_ATTR_DST_SHIFT, 0);
    (void)ZbZclAttrIntegerWrite(&server->cluster, ZCL_TIME_ATTR_VALID_UNTIL_TIME, 0xffffffffLL);

    (void)ZbZclClusterAttach(&server->cluster);
    return &server->cluster;
}

static enum ZclStatusCodeT
zcl_attr_read_cb(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, uint8_t *data,
    unsigned int maxlen, void *app_cb_arg)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)clusterPtr;
    uint32_t rtc;
    enum ZclStatusCodeT rc = ZCL_STATUS_SUCCESS;

    rtc = ZbZclTimeServerCurrentTime(clusterPtr);

    /* Handle the attribute. */
    switch (attributeId) {
        case ZCL_TIME_ATTR_TIME:
            /* Return the current time. */
            if (maxlen < 4U) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Ignoring request (buffer too small).");
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            putle32(data, rtc);
            break;

        case ZCL_TIME_ATTR_STATUS:
            if (maxlen < 1U) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Ignoring request (buffer too small).");
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            data[0] = 0;
            if (server->isMaster) {
                data[0] |= ZCL_TIME_STATUS_MASTER;
            }
            if (server->isSynchronized) {
                data[0] |= ZCL_TIME_STATUS_SYNCHRONIZED;
            }
            if (server->isLocalMaster) {
                data[0] |= ZCL_TIME_STATUS_ZONE_MASTER;
            }
            if (server->isSuperseding) {
                data[0] |= ZCL_TIME_STATUS_SUPERSEDING;
            }
            break;

        case ZCL_TIME_ATTR_TIME_ZONE:
            if (maxlen < 4U) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Ignoring request (buffer too small).");
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            putle32(data, (uint32_t)server->timeZone);
            break;

        case ZCL_TIME_ATTR_DST_START:
            if (maxlen < 4U) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Ignoring request (buffer too small).");
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            putle32(data, server->dstStart);
            break;

        case ZCL_TIME_ATTR_DST_END:
            if (maxlen < 4U) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Ignoring request (buffer too small).");
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            putle32(data, server->dstEnd);
            break;

        case ZCL_TIME_ATTR_DST_SHIFT:
            if (maxlen < 4U) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Ignoring request (buffer too small).");
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            putle32(data, (uint32_t)server->dstShift);
            break;

        case ZCL_TIME_ATTR_LOCAL_TIME:
            /* Local Time = UTC + time zone + DST. */
            if ((server->dstShift != 0U) && (rtc > server->dstStart) && (rtc < server->dstEnd)) {
                /* If daylight savings time is in effect, then add the time zone and the dst shift. */
                rtc = (uint32_t)((int32_t)rtc + server->dstShift);
            }
        /*lint -fallthrough */

        case ZCL_TIME_ATTR_STANDARD_TIME:
            /* Standard Time = UTC + time zone. */
            if (maxlen < 4U) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Ignoring request (buffer too small).");
                rc = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            rtc += server->timeZone;
            putle32(data, rtc);
            break;

        default:
            /* Unknown attribute identifier. */
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Ignoring request (unsupported attribute).");
            rc = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            break;
    }
    return rc;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src,
    uint16_t attributeId, const uint8_t *inputData, unsigned int inputMaxLen,
    void *attrData, ZclWriteModeT mode, void *app_cb_arg)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)clusterPtr;
    enum ZclStatusCodeT rc = ZCL_STATUS_SUCCESS;

    switch (attributeId) {
        case ZCL_TIME_ATTR_TIME:
            if (inputMaxLen < 4U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            /* Unless the write is being forced, check if the time is writable. */
            if ((mode & ZCL_ATTR_WRITE_FLAG_FORCE) == 0U) {
                /* The time attribute is read only if we're the master clock. */
                if (server->isMaster) {
                    rc = ZCL_STATUS_READ_ONLY;
                    break;
                }
                /* If just testing, return SUCCESS now. */
                if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) != 0U) {
                    break;
                }
            }

            /* Update our RTC. */
            ZbZclTimeServerSetTime(clusterPtr, pletoh32(inputData));

            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Setting current time to 0x%08x.", pletoh32(inputData));
            break;

        case ZCL_TIME_ATTR_STATUS:
        {
            uint8_t statusVal;

            if (inputMaxLen < 1U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            /* If just testing, return SUCCESS now. */
            if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) != 0U) {
                break;
            }

            statusVal = *inputData;

            /* The synchronized bit is always writable. */
            if ((statusVal & ZCL_TIME_STATUS_SYNCHRONIZED) != 0U) {
                server->isSynchronized = true;
            }
            else {
                server->isSynchronized = false;
            }

            /* If the write is being forced, overwrite the master bits too. */
            if ((mode & ZCL_ATTR_WRITE_FLAG_FORCE) != 0U) {
                if ((statusVal & ZCL_TIME_STATUS_MASTER) != 0U) {
                    server->isMaster = true;
                }
                else {
                    server->isMaster = false;
                }
                if ((statusVal & ZCL_TIME_STATUS_ZONE_MASTER) != 0U) {
                    server->isLocalMaster = true;
                }
                else {
                    server->isLocalMaster = false;
                }
                if ((statusVal & ZCL_TIME_STATUS_SUPERSEDING) != 0U) {
                    server->isSuperseding = true;
                }
                else {
                    server->isSuperseding = false;
                }
            }
            break;
        }

        case ZCL_TIME_ATTR_TIME_ZONE:
        {
            int32_t timeZone;

            if (inputMaxLen < 4U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            /* Unless the write is being forced, check if the time zone is writable */
            if ((mode & ZCL_ATTR_WRITE_FLAG_FORCE) == 0U) {
                /* The time attribute is read only if we're the time zone master. */
                if (server->isLocalMaster) {
                    rc = ZCL_STATUS_READ_ONLY;
                    break;
                }
                /* If just testing, return SUCCESS now. */
                if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) != 0U) {
                    break;
                }
            }

            timeZone = (int32_t)pletoh32(inputData);
            if ((timeZone < ZCL_TIME_TIME_ZONE_MIN) || (timeZone > ZCL_TIME_TIME_ZONE_MAX)) {
                rc = ZCL_STATUS_INVALID_VALUE;
                break;
            }
            server->timeZone = timeZone;
            break;
        }

        case ZCL_TIME_ATTR_DST_START:
            if (inputMaxLen < 4U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            /* Unless the write is being forced, check if the DST is writable. */
            if ((mode & ZCL_ATTR_WRITE_FLAG_FORCE) == 0U) {
                /* The time attribute is read-only if we're the time zone master. */
                if (server->isLocalMaster) {
                    rc = ZCL_STATUS_READ_ONLY;
                    break;
                }
                /* If just testing, return SUCCESS now. */
                if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) != 0U) {
                    break;
                }
            }
            /* Otherwise, overwrite our current time zone. */
            server->dstStart = pletoh32(inputData);
            break;

        case ZCL_TIME_ATTR_DST_END:
            if (inputMaxLen < 4U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            /* Unless the write is being forced, check if the DST is writable. */
            if ((mode & ZCL_ATTR_WRITE_FLAG_FORCE) == 0U) {
                /* The time attribute is read only if we're the time zone master. */
                if (server->isLocalMaster) {
                    rc = ZCL_STATUS_READ_ONLY;
                    break;
                }
                /* If just testing, return SUCCESS now. */
                if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) != 0U) {
                    break;
                }
            }
            /* Otherwise, overwrite our current time zone. */
            server->dstEnd = pletoh32(inputData);
            break;

        case ZCL_TIME_ATTR_DST_SHIFT:
        {
            int32_t dstShift;

            if (inputMaxLen < 4U) {
                rc = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }
            /* Unless the write is being forced, check if the DST is writable. */
            if ((mode & ZCL_ATTR_WRITE_FLAG_FORCE) == 0U) {
                /* The time attribute is read only if we're the time zone master. */
                if (server->isLocalMaster) {
                    rc = ZCL_STATUS_READ_ONLY;
                    break;
                }
                /* If just testing, return SUCCESS now. */
                if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) != 0U) {
                    break;
                }
            }

            dstShift = (int32_t)pletoh32(inputData);
            if ((dstShift < ZCL_TIME_DST_SHIFT_MIN) || (dstShift > ZCL_TIME_DST_SHIFT_MAX)) {
                rc = ZCL_STATUS_INVALID_VALUE;
                break;
            }
            server->dstShift = dstShift;
            break;
        }

        case ZCL_TIME_ATTR_STANDARD_TIME:
        case ZCL_TIME_ATTR_LOCAL_TIME:
            /* These are always read-only attributes - (ignore forced writes). */
            rc = ZCL_STATUS_READ_ONLY;
            break;

        default:
            /* Unknown attribute identifier. */
            rc = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            break;
    }
    return rc;
}

uint32_t
ZbZclTimeServerCurrentTime(struct ZbZclClusterT *cluster)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)cluster;

    return server->callbacks.get_time(cluster, cluster->app_cb_arg);
}

void
ZbZclTimeServerSetTime(struct ZbZclClusterT *cluster, uint32_t current_time)
{
    struct cluster_priv_t *server = (struct cluster_priv_t *)cluster;

    server->callbacks.set_time(cluster, current_time, cluster->app_cb_arg);
}
