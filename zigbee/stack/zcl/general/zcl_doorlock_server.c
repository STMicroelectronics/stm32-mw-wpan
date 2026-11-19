/* Copyright [2017 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.doorlock.h"

/* Operational settings. */
#define ZCL_DRLK_LANGUAGE_LENGTH             3
static const uint8_t zcl_doorlock_lang_default[] = {
    0x03, 'E', 'N', 'G' /* "ENG" */
};
#define ZCL_DRLK_SUPPORTED_NORMAL            1
#define ZCL_DRLK_LOCAL_PROG_ENABLE           1

/* Door Lock cluster */
struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct ZbZclDoorLockServerCallbacksT callbacks;
};

static enum ZclStatusCodeT cluster_command_ind(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

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
static const struct ZbZclAttrT lockAttrList[] = {
    {
        ZCL_DRLK_ATTR_LOCKSTATE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_LOCKTYPE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_ACT_ENABLED, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_DOORSTATE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_OPENEVENTS, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFFFFFFFF}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_CLOSEDEVENTS, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFFFFFFFF}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_OPENPERIOD, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_WRITABLE, 0, NULL, {0, 0xFFFF}, {0, 0}
    },
    /* User/PIN/Schedule/Log attributes */
    {
        ZCL_DRLK_ATTR_NUM_LOGRECORDS, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xFFFF}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_NUM_TOTALUSERS, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xFFFF}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_NUM_PINUSERS, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xFFFF}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_NUM_RFIDUSERS, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xFFFF}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_NUM_WD_SCHEDULES, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_NUM_YD_SCHEDULES, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_NUM_HD_SCHEDULES, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_MAX_PIN_LEN, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_MIN_PIN_LEN, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_MAX_RFID_LEN, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_MIN_RFID_LEN, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
#if 0 /* example */
    {
        ZCL_DRLK_ATTR_LOGGING, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
#endif
    {
        ZCL_DRLK_ATTR_LANGUAGE, ZCL_DATATYPE_STRING_CHARACTER,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, ZCL_DRLK_LANGUAGE_LENGTH,
        NULL, {0, 0}, {0, 0}
    },
#if 0 /* example */
    {
        ZCL_DRLK_ATTR_LED_SETTINGS, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
#endif
    {
        ZCL_DRLK_ATTR_AUTO_RELOCK, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0xFFFFFFFF}, {0, 0}
    },
#if 0 /* example */
    {
        ZCL_DRLK_ATTR_VOLUME, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0xFF}, {0, 0}
    },
#endif
    {
        ZCL_DRLK_ATTR_MODE, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {ZCL_DRLK_MODE_NORMAL, ZCL_DRLK_MODE_PASSAGE}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_SUPPORTED_MODES, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xFFFF}, {0, 0}
    },
#if 0 /* example */
    {
        ZCL_DRLK_ATTR_DEF_CFG, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xFFFF}, {0, 0}
    },
#endif
    {
        ZCL_DRLK_ATTR_LOCAL_PROG, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0}, {0, 0}
    },
#if 0 /* example */
    {
        ZCL_DRLK_ATTR_ONETOUCH_LOCK, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_INSIDE_STATUS, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_PRIV_BUTTON, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0}, {0, 0}
    },
#endif
    /* Security Settings */
    {
        ZCL_DRLK_ATTR_WRONGCODE_LIMIT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0xFF}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_TEMP_DISABLE, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0xFF}, {0, 0}
    },
#if 0 /* example */
    {
        ZCL_DRLK_ATTR_PIN_OTA, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0}, {0, 0}
    },
#endif
    {
        ZCL_DRLK_ATTR_PIN_FOR_RF, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0,
        NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_SEC_LEVEL, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0x01}, {0, 0}
    },
    /* Alarms and Event masks */
    {
        ZCL_DRLK_ATTR_ALARM_MASK, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_CB_WRITE | ZCL_ATTR_FLAG_REPORTABLE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
#if 0
    {
        ZCL_DRLK_ATTR_KEYPAD_OP_EVENT_MASK, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_RF_OP_EVENT_MASK, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_MANUAL_OP_EVENT_MASK, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_RFID_EVENT_MASK, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_KEYPAD_EVENT_MASK, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_RF_PROG_EVENT_MASK, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_DRLK_ATTR_RFID_PROG_EVENT_MASK, ZCL_DATATYPE_BITMAP_16BIT,
        ZCL_ATTR_FLAG_WRITABLE | ZCL_ATTR_FLAG_REPORTABLE, 0, NULL, {0, 0}, {0, 0}
    },
#endif
};

struct ZbZclClusterT *
ZbZclDoorLockServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclDoorLockServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_DOOR_LOCK, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "CCB 2430"
     * (need to investigate these changes) */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    if (callbacks != NULL) {
        memcpy(&clusterPtr->callbacks, callbacks, sizeof(clusterPtr->callbacks));
    }
    else {
        memset(&clusterPtr->callbacks, 0, sizeof(clusterPtr->callbacks));
    }

    clusterPtr->cluster.command = cluster_command_ind;

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, lockAttrList, ZCL_ATTR_LIST_LEN(lockAttrList))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    /* Set some initial default attribute values */
    /* Customer should set these as appropriate for them! */
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_LOCKSTATE, ZCL_DRLK_LOCKSTATE_UNDEFINED);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_LOCKTYPE, ZCL_DRLK_LOCKTYPE);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_ACT_ENABLED, ZCL_DRLK_ACT_ENABLED_DISABLED);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_MAX_PIN_LEN, ZCL_DRLK_MAX_PIN_LEN);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_MIN_PIN_LEN, ZCL_DRLK_MIN_PIN_LEN);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_MAX_RFID_LEN, ZCL_DRLK_MAX_RFID_LEN);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_MIN_RFID_LEN, ZCL_DRLK_MIN_RFID_LEN);
    ZbZclAttrStringWriteShort(&clusterPtr->cluster, ZCL_DRLK_ATTR_LANGUAGE, zcl_doorlock_lang_default);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_SUPPORTED_MODES, ZCL_DRLK_SUPPORTED_NORMAL);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_LOCAL_PROG, ZCL_DRLK_LOCAL_PROG_ENABLE);

    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_NUM_LOGRECORDS, ZCL_DRLK_LOGRECORDS_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_NUM_TOTALUSERS, ZCL_DRLK_TOTALUSERS_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_NUM_PINUSERS, ZCL_DRLK_PINUSERS_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_NUM_RFIDUSERS, ZCL_DRLK_RFIDUSERS_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_NUM_WD_SCHEDULES, ZCL_DRLK_WD_SCHEDULES_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_NUM_YD_SCHEDULES, ZCL_DRLK_YD_SCHEDULES_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_NUM_HD_SCHEDULES, ZCL_DRLK_HD_SCHEDULES_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_AUTO_RELOCK, ZCL_DRLK_AUTO_RELOCK_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_MODE, ZCL_DRLK_MODE_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_WRONGCODE_LIMIT, ZCL_DRLK_BADCODE_LIMIT_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_TEMP_DISABLE, ZCL_DRLK_TEMP_DISABLE_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_PIN_FOR_RF, ZCL_DRLK_PIN_FOR_RF_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_SEC_LEVEL, ZCL_DRLK_SEC_LEVEL_DEFAULT);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_DRLK_ATTR_ALARM_MASK, ZCL_DRLK_ALARM_DEFAULT);

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src, uint16_t attribute_id,
    const uint8_t *input_data, unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg)
{
    enum ZclStatusCodeT status = ZCL_STATUS_SUCCESS;
    unsigned int len = 0;

    switch (attribute_id) {
        case ZCL_DRLK_ATTR_ALARM_MASK:
        {
            uint16_t val;

            val = pletoh16(input_data);
            if ((val & ~(ZCL_DRLK_ALARM_CODE_MASK)) != 0U) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            len = 2;
            break;
        }

        default:
            status = ZCL_STATUS_UNSUPP_ATTRIBUTE;
            break;
    }

    if (((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) && (status == ZCL_STATUS_SUCCESS)) {
        (void)memcpy(attr_data, input_data, len);
    }
    return status;
}

static enum ZclStatusCodeT
cluster_command_ind(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *doorlock_cluster = (struct cluster_priv_t *)clusterPtr;
    struct ZbZclAddrInfoT srcInfo;
    uint8_t cmdId = zclHdrPtr->cmdId;
    enum ZclStatusCodeT return_status = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

    (void)memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zclHdrPtr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    /* this req must be headed to server. */
    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (zclHdrPtr->frameCtrl.manufacturer) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    switch (cmdId) {
        case ZCL_DRLK_CLI_LOCK:
        {
            struct ZbZclDoorLockLockDoorReqT req;

            if (doorlock_cluster->callbacks.lock == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            if (dataIndPtr->asduLength > 1) {
                req.pin_len = dataIndPtr->asdu[0];
                if ((req.pin_len > sizeof(req.pin)) || (req.pin_len > (dataIndPtr->asduLength - 1))) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                memcpy(req.pin, &dataIndPtr->asdu[1], req.pin_len);
            }

            return_status = doorlock_cluster->callbacks.lock(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_UNLOCK:
        {
            struct ZbZclDoorLockUnlockDoorReqT req;

            if (doorlock_cluster->callbacks.unlock == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            if (dataIndPtr->asduLength > 1) {
                req.pin_len = dataIndPtr->asdu[0];
                if ((req.pin_len > sizeof(req.pin)) || (req.pin_len > (dataIndPtr->asduLength - 1))) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                memcpy(req.pin, &dataIndPtr->asdu[1], req.pin_len);
            }

            return_status = doorlock_cluster->callbacks.unlock(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_TOGGLE:
        {
            struct ZbZclDoorLockToggleReqT req;

            if (doorlock_cluster->callbacks.toggle == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            if (dataIndPtr->asduLength > 1) {
                req.pin_len = dataIndPtr->asdu[0];
                if ((req.pin_len > sizeof(req.pin)) || (req.pin_len > (dataIndPtr->asduLength - 1))) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                memcpy(req.pin, &dataIndPtr->asdu[1], req.pin_len);
            }
            return_status = doorlock_cluster->callbacks.toggle(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_UNLOCK_TIMEOUT:
        {
            struct ZbZclDoorLockUnlockTimeoutReqT req;

            if (doorlock_cluster->callbacks.unlock_timeout == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 2U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.timeout = pletoh16(dataIndPtr->asdu);
            if (dataIndPtr->asduLength > 2) {
                req.pin_len = dataIndPtr->asdu[2];
                if ((req.pin_len > sizeof(req.pin)) || (req.pin_len > (dataIndPtr->asduLength - 1))) {
                    return_status = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }
                memcpy(req.pin, &dataIndPtr->asdu[3], req.pin_len);
            }
            return_status = doorlock_cluster->callbacks.unlock_timeout(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_GET_LOG:
        {
            struct ZbZclDoorLockGetLogReqT req;

            if (doorlock_cluster->callbacks.get_log == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 2U) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.log_index = pletoh16(dataIndPtr->asdu);
            return_status = doorlock_cluster->callbacks.get_log(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_SETPIN:
        {
            struct ZbZclDoorLockSetPinReqT req;

            if (doorlock_cluster->callbacks.set_pin == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 5) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.user_id = pletoh16(dataIndPtr->asdu);
            req.user_status = dataIndPtr->asdu[2];
            req.user_type = dataIndPtr->asdu[3];
            req.pin_len = dataIndPtr->asdu[4];
            (void)memcpy(req.pin, &dataIndPtr->asdu[5], req.pin_len);
            return_status = doorlock_cluster->callbacks.set_pin(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_GETPIN:
        {
            struct ZbZclDoorLockGetPinReqT req;

            if (doorlock_cluster->callbacks.get_pin == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 2) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.user_id = pletoh16(dataIndPtr->asdu);
            return_status = doorlock_cluster->callbacks.get_pin(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_CLRPIN:
        {
            struct ZbZclDoorLockClrPinReqT req;

            if (doorlock_cluster->callbacks.clr_pin == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 2) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.user_id = pletoh16(dataIndPtr->asdu);
            return_status = doorlock_cluster->callbacks.clr_pin(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_CLR_ALL_PINS:
            if (doorlock_cluster->callbacks.clr_all_pins == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            return_status = doorlock_cluster->callbacks.clr_all_pins(clusterPtr, &srcInfo, clusterPtr->app_cb_arg);
            break;

        case ZCL_DRLK_CLI_SETUSER_STATUS:
        {
            struct ZbZclDoorLockSetUserStatusReqT req;

            if (doorlock_cluster->callbacks.set_user_status == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 3) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.user_id = pletoh16(dataIndPtr->asdu);
            req.user_status = dataIndPtr->asdu[2];
            return_status = doorlock_cluster->callbacks.set_user_status(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_GETUSER_STATUS:
        {
            struct ZbZclDoorLockGetUserStatusReqT req;

            if (doorlock_cluster->callbacks.get_user_status == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 2) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.user_id = pletoh16(dataIndPtr->asdu);
            return_status = doorlock_cluster->callbacks.get_user_status(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_SETWD_SCHED:
        {
            struct ZbZclDoorLockSetWDScheduleReqT req;

            if (doorlock_cluster->callbacks.set_wd_sched == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 8) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }

            memset(&req, 0, sizeof(req));
            req.schedule_id = dataIndPtr->asdu[0];
            req.user_id = pletoh16(&dataIndPtr->asdu[1]);
            req.days_mask = dataIndPtr->asdu[3];
            req.start_hour = dataIndPtr->asdu[4];
            req.start_minute = dataIndPtr->asdu[5];
            req.end_hour = dataIndPtr->asdu[6];
            req.end_minute = dataIndPtr->asdu[7];
            return_status = doorlock_cluster->callbacks.set_wd_sched(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_GETWD_SCHED:
        {
            struct ZbZclDoorLockGetWDScheduleReqT req;

            if (doorlock_cluster->callbacks.get_wd_sched == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 3) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.schedule_id = dataIndPtr->asdu[0];
            req.user_id = pletoh16(&dataIndPtr->asdu[1]);
            return_status = doorlock_cluster->callbacks.get_wd_sched(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_CLRWD_SCHED:
        {
            struct ZbZclDoorLockClrWDScheduleReqT req;

            if (doorlock_cluster->callbacks.clr_wd_sched == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 3) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.schedule_id = dataIndPtr->asdu[0];
            req.user_id = pletoh16(&dataIndPtr->asdu[1]);
            return_status = doorlock_cluster->callbacks.clr_wd_sched(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_SETYD_SCHED:
        {
            struct ZbZclDoorLockSetYDScheduleReqT req;

            if (doorlock_cluster->callbacks.set_yd_sched == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 11) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.schedule_id = dataIndPtr->asdu[0];
            req.user_id = pletoh16(&dataIndPtr->asdu[1]);
            req.local_start_time = pletoh32(&dataIndPtr->asdu[3]);
            req.local_end_time = pletoh32(&dataIndPtr->asdu[7]);
            return_status = doorlock_cluster->callbacks.set_yd_sched(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_GETYD_SCHED:
        {
            struct ZbZclDoorLockGetYDScheduleReqT req;

            if (doorlock_cluster->callbacks.get_yd_sched == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 3) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.schedule_id = dataIndPtr->asdu[0];
            req.user_id = pletoh16(&dataIndPtr->asdu[1]);
            return_status = doorlock_cluster->callbacks.get_yd_sched(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_CLRYD_SCHED:
        {
            struct ZbZclDoorLockClrYDScheduleReqT req;

            if (doorlock_cluster->callbacks.clr_yd_sched == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 3) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.schedule_id = dataIndPtr->asdu[0];
            req.user_id = pletoh16(&dataIndPtr->asdu[1]);
            return_status = doorlock_cluster->callbacks.clr_yd_sched(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_SETHD_SCHED:
        {
            struct ZbZclDoorLockSetHDScheduleReqT req;

            if (doorlock_cluster->callbacks.set_hd_sched == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 10) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.schedule_id = dataIndPtr->asdu[0];
            req.local_start_time = pletoh32(&dataIndPtr->asdu[1]);
            req.local_end_time = pletoh32(&dataIndPtr->asdu[5]);
            req.operating_mode = dataIndPtr->asdu[9];
            return_status = doorlock_cluster->callbacks.set_hd_sched(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_GETHD_SCHED:
        {
            struct ZbZclDoorLockGetHDScheduleReqT req;

            if (doorlock_cluster->callbacks.get_hd_sched == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 1) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.schedule_id = dataIndPtr->asdu[0];
            return_status = doorlock_cluster->callbacks.get_hd_sched(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_CLRHD_SCHED:
        {
            struct ZbZclDoorLockClrHDScheduleReqT req;

            if (doorlock_cluster->callbacks.clr_hd_sched == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 1) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.schedule_id = dataIndPtr->asdu[0];
            return_status = doorlock_cluster->callbacks.clr_hd_sched(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_SET_USERTYPE:
        {
            struct ZbZclDoorLockSetUserTypeReqT req;

            if (doorlock_cluster->callbacks.set_user_type == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 3) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.user_id = pletoh16(dataIndPtr->asdu);
            req.user_type = dataIndPtr->asdu[2];
            return_status = doorlock_cluster->callbacks.set_user_type(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_GET_USERTYPE:
        {
            struct ZbZclDoorLockGetUserTypeReqT req;

            if (doorlock_cluster->callbacks.get_user_type == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 2) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.user_id = pletoh16(dataIndPtr->asdu);
            return_status = doorlock_cluster->callbacks.get_user_type(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_SET_RFID:
        {
            struct ZbZclDoorLockSetRfidReqT req;

            if (doorlock_cluster->callbacks.set_rfid == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 5) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.user_id = pletoh16(dataIndPtr->asdu);
            req.user_status = dataIndPtr->asdu[2];
            req.user_type = dataIndPtr->asdu[3];
            req.rfid_len = dataIndPtr->asdu[4];
            (void)memcpy(req.rfid, &dataIndPtr->asdu[5], req.rfid_len);
            return_status = doorlock_cluster->callbacks.set_rfid(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_GET_RFID:
        {
            struct ZbZclDoorLockGetRfidReqT req;

            if (doorlock_cluster->callbacks.get_rfid == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 2) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.user_id = pletoh16(dataIndPtr->asdu);
            return_status = doorlock_cluster->callbacks.get_rfid(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_CLR_RFID:
        {
            struct ZbZclDoorLockClrRfidReqT req;

            if (doorlock_cluster->callbacks.clr_rfid == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            if (dataIndPtr->asduLength < 2) {
                return_status = ZCL_STATUS_MALFORMED_COMMAND;
                break;
            }

            memset(&req, 0, sizeof(req));
            req.user_id = pletoh16(dataIndPtr->asdu);
            return_status = doorlock_cluster->callbacks.clr_rfid(clusterPtr, &req, &srcInfo, clusterPtr->app_cb_arg);
            break;
        }

        case ZCL_DRLK_CLI_CLR_ALL_RFIDS:
            if (doorlock_cluster->callbacks.clr_all_rfids == NULL) {
                return_status = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            return_status = doorlock_cluster->callbacks.clr_all_rfids(clusterPtr, &srcInfo, clusterPtr->app_cb_arg);
            break;

        default:
            return_status = ZCL_STATUS_UNSUPP_COMMAND;
            break;
    }
    return return_status;
}

static enum ZclStatusCodeT
zcl_doorlock_send_status_rsp(struct ZbZclClusterT *clusterPtr, uint8_t cmd_id, struct ZbZclAddrInfoT *dst,
    uint8_t *status, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    struct ZbApsBufT bufv;

    bufv.data = status;
    bufv.len = 1U;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, cmd_id, &bufv, 1U, callback, arg);
}

static enum ZclStatusCodeT
zcl_doorlock_lock_rsp(struct ZbZclClusterT *clusterPtr, uint8_t cmd_id, struct ZbZclAddrInfoT *dst,
    uint8_t *status, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    return zcl_doorlock_send_status_rsp(clusterPtr, cmd_id, dst, status, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendLockRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockLockDoorRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    return zcl_doorlock_lock_rsp(clusterPtr, ZCL_DRLK_SVR_LOCK_RSP, dst, &rsp->status, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendUnlockRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockUnlockDoorRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    return zcl_doorlock_lock_rsp(clusterPtr, ZCL_DRLK_SVR_UNLOCK_RSP, dst, &rsp->status, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendToggleRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockToggleRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    return zcl_doorlock_lock_rsp(clusterPtr, ZCL_DRLK_SVR_TOGGLE_RSP, dst, &rsp->status, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendUnlockTimeoutRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockUnlockTimeoutRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    return zcl_doorlock_lock_rsp(clusterPtr, ZCL_DRLK_SVR_UNLOCK_TO_RSP, dst, &rsp->status, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendGetLogRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockGetLogRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    putle16(&payload[len], rsp->log_entry_id);
    len += 2;
    putle32(&payload[len], rsp->time_stamp);
    len += 4;
    payload[len++] = rsp->event_type;
    payload[len++] = rsp->source;
    payload[len++] = rsp->alarm_code;
    putle16(&payload[len], rsp->user_id);
    len += 2;
    payload[len++] = rsp->pin_len;
    (void)memcpy(&payload[len], &rsp->pin, rsp->pin_len);
    len += rsp->pin_len;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_GET_LOG_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendSetPinRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockSetPinRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_SETPIN_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendGetPinRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockGetPinRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    putle16(&payload[len], rsp->user_id);
    len += 2;
    payload[len++] = rsp->user_status;
    payload[len++] = rsp->user_type;
    payload[len++] = rsp->pin_len;
    (void)memcpy(&payload[len], &rsp->pin, rsp->pin_len);
    len += rsp->pin_len;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_GETPIN_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendClrPinRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockClrPinRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_CLRPIN_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendClrAllPinRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockClrAllPinRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_CLR_ALL_PINS_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendSetUserStatusRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockSetUserStatusRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_SETUSER_STATUS_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendGetUserStatusRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockGetUserStatusRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[3];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    putle16(&payload[len], rsp->user_id);
    len += 2;
    payload[len++] = rsp->user_status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_GETUSER_STATUS_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendSetWDScheduleRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockSetWDScheduleRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_SETWD_SCHED_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendGetWDScheduleRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockGetWDScheduleRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[9];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->schedule_id;
    putle16(&payload[len], rsp->user_id);
    len += 2;
    payload[len++] = rsp->status;
    if (rsp->status == ZCL_STATUS_SUCCESS) {
        payload[len++] = rsp->days_mask;
        payload[len++] = rsp->start_hour;
        payload[len++] = rsp->start_minute;
        payload[len++] = rsp->end_hour;
        payload[len++] = rsp->end_minute;
    }

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_GETWD_SCHED_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendClrWDScheduleRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockClrWDScheduleRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_CLRWD_SCHED_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendSetYDScheduleRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockSetYDScheduleRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_SETYD_SCHED_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendGetYDScheduleRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockGetYDScheduleRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[12];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->schedule_id;
    putle16(&payload[len], rsp->user_id);
    len += 2;
    payload[len++] = rsp->status;
    if (rsp->status == ZCL_STATUS_SUCCESS) {
        putle32(&payload[len], rsp->local_start_time);
        len += 4;
        putle32(&payload[len], rsp->local_end_time);
        len += 4;
    }

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_GETYD_SCHED_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendClrYDScheduleRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockClrYDScheduleRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_CLRYD_SCHED_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendSetHDScheduleRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockSetHDScheduleRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_SETHD_SCHED_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendGetHDScheduleRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockGetHDScheduleRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[11];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->schedule_id;
    payload[len++] = rsp->status;
    if (rsp->status == ZCL_STATUS_SUCCESS) {
        putle32(&payload[len], rsp->local_start_time);
        len += 4;
        putle32(&payload[len], rsp->local_end_time);
        len += 4;
        payload[len++] = rsp->operating_mode;
    }

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_GETHD_SCHED_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendClrHDScheduleRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockClrHDScheduleRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_CLRHD_SCHED_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendSetUserTypeRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockSetUserTypeRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_SET_USERTYPE_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendGetUserTypeRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockGetUserTypeRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[3];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    putle16(&payload[len], rsp->user_id);
    len += 2;
    payload[len++] = rsp->user_type;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_GET_USERTYPE_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendSetRfidRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockSetRfidRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_SET_RFID_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendGetRfidRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockGetRfidRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    putle16(&payload[len], rsp->user_id);
    len += 2;
    payload[len++] = rsp->user_status;
    payload[len++] = rsp->user_type;
    payload[len++] = rsp->rfid_len;
    (void)memcpy(&payload[len], &rsp->rfid, rsp->rfid_len);
    len += rsp->rfid_len;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_GET_RFID_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendClrRfidRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockClrRfidRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_CLR_RFID_RSP, &bufv, 1U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockServerSendClrAllRfidRsp(struct ZbZclClusterT *clusterPtr, struct ZbZclAddrInfoT *dst,
    struct ZbZclDoorLockClrAllRfidRspT *rsp, void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[1];
    uint16_t len = 0;
    struct ZbApsBufT bufv;

    payload[len++] = rsp->status;

    bufv.data = payload;
    bufv.len = len;
    return ZbZclClusterCommandRspWithCb(clusterPtr, dst, ZCL_DRLK_SVR_CLR_ALL_RFIDS_RSP, &bufv, 1U, callback, arg);
}
