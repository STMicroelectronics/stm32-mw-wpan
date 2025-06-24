/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.doorlock.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster;
};

struct ZbZclClusterT *
ZbZclDoorLockClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_DOOR_LOCK, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_doorlock_lock_req(struct ZbZclClusterT *clusterPtr, uint8_t cmd_id,
    const struct ZbApsAddrT *dst, uint8_t *pin, uint8_t pin_len, uint16_t timeout,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    if (cmd_id == ZCL_DRLK_CLI_UNLOCK_TIMEOUT) {
        putle16(&payload[length], timeout);
        length += 2;
    }
    if ((pin != NULL) && (pin_len > 0U)) {
        /* Octet String */
        if ((length + pin_len + 1) > sizeof(payload)) {
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }
        payload[length++] = pin_len;
        (void)memcpy(&payload[length], pin, pin_len);
        length += pin_len;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = cmd_id;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    if (length > 0) {
        req.payload = payload;
        req.length = length;
    }
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientLockReq(struct ZbZclClusterT *clusterPtr,
    const struct ZbApsAddrT *dst, struct ZbZclDoorLockLockDoorReqT *cmd_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    return zcl_doorlock_lock_req(clusterPtr, ZCL_DRLK_CLI_LOCK, dst,
        cmd_req->pin, cmd_req->pin_len, 0U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientUnlockReq(struct ZbZclClusterT *clusterPtr,
    const struct ZbApsAddrT *dst, struct ZbZclDoorLockUnlockDoorReqT *cmd_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    return zcl_doorlock_lock_req(clusterPtr, ZCL_DRLK_CLI_UNLOCK, dst,
        cmd_req->pin, cmd_req->pin_len, 0U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientToggleReq(struct ZbZclClusterT *clusterPtr,
    const struct ZbApsAddrT *dst, struct ZbZclDoorLockToggleReqT *cmd_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    return zcl_doorlock_lock_req(clusterPtr, ZCL_DRLK_CLI_TOGGLE, dst,
        cmd_req->pin, cmd_req->pin_len, 0U, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientUnlockTimeoutReq(struct ZbZclClusterT *clusterPtr,
    const struct ZbApsAddrT *dst, struct ZbZclDoorLockUnlockTimeoutReqT *cmd_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    return zcl_doorlock_lock_req(clusterPtr, ZCL_DRLK_CLI_UNLOCK_TIMEOUT, dst,
        cmd_req->pin, cmd_req->pin_len, cmd_req->timeout, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientGetLogReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockGetLogReqT *get_log_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[2];

    putle16(payload, get_log_req->log_index);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_GET_LOG;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 2;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientSetPinReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockSetPinReqT *set_pin_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    if ((set_pin_req->user_status == ZCL_DRLK_USER_STATUS_OCC_ENABLED)
        || (set_pin_req->user_status == ZCL_DRLK_USER_STATUS_OCC_DISABLED)) {
        if ((length + set_pin_req->pin_len + 5) > sizeof(payload)) {
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }
        putle16(&payload[length], set_pin_req->user_id);
        length += 2;
        payload[length++] = set_pin_req->user_status;
        payload[length++] = set_pin_req->user_type;
        payload[length++] = set_pin_req->pin_len;
        if (set_pin_req->pin_len) {
            (void)memcpy(&payload[length], set_pin_req->pin, set_pin_req->pin_len);
            length += set_pin_req->pin_len;
        }
    }
    else {
        return ZCL_STATUS_FAILURE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_SETPIN;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    if (length > 0) {
        req.payload = payload;
        req.length = length;
    }
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientGetPinReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockGetPinReqT *get_pin_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[2];

    putle16(payload, get_pin_req->user_id);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_GETPIN;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 2;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientClrPinReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockClrPinReqT *clr_pin_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[2];
    struct ZbZclClusterCommandReqT req;

    putle16(payload, clr_pin_req->user_id);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_CLRPIN;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 2;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientClrAllPinReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_CLR_ALL_PINS;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientSetUserStatusReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockSetUserStatusReqT *set_user_status_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    if ((set_user_status_req->user_status == ZCL_DRLK_USER_STATUS_OCC_ENABLED)
        || (set_user_status_req->user_status == ZCL_DRLK_USER_STATUS_OCC_DISABLED)
        || (set_user_status_req->user_status == ZCL_DRLK_USER_STATUS_NOT_SUPP)) {
        putle16(&payload[length], set_user_status_req->user_id);
        length += 2;
        payload[length++] = set_user_status_req->user_status;
    }
    else {
        return ZCL_STATUS_FAILURE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_SETUSER_STATUS;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    if (length > 0) {
        req.payload = payload;
        req.length = length;
    }
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientGetUserStatusReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockGetUserStatusReqT *get_user_status_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[2];
    struct ZbZclClusterCommandReqT req;

    putle16(payload, get_user_status_req->user_id);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_GETUSER_STATUS;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 2;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientSetWDScheduleReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockSetWDScheduleReqT *set_wd_sched_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[8];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    if ((set_wd_sched_req->start_hour <= ZCL_DRLK_HOURS_LIMIT) && (set_wd_sched_req->start_minute <= ZCL_DRLK_MINUTES_LIMIT)
        && (set_wd_sched_req->end_hour <= ZCL_DRLK_HOURS_LIMIT) && (set_wd_sched_req->end_minute <= ZCL_DRLK_MINUTES_LIMIT)
        && set_wd_sched_req->end_hour >= set_wd_sched_req->start_hour) {
        if ((set_wd_sched_req->end_hour == set_wd_sched_req->start_hour) && (set_wd_sched_req->end_minute < set_wd_sched_req->start_minute)) {
            return ZCL_STATUS_FAILURE;
        }
        payload[length++] = set_wd_sched_req->schedule_id;
        putle16(&payload[length], set_wd_sched_req->user_id);
        length += 2;
        payload[length++] = set_wd_sched_req->days_mask;
        payload[length++] = set_wd_sched_req->start_hour;
        payload[length++] = set_wd_sched_req->start_minute;
        payload[length++] = set_wd_sched_req->end_hour;
        payload[length++] = set_wd_sched_req->end_minute;
    }
    else {
        return ZCL_STATUS_FAILURE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_SETWD_SCHED;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    if (length > 0) {
        req.payload = payload;
        req.length = length;
    }
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientGetWDScheduleReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockGetWDScheduleReqT *get_wd_sched_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[3];

    payload[0] = get_wd_sched_req->schedule_id;
    putle16(&payload[1], get_wd_sched_req->user_id);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_GETWD_SCHED;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 3;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientClrWDScheduleReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockClrWDScheduleReqT *clr_wd_sched_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[3];
    struct ZbZclClusterCommandReqT req;

    payload[0] = clr_wd_sched_req->schedule_id;
    putle16(&payload[1], clr_wd_sched_req->user_id);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_CLRWD_SCHED;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 3;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientSetYDScheduleReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockSetYDScheduleReqT *set_yd_sched_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[11];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    if (set_yd_sched_req->local_end_time < set_yd_sched_req->local_start_time) {
        return ZCL_STATUS_FAILURE;
    }
    payload[length++] = set_yd_sched_req->schedule_id;
    putle16(&payload[length], set_yd_sched_req->user_id);
    length += 2;
    putle32(&payload[length], set_yd_sched_req->local_start_time);
    length += 4;
    putle32(&payload[length], set_yd_sched_req->local_end_time);
    length += 4;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_SETYD_SCHED;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientGetYDScheduleReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockGetYDScheduleReqT *get_yd_sched_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[3];

    payload[0] = get_yd_sched_req->schedule_id;
    putle16(&payload[1], get_yd_sched_req->user_id);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_GETYD_SCHED;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 3;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientClrYDScheduleReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockClrYDScheduleReqT *clr_yd_sched_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[3];
    struct ZbZclClusterCommandReqT req;

    payload[0] = clr_yd_sched_req->schedule_id;
    putle16(&payload[1], clr_yd_sched_req->user_id);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_CLRYD_SCHED;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 3;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientSetHDScheduleReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockSetHDScheduleReqT *set_hd_sched_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[10];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    if (set_hd_sched_req->local_end_time < set_hd_sched_req->local_start_time) {
        return ZCL_STATUS_FAILURE;
    }
    payload[length++] = set_hd_sched_req->schedule_id;
    putle32(&payload[length], set_hd_sched_req->local_start_time);
    length += 4;
    putle32(&payload[length], set_hd_sched_req->local_end_time);
    length += 4;
    payload[length++] = set_hd_sched_req->operating_mode;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_SETHD_SCHED;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientGetHDScheduleReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockGetHDScheduleReqT *get_hd_sched_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[1];

    payload[0] = get_hd_sched_req->schedule_id;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_GETHD_SCHED;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 1;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientClrHDScheduleReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockClrHDScheduleReqT *clr_hd_sched_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[1];
    struct ZbZclClusterCommandReqT req;

    payload[0] = clr_hd_sched_req->schedule_id;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_CLRHD_SCHED;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 1;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientSetUserTypeReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockSetUserTypeReqT *set_user_type_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    putle16(&payload[length], set_user_type_req->user_id);
    length += 2;
    payload[length++] = set_user_type_req->user_type;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_SET_USERTYPE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientGetUserTypeReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockGetUserTypeReqT *get_user_type_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[2];
    struct ZbZclClusterCommandReqT req;

    putle16(payload, get_user_type_req->user_id);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_GET_USERTYPE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 2;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientSetRfidReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockSetRfidReqT *set_rfid_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    if ((set_rfid_req->user_status != ZCL_DRLK_USER_STATUS_OCC_ENABLED)
        && (set_rfid_req->user_status != ZCL_DRLK_USER_STATUS_OCC_DISABLED)) {
        return ZCL_STATUS_FAILURE;
    }

    if ((length + set_rfid_req->rfid_len + 5) > sizeof(payload)) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
    putle16(&payload[length], set_rfid_req->user_id);
    length += 2;
    payload[length++] = set_rfid_req->user_status;
    payload[length++] = set_rfid_req->user_type;
    payload[length++] = set_rfid_req->rfid_len;
    if (set_rfid_req->rfid_len) {
        (void)memcpy(&payload[length], set_rfid_req->rfid, set_rfid_req->rfid_len);
        length += set_rfid_req->rfid_len;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_SET_RFID;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientGetRfidReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockGetRfidReqT *get_rfid_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[2];

    putle16(payload, get_rfid_req->user_id);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_GET_RFID;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 2;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientClrRfidReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclDoorLockClrRfidReqT *clr_rfid_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[2];
    struct ZbZclClusterCommandReqT req;

    putle16(payload, clr_rfid_req->user_id);

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_CLR_RFID;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = 2;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclDoorLockClientClrAllRfidReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_DRLK_CLI_CLR_ALL_RFIDS;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}
