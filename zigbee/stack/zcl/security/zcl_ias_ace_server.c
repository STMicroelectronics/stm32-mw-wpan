/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

/*-------------------------------------------------
 *  DESCRIPTION
 *      HA IAS devices Implementation.
 *-------------------------------------------------
 */

#include "zcl/security/zcl.ias_ace.h"
#include "../zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */

struct ZbZclIasAceZoneTableT {
    struct LinkListT link;
    uint8_t zone_id;
    enum ZbZclIasZoneServerZoneTypeT zone_type;
    uint64_t zone_addr;
    /* EXEGIN - save endpoint? */
    enum ZbZclIasZoneServerZoneStatusT zone_status;
    char zone_label[ZCL_IAS_ACE_ZONE_LABEL_STRING_MAX_LEN + 1U];
    enum ZbZclIasAceBypassPermsT bypass_perms;
    bool bypass_status;
};

struct cluster_priv_t {
    struct ZbZclClusterT cluster;

    /* List of struct ZbZclIasAceZoneTableT entries */
    struct LinkListT zone_table_list;
    unsigned int zone_table_sz;

    /* Arm/Disarm Code */
    char arm_code[ZCL_IAS_ACE_ARM_CODE_STRING_MAX_LEN + 1U];

    /* Panel Status */
    enum ZbZclIasAcePanelStatusT panel_status;
    uint8_t seconds_remain;
    enum ZbZclIasAceAudibleNotifyT audible_notify;
    enum ZbZclIasAceAlarmStatusT alarm_status;

    /* Application callbacks */
    struct ZbZclIasAceServerCallbacksT callbacks;
};

static enum ZclStatusCodeT zcl_ias_ace_server_command(struct ZbZclClusterT *clusterPtr,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);
static void zcl_ias_ace_server_cleanup(struct ZbZclClusterT *clusterPtr);
static void zcl_ias_ace_server_send_panel_status_changed(struct cluster_priv_t *serverPtr);

static void zcl_ias_ace_server_zone_table_bypass_clear(struct ZbZclClusterT *clusterPtr);

static bool zcl_ias_ace_server_zone_table_status_all_clear(struct cluster_priv_t *serverPtr);

/* keep as private for now */
const char * ZbZclIasAcePanelStatusToStr(enum ZbZclIasAcePanelStatusT panel_status);

struct ZbZclClusterT *
ZbZclIasAceServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclIasAceServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t),
            ZCL_CLUSTER_SECURITY_IAS_ANCILLARY, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }
    clusterPtr->cluster.command = zcl_ias_ace_server_command;
    clusterPtr->cluster.cleanup = zcl_ias_ace_server_cleanup;

    clusterPtr->panel_status = ZCL_IAS_ACE_PANEL_STATUS_PANEL_DISARMED;
    clusterPtr->alarm_status = ZCL_IAS_ACE_ALARM_STATUS_NO_ALARM;
    clusterPtr->audible_notify = ZCL_IAS_ACE_AUDIBLE_NOTIFY_MUTE;

    LINK_LIST_INIT(&clusterPtr->zone_table_list);

    ZbZclClusterSetCallbackArg(&clusterPtr->cluster, arg);
    if (callbacks != NULL) {
        (void)memcpy(&clusterPtr->callbacks, callbacks, sizeof(struct ZbZclIasAceServerCallbacksT));
    }
    else {
        (void)memset(&clusterPtr->callbacks, 0, sizeof(struct ZbZclIasAceServerCallbacksT));
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

bool
ZbZclIasAceServerPanelCodeConfig(struct ZbZclClusterT *cluster, const char *arm_code)
{
    struct cluster_priv_t *serverPtr = (void *)cluster;

    if (arm_code && (strlen(arm_code) > ZCL_IAS_ACE_ARM_CODE_STRING_MAX_LEN)) {
        return false;
    }
    (void)memset(serverPtr->arm_code, 0, sizeof(serverPtr->arm_code));
    if (arm_code) {
        (void)strcpy(serverPtr->arm_code, arm_code);
    }
    return true;
}

bool
ZbZclIasAceServerPanelStatusConfig(struct ZbZclClusterT *cluster, enum ZbZclIasAcePanelStatusT panel_status,
    uint8_t seconds_remain, enum ZbZclIasAceAudibleNotifyT audible_notify)
{
    struct cluster_priv_t *serverPtr = (void *)cluster;
    bool send_panel_status = false;

    if (serverPtr->panel_status == panel_status) {
        if (panel_status == ZCL_IAS_ACE_PANEL_STATUS_PANEL_DISARMED) {
            /* Already disarmed */
            return false;
        }
    }
    else {
        /* Check if trying to arm */
        switch (panel_status) {
            case ZCL_IAS_ACE_PANEL_STATUS_ARMED_STAY:
            /*lint -fallthrough */
            case ZCL_IAS_ACE_PANEL_STATUS_ARMED_NIGHT:
            /*lint -fallthrough */
            case ZCL_IAS_ACE_PANEL_STATUS_ARMED_AWAY:
            /*lint -fallthrough */
            case ZCL_IAS_ACE_PANEL_STATUS_EXIT_DELAY:
            /*lint -fallthrough */
            case ZCL_IAS_ACE_PANEL_STATUS_ARMING_STAY:
            /*lint -fallthrough */
            case ZCL_IAS_ACE_PANEL_STATUS_ARMING_NIGHT:
            /*lint -fallthrough */
            case ZCL_IAS_ACE_PANEL_STATUS_ARMING_AWAY:
                /* If arming, check if allowed */
                if ((serverPtr->panel_status == ZCL_IAS_ACE_PANEL_STATUS_NOT_READY_TO_ARM)
                    || (serverPtr->panel_status == ZCL_IAS_ACE_PANEL_STATUS_IN_ALARM)) {
                    return false;
                }
                break;

            default:
                break;
        }

        if (panel_status == ZCL_IAS_ACE_PANEL_STATUS_PANEL_DISARMED) {
            /* If disarming, clear any bypassed zones */
            zcl_ias_ace_server_zone_table_bypass_clear(cluster);

            if (zcl_ias_ace_server_zone_table_status_all_clear(serverPtr)) {
                /* All zones are clear, we can go to the disarmed state */
                serverPtr->panel_status = ZCL_IAS_ACE_PANEL_STATUS_PANEL_DISARMED;
            }
            else {
                /* At least one zone is not ready, so go directly to the NOT_READY_TO_ARM state. */
                serverPtr->panel_status = ZCL_IAS_ACE_PANEL_STATUS_NOT_READY_TO_ARM;
            }
        }
        else {
            serverPtr->panel_status = panel_status;
        }

        send_panel_status = true;
    }

    if ((serverPtr->panel_status != ZCL_IAS_ACE_PANEL_STATUS_EXIT_DELAY)
        && (serverPtr->panel_status != ZCL_IAS_ACE_PANEL_STATUS_ENTRY_DELAY)) {
        serverPtr->seconds_remain = 0;
    }

    if ((serverPtr->seconds_remain != seconds_remain) || serverPtr->audible_notify != audible_notify) {
        serverPtr->seconds_remain = seconds_remain;
        serverPtr->audible_notify = audible_notify;
        send_panel_status = true;
    }

    if (send_panel_status) {
        zcl_ias_ace_server_send_panel_status_changed(serverPtr);
    }

    return true;
}

bool
ZbZclIasAceServerGetFreeZoneId(struct ZbZclClusterT *cluster, uint8_t *zone_id_ptr)
{
    struct cluster_priv_t *serverPtr = (void *)cluster;
    unsigned int zone_id;

    if (serverPtr->zone_table_sz == ZCL_IAS_ACE_SVR_MAX_ZONES) {
        return false;
    }
    for (zone_id = 0; zone_id < ZCL_IAS_ACE_SVR_MAX_ZONES; zone_id++) {
        if (ZbZclIasAceServerZoneTableAddrLookup(&serverPtr->cluster, zone_id)) {
            continue;
        }
        *zone_id_ptr = zone_id;
        return true;
    }
    return false;
}

static bool
zcl_ias_ace_server_zone_table_check_duplicate(struct cluster_priv_t *serverPtr, uint64_t zone_addr, uint8_t zone_id)
{
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry;

    LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
        entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);
        if (entry->zone_addr == zone_addr) {
            return true;
        }
        if (entry->zone_id == zone_id) {
            return true;
        }
    }
    return false;
}

bool
ZbZclIasAceServerZoneTableAdd(struct ZbZclClusterT *cluster, struct ZbZclIasAceServerZoneTableAddT *req)
{
    struct cluster_priv_t *serverPtr = (void *)cluster;
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry, *new_entry;

    if (req->zone_label && (strlen(req->zone_label) > ZCL_IAS_ACE_ZONE_LABEL_STRING_MAX_LEN)) {
        return false;
    }

    /* Check for duplicate address or id */
    if (zcl_ias_ace_server_zone_table_check_duplicate(serverPtr, req->zone_addr, req->zone_id)) {
        ZCL_LOG_PRINTF(serverPtr->cluster.zb, __func__,
            "Error, a zone with address 0x%016" PRIx64 " already exists (zone_id = 0x%02x)",
            req->zone_addr, req->zone_id);
        return false;
    }

    new_entry = ZbHeapAlloc(cluster->zb, sizeof(struct ZbZclIasAceZoneTableT));
    if (new_entry == NULL) {
        return false;
    }
    (void)memset(new_entry, 0, sizeof(struct ZbZclIasAceZoneTableT));
    LINK_LIST_INIT(&new_entry->link);
    new_entry->zone_id = req->zone_id;
    new_entry->zone_type = req->zone_type;
    new_entry->zone_addr = req->zone_addr;
    new_entry->zone_status = ZCL_IAS_ZONE_SVR_ZONE_STATUS_NONE;
    if (req->zone_label) {
        (void)strcpy(new_entry->zone_label, req->zone_label);
    }

    new_entry->bypass_perms = ZCL_IAS_ACE_BYPASS_PERMS_ALLOWED;
    new_entry->bypass_status = false;

    /* For ZCL_IAS_ACE_CLI_CMD_GET_ZONE_STATUS, the list should be
     * sorted in ascending order. */
    LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
        entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);

        if (new_entry->zone_id == entry->zone_id) {
            /* Should never get here */
            ZbHeapFree(cluster->zb, new_entry);
            return false;
        }
        if (new_entry->zone_id < entry->zone_id) {
            LINK_LIST_INSERT_BEFORE(&entry->link, &new_entry->link);
            serverPtr->zone_table_sz++;
            return true;
        }
    }
    /* If get here, add it to the end */
    LINK_LIST_INSERT_TAIL(&serverPtr->zone_table_list, &new_entry->link);
    serverPtr->zone_table_sz++;
    return true;
}

bool
ZbZclIasAceServerZoneTableDeleteById(struct ZbZclClusterT *cluster, uint8_t zone_id)
{
    struct cluster_priv_t *serverPtr = (void *)cluster;
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry;

    LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
        entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);
        if (entry->zone_id != zone_id) {
            continue;
        }
        LINK_LIST_UNLINK(&entry->link);
        serverPtr->zone_table_sz--;
        ZbHeapFree(cluster->zb, entry);
        return true;
    }
    return false;
}

bool
ZbZclIasAceServerZoneTableDeleteByAddr(struct ZbZclClusterT *cluster, uint64_t zone_addr)
{
    struct cluster_priv_t *serverPtr = (void *)cluster;
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry;

    LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
        entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);
        if (entry->zone_addr != zone_addr) {
            continue;
        }
        LINK_LIST_UNLINK(&entry->link);
        serverPtr->zone_table_sz--;
        ZbHeapFree(cluster->zb, entry);
        return true;
    }
    return false;
}

uint64_t
ZbZclIasAceServerZoneTableAddrLookup(struct ZbZclClusterT *cluster, uint8_t zone_id)
{
    struct cluster_priv_t *serverPtr = (void *)cluster;
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry;

    LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
        entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);
        if (entry->zone_id == zone_id) {
            return entry->zone_addr;
        }
    }
    return 0;
}

bool
ZbZclIasAceServerZoneTableIdLookup(struct ZbZclClusterT *cluster, uint64_t zone_addr, uint8_t *zone_id_ptr)
{
    struct cluster_priv_t *serverPtr = (void *)cluster;
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry;

    LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
        entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);
        if (entry->zone_addr == zone_addr) {
            if (zone_id_ptr) {
                *zone_id_ptr = entry->zone_id;
            }
            return true;
        }
    }
    return false;
}

static void
zcl_ias_ace_server_zone_table_bypass_clear(struct ZbZclClusterT *cluster)
{
    struct cluster_priv_t *serverPtr = (void *)cluster;
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry;

    LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
        entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);
        if (entry->bypass_status) {
            /* EXEGIN - notify application? */
            entry->bypass_status = false;
        }
    }
}

static bool
zcl_ias_ace_server_zone_table_status_all_clear(struct cluster_priv_t *serverPtr)
{
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry;

    LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
        entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);
        /* Skip bypassed zones */
        if (entry->bypass_status) {
            continue;
        }
        if (entry->zone_status) {
            return false;
        }
    }
    return true;
}

bool
ZbZclIasAceServerZoneStatusConfig(struct ZbZclClusterT *cluster, uint8_t zone_id,
    enum ZbZclIasZoneServerZoneStatusT zone_status, enum ZbZclIasAceAudibleNotifyT audible_notify)
{
    struct cluster_priv_t *serverPtr = (void *)cluster;
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry;

    LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
        entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);
        if (entry->zone_id == zone_id) {
            uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
            unsigned int len = 0, zone_label_len;
            struct ZbZclClusterCommandReqT req;
            bool send_panel_status = false;

            if (entry->zone_status != zone_status) {
                /* Update the zone's status */
                entry->zone_status = zone_status;

                /* EXEGIN - check if the alarm bits have actually changed */
                if ((zone_status & ZCL_IAS_ZONE_SVR_ZONE_STATUS_ALARM1)
                    || (zone_status & ZCL_IAS_ZONE_SVR_ZONE_STATUS_ALARM2)) {

                    switch (serverPtr->panel_status) {
                        case ZCL_IAS_ACE_PANEL_STATUS_ENTRY_DELAY:
                            break;

                        case ZCL_IAS_ACE_PANEL_STATUS_EXIT_DELAY:
                            break;

                        case ZCL_IAS_ACE_PANEL_STATUS_ARMING_STAY:
                        case ZCL_IAS_ACE_PANEL_STATUS_ARMING_NIGHT:
                        case ZCL_IAS_ACE_PANEL_STATUS_ARMING_AWAY:
                            break;

                        case ZCL_IAS_ACE_PANEL_STATUS_ARMED_STAY:
                        case ZCL_IAS_ACE_PANEL_STATUS_ARMED_NIGHT:
                        case ZCL_IAS_ACE_PANEL_STATUS_ARMED_AWAY:
                            /* System is armed, trigger an alarm */
                            ZbZclIasAceServerPanelStatusConfig(cluster, ZCL_IAS_ACE_PANEL_STATUS_IN_ALARM, 0,
                                ZCL_IAS_ACE_AUDIBLE_NOTIFY_DEFAULT_SOUND);
                            break;

                        case ZCL_IAS_ACE_PANEL_STATUS_PANEL_DISARMED:
                            /* System is disarmed, switch to NOT_READY_TO_ARM state, unless zone is bypassed. */
                            if (!entry->bypass_status) {
                                ZbZclIasAceServerPanelStatusConfig(cluster, ZCL_IAS_ACE_PANEL_STATUS_NOT_READY_TO_ARM, 0,
                                    ZCL_IAS_ACE_AUDIBLE_NOTIFY_MUTE);
                            }
                            break;

                        case ZCL_IAS_ACE_PANEL_STATUS_NOT_READY_TO_ARM:
                        case ZCL_IAS_ACE_PANEL_STATUS_IN_ALARM:
                        /* Already in-alarm or not-ready-to-arm, so nothing more to do. */
                        default:
                            break;
                    }
                }
                else {
                    /* EXEGIN - check if the alarm bits have actually changed */

                    if ((serverPtr->panel_status == ZCL_IAS_ACE_PANEL_STATUS_NOT_READY_TO_ARM)
                        && zcl_ias_ace_server_zone_table_status_all_clear(serverPtr)) {
                        /* If all the zones are now clear, set the panel status back to disarmed. */
                        serverPtr->panel_status = ZCL_IAS_ACE_PANEL_STATUS_PANEL_DISARMED;
                        send_panel_status = true;
                    }
                }
            }

            /* EXEGIN - do something with audible_notify? */
            if (serverPtr->audible_notify != audible_notify) {
                serverPtr->audible_notify = audible_notify;
                send_panel_status = true;
            }

            if (send_panel_status) {
                zcl_ias_ace_server_send_panel_status_changed(serverPtr);
            }

            /* Form the payload */
            payload[len++] = entry->zone_id;
            putle16(&payload[len], entry->zone_status);
            len += 2;
            payload[len++] = audible_notify;
            /* Zone Label */
            zone_label_len = strlen(entry->zone_label);
            payload[len++] = zone_label_len;
            if (zone_label_len) {
                (void)memcpy(&payload[len], entry->zone_label, zone_label_len);
                len += zone_label_len;
            }

            (void)memset(&req, 0, sizeof(req));
            req.dst = *ZbApsAddrBinding;
            req.cmdId = ZCL_IAS_ACE_SVR_CMD_ZONE_STATUS_CHANGED;
            req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
            req.payload = payload;
            req.length = len;
            if (ZbZclClusterCommandReq(cluster, &req, NULL, NULL) != ZCL_STATUS_SUCCESS) {
                return false;
            }
            return true;
        }
    }
    return false;
}

bool
ZbZclIasAceServerZoneBypassPerms(struct ZbZclClusterT *cluster, uint8_t zone_id, enum ZbZclIasAceBypassPermsT bypass_perms)
{
    struct cluster_priv_t *serverPtr = (void *)cluster;
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry;

    LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
        entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);
        if (entry->zone_id == zone_id) {
            /* Don't allow setting bypass permission to NOT_ALLOWED
             * if zone is currently bypassed. */
            if (entry->bypass_status && (bypass_perms == ZCL_IAS_ACE_BYPASS_PERMS_NOT_ALLOWED)) {
                return false;
            }
            entry->bypass_perms = bypass_perms;
            return true;
        }
    }
    return false;
}

enum ZbZclIasAceBypassResultT
ZbZclIasAceServerZoneBypassConfig(struct ZbZclClusterT *cluster, uint8_t zone_id, bool bypass)
{
    struct cluster_priv_t *serverPtr = (void *)cluster;
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry;
    enum ZbZclIasAceBypassResultT result;

    LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
        entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);
        if (entry->zone_id == zone_id) {
            if (bypass) {
                if (entry->bypass_perms != ZCL_IAS_ACE_BYPASS_PERMS_ALLOWED) {
                    result = ZCL_IAS_ACE_BYPASS_RESULT_NOT_ALLOWED;
                }
                else if (entry->bypass_status) {
                    /* Already bypassed */
                    return ZCL_IAS_ACE_BYPASS_RESULT_ZONE_BYPASSED;
                }
                else {
                    entry->bypass_status = true;
                    result = ZCL_IAS_ACE_BYPASS_RESULT_ZONE_BYPASSED;
                }
            }
            else if (!entry->bypass_status) {
                /* Already not bypassed */
                return ZCL_IAS_ACE_BYPASS_RESULT_ZONE_NOT_BYPASSED;
            }
            else {
                entry->bypass_status = false;
                result = ZCL_IAS_ACE_BYPASS_RESULT_ZONE_NOT_BYPASSED;
            }

            /* Check if the panel status can be updated */
            if (zcl_ias_ace_server_zone_table_status_all_clear(serverPtr)) {
                if (serverPtr->panel_status == ZCL_IAS_ACE_PANEL_STATUS_NOT_READY_TO_ARM) {
                    /* If all the zones are now clear, set the panel status back to disarmed. */
                    serverPtr->panel_status = ZCL_IAS_ACE_PANEL_STATUS_PANEL_DISARMED;
                }
            }
            else {
                if (serverPtr->panel_status == ZCL_IAS_ACE_PANEL_STATUS_PANEL_DISARMED) {
                    /* This update caused us to go into the NOT_READY_TO_ARM state
                     * (removed bypass of zone with status bit(s) set). */
                    serverPtr->panel_status = ZCL_IAS_ACE_PANEL_STATUS_NOT_READY_TO_ARM;
                }
            }
            return result;
        }
    }
    return ZCL_IAS_ACE_BYPASS_RESULT_UNKNOWN_ZONE_ID;
}

static void
zcl_ias_ace_server_cleanup(struct ZbZclClusterT *clusterPtr)
{
    struct cluster_priv_t *serverPtr = (void *)clusterPtr;
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry;

    /* Free the zone table */
    while (true) {
        p = LINK_LIST_HEAD(&serverPtr->zone_table_list);
        if (p == NULL) {
            break;
        }
        entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);
        LINK_LIST_UNLINK(&entry->link);
        serverPtr->zone_table_sz--;
        ZbHeapFree(clusterPtr->zb, entry);
    }
}

static enum ZclStatusCodeT
zcl_ias_ace_server_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr,
    struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *serverPtr = (void *)clusterPtr;
    unsigned int i = 0;
    uint8_t rsp_payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    struct ZbApsBufT bufv[1];
    struct LinkListT *p;
    struct ZbZclIasAceZoneTableT *entry;
    enum ZclStatusCodeT status = ZCL_STATUS_UNSUPP_COMMAND;
    struct ZbZclAddrInfoT srcInfo;

    (void)memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zclHdrPtr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    if (zclHdrPtr->frameCtrl.manufacturer) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    switch (zclHdrPtr->cmdId) {
        case ZCL_IAS_ACE_CLI_CMD_ARM:
            if (serverPtr->callbacks.arm_req) {
                struct ZbZclIasAceClientCommandArmT arm_req;
                struct ZbZclIasAceServerCommandArmRspT arm_rsp;
                uint8_t arm_code_len;
                bool success = true;

                (void)memset(&arm_req, 0, sizeof(arm_req));
                if ((i + 2) > dataIndPtr->asduLength) {
                    return ZCL_STATUS_MALFORMED_COMMAND;
                }
                arm_req.arm_mode = (enum ZbZclIasAceArmModeT)dataIndPtr->asdu[i++];
                /* Arm Code (UTF-8) */
                arm_code_len = dataIndPtr->asdu[i++];
                if (arm_code_len != 0U) {
                    if (arm_code_len > ZCL_IAS_ACE_ARM_CODE_STRING_MAX_LEN) {
                        return ZCL_STATUS_INSUFFICIENT_SPACE;
                    }
                    if ((i + arm_code_len) > dataIndPtr->asduLength) {
                        return ZCL_STATUS_MALFORMED_COMMAND;
                    }
                    (void)memcpy(arm_req.arm_code, &dataIndPtr->asdu[i], arm_code_len);
                    i += arm_code_len;
                }
                if ((i + 1) > dataIndPtr->asduLength) {
                    return ZCL_STATUS_MALFORMED_COMMAND;
                }
                arm_req.zone_id = dataIndPtr->asdu[i++];

                /* Set i = 0 for forming response */
                i = 0;

                /* EXEGIN - arm code is optional in some cases */
                if (strcmp(serverPtr->arm_code, arm_req.arm_code)) {
                    rsp_payload[i++] = ZCL_IAS_ACE_ARM_NOTIFY_INVALID_ARM_CODE;
                    success = false;
                    goto SEND_ARM_RSP;
                }

                (void)memset(&arm_rsp, 0, sizeof(arm_rsp));
                if (!serverPtr->callbacks.arm_req(clusterPtr, clusterPtr->app_cb_arg, &arm_req, &arm_rsp)) {
                    /* Assume invalid request */
                    return ZCL_STATUS_FAILURE;
                }
                rsp_payload[i++] = arm_rsp.arm_notify;

SEND_ARM_RSP:
                bufv[0].data = rsp_payload;
                bufv[0].len = i;

                ZbZclClusterCommandRsp(clusterPtr, &srcInfo, ZCL_IAS_ACE_SVR_CMD_ARM_RSP, bufv, 1);

                if (success) {
                    /* EXEGIN - go through various exit/arming delays */
                }
                return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            }
            return status;

        case ZCL_IAS_ACE_CLI_CMD_BYPASS:
            if (serverPtr->callbacks.bypass_req) {
                struct ZbZclIasAceClientCommandBypassT bypass_req;
                struct ZbZclIasAceServerCommandBypassRspT bypass_rsp;
                uint8_t arm_code_len;
                unsigned int j;

                (void)memset(&bypass_req, 0, sizeof(bypass_req));
                if ((i + 1) > dataIndPtr->asduLength) {
                    return ZCL_STATUS_MALFORMED_COMMAND;
                }
                bypass_req.num_zones = dataIndPtr->asdu[i++];
                if (bypass_req.num_zones > 0) {
                    if ((i + bypass_req.num_zones) > dataIndPtr->asduLength) {
                        return ZCL_STATUS_MALFORMED_COMMAND;
                    }
                    for (j = 0; j < bypass_req.num_zones; j++) {
                        bypass_req.zone_id_list[j] = dataIndPtr->asdu[i++];
                    }
                }
                /* Arm Code (UTF-8) */
                if ((i + 1) > dataIndPtr->asduLength) {
                    return ZCL_STATUS_MALFORMED_COMMAND;
                }
                arm_code_len = dataIndPtr->asdu[i++];
                if (arm_code_len) {
                    if (arm_code_len > ZCL_IAS_ACE_ARM_CODE_STRING_MAX_LEN) {
                        return ZCL_STATUS_INSUFFICIENT_SPACE;
                    }
                    if ((i + arm_code_len) > dataIndPtr->asduLength) {
                        return ZCL_STATUS_MALFORMED_COMMAND;
                    }
                    (void)memcpy(bypass_req.arm_code, &dataIndPtr->asdu[i], arm_code_len);
                    i += arm_code_len;
                }

                /* EXEGIN - arm code is optional in some cases */
                if (strcmp(serverPtr->arm_code, bypass_req.arm_code)) {
                    i = 0;
                    rsp_payload[i++] = 0x00;
                    goto SEND_BYPASS_RSP;
                }

                (void)memset(&bypass_rsp, 0, sizeof(bypass_rsp));
                serverPtr->callbacks.bypass_req(clusterPtr, clusterPtr->app_cb_arg, &bypass_req, &bypass_rsp);

                /* Form the payload */
                i = 0;
                rsp_payload[i++] = bypass_rsp.num_zones;
                for (j = 0; j < bypass_rsp.num_zones; j++) {
                    rsp_payload[i++] = bypass_rsp.bypass_result_list[j];
                }

SEND_BYPASS_RSP:
                bufv[0].data = rsp_payload;
                bufv[0].len = i;

                ZbZclClusterCommandRsp(clusterPtr, &srcInfo, ZCL_IAS_ACE_SVR_CMD_BYPASS_RSP, bufv, 1);
                return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
            }
            return status;

        case ZCL_IAS_ACE_CLI_CMD_EMERGENCY:
            if (serverPtr->callbacks.emerg_req != NULL) {
                status = serverPtr->callbacks.emerg_req(clusterPtr, clusterPtr->app_cb_arg, &srcInfo);
            }
            return status;

        case ZCL_IAS_ACE_CLI_CMD_FIRE:
            if (serverPtr->callbacks.fire_req != NULL) {
                status = serverPtr->callbacks.fire_req(clusterPtr, clusterPtr->app_cb_arg, &srcInfo);
            }
            return status;

        case ZCL_IAS_ACE_CLI_CMD_PANIC:
            if (serverPtr->callbacks.panic_req != NULL) {
                status = serverPtr->callbacks.panic_req(clusterPtr, clusterPtr->app_cb_arg, &srcInfo);
            }
            return status;

        case ZCL_IAS_ACE_CLI_CMD_GET_ZONE_ID_MAP:
        {
            struct LinkListT *p;
            struct ZbZclIasAceZoneTableT *entry;
            unsigned int j;

            uint16_t zond_id_map_list[ZCL_IAS_ACE_ZONE_ID_MAP_NUM_SECTIONS];

            /* Build the zone_id map */
            (void)memset(zond_id_map_list, 0, sizeof(zond_id_map_list));
            LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
                entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);

                j = entry->zone_id / ZCL_IAS_ACE_ZONE_ID_MAP_NUM_SECTIONS;
                zond_id_map_list[j] |= 1 << (entry->zone_id % ZCL_IAS_ACE_ZONE_ID_MAP_NUM_SECTIONS);
            }

            /* Form the payload */
            i = 0;
            for (j = 0; j < ZCL_IAS_ACE_ZONE_ID_MAP_NUM_SECTIONS; j++) {
                putle16(&rsp_payload[i], zond_id_map_list[j]);
                i += 2;
            }

            bufv[0].data = rsp_payload;
            bufv[0].len = i;

            ZbZclClusterCommandRsp(clusterPtr, &srcInfo, ZCL_IAS_ACE_SVR_CMD_GET_ZONE_ID_MAP_RSP, bufv, 1);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
        }

        case ZCL_IAS_ACE_CLI_CMD_GET_ZONE_INFO:
        {

            struct ZbZclIasAceClientCommandGetZoneInfoT get_info;
            uint8_t rsp_payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
            unsigned int zone_label_len;

            (void)memset(&get_info, 0, sizeof(get_info));
            if ((i + 1) > dataIndPtr->asduLength) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            get_info.zone_id = dataIndPtr->asdu[i++];

            LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
                entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);

                if (entry->zone_id == get_info.zone_id) {
                    zone_label_len = strlen(entry->zone_label);

                    /* Form the payload */
                    i = 0;
                    rsp_payload[i++] = entry->zone_id;
                    putle16(&rsp_payload[i], entry->zone_type);
                    i += 2;
                    putle64(&rsp_payload[i], entry->zone_addr);
                    i += 8;
                    rsp_payload[i++] = zone_label_len;
                    if (zone_label_len) {
                        (void)memcpy(&rsp_payload[i], entry->zone_label, zone_label_len);
                        i += zone_label_len;
                    }

                    bufv[0].data = rsp_payload;
                    bufv[0].len = i;

                    ZbZclClusterCommandRsp(clusterPtr, &srcInfo, ZCL_IAS_ACE_SVR_CMD_GET_ZONE_INFO_RSP, bufv, 1);
                    return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
                }
            }
            /* EXEGIN - response type or code? */
            return ZCL_STATUS_NOT_FOUND;
        }

        case ZCL_IAS_ACE_CLI_CMD_GET_PANEL_STATUS:
            /* Form the payload */
            rsp_payload[i++] = serverPtr->panel_status;
            rsp_payload[i++] = serverPtr->seconds_remain;
            rsp_payload[i++] = serverPtr->audible_notify;
            rsp_payload[i++] = serverPtr->alarm_status;

            bufv[0].data = rsp_payload;
            bufv[0].len = i;

            ZbZclClusterCommandRsp(clusterPtr, &srcInfo, ZCL_IAS_ACE_SVR_CMD_GET_PANEL_STATUS_RSP, bufv, 1);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

        case ZCL_IAS_ACE_CLI_CMD_GET_BYPASSED_ZONE_LIST:
            /* Form the payload */
            i = 0;
            rsp_payload[i++] = 0;
            LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
                entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);
                if (!entry->bypass_status) {
                    continue;
                }
                rsp_payload[i++] = entry->zone_id;
                rsp_payload[0]++;
            }

            bufv[0].data = rsp_payload;
            bufv[0].len = i;

            ZbZclClusterCommandRsp(clusterPtr, &srcInfo, ZCL_IAS_ACE_SVR_CMD_SET_BYPASSED_ZONE_LIST, bufv, 1);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

        case ZCL_IAS_ACE_CLI_CMD_GET_ZONE_STATUS:
        {
            struct ZbZclIasAceClientCommandGetZoneStatusT get_status;

            (void)memset(&get_status, 0, sizeof(get_status));
            if ((i + 5) > dataIndPtr->asduLength) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            get_status.starting_zone_id = dataIndPtr->asdu[i++];
            get_status.max_zone_ids = dataIndPtr->asdu[i++];
            get_status.zone_status_mask_flag = dataIndPtr->asdu[i++];
            get_status.zone_status_mask = pletoh16(&dataIndPtr->asdu[i]);
            i += 2;

            /* Form the payload */
            i = 0;
            /* Zone Status Complete */
            rsp_payload[i++] = 1;
            /* Number of Zones */
            rsp_payload[i++] = 0;

            LINK_LIST_FOREACH(p, &serverPtr->zone_table_list) {
                entry = LINK_LIST_ITEM(p, struct ZbZclIasAceZoneTableT, link);

                if (entry->zone_id < get_status.starting_zone_id) {
                    continue;
                }
                if (get_status.zone_status_mask_flag
                    && !(entry->zone_status & get_status.zone_status_mask)) {
                    continue;
                }
                if (rsp_payload[1] == get_status.max_zone_ids) {
                    /* Zone Status Complete */
                    rsp_payload[0] = 0;
                    break;
                }

                if ((i + 3) > sizeof(rsp_payload)) {
                    /* Zone Status Complete */
                    rsp_payload[0] = 0;
                    break;
                }
                rsp_payload[i++] = entry->zone_id;
                putle16(&rsp_payload[i], entry->zone_status);
                i += 2;
                /* Number of Zones */
                rsp_payload[1]++;
            }

            bufv[0].data = rsp_payload;
            bufv[0].len = i;

            ZbZclClusterCommandRsp(clusterPtr, &srcInfo, ZCL_IAS_ACE_SVR_CMD_GET_ZONE_STATUS_RSP, bufv, 1);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
        }

        default:
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
}

static void
zcl_ias_ace_server_send_panel_status_changed(struct cluster_priv_t *serverPtr)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int len = 0;
    struct ZbZclClusterCommandReqT req;

    /* Form the payload */
    payload[len++] = serverPtr->panel_status;
    payload[len++] = serverPtr->seconds_remain;
    payload[len++] = serverPtr->audible_notify;
    payload[len++] = serverPtr->alarm_status;

    ZCL_LOG_PRINTF(serverPtr->cluster.zb, __func__, "Sending PANEL_STATUS_CHANGED to binding. Panel Status = %s (%d)",
        ZbZclIasAcePanelStatusToStr(serverPtr->panel_status), serverPtr->panel_status);

    (void)memset(&req, 0, sizeof(req));
    /* EXEGIN - to binding? */
    req.dst = *ZbApsAddrBinding;
    req.cmdId = ZCL_IAS_ACE_SVR_CMD_PANEL_STATUS_CHANGED;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = len;
    (void)ZbZclClusterCommandReqDelayed(&serverPtr->cluster, &req, ZB_NWK_RSP_DELAY_DEFAULT, NULL, NULL);
}

const char *
ZbZclIasAcePanelStatusToStr(enum ZbZclIasAcePanelStatusT panel_status)
{
    switch (panel_status) {
        case ZCL_IAS_ACE_PANEL_STATUS_PANEL_DISARMED:
            return "Disarmed";

        case ZCL_IAS_ACE_PANEL_STATUS_ARMED_STAY:
            return "Armed-Stay";

        case ZCL_IAS_ACE_PANEL_STATUS_ARMED_NIGHT:
            return "Armed-Night";

        case ZCL_IAS_ACE_PANEL_STATUS_ARMED_AWAY:
            return "Armed-Away";

        case ZCL_IAS_ACE_PANEL_STATUS_EXIT_DELAY:
            return "Exit-Delay";

        case ZCL_IAS_ACE_PANEL_STATUS_ENTRY_DELAY:
            return "Entry-Delay";

        case ZCL_IAS_ACE_PANEL_STATUS_NOT_READY_TO_ARM:
            return "Not-Ready-To-Arm";

        case ZCL_IAS_ACE_PANEL_STATUS_IN_ALARM:
            return "In-Alarm";

        case ZCL_IAS_ACE_PANEL_STATUS_ARMING_STAY:
            return "Arming-Stay";

        case ZCL_IAS_ACE_PANEL_STATUS_ARMING_NIGHT:
            return "Arming-Night";

        case ZCL_IAS_ACE_PANEL_STATUS_ARMING_AWAY:
            return "Arming-Away";

        default:
            return "Unknown";
    }
}
