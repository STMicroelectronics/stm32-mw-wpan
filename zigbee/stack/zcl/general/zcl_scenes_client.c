/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl/general/zcl.scenes.h"

/* Debugging (verbose) */
/* #define SCENES_DEBUG               ZCL_LOG_PRINTF */
#define SCENES_DEBUG(_zb_, _mask_, _hdr_, ...) /* empty */

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;

    /* The local endpoint this cluster is assigned */
    uint8_t endpoint;
};

static enum ZclStatusCodeT zcl_scenes_client_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclScenesClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_SCENES, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    clusterPtr->cluster.command = zcl_scenes_client_command;

    /* Other internal data */
    clusterPtr->endpoint = endpoint;

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
zcl_scenes_client_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_CLIENT) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (zclHdrPtr->frameCtrl.manufacturer) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    switch (zclHdrPtr->cmdId) {
        case ZCL_SCENES_COMMAND_ADD_SCENE:
        case ZCL_SCENES_COMMAND_VIEW_SCENE:
        case ZCL_SCENES_COMMAND_REMOVE_SCENE:
        case ZCL_SCENES_COMMAND_REMOVE_ALL_SCENES:
        case ZCL_SCENES_COMMAND_STORE_SCENE:
        case ZCL_SCENES_COMMAND_RECALL_SCENE:
        case ZCL_SCENES_COMMAND_GET_SCENE_MBRSHIP:
        case ZCL_SCENES_COMMAND_ENH_ADD_SCENE:
        case ZCL_SCENES_COMMAND_ENH_VIEW_SCENE:
        case ZCL_SCENES_COMMAND_COPY_SCENE:
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

        default:
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
}

enum ZclStatusCodeT
zcl_scenes_client_add_req(struct ZbZclClusterT *clusterPtr, struct zcl_scenes_add_request_t *add_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int payLen = 0;
    uint8_t cmdId = add_req->isEnhanced ? ZCL_SCENES_COMMAND_ENH_ADD_SCENE : ZCL_SCENES_COMMAND_ADD_SCENE;
    int ret;
    unsigned int nameLen;

    /* Create the "Add Scene" command payload */
    /* Group ID */
    putle16(&payload[payLen], add_req->groupId);
    payLen += 2;
    /* Scene ID */
    payload[payLen++] = add_req->sceneId;
    /* Transition (isEnhanced ? Tenths of seconds : Seconds) */
    putle16(&payload[payLen], add_req->transition);
    payLen += 2;

    /* Scene Name */
    if (add_req->sceneName) {
        nameLen = strlen(add_req->sceneName);
        /* Check length */
        if (nameLen > ZCL_SCENES_NAME_MAX_LENGTH) {
            return ZCL_STATUS_INVALID_VALUE;
        }
        /* Extra sanity check. */
        if ((nameLen + 1) > (sizeof(payload) - payLen)) {
            return ZCL_STATUS_INVALID_VALUE;
        }
        payload[payLen++] = nameLen;
        if (nameLen) {
            (void)memcpy(&payload[payLen], add_req->sceneName, nameLen);
            payLen += nameLen;
        }
    }
    else {
        payload[payLen++] = 0x00; /* none */
    }

    /* Extension field sets (optional) */
    if (add_req->extStrPtr) {
        ret = zb_hex_str_to_bin(add_req->extStrPtr, &payload[payLen], sizeof(payload) - payLen);
        if (ret > 0) {
            payLen += ret;
        }
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = add_req->dst;
    req.cmdId = cmdId;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = payLen;
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

enum ZclStatusCodeT
zcl_scenes_client_add_rsp_parse(struct zcl_scenes_add_response_t *add_rsp, struct ZbZclCommandRspT *zcl_rsp)
{
    unsigned int i = 0;

    if (zcl_rsp->status) {
        return zcl_rsp->status;
    }
    if ((zcl_rsp->hdr.cmdId != ZCL_SCENES_COMMAND_ADD_SCENE)
        && (zcl_rsp->hdr.cmdId != ZCL_SCENES_COMMAND_ENH_ADD_SCENE)) {
        return ZCL_STATUS_FAILURE;
    }
    if (zcl_rsp->length != 4) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    add_rsp->status = zcl_rsp->payload[i++];
    add_rsp->groupId = pletoh16(&zcl_rsp->payload[i]);
    i += 2;
    add_rsp->sceneId = zcl_rsp->payload[i++];
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
zcl_scenes_client_view_req(struct ZbZclClusterT *clusterPtr, struct zcl_scenes_view_request_t *view_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[3];
    uint8_t cmdId = view_req->isEnhanced ? ZCL_SCENES_COMMAND_ENH_VIEW_SCENE : ZCL_SCENES_COMMAND_VIEW_SCENE;

    /* Create the "View Scene" command payload */
    putle16(&payload[0], view_req->groupId); /* Group */
    payload[2] = view_req->sceneId; /* Scene */

    (void)memset(&req, 0, sizeof(req));
    req.dst = view_req->dst;
    req.cmdId = cmdId;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = sizeof(payload);
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

enum ZclStatusCodeT
zcl_scenes_client_view_rsp_parse(struct zcl_scenes_view_response_t *view_rsp, struct ZbZclCommandRspT *zcl_rsp)
{
    unsigned int i = 0;
    uint8_t nameLen;

    (void)memset(view_rsp, 0, sizeof(struct zcl_scenes_view_response_t));

    if (zcl_rsp->status) {
        return zcl_rsp->status;
    }
    if ((zcl_rsp->hdr.cmdId != ZCL_SCENES_COMMAND_VIEW_SCENE)
        && (zcl_rsp->hdr.cmdId != ZCL_SCENES_COMMAND_ENH_VIEW_SCENE)) {
        return ZCL_STATUS_FAILURE;
    }
    if (zcl_rsp->length < 4) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }

    view_rsp->status = zcl_rsp->payload[i++];
    view_rsp->groupId = pletoh16(&zcl_rsp->payload[i]);
    i += 2;
    view_rsp->sceneId = zcl_rsp->payload[i++];

    if (view_rsp->status) {
        return ZCL_STATUS_SUCCESS;
    }

    if ((i + 3) > zcl_rsp->length) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    view_rsp->transition = pletoh16(&zcl_rsp->payload[i]);
    i += 2;

    nameLen = zcl_rsp->payload[i++];
    if ((i + nameLen) > zcl_rsp->length) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    if (nameLen > ZCL_SCENES_VIEW_NAME_MAX_LEN) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
    (void)memcpy((uint8_t *)view_rsp->nameStr, &zcl_rsp->payload[i], nameLen);
    view_rsp->nameStr[nameLen] = 0;
    i += nameLen;

    if (i >= zcl_rsp->length) {
        return ZCL_STATUS_SUCCESS;
    }

    while (i < zcl_rsp->length) {
        uint16_t clusterId;
        uint8_t extLen;

        if ((i + 3) > zcl_rsp->length) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (view_rsp->extNum >= ZCL_SCENES_VIEW_EXT_LIST_MAX_SZ) {
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }

        clusterId = pletoh16(&zcl_rsp->payload[i]);
        i += 2;

        extLen = zcl_rsp->payload[i++];

        if ((i + extLen) > zcl_rsp->length) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (extLen > ZCL_SCENES_VIEW_EXT_FIELD_MAX_LEN) {
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }

        view_rsp->extList[view_rsp->extNum].clusterId = clusterId;
        view_rsp->extList[view_rsp->extNum].length = extLen;
        (void)memcpy(view_rsp->extList[view_rsp->extNum].field, (uint8_t *)&zcl_rsp->payload[i], extLen);
        i += extLen;
    } /* while */

    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
zcl_scenes_client_remove_req(struct ZbZclClusterT *clusterPtr, struct zcl_scenes_remove_request_t *remove_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[3];

    /* Create the "Remove Scene" command payload */
    putle16(&payload[0], remove_req->groupId); /* Group */
    payload[2] = remove_req->sceneId; /* Scene */

    (void)memset(&req, 0, sizeof(req));
    req.dst = remove_req->dst;
    req.cmdId = ZCL_SCENES_COMMAND_REMOVE_SCENE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = sizeof(payload);
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

enum ZclStatusCodeT
zcl_scenes_client_remove_rsp_parse(struct zcl_scenes_remove_response_t *remove_rsp, struct ZbZclCommandRspT *zcl_rsp)
{
    unsigned int i = 0;

    if (zcl_rsp->status) {
        return zcl_rsp->status;
    }
    if (zcl_rsp->hdr.cmdId != ZCL_SCENES_COMMAND_REMOVE_SCENE) {
        SCENES_DEBUG(zb, __func__, "cmdId = 0x%02x", zcl_rsp->hdr.cmdId);
        return ZCL_STATUS_FAILURE;
    }
    if (zcl_rsp->length != 4) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }

    remove_rsp->status = zcl_rsp->payload[i++];
    remove_rsp->groupId = pletoh16(&zcl_rsp->payload[i]);
    i += 2;
    remove_rsp->sceneId = zcl_rsp->payload[i++];
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
zcl_scenes_client_remove_all_req(struct ZbZclClusterT *clusterPtr, struct zcl_scenes_remove_all_request_t *remove_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[2];

    /* Create the "Remove All Scenes" command payload */
    putle16(&payload[0], remove_req->groupId); /* Group */

    (void)memset(&req, 0, sizeof(req));
    req.dst = remove_req->dst;
    req.cmdId = ZCL_SCENES_COMMAND_REMOVE_ALL_SCENES;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = sizeof(payload);
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

enum ZclStatusCodeT
zcl_scenes_client_remove_all_rsp_parse(struct zcl_scenes_remove_all_response_t *remove_rsp, struct ZbZclCommandRspT *zcl_rsp)
{
    unsigned int i = 0;

    if (zcl_rsp->status) {
        return zcl_rsp->status;
    }
    if (zcl_rsp->hdr.cmdId != ZCL_SCENES_COMMAND_REMOVE_ALL_SCENES) {
        return ZCL_STATUS_FAILURE;
    }
    if (zcl_rsp->length != 3) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }

    i = 0;
    remove_rsp->status = zcl_rsp->payload[i++];
    remove_rsp->groupId = pletoh16(&zcl_rsp->payload[i]);
    i += 2;

    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
zcl_scenes_client_store_req(struct ZbZclClusterT *clusterPtr, struct zcl_scenes_store_request_t *store_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[3];

    /* Create the "Store Scene" command payload */
    putle16(&payload[0], store_req->groupId); /* Group */
    payload[2] = store_req->sceneId; /* Scene */

    (void)memset(&req, 0, sizeof(req));
    req.dst = store_req->dst;
    req.cmdId = ZCL_SCENES_COMMAND_STORE_SCENE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = sizeof(payload);
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

enum ZclStatusCodeT
zcl_scenes_client_store_rsp_parse(struct zcl_scenes_store_response_t *store_rsp, struct ZbZclCommandRspT *zcl_rsp)
{
    unsigned int i = 0;

    if (zcl_rsp->status) {
        return zcl_rsp->status;
    }
    if (zcl_rsp->hdr.cmdId != ZCL_SCENES_COMMAND_STORE_SCENE) {
        return ZCL_STATUS_FAILURE;
    }
    if (zcl_rsp->length != 4) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }

    /* Parse the response */
    i = 0;
    store_rsp->status = zcl_rsp->payload[i++];
    store_rsp->groupId = pletoh16(&zcl_rsp->payload[i]);
    i += 2;
    store_rsp->sceneId = zcl_rsp->payload[i++];

    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
zcl_scenes_client_recall_req(struct ZbZclClusterT *clusterPtr, struct zcl_scenes_recall_request_t *recall_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[5];
    unsigned int i = 0;

    /* Create the "Recall Scene" command payload */
    putle16(&payload[i], recall_req->groupId);
    i += 2;
    payload[i++] = recall_req->sceneId;
    if (recall_req->transition != ZCL_SCENES_RECALL_TRANSITION_INVALID) {
        putle16(&payload[i], recall_req->transition);
        i += 2;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst = recall_req->dst;
    req.cmdId = ZCL_SCENES_COMMAND_RECALL_SCENE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = i;
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

enum ZclStatusCodeT
zcl_scenes_client_recall_rsp_parse(struct zcl_scenes_recall_response_t *recall_rsp, struct ZbZclCommandRspT *zcl_rsp)
{
    /* Expecting Default Response */
    if (zcl_rsp->hdr.cmdId != ZCL_COMMAND_DEFAULT_RESPONSE) {
        return ZCL_STATUS_FAILURE;
    }
    (void)memset(recall_rsp, 0, sizeof(struct zcl_scenes_recall_response_t));
    recall_rsp->status = zcl_rsp->status;
    return zcl_rsp->status;
}

enum ZclStatusCodeT
zcl_scenes_client_get_membership_req(struct ZbZclClusterT *clusterPtr, struct zcl_scenes_membership_request_t *get_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[2];

    /* Create the "Get Scene Membership" command payload */
    putle16(&payload[0], get_req->groupId); /* Group */

    (void)memset(&req, 0, sizeof(req));
    req.dst = get_req->dst;
    req.cmdId = ZCL_SCENES_COMMAND_GET_SCENE_MBRSHIP;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = sizeof(payload);
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

enum ZclStatusCodeT
zcl_scenes_client_get_membership_rsp_parse(struct zcl_scenes_membership_response_t *get_rsp, struct ZbZclCommandRspT *zcl_rsp)
{
    unsigned int i = 0, j;

    if (zcl_rsp->status) {
        return zcl_rsp->status;
    }

    if (zcl_rsp->hdr.cmdId != ZCL_SCENES_COMMAND_GET_SCENE_MBRSHIP) {
        return ZCL_STATUS_FAILURE;
    }

    if (zcl_rsp->length < 4) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }

    i = 0;
    (void)memset(get_rsp, 0, sizeof(struct zcl_scenes_membership_response_t));
    get_rsp->status = zcl_rsp->payload[i++];
    get_rsp->capacity = zcl_rsp->payload[i++];
    get_rsp->groupId = pletoh16(&zcl_rsp->payload[i]);
    i += 2;

    if (get_rsp->status) {
        return ZCL_STATUS_SUCCESS;
    }

    if ((i + 1) > zcl_rsp->length) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    get_rsp->sceneCount = zcl_rsp->payload[i++];

    if (get_rsp->sceneCount > ZCL_SCENES_GET_MEMBERSHIP_MAX_SCENES) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
    if ((i + get_rsp->sceneCount) > zcl_rsp->length) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    for (j = 0; j < get_rsp->sceneCount; j++) {
        get_rsp->sceneList[j] = zcl_rsp->payload[i++];
    }
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
zcl_scenes_client_copy_req(struct ZbZclClusterT *clusterPtr, struct zcl_scenes_copy_request_t *copy_req,
    void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT req;
    uint8_t payload[7];

    /* Create the "Copy Scene" command payload */
    payload[0] = copy_req->allScenes ? 0x01 : 0x00;
    putle16(&payload[1], copy_req->groupFrom);
    payload[3] = copy_req->allScenes ? 0x00 : copy_req->sceneFrom;
    putle16(&payload[4], copy_req->groupTo);
    payload[6] = copy_req->allScenes ? 0x00 : copy_req->sceneTo;

    (void)memset(&req, 0, sizeof(req));
    req.dst = copy_req->dst;
    req.cmdId = ZCL_SCENES_COMMAND_COPY_SCENE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = sizeof(payload);
    return ZbZclClusterCommandReq(clusterPtr, &req, callback, arg);
}

enum ZclStatusCodeT
zcl_scenes_client_copy_rsp_parse(struct zcl_scenes_copy_response_t *copy_rsp, struct ZbZclCommandRspT *zcl_rsp)
{
    unsigned int i = 0;

    if (zcl_rsp->status) {
        return zcl_rsp->status;
    }
    if (zcl_rsp->hdr.cmdId != ZCL_SCENES_COMMAND_COPY_SCENE) {
        return ZCL_STATUS_FAILURE;
    }
    if (zcl_rsp->length != 4) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    copy_rsp->status = zcl_rsp->payload[i++];
    copy_rsp->groupFrom = pletoh16(&zcl_rsp->payload[i]);
    i += 2;
    copy_rsp->sceneFrom = zcl_rsp->payload[i++];
    return ZCL_STATUS_SUCCESS;
}
