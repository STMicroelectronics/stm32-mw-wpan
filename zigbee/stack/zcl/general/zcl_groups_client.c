/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.groups.h"

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;
};

struct ZbZclClusterT *
ZbZclGroupsClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t),
            ZCL_CLUSTER_GROUPS, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

enum ZclStatusCodeT
ZbZclGroupsClientAddReq(struct ZbZclClusterT *cluster,
    struct ZbZclGroupsClientAddReqT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int i = 0;
    struct ZbZclClusterCommandReqT cmd_req;

    /* Group ID */
    putle16(&payload[i], req->group_id);
    i += 2;
    /* Group Name */
    payload[i++] = 0x00;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = req->dst;
    cmd_req.cmdId = ZCL_GROUPS_COMMAND_ADD;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    cmd_req.payload = payload;
    cmd_req.length = i;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

enum ZclStatusCodeT
ZbZclGroupsClientViewReq(struct ZbZclClusterT *cluster,
    struct ZbZclGroupsClientViewReqT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int i = 0;
    struct ZbZclClusterCommandReqT cmd_req;

    /* Group ID */
    putle16(&payload[i], req->group_id);
    i += 2;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = req->dst;
    cmd_req.cmdId = ZCL_GROUPS_COMMAND_VIEW;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    cmd_req.payload = payload;
    cmd_req.length = i;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

enum ZclStatusCodeT
ZbZclGroupsClientGetMembershipReq(struct ZbZclClusterT *cluster,
    struct ZbZclGroupsClientGetMembershipReqT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int i = 0, j;
    struct ZbZclClusterCommandReqT cmd_req;

    payload[i++] = req->num_groups;
    for (j = 0; j < req->num_groups; j++) {
        if ((i + 2) > ZCL_PAYLOAD_UNFRAG_SAFE_SIZE) {
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }
        putle16(&payload[i], req->group_list[j]);
        i += 2;
    }

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = req->dst;
    cmd_req.cmdId = ZCL_GROUPS_COMMAND_GET_MEMBERSHIP;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    cmd_req.payload = payload;
    cmd_req.length = i;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

enum ZclStatusCodeT
ZbZclGroupsClientRemoveReq(struct ZbZclClusterT *cluster,
    struct ZbZclGroupsClientRemoveReqT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int i = 0;
    struct ZbZclClusterCommandReqT cmd_req;

    /* Group ID */
    putle16(&payload[i], req->group_id);
    i += 2;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = req->dst;
    cmd_req.cmdId = ZCL_GROUPS_COMMAND_REMOVE;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    cmd_req.payload = payload;
    cmd_req.length = i;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

enum ZclStatusCodeT
ZbZclGroupsClientRemoveAllReq(struct ZbZclClusterT *cluster, struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    struct ZbZclClusterCommandReqT cmd_req;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = *dst;
    cmd_req.cmdId = ZCL_GROUPS_COMMAND_REMOVE_ALL;
    cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE; /* No cluster specific response */
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}

enum ZclStatusCodeT
ZbZclGroupsClientAddIdentifyingReq(struct ZbZclClusterT *cluster,
    struct ZbZclGroupsClientAddIdentifyingReqT *req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int i = 0;
    struct ZbZclClusterCommandReqT cmd_req;

    /* Group ID */
    putle16(&payload[i], req->group_id);
    i += 2;
    /* Group Name */
    payload[i++] = 0x00;

    (void)memset(&cmd_req, 0, sizeof(cmd_req));
    cmd_req.dst = req->dst;
    cmd_req.cmdId = ZCL_GROUPS_COMMAND_ADD_IDENTIFYING;
    if (ZbApsAddrIsBcast(&req->dst)) {
        cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    }
    else {
        cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    }
    cmd_req.payload = payload;
    cmd_req.length = i;
    return ZbZclClusterCommandReq(cluster, &cmd_req, callback, arg);
}
