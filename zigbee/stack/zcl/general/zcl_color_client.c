/* Copyright [2016 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/general/zcl.onoff.h"
#include "zcl/general/zcl.level.h"
#include "zcl/general/zcl.color.h"
#include "zcl/zcl.payload.h"

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
};

struct ZbZclClusterT *
ZbZclColorClientAlloc(struct ZigBeeT *zb, uint8_t endpoint)
{
    struct cluster_priv_t *clusterPtr;

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_COLOR_CONTROL, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (clusterPtr == NULL) {
        return NULL;
    }

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

int
ZbZclColorClientMoveToHueBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientMoveToHueReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, req->hue) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, length, &index, req->direction) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientMoveHueBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientMoveHueReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, req->move_mode) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, length, &index, req->rate) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientStepHueBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientStepHueReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, req->step_mode) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, length, &index, req->step_size) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientMoveToSatBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientMoveToSatReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, req->sat) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientMoveSatBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientMoveSatReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, req->move_mode) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, length, &index, req->rate) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientStepSatBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientStepSatReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, req->step_mode) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, length, &index, req->step_size) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientMoveToHueSatBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientMoveToHueSatReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, req->hue) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, length, &index, req->sat) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientMoveToColorXYBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientMoveToColorXYReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint16(payload, length, &index, req->color_x) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->color_y) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }
    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientMoveColorXYBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientMoveColorXYReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint16(payload, length, &index, req->rate_x) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->rate_y) < 0) {
        return -1;
    }
    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientStepColorXYBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientStepColorXYReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint16(payload, length, &index, req->step_x) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->step_y) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }
    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientMoveToColorTempBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientMoveToColorTempReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint16(payload, length, &index, req->color_temp) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }
    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientMoveToHueEnhBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientMoveToHueEnhReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint16(payload, length, &index, req->enh_hue) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, length, &index, req->direction) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientMoveHueEnhBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientMoveHueEnhReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, req->move_mode) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->rate) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientStepHueEnhBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientStepHueEnhReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, req->step_mode) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->step_size) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientMoveToHueSatEnhBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientMoveToHueSatEnhReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint16(payload, length, &index, req->enh_hue) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, length, &index, req->sat) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientColorLoopSetBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientColorLoopSetReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, req->update_flags) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, length, &index, req->action) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, length, &index, req->direction) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->start_hue) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientStopMoveStepBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientStopMoveStepReqT *req)
{
    unsigned int index = 0;

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    else {
        payload = NULL;
    }
    return index;
}

int
ZbZclColorClientMoveColorTempBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientMoveColorTempReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, req->move_mode) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->rate) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->color_temp_min) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->color_temp_max) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

int
ZbZclColorClientStepColorTempBuild(uint8_t *payload, unsigned int length, struct ZbZclColorClientStepColorTempReqT *req)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, req->step_mode) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->step_size) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->transition_time) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->color_temp_min) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, req->color_temp_max) < 0) {
        return -1;
    }

    if (req->mask != 0) {
        if (zb_zcl_append_uint8(payload, length, &index, req->mask) < 0) {
            return -1;
        }
        if (zb_zcl_append_uint8(payload, length, &index, req->override) < 0) {
            return -1;
        }
    }
    return index;
}

#define ZCL_COLOR_CLIENT_REQ_FUNC(func_prefix, cmd_id, req_type) \
    enum ZclStatusCodeT func_prefix ## Req(struct ZbZclClusterT *clusterPtr, \
    const struct ZbApsAddrT *dst, req_type *req, \
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg) \
    { \
        uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE]; \
        int length = 0; \
        struct ZbZclClusterCommandReqT cmd_req; \
         \
        length = func_prefix ## Build(payload, sizeof(payload), req); \
        if (length < 0) { \
            return ZCL_STATUS_INSUFFICIENT_SPACE; \
        } \
        (void)memset(&cmd_req, 0, sizeof(cmd_req)); \
        cmd_req.dst = *dst; \
        cmd_req.cmdId = cmd_id; \
        cmd_req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE; \
        cmd_req.payload = payload; \
        cmd_req.length = length; \
        return ZbZclClusterCommandReq(clusterPtr, &cmd_req, callback, arg); \
    }

ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientMoveToHue, ZCL_COLOR_COMMAND_MOVE_TO_HUE, struct ZbZclColorClientMoveToHueReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientMoveHue, ZCL_COLOR_COMMAND_MOVE_HUE, struct ZbZclColorClientMoveHueReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientStepHue, ZCL_COLOR_COMMAND_STEP_HUE, struct ZbZclColorClientStepHueReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientMoveToSat, ZCL_COLOR_COMMAND_MOVE_TO_SAT, struct ZbZclColorClientMoveToSatReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientMoveSat, ZCL_COLOR_COMMAND_MOVE_SAT, struct ZbZclColorClientMoveSatReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientStepSat, ZCL_COLOR_COMMAND_STEP_SAT, struct ZbZclColorClientStepSatReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientMoveToHueSat, ZCL_COLOR_COMMAND_MOVE_TO_HS, struct ZbZclColorClientMoveToHueSatReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientMoveToColorXY, ZCL_COLOR_COMMAND_MOVE_TO_COLOR, struct ZbZclColorClientMoveToColorXYReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientMoveColorXY, ZCL_COLOR_COMMAND_MOVE_COLOR, struct ZbZclColorClientMoveColorXYReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientStepColorXY, ZCL_COLOR_COMMAND_STEP_COLOR, struct ZbZclColorClientStepColorXYReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientMoveToColorTemp, ZCL_COLOR_COMMAND_MOVE_TO_COLOR_TEMP, struct ZbZclColorClientMoveToColorTempReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientMoveToHueEnh, ZCL_COLOR_COMMAND_ENH_MOVE_TO_HUE, struct ZbZclColorClientMoveToHueEnhReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientMoveHueEnh, ZCL_COLOR_COMMAND_ENH_MOVE_HUE, struct ZbZclColorClientMoveHueEnhReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientStepHueEnh, ZCL_COLOR_COMMAND_ENH_STEP_HUE, struct ZbZclColorClientStepHueEnhReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientMoveToHueSatEnh, ZCL_COLOR_COMMAND_ENH_MOVE_TO_HS, struct ZbZclColorClientMoveToHueSatEnhReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientColorLoopSet, ZCL_COLOR_COMMAND_COLOR_LOOP_SET, struct ZbZclColorClientColorLoopSetReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientStopMoveStep, ZCL_COLOR_COMMAND_STOP_MOVE_STEP, struct ZbZclColorClientStopMoveStepReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientMoveColorTemp, ZCL_COLOR_COMMAND_MOVE_COLOR_TEMP, struct ZbZclColorClientMoveColorTempReqT)
ZCL_COLOR_CLIENT_REQ_FUNC(ZbZclColorClientStepColorTemp, ZCL_COLOR_COMMAND_STEP_COLOR_TEMP, struct ZbZclColorClientStepColorTempReqT)
