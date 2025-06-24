/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/se/zcl.price.h"

/* Price client information struct. */
struct cluster_priv_t {
    struct ZbZclClusterT cluster;
    struct ZbZclPriceClientCallbacksT callbacks;
};

static enum ZclStatusCodeT ZbZclPriceClientCommand(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclPriceClientAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclPriceClientCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *cluster;

    cluster = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t),
            ZCL_CLUSTER_PRICE, endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (cluster == NULL) {
        return NULL;
    }
    cluster->cluster.command = ZbZclPriceClientCommand;

    /* Assume this is for SE */
    ZbZclClusterSetProfileId(&cluster->cluster, ZCL_PROFILE_SMART_ENERGY);

    if (!ZbZclClusterSetMinSecurity(&cluster->cluster, ZB_APS_STATUS_SECURED_LINK_KEY)) {
        ZbZclClusterFree(&cluster->cluster);
        return NULL;
    }
    if (!ZbZclClusterSetMaxAsduLength(&cluster->cluster, ZCL_ASDU_LENGTH_SMART_ENERGY)) {
        ZbZclClusterFree(&cluster->cluster);
        return NULL;
    }

    ZbZclClusterSetCallbackArg(&cluster->cluster, arg);
    if (callbacks != NULL) {
        (void)memcpy(&cluster->callbacks, callbacks, sizeof(struct ZbZclPriceClientCallbacksT));
    }
    else {
        (void)memset(&cluster->callbacks, 0, sizeof(struct ZbZclPriceClientCallbacksT));
    }

    (void)ZbZclClusterAttach(&cluster->cluster);
    return &cluster->cluster;
}

static enum ZclStatusCodeT
ZbZclPriceClientCommand(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr,
    struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;
    struct ZbZclAddrInfoT srcInfo;
    enum ZclStatusCodeT rc;
    unsigned int i = 0;

    if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    (void)memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zclHdrPtr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    switch (zclHdrPtr->cmdId) {
        case (uint8_t)ZCL_PRICE_SVR_CMD_PUB_PRICE:
        {
            struct ZbZclPriceServerPublishPriceT price;
            uint8_t str_len;

            if (client->callbacks.publish_price == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }

            /* Optional parameters set to all 1's indicate not present. */
            memset(&price, 0xffU, sizeof(price));
            if (dataIndPtr->asduLength < ZCL_PRICE_PUBLISH_MIN_SIZE) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }

            price.provider_id = pletoh32(&dataIndPtr->asdu[i]);
            i += 4;
            str_len = dataIndPtr->asdu[i++];
            memset(price.rate_lable, 0, sizeof(price.rate_lable));
            if (str_len > 0) {
                if (str_len > ZCL_PRICE_LABEL_MAX_LENGTH) {
                    return ZCL_STATUS_MALFORMED_COMMAND;
                }
                if (dataIndPtr->asduLength < (ZCL_PRICE_PUBLISH_MIN_SIZE + str_len)) {
                    return ZCL_STATUS_MALFORMED_COMMAND;
                }
                memcpy(price.rate_lable, &dataIndPtr->asdu[i], str_len);
                i += str_len;
            }
            price.issuer_event_id = pletoh32(&dataIndPtr->asdu[i]);
            i += 4;
            price.current_Time = pletoh32(&dataIndPtr->asdu[i]);
            i += 4;
            price.unit_of_measure = (enum ZbZclMeterUnitsT)dataIndPtr->asdu[i++];
            price.currency = pletoh16(&dataIndPtr->asdu[i]);
            i += 2;
            price.trailing_digit_and_price_tier = dataIndPtr->asdu[i++];
            price.num_price_tiers = dataIndPtr->asdu[i++];
            price.start_time = pletoh32(&dataIndPtr->asdu[i]);
            i += 4;
            price.duration = pletoh16(&dataIndPtr->asdu[i]);
            i += 2;
            price.price = pletoh32(&dataIndPtr->asdu[i]);
            i += 4;

            /* Optional parameters. */
            do {
                if ((i + 1) > dataIndPtr->asduLength) {
                    break;
                }
                price.price_ratio = dataIndPtr->asdu[i++];

                if ((i + 4) > dataIndPtr->asduLength) {
                    break;
                }
                price.generation_price = pletoh32(&dataIndPtr->asdu[i]);
                i += 4;

                if ((i + 1) > dataIndPtr->asduLength) {
                    break;
                }
                price.generation_price_ratio = dataIndPtr->asdu[i++];

                if ((i + 4) > dataIndPtr->asduLength) {
                    break;
                }
                price.alternate_cost_delivered = pletoh32(&dataIndPtr->asdu[i]);
                i += 4;

                if ((i + 1) > dataIndPtr->asduLength) {
                    break;
                }
                price.alternate_cost_units = dataIndPtr->asdu[i++];

                if ((i + 1) > dataIndPtr->asduLength) {
                    break;
                }
                price.alternate_cost_trail_digits = dataIndPtr->asdu[i++];

                if ((i + 1) > dataIndPtr->asduLength) {
                    break;
                }
                price.num_block_thresholds = dataIndPtr->asdu[i++];

                if ((i + 1) > dataIndPtr->asduLength) {
                    break;
                }
                price.price_control = dataIndPtr->asdu[i++];

                if ((i + 1) > dataIndPtr->asduLength) {
                    break;
                }
                price.number_of_gen_tiers = dataIndPtr->asdu[i++];

                if ((i + 1) > dataIndPtr->asduLength) {
                    break;
                }
                price.gen_tier = dataIndPtr->asdu[i++];

                if ((i + 1) > dataIndPtr->asduLength) {
                    break;
                }
                price.ext_number_price_tiers = dataIndPtr->asdu[i++];

                if ((i + 1) > dataIndPtr->asduLength) {
                    break;
                }
                price.ext_price_tier = dataIndPtr->asdu[i++];

                if ((i + 1) > dataIndPtr->asduLength) {
                    break;
                }
                price.ext_register_tier = dataIndPtr->asdu[i++];
            } while (false);

            rc = client->callbacks.publish_price(cluster, client->cluster.app_cb_arg, &price, &srcInfo);
            break;
        }

        default:
            /* For all other commands, check if the application can handle them. */
            if (client->callbacks.optional == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            rc = client->callbacks.optional(cluster, zclHdrPtr, dataIndPtr);
            break;
    }
    return rc;
}

enum ZclStatusCodeT
ZbZclPriceClientCommandGetCurrentPriceReq(struct ZbZclClusterT *cluster,
    const struct ZbApsAddrT *dst,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;
    uint8_t capability;

    (void)ZbNwkGet(cluster->zb, ZB_NWK_NIB_ID_CapabilityInformation, &capability, sizeof(uint8_t));

    payload[length] = 0;
    if ((capability & MCP_ASSOC_CAP_RXONIDLE) != 0U) {
        payload[length] |= ZCL_PRICE_GET_FLAGS_RX_ON_IDLE;
    }
    length++;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_PRICE_CLI_CMD_GET_CURRENT_PRICE;
    /* Server will send a Default Response, and may send a Publish command
     * as a separate ZCL request. */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclPriceClientCommandGetScheduledPricesReq(struct ZbZclClusterT *cluster,
    const struct ZbApsAddrT *dst, struct ZbZclPriceClientGetScheduledPricesT *cmd_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    putle32(&payload[length], cmd_req->startTime);
    length += 4U;
    payload[length++] = cmd_req->maxPrices;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_PRICE_CLI_CMD_GET_SCHEDULED_PRICES;
    /* Server will send a Default Response, and may send a Publish command
     * as a separate ZCL request. */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclPriceClientCommandPriceAckReq(struct ZbZclClusterT *cluster,
    const struct ZbApsAddrT *dst, struct ZbZclPriceClientPriceAckT *cmd_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    putle32(&payload[length], cmd_req->provider_id);
    length += 4U;
    putle32(&payload[length], cmd_req->issuer_event_id);
    length += 4U;
    putle32(&payload[length], cmd_req->price_ack_time);
    length += 4U;
    payload[length++] = cmd_req->control;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_PRICE_CLI_CMD_PRICE_ACKNOWLEDGEMENT;
    /* Price ACK doesn't generate a response, so request a Default Response. */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclPriceClientCommandGetTariffInfoReq(struct ZbZclClusterT *cluster,
    const struct ZbApsAddrT *dst, struct ZbZclPriceClientGetTariffInfoT *cmd_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    putle32(&payload[length], cmd_req->earliest_start_time);
    length += 4U;
    putle32(&payload[length], cmd_req->min_issuer_event_id);
    length += 4U;
    payload[length++] = cmd_req->num_commands;
    payload[length++] = cmd_req->tariff_type;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_PRICE_CLI_CMD_GET_TARIFF_INFORMATION;
    /* Server will send a Default Response, and may send a Publish command
     * as a separate ZCL request. */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclPriceClientCommandGetPriceMatrixReq(struct ZbZclClusterT *cluster,
    const struct ZbApsAddrT *dst, struct ZbZclPriceClientGetPriceMatrixT *cmd_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    putle32(&payload[length], cmd_req->issuer_tariff_id);
    length += 4U;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_PRICE_CLI_CMD_GET_PRICE_MATRIX;
    /* Server will send a Default Response, and may send a Publish command
     * as a separate ZCL request. */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}

enum ZclStatusCodeT
ZbZclPriceClientCommandGetBlockThresholdsReq(struct ZbZclClusterT *cluster,
    const struct ZbApsAddrT *dst, struct ZbZclPriceClientGetBlockThresholdsT *cmd_req,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int length = 0;
    struct ZbZclClusterCommandReqT req;

    putle32(&payload[length], cmd_req->issuer_tariff_id);
    length += 4U;

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = (uint8_t)ZCL_PRICE_CLI_CMD_GET_BLOCK_THRESHOLDS;
    /* Server will send a Default Response, and may send a Publish command
     * as a separate ZCL request. */
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(cluster, &req, callback, arg);
}
