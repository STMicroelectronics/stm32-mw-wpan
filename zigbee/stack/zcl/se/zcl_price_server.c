/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

#include "zcl/se/zcl.price.h"

/*lint -save -e9087 "cluster_priv_t* <- ZbZclClusterT* [MISRA Rule 11.3 (REQUIRED)]" */

/* Price server information struct. */
struct cluster_priv_t {
    struct ZbZclClusterT cluster;
    struct ZbZclPriceServerCallbacksT callbacks;
};

static enum ZclStatusCodeT zcl_price_server_command(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);

struct ZbZclClusterT *
ZbZclPriceServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, struct ZbZclPriceServerCallbacksT *callbacks, void *arg)
{
    struct cluster_priv_t *cluster;

    cluster = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_PRICE, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (cluster == NULL) {
        return NULL;
    }
    cluster->cluster.command = zcl_price_server_command;

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
        (void)memcpy(&cluster->callbacks, callbacks, sizeof(struct ZbZclPriceServerCallbacksT));
    }
    else {
        (void)memset(&cluster->callbacks, 0, sizeof(struct ZbZclPriceServerCallbacksT));
    }

    (void)ZbZclClusterAttach(&cluster->cluster);
    return &cluster->cluster;
}

void
ZbZclPriceServerPublishPriceInit(struct ZbZclPriceServerPublishPriceT *notify)
{
    (void)memset(notify, 0, sizeof(struct ZbZclPriceServerPublishPriceT));
    /* Initialize the optional values */
    notify->price_ratio = 0xffU;
    notify->generation_price = 0xffffffffU;
    notify->generation_price_ratio = 0xffU;
    notify->alternate_cost_delivered = 0xffffffffU;
    notify->alternate_cost_units = 0xffU;
    notify->alternate_cost_trail_digits = 0xffU;
    notify->num_block_thresholds = 0xffU;
    notify->price_control = 0xffU;
    notify->number_of_gen_tiers = 0xffU;
    notify->gen_tier = 0xffU;
    notify->ext_number_price_tiers = 0xffU;
    notify->ext_price_tier = 0xffU;
    notify->ext_register_tier = 0xffU;
}

enum ZclStatusCodeT
ZbZclPriceServerSendPublishPrice(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPriceServerPublishPriceT *notify,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_ASDU_LENGTH_SMART_ENERGY]; /* may require fragmentation */
    unsigned int i = 0;
    struct ZbZclClusterCommandReqT req;
    unsigned int str_len;

    /* Form the payload */
    putle32(&payload[i], notify->provider_id);
    i += 4U;

    str_len = strlen(notify->rate_lable);
    if (str_len > ZCL_PRICE_LABEL_MAX_LENGTH) {
        return ZCL_STATUS_INVALID_VALUE;
    }
    payload[i++] = (uint8_t)str_len;
    (void)memcpy(&payload[i], notify->rate_lable, str_len);
    i += str_len;

    putle32(&payload[i], notify->issuer_event_id);
    i += 4U;
    putle32(&payload[i], notify->current_Time);
    i += 4U;
    payload[i++] = (uint8_t)notify->unit_of_measure;
    putle16(&payload[i], notify->currency);
    i += 2U;
    payload[i++] = notify->trailing_digit_and_price_tier;
    payload[i++] = notify->num_price_tiers;
    putle32(&payload[i], notify->start_time);
    i += 4U;
    putle16(&payload[i], notify->duration);
    i += 2U;
    putle32(&payload[i], notify->price);
    i += 4U;

    /* Optional parameters (all fields are still present) */
    payload[i++] = notify->price_ratio;
    putle32(&payload[i], notify->generation_price);
    i += 4U;
    payload[i++] = notify->generation_price_ratio;
    putle32(&payload[i], notify->alternate_cost_delivered);
    i += 4U;
    payload[i++] = notify->alternate_cost_units;
    payload[i++] = notify->alternate_cost_trail_digits;
    payload[i++] = notify->num_block_thresholds;
    payload[i++] = notify->price_control;
    payload[i++] = notify->number_of_gen_tiers;
    payload[i++] = notify->gen_tier;
    payload[i++] = notify->ext_number_price_tiers;
    payload[i++] = notify->ext_price_tier;
    payload[i++] = notify->ext_register_tier;

    /* dstInfo->tx_options |= ZB_APSDE_DATAREQ_TXOPTIONS_FRAG; */

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_PRICE_SVR_CMD_PUB_PRICE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = i;
    return ZbZclClusterCommandReqDelayed(cluster, &req, ZB_NWK_RSP_DELAY_DEFAULT, callback, arg);
}

enum ZclStatusCodeT
ZbZclPriceServerSendPublishTariffInfo(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPriceServerPublishTariffInfoT *notify,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_ASDU_LENGTH_SMART_ENERGY]; /* may require fragmentation */
    unsigned int i = 0;
    struct ZbZclClusterCommandReqT req;
    unsigned int str_len;

    /* Form the payload */
    putle32(&payload[i], notify->provider_id);
    i += 4U;
    putle32(&payload[i], notify->issuer_event_id);
    i += 4U;
    putle32(&payload[i], notify->issuer_tariff_id);
    i += 4U;
    putle32(&payload[i], notify->start_time);
    i += 4U;
    payload[i++] = notify->tariff_type_and_charging_scheme;

    str_len = strlen(notify->tariff_label);
    if (str_len > ZCL_PRICE_TARIFF_LABEL_MAX_LENGTH) {
        return ZCL_STATUS_INVALID_VALUE;
    }
    payload[i++] = (uint8_t)str_len;
    (void)memcpy(&payload[i], notify->tariff_label, str_len);
    i += str_len;

    payload[i++] = notify->number_of_price_tiers_in_use;
    payload[i++] = notify->number_of_block_thresh_in_use;
    payload[i++] = (uint8_t)notify->unit_of_measure;
    putle16(&payload[i], notify->currency);
    i += 2U;
    payload[i++] = notify->price_trailing_digit;
    putle32(&payload[i], notify->standing_charge);
    i += 4U;
    payload[i++] = notify->tier_block_mode;
    putle24(&payload[i], notify->block_thresh_multiplier);
    i += 3U;
    putle24(&payload[i], notify->block_thresh_divisor);
    i += 3U;

    /* dstInfo->tx_options |= ZB_APSDE_DATAREQ_TXOPTIONS_FRAG; */

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_PRICE_SVR_CMD_PUB_TARIFF_INFORMATION;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = i;
    return ZbZclClusterCommandReqDelayed(cluster, &req, ZB_NWK_RSP_DELAY_DEFAULT, callback, arg);
}

enum ZclStatusCodeT
ZbZclPriceServerSendPublishMatrix(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPriceServerPublishPriceMatrixT *notify,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_ASDU_LENGTH_SMART_ENERGY]; /* may require fragmentation */
    unsigned int i = 0, j;
    struct ZbZclClusterCommandReqT req;

    /* Sanity check */
    if (notify->num_sub_paylad > ZCL_PRICE_SVR_PRICE_MATRIX_NUM_SUB_PAYLOAD_MAX) {
        return ZCL_STATUS_INVALID_VALUE;
    }

    /* Form the payload */
    putle32(&payload[i], notify->provider_id);
    i += 4U;
    putle32(&payload[i], notify->issuer_event_id);
    i += 4U;
    putle32(&payload[i], notify->start_time);
    i += 4U;
    putle32(&payload[i], notify->issuer_tariff_id);
    i += 4U;
    payload[i++] = notify->command_index;
    payload[i++] = notify->total_number_commands;
    payload[i++] = notify->sub_payload_control;

    for (j = 0; j < notify->num_sub_paylad; j++) {
        payload[i++] = notify->sub_payload[j].tier_block_id;
        putle32(&payload[i], notify->sub_payload[j].price);
        i += 4U;
    }

    /* dstInfo->tx_options |= ZB_APSDE_DATAREQ_TXOPTIONS_FRAG; */

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_PRICE_SVR_CMD_PUB_PRICE_MATRIX;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = i;
    return ZbZclClusterCommandReqDelayed(cluster, &req, ZB_NWK_RSP_DELAY_DEFAULT, callback, arg);
}

enum ZclStatusCodeT
ZbZclPriceServerSendPublishBlockThresholds(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclPriceServerPublishBlockThresholdsT *notify,
    void (*callback)(struct ZbZclCommandRspT *rsp, void *arg), void *arg)
{
    uint8_t payload[ZCL_ASDU_LENGTH_SMART_ENERGY]; /* may require fragmentation */
    unsigned int i = 0, j, k;
    struct ZbZclClusterCommandReqT req;

    /* Sanity check */
    if (notify->num_sub_paylad > ZCL_PRICE_SVR_BLOCK_THRESH_NUM_SUB_PAYLOAD_MAX) {
        return ZCL_STATUS_INVALID_VALUE;
    }

    /* Form the payload */
    putle32(&payload[i], notify->provider_id);
    i += 4U;
    putle32(&payload[i], notify->issuer_event_id);
    i += 4U;
    putle32(&payload[i], notify->start_time);
    i += 4U;
    putle32(&payload[i], notify->issuer_tariff_id);
    i += 4U;
    payload[i++] = notify->command_index;
    payload[i++] = notify->total_number_commands;
    payload[i++] = notify->sub_payload_control;

    for (j = 0; j < notify->num_sub_paylad; j++) {
        uint8_t num_blocks = notify->sub_payload[j].tier & 0x0fU;

        if ((i + 1U + (6U * (unsigned int)num_blocks)) > sizeof(payload)) {
            return ZCL_STATUS_INSUFFICIENT_SPACE;
        }
        payload[i++] = notify->sub_payload[j].tier;
        for (k = 0; k < num_blocks; k++) {
            putle48(&payload[i], notify->sub_payload[j].block_thresh[k]);
            i += 6U;
        }
    }

    /* dstInfo->tx_options |= ZB_APSDE_DATAREQ_TXOPTIONS_FRAG; */

    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_PRICE_SVR_CMD_PUB_BLK_THRESHOLDS;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = i;
    return ZbZclClusterCommandReqDelayed(cluster, &req, ZB_NWK_RSP_DELAY_DEFAULT, callback, arg);
}

static enum ZclStatusCodeT
zcl_price_server_command(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *serverPtr = (struct cluster_priv_t *)cluster;
    unsigned int i = 0;
    enum ZclStatusCodeT rc = ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    struct ZbZclAddrInfoT srcInfo;

    (void)memset(&srcInfo, 0, sizeof(srcInfo));
    srcInfo.addr = dataIndPtr->src;
    srcInfo.seqnum = zclHdrPtr->seqNum;
    srcInfo.tx_options = ZbZclTxOptsFromSecurityStatus(dataIndPtr->securityStatus);

    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (zclHdrPtr->frameCtrl.manufacturer != 0U) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&dataIndPtr->dst)) {
        /* Drop bcast messages */
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    switch (zclHdrPtr->cmdId) {
        case (uint8_t)ZCL_PRICE_CLI_CMD_GET_CURRENT_PRICE:
            if (serverPtr->callbacks.get_current_price != NULL) {
                struct ZbZclPriceClientGetCurrentPriceT req;

                if (dataIndPtr->asduLength < 1U) {
                    rc = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }

                (void)memset(&req, 0, sizeof(req));
                req.command_options = dataIndPtr->asdu[i];

                rc = serverPtr->callbacks.get_current_price(cluster, serverPtr->cluster.app_cb_arg, &req, &srcInfo);
            }
            else {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
            }
            break;

        case (uint8_t)ZCL_PRICE_CLI_CMD_PRICE_ACKNOWLEDGEMENT:
            if (serverPtr->callbacks.price_ack != NULL) {
                struct ZbZclPriceClientPriceAckT req;

                if (dataIndPtr->asduLength < 13U) {
                    rc = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }

                (void)memset(&req, 0, sizeof(req));
                req.provider_id = pletoh32(&dataIndPtr->asdu[i]);
                i += 4U;
                req.issuer_event_id = pletoh32(&dataIndPtr->asdu[i]);
                i += 4U;
                req.price_ack_time = pletoh32(&dataIndPtr->asdu[i]);
                i += 4U;
                req.control = dataIndPtr->asdu[i];

                rc = serverPtr->callbacks.price_ack(cluster, serverPtr->cluster.app_cb_arg, &req, &srcInfo);
                /* Reply with a Default Response */
            }
            else {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
            }
            break;

        case (uint8_t)ZCL_PRICE_CLI_CMD_GET_TARIFF_INFORMATION:
            if (serverPtr->callbacks.get_tariff_info != NULL) {
                struct ZbZclPriceClientGetTariffInfoT req;

                if (dataIndPtr->asduLength < 10U) {
                    rc = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }

                (void)memset(&req, 0, sizeof(req));
                req.earliest_start_time = pletoh32(&dataIndPtr->asdu[i]);
                i += 4U;
                req.min_issuer_event_id = pletoh32(&dataIndPtr->asdu[i]);
                i += 4U;
                req.num_commands = dataIndPtr->asdu[i++];
                req.tariff_type = dataIndPtr->asdu[i];

                rc = serverPtr->callbacks.get_tariff_info(cluster, serverPtr->cluster.app_cb_arg, &req, &srcInfo);
            }
            else {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
            }
            break;

        case (uint8_t)ZCL_PRICE_CLI_CMD_GET_PRICE_MATRIX:
            if (serverPtr->callbacks.get_price_matrix != NULL) {
                struct ZbZclPriceClientGetPriceMatrixT req;

                if (dataIndPtr->asduLength < 4U) {
                    rc = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }

                (void)memset(&req, 0, sizeof(req));
                req.issuer_tariff_id = pletoh32(&dataIndPtr->asdu[i]);

                rc = serverPtr->callbacks.get_price_matrix(cluster, serverPtr->cluster.app_cb_arg, &req, &srcInfo);
            }
            else {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
            }
            break;

        case (uint8_t)ZCL_PRICE_CLI_CMD_GET_BLOCK_THRESHOLDS:
            if (serverPtr->callbacks.get_block_thresholds != NULL) {
                struct ZbZclPriceClientGetBlockThresholdsT req;

                if (dataIndPtr->asduLength < 4U) {
                    rc = ZCL_STATUS_MALFORMED_COMMAND;
                    break;
                }

                (void)memset(&req, 0, sizeof(req));
                req.issuer_tariff_id = pletoh32(&dataIndPtr->asdu[i]);

                rc = serverPtr->callbacks.get_block_thresholds(cluster, serverPtr->cluster.app_cb_arg, &req, &srcInfo);
            }
            else {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
            }
            break;

        default:
            if (serverPtr->callbacks.optional == NULL) {
                rc = ZCL_STATUS_UNSUPP_COMMAND;
                break;
            }
            rc = serverPtr->callbacks.optional(cluster, zclHdrPtr, dataIndPtr);
            break;
    }
    return rc;
}

/*lint -restore */
