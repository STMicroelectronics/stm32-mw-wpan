/* Copyright [2017 - 2025] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl/general/zcl.ota.h"
#include "zcl/general/zcl.time.h"
#include "zcl/zcl.payload.h"

/* cluster definition */
struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    uint16_t minimum_block_period;
    uint32_t upgrade_end_current_time;
    uint32_t upgrade_end_upgrade_time;
    ZbZclOtaServerImageEvalT image_eval;
    ZbZclOtaServerImageReadT image_read;
    ZbZclOtaServerUpgradeEndReqT image_upgrade_end_req;
};

static enum ZclStatusCodeT cluster_command(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind);

static enum ZclStatusCodeT parse_query_next_image_req(const uint8_t *payload, const unsigned int length,
    struct ZbZclOtaImageDefinition *image_definition, uint8_t *field_control, uint16_t *hardware_version);
static enum ZclStatusCodeT parse_image_block_req(const uint8_t *payload, const unsigned int length,
    struct ZbZclOtaImageDefinition *image_definition, struct ZbZclOtaImageData *image_data,
    uint8_t *field_control, uint64_t *ieee_addr, struct ZbZclOtaImageWaitForData *image_wait);
static enum ZclStatusCodeT parse_query_upgrade_end_req(const uint8_t *payload, const unsigned int length,
    struct ZbZclOtaImageDefinition *image_definition, enum ZclStatusCodeT *status);

#if 0 /* EXEGIN - not called  */
static int build_image_notify_req(uint8_t *payload, unsigned int length,
    uint8_t payload_type, uint8_t jitter, struct ZbZclOtaImageDefinition *ota_header);
#endif
static int build_query_next_image_rsp(uint8_t *payload, const unsigned int length,
    uint8_t status, struct ZbZclOtaImageDefinition *image_definition, uint32_t total_image_size);
static int build_image_block_rsp_wait_for_data(uint8_t *payload,
    const unsigned int length, struct ZbZclOtaImageWaitForData *image_wait);
static int build_image_block_rsp_abort(uint8_t *payload, const unsigned int length);
static int build_image_block_rsp_success(uint8_t *payload, const unsigned int capacity,
    struct ZbZclOtaImageDefinition *image_definition,
    struct ZbZclOtaImageData *image_data);
static int build_upgrade_end_rsp(uint8_t *payload, unsigned int capacity,
    struct ZbZclOtaImageDefinition *image_definition, uint32_t current_time, uint32_t upgrade_time);

static void handle_query_image_req(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind);
static void handle_image_block_req(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind);
static void handle_upgrade_end_req(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind);

struct ZbZclClusterT *
ZbZclOtaServerAlloc(struct ZigBeeT *zb, struct ZbZclOtaServerConfig *config, void *arg)
{
    struct cluster_priv_t *clusterPtr;

    if ((config->image_eval == NULL) || (config->image_read == NULL)) {
        return NULL;
    }

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t),
            ZCL_CLUSTER_OTA_UPGRADE, config->endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Revision 2 implements: "alternative Image Activation Policies; 128-bit Crypto suite, Smart Energy Profile 1.2a & 1.2b"
     * Revision 3 implements: "CCB 2219 2220 2221 2222 2223 2224 2225 2226 2227 2228 2296 2307 2315 2342 2398 2464"
     * (need to investigate these changes) */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 1);

    clusterPtr->cluster.command = cluster_command;
    clusterPtr->cluster.app_cb_arg = arg;

    clusterPtr->cluster.txOptions &= ~(ZB_APSDE_DATAREQ_TXOPTIONS_FRAG);

    clusterPtr->minimum_block_period = config->minimum_block_period;
    clusterPtr->image_eval = config->image_eval;
    clusterPtr->image_read = config->image_read;
    clusterPtr->image_upgrade_end_req = config->image_upgrade_end_req;
    clusterPtr->upgrade_end_current_time = config->upgrade_end_current_time;
    clusterPtr->upgrade_end_upgrade_time = config->upgrade_end_upgrade_time;

    /* reset as OTA can be used for Z3 and ZSE */
    ZbZclClusterSetProfileId(&clusterPtr->cluster, config->profile_id);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static enum ZclStatusCodeT
cluster_command(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind)
{
    /* ZCL_LOG_PRINTF(cluster->zb, __func__, "received command 0x%02x %s", zcl_header->cmdId,
        zcl_header->frameCtrl.direction == ZCL_DIRECTION_TO_CLIENT ? "to client" : "to server"); */

    if (zcl_header->frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (ZbApsAddrIsBcast(&data_ind->dst)) {
        return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
    }

    switch (zcl_header->cmdId) {
        case ZCL_OTA_COMMAND_QUERY_IMAGE_REQUEST:
            handle_query_image_req(cluster, zcl_header, data_ind);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

        case ZCL_OTA_COMMAND_IMAGE_BLOCK_REQUEST:
            handle_image_block_req(cluster, zcl_header, data_ind);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

        case ZCL_OTA_COMMAND_UPGRADE_END_REQUEST:
            handle_upgrade_end_req(cluster, zcl_header, data_ind);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

        default:
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
}

/*
 * ZCL Message Parsers
 */
static enum ZclStatusCodeT
parse_query_next_image_req(const uint8_t *payload, const unsigned int length,
    struct ZbZclOtaImageDefinition *image_definition,
    uint8_t *field_control, uint16_t *hardware_version)
{
    unsigned int index = 0;

    if (image_definition) {

        (void)memset(image_definition, 0, sizeof(struct ZbZclOtaImageDefinition));

        if (zb_zcl_parse_uint8(payload, length, &index, field_control) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (zb_zcl_parse_uint16(payload, length, &index, &image_definition->manufacturer_code) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (zb_zcl_parse_uint16(payload, length, &index, &image_definition->image_type) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }
        if (zb_zcl_parse_uint32(payload, length, &index, &image_definition->file_version) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (*field_control & ZCL_OTA_QUERY_FIELD_CONTROL_HW_VERSION) {
            if (zb_zcl_parse_uint16(payload, length, &index, hardware_version) < 0) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
        }

        return ZCL_STATUS_SUCCESS;
    }
    else {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
}

static enum ZclStatusCodeT
parse_image_block_req(const uint8_t *payload, const unsigned int length, struct ZbZclOtaImageDefinition *image_definition,
    struct ZbZclOtaImageData *image_data, uint8_t *field_control, uint64_t *ieee_addr,
    struct ZbZclOtaImageWaitForData *image_wait)
{
    unsigned int index = 0;

    if (image_definition) {

        (void)memset(image_definition, 0, sizeof(struct ZbZclOtaImageDefinition));

        if (zb_zcl_parse_uint8(payload, length, &index, field_control) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (zb_zcl_parse_uint16(payload, length, &index, &image_definition->manufacturer_code) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (zb_zcl_parse_uint16(payload, length, &index, &image_definition->image_type) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (zb_zcl_parse_uint32(payload, length, &index, &image_definition->file_version) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        (void)memset(image_data, 0, sizeof(struct ZbZclOtaImageData));

        if (zb_zcl_parse_uint32(payload, length, &index, &image_data->file_offset) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (zb_zcl_parse_uint8(payload, length, &index, &image_data->data_size) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (*field_control & ZCL_OTA_IMAGE_BLOCK_FC_IEEE) {
            if (zb_zcl_parse_uint64(payload, length, &index, ieee_addr) < 0) {
                return ZCL_STATUS_UNSUPP_COMMAND;
            }
        }

        (void)memset(image_wait, 0, sizeof(struct ZbZclOtaImageWaitForData));

        if (*field_control & ZCL_OTA_IMAGE_BLOCK_FC_MIN_PERIOD) {
            if (zb_zcl_parse_uint16(payload, length, &index, &image_wait->minimum_block_period) < 0) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
        }

        return ZCL_STATUS_SUCCESS;
    }
    else {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
}

static enum ZclStatusCodeT
parse_query_upgrade_end_req(const uint8_t *payload, const unsigned int length,
    struct ZbZclOtaImageDefinition *image_definition, enum ZclStatusCodeT *status)
{
    unsigned int index = 0;

    if (image_definition) {
        uint8_t uint8_val;

        *status = ZCL_STATUS_FAILURE;
        (void)memset(image_definition, 0, sizeof(struct ZbZclOtaImageDefinition));

        if (zb_zcl_parse_uint8(payload, length, &index, &uint8_val) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }
        *status = (enum ZclStatusCodeT)uint8_val;

        if (zb_zcl_parse_uint16(payload, length, &index, &image_definition->manufacturer_code) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (zb_zcl_parse_uint16(payload, length, &index, &image_definition->image_type) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (zb_zcl_parse_uint32(payload, length, &index, &image_definition->file_version) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        return ZCL_STATUS_SUCCESS;
    }
    else {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
}

/*
 * ZCL Message Builders
 */
#if 0 /* not called  */
static int
build_image_notify_req(uint8_t *payload, unsigned int length,
    uint8_t payload_type, uint8_t jitter, struct ZbZclOtaImageDefinition *ota_header)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, payload_type) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, length, &index, jitter) < 0) {
        return -1;
    }

    if (payload_type == ZCL_OTA_NOTIFY_TYPE_JITTER) {
        return index;
    }

    if (zb_zcl_append_uint16(payload, length, &index, ota_header->manufacturer_code) < 0) {
        return -1;
    }
    if (payload_type == ZCL_OTA_NOTIFY_TYPE_MFG_CODE) {
        return index;
    }

    if (zb_zcl_append_uint16(payload, length, &index, ota_header->image_type) < 0) {
        return -1;
    }
    if (payload_type == ZCL_OTA_NOTIFY_TYPE_IMAGE_TYPE) {
        return index;
    }

    if (zb_zcl_append_uint32(payload, length, &index, ota_header->file_version) < 0) {
        return -1;
    }
    if (payload_type == ZCL_OTA_NOTIFY_TYPE_FILE_VERSION) {
        return index;
    }
    else {
        return -1;
    }
}

#endif

static int
build_query_next_image_rsp(uint8_t *payload, const unsigned int length,
    uint8_t status, struct ZbZclOtaImageDefinition *image_definition, uint32_t total_image_size)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, status) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, image_definition->manufacturer_code) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, image_definition->image_type) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint32(payload, length, &index, image_definition->file_version) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint32(payload, length, &index, total_image_size) < 0) {
        return -1;
    }
    return index;
}

static int
build_image_block_rsp_success(uint8_t *payload, const unsigned int capacity,
    struct ZbZclOtaImageDefinition *image_definition,
    struct ZbZclOtaImageData *image_data)
{
    unsigned int index = 0;

    /* status */
    if (zb_zcl_append_uint8(payload, capacity, &index, ZCL_STATUS_SUCCESS) < 0) {
        return -1;
    }

    /* header */
    if (zb_zcl_append_uint16(payload, capacity, &index, image_definition->manufacturer_code) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, capacity, &index, image_definition->image_type) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint32(payload, capacity, &index, image_definition->file_version) < 0) {
        return -1;
    }

    /* data */
    if (zb_zcl_append_uint32(payload, capacity, &index, image_data->file_offset) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, capacity, &index, image_data->data_size) < 0) {
        return -1;
    }

    /* data */
    if (zb_zcl_append_uint8_array(payload, capacity, &index, image_data->data, image_data->data_size) < 0) {
        return -1;
    }
    return index;
}

static int
build_image_block_rsp_wait_for_data(uint8_t *payload, const unsigned int length, struct ZbZclOtaImageWaitForData *image_wait)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, ZCL_STATUS_WAIT_FOR_DATA) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint32(payload, length, &index, image_wait->current_time) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint32(payload, length, &index, image_wait->request_time) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, image_wait->minimum_block_period) < 0) {
        return -1;
    }
    return index;
}

static int
build_image_block_rsp_abort(uint8_t *payload, const unsigned int capacity)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, capacity, &index, ZCL_STATUS_ABORT) < 0) {
        return -1;
    }
    return index;
}

static int
build_upgrade_end_rsp(uint8_t *payload, unsigned int capacity, struct ZbZclOtaImageDefinition *image_definition,
    uint32_t current_time, uint32_t upgrade_time)
{
    unsigned int index = 0;

    /* header */
    if (zb_zcl_append_uint16(payload, capacity, &index, image_definition->manufacturer_code) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, capacity, &index, image_definition->image_type) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint32(payload, capacity, &index, image_definition->file_version) < 0) {
        return -1;
    }

    /* direct the client with the upgrade time */
    if (zb_zcl_append_uint32(payload, capacity, &index, current_time) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint32(payload, capacity, &index, upgrade_time) < 0) {
        return -1;
    }
    return index;
}

/*
 * ZCL Message callback handlers
 */
static void
handle_query_image_req(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)cluster;
    enum ZclStatusCodeT status;
    uint8_t payload[ZCL_HEADER_MAX_SIZE + 13];
    unsigned int index = 0;
    int result;
    struct ZbZclOtaImageDefinition image_definition;
    uint8_t field_control;
    uint16_t hardware_version = 0x0000; /* fix compiler warning */
    uint32_t total_image_size;

    /* parse */
    status = parse_query_next_image_req(data_ind->asdu, data_ind->asduLength, &image_definition, &field_control, &hardware_version);
    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "failed to parse Query Next Image request (status = 0x%02x)", status);
        return;
    }

    /* build response */
    index = 0;
    if (ota_cluster->image_eval(&image_definition, field_control, hardware_version, &total_image_size, ota_cluster->cluster.app_cb_arg)) {
        result = build_query_next_image_rsp(payload, ZCL_HEADER_MAX_SIZE + 13, ZCL_STATUS_SUCCESS,
                &image_definition, total_image_size);
        if (result < 0) {
            ZCL_LOG_PRINTF(cluster->zb, __func__, "query_next_image_rsp_build failed");
            return;
        }
        index = (unsigned int)result;
        ZbZclSendClusterStatusResponse(cluster, data_ind, zcl_header, ZCL_OTA_COMMAND_QUERY_IMAGE_RESPONSE, payload,
            index, false);
    }
    else {
        if (zb_zcl_append_uint8(payload, ZCL_HEADER_MAX_SIZE + 13, &index, ZCL_STATUS_NO_IMAGE_AVAILABLE) < 0) {
            return;
        }
        ZbZclSendClusterStatusResponse(cluster, data_ind, zcl_header, ZCL_OTA_COMMAND_QUERY_IMAGE_RESPONSE, payload,
            index, false);
    }
}

static void
handle_image_block_req(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)cluster;
    enum ZclStatusCodeT status;
    uint8_t payload[ZB_APS_CONST_MAX_PAYLOAD_SIZE];
    int length;
    struct ZbZclOtaImageDefinition image_definition;
    struct ZbZclOtaImageData image_data;
    struct ZbZclOtaImageWaitForData image_wait;
    uint8_t field_control = 0;
    uint64_t request_node_address = 0;

    /* parse */
    status = parse_image_block_req(data_ind->asdu, data_ind->asduLength, &image_definition, &image_data,
            &field_control, &request_node_address, &image_wait);
    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "failed to parse Image Block request (status = 0x%02x)", status);
        return;
    }

    /* build response, depending on read result */
    /* EXEGIN - include source address of client? */
    status = ota_cluster->image_read(&image_definition, &image_data, field_control,
            request_node_address, &image_wait, ota_cluster->cluster.app_cb_arg);

    if ((status == ZCL_STATUS_SUCCESS) || (status == ZCL_STATUS_WAIT_FOR_DATA)) {
        unsigned int max_data_sz;

        /* The OTA Client may request more data than can safely fit inside a
         * non-fragmented APS frame. Make sure we don't exceed that limit. */
        if (data_ind->securityStatus == ZB_APS_STATUS_SECURED_LINK_KEY) {
            max_data_sz = ZCL_OTA_BLOCK_DATA_SIZE_APSSEC_MAX;
        }
        else {
            max_data_sz = ZCL_OTA_BLOCK_DATA_SIZE_NWKSEC_MAX;
        }
        if (image_data.data_size > max_data_sz) {
            image_data.data_size = max_data_sz;
        }
    }

    switch (status) {
        case ZCL_STATUS_SUCCESS:
            length = build_image_block_rsp_success(payload, ZB_APS_CONST_MAX_PAYLOAD_SIZE, &image_definition, &image_data);
            break;

        case ZCL_STATUS_WAIT_FOR_DATA:
            length = build_image_block_rsp_wait_for_data(payload, ZB_APS_CONST_MAX_PAYLOAD_SIZE, &image_wait);
            break;

        case ZCL_STATUS_ABORT:
            length = build_image_block_rsp_abort(payload, ZB_APS_CONST_MAX_PAYLOAD_SIZE);
            break;

        case ZCL_STATUS_NO_IMAGE_AVAILABLE:
        case ZCL_STATUS_MALFORMED_COMMAND:
        case ZCL_STATUS_UNSUPP_COMMAND:
            ZbZclSendDefaultResponse(cluster, data_ind, zcl_header, (enum ZclStatusCodeT)status);
            return;

        default:
            ZCL_LOG_PRINTF(cluster->zb, __func__, "application read callback returned invalid status");
            ZbZclSendDefaultResponse(cluster, data_ind, zcl_header, ZCL_STATUS_FAILURE);
            return;
    }

    if (length < 0) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "error building rsp message");
        return;
    }

    status = ZbZclSendClusterStatusResponse(cluster, data_ind, zcl_header,
            ZCL_OTA_COMMAND_IMAGE_BLOCK_RESPONSE, payload, (unsigned int)length, false);
    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Error, failed to send response (0x%02x)", status);
    }

}

static void
handle_upgrade_end_req(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zcl_header,
    struct ZbApsdeDataIndT *data_ind)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)cluster;
    enum ZclStatusCodeT status;
    enum ZclStatusCodeT upgrade_status;
    struct ZbZclOtaImageDefinition image_definition;
    struct ZbZclOtaEndResponseTimes end_response_times;
    struct ZbZclAddrInfoT src_info;

    (void)memset(&src_info, 0, sizeof(src_info));
    src_info.addr = data_ind->src;
    src_info.seqnum = zcl_header->seqNum;
    src_info.tx_options = ZbZclTxOptsFromSecurityStatus(data_ind->securityStatus);

    (void)memset(&image_definition, 0, sizeof(image_definition));

    /* parse */
    status = parse_query_upgrade_end_req(data_ind->asdu, data_ind->asduLength, &image_definition, &upgrade_status);
    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(cluster->zb, __func__,
            "failed to parse Query Next Image request (status = 0x%02x)", status);
        return;
    }

    ZCL_LOG_PRINTF(cluster->zb, __func__, "Upgrade End (status = 0x%02x)", upgrade_status);

    /* set defaults, if defined the callback can override */
    end_response_times.current_time = ota_cluster->upgrade_end_current_time;
    end_response_times.upgrade_time = ota_cluster->upgrade_end_upgrade_time;
    if (ota_cluster->image_upgrade_end_req != NULL) {
        status = ota_cluster->image_upgrade_end_req(&image_definition, upgrade_status,
                &end_response_times, &src_info, ota_cluster->cluster.app_cb_arg);
        if (status == ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE) {
            /* Application callback has taken care of sending any response. */
            return;
        }
        if (status != ZCL_STATUS_SUCCESS) {
            /* OTA Spec requires us to send a Default Response regardless of the DDR bit in the
             * incoming request, so force it. */
            zcl_header->frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
            ZbZclSendDefaultResponse(cluster, data_ind, zcl_header, status);
            return;
        }
    }

    /* OTA Spec requires us to send a Default Response regardless of the DDR bit in the
     * incoming request, so force it. */
    zcl_header->frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    ZbZclSendDefaultResponse(cluster, data_ind, zcl_header, ZCL_STATUS_SUCCESS);

    if (upgrade_status == ZCL_STATUS_SUCCESS) {
        /* resp[0] is not status, so can't use ZbZclSendClusterStatusResponse */
        if ((ZbApsAddrIsBcast(&data_ind->dst)) || (data_ind->dst.endpoint == ZB_ENDPOINT_BCAST)) {
            /* request was broadcast, so don't send response. */
            return;
        }

        /* Send Upgrade End Response as a ZCL request so client can send a Default Response */
        status = ZbZclOtaServerUpgradeEndRespUnsolic(cluster, &data_ind->src,
                &image_definition, &end_response_times);
        if (status != ZCL_STATUS_SUCCESS) {
            ZCL_LOG_PRINTF(cluster->zb, __func__,
                "Error, failed to send Upgrade End Response (status = 0x%02x)", status);
        }
    }
}

enum ZclStatusCodeT
ZbZclOtaServerImageNotifyReq(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    uint8_t payload_type, uint8_t jitter, struct ZbZclOtaImageDefinition *image_definition)
{
    struct ZbApsdeDataReqT dataReq;
    struct ZbZclHeaderT zclHeader;
    uint8_t rawbuf[ZCL_HEADER_MAX_SIZE + 10];
    int i;

    /* Form the ZCL OTA Image Notify Request. */
    zclHeader.frameCtrl.frameType = ZCL_FRAMETYPE_CLUSTER;
    zclHeader.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    zclHeader.frameCtrl.direction = ZCL_DIRECTION_TO_CLIENT;
    zclHeader.frameCtrl.manufacturer = false;
    zclHeader.cmdId = ZCL_OTA_COMMAND_IMAGE_NOTIFY;
    zclHeader.seqNum = ZbZclGetNextSeqnum();
    i = ZbZclAppendHeader(&zclHeader, rawbuf, sizeof(rawbuf));

#if 0
    i += build_image_notify_req(payload, sizeof(payload), payload_type, jitter, image_definition);
#endif

    /* Payload: Timeout (2) */
    rawbuf[i++] = payload_type;
    rawbuf[i++] = jitter;
    if (payload_type > ZCL_OTA_NOTIFY_TYPE_JITTER) {
        putle16(&rawbuf[i], image_definition->manufacturer_code);
        i += 2;
    }
    if (payload_type > ZCL_OTA_NOTIFY_TYPE_MFG_CODE) {
        putle16(&rawbuf[i], image_definition->image_type);
        i += 2;
    }
    if (payload_type > ZCL_OTA_NOTIFY_TYPE_IMAGE_TYPE) {
        putle32(&rawbuf[i], image_definition->file_version);
        i += 4;
    }

    /* Form an APSDE-DATA.request. */
    ZbZclClusterInitApsdeReq(cluster, &dataReq, NULL);
    dataReq.dst = *dst;
    dataReq.discoverRoute = false;
    dataReq.radius = 0;
    dataReq.txOptions = ZbZclTxOptsFromSecurityStatus(cluster->minSecurity);
    if (ZbApsAddrIsBcast((const struct ZbApsAddrT *)dst)) {
        /* If broadcast, use the network key only, and disable APS ACKing.
         * Note: a broadcast to an SE cluster will be dropped if it doesn't
         * meet the minimum security level (i.e. APS). */
        dataReq.txOptions |= (uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_NWKKEY;
        dataReq.txOptions &= ~(uint16_t)ZB_APSDE_DATAREQ_TXOPTIONS_ACK;
    }
    dataReq.asdu = rawbuf;
    dataReq.asduLength = i;

    /* Send the Query response command. */
    if (ZbApsdeDataReqCallback(cluster->zb, &dataReq, NULL, NULL) != ZB_APS_STATUS_SUCCESS) {
        /* Ignored */
    }
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclOtaServerUpgradeEndRespUnsolic(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *dst,
    struct ZbZclOtaImageDefinition *image_definition, struct ZbZclOtaEndResponseTimes *end_response_times)
{
    struct ZbZclClusterCommandReqT req;
    unsigned int index = 0;
    int result;
    uint8_t payload[16U];

    /* build response */
    index = 0;
    result = build_upgrade_end_rsp(payload, sizeof(payload), image_definition,
            end_response_times->current_time, end_response_times->upgrade_time);
    if (result < 0) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "build_upgrade_end_rsp failed");
        return ZCL_STATUS_FAILURE;
    }
    index = (unsigned int)result;
    /* Send Upgrade End Response as a ZCL request so client can send a Default Response */
    (void)memset(&req, 0, sizeof(req));
    req.dst = *dst;
    req.cmdId = ZCL_OTA_COMMAND_UPGRADE_END_RESPONSE;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    req.payload = payload;
    req.length = index;
    /* Send response after a short delay, to let request APS ACKing and Default Response to be sent first. */
    (void)ZbZclClusterCommandReqDelayed(cluster, &req, ZB_NWK_RSP_DELAY_DEFAULT, NULL, NULL);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclOtaServerUpgradeEndRespSolic(struct ZbZclClusterT *cluster, struct ZbZclAddrInfoT *dst,
    struct ZbZclOtaImageDefinition *image_definition, struct ZbZclOtaEndResponseTimes *end_response_times,
    void (*callback)(struct ZbApsdeDataConfT *conf, void *arg), void *arg)
{
    uint8_t payload[16U];
    int err;
    struct ZbApsBufT bufv;

    err = build_upgrade_end_rsp(payload, sizeof(payload), image_definition,
            end_response_times->current_time, end_response_times->upgrade_time);
    if (err <= 0) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "build_upgrade_end_rsp failed");
        return ZCL_STATUS_FAILURE;
    }
    bufv.data = payload;
    bufv.len = (unsigned int)err;
    return ZbZclClusterCommandRspWithCb(cluster, dst, ZCL_OTA_COMMAND_UPGRADE_END_RESPONSE, &bufv, 1U, callback, arg);
}
