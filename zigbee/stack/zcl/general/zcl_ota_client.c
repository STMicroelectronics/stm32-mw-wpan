/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include <stdlib.h> /* rand */
#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl/general/zcl.ota.h"
#include "zcl/zcl.payload.h"
#include "../zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */

/* Arbitrary value. Should make this user configurable */
#define ZCL_OTA_CLIENT_BLOCK_RETRY_MAX              10U

#define ZCL_OTA_CLI_BLOCK_DELAY_MIN                 50U

/* Set the block cache to be at least 2 blocks */
#define ZCL_OTA_CLI_BLOCK_CACHE_SZ                  (2U * ZCL_OTA_BLOCK_DATA_SIZE_NWKSEC_MAX)

static enum ZclStatusCodeT zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src, uint16_t attribute_id,
    const uint8_t *input_data, unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg);

static enum ZclStatusCodeT zcl_attr_read_cb(struct ZbZclClusterT *cluster, uint16_t attributeId, uint8_t *data,
    unsigned int maxlen, void *app_cb_arg);

static enum ZclStatusCodeT
zcl_attr_cb(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrCbInfoT *cb)
{
    if (cb->type == ZCL_ATTR_CB_TYPE_WRITE) {
        return zcl_attr_write_cb(clusterPtr, cb->src, cb->info->attributeId, cb->zcl_data, cb->zcl_len,
            cb->attr_data, cb->write_mode, cb->app_cb_arg);
    }
    else if (cb->type == ZCL_ATTR_CB_TYPE_READ) {
        return zcl_attr_read_cb(clusterPtr, cb->info->attributeId, cb->zcl_data, cb->zcl_len, cb->app_cb_arg);
    }
    else {
        return ZCL_STATUS_FAILURE;
    }
}

/* Attributes */
static const struct ZbZclAttrT zcl_otacli_attr_list[] = {
    /* OTA Attributes */
    {
        ZCL_OTA_ATTR_UPGRADE_SERVER_ID, ZCL_DATATYPE_EUI64,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_OTA_ATTR_FILE_OFFSET, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_OTA_ATTR_CURRENT_FILE_VERSION, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_OTA_ATTR_CURRENT_STACK_VERSION, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_OTA_ATTR_DOWNLOAD_FILE_VERSION, ZCL_DATATYPE_UNSIGNED_32BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_OTA_ATTR_DOWNLOAD_STACK_VERSION, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_OTA_ATTR_IMAGE_UPGRADE_STATUS, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE, 0, zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_OTA_ATTR_MANUFACTURER_ID, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_OTA_ATTR_IMAGE_TYPE_ID, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_OTA_ATTR_MIN_BLOCK_PERIOD, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0x0000, 0xfffe}, {0, 0}
    },
    {
        ZCL_OTA_ATTR_UPGRADE_ACTIVATION_POLICY, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0x00, 0x01}, {0, 0}
    },
    {
        ZCL_OTA_ATTR_UPGRADE_TIMEOUT_POLICY, ZCL_DATATYPE_ENUMERATION_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0x00, 0x01}, {0, 0}
    },
};

/*---------------------------------------------------------
 * Cluster Private Info
 *---------------------------------------------------------
 */

struct cluster_priv_t {
    struct ZbZclClusterT cluster; /* goes first for inheritance. */
    struct ZbZclOtaClientConfig config;
    struct ZbTimerT *image_block_timer;
    struct ZbTimerT *activation_timer;

    uint64_t requested_server_ext;
    uint8_t upgrade_server_endpoint;

    /* Info about the last query */
    struct ZbZclOtaImageDefinition image_definition_last_query;
    uint32_t last_query_image_size;
    enum ZclStatusCodeT last_query_status;

    /* Current Download Info */
    enum ZbZclOtaStatus ota_status;
    struct ZbZclOtaHeader ota_header;
    uint32_t file_offset;
    uint8_t data_size;
    bool image_verified;

    bool is_ota_header;
    uint8_t block_cache[ZCL_OTA_CLI_BLOCK_CACHE_SZ];
    uint16_t block_cache_end;
    uint16_t block_cache_threshold;
    uint8_t block_retry; /* max = ZCL_OTA_CLIENT_BLOCK_RETRY_MAX */
    bool have_tag_id;
    uint16_t current_tag_id;
    uint32_t field_length_total;
    uint32_t field_length_remaining;

    /* NHLE Pause and Resume (ZCL_STATUS_WAIT_FOR_DATA) */
    bool waiting_for_nhle;
    ZbUptimeT next_block_timeout;

    /* Received Certificate and Signature (Tags) */
    uint8_t certificate2[ZB_SEC_CRYPTO_SUITE_V2_CERT_LEN];
    uint8_t certificate2_offset;
    uint8_t signature2[ZB_SEC_CRYPTO_SUITE_V2_SIG_LEN];
    uint8_t signature2_offset;

    bool rx_tags[ZCL_OTA_SUB_TAG_TOTAL];

    /* Running hash */
    struct ZbHash hash;
};

struct image_ident {
    uint16_t manufacturer_code;
    uint16_t image_type;
    uint32_t file_version;
};

static void zcl_otacli_cluster_cleanup(struct ZbZclClusterT *clusterPtr);
static enum ZclStatusCodeT zcl_otacli_handle_command(struct ZbZclClusterT *cluster,
    struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind);

static void zcl_otacli_reset_cluster(struct cluster_priv_t *client);

static void zcl_otacli_nwk_addr_rsp(struct ZbZdoNwkAddrRspT *nwk_rsp, void *arg);
static void zcl_otacli_ieee_addr_rsp(struct ZbZdoIeeeAddrRspT *ieee_rsp, void *arg);

static int zcl_otacli_build_query_next_image_req(uint8_t *payload, const unsigned int length,
    struct ZbZclOtaImageDefinition *image_definition, uint8_t field_control, uint16_t hardware_version);
static int zcl_otacli_build_image_block_req(uint8_t *payload, const unsigned int length,
    struct ZbZclOtaImageDefinition *image_definition,
    uint32_t file_offset, uint8_t data_size, uint16_t min_block);
static int zcl_otacli_build_upgrade_end_req(uint8_t *payload, const unsigned int length,
    uint8_t status, struct ZbZclOtaImageDefinition *image_definition);

static enum ZclStatusCodeT zcl_otacli_parse_query_next_image_rsp(const uint8_t *payload, const unsigned int length,
    struct ZbZclOtaImageDefinition *image_definition, uint32_t *image_size);

static enum ZclStatusCodeT zcl_otacli_parse_image_block_rsp(const uint8_t *payload, const unsigned int length,
    struct ZbZclOtaImageDefinition *image_definition, struct ZbZclOtaImageData *image_data,
    struct ZbZclOtaImageWaitForData *image_wait);
static enum ZclStatusCodeT zcl_otacli_parse_image_block_rsp_success(const uint8_t *payload, const unsigned int length, unsigned int *index,
    struct ZbZclOtaImageDefinition *image_definition, struct ZbZclOtaImageData *image_data);
static enum ZclStatusCodeT zcl_otacli_parse_image_block_rsp_wait(const uint8_t *payload, const unsigned int length, unsigned int *index,
    struct ZbZclOtaImageWaitForData *image_wait);
static enum ZclStatusCodeT zcl_otacli_parse_upgrade_end_rsp(const uint8_t *payload, const unsigned int length,
    struct ZbZclOtaImageDefinition *image_definition, uint32_t *current_time, uint32_t *upgrade_time);

static void zcl_ota_header_print(struct ZigBeeT *zb, struct ZbZclOtaHeader *ota_header);
static void zcl_ota_image_def_print(struct ZigBeeT *zb, struct ZbZclOtaImageDefinition *image_definition, unsigned int image_size);

static void zcl_otacli_send_image_block_req(struct ZigBeeT *zb, void *arg);
static enum ZclStatusCodeT zcl_otacli_send_upgrade_end_req(struct cluster_priv_t *ota_cluster, uint8_t status);
static void zcl_otacli_disc_complete(struct ZbZclClusterT *cluster, enum ZclStatusCodeT status);

static void zcl_otacli_handle_query_next_image_rsp(struct ZbZclCommandRspT *rsp, void *arg);
static void zcl_otacli_handle_image_block_rsp(struct ZbZclCommandRspT *rsp, void *arg);
static enum ZclStatusCodeT zcl_otacli_handle_upgrade_end_rsp(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind);
static void zcl_otacli_handle_image_notify(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind);

static enum ZclStatusCodeT zcl_otacli_send_command(struct cluster_priv_t *ota_cluster, uint8_t cmd_id, uint8_t *payload,
    unsigned int length, void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg));

static void zcl_otacli_remove_from_cache(struct cluster_priv_t *ota_cluster, unsigned int count);
static enum ZclStatusCodeT zcl_otacli_process_block_data(struct cluster_priv_t *ota_cluster);
static void zcl_otacli_request_next_block(struct cluster_priv_t *ota_cluster, ZbUptimeT timeout, unsigned int debug_line);

static void zcl_otacli_reboot_timer(struct ZigBeeT *zb, void *arg);

/* Default Callbacks */
static void ZbZclOtaClientQueryNextImageCb(struct ZbZclClusterT *clusterPtr, enum ZclStatusCodeT status,
    struct ZbZclOtaImageDefinition *image_definition, uint32_t image_size, void *arg);
static enum ZclStatusCodeT ZbZclOtaClientImageUpdateRawCb(struct ZbZclClusterT *clusterPtr, uint8_t length, uint8_t *data, void *arg);
static enum ZclStatusCodeT ZbZclOtaClientImageWriteTagCb(struct ZbZclClusterT *clusterPtr, struct ZbZclOtaHeader *header,
    uint16_t tag_id, uint32_t tag_length, uint8_t data_length, uint8_t *data, void *arg);
static enum ZclStatusCodeT ZbZclOtaClientImageValidateCb(struct ZbZclClusterT *clusterPtr, struct ZbZclOtaHeader *image_definition, void *arg);
static enum ZclStatusCodeT ZbZclOtaClientImageUpgradeEndCb(struct ZbZclClusterT *clusterPtr, struct ZbZclOtaHeader *header,
    uint32_t current_time, uint32_t upgrade_time, void *arg);
static enum ZclStatusCodeT ZbZclOtaClientImageNotifyCb(struct ZbZclClusterT *clusterPtr, uint8_t payload_type,
    uint8_t jitter, struct ZbZclOtaImageDefinition *image_definition, struct ZbApsdeDataIndT *data_ind, struct ZbZclHeaderT *zcl_header);
static void ZbZclOtaClientDiscoveryFinishCb(struct ZbZclClusterT *clusterPtr, enum ZclStatusCodeT status, void *arg);

void
ZbZclOtaClientGetDefaultCallbacks(struct ZbZclOtaClientCallbacksT *callbacks)
{
    callbacks->query_next = ZbZclOtaClientQueryNextImageCb;
    callbacks->update_raw = ZbZclOtaClientImageUpdateRawCb;
    callbacks->write_tag = ZbZclOtaClientImageWriteTagCb;
    callbacks->image_validate = ZbZclOtaClientImageValidateCb;
    callbacks->upgrade_end = ZbZclOtaClientImageUpgradeEndCb;
    callbacks->image_notify = ZbZclOtaClientImageNotifyCb;
    callbacks->discover_complete = ZbZclOtaClientDiscoveryFinishCb;
}

struct ZbZclClusterT *
ZbZclOtaClientAlloc(struct ZigBeeT *zb, struct ZbZclOtaClientConfig *config, void *arg)
{
    struct cluster_priv_t *client;

    client = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_OTA_UPGRADE, config->endpoint, ZCL_DIRECTION_TO_CLIENT);
    if (client == NULL) {
        return NULL;
    }
    client->cluster.command = zcl_otacli_handle_command;
    client->cluster.cleanup = zcl_otacli_cluster_cleanup;
    client->cluster.app_cb_arg = arg;

    /* Copy configuration */
    (void)memcpy(&client->config, config, sizeof(struct ZbZclOtaClientConfig));

    /* Sanity check the callbacks */
    if (client->config.callbacks.abort_download == NULL) {
        ZCL_LOG_PRINTF(zb, __func__, "Error, abort callback cannot be NULL");
        ZbHeapFree(zb, client);
        return NULL;
    }
    if (client->config.callbacks.reboot == NULL) {
        ZCL_LOG_PRINTF(zb, __func__, "Error, reboot callback cannot be NULL");
        ZbHeapFree(zb, client);
        return NULL;
    }
    /* The OTA client is rather useless if there's nowhere for the OTA image data to go. */
    if ((client->config.callbacks.write_tag == ZbZclOtaClientImageWriteTagCb) && (client->config.callbacks.write_image == NULL)) {
        ZCL_LOG_PRINTF(zb, __func__, "Error, write_image callback cannot be NULL if write_tag set to default callback.");
        ZbHeapFree(zb, client);
        return NULL;
    }

    if (client->config.callbacks.image_validate == ZbZclOtaClientImageValidateCb) {
        if ((client->config.ca_pub_key_array == NULL) || (client->config.ca_pub_key_len == 0U)) {
            ZCL_LOG_PRINTF(zb, __func__, "Error, ca_pub_key_array cannot be empty if image_validate set to default callback");
            ZbHeapFree(zb, client);
            return NULL;
        }
    }

    /* Block Delay */
    if (client->config.image_block_delay < ZCL_OTA_CLI_BLOCK_DELAY_MIN) {
        ZCL_LOG_PRINTF(zb, __func__, "Warning, block delay too short. Setting to %d mS", ZCL_OTA_CLI_BLOCK_DELAY_MIN);
        client->config.image_block_delay = ZCL_OTA_CLI_BLOCK_DELAY_MIN;
    }

    client->activation_timer = ZbTimerAlloc(zb, zcl_otacli_reboot_timer, &client->cluster);
    if (client->activation_timer == NULL) {
        ZbHeapFree(zb, client);
        return NULL;
    }

    client->image_block_timer = ZbTimerAlloc(zb, zcl_otacli_send_image_block_req, client);
    if (client->image_block_timer == NULL) {
        ZbZclClusterFree(&client->cluster);
        return NULL;
    }

    /* reset as OTA can be used for Z3 and ZSE */
    ZbZclClusterSetProfileId(&client->cluster, client->config.profile_id);

    /* Configured in ZbZclOtaClientDiscover */
    client->requested_server_ext = ZCL_INVALID_UNSIGNED_64BIT;

    /* safe size less length of Image Block Response ZCL message */
    client->field_length_total = 0;
    client->field_length_remaining = 0;
    client->block_cache_end = 0;

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&client->cluster, zcl_otacli_attr_list, ZCL_ATTR_LIST_LEN(zcl_otacli_attr_list))) {
        ZbZclClusterFree(&client->cluster);
        return NULL;
    }

    ZbZclAttrIntegerWrite(&client->cluster, ZCL_OTA_ATTR_UPGRADE_SERVER_ID, ZCL_INVALID_UNSIGNED_64BIT);
    ZbZclAttrIntegerWrite(&client->cluster, ZCL_OTA_ATTR_CURRENT_FILE_VERSION, client->config.current_image.file_version);
    ZbZclAttrIntegerWrite(&client->cluster, ZCL_OTA_ATTR_CURRENT_STACK_VERSION, client->config.current_image.stack_version);
    ZbZclAttrIntegerWrite(&client->cluster, ZCL_OTA_ATTR_MANUFACTURER_ID, client->config.current_image.manufacturer_code);
    ZbZclAttrIntegerWrite(&client->cluster, ZCL_OTA_ATTR_IMAGE_TYPE_ID, client->config.current_image.image_type);
    ZbZclAttrIntegerWrite(&client->cluster, ZCL_OTA_ATTR_MIN_BLOCK_PERIOD, client->config.image_block_delay);
    ZbZclAttrIntegerWrite(&client->cluster, ZCL_OTA_ATTR_UPGRADE_ACTIVATION_POLICY, client->config.activation_policy);
    ZbZclAttrIntegerWrite(&client->cluster, ZCL_OTA_ATTR_UPGRADE_TIMEOUT_POLICY, client->config.timeout_policy);

    zcl_otacli_reset_cluster(client);

    (void)ZbZclClusterAttach(&client->cluster);
    return &client->cluster;
}

static void
zcl_otacli_cluster_cleanup(struct ZbZclClusterT *clusterPtr)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)clusterPtr;

    if (ota_cluster->activation_timer != NULL) {
        ZbTimerFree(ota_cluster->activation_timer);
        ota_cluster->activation_timer = NULL;
    }
    if (ota_cluster->image_block_timer != NULL) {
        ZbTimerFree(ota_cluster->image_block_timer);
        ota_cluster->image_block_timer = NULL;
    }
}

static enum ZclStatusCodeT
zcl_otacli_handle_command(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind)
{
    /* ZCL_LOG_PRINTF(cluster->zb, __func__, "received command 0x%02x %s", zcl_header->cmdId,
        zcl_header->frameCtrl.direction == ZCL_DIRECTION_TO_CLIENT ? "to client" : "to server"); */
    if (zcl_header->frameCtrl.direction != ZCL_DIRECTION_TO_CLIENT) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    switch (zcl_header->cmdId) {
        case ZCL_OTA_COMMAND_IMAGE_NOTIFY:
            zcl_otacli_handle_image_notify(cluster, zcl_header, data_ind);
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

        case ZCL_OTA_COMMAND_UPGRADE_END_RESPONSE:
            /* Upgrade end response can be sent unsolicited and should always return a default
             * response, unless response is a broadcast. */
            return zcl_otacli_handle_upgrade_end_rsp(cluster, zcl_header, data_ind);

        case ZCL_OTA_COMMAND_QUERY_IMAGE_RESPONSE:
        case ZCL_OTA_COMMAND_IMAGE_BLOCK_RESPONSE:
        case ZCL_OTA_COMMAND_QUERY_FILE_RESPONSE:
            return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;

        default:
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
}

static void
zcl_otacli_write_upgrade_status(struct cluster_priv_t *client, enum ZbZclOtaStatus status, unsigned int debug_line)
{
    struct ZigBeeT *zb = client->cluster.zb;

    ZCL_LOG_PRINTF(zb, __func__, "OTA Client setting IMAGE_UPGRADE_STATUS = 0x%02x (debug_line = %d)", status, debug_line);
    client->ota_status = status;
}

static void
zcl_otacli_reset_block_timer(struct cluster_priv_t *client, unsigned int timeout, unsigned int debug_line)
{
    /* ZCL_LOG_PRINTF(client->cluster.zb, __func__, "Requesting next block in %d mS (file_offset = %d, debug_line = %d)",
        timeout, client->file_offset, debug_line); */
    ZbTimerReset(client->image_block_timer, timeout);
}

static void
zcl_otacli_reset_cluster(struct cluster_priv_t *client)
{
    client->file_offset = ZCL_INVALID_UNSIGNED_32BIT;

    client->is_ota_header = true;
    (void)memset(&client->ota_header, 0, sizeof(struct ZbZclOtaHeader));

    client->have_tag_id = false;
    client->field_length_total = 0;
    client->field_length_remaining = 0;
    client->block_cache_end = 0;
    client->block_cache_threshold = ZCL_OTA_HEADER_LENGTH_MIN;
    client->image_verified = false;

    client->certificate2_offset = 0;
    (void)memset(&client->certificate2, 0, sizeof(client->certificate2));
    client->signature2_offset = 0;
    (void)memset(&client->signature2, 0, sizeof(client->signature2));
    ZbHashInit(&client->hash);

    ZbZclAttrIntegerWrite(&client->cluster, ZCL_OTA_ATTR_DOWNLOAD_FILE_VERSION, ZCL_INVALID_UNSIGNED_32BIT);
    ZbZclAttrIntegerWrite(&client->cluster, ZCL_OTA_ATTR_DOWNLOAD_STACK_VERSION, ZCL_INVALID_UNSIGNED_16BIT);
    zcl_otacli_write_upgrade_status(client, ZCL_OTA_STATUS_NORMAL, __LINE__);

    memset(client->rx_tags, 0, sizeof(client->rx_tags));
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *src, uint16_t attribute_id,
    const uint8_t *input_data, unsigned int input_max_len, void *attr_data, ZclWriteModeT mode, void *app_cb_arg)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;

    switch (attribute_id) {
        case ZCL_OTA_ATTR_FILE_OFFSET:
        {
            uint32_t file_offset;

            if (input_max_len < 4U) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            file_offset = pletoh32(input_data);
            if ((file_offset != ZCL_INVALID_UNSIGNED_32BIT) && (file_offset != 0U)) {
                /* If setting a non-zero FileOffset, we must have an OTA header already downloaded. */
                if (client->ota_header.header_length == 0) {
                    return ZCL_STATUS_INVALID_VALUE;
                }
                /* If we have an OTA Header, then make sure the FileOffset is valid. */
                /* NOTE: OTA can be reset by setting ZCL_OTA_STATUS_NORMAL */
                if (file_offset < client->ota_header.header_length) {
                    ZCL_LOG_PRINTF(cluster->zb, __func__, "OTA Client: Error, cannot set file_offset (%d) less than header_length (%d)",
                        file_offset, client->ota_header.header_length);
                    return ZCL_STATUS_INVALID_VALUE;
                }
                if (file_offset > client->ota_header.total_image_size) {
                    ZCL_LOG_PRINTF(cluster->zb, __func__, "OTA Client: Error, cannot set file_offset (%d) greater than total_image_size (%d)",
                        file_offset, client->ota_header.total_image_size);
                    return ZCL_STATUS_INVALID_VALUE;
                }
                /* If file_offset is non-zero, then app must provide it's own image_validate callback.
                 * Otherwise, we cannot assume the computed hash, at the least, will be valid. */
                if ((client->config.callbacks.image_validate == NULL)
                    || (client->config.callbacks.image_validate == ZbZclOtaClientImageValidateCb)) {
                    ZCL_LOG_PRINTF(cluster->zb, __func__, "OTA Client: Error, cannot set FILE_OFFSET when using default image_validate() callback.");
                    return ZCL_STATUS_FAILURE;
                }
            }
            if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) {
                /* Save the file offset */
                client->file_offset = file_offset;
                ZCL_LOG_PRINTF(cluster->zb, __func__, "OTA Client file_offset = %d", client->file_offset);

                /* Forget any data in the cache */
                client->block_cache_end = 0U;
            }
            return ZCL_STATUS_SUCCESS;
        }

        case ZCL_OTA_ATTR_IMAGE_UPGRADE_STATUS:
        {
            enum ZbZclOtaStatus ota_status;

            if (input_max_len < 1U) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
            ota_status = *input_data;
            if (ota_status > ZCL_OTA_STATUS_WAIT_FOR_MORE) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) {
                if (ota_status == ZCL_OTA_STATUS_NORMAL) {
                    zcl_otacli_reset_cluster(client);
                }
                else {
                    zcl_otacli_write_upgrade_status(client, ota_status, __LINE__);
                }
            }
            return ZCL_STATUS_SUCCESS;
        }

        default:
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
}

static enum ZclStatusCodeT
zcl_attr_read_cb(struct ZbZclClusterT *cluster, uint16_t attributeId, uint8_t *data, unsigned int maxlen, void *app_cb_arg)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;

    switch (attributeId) {
        case ZCL_OTA_ATTR_FILE_OFFSET:
            if (maxlen < 4U) {
                return ZCL_STATUS_INSUFFICIENT_SPACE;
            }
            putle32(data, client->file_offset);
            return ZCL_STATUS_SUCCESS;

        case ZCL_OTA_ATTR_IMAGE_UPGRADE_STATUS:
            if (maxlen < 1U) {
                return ZCL_STATUS_INSUFFICIENT_SPACE;
            }
            *data = client->ota_status;
            return ZCL_STATUS_SUCCESS;

        default:
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
}

enum ZclStatusCodeT
ZbZclOtaClientDiscover(struct ZbZclClusterT *cluster, const struct ZbApsAddrT *addr)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;

    if (addr->mode == ZB_APSDE_ADDRMODE_EXT) {
        struct ZbZdoNwkAddrReqT nwk_req;

        memset(&nwk_req, 0, sizeof(nwk_req));
        nwk_req.dstNwkAddr = ZB_NWK_ADDR_BCAST_RXON;
        nwk_req.extAddr = addr->extAddr;
        nwk_req.reqType = ZB_ZDO_ADDR_REQ_TYPE_SINGLE;
        nwk_req.startIndex = 0;
        if (ZbZdoNwkAddrReq(cluster->zb, &nwk_req, zcl_otacli_nwk_addr_rsp, client) != ZB_ZDP_STATUS_SUCCESS) {
            client->requested_server_ext = ZCL_INVALID_UNSIGNED_64BIT;
            return ZCL_STATUS_FAILURE;
        }
    }
    else if (addr->mode == ZB_APSDE_ADDRMODE_SHORT) {
        struct ZbZdoIeeeAddrReqT ieee_req;

        memset(&ieee_req, 0, sizeof(ieee_req));
        ieee_req.reqType = ZB_ZDO_ADDR_REQ_TYPE_SINGLE;
        ieee_req.startIndex = 0;
        ieee_req.dstNwkAddr = addr->nwkAddr;
        ieee_req.nwkAddrOfInterest = addr->nwkAddr;
        if (ZbZdoIeeeAddrReq(cluster->zb, &ieee_req, zcl_otacli_ieee_addr_rsp, client) != ZB_ZDP_STATUS_SUCCESS) {
            client->requested_server_ext = ZCL_INVALID_UNSIGNED_64BIT;
            return ZCL_STATUS_FAILURE;
        }
    }
    else {
        return ZCL_STATUS_FAILURE;
    }

    return ZCL_STATUS_SUCCESS;
}

static void
zcl_otacli_disc_complete(struct ZbZclClusterT *cluster, enum ZclStatusCodeT status)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)cluster;

    if (status != ZCL_STATUS_SUCCESS) {
        client->requested_server_ext = ZCL_INVALID_UNSIGNED_64BIT;
    }
    if (client->config.callbacks.discover_complete != NULL) {
        client->config.callbacks.discover_complete(cluster, status, cluster->app_cb_arg);
    }
}

void
ZbZclOtaClientDiscoverForced(struct ZbZclClusterT *cluster, uint64_t ieee, uint8_t endpoint)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)cluster;

    ota_cluster->requested_server_ext = ieee;
    ota_cluster->upgrade_server_endpoint = endpoint;
    ZbZclAttrIntegerWrite(&ota_cluster->cluster, ZCL_OTA_ATTR_UPGRADE_SERVER_ID, ota_cluster->requested_server_ext);
}

enum ZclStatusCodeT
ZbZclOtaClientImageTransferStart(struct ZbZclClusterT *cluster)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)cluster;

    /* only allowed in NORMAL mode */
    if (ota_cluster->ota_status != ZCL_OTA_STATUS_NORMAL) {
        return ZCL_STATUS_FAILURE;
    }

    if ((ota_cluster->image_definition_last_query.manufacturer_code == 0)
        && (ota_cluster->image_definition_last_query.image_type == 0)
        && (ota_cluster->image_definition_last_query.file_version == 0)) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "must issue Query Next Image first or image was empty, can't download");
        return ZCL_STATUS_NO_IMAGE_AVAILABLE;
    }

    zcl_otacli_reset_cluster(ota_cluster);
    ota_cluster->file_offset = 0U;
    ota_cluster->block_retry = 0U;
    /* Set the size to the larger of the two choices. The server can truncate
     * the Block Response so it's not fragmented. */
    ota_cluster->data_size = ZCL_OTA_BLOCK_DATA_SIZE_NWKSEC_MAX;

    zcl_otacli_write_upgrade_status(ota_cluster, ZCL_OTA_STATUS_DOWNLOAD_IN_PROGRESS, __LINE__);

    /* ZCL_LOG_PRINTF(cluster->zb, __func__, "endpoint 0x%02x data_size 0x%02x", ota_cluster->cluster.endpoint, ota_cluster->data_size); */

    zcl_otacli_send_image_block_req(cluster->zb, ota_cluster);
    return ZCL_STATUS_SUCCESS;
}

/* Resume after write_image() callback returns ZCL_STATUS_WAIT_FOR_DATA. */
enum ZclStatusCodeT
ZbZclOtaClientImageTransferResume(struct ZbZclClusterT *cluster)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)cluster;
    ZbUptimeT timeout_remain;

    if (!ota_cluster->waiting_for_nhle) {
        return ZCL_STATUS_FAILURE;
    }
    ota_cluster->waiting_for_nhle = false;

    timeout_remain = ZbTimeoutRemaining(ZbZclUptime(cluster->zb), ota_cluster->next_block_timeout);
    zcl_otacli_request_next_block(ota_cluster, timeout_remain, __LINE__);
    return ZCL_STATUS_SUCCESS;
}

static void
zcl_otacli_handle_query_next_image_rsp(struct ZbZclCommandRspT *rsp, void *arg)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)arg;

    /* Check the response status */
    if (rsp->status != ZCL_STATUS_SUCCESS) {
        ota_cluster->last_query_status = rsp->status;
        return;
    }
    /* Parse the response and get info about the last query. */
    ota_cluster->last_query_status = zcl_otacli_parse_query_next_image_rsp(rsp->payload, rsp->length,
            &ota_cluster->image_definition_last_query, &ota_cluster->last_query_image_size);

    /* If the application callback is defined, then call it. */
    if (ota_cluster->config.callbacks.query_next != NULL) {
        ota_cluster->config.callbacks.query_next(&ota_cluster->cluster, ota_cluster->last_query_status,
            &ota_cluster->image_definition_last_query, ota_cluster->last_query_image_size,
            ota_cluster->cluster.app_cb_arg);
    }
}

enum ZclStatusCodeT
ZbZclOtaClientQueryNextImageReq(struct ZbZclClusterT *cluster,
    struct ZbZclOtaImageDefinition *image_definition,
    uint8_t field_control, uint16_t hardware_version)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)cluster;
    uint8_t payload[11];
    int length = 0;

    /* Check input parameters */
    if (image_definition == NULL) {
        return ZCL_STATUS_FAILURE;
    }

    /* only allowed in NORMAL mode */
    if (ota_cluster->ota_status != ZCL_OTA_STATUS_NORMAL) {
        return ZCL_STATUS_FAILURE;
    }

    length = zcl_otacli_build_query_next_image_req(payload, sizeof(payload), image_definition, field_control, hardware_version);
    if (length < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    return zcl_otacli_send_command(ota_cluster, ZCL_OTA_COMMAND_QUERY_IMAGE_REQUEST,
        payload, length, zcl_otacli_handle_query_next_image_rsp);
}

static void
zcl_otacli_match_desc_rsp(struct ZbZdoMatchDescRspT *match_rsp, void *arg)
{
    struct cluster_priv_t *client = (struct cluster_priv_t *)arg;
    struct ZbZclClusterT *cluster = &client->cluster;

    if (match_rsp->status != ZB_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "ZDO Match Descriptor request returned status 0x%02x", match_rsp->status);
        zcl_otacli_disc_complete(cluster, ZCL_STATUS_FAILURE);
        return;
    }

    if (match_rsp->matchLength == 0) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "ZDO Match Descriptor request returned no endpoints");
        zcl_otacli_disc_complete(cluster, ZCL_STATUS_FAILURE);
        return;
    }

    client->upgrade_server_endpoint = match_rsp->matchList[0];

    ZCL_LOG_PRINTF(cluster->zb, __func__,
        "OTA Server located with EUI64 0x%016" PRIx64 ", endpoint 0x%02x",
        client->requested_server_ext, client->upgrade_server_endpoint);

    ZbZclAttrIntegerWrite(&client->cluster, ZCL_OTA_ATTR_UPGRADE_SERVER_ID, client->requested_server_ext);
    if (client->requested_server_ext == ZCL_INVALID_UNSIGNED_64BIT) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "failed to locate OTA server");
        zcl_otacli_disc_complete(cluster, ZCL_STATUS_FAILURE);
        return;
    }

    zcl_otacli_disc_complete(cluster, ZCL_STATUS_SUCCESS);
}

static void
zcl_otacli_nwk_addr_rsp(struct ZbZdoNwkAddrRspT *nwk_rsp, void *arg)
{
    struct cluster_priv_t *client = arg;
    struct ZbZdoMatchDescReqT match_req;
    struct ZbZclClusterT *cluster = &client->cluster;

    if (nwk_rsp->status != ZB_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "Unable to locate requested server");
        ZCL_LOG_PRINTF(cluster->zb, __func__, "ZDO Nwk Addr Req request returned status 0x%02x", nwk_rsp->status);
        zcl_otacli_disc_complete(cluster, ZCL_STATUS_FAILURE);
        return;
    }

    client->requested_server_ext = nwk_rsp->extAddr;

    memset(&match_req, 0, sizeof(match_req));
    match_req.profileId = cluster->profileId;
    match_req.nwkAddrOfInterest = nwk_rsp->nwkAddr;
    match_req.dstNwkAddr = match_req.nwkAddrOfInterest;
    match_req.numInClusters = 1;
    match_req.inClusterList[0] = ZCL_CLUSTER_OTA_UPGRADE;
    match_req.numOutClusters = 0;

    if (ZbZdoMatchDescReq(cluster->zb, &match_req, zcl_otacli_match_desc_rsp, client) != ZB_ZDP_STATUS_SUCCESS) {
        zcl_otacli_disc_complete(cluster, ZCL_STATUS_FAILURE);
        return;
    }
}

static void
zcl_otacli_ieee_addr_rsp(struct ZbZdoIeeeAddrRspT *ieee_rsp, void *arg)
{
    struct cluster_priv_t *client = arg;
    struct ZbZclClusterT *cluster = &client->cluster;
    struct ZbZdoMatchDescReqT match_req;

    if (ieee_rsp->status != ZB_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(cluster->zb, __func__, "ZDO IEEE request returned status 0x%02x", ieee_rsp->status);
        zcl_otacli_disc_complete(cluster, ZCL_STATUS_FAILURE);
        return;
    }

    client->requested_server_ext = ieee_rsp->extAddr;

    memset(&match_req, 0, sizeof(match_req));
    match_req.profileId = cluster->profileId;
    match_req.nwkAddrOfInterest = ieee_rsp->nwkAddr;
    match_req.dstNwkAddr = match_req.nwkAddrOfInterest;
    match_req.numInClusters = 1;
    match_req.inClusterList[0] = ZCL_CLUSTER_OTA_UPGRADE;
    match_req.numOutClusters = 0;
    if (ZbZdoMatchDescReq(cluster->zb, &match_req, zcl_otacli_match_desc_rsp, client) != ZB_ZDP_STATUS_SUCCESS) {
        zcl_otacli_disc_complete(cluster, ZCL_STATUS_FAILURE);
        return;
    }
}

/*
 * ZCL Message Builders
 */
static int
zcl_otacli_build_query_next_image_req(uint8_t *payload, const unsigned int length, struct ZbZclOtaImageDefinition *image_definition,
    uint8_t field_control, uint16_t hardware_version)
{
    unsigned int index = 0;

    if (zb_zcl_append_uint8(payload, length, &index, field_control) < 0) {
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
    if (field_control & ZCL_OTA_QUERY_FIELD_CONTROL_HW_VERSION) {
        if (zb_zcl_append_uint16(payload, length, &index, hardware_version) < 0) {
            return -1;
        }
    }
    return index;
}

static int
zcl_otacli_build_image_block_req(uint8_t *payload, const unsigned int length, struct ZbZclOtaImageDefinition *image_definition,
    uint32_t file_offset, uint8_t data_size, uint16_t min_block)
{
    unsigned int index = 0;
    uint8_t field_control = ZCL_OTA_IMAGE_BLOCK_FC_MAX_BLOCK;

    if (zb_zcl_append_uint8(payload, length, &index, field_control) < 0) {
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
    if (zb_zcl_append_uint32(payload, length, &index, file_offset) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint8(payload, length, &index, data_size) < 0) {
        return -1;
    }
    if (zb_zcl_append_uint16(payload, length, &index, min_block) < 0) {
        return -1;
    }
    return index;
}

static int
zcl_otacli_build_upgrade_end_req(uint8_t *payload, const unsigned int length, uint8_t status, struct ZbZclOtaImageDefinition *image_definition)
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

    return index;
}

/*
 * ZCL Message Parsers
 */
static enum ZclStatusCodeT
zcl_otacli_parse_query_next_image_rsp(const uint8_t *payload, const unsigned int length, struct ZbZclOtaImageDefinition *image_definition,
    uint32_t *image_size)
{
    uint8_t status;
    unsigned int index = 0;

    if (zb_zcl_parse_uint8(payload, length, &index, &status) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    if (status != 0x00) {
        return (enum ZclStatusCodeT)status;
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
    if (zb_zcl_parse_uint32(payload, length, &index, image_size) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }

    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
zcl_otacli_parse_image_block_rsp_success(const uint8_t *payload, const unsigned int length, unsigned int *index,
    struct ZbZclOtaImageDefinition *image_definition, struct ZbZclOtaImageData *image_data)
{
    (void)memset(image_definition, 0, sizeof(struct ZbZclOtaImageDefinition));

    if (zb_zcl_parse_uint16(payload, length, index, &image_definition->manufacturer_code) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    if (zb_zcl_parse_uint16(payload, length, index, &image_definition->image_type) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    if (zb_zcl_parse_uint32(payload, length, index, &image_definition->file_version) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }

    (void)memset(image_data, 0, sizeof(struct ZbZclOtaImageData));
    if (zb_zcl_parse_uint32(payload, length, index, &image_data->file_offset) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    if (zb_zcl_parse_uint8(payload, length, index, &image_data->data_size) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    if (length < (*index + image_data->data_size)) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    (void)memcpy(image_data->data, payload + *index, image_data->data_size);

    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
zcl_otacli_parse_image_block_rsp_wait(const uint8_t *payload, const unsigned int length, unsigned int *index,
    struct ZbZclOtaImageWaitForData *image_wait)
{
    (void)memset(image_wait, 0, sizeof(struct ZbZclOtaImageWaitForData));

    if (zb_zcl_parse_uint32(payload, length, index, &image_wait->current_time) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    if (zb_zcl_parse_uint32(payload, length, index, &image_wait->request_time) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    if (zb_zcl_parse_uint16(payload, length, index, &image_wait->minimum_block_period) < 0) {
        /* From section 11.13.8.2.9 of the ZCL7 spec:
         * The client SHALL check the existence of this field by looking at the length of the message. If the field does not exist,
         * then the field SHALL have the value of zero.
         */
        image_wait->minimum_block_period = 0;
    }
    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
zcl_otacli_parse_image_block_rsp(const uint8_t *payload, const unsigned int length, struct ZbZclOtaImageDefinition *image_definition,
    struct ZbZclOtaImageData *image_data, struct ZbZclOtaImageWaitForData *image_wait)
{
    uint8_t status;
    unsigned int index = 0;

    if (zb_zcl_parse_uint8(payload, length, &index, &status) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }

    (void)memset(image_definition, 0, sizeof(struct ZbZclOtaImageDefinition));

    switch ((enum ZclStatusCodeT)status) {
        case ZCL_STATUS_SUCCESS:
            status = zcl_otacli_parse_image_block_rsp_success(payload, length, &index, image_definition, image_data);
            break;

        case ZCL_STATUS_WAIT_FOR_DATA:
            status = zcl_otacli_parse_image_block_rsp_wait(payload, length, &index, image_wait);
            if (status == ZCL_STATUS_SUCCESS) {
                status = ZCL_STATUS_WAIT_FOR_DATA;
            }
            break;

        case ZCL_STATUS_ABORT:
            status = ZCL_STATUS_ABORT;
            break;

        default:
            status = ZCL_STATUS_INVALID_FIELD;
            break;
    }
    return (enum ZclStatusCodeT)status;
}

static enum ZclStatusCodeT
zcl_otacli_parse_upgrade_end_rsp(const uint8_t *payload, const unsigned int length,
    struct ZbZclOtaImageDefinition *image_definition, uint32_t *current_time, uint32_t *upgrade_time)
{
    unsigned int index = 0;

    (void)memset(image_definition, 0, sizeof(struct ZbZclOtaImageDefinition));

    if (zb_zcl_parse_uint16(payload, length, &index, &image_definition->manufacturer_code) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    if (zb_zcl_parse_uint16(payload, length, &index, &image_definition->image_type) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    if (zb_zcl_parse_uint32(payload, length, &index, &image_definition->file_version) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    if (zb_zcl_parse_uint32(payload, length, &index, current_time) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    if (zb_zcl_parse_uint32(payload, length, &index, upgrade_time) < 0) {
        return ZCL_STATUS_MALFORMED_COMMAND;
    }

    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
zcl_otacli_parse_image_notify_req(const uint8_t *payload, const unsigned int length,
    uint8_t *payload_type, uint8_t *jitter, struct ZbZclOtaImageDefinition *image_definition)
{
    unsigned int index = 0;

    if (image_definition != NULL) {
        (void)memset(image_definition, 0, sizeof(struct ZbZclOtaImageDefinition));

        if (zb_zcl_parse_uint8(payload, length, &index, payload_type) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (zb_zcl_parse_uint8(payload, length, &index, jitter) < 0) {
            return ZCL_STATUS_MALFORMED_COMMAND;
        }

        if (*payload_type > 0) {
            if (zb_zcl_parse_uint16(payload, length, &index, &image_definition->manufacturer_code) < 0) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
        }

        if (*payload_type > 1) {
            if (zb_zcl_parse_uint16(payload, length, &index, &image_definition->image_type) < 0) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
        }

        if (*payload_type > 2) {
            if (zb_zcl_parse_uint32(payload, length, &index, &image_definition->file_version) < 0) {
                return ZCL_STATUS_MALFORMED_COMMAND;
            }
        }
        return ZCL_STATUS_SUCCESS;
    }
    else {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

}

uint8_t
ZbZclOtaHeaderParse(const uint8_t *payload, const uint8_t length, struct ZbZclOtaHeader *ota_header)
{
    unsigned int index = 0;

    (void)memset(ota_header, 0, sizeof(struct ZbZclOtaHeader));

    if (zb_zcl_parse_uint32(payload, length, &index, &ota_header->file_identifier) < 0) {
        return 0;
    }
    if (ota_header->file_identifier != ZCL_OTA_HEADER_FILE_IDENTIFIER) {
        return 0;
    }
    if (zb_zcl_parse_uint16(payload, length, &index, &ota_header->header_version) < 0) {
        return index;
    }
    if (zb_zcl_parse_uint16(payload, length, &index, &ota_header->header_length) < 0) {
        return index;
    }
    if (zb_zcl_parse_uint16(payload, length, &index, &ota_header->header_field_control) < 0) {
        return index;
    }
    if (zb_zcl_parse_uint16(payload, length, &index, &ota_header->manufacturer_code) < 0) {
        return index;
    }
    if (zb_zcl_parse_uint16(payload, length, &index, &ota_header->image_type) < 0) {
        return index;
    }
    if (zb_zcl_parse_uint32(payload, length, &index, &ota_header->file_version) < 0) {
        return index;
    }
    if (zb_zcl_parse_uint16(payload, length, &index, &ota_header->stack_version) < 0) {
        return index;
    }
    if (index + 32 > length) {
        return index;
    }
    (void)memcpy(ota_header->header_string, payload + index, 32);
    index += 32;

    if (zb_zcl_parse_uint32(payload, length, &index, &ota_header->total_image_size) < 0) {
        return index;
    }

    /* optional fields are based field control */
    if (ota_header->header_field_control & ZCL_OTA_HEADER_FIELD_CONTROL_SECURITY_VERSION) {
        if (zb_zcl_parse_uint8(payload, length, &index, &ota_header->sec_credential_version) < 0) {
            return index;
        }
    }
    if (ota_header->header_field_control & ZCL_OTA_HEADER_FIELD_CONTROL_DEVICE_SPECIFIC) {
        if (zb_zcl_parse_uint64(payload, length, &index, &ota_header->file_destination) < 0) {
            return index;
        }
    }
    if (ota_header->header_field_control & ZCL_OTA_HEADER_FIELD_CONTROL_HARDWARE_VERSIONS) {
        if (zb_zcl_parse_uint16(payload, length, &index, &ota_header->min_hardware_version) < 0) {
            return index;
        }
        if (zb_zcl_parse_uint16(payload, length, &index, &ota_header->max_hardware_version) < 0) {
            return index;
        }
    }
    return index;
}

static void
zcl_ota_header_print(struct ZigBeeT *zb, struct ZbZclOtaHeader *ota_header)
{
    ZCL_LOG_PRINTF(zb, __func__, "OTA Header:");
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: 0x%08x", "Identifier", ota_header->file_identifier);
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: 0x%04x", "Header Version", ota_header->header_version);
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: %d (0x%04x)", "Header Length", ota_header->header_length, ota_header->header_length);
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: 0x%04x", "Header Field Control", ota_header->header_field_control);
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: 0x%04x", "Manufacturer Code", ota_header->manufacturer_code);
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: 0x%04x", "Image Type", ota_header->image_type);
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: 0x%08x", "File Version", ota_header->file_version);
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: 0x%04x", "ZigBee Stack Version", ota_header->stack_version);
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: \"%s\"", "OTA Header String", ota_header->header_string);
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: %d (0x%08x)", "Total Image Size", ota_header->total_image_size, ota_header->total_image_size);
}

static void
zcl_ota_image_def_print(struct ZigBeeT *zb, struct ZbZclOtaImageDefinition *image_definition, unsigned int image_size)
{
    ZCL_LOG_PRINTF(zb, __func__, "OTA Image Def:");
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: 0x%04x", "Manufacturer Code", image_definition->manufacturer_code);
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: 0x%04x", "Image Type", image_definition->image_type);
    ZCL_LOG_PRINTF(zb, __func__, "    %20s: 0x%" PRIx32, "File Version", image_definition->file_version);
    if (image_size > 0U) {
        ZCL_LOG_PRINTF(zb, __func__, "    %20s: %d", "Total Image Size", image_size);
    }
    else {
        ZCL_LOG_PRINTF(zb, __func__, "    %20s: %s", "Total Image Size", "N/A");
    }
}

static void
zcl_otacli_abort_download(struct cluster_priv_t *ota_cluster, enum ZbZclOtaCommandId cmd_id)
{
    struct ZigBeeT *zb = ota_cluster->cluster.zb;
    enum ZclStatusCodeT status;

    ZCL_LOG_PRINTF(zb, __func__, "Error, aborting OTA download (cmd = 0x%02x)", cmd_id);
    status = ota_cluster->config.callbacks.abort_download(&ota_cluster->cluster, cmd_id, ota_cluster->cluster.app_cb_arg);
    if (status != ZCL_STATUS_SUCCESS) {
        /* If app returns an error, then don't clear this download and let app be able to resume
         * by calling ZbZclOtaClientImageTransferResume(). */
        ZCL_LOG_PRINTF(zb, __func__, "Application returned status = 0x%02x. Leaving OTA intact for app to resume upon request.", status);
        ota_cluster->next_block_timeout = ZbZclUptime(zb) + ota_cluster->config.image_block_delay;
        ota_cluster->waiting_for_nhle = true;
        ota_cluster->block_retry = 0U;
        return;
    }
    ZCL_LOG_PRINTF(zb, __func__, "Resetting OTA Client.", status);
    zcl_otacli_reset_cluster(ota_cluster);
    ota_cluster->waiting_for_nhle = false;
}

static void
zcl_otacli_raw_write_skip_sig(struct cluster_priv_t *ota_cluster, uint16_t tag_id, uint16_t remaining)
{
    uint32_t block_cache_offset = ota_cluster->field_length_total - ota_cluster->field_length_remaining;
    uint32_t length;

    switch (tag_id) {
        case ZCL_OTA_SUB_TAG_ECDSA_SIG1:
        case ZCL_OTA_SUB_TAG_ECDSA_SIG2:
            /* include IEEE Address, skip remainder */
            if (block_cache_offset >= sizeof(uint64_t)) {
                return; /* already past */
            }
            /* figure how much of the next 8 bytes we have in the cache */
            if ((block_cache_offset + ota_cluster->block_cache_end) > 8) {
                length = 8 - block_cache_offset;
            }
            else {
                length = ota_cluster->block_cache_end;
            }
            break;

        case ZCL_OTA_SUB_TAG_IMAGE_INTEGRITY_CODE:
            return; /* omit hash, which is all of payload */

        default:
            length = remaining;
            break;
    }
    if (ota_cluster->config.callbacks.update_raw != NULL) {
        ota_cluster->config.callbacks.update_raw(&ota_cluster->cluster, (uint8_t)length, ota_cluster->block_cache,
            ota_cluster->cluster.app_cb_arg);
    }
}

static void
zcl_otacli_remove_from_cache(struct cluster_priv_t *ota_cluster, unsigned int count)
{
    (void)memmove(ota_cluster->block_cache, ota_cluster->block_cache + count, ota_cluster->block_cache_end - count);
    ota_cluster->block_cache_end -= count;
}

static enum ZclStatusCodeT
zcl_otacli_process_block_data(struct cluster_priv_t *ota_cluster)
{
    struct ZigBeeT *zb = ota_cluster->cluster.zb;
    unsigned int index;
    uint8_t parsed_header_length;
    enum ZclStatusCodeT status;

    if (ota_cluster->is_ota_header) {
        parsed_header_length = ZbZclOtaHeaderParse(ota_cluster->block_cache, (uint8_t)ota_cluster->block_cache_end, &ota_cluster->ota_header);
        if (parsed_header_length < ota_cluster->ota_header.header_length) {
            /* so far less than a full OTA Header, keep fetching */
            return ZCL_STATUS_SUCCESS;
        }
        else if (parsed_header_length > ota_cluster->ota_header.header_length) {
            ZCL_LOG_PRINTF(zb, __func__, "internal error processing OTA processed header length %d > %d contained in header itself ",
                parsed_header_length > ota_cluster->ota_header.header_length);
            return ZCL_STATUS_FAILURE;
        }

        /* we read a full OTA header, switching to sub-element reading mode */
        ota_cluster->is_ota_header = false;
        ota_cluster->have_tag_id = false;
        ota_cluster->field_length_remaining = 0; /* not read yet */

        zcl_ota_header_print(zb, &ota_cluster->ota_header);

        /* the cache contains a valid header, write it raw */
        if (ota_cluster->config.callbacks.update_raw != NULL) {
            ota_cluster->config.callbacks.update_raw(&ota_cluster->cluster, parsed_header_length,
                ota_cluster->block_cache, ota_cluster->cluster.app_cb_arg);
        }

        /* read *exactly* the OTA header - no more to process */
        if (ota_cluster->block_cache_end == ota_cluster->ota_header.header_length) {
            ota_cluster->block_cache_end = 0U;
            return ZCL_STATUS_SUCCESS;
        }

        /* more in the cache to process */
        /* remove OTA header from cache */
        zcl_otacli_remove_from_cache(ota_cluster, parsed_header_length);

        /* decrease threshold. Will need at least the sub-element header (6 bytes) in the cache */
        ota_cluster->block_cache_threshold = ZCL_OTA_IMAGE_BLOCK_SUB_ELEMENT_HEADER;
    }

    /* Process sub-elements (not OTA Header) */
    while (true) {
        /* get tag id if we don't have it */
        if (!ota_cluster->have_tag_id) {
            if (ota_cluster->block_cache_end > 2) {
                if (ota_cluster->config.callbacks.update_raw != NULL) {
                    ota_cluster->config.callbacks.update_raw(&ota_cluster->cluster, 2, ota_cluster->block_cache,
                        ota_cluster->cluster.app_cb_arg);
                }
                index = 0; /* don't use index, start at the beginning of the buffer */
                zb_zcl_parse_uint16(ota_cluster->block_cache, ota_cluster->block_cache_end, &index, &ota_cluster->current_tag_id);
                zcl_otacli_remove_from_cache(ota_cluster, 2);
                ota_cluster->have_tag_id = true;
                ota_cluster->field_length_remaining = 0;
            }
            else {
                /* one byte left, need more */
                ZCL_LOG_PRINTF(zb, __func__, "Returning SUCCESS (debug_line = %d)", __LINE__);
                return ZCL_STATUS_SUCCESS;
            }
        }

        index = 0; /* continue at beginning of the buffer */
        /* get tag length if we don't have it */
        if (ota_cluster->field_length_remaining == 0) { /* have not read sub-element header when tag-length is zero */
            if (ota_cluster->block_cache_end > 4) {
                if (ota_cluster->config.callbacks.update_raw != NULL) {
                    ota_cluster->config.callbacks.update_raw(&ota_cluster->cluster, 4, ota_cluster->block_cache,
                        ota_cluster->cluster.app_cb_arg);
                }
                /* Get the field length */
                index = 0;
                zb_zcl_parse_uint32(ota_cluster->block_cache, ota_cluster->block_cache_end, &index, &ota_cluster->field_length_total);
                /* Change the threshold element to 1 byte (minimum amount of data in a image block response) now that tag-ID and length was receieved */
                ota_cluster->block_cache_threshold = 1U;
                ota_cluster->field_length_remaining = ota_cluster->field_length_total;
                zcl_otacli_remove_from_cache(ota_cluster, 4);
            }
            else {
                /* not enough for field length, need more */
                ZCL_LOG_PRINTF(zb, __func__, "Returning SUCCESS (debug_line = %d)", __LINE__);
                return ZCL_STATUS_SUCCESS;
            }
        }

        if (ota_cluster->block_cache_end == 0) {
            ZCL_LOG_PRINTF(zb, __func__, "Returning SUCCESS (debug_line = %d)", __LINE__);
            return ZCL_STATUS_SUCCESS;
        }

        /* if the cache doesn't contain the what's left in the field */
        if (ota_cluster->block_cache_end < ota_cluster->field_length_remaining) {
            /* write the whole cache */
            zcl_otacli_raw_write_skip_sig(ota_cluster, ota_cluster->current_tag_id, ota_cluster->block_cache_end);
            if (ota_cluster->config.callbacks.write_tag != NULL) {
                status = ota_cluster->config.callbacks.write_tag(&ota_cluster->cluster, &ota_cluster->ota_header,
                        ota_cluster->current_tag_id, ota_cluster->field_length_total, (uint8_t)ota_cluster->block_cache_end,
                        ota_cluster->block_cache, ota_cluster->cluster.app_cb_arg);
            }
            else {
                status = ZCL_STATUS_SUCCESS;
            }
            ota_cluster->field_length_remaining -= ota_cluster->block_cache_end;
            zcl_otacli_remove_from_cache(ota_cluster, ota_cluster->block_cache_end);
            return status;
        }

        /* write the rest of the field and start next one */
        zcl_otacli_raw_write_skip_sig(ota_cluster, ota_cluster->current_tag_id, (uint16_t)ota_cluster->field_length_remaining);
        if (ota_cluster->config.callbacks.write_tag != NULL) {
            status = ota_cluster->config.callbacks.write_tag(&ota_cluster->cluster, &ota_cluster->ota_header,
                    ota_cluster->current_tag_id, ota_cluster->field_length_total, (uint8_t)ota_cluster->field_length_remaining,
                    ota_cluster->block_cache, ota_cluster->cluster.app_cb_arg);
        }
        else {
            status = ZCL_STATUS_SUCCESS;
        }
        /* The status is not checked but the application could return ZCL_STATUS_INVALID_FIELD. */
        /* Continue processing in case the application wants to deal with the other sub-elements */

        zcl_otacli_remove_from_cache(ota_cluster, ota_cluster->field_length_remaining);

        /* start next sub-element */
        ota_cluster->have_tag_id = false;
        /* Read the next sub-element so set threshold back to the minimum (6 bytes) */
        ota_cluster->block_cache_threshold = ZCL_OTA_IMAGE_BLOCK_SUB_ELEMENT_HEADER;
        ota_cluster->field_length_remaining = 0;

        /* ZCL_LOG_PRINTF(zb, __func__, "status = 0x%02x, block_cache_end = %d", status, ota_cluster->block_cache_end); */

        if (status == ZCL_STATUS_WAIT_FOR_DATA) {
            return ZCL_STATUS_WAIT_FOR_DATA;
        }

        if (ota_cluster->block_cache_end == 0) {
            return ZCL_STATUS_SUCCESS;
        }
    }
}

static void
zcl_otacli_request_next_block(struct cluster_priv_t *ota_cluster, ZbUptimeT timeout, unsigned int debug_line)
{
    struct ZigBeeT *zb = ota_cluster->cluster.zb;
    uint8_t validation_status;
    uint8_t upgrade_status;

    /* send next request */
    if (ota_cluster->file_offset < ota_cluster->ota_header.total_image_size) {
        /* kick off timer to call zcl_otacli_send_image_block_req after delay*/
        zcl_otacli_reset_block_timer(ota_cluster, timeout, debug_line);
        return;
    }

    /* transfer is complete, validate and upgrade */
    zcl_otacli_write_upgrade_status(ota_cluster, ZCL_OTA_STATUS_DOWNLOAD_COMPLETE, __LINE__);

    /* validate callback */
    if (ota_cluster->config.callbacks.image_validate != NULL) {
        validation_status = ota_cluster->config.callbacks.image_validate(&ota_cluster->cluster,
                &ota_cluster->ota_header, ota_cluster->cluster.app_cb_arg);
    }
    else {
        validation_status = ZCL_STATUS_SUCCESS;
    }

    ota_cluster->image_verified = (validation_status == ZCL_STATUS_SUCCESS);

    if (ota_cluster->image_verified) {
        ZCL_LOG_PRINTF(zb, __func__, "Validation successful");
    }
    else {
        ZCL_LOG_PRINTF(zb, __func__, "Error, validation failed. Resetting cluster.");
        zcl_otacli_reset_cluster(ota_cluster);
    }

    /* Send Upgrade End Response to server */
    upgrade_status = zcl_otacli_send_upgrade_end_req(ota_cluster, validation_status);
    if (upgrade_status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(zb, __func__, "sending upgrade end failed status 0x%02x", upgrade_status);
    }
    /* at this point we're done, the upgrade_end_response_handler will handle any response */
    /* can't free callback_data just yet, we have one more callback */
}

static void
zcl_otacli_block_req_retry(struct cluster_priv_t *client, enum ZclStatusCodeT status)
{
    struct ZigBeeT *zb = client->cluster.zb;

    /* EXEGIN - Stop watchdog timer */
    if (client->block_retry >= ZCL_OTA_CLIENT_BLOCK_RETRY_MAX) {
        ZCL_LOG_PRINTF(zb, __func__, "Error, aborting download (status = 0x%02x)", status);
        zcl_otacli_abort_download(client, ZCL_OTA_COMMAND_IMAGE_BLOCK_REQUEST);
        return;
    }
    /* Request the block again after the delay */
    client->block_retry++;
    ZCL_LOG_PRINTF(zb, __func__, "Retrying OTA Block Request (status = 0x%02x, retry = %d, delay = %d)",
        status, client->block_retry, client->config.image_block_delay);
    zcl_otacli_reset_block_timer(client, client->config.image_block_delay, __LINE__);
}

static void
zcl_otacli_handle_image_block_rsp(struct ZbZclCommandRspT *rsp, void *arg)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)arg;
    struct ZigBeeT *zb = ota_cluster->cluster.zb;
    struct ZbZclOtaImageDefinition image_definition_rsp;
    struct ZbZclOtaImageDefinition *image_definition_req;
    struct ZbZclOtaImageData image_data;
    struct ZbZclOtaImageWaitForData image_wait;
    uint8_t cmd_id = 0;
    unsigned int index = 0;
    enum ZclStatusCodeT status;
    uint32_t wait_time;

    if (rsp->status != ZCL_STATUS_SUCCESS) {
        zcl_otacli_block_req_retry(ota_cluster, rsp->status);
        return;
    }

    ota_cluster->block_retry = 0;

    if (rsp->hdr.frameCtrl.frameType == ZCL_FRAMETYPE_PROFILE) {
        if (rsp->hdr.cmdId == ZCL_COMMAND_DEFAULT_RESPONSE) {
            uint8_t byte_val;

            if (zb_zcl_parse_uint8(rsp->payload, rsp->length, &index, &cmd_id) < 0) {
                return;
            }
            if (cmd_id != ZCL_OTA_COMMAND_IMAGE_BLOCK_RESPONSE) {
                ZCL_LOG_PRINTF(zb, __func__, "Error, received default response for illegal command id (0x%02x)", cmd_id);
                return;
            }
            if (zb_zcl_parse_uint8(rsp->payload, rsp->length, &index, &byte_val) < 0) {
                return;
            }
            /* anticipated responses are MALFORMED_COMMAND, NO_IMAGE_AVAILABLE, and UNSUP_CLUSTER_COMMAND */
            ZCL_LOG_PRINTF(zb, __func__, "received default response status 0x%02x, resetting OTA client cluster", byte_val);
            zcl_otacli_abort_download(ota_cluster, ZCL_OTA_COMMAND_IMAGE_BLOCK_RESPONSE);
        }
        else {
            ZCL_LOG_PRINTF(zb, __func__, "OTA client cluster received unexpected Profile Command 0x%02x", rsp->hdr.cmdId);
        }
        return;
    }

    /* ! Stop watchdog timer? */

    image_definition_req = &ota_cluster->image_definition_last_query;

    status = zcl_otacli_parse_image_block_rsp(rsp->payload, rsp->length, &image_definition_rsp, &image_data, &image_wait);

    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(zb, __func__, "Error status = 0x%02x, packet length %d", status, rsp->length);
    }

    switch (status) {
        case ZCL_STATUS_SUCCESS:
            /* check received image definition against callback */
            if ((image_definition_rsp.manufacturer_code != image_definition_req->manufacturer_code)
                || (image_definition_rsp.image_type != image_definition_req->image_type)
                || (image_definition_rsp.file_version != image_definition_req->file_version)) {
                ZCL_LOG_PRINTF(zb, __func__, "response image definition does not match request, rejecting");
                break;
            }

            if (image_data.file_offset != ota_cluster->file_offset) {
                ZCL_LOG_PRINTF(zb, __func__, "Error, block response file offset doesn't match expected file offset, ignoring.");
                break;
            }

            if ((ota_cluster->block_cache_end + image_data.data_size) > ZCL_OTA_CLI_BLOCK_CACHE_SZ) {
                /* Should never get here. This means there was a buffer overflow. */
                ZCL_LOG_PRINTF(zb, __func__, "Fatal Error, OTA client cache buffer overflow");
                break;
            }

            /* append it cache */
            (void)memcpy(ota_cluster->block_cache + ota_cluster->block_cache_end, image_data.data, image_data.data_size);
            ota_cluster->block_cache_end += image_data.data_size;
            ota_cluster->file_offset += image_data.data_size;

            if (ota_cluster->block_cache_end >= ota_cluster->block_cache_threshold) {
                /* process and pass data to application to write */
                status = zcl_otacli_process_block_data(ota_cluster);
                if (status != ZCL_STATUS_SUCCESS) {
                    if (status == ZCL_STATUS_WAIT_FOR_DATA) {
                        /* Pause the download until the client calls ZbZclOtaClientImageTransferResume */
                        ota_cluster->next_block_timeout = ZbZclUptime(zb) + ota_cluster->config.image_block_delay;
                        ota_cluster->waiting_for_nhle = true;
                    }
                    else {
                        ZCL_LOG_PRINTF(zb, __func__, "Processing block failed (status = 0x%02x), aborting download", status);
                        zcl_otacli_abort_download(ota_cluster, ZCL_OTA_COMMAND_IMAGE_BLOCK_RESPONSE);
                    }
                    break;
                }
                zcl_otacli_request_next_block(ota_cluster, ota_cluster->config.image_block_delay, __LINE__);
            }
            else {
                /* kick off timer to call zcl_otacli_send_image_block_req after delay*/
                zcl_otacli_reset_block_timer(ota_cluster, ota_cluster->config.image_block_delay, __LINE__);
            }
            break;

        case ZCL_STATUS_WAIT_FOR_DATA:
            /* Modify the image block delay only if the MinimumBlockPeriod from the response is more than our cluster minimum */
            if (image_wait.minimum_block_period > ota_cluster->config.image_block_delay) {
                ZbZclAttrIntegerWrite(&ota_cluster->cluster, ZCL_OTA_ATTR_MIN_BLOCK_PERIOD, image_wait.minimum_block_period);
                ota_cluster->config.image_block_delay = image_wait.minimum_block_period;
            }

            zcl_otacli_write_upgrade_status(ota_cluster, ZCL_OTA_STATUS_DOWNLOAD_IN_PROGRESS, __LINE__);

            if (image_wait.current_time == 0U && image_wait.request_time != 0U) {
                wait_time = image_wait.request_time * 1000;
            }
            else if (image_wait.current_time == image_wait.request_time) {
                wait_time = ota_cluster->config.image_block_delay;
            }
            else {
                wait_time = (image_wait.request_time - image_wait.current_time) * 1000;
            }
            zcl_otacli_reset_block_timer(ota_cluster, wait_time, __LINE__);
            break;

        case ZCL_STATUS_ABORT:
            zcl_otacli_abort_download(ota_cluster, ZCL_OTA_COMMAND_IMAGE_BLOCK_RESPONSE);
            break;

        default:
            ZCL_LOG_PRINTF(zb, __func__, "illegal status data not handled");
            /* zcl_otacli_abort_download(ota_cluster, ZCL_OTA_COMMAND_IMAGE_BLOCK_RESPONSE); ? */
            break;
    }
}

static enum ZclStatusCodeT
zcl_otacli_handle_upgrade_end_rsp(struct ZbZclClusterT *cluster, struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)cluster;
    struct ZigBeeT *zb = ota_cluster->cluster.zb;
    struct ZbZclOtaImageDefinition image_definition;
    uint32_t current_time = 0;
    uint32_t upgrade_time = 0;
    enum ZclStatusCodeT status;

    if (!ota_cluster->image_verified) {
        ZCL_LOG_PRINTF(zb, __func__, "Warning, received UpgradeEndResponse without a valid image, ignoring.");
        return ZCL_STATUS_INVALID_IMAGE;
    }

    status = zcl_otacli_parse_upgrade_end_rsp(data_ind->asdu, data_ind->asduLength, &image_definition, &current_time, &upgrade_time);
    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(zb, __func__, "Error, failed to parse UpgradeEndResponse, resetting cluster.");
        zcl_otacli_reset_cluster(ota_cluster);
        return status;
    }

    ZCL_LOG_PRINTF(zb, __func__, "current_time = %d, upgrade_time = %d", current_time, upgrade_time);

    /* initiate upgrade, may involve delay, handled by application */
    if (ota_cluster->config.callbacks.upgrade_end != NULL) {
        status = ota_cluster->config.callbacks.upgrade_end(&ota_cluster->cluster,
                &ota_cluster->ota_header, current_time, upgrade_time, ota_cluster->cluster.app_cb_arg);
        if (status == ZCL_STATUS_SUCCESS) {
            if (ota_cluster->ota_status != ZCL_OTA_STATUS_NORMAL) {
                /* Don't reset the OTA Client cluster. The OTA upgrade is waiting to complete.
                 * The application can reset the cluster once complete by writing ZCL_OTA_STATUS_NORMAL to
                 * the ImageUpgradeStatus attribute. */
                return ZCL_STATUS_SUCCESS;
            }

            /* Upgrade done */
            zcl_otacli_reset_cluster(ota_cluster);
            return ZCL_STATUS_SUCCESS;
        }
    }
    else {
        ZCL_LOG_PRINTF(zb, __func__, "Warning, client upgrade callback is NULL");
    }

    if (status != ZCL_STATUS_SUCCESS) {
        zcl_otacli_reset_cluster(ota_cluster);
    }
    return status;
}

static void
zcl_otacli_handle_image_notify(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zcl_header, struct ZbApsdeDataIndT *data_ind)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)clusterPtr;
    enum ZclStatusCodeT status;
    struct ZbZclOtaImageDefinition image_definition;
    uint8_t payload_type, jitter;

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Received Image Notify Command");

    status = zcl_otacli_parse_image_notify_req(data_ind->asdu, data_ind->asduLength, &payload_type, &jitter, &image_definition);
    if (status != 0x00) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, failed to parse Notify Image request (0x%02x)", status);
        return;
    }

    zcl_ota_image_def_print(clusterPtr->zb, &image_definition, 0);

    if (ota_cluster->config.callbacks.image_notify != NULL) {
        (void)ota_cluster->config.callbacks.image_notify(clusterPtr, payload_type, jitter, &image_definition,
            data_ind, zcl_header);
    }
}

static enum ZclStatusCodeT
zcl_otacli_send_command(struct cluster_priv_t *ota_cluster, uint8_t cmd_id, uint8_t *payload,
    unsigned int length, void (*callback)(struct ZbZclCommandRspT *zcl_rsp, void *arg))
{
    struct ZbZclClusterCommandReqT req;

    if (ota_cluster->requested_server_ext == ZCL_INVALID_UNSIGNED_64BIT) {
        ZCL_LOG_PRINTF(ota_cluster->cluster.zb, __func__, "Error, OTA Server address not configured!");
        return ZCL_STATUS_FAILURE;
    }
    if (ota_cluster->upgrade_server_endpoint == ZB_ENDPOINT_ZDO) {
        ZCL_LOG_PRINTF(ota_cluster->cluster.zb, __func__, "Error, OTA Server endpoint not configured!");
        return ZCL_STATUS_FAILURE;
    }

    (void)memset(&req, 0, sizeof(req));
    req.dst.mode = ZB_APSDE_ADDRMODE_EXT;
    req.dst.extAddr = ota_cluster->requested_server_ext;
    req.dst.endpoint = ota_cluster->upgrade_server_endpoint;
    req.cmdId = cmd_id;
    req.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_TRUE;
    req.payload = payload;
    req.length = length;
    return ZbZclClusterCommandReq(&ota_cluster->cluster, &req, callback, ota_cluster);
}

static void
zcl_otacli_send_image_block_req(struct ZigBeeT *zb, void *arg)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)arg;
    uint8_t payload[ZCL_OTA_IMAGE_BLOCK_REQ_HDR_SIZE_MAX];
    int length;
    enum ZclStatusCodeT status;
    uint16_t min_block;

    min_block = (uint16_t)ZbZclAttrIntegerRead(&ota_cluster->cluster, (uint16_t)ZCL_OTA_ATTR_MIN_BLOCK_PERIOD, NULL, &status);
    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(zb, __func__, "Error, cannot read MIN_BLOCK_PERIOD attribute");
        /* EXEGIN - abort download? */
        return;
    }

    length = zcl_otacli_build_image_block_req(payload, sizeof(payload), &ota_cluster->image_definition_last_query,
            ota_cluster->file_offset, ota_cluster->data_size, min_block);
    if (length < 0) {
        /* EXEGIN - abort download? */
        return;
    }

    /* EXEGIN - add a long watchdog timer in case something goes horribly wrong?
     * (30 seconds + block delay?). Stop timer when valid response is received
     * in zcl_otacli_handle_image_block_rsp. */
    ZCL_LOG_PRINTF(zb, __func__, "Image Block Request (file_offset = %d, retry = %d)",
        ota_cluster->file_offset, ota_cluster->block_retry);
    status = zcl_otacli_send_command(ota_cluster, ZCL_OTA_COMMAND_IMAGE_BLOCK_REQUEST,
            payload, length, zcl_otacli_handle_image_block_rsp);
    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(zb, __func__, "Error, cannot send command (status = 0x%02x)", status);
        zcl_otacli_block_req_retry(ota_cluster, status);
        return;
    }
}

static enum ZclStatusCodeT
zcl_otacli_send_upgrade_end_req(struct cluster_priv_t *ota_cluster, uint8_t status)
{
    uint8_t payload[9]; /* including optional fields */
    int length = 0;

    length = zcl_otacli_build_upgrade_end_req(payload, sizeof(payload), status, &ota_cluster->image_definition_last_query);
    if (length < 0) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    return zcl_otacli_send_command(ota_cluster, ZCL_OTA_COMMAND_UPGRADE_END_REQUEST,
        payload, length, NULL);
}

static void
zcl_otacli_reboot_timer(struct ZigBeeT *zb, void *arg)
{
    struct ZbZclClusterT *clusterPtr = arg;
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)clusterPtr;

    zcl_otacli_reset_cluster(ota_cluster);
    if (ota_cluster->config.callbacks.reboot != NULL) {
        ota_cluster->config.callbacks.reboot(clusterPtr, clusterPtr->app_cb_arg);
    }
}

void
ZbZclOtaClientQueryNextImageCb(struct ZbZclClusterT *clusterPtr, enum ZclStatusCodeT status,
    struct ZbZclOtaImageDefinition *image_definition, uint32_t image_size, void *arg)
{
    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Query Next Image callback status (0x%02x)", status);
    if (status != ZCL_STATUS_SUCCESS) {
        /* No image available, or current image version matches server's version. */
        return;
    }

    zcl_ota_image_def_print(clusterPtr->zb, image_definition, image_size);

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Start image block request");
    status = ZbZclOtaClientImageTransferStart(clusterPtr);
    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "OTA cluster download failed status (0x%02x)", status);
        return;
    }
    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "OTA image block exchange started");
}

enum ZclStatusCodeT
ZbZclOtaClientImageUpdateRawCb(struct ZbZclClusterT *clusterPtr, uint8_t length, uint8_t *data, void *arg)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)clusterPtr;

    /* ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Wr-Raw length = %d, File offset = %d, Image size = %d",
        length, ota_cluster->file_offset, ota_cluster->last_query_image_size); */
    ZbHashAdd(&ota_cluster->hash, data, length);
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclOtaClientImageWriteTagCb(struct ZbZclClusterT *clusterPtr, struct ZbZclOtaHeader *ota_header,
    uint16_t tag_id, uint32_t tag_length, uint8_t data_length, uint8_t *data, void *arg)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)clusterPtr;
    enum ZclStatusCodeT status = ZCL_STATUS_SUCCESS;

    /* ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Wr-Tag length = %d of tag %04x (tag_length = %d)",
        data_length, tag_id, tag_length); */

    switch (tag_id) {
        case ZCL_OTA_SUB_TAG_UPGRADE_IMAGE:
            if (ota_cluster->config.callbacks.write_image != NULL) {
                status = ota_cluster->config.callbacks.write_image(clusterPtr, ota_header, data_length, data, clusterPtr->app_cb_arg);
                break;
            }
            break;

        case ZCL_OTA_SUB_TAG_ECDSA_SIG1:
        case ZCL_OTA_SUB_TAG_ECDSA_CERT_1:
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__,
                "Crypto Suite v1 not supported, cannot process Tag Id 0x%04x length %d", tag_id, tag_length);
            status = ZCL_STATUS_INVALID_FIELD;
            break;

        case ZCL_OTA_SUB_TAG_IMAGE_INTEGRITY_CODE:
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__,
                "Image Integrity Code not supported, cannot process Tag Id 0x%04x length %d", tag_id, tag_length);
            status = ZCL_STATUS_INVALID_FIELD;
            break;

        case ZCL_OTA_SUB_TAG_ECDSA_SIG2:
            if ((ota_cluster->signature2_offset + data_length) > sizeof(ota_cluster->signature2)) {
                status = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            (void)memcpy(&ota_cluster->signature2[ota_cluster->signature2_offset], data, data_length);
            ota_cluster->signature2_offset += data_length;
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "signature_length %d", ota_cluster->signature2_offset);
            if (ota_cluster->signature2_offset == ZB_SEC_CRYPTO_SUITE_V2_SIG_LEN) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Received full signature");
            }
            break;

        case ZCL_OTA_SUB_TAG_ECDSA_CERT_2:
            if ((ota_cluster->certificate2_offset + data_length) > sizeof(ota_cluster->certificate2)) {
                status = ZCL_STATUS_INSUFFICIENT_SPACE;
                break;
            }
            (void)memcpy(&ota_cluster->certificate2[ota_cluster->certificate2_offset], data, data_length);
            ota_cluster->certificate2_offset += data_length;
            if (ota_cluster->certificate2_offset == ZB_SEC_CRYPTO_SUITE_V2_CERT_LEN) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Received full certificate");
            }
            break;

        default:
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Unknown Tag 0x%04x of length %d", tag_id, tag_length);
            status = ZCL_STATUS_INVALID_FIELD;
            break;
    }

    if ((status == ZCL_STATUS_SUCCESS) && (tag_id < ZCL_OTA_SUB_TAG_TOTAL)) {
        ota_cluster->rx_tags[tag_id] = true;
    }

    return status;
}

static bool
zcl_otacli_has_tag(struct cluster_priv_t *ota_cluster, enum ZbZclOtaSubElementTag tag_id)
{
    if (tag_id >= ZCL_OTA_SUB_TAG_TOTAL) {
        return false;
    }
    return ota_cluster->rx_tags[tag_id];
}

static enum ZclStatusCodeT
ZbZclOtaClientImageValidateCb(struct ZbZclClusterT *clusterPtr, struct ZbZclOtaHeader *ota_header, void *arg)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)clusterPtr;
    struct ZbHash *cert_hash;
    uint8_t image_digest[AES_BLOCK_SIZE];
    uint8_t cert_digest[AES_BLOCK_SIZE];

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Validate:");
    zcl_ota_header_print(clusterPtr->zb, ota_header);

    /* Only Crypto Suite v2 is supported */
    if (!zcl_otacli_has_tag(ota_cluster, ZCL_OTA_SUB_TAG_ECDSA_SIG2)) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, ECDSA_SIG2 tag not found");
        return ZCL_STATUS_INVALID_IMAGE;
    }
    if (!zcl_otacli_has_tag(ota_cluster, ZCL_OTA_SUB_TAG_ECDSA_CERT_2)) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, ECDSA_CERT_2 tag not found");
        return ZCL_STATUS_INVALID_IMAGE;
    }

#if 0 /* debugging hash */
    {
        uint64_t hash_low, hash_high;

        hash_low = *(uint64_t *)&ota_cluster->hash.hash[0];
        hash_high = *(uint64_t *)&ota_cluster->hash.hash[8];
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "hash = 0x%016" PRIx64 "%016" PRIx64, hash_low, hash_high);
    }
#endif

    /* Compute hash of image data */
    ZbHashDigest(&ota_cluster->hash, image_digest);

    /* Compute the hash of the certificate */
    cert_hash = ZbHeapAlloc(clusterPtr->zb, sizeof(struct ZbHash));
    if (cert_hash == NULL) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }
    ZbHashInit(cert_hash);
    ZbHashAdd(cert_hash, ota_cluster->certificate2, ZB_SEC_CRYPTO_SUITE_V2_CERT_LEN);
    ZbHashDigest(cert_hash, cert_digest);
    ZbHeapFree(clusterPtr->zb, cert_hash);

#ifdef CONFIG_ZB_ZCL_SE
    if (ZbSecEcdsaValidate(clusterPtr->zb, ZB_SEC_ECDSA_SIG_SUITE_2,
            ota_cluster->config.ca_pub_key_array, ota_cluster->config.ca_pub_key_len,
            ota_cluster->certificate2, ota_cluster->signature2,
            (const uint8_t *)image_digest, (const uint8_t *)cert_digest) != ZB_STATUS_SUCCESS) {
        return ZCL_STATUS_FAILURE;
    }
#else
    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Warning, stack was not built with SE components, so ZbSecEcdsaValidate is not available.");
#endif

    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
ZbZclOtaClientImageUpgradeEndCb(struct ZbZclClusterT *clusterPtr, struct ZbZclOtaHeader *ota_header,
    uint32_t current_time, uint32_t upgrade_time, void *arg)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)clusterPtr;
    enum ZbZclOtaActivationPolicy activation_policy;
    enum ZclStatusCodeT status;
    uint32_t diff;

    /* read the activation policy attribute ZCL_OTA_ATTR_UPGRADE_ACTIVATION_POLICY,
     * if doesn't exist assume policy ZCL_OTA_ACTIVATION_POLICY_SERVER (0x00) */
    activation_policy = (enum ZbZclOtaActivationPolicy)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_OTA_ATTR_UPGRADE_ACTIVATION_POLICY, NULL, &status);
    if (status != ZCL_STATUS_SUCCESS) {
        activation_policy = ZCL_OTA_ACTIVATION_POLICY_SERVER;
    }

    /* when our policy is out of band, do not accept a request for a different upgrade time */
    if ((activation_policy == ZCL_OTA_ACTIVATION_POLICY_OUT_OF_BAND) && (upgrade_time != ZCL_OTA_UPGRADE_TIME_WAIT)) {
        return ZCL_STATUS_NOT_AUTHORIZED;
    }

    if (upgrade_time == ZCL_OTA_UPGRADE_TIME_WAIT) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "OTA Client: UpgradeTime equals indefinite wait, must receive unsolicited UpgradeEndRequest");
        zcl_otacli_write_upgrade_status(ota_cluster, ZCL_OTA_STATUS_WAITING_TO_UPGRADE, __LINE__);
        /* EXEGIN section 11.16 begin periodic poll as to when the upgrade should be performed */
        /* this SHALL happen not more than once every 60 minutes, if the server is unreachable
         * after 3 retries the device MAY apply the upgrade per section 11.11.4 */
        return ZCL_STATUS_SUCCESS;
    }

    if (upgrade_time < current_time) {
        return ZCL_STATUS_FAILURE;
    }

    diff = upgrade_time - current_time;
    if (diff > 0) {
        zcl_otacli_write_upgrade_status(ota_cluster, ZCL_OTA_STATUS_COUNT_DOWN, __LINE__);

        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Starting countdown to finish upgrade in %d seconds", diff);
        ZbTimerReset(ota_cluster->activation_timer, diff * 1000);
    }
    else {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Immediate upgrade");
        zcl_otacli_reboot_timer(clusterPtr->zb, clusterPtr);
    }
    return ZCL_STATUS_SUCCESS;
}

static enum ZclStatusCodeT
ZbZclOtaClientImageNotifyCb(struct ZbZclClusterT *clusterPtr, uint8_t payload_type, uint8_t jitter,
    struct ZbZclOtaImageDefinition *image_definition, struct ZbApsdeDataIndT *data_ind, struct ZbZclHeaderT *zcl_header)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)clusterPtr;
    enum ZclStatusCodeT status;
    uint8_t field_control = 0;
    uint16_t random_number;
    uint16_t manufacturer_code;
    uint16_t image_type;
    uint32_t file_version;
    struct ZbZclOtaImageDefinition query_image;

    manufacturer_code = (uint16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_OTA_ATTR_MANUFACTURER_ID, NULL, NULL);
    image_type = (uint16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_OTA_ATTR_IMAGE_TYPE_ID, NULL, NULL);
    file_version = (uint32_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_OTA_ATTR_CURRENT_FILE_VERSION, NULL, NULL);

    /* On receipt of a unicast Image Notify command, the device SHALL always send a Query Next Image
     * request back to the upgrade server regardless of the contents of the image notify command payload.
     * So only check image notify contents if command is broadcast. Query next image request payload
     * values are still the values from our OTA client attributes. */
    if (ZbApsAddrIsBcast(&data_ind->dst)) {
        /* For invalid broadcast or multicast Image Notify command, for example, out-of-range query jitter value is used,
         * or the reserved payload type value is used, or the command is badly formatted, the client SHALL ignore such command
         * and no processing SHALL be done. */
        /* jitter: random number from 1 to 100 */
        if (jitter > 100 || payload_type > (uint8_t)ZCL_OTA_NOTIFY_TYPE_FILE_VERSION) {
            return ZCL_STATUS_FAILURE;
        }

        random_number = (rand() % 100) + 1;
        if (random_number > jitter) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Dropping request since jitter too small");
            return ZCL_STATUS_SUCCESS;
        }

        if (payload_type > (uint8_t)ZCL_OTA_NOTIFY_TYPE_JITTER) {
            if (image_definition->manufacturer_code != manufacturer_code) {
                /* drop command since manufacturer code isn't equal */
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Manufacturer code isn't equal, dropping.");
                return ZCL_STATUS_FAILURE;
            }
        }
        if (payload_type > (uint8_t)ZCL_OTA_NOTIFY_TYPE_MFG_CODE) {
            if ((image_definition->image_type != image_type) && (image_definition->image_type != ZCL_OTA_IMAGE_TYPE_WILDCARD)) {
                /* drop command since image type isn't equal */
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Image type isn't equal, dropping.");
                return ZCL_STATUS_FAILURE;
            }
        }
        if (payload_type > (uint8_t)ZCL_OTA_NOTIFY_TYPE_IMAGE_TYPE) {
            /* However, payload type value of 0x03 has a slightly different effect. If the client
            * device has all the information matching those included in the command including the
            * new file version, the device SHALL then ignore the command. This indicates that the
            * device has already gone through the upgrade process. This is to prevent the device
            * from downloading the same image version multiple times. This is only true if the
            * command is sent as broadcast/multicast. */
            if ((image_definition->file_version == file_version) || (image_definition->file_version == ZCL_OTA_FILE_VERSION_WILDCARD)) {
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "File version is equal, dropping.");
                return ZCL_STATUS_FAILURE;
            }
        }
    }

    if (data_ind->src.extAddr == 0U) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, ext. source address of sender is not known, dropping.");
        return ZCL_STATUS_FAILURE;
    }
    if (ota_cluster->requested_server_ext == ZCL_INVALID_UNSIGNED_64BIT) {
        /* If the address is not already configured, use this info. */
        ota_cluster->requested_server_ext = data_ind->src.extAddr;
        ota_cluster->upgrade_server_endpoint = (uint8_t)data_ind->src.endpoint;
    }
    else if (ota_cluster->requested_server_ext != data_ind->src.extAddr) {
        /* If source doesn't match our currently configured OTA server, then drop this message. */
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Source address doesn't match current OTA server address, dropping.");
        return ZCL_STATUS_FAILURE;
    }
    else {
        /* Make sure the endpoint matches */
        ota_cluster->upgrade_server_endpoint = (uint8_t)data_ind->src.endpoint;
    }

    /* The Query Next Image request uses our CURRENT info and version. */
    (void)memset(&query_image, 0, sizeof(query_image));
    query_image.manufacturer_code = manufacturer_code;
    query_image.image_type = image_type;
    query_image.file_version = file_version;
    field_control |= ZCL_OTA_QUERY_FIELD_CONTROL_HW_VERSION;

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Sending Query Next Image request to server.");
    status = ZbZclOtaClientQueryNextImageReq(clusterPtr, &query_image, field_control, ota_cluster->config.hardware_version);
    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "failed to send Query Next Image Request");
        return ZCL_STATUS_FAILURE;
    }
    return ZCL_STATUS_SUCCESS;
}

static void
ZbZclOtaClientDiscoveryFinishCb(struct ZbZclClusterT *clusterPtr, enum ZclStatusCodeT status, void *arg)
{
    struct cluster_priv_t *ota_cluster = (struct cluster_priv_t *)clusterPtr;
    /* enum ZclStatusCodeT status; */
    uint8_t field_control = 0;
    uint16_t manufacturer_code;
    uint16_t image_type;
    uint32_t file_version;
    struct ZbZclOtaImageDefinition query_image;

    /* If discovery failed, then don't continue. */
    if (status != ZCL_STATUS_SUCCESS) {
        return;
    }

    manufacturer_code = (uint16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_OTA_ATTR_MANUFACTURER_ID, NULL, NULL);
    image_type = (uint16_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_OTA_ATTR_IMAGE_TYPE_ID, NULL, NULL);
    file_version = (uint32_t)ZbZclAttrIntegerRead(clusterPtr, (uint16_t)ZCL_OTA_ATTR_CURRENT_FILE_VERSION, NULL, NULL);

    /* The Query Next Image request uses our CURRENT info and version. */
    (void)memset(&query_image, 0, sizeof(query_image));
    query_image.manufacturer_code = manufacturer_code;
    query_image.image_type = image_type;
    query_image.file_version = file_version;
    field_control |= ZCL_OTA_QUERY_FIELD_CONTROL_HW_VERSION;

    status = ZbZclOtaClientQueryNextImageReq(clusterPtr, &query_image, field_control,
            ota_cluster->config.hardware_version);
    if (status != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "OTA query next image failed");
        return;
    }
}
