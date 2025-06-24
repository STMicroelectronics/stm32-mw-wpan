/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl/general/zcl.scenes.h"
#include "../zcl_heap.h" /* ZbHeapAlloc / ZbHeapFree */

/* 07-5123-06: Clusters with Scenes Table Extensions:
 *
 * Currently, there are only 6 clusters that support Scenes Table Extensions,
 * and the longest extension field set is 10 bytes (Lighting)
 *
 * Cluster ID   Category    Name                        Attributes
 * ----------------------------------------------------------------------------
 * 0x0006       General     OnOff Server                OnOff (bool)
 *
 * 0x0008       General     Level Control Server        CurrentLevel (uint8)
 *
 * 0x0101       Closures    Door Lock Server            LockState (enum8)
 *
 * 0x0102       Closures    Window Covering Server      CurrentPositionLiftPercentage (uint8)
 *                                                      CurrentPositionTiltPercentage (uint8)
 *
 * 0x0201       HVAC        Thermostat Server           OccupiedCoolingSetpoint (int16)
 *                                                      OccupiedHeatingSetpoint (int16)
 *                                                      SystemMode (enum8)
 *
 * 0x0300       Lighting    Color Control Server        CurrentX (uint16)
 *                                                      CurrentY (uint16)
 *                                                      EnhancedCurrentHue (uint8)
 *                                                      CurrentSaturation (uint8)
 *                                                      ColorLoopActive (uint8)
 *                                                      ColorLoopDirection (uint8)
 *                                                      ColorLoopTime (uint16)
 * ----------------------------------------------------------------------------
 */

#define ZCL_SCENES_EXT_FIELD_NUM_MAX        6
#define ZCL_SCENES_EXT_FIELD_LENGTH_MAX     16 /* a few extra bytes for safety */

/* Scene Name */
#define ZCL_SCENES_NAME_SUPPORT_BIT         0x80

static enum ZclStatusCodeT zcl_attr_read_cb(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, uint8_t *data,
    unsigned int maxlen, void *app_cb_arg);

static enum ZclStatusCodeT zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attributeId,
    const uint8_t *inputData, unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg);

static enum ZclStatusCodeT
zcl_attr_cb(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrCbInfoT *cb)
{
    if (cb->type == ZCL_ATTR_CB_TYPE_READ) {
        return zcl_attr_read_cb(clusterPtr, cb->info->attributeId, cb->zcl_data, cb->zcl_len, cb->app_cb_arg);
    }
    else if (cb->type == ZCL_ATTR_CB_TYPE_WRITE) {
        return zcl_attr_write_cb(clusterPtr, cb->src, cb->info->attributeId, cb->zcl_data, cb->zcl_len,
            cb->attr_data, cb->write_mode, cb->app_cb_arg);
    }
    else {
        return ZCL_STATUS_FAILURE;
    }
}

/* Scenes Attributes
 *
 * For many of the attributes, we purposely don't set ZCL_ATTR_FLAG_PERSISTABLE,
 * because when the persisted ZCL_SCENES_ATTR_SCENES_TABLE is restored, it uses
 * zcl_scenes_server_add_scene which also configures those attributes.
 * ZCL_SCENES_ATTR_LAST_CONFIGURED_BY gets set to ZCL_SCENES_LAST_CONFIG_UNKNOWN
 * when loading ZCL_SCENES_ATTR_SCENES_TABLE from persistence. */
static const struct ZbZclAttrT zcl_scenes_server_attr_list[] = {
    {
        /* Don't set ZCL_ATTR_FLAG_PERSISTABLE. Handled by ZCL_SCENES_ATTR_SCENES_TABLE */
        ZCL_SCENES_ATTR_SCENE_COUNT, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_SCENES_ATTR_CURRENT_SCENE, ZCL_DATATYPE_UNSIGNED_8BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_SCENES_ATTR_CURRENT_GROUP, ZCL_DATATYPE_UNSIGNED_16BIT,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0xfff7U}, {0, 0}
    },
    {
        ZCL_SCENES_ATTR_SCENE_VALID, ZCL_DATATYPE_BOOLEAN,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
    {
        ZCL_SCENES_ATTR_NAME_SUPPORT, ZCL_DATATYPE_BITMAP_8BIT,
        ZCL_ATTR_FLAG_PERSISTABLE | ZCL_ATTR_FLAG_CB_WRITE, 0,
        zcl_attr_cb, {0, 0}, {0, 0}
    },
    {
        ZCL_SCENES_ATTR_LAST_CONFIGURED_BY, ZCL_DATATYPE_EUI64,
        ZCL_ATTR_FLAG_NONE, 0, NULL, {0, 0}, {0, 0}
    },
};

struct ZbZclScenesExtFieldT {
    struct LinkListT link;
    uint16_t cluster_id;
    uint8_t length;
    uint8_t field[ZCL_SCENES_EXT_FIELD_LENGTH_MAX];
};
#define ZCL_SCENES_TABLE_PERSIST_EXT_FIELD_SZ \
    (2 /* cluster */ + 1 /* length */ + ZCL_SCENES_EXT_FIELD_LENGTH_MAX /* field */)

/* Special case when Group ID == 0x0000:
 *
 * "In most cases scenes are associated with a particular group ID.
 * Scenes MAY also exist without a group, in which case the value
 * 0x0000 replaces the group ID. Note that extra care is required
 * in these cases to avoid a scene ID collision, and that commands
 * related to scenes without a group MAY only be unicast, i.e.,
 * they MAY not be multicast or broadcast."
 *
 * Interestingly, an APS Group ID of 0x0000 is a valid group.
 * The valid range of APS Group Addresses is 0x0000 to 0xffff (inclusive),
 * according to R21. I suppose ZCL Scenes is more restrictive as
 * to Group Addresses a Scene can belong to. It seems like the Spec
 * could have better addressed Scenes that don't belong to a specific
 * Group Address, rather than trying to use special values. */

#define ZCL_SCENES_LAST_CONFIG_UNKNOWN      0xffffffffffffffffull

/* Copy Scene Command "Mode" Field */
#define ZCL_SCENES_COPY_MODE_ALL            0x01

/* Exegin custom internal attributes */
enum {
    /* For persisting Scenes Table */
    ZCL_SCENES_ATTR_SCENES_TABLE = 0x7fff,
};

struct ZbZclScenesTableEntryT {
    struct LinkListT link;
    uint16_t group_id;
    uint8_t scene_id;
    char scene_name[ZCL_SCENES_NAME_MAX_LENGTH + 1U];
    uint16_t transition_time_sec; /* seconds */
    uint8_t transition_time_tenths; /* tenth's of a second */
    uint8_t extension_field_num;
    struct LinkListT extension_field_sets; /* List of "struct ZbZclScenesExtFieldT" */
};

/* Size of a scene */
#define ZCL_SCENES_TABLE_PERSIST_SCENE_SZ \
    (2 /* group */ + 1 /* scene */ + (1 + ZCL_SCENES_NAME_MAX_LENGTH + 1) /* name */ + \
     2 /* sec */ + 1 /* tenths */ + 1 /* ext num */ + \
     (ZCL_SCENES_TABLE_PERSIST_EXT_FIELD_SZ * ZCL_SCENES_EXT_FIELD_NUM_MAX) /* ext set */)

/* Max size required to persist scenes table */
#define ZCL_SCENES_TABLE_PERSIST_MAX_SZ(_num_scenes_) \
    (1 /* num_scenes field */ + ((unsigned int)(_num_scenes_) * ZCL_SCENES_TABLE_PERSIST_SCENE_SZ))

struct cluster_priv_t {
    /* ZCL Cluster struct - goes first for inheritance. */
    struct ZbZclClusterT cluster;

    /* List of "struct ZbZclScenesTableEntryT" */
    struct LinkListT scenes_list;
    uint8_t max_scenes;

    /* Scenes Table attribute. Cannot be const because ZbZclScenesServerAlloc
     * defines how large the table can be (max_scenes). */
    struct ZbZclAttrT scenes_table_attr;
};

/* Callback Prototypes */
static enum ZclStatusCodeT zcl_scenes_server_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr);
static void zcl_scenes_server_cleanup(struct ZbZclClusterT *clusterPtr);

/* Internal Scene Table Functions */
static struct ZbZclScenesTableEntryT * zcl_scenes_server_alloc_scene(struct ZigBeeT *zb);
static struct ZbZclScenesExtFieldT * zcl_scenes_server_alloc_ext_field(struct ZigBeeT *zb, uint16_t clusterId,
    const uint8_t *ext_data, uint8_t ext_length);
static bool zcl_scenes_server_add_scene(struct cluster_priv_t *serverPtr, struct ZbZclScenesTableEntryT *newScene,
    uint64_t srcExtAddr);
static struct ZbZclScenesTableEntryT * zcl_scenes_server_find_scene(
    struct cluster_priv_t *serverPtr, uint16_t group_id, uint8_t scene_id);
static void zcl_scenes_server_scene_extension_set_free_all(struct ZigBeeT *zb, struct ZbZclScenesTableEntryT *scene);
static bool zcl_scenes_server_remove_scene(struct cluster_priv_t *serverPtr, uint16_t group_id, uint8_t scene_id);
static unsigned int zcl_scenes_server_remove_all_scenes_by_group(
    struct cluster_priv_t *serverPtr, uint16_t group_id);
static unsigned int zcl_scenes_server_remove_all_scenes(struct cluster_priv_t *serverPtr);
static uint8_t zcl_scenes_server_copy_scene(struct cluster_priv_t *serverPtr, uint16_t groupIdFrom,
    uint8_t sceneIdFrom, uint16_t groupIdTo, uint8_t sceneIdTo, uint64_t srcExtAddr);
static void zcl_scenes_server_update_current_scene(struct cluster_priv_t *serverPtr, uint16_t groupId,
    uint8_t sceneId, bool sceneValid);
static void zcl_scenes_server_update_last_configured_by(struct cluster_priv_t *serverPtr, uint64_t srcExtAddr);

/* Command Handler Prototypes */
static void zcl_scenes_server_handle_add(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr, bool isEnhanced);
static void zcl_scenes_server_handle_view(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr, bool isEnhanced);
static void zcl_scenes_server_handle_remove_scene(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr);
static void zcl_scenes_server_handle_remove_all(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr);
static void zcl_scenes_server_handle_store(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr);
static enum ZclStatusCodeT zcl_scenes_server_handle_recall(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr);
static void zcl_scenes_server_handle_get_membership(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr);
static void zcl_scenes_server_handle_copy(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr);

static bool zcl_scenes_server_scene_count_increment(struct ZbZclClusterT *clusterPtr);
static bool zcl_scenes_server_scene_count_decrement(struct ZbZclClusterT *clusterPtr);

struct ZbZclClusterT *
ZbZclScenesServerAlloc(struct ZigBeeT *zb, uint8_t endpoint, uint8_t max_scenes)
{
    struct cluster_priv_t *clusterPtr;

    ZCL_LOG_PRINTF(zb, __func__, "max_scenes = %d", max_scenes);
    ZCL_LOG_PRINTF(zb, __func__, "ZCL_SCENES_TABLE_PERSIST_MAX_SZ(max_scenes) = %d",
        ZCL_SCENES_TABLE_PERSIST_MAX_SZ(max_scenes));

    clusterPtr = ZbZclClusterAlloc(zb, sizeof(struct cluster_priv_t), ZCL_CLUSTER_SCENES, endpoint, ZCL_DIRECTION_TO_SERVER);
    if (clusterPtr == NULL) {
        return NULL;
    }

    /* Revision 2 implemented: "Recall Scene Transition Time field" */
    (void)ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_GLOBAL_ATTR_CLUSTER_REV, 2);

    clusterPtr->cluster.command = zcl_scenes_server_command;
    clusterPtr->cluster.cleanup = zcl_scenes_server_cleanup;

    clusterPtr->max_scenes = max_scenes;
    LINK_LIST_INIT(&clusterPtr->scenes_list);

    /* Allocate the attributes */
    if (ZbZclAttrAppendList(&clusterPtr->cluster, zcl_scenes_server_attr_list, ZCL_ATTR_LIST_LEN(zcl_scenes_server_attr_list))) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    clusterPtr->scenes_table_attr.attributeId = ZCL_SCENES_ATTR_SCENES_TABLE;
    clusterPtr->scenes_table_attr.dataType = ZCL_DATATYPE_STRING_LONG_OCTET;
    clusterPtr->scenes_table_attr.flags = ZCL_ATTR_FLAG_INTERNAL | ZCL_ATTR_FLAG_PERSISTABLE | ZCL_ATTR_FLAG_CB_READ | ZCL_ATTR_FLAG_CB_WRITE;
    clusterPtr->scenes_table_attr.customValSz = ZCL_SCENES_TABLE_PERSIST_MAX_SZ(max_scenes);
    clusterPtr->scenes_table_attr.callback = zcl_attr_cb;
    if (ZbZclAttrAppendList(&clusterPtr->cluster, &clusterPtr->scenes_table_attr, 1)) {
        ZbZclClusterFree(&clusterPtr->cluster);
        return NULL;
    }

    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_SCENES_ATTR_SCENE_COUNT, 0);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_SCENES_ATTR_CURRENT_SCENE, 0x00);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_SCENES_ATTR_CURRENT_GROUP, 0x0000);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_SCENES_ATTR_SCENE_VALID, false);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_SCENES_ATTR_NAME_SUPPORT, 0x00);
    ZbZclAttrIntegerWrite(&clusterPtr->cluster, ZCL_SCENES_ATTR_LAST_CONFIGURED_BY, ZCL_SCENES_LAST_CONFIG_UNKNOWN);

    (void)ZbZclClusterAttach(&clusterPtr->cluster);
    return &clusterPtr->cluster;
}

static void
zcl_scenes_server_cleanup(struct ZbZclClusterT *clusterPtr)
{
    struct cluster_priv_t *serverPtr = (void *)clusterPtr;

    /* Free the Scenes Table */
    zcl_scenes_server_remove_all_scenes(serverPtr);
}

static enum ZclStatusCodeT
zcl_attr_read_cb(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, uint8_t *attr_ptr,
    unsigned int maxlen, void *app_cb_arg)
{
    struct cluster_priv_t *serverPtr = (void *)clusterPtr;

    switch (attributeId) {
        case ZCL_SCENES_ATTR_SCENES_TABLE:
        {
            struct LinkListT *p, *q;
            struct ZbZclScenesTableEntryT *scene;
            unsigned int i = 2, num_scenes = 0;

            /* Scene Persistence Format:
             *    NumScenes (1 octet)
             *    Scene[0] = {
             *        Group ID (2 octets)
             *        Scene ID (1 octet)
             *        NameLen (1 octet)
             *        Name (NameLen octets)
             *        TransTimeSecs (2 octets)
             *        TransTimeTenths (1 octet)
             *        ExtFieldNum (1 octet)
             *        ExtField[0] = {
             *            ClusterId (2 octets)
             *            FieldLen (1 octet)
             *            Field (FieldLen octets)
             *        } ...
             *    } ...
             */

            /* Num Scenes (1 octet) */
            if ((i + 1) > maxlen) {
                return ZCL_STATUS_INSUFFICIENT_SPACE;
            }
            attr_ptr[i++] = 0;

            for (p = LINK_LIST_HEAD(&serverPtr->scenes_list); p; p = LINK_LIST_NEXT(p, &serverPtr->scenes_list)) {
                unsigned int name_len;

                scene = LINK_LIST_ITEM(p, struct ZbZclScenesTableEntryT, link);
                name_len = strlen(scene->scene_name);

                if ((i + 4) > maxlen) {
                    return ZCL_STATUS_INSUFFICIENT_SPACE;
                }
                putle16(&attr_ptr[i], scene->group_id);
                i += 2;
                attr_ptr[i++] = scene->scene_id;
                attr_ptr[i++] = (uint8_t)name_len;
                if (name_len != 0U) {
                    if ((i + name_len) > maxlen) {
                        return ZCL_STATUS_INSUFFICIENT_SPACE;
                    }
                    (void)memcpy(&attr_ptr[i], scene->scene_name, name_len);
                    i += name_len;
                }
                if ((i + 4) > maxlen) {
                    return ZCL_STATUS_INSUFFICIENT_SPACE;
                }
                putle16(&attr_ptr[i], scene->transition_time_sec);
                i += 2;
                attr_ptr[i++] = scene->transition_time_tenths;
                attr_ptr[i++] = scene->extension_field_num;

                /* Traverse the Extension Field Sets */
                for (q = LINK_LIST_HEAD(&scene->extension_field_sets); q;
                     q = LINK_LIST_NEXT(q, &scene->extension_field_sets)) {
                    struct ZbZclScenesExtFieldT *ext_field;

                    ext_field = LINK_LIST_ITEM(q, struct ZbZclScenesExtFieldT, link);
                    if (ext_field->length == 0) {
                        /* Shouldn't get here */
                        continue;
                    }

                    if ((i + 3 + ext_field->length) > maxlen) {
                        return ZCL_STATUS_INSUFFICIENT_SPACE;
                    }
                    putle16(&attr_ptr[i], ext_field->cluster_id);
                    i += 2;
                    attr_ptr[i++] = ext_field->length;
                    (void)memcpy(&attr_ptr[i], ext_field->field, ext_field->length);
                    i += ext_field->length;
                }

                num_scenes++;
            }

            /* Num Scenes (1 octet) */
            attr_ptr[2] = num_scenes;

            /* string-long-octet length */
            putle16(&attr_ptr[0], i - 2);
            return ZCL_STATUS_SUCCESS;
        }

        default:
            /* Unsupported Attribute */
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
}

static enum ZclStatusCodeT
zcl_attr_write_cb(struct ZbZclClusterT *clusterPtr, const struct ZbApsAddrT *src, uint16_t attributeId, const uint8_t *inputData,
    unsigned int inputMaxLen, void *attrData, ZclWriteModeT mode, void *app_cb_arg)
{
    struct cluster_priv_t *serverPtr = (void *)clusterPtr;

    switch (attributeId) {
        case ZCL_SCENES_ATTR_SCENES_TABLE:
        {
            const uint8_t *attr_ptr = inputData;
            uint16_t strlong_len;
            unsigned int i = 0, j, k, num_scenes = 0;
            uint8_t name_len;
            unsigned int maxlen = ZCL_SCENES_TABLE_PERSIST_MAX_SZ(serverPtr->max_scenes);
            enum ZclStatusCodeT status = ZCL_STATUS_SUCCESS;

            if ((mode & ZCL_ATTR_WRITE_FLAG_PERSIST) == 0U) {
                return ZCL_STATUS_READ_ONLY;
            }

            /* EXEGIN - check inputMaxLen */

            /* ZCL_DATATYPE_STRING_LONG_OCTET */
            strlong_len = pletoh16(&attr_ptr[i]);
            i += 2;
            if (strlong_len > maxlen) {
                return ZCL_STATUS_INSUFFICIENT_SPACE;
            }
            /* For inputData buffer underflow checking, add 2 octets for the
             * ZCL_DATATYPE_STRING_LONG_OCTET length field. */
            strlong_len += 2;

            if ((i + 1) > strlong_len) {
                /* Shouldn't get here, even for an empty scenes table. */
                return ZCL_STATUS_SUCCESS;
            }
            /* Num Scenes (1 octet) */
            num_scenes = attr_ptr[i++];
            if (num_scenes > serverPtr->max_scenes) {
                return ZCL_STATUS_INSUFFICIENT_SPACE;
            }

            /* Remove all scenes (there shouldn't be any yet) */
            zcl_scenes_server_remove_all_scenes(serverPtr);

            for (j = 0; j < num_scenes; j++) {
                struct ZbZclScenesTableEntryT *scene = NULL;

                if ((i + 4) > strlong_len) {
                    status = ZCL_STATUS_MALFORMED_COMMAND;
                    goto FREE_FAILED_SCENE;
                }
                scene = zcl_scenes_server_alloc_scene(clusterPtr->zb);
                if (!scene) {
                    status = ZCL_STATUS_INSUFFICIENT_SPACE;
                    goto FREE_FAILED_SCENE;
                }
                scene->group_id = pletoh16(&attr_ptr[i]);
                i += 2;
                scene->scene_id = attr_ptr[i++];
                name_len = attr_ptr[i++];
                if (name_len) {
                    if (name_len > ZCL_SCENES_NAME_MAX_LENGTH) {
                        return ZCL_STATUS_FAILURE;
                    }
                    if ((i + name_len) > strlong_len) {
                        status = ZCL_STATUS_MALFORMED_COMMAND;
                        goto FREE_FAILED_SCENE;
                    }
                    (void)memcpy(&scene->scene_name, &attr_ptr[i], name_len);
                    scene->scene_name[name_len] = 0; /* redundant */
                    i += name_len;
                }
                scene->transition_time_sec = pletoh16(&attr_ptr[i]);
                i += 2;
                scene->transition_time_tenths = attr_ptr[i++];
                scene->extension_field_num = attr_ptr[i++];

                for (k = 0; k < scene->extension_field_num; k++) {
                    struct ZbZclScenesExtFieldT ext_field;
                    struct ZbZclScenesExtFieldT *ext_field_ptr;

                    if ((i + 3) > strlong_len) {
                        status = ZCL_STATUS_MALFORMED_COMMAND;
                        goto FREE_FAILED_SCENE;
                    }
                    (void)memset(&ext_field, 0, sizeof(ext_field));
                    ext_field.cluster_id = pletoh16(&attr_ptr[i]);
                    i += 2;
                    ext_field.length = attr_ptr[i++];
                    if (ext_field.length) {
                        if (ext_field.length > ZCL_SCENES_EXT_FIELD_LENGTH_MAX) {
                            return ZCL_STATUS_FAILURE;
                        }
                        if ((i + ext_field.length) > strlong_len) {
                            status = ZCL_STATUS_MALFORMED_COMMAND;
                            goto FREE_FAILED_SCENE;
                        }
                        (void)memcpy(ext_field.field, &attr_ptr[i], ext_field.length);
                        i += ext_field.length;
                    }
                    ext_field_ptr = zcl_scenes_server_alloc_ext_field(clusterPtr->zb, ext_field.cluster_id,
                            ext_field.field, ext_field.length);
                    if (!ext_field_ptr) {
                        status = ZCL_STATUS_INSUFFICIENT_SPACE;
                        goto FREE_FAILED_SCENE;
                    }
                    LINK_LIST_INSERT_TAIL(&scene->extension_field_sets, &ext_field_ptr->link);
                } /* for (k) */

                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Restoring scene (g = 0x%04x, s = 0x%02x, n = %s)",
                    scene->group_id, scene->scene_id, scene->scene_name);

                /* Add this scene */
                if (zcl_scenes_server_add_scene(serverPtr, scene, ZCL_SCENES_LAST_CONFIG_UNKNOWN)) {
                    continue;
                }

FREE_FAILED_SCENE:
                ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, failed to restore scenes table from persistence");

                if (scene != NULL) {
                    /* Free the half-baked scene */
                    zcl_scenes_server_scene_extension_set_free_all(clusterPtr->zb, scene);
                    ZbHeapFree(clusterPtr->zb, scene);
                }

                /* Remove any scenes added through partial persistence restore */
                zcl_scenes_server_remove_all_scenes(serverPtr);
                return status;
            } /* for (j) */
            return ZCL_STATUS_SUCCESS;
        }

        case ZCL_SCENES_ATTR_NAME_SUPPORT:
        {
            uint8_t val;

            val = inputData[0];
            if ((val & ~(ZCL_SCENES_NAME_SUPPORT_MASK)) != 0U) {
                return ZCL_STATUS_INVALID_VALUE;
            }
            if ((mode & ZCL_ATTR_WRITE_FLAG_TEST) == 0U) {
                (void)memcpy(attrData, inputData, 1);
            }
            return ZCL_STATUS_SUCCESS;
        }

        default:
            /* Unsupported Attribute */
            return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }
}

static enum ZclStatusCodeT
zcl_scenes_server_command(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *dataIndPtr)
{
    struct cluster_priv_t *serverPtr = (void *)clusterPtr;

    if (zclHdrPtr->frameCtrl.direction != ZCL_DIRECTION_TO_SERVER) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }
    if (zclHdrPtr->frameCtrl.manufacturer) {
        return ZCL_STATUS_UNSUPP_COMMAND;
    }

    ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Handling Cluster command: 0x%02x", zclHdrPtr->cmdId);

    /* Handle Cluster Specific Commands */
    switch (zclHdrPtr->cmdId) {
        case ZCL_SCENES_COMMAND_ADD_SCENE:
            zcl_scenes_server_handle_add(serverPtr, dataIndPtr, zclHdrPtr, false);
            break;

        case ZCL_SCENES_COMMAND_VIEW_SCENE:
            zcl_scenes_server_handle_view(serverPtr, dataIndPtr, zclHdrPtr, false);
            break;

        case ZCL_SCENES_COMMAND_REMOVE_SCENE:
            zcl_scenes_server_handle_remove_scene(serverPtr, dataIndPtr, zclHdrPtr);
            break;

        case ZCL_SCENES_COMMAND_REMOVE_ALL_SCENES:
            zcl_scenes_server_handle_remove_all(serverPtr, dataIndPtr, zclHdrPtr);
            break;

        case ZCL_SCENES_COMMAND_STORE_SCENE:
            zcl_scenes_server_handle_store(serverPtr, dataIndPtr, zclHdrPtr);
            break;

        case ZCL_SCENES_COMMAND_RECALL_SCENE:
            return zcl_scenes_server_handle_recall(serverPtr, dataIndPtr, zclHdrPtr);

        case ZCL_SCENES_COMMAND_GET_SCENE_MBRSHIP:
            zcl_scenes_server_handle_get_membership(serverPtr, dataIndPtr, zclHdrPtr);
            break;

        case ZCL_SCENES_COMMAND_ENH_ADD_SCENE:
            zcl_scenes_server_handle_add(serverPtr, dataIndPtr, zclHdrPtr, true);
            break;

        case ZCL_SCENES_COMMAND_ENH_VIEW_SCENE:
            zcl_scenes_server_handle_view(serverPtr, dataIndPtr, zclHdrPtr, true);
            break;

        case ZCL_SCENES_COMMAND_COPY_SCENE:
            zcl_scenes_server_handle_copy(serverPtr, dataIndPtr, zclHdrPtr);
            break;

        default:
            /* Unsupported command*/
            return ZCL_STATUS_UNSUPP_COMMAND;
    }
    return ZCL_STATUS_SUCCESS_NO_DEFAULT_RESPONSE;
}

static struct ZbZclScenesTableEntryT *
zcl_scenes_server_alloc_scene(struct ZigBeeT *zb)
{
    struct ZbZclScenesTableEntryT *newScene;

    newScene = ZbHeapAlloc(zb, sizeof(struct ZbZclScenesTableEntryT));
    if (newScene == NULL) {
        return NULL;
    }
    (void)memset(newScene, 0, sizeof(struct ZbZclScenesTableEntryT));
    LINK_LIST_INIT(&newScene->link);
    LINK_LIST_INIT(&newScene->extension_field_sets);
    return newScene;
}

static struct ZbZclScenesExtFieldT *
zcl_scenes_server_alloc_ext_field(struct ZigBeeT *zb, uint16_t clusterId, const uint8_t *ext_data, uint8_t ext_length)
{
    struct ZbZclScenesExtFieldT *extField;

    if (ext_length > ZCL_SCENES_EXT_FIELD_LENGTH_MAX) {
        return NULL;
    }

    extField = ZbHeapAlloc(zb, sizeof(struct ZbZclScenesExtFieldT));
    if (extField == NULL) {
        return NULL;
    }
    (void)memset(extField, 0, sizeof(struct ZbZclScenesExtFieldT));
    LINK_LIST_INIT(&extField->link);
    extField->cluster_id = clusterId;
    extField->length = ext_length;
    if (ext_length) {
        (void)memcpy(extField->field, ext_data, ext_length);
    }
    return extField;
}

static bool
zcl_scenes_server_scene_count_increment(struct ZbZclClusterT *clusterPtr)
{
    struct cluster_priv_t *serverPtr = (void *)clusterPtr;
    uint8_t sceneCount;

    if (ZbZclAttrRead(clusterPtr, ZCL_SCENES_ATTR_SCENE_COUNT, NULL, &sceneCount, sizeof(sceneCount), false) != ZCL_STATUS_SUCCESS) {
        return false;
    }
    if (sceneCount >= serverPtr->max_scenes) {
        return false;
    }
    sceneCount++;
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_SCENES_ATTR_SCENE_COUNT, sceneCount);
    return true;
}

static bool
zcl_scenes_server_scene_count_decrement(struct ZbZclClusterT *clusterPtr)
{
    uint8_t sceneCount;

    if (ZbZclAttrRead(clusterPtr, ZCL_SCENES_ATTR_SCENE_COUNT, NULL, &sceneCount, sizeof(sceneCount), false) != ZCL_STATUS_SUCCESS) {
        /* Might get here if destroying cluster */
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Failed to read scene count attribute");
        return false;
    }
    if (!sceneCount) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, scene count is already 0");
        return false;
    }
    sceneCount--;
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_SCENES_ATTR_SCENE_COUNT, sceneCount);
    return true;
}

static void
zcl_scenes_server_scene_update_last_configured(struct cluster_priv_t *serverPtr, uint16_t new_group_id,
    uint8_t new_scene_id, uint64_t srcExtAddr)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    uint16_t group_id;
    uint8_t scene_id;

    if (ZbZclAttrRead(clusterPtr, ZCL_SCENES_ATTR_CURRENT_GROUP, NULL, &group_id, sizeof(group_id), false) != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Failed to read current group attribute");
        return;
    }
    if (ZbZclAttrRead(clusterPtr, ZCL_SCENES_ATTR_CURRENT_SCENE, NULL, &scene_id, sizeof(scene_id), false) != ZCL_STATUS_SUCCESS) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Failed to read current scene attribute");
        return;
    }
    if ((group_id == new_group_id) && (scene_id == new_scene_id)) {
        /* If we're changing the current scene, then set the
         * current scene to false. */
        zcl_scenes_server_update_current_scene(serverPtr, 0x0000, 0x00, false);
    }
    zcl_scenes_server_update_last_configured_by(serverPtr, srcExtAddr);
}

static bool
zcl_scenes_server_add_scene(struct cluster_priv_t *serverPtr, struct ZbZclScenesTableEntryT *newScene, uint64_t srcExtAddr)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;

    /* Delete Scene Table entry that may have the same Scene ID and Group ID */
    zcl_scenes_server_remove_scene(serverPtr, newScene->group_id, newScene->scene_id);

    if (!zcl_scenes_server_scene_count_increment(clusterPtr)) {
        /* May have hit max number of scenes (serverPtr->max_scenes) */
        return false;
    }

    /* Add scene to our Scenes Table */
    LINK_LIST_INSERT_TAIL(&serverPtr->scenes_list, &newScene->link);

    zcl_scenes_server_scene_update_last_configured(serverPtr, newScene->group_id, newScene->scene_id, srcExtAddr);

    ZbZclAttrPersist(clusterPtr, ZCL_SCENES_ATTR_SCENES_TABLE);
    return true;
}

static struct ZbZclScenesTableEntryT *
zcl_scenes_server_find_scene(struct cluster_priv_t *serverPtr, uint16_t group_id, uint8_t scene_id)
{
    struct LinkListT *p;
    struct ZbZclScenesTableEntryT *scene;

    for (p = LINK_LIST_HEAD(&serverPtr->scenes_list); p; p = LINK_LIST_NEXT(p, &serverPtr->scenes_list)) {
        scene = LINK_LIST_ITEM(p, struct ZbZclScenesTableEntryT, link);

        if (scene->group_id != group_id) {
            continue;
        }
        if (scene->scene_id != scene_id) {
            continue;
        }
        return scene;
    }
    return NULL;
}

static void
zcl_scenes_server_scene_extension_set_free_all(struct ZigBeeT *zb, struct ZbZclScenesTableEntryT *scene)
{
    struct LinkListT *p;
    struct ZbZclScenesExtFieldT *ext_field;

    while ((p = LINK_LIST_HEAD(&scene->extension_field_sets))) {
        ext_field = LINK_LIST_ITEM(p, struct ZbZclScenesExtFieldT, link);
        LINK_LIST_UNLINK(&ext_field->link);
        scene->extension_field_num--;
        ZbHeapFree(zb, ext_field);
    } /* while */
}

static bool
zcl_scenes_server_remove_scene(struct cluster_priv_t *serverPtr, uint16_t group_id, uint8_t scene_id)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    struct ZbZclScenesTableEntryT *scene;

    scene = zcl_scenes_server_find_scene(serverPtr, group_id, scene_id);
    if (!scene) {
        return false;
    }
    /* Remove this scene from the list */
    LINK_LIST_UNLINK(&scene->link);

    /* Free the extension list */
    zcl_scenes_server_scene_extension_set_free_all(clusterPtr->zb, scene);

    /* Free the scene */
    ZbHeapFree(clusterPtr->zb, scene);
    zcl_scenes_server_scene_count_decrement(clusterPtr);

    ZbZclAttrPersist(clusterPtr, ZCL_SCENES_ATTR_SCENES_TABLE);
    return true;
}

static unsigned int
zcl_scenes_server_remove_all_scenes_by_group(struct cluster_priv_t *serverPtr, uint16_t group_id)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    struct LinkListT *p, *next;
    struct ZbZclScenesTableEntryT *scene;
    unsigned int numDelete = 0;

    for (p = LINK_LIST_HEAD(&serverPtr->scenes_list); p; p = next) {
        next = LINK_LIST_NEXT(p, &serverPtr->scenes_list);
        scene = LINK_LIST_ITEM(p, struct ZbZclScenesTableEntryT, link);

        if (scene->group_id != group_id) {
            continue;
        }

        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Removing scene: groupId=0x%04x, sceneId=0x%02x",
            group_id, scene->scene_id);

        /* Unlink this scene */
        LINK_LIST_UNLINK(&scene->link);

        /* Free the extension field */
        zcl_scenes_server_scene_extension_set_free_all(clusterPtr->zb, scene);

        /* Free this scene */
        ZbHeapFree(clusterPtr->zb, scene);
        zcl_scenes_server_scene_count_decrement(clusterPtr);

        numDelete++;
    }
    if (numDelete) {
        ZbZclAttrPersist(clusterPtr, ZCL_SCENES_ATTR_SCENES_TABLE);
    }

    return numDelete;
}

static unsigned int
zcl_scenes_server_remove_all_scenes(struct cluster_priv_t *serverPtr)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    struct LinkListT *p;
    struct ZbZclScenesTableEntryT *scene;
    unsigned int numDelete = 0;

    while (true) {
        p = LINK_LIST_HEAD(&serverPtr->scenes_list);
        if (p == NULL) {
            break;
        }
        scene = LINK_LIST_ITEM(p, struct ZbZclScenesTableEntryT, link);
        /* Unlink this scene */
        LINK_LIST_UNLINK(&scene->link);
        /* Free the extension field */
        zcl_scenes_server_scene_extension_set_free_all(clusterPtr->zb, scene);
        /* Free this scene */
        ZbHeapFree(clusterPtr->zb, scene);
        zcl_scenes_server_scene_count_decrement(clusterPtr);
        numDelete++;
    }
    if (numDelete != 0U) {
        ZbZclAttrPersist(clusterPtr, ZCL_SCENES_ATTR_SCENES_TABLE);
    }
    return numDelete;
}

static uint8_t
zcl_scenes_server_copy_scene(struct cluster_priv_t *serverPtr, uint16_t groupIdFrom, uint8_t sceneIdFrom,
    uint16_t groupIdTo, uint8_t sceneIdTo, uint64_t srcExtAddr)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    struct ZbZclScenesTableEntryT *scene, *newScene;
    struct LinkListT *p;
    struct ZbZclScenesExtFieldT *ext_field, *new_ext_field;

    scene = zcl_scenes_server_find_scene(serverPtr, groupIdFrom, sceneIdFrom);
    if (scene == NULL) {
        return ZCL_STATUS_NOT_FOUND;
    }

    newScene = zcl_scenes_server_alloc_scene(clusterPtr->zb);
    if (newScene == NULL) {
        return ZCL_STATUS_INSUFFICIENT_SPACE;
    }

    newScene->group_id = groupIdTo;
    newScene->scene_id = sceneIdTo;
    (void)strcpy(newScene->scene_name, scene->scene_name);
    newScene->transition_time_sec = scene->transition_time_sec;
    newScene->transition_time_tenths = scene->transition_time_tenths;

    /* Traverse the Extension Field Sets */
    for (p = LINK_LIST_HEAD(&scene->extension_field_sets); p;
         p = LINK_LIST_NEXT(p, &scene->extension_field_sets)) {
        ext_field = LINK_LIST_ITEM(p, struct ZbZclScenesExtFieldT, link);

        new_ext_field = zcl_scenes_server_alloc_ext_field(clusterPtr->zb, ext_field->cluster_id, ext_field->field, ext_field->length);
        if (!new_ext_field) {
            goto FREE_FAILED_SCENE;
        }
        LINK_LIST_INSERT_TAIL(&newScene->extension_field_sets, &new_ext_field->link);
        newScene->extension_field_num++;
    }

    if (!zcl_scenes_server_add_scene(serverPtr, newScene, srcExtAddr)) {
        goto FREE_FAILED_SCENE;
    }

    return ZCL_STATUS_SUCCESS;

FREE_FAILED_SCENE:
    /* Free the partially allocated scene. See zcl_scenes_server_remove_scene. */
    zcl_scenes_server_scene_extension_set_free_all(clusterPtr->zb, newScene);
    ZbHeapFree(clusterPtr->zb, newScene);
    return ZCL_STATUS_INSUFFICIENT_SPACE;
}

static void
zcl_scenes_server_update_current_scene(struct cluster_priv_t *serverPtr, uint16_t groupId, uint8_t sceneId, bool sceneValid)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;

    ZbZclAttrIntegerWrite(clusterPtr, ZCL_SCENES_ATTR_CURRENT_SCENE, sceneId);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_SCENES_ATTR_CURRENT_GROUP, groupId);
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_SCENES_ATTR_SCENE_VALID, sceneValid);
}

static void
zcl_scenes_server_update_last_configured_by(struct cluster_priv_t *serverPtr, uint64_t srcExtAddr)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;

    if (srcExtAddr == 0) {
        srcExtAddr = ZCL_SCENES_LAST_CONFIG_UNKNOWN;
    }
    ZbZclAttrIntegerWrite(clusterPtr, ZCL_SCENES_ATTR_LAST_CONFIGURED_BY, srcExtAddr);
}

static void
zcl_scenes_server_handle_add(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr, bool isEnhanced)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    struct ZbZclScenesTableEntryT *newScene;
    struct ZbZclScenesExtFieldT *extField;
    uint8_t *asdu = dataIndPtr->asdu;
    unsigned int i;
    uint8_t name_length;
    uint8_t rspBuf[4];
    uint8_t rsp_cmd = isEnhanced ? ZCL_SCENES_COMMAND_ENH_ADD_SCENE : ZCL_SCENES_COMMAND_ADD_SCENE;

    /* Group(2) + Scene(1) + Transition(2) + NameString(>=1)  */
    if (dataIndPtr->asduLength < 6) {
        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    newScene = zcl_scenes_server_alloc_scene(clusterPtr->zb);
    if (!newScene) {
        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_INSUFFICIENT_SPACE);
        return;
    }

    i = 0;
    newScene->group_id = pletoh16(&asdu[i]);
    i += 2;
    newScene->scene_id = asdu[i++];
    if (isEnhanced) {
        uint16_t time_tenths;

        time_tenths = pletoh16(&asdu[i]);
        i += 2;
        newScene->transition_time_sec = time_tenths / 10;
        newScene->transition_time_tenths = time_tenths % 10;
    }
    else {
        newScene->transition_time_sec = pletoh16(&asdu[i]);
        i += 2;
        newScene->transition_time_tenths = 0;
    }

    name_length = asdu[i++];
    if ((name_length > ZCL_SCENES_NAME_MAX_LENGTH) || ((i + name_length) > dataIndPtr->asduLength)) {
        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        goto FREE_FAILED_SCENE;
    }
    (void)memcpy((uint8_t *)newScene->scene_name, &asdu[i], name_length);
    newScene->scene_name[name_length] = 0;
    i += name_length;

    /* Form the response */
    rspBuf[0] = ZCL_STATUS_SUCCESS;
    putle16(&rspBuf[1], newScene->group_id);
    rspBuf[3] = newScene->scene_id;

    if (newScene->group_id > ZCL_GROUPS_ID_MAX) {
        rspBuf[0] = ZCL_STATUS_INVALID_VALUE;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, rsp_cmd, rspBuf, sizeof(rspBuf), false);
        goto FREE_FAILED_SCENE;
    }

    /* Find the Group ID in the APS Groups Table */
    if ((newScene->group_id != 0x0000) && !ZbApsGroupIsMember(clusterPtr->zb, newScene->group_id, serverPtr->cluster.endpoint)) {
        /* Make sure we don't have any scenes on this group. */
        zcl_scenes_server_remove_all_scenes_by_group(serverPtr, newScene->group_id);
        /* Send INVALID_FIELD response */
        rspBuf[0] = ZCL_STATUS_INVALID_FIELD;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, rsp_cmd, rspBuf, sizeof(rspBuf), false);
        goto FREE_FAILED_SCENE;
    }

    /* Parse the extension field
     *
     * Note: "It is not mandatory for a field set to be included in the
     * command for every cluster on that endpoint that has a defined
     * field set. Extension field sets MAY be omitted, including the
     * case of no field sets at all." */
    while (i < dataIndPtr->asduLength) {
        uint16_t clusterId;
        uint8_t extLength;

        if ((i + 3) > dataIndPtr->asduLength) {
            rspBuf[0] = ZCL_STATUS_MALFORMED_COMMAND;
            break;
        }

        clusterId = pletoh16(&asdu[i]);
        i += 2;
        extLength = asdu[i++];
        if ((i + extLength) > dataIndPtr->asduLength) {
            rspBuf[0] = ZCL_STATUS_INVALID_FIELD;
            break;
        }

        if (newScene->extension_field_num >= ZCL_SCENES_EXT_FIELD_NUM_MAX) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, number of extension field entries exceeded!");
            rspBuf[0] = ZCL_STATUS_INSUFFICIENT_SPACE;
            break;
        }

        extField = zcl_scenes_server_alloc_ext_field(clusterPtr->zb, clusterId, &asdu[i], extLength);
        if (!extField) {
            rspBuf[0] = ZCL_STATUS_INSUFFICIENT_SPACE;
            break;
        }
        i += extField->length;

        /* Add extension set to scene */
        LINK_LIST_INSERT_TAIL(&newScene->extension_field_sets, &extField->link);
        newScene->extension_field_num++;
    } /* while */
    if (rspBuf[0]) {
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, rsp_cmd, rspBuf, sizeof(rspBuf), false);
        goto FREE_FAILED_SCENE;
    }

    if (!zcl_scenes_server_add_scene(serverPtr, newScene, dataIndPtr->src.extAddr)) {
        rspBuf[0] = ZCL_STATUS_INSUFFICIENT_SPACE;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, rsp_cmd, rspBuf, sizeof(rspBuf), false);
        goto FREE_FAILED_SCENE;
    }

    /* Send the SUCCESS response */
    ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, rsp_cmd, rspBuf, sizeof(rspBuf), false);
    return;

FREE_FAILED_SCENE:
    /* Free the partially allocated scene. See zcl_scenes_server_remove_scene. */
    zcl_scenes_server_scene_extension_set_free_all(clusterPtr->zb, newScene);
    ZbHeapFree(clusterPtr->zb, newScene);
}

static void
zcl_scenes_server_handle_view(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr, bool isEnhanced)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    uint16_t groupId;
    uint8_t sceneId;
    struct ZbZclScenesTableEntryT *scene;
    uint8_t *asdu = dataIndPtr->asdu;
    uint8_t rspBuf[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int rspLen, rspErrorLen;
    struct LinkListT *p;
    struct ZbZclScenesExtFieldT *ext_field;
    unsigned int sceneNameLen;
    uint8_t rsp_cmd = isEnhanced ? ZCL_SCENES_COMMAND_ENH_VIEW_SCENE : ZCL_SCENES_COMMAND_VIEW_SCENE;

    if (dataIndPtr->asduLength != (2 + 1)) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, invalid length");
        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    /* Parse the command payload */
    groupId = pletoh16(&asdu[0]);
    sceneId = asdu[2];

    /* Form the response */
    rspBuf[0] = ZCL_STATUS_SUCCESS;
    putle16(&rspBuf[1], groupId);
    rspBuf[3] = sceneId;
    rspErrorLen = rspLen = 4;

    if (groupId > ZCL_GROUPS_ID_MAX) {
        rspBuf[0] = ZCL_STATUS_INVALID_VALUE;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, rsp_cmd, rspBuf, rspErrorLen, false);
        return;
    }

    /* Find the Group ID in the APS Groups Table */
    if ((groupId != 0x0000) && !ZbApsGroupIsMember(clusterPtr->zb, groupId, serverPtr->cluster.endpoint)) {
        /* Make sure we don't have any scenes on this group. */
        zcl_scenes_server_remove_all_scenes_by_group(serverPtr, groupId);
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, not part of group");
        /* Send INVALID_FIELD response */
        rspBuf[0] = ZCL_STATUS_INVALID_FIELD;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, rsp_cmd, rspBuf, rspErrorLen, false);
        return;
    }

    scene = zcl_scenes_server_find_scene(serverPtr, groupId, sceneId);
    if (!scene) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, scene not found");
        rspBuf[0] = ZCL_STATUS_NOT_FOUND;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, rsp_cmd, rspBuf, rspErrorLen, false);
        return;
    }

    /* 2-octet transition time */
    if (isEnhanced) {
        uint16_t time_tenths;

        time_tenths = scene->transition_time_sec * 10;
        time_tenths += scene->transition_time_tenths;
        putle16(&rspBuf[rspLen], time_tenths);
        rspLen += 2;
    }
    else {
        putle16(&rspBuf[rspLen], scene->transition_time_sec);
        rspLen += 2;
    }

    /* Variable length scene name */
    sceneNameLen = strlen(scene->scene_name);
    if ((sceneNameLen >= 0xff) || (rspLen + sceneNameLen + 1) > sizeof(rspBuf)) {
        rspBuf[0] = ZCL_STATUS_INSUFFICIENT_SPACE;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, rsp_cmd, rspBuf, rspErrorLen, false);
        return;
    }
    rspBuf[rspLen++] = sceneNameLen;
    if (sceneNameLen) {
        (void)memcpy(&rspBuf[rspLen], scene->scene_name, sceneNameLen);
        rspLen += sceneNameLen;
    }

    /* Traverse the Extension Field Sets */
    for (p = LINK_LIST_HEAD(&scene->extension_field_sets); p;
         p = LINK_LIST_NEXT(p, &scene->extension_field_sets)) {
        ext_field = LINK_LIST_ITEM(p, struct ZbZclScenesExtFieldT, link);

        if ((rspLen + 2 + 1 + ext_field->length) > sizeof(rspBuf)) {
            rspBuf[0] = ZCL_STATUS_INSUFFICIENT_SPACE;
            ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, rsp_cmd, rspBuf, rspErrorLen, false);
            return;
        }
        /* Cluster ID */
        putle16(&rspBuf[rspLen], ext_field->cluster_id);
        rspLen += 2;
        /* Length */
        rspBuf[rspLen++] = ext_field->length;
        /* Extension Field Set */
        (void)memcpy(&rspBuf[rspLen], ext_field->field, ext_field->length);
        rspLen += ext_field->length;
    }

    ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, rsp_cmd, rspBuf, rspLen, false);
}

static void
zcl_scenes_server_handle_remove_scene(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    uint16_t groupId;
    uint8_t sceneId;
    uint8_t *asdu = dataIndPtr->asdu;
    uint8_t rspBuf[4];

    if (dataIndPtr->asduLength != (2 + 1)) {
        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    /* Parse the command payload */
    groupId = pletoh16(&asdu[0]);
    sceneId = asdu[2];

    /* Form the response */
    rspBuf[0] = ZCL_STATUS_SUCCESS;
    putle16(&rspBuf[1], groupId);
    rspBuf[3] = sceneId;

    if (groupId > ZCL_GROUPS_ID_MAX) {
        rspBuf[0] = ZCL_STATUS_INVALID_VALUE;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_REMOVE_SCENE, rspBuf,
            sizeof(rspBuf), false);
        return;
    }

    /* Find the Group ID in the APS Groups Table */
    if ((groupId != 0x0000) && !ZbApsGroupIsMember(clusterPtr->zb, groupId, serverPtr->cluster.endpoint)) {
        /* Make sure we don't have any scenes on this group. */
        zcl_scenes_server_remove_all_scenes_by_group(serverPtr, groupId);
        /* Send INVALID_FIELD response */
        rspBuf[0] = ZCL_STATUS_INVALID_FIELD;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_REMOVE_SCENE, rspBuf,
            sizeof(rspBuf), false);
        return;
    }

    if (!zcl_scenes_server_remove_scene(serverPtr, groupId, sceneId)) {
        rspBuf[0] = ZCL_STATUS_NOT_FOUND;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_REMOVE_SCENE, rspBuf,
            sizeof(rspBuf), false);
        return;
    }

    /* Update the attributes */
    zcl_scenes_server_scene_update_last_configured(serverPtr, groupId, sceneId, dataIndPtr->src.extAddr);

    /* Send the SUCCESS response */
    ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_REMOVE_SCENE, rspBuf,
        sizeof(rspBuf), false);
}

static void
zcl_scenes_server_handle_remove_all(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    uint16_t groupId;
    uint8_t *asdu = dataIndPtr->asdu;
    uint8_t rspBuf[3];

    if (dataIndPtr->asduLength != 2) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, invalid length");
        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    /* Parse the command payload */
    groupId = pletoh16(&asdu[0]);

    /* Form the response */
    rspBuf[0] = ZCL_STATUS_SUCCESS;
    putle16(&rspBuf[1], groupId);

    if (groupId > ZCL_GROUPS_ID_MAX) {
        rspBuf[0] = ZCL_STATUS_INVALID_VALUE;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_REMOVE_ALL_SCENES,
            rspBuf, sizeof(rspBuf), false);
        return;
    }

    /* Find the Group ID in the APS Groups Table */
    if ((groupId != 0x0000) && !ZbApsGroupIsMember(clusterPtr->zb, groupId, serverPtr->cluster.endpoint)) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, not member of group");
        /* Make sure we don't have any scenes on this group. */
        zcl_scenes_server_remove_all_scenes_by_group(serverPtr, groupId);
        /* Send INVALID_FIELD response */
        rspBuf[0] = ZCL_STATUS_INVALID_FIELD;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_REMOVE_ALL_SCENES,
            rspBuf, sizeof(rspBuf), false);
        return;
    }

    if (zcl_scenes_server_remove_all_scenes_by_group(serverPtr, groupId) == 0) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Warning, no scenes found, but returning SUCCESS");
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_REMOVE_ALL_SCENES,
            rspBuf, sizeof(rspBuf), false);
        return;
    }

    /* Update the attributes */
    zcl_scenes_server_update_current_scene(serverPtr, 0x0000, 0x00, false);
    zcl_scenes_server_update_last_configured_by(serverPtr, dataIndPtr->src.extAddr);

    /* Send the SUCCESS response */
    ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_REMOVE_ALL_SCENES,
        rspBuf, sizeof(rspBuf), false);
}

struct store_callback_t {
    struct cluster_priv_t *serverPtr;
    uint8_t status;
    uint8_t clusterCount;
    uint8_t numResponses;
    struct ZbZclScenesTableEntryT *scene;
    struct ZbApsdeDataIndT srcDataInd;
    struct ZbZclHeaderT srcZclHdr;
};

static void
zcl_scenes_server_store_callback(struct ZbZclCommandRspT *rspPtr, void *arg)
{
    struct store_callback_t *store_info = arg;
    struct ZbZclClusterT *clusterPtr = &store_info->serverPtr->cluster;
    struct ZbZclScenesExtFieldT *extField;
    uint16_t clusterId;
    uint8_t extLength;

    /* Make sure it's from our endpoint */
    if (rspPtr->src.endpoint != store_info->serverPtr->cluster.endpoint) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, response from wrong endpoint (%d)", rspPtr->src.endpoint);
        /* Don't increment numResponses. Assume this is a duplicate cluster on
         * a different endpoint. Only count the response from the cluster
         * on our endpoint. */
        return;
    }

    store_info->numResponses++;

    do {
        /* Check for a default response */
        if (rspPtr->hdr.cmdId == ZCL_COMMAND_DEFAULT_RESPONSE) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Ignoring Default Response status = 0x%02x", rspPtr->status);
#if 0
            store_info->status = rspPtr->status;
#endif
            break;
        }
        /* Check command ID */
        if (rspPtr->hdr.cmdId != ZCL_CMD_MANUF_INTERNAL_GET_SCENE_EXTDATA) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, wrong cmdId = 0x%02x", rspPtr->hdr.cmdId);
            store_info->status = ZCL_STATUS_INVALID_FIELD;
            break;
        }
        /* Check status */
        if (rspPtr->status != 0x00) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Dropping, cl = 0x%04x, status = 0x%02x", rspPtr->clusterId, rspPtr->status);
            store_info->status = rspPtr->status;
            break;
        }
        /* Check length */
        if (rspPtr->length < 3) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, response length = %d", rspPtr->length);
            store_info->status = ZCL_STATUS_INVALID_FIELD;
            break;
        }
        /* Parse extension field set [cluster_id(2) | length(1) | data(N)] */
        clusterId = pletoh16(&rspPtr->payload[0]);
        extLength = rspPtr->payload[2];
        if (extLength == 0) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, extension field length = 0");
            store_info->status = ZCL_STATUS_INVALID_FIELD;
            break;
        }
        if ((unsigned int)(3 + extLength) > rspPtr->length) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, extension field length (%d) exceeds input buffer length (%d)", extLength, rspPtr->length);
            store_info->status = ZCL_STATUS_MALFORMED_COMMAND;
            break;
        }

        if (store_info->scene->extension_field_num >= ZCL_SCENES_EXT_FIELD_NUM_MAX) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, number of extension field entries exceeded!");
            store_info->status = ZCL_STATUS_INSUFFICIENT_SPACE;
            break;
        }

        /* Allocate an extension field set */
        extField = zcl_scenes_server_alloc_ext_field(clusterPtr->zb, clusterId, &rspPtr->payload[3], extLength);
        if (!extField) {
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Error, memory exhausted, cannot allocate extension field entry");
            store_info->status = ZCL_STATUS_INSUFFICIENT_SPACE;
            break;
        }

        /* Add extension set to scene */
        LINK_LIST_INSERT_TAIL(&store_info->scene->extension_field_sets, &extField->link);
        store_info->scene->extension_field_num++;

        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Added scene data from cluster = 0x%04x, extLength = %d", clusterId, extLength);
    } while (false);

    if (store_info->numResponses == store_info->clusterCount) {
        uint8_t rspBuf[4];

        /* Form the response */
        rspBuf[0] = store_info->status;
        putle16(&rspBuf[1], store_info->scene->group_id);
        rspBuf[3] = store_info->scene->scene_id;

        /* Check for an error status */
        if (store_info->status) {
            /* Free the extension list */
            zcl_scenes_server_scene_extension_set_free_all(clusterPtr->zb, store_info->scene);
            /* Free the scene */
            ZbHeapFree(clusterPtr->zb, store_info->scene);
        }
        /* We don't use zcl_scenes_server_add_scene, because the attributes
         * are handled differently for a store v.s. an add. */
        else if (!zcl_scenes_server_scene_count_increment(clusterPtr)) {
            /* May have hit max number of scenes (serverPtr->max_scenes) */
            rspBuf[0] = ZCL_STATUS_INSUFFICIENT_SPACE;
            /* Free the extension list */
            zcl_scenes_server_scene_extension_set_free_all(clusterPtr->zb, store_info->scene);
            /* Free the scene */
            ZbHeapFree(clusterPtr->zb, store_info->scene);
        }
        else {
            /* Add this scene to the list */
            LINK_LIST_INSERT_TAIL(&store_info->serverPtr->scenes_list, &store_info->scene->link);

            /* After a successful Store Scene or Recall Scene command, the
             * SceneValid attribute is set to TRUE. */
            zcl_scenes_server_update_current_scene(store_info->serverPtr, store_info->scene->group_id, store_info->scene->scene_id, true);

            zcl_scenes_server_update_last_configured_by(store_info->serverPtr, store_info->srcDataInd.src.extAddr);

            ZbZclAttrPersist(clusterPtr, ZCL_SCENES_ATTR_SCENES_TABLE);
        }

        /* Send the response */
        ZbZclSendClusterStatusResponse(clusterPtr, &store_info->srcDataInd, &store_info->srcZclHdr, ZCL_SCENES_COMMAND_STORE_SCENE,
            rspBuf, sizeof(rspBuf), false);

        /* We're done with the temporary store_info buffer. */
        ZbHeapFree(clusterPtr->zb, store_info);
    }
}

static void
zcl_scenes_server_simple_desc_callback(struct ZbZdoSimpleDescRspT *simpleRsp, void *arg)
{
    struct store_callback_t *store_info = arg;
    struct ZbZclClusterT *clusterPtr = &store_info->serverPtr->cluster;
    struct ZbZclCommandReqT cmdReq;
    uint16_t clusterList[ZB_ZDO_CLUSTER_LIST_MAX_SZ];
    unsigned int i, numReqSent;
    uint8_t rspBuf[4];

    /* Form the response */
    rspBuf[0] = store_info->status;
    putle16(&rspBuf[1], store_info->scene->group_id);
    rspBuf[3] = store_info->scene->scene_id;

    if (simpleRsp->status != ZB_ZDP_STATUS_SUCCESS) {
        /* Shouldn't get here. */
        rspBuf[0] = ZCL_STATUS_FAILURE;
        ZbZclSendClusterStatusResponse(clusterPtr, &store_info->srcDataInd, &store_info->srcZclHdr,
            ZCL_SCENES_COMMAND_STORE_SCENE, rspBuf, sizeof(rspBuf), false);
        goto FREE_FAILED_SCENE;
    }

#if 0 /* This was always a hack. Instead, for scenes, assume we only care about the server clusters */
    store_info->clusterCount = ZbZdoSimpleDescGetClusterList(&simpleRsp->simpleDesc, clusterList, ZB_ZDO_CLUSTER_LIST_MAX_SZ);
#else
    store_info->clusterCount = simpleRsp->simpleDesc.inputClusterCount;
    (void)memcpy(clusterList, simpleRsp->simpleDesc.inputClusterList, sizeof(clusterList));
#endif

    /* ZCL Command Destination */
    (void)memset(&cmdReq, 0, sizeof(cmdReq));
    /* Loopback */
    cmdReq.dst.mode = ZB_APSDE_ADDRMODE_EXT;
    cmdReq.dst.extAddr = ZbExtendedAddress(clusterPtr->zb);
    cmdReq.dst.endpoint = store_info->serverPtr->cluster.endpoint;
    cmdReq.profileId = simpleRsp->simpleDesc.profileId;
    /* cmdReq.clusterId filled in below */
    cmdReq.srcEndpt = store_info->serverPtr->cluster.endpoint;
    cmdReq.txOptions = 0x00;
    cmdReq.discoverRoute = 0;
    cmdReq.radius = 0;

    /* ZCL Header */
    cmdReq.hdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    cmdReq.hdr.frameCtrl.manufacturer = 1;
    cmdReq.hdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
    cmdReq.hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmdReq.hdr.manufacturerCode = ZCL_MANUF_CODE_INTERNAL;
    cmdReq.hdr.seqNum = ZbZclGetNextSeqnum();
    cmdReq.hdr.cmdId = ZCL_CMD_MANUF_INTERNAL_GET_SCENE_EXTDATA;

    /* ZCL Payload */
    cmdReq.payload = NULL;
    cmdReq.length = 0;

    numReqSent = 0;
    for (i = 0; i < store_info->clusterCount; i++) {
        /* Skip the Scenes Cluster */
        if (clusterList[i] == ZCL_CLUSTER_SCENES) {
            store_info->numResponses++;
            continue;
        }

        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Getting scene data from: 0x%04x", clusterList[i]);

        cmdReq.clusterId = (enum ZbZclClusterIdT)clusterList[i];
        ZbZclCommandReq(clusterPtr->zb, &cmdReq, zcl_scenes_server_store_callback, store_info);
        numReqSent++;
    }

    if (numReqSent == 0) {
        /* There is no Spec text that describes how to handle the case where
         * there are no clusters on this endpoint that support scenes
         * (why would you have a Scenes cluster on such an endpoint?). */
        rspBuf[0] = ZCL_STATUS_INVALID_FIELD;
        ZbZclSendClusterStatusResponse(clusterPtr, &store_info->srcDataInd, &store_info->srcZclHdr, ZCL_SCENES_COMMAND_STORE_SCENE,
            rspBuf, sizeof(rspBuf), false);
        goto FREE_FAILED_SCENE;
    }

    /* Response is sent from zcl_scenes_server_store_callback */
    return;

FREE_FAILED_SCENE:
    /* Free the extension list */
    zcl_scenes_server_scene_extension_set_free_all(clusterPtr->zb, store_info->scene);
    /* Free the scene */
    ZbHeapFree(clusterPtr->zb, store_info->scene);
    /* Free the temporary struct */
    ZbHeapFree(clusterPtr->zb, store_info);
}

static void
zcl_scenes_server_handle_store(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr, struct ZbZclHeaderT *zclHdrPtr)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    uint16_t groupId;
    uint8_t sceneId;
    uint8_t *asdu = dataIndPtr->asdu;
    uint8_t rspBuf[4];
    struct ZbZdoSimpleDescReqT simpleReq;
    struct store_callback_t *store_info;
    struct ZbZclScenesTableEntryT *old_scene;

    if (dataIndPtr->asduLength != (2 + 1)) {
        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    /* Parse the command payload */
    groupId = pletoh16(&asdu[0]);
    sceneId = asdu[2];

    /* Form the response */
    rspBuf[0] = ZCL_STATUS_SUCCESS;
    putle16(&rspBuf[1], groupId);
    rspBuf[3] = sceneId;

    if (groupId > ZCL_GROUPS_ID_MAX) {
        rspBuf[0] = ZCL_STATUS_INVALID_VALUE;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_STORE_SCENE, rspBuf,
            sizeof(rspBuf), false);
        return;
    }

    /* Find the Group ID in the APS Groups Table */
    if ((groupId != 0x0000) && !ZbApsGroupIsMember(clusterPtr->zb, groupId, serverPtr->cluster.endpoint)) {
        /* Make sure we don't have any scenes on this group. */
        zcl_scenes_server_remove_all_scenes_by_group(serverPtr, groupId);
        /* If the Group ID field is not zero, and the device is not a
         * member of this group, the scene will not be added. */
        /* Send INVALID_FIELD response */
        rspBuf[0] = ZCL_STATUS_INVALID_FIELD;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_STORE_SCENE, rspBuf,
            sizeof(rspBuf), false);
        return;
    }

    /* Allocate the callback info */
    store_info = ZbHeapAlloc(clusterPtr->zb, sizeof(struct store_callback_t));
    if (store_info == NULL) {
        rspBuf[0] = ZCL_STATUS_INSUFFICIENT_SPACE;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_STORE_SCENE, rspBuf,
            sizeof(rspBuf), false);
        return;
    }
    (void)memset(store_info, 0, sizeof(struct store_callback_t));
    store_info->serverPtr = serverPtr;
    store_info->status = ZCL_STATUS_SUCCESS;
    (void)memcpy(&store_info->srcDataInd, dataIndPtr, sizeof(struct ZbApsdeDataIndT));
    store_info->srcDataInd.asdu = NULL;
    store_info->srcDataInd.asduLength = 0;
    (void)memcpy(&store_info->srcZclHdr, zclHdrPtr, sizeof(struct ZbZclHeaderT));

    /* Allocate a new Scene */
    store_info->scene = zcl_scenes_server_alloc_scene(clusterPtr->zb);
    if (store_info->scene == NULL) {
        rspBuf[0] = ZCL_STATUS_INSUFFICIENT_SPACE;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_STORE_SCENE, rspBuf,
            sizeof(rspBuf), false);
        ZbHeapFree(clusterPtr->zb, store_info);
        return;
    }
    store_info->scene->group_id = groupId;
    store_info->scene->scene_id = sceneId;

    /* Check if there's already a scene that matches the Group and Scene IDs. */
    old_scene = zcl_scenes_server_find_scene(serverPtr, groupId, sceneId);
    if (old_scene) {
        /* If an entry already exists with the same Scene ID and Group ID,
         * as a result of a previous Add Scene command, the extension
         * field sets are overwritten (i.e., completely replaced) with the
         * current values of the attributes that are extension fields on
         * clusters that are on the same endpoint, but the transition time
         * field and the scene name field are left unaltered. If no such
         * entry exists, the transition time field SHALL be set to 0, and
         * the scene name field SHALL be set to the null string. */
        (void)strcpy(store_info->scene->scene_name, old_scene->scene_name);
        store_info->scene->transition_time_sec = old_scene->transition_time_sec;
        store_info->scene->transition_time_tenths = old_scene->transition_time_tenths;

        /* Remove the old scene now that we're done with it. */
        zcl_scenes_server_remove_scene(serverPtr, groupId, sceneId);
    }

    /* Before a scene has been stored or recalled, this attribute (SceneValid)
     * is set to FALSE. */
    zcl_scenes_server_update_current_scene(serverPtr, 0x0000, 0x00, false);

    /* Send a simple descriptor to ourselves to get the cluster list on this endpoint. */
    (void)memset(&simpleReq, 0, sizeof(simpleReq));
    (void)ZbNwkGet(clusterPtr->zb, ZB_NWK_NIB_ID_NetworkAddress, &simpleReq.nwkAddrOfInterest, sizeof(simpleReq.nwkAddrOfInterest));
    simpleReq.dstNwkAddr = simpleReq.nwkAddrOfInterest;
    simpleReq.endpt = serverPtr->cluster.endpoint;
    if (ZbZdoSimpleDescReq(clusterPtr->zb, &simpleReq, zcl_scenes_server_simple_desc_callback, store_info) != ZB_ZDP_STATUS_SUCCESS) {
        struct ZbZdoSimpleDescRspT simpleRsp;

        (void)memset(&simpleRsp, 0, sizeof(simpleRsp));
        simpleRsp.status = ZB_ZDP_STATUS_INV_REQTYPE;
        zcl_scenes_server_simple_desc_callback(&simpleRsp, store_info);
        return;
    }

    /* Response is sent from zcl_scenes_server_simple_desc_callback or
     * zcl_scenes_server_store_callback */
}

static enum ZclStatusCodeT
zcl_scenes_server_handle_recall(struct cluster_priv_t *serverPtr,
    struct ZbApsdeDataIndT *dataIndPtr, struct ZbZclHeaderT *zclHdrPtr)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    uint16_t groupId;
    uint8_t sceneId;
    uint8_t *asdu = dataIndPtr->asdu;
    struct ZbZclScenesTableEntryT *scene;
    struct ZbZclCommandReqT cmdReq;
    struct LinkListT *p;
    struct ZbZclScenesExtFieldT *ext_field;
    uint8_t payload[SET_SCENE_EXTDATA_HEADER_LEN + ZCL_SCENES_EXT_FIELD_LENGTH_MAX];
    uint32_t transition_tenths = ZCL_SCENES_RECALL_TRANSITION_INVALID;
    unsigned int i = 0;

    if ((i + 3) > dataIndPtr->asduLength) {
        /* "This command does not result in a response command." */
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Warning, received malformed Recall Scene Command (length = %d)", dataIndPtr->asduLength);
        return ZCL_STATUS_MALFORMED_COMMAND;
    }
    /* Parse the command payload */
    groupId = pletoh16(&asdu[i]);
    i += 2;
    sceneId = asdu[i++];

    if ((i + 2) <= dataIndPtr->asduLength) {
        /* [optional] Transition time in tenths. ZCL_SCENES_RECALL_TRANSITION_INVALID
         * (0xffff) means invalid. */
        transition_tenths = pletoh16(&asdu[i]);
        i += 2;
    }

    if (groupId > ZCL_GROUPS_ID_MAX) {
        /* "This command does not result in a response command." */
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Warning, received invalid Recall Scene Command (group = 0x%04x > max)", groupId);
        return ZCL_STATUS_INVALID_VALUE;
    }

    /* Find the Group ID in the APS Groups Table */
    if ((groupId != 0x0000) && !ZbApsGroupIsMember(clusterPtr->zb, groupId, serverPtr->cluster.endpoint)) {
        /* Make sure we don't have any scenes on this group. */
        zcl_scenes_server_remove_all_scenes_by_group(serverPtr, groupId);
        /* "This command does not result in a response command." */
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Warning, received invalid Recall Scene Command (not part of group = 0x%04x)", groupId);
        return ZCL_STATUS_INVALID_FIELD;
    }

    scene = zcl_scenes_server_find_scene(serverPtr, groupId, sceneId);
    if (scene == NULL) {
        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Warning, no scene found for Recall Scene Command (group = 0x%04x, scene = 0x%02x)", groupId, sceneId);
        return ZCL_STATUS_NOT_FOUND;
    }

    /* ZCL Command Destination */
    (void)memset(&cmdReq, 0, sizeof(cmdReq));
    /* Loopback */
    cmdReq.dst.mode = ZB_APSDE_ADDRMODE_EXT;
    cmdReq.dst.extAddr = ZbExtendedAddress(clusterPtr->zb);
    cmdReq.dst.endpoint = serverPtr->cluster.endpoint;
    cmdReq.profileId = ZCL_PROFILE_WILDCARD;
    /* cmdReq.clusterId filled in below */
    cmdReq.srcEndpt = serverPtr->cluster.endpoint;
    cmdReq.txOptions = 0x00;
    cmdReq.discoverRoute = 0;
    cmdReq.radius = 0;

    /* ZCL Header */
    cmdReq.hdr.frameCtrl.frameType = ZCL_FRAMETYPE_PROFILE;
    cmdReq.hdr.frameCtrl.manufacturer = 1;
    /* Only server cluster's are supported by scenes.
     * This is a failing of the ZCL Scenes Cluster in the Spec. */
    cmdReq.hdr.frameCtrl.direction = ZCL_DIRECTION_TO_SERVER;
    cmdReq.hdr.frameCtrl.noDefaultResp = ZCL_NO_DEFAULT_RESPONSE_FALSE;
    cmdReq.hdr.manufacturerCode = ZCL_MANUF_CODE_INTERNAL;
    cmdReq.hdr.seqNum = ZbZclGetNextSeqnum();
    cmdReq.hdr.cmdId = ZCL_CMD_MANUF_INTERNAL_SET_SCENE_EXTDATA;

    /* ZCL Payload */
    cmdReq.payload = payload;
    cmdReq.length = 0;

    if (transition_tenths == ZCL_SCENES_RECALL_TRANSITION_INVALID) {
        transition_tenths = scene->transition_time_sec * 10;
        transition_tenths += scene->transition_time_tenths;
    }
    putle32(payload, transition_tenths);

    /* Traverse the Extension Field Sets */
    for (p = LINK_LIST_HEAD(&scene->extension_field_sets); p;
         p = LINK_LIST_NEXT(p, &scene->extension_field_sets)) {
        ext_field = LINK_LIST_ITEM(p, struct ZbZclScenesExtFieldT, link);

        /* Set the cluster ID */
        cmdReq.clusterId = (enum ZbZclClusterIdT)ext_field->cluster_id;

        /* Form the payload */
        if ((SET_SCENE_EXTDATA_HEADER_LEN + ext_field->length) > sizeof(payload)) {
            /* Should never get here */
            ZCL_LOG_PRINTF(clusterPtr->zb, __func__,
                "Error, scene data for 0x%04x exceeds max length", cmdReq.clusterId);
            continue;
        }
        payload[SET_SCENE_EXTDATA_OFFSET_EXT_LEN] = ext_field->length;
        (void)memcpy(&payload[SET_SCENE_EXTDATA_OFFSET_EXT_FIELD], ext_field->field, ext_field->length);

        cmdReq.length = SET_SCENE_EXTDATA_HEADER_LEN + ext_field->length;

        ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Setting scene data to: 0x%04x", cmdReq.clusterId);

        ZbZclCommandReq(clusterPtr->zb, &cmdReq, NULL, NULL);
    }

    /* Update the attributes */
    zcl_scenes_server_update_current_scene(serverPtr, groupId, sceneId, true);

    /* "This command does not result in a response command." */
    return ZCL_STATUS_SUCCESS;
}

static void
zcl_scenes_server_handle_get_membership(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    uint16_t groupId;
    uint8_t *asdu = dataIndPtr->asdu;
    uint8_t rspBuf[ZCL_PAYLOAD_UNFRAG_SAFE_SIZE];
    unsigned int rspLen;
    unsigned int sceneCountIdx, sceneCount;
    struct LinkListT *p;
    struct ZbZclScenesTableEntryT *scene;

    if (dataIndPtr->asduLength != 2) {
        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    /* Parse the command payload */
    groupId = pletoh16(&asdu[0]);

    /* Form the response */
    rspBuf[0] = ZCL_STATUS_SUCCESS;
    rspBuf[1] = 0xff; /* It is unknown if any further scenes MAY be added. */
    putle16(&rspBuf[2], groupId);
    rspLen = 4;

    /* Initialize Scene Count */
    sceneCount = 0;
    sceneCountIdx = rspLen;
    rspBuf[rspLen] = 0;

    if (groupId > ZCL_GROUPS_ID_MAX) {
        rspBuf[0] = ZCL_STATUS_INVALID_VALUE;
    }
    /* Find the Group ID in the APS Groups Table */
    else if ((groupId != 0x0000)
             && !ZbApsGroupIsMember(clusterPtr->zb, groupId, serverPtr->cluster.endpoint)) {
        /* Make sure we don't have any scenes on this group. */
        zcl_scenes_server_remove_all_scenes_by_group(serverPtr, groupId);
        /* Send INVALID_FIELD response */
        rspBuf[0] = ZCL_STATUS_INVALID_FIELD;
    }
    else {
        rspLen++;

        for (p = LINK_LIST_HEAD(&serverPtr->scenes_list); p; p = LINK_LIST_NEXT(p, &serverPtr->scenes_list)) {
            scene = LINK_LIST_ITEM(p, struct ZbZclScenesTableEntryT, link);

            if (scene->group_id != groupId) {
                continue;
            }

            if ((rspLen + 1) > sizeof(rspBuf)) {
                /* If the total number of scenes associated with this Group ID
                * will cause the maximum payload length of a ZigBee frame to
                * be exceeded, then the Scene list field shall contain only
                * as many scenes as will fit. */
                break;
            }

            rspBuf[rspLen++] = scene->scene_id;
            sceneCount++;
        }
    }

    /* ZCL 8 Section 3.7.2.4.8.2: "If the Get Scene Membership command was not received as a unicast,
     * the device SHALL only generate a Get Scene Membership Response command with the Status field
     * set to the evaluated status if an entry within the Scene Table corresponds to the Group ID" */
    if (ZbApsAddrIsBcast(&dataIndPtr->dst) && sceneCount == 0U) {
        return;
    }

    rspBuf[sceneCountIdx] = sceneCount;

    ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_GET_SCENE_MBRSHIP,
        rspBuf, rspLen, true);
}

static void
zcl_scenes_server_handle_copy(struct cluster_priv_t *serverPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr)
{
    struct ZbZclClusterT *clusterPtr = &serverPtr->cluster;
    uint8_t copyMode;
    uint16_t groupIdFrom, groupIdTo;
    uint8_t sceneIdFrom, sceneIdTo;
    uint8_t *asdu = dataIndPtr->asdu;
    uint8_t rspBuf[4];
    unsigned int i;

    if (dataIndPtr->asduLength != 7) {
        ZbZclSendDefaultResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_STATUS_MALFORMED_COMMAND);
        return;
    }

    /* Parse the command payload */
    i = 0;
    copyMode = asdu[i++];
    groupIdFrom = pletoh16(&asdu[i]);
    i += 2;
    sceneIdFrom = asdu[i++];
    groupIdTo = pletoh16(&asdu[i]);
    i += 2;
    sceneIdTo = asdu[i++];

    /* Form the response */
    rspBuf[0] = ZCL_STATUS_SUCCESS;
    putle16(&rspBuf[1], groupIdFrom);
    rspBuf[3] = sceneIdFrom;

    /* Check group range */
    if ((groupIdFrom > ZCL_GROUPS_ID_MAX) || (groupIdTo > ZCL_GROUPS_ID_MAX)) {
        rspBuf[0] = ZCL_STATUS_INVALID_VALUE;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_COPY_SCENE, rspBuf,
            sizeof(rspBuf), false);
        return;
    }
    /* Check if from == to */
    if ((groupIdFrom == groupIdTo) && ((copyMode & ZCL_SCENES_COPY_MODE_ALL) || (sceneIdFrom == sceneIdTo))) {
        rspBuf[0] = ZCL_STATUS_INVALID_FIELD;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_COPY_SCENE, rspBuf,
            sizeof(rspBuf), false);
        return;
    }

    /* Find the Group ID in the APS Groups Table */
    if ((groupIdFrom != 0x0000) && !ZbApsGroupIsMember(clusterPtr->zb, groupIdFrom, serverPtr->cluster.endpoint)) {
        /* Make sure we don't have any scenes on this group. */
        zcl_scenes_server_remove_all_scenes_by_group(serverPtr, groupIdFrom);
        /* Send INVALID_FIELD response */
        rspBuf[0] = ZCL_STATUS_INVALID_FIELD;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_COPY_SCENE, rspBuf,
            sizeof(rspBuf), false);
        return;
    }
    /* Find the Group ID in the APS Groups Table */
    if ((groupIdTo != 0x0000) && !ZbApsGroupIsMember(clusterPtr->zb, groupIdTo, serverPtr->cluster.endpoint)) {
        /* Make sure we don't have any scenes on this group. */
        zcl_scenes_server_remove_all_scenes_by_group(serverPtr, groupIdTo);
        /* Send INVALID_FIELD response */
        rspBuf[0] = ZCL_STATUS_INVALID_FIELD;
        ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_COPY_SCENE, rspBuf,
            sizeof(rspBuf), false);
        return;
    }

    if (copyMode & ZCL_SCENES_COPY_MODE_ALL) {
        struct LinkListT *p;
        struct ZbZclScenesTableEntryT *scene;

        for (p = LINK_LIST_HEAD(&serverPtr->scenes_list); p; p = LINK_LIST_NEXT(p, &serverPtr->scenes_list)) {
            scene = LINK_LIST_ITEM(p, struct ZbZclScenesTableEntryT, link);

            if (scene->group_id != groupIdFrom) {
                continue;
            }
            rspBuf[0] = zcl_scenes_server_copy_scene(serverPtr, groupIdFrom, scene->scene_id, groupIdTo,
                    scene->scene_id, dataIndPtr->src.extAddr);
            if (rspBuf[0]) {
                break;
            }
        }
    }
    else {
        rspBuf[0] = zcl_scenes_server_copy_scene(serverPtr, groupIdFrom, sceneIdFrom, groupIdTo, sceneIdTo, dataIndPtr->src.extAddr);
    }

    ZbZclSendClusterStatusResponse(clusterPtr, dataIndPtr, zclHdrPtr, ZCL_SCENES_COMMAND_COPY_SCENE, rspBuf,
        sizeof(rspBuf), false);
}
