/* Copyright [2009 - 2025] Exegin Technologies Limited. All rights reserved. */

#ifndef ZCL_ATTR_H
#define ZCL_ATTR_H

/* The internal allocated attribute struct */
struct ZbZclAttrListEntryT {
    struct LinkListT link;
    const struct ZbZclAttrT *info; /* Attribute info */
    uint8_t *valBuf; /* ZCL format (i.e. same as what is sent over-the-air) */
    unsigned int valSz; /* Allocation size of valBuf. */
    struct {
        uint16_t interval_secs_min; /* seconds */
        uint16_t interval_secs_max; /* seconds */
    } reporting;
};

void ZbZclAttrAddSorted(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrListEntryT *new_entry);
struct ZbZclAttrListEntryT * ZbZclAttrFind(struct ZbZclClusterT *clusterPtr, uint16_t attrId);

unsigned int ZbZclAttrDiscoverGetList(struct ZbZclClusterT *clusterPtr, uint16_t start_attr,
    uint8_t *max_num_attr, uint8_t *buf, unsigned int max_len);

enum ZclStatusCodeT ZbZclAttrCallbackExec(struct ZbZclClusterT *clusterPtr,
    struct ZbZclAttrListEntryT *attrPtr, struct ZbZclAttrCbInfoT *cb);

void ZbZclAttrFreeAttr(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrListEntryT *attrPtr);
void ZbZclAttrFreeList(struct ZbZclClusterT *cluster);

enum ZclStatusCodeT ZbZclAttrDefaultWrite(struct ZbZclClusterT *clusterPtr,
    struct ZbZclAttrListEntryT *attrPtr, const uint8_t *data, ZclWriteModeT mode);

void ZbZclAttrPostWrite(struct ZbZclClusterT *clusterPtr, struct ZbZclAttrListEntryT *attrPtr);

void ZbZclHandleConfigReport(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind);
void ZbZclHandleReadReport(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind);
void ZbZclHandleReportAttr(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind);
void ZbZclAttrHandleDiscover(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind);
void ZbZclHandleGetSceneData(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind);
void ZbZclHandleSetSceneData(struct ZbZclClusterT *clusterPtr, struct ZbZclHeaderT *zclHdrPtr, struct ZbApsdeDataIndT *ind);

/* Misc. */
bool ZbZclClusterCheckMinSecurity(struct ZbZclClusterT *clusterPtr, struct ZbApsdeDataIndT *dataIndPtr,
    struct ZbZclHeaderT *zclHdrPtr);
bool ZbZclDeviceLogCheckAllow(struct ZigBeeT *zb, struct ZbApsdeDataIndT *dataIndPtr, struct ZbZclHeaderT *zclHdrPtr);

enum ZclStatusCodeT zcl_cluster_bind(struct ZbZclClusterT *cluster,
    struct ZbApsFilterT *filter, uint8_t endpoint,
    uint16_t profileId, enum ZbZclDirectionT direction);

int zcl_cluster_data_ind(struct ZbApsdeDataIndT *dataIndPtr, void *arg);
int zcl_cluster_alarm_data_ind(struct ZbApsdeDataIndT *data_ind, void *arg);

/*---------------------------------------------------------------
 * Reporting
 *---------------------------------------------------------------
 */
void ZbZclReportCleanup(struct ZbZclClusterT *cluster);
void zcl_attr_reporting_check(struct ZbZclClusterT *clusterPtr,
    uint16_t attributeId, enum ZbZclReportDirectionT direction);
enum ZclStatusCodeT zcl_reporting_create_default_reports(struct ZbZclClusterT *clusterPtr);
bool zcl_cluster_attr_report_delete(struct ZbZclClusterT *clusterPtr, uint16_t attributeId,
    enum ZbZclReportDirectionT direction);
enum zb_msg_filter_rc zcl_reporting_stack_event(struct ZigBeeT *zb, uint32_t id, void *msg, void *cbarg);
void zcl_cluster_reports_timer(struct ZigBeeT *zb, void *arg);

/*---------------------------------------------------------------
 * Range Checking
 *---------------------------------------------------------------
 */
bool ZbZclAttrIntegerRangeCheck(long long value, uint8_t attr_type, long long attr_min, long long attr_max);

#endif
