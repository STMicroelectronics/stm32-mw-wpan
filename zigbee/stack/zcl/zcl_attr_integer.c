/* Copyright [2009 - 2022] Exegin Technologies Limited. All rights reserved. */

#include "zigbee.h"
#include "zcl/zcl.h"
#include "zcl_attr.h"

#define ZCL_UNSIGNED_8BIT_MAX                       0xff
#define ZCL_UNSIGNED_16BIT_MAX                      0xffff
#define ZCL_UNSIGNED_24BIT_MAX                      0xffffff
#define ZCL_UNSIGNED_32BIT_MAX                      0xffffffff
#define ZCL_UNSIGNED_40BIT_MAX                      0xffffffffff
#define ZCL_UNSIGNED_48BIT_MAX                      0xffffffffffff
#define ZCL_UNSIGNED_56BIT_MAX                      0xffffffffffffff
#define ZCL_UNSIGNED_64BIT_MAX                      0xffffffffffffffff

#define ZCL_SIGNED_8BIT_MIN                         (-128) /* ZCL_INVALID_SIGNED_8BIT */
#define ZCL_SIGNED_8BIT_MAX                         127
#define ZCL_SIGNED_16BIT_MIN                        (-32768) /* ZCL_INVALID_SIGNED_16BIT */
#define ZCL_SIGNED_16BIT_MAX                        32767
#define ZCL_SIGNED_24BIT_MIN                        (-8388608) /* ZCL_INVALID_SIGNED_24BIT */
#define ZCL_SIGNED_24BIT_MAX                        8388607
#define ZCL_SIGNED_32BIT_MIN                        (-2147483648LL) /* ZCL_INVALID_SIGNED_32BIT */
#define ZCL_SIGNED_32BIT_MAX                        2147483647LL
#define ZCL_SIGNED_40BIT_MIN                        (-549755813888LL) /* ZCL_INVALID_SIGNED_40BIT */
#define ZCL_SIGNED_40BIT_MAX                        549755813887LL
#define ZCL_SIGNED_48BIT_MIN                        (-140737488355328LL) /* ZCL_INVALID_SIGNED_48BIT */
#define ZCL_SIGNED_48BIT_MAX                        140737488355327LL
#define ZCL_SIGNED_56BIT_MIN                        (-36028797018963968LL) /* ZCL_INVALID_SIGNED_56BIT */
#define ZCL_SIGNED_56BIT_MAX                        36028797018963967LL
#define ZCL_SIGNED_64BIT_MIN                        (-9223372036854775808LL) /* ZCL_INVALID_SIGNED_64BIT */
#define ZCL_SIGNED_64BIT_MAX                        9223372036854775807LL

/* Helper function to append integers of unusual sizes (ie:
 * that 48-bit integer that the SE profile is so fond of). */
int
ZbZclAppendInteger(unsigned long long value, enum ZclDataTypeT dataType, uint8_t *data, unsigned int len)
{
    unsigned int i = 0;
    int rc = 0;

    switch (dataType) {
        case ZCL_DATATYPE_BOOLEAN:
            /* Handle bools separately to ensure that the value is either TRUE or FALSE. */
            if (len == 0U) {
                return -1;
            }
            *data = (uint8_t)(value != 0U);
            return 1;

        /* 64-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_64BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_64BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_64BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_64BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_EUI64:
            if (len <= i) {
                return -1;
            }
            data[i++] = (uint8_t)value & 0xffU;
            value >>= 8;
        /*lint -fallthrough */

        /* 56-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_56BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_56BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_56BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_56BIT:
            if (len <= i) {
                return -1;
            }
            data[i++] = (uint8_t)value;
            value >>= 8;
        /*lint -fallthrough */

        /* 48-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_48BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_48BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_48BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_48BIT:
            if (len <= i) {
                return -1;
            }
            data[i++] = (uint8_t)value;
            value >>= 8;
        /*lint -fallthrough */

        /* 40-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_40BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_40BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_40BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_40BIT:
            if (len <= i) {
                return -1;
            }
            data[i++] = (uint8_t)value;
            value >>= 8;
        /*lint -fallthrough */

        /* 32-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_32BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_32BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_32BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_32BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_TIME_UTC:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BACNET_OID:
            if (len <= i) {
                return -1;
            }
            data[i++] = (uint8_t)value;
            value >>= 8;
        /*lint -fallthrough */

        /* 24-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_24BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_24BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_24BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_24BIT:
            if (len <= i) {
                return -1;
            }
            data[i++] = (uint8_t)value;
            value >>= 8;
        /*lint -fallthrough */

        /* 16-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_16BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_16BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_16BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_16BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_ENUMERATION_16BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_CLUSTER_ID:
        /*lint -fallthrough */
        case ZCL_DATATYPE_ATTRIBUTE_ID:
            if (len <= i) {
                return -1;
            }
            data[i++] = (uint8_t)value;
            value >>= 8;
        /*lint -fallthrough */

        /* 8-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_8BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_8BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_8BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_8BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_ENUMERATION_8BIT:
            if (len <= i) {
                return -1;
            }
            data[i++] = (uint8_t)value;
            return (int)i;

        /* Not Integer Types. */
        case ZCL_DATATYPE_NULL:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNKNOWN:
        /*lint -fallthrough */
        case ZCL_DATATYPE_FLOATING_SEMI:
        /*lint -fallthrough */
        case ZCL_DATATYPE_FLOATING_SINGLE:
        /*lint -fallthrough */
        case ZCL_DATATYPE_TIME_OF_DAY:
        /*lint -fallthrough */
        case ZCL_DATATYPE_DATE:
        /*lint -fallthrough */
        case ZCL_DATATYPE_FLOATING_DOUBLE:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SECURITY_KEY128:
        /*lint -fallthrough */
        case ZCL_DATATYPE_STRING_OCTET:
        /*lint -fallthrough */
        case ZCL_DATATYPE_STRING_CHARACTER:
        /*lint -fallthrough */
        case ZCL_DATATYPE_STRING_LONG_OCTET:
        /*lint -fallthrough */
        case ZCL_DATATYPE_STRING_LONG_CHARACTER:
        /*lint -fallthrough */
        case ZCL_DATATYPE_ARRAY:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SET:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BAG:
        /*lint -fallthrough */
        case ZCL_DATATYPE_STRUCT:
        /*lint -fallthrough */
        default:
            rc = -1;
            break;
    }
    return rc;
}

long long
ZbZclParseInteger(enum ZclDataTypeT dataType, const uint8_t *data, enum ZclStatusCodeT *statusPtr)
{
    unsigned int i = 0;
    unsigned long long value = 0;
    long long rc = 0;

    if (!ZbZclAttrIsInteger(dataType)) {
        *statusPtr = ZCL_STATUS_INVALID_DATA_TYPE;
        return 0;
    }

    *statusPtr = ZCL_STATUS_SUCCESS;

    /*lint -save -e9090 "switch with fallthrough [MISRA Rule 16.3 (REQUIRED)]" */
    switch (dataType) {
        /* 64-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_64BIT:
        case ZCL_DATATYPE_BITMAP_64BIT:
        case ZCL_DATATYPE_UNSIGNED_64BIT:
        case ZCL_DATATYPE_EUI64:
            value |= (unsigned long long)data[i];
            i++;
        /*lint -fallthrough */

        /* 56-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_56BIT:
        case ZCL_DATATYPE_BITMAP_56BIT:
        case ZCL_DATATYPE_UNSIGNED_56BIT:
            value |= (unsigned long long)(data[i]) << (8U * i);
            i++;
        /*lint -fallthrough */

        /* 48-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_48BIT:
        case ZCL_DATATYPE_BITMAP_48BIT:
        case ZCL_DATATYPE_UNSIGNED_48BIT:
            value |= (unsigned long long)(data[i]) << (8U * i);
            i++;
        /*lint -fallthrough */

        /* 40-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_40BIT:
        case ZCL_DATATYPE_BITMAP_40BIT:
        case ZCL_DATATYPE_UNSIGNED_40BIT:
            value |= (unsigned long long)(data[i]) << (8U * i);
            i++;
        /*lint -fallthrough */

        /* 32-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_32BIT:
        case ZCL_DATATYPE_BITMAP_32BIT:
        case ZCL_DATATYPE_UNSIGNED_32BIT:
        case ZCL_DATATYPE_TIME_UTC:
        case ZCL_DATATYPE_BACNET_OID:
            value |= (unsigned long long)(data[i]) << (8U * i);
            i++;
        /*lint -fallthrough */

        /* 24-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_24BIT:
        case ZCL_DATATYPE_BITMAP_24BIT:
        case ZCL_DATATYPE_UNSIGNED_24BIT:
            value |= (unsigned long long)(data[i]) << (8U * i);
            i++;
        /*lint -fallthrough */

        /* 16-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_16BIT:
        case ZCL_DATATYPE_BITMAP_16BIT:
        case ZCL_DATATYPE_UNSIGNED_16BIT:
        case ZCL_DATATYPE_ENUMERATION_16BIT:
        case ZCL_DATATYPE_CLUSTER_ID:
        case ZCL_DATATYPE_ATTRIBUTE_ID:
            value |= (unsigned long long)(data[i]) << (8U * i);
            i++;
        /*lint -fallthrough */

        /* 8-bit Integer Types. */
        case ZCL_DATATYPE_GENERAL_8BIT:
        case ZCL_DATATYPE_BOOLEAN:
        case ZCL_DATATYPE_BITMAP_8BIT:
        case ZCL_DATATYPE_UNSIGNED_8BIT:
        case ZCL_DATATYPE_ENUMERATION_8BIT:
            value |= (unsigned long long)(data[i]) << (8U * i);
            return (long long)value;

        /* Signed values. */
        case ZCL_DATATYPE_SIGNED_64BIT:
            value |= (unsigned long long)data[i];
            i++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_56BIT:
            value |= (unsigned long long)(data[i]) << (8U * i);
            i++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_48BIT:
            value |= (unsigned long long)(data[i]) << (8U * i);
            i++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_40BIT:
            value |= (unsigned long long)(data[i]) << (8U * i);
            i++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_32BIT:
            value |= (unsigned long long)(data[i]) << (8U * i);
            i++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_24BIT:
            value |= (unsigned long long)(data[i]) << (8U * i);
            i++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_16BIT:
            value |= (unsigned long long)(data[i]) << (8U * i);
            i++;
        /*lint -fallthrough */

        case ZCL_DATATYPE_SIGNED_8BIT:
            value |= (unsigned long long)(data[i]) << (8U * i);
            /* Perform sign extension. */
            if (((data[i++] & 0x80U) != 0U) && (i < sizeof(long long))) {
                value |= (((unsigned long long)0x1U << ((sizeof(long long) - i) * 8U)) - 1U) << (8U * i);
            }
            return (long long)value;

        default:
            /* Shouldn't get here */
            *statusPtr = ZCL_STATUS_INVALID_DATA_TYPE;
            rc = 0;
            break;
            /*lint -restore */
    }
    return rc;
}

bool
ZbZclAttrIsInteger(enum ZclDataTypeT dataType)
{
    bool returnVal = false;

    switch (dataType) {
        case ZCL_DATATYPE_GENERAL_8BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_GENERAL_16BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_GENERAL_24BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_GENERAL_32BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_GENERAL_40BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_GENERAL_48BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_GENERAL_56BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_GENERAL_64BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BOOLEAN:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_8BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_16BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_24BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_32BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_40BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_48BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_56BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BITMAP_64BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_8BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_16BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_24BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_32BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_40BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_48BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_56BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_64BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_8BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_16BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_24BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_32BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_40BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_48BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_56BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SIGNED_64BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_ENUMERATION_8BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_ENUMERATION_16BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_TIME_UTC:
        /*lint -fallthrough */
        case ZCL_DATATYPE_CLUSTER_ID:
        /*lint -fallthrough */
        case ZCL_DATATYPE_ATTRIBUTE_ID:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BACNET_OID:
        /*lint -fallthrough */
        case ZCL_DATATYPE_EUI64:
            returnVal = true;
            break;

        /* Not Integer Types. */
        case ZCL_DATATYPE_NULL:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNKNOWN:
        /*lint -fallthrough */
        case ZCL_DATATYPE_FLOATING_SEMI:
        /*lint -fallthrough */
        case ZCL_DATATYPE_FLOATING_SINGLE:
        /*lint -fallthrough */
        case ZCL_DATATYPE_TIME_OF_DAY:
        /*lint -fallthrough */
        case ZCL_DATATYPE_DATE:
        /*lint -fallthrough */
        case ZCL_DATATYPE_FLOATING_DOUBLE:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SECURITY_KEY128:
        /*lint -fallthrough */
        case ZCL_DATATYPE_STRING_OCTET:
        /*lint -fallthrough */
        case ZCL_DATATYPE_STRING_CHARACTER:
        /*lint -fallthrough */
        case ZCL_DATATYPE_STRING_LONG_OCTET:
        /*lint -fallthrough */
        case ZCL_DATATYPE_STRING_LONG_CHARACTER:
        /*lint -fallthrough */
        case ZCL_DATATYPE_ARRAY:
        /*lint -fallthrough */
        case ZCL_DATATYPE_SET:
        /*lint -fallthrough */
        case ZCL_DATATYPE_BAG:
        /*lint -fallthrough */
        case ZCL_DATATYPE_STRUCT:
        /*lint -fallthrough */
        default:
            returnVal = false;
            break;
    }
    return returnVal;
}

bool
ZbZclAttrIntegerRangeCheck(long long value, uint8_t attr_type, long long attr_min, long long attr_max)
{
    /* Return true if input data is a non-value */
    switch (attr_type) {
        case ZCL_DATATYPE_BOOLEAN:
            if (value == ZCL_INVALID_BOOLEAN) {
                return true;
            }
            /* The value is only either 0 or 1 for a boolean data type */
            if ((value > 1U)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_BITMAP_8BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_8BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_ENUMERATION_8BIT:
            if (value == ZCL_INVALID_UNSIGNED_8BIT) {
                return true;
            }
            if ((value < 0) || (value > ZCL_UNSIGNED_8BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_BITMAP_16BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_16BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_ENUMERATION_16BIT:
            if (value == ZCL_INVALID_UNSIGNED_16BIT) {
                return true;
            }
            if ((value < 0) || (value > ZCL_UNSIGNED_16BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_BITMAP_24BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_24BIT:
            if (value == ZCL_INVALID_UNSIGNED_24BIT) {
                return true;
            }
            if ((value < 0) || (value > ZCL_UNSIGNED_24BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_BITMAP_32BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_32BIT:
            if (value == ZCL_INVALID_UNSIGNED_32BIT) {
                return true;
            }
            if ((value < 0) || (value > ZCL_UNSIGNED_32BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_BITMAP_40BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_40BIT:
            if (value == ZCL_INVALID_UNSIGNED_40BIT) {
                return true;
            }
            if ((value < 0) || (value > ZCL_UNSIGNED_40BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_BITMAP_48BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_48BIT:
            if (value == ZCL_INVALID_UNSIGNED_48BIT) {
                return true;
            }
            if ((value < 0) || (value > ZCL_UNSIGNED_48BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_BITMAP_56BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_56BIT:
            if (value == ZCL_INVALID_UNSIGNED_56BIT) {
                return true;
            }
            if ((value < 0) || (value > ZCL_UNSIGNED_56BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_BITMAP_64BIT:
        /*lint -fallthrough */
        case ZCL_DATATYPE_UNSIGNED_64BIT:
            if ((unsigned long long)value == ZCL_INVALID_UNSIGNED_64BIT) {
                return true;
            }
            break;

        case ZCL_DATATYPE_SIGNED_8BIT:
            if (value == (int8_t)ZCL_INVALID_SIGNED_8BIT) {
                return true;
            }
            if ((value < ZCL_SIGNED_8BIT_MIN) || (value > ZCL_SIGNED_8BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_SIGNED_16BIT:
            if (value == (int16_t)ZCL_INVALID_SIGNED_16BIT) {
                return true;
            }
            if ((value < ZCL_SIGNED_16BIT_MIN) || (value > ZCL_SIGNED_16BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_SIGNED_24BIT:
            if (value == (int32_t)ZCL_INVALID_SIGNED_24BIT) {
                return true;
            }
            if ((value < ZCL_SIGNED_24BIT_MIN) || (value > ZCL_SIGNED_24BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_SIGNED_32BIT:
            if (value == (int32_t)ZCL_INVALID_SIGNED_32BIT) {
                return true;
            }
            if ((value < ZCL_SIGNED_32BIT_MIN) || (value > ZCL_SIGNED_32BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_SIGNED_40BIT:
            if (value == (int64_t)ZCL_INVALID_SIGNED_40BIT) {
                return true;
            }
            if ((value < ZCL_SIGNED_40BIT_MIN) || (value > ZCL_SIGNED_40BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_SIGNED_48BIT:
            if (value == (int64_t)ZCL_INVALID_SIGNED_48BIT) {
                return true;
            }
            if ((value < ZCL_SIGNED_48BIT_MIN) || (value > ZCL_SIGNED_48BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_SIGNED_56BIT:
            if (value == (int64_t)ZCL_INVALID_SIGNED_56BIT) {
                return true;
            }
            if ((value < ZCL_SIGNED_56BIT_MIN) || (value > ZCL_SIGNED_56BIT_MAX)) {
                return false;
            }
            break;

        case ZCL_DATATYPE_SIGNED_64BIT:
            if (value == (int64_t)ZCL_INVALID_SIGNED_64BIT) {
                return true;
            }
            /* Further type checking unnecessary, since input type is 'long long' */
            break;

        default:
            /* ? return false ? */
            break;
    }

    if ((attr_min == 0) && (attr_max == 0)) {
        return true;
    }
    /* If the cluster has defined a smaller range of values, check them now. */
    return ((value >= attr_min) && (value <= attr_max));
}

/* Wrapper to ZbZclAttrRead to read integer values */
long long
ZbZclAttrIntegerRead(struct ZbZclClusterT *clusterPtr, uint16_t attributeId,
    enum ZclDataTypeT *typePtr, enum ZclStatusCodeT *statusPtr)
{
    long long val;
    uint8_t buf[8];
    enum ZclStatusCodeT status;
    enum ZclDataTypeT attr_type = ZCL_DATATYPE_NULL;

    (void)memset(buf, 0, sizeof(buf));
    status = ZbZclAttrRead(clusterPtr, attributeId, &attr_type, buf, sizeof(buf), false);
    if (statusPtr != NULL) {
        *statusPtr = status;
    }
    if (status != ZCL_STATUS_SUCCESS) {
        return 0;
    }

    val = ZbZclParseInteger(attr_type, buf, &status);
    if (statusPtr != NULL) {
        *statusPtr = status;
    }
    if (status != ZCL_STATUS_SUCCESS) {
        return 0;
    }

    if (typePtr != NULL) {
        *typePtr = attr_type;
    }
    return val;
}

/* Wrapper to ZbZclAttrWrite to write integer values */
enum ZclStatusCodeT
ZbZclAttrIntegerWrite(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, long long value)
{
    enum ZclStatusCodeT status;
    uint8_t attr_data[8];
    long long current;
    enum ZclDataTypeT attr_type;

    if (clusterPtr == NULL) {
        return ZCL_STATUS_INVALID_VALUE;
    }
    current = ZbZclAttrIntegerRead(clusterPtr, attributeId, &attr_type, &status);
    if (status != ZCL_STATUS_SUCCESS) {
        return status;
    }
    if (current == value) {
        return ZCL_STATUS_SUCCESS;
    }

    /* ZCL_LOG_PRINTF(clusterPtr->zb, __func__, "Setting cl = 0x%04x, attr = 0x%04x = %lld",
        clusterPtr->clusterId, attributeId, value); */

    /* Integer attributes are stored little-endian (same format as over-the-air messages). */
    if (!ZbZclAttrIntegerRangeCheck(value, attr_type, 0, 0)) {
        return ZCL_STATUS_INVALID_VALUE;
    }

    putle64(attr_data, (uint64_t)value);
    status = ZbZclAttrWrite(clusterPtr, NULL, attributeId, attr_data, sizeof(attr_data), ZCL_ATTR_WRITE_FLAG_FORCE);
    if (status != ZCL_STATUS_SUCCESS) {
        return status;
    }
    return ZCL_STATUS_SUCCESS;
}

enum ZclStatusCodeT
ZbZclAttrIntegerIncrement(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, long long value)
{
    enum ZclDataTypeT attrType;
    unsigned int typeLen;
    enum ZclStatusCodeT status;
    long long newval;
    unsigned long long uintnewval;
    bool unsupportedAttribute = false;

    newval = ZbZclAttrIntegerRead(clusterPtr, attributeId, &attrType, &status);
    if (status != ZCL_STATUS_SUCCESS) {
        return status;
    }
    newval += value;
    uintnewval = (unsigned long long)newval;

    /* All integers use fixed-length attribute types. Get the length. */
    typeLen = ZbZclAttrTypeLength(attrType);
    switch (typeLen) {
        case 8:
            break;

        case 4:
            uintnewval = ((unsigned long long)newval & 0xffffffffU);
            break;

        case 2:
            uintnewval = ((unsigned long long)newval & 0xffffU);
            break;

        case 1:
            uintnewval = ((unsigned long long)newval & 0xffU);
            break;

        default:
            unsupportedAttribute = true;
            break;
    }

    if (unsupportedAttribute) {
        return ZCL_STATUS_UNSUPP_ATTRIBUTE;
    }

    newval = (long long)uintnewval;
    (void)ZbZclAttrIntegerWrite(clusterPtr, attributeId, newval);

    return ZCL_STATUS_SUCCESS;

}

/* Wrapper to ZbZclAttrRead to read integer values */
uint64_t
ZbZclAttrEuiRead(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, enum ZclStatusCodeT *statusPtr)
{
    uint64_t eui;
    uint8_t buf[8];
    enum ZclStatusCodeT status;

    (void)memset(buf, 0, sizeof(buf));
    status = ZbZclAttrRead(clusterPtr, attributeId, NULL, buf, sizeof(buf), false);
    if (statusPtr != NULL) {
        *statusPtr = status;
    }
    if (status != ZCL_STATUS_SUCCESS) {
        return 0;
    }

    eui = pletoh64(buf);
    return eui;
}

/* Wrapper to ZbZclAttrWrite to write integer values */
enum ZclStatusCodeT
ZbZclAttrEuiWrite(struct ZbZclClusterT *clusterPtr, uint16_t attributeId, uint64_t eui)
{
    enum ZclStatusCodeT status;
    uint8_t buf[8];
    uint64_t current;

    if (clusterPtr == NULL) {
        return ZCL_STATUS_INVALID_VALUE;
    }
    current = ZbZclAttrEuiRead(clusterPtr, attributeId, &status);
    if (status != ZCL_STATUS_SUCCESS) {
        return status;
    }
    if (current == eui) {
        return ZCL_STATUS_SUCCESS;
    }

    /* Integer attributes are stored little-endian (same format as
     * over-the-air messages). */
    putle64(buf, eui);
    status = ZbZclAttrWrite(clusterPtr, NULL, attributeId, buf, sizeof(buf), ZCL_ATTR_WRITE_FLAG_FORCE);
    if (status != ZCL_STATUS_SUCCESS) {
        return status;
    }
    return ZCL_STATUS_SUCCESS;
}
