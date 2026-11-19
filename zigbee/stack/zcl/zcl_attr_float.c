/* Copyright [2009 - 2021] Exegin Technologies Limited. All rights reserved. */

/*-------------------------------------------------
 *  DESCRIPTION
 *      Implements ZCL helper functions.
 *-------------------------------------------------
 */

#include "zigbee.h"
#include "zcl/zcl.h"

#if defined(WITH_MATH_LDEXP) || defined(WITH_MATH_FREXP)
# include <math.h>
#endif

#ifdef __ICCARM__ /* IAR */
#pragma diag_suppress=Pe222 /* Floating point stuff */
#endif

/*lint -efunc(414, ZbZclFloatFrexp) [ possible division by 0 <Rule 1.3, REQUIRED> ] */
/*lint -e54 -e414 [ ZCL_FLOAT_NAN/ZCL_FLOAT_INFINITY uses div 0 <Rule 1.3, REQUIRED> ] */

static double ZbZclFloatLdexp(double x, int exponent);
static double ZbZclFloatFrexp(double x, int *exponent, int inf_exp, int denorm_exp);

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      ZbZclAppendFloat
 *  DESCRIPTION
 *      Helper function to append floating-point values.
 *  PARAMETERS
 *      value           ; double-precision floating point value.
 *      dataType        ; ZCL Attribute data type.
 *      data            ; Output buffer.
 *      len             ; Buffer size.
 *  RETURNS
 *      int             ; Length of data written, or <0 on error.
 *---------------------------------------------------------------
 */
int
ZbZclAppendFloat(double value, enum ZclDataTypeT dataType, uint8_t *data, unsigned int maxlen)
{
    int exponent;
    double mantissa;
    int exponent32bit;
    long long exponent64bit;

    if (dataType == ZCL_DATATYPE_FLOATING_SEMI) {
        uint16_t semi_val = 0;
        const int inf_exp = (int)((uint16_t)1U + (ZCL_FLOAT_SEMI_EXPONENT >> (ZCL_FLOAT_SEMI_HIDDEN_BIT + 1U)));
        const int denorm_exp = -(int)(ZCL_FLOAT_SEMI_EXPONENT >> (ZCL_FLOAT_SEMI_HIDDEN_BIT + 1U));

        /* Sanity */
        if (maxlen < sizeof(uint16_t)) {
            return -1;
        }

        /* Convert to an exponent and mantissa. */
        mantissa = ZbZclFloatFrexp(value, &exponent, inf_exp, denorm_exp);
        /*lint -save -e701 -e9027 [ unpermitted operand to '<<' '&' <Rule 10.1, REQUIRED> ] */
        exponent32bit = ((int)(exponent - denorm_exp) << ZCL_FLOAT_SEMI_HIDDEN_BIT) & (int)ZCL_FLOAT_SEMI_EXPONENT;
        /*lint -restore */

        if (mantissa < 0.0) {
            semi_val = (uint16_t)(-mantissa) * ((uint16_t)1U << ZCL_FLOAT_SEMI_HIDDEN_BIT);
            semi_val &= ZCL_FLOAT_SEMI_MANTISSA;
            semi_val |= (uint16_t)exponent32bit;
            semi_val |= ZCL_FLOAT_SEMI_SIGN;
        }
        else {
            semi_val = (uint16_t)mantissa * ((uint16_t)1U << ZCL_FLOAT_SEMI_HIDDEN_BIT);
            semi_val &= ZCL_FLOAT_SEMI_MANTISSA;
            semi_val |= (uint16_t)exponent32bit;
        }

        /* Copy the floating point number. */
        data[0] = (uint8_t)semi_val;
        data[1] = (uint8_t)((semi_val >> 8) & (uint16_t)0xff);
        return (int)sizeof(uint16_t);
    }
    else if (dataType == ZCL_DATATYPE_FLOATING_SINGLE) {
        uint32_t single_val = 0;
        const int inf_exp = (int)(1U + (ZCL_FLOAT_SINGLE_EXPONENT >> (ZCL_FLOAT_SINGLE_HIDDEN_BIT + 1U)));
        const int denorm_exp = -(int)(ZCL_FLOAT_SINGLE_EXPONENT >> (ZCL_FLOAT_SINGLE_HIDDEN_BIT + 1U));

        /* Sanity */
        if (maxlen < sizeof(uint32_t)) {
            return -1;
        }

        /* Convert to an exponent and mantissa. */
        mantissa = ZbZclFloatFrexp(value, &exponent, inf_exp, denorm_exp);
        /*lint -save -e701 -e9027 [ unpermitted operand to '<<' '&' <Rule 10.1, REQUIRED> ] */
        exponent32bit = (((int)exponent - denorm_exp) << ZCL_FLOAT_SINGLE_HIDDEN_BIT) & (int)ZCL_FLOAT_SINGLE_EXPONENT;
        /*lint -restore*/

        if (mantissa < 0.0) {
            single_val = (uint32_t)(-mantissa) * ((uint32_t)1U << ZCL_FLOAT_SINGLE_HIDDEN_BIT);
            single_val &= ZCL_FLOAT_SINGLE_MANTISSA;
            single_val |= (uint32_t)exponent32bit;
            single_val |= ZCL_FLOAT_SINGLE_SIGN;
        }
        else {
            single_val = (uint32_t)mantissa * ((uint32_t)1U << ZCL_FLOAT_SINGLE_HIDDEN_BIT);
            single_val &= ZCL_FLOAT_SINGLE_MANTISSA;
            single_val |= (uint32_t)exponent32bit;
        }

        /* Copy the floating point number. */
        data[0] = (uint8_t)((single_val >> 0U) & 0xffU);
        data[1] = (uint8_t)((single_val >> 8U) & 0xffU);
        data[2] = (uint8_t)((single_val >> 16U) & 0xffU);
        data[3] = (uint8_t)((single_val >> 24U) & 0xffU);
        return (int)sizeof(uint32_t);
    }
    else if (dataType == ZCL_DATATYPE_FLOATING_DOUBLE) {
        uint64_t double_val = 0;
        const int inf_exp = 1 + (int)(ZCL_FLOAT_DOUBLE_EXPONENT >> (ZCL_FLOAT_DOUBLE_HIDDEN_BIT + 1U));
        const int denorm_exp = -(int)(ZCL_FLOAT_DOUBLE_EXPONENT >> (ZCL_FLOAT_DOUBLE_HIDDEN_BIT + 1U));

        /* Sanity */
        if (maxlen < sizeof(uint64_t)) {
            return -1;
        }

        /* Convert to an exponent and mantissa. */
        mantissa = ZbZclFloatFrexp(value, &exponent, inf_exp, denorm_exp);

        /*lint -save -e703 -e9027 [ unpermitted operand to '<<' '&' <Rule 10.1, REQUIRED> ] */
        exponent64bit = (((long long)exponent - (long long)denorm_exp) << ZCL_FLOAT_DOUBLE_HIDDEN_BIT) & (long long)ZCL_FLOAT_DOUBLE_EXPONENT;
        /*lint -restore*/

        if (mantissa < 0.0) {
            double_val = (uint64_t)(-mantissa) * ((uint64_t)1U << ZCL_FLOAT_DOUBLE_HIDDEN_BIT);
            double_val &= ZCL_FLOAT_DOUBLE_MANTISSA;
            double_val |= (uint64_t)exponent64bit;
            double_val |= ZCL_FLOAT_DOUBLE_SIGN;
        }
        else {
            double_val = (uint64_t)mantissa * ((uint64_t)1U << ZCL_FLOAT_DOUBLE_HIDDEN_BIT);
            double_val &= ZCL_FLOAT_DOUBLE_MANTISSA;
            double_val |= (uint64_t)exponent64bit;
        }

        /* Copy the floating point number. */
        data[0] = (uint8_t)((double_val >> 0U) & 0xffU);
        data[1] = (uint8_t)((double_val >> 8U) & 0xffU);
        data[2] = (uint8_t)((double_val >> 16U) & 0xffU);
        data[3] = (uint8_t)((double_val >> 24U) & 0xffU);
        data[4] = (uint8_t)((double_val >> 32U) & 0xffU);
        data[5] = (uint8_t)((double_val >> 40U) & 0xffU);
        data[6] = (uint8_t)((double_val >> 48U) & 0xffU);
        data[7] = (uint8_t)((double_val >> 56U) & 0xffU);
        return (int)sizeof(uint64_t);
    }
    /* Not a floating point data type. */
    else {
        return -1;
    }
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      ZbZclParseFloat
 *  DESCRIPTION
 *      Parses a floating point number from a buffer starting at
 *      the given pointer and returns it as a native floating
 *      point type.
 *
 *      Note that the length of the buffer isn't checked. The caller
 *      is assumed to have sanity-checked the buffer length already
 *      by a call to ZbZclAttrParseLength.
 *  PARAMETERS
 *      dataType        ; ZCL Attribute data type.
 *      data            ; ZCL attribute data.
 *  RETURNS
 *      double          ;
 *---------------------------------------------------------------
 */
double
ZbZclParseFloat(enum ZclDataTypeT dataType, const uint8_t *data, enum ZclStatusCodeT *statusPtr)
{
    int exponent;
    double temp;
    uint64_t uint64temp;
    uint32_t uint32temp;
    uint16_t uint16temp, unsignedexp;

    /* EXEGIN - length check of data? */
    *statusPtr = ZCL_STATUS_SUCCESS;

    switch (dataType) {
        case ZCL_DATATYPE_FLOATING_SEMI:
        {
            uint16_t dblVal = pletoh16(data);

            /* Parse 16-bit floating point values. */

            /* Check for infinity/NaN */
            if ((dblVal & ZCL_FLOAT_SEMI_EXPONENT) == ZCL_FLOAT_SEMI_EXPONENT) {
                /* NaN has Mantissa != 0. */
                if ((dblVal & ZCL_FLOAT_SEMI_MANTISSA) != 0U) {
                    return ZCL_FLOAT_NAN;
                }
                /* Infinity has Mantissa == 0. */
                return (((dblVal & ZCL_FLOAT_SEMI_SIGN) > 0U) ? (-ZCL_FLOAT_INFINITY) : (ZCL_FLOAT_INFINITY));
            }

            /* Parse the exponent. */
            unsignedexp = (dblVal & ZCL_FLOAT_SEMI_EXPONENT) >> ZCL_FLOAT_SEMI_HIDDEN_BIT;
            exponent = (int)unsignedexp;
            exponent -= (int)(ZCL_FLOAT_SEMI_EXPONENT >> (ZCL_FLOAT_SEMI_HIDDEN_BIT + 1U));
            exponent -= (int)(ZCL_FLOAT_SEMI_HIDDEN_BIT);

            /* Parse the mantissa. */
            if ((dblVal & ZCL_FLOAT_SEMI_EXPONENT) != 0U) {
                /* Normalized. */
                uint16temp = ((dblVal & ZCL_FLOAT_SEMI_MANTISSA) + ((uint16_t)1U << ZCL_FLOAT_SEMI_HIDDEN_BIT));
            }
            else {
                /* Denormalized */
                exponent++;
                uint16temp = (dblVal & ZCL_FLOAT_SEMI_MANTISSA);
            }
            temp = (double)uint16temp;

            /* Apply the sign. */
            if ((dblVal & ZCL_FLOAT_SEMI_SIGN) != 0U) {
                temp = -temp;
            }

            /* Apply the exponent and return. */
            return ZbZclFloatLdexp(temp, exponent);
        }

        case ZCL_DATATYPE_FLOATING_SINGLE:
        {
            uint32_t quadVal = pletoh32(data);

            /* Parse 32-bit floating point values. */

            /* Check for infinity/NaN */
            if ((quadVal & ZCL_FLOAT_SINGLE_EXPONENT) == ZCL_FLOAT_SINGLE_EXPONENT) {
                /* NaN has Mantissa != 0. */
                if ((quadVal & ZCL_FLOAT_SINGLE_MANTISSA) != 0U) {
                    return ZCL_FLOAT_NAN;
                }
                /* Infinity has Mantissa == 0. */
                return (((quadVal & ZCL_FLOAT_SINGLE_SIGN) > 0U) ? (-ZCL_FLOAT_INFINITY) : (ZCL_FLOAT_INFINITY));
            }

            /* Parse the exponent. */
            unsignedexp = (uint16_t)((quadVal & ZCL_FLOAT_SINGLE_EXPONENT) >> ZCL_FLOAT_SINGLE_HIDDEN_BIT);
            exponent = (int)unsignedexp;
            exponent -= (int)(ZCL_FLOAT_SINGLE_EXPONENT >> (ZCL_FLOAT_SINGLE_HIDDEN_BIT + 1U));
            exponent -= (int)(ZCL_FLOAT_SINGLE_HIDDEN_BIT);

            /* Parse the mantissa. */
            if ((quadVal & ZCL_FLOAT_SINGLE_EXPONENT) != 0U) {
                /* Normalized. */
                uint32temp = (quadVal & ZCL_FLOAT_SINGLE_MANTISSA) + ((uint32_t)1U << ZCL_FLOAT_SINGLE_HIDDEN_BIT);
            }
            else {
                /* Denormalized */
                exponent++;
                uint32temp = (quadVal & ZCL_FLOAT_SINGLE_MANTISSA);
            }
            temp = (double)uint32temp;

            /* Apply the sign. */
            if ((quadVal & ZCL_FLOAT_SINGLE_SIGN) != 0U) {
                temp = -temp;
            }

            /* Apply the exponent and return. */
            return ZbZclFloatLdexp(temp, exponent);
        }

        case ZCL_DATATYPE_FLOATING_DOUBLE:
        {
            uint64_t octVal = pletoh64(data);

            /* Parse 64-bit floating point values. */

            /* Check for infinity/NaN */
            if ((octVal & ZCL_FLOAT_DOUBLE_EXPONENT) == ZCL_FLOAT_DOUBLE_EXPONENT) {
                /* NaN has Mantissa != 0. */
                if ((octVal & ZCL_FLOAT_DOUBLE_MANTISSA) != 0U) {
                    return ZCL_FLOAT_NAN;
                }
                /* Infinity has Mantissa == 0. */
                return (((octVal & ZCL_FLOAT_DOUBLE_SIGN) > 0ULL) ? (-ZCL_FLOAT_INFINITY) : (ZCL_FLOAT_INFINITY));
            }

            /* Parse the exponent. */
            unsignedexp = (uint16_t)((octVal & ZCL_FLOAT_DOUBLE_EXPONENT) >> ZCL_FLOAT_DOUBLE_HIDDEN_BIT);
            exponent = (int)unsignedexp;
            exponent -= (int)(ZCL_FLOAT_DOUBLE_EXPONENT >> (ZCL_FLOAT_DOUBLE_HIDDEN_BIT + 1U));
            exponent -= (int)(ZCL_FLOAT_DOUBLE_HIDDEN_BIT);

            /* Parse the mantissa. */
            if ((octVal & ZCL_FLOAT_DOUBLE_EXPONENT) != 0U) {
                /* Normalized. */
                uint64temp = ((octVal & ZCL_FLOAT_DOUBLE_MANTISSA) + ((uint64_t)1U << ZCL_FLOAT_DOUBLE_HIDDEN_BIT));
            }
            else {
                /* Denormalized */
                exponent++;
                uint64temp = (octVal & ZCL_FLOAT_DOUBLE_MANTISSA);
            }
            temp = (double)uint64temp;

            /* Apply the sign. */
            if ((octVal & ZCL_FLOAT_DOUBLE_SIGN) != 0U) {
                temp = -temp;
            }

            /* Apply the exponent and return. */
            return ZbZclFloatLdexp(temp, exponent);
        }

        default:
            /* Otherwise, this is isn't a floating point value. */
            *statusPtr = ZCL_STATUS_INVALID_DATA_TYPE;
            return ZCL_FLOAT_NAN;
    }
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      ZbZclFloatLdexp
 *  DESCRIPTION
 *      An emulation of the ldexp() function provided by most
 *      math libraries, but absent on the Q5x.
 *
 *      returns x * 2^exp.
 *
 *      Since direct access to the floating-point exponent isn't
 *      portable, we instead multiply x by powers of two, and
 *      decrease the exponent until the exponent is two.
 *
 *      For a double-precision floating point number, this should
 *      work out to a maximum of about 20 iterations.
 *  PARAMETERS
 *      x               ;
 *      exp             ;
 *  RETURNS
 *      double          ;
 *---------------------------------------------------------------
 */
static double
ZbZclFloatLdexp(double x, int exponent)
{
#ifndef WITH_MATH_LDEXP
    /*
     * The stride defines maximum power of two (2^stride) to apply in a
     * single iteration. Larger values will reduce the number of
     * iterations. Value of 48 chosen as it is the nearest multiple of
     * eight that's less than the mantissa for double-precision floats.
     */
    const unsigned int stride = 48;
    unsigned long long uintMultiplier, uintDivisor;

    /* Test for NaN and zero. */
    /*lint -save -e777 [ !MISRA -testing floats for equality] */
    if (ZCL_FLOAT_ISNAN(x) || ((x + x) == x)) {
        /*lint -restore*/
        return x;
    }

    /* If the exponent is positive, multiply until exponent==0. */
    if (exponent > 0) {
        uintMultiplier = (unsigned long long)1U << stride;
        const double multiplier = (double)uintMultiplier;
        for (; exponent >= (int)stride; exponent -= (int)stride) {
            x *= multiplier;
        }
        uintMultiplier = ((unsigned long long)1U << (unsigned int)exponent);
        x *= (double)uintMultiplier;
    }
    /* If the exponent is negative, divide until exponent==0. */
    else if (exponent < 0) {
        uintDivisor = (unsigned long long)1U << stride;
        const double multiplier = 1.0 / ((double)uintDivisor);
        int exponentAbs;
        for (exponentAbs = -exponent; exponentAbs >= (int)stride; exponentAbs -= (int)stride) {
            x *= multiplier;
        }
        uintDivisor = (unsigned long long)1U << (unsigned int)exponentAbs;
        x /= (double)uintDivisor;
    }
    else {
        /* MISRA wants else at the end of else if chain, cannot be empty so here's a comment */
    }
    return x;
#else
    return ldexp(x, exponent);
#endif /* WITH_MATH_LDEXP */
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      ZbZclFloatFrexp
 *  DESCRIPTION
 *      Function used to break a double-precision floating point
 *      value into a ZCL exponent and mantissa.
 *  PARAMETERS
 *      x               ; Input value.
 *      exponent        ; Output exponent.
 *      inf_exp         ; Exponent for infinity.
 *      denorm_exp      ; Exponent for denormalized numbers.
 *  RETURNS
 *      double          ;
 *---------------------------------------------------------------
 */
static double
ZbZclFloatFrexp(double x, int *exponent, int inf_exp, int denorm_exp)
{
#ifdef WITH_MATH_FREXP
    double mantissa;
#else
    const unsigned int stride = 48;
    int temp = 0;
    unsigned long long uintMultiplier, uintDivisor;
    unsigned long long constraint;
#endif
    int sign = 1;
    double xAbs = x;

    /* Take the absolute value of x */
    if (x < 0.0) {
        sign = -1;
        xAbs = -xAbs;
    }

    /* Test for NaN, Inf and zero. */
    /*lint -save -e777 [!MISRA - testing float for equality] */
    if (ZCL_FLOAT_ISNAN(xAbs)) {
        *exponent = inf_exp;
        return ((double)sign * 1.5);
    }
    if (ZCL_FLOAT_ISINF(xAbs)) {
        *exponent = inf_exp;
        return ((double)sign * 1.0);
    }
    if ((xAbs + xAbs) == xAbs) {
        *exponent = denorm_exp;
        return ((double)sign * 0.0);
    }
    /*lint -restore*/

#ifdef WITH_MATH_FREXP
    mantissa = 2.0 * frexp(xabs, exponent);
    *exponent = *exponent - 1;
    if (*exponent >= inf_exp) {
        goto frexp_return_inf;
    }
    if (*exponent <= denorm_exp) {
        mantissa /= (0x1LL << (denorm_exp - *exponent + 1));
        *exponent = denorm_exp;
    }
    return (sign * mantissa);
#else
    /* Handle numbers larger than 2.0. */
    if (xAbs >= 2.0) {
        uintDivisor = ((unsigned long long)1U << stride);
        const double multiplier = 1.0 / ((double)uintDivisor);
        /* Divide until the number is < 2.0 * 2^stride. */
        constraint = (unsigned long long)2U << stride;
        while (xAbs >= (double)constraint) {
            xAbs *= multiplier;
            temp += (int)stride;
            if (temp >= inf_exp) {
                *exponent = inf_exp;
                return ((double)sign * 1.0);
            }
        }
        /* Divide until the number is < 2.0 */
        while (xAbs >= 2.0) {
            xAbs *= 0.5;
            temp++;
            if (temp >= inf_exp) {
                *exponent = inf_exp;
                return ((double)sign * 1.0);
            }
        }
    }
    /* Handle numbers smaller than 1.0 */
    else {
        if (xAbs < 1.0) {
            uintMultiplier = (unsigned long long)1U << stride;
            const double multiplier = (double)uintMultiplier;
            /* Multiply until the number is >= 2^-stride. */
            constraint = (unsigned long long)1U << stride;
            while (x < (1.0 / (double)constraint)) {
                if ((temp - (int)stride) <= denorm_exp) {
                    break;
                }
                xAbs *= multiplier;
                temp -= (int)stride;
            }
            /* Multiply until the number is >= 1.0. */
            while (xAbs < 1.0) {
                temp--;
                if (temp == denorm_exp) {
                    break;
                }
                xAbs *= 2.0;
            }
        }
    }

    /* Done */
    *exponent = temp;
    return (xAbs * (double)sign);
#endif
}

bool
ZbZclAttrIsFloat(enum ZclDataTypeT dataType)
{
    if ((dataType >= ZCL_DATATYPE_FLOATING_SEMI) && (dataType <= ZCL_DATATYPE_FLOATING_DOUBLE)) {
        return true;
    }
    return false;
}
