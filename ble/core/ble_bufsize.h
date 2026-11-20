/*****************************************************************************
 * @file    ble_bufsize.h
 *
 * @brief   Definition of BLE stack buffers size
 *****************************************************************************
 * @attention
 *
 * Copyright (c) 2018-2026 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 *****************************************************************************
 */

#ifndef BLE_BUFSIZE_H__
#define BLE_BUFSIZE_H__


/*
 * BLE_DEFAULT_ATT_MTU: minimum MTU value that GATT must support.
 */
#define BLE_DEFAULT_ATT_MTU                  23

/*
 * BLE_DEFAULT_MAX_ATT_SIZE: maximum attribute size.
 */
#define BLE_DEFAULT_MAX_ATT_SIZE            512

/*
 * BLE_PREP_WRITE_X_ATT: compute how many memory blocks are needed to store
 * Prepare Write Request packets when writing a characteristic with size
 * 'max_att' and the used ATT_MTU value is equal to BLE_DEFAULT_ATT_MTU (23).
 */
#define BLE_PREP_WRITE_X_ATT(max_att) \
        (DIVC(max_att, BLE_DEFAULT_ATT_MTU - 5) * 2)

/*
 * BLE_DEFAULT_PREP_WRITE_LIST_SIZE: default minimum Prepare Write List size.
 */
#define BLE_DEFAULT_PREP_WRITE_LIST_SIZE \
        BLE_PREP_WRITE_X_ATT(BLE_DEFAULT_MAX_ATT_SIZE)

/*
 * BLE_MEM_BLOCK_X_... compute how many memory blocks are needed to compose
 * ACL packets, based on the MTU (mtu) and the number of links (n_link)
 */
#define BLE_MEM_BLOCK_SIZE                   32

#if (SLAVE_ONLY != 0) || (BASIC_FEATURES != 0)
#define BLE_MEM_BLOCK_X_PTX(n_link)           0
#else
#define BLE_MEM_BLOCK_X_PTX(n_link)           (n_link)
#endif

#define BLE_MEM_BLOCK_X_TX(mtu) \
        (DIVC((mtu) + 4, BLE_MEM_BLOCK_SIZE) + 1)

#define BLE_MEM_BLOCK_X_RX(mtu, n_link) \
        (((DIVC((mtu) + 4, BLE_MEM_BLOCK_SIZE) + 2) * (n_link)) + 1)

/*
 * BLE_MBLOCKS_CALC: minimum number of buffers needed by the stack.
 * This is the minimum recommended value and depends on:
 *  - pw: size of Prepare Write List
 *  - mtu: maximum between ATT MTU, SMP MTU (65) and L2CAP COC MPS
 *  - n_link: maximum number of simultaneous connections
 */
#define BLE_MBLOCKS_CALC(pw, mtu, n_link) \
        ((pw) + BLE_MEM_BLOCK_X_TX(mtu) + BLE_MEM_BLOCK_X_PTX(n_link) + \
         BLE_MEM_BLOCK_X_RX(mtu, n_link))

/*
 * BLE_FIXED_BUFFER_SIZE_BYTES:
 * A part of the RAM, is dynamically allocated by initializing all the pointers
 * defined in a global context variable "mem_alloc_ctx_p".
 * This initialization is made in the Dynamic_allocator functions, which
 * assign a portion of RAM given by the external application to the above
 * mentioned "global pointers".
 *
 * The size of this Dynamic RAM is made of 2 main components:
 * - a part that is parameters-dependent (num of links, GATT buffers, ...),
 *   and which value is made explicit by the following macro;
 * - a part, that may be considered "fixed", i.e. independent from the above
 *   mentioned parameters.
*/
#if (BEACON_ONLY != 0)
#define BLE_FIXED_BUFFER_SIZE_BYTES  4200   /* Beacon only */
#elif (LL_ONLY_BASIC != 0)
#define BLE_FIXED_BUFFER_SIZE_BYTES  5960   /* LL only Basic*/
#elif (LL_ONLY != 0)
#define BLE_FIXED_BUFFER_SIZE_BYTES  6288   /* LL only Full */
#elif (SLAVE_ONLY != 0)
#define BLE_FIXED_BUFFER_SIZE_BYTES  6408   /* Peripheral only */
#elif (BASIC_FEATURES != 0)
#define BLE_FIXED_BUFFER_SIZE_BYTES  6928   /* Basic Features */
#else
#define BLE_FIXED_BUFFER_SIZE_BYTES  7212   /* Full stack */
#endif

/*
 * BLE_PER_LINK_SIZE_BYTES: additional memory size used per link
 */
#if (BEACON_ONLY != 0)
#define BLE_PER_LINK_SIZE_BYTES        76   /* Beacon only */
#elif (LL_ONLY_BASIC != 0)
#define BLE_PER_LINK_SIZE_BYTES       244   /* LL only Basic */
#elif (LL_ONLY != 0)
#define BLE_PER_LINK_SIZE_BYTES       244   /* LL only Full */
#elif (SLAVE_ONLY != 0)
#define BLE_PER_LINK_SIZE_BYTES       392   /* Peripheral only */
#elif (BASIC_FEATURES != 0)
#define BLE_PER_LINK_SIZE_BYTES       420   /* Basic Features */
#else
#define BLE_PER_LINK_SIZE_BYTES       432   /* Full stack */
#endif

/*
 * BLE_TOTAL_BUFFER_SIZE: this macro returns the amount of memory, in bytes,
 * needed for the storage of data structures (except GATT database elements)
 * whose size depends on the number of supported connections.
 *
 * @param n_link: Maximum number of simultaneous connections that the device
 * will support. Valid values are from 1 to 8.
 *
 * @param mblocks_count: Number of memory blocks allocated for packets.
 */
#define BLE_TOTAL_BUFFER_SIZE(n_link, mblocks_count) \
        (16 + BLE_FIXED_BUFFER_SIZE_BYTES + \
         (BLE_PER_LINK_SIZE_BYTES * (n_link)) + \
         ((BLE_MEM_BLOCK_SIZE + 8) * (mblocks_count)))

/*
 * BLE_EXT_ADV_BUFFER_SIZE
 * additional memory size used for Extended advertising;
 * It has to be added to BLE_TOTAL_BUFFER_SIZE() if the Extended advertising
 * feature is used.
 *
 * @param set_nbr: Maximum number of advertising sets.
 * Valid values are from 1 to 8.
 *
 * @param data_len: Maximum size of advertising data.
 * Valid values are from 31 to 1650.
 */
#define BLE_EXT_ADV_BUFFER_SIZE(set_nbr, data_len) \
        (2512 + ((892 + (DIVC(data_len, 207) * 244)) * (set_nbr)))

/*
 * BLE_DEFAULT_NUM_GATT_SERVICES: this macro returns the number of services
 * created by the BLE stack after call to ACI_GATT_INIT and ACI_GAP_INIT.
 */
#define BLE_DEFAULT_NUM_GATT_SERVICES 2

/*
 * BLE_DEFAULT_NUM_GATT_ATTRIBUTES: this macro returns the number of attributes
 * created by the BLE stack after call to ACI_GATT_INIT and ACI_GAP_INIT.
 *
 * @param options: option flags used at BLE stack initialization
 *
 * @param privacy_en: 1 if privacy is used; otherwise 0
 */
#define BLE_DEFAULT_NUM_GATT_ATTRIBUTES(options, privacy_en) \
        ((((options) & BLE_OPTIONS_ENHANCED_ATT) ? \
          (((options) & BLE_OPTIONS_NO_SVC_CHANGE_DESC) ? 4 : \
           ((options) & BLE_OPTIONS_GATT_CACHING) ? 9 : 7) : \
          (((options) & BLE_OPTIONS_NO_SVC_CHANGE_DESC) ? 0 : \
           ((options) & BLE_OPTIONS_GATT_CACHING) ?  7 : 3)) + \
         ((privacy_en) ? 8 : 6))

/*
 * BLE_DEFAULT_ATT_VALUE_ARRAY_SIZE : this macro returns the size of attribute
 * values array used by the BLE stack after call to ACI_GATT_INIT and
 * ACI_GAP_INIT.
 *
 * @param options: option flags used at BLE stack initialization
 *
 * @param n_link: Maximum number of simultaneous connections that the device
 * supports. Valid values are from 1 to 8.
 *
 * @param dev_name_len: Length of the device name as passed to ACI_GAP_INIT
 */
#define BLE_DEFAULT_ATT_VALUE_ARRAY_SIZE(options, n_link, dev_name_len) \
        ((((options) & BLE_OPTIONS_NO_SVC_CHANGE_DESC) ? \
          (((options) & BLE_OPTIONS_ENHANCED_ATT) ? (11 + (n_link)) : 0) : \
          (((options) & BLE_OPTIONS_GATT_CACHING) ? (41 + ((n_link) * 3)) : \
           ((options) & BLE_OPTIONS_ENHANCED_ATT) ? (20 + ((n_link) * 3)) : \
            (9 + ((n_link) * 2)))) + 31 + (dev_name_len))

/*
 * BLE_TOTAL_BUFFER_SIZE_GATT: this macro returns the amount of memory,
 * in bytes, needed for the storage of GATT database elements.
 *
 * @param num_gatt_attributes: Maximum number of Attributes (i.e. the number
 * of characteristic + the number of characteristic values + the number of
 * descriptors, excluding the services) that can be stored in the GATT
 * database. Note that certain characteristics and relative descriptors are
 * added automatically during device initialization so this parameters should
 * be 9 plus the number of user Attributes
 *
 * @param num_gatt_services: Maximum number of Services that can be stored in
 * the GATT database. Note that the GAP and GATT services are automatically
 * added so this parameter should be 2 plus the number of user services
 *
 * @param att_value_array_size: Size of the storage area for Attribute values.
  */
#define BLE_TOTAL_BUFFER_SIZE_GATT(num_gatt_attributes, num_gatt_services, att_value_array_size) \
        (((((att_value_array_size) - 1) | 3) + 1) + \
         (40 * (num_gatt_attributes)) + (48 * (num_gatt_services)))


#endif /* BLE_BUFSIZE_H__ */
