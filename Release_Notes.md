

# Release Notes for
# <mark>STM32 Middleware WPAN</mark>
Copyright &copy; 2020 STMicroelectronics\
    
[![ST logo](_htmresc/st_logo_2020.png)](https://www.st.com)


Purpose
=======

STM32 Wireless Personal Area Network Middleware developed within the
STM32WB framework is used to support:

-   Bluetooth Low Energy 5 Certified Applications

**NOTE**: 
The list of BLE commands is documented in the following file: /STM32_WPAN/ble/core/doc/**STM32WB_BLE_Wireless_Interface.html**.

Refer to /STM32_WPAN/ble/core/doc/**GATT_DB_Size_SRAM_NVM.xlsx** document to calculate the size of the GATT Database stored in SRAM and the GATT DB and security records in NVM.

-   802.15.4 Thread Certified Applications (based on
    [OpenThread](thread\openthread\Release_Notes.html) stack)

-   802.15.4 MAC layer

-   Zigbee Applications

**NOTE** : Depending on the kind of Application targeted, the appropriate
Wireless Coprocessor Firmware needs to be loaded.

- **Zigbee** clusters are provided as a library. 
  - Available on **IAR/STM32CubeIDE** (**stm32wb_zigbee_wb_lib.a**) and **Keil** (**stm32wb_zigbee_wb_lib_keil.lib**) under Middlewares/ST/STM32_WPAN/zigbee/lib.
  - To get access to Zigbee clusters source code, please contact ST local office.

- All available binaries are located under /Projects/STM32\_Copro\_Wireless\_Binaries directory.

- Refer to UM2237 to learn how to use/install STM32CubeProgrammer.

- Refer to /Projects/STM32\_Copro\_Wireless\_Binaries/ReleaseNote.html for the detailed procedure to change the Coprocessor binary.

Update History
==============

<label for="collapse-section35" aria-hidden="false">V1.25.0 / 11-Sept-2026</label>
<div>
## Main Changes

- General: 

  
- BLE: 


</div>


<label for="collapse-section34" aria-hidden="false">V1.24.0 / 23-October-2025</label>
<div>
## Main Changes

- General: 
  - SLA0044 Legal terms updated to latest revision (Rev 6 / October 2025)
  
- BLE: 
  - ID 211055 : Unexpected events handling improved in some BLE applications
  - ID 214927 : The support of ACI_HAL_SCAN_REQ_REPORT_EVENT and ACI_HAL_SET_EVENT_MASK is added in most variants.
  - ID 217438 : New MESH Library version 1.13.011 to update End of Radio Activity event definition

</div>

<label for="collapse-section33" aria-hidden="false">V1.23.0 / 02-June-2025</label>
<div>
## Main Changes
- BLE:
  - TCRL-2025-1 compliancy.
  
- Zigbee:
  - ID 198926 : ZbZclClusterGetProfileId modified to return the Profile Id making the alignment with ZbZclClusterSetProfileId.
  - ID 201684 : Removed ZB_BDB_FLAG_DEBUG_APS, which if enabled, would cause ZbApsPacketFreeAll to lock up the device.

</div>

<label for="collapse-section32" aria-hidden="false">V1.22.1 / 12-March-2025</label>
<div>
## Main Changes
  
- Zigbee:
  - Add following missing definition : MSG_M4TOM0_PHY_SET_TX_POWER.

</div>

<label for="collapse-section31" aria-hidden="false">V1.22.0 / 05-February-2025</label>
<div>
## Main Changes

- BLE:
  - Compliancy TCRL-2024-2.
  
- Zigbee:
  - ID 188250 : Zigbee PAN ID Update Notification.

</div>

<label for="collapse-section30" aria-hidden="false">V1.21.0 / 30-October-2024</label>
<div>
## Main Changes

- BLE:
  - ID 188214 : Fix cast issue in OutputDbgTrace for system command response buffer
- Thread:
  - OpenThread update to SHA-1: 4a0d6b7b6495a1e4e2e03ab7a4f8baa064df4a6e (June 11th 2024)
- Zigbee
  - ID 184349 : Support of a new API named ZbStartupFindBindStartEndpoint. This new API is similar to ZbStartupFindBindStart but is addressing one single end point. Through this API, it is possible to specify the end point on which to perform the Finding & Binding.
  
</div>

<label for="collapse-section29" aria-hidden="false">V1.20.0 / 04-June-2024</label>
<div>
## Main Changes

- General: 
  - ID 180081 : SHCI_C2_SetSystemClock command fixed to return properly it's status.   
  - ID 178250 : USB Device ID are now based on UID register to have a unique identifier by STM32 chip. 

- BLE: 
  - ID 176718 : A new command ACI_HAL_EAD_ENCRYPT_DECRYPT is added to ease implementation of Encrypted Advertising Data feature.   

- Thread:  
  - ID 176836 : Added a bit to set when calling SHCI_C2_Config() to indicate if Thread stack should be initialized using an alternate EUI64 format. 
  
</div>

<label for="collapse-section28" aria-hidden="false">V1.19.1 / 8-April-2024</label>
<div>
## Main Changes

- Thread: 
  - Ticket 170698 : Solving issue with OpenThread Cli command <networkdiagnostic get>.
  
</div>

<label for="collapse-section27" aria-hidden="false">V1.19.0 / 7-Feb-2024</label>
<div>
## Main Changes

- BLE: 
  - BLE-Mesh Library v01.13.009 
  - ID 164373 : Mesh Provisioner self provisioning and self configuration robustness improved 

- Thread: 
  - OT stack update to SHA-1 : 8bc25042ba5cde20605eec2a329c0dff575303f4 (07/07/2023) 
  - ID 158717 : Move OpenThread Command Line Interface (CLI) from M0 to M4. OpenThread CLI has been moved from M0 to M4 to optimize memory footrint on the coprocessor. Use ENABLE_OPENTHREAD_CLI to enable it.  
  
</div>

<label for="collapse-section26" aria-hidden="false">V1.18.0 / 30-Oct-2023</label>
<div>
## Main Changes

- BLE: 
  - MESH Library version 1.13.008: 
      - Reduce the FLASH accesses during provisioning and unprovisioning with the provisioner. 
  - ID 154468 : New parameter setting SHCI_C2_BLE_INIT_BLE_CORE_5_4 for upgraded QDID and declaration ID of Stack BLE 5.4 
  - ID 157039 : BLE_Hid Application - added GATT keyboard report descriptor 

- 802.15.4 Common (MAC / Thread / Zigbee) : 
  - ID 157671 : Enabled some PHY features (continuous wave start/stop, rx_start/stop, tx_start, set_channel) in MAC/OT/Zigbee firmware.  

- Zigbee: 
  - ID 157866 : Solve potential memory leaks inside the IPCC communication driver if an Zigbee API callback returns a failure. 

- Thread: 
  - ID 160888 : Callback odDnsServiceCb corrected 
  
</div>

<label for="collapse-section25" aria-hidden="false">V1.17.3 / 10-Sep-2023</label>
<div>
## Main Changes

- BLE:
  - ID 153449 : Support of a new system command SHCI_C2_SetSystemClock added
  
</div>

<label for="collapse-section24" aria-hidden="false">V1.17.1 / 25-July-2023</label>
<div>
## Main Changes

- BLE:
  - Compliancy TCRL-2023-1 with BLE 5.4 certification.
  
- Zigbee:
  - ID 152635 : All Zigbee commands (Messages going from the M4 to the M0) are now protected through 2 weak functions named respectively Pre_ZigbeeCmdProcessing() and Post_ZigbeeCmdProcessing(void). 
  In case of FreeRTOS, these two functions need to be overloaded in order to manage a semaphore used to ensure that all commands are correctly handled. 
  Without this protection, the system cannot guarantee the validity of the return value associated to the command.
  
</div>

<label for="collapse-section23" aria-hidden="false">V1.17.0 / 31-May-2023</label>
<div>
## Main Changes

- BLE:
  - MESH Library version 1.13.007:
      - Get correct value of RSSI from scan result
      - Updated according last HCI defines
  - ID 142283: SHCI local buffer size correction to support TL command complete format. 
  
- Zigbee:
  - ID 142197: Adding of debug capabilities
      -  There are two new APIS for debug purpose.
      -  ZbHeapDumpInfo() displays information regarding the heap size available.
      -  ZbDebugInfo() is available in case some specific parameters need to be retrieved from the M0.
      By default, no parameters are being retrieved, but for specific customer support, 
      ST can provide dedicated binaries to dump specific variables. 
      To do so, there is no need to update the application nor the middleware. 
      Only a dedicated firmware will be required.  
  - ID 149859: Removal of unused test functions from the Middleware. 

- MAC 802.15.4:
  - Global transaction robustness improvement on overload and noisy network.
  - Extend CSMA-CA retry solution in case host participate within 15.4 network with high concurrency access.
  - Consolidate TX engine and review radio sleep strategy.
 
</div>

<label for="collapse-section22" aria-hidden="false">V1.16.0 / 01-Feb-2023</label>
<div>
## Main Changes

- BLE:
  - BLE GATT caching supported (certified BLE 5.3)
  - BLE Enhanced ATT supported (certified BLE 5.3)
  - ID 123937 : MW BLE legacy file deprecated content has been removed and only kept last changes
  - ID 140069 : A new parameter "Options_extension" has been added in SHCI_C2_Ble_Init_Cmd_Param_t structure
                to configure further BLE features in stack init (keeping former Options bits field)
 
- Zigbee:
  - ID 142192: Adding of a new configuration parameter named ZB_NWK_NIB_ID_SedLeaveRspDuringRejoin. This parameter controls whether a Leave Response is sent while a SED is rejoining.
  - ID 142197: Adding of a new configuration parameter named ZB_APS_IB_ID_MAX_IN_QUEUED_PACKETS. Maximum number of incoming packets the APS is allowed to queue.Default is 0, which means there's no limit, other than available memory.
  - ID 142199: Removal of the following parameters ZB_NWK_NIB_ID_RouteDiscoverySendDelay, ZB_NWK_NIB_ID_RouteCostPerHop, ZB_NWK_NIB_ID_RouteNeighborMaxCost, ZB_NWK_NIB_ID_KeepAliveInfo since not supported.
 
</div>

<label for="collapse-section21" aria-hidden="false">V1.15.0 / 04-Nov-2022</label>
<div>
## Main Changes

- BLE:
  - Mesh library version 1.13.006
  - BLE Init Options flags used for stack configuration have been updated to support new BLE features (as Appearance writing)
  - Appearance characteristic is now optionally writable
  - Ability to read RSSI even in non-connected mode: Added new command: ACI_HAL_READ_RSSI
  - ID 135751 : BLE Mesh improvement to manage the different behavior of “Command Responses” with Embedded Provisioner vs Android App Provisioner
  - ID 131594 :  Management of the BLE Mesh unprovisionning command for the BLE Mesh embedded provisionner (ATEP UNPV)

- ZIGBEE:
  - OTA cluster enhancement (OTA support for multiple download in parallel)
  - ID 137459: Poll cluster enhancement:
    - Zigbee Poll Control server fix to perform fast-polling during check-in request
    - Zigbee ZCL Poll Control refactoring to fix handling of multiple clients.
  - ID 129203: Minor changes in the Callbacks prototypes functions used when allocating the following clusters:  PollControl, IAS and OTA

- THREAD:
  - Thread 1.3 ready
  - OT stack updated to SHA-1: 32ac6ddfad2bc196e216c42249c73420542daac0 (July 26th 2022)


</div>

<label for="collapse-section20" aria-hidden="false">V1.14.1 / 06-July-2022</label>
<div>
## Main Changes
- BLE:
  - ID 103612 : Scanning only on selected channels: Added new parameter to ACI_HAL_WRITE_CONFIG_DATA
  - ID 108072 : Possibility to trigger the NVM update: Added new command: ACI_GATT_STORE_DB
  - ID 116535 : Reduce GATT information size in NVM: Added new “options” flag at BLE stack initialization: BLE_OPTIONS_REDUCED_DB_IN_NVM
  - ID 128925 : Add the possibility to activate or not the blacklist mechanism:	Added new parameter to ACI_HAL_WRITE_CONFIG_DATA
  - ID 130115 : Add information in ACI_HAL_END_OF_RADIO_ACTIVITY_EVENT and ACI_HAL_GET_LINK_STATUS for additional beacon synchro:
                Added slot numbers in ACI_HAL_END_OF_RADIO_ACTIVITY_EVENT; Added new 0x81 value for additional beacon in ACI_HAL_GET_LINK_STATUS

- THREAD:
  - Bug fix applied on OpenThread wrapper

</div>

<label for="collapse-section19" aria-hidden="false">V1.14.0 / 06-June-2022</label>
<div>
## Main Changes
- BLE (v5.3):
  - ID 124622 : HCI White List commands are renamed in BLE spec 5.3
  - ID 124670 : Default Tx_power min/max settings aligned
  - ID 125069 : BLE_HeartRate & BLE_P2PSserver application based on new MW ThreadX RTOS
  - ID 125173 : AGC LUT activation with rx_model_config option
  - ID 125575 : reduce LSE sensitivity to jitter

- BLE-Mesh library version 1.13.005
  - replacement of MoblePalBluetoothSleep() calls by MobleTransmitSuspendAll() calls when using BLEMesh_Shutdown() and BLEMesh_Resume() APIs
  - ID 122886 : device peripheral server in multilink, error in notification data sent over several links, management of busy state for ACI GATT update characteristic command

- THREAD:
  - Interface update to support the integrated openthreadv1.2 commit ec02abc47c6d7663f82132d64555839a5c93e018
  - NVM can now be managed directly from application
  
- ZIGBEE:
  - BDB 3.0.1 & ZCL 8 update
  - OTA cluster enhancement (Modified discover_complete callback to be called if discovery fails and not just success) 
   
</div>
<label for="collapse-section18" aria-hidden="false">V1.13.3 / 18-March-2022</label>
<div>
## Main Changes
- BLE:
  - BLE security pairing fix
  - BLE Extended advertising features improvements
</div>
<label for="collapse-section17" aria-hidden="false">V1.13.2 / 9-February-2022</label>
<div>

## Main Changes

- BLE:
  - Changes directly linked to support the new BLE Wireless Coprocessor Binaries firmware

- Zigbee:
  - Increase message filter maximum number from 4 to 32

</div>

<label for="collapse-section16" aria-hidden="false">V1.13.1 / 3-December-2021</label>
<div>

## Main Changes

- BLE updates:
  - BLE Multi link support
  - L2CAP connection oriented channels support (IP over BLE enabler)
  - ACI_GAP_START_NAME_DISCOVERY_PROC command is deprecated 
  - BLE Extended advertizing (under flag selection) 
  - Channel selection #2 (under flag selection) 
  - ID 117557 : updated buffer index in MW BLE Blood pressure service

</div>

<label for="collapse-section15" aria-hidden="false">V1.13.0 / 3-November-2021</label>
<div>

## Main Changes

- BLE:
    - BLE Multi link support
    - ID 108789 : ACI_GAP_START_NAME_DISCOVERY_PROC command is deprecated    
    - ID 109815 : IP over BLE enablement by default    
    - ID 109676 : New HCI error status overlap with ACI error status
    - New HCI errors are added (from BLE spec. v5.2):
      - HCI_UNKNOWN_ADVERTISING_IDENTIFIER_ERR_CODE:    0x42
      - HCI_PACKET_TOO_LONG_ERR_CODE:                   0x45
    - Following ACI errors(already supported by BLE Host) are remapped to HCI errors:
      - BLE_STATUS_UNKNOWN_CONNECTION_ID:   0x40 -> 0x02 (HCI_UNKNOWN_CONNECTION_IDENTIFIER_ERR_CODE)
      - BLE_STATUS_NOT_ALLOWED:             0x46 -> 0x0C (HCI_COMMAND_DISALLOWED_ERR_CODE)
    - Following ACI errors (already supported by BLE Host) are renumbered:
      - BLE_STATUS_FAILED:                  0x41 -> 0x91
      - BLE_STATUS_INVALID_PARAMS:          0x42 -> 0x92
      - BLE_STATUS_BUSY:                    0x43 -> 0x93
      - BLE_STATUS_PENDING:                 0x45 -> 0x95
      - BLE_STATUS_ERROR:                   0x47 -> 0x97
      - BLE_STATUS_OUT_OF_MEMORY:           0x48 -> 0x98
  - ID 111208 : Support Dory Cut2.1 in parallel to Cut2.2 with new SHCI_C2_CONFIG parameter.  
  - ID 112402 : Implement SMP bypass controlled via config data command
  - ID 113007 : add new parameter "rx_model_config" used for RSSI/AGC-LUT selection in SHCI_C2_Ble_Init() interface
  - ID 114031 : Some BLE HCI command names are not aligned with Bluetooth standard 5.2


- BLE Mesh lib:
    - Added BLE MESH libraries for lighting projects (LP Node and PRF Node) on STM32 WB15.
 
- Zigbee:
    - Alignment of Zigbee Clusters PICS regarding mainly the attribute reporting status.
    - API changes inside the Metering cluster. The ZbZclMeterClientCallbacksT and ZbZclMeterServerCallbacksT structures have been modified.For instance the previous request_mirror(..) and remove_mirror(..) functions inside the ZbZclMeterServerCallbacksT have been replaced by one single function. Refer to zcl.meter.h file for more details.
    - The ZbZclAttrReportConfigT structure has been updated in order to manage in parallel several attribute reports. An array of fixed size (ZCL_ATTR_REPORT_CONFIG_NUM_MAX) is now used to handle multiple reporting. Refer to zcl.h file to see the new structure ZbZclAttrReportConfigT. You can also refer yourself to the Zigbee_PressMeas_Client_router Application to see how to use this new structure.
    - The ZbNwkFastPollRequest(..) API has been updated and contains additional parameters to tune the delay and the timeout . The Delay in used to postpone the sending of the first NLME-SYNC. The Timeout is used for setting the fast pool interval value. Refer to Zigbee.nwk.h file for more details.
    - The types of several fields inside the ZbZclPriseServerPublishPriceT structure have been updated. Refer to zcl.price.h file for more details.
    - The ZbZclKeepAliveClient(..) API prototype has been updated. This function is now using the stack instance instead of the cluster instance as input parameter. Refer to zcl.keepalive.h file for more details.
    - The ZbZclClutsterT structure has been reworked after code cleanup and factorization. In particular, the field handling the reporting has been re-architectured. Refer to zcl.h file for more details.
    - A new API named ZbApsBindSrcExists(...) has been added in order to check if a binding exist.

</div>

<label for="collapse-section14" aria-hidden="false">V1.12.0 / 17-June-2021</label>
<div>

## Main Changes

- Zigbee:
  - ZCL Reporting improvement in order to eliminate an unused 1 second timer handler processing
  - Comments improvements in the API descriptions associated to the clusters  (header files)
  - Code cleanup (MISRA rules compliance)
  - Adding of a function requested by the Scene Cluster which was missing on the previous stm32wb_zigbee_wb_lib library
  - Security API cleanup + install code management
  
- BLE updates:
  - Remove completely ACI_HAL_SET_SMP_ENG_CONFIG command
  - GATT_Check_For_Service_Change: add check of GATT database minimum length    
  -	ID 104796 : HIDS_Handle_Mouse_Input_Write/HIDS_Handle_Keyboard_Output_Write : Null pointer used             

</div>

<label for="collapse-section13" aria-hidden="false">V1.11.0 / 5-February-2021</label>
<div>

## Main Changes


- BLE-Mesh library version 1.13.002
  - Updated max number of element to 5 and max number of Model per element to 11:
      To support lighting control system with occupancy sensing.  
  - Bug fix: Client API, Light LC model and sensor status, modify Light LC FSM default Lightness values
  - Sensor & Light LC Server Models updated
  - Client Models updated
  - Config Model APIs callbacks added over application layer
  - Save & Restore APIs for Models parameters in Flash updated
  - Publication enabled for multiple elements
  - Remove double disconnection to accelerate provisioning with IOS ST BLE Mesh App version 1.08.001
  - Bug correction during unprovisioning with ST BLE Mesh App of non GATT connected Nodes. 
  - Bug correction for loss of Vendor model publication: fix on dynamic memory allocation leak when publishing vendor command into group      

- BLE is Compliant BT5.2:
  - HID: added: Battery Service and Device Information Service, connection and disconnection events
  - ID 97936 :  L2CAP update to support IP over BLE (M.6874), SHCI_C2_BLE_init() updated parameters to be provided to CPU2 with new BLE stack Options flags to be configured as:
    - SHCI_C2_BLE_INIT_OPTIONS_LL_ONLY
    - SHCI_C2_BLE_INIT_OPTIONS_LL_HOST
    - SHCI_C2_BLE_INIT_OPTIONS_NO_SVC_CHANGE_DESC
    - SHCI_C2_BLE_INIT_OPTIONS_WITH_SVC_CHANGE_DESC
    - SHCI_C2_BLE_INIT_OPTIONS_DEVICE_NAME_RO
    - SHCI_C2_BLE_INIT_OPTIONS_DEVICE_NAME_RW
    - SHCI_C2_BLE_INIT_OPTIONS_POWER_CLASS_1
    - SHCI_C2_BLE_INIT_OPTIONS_POWER_CLASS_2_3
  - ID 95186 :  SHCI_C2_FUS_GetState fixed to identify when wireless stack running (with correct error code)
  - ID 94042, ID 97931 : STM32WB to handle certification BT5.2 (tcrl 2019-2)

- THREAD:
  - Update OpenThread stack to **SHA-1: 3dbd91aa2b70c7d5cc71b2c465ce3583a13dea79** (thread-reference-20191113)
  - ID 91270: CoapSecure support added
  - ID 96955: Fix for entering standby mode while Thread stop procedure is called. New system command SHCI_C2_802_15_4_DeInit added

- Zigbee:
  - Clarification of PICS information inside the Clusters API interface include files 
  - New directory structure used to store Clusters API interfaces include files
  - Range input parameter checks added when managing Clusters
  - ZCL Commissioning Cluster improvement to allow joining commissioning network and sending unicast frames (as well as Inter-PAN)
  - Support of a Custom Cluster (Refer to the appropriate applications to see how to use it : Zigbee_custom_ls_Server_Coord, and Zigbee_custom_ls_Client_Router)
  - Support of new APIs to control  TouchLink features (Refer to  zcl.touchlink.h file for more details). Adding of TouchLink utility commands
  - Minor fixes in DRLC, Voice over Zigbee & RSSI location Clusters

</div>

<label for="collapse-section12" aria-hidden="false">V1.10.0 / 26-October-2020</label>
<div>

## Main Changes

- General:
    - tl_dbg_conf.h file removed from STM32WPAN Middleware and moved to application side.

- BLE-Mesh library version 1.13.001
    - Improvements:
      - Updated number of element to 8 and number of Model per element to 7
	- Bug fix:
      - Bug correction on Vendor Model: set correct peer address for Vendor Model command
	  
- BLE updates :
    - **ID 91486** - Trace support on all BLE / SYSTEM packets exchanged over the MailBox
    - **ID 92539** - Calibration for RFWUCK - code comment improvement
    - **ID 93153** - Wrong comment on CFG_RTC_WUCKSEL_DIVIDER in app_conf.h
    - **ID 93790** - Clear FLASH_FLAG_OPTVERR at the begin of main.c 
    - **ID 95187** - BLE_OTA : infinite loop when trying to update the wireless stack with a wrong binary file
    
- ZIGBEE :
    - Zigbee interface clarification by adding comments inside the ZCL header files
    - Minor Poll control, IAS and Window covering cluster improvements (For ex : return status and parameter range checking)
    
</div>

<label for="collapse-section11" aria-hidden="false">V1.9.0 / 21-September-2020</label>
<div>

## Main Changes

- BLE-Mesh library version 1.13.000
    - New Development:
      - Light LC Server model
      - New state transition functions and structures in common, new TID check & update functions in common
      - Disable No OOB authentication
      - Multi-element support in Friendship
      - Use of hardware cryptogrphic functions instead of ST Cryptographic Library
      - Remove hci_reset() function calls during provisionning
    - Improvements:
      - Logs optimization and clean up of Server models
      - ATLLC & ATSNR modified to ATUT
      - Server model publication modifications
      - Serial_ut moved to middleware
      - Fixed firmware for crash issue with the publish message
      - Model flash data saving for multi-element
      - APIs update, naming convention updated in light.c
      - Unused code commented in model_generic.c
      - NULL checks added in remaining exposed functions to avoid hardfault in case sensor server is not initialized or failed to initialize
    - Bug fix:
      - Generic OnOff bug when Generic Default Transition Time is enabled
      - Element index update for Generic OnOff
      - Generic OnOff Transition bug, LED not turning off
      - Ongoing Transition should be turned off if any other on/off command received in between
      - The Light Lightness model appears to behave in a non compliant way in the case a new Light_Lightness_Set command is received during an ongoing transition of the Light Level. This causes also the ‘Light Lightness Last’ value to get a wrong value.
      - API MobleConfigModel_SendAppKeyList updated in model_config.c & pal_crypto.c to get the list of all appKeys bounded with a netKey if number of appKeys is>1
      - Bug related to AppKey Delete resolved
      - Bug related to Memory Leak resolved
      - Checkpoint has been added in API ApplicationGetVendorModelList if someone commented ENABLE_VENDOR_MODEL_SERVER in mesh_cfg_usr.h
      
- BLE WPAN updates
    - **ID 88523** - SHCI_C2_BLE_Init() return value type wrong
    - **ID 91533** - Improve the SHCI_GetWirelessFwInfo() to decode the Device Information Table when FUS is running on CPU2

- Thread
  - **ID 91267** - Fix CoAP OpenThread API exposed on application side
    - The CoAP API is now compliant with OpenThread definition and mContext parameter is then correctly returned to the application.

- Zigbee
  - Update on PICS for following clusters : Power Configuration, Diagnostics, Scenes
  - APIs renaming on the Door Lock cluster
  - Parameter range checking updates on several clusters (Power config, Door lock, Commissioning, Color)
    
</div>

<label for="collapse-section10" aria-hidden="false">V1.8.0 / 22-June-2020</label>
<div>

## Main Changes

- BLE-Mesh library version 1.12.008
    - Mesh Model Client & Server Certification Passed – TCRL 2019-2
    - Management of Client Models in PRF Node project
    - Correction on Vendor message commands
    - Changes Models enabling in mesh_cfg_usr.h
      with the definition of a bitmap of 3 bits: 
      -	bit 2 element 3 
      -	 bit 1 element 2
      -	 bit 0 element 1
      
- BLE WPAN updates
    - **ID 83714** - Support of four new events to notify the CPU1 about flash operation (after aci_gap_clear_security_db())
    - **ID 83750** - PREPARE_WRITE_LIST_SIZE and MBLOCKS_COUNT in app_conf.f defined with macro
                 The macro definition is required to keep these parameters consistent with other parameters.
    - **ID 85448** - Bonding (CFG_BONDING_MODE=1) in BLE_HeartRate application
    - **ID 85782** - Option to move NVM to unsecure SRAM2
    - **ID 86573** - BLE_Ota updated to pad with 0xFF the incomplete data to be written in flash
    - **ID 86711** - New command SHCI_C2_Config() available to configure system parameter on the CPU2
                 This command can be used to configure the NVM in either SRAM2 or Flash and
                 to mask asynchronous system events reported by the CPU2. More details in ./interface/patterns/ble_thread/shci/shci.h

- ZigBee
    - FFD Zigbee 3.0 certification compliant.
    - Support of OTA.
    - Support of persistent data management (NVM).
    - Exposure of APIs allowing access to APS layer.
    
</div>

<label for="collapse-section9" aria-hidden="false">V1.7.0 / 11-May-2020</label>
<div>

## Main Changes

BLE-Mesh:

- BLE Mesh Models Fix/Update

</div>

<label for="collapse-section8" aria-hidden="false">V1.6.0 / 27-March-2020</label>
<div>

## Main Changes

BLE-Mesh:

- BLE-Mesh library version 1.12.007
    - Updated for Delta level set binding to Light lightness
    - Multi Key updates.
    - Correction of FSM issues in the LC Model: no way to consume a packet internally.
    - Correction of Sensor_LC_Light_Publish sending wrong property (and LC Model handling wrong property).
    - Updates on Generic Models for Certification tests: Generic OnOff, Level, Power OnOff, Transition Time    
    - Update Multi elements support
    - Changes for DYNAMIC_PROVISIONER in Provisioner project
- New Cryptographic library v3.1.3

    
Zigbee:

- Libarry available on IAR/SW4STM32(stm32wb_zigbee_wb_lib.a) and Keil(stm32wb_zigbee_wb_lib_keil.lib)
- Support following list (47 clusters):

Cluster Number      Cluster ID      Cluster Name
1	                0x0000	        Basic
2	                0x0001	        Power Configuration
3	                0x0003	        Identify6
4	                0x0004	        Groups
5	                0x0005	        Scenes
6	                0x0006	        On/Off
7	                0x0008	        Level Control
8	                0x000a	        Time
9	                0x0019	        OTA Upgrade
10	                0x0020	        Poll Control
11	                0x0021	        Green Power Proxy
12	                0x0102	        Window Covering
13	                0x0202	        Fan Control
14	                0x0204	        Thermostat User Interface Configuration
15	                0x0300	        Color control
16	                0x0301	        Ballast Configuration
17	                0x0400	        Illuminance Measurement
18	                0x0402	        Temperature Measurement
19	                0x0406	        Occupancy Sensing
20	                0x0502	        IAS Warning Device (WD)
21	                0x0b05	        Diagnostics
22	                0x1000	        Touchlink
23	                0x0002	        Device Temperature Configuration
24	                0x0007	        On/Off Switch Configuration
25	                0x0009	        Alarms
26	                0x000b	        RSSI Location
27	                0x0015	        Commissioning
28	                0x001a	        Power Profile Cluster
29	                0x0024	        Nearest Gateway Cluster
30	                0x0101	        Door Lock
31	                0x0200	        Pump Configuration and Control
32	                0x0201	        Thermostat
33	                0x0203	        Dehumidification Control
34	                0x0401	        Illuminance Level Sensing
35	                0x0403	        Pressure Measurement
36	                0x0405	        Relative Humidity Measurement
37	                0x0500	        IAS Zone
38	                0x0501	        IAS Ancillary Control Equipment (ACE)
39	                0x0700	        Price
40	                0x0701	        Demand Response and Load Control
41	                0x0702	        Metering
42	                0x0703	        Messaging
43	                0x0704	        Smart Energy Tunneling (Complex Metering)
44	                0x0800	        Key Establishment
45	                0x0904	        Voice Over ZigBee
46	                0x0b01	        Meter Identification
47	                0x0b04	        Electrical Measurement


</div>

<label for="collapse-section7" aria-hidden="false">V1.5.0 / 22-January-2020</label>
<div>

## Main Changes

Interface:

-	Added new command SHCI_C2_SetFlashActivityControl() to configure BLE timing protection

Zigbee:

- Support of the following Zigbee clusters:
    - Basic
    - On/Off
    - Device Temperature Configuration
    - Identify
    - Power Profile
    - Thermostat-UI-Config
    - Ballast-Configuration
    - Illuminance-Measurement
    - Temperature Measurement
    - Pressure Measurement
    - Occupancy-Sensing
    - Messaging
    - Meter Identification

BLE-Mesh:

- BLE-Mesh library version 1.12.000
    - Embedded Provisioner example added including config-client
    - Multi Net Key support has been added(limited to 2 Net Keys)
    - Key Refresh updated for Multiple Keys
    - Vendor Model updated to add Read and Write messages
    - TID check added in the firmware
    - Light_LC sensor property updated
    - Generic Power OnOff Message updated
    - Multi elements support limited to 3


</div>

<label for="collapse-section6" aria-hidden="true">V1.4.0 / 22-November-2019</label>
<div>

## Main Changes

Interface:

-	Added new command SHCI_C2_ExtpaConfig() to support external PA
-	Update System and BLE transport layer so that a user event packet is released by default

BLE:

-	Added support to ACI_GATT_READ_EX_EVENT
-	Added macro HCI_LE_ADVERTISING_REPORT_RSSI_0(p) to extract properly RSSI from the event packet


</div>

<label for="collapse-section5" aria-hidden="true">V1.3.0 / 4-September-2019</label>
<div>

## Main Changes

General:

-   Introducing support of Zigbee 

Interface:

-	Cleanup inclusion file dependencies
-	Fix local buffer size used in command SHCI_C2_FUS_StoreUsrKey()
-	ble user events are now reported one by one (hci_notify_asynch_evt is called for each packet reported)
-	system users event are now reported one by one (shci_notify_asynch_evt is called for each packet reported)

Zigbee:

- 	First release supporting Zigbee (FFD :Full Function Device)
-	Supporting only On/Off Cluster

BLE-Mesh:

-	BLE-Mesh library version 1.10.004
	-	Light LC Controller state machine for Occupancy detection is implemented
	-	Light LC Controller state machine for Ambient Lux Level is implemented 
	-	Light LC Server Mode messages added
	-	Light LC Server Occupancy Mode messages added
	-	Light LC Server Property messages added
	-	Save State in NVM controlled by Macro ENABLE_SAVE_MODEL_STATE_NVM
	-	Mode of Save State in NVM selected by Macro SAVE_MODEL_STATE_FOR_ALL_MESSAGES and SAVE_MODEL_STATE_POWER_FAILURE_DETECTION
	-	Generic Power OnOff message added
	-	Generic Power OnOff Setup message added
	-	Generic Default Transition Time message added

</div>

<label for="collapse-section4" aria-hidden="true">V1.2.0 / 27-June-2019</label>
<div>

## Main Changes

General:

-   Following utilities : Scheduler and Low Power Manager reworked and moved to "Utilities" directory
-	Split tl_if.c into hci_tl_if.c (BLE) and shci_tl_if.c (System) to remove dependencies to the BLE library when the application is built on top of HCI.

BLE:

- 	Add 2 new GATT events: aci_gatt_indication_event_rp0 and aci_gatt_notification_event_rp0
-	Rework BLE folder architecture to separate the Core from the Services implementation
-	Mesh library V1.10.000:
	- 	Sensors Model example updated 
	-	Sensor data publishing updated 
	-	PB-ADV implementation added 
	-	APIs to control frequency of unprovisioned device beacon, secure network beacon, provisioning service advertisement and proxy service advertisement 
	-	Node unprovision on 5 consecutive Power Replug or Reset cycle with duration of each cycle(ON) less than 2 seconds 
	-	SIG Models handling optimized 
	-	printf statement is replaced with TRACE_M(Function name print) and TRACE_I in application code 

</div>

<label for="collapse-section3" aria-hidden="true">V1.1.1 / 10-May-2019</label>
<div>

## Main Changes

BLE:

-	Fix race condition in transport layer when an operating system is used.
-   Mesh Library V1.09.000:
	-	Fix of the BD Address issue.
	-	Light HSL Model implementation.
	-	Sensor Server Model Example.
	-	CID, PID Configuration.
-	STM32 Cryptographic Library V3.1.1/ 20 April 2018:
	-	Two new STM32 Cryptographic Libraries provided for IAR Embedded Workbench for ARM (EWARM) Toolchain v8.22:
		-	**STM32CryptographicV3.1.1_CM4_IARv8.a**: First official release of optimized STM32 Cryptographic Library for ***Cortex M4*** with ***High size*** optimization.
		-	**STM32CryptographicV3.1.1_CM4_IARv8_otnsc.a**: First official release of optimized STM32 Cryptographic Library for ***Cortex M4*** with ***High speed*** optimization and the option ***No Size constraints*** is enabled.
-	STM32 Cryptographic Library V3.0.0/ 05 June 2015:
	-	Two STM32 Cryptographic Libraries provided for each Development Toolchain:
		-	IAR Embedded Workbench for ARM (EWARM) toolchain v7.40:
			-	**STM32CryptographicV3.0.0_CM4_IAR.a**: New official release of optimized STM32 Cryptographic Library for ***Cortex M4*** with ***High size*** optimization.
			-	**STM32CryptographicV3.0.0_CM4_IAR_otnsc.a**: First official release of optimized STM32 Cryptographic Library for ***Cortex M4*** with ***High speed*** optimization and the option ***No Size constraints*** is enabled.
		-	RealView Microcontroller Development Kit (MDK-ARM) toolchain v5.14:
			-	**STM32CryptographicV3.0.0_CM4_KEIL_slsm1elfspf.lib**: New official release of optimized STM32 Cryptographic Library for ***Cortex M4*** with ***High size*** optimization.
			-	**STM32CryptographicV3.0.0_CM4_KEIL_otslsm1elfspf.lib**: First official release of optimized STM32 Cryptographic Library for ***Cortex M4*** with ***High speed*** optimization and the option ***Split Load and Store Multiple*** and ***One elf Section per Function*** are enabled.
		-	Atollic TrueSTUDIO STM32 (TrueSTUDIO) toolchain v5.3.0:
			-	**STM32CryptographicV3.0.0_CM4_GCC.a**: First official release of optimized STM32 Cryptographic Library for ***Cortex M4*** with ***High size*** optimization.
			-	**STM32CryptographicV3.0.0_CM4_GCC_ot.a**: First official release of optimized STM32 Cryptographic Library for ***Cortex M4*** with ***High speed*** optimization.

</div>

<label for="collapse-section2" aria-hidden="true">V1.1.0 / 29-March-2019</label>
<div>

## Main Changes

General:

-   Licenses in utilities and patterns moved from sla0044 to 3-clauses  BSD
-   Customer Key Storage APIs
-   Get Wireless Coprocessor Firmware information using following API : SHCI\_GetWirelessFwInfo()

BLE:

-   New BLE Mesh lib to fix provisioning issue

Thread:

-	802.15.4 radio driver robustness improvement with additional error checks; the application is now notified in case of radio error
    detected inside the wireless binary
-	TxPower management improvement:
	-   New APIs provided to control the Tx power: otPlatRadioGetTransmitPower() and otPlatRadioSetTransmitPower()
	-	The default Tx power is now set to 0dBm\

</div>

<label for="collapse-section1" aria-hidden="true">V1.0.0 / 31-January-2019</label>
<div>			

## Main Changes

First release

</div>


For complete documentation on STM32WBxx, visit: