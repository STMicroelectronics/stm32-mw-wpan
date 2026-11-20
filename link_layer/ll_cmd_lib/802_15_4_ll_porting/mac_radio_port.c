/**
  ******************************************************************************
  * @file    mac_radio_port.c
  * @author  802.15.4 Team
  * @brief   Porting layer for ST 802.15.4 MAC to the 802.15.4 ST RAL for Cube
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include "common_types.h"
#include <string.h>
#include "st_802154_ral.h"
#include "st_802154_ral_callbacks.h"
#include "st_radio.h"

/* Defines ------------------------------------------------------------------*/
#define ARG_UNUSED(x) ((void)(x))


/* typedef -----------------------------------------------------------*/
typedef struct
{
	StRadioFrame_t     ack_frame;
	StRadioFrame_t*	   tx_frame;
} tx_data_t;

typedef struct
{
	uint8_t channel;
} rx_data_t;

typedef struct
{
	StMacCbkDispatchTbl_t*    cbk_dispatch_tbl; //callbacks to st_mac.c
	tx_data_t 			      tx;
	rx_data_t 			      rx;
} mac_port_context_t;


/*  variables ---------------------------------------------------------*/
static mac_port_context_t mac_port_ctx;


/*---------------------- Private functions -----------------------------------------------*/

/*This function is opposite of st_ral_error_from_ot_error implemented in st_ral.c*/
static StRadioError map_st_ral_error_to_st_radio_error(st_802154_ral_error_t    aStRalError)
{
	StRadioError st_radio_error;

	switch (aStRalError)
	{
		case ST_802154_RAL_ERROR_NONE:
			st_radio_error = ST_RADIO_ERROR_NONE;
			break;

		case ST_802154_RAL_ERROR_FAILED:
			st_radio_error = ST_RADIO_ERROR_FAILED;
			break;

		case ST_802154_RAL_ERROR_DROP:
			st_radio_error = ST_RADIO_ERROR_FAILED;
			break;

		case ST_802154_RAL_ERROR_NO_BUFS:
			st_radio_error = ST_RADIO_ERROR_NO_BUFS;
			break;

		case ST_802154_RAL_ERROR_BUSY:
			st_radio_error = ST_RADIO_ERROR_BUSY;
			break;

		case ST_802154_RAL_ERROR_INVALID_ARGS:
			st_radio_error = ST_RADIO_ERROR_INVALID_ARGS;
			break;

		case ST_802154_RAL_ERROR_SECURITY:
			st_radio_error = ST_RADIO_ERROR_SECURITY;
			break;

		case ST_802154_RAL_ERROR_NO_ADDRESS:
			st_radio_error = ST_RADIO_ERROR_NO_ADDRESS;
			break;

		case ST_802154_RAL_ERROR_ABORT:
			st_radio_error = ST_RADIO_ERROR_ABORT;
			break;

		case ST_802154_RAL_ERROR_NOT_IMPLEMENTED:
			st_radio_error = ST_RADIO_ERROR_NOT_IMPLEMENTED;
			break;

		case ST_802154_RAL_ERROR_INVALID_STATE:
			st_radio_error = ST_RADIO_ERROR_INVALID_STATE;
			break;

		case ST_802154_RAL_ERROR_NO_ACK:
			st_radio_error = ST_RADIO_ERROR_NO_ACK;
			break;

		case ST_802154_RAL_ERROR_CHANNEL_ACCESS_FAILURE:
			st_radio_error = ST_RADIO_ERROR_CHANNEL_ACCESS_FAILURE;
			break;

		case ST_802154_RAL_ERROR_FCS:
			st_radio_error = ST_RADIO_ERROR_FCS;
			break;

		case ST_802154_RAL_ERROR_NO_FRAME_RECEIVED:
			st_radio_error = ST_RADIO_ERROR_NO_FRAME_RECEIVED;
			break;

		case ST_802154_RAL_ERROR_INVALID_SOURCE_ADDRESS:
			st_radio_error = ST_RADIO_ERROR_INVALID_SOURCE_ADDRESS;
			break;

		case ST_802154_RAL_ERROR_DESTINATION_ADDRESS_FILTERED:
			st_radio_error = ST_RADIO_ERROR_DESTINATION_ADDRESS_FILTERED;
			break;

		case ST_802154_RAL_ERROR_NOT_FOUND:
			st_radio_error = ST_RADIO_ERROR_NOT_FOUND;
			break;

		case ST_802154_RAL_ERROR_GENERIC:
			st_radio_error = ST_RADIO_ERROR_GENERIC;
			break;

		case ST_802154_RAL_ERROR_UNKNOWN:
		default:
			st_radio_error = ST_RADIO_ERROR_FAILED;
			break;
	}

	return st_radio_error;
}


static StRadioState map_st_ral_state_to_st_radio_state(st_802154_ral_state_t    a_st_ral_state)
{
	StRadioState st_state;

	switch(a_st_ral_state)
	{
		case ST_802154_RAL_STATE_SLEEP:
			st_state = ST_RADIO_STATE_SLEEP;
			break;

		case  ST_802154_RAL_STATE_TRANSMIT:
			st_state = ST_RADIO_STATE_TRANSMIT;
			break;

		case ST_802154_RAL_STATE_RECEIVE:
			st_state = ST_RADIO_STATE_RECEIVE;
			break;

		case ST_802154_RAL_STATE_DISABLED:
		default:
			st_state = ST_RADIO_STATE_DISABLED;
			break;
	}

	return st_state;
}


/*not needed for zigbee or OT*/
static void st_802154_ral_cca_done_cbk(uint8_t    error)
{
	ARG_UNUSED(error);
}


static void st_802154_ral_tx_started_cbk(uint64_t a_Timestamp)
{
    ARG_UNUSED(a_Timestamp);
	mac_port_ctx.cbk_dispatch_tbl->st_mac_tx_strtd(mac_port_ctx.tx.tx_frame);
}


static void st_802154_ral_transmit_done_cbk(uint8_t*    p_frame,
											st_802154_ral_error_t    error,
											const st_802154_ral_transmit_done_metadata_t*    p_metadata)
{
	StRadioError    st_radio_error;
	StRadioFrame_t*   ack_frame = NULL;

	ARG_UNUSED(p_frame);

	if(p_metadata->ack_ptr != NULL)
	{
		mac_port_ctx.tx.ack_frame.mPsduPtr = p_metadata->ack_ptr;
		mac_port_ctx.tx.ack_frame.mLength = p_metadata->length;
		mac_port_ctx.tx.ack_frame.mChannel = p_metadata->ack_channel;
		mac_port_ctx.tx.ack_frame.mInfo.mRxInfo.mRssi = p_metadata->power;
		mac_port_ctx.tx.ack_frame.mInfo.mRxInfo.mLqi = p_metadata->lqi;
		mac_port_ctx.tx.ack_frame.mInfo.mRxInfo.mTimestamp = p_metadata->time;

		ack_frame = &mac_port_ctx.tx.ack_frame;
	}

	st_radio_error = map_st_ral_error_to_st_radio_error(error);
        
	mac_port_ctx.cbk_dispatch_tbl->st_mac_tx_done(mac_port_ctx.tx.tx_frame,
			                                      ack_frame,
												  st_radio_error);
}


static void st_802154_ral_receive_done_cbk(uint8_t*                                  p_frame,
										   st_802154_ral_receive_done_metadata_t*    p_metadata)
{
	StRadioError      st_radio_error;
	StRadioFrame_t    received_frame;

	received_frame.mPsduPtr = p_frame;
	received_frame.mLength = p_metadata->length;
	received_frame.mChannel = mac_port_ctx.rx.channel;
	received_frame.mInfo.mRxInfo.mLqi = p_metadata->lqi;
	received_frame.mInfo.mRxInfo.mRssi = p_metadata->power;
	received_frame.mInfo.mRxInfo.mTimestamp = p_metadata->time;
	received_frame.mInfo.mRxInfo.mAckedWithFramePending = p_metadata->acked_with_frame_pending;
	st_radio_error = map_st_ral_error_to_st_radio_error(p_metadata->error);

	mac_port_ctx.cbk_dispatch_tbl->st_mac_rx_done(&received_frame, st_radio_error);
}


//not needed for zigbee or OT
static void st_802154_ral_tx_ack_started_cbk(bool    ack_fpb,
											 bool    ack_seb)
{
	ARG_UNUSED(ack_fpb);
	ARG_UNUSED(ack_seb);
}


static void st_802154_ral_energy_scan_done_cbk(int8_t    aMaxEd)
{
	mac_port_ctx.cbk_dispatch_tbl->st_mac_ed_scan_done(aMaxEd);
}


/* ---------------------------------Public functions ---------------------------------------*/
void StRadioInit(void)
{
	st_802154_ral_init();
}


void StRadioCallbackFuncsInit(StMacCbkDispatchTbl_t*    aCbkDispatchTblPtr)
{
	static struct st_802154_ral_cbk_dispatch_tbl ll_cbk_dispatch_tbl =
	{
		.st_802154_ral_cbk_ed_scan_done   = st_802154_ral_energy_scan_done_cbk,
		.st_802154_ral_cbk_tx_done        = st_802154_ral_transmit_done_cbk,
		.st_802154_ral_cbk_rx_done        = st_802154_ral_receive_done_cbk,
		.st_802154_ral_cbk_cca_done       = st_802154_ral_cca_done_cbk,
		.st_802154_ral_cbk_tx_ack_started = st_802154_ral_tx_ack_started_cbk,
		//added
		.st_802154_ral_cbk_tx_started = st_802154_ral_tx_started_cbk,
	};

	/*save mac.c callbacks*/
	mac_port_ctx.cbk_dispatch_tbl = aCbkDispatchTblPtr;

	/*register callbacks with ST RAL*/
	st_802154_ral_call_back_funcs_init(&ll_cbk_dispatch_tbl);
}


StRadioError StRadioReset(void)
{
	StRadioError status = ST_RADIO_ERROR_NONE;

	/*call reset API in ST RAL*/

	status = map_st_ral_error_to_st_radio_error(st_802154_ral_radio_reset());

	return status;
}


StRadioError StRadioTransmit(StRadioFrame_t*    aFramePtr)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

    st_802154_ral_transmit_metadata_t metadata = {
		.is_secured = TRUE,
		.dynamic_data_is_set = 0,
		.cca = aFramePtr->mInfo.mTxInfo.mCsmaCaEnabled,
		.tx_power = aFramePtr->mInfo.mTxInfo.mTxPower,
		.tx_channel = aFramePtr->mChannel,
		.aes_key_ptr = NULL,
		.ie_info_ptr = NULL,
		.tx_delay_base_time = 0,
		.tx_delay = 0,
		.max_csma_backoffs = aFramePtr->mInfo.mTxInfo.mMaxCsmaBackoffs,
		.max_frame_retries = aFramePtr->mInfo.mTxInfo.mMaxFrameRetries,
		.rx_channel_after_tx_done = aFramePtr->mInfo.mTxInfo.mRxChannelAfterTxDone,
		.is_retx = aFramePtr->mInfo.mTxInfo.mIsARetx,
		.csl_present = 0,
		.timestamp = 0
	};
    
	st_ral_error = st_802154_ral_transmit(aFramePtr->mPsduPtr, aFramePtr->mLength, &metadata);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	if (st_radio_error != ST_RADIO_ERROR_NONE) {
		goto func_exit;
	}

	/*need to be saved as they are arguments to tx done callback in mac.c that will be called later*/
	mac_port_ctx.tx.tx_frame = aFramePtr;
	memset(&mac_port_ctx.tx.ack_frame, 0, sizeof(StRadioFrame_t));

func_exit:
	return st_radio_error;
}


void StRadioGetIeeeEui64(uint8_t*    aIeeeEui64Ptr)
{
	st_802154_ral_eui64_get(aIeeeEui64Ptr);
}


void StRadioSetPanId(uint16_t       aPanId)
{
	st_802154_ral_pan_id_set(aPanId);
}


void StRadioSetExtendedAddress(const uint8_t*    aExtAddressPtr)
{
	st_802154_ral_extended_address_set(aExtAddressPtr);
}


void StRadioSetShortAddress(uint16_t    aShortAddress)
{
	st_802154_ral_short_address_set(aShortAddress);
}


/*This API is needed for raw mac*/
StRadioState StRadioGetState(void)
{
	st_802154_ral_state_t    st_ral_state;
	StRadioState             st_radio_state;

	st_ral_state = st_802154_ral_get_state();
	st_radio_state= map_st_ral_state_to_st_radio_state(st_ral_state);

	return st_radio_state;
}


StRadioError StRadioSleep(void)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_sleep();
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


int8_t StRadioGetRssi(void)
{
	return st_802154_ral_get_rssi();
}


bool StRadioGetPromiscuous(void)
{
	return st_802154_ral_promiscuous_get();
}


void StRadioSetPromiscuous(bool    aEnable)
{
	st_802154_ral_promiscuous_set(aEnable);
}


void StRadioSetPanCoordinator(bool    aEnable)
{
	st_802154_ral_pan_coord_set(aEnable);
}


void StRadioSetContinuousReception(bool    aEnable)
{
	st_802154_ral_set_continuous_reception(aEnable);
}

StRadioError StRadioReceive(uint8_t    aChannel)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_receive(aChannel);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	if (st_ral_error != ST_802154_RAL_ERROR_NONE)
	{
		goto func_exit;
	}
	mac_port_ctx.rx.channel = aChannel;

func_exit:
	return st_radio_error;
}


void StRadioSetMaxFrmRetries(uint8_t    aValue)
{
	st_802154_ral_set_max_frame_retries(aValue);
}


void StRadioSetMinCsmaBe(uint8_t    aValue)
{
	st_802154_ral_set_min_csma_be(aValue);
}


void StRadioSetMaxCsmaBe(uint8_t    aValue)
{
	st_802154_ral_set_max_csma_be(aValue);
}


void StRadioSetMaxCsmaBackoff(uint8_t    aValue)
{
	st_802154_ral_set_max_csma_backoff(aValue);
}


void StRadioSetMaxFullCsmaFrmRetries(uint8_t    aValue)
{
	st_802154_ral_set_max_csma_frame_retries(aValue);
}


StRadioError StRadioEnergyScan(uint8_t        aScanChannel,
							   uint16_t       aScanDuration)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_802154_ral_scan_ed_metadata_t metadata = {
		.channel = aScanChannel
	};

	st_ral_error = st_802154_ral_energy_detection(aScanDuration, &metadata);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	if (st_ral_error != ST_802154_RAL_ERROR_NONE)
	{
		goto func_exit;
	}

func_exit:
	return st_radio_error;
}


void StRadioEnableSrcMatch(bool    aEnable)
{
	st_802154_ral_auto_pending_bit_set(aEnable);
}


StRadioError StRadioAddSrcMatchShortEntry(const uint16_t    aShortAddress)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_pending_bit_for_short_addr_set(aShortAddress);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


StRadioError StRadioAddSrcMatchExtEntry(uint8_t*    aExtAddressPtr)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_pending_bit_for_ext_addr_set((const uint8_t*)aExtAddressPtr);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


StRadioError StRadioClearSrcMatchShortEntry(const uint16_t    aShortAddress)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_pending_bit_for_short_addr_clear(aShortAddress);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


StRadioError StRadioClearSrcMatchExtEntry(uint8_t* aExtAddressPtr)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_pending_bit_for_ext_addr_clear((const uint8_t*)aExtAddressPtr);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


void StRadioClearSrcMatchShortEntries(void)
{
	st_802154_ral_pending_bit_for_short_addr_reset();
}


void StRadioClearSrcMatchExtEntries(void)
{
	st_802154_ral_pending_bit_for_ext_addr_reset();
}


StRadioError StRadioGetTransmitPower(int8_t*    aPower)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_tx_power_get(aPower);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


StRadioError StRadioSetTransmitPower(int8_t aPower)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_tx_power_set(aPower);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


StRadioError StRadioGenRndNum(uint8_t*     aRndPtr,
		                      uint16_t     aLength,
							  bool         aCheckContRx)
{
	StRadioError             st_radio_error;
	st_802154_ral_error_t    st_ral_error;

	st_ral_error = st_802154_ral_mac_gen_rnd_num(aRndPtr, aLength, aCheckContRx);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


StRadioError StRadioGetCcaEnergyDetectThreshold(int8_t*    aThresholdPtr)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_get_cca_energy_detect_threshold(aThresholdPtr);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


StRadioError StRadioSetCcaEnergyDetectThreshold(int8_t    aThreshold)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_set_cca_energy_detect_threshold(aThreshold);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}

#if SUPPORT_ZIGBEE_PHY_CERTIFICATION
uint8_t StRadioGetLqiValue(void)
{
	return st_802154_ral_get_lqi_value();
}
#endif /*SUPPORT_ZIGBEE_PHY_CERTIFICATION*/

StRadioError StRadioZigbeeSetPhyContModulMode(uint8_t     aType,
                                              uint8_t     aEnableMode,
											  uint8_t     aChannel,
											  int8_t      aPwr)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_platform_zigbee_set_phy_cont_modul_mode(aType, aEnableMode, aChannel, aPwr);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


void StRadioSetImplicitBroadcast(uint8_t    aImplicitBroadcast)
{
	st_802154_ral_set_implicit_broadcast(aImplicitBroadcast);
}


void StRadioSetCsmaEnable(uint8_t    aCsmaEnable)
{
	st_802154_ral_set_csma_en(aCsmaEnable);
}


uint8_t StRadioGetCsmaEnable(void)
{
	return st_802154_ral_get_csma_en();
}


void StRadioSetCcaEnable(uint8_t    aCcaEnable)
{
	st_802154_ral_set_cca_en(aCcaEnable);
}


uint8_t StRadioGetCcaEnable(void)
{
	return st_802154_ral_get_cca_en();
}


StRadioError StRadioSetAntDivParams(antenna_diversity_st*    aAntDivParamsPtr)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_set_ant_div_params( aAntDivParamsPtr);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


void StRadioGetAntDivParams(antenna_diversity_st*     aAntDivParamsPtr)
{
	st_802154_ral_get_ant_div_params(aAntDivParamsPtr);
}


StRadioError StRadioSetAntDivEnable(bool    aEnable)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_set_ant_div_enable(aEnable);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


StRadioError StRadioSetDefaultAntId(uint8_t    aDefaultAntId)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_set_default_ant_id(aDefaultAntId);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


StRadioError StRadioSetAntDivRssiThreshold(int8_t    aRssiThreshold)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_set_ant_div_rssi_threshold(aRssiThreshold);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


StRadioError StRadioSetConfigLibParams(bool    aSupportOpenthread,
                                       bool    aMacLayerBuild,
									   bool    aAckAllReceivedFramesWithArBitSet)
{
	st_802154_ral_error_t    st_ral_error;
	StRadioError             st_radio_error;

	st_ral_error = st_802154_ral_set_config_lib_params(aSupportOpenthread,
                                                       aMacLayerBuild,
									                   aAckAllReceivedFramesWithArBitSet);
	st_radio_error = map_st_ral_error_to_st_radio_error(st_ral_error);

	return st_radio_error;
}


void StRadioGetConfigLibParams(bool*    aSupportOpenthreadPtr,
                               bool*    aMacLayerBuildPtr,
							   bool*    aAckAllReceivedFramesWithArBitSetPtr)
{

	st_802154_ral_get_config_lib_params(aSupportOpenthreadPtr,
			                            aMacLayerBuildPtr,
										aAckAllReceivedFramesWithArBitSetPtr);
}


void StRadioSetRtlPollingTime(uint8_t    aRtlPollingTime)
{

	st_802154_ral_set_rtl_polling_time(aRtlPollingTime);
}


uint8_t StRadioGetRtlPollingTime(void)
{
	return st_802154_ral_get_rtl_polling_time();
}
