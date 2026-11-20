/**
  ******************************************************************************
  * @file    thread_radio_port.c
  * @author  802.15.4 Team
  * @brief   Porting layer for Open Thread to the 802.15.4 ST RAL for Cube
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
#include <ot_inc/instance.h>
#include <ot_inc/radio.h>

#include "common_types.h"
#include "platform.h"
#include <string.h>
#include "st_802154_ral.h"
#include "st_802154_ral_callbacks.h"


/* Defines ------------------------------------------------------------------*/
#define ARG_UNUSED(x) ((void)(x))


/* typedef -----------------------------------------------------------*/
typedef struct
{
	otRadioFrame 			    ack_frame;
	otRadioFrame*			    tx_frame;
} tx_data_t;

typedef struct
{
	uint8_t channel;
} rx_data_t;

typedef struct
{
	struct mac_cbk_dispatch_tbl*    cbk_dispatch_tbl; //callbacks to mac.c
	tx_data_t 			            tx;
	rx_data_t 			            rx;
	otInstance* 			        instance;
} mac_port_context_t;


/*  variables ---------------------------------------------------------*/
static mac_port_context_t mac_port_ctx;


/* Global and extern variables -----------------------------------------------*/
extern otRadioFrame * allocate_radio_frame(void);



/*---------------------- Private functions -----------------------------------------------*/

/*This function is opposite of st_ral_error_from_ot_error implemented in st_ral.c*/
static otError map_st_ral_error_to_ot_error(st_802154_ral_error_t    a_st_ral_error)
{
	otError ot_error;

	switch (a_st_ral_error)
	{
		case ST_802154_RAL_ERROR_NONE:
			ot_error = OT_ERROR_NONE;
			break;

		case ST_802154_RAL_ERROR_FAILED:
			ot_error = OT_ERROR_FAILED;
			break;

		case ST_802154_RAL_ERROR_DROP:
			ot_error = OT_ERROR_FAILED;
			break;

		case ST_802154_RAL_ERROR_NO_BUFS:
			ot_error = OT_ERROR_NO_BUFS;
			break;

		case ST_802154_RAL_ERROR_BUSY:
			ot_error = OT_ERROR_BUSY;
			break;

		case ST_802154_RAL_ERROR_INVALID_ARGS:
			ot_error = OT_ERROR_INVALID_ARGS;
			break;

		case ST_802154_RAL_ERROR_SECURITY:
			ot_error = OT_ERROR_SECURITY;
			break;

		case ST_802154_RAL_ERROR_NO_ADDRESS:
			ot_error = OT_ERROR_NO_ADDRESS;
			break;

		case ST_802154_RAL_ERROR_ABORT:
			ot_error = OT_ERROR_ABORT;
			break;

		case ST_802154_RAL_ERROR_NOT_IMPLEMENTED:
			ot_error = OT_ERROR_NOT_IMPLEMENTED;
			break;

		case ST_802154_RAL_ERROR_INVALID_STATE:
			ot_error = OT_ERROR_INVALID_STATE;
			break;

		case ST_802154_RAL_ERROR_NO_ACK:
			ot_error = OT_ERROR_NO_ACK;
			break;

		case ST_802154_RAL_ERROR_CHANNEL_ACCESS_FAILURE:
			ot_error = OT_ERROR_CHANNEL_ACCESS_FAILURE;
			break;

		case ST_802154_RAL_ERROR_FCS:
			ot_error = OT_ERROR_FCS;
			break;

		case ST_802154_RAL_ERROR_NO_FRAME_RECEIVED:
			ot_error = OT_ERROR_NO_FRAME_RECEIVED;
			break;

		case ST_802154_RAL_ERROR_INVALID_SOURCE_ADDRESS:
			ot_error = OT_ERROR_INVALID_SOURCE_ADDRESS;
			break;

		case ST_802154_RAL_ERROR_DESTINATION_ADDRESS_FILTERED:
			ot_error = OT_ERROR_DESTINATION_ADDRESS_FILTERED;
			break;

		case ST_802154_RAL_ERROR_NOT_FOUND:
			ot_error = OT_ERROR_NOT_FOUND;
			break;

		case ST_802154_RAL_ERROR_GENERIC:
			ot_error = OT_ERROR_GENERIC;
			break;

		case ST_802154_RAL_ERROR_UNKNOWN:
		default:
			ot_error = OT_ERROR_FAILED;
			break;
	}

	return ot_error;
}


static otRadioState map_st_ral_state_to_ot_state(st_802154_ral_state_t    a_st_ral_state)
{
	otRadioState ot_state;

	switch(a_st_ral_state)
	{
		case ST_802154_RAL_STATE_SLEEP:
			ot_state = OT_RADIO_STATE_SLEEP;
			break;

		case  ST_802154_RAL_STATE_TRANSMIT:
			ot_state = OT_RADIO_STATE_TRANSMIT;
			break;

		case ST_802154_RAL_STATE_RECEIVE:
			ot_state = OT_RADIO_STATE_RECEIVE;
			break;

		case ST_802154_RAL_STATE_DISABLED:
		default:
			ot_state = OT_RADIO_STATE_DISABLED;
			break;
	}

	return ot_state;
}


/*not needed for zigbee or OT*/
static void st_802154_ral_cca_done_cbk(uint8_t    error)
{
	ARG_UNUSED(error);
}


static void st_802154_ral_tx_started_cbk(uint64_t a_Timestamp)
{
	mac_port_ctx.tx.tx_frame->mInfo.mTxInfo.mTimestamp = a_Timestamp;
	mac_port_ctx.cbk_dispatch_tbl->mac_tx_strtd(mac_port_ctx.instance,
												mac_port_ctx.tx.tx_frame);
}


static void st_802154_ral_transmit_done_cbk(
				uint8_t*                                             p_frame,
				st_802154_ral_error_t                                error,
				const st_802154_ral_transmit_done_metadata_t*        p_metadata)
{
	otError          ot_error;
	otRadioFrame*    ack_frame = NULL;

	/*These flags are updated by ST RAL*/
	mac_port_ctx.tx.tx_frame->mInfo.mTxInfo.mIsSecurityProcessed = p_metadata->is_secured;
	mac_port_ctx.tx.tx_frame->mInfo.mTxInfo.mIsHeaderUpdated = p_metadata->dynamic_data_is_set;

	/*
	* ST RAL transmits a private copy of the OpenThread frame.
	* Return the ST RAL-updated CSL/security header, frame counter, ...etc
	* to the OpenThread-owned frame before reporting TX completion.
	*/
	MEMCPY(mac_port_ctx.tx.tx_frame->mPsdu, p_frame, mac_port_ctx.tx.tx_frame->mLength);

	if(p_metadata->ack_ptr != NULL)
	{
		mac_port_ctx.tx.ack_frame.mPsdu = p_metadata->ack_ptr;
		mac_port_ctx.tx.ack_frame.mLength = p_metadata->length;
		mac_port_ctx.tx.ack_frame.mChannel = p_metadata->ack_channel;
		mac_port_ctx.tx.ack_frame.mInfo.mRxInfo.mRssi = p_metadata->power;
		mac_port_ctx.tx.ack_frame.mInfo.mRxInfo.mLqi = p_metadata->lqi;
		mac_port_ctx.tx.ack_frame.mInfo.mRxInfo.mTimestamp = p_metadata->time;

		ack_frame = &mac_port_ctx.tx.ack_frame;

	}

	ot_error = map_st_ral_error_to_ot_error(error);

	mac_port_ctx.cbk_dispatch_tbl->mac_tx_done(mac_port_ctx.instance,
												   mac_port_ctx.tx.tx_frame,
												   ack_frame,
												   ot_error);
}


static void st_802154_ral_receive_done_cbk(
				uint8_t*                                  p_frame,
				st_802154_ral_receive_done_metadata_t*    p_metadata)
{
	otError         ot_error;
	otRadioFrame    received_frame;

	received_frame.mPsdu = p_frame;
	received_frame.mLength = p_metadata->length;
	received_frame.mChannel = mac_port_ctx.rx.channel;
	received_frame.mInfo.mRxInfo.mLqi = p_metadata->lqi;
	received_frame.mInfo.mRxInfo.mRssi = p_metadata->power;
	received_frame.mInfo.mRxInfo.mTimestamp = p_metadata->time;
	received_frame.mInfo.mRxInfo.mAckedWithFramePending = p_metadata->acked_with_frame_pending;
	received_frame.mInfo.mRxInfo.mAckedWithSecEnhAck = p_metadata->acked_with_sec_enh_ack;
	received_frame.mInfo.mRxInfo.mAckFrameCounter = p_metadata->ack_frame_counter;
	received_frame.mInfo.mRxInfo.mAckKeyId = p_metadata->ack_key_id;
	ot_error = map_st_ral_error_to_ot_error(p_metadata->error);

	mac_port_ctx.cbk_dispatch_tbl->mac_rx_done(mac_port_ctx.instance,
											   &received_frame,
											   ot_error);
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
	mac_port_ctx.cbk_dispatch_tbl->mac_ed_scan_done(mac_port_ctx.instance, aMaxEd);
}


/* ---------------------------------Public functions ---------------------------------------*/
void radio_init(void)
{
	st_802154_ral_init();
}


void radio_call_back_funcs_init(struct mac_cbk_dispatch_tbl*    aCbkDispatchTblPtr)
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


otError radio_set_auto_Ack_state(uint8_t    auto_ack_state)
{
	st_802154_ral_error_t    st_ral_error;
	otError                        ot_error;

	st_ral_error = st_802154_ral_set_auto_ack_state(auto_ack_state);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


uint32_t radio_reset(void)
{
	uint32_t status = 0;

	/*call reset API in ST RAL*/
	if (st_802154_ral_radio_reset() != 0)
	{
		status = 1;
	}

	return status;
}


otError otPlatRadioTransmit(otInstance*      aInstancePtr,
							otRadioFrame*    aFramePtr)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

    st_802154_ral_transmit_metadata_t metadata = {
		.is_secured = aFramePtr->mInfo.mTxInfo.mIsSecurityProcessed,
		.dynamic_data_is_set = aFramePtr->mInfo.mTxInfo.mIsHeaderUpdated,
		.cca = aFramePtr->mInfo.mTxInfo.mCsmaCaEnabled,
		.tx_power = aFramePtr->mInfo.mTxInfo.mTxPower,
		.tx_channel = aFramePtr->mChannel,
		//added
        /*FIXME fix as to avoid cast*/
		.aes_key_ptr = (st_802154_ral_mac_key_material*)aFramePtr->mInfo.mTxInfo.mAesKey,
		.ie_info_ptr = (st_802154_ral_ie_info*)aFramePtr->mInfo.mTxInfo.mIeInfo,
		.tx_delay_base_time = aFramePtr->mInfo.mTxInfo.mTxDelayBaseTime,
		.tx_delay = aFramePtr->mInfo.mTxInfo.mTxDelay,
		.max_csma_backoffs = aFramePtr->mInfo.mTxInfo.mMaxCsmaBackoffs,
		.max_frame_retries = aFramePtr->mInfo.mTxInfo.mMaxFrameRetries,
		.rx_channel_after_tx_done = aFramePtr->mInfo.mTxInfo.mRxChannelAfterTxDone,
		.is_retx = aFramePtr->mInfo.mTxInfo.mIsARetx,
		.csl_present = aFramePtr->mInfo.mTxInfo.mCslPresent,
		.timestamp = aFramePtr->mInfo.mTxInfo.mTimestamp
	};
    
	/*need to be saved as they are arguments to tx done callback in mac.c that will be called later*/
	mac_port_ctx.instance = aInstancePtr;
	mac_port_ctx.tx.tx_frame = aFramePtr;
	memset(&mac_port_ctx.tx.ack_frame, 0, sizeof(otRadioFrame));

	st_ral_error = st_802154_ral_transmit(aFramePtr->mPsdu, aFramePtr->mLength, &metadata);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	if (ot_error != OT_ERROR_NONE) {
		goto func_exit;
	}


func_exit:
	return ot_error;
}


void otPlatRadioGetIeeeEui64(otInstance*    aInstancePtr,
		uint8_t *aIeeeEui64Ptr)
{
	ARG_UNUSED(aInstancePtr);

	st_802154_ral_eui64_get(aIeeeEui64Ptr);
}


void otPlatRadioSetPanId(otInstance*    aInstancePtr,
						 uint16_t       aPanId)
{
	ARG_UNUSED(aInstancePtr);

	st_802154_ral_pan_id_set(aPanId);
}


void otPlatRadioSetExtendedAddress(otInstance*            aInstancePtr,
								   const otExtAddress*    aExtAddressPtr)
{
	ARG_UNUSED(aInstancePtr);

	st_802154_ral_extended_address_set(aExtAddressPtr->m8);
}


void otPlatRadioSetShortAddress(otInstance*    aInstancePtr,
		                        uint16_t       aShortAddress)
{
	ARG_UNUSED(aInstancePtr);

	st_802154_ral_short_address_set(aShortAddress);
}


/*This API is needed for raw mac*/
otRadioState otPlatRadioGetState(otInstance*    aInstance)
{
	st_802154_ral_state_t    st_ral_state;
	otRadioState             ot_state;

	ARG_UNUSED(aInstance);

	st_ral_state = st_802154_ral_get_state();
	ot_state= map_st_ral_state_to_ot_state(st_ral_state);

	return ot_state;
}


otError otPlatRadioEnable(otInstance*    aInstance)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_enable();
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


otError otPlatRadioDisable(otInstance*    aInstance)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_disable();
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


bool otPlatRadioIsEnabled(otInstance*    aInstance)
{
	bool is_enabled;

	ARG_UNUSED(aInstance);

	is_enabled = st_802154_ral_is_enabled();

	return is_enabled;
}


otError otPlatRadioSleep(otInstance*    aInstancePtr)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstancePtr);

	st_ral_error = st_802154_ral_sleep();
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


int8_t otPlatRadioGetRssi(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	return st_802154_ral_get_rssi();
}


otRadioCaps otPlatRadioGetCaps(otInstance*    aInstance)
{
	otRadioCaps caps;

	ARG_UNUSED(aInstance);

	caps = (otRadioCaps)(st_802154_ral_get_capabilities());

	return caps;
}


bool otPlatRadioGetPromiscuous(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	return st_802154_ral_promiscuous_get();
}


void otPlatRadioSetPromiscuous(otInstance*    aInstancePtr,
							   bool           aEnable)
{
	ARG_UNUSED(aInstancePtr);

	st_802154_ral_promiscuous_set(aEnable);
}


int8_t otPlatRadioGetReceiveSensitivity(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	return st_802154_ral_get_receive_sensitivity();
}


otError otPlatRadioReceive(otInstance*    aInstancePtr,
						   uint8_t        aChannel)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	st_ral_error = st_802154_ral_receive(aChannel);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	if (st_ral_error != ST_802154_RAL_ERROR_NONE)
	{
		goto func_exit;
	}

	mac_port_ctx.instance = aInstancePtr;
	mac_port_ctx.rx.channel = aChannel;

func_exit:
	return ot_error;
}


void set_min_csma_be(uint8_t aValue)
{
	st_802154_ral_set_min_csma_be(aValue);
}


void set_max_csma_be(uint8_t aValue)
{
	st_802154_ral_set_max_csma_be(aValue);
}


void set_max_csma_backoff(uint8_t aValue)
{
	st_802154_ral_set_max_csma_backoff(aValue);
}


otError otPlatRadioEnergyScan(otInstance*    aInstancePtr,
							  uint8_t        aScanChannel,
							  uint16_t       aScanDuration)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	//added
	st_802154_ral_scan_ed_metadata_t metadata = {
		.channel = aScanChannel
	};

	st_ral_error = st_802154_ral_energy_detection(aScanDuration, &metadata);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	if (st_ral_error != ST_802154_RAL_ERROR_NONE)
	{
		goto func_exit;
	}

	mac_port_ctx.instance = aInstancePtr;

func_exit:
	return ot_error;
}


void otPlatRadioEnableSrcMatch(otInstance*    aInstancePtr,
		                       bool           aEnable)
{
	ARG_UNUSED(aInstancePtr);

	st_802154_ral_auto_pending_bit_set(aEnable);
}


otError otPlatRadioAddSrcMatchShortEntry(otInstance*       aInstancePtr,
										 const uint16_t    aShortAddress)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstancePtr);

	st_ral_error = st_802154_ral_pending_bit_for_short_addr_set(aShortAddress);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


otError otPlatRadioAddSrcMatchExtEntry(otInstance*            aInstancePtr,
									   const otExtAddress*    aExtAddressPtr)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstancePtr);

	st_ral_error = st_802154_ral_pending_bit_for_ext_addr_set((const uint8_t*)aExtAddressPtr);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


otError otPlatRadioClearSrcMatchShortEntry(otInstance*       aInstancePtr,
										   const uint16_t    aShortAddress)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstancePtr);

	st_ral_error = st_802154_ral_pending_bit_for_short_addr_clear(aShortAddress);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


otError otPlatRadioClearSrcMatchExtEntry(otInstance*    aInstancePtr,
										 const otExtAddress*    aExtAddressPtr)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstancePtr);

	st_ral_error = st_802154_ral_pending_bit_for_ext_addr_clear((const uint8_t*)aExtAddressPtr);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


void otPlatRadioClearSrcMatchShortEntries(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	st_802154_ral_pending_bit_for_short_addr_reset();
}


void otPlatRadioClearSrcMatchExtEntries(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	st_802154_ral_pending_bit_for_ext_addr_reset();
}


otError otPlatRadioGetTransmitPower(otInstance*    aInstancePtr,
									int8_t*        aPower)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstancePtr);

	st_ral_error = st_802154_ral_tx_power_get(aPower);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


otError otPlatRadioSetTransmitPower(otInstance*    aInstancePtr,
									int8_t aPower)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstancePtr);

	st_ral_error = st_802154_ral_tx_power_set(aPower);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


uint32_t mac_gen_rnd_num(uint8_t*    aPtrRnd,
						 uint16_t    aLen,
						 uint8_t     aCheckContRx)
{
	uint32_t                 status = SUCCESS;
	st_802154_ral_error_t    st_ral_error;

	st_ral_error = st_802154_ral_mac_gen_rnd_num(aPtrRnd, aLen, aCheckContRx);

	if(ST_802154_RAL_ERROR_NONE != st_ral_error)
	{
		status = 1;
	}

	return status;
}


otError otPlatRadioGetCcaEnergyDetectThreshold(otInstance*    aInstancePtr,
											   int8_t*        aThresholdPtr)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstancePtr);

	st_ral_error = st_802154_ral_get_cca_energy_detect_threshold(aThresholdPtr);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


otError otPlatRadioSetCcaEnergyDetectThreshold(otInstance*    aInstancePtr,
											   int8_t         aThreshold)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstancePtr);

	st_ral_error = st_802154_ral_set_cca_energy_detect_threshold(aThreshold);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


otError otPlatRadioGetFemLnaGain(otInstance*    aInstance,
								 int8_t*        aGain)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);
	
	/*FIXME ST RAL to be fixed to remove instance not add it here */
	st_ral_error = st_802154_ral_get_fem_lna_gain(aGain);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


otError otPlatRadioSetFemLnaGain(otInstance*    aInstance,
								 int8_t         aGain)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_set_fem_lna_gain(aGain);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


uint32_t otPlatRadioGetSupportedChannelMask(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	return st_802154_ral_get_supported_channel_mask();
}


uint32_t otPlatRadioGetPreferredChannelMask(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	return st_802154_ral_get_preferred_channel_mask();
}


void otPlatRadioSetMacFrameCounter(otInstance*    aInstance,
								   uint32_t       aMacFrameCounter)
{
	ARG_UNUSED(aInstance);

	st_802154_ral_set_mac_frame_counter(aMacFrameCounter);
}


void otPlatRadioSetMacFrameCounterIfLarger(otInstance*    aInstance,
										   uint32_t       aMacFrameCounter)
{
	ARG_UNUSED(aInstance);

	st_802154_ral_set_mac_frame_counter_if_larger(aMacFrameCounter);
}


void otPlatRadioSetMacKey(otInstance *               aInstance,
                          uint8_t                    aKeyIdMode,
                          uint8_t                    aKeyId,
                          const otMacKeyMaterial*    aPrevKey,
                          const otMacKeyMaterial*    aCurrKey,
                          const otMacKeyMaterial*    aNextKey,
                          otRadioKeyType             aKeyType)
{
	ARG_UNUSED(aInstance);

	st_802154_ral_set_mac_key(aKeyIdMode, aKeyId,
			(const uint8_t*)(&(aPrevKey->mKeyMaterial.mKey)),
			aPrevKey->mKeyMaterial.mKeyRef,
			(const uint8_t*)(&(aCurrKey->mKeyMaterial.mKey)),
			aCurrKey->mKeyMaterial.mKeyRef,
			(const uint8_t*)(&(aNextKey->mKeyMaterial.mKey)),
			aNextKey->mKeyMaterial.mKeyRef,
			(st_802154_ral_key_type_enum_t)aKeyType
	);
}


otError otPlatRadioConfigureEnhAckProbing(otInstance*            aInstance,
										  otLinkMetrics          aLinkMetrics,
										  otShortAddress         aShortAddress,
										  const otExtAddress*    aExtAddress)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_configure_enh_ack_probing(aLinkMetrics.mPduCount, aLinkMetrics.mLqi, aLinkMetrics.mLinkMargin, aLinkMetrics.mRssi,
			aShortAddress, (const uint8_t*)aExtAddress);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


uint64_t otPlatRadioGetNow(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	return st_802154_ral_time_get();
}


uint32_t otPlatRadioGetBusSpeed(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	return st_802154_ral_get_bus_speed();
}


otError otPlatRadioReceiveAt(otInstance*    aInstance,
							 uint8_t        aChannel,
							 uint32_t       aStart,
							 uint32_t       aDuration)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	st_ral_error = st_802154_ral_receive_at(aChannel, aStart, aDuration);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	if (st_ral_error != ST_802154_RAL_ERROR_NONE) {
		goto func_exit;
	}

	mac_port_ctx.instance = aInstance;
	mac_port_ctx.rx.channel = aChannel;

func_exit:
	return ot_error;
}


otError otPlatRadioEnableCsl(otInstance*            aInstance,
                             uint32_t               aCslPeriod,
                             otShortAddress         aShortAddr,
                             const otExtAddress*    aExtAddr)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_enable_csl(aCslPeriod, aShortAddr, (const uint8_t *)aExtAddr);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


otError otPlatRadioResetCsl(otInstance*    aInstance)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_reset_csl();
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


void otPlatRadioUpdateCslSampleTime(otInstance*    aInstance,
									uint32_t       aCslSampleTime)
{
	ARG_UNUSED(aInstance);

	st_802154_ral_update_csl_sample_time(aCslSampleTime);
}


uint8_t otPlatRadioGetCslAccuracy(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	return st_802154_ral_get_csl_accuracy();

}


uint8_t otPlatRadioGetCslUncertainty(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	return st_802154_ral_get_csl_uncertainty();
}


void radio_set_clk_accuracy(uint8_t    clk_acc)
{
	st_802154_ral_set_clk_accuracy(clk_acc);
}


void radio_set_clk_uncertainty(uint8_t    clk_uncer)
{
	st_802154_ral_set_clk_uncertainty(clk_uncer);
}


otError otPlatRadioSetRegion(otInstance*    aInstance,
							 uint16_t       aRegionCode)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_set_region(aRegionCode);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;

}


otError otPlatRadioGetRegion(otInstance*    aInstance,
							 uint16_t*      aRegionCode)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_get_region(aRegionCode);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


otError otPlatRadioSetCoexEnabled(otInstance*    aInstance,
								  bool           aEnabled)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_set_coex_enabled(aEnabled);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


bool otPlatRadioIsCoexEnabled(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	return st_802154_ral_is_coex_enabled();
}


otError otPlatRadioGetCoexMetrics(otInstance*            aInstance,
								  otRadioCoexMetrics*    aCoexMetrics)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

        /*FIXME fix so as to avoid cast*/
	st_ral_error = st_802154_ral_get_coex_metrics((st_802154_ral_coex_metrics*)aCoexMetrics);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


otError radio_set_config_lib_params(otInstance*       aInstance,
									config_lib_st*    ptr_config_lib_params)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_set_config_lib_params(ptr_config_lib_params->support_openthread_1_2,
			ptr_config_lib_params->mac_layer_build, ptr_config_lib_params->ack_all_received_frames_with_ar_bit_set);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


void radio_get_config_lib_params(otInstance*       aInstance,
								 config_lib_st*    ptr_config_lib_params)
{
	ARG_UNUSED(aInstance);

	st_802154_ral_get_config_lib_params((bool*)&(ptr_config_lib_params->support_openthread_1_2),
			(bool*)&(ptr_config_lib_params->mac_layer_build), (bool*)&(ptr_config_lib_params->ack_all_received_frames_with_ar_bit_set));
}


otError otPlatRadioAddCalibratedPower(otInstance*       aInstance,
                                      uint8_t           aChannel,
                                      int16_t           aActualPower,
                                      const uint8_t*    aRawPowerSetting,
                                      uint16_t          aRawPowerSettingLength)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_add_calibrated_power(aChannel,aActualPower, aRawPowerSetting, aRawPowerSettingLength);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


void radio_set_rtl_polling_time(otInstance*    aInstance,
		                        uint8_t        rtl_polling_time)
{
	ARG_UNUSED(aInstance);

	st_802154_ral_set_rtl_polling_time(rtl_polling_time);
}


uint8_t radio_get_rtl_polling_time(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	return st_802154_ral_get_rtl_polling_time();
}


otError otPlatRadioClearCalibratedPowers(otInstance*    aInstance)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_clear_calibrated_power();
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}

otError otPlatRadioSetChannelTargetPower(otInstance*    aInstance,
										 uint8_t        aChannel,
										 int16_t        aTargetPower)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_set_channel_target_power(aChannel, aTargetPower);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


otError otPlatRadioGetRawPowerSetting(otInstance*    aInstance,
									  uint8_t        aChannel,
									  uint8_t*       aRawPowerSetting,
									  uint16_t*      aRawPowerSettingLength)
{
	st_802154_ral_error_t    st_ral_error;
	otError                  ot_error;

	ARG_UNUSED(aInstance);

	st_ral_error = st_802154_ral_get_raw_power_setting(aChannel, aRawPowerSetting, aRawPowerSettingLength);
	ot_error = map_st_ral_error_to_ot_error(st_ral_error);

	return ot_error;
}


void otPlatRadioSetRxOnWhenIdle(otInstance*    aInstance,
								bool           aEnable)
{
	ARG_UNUSED(aInstance);

	st_802154_ral_set_rx_on_when_idle(aEnable);

}


uint32_t otPlatRadioGetBusLatency(otInstance*    aInstance)
{
	ARG_UNUSED(aInstance);

	return st_802154_ral_get_bus_latency();
}


void otPlatRadioSetBusLatency(otInstance*    aInstance,
							  uint32_t       bus_latency)
{
	ARG_UNUSED(aInstance);

	st_802154_ral_set_bus_latency(bus_latency);

}

otRadioFrame * otPlatRadioGetTransmitBuffer(otInstance*    aInstancePtr)
{
	otRadioFrame * TransmitFrame = NULL;

	ARG_UNUSED(aInstancePtr);

	TransmitFrame = allocate_radio_frame();

	return TransmitFrame;
}


//add this to silence keil thread projects build error for undefined symbol mac_destroy
void mac_destroy(void)
{

}
