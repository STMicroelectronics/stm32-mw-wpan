/* Copyright [2009 - 2020] Exegin Technologies Limited. All rights reserved. */

#ifndef LOCAL_ZCL_TUNNEL_H_
#define LOCAL_ZCL_TUNNEL_H_

/* Size of Message commands. */
#define ZCL_TUNNEL_STATUS_MAX_SIZE          6U
#define ZCL_TUNNEL_REQUEST_SIZE             6U
#define ZCL_TUNNEL_RESPONSE_SIZE            5U
#define ZCL_TUNNEL_DATA_ERROR_SIZE          3U
#define ZCL_TUNNEL_DATA_ACK_SIZE            4U
#define ZCL_TUNNEL_DATA_HDR_SIZE            2U

struct ZbZclTunnelProtoT {
    struct LinkListT link; /* LinkList required for keeping list of supported protocols. */
    /* Tunneling protocol description */
    enum ZbZclTunnelProtocolT protocol; /* Protocol ID enumeration. */
    uint16_t mfr; /* Manufacturer ID. */
    uint16_t mtu; /* Protocol's MTU. */
    /* Callbacks */
    struct ZbZclTunnelProtoCbT callbacks;
};

/* Cluster state structure. */
struct ZbZclTunnelStateT {
    struct ZbZclClusterT *cluster; /* The Tunnel Server cluster */
    struct ZbZclTunnelProtoT *proto;
    struct ZbTimerT *timer;
    struct LinkListT link;
    /* Tunnel state and protocol info. */
    uint16_t id; /* Allocated tunnel ID. */
    uint64_t addr; /* Remote address. */
    uint8_t endpoint; /* Remote endpoint. */
    uint8_t flow; /* Flow control enabled for this tunnel. */
    uint16_t mtu; /* Tunnel MTU, and length of space allocated for data. */
    uint32_t length; /* Length of data in the buffer. */
    uint8_t *data; /* Packet receive buffer. */
};

/* Returns ZCL_TUNNEL_STATUS_xxx code */
enum ZclStatusCodeT zcl_tunnel_handle_data(struct ZbZclClusterT *clusterPtr,
    struct ZbZclTunnelStateT *state, struct ZbZclHeaderT *zcl_hdr, struct ZbApsdeDataIndT *aps_ind);
void zcl_tunnel_send_error(struct ZbZclClusterT *clusterPtr, struct ZbApsdeDataIndT *dataIndPtr,
    uint16_t id, enum ZbZclTunnelXferStatusT status);

#endif /* _LOCAL_ZCL_TUNNEL_H_ */
