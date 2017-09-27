/*
 * \file packet.c
 *
 */

#include <string.h>
#include "packet.h"
#include "BoardConfig.h"
#include "node.h"

buffer_ctrl_t pup_ctrl;
packet_t buffer_down[UNET_DOWN_BUF_SIZE];
buffer_ctrl_t pdown_ctrl; // packets down control
packet_t packet_multicast_up;

/************************************************************************************/
/************************************************************************************/

/**
 * \brief Add a packet to the down buffer (FIFO)
 * \param *p Pointer to the packet that will be inserted
 * \return WRITE_BUFFER_OK When successfully copied
 * \return NO_AVAILABLE_MEMORY When the buffer is full
 */
uint8_t add_packet_down(packet_t *p){
	// Check if there is available space
	if(pdown_ctrl.entries < UNET_DOWN_BUF_SIZE){
		pdown_ctrl.entries++;
		memcpy(&(buffer_down[pdown_ctrl.end]),p,sizeof(packet_t));
		if(++pdown_ctrl.end == UNET_DOWN_BUF_SIZE) pdown_ctrl.end = 0;
		return WRITE_BUFFER_OK;
	}
	// Buffer full
	return NO_AVAILABLE_MEMORY;
}

/**
 * \brief Get the first element inserted in the down buffer
 * \param *p Pointer to store the packet that will be read
 * \return READ_BUFFER_OK When successfully copied
 * \return NO_ENTRY_AVAILABLE When there is no entry in the buffer
 */
uint8_t get_packet_down(packet_t *p){
	// Check if there is any entry in the buffer
	if(pdown_ctrl.entries){
		memcpy(p,&(buffer_down[pdown_ctrl.start]),sizeof(packet_t));
		if(++pdown_ctrl.start == UNET_DOWN_BUF_SIZE) pdown_ctrl.start = 0;
		pdown_ctrl.entries--;
		return READ_BUFFER_OK;
	}
	// Buffer empty
	return NO_ENTRY_AVAILABLE;
}


/**
 * \brief If there is any space on buffer, get the end of line
 *        and return it to be used as a packet that will be inserted
 *        in the queue.
 * \return packet_t* Return the last packet not in use in the buffer
 */
packet_t* aquire_packet_down(void){
	packet_t *p = NULL;
	if(!is_buffer_down_full()){
		if(++pdown_ctrl.end == UNET_DOWN_BUF_SIZE) pdown_ctrl.end = 0;
		p = &buffer_down[pdown_ctrl.end];
		pdown_ctrl.entries++;
	}
	return p;
}

/**
 * \brief Just release/remove the first packet
 */
void release_packet_down (void){
	// If there is any entry
	if(pdown_ctrl.entries){
		// Remove it from the queue
		if(++pdown_ctrl.start == UNET_DOWN_BUF_SIZE) pdown_ctrl.start = 0;
		pdown_ctrl.entries--;
	}
}

/**
 * \brief Get the packet address to be able to edit inside the queue
 * \param i Is the packet index inside the queue (eg. pdown_ctrl.start)
 * \return packet_t* Is the address of the packet inside the queue
 * TODO maybe substitute this function to a status update only
 */
packet_t* edit_packet_down(uint8_t i){
	return &buffer_down[i];
}

/**
 * \brief Update the status of the first element of the queue
 * \param s the status that will be set
 */
void update_packet_down_header_status(packet_state_t s){
	buffer_down[pdown_ctrl.ack].state = s;
}

/**
 * \brief Get the next packet to be ACKed
 * \return packet_t* Return the pointer to the packet in the queue
 */
packet_t* next_packet_down_to_ack(){
	packet_t *p;
	while(pdown_ctrl.ack != pdown_ctrl.end){
		p = &buffer_down[pdown_ctrl.ack];
		if(++pdown_ctrl.ack == UNET_DOWN_BUF_SIZE) pdown_ctrl.ack = 0;
		/**
		 * If the source of the packet is this device, then it
		 * doesn't need a ACK, so skip this packet
		 */
		if(((uint16_t)(p->packet[MAC_SRC_16] | p->packet[MAC_SRC_16+1]<<8)) !=
				node_data_get_16b(NODE_ADDR16))
		{
			return p;
		}
	}
	return NULL;
}

/**
 * \brief Set the controller to start of buffer as is clean
 */
void packet_clear_buffer_down(void){
	pdown_ctrl.ack = 0;
	pdown_ctrl.end = 0;
	pdown_ctrl.start = 0;
	pdown_ctrl.entries = 0;
}

/*--------------------------------------------------------------------------------------------*/
uint8_t packet_info_get(packet_t *pkt, packet_info_t opt)
{
	return pkt->info[opt];
}
/*--------------------------------------------------------------------------------------------*/
uint8_t packet_info_set(packet_t *pkt, packet_info_t opt, uint8_t val)
{
	REQUIRE_FOREVER(opt < PKTINFO_MAX_OPT);
	pkt->info[opt] = val;
	return 0;
}

/*--------------------------------------------------------------------------------------------*/
#define PACKET_PRINT_ENABLE   1
void packet_print(uint8_t *pkt, uint8_t len)
{
#if PACKET_PRINT_ENABLE
	while(len > 0)
	{
		len--;
		PRINTF("%02X ", *pkt++);
	}
	PRINTF("\r\n");

#else
	(void)pkt; (void)len;
#endif
}
/*--------------------------------------------------------------------------------------------*/
uint8_t packet_acquire_down(void)
{
	OS_SR_SAVE_VAR
	extern packet_t packet_down;
	/* todo : use a mutex with timeout */
	OSEnterCritical();
	if(packet_down.state != PACKET_IDLE)
	{
		OSExitCritical();
		return PACKET_ACCESS_DENIED;
	}else
	{

		packet_down.state = PACKET_START_ROUTE;
		OSExitCritical();
		return PACKET_ACCESS_ALLOWED;
	}

}
/*--------------------------------------------------------------------------------------------*/
void packet_release_down(void)
{
	OS_SR_SAVE_VAR
	extern packet_t packet_down;
	/* todo : use a mutex */
	OSEnterCritical();
//	packet_down.state = PACKET_IDLE;
	release_packet_down();
	OSExitCritical();
}
/*--------------------------------------------------------------------------------------------*/
uint8_t packet_acquire_up(void)
{
	OS_SR_SAVE_VAR
	extern packet_t packet_up;
	/* todo : use a mutex with timeout */
	OSEnterCritical();
	if(packet_up.state != PACKET_IDLE)
	{
		OSExitCritical();
		return PACKET_ACCESS_DENIED;
	}else
	{
		packet_up.state = PACKET_START_ROUTE;
		OSExitCritical();

		PRINTF_ROUTER(1,"PACKET OWNED BY TASK %s \r\n", ContextTask[currentTask].TaskName);
		return PACKET_ACCESS_ALLOWED;
	}

}
/*--------------------------------------------------------------------------------------------*/
void packet_release_up(void)
{
	OS_SR_SAVE_VAR
	extern packet_t packet_up;
	/* todo : use a mutex */
	OSEnterCritical();
	packet_up.state = PACKET_IDLE;
	OSExitCritical();
}
/*--------------------------------------------------------------------------------------------*/
packet_state_t packet_state_down(void)
{
	extern packet_t packet_down;
	return packet_down.state;
}
/*--------------------------------------------------------------------------------------------*/
packet_state_t packet_state_up(void)
{
	extern packet_t packet_up;
	return packet_up.state;
}
/*--------------------------------------------------------------------------------------------*/
uint16_t packet_get_source_addr16(packet_t *pkt){
	uint16_t addr16;
	addr16 = (pkt->info[PKTINFO_SRC16H]<<8) + pkt->info[PKTINFO_SRC16L];
	return addr16;

}
uint16_t packet_get_dest_addr16(packet_t *pkt){
	uint16_t addr16;
	addr16 = (pkt->info[PKTINFO_DEST16H]<<8) + pkt->info[PKTINFO_DEST16L];
	return addr16;
}
/*--------------------------------------------------------------------------------------------*/

#include "link.h"
const char* type_to_string_table[] = {"BCAST\0", "UDOWN\0", "UUP  \0", "ADOWN\0", "AUP  \0", "MUP  \0", "MAUP \0"};
const char* type_to_string(unet_packet_type_t t){
	switch(t){
		case BROADCAST_LOCAL_LINK: 	return type_to_string_table[0];
		case UNICAST_DOWN: 			return type_to_string_table[1];
		case UNICAST_UP:  			return type_to_string_table[2];
		case UNICAST_ACK_DOWN: 		return type_to_string_table[3];
		case UNICAST_ACK_UP: 		return type_to_string_table[4];
		case MULTICAST_UP: 			return type_to_string_table[5];
		case MULTICAST_ACK_UP: 		return type_to_string_table[6];
	}
}

const char* header_to_string_table[] = {"NONE\0", "TCP \0", "UDP \0", "CTRL\0", "APP \0", "RESR\0"};
const char* header_to_string(uint8_t t){
	switch(t){
		case NO_NEXT_HEADER:			return header_to_string_table[0];
		case NEXT_HEADER_TCP:			return header_to_string_table[1];
		case NEXT_HEADER_UDP:			return header_to_string_table[2];
		case NEXT_HEADER_UNET_CTRL_MSG: return header_to_string_table[3];
		case NEXT_HEADER_UNET_APP:		return header_to_string_table[4];
		case NET_HEADER_RESERVED:		return header_to_string_table[5];
	}
}

/**
 * \brief Get all packet information as string formated with the options
 * \param *p Is the packet information
 * \param *str Is where the string will be stored
 */
void packet_to_string(packet_t *p, char *str){



	sprintf(str,"[LEN %d][FC %04X][SN %d][PID %04X][D16 %d][S16 %d][PT %s][PAYL %d][NH %s][S %d][D %d][ALEN %d][>%s]",
			p->packet[PHY_PKT_SIZE],
			(uint16_t)(p->packet[MAC_FRAME_CTRL] | p->packet[MAC_FRAME_CTRL+1]<<8),
			p->packet[MAC_SEQ_NUM],
			(uint16_t)(p->packet[MAC_PANID_16] | p->packet[MAC_PANID_16+1]<<8),
			(uint16_t)(p->packet[MAC_DEST_16] | p->packet[MAC_DEST_16+1]<<8),
			(uint16_t)(p->packet[MAC_SRC_16] | p->packet[MAC_SRC_16+1]<<8),
			type_to_string(p->packet[UNET_PKT_TYPE]),
			p->packet[UNET_PAYLOAD_LEN],
			header_to_string(p->packet[UNET_NEXT_HEADER]),
			(uint8_t)p->packet[UNET_SRC_64+7],
			(uint8_t)p->packet[UNET_DEST_64+7],
			p->packet[UNET_APP_PAYLOAD_LEN],
			&p->packet[UNET_APP_HEADER_START]
			);
}

unsigned char packet_string[200];
void packet_print_info(packet_t *p){
	packet_to_string(p,packet_string);
	printf("%s\n",packet_string);
}
/*--------------------------------------------------------------------------------------------*/
