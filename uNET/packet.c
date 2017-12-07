/*
 * \file packet.c
 *
 */

#include <string.h>
#include "packet.h"
#include "BoardConfig.h"
#include "node.h"

//packet_t buffer_up[UNET_UP_BUF_SIZE];
buffer_ctrl_t pup_ctrl;

packet_t buffer_down[UNET_DOWN_BUF_SIZE];
volatile buffer_ctrl_t pdown_ctrl; // packets down control

packet_t packet_multicast_up;

#define PRINT_PKT(pkt) do{int _i; for(_i=0;_i<sizeof(packet_t);_i++){printf("%d:",((char*)pkt)[_i]);}printf("\n");}while(0)


#if 0 // Under analysis
/************************************************************************************/
/** Memory Management Function */


//! Buffer Down Memory Control
#if (UNET_DOWN_BUF_SIZE <= 8)
uint8_t bdown_memory_ctrl;
#elif (UNET_DOWN_BUF_SIZE <= 16)
uint16_t bdown_memory_ctrl;
#elif (UNET_DOWN_BUF_SIZE <= 32)
uint32_t bdown_memory_ctrl;
#elif (UNET_DOWN_BUF_SIZE <= 64)
uint64_t bdown_memory_ctrl;
#else
#error "Network down buffer size too large, cannot handle it!"
#endif

/**
 * \brief Search in the queue memory for a slot to insert a packet
 * \param memory_ctrl is the pointer that control the memory management
 * \param memory_size is the total length of the buffer
 * \return the vector index that is free
 * \return -1 if no space are available
 */
uint8_t packet_alloc(uint8_t *memory_ctrl, uint8_t memory_size){
	unsigned char i = 0;
	for(i=0; i < memory_size; i++){
		if(!(memory_ctrl&(1<<i))){
			memory_ctrl |= (1<<i);
			return i;
		}
	}
	return -1;
}

/**
 * \brief Free the memory index
 * \param memory_ctrl is the memory management variable
 * \param index is the position of the queue that will be free
 */
void packet_free(uint8_t *memory_ctrl, uint8_t index){
	memory_ctrl &= ~(1<<index);
}

/************************************************************************************/
/** Queue Management Function */

/// TODO make a management system more lightweight and simple

typedef struct{
	packet_t *packet;
	uint8_t packet_index;
	uint8_t next;
	uint8_t previous;
}packet_queue_t;

typedef struct{
	packet_queue_t *head;
	packet_queue_t *tail;
}packet_queue_ctrl_t;


/**
 * \brief Add a packet to the down buffer (FIFO)
 * \param queue structure that control packets order
 * \param *p Pointer to the packet that will be inserted
 * \return WRITE_BUFFER_OK When successfully copied
 * \return NO_AVAILABLE_MEMORY When the buffer is full
 */
uint8_t insert_queue_down(packet_queue_t *queue, packet_t *p){
	uint8_t memory = packet_alloc(bdown_memory_ctrl, UNET_DOWN_BUF_SIZE);
	if(memory == -1) return NO_AVAILABLE_MEMORY;
	queue->packet_index = memory;
	queue->packet = &buffer_down[memory];
	memcpy(queue->packet,p,sizeof(packet_t));
}
#endif


/************************************************************************************/
/************************************************************************************/

/**
 * \brief Add a packet to the down buffer (FIFO)
 * \param *p Pointer to the packet that will be inserted
 * \return WRITE_BUFFER_OK When successfully copied
 * \return NO_AVAILABLE_MEMORY When the buffer is full
 */
uint8_t packet_down_insert(packet_t *p){
	// Check if there is available space
	if(pdown_ctrl.entries < UNET_DOWN_BUF_SIZE){
		pdown_ctrl.entries++;
		memcpy(&buffer_down[pdown_ctrl.end],p,sizeof(packet_t));
		if(++pdown_ctrl.end >= UNET_DOWN_BUF_SIZE) pdown_ctrl.end = 0;
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
uint8_t packet_down_head(packet_t **p){
	// Check if there is any entry in the buffer
	if(pdown_ctrl.entries){
		*p = &buffer_down[pdown_ctrl.start];
		return READ_BUFFER_OK;
	}
	// Buffer empty
	return NO_ENTRY_AVAILABLE;
}

uint8_t packet_down_remove(void){
	if(pdown_ctrl.entries){
		if(++pdown_ctrl.start >= UNET_DOWN_BUF_SIZE) pdown_ctrl.start = 0;
		pdown_ctrl.entries--;
		return WRITE_BUFFER_OK;
	}
	return NO_ENTRY_AVAILABLE;
}

/**
 * \brief Get the next packet to be ACKed
 * \return packet_t* Return the pointer to the packet in the queue
 */
packet_t* packet_down_next_to_ack(){
	packet_t *p;
	do{
		p = &buffer_down[pdown_ctrl.ack];
		if(pdown_ctrl.ack != pdown_ctrl.end){
			if(++pdown_ctrl.ack >= UNET_DOWN_BUF_SIZE) pdown_ctrl.ack = 0;
		}

		/**
		 * If the source of the packet is this device, then it
		 * doesn't need a ACK, so skip this packet
		 */
		if(((uint16_t)(p->packet[MAC_SRC_16] | p->packet[MAC_SRC_16+1]<<8)) !=
				node_data_get_16b(NODE_ADDR16))
		{
			/* check if this packet is pending a ack */
			if(p->state == PACKET_SENDING_ACK){
				// TODO check if this is OK
//				printf("Will ACK %d from %d\n",p->packet[MAC_SEQ_NUM], p->packet[MAC_SRC_16]);
				return p;
			}
		}
	}while(pdown_ctrl.ack != pdown_ctrl.end);
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
///*--------------------------------------------------------------------------------------------*/
//uint8_t packet_acquire_down(void)
//{
//	OS_SR_SAVE_VAR
//	extern packet_t packet_down;
//	/* todo : use a mutex with timeout */
//	OSEnterCritical();
//	if(packet_down.state != PACKET_IDLE)
//	{
//		OSExitCritical();
//		return PACKET_ACCESS_DENIED;
//	}else
//	{
//
//		packet_down.state = PACKET_START_ROUTE;
//		OSExitCritical();
//		return PACKET_ACCESS_ALLOWED;
//	}
//
//}
///*--------------------------------------------------------------------------------------------*/
//void packet_release_down(void)
//{
//	OS_SR_SAVE_VAR
//	extern packet_t packet_down;
//	/* todo : use a mutex */
//	OSEnterCritical();
//	packet_down.state = PACKET_IDLE;
//	OSExitCritical();
//}
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
//packet_state_t packet_state_down(void)
//{
//	extern packet_t packet_down;
//	return packet_down.state;
//}
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

//#include "link.h"
//const char* type_to_string_table[] = {"BCAST\0", "UDOWN\0", "UUP  \0", "ADOWN\0", "AUP  \0", "MUP  \0", "MAUP \0"};
//const char* type_to_string(unet_packet_type_t t){
//	switch(t){
//		case BROADCAST_LOCAL_LINK: 	return type_to_string_table[0];
//		case UNICAST_DOWN: 			return type_to_string_table[1];
//		case UNICAST_UP:  			return type_to_string_table[2];
//		case UNICAST_ACK_DOWN: 		return type_to_string_table[3];
//		case UNICAST_ACK_UP: 		return type_to_string_table[4];
//		case MULTICAST_UP: 			return type_to_string_table[5];
//		case MULTICAST_ACK_UP: 		return type_to_string_table[6];
//	}
//}
//
//const char* header_to_string_table[] = {"NONE\0", "TCP \0", "UDP \0", "CTRL\0", "APP \0", "RESR\0"};
//const char* header_to_string(uint8_t t){
//	switch(t){
//		case NO_NEXT_HEADER:			return header_to_string_table[0];
//		case NEXT_HEADER_TCP:			return header_to_string_table[1];
//		case NEXT_HEADER_UDP:			return header_to_string_table[2];
//		case NEXT_HEADER_UNET_CTRL_MSG: return header_to_string_table[3];
//		case NEXT_HEADER_UNET_APP:		return header_to_string_table[4];
//		case NET_HEADER_RESERVED:		return header_to_string_table[5];
//	}
//}

/**
 * \brief Get all packet information as string formated with the options
 * \param *p Is the packet information
 * \param *str Is where the string will be stored
 */
//void packet_to_string(packet_t *p, char *str){
//	sprintf(str,"[LEN %d][FC %04X][SN %d][PID %04X][D16 %d][S16 %d][PT %s][PAYL %d][NH %s][S %d][D %d][ALEN %d][>%s]",
//			p->packet[PHY_PKT_SIZE],
//			(uint16_t)(p->packet[MAC_FRAME_CTRL] | p->packet[MAC_FRAME_CTRL+1]<<8),
//			p->packet[MAC_SEQ_NUM],
//			(uint16_t)(p->packet[MAC_PANID_16] | p->packet[MAC_PANID_16+1]<<8),
//			(uint16_t)(p->packet[MAC_DEST_16] | p->packet[MAC_DEST_16+1]<<8),
//			(uint16_t)(p->packet[MAC_SRC_16] | p->packet[MAC_SRC_16+1]<<8),
//			type_to_string(p->packet[UNET_PKT_TYPE]),
//			p->packet[UNET_PAYLOAD_LEN],
//			header_to_string(p->packet[UNET_NEXT_HEADER]),
//			(uint8_t)p->packet[UNET_SRC_64+7],
//			(uint8_t)p->packet[UNET_DEST_64+7],
//			p->packet[UNET_APP_PAYLOAD_LEN],
//			&p->packet[UNET_APP_HEADER_START]
//			);
//}
//
//unsigned char packet_string[200];
//void packet_print_info(packet_t *p){
//	packet_to_string(p,packet_string);
//	printf("%s\n",packet_string);
//}
/*--------------------------------------------------------------------------------------------*/
