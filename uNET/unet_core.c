
/**********************************************************************************
@file   unet_core.c
@brief  UNET tasks code
@authors: Gustavo Weber Denardin
          Carlos Henrique Barriquello

Copyright (c) <2009-2013> <Universidade Federal de Santa Maria>

  * Software License Agreement
  *
  * The Software is owned by the authors, and is protected under 
  * applicable copyright laws. All rights are reserved.
  *
  * The above copyright notice shall be included in
  * all copies or substantial portions of the Software.
  *  
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  * THE SOFTWARE. 
*********************************************************************************/

#include "BRTOS.h"
#include "BoardConfig.h"
#include "stimer.h"
#include "unet_api.h"
#include "string.h"
#include "packet.h"
#include "link.h"
#include "ieee802154.h"
#include "unet_router.h"
#include "transport.h"
#include "trickle.h"

#if ! defined assert
#if WINNT
#include "assert.h"
#else
#define assert(x)   if(!(x)) while(1){};
#endif
#endif

#ifdef assert
#undef assert
#define assert(x)   if(!(x)){ PRINTF("Error: %s:%d\n",__FILE__,__LINE__); UserEnterCritical(); while(1); }
#endif

#define DEBUG_ENABLED
#ifdef DEBUG_ENABLED
#define PRINTD(...) PRINTF(__VA_ARGS__)
#endif

volatile long i;
#define PRINT_WAIT(...) PRINTF(__VA_ARGS__); for(i=0;i<200000;i++)

uint16_t unet_verbose = 0; //UNET_VERBOSE_LEVEL_MAX;

/* payload vector - max. bytes = MAX_APP_PAYLOAD_SIZE */
volatile uint8_t     NWKPayload[MAX_APP_PAYLOAD_SIZE];


#if (NWK_MUTEX_TYPE == BRTOS_MUTEX)
/* Mutex for Radio IEEE 802.15.4 */
BRTOS_Mutex                  *Radio_IEEE802;
int 					radio_int_status = 0;
#endif

/**************************************************************//*!
*
* Global variables
*
******************************************************************/  
BRTOS_Sem* Radio_RX_Event;
BRTOS_Sem* Radio_TX_Event;
BRTOS_Sem* Link_Packet_TX_Event;


BRTOS_Sem* Router_Down_Ack_Request;
BRTOS_Sem* Router_Down_Route_Request;
BRTOS_Sem* Router_Down_Ack_Received;

BRTOS_Sem* Router_Up_Ack_Request;
BRTOS_Sem* Router_Up_Route_Request;
BRTOS_Sem* Router_Up_Ack_Received;

BRTOS_Sem* App_Callback;

BRTOS_TH	TH_RADIO;
BRTOS_TH	TH_MAC;
BRTOS_TH	TH_NETWORK;

#ifdef SIGNAL_APP1
BRTOS_Sem    *(SIGNAL_APP1);
#endif


/* UNET network statistics */
struct netstat_t UNET_NodeStat;
char UNET_NodeStat_Ctrl = 1; // Default: enabled

/* Return a pointer to "UNET_NodeStat" struct */
void * GetUNET_Statistics(uint8_t* tamanho)
{
    if(tamanho == NULL) return NULL;

    *tamanho = sizeof(UNET_NodeStat);
    return (void*)&UNET_NodeStat;
}


#if TASK_WITH_PARAMETERS == 1
void UNET_Radio_Task(void* p);
void UNET_Link_Task(void *p);
void UNET_Router_Down_Ack_Task(void* p);
void UNET_Router_Down_Task(void* p);
void UNET_Router_Up_Ack_Task(void* p);
void UNET_Router_Up_Task(void* p);
#else
void UNET_Radio_Task(void); // ok
void UNET_Link_Task(void); // ok
void UNET_Router_Down_Ack_Task(void);  // ok
void UNET_Router_Down_Task(void);
void UNET_Router_Up_Ack_Task(void);
void UNET_Router_Up_Task(void);
#endif

#if (RUN_TESTS == TRUE)
void UNET_test(void *param);
#endif

#define UNET_RADIO_STACKSIZE   (UNET_DEFAULT_STACKSIZE) + 64

#define UNET_Radio_Task_Priority     10
#define UNET_Link_Task_Priority      9

#define UNET_Router_Down_Ack_Task_Priority  8
#define UNET_Router_Down_Task_Priority      6
#define UNET_Router_Up_Ack_Task_Priority    7
#define UNET_Router_Up_Task_Priority        5

/*----------------------------------------------------------------------------*/
static void UNET_radio_isr_handler(void)
{

	uint8_t state;
	UNET_RADIO.get(RADIO_STATE,&state);

	// NOTE this function is called inside ISR, so it's preferable not use OS_Critical instructions
	//      since the ISR already disable interruptions
	if(is_radio_rxing(state))
	{
		RADIO_STATE_SET(RX_DISABLED); // radio_rx_disabled(TRUE);
		RADIO_STATE_RESET(RX_OK);     // radio_rxing(FALSE); /* clear RX interrupt flag */
		OSSemPost(Radio_RX_Event);
	}
	if(is_radio_txing(state))
	{
		RADIO_STATE_RESET(TX_OK);    // radio_txing(FALSE); /* clear TX interrupt flag */
		OSSemPost(Radio_TX_Event);
	}
}

/*----------------------------------------------------------------------------*/
void RadioReset(void){
	const addr16_t node_addr16 = {.u8 = {MAC16_INIT_VALUE}};
	const addr64_t node_addr64 = {.u8 = {PANID_INIT_VALUE,0x00,0x00,0x00,0x00,MAC16_INIT_VALUE}};
	const uint8_t pan_id_64[8] = {PANID_INIT_VALUE,0x00,0x00,0x00,0x00,0x00,0x00};
	const uint8_t pan_id_16[2] = {PANID_INIT_VALUE};

	UNET_RADIO.init(UNET_radio_isr_handler);

	/* init network and node addresses  */
	node_pan_id64_set((uint8_t*)pan_id_64);
	node_addr64_set((uint8_t*)&node_addr64);

	node_data_set(NODE_ADDR16H,node_addr16.u8[0]);
	node_data_set(NODE_ADDR16L,node_addr16.u8[1]);
	node_data_set(NODE_PANID16H,pan_id_16[0]);
	node_data_set(NODE_PANID16L,pan_id_16[1]);
	node_data_set(NODE_CHANNEL, CHANNEL_INIT_VALUE);
}
/* Function to start all UNET Tasks */
void UNET_Init(void)
{  
	////////////////////////////////////////////////////
	//     Initialize IEEE 802.15.4 radio mutex     ////
	////////////////////////////////////////////////////
	init_resourceRadio(UNET_Mutex_Priority);

#if 0

	/* define network and node addresses  */
	const addr16_t node_addr16 = {.u8 = {MAC16_INIT_VALUE}};
	const addr64_t node_addr64 = {.u8 = {PANID_INIT_VALUE,0x00,0x00,0x00,0x00,MAC16_INIT_VALUE}};
	const uint8_t pan_id_64[8] = {PANID_INIT_VALUE,0x00,0x00,0x00,0x00,0x00,0x00};
	const uint8_t pan_id_16[2] = {PANID_INIT_VALUE};

	UNET_RADIO.init(UNET_radio_isr_handler);

	/* init network and node addresses  */
	node_pan_id64_set((uint8_t*)pan_id_64);
	node_addr64_set((uint8_t*)&node_addr64);

	node_data_set(NODE_ADDR16H,node_addr16.u8[0]);
	node_data_set(NODE_ADDR16L,node_addr16.u8[1]);
	node_data_set(NODE_PANID16H,pan_id_16[0]);
	node_data_set(NODE_PANID16L,pan_id_16[1]);
	node_data_set(NODE_DISTANCE, NODE_DISTANCE_INIT);
	node_data_set(NODE_PARENTINDEX, NO_PARENT);
#endif

  ////////////////////////////////////////////////
  //     Initialize OS Network Services     //////
  ////////////////////////////////////////////////

  /* set the pointer to the first element */
  extern packet_t *packet_down;
  extern packet_t buffer_down[UNET_DOWN_BUF_SIZE];
  packet_down = buffer_down;

  /* UNET signals */
  App_Callback = NULL;
  assert(OSSemCreate(0,&Radio_RX_Event) == ALLOC_EVENT_OK);
  assert(OSSemCreate(0,&Radio_TX_Event) == ALLOC_EVENT_OK);

#ifdef SIGNAL_APP1
 assert(OSSemCreate(0,&(SIGNAL_APP1)) == ALLOC_EVENT_OK);
#endif

  /* Initialize UNET Tasks  */
#if (TASK_WITH_PARAMETERS == 1)
 assert(OSInstallTask(&UNET_Radio_Task,"Radio Handler",UNET_RADIO_STACKSIZE,
		 UNET_Radio_Task_Priority, NULL, &TH_RADIO)== OK);

 assert(OSInstallTask(&UNET_Link_Task,"Link packet TX Task",UNET_DEFAULT_STACKSIZE,
		 UNET_Link_Task_Priority, NULL, NULL)== OK);

 assert(OSInstallTask(&UNET_Router_Down_Ack_Task,"Router down ack TX Task",UNET_DEFAULT_STACKSIZE,
		 UNET_Router_Down_Ack_Task_Priority, NULL, NULL)== OK);

 assert(OSInstallTask(&UNET_Router_Down_Task,"Router down TX Task",UNET_DEFAULT_STACKSIZE,
		 UNET_Router_Down_Task_Priority, NULL, NULL)== OK);

 assert(OSInstallTask(&UNET_Router_Up_Ack_Task,"Router up ack TX Task",UNET_DEFAULT_STACKSIZE,
		 UNET_Router_Up_Ack_Task_Priority, NULL, NULL)== OK);

 assert(OSInstallTask(&UNET_Router_Up_Task,"Router up TX Task",UNET_DEFAULT_STACKSIZE,
		 UNET_Router_Up_Task_Priority, NULL, NULL)== OK);

#if (RUN_TESTS == TRUE)
 assert(OSInstallTask(&UNET_test,"UNET tester",UNET_RADIO_STACKSIZE,
		 UNET_Radio_Task_Priority+1, NULL, NULL)== OK);
#endif

#else /* (TASK_WITH_PARAMETERS == 1) */

 assert(OSInstallTask(&UNET_Radio_Task,"Radio Handler",UNET_RADIO_STACKSIZE,
		 UNET_Radio_Task_Priority, &TH_RADIO)== OK);

 assert(OSInstallTask(&UNET_Link_Task,"Link packet TX Task",UNET_DEFAULT_STACKSIZE,
		 UNET_Link_Task_Priority, NULL)== OK);

 assert(OSInstallTask(&UNET_Router_Down_Ack_Task,"Router down ack TX Task",UNET_DEFAULT_STACKSIZE,
		 UNET_Router_Down_Ack_Task_Priority, NULL)== OK);

 assert(OSInstallTask(&UNET_Router_Down_Task,"Router down TX Task",UNET_DEFAULT_STACKSIZE,
		 UNET_Router_Down_Task_Priority, NULL)== OK);

 assert(OSInstallTask(&UNET_Router_Up_Ack_Task,"Router up ack TX Task",UNET_DEFAULT_STACKSIZE,
		 UNET_Router_Up_Ack_Task_Priority, NULL)== OK);

 assert(OSInstallTask(&UNET_Router_Up_Task,"Router up TX Task",UNET_DEFAULT_STACKSIZE,
		 UNET_Router_Up_Task_Priority, NULL)== OK);

#if (RUN_TESTS == TRUE)
// assert(OSInstallTask(&UNET_test,"UNET tester",UNET_RADIO_STACKSIZE,
//		 UNET_Radio_Task_Priority+1, NULL)== OK);
 asserte((status=OSInstallTask(&UNET_test,"UNET tester",UNET_RADIO_STACKSIZE,
		 UNET_Radio_Task_Priority+1, NULL)) == OK, status);
#endif
#endif

}

#if 1
#define NEIGHBOURHOOD_TIMEOUT	131072
/// Experimental
BRTOS_TIMER neighbourhood_timer;

TIMER_CNT neighbourhood_callback(void)
{
	link_verify_neighbourhood();
	#if UNET_DEVICE_TYPE != PAN_COORDINATOR
	if (link_is_symmetric_parent() == TRUE){
		// Turn on simmetric parent LED
		#if defined BRTOS_PLATFORM
		#if BRTOS_PLATFORM == FRDM_KL25Z
			GPIOPinReset(GPIOB_BASE, GPIO_PIN_19);
		#endif
		#endif
	}else
	{
		// Turn off simmetric parent LED
		#if defined BRTOS_PLATFORM
		#if BRTOS_PLATFORM == FRDM_KL25Z
		GPIOPinSet(GPIOB_BASE, GPIO_PIN_19);
		#endif
		#endif
	}
	#endif
	return (TIMER_CNT)NEIGHBOURHOOD_TIMEOUT;
}

#endif


/** UNET Network Timeout Function */
void BRTOS_TimerHook(void)
{   

#if 0

    IncDepthWatchdog();    
    
    // update throughput stats every one sec
    // keep average of last 8 sec.
    if(++StatTimer >= 1000){
       StatTimer = 0;
       UNET_NodeStat.rxbps = (UNET_NodeStat.rxbps*7 + (UNET_NodeStat.rxedbytes*8))>>3;
       UNET_NodeStat.txbps = (UNET_NodeStat.txbps*7 + (UNET_NodeStat.txedbytes*8))>>3;
       UNET_NodeStat.rxedbytes = 0;
       UNET_NodeStat.txedbytes = 0;
    } 
#endif

}

#if 0
/* UNET Application Handler */
void UNET_APP(void)
{   
	/* todo: execute app task protocol */
}
#endif



/* UNET Link packet TX task */
trickle_t timer_down;
#if TASK_WITH_PARAMETERS == 1
void UNET_Link_Task(void *param)
{
   (void)param;
#else
void UNET_Link_Task(void)
{
#endif
   uint8_t res;
   trickle_t timer;

   REQUIRE_FOREVER(OSSemCreate(0,&Link_Packet_TX_Event) == ALLOC_EVENT_OK);

#if 0
   /* BRTOS Soft Timer Init : start BRTOS Timer Service
      with stack size and priority for the Timer Task */
    OSTimerInit(Timers_StackSize,Timer_Priority);

    // The first verification occurs sooner
    OSTimerSet (&neighbourhood_timer, neighbourhood_callback, 4000);
#endif

   link_neighbor_table_init();

   #define LINK_PACKET_TX_TIME    	  (2000)
   #define MAX_LINK_PACKET_TX_TIME    (131072)

   open_trickle(&timer,LINK_PACKET_TX_TIME,MAX_LINK_PACKET_TX_TIME);

   for (;;)
   {
	    run_trickle(&timer);

		if (OSSemPend(Link_Packet_TX_Event, timer.t) != TIMEOUT)
		{
		  // If this semaphore is post, we must reset all the trickle timers
		  reset_trickle(&timer);

		  // Correct the up routes as soon as possible, if the node has a path to the coordinator
		  if (node_data_get(NODE_DISTANCE) != NODE_DISTANCE_INIT)
		  {
			  reset_trickle(&timer_down);
		  	  OSSemPost(Router_Down_Route_Request);
		  }
		}

		link_packet_create();

		res = unet_packet_output(link_packet_get(), NWK_TX_RETRIES, 100);

		if (res == PACKET_SEND_OK)
		{
			PRINTF_LINK(2,"Link packet transmitted!\n\r");
		}
		else
		{
			UNET_RADIO.get(TX_STATUS, &res);
			PRINTF_LINK(2,"TX FAILED: link packet! Cause: %u\n\r", res);

			UNET_RADIO.get(TX_RETRIES, &res);
			PRINTF_LINK(2,"TX RETRIES: %u\n\r", res);
		}
   }
}


static packet_t Radio_RX_buffer;
#if TASK_WITH_PARAMETERS == 1
void UNET_Radio_Task(void* p)
{
	(void)p;
#else
void UNET_Radio_Task(void)
{
#endif
	/* define network and node addresses  */
	const addr16_t node_addr16 = {.u8 = {MAC16_INIT_VALUE}};
	const addr64_t node_addr64 = {.u8 = {PANID_INIT_VALUE,0x00,0x00,0x00,0x00,MAC16_INIT_VALUE}};
	const uint8_t pan_id_64[8] = {PANID_INIT_VALUE,0x00,0x00,0x00,0x00,0x00,0x00};
	const uint8_t pan_id_16[2] = {PANID_INIT_VALUE};

	uint16_t len;
	uint8_t data;

	UNET_RADIO.init(UNET_radio_isr_handler);

	/* init network and node addresses  */
	node_pan_id64_set((uint8_t*)pan_id_64);
	node_addr64_set((uint8_t*)&node_addr64);

#if BRTOS_ENDIAN == BIG_ENDIAN
	// Big endian                           0   1
	// MSB comes first in the memory Ex.: [ H , L ]
	node_data_set(NODE_ADDR16L,node_addr16.u8[0]);
	node_data_set(NODE_ADDR16H,node_addr16.u8[1]);
	node_data_set(NODE_PANID16L,pan_id_16[0]);
	node_data_set(NODE_PANID16H,pan_id_16[1]);
#else
	// Little endian                        0   1
	// LSB comes first in the memory Ex.: [ L , H ]
	node_data_set(NODE_ADDR16H,node_addr16.u8[0]);
	node_data_set(NODE_ADDR16L,node_addr16.u8[1]);
	node_data_set(NODE_PANID16H,pan_id_16[0]);
	node_data_set(NODE_PANID16L,pan_id_16[1]);
#endif

	node_data_set(NODE_DISTANCE, NODE_DISTANCE_INIT);
	node_data_set(NODE_PARENTINDEX, NO_PARENT);
	node_data_set(NODE_CHANNEL, CHANNEL_INIT_VALUE);
	node_data_set(NODE_SEQ_NUM, node_addr16.u8[0]);/* start with a "random" seq. num. */


	/* Create the advertise packet */
	unet_adv_packet_create();

#if defined TX_POWER_INIT_VALUE
	UNET_RADIO.set(TXPOWER,TX_POWER_INIT_VALUE);
#endif

	radio_rx_autoack(TRUE);

#if 0
	/* todo: colocar o c�digo abaixo em uma fun��o port�vel p/ cada plataforma */
#if defined BRTOS_PLATFORM
#if BRTOS_PLATFORM == FRDM_KL25Z
	// Enables the port clock
	SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOB);

	GPIOPinConfigure(GPIO_PB19_PB19);

	// Enables Drive Strength
	GPIOPadConfigSet (GPIOB_BASE, GPIO_PIN_19, PORT_TYPE_DSE_HIGH);

	// Set port for LED to output
	GPIOPinSet(GPIOB_BASE, GPIO_PIN_19);
	xGPIODirModeSet(GPIOB_BASE, GPIO_PIN_19, xGPIO_DIR_MODE_OUT);
#endif
#endif

#endif

	for(;;)
	{
		OSSemPend(Radio_RX_Event, 0);

		radio_rx_disabled(TRUE);

		UNET_RADIO.recv(&(Radio_RX_buffer.packet[MAC_FRAME_CTRL]),&len);

		REQUIRE_OR_EXIT(((len > 0) && (len < PACKET_END)), exit_on_error);

		NODESTAT_UPDATE(rxed);


#if RADIO_AUTOCRC == TRUE
		/* todo: use only one field for pkt size */
		Radio_RX_buffer.packet[PHY_PKT_SIZE] = len;
		Radio_RX_buffer.info[PKTINFO_SIZE] = len;
#else
		/* todo: use only one field for pkt size */
		Radio_RX_buffer.packet[PHY_PKT_SIZE] = len-2;
		Radio_RX_buffer.info[PKTINFO_SIZE] = len-2;

		Radio_RX_buffer.info[PKTINFO_FCSH] = Radio_RX_buffer.packet[len + 0];
		Radio_RX_buffer.info[PKTINFO_FCSL] = Radio_RX_buffer.packet[len + 1];
#endif

		UNET_RADIO.get(RSSI,&data);
		Radio_RX_buffer.info[PKTINFO_RSSI] = data;
	    UNET_RADIO.get(LQI,&data);
		Radio_RX_buffer.info[PKTINFO_LQI] = data;


		/* prepare packet state */
		Radio_RX_buffer.state = PACKET_BUSY;


		IF_VERBOSE_LEVEL(UNET_VERBOSE_PHY,1,packet_print(&Radio_RX_buffer.packet[MAC_FRAME_CTRL], Radio_RX_buffer.info[PKTINFO_SIZE]));

		if(ieee802154_packet_input(&Radio_RX_buffer) == ACK_REQ_TRUE)
		{
		}

		#if UNET_DEVICE_TYPE != PAN_COORDINATOR
		if (link_is_symmetric_parent() == TRUE){
			// Turn on simmetric parent LED
			#if defined BRTOS_PLATFORM
			#if BRTOS_PLATFORM == FRDM_KL25Z
        		GPIOPinReset(GPIOB_BASE, GPIO_PIN_19);
			#endif
			#endif
		}else
		{
			// Turn off simmetric parent LED
			#if defined BRTOS_PLATFORM
			#if BRTOS_PLATFORM == FRDM_KL25Z
        	GPIOPinSet(GPIOB_BASE, GPIO_PIN_19);
			#endif
			#endif
		}
		#endif

		exit_on_error:
		/* free RX Buffer */
		BUF_CLEAN(Radio_RX_buffer.info);

		radio_rxing(FALSE);

		radio_rx_disabled(FALSE);
	}
}

static packet_ack_t Radio_TX_ACK_down_buffer;
#if TASK_WITH_PARAMETERS == 1
void UNET_Router_Down_Ack_Task(void* p)
{
	(void)p;
#else
void UNET_Router_Down_Ack_Task(void)
{
#endif
//	extern packet_t packet_down;
    packet_t *r;// = &packet_down;
    packet_t *ack = (packet_t *)&Radio_TX_ACK_down_buffer;

    REQUIRE_FOREVER(OSSemCreate(0,&Router_Down_Ack_Request) == ALLOC_EVENT_OK);

	for(;;)
	{
		wait_next_ack_request:
		OSSemPend(Router_Down_Ack_Request, 0);

		/* check if has packets to be ack */
		if((r = packet_down_next_to_ack()) == NULL) goto wait_next_ack_request;

		/* copy packet headers to ack buffer */
		memcpy(ack,r, sizeof(packet_ack_t));

		ack->state = PACKET_WAITING_TX;

		/* packet received, create a link layer ack packet */
		link_packet_create_ack(ack);

		do
		{
			if(unet_packet_output(ack, NWK_TX_RETRIES, 10) == PACKET_SEND_OK)
			{
				ack->state = PACKET_ACKED;
				r->state = PACKET_ACKED;

				PRINTF_ROUTER(1,"TX ACK DOWN, to %u SN %u \r\n", BYTESTOSHORT(ack->info[PKTINFO_DEST16H],ack->info[PKTINFO_DEST16L]),ack->info[PKTINFO_SEQNUM]);
			}else
			{
				/* o ACK pode ter sido enviado com sucesso,
				 * mesmo que o ACK da MAC não tenha sido recebido,
				 * pois o link de lá para cá pode estar ruim.
				 * neste caso, vamos desistir de enviar ACKs por enquanto.
				 * Mesmo assim, o pacote será passado adiante (para roteamento ou entrega),
				 * mas vamos guardar o SN do pacote, para apagar as cópias do mesmo que
				 * eventualmente chegarão aqui. */
				/* todo: isto pode ser removido, pois é só para debug */
				PRINTF_ROUTER(1,"TX ACK DOWN FAILED, to %u SN %u \r\n", BYTESTOSHORT(ack->info[PKTINFO_DEST16H],ack->info[PKTINFO_DEST16L]),ack->info[PKTINFO_SEQNUM]);
				ack->state = PACKET_NOT_ACKED;
				r->state = PACKET_NOT_ACKED;
				break;
			}
		}while(ack->state == PACKET_WAITING_TX);


		/* Só deve atualizar se não for uma duplicada */
		if(r->info[PKTINFO_DUPLICATED] == FALSE){
			/* se chegou até aqui, armazena último numero de sequencia, para ser usado no teste de duplicatas */
			link_set_neighbor_seqnum(r);
		}


		// If there is more packets to be acked, do it first
		if(!is_buffer_down_acked()){
#if UNET_DOWN_BUF_SIZE == 1
			printf("FUCKING ERROR! BUFFER is 1, why is here?????");
#endif
			OSSemPost(Router_Down_Ack_Request);
		}
		else{
			/*
			 * wake up router down to finish managing the packet
			 * it's done this way because the buffer needed to be freed, BUT
			 * if done in this task, this would cause to remove the element
			 * in the middle of the queue (eventually), so to avoid it
			 * the packet is managed in the Down_Task
			 */
			OSSemPost(Router_Down_Route_Request);
		}
	}
}

//packet_t packet_down;// = &packet_down;
#if TASK_WITH_PARAMETERS == 1
void UNET_Router_Down_Task(void* p)
{
	(void)p;
#else
void UNET_Router_Down_Task(void)
{
#endif

	extern packet_t *packet_down;
	uint8_t routing_retries;
    trickle_t timer_down_retry;
    unet_transport_t *server_client = unet_tp_head;

    REQUIRE_FOREVER(OSSemCreate(0,&Router_Down_Route_Request) == ALLOC_EVENT_OK);
    REQUIRE_FOREVER(OSSemCreate(0,&Router_Down_Ack_Received) == ALLOC_EVENT_OK);

	/* todo: choose a good value for ROUTER_ADV_PERIOD_MS */
	#if UNET_DEVICE_TYPE == ROUTER
	#define ROUTER_ADV_PERIOD_MS  	  4000
	#define MAX_ROUTER_ADV_PERIOD_MS  524288
	#else
	#define ROUTER_ADV_PERIOD_MS  	  0
	#define MAX_ROUTER_ADV_PERIOD_MS  0
	#endif

	open_trickle(&timer_down,ROUTER_ADV_PERIOD_MS,MAX_ROUTER_ADV_PERIOD_MS);
	#define TIMEOUT_FOR_ROUTE_AGAIN_DOWN   		(64)
	#define MAX_TIMEOUT_FOR_ROUTE_AGAIN_DOWN    (256)
	open_trickle(&timer_down_retry,TIMEOUT_FOR_ROUTE_AGAIN_DOWN,MAX_TIMEOUT_FOR_ROUTE_AGAIN_DOWN);

	for(;;)
	{
		/* wait ack tx */
		wait_again:
		run_trickle(&timer_down);
		
		if(OSSemPend(Router_Down_Route_Request,timer_down.t) == TIMEOUT)
		{
			/* if no packet sent down after ROUTER_ADV_PERIOD_MS ms, send a router adv
			 * to the pan coordinator */
			#if UNET_DEVICE_TYPE != PAN_COORDINATOR
			if(unet_router_adv() != RESULT_PACKET_SEND_OK)
			{
				goto wait_again;
			}
			#endif
		}else{
			#if UNET_DEVICE_TYPE != PAN_COORDINATOR
			// Isso é necessário para corrigir as rotas, mas e se estiver roteando um pacote?
			// Acredito que é necessário verificar se foi acordado pelo roteamento
			// ou se foi pelas alterações de link. Como verificar se um pacote foi
			// agendado para roteamento? Que teste fazer? O teste de trickle reseted é suficiente?
			// A ideia do trickle reset é a seguinte: quando for acordado por alterações
			// de link, o trickle estará resetado. Daí o pq de só enviar o router_adv nesse caso.
			if ((is_trickle_reseted(&timer_down) == TRUE) && (packet_down->state == PACKET_IDLE)){
				if(unet_router_adv() != RESULT_PACKET_SEND_OK)
				{
					goto wait_again;
				}
			}
			#endif
		}

		// Get a packet from the buffer, if is empty there was some error getting here
		if((packet_down_head(&(packet_down))) == NO_ENTRY_AVAILABLE) goto wait_again;

		/**
		 * Check duplicated packets here, since the packet could be
		 * stored before  but not ACKed,
		 * to the previous radio could be stuck if not emitted the ACK,
		 * in such case the ACK will be returned but the packet
		 * doesn't have to be forwarded
		 */
		if(packet_down->info[PKTINFO_DUPLICATED] == TRUE)
		{
			NODESTAT_UPDATE(dupnet);
			PRINTF_ROUTER(1,"DROP DUP PACKET, to %u SN %u \r\n",
								BYTESTOSHORT(packet_down->info[PKTINFO_DEST16H],
								packet_down->info[PKTINFO_DEST16L]),packet_down->info[PKTINFO_SEQNUM]);
			// Discard packet
			packet_down_remove();
			goto wait_again;
		}

		// If get here called by application when the packet in the first place in queue
		// still being acked, return to wait ack until it's done
		/**
		 * But by priority, if there is any data being processed in the ack_down task,
		 * this task will be only freed when another task is done...
		 * so it shouldn't be a problem.
		 */


		// Não deveria passar o pacote para a camada superior somente se o ack foi
		// recebido com sucesso????
		/* R: se o link daqui para lá estiver muito ruim, o ack pode demorar para ser entregue.
		 * Então é mais eficiente passar o pacote adiante, e descartar as cópias futuras. */

		/* packet is ack'ed (or not), but is not a duplicate, so we can deliver it to next layer or route it */
//		printf("Down [D: %d][S: %d]\n",packet_down.packet[UNET_DEST_64+7],packet_down.packet[UNET_SRC_64+7]);
		if(memcmp(&packet_down->packet[UNET_DEST_64],node_addr64_get(),8) == 0)
		{

//			printf("PACKET FOUND DESTINATION\n");
//			packet_print_info(&packet_down);

			/* isto � s� para debug e pode ser removido futuramente. */
			packet_down->state = PACKET_DELIVERED;

			/* todo: colocar este código em uma função unet_packet_deliver(...) */

			/* get the last unet_tp_head */
			server_client = unet_tp_head;

			if(packet_down->packet[UNET_NEXT_HEADER] == NEXT_HEADER_UNET_APP){
				NODESTAT_UPDATE(netapprx);
				while(server_client != NULL){
					if (server_client->src_port == packet_down->packet[UNET_DEST_PORT]){
						server_client->packet = &(packet_down->packet[UNET_APP_HEADER_START]);
						server_client->payload_size = packet_down->packet[UNET_APP_PAYLOAD_LEN];
						server_client->sender_port = packet_down->packet[UNET_SOURCE_PORT];
						memcpy(&(server_client->sender_address),&(packet_down->packet[UNET_SRC_64]),8);
						OSSemPost(server_client->wake_up);
						if(App_Callback != NULL) OSSemPost(App_Callback);
						break;
					}
					server_client = server_client->next;
				}
			}

			// Buffer not used to send ACK
			/* pacote foi entregue, e o buffer pode ser liberado. */
			packet_down_remove();
			goto wait_again;
		}else
		{
			// If packet already in route, don't update it
			//   this can happen when packet come from application layer
			if(packet_down->state != PACKET_IN_ROUTE){
				/* this function update source and destination */
				/* pacote será roteado ou descartado se não for possível roteá-lo. */
				if (unet_router_down(packet_down) == TRUE)
				{
					PRINTF_ROUTER(2,"Packet will be routed down\r\n");
	//				OSSemPost(Router_Down_Route_Request);
				}else
				{
					// If there is no route, the send task will handle it

					/* todo: o que fazer neste caso ?
					 * Simplesmente descartar ou avisar SRC e/ou DEST disso ?
					 * Seria interessante guardar nas estatísticas */
					PRINTF_ROUTER(2,"Packet route down failure\r\n");
					packet_down_remove();
					goto wait_again;
				}
			}
		}

//		if(p.state == PACKET_ACKED); /// packet aked, so it's ready to be routed
		packet_down->state = PACKET_WAITING_TX;

		/* quantas vezes vale a pena tentar a transmiss�o? */
		routing_retries = 10*NWK_TX_RETRIES;
		reset_trickle(&timer_down_retry);
		while(routing_retries-- > 0)
		{
			/* send packet down */
			if(unet_packet_output(packet_down, NWK_TX_RETRIES, 10) == PACKET_SEND_OK)
			{
				/* se veio o ACK da MAC, então o pacote chegou até o outro lado.
				 * Neste caso, pode não ter espaço no buffer, ou este pacote já pode estar duplicado do outro lado,
				 * mas o ACK ainda não foi recebido. Neste caso, não vamos descontar do routing_retries,
				 * pois vale a pena continuar tentando, já que o link está funcionando. */
				++routing_retries;

				/**
				 * Testar se o nodo pai foi atualizado entre transmissoes,
				 * pois se a rota foi atualizada, o pacote precisa ser atualizado tambem.
				 * Caso não tenha essa atualizacao de rota, a rede pode entrar em Deadlock
				 *
				 * Explicacao do Deadlock:
				 * 		 Dado rádios X e Y e as seguintes premissas:
				 * 		 1 - X tenta enviar para Y;
				 * 		 2 - Y tenta enviar para X;
				 * 		 3 - As transmissoes ocorrem em tempos curto suficiente
				 * 		     para que os dois ocupem o buffer de saída ao mesmo tempo
				 * 		 Então:
				 * 		 X e Y ficam presos aguardando o buffer de saida ficar livre,
				 * 		 para que dessa forma seja possivel enviar o ACK para seus
				 * 		 respectivos. Entrentanto, como o buffer de ambos estão ocupados
				 * 		 com a transmissao, o ACK nao e enviado.
				 */
				if(packet_get_dest_addr16(packet_down) != link_get_parent_addr16()){
					// Route has changed between transmissions, update the packet next hop
					PRINTF_ROUTER(1,"ROUTE DEST UPDATE: was %d now is %d \r\n",
							packet_get_dest_addr16(packet_down), link_get_parent_addr16());
					unet_update_packet_down_dest(packet_down);
				}

				PRINTF_ROUTER(1,"TX DOWN, WAIT ACK, to %u, SN %d \r\n",
						BYTESTOSHORT(packet_down->info[PKTINFO_DEST16H],packet_down->info[PKTINFO_DEST16L]),
						packet_down->info[PKTINFO_SEQNUM]);
			}

			/* aguarda o ACK mesmo que não tenha recebido o ACK da MAC,
			 * pois o pacote pode ter sido transmitido com sucesso,
			 * mas o ACK da MAC foi perdido. O link de lá pra cá está ruim, mas pode
			 * ser que o ACK chegue mesmo assim. */
			packet_down->state = PACKET_WAITING_ACK;

			/* wait ack rx */
			run_trickle(&timer_down_retry);
			if(OSSemPend(Router_Down_Ack_Received, timer_down_retry.t) != TIMEOUT)
			{
				/* isto é só p/ debug, pois quando o semáforo é postado,
				 * o estado do pacote passa para ACKED.
				 * Como o buffer do pacote será liberado,
				 * deveríamos garantir que o semáforo valha zero,
				 * por isso talvez seja necessário mudar p/ semáforo binário. */
				if(packet_down->state != PACKET_ACKED)
				{
					PRINTF_LINK(1,"PACKET STATE ERROR: at %u \r\n", __LINE__);
				}

				/* ack is received, free buffer */
				NODESTAT_UPDATE(routed);
//				packet_release_down();

				PRINTF_ROUTER(1,"TX DOWN, RX ACK, from %u, SN %d \r\n",
						BYTESTOSHORT(packet_down->info[PKTINFO_DEST16H],packet_down->info[PKTINFO_DEST16L]),
						packet_down->info[PKTINFO_SEQNUM]);
				(void)node_data_set(NODE_PARENTFAILURES, 0);
				break;
			}else
			{
				/* Se chegou até aqui, é porque mesmo após várias tentativas não foi possível enviar o pacote.
				 * Neste caso, vamos desistir e liberar o buffer. Poderíamos também dar um tempo,
				 * e tentar mais um pouco mais adiante, mas é díficil saber até quando vale a pena tentar.
				 * Em https://sing.stanford.edu/pubs/sensys08-beta.pdf, sugere-se retentar após 500ms,
				 * devido ao "link burstiness".
				 * Outra opção é tentar trocar de parent/rota,
				 * mas isso pode causar replicação de pacote, pois o pacote pode ter chegado do outro
				 * lado e estar sendo roteado.  */


				NODESTAT_UPDATE(txnacked);
				/* packet lost, free buffer */
				if(routing_retries == 0)
				{
//					packet_release_down();

					NODESTAT_UPDATE(routdrop);
					PRINTF_ROUTER(1,"TX DOWN LOST, SN %d\r\n",packet_down->info[PKTINFO_SEQNUM]);

					uint8_t failures = node_data_get(NODE_PARENTFAILURES);
					failures++;
					#if 0
					if (failures >= MAX_PARENT_ALLOWED_FAILURES){
						node_data_set(NODE_DISTANCE, NODE_DISTANCE_INIT);
						node_data_set(NODE_PARENTINDEX, NO_PARENT);
						link_neighbor_table_init();
						unet_router_up_table_clear();
						// Turn off simmetric parent LED
						#if defined BRTOS_PLATFORM
						#if BRTOS_PLATFORM == FRDM_KL25Z
						GPIOPinSet(GPIOB_BASE, GPIO_PIN_19);
						#endif
						#endif
					}else{
						(void)node_data_set(NODE_PARENTFAILURES, failures);
					}
					#endif
				}
			}
		}

		// Process done, free the buffer
		packet_down_remove();

		/**
		 * If there any packet in the buffer, go and handle it
		 */
		if(!is_buffer_down_empty()){
			OSSemPost(Router_Down_Route_Request);
		}

	}
}

static packet_ack_t Radio_TX_ACK_up_buffer;
#if TASK_WITH_PARAMETERS == 1
void UNET_Router_Up_Ack_Task(void* p)
{
	(void)p;
#else
void UNET_Router_Up_Ack_Task(void)
{
#endif
	extern packet_t packet_up;
    packet_t *r = &packet_up;
    packet_t *ack = (packet_t *)&Radio_TX_ACK_up_buffer;
    unet_transport_t *server_client = unet_tp_head;

    REQUIRE_FOREVER(OSSemCreate(0,&Router_Up_Ack_Request) == ALLOC_EVENT_OK);

	for(;;)
	{
		OSSemPend(Router_Up_Ack_Request,0); // TODO: problem here when changing context to next task

		/* get the last unet_tp_head */
		server_client = unet_tp_head;

		/* copy packet headers to ack buffer */
		memcpy(ack,r, sizeof(packet_ack_t));

		/* packet received, create a link layer ack packet */
		link_packet_create_ack(ack);

		if(unet_packet_output(ack, NWK_TX_RETRIES, 10) == PACKET_SEND_OK)
		{
			PRINTF_ROUTER(1,"TX ACK UP, to %u, SN %d \r\n",
					BYTESTOSHORT(ack->info[PKTINFO_DEST16H],ack->info[PKTINFO_DEST16L]),
					ack->info[PKTINFO_SEQNUM]);
		}

		/* packet is ack'ed, deliver to next layer or route it */
		if(memcmp(&r->packet[UNET_DEST_64],node_addr64_get(),8) == 0)
		{
			/* delivery packet to next layer */
			//PRINTF("Packet received\r\n");
			//packet_print(&r->packet[PHY_PKT_SIZE],r->info[PKTINFO_SIZE]);
			/// Experimental
			if(r->packet[UNET_NEXT_HEADER] == NEXT_HEADER_UNET_APP){
				NODESTAT_UPDATE(netapprx);
				while(server_client != NULL){
					if (server_client->src_port == r->packet[UNET_DEST_PORT]){
						server_client->packet = &(r->packet[UNET_APP_HEADER_START]);
						server_client->payload_size = r->packet[UNET_APP_PAYLOAD_LEN];
						server_client->sender_port = r->packet[UNET_SOURCE_PORT];
						memcpy(&(server_client->sender_address),&(r->packet[UNET_SRC_64]),8);
						OSSemPost(server_client->wake_up);
						if(App_Callback != NULL) OSSemPost(App_Callback);
						break;
					}
					server_client = server_client->next;
				}
			}

			packet_release_up();
		}else
		{
			/* set next hop */
			unet_router_up();
			PRINTF_ROUTER(2,"Packet will be routed up\r\n");
			OSSemPost(Router_Up_Route_Request);
		}
	}
}

#if TASK_WITH_PARAMETERS == 1
void UNET_Router_Up_Task(void* p)
{
	(void)p;
#else
void UNET_Router_Up_Task(void)
{
#endif

	uint8_t routing_retries;
	extern packet_t packet_up;
    packet_t *r = &packet_up;
    trickle_t timer_up_retry;

    REQUIRE_FOREVER(OSSemCreate(0,&Router_Up_Route_Request) == ALLOC_EVENT_OK);
    REQUIRE_FOREVER(OSSemCreate(0,&Router_Up_Ack_Received) == ALLOC_EVENT_OK);

	#define TIMEOUT_FOR_ROUTE_AGAIN_UP   	 (64)
	#define MAX_TIMEOUT_FOR_ROUTE_AGAIN_UP   (256)
	open_trickle(&timer_up_retry,TIMEOUT_FOR_ROUTE_AGAIN_UP,MAX_TIMEOUT_FOR_ROUTE_AGAIN_UP);

	for(;;)
	{
		/* wait ack tx */
		OSSemPend(Router_Up_Route_Request,0);

		routing_retries = NWK_TX_RETRIES;
		reset_trickle(&timer_up_retry);
		while(routing_retries-- > 0)
		{
			/* send packet up */
			if(unet_packet_output(r, NWK_TX_RETRIES, 10) == PACKET_SEND_OK)
			{
				PRINTF_ROUTER(1,"TX UP, WAIT ACK, to %u SN %d \r\n", BYTESTOSHORT(r->info[PKTINFO_DEST16H],r->info[PKTINFO_DEST16L]), r->info[PKTINFO_SEQNUM]);
			}else
			{
				PRINTF_ROUTER(1,"TX UP FAILED, to %u SN %d \r\n", BYTESTOSHORT(r->info[PKTINFO_DEST16H],r->info[PKTINFO_DEST16L]),r->info[PKTINFO_SEQNUM]);
			}

			r->state = PACKET_WAITING_ACK;

			/* wait ack rx */
			run_trickle(&timer_up_retry);
			if(OSSemPend(Router_Up_Ack_Received, timer_up_retry.t) != TIMEOUT)
			{
				/* ack is received, free buffer */
				packet_release_up();
	            NODESTAT_UPDATE(routed);
				break;
			}else
			{
				NODESTAT_UPDATE(txnacked);
				/* packet lost, free buffer */
				if(routing_retries == 0)
				{
					#if 0  /* removido, pois o reset est� sendo feito dentro da fun��o unet_packet_output (...)*/
					// Radio Reset
					NODESTAT_UPDATE(radioresets);
					RadioReset();
					#endif

					PRINTF_ROUTER(1, "TX UP LOST, to %u SN %u\r\n", BYTESTOSHORT(r->info[PKTINFO_DEST16H],r->info[PKTINFO_DEST16L]), r->info[PKTINFO_SEQNUM]);
					NODESTAT_UPDATE(routdrop);
					packet_release_up();
				}
			}
		}

	}
}

/**
 * \brief notify application that has pending packets
 * \param callback is an semaphore that will wake up the application
 */
void UNET_Set_App_Callback(BRTOS_Sem *callback){
	App_Callback = callback;
}
