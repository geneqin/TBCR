/*This file contains the detailed major functions for Tree Based Converge Routing Protocol and
 * used under the Quanlnet License and agreement.
 * Author1: Zhijing Qin
 * Email: zhijing.qin@gmail.com
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "partition.h"
#include "network_ip.h"
#include "ipv6.h"
#include "buffer.h"
#include "external_socket.h"
#include "mapping.h"

#include "routing_tbcr.h"

#define  TBCR_DEBUG 0
#define  TBCR_DEBUG_TBCR_TRACE 0
#define  TBCR_DEBUG_HELLO 0
#define  TBCR_DEBUG_NEILIST 0
#define  TBCR_DEBUG_PARENTCLAIM 0
#define TBCR_PC_ERAND(tbcrJitterSeed) (RANDOM_nrand(tbcrJitterSeed)\
    % TBCR_BROADCAST_JITTER)
#define TBCR_DEFAULT_HELLO_INTERVAL            (700 * MILLI_SECOND)
#define TBCR_SELECT_PARENT_INTERVAL     (60*MILLI_SECOND)//(2*TBCR_DEFAULT_HELLO_INTERVAL)//(360 * MILLI_SECOND)
#define TBCR_FLUSH_TABLE_INTERVAL (8*TBCR_DEFAULT_HELLO_INTERVAL)
#define TBCR_HEART_BEAT_INTERVAL (TBCR_DEFAULT_HELLO_INTERVAL*10)
#define setbit(x,y) x|=(1<<y) //set the yth bit of x
#define clrbit(x,y) x&=!(1<<y) //reset the yth bit ofx
// Tbcr Packet Types
Address OldBestParentAddress;
clocktype LastHeardBestParent;
// /**
// FUNCTION   :: TbcrInitializeConfigurableParameters
// LAYER      :: NETWORK
// PURPOSE    :: To initialize the user configurable parameters or initialize
//               the corresponding variables with the default values as
//               specified in draft-ietf-manet-tbcr-08.txt.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +nodeInput:  const NodeInput* : Pointer to Chached file.
//  +tbcr:  TbcrData* : Pointer to TBCR Data.
//  +interfaceAddress:  Address : Interface Address.
// RETURN     :: void : NULL.
// **/
static
void TbcrInitializeConfigurableParameters(
    Node* node,
    const NodeInput* nodeInput,
    TbcrData* tbcr,
    Address interfaceAddress){

	    BOOL wasFound;
	    char buf[MAX_STRING_LENGTH];
	    UInt32 nodeId = node->nodeId;

	    tbcr->gen=200;
	    tbcr->NumOfChd=0;
	    tbcr->PowerLevel=100;
	    tbcr->ParentIsAlive=false;
	    if(tbcr->isSource)
	    	tbcr->ParentIsAlive=true;

	    tbcr->AllowMoreChild=true;
	    tbcr->ClaimDone=false;
	    tbcr->hasChild=false;
	    tbcr->bufferSizeInNumPacket = 200;
	    tbcr->bufferSizeInByte = 0;



	    IO_ReadInt(
	            nodeId,
	            &interfaceAddress,
	            nodeInput,
	            "TBCR-ALLOWED-HELLO-LOSS",
	            &wasFound,
	            &tbcr->allowedHelloLoss);

	        if (!wasFound)
	        {
	            tbcr->allowedHelloLoss = TBCR_DEFAULT_ALLOWED_HELLO_LOSS;
	            printf("allowed Hello Loss: %d",tbcr->allowedHelloLoss );
	        }
	        else
	        {
	            ERROR_Assert(
	                    tbcr->allowedHelloLoss > 0,
	            "Invalid TBCR_DEFAULT_ALLOWED_HELLO_LOSS configuration");
	        }
	    IO_ReadTime(
	               nodeId,
	               &interfaceAddress,
	               nodeInput,
	               "TBCR-HELLO-INTERVAL",
	               &wasFound,
	               &tbcr->helloInterval);

	           if (!wasFound)
	           {
	               tbcr->helloInterval = TBCR_DEFAULT_HELLO_INTERVAL;
	           }
	           else
	           {
	               ERROR_Assert(
	                       tbcr->helloInterval > 0,
	               "Invalid TBCR_DEFAULT_HELLO_INTERVAL configuration");
	           }

		   IO_ReadString(
				   nodeId,
				   &interfaceAddress,
				   nodeInput,
				   "TBCR-PROCESS-HELLO",
				   &wasFound,
				   buf);

			   if ((wasFound == FALSE) || (strcmp(buf, "NO") == 0))
			   {
				   tbcr->processHello = FALSE;
			   }
			   else if (strcmp(buf, "YES") == 0)
			   {
				   tbcr->processHello = TRUE;
			   }
			   else
			   {
				   ERROR_ReportError("Needs YES/NO against TBCR-PROCESS-HELLO");
			   }
			IO_ReadString(
						   nodeId,
						   &interfaceAddress,
						   nodeInput,
						   "TBCR-IS-SOURCE-NODE",
						   &wasFound,
						   buf);

			   if ((wasFound == FALSE) || (strcmp(buf, "NO") == 0))
			   {
				   tbcr->isSource = FALSE;
			   }
			   else if (strcmp(buf, "YES") == 0)
			   {
				   tbcr->isSource = TRUE;
			   }
			   else
			   {
				   ERROR_ReportError("Needs YES/NO against TBCR-IS-SOURCE-NODE");
			   }

			   IO_ReadTime(
				   nodeId,
				   &interfaceAddress,
				   nodeInput,
				   "TBCR-HELLO-INTERVAL",
				   &wasFound,
				   &tbcr->parentClaimInterval);

			   if (!wasFound)
			   {
				   tbcr->parentClaimInterval = TBCR_DEFAULT_HELLO_INTERVAL;
			   }

			   else
			   {
				   ERROR_Assert(
						   tbcr->parentClaimInterval > 0,
				   "Invalid TBCR_DEFAULT_HELLO_INTERVAL configuration");
			   }


}//TBD

// /**
// FUNCTION   :: TbcrIsEligibleInterface
// LAYER      :: NETWORK
// PURPOSE    :: Check whether interface is valid for TBCR for IPv4 or IPv6.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +destAddr:  Address* : Pointer to Dest Address.
//  +iface:  TbcrInterfaceInfo* : Pointer to TBCR Interface.
// RETURN     :: TRUE if Eligible, FALSE otherwise.
// **/
static
BOOL TbcrIsEligibleInterface(
    Node* node,
    Address* destAddr,
    TbcrInterfaceInfo* iface)
{
    if (((destAddr->networkType == NETWORK_IPV4)
        && (iface->tbcr4eligible == TRUE)))
    {
        return TRUE;
    }

    return FALSE;
}

// /**
// FUNCTION   :: TbcrPrintTraceXML
// LAYER      :: NETWORK
// PURPOSE    :: Print out packet trace information in XML format
// PARAMETERS ::
// + node : Node* : Pointer to node, doing the packet trace
// + mntMsg  : Message* : Pointer to Message
// RETURN ::  void : NULL
// **/

void TbcrPrintTraceXML(Node* node, Message* msg, NetworkType netType)
{
    char buf[MAX_STRING_LENGTH];
    char dest[MAX_STRING_LENGTH];
    char src[MAX_STRING_LENGTH];
    BOOL IPV6 = FALSE;

    if( msg == NULL)
    {
        return;
    }
    if(netType == NETWORK_IPV6)
    {
        IPV6 = TRUE;

    }

    UInt32* pktPtr = (UInt32* )MESSAGE_ReturnPacket(msg);

    sprintf(buf, "<tbcr>");
    TRACE_WriteToBufferXML(node, buf);

    switch (*pktPtr >> 24)
    {

        case TBCR_HELLO:
        {

        	sprintf(buf, "<rreq>");
        	TRACE_WriteToBufferXML(node, buf);

            //trace info
			sprintf(buf, "</rreq>");
			TRACE_WriteToBufferXML(node, buf);
			break;

        }


    }//end of switch
    sprintf(buf, "</tbcr>");
    TRACE_WriteToBufferXML(node, buf);



}

// /**
// FUNCTION     :TbcrInitTrace()
// LAYER        :NETWORK
// PURPOSE      :Enabling Tbcr trace. The output will go in file tbcr.trace
// ASSUMPTION   :None
// PARAMETERS   :
// + node : Node* : Pointer to node
// + nodeInput    : const NodeInput* : Pointer to NodeInput
// RETURN   ::void:NULL
//**/

static
void TbcrInitTrace(Node* node, const NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    BOOL traceAll = TRACE_IsTraceAll(node);
    BOOL trace = FALSE;
    static BOOL writeMap = TRUE;

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TRACE-TBCR",
        &retVal,
        buf);

    if (retVal)
    {
        if (strcmp(buf, "YES") == 0)
        {
            trace = TRUE;
        }
        else if (strcmp(buf, "NO") == 0)
        {
            trace = FALSE;
        }
        else
        {
            ERROR_ReportError(
                "TRACE-TBCR should be either \"YES\" or \"NO\".\n");
        }
    }
    else
    {
        if (traceAll)
        {
            trace = TRUE;
        }
    }

    if (trace)
    {
            TRACE_EnableTraceXMLFun(node, TRACE_TBCR,
                "tbcr", TbcrPrintTraceXML, writeMap);
    }
    else
    {
            TRACE_DisableTraceXML(node, TRACE_TBCR,
                "tbcr", writeMap);
    }
    writeMap = FALSE;

    if (TBCR_DEBUG_TBCR_TRACE)
    {
        // Empty or create a file named tbcr.trace to print the packet
        // contents
        FILE* fp = fopen("tbcr.trace", "w");
        fclose(fp);
    }
}
// /**
// FUNCTION :TbcrPrintTrace()
// LAYER    :NETWORK
// PURPOSE  :Trace printing function to call for Tbcr packet.
// ASSUMPTION   :None
// PARAMETERS:
// +node:Node*:Pointer to node
// +msg:Message*:Pointer to message
// +sendorReceive:char:value specify whether send or received
// RETURN   ::void:NULL
// **/

static
void TbcrPrintTrace(
         Node* node,
         Message* msg,
         char sendOrReceive,
         BOOL ipv6Flag)
{
    unsigned int* pktPtr = (unsigned int *) MESSAGE_ReturnPacket(msg);
    char clockStr[MAX_STRING_LENGTH];
    FILE* fp = fopen("tbcr.trace", "a");
    char dest[MAX_STRING_LENGTH];
    char src[MAX_STRING_LENGTH];

    if (!fp)
    {
        ERROR_ReportError("Can't open tbcr.trace\n");
    }

    TIME_PrintClockInSecond(getSimTime(node), clockStr);

    // print packet ID
    fprintf(fp, "%u, %d; %s; %u %c; ",
        msg->originatingNodeId,
        msg->sequenceNumber,
        clockStr,
        node->nodeId,
        sendOrReceive);

    if ((*pktPtr >> 24) == TBCR_HELLO)
    {
        // Print content of route request packets
        if(ipv6Flag)
        {

        }
        else
        {
            TbcrHelloPacket* helloPkt = (TbcrHelloPacket *) pktPtr;

            IO_ConvertIpAddressToString(helloPkt->destination.address, dest);
            IO_ConvertIpAddressToString(helloPkt->source.address, src);

            fprintf(fp, "%u, %u, %u, %u, %s, %s, %u",
                TBCR_GetType(helloPkt->info.typeBitsHopcounts),

                0,//rreqPkt->reserved,
                helloPkt->info.typeBitsHopcounts & TBCR_HOP_COUNT_BITS,

                dest,
                src,
                helloPkt->source.seqNum);
        }
    }


    fprintf(fp, "\n");
    fclose(fp);
}

// /**
// FUNCTION   :: TbcrIsSmallerAddress
// LAYER      :: NETWORK
// PURPOSE    :: Check if address1 is smaller than address2.
//
// PARAMETERS ::
//  +destAddr:  Address : Destination Address.
//
// RETURN     :: TRUE if Smaller.
// **/
static BOOL
TbcrIsSmallerAddress(Address address1, Address address2)
{
    if (address1.networkType != address2.networkType)
    {
        ERROR_Assert(FALSE, "Address of same type not compared \n");
    }
    else

        if (address1.interfaceAddr.ipv4 < address2.interfaceAddr.ipv4)
        {
            return TRUE;
        }

    return FALSE;
}
// /**
// FUNCTION : TbcrInsertBuffer
// LAYER   : NETWORK
// PURPOSE  : Insert a packet into the buffer if no route is available
// PARAMETERS:
// +node:Node*:Pointer to node
// +msg:Message*: Pointer to the message waiting for a route to destination
// +destAddr:Address:The destination address of the packet
// +previousHop:Address:Previous hop address
// +buffer:TbcrMessageBuffer*:Pointer to the buffer to store the message
// RETURN   ::void:NULL
// **/

static
void TbcrInsertBuffer(
         Node* node,
         Message* msg,
         Address destAddr,
         Address previousHop,
         TbcrMessageBuffer* buffer)
{
		TbcrBufferNode* current = NULL;
		TbcrBufferNode* previous = NULL;
		TbcrBufferNode* newNode = NULL;
		TbcrData* tbcr = NULL;

		tbcr = (TbcrData*) NetworkIpGetRoutingProtocol(
		                                     node,
		                                     ROUTING_PROTOCOL_TBCR,
		                                     NETWORK_IPV4);
		 // if the buffer exceeds silently drop the packet
		    // if no buffer size is specified in bytes it will only check for
		    // number of packet.
		printf("Insert pkt into buffer due to no route!by node%d\n", node->nodeId);
		if (tbcr->bufferSizeInByte == 0)
		{
			if (buffer->size == tbcr->bufferSizeInNumPacket)
			{

				//Trace drop
				ActionData acnData;
				acnData.actionType = DROP;
				acnData.actionComment = DROP_BUFFER_SIZE_EXCEED;
				TRACE_PrintTrace(node,
								 msg,
								 TRACE_NETWORK_LAYER,
								 PACKET_IN,
								 &acnData,
								 tbcr->defaultInterfaceAddr.networkType);
				MESSAGE_Free(node, msg);
				tbcr->stats.numDataDroppedForOverlimit++;
				return;
			}
		}
		else{
			 if ((buffer->numByte + MESSAGE_ReturnPacketSize(msg)) >
			            tbcr->bufferSizeInByte)
			        {
			            //Trace drop
			            ActionData acnData;
			            acnData.actionType = DROP;
			            acnData.actionComment = DROP_BUFFER_SIZE_EXCEED;
			            TRACE_PrintTrace(node,
			                             msg,
			                             TRACE_NETWORK_LAYER,
			                             PACKET_IN,
			                             &acnData,
			                             tbcr->defaultInterfaceAddr.networkType);
			            MESSAGE_Free(node, msg);
			            tbcr->stats.numDataDroppedForOverlimit++;
			            return;
			        }
		}

		// Find Insertion point.  Insert after all address matches.
		// This is to maintain a sorted list in ascending order of the
		// destination address
		previous = NULL;
		current = buffer->head;

		while (current
				&&
				(TbcrIsSmallerAddress(current->destAddr, destAddr)
				|| Address_IsSameAddress(&current->destAddr, &destAddr)))
		{
			previous = current;
			current = current->next;
		}
		newNode = (TbcrBufferNode*) MEM_malloc(sizeof(TbcrBufferNode));
		// Store the allocate message along with the destination number and
		// the time at which the packet has been inserted

		SetIPv4AddressInfo(&newNode->destAddr,
										destAddr.interfaceAddr.ipv4);
		SetIPv4AddressInfo(&newNode->previousHop,
										previousHop.interfaceAddr.ipv4);
		newNode->msg = msg;
		newNode->timestamp = getSimTime(node);
		newNode->next = current;

		// Increase the size of the buffer
		++(buffer->size);
		buffer->numByte += MESSAGE_ReturnPacketSize(msg);

		// Got the insertion point
		if (previous == NULL)
		{
			// The is the first message in the buffer or to be
			// inserted in the first
			buffer->head = newNode;
		}
		else
		{
			// This is an intermediate node in the list
			previous->next = newNode;
		}

		tbcr->stats.numBufferedData++;

}
// /**
// FUNCTION : TbcrGetBufferedPacket
// LAYER    : NETWORK
// PURPOSE  : Extract the packet that was buffered
// PARAMETERS:
// +destAddr:Address:the destination address of the packet to be
//                   retrieved
// +previousHop:Address: Previous hop address
// +buffer:AodvMessageBuffer*:Pointer to the message buffer
// RETURN   :
// +pkttoDest:Message*:The message for this destination
// **/

static
Message* TbcrGetBufferedPacket(
    Node* node,
    Address destAddr,
    Address* previousHop,
    TbcrMessageBuffer* buffer)
{
    TbcrBufferNode* current = buffer->head;
    Message* pktToDest = NULL;
    TbcrBufferNode* toFree = NULL;
    BOOL IPV6 = FALSE;

	previousHop->networkType = NETWORK_IPV4;
	previousHop->interfaceAddr.ipv4 = 0;

    if (!current)
    {
        // No packet in the buffer so nothing to do
    }
    else if (Address_IsSameAddress(&current->destAddr, &destAddr))
    {
        // The first packet is the desired packet
        toFree = current;
        buffer->head = toFree->next;

        pktToDest = toFree->msg;

        SetIPv4AddressInfo(previousHop,
                           toFree->previousHop.interfaceAddr.ipv4);

        buffer->numByte -= MESSAGE_ReturnPacketSize(toFree->msg);
        MEM_free(toFree);
        --(buffer->size);
    }
    else
    {
        while (current->next
                && TbcrIsSmallerAddress(current->next->destAddr, destAddr))
        {
            current = current->next;
        }

        if (current->next
            && Address_IsSameAddress(&current->next->destAddr,&destAddr))
        {
            // Got the matched destination so return the packet
            toFree = current->next;


            SetIPv4AddressInfo(previousHop,
                                toFree->previousHop.interfaceAddr.ipv4);

            pktToDest = toFree->msg;
            buffer->numByte -= MESSAGE_ReturnPacketSize(toFree->msg);
            current->next = toFree->next;
            MEM_free(toFree);
            --(buffer->size);
        }
    }

    return pktToDest;
}
// /**
// FUNCTION   :: TbcrSendPacket
// LAYER      :: NETWORK
// PURPOSE    :: Send TBCR Packets.
// PARAMETERS ::
//  +node:  Node* : Pointer to Node.
//  +msg:  Message* : Pointer to message.
//  +srcAddr:  Address : Source Address.
//  +destAddr:  Address : Dest Address.
//  +interfaceIndex:  int : Interface Index.
//  +ttl: int : TTL value for the message.
//  +nextHopAddress:  Address : Next Hop used by TBCR for IPv4.
//  +delay:  clocktype : Delay used by TBCR for IPv4.
// RETURN     :: void : NULL.
// **/
void
TbcrSendPacket(
    Node* node,
    Message* msg,
    Address srcAddr,
    Address destAddr,
    int interfaceIndex,
    int ttl,
    NodeAddress nextHopAddress,
    clocktype delay,
    BOOL isDelay)
{

    if(srcAddr.networkType == NETWORK_IPV4)
    {
        if(isDelay)
        {
            //Trace sending packet
            ActionData acnData;
            acnData.actionType = SEND;
            acnData.actionComment = NO_COMMENT;
            TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER,
                  PACKET_OUT, &acnData , srcAddr.networkType);


            NetworkIpSendRawMessageToMacLayerWithDelay(
                node,
                msg,
                srcAddr.interfaceAddr.ipv4,
                destAddr.interfaceAddr.ipv4,
                IPTOS_PREC_INTERNETCONTROL,
                IPPROTO_TBCR,
                ttl,
                interfaceIndex,
                nextHopAddress,
                delay);

            //printf("IPPROTO_TBCR:%d\n", IPPROTO_TBCR);
        }
        else
        {
            //Trace sending packet
            ActionData acnData;
            acnData.actionType = SEND;
            acnData.actionComment = NO_COMMENT;
            TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER,
                      PACKET_OUT, &acnData, srcAddr.networkType);

            NetworkIpSendRawMessageToMacLayer(
                node,
                msg,
                srcAddr.interfaceAddr.ipv4,
                destAddr.interfaceAddr.ipv4,
                IPTOS_PREC_INTERNETCONTROL,
                IPPROTO_TBCR,
                1,
                interfaceIndex,
                nextHopAddress);

        }

    }

}

static
void
TbcrBroadcastHeartBeat(Node* node, TbcrData* tbcr, Address* destAddr,clocktype eni){

		Message* newMsg = NULL;
		TbcrHeartBeatPacket* HeartbeatPkt = NULL;
		NetworkRoutingProtocolType protocolType = ROUTING_PROTOCOL_TBCR;
		char* pktPtr = NULL;
		int pktSize = sizeof(TbcrHeartBeatPacket);
		int i= 0;
		UInt32 typeBits = 0;
		BOOL isDelay = TRUE;
		BOOL IPV6 = FALSE;
		Address broadcastAddress;



		newMsg = MESSAGE_Alloc(
					 node,
					 NETWORK_LAYER,
					 protocolType,
					 MSG_MAC_FromNetwork);

		MESSAGE_PacketAlloc(
			node,
			newMsg,
			pktSize,
			TRACE_TBCR);

		pktPtr = (char *) MESSAGE_ReturnPacket(newMsg);

		memset(pktPtr, 0, pktSize);



		typeBits |= (TBCR_HEART_BEAT << 24);




		   HeartbeatPkt = (TbcrHeartBeatPacket *) pktPtr;
		   HeartbeatPkt->typeBits = typeBits;
		   HeartbeatPkt->sourceAddr = ANY_IP;
		   HeartbeatPkt->gen=tbcr->gen;
		   HeartbeatPkt->eni=eni;



		for (i = 0; i < node->numberInterfaces; i++)
		{
			if (TbcrIsEligibleInterface(node, destAddr, &tbcr->iface[i])
																	== FALSE)
			{
				continue;
			}

			clocktype delay =
				(clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);
			HeartbeatPkt->sendtime +=delay;



			HeartbeatPkt = (TbcrHeartBeatPacket *) MESSAGE_ReturnPacket(newMsg);
			HeartbeatPkt->destination = tbcr->iface[i].address.interfaceAddr.ipv4;
			 SetIPv4AddressInfo(&broadcastAddress,ANY_DEST);



			if (TBCR_DEBUG_TBCR_TRACE)
			{
				TbcrPrintTrace(node, newMsg, 'S',IPV6);
			}

			TbcrSendPacket(
				node,
				MESSAGE_Duplicate(node, newMsg),
				tbcr->iface[i].address,
				*destAddr,
				i,
				1,
				ANY_DEST,
				delay,
				isDelay);
		}
		//printf("TbcrSendPacket!\n");
		MESSAGE_Free(node, newMsg);

	tbcr->stats.numHeatBeatSent++;

}
// /**
// FUNCTION   :: TbcrBroadcastHelloMessage
// LAYER      :: NETWORK
// PURPOSE    :: Function to advertise hello message if a node wants to.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +tbcr:  TbcrData* : Pointer to TBCR Data.
// RETURN     :: void : NULL.
// **/
//note you can set Enable hello or not in GUI(config file), however, we do not use
//this primitives, we use heartbeat by default.
static
void TbcrBroadcastHelloMessage(Node* node, TbcrData* tbcr, Address* destAddr)
{
    IPv6Data *ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;
    Message* newMsg = NULL;
    TbcrHelloPacket* helloPkt = NULL;
    NetworkRoutingProtocolType protocolType = ROUTING_PROTOCOL_TBCR;
    char* pktPtr = NULL;
    int pktSize = sizeof(TbcrHelloPacket);
    int i= 0;
    clocktype lifetime = (unsigned int) ((TBCR_ALLOWED_HELLO_LOSS
        * TBCR_HELLO_INTERVAL) / MILLI_SECOND);
    UInt32 typeBitsPrefixSizeHop = 0;
    BOOL isDelay = TRUE;
    BOOL IPV6 = FALSE;
    Address broadcastAddress;

    if (TBCR_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(getSimTime(node), time);
        printf("Node %u is sending Hello packet at %s\n",
            node->nodeId, time);
    }

    newMsg = MESSAGE_Alloc(
                 node,
                 NETWORK_LAYER,
                 protocolType,
                 MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        pktSize,
        TRACE_TBCR);

    pktPtr = (char *) MESSAGE_ReturnPacket(newMsg);

    memset(pktPtr, 0, pktSize);



    typeBitsPrefixSizeHop |= (TBCR_HELLO << 24);




       helloPkt = (TbcrHelloPacket *) pktPtr;
       helloPkt->typeBitsPrefixSizeHop = typeBitsPrefixSizeHop;
       helloPkt->sourceAddr = ANY_IP;
       helloPkt->lifetime = (UInt32)lifetime;


    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (TbcrIsEligibleInterface(node, destAddr, &tbcr->iface[i])
                                                                == FALSE)
        {
            continue;
        }

        clocktype delay =
            (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);



        helloPkt = (TbcrHelloPacket *) MESSAGE_ReturnPacket(newMsg);
        helloPkt->destination.address = tbcr->iface[i].address.interfaceAddr.ipv4;
         SetIPv4AddressInfo(&broadcastAddress,ANY_DEST);



        if (TBCR_DEBUG_TBCR_TRACE)
        {
            TbcrPrintTrace(node, newMsg, 'S',IPV6);
        }

        TbcrSendPacket(
            node,
            MESSAGE_Duplicate(node, newMsg),
            tbcr->iface[i].address,
            *destAddr,
            i,
            1,
            ANY_DEST,
            delay,
            isDelay);
    }
    //printf("TbcrSendPacket!\n");
    MESSAGE_Free(node, newMsg);

    tbcr->stats.numHelloSent++;

}
// /**
// FUNCTION   :: TbcrBroadcastParentRequestMessage
// LAYER      :: NETWORK
// PURPOSE    :: Different with unicast parent request. this broadcast parent request
//               is used in maintenance phase.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +tbcr:  TbcrData* : Pointer to TBCR Data.
// RETURN     :: void : NULL.
// **/
static
void TbcrBroadcastParentRequestMessage(Node* node, TbcrData* tbcr, Address* destAddr)
{
	    IPv6Data *ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;
	    Message* newMsg = NULL;
	    TbcrBSTParentRequestPacket* BstparentReqPkt = NULL;
	    NetworkRoutingProtocolType protocolType = ROUTING_PROTOCOL_TBCR;
	    char* pktPtr = NULL;
	    int pktSize = sizeof(TbcrBSTParentRequestPacket);
	    int i= 0;
	    UInt32 typeBits = 0;
	    BOOL isDelay = TRUE;
	    BOOL IPV6 = FALSE;
	    Address broadcastAddress;

	    if (TBCR_DEBUG)
	    {
	        char time[MAX_STRING_LENGTH];
	        TIME_PrintClockInSecond(getSimTime(node), time);
	        printf("Node %u is broadcasting parent request packet at %s\n",
	            node->nodeId, time);
	    }

	    newMsg = MESSAGE_Alloc(
	                 node,
	                 NETWORK_LAYER,
	                 protocolType,
	                 MSG_MAC_FromNetwork);

	    MESSAGE_PacketAlloc(
	        node,
	        newMsg,
	        pktSize,
	        TRACE_TBCR);

	    pktPtr = (char *) MESSAGE_ReturnPacket(newMsg);

	    memset(pktPtr, 0, pktSize);



	    typeBits |= (TBCR_BST_PARENT_REQUEST << 24);



//reuse parent claim packet structure to broadcast
	       BstparentReqPkt = (TbcrBSTParentRequestPacket *) pktPtr;
	       BstparentReqPkt->typeBits = typeBits;
	       BstparentReqPkt->sourceAddr = ANY_IP;
	       BstparentReqPkt->sendtime = getSimTime(node);
	       BstparentReqPkt->NumOfChd=tbcr->NumOfChd;
	       BstparentReqPkt->PowerLevel=tbcr->PowerLevel;
	       BstparentReqPkt->gen=tbcr->gen;


	    for (i = 0; i < node->numberInterfaces; i++)
	    {
	        if (TbcrIsEligibleInterface(node, destAddr, &tbcr->iface[i])
	                                                                == FALSE)
	        {
	            continue;
	        }

	        clocktype delay =
	            (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);
	        BstparentReqPkt->sendtime +=delay;



	        BstparentReqPkt = (TbcrBSTParentRequestPacket *) MESSAGE_ReturnPacket(newMsg);
	        BstparentReqPkt->destination = tbcr->iface[i].address.interfaceAddr.ipv4;
	         SetIPv4AddressInfo(&broadcastAddress,ANY_DEST);



	        if (TBCR_DEBUG_TBCR_TRACE)
	        {
	            TbcrPrintTrace(node, newMsg, 'S',IPV6);
	        }

	        TbcrSendPacket(
	            node,
	            MESSAGE_Duplicate(node, newMsg),
	            tbcr->iface[i].address,
	            *destAddr,
	            i,
	            1,
	            ANY_DEST,
	            delay,
	            isDelay);
	    }
	   // printf("TbcrSendBSTRequestPacket!\n");
	    MESSAGE_Free(node, newMsg);

	    tbcr->stats.numBstParentRequestSent++;
}
// /**
// FUNCTION   :: TbcrBroadcastParentClaimMessage
// LAYER      :: NETWORK
// PURPOSE    :: Function to broadcast parent claim messages in the initialize phase
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +tbcr:  TbcrData* : Pointer to TBCR Data.
// RETURN     :: void : NULL.
// **/
static
void TbcrBroadcastParentClaimMessage(Node* node, TbcrData* tbcr, Address* destAddr)
{
    IPv6Data *ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;
    Message* newMsg = NULL;
    TbcrParentClaimPacket* parentClaimPkt = NULL;
    NetworkRoutingProtocolType protocolType = ROUTING_PROTOCOL_TBCR;
    char* pktPtr = NULL;
    int pktSize = sizeof(TbcrParentClaimPacket);
    int i= 0;
    UInt32 typeBits = 0;
    BOOL isDelay = TRUE;
    BOOL IPV6 = FALSE;
    Address broadcastAddress;

    if (TBCR_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(getSimTime(node), time);
        printf("Node %u is sending parent claim packet at %s\n",
            node->nodeId, time);
    }

    newMsg = MESSAGE_Alloc(
                 node,
                 NETWORK_LAYER,
                 protocolType,
                 MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        pktSize,
        TRACE_TBCR);

    pktPtr = (char *) MESSAGE_ReturnPacket(newMsg);

    memset(pktPtr, 0, pktSize);



    typeBits |= (TBCR_PARENT_CLAIM << 24);




       parentClaimPkt = (TbcrParentClaimPacket *) pktPtr;
       parentClaimPkt->typeBits = typeBits;
       parentClaimPkt->sourceAddr = ANY_IP;
       parentClaimPkt->sendtime = getSimTime(node);
       parentClaimPkt->NumOfChd=tbcr->NumOfChd;
       parentClaimPkt->PowerLevel=tbcr->PowerLevel;
       parentClaimPkt->gen=tbcr->gen;


    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (TbcrIsEligibleInterface(node, destAddr, &tbcr->iface[i])
                                                                == FALSE)
        {
            continue;
        }

        clocktype delay =
            (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);
        parentClaimPkt->sendtime +=delay;



        parentClaimPkt = (TbcrParentClaimPacket *) MESSAGE_ReturnPacket(newMsg);
        parentClaimPkt->destination = tbcr->iface[i].address.interfaceAddr.ipv4;
         SetIPv4AddressInfo(&broadcastAddress,ANY_DEST);



        if (TBCR_DEBUG_TBCR_TRACE)
        {
            TbcrPrintTrace(node, newMsg, 'S',IPV6);
        }

        TbcrSendPacket(
            node,
            MESSAGE_Duplicate(node, newMsg),
            tbcr->iface[i].address,
            *destAddr,
            i,
            1,
            ANY_DEST,
            delay,
            isDelay);
    }
    //printf("TbcrSendPacket!\n");
    MESSAGE_Free(node, newMsg);

    tbcr->stats.numParentClaimSent++;

}
// /**
// FUNCTION   :: TbcrUnicastDescendantMessage
// LAYER      :: NETWORK
// PURPOSE    :: Function to unicast/report descendant address to parent
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +tbcr:  TbcrData* : Pointer to TBCR Data.
//  +descendant: Address* : descendant address.
//  +destAddr Address* : destination address.
//  +interface: Unit32 : outgoing interface
// RETURN     :: void : NULL.
// **/
static
void TbcrUnicastDescendantMessage(Node* node, TbcrData* tbcr, Address descendant, Address* destAddr, UInt32 interfaceIndex)
{
	        Message* newMsg = NULL;
	        TbcrDescendantReportPacket* desdReportPkt = NULL;
		    NetworkRoutingProtocolType protocolType = ROUTING_PROTOCOL_TBCR;
		    char* pktPtr = NULL;
		    int pktSize = sizeof(TbcrDescendantReportPacket);
		    int i= 0;
		    UInt32 typeBits = 0;
		    BOOL isDelay = TRUE;
		    BOOL IPV6 = FALSE;


		    if (TBCR_DEBUG)
		    {
		        char time[MAX_STRING_LENGTH];
		        TIME_PrintClockInSecond(getSimTime(node), time);
		        printf("Node %u is sending parent confirm packet at %s\n",
		            node->nodeId, time);
		    }

		    newMsg = MESSAGE_Alloc(
		                 node,
		                 NETWORK_LAYER,
		                 protocolType,
		                 MSG_MAC_FromNetwork);

		    MESSAGE_PacketAlloc(
		        node,
		        newMsg,
		        pktSize,
		        TRACE_TBCR);

		    pktPtr = (char *) MESSAGE_ReturnPacket(newMsg);

		    memset(pktPtr, 0, pktSize);



		    typeBits |= (TBCR_DESCENDANT_REPORT << 24);




		    desdReportPkt = (TbcrDescendantReportPacket *) pktPtr;
		    desdReportPkt->typeBits = typeBits;
		    desdReportPkt->sourceAddr = ANY_IP;
		    desdReportPkt->sendtime = getSimTime(node);
		    desdReportPkt->descendant =descendant;



		        if (TbcrIsEligibleInterface(node, destAddr, &tbcr->iface[interfaceIndex])
		                                                                == FALSE)
		        {
		            printf("interface %d is not eligible\n", interfaceIndex);
		        }

		        clocktype delay =
		            (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);
		        desdReportPkt->sendtime +=delay;



		        desdReportPkt = (TbcrDescendantReportPacket *) MESSAGE_ReturnPacket(newMsg);
		        desdReportPkt->destination = tbcr->iface[interfaceIndex].address.interfaceAddr.ipv4;




		        if (TBCR_DEBUG_TBCR_TRACE)
		        {
		            TbcrPrintTrace(node, newMsg, 'S',IPV6);
		        }

		        TbcrSendPacket(
		            node,
		            MESSAGE_Duplicate(node, newMsg),
		            tbcr->iface[interfaceIndex].address,
		            *destAddr,
		            interfaceIndex,
		            1,
		            destAddr->interfaceAddr.ipv4,
		            delay,
		            isDelay);

		    //printf("TbcrSendPacket!\n");
		    MESSAGE_Free(node, newMsg);

		    tbcr->stats.numDescendantReportSent++;

}


// /**
// FUNCTION   :: TbrcUnicastParentFailedMessage
// LAYER      :: NETWORK
// PURPOSE    :: Function to unicast parent failed messages
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +tbcr:  TbcrData* : Pointer to TBCR Data.
//  +destAddr: Address* : destination address (child address)
//  +InterfaceIndex: UInt32 : interface index
// RETURN     :: void : NULL.
// **/
static
void TbcrUnicastParentFailedMessage(Node* node, TbcrData* tbcr, Address* destAddr, UInt32 interfaceIndex)
{
			Message* newMsg = NULL;
			TbcrParentFailedPacket* parentFailPkt = NULL;
		    NetworkRoutingProtocolType protocolType = ROUTING_PROTOCOL_TBCR;
		    char* pktPtr = NULL;
		    int pktSize = sizeof(TbcrParentFailedPacket);
		    int i= 0;
		    UInt32 typeBits = 0;
		    BOOL isDelay = TRUE;
		    BOOL IPV6 = FALSE;


		    if (TBCR_DEBUG)
		    {
		        char time[MAX_STRING_LENGTH];
		        TIME_PrintClockInSecond(getSimTime(node), time);
		        printf("Node %u is sending parent failed packet at %s\n",
		            node->nodeId, time);
		    }

		    newMsg = MESSAGE_Alloc(
		                 node,
		                 NETWORK_LAYER,
		                 protocolType,
		                 MSG_MAC_FromNetwork);

		    MESSAGE_PacketAlloc(
		        node,
		        newMsg,
		        pktSize,
		        TRACE_TBCR);

		    pktPtr = (char *) MESSAGE_ReturnPacket(newMsg);
		    memset(pktPtr, 0, pktSize);
		    typeBits |= (TBCR_PARENT_FAILED << 24);
		    parentFailPkt = (TbcrParentFailedPacket *) pktPtr;
		    parentFailPkt->typeBits = typeBits;
		    parentFailPkt->sourceAddr = ANY_IP;
		    parentFailPkt->sendtime = getSimTime(node);



			if (TbcrIsEligibleInterface(node, destAddr, &tbcr->iface[interfaceIndex])
																	== FALSE)
			{
				printf("interface %d is not eligible\n", interfaceIndex);
			}

			clocktype delay =
				(clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);
			parentFailPkt->sendtime +=delay;



			parentFailPkt = (TbcrParentFailedPacket *) MESSAGE_ReturnPacket(newMsg);
			parentFailPkt->destination = tbcr->iface[interfaceIndex].address.interfaceAddr.ipv4;




			if (TBCR_DEBUG_TBCR_TRACE)
			{
				TbcrPrintTrace(node, newMsg, 'S',IPV6);
			}

			TbcrSendPacket(
				node,
				MESSAGE_Duplicate(node, newMsg),
				tbcr->iface[interfaceIndex].address,
				*destAddr,
				interfaceIndex,
				1,
				destAddr->interfaceAddr.ipv4,
				delay,
				isDelay);

		    //printf("TbcrSendPacket!\n");
		    MESSAGE_Free(node, newMsg);




		    tbcr->stats.numParentfailedSent++;
}
// /**
// FUNCTION   :: TbrcUnicastParentConfirmMessage
// LAYER      :: NETWORK
// PURPOSE    :: Function to unicast parent confirm messages
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +tbcr:  TbcrData* : Pointer to TBCR Data.
//  +destAddr Address* : destination address.
//  +interface: Unit32 : outgoing interface
// RETURN     :: void : NULL.
// **/
static
void TbcrUnicastParentConfirmMessage(Node* node, TbcrData* tbcr, Address* destAddr, UInt32 interfaceIndex)
{
	    Message* newMsg = NULL;
	    TbcrParentRequestAndConfirmPacket* parentReqConPkt = NULL;
	    NetworkRoutingProtocolType protocolType = ROUTING_PROTOCOL_TBCR;
	    char* pktPtr = NULL;
	    int pktSize = sizeof(TbcrParentRequestAndConfirmPacket);
	    int i= 0;
	    UInt32 typeBits = 0;
	    BOOL isDelay = TRUE;
	    BOOL IPV6 = FALSE;


	    if (TBCR_DEBUG)
	    {
	        char time[MAX_STRING_LENGTH];
	        TIME_PrintClockInSecond(getSimTime(node), time);
	        printf("Node %u is sending parent confirm packet at %s\n",
	            node->nodeId, time);
	    }

	    newMsg = MESSAGE_Alloc(
	                 node,
	                 NETWORK_LAYER,
	                 protocolType,
	                 MSG_MAC_FromNetwork);

	    MESSAGE_PacketAlloc(
	        node,
	        newMsg,
	        pktSize,
	        TRACE_TBCR);

	    pktPtr = (char *) MESSAGE_ReturnPacket(newMsg);

	    memset(pktPtr, 0, pktSize);



	    typeBits |= (TBCR_PARENT_CONFIRM << 24);




	       parentReqConPkt = (TbcrParentRequestAndConfirmPacket *) pktPtr;
	       parentReqConPkt->typeBits = typeBits;
	       parentReqConPkt->sourceAddr = ANY_IP;
	       parentReqConPkt->sendtime = getSimTime(node);



	        if (TbcrIsEligibleInterface(node, destAddr, &tbcr->iface[interfaceIndex])
	                                                                == FALSE)
	        {
	            printf("interface %d is not eligible\n", interfaceIndex);
	        }

	        clocktype delay =
	            (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);
	        parentReqConPkt->sendtime +=delay;



	        parentReqConPkt = (TbcrParentRequestAndConfirmPacket *) MESSAGE_ReturnPacket(newMsg);
	        parentReqConPkt->destination = tbcr->iface[interfaceIndex].address.interfaceAddr.ipv4;




	        if (TBCR_DEBUG_TBCR_TRACE)
	        {
	            TbcrPrintTrace(node, newMsg, 'S',IPV6);
	        }

	        TbcrSendPacket(
	            node,
	            MESSAGE_Duplicate(node, newMsg),
	            tbcr->iface[interfaceIndex].address,
	            *destAddr,
	            interfaceIndex,
	            1,
	            destAddr->interfaceAddr.ipv4,
	            delay,
	            isDelay);

	    //printf("TbcrSendPacket!\n");
	    MESSAGE_Free(node, newMsg);




	    tbcr->stats.numParentConfirmSent++;



}
// /**
// FUNCTION   :: TbrcUnicastParentRequestMessage
// LAYER      :: NETWORK
// PURPOSE    :: Function to unicast parent request messages
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +tbcr:  TbcrData* : Pointer to TBCR Data.
//  +destAddr Address* : destination address.
//  +interface: Unit32 : outgoing interface
// RETURN     :: void : NULL.
// **/
static
void TbrcUnicastParentRequestMessage(Node* node, TbcrData* tbcr, Address* destAddr, UInt32 interfaceIndex)
{

    Message* newMsg = NULL;
    TbcrParentRequestAndConfirmPacket* parentReqConPkt = NULL;
    NetworkRoutingProtocolType protocolType = ROUTING_PROTOCOL_TBCR;
    char* pktPtr = NULL;
    int pktSize = sizeof(TbcrParentRequestAndConfirmPacket);
    int i= 0;
    UInt32 typeBits = 0;
    BOOL isDelay = TRUE;
    BOOL IPV6 = FALSE;


    if (TBCR_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(getSimTime(node), time);
        printf("Node %u is sending parent request packet at %s\n",
            node->nodeId, time);
    }

    newMsg = MESSAGE_Alloc(
                 node,
                 NETWORK_LAYER,
                 protocolType,
                 MSG_MAC_FromNetwork);

    MESSAGE_PacketAlloc(
        node,
        newMsg,
        pktSize,
        TRACE_TBCR);

    pktPtr = (char *) MESSAGE_ReturnPacket(newMsg);

    memset(pktPtr, 0, pktSize);



    typeBits |= (TBCR_PARENT_REQUEST << 24);




       parentReqConPkt = (TbcrParentRequestAndConfirmPacket *) pktPtr;
       parentReqConPkt->typeBits = typeBits;
       parentReqConPkt->sourceAddr = ANY_IP;
       parentReqConPkt->sendtime = getSimTime(node);
       parentReqConPkt->PowerLevel=tbcr->PowerLevel;




        if (TbcrIsEligibleInterface(node, destAddr, &tbcr->iface[interfaceIndex])
                                                                == FALSE)
        {
            printf("interface %d is not eligible\n", interfaceIndex);
        }

        clocktype delay =
            (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);
        parentReqConPkt->sendtime +=delay;



        parentReqConPkt = (TbcrParentRequestAndConfirmPacket *) MESSAGE_ReturnPacket(newMsg);
        parentReqConPkt->destination = tbcr->iface[interfaceIndex].address.interfaceAddr.ipv4;




        if (TBCR_DEBUG_TBCR_TRACE)
        {
            TbcrPrintTrace(node, newMsg, 'S',IPV6);
        }

        TbcrSendPacket(
            node,
            MESSAGE_Duplicate(node, newMsg),
            tbcr->iface[interfaceIndex].address,
            *destAddr,
            interfaceIndex,
            1,
            destAddr->interfaceAddr.ipv4,
            delay,
            isDelay);


    //printf("TbcrSendPacket!\n");
    MESSAGE_Free(node, newMsg);

    tbcr->stats.numParentRequestSent++;



}

// /**
// FUNCTION : TbcrSetTimer
// LAYER    : NETWORK
// PURPOSE  : Set timers for protocol events
// PARAMETERS:
// +node:Node*:Pointer to node which is scheduling an event
// +eventType:int:The event type of the message
// +destAddr:Address:Destination for which the event has been sent (if
//                      necessary)
// +delay:clocktype:Time after which the event will expire
//RETURN    ::void:NULL
// **/

static
void TbcrSetTimer(
         Node* node,
         int eventType,
         Address destAddr,
         clocktype delay)
{
    Message* newMsg = NULL;
    Address* info = NULL;
    NetworkRoutingProtocolType protocolType;

    protocolType = ROUTING_PROTOCOL_TBCR;

    if (TBCR_DEBUG)
    {
        char clockStr[MAX_STRING_LENGTH];

        char address[MAX_STRING_LENGTH];
                 IO_ConvertIpAddressToString(&destAddr, address);


        TIME_PrintClockInSecond(getSimTime(node), clockStr);

        printf("\t\tnow %s\n", clockStr);

        TIME_PrintClockInSecond((getSimTime(node) + delay), clockStr);

        printf("\t\ttimer to expire at %s\n", clockStr);

        if (((destAddr.interfaceAddr.ipv4 != ANY_IP)
            && (destAddr.networkType == NETWORK_IPV4))
            || ((!IS_MULTIADDR6(destAddr.interfaceAddr.ipv6))
            && (destAddr.networkType == NETWORK_IPV6)))
        {
            printf("\t\tdestination %s\n", address);
        }
    }

    // Allocate message for the timer
    newMsg = MESSAGE_Alloc(
                 node,
                 NETWORK_LAYER,
                 protocolType,
                 eventType);

    // Assign the address for which the timer is meant for
    MESSAGE_InfoAlloc(
        node,
        newMsg,
        sizeof(Address));

    info = (Address *) MESSAGE_ReturnInfo(newMsg);

    memcpy(info, &destAddr, sizeof(Address));

    // Schedule the timer after the specified delay
    MESSAGE_Send(node, newMsg, delay);
    printf("SetTimer send  message\n");
}

// /**
// FUNCTION : TbcrNeiListInit
// LAYER    : NETWORK
// PURPOSE  : Init the neighbor list, set the initial value for each attributes
//
// PARAMETERS:
//    void
// RETURN   : poiter to the newly initialed neighbor list.
// **/
static
TbcrNeighborInfo* TbcrNeiListInit(){

	TbcrNeighborInfo* Nei=(TbcrNeighborInfo*)MEM_malloc(sizeof(TbcrNeighborInfo));
	Nei->IsChild=FALSE;
	Nei->IsParent=FALSE;
	Nei->IsParentCand=FALSE;
	Nei->NumOfChd=0;
	Nei->PowerLevel=0;
	Nei->gen=0;
	Nei->lastHeardTime=0;
	Nei->DesdtList=NULL;
	return Nei;
}
// /**
// FUNCTION : TbcrLookupNeibor
// LAYER    : NETWORK
// PURPOSE  : lookup whether there this neighbor is in the list
//
// PARAMETERS:
//    +node: Node*: The node received message
//    +srcAddr: Address:Source Address of the message
//    +NeiList: neibghbor list
//    +interfaceIndex: int :Receiving interface
// RETURN   : neiborinfo if found, NULL otherwise
// **/
static
TbcrNeighborInfo* TbcrLookupNeibor(
		         Node* node,
		         Address srcAddr,
		         TbcrNeighborInfo* NeiList,
		         int interfaceIndex){
	             TbcrNeighborInfo* ptr=NULL;

	             ptr=NeiList;
				 while (ptr!=NULL){
					 if((ptr->Addr.interfaceAddr.ipv4==srcAddr.interfaceAddr.ipv4) && (ptr->outInterface==interfaceIndex)){
						 return ptr;
					 }
					 ptr=ptr->next;
				 }

				 return NULL;

}
// /**
// FUNCTION : TbcrIpIsMyIP()
// LAYER    : NETWORK
// PURPOSE  : Returns true of false depending upon the address matching.
// PARAMETERS:
//  +node:Node*:Pointer to node
//  +destAddr:Address:Address to be compared
// RETURN:
//  +TRUE:BOOL:If its own packet.
//  +FALSE:BOOL: If address do ot matches.
//  **/
static
BOOL TbcrIpIsMyIP(Node* node,Address destAddr)
{

        return(NetworkIpIsMyIP(node,destAddr.interfaceAddr.ipv4));

}
// /**
// FUNCTION : TbcrFlushNeibor
// LAYER    : NETWORK
// PURPOSE  : flush the neighbor list and delete the expired one
//
// PARAMETERS:
//    +node: Node*: The node received message
//    +NeiList: neibghbor list
// RETURN   : true if add successfully/
// **/
static
BOOL TbcrFlushNeibor(
		         Node* node,
		         TbcrNeighborInfo* &NeiList){

	 	 	 	 TbcrData* tbcr=NULL;
	             tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
						node,
						ROUTING_PROTOCOL_TBCR,
						NETWORK_IPV4);

				 if(NeiList==NULL){
					 return NULL;

				 }
                clocktype Defflush=TBCR_FLUSH_TABLE_INTERVAL;

				if(NeiList->next==NULL){
					if(NeiList->ENI>Defflush)
						Defflush=NeiList->ENI;

                	 if((getSimTime(node)-NeiList->lastHeardTime)>Defflush){
						 if(NeiList->IsParent){
							 if(NeiList->Addr.interfaceAddr.ipv4==SOURCE_NODE){
								 return NULL;
							 }
						 tbcr->ParentIsAlive=false;
						// tbcr->gen=200;
						 TbcrBroadcastParentRequestMessage(node, tbcr,&tbcr->defaultInterfaceAddr);
						 }
						 if(NeiList->IsChild){
							 tbcr->hasChild=false;
							 tbcr->HasChildOut=true;
						 }
						 TbcrNeighborInfo* t=NeiList;
						 NeiList=t->next;
						 MEM_free(t);
					  }

                 }
				else{
					 TbcrNeighborInfo* ptr=NeiList;
					 TbcrNeighborInfo* ptrnext;
					 TbcrNeighborInfo* temp;
					 TbcrNeighborInfo* lasttwo;
					 while (ptr){
						 ptrnext=ptr->next;
						 if(ptrnext){
							 if(ptrnext->next==NULL)
								 lasttwo=ptr;
						 }

						 Defflush=TBCR_FLUSH_TABLE_INTERVAL;
						 if(ptr->ENI>Defflush)
							 Defflush=ptr->ENI;

						 if((getSimTime(node)-ptr->lastHeardTime)>Defflush){
							 if(ptr->IsParent){
								 if(ptr->Addr.interfaceAddr.ipv4==SOURCE_NODE){
									 ptr=ptrnext;

									 continue;
								 }
								 else{
							      tbcr->ParentIsAlive=false;
							     // tbcr->gen=200;

							      TbcrBroadcastParentRequestMessage(node, tbcr,&tbcr->defaultInterfaceAddr);
								 }
							 }

						//	  printf("nodeId:%d, del nei %u, at %u",node->nodeId,ptr->Addr.interfaceAddr.ipv4
						//			  ,(getSimTime(node)-ptr->lastHeardTime));
							  if(NeiList->IsChild){
							 		 tbcr->hasChild=false;
							 		 tbcr->HasChildOut=true;
							  }
                              if(ptrnext){
								  ptr->Addr=ptrnext->Addr;
								  ptr->lastHeardTime=ptrnext->lastHeardTime;
								  ptr->IsParentCand=ptrnext->IsParentCand;
								  ptr->IsParent=ptrnext->IsParent;
								  ptr->IsChild=ptrnext->IsChild;
								  ptr->gen=ptrnext->gen;
								  ptr->outInterface=ptrnext->outInterface;
								  ptr->NumOfChd=ptrnext->NumOfChd;
								  ptr->PowerLevel=ptrnext->PowerLevel;
								  ptr->DesdtList=ptrnext->DesdtList;
								  ptr->next=ptrnext->next;
								  ptr->ENI=ptr->ENI;
								  temp=ptrnext;
								  ptrnext=ptr->next;
								  MEM_free(temp);
								}
                              else{
                            	  lasttwo->next=NULL;
                            	  //MEM_free(ptr);
								  ptr=NULL;
                              }
						  }
						  else{
							  ptr=ptrnext;


						  }
						 


				     }

				}
				 return true;



}
// /**
// FUNCTION : TbcrAddNeibor
// LAYER    : NETWORK
// PURPOSE  : Add a new neighbor in the list
//
// PARAMETERS:
//    +node: Node*: The node received message
//    +srcAddr: Address:Source Address of the message
//    +NeiList: neibghbor list
//    +interfaceIndex: int :Receiving interface
// RETURN   : true if add successfully/
// **/
static
BOOL TbcrAddNeibor(
		         Node* node,
		         TbcrNeighborInfo* srcNei,
		         TbcrNeighborInfo* &NeiList,
		         int interfaceIndex){

	             TbcrNeighborInfo* existedNei;//stors the neigbor that already existed in neighbor list.
                 existedNei=TbcrLookupNeibor(node,srcNei->Addr,NeiList,interfaceIndex);
				 if(existedNei!=NULL){
					 if(TBCR_DEBUG_NEILIST){
						 printf("neighbor already there\n");
					 }
					// if((node->nodeId)&0xff==1){
					// printf("neighbor already there\n");
					 existedNei->lastHeardTime=getSimTime(node);

					 return NULL;

				 }

				 if(NeiList==NULL){
					 TbcrNeighborInfo* newentry = NULL;
					 newentry=(TbcrNeighborInfo*)TbcrNeiListInit();
					 newentry->Addr=srcNei->Addr;
					 newentry->IsChild=srcNei->IsChild;
					 newentry->IsParent=srcNei->IsParent;
					 newentry->IsParentCand=srcNei->IsParentCand;
					 newentry->NumOfChd=srcNei->NumOfChd;
					 newentry->PowerLevel=srcNei->PowerLevel;
					 newentry->gen=srcNei->gen;
					 newentry->lastHeardTime=getSimTime(node);
					 newentry->outInterface=interfaceIndex;
					 newentry->next=NULL;
					 NeiList=newentry;

				 }
				 else{
				 TbcrNeighborInfo* ptr=NeiList;
				 while (ptr->next){

					 ptr=ptr->next;
				 }
				 TbcrNeighborInfo* newentry = NULL;
				 newentry=(TbcrNeighborInfo*)TbcrNeiListInit();
				 newentry->Addr=srcNei->Addr;
				 newentry->IsChild=srcNei->IsChild;
				 newentry->IsParent=srcNei->IsParent;
				 newentry->IsParentCand=srcNei->IsParentCand;
				 newentry->NumOfChd=srcNei->NumOfChd;
				 newentry->PowerLevel=srcNei->PowerLevel;
				 newentry->gen=srcNei->gen;
				 newentry->lastHeardTime=getSimTime(node);
				 newentry->outInterface=interfaceIndex;
				 newentry->next=ptr->next;
				 ptr->next=newentry;
				// MEM_free(newentry);

				 }
				 return true;

}

// /**
// FUNCTION: TbcrTransmitData
// LAYER: NETWORK
// PURPOSE:  send data out
// PARAMETERS:
// +node: Node*:Pointer to node(The node which has received data)
// +msg:Message*:Pointer to message(The message received)
// +destAddr:Address:The destination for the packet
// +previousHopAddress:Address:Previous Hop Destination
// RETURN   ::void:Null
// **/
static
void TbcrTransmitData(
		Node* node,
        Message* msg,
        Address destAddr,
        Address previousHopAddress,
        Address nextHopAddr,
        UInt32 InterfaceIndex)
{


		NetworkIpSendPacketToMacLayer(
						node,
						msg,
						InterfaceIndex,
						nextHopAddr.interfaceAddr.ipv4);



}
// /**
// FUNCTION : TbcrCheckRoute
// LAYER    : NETWORK
// PURPOSE  : given a destination address, check whether there is a route to this dest or not
//
// PARAMETERS:
//    +node: Node*: The node received message
//    +destAddr: Address:Destination Address of the message
//    +nextHopAddr: Address&: next hop address
// 	  +InterfaceIndex: UInt32& : out interface of next hop

// RETURN   : true if found
// **/
bool TbcrCheckRoute(
    Node* node,
    Address destAddr,
    Address& nextHopAddr,
    UInt32& InterfaceIndex){

					 TbcrData* tbcr=NULL;
		             tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
										node,
										ROUTING_PROTOCOL_TBCR,
										NETWORK_IPV4);
		             TbcrNeighborInfo* NeiList;
		             NeiList=tbcr->NeiList;
		             if(destAddr.interfaceAddr.ipv4==SOURCE_NODE){

						 nextHopAddr.interfaceAddr.ipv4=tbcr->Parent.interfaceAddr.ipv4;
						 SetIPv4AddressInfo(&nextHopAddr,
											tbcr->Parent.interfaceAddr.ipv4);
						 InterfaceIndex=tbcr->ParentInterface;

		            	 return tbcr->ParentIsAlive;
		             }
		             else{

						 while(NeiList!=NULL&&NeiList->IsChild){
							DescendantList* Dlist;
							Dlist=NeiList->DesdtList;
							while(Dlist){
								if(destAddr.interfaceAddr.ipv4==Dlist->Addr.interfaceAddr.ipv4){
									 nextHopAddr.interfaceAddr.ipv4=NeiList->Addr.interfaceAddr.ipv4;
									 SetIPv4AddressInfo(&nextHopAddr,
														NeiList->Addr.interfaceAddr.ipv4);
									 InterfaceIndex=NeiList->outInterface;
									 return true;
								}
								Dlist=Dlist->next;
							}
							NeiList=NeiList->next;
						 }
		             }

		             return false;

}
// /**
// FUNCTION : GetParent
// LAYER    : NETWORK
// PURPOSE  : return the parent address in neighbor list
//
// PARAMETERS:
//    +node: Node*: The node received message
// RETURN   : true if add successfully
// **/
static
Address*
GetParent(Node* node, UInt32 &parentIntface)
{
	      TbcrData* tbcr=NULL;
          tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
					node,
					ROUTING_PROTOCOL_TBCR,
					NETWORK_IPV4);
          TbcrNeighborInfo* NeiPtr;
          NeiPtr=tbcr->NeiList;
          while(NeiPtr!=NULL){
        	  if(NeiPtr->IsParent==TRUE){
        		  parentIntface=NeiPtr->outInterface;
        		  return &(NeiPtr->Addr);
        	  }
        	  NeiPtr=NeiPtr->next;
          }
          return NULL;

}
// /**
// FUNCTION : TbcrAddParent
// LAYER    : NETWORK
// PURPOSE  : Add a new Parent in the list by setting the parent flag
//
// PARAMETERS:
//    +node: Node*: The node received message
//    +srcAddr: Address:Source Address of the message
//    +interfaceIndex: int :Receiving interface
// RETURN   : true if add successfully/
// **/
static
BOOL TbcrAddParent(Node* node, Address srcAddr, UInt32 interfaceIndex)
{
	     TbcrData* tbcr=NULL;
		 tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
							node,
							ROUTING_PROTOCOL_TBCR,
							NETWORK_IPV4);
		 Int32 OldGen=tbcr->gen;
		 TbcrNeighborInfo* existedNei;//stors the neigbor that already existed in neighbor list.
		 existedNei=TbcrLookupNeibor(node,srcAddr,tbcr->NeiList,interfaceIndex);
		 if(existedNei!=NULL){
			 if(TBCR_DEBUG_NEILIST){
				 printf("neighbor already there\n");
			 }
			existedNei->IsParent=TRUE;
			tbcr->gen=existedNei->gen+1;
			tbcr->ParentIsAlive=true;
			tbcr->Parent.interfaceAddr.ipv4=existedNei->Addr.interfaceAddr.ipv4;
			tbcr->ParentInterface=existedNei->outInterface;
			existedNei->lastHeardTime=getSimTime(node);
		 }
		 else{
			 printf("receive confirm message, but cannot find parent in the neighbor list\n");
		 }

		 if(tbcr->gen>(OldGen+1)){
			 TbcrNeighborInfo* Neilist=tbcr->NeiList;
			 while(Neilist!=NULL){
				 if(Neilist->IsChild){
					 TbcrUnicastParentFailedMessage(node, tbcr, &(Neilist->Addr), Neilist->outInterface);
					 Neilist->IsChild=false;
				 }
				 Neilist=Neilist->next;
			 }

		 }
		 Address destAddr;
		 Address previousHop;
		 Address nextHop;
		 UInt32 InterfaceOfNextHop;
		 Message* msg;
		 destAddr.interfaceAddr.ipv4=SOURCE_NODE;
		 while(true){
			 msg=TbcrGetBufferedPacket(node, destAddr, &previousHop, &tbcr->msgBuffer);
			 if(msg){
				 if(TbcrCheckRoute(node, destAddr,nextHop, InterfaceOfNextHop)){

					TbcrTransmitData(node,msg, destAddr,previousHop,nextHop,InterfaceOfNextHop);
				 }
				// printf("resend data\n");
			 }
			 else{
				 break;
			 }
		 }
		 return true;

}
// /**
// FUNCTION : TbcrDeleteDupDescendant
// LAYER    : NETWORK
// PURPOSE  : delete descendant from child A if this descendant newly come from child B.
// PARAMETERS:
//    +DescendantList*: descendant list of child A.
//    +desc: Address: Address of descendant
// RETURN   : true if add successfully/
// **/
static BOOL TbcrDeleteDupDescendant(DescendantList* &Dlist, Address desc){

		 if(Dlist==NULL){
				 return NULL;

			 }
		 if(Dlist->Addr.interfaceAddr.ipv4==desc.interfaceAddr.ipv4){
			 DescendantList* t=Dlist;
			 Dlist=t->next;
			 MEM_free(t);
		 }
		 else{
			 DescendantList* ptr=NULL;
			 DescendantList* Preptr=Dlist;
			 DescendantList* temp;
			 ptr=Preptr->next;
			 while (ptr){

				 if(ptr->Addr.interfaceAddr.ipv4==desc.interfaceAddr.ipv4){//expired
					 Preptr->next=ptr->next;
					 temp=ptr;
					 ptr=Preptr->next;
					 MEM_free(temp);
				 }
				 if(ptr){
					 Preptr=ptr;
					 ptr=ptr->next;
				 }
			 }

		}
		 return true;

}
// /**
// FUNCTION : TbcrCheckDescendant
// LAYER    : NETWORK
// PURPOSE  : check whether this descendant already under a child
// PARAMETERS:
//    +node: Node*: The node received message
//    +srcAddr: Address:Source Address of the message
//    +desc: Address: Address of descendant
// RETURN   : true if add successfully/
// **/
static
int TbcrCheckDescendant(Node* node, Address srcAddr, Address desc)
{
				 TbcrData* tbcr=NULL;
				 tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
									node,
									ROUTING_PROTOCOL_TBCR,
									NETWORK_IPV4);
				 TbcrNeighborInfo* ptr;//stors the neigbor that already existed in neighbor list.
				 ptr=tbcr->NeiList;
				 while(ptr){

						 DescendantList* dlist;
						 dlist=ptr->DesdtList;
						 while(dlist){
							 if((dlist->Addr.interfaceAddr.ipv4==desc.interfaceAddr.ipv4)&&(ptr->Addr.interfaceAddr.ipv4==srcAddr.interfaceAddr.ipv4)){
								 //printf("report redundant descendant message\n");
								 return 0;
								 // found descendant under the same child
							 }
							 if((dlist->Addr.interfaceAddr.ipv4==desc.interfaceAddr.ipv4)&&(ptr->Addr.interfaceAddr.ipv4!=srcAddr.interfaceAddr.ipv4)){//found descendant under another child
								 TbcrDeleteDupDescendant(ptr->DesdtList, desc);// delete it.
								 return 1;// if true, this node is the most recent ancestor, no need to report again.
							 }
							 dlist=dlist->next;
						 }

						 ptr=ptr->next;
				 }

				 return 2;

}
// /**
// FUNCTION : TbcrAddDescendant
// LAYER    : NETWORK
// PURPOSE  : add descendant under one child
// PARAMETERS:
//    +node: Node*: The node received message
//    +srcAddr: Address:Source Address of the message
//    +desc: descendant address
//    +interfaceIndex: int :Receiving interface
// RETURN   : true if add successfully/
// **/
static
BOOL TbcrAddDescendant(Node* node, Address srcAddr, Address desc, UInt32 interfaceIndex)
{
					 TbcrData* tbcr=NULL;
		             tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
										node,
										ROUTING_PROTOCOL_TBCR,
										NETWORK_IPV4);
		             TbcrNeighborInfo* existedNei;//stors the neigbor that already existed in neighbor list.
	                 existedNei=TbcrLookupNeibor(node,srcAddr,tbcr->NeiList,interfaceIndex);
                     char addr[MAX_STRING_LENGTH];
					 IO_ConvertIpAddressToString(&srcAddr, addr);

	                 if(existedNei==NULL){
	                	 printf("can not find node %s in Neilist\n", addr);
	                 }
	                 else{
	                	if(existedNei->IsChild!=TRUE){
	                			 printf("node %s is not a child\n", addr);
	                	}

						else{
							    if(TBCR_DEBUG_NEILIST){
									 printf("neighbor already there\n");
								 }
								 if(existedNei->DesdtList==NULL){
									DescendantList* Dlist= (DescendantList*)MEM_malloc(sizeof(DescendantList));
									Dlist->Addr=desc;
									Dlist->next=NULL;
									existedNei->DesdtList=Dlist;

								 }
								 else{
									DescendantList* ptr=existedNei->DesdtList;
									DescendantList* p;

									while(ptr!=NULL){
										if(ptr->Addr.interfaceAddr.ipv4==desc.interfaceAddr.ipv4){
											return true;
										}
										p=ptr;
										ptr=ptr->next;
									}

									ptr=(DescendantList*)MEM_malloc(sizeof(DescendantList));
									ptr->Addr=desc;
									ptr->next=NULL;
									p->next=ptr;
								 }
						}
	                }

					 return true;
}

// /**
// FUNCTION : TbcrAddChildren
// LAYER    : NETWORK
// PURPOSE  : Add a new children in the list if not in the NeiList, other wise change status to child
//
// PARAMETERS:
//    +node: Node*: The node received message
//    +srcAddr: Address:Source Address of the message
//    +interfaceIndex: int :Receiving interface
// RETURN   : true if add successfully/
// **/
static
BOOL TbcrAddChildren(Node* node, TbcrNeighborInfo* nei, UInt32 interfaceIndex)
{
		         TbcrData* tbcr=NULL;
	             tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
									node,
									ROUTING_PROTOCOL_TBCR,
									NETWORK_IPV4);
	             tbcr->HasChildIn=true;// for ENI

	             TbcrNeighborInfo* existedNei;//stors the neigbor that already existed in neighbor list.
                 existedNei=TbcrLookupNeibor(node,nei->Addr,tbcr->NeiList,interfaceIndex);
				 if(existedNei!=NULL){
					 if(TBCR_DEBUG_NEILIST){
						 printf("neighbor already there\n");
					 }
					existedNei->IsChild=TRUE;
					existedNei->gen=tbcr->gen+1;
					existedNei->PowerLevel=nei->PowerLevel;
					existedNei->lastHeardTime=getSimTime(node);



				 }
				 else{
					TbcrNeighborInfo* newNei=(TbcrNeighborInfo* )TbcrNeiListInit();
					newNei->Addr=nei->Addr;
					newNei->IsChild=TRUE;
					newNei->PowerLevel=nei->PowerLevel;
					newNei->lastHeardTime=getSimTime(node);
					int ref=TbcrAddNeibor(node,
								  newNei,
								  tbcr->NeiList,
								  interfaceIndex);
					MEM_free(newNei);

				 }
				 tbcr->hasChild=true;
				 return true;

}

// /**
// FUNCTION : TbcrPrintNeibor
// LAYER    : NETWORK
// PURPOSE  : print neighbors in the list
//
// PARAMETERS:
//    +node: Node*: The node received message
//    +NeiList: neibghbor list
// RETURN   : true if print successfully/
// **/
static
BOOL TbcrPrintNeibor(Node* node,
		         TbcrNeighborInfo* NeiList){
				 printf("Printing Neighbors for node [%d]: \n", node->nodeId);
				 char address[MAX_STRING_LENGTH];

				 while (NeiList!=NULL){
					 IO_ConvertIpAddressToString(NeiList->Addr.interfaceAddr.ipv4, address);
					 int nodeId=MAPPING_GetNodeIdFromInterfaceAddress(node,NeiList->Addr);
                     printf("node:[%d] %s, from Interface: %d, number of Children: %d, generation: %d,"
                    		 "IsParent: %d, IsChild: %d, IsParentCand: %d, PowerLevel: %d\n",
                    		 nodeId,
                    		 address,
                    		 NeiList->outInterface,
                    		 NeiList->NumOfChd,
                    		 NeiList->gen,
                    		 NeiList->IsParent,
                    		 NeiList->IsChild,
                    		 NeiList->IsParentCand,
                    		 NeiList->PowerLevel);
					 NeiList=NeiList->next;
				 }
				 return true;

}
static
BOOL TbcrPrintDescendant(Node* node, TbcrData* tbcr){
				 TbcrNeighborInfo* ptr;
		         DescendantList* Dptr;
		         char addr[MAX_STRING_LENGTH];
		         int nodeId;
		         ptr=tbcr->NeiList;
		         while(ptr!=NULL){
		        	 if(ptr->IsChild){
		        		 IO_ConvertIpAddressToString(&(ptr->Addr), addr);
		        		 Dptr=ptr->DesdtList;
		        		 if(Dptr==NULL){
		        			 nodeId=MAPPING_GetNodeIdFromInterfaceAddress(node,ptr->Addr);
		        			 printf("there is no descendant under child [%d] %s\n", nodeId, addr);
		        		 }
		        		 else{
		        		 nodeId=MAPPING_GetNodeIdFromInterfaceAddress(node,ptr->Addr);
		        		 printf("Child [%d] %s has descendant:\n",nodeId,addr);

		        		 	 while(Dptr!=NULL){
		        		 		 IO_ConvertIpAddressToString(&(Dptr->Addr), addr);
		        		 		 nodeId=MAPPING_GetNodeIdFromInterfaceAddress(node,Dptr->Addr);
		        		 		 printf("\t[%d] %s\n",nodeId,addr);
		        		 		 Dptr=Dptr->next;
		        			 }
		        		 }
		        	 }

		        	 ptr=ptr->next;

		         }
		         return true;
}

// /**
// FUNCTION   :: TbcrHandleHello
// LAYER      :: NETWORK
// PURPOSE    :: Processing procedure when Hello is received.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +msg:  Message* : Pointer to Message.
//  +srcAddr:  Address : Source Address.
//  +interfaceIndex:  int : Interface Index.
// RETURN     :: void : NULL.
// **/
static
void TbcrHandleHello(
         Node* node,
         Message* msg,
         Address srcAddr,
         int interfaceIndex,
         Address destAddr)
{
    TbcrData* tbcr = NULL;

    TbcrHelloPacket* helloPkt = NULL;

    clocktype lifetime;

    TbcrNeighborInfo* neiInfo = NULL;

    Address sourceAddress;
    Address destinationAddress;
    BOOL IPV6 = FALSE;
    UInt32 dseqNum = 0;



    BOOL newRtAdded = FALSE;
    BOOL routeUpdated = FALSE;
    BOOL isHelloMsg = FALSE;
    BOOL isValidRt = FALSE;
    int routingProtocol = 0;





	tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
								node,
								ROUTING_PROTOCOL_TBCR,
								NETWORK_IPV4);
	routingProtocol = ROUTING_PROTOCOL_TBCR;
	helloPkt = (TbcrHelloPacket *) MESSAGE_ReturnPacket(msg);


	SetIPv4AddressInfo(&sourceAddress,helloPkt->sourceAddr);
	SetIPv4AddressInfo(&destinationAddress,
			helloPkt->destination.address);
	// clocktype must be copied to access the field of that type
	lifetime = (clocktype) helloPkt->lifetime * MILLI_SECOND;
	dseqNum = 0;
    if (lifetime == 0)
    {

        ActionData acnData;
        acnData.actionType = DROP;
        acnData.actionComment = DROP_LIFETIME_EXPIRY;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData,
                         tbcr->defaultInterfaceAddr.networkType);
        return;
    }

    if (TBCR_DEBUG)
    {
        char address[MAX_STRING_LENGTH];
        char clockStr[MAX_STRING_LENGTH];

        TIME_PrintClockInSecond(getSimTime(node), clockStr);

        IO_ConvertIpAddressToString(&sourceAddress, address);

        printf("\trrepPkt->srcAddr = %s\n", address);

        IO_ConvertIpAddressToString(&destinationAddress, address);

        printf("\trrepPkt->destAddr = %s\n"
            "\trrepPkt->destSeq = %u\n", address,
            dseqNum);
    }


    if((helloPkt && (helloPkt->sourceAddr == ANY_IP)))
    {
        isHelloMsg = TRUE;
    }


    if (isHelloMsg)
    {
        if (TBCR_DEBUG_HELLO)
        {
            char clockStr[MAX_STRING_LENGTH];

            TIME_PrintClockInSecond(getSimTime(node), clockStr);

            printf("Received hello message at %s\n", clockStr);
        }

        TbcrNeighborInfo* newNei=(TbcrNeighborInfo* )TbcrNeiListInit();
        newNei->Addr=srcAddr;

        int ref=TbcrAddNeibor(node,
        		      newNei,
        		      tbcr->NeiList,
        		      interfaceIndex);

        //printf("received hello from address: %u\n",srcAddr.interfaceAddr.ipv4);

      //  MEM_free(newNei);
        tbcr->stats.numHelloRecved++;

        return;
    }

}
// /**
// FUNCTION   :: TbcrHandleDescendantReport
// LAYER      :: NETWORK
// PURPOSE    :: Processing procedure when DescendantReport is received.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +msg:  Message* : Pointer to Message.
//  +srcAddr:  Address : Source Address.
//  +interfaceIndex:  int : Interface Index.
// RETURN     :: void : NULL.
// **/
static
void TbcrHandleDescendantMessage(
         Node* node,
         Message* msg,
         Address srcAddr,
         int interfaceIndex,
         Address destAddr)
{
				TbcrData* tbcr = NULL;

				TbcrDescendantReportPacket* desdReportPkt = NULL;

			    clocktype lifetime;

			    TbcrNeighborInfo* neiInfo = NULL;

			    Address sourceAddress;
			    Address destinationAddress;
			    BOOL IPV6 = FALSE;
			    UInt32 dseqNum = 0;

			    int routingProtocol = 0;

				tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
											node,
											ROUTING_PROTOCOL_TBCR,
											NETWORK_IPV4);
				routingProtocol = ROUTING_PROTOCOL_TBCR;
				desdReportPkt = (TbcrDescendantReportPacket *) MESSAGE_ReturnPacket(msg);


				SetIPv4AddressInfo(&sourceAddress,desdReportPkt->sourceAddr);
				SetIPv4AddressInfo(&destinationAddress,
						desdReportPkt->destination);
				// clocktype must be copied to access the field of that type
				lifetime = (clocktype) desdReportPkt->lifetime * MILLI_SECOND;
				dseqNum = 0;

			    if (TBCR_DEBUG)
			    {
			        char address[MAX_STRING_LENGTH];
			        char clockStr[MAX_STRING_LENGTH];

			        TIME_PrintClockInSecond(getSimTime(node), clockStr);

			        IO_ConvertIpAddressToString(&sourceAddress, address);

			        printf("\tdesdReportPkt->srcAddr = %s\n", address);


			    }
			        if (TBCR_DEBUG_PARENTCLAIM)
			        {
			            char clockStr[MAX_STRING_LENGTH];

			            TIME_PrintClockInSecond(getSimTime(node), clockStr);

			            printf("Received Descendant Report at %s\n", clockStr);
			        }


			        Address desc = desdReportPkt->descendant;
			        switch(TbcrCheckDescendant(node, srcAddr, desc))
			        {
						case 1 :
						{//find this desc already under another child, just delete the old
							TbcrAddDescendant(node, srcAddr, desc, interfaceIndex);// add the new
							break;
						}
			        	case 2:
			        	{//do not find this descendant in the list. just add it and report upwards.

							TbcrAddDescendant(node, srcAddr, desc, interfaceIndex);
							if(!tbcr->isSource){
								UInt32 parentInterface;
								Address* parent=GetParent(node, parentInterface);
								if(parent){
									TbcrUnicastDescendantMessage(node, tbcr, desc, parent,parentInterface);
								}
							}
							break;

			           }
			        	default :{
			        		break;
			        	}
			        }
			        tbcr->stats.numDescendantReportReceived++;

			        return;
}

// /**
// FUNCTION   :: TbcrHandleParentConfirm
// LAYER      :: NETWORK
// PURPOSE    :: Processing procedure when ParentConfirm is received.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +msg:  Message* : Pointer to Message.
//  +srcAddr:  Address : Source Address.
//  +interfaceIndex:  int : Interface Index.
// RETURN     :: void : NULL.
// **/
static
void TbcrHandleParentconfirm(
         Node* node,
         Message* msg,
         Address srcAddr,
         int interfaceIndex,
         Address destAddr)
{
	        TbcrData* tbcr = NULL;

		    TbcrParentRequestAndConfirmPacket* ParentConfirmPkt = NULL;

		    clocktype lifetime;

		    TbcrNeighborInfo* neiInfo = NULL;

		    Address sourceAddress;
		    Address destinationAddress;
		    BOOL IPV6 = FALSE;
		    UInt32 dseqNum = 0;

		    int routingProtocol = 0;

			tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
										node,
										ROUTING_PROTOCOL_TBCR,
										NETWORK_IPV4);
			routingProtocol = ROUTING_PROTOCOL_TBCR;
			ParentConfirmPkt = (TbcrParentRequestAndConfirmPacket *) MESSAGE_ReturnPacket(msg);


			SetIPv4AddressInfo(&sourceAddress,ParentConfirmPkt->sourceAddr);
			SetIPv4AddressInfo(&destinationAddress,
					ParentConfirmPkt->destination);
			// clocktype must be copied to access the field of that type
			lifetime = (clocktype) ParentConfirmPkt->lifetime * MILLI_SECOND;
			dseqNum = 0;

		    if (TBCR_DEBUG)
		    {
		        char address[MAX_STRING_LENGTH];
		        char clockStr[MAX_STRING_LENGTH];

		        TIME_PrintClockInSecond(getSimTime(node), clockStr);

		        IO_ConvertIpAddressToString(&sourceAddress, address);

		        printf("\tParentConfirmPkt->srcAddr = %s\n", address);


		    }






		        if (TBCR_DEBUG_PARENTCLAIM)
		        {
		            char clockStr[MAX_STRING_LENGTH];

		            TIME_PrintClockInSecond(getSimTime(node), clockStr);

		            printf("Received Parent Comfirm message at %s\n", clockStr);
		        }

		        TbcrAddParent(node, srcAddr, interfaceIndex);

		        //tbcrparentclaim next
		        destAddr.networkType = NETWORK_IPV4;
		        destAddr.interfaceAddr.ipv4 = ANY_DEST;
		       // TbcrBroadcastParentClaimMessage(node, tbcr, &destAddr);
		        if((!tbcr->ClaimDone)){
					TbcrBroadcastParentClaimMessage(node, tbcr, &destAddr);
					tbcr->ClaimDone=true;
					tbcr->lastBroadcastSent = getSimTime(node);

				}

		       tbcr->stats.numParentConfirmReceived++;

		        return;



}

// /**
// FUNCTION   :: TbcrHandleParentFailed
// LAYER      :: NETWORK
// PURPOSE    :: Processing procedure when ParentFailed is received.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +msg:  Message* : Pointer to Message.
//  +srcAddr:  Address : Source Address.
//  +interfaceIndex:  int : Interface Index.
// RETURN     :: void : NULL.
// **/
static
void TbcrHandleParentFailed(
         Node* node,
         Message* msg,
         Address srcAddr,
         int interfaceIndex,
         Address destAddr)
{

	    TbcrData* tbcr = NULL;
		TbcrParentFailedPacket* ParentFailPkt = NULL;
		clocktype lifetime;
		TbcrNeighborInfo* neiInfo = NULL;

		Address sourceAddress;
		Address destinationAddress;
		BOOL IPV6 = FALSE;
		UInt32 dseqNum = 0;
		int routingProtocol = 0;

		tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
									node,
									ROUTING_PROTOCOL_TBCR,
									NETWORK_IPV4);
		routingProtocol = ROUTING_PROTOCOL_TBCR;
		ParentFailPkt = (TbcrParentFailedPacket *) MESSAGE_ReturnPacket(msg);

		SetIPv4AddressInfo(&sourceAddress,ParentFailPkt->sourceAddr);
		SetIPv4AddressInfo(&destinationAddress,
				ParentFailPkt->destination);
		// clocktype must be copied to access the field of that type
		lifetime = (clocktype) ParentFailPkt->lifetime * MILLI_SECOND;
		dseqNum = 0;

		if (TBCR_DEBUG)
		{
			char address[MAX_STRING_LENGTH];
			char clockStr[MAX_STRING_LENGTH];
			TIME_PrintClockInSecond(getSimTime(node), clockStr);
			IO_ConvertIpAddressToString(&sourceAddress, address);
			printf("\tParentFailedPkt->srcAddr = %s\n", address);
		}
		if (TBCR_DEBUG_PARENTCLAIM)
			{
				char clockStr[MAX_STRING_LENGTH];

				TIME_PrintClockInSecond(getSimTime(node), clockStr);

				printf("Received Parent failed message at %s\n", clockStr);
			}

			TbcrNeighborInfo* Neilist=tbcr->NeiList;
			 while(Neilist!=NULL){
				 if(Neilist->Addr.interfaceAddr.ipv4==srcAddr.interfaceAddr.ipv4){
					 Neilist->IsParent=false;
					 tbcr->ParentIsAlive=false;
					 //tbcr->gen=200;
					 TbcrBroadcastParentRequestMessage(node, tbcr,&tbcr->defaultInterfaceAddr);

				 }
				 if(Neilist->IsChild){
					 TbcrUnicastParentFailedMessage(node, tbcr, &(Neilist->Addr), Neilist->outInterface);
					 Neilist->IsChild=false;
				 }
				 Neilist=Neilist->next;
			 }

			tbcr->stats.numParentfailedReceived++;

			return;


	}
// /**
// FUNCTION: TbcrHandleData
// LAYER: NETWORK
// PURPOSE:  Processing procedure when data is received from another node.
//           this node is either intermediate hop or destination of the data
// PARAMETERS:
// +node: Node*:Pointer to node(The node which has received data)
// +msg:Message*:Pointer to message(The message received)
// +destAddr:Address:The destination for the packet
// +previousHopAddress:Address:Previous Hop Destination
// RETURN   ::void:Null
// **/

static
void TbcrHandleData(
         Node* node,
         Message* msg,
         Address destAddr,
         Address previousHopAddress)
{
	    TbcrData* tbcr =    NULL;
		IpHeaderType* ipHeader = NULL;
		Address sourceAddress;
		Address nextHop;
		UInt32 InterfaceOfNextHop;

		tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
								node,
								ROUTING_PROTOCOL_TBCR,
								NETWORK_IPV4);
		ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
		SetIPv4AddressInfo(&sourceAddress,
							  ipHeader->ip_src);



		// the node is the destination of the route
		if (TbcrIpIsMyIP(node, destAddr))
		{
			tbcr->stats.numDataRecved++;

			if (TBCR_DEBUG)
			{
				char clockStr[MAX_STRING_LENGTH];
				TIME_PrintClockInSecond(getSimTime(node), clockStr);
				printf("\tis my packet, so let IP handle it\n");
			}
		}
		else{
			tbcr->stats.numDataForward++;
			TbcrData* tbcr=NULL;
			tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
								node,
								ROUTING_PROTOCOL_TBCR,
								NETWORK_IPV4);
			TbcrNeighborInfo* NeiList;
			UInt32 InterfaceIndex;
			MESSAGE_SetLayer(msg, MAC_LAYER, 0);

			MESSAGE_SetEvent(msg, MSG_MAC_FromNetwork);

			if (TBCR_DEBUG)
			{
				char clockStr[MAX_STRING_LENGTH];
				TIME_PrintClockInSecond(getSimTime(node), clockStr);
				printf("\tnot my packet, so need to route\n");
			}

			if(TbcrCheckRoute(node, destAddr,nextHop, InterfaceOfNextHop)){

				TbcrTransmitData(node,msg, destAddr,previousHopAddress,nextHop,InterfaceOfNextHop);
			}
			else{

				TbcrInsertBuffer(
								node,
								msg,
								destAddr,
								previousHopAddress,
								&tbcr->msgBuffer);

			}

		}



}
// /**
// FUNCTION   :: TbcrHandleParentRequest
// LAYER      :: NETWORK
// PURPOSE    :: Processing procedure when ParentRequest is received.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +msg:  Message* : Pointer to Message.
//  +srcAddr:  Address : Source Address.
//  +interfaceIndex:  int : Interface Index.
// RETURN     :: void : NULL.
// **/
static
void TbcrHandleParentRequest(
         Node* node,
         Message* msg,
         Address srcAddr,
         int interfaceIndex,
         Address destAddr)
{
	    TbcrData* tbcr = NULL;

	    TbcrParentRequestAndConfirmPacket* ParentRequestPkt = NULL;

	    clocktype lifetime;

	    TbcrNeighborInfo* neiInfo = NULL;

	    Address sourceAddress;
	    Address destinationAddress;
	    BOOL IPV6 = FALSE;
	    UInt32 dseqNum = 0;




	    int routingProtocol = 0;





		tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
									node,
									ROUTING_PROTOCOL_TBCR,
									NETWORK_IPV4);
		routingProtocol = ROUTING_PROTOCOL_TBCR;
		ParentRequestPkt = (TbcrParentRequestAndConfirmPacket *) MESSAGE_ReturnPacket(msg);


		SetIPv4AddressInfo(&sourceAddress,ParentRequestPkt->sourceAddr);
		SetIPv4AddressInfo(&destinationAddress,
				ParentRequestPkt->destination);
		// clocktype must be copied to access the field of that type
		lifetime = (clocktype) ParentRequestPkt->lifetime * MILLI_SECOND;
		dseqNum = 0;

	    if (TBCR_DEBUG)
	    {
	        char address[MAX_STRING_LENGTH];
	        char clockStr[MAX_STRING_LENGTH];

	        TIME_PrintClockInSecond(getSimTime(node), clockStr);

	        IO_ConvertIpAddressToString(&sourceAddress, address);

	        printf("\tParentRequestPkt->srcAddr = %s\n", address);


	    }






	        if (TBCR_DEBUG_PARENTCLAIM)
	        {
	            char clockStr[MAX_STRING_LENGTH];

	            TIME_PrintClockInSecond(getSimTime(node), clockStr);

	            printf("Received Parent Request message at %s\n", clockStr);
	        }
	        TbcrNeighborInfo* newNei=(TbcrNeighborInfo* )TbcrNeiListInit();
	        newNei->Addr=srcAddr;
	        newNei->PowerLevel=ParentRequestPkt->PowerLevel;

	        TbcrAddNeibor(node,
	        		  newNei,
					  tbcr->NeiList,
					  interfaceIndex);
	        if(tbcr->AllowMoreChild&&(tbcr->ParentIsAlive||tbcr->isSource)){



	        	TbcrAddChildren(node, newNei, interfaceIndex);
	        	TbcrUnicastParentConfirmMessage(node,tbcr,&srcAddr,interfaceIndex);


	        	UInt32 parentInterface;
	        	Address* parent=GetParent(node, parentInterface);
	        	if(!tbcr->isSource){
	        		TbcrUnicastDescendantMessage(node, tbcr, srcAddr, parent,parentInterface);
	        	}

	        }

	        //printf("received hello from address: %u\n",srcAddr.interfaceAddr.ipv4);






	        tbcr->stats.numParentRequestReceived++;

	        return;

}
// /**
// FUNCTION   :: TbrcUnicastAccept
// LAYER      :: NETWORK
// PURPOSE    :: Function to unicast accept message when received broadcast
//               request msg.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +tbcr:  TbcrData* : Pointer to TBCR Data.
//  +destAddr Address* : destination address.
//  +interface: Unit32 : outgoing interface
// RETURN     :: void : NULL.
// **/
static
void TbcrUnicastAcceptMessage(Node* node, TbcrData* tbcr,
		Address* destAddr, UInt32 interfaceIndex)
{
	    Message* newMsg = NULL;
	    //reuse parent claim message to send parent accept
	    TbcrParentClaimPacket* parentAccPkt = NULL;
	    NetworkRoutingProtocolType protocolType = ROUTING_PROTOCOL_TBCR;
	    char* pktPtr = NULL;
	    int pktSize = sizeof(TbcrParentClaimPacket);
	    int i= 0;
	    UInt32 typeBits = 0;
	    BOOL isDelay = TRUE;
	    BOOL IPV6 = FALSE;


	    if (TBCR_DEBUG)
	    {
	        char time[MAX_STRING_LENGTH];
	        TIME_PrintClockInSecond(getSimTime(node), time);
	        printf("Node %u is sending parent request packet at %s\n",
	            node->nodeId, time);
	    }

	    newMsg = MESSAGE_Alloc(
	                 node,
	                 NETWORK_LAYER,
	                 protocolType,
	                 MSG_MAC_FromNetwork);

	    MESSAGE_PacketAlloc(
	        node,
	        newMsg,
	        pktSize,
	        TRACE_TBCR);

	    pktPtr = (char *) MESSAGE_ReturnPacket(newMsg);

	    memset(pktPtr, 0, pktSize);



	    typeBits |= (TBCR_PARENT_ACCT << 24);




	       parentAccPkt = (TbcrParentClaimPacket *) pktPtr;
	       parentAccPkt->typeBits = typeBits;
	       parentAccPkt->sourceAddr = ANY_IP;
	       parentAccPkt->sendtime = getSimTime(node);
	       parentAccPkt->PowerLevel=tbcr->PowerLevel;
	       parentAccPkt->NumOfChd=tbcr->NumOfChd;
	       parentAccPkt->gen=tbcr->gen;



	        if (TbcrIsEligibleInterface(node, destAddr, &tbcr->iface[interfaceIndex])
	                                                                == FALSE)
	        {
	            printf("interface %d is not eligible\n", interfaceIndex);
	        }

	        clocktype delay =
	            (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);
	        parentAccPkt->sendtime +=delay;



	        parentAccPkt = (TbcrParentClaimPacket *) MESSAGE_ReturnPacket(newMsg);
	        parentAccPkt->destination = tbcr->iface[interfaceIndex].address.interfaceAddr.ipv4;




	        if (TBCR_DEBUG_TBCR_TRACE)
	        {
	            TbcrPrintTrace(node, newMsg, 'S',IPV6);
	        }

	        TbcrSendPacket(
	            node,
	            MESSAGE_Duplicate(node, newMsg),
	            tbcr->iface[interfaceIndex].address,
	            *destAddr,
	            interfaceIndex,
	            1,
	            destAddr->interfaceAddr.ipv4,
	            delay,
	            isDelay);

	  //  printf("TbcrSendAcceptPacket!\n");
	    MESSAGE_Free(node, newMsg);

	    tbcr->stats.numAcceptSent++;


}
// /**
// FUNCTION   :: TbcrHandleHeartBeat
// LAYER      :: NETWORK
// PURPOSE    :: Processing procedure when HeatBeat Msg is received.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +msg:  Message* : Pointer to Message.
//  +srcAddr:  Address : Source Address.
//  +interfaceIndex:  int : Interface Index.
// RETURN     :: void : NULL.
// **/

static
void TbcrHandleHeartBeat(
        Node* node,
        Message* msg,
        Address srcAddr,
        int interfaceIndex,
        Address destAddr)
{
		TbcrData* tbcr = NULL;
		TbcrHeartBeatPacket* HeartbeatPkt = NULL;
		clocktype lifetime;
		TbcrNeighborInfo* neiInfo = NULL;
		Address sourceAddress;
		Address destinationAddress;
		BOOL IPV6 = FALSE;
		UInt32 dseqNum = 0;
		int routingProtocol = 0;
		tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
									node,
									ROUTING_PROTOCOL_TBCR,
									NETWORK_IPV4);
		routingProtocol = ROUTING_PROTOCOL_TBCR;
		HeartbeatPkt = (TbcrHeartBeatPacket *) MESSAGE_ReturnPacket(msg);
		SetIPv4AddressInfo(&sourceAddress,HeartbeatPkt->sourceAddr);
		SetIPv4AddressInfo(&destinationAddress,
				HeartbeatPkt->destination);
		//lifetime = (clocktype) HeartbeatPkt->lifetime * MILLI_SECOND;
		dseqNum = 0;



		TbcrNeighborInfo* existedNei;//stors the neigbor that already existed in neighbor list.
		existedNei=TbcrLookupNeibor(node,srcAddr,tbcr->NeiList,interfaceIndex);
		if(existedNei!=NULL){
			 existedNei->PowerLevel=HeartbeatPkt->PowerLevel;
			 existedNei->lastHeardTime=getSimTime(node);
			 existedNei->ENI=HeartbeatPkt->eni;

		}
		else{
			TbcrNeighborInfo* newNei=(TbcrNeighborInfo* )TbcrNeiListInit();
			newNei->Addr=srcAddr;
			newNei->IsParentCand=TRUE;
			//newNei->NumOfChd=ParentClaimPkt->NumOfChd;
			newNei->PowerLevel=HeartbeatPkt->PowerLevel;
			newNei->gen=HeartbeatPkt->gen;
			newNei->lastHeardTime=getSimTime(node);
			newNei->ENI=HeartbeatPkt->eni;
				//Link delay=getSimTime(node)-ParentClaimPkt->sendtime;
			int ref=TbcrAddNeibor(node,
			  newNei,
			  tbcr->NeiList,
			  interfaceIndex);
			MEM_free(newNei);
		}
		tbcr->stats.numHeatBeatReceived++;
		return;



}
// /**
// FUNCTION   :: TbcrHandleBSTParentRequest
// LAYER      :: NETWORK
// PURPOSE    :: Processing procedure when BSTParentRequest is received.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +msg:  Message* : Pointer to Message.
//  +srcAddr:  Address : Source Address.
//  +interfaceIndex:  int : Interface Index.
// RETURN     :: void : NULL.
// **/
static
void TbcrHandleBSTParentRequest(
         Node* node,
         Message* msg,
         Address srcAddr,
         int interfaceIndex,
         Address destAddr)
{
	    TbcrData* tbcr = NULL;
	    TbcrBSTParentRequestPacket* ParentRQPkt = NULL;
	    clocktype lifetime;
	    TbcrNeighborInfo* neiInfo = NULL;
	    Address sourceAddress;
	    Address destinationAddress;
	    BOOL IPV6 = FALSE;
	    UInt32 dseqNum = 0;
	    int routingProtocol = 0;
		tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
									node,
									ROUTING_PROTOCOL_TBCR,
									NETWORK_IPV4);
		routingProtocol = ROUTING_PROTOCOL_TBCR;
		ParentRQPkt = (TbcrBSTParentRequestPacket *) MESSAGE_ReturnPacket(msg);
		SetIPv4AddressInfo(&sourceAddress,ParentRQPkt->sourceAddr);
		SetIPv4AddressInfo(&destinationAddress,
				ParentRQPkt->destination);
		// clocktype must be copied to access the field of that type
		lifetime = (clocktype) ParentRQPkt->lifetime * MILLI_SECOND;
		dseqNum = 0;

	    if (TBCR_DEBUG)
	    {
	        char address[MAX_STRING_LENGTH];
	        char clockStr[MAX_STRING_LENGTH];

	        TIME_PrintClockInSecond(getSimTime(node), clockStr);

	        IO_ConvertIpAddressToString(&sourceAddress, address);

	        printf("\tParentRQPkt->srcAddr = %s\n", address);
	    }
	        if (TBCR_DEBUG_PARENTCLAIM)
	        {
	            char clockStr[MAX_STRING_LENGTH];

	            TIME_PrintClockInSecond(getSimTime(node), clockStr);

	            printf("Received BST Parent Request message at %s\n", clockStr);
	        }

	        TbcrNeighborInfo* existedNei;//stors the neigbor that already existed in neighbor list.
	        existedNei=TbcrLookupNeibor(node,srcAddr,tbcr->NeiList,interfaceIndex);
	        if(existedNei!=NULL){
	        	 existedNei->PowerLevel=ParentRQPkt->PowerLevel;
	        	 existedNei->lastHeardTime=getSimTime(node);

	        }
	        else{
	        TbcrNeighborInfo* newNei=(TbcrNeighborInfo* )TbcrNeiListInit();
	        	        newNei->Addr=srcAddr;
	        	        newNei->PowerLevel=ParentRQPkt->PowerLevel;
	        	        newNei->lastHeardTime=getSimTime(node);
	        	        	//Link delay=getSimTime(node)-ParentClaimPkt->sendtime;
	        int ref=TbcrAddNeibor(node,
	        		      newNei,
	        		      tbcr->NeiList,
	        		      interfaceIndex);
	        MEM_free(newNei);
	        }
	        //printf("received hello from address: %u\n",srcAddr.interfaceAddr.ipv4);
	        tbcr->stats.numBSTParentRequestRecved++;
	        if(tbcr->ParentIsAlive||tbcr->isSource)
	        	TbcrUnicastAcceptMessage(node,tbcr,&srcAddr,interfaceIndex);
	        return;
}
// /**
// FUNCTION   :: TbcrHandleAccept
// LAYER      :: NETWORK
// PURPOSE    :: Processing procedure when Accept message is received.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +msg:  Message* : Pointer to Message.
//  +srcAddr:  Address : Source Address.
//  +interfaceIndex:  int : Interface Index.
// RETURN     :: void : NULL.
// **/
static
void TbcrHandleAccept(
         Node* node,
         Message* msg,
         Address srcAddr,
         int interfaceIndex,
         Address destAddr)
{
	    TbcrData* tbcr = NULL;
	    //reuse parent claim message to send parent accept
	   	TbcrParentClaimPacket* parentAccPkt = NULL;
	    clocktype lifetime;
	    TbcrNeighborInfo* neiInfo = NULL;
	    Address sourceAddress;
	    Address destinationAddress;
	    BOOL IPV6 = FALSE;
	    UInt32 dseqNum = 0;
	    int routingProtocol = 0;
		tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
									node,
									ROUTING_PROTOCOL_TBCR,
									NETWORK_IPV4);
		routingProtocol = ROUTING_PROTOCOL_TBCR;
		parentAccPkt = (TbcrParentClaimPacket *) MESSAGE_ReturnPacket(msg);
		SetIPv4AddressInfo(&sourceAddress,parentAccPkt->sourceAddr);
		SetIPv4AddressInfo(&destinationAddress,
				parentAccPkt->destination);
		// clocktype must be copied to access the field of that type
		lifetime = (clocktype) parentAccPkt->lifetime * MILLI_SECOND;
		dseqNum = 0;
	/*    if (lifetime == 0)
	    {

	        ActionData acnData;
	        acnData.actionType = DROP;
	        acnData.actionComment = DROP_LIFETIME_EXPIRY;
	        TRACE_PrintTrace(node,
	                         msg,
	                         TRACE_NETWORK_LAYER,
	                         PACKET_OUT,
	                         &acnData,
	                         tbcr->defaultInterfaceAddr.networkType);
	        return;
	    }
	*/
	    if (TBCR_DEBUG)
	    {
	        char address[MAX_STRING_LENGTH];
	        char clockStr[MAX_STRING_LENGTH];

	        TIME_PrintClockInSecond(getSimTime(node), clockStr);

	        IO_ConvertIpAddressToString(&sourceAddress, address);

	        printf("\tparentAccPkt->srcAddr = %s\n", address);


	    }
	        if (TBCR_DEBUG_PARENTCLAIM)
	        {
	            char clockStr[MAX_STRING_LENGTH];

	            TIME_PrintClockInSecond(getSimTime(node), clockStr);

	            printf("Received Parent Accept message at %s\n", clockStr);
	        }

	        TbcrNeighborInfo* existedNei;//stors the neigbor that already existed in neighbor list.
	        existedNei=TbcrLookupNeibor(node,srcAddr,tbcr->NeiList,interfaceIndex);
	        if(existedNei!=NULL){
	        	 existedNei->IsParentCand=TRUE;
	        	 existedNei->NumOfChd=parentAccPkt->NumOfChd;
	        	 existedNei->PowerLevel=parentAccPkt->PowerLevel;
	        	 existedNei->gen=parentAccPkt->gen;
	        	 existedNei->lastHeardTime=getSimTime(node);

	        }
	        else{
	        TbcrNeighborInfo* newNei=(TbcrNeighborInfo* )TbcrNeiListInit();
	        	        newNei->Addr=srcAddr;
	        	        newNei->IsParentCand=TRUE;
	        	        newNei->NumOfChd=parentAccPkt->NumOfChd;
	        	        newNei->PowerLevel=parentAccPkt->PowerLevel;
	        	        newNei->gen=parentAccPkt->gen;
	        	        newNei->lastHeardTime=getSimTime(node);
	        	        	//Link delay=getSimTime(node)-ParentClaimPkt->sendtime;
	        int ref=TbcrAddNeibor(node,
	        		      newNei,
	        		      tbcr->NeiList,
	        		      interfaceIndex);
	        MEM_free(newNei);
	        }
	    //    printf("received accept hello by : %d\n",node->nodeId);






	        tbcr->stats.numAcceptReceived++;

	        return;


}
// /**
// FUNCTION   :: TbcrHandleParentClaim
// LAYER      :: NETWORK
// PURPOSE    :: Processing procedure when ParentClaim is received.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +msg:  Message* : Pointer to Message.
//  +srcAddr:  Address : Source Address.
//  +interfaceIndex:  int : Interface Index.
// RETURN     :: void : NULL.
// **/
static
void TbcrHandleParentClaim(
         Node* node,
         Message* msg,
         Address srcAddr,
         int interfaceIndex,
         Address destAddr)
{
    TbcrData* tbcr = NULL;

    TbcrParentClaimPacket* ParentClaimPkt = NULL;

    clocktype lifetime;

    TbcrNeighborInfo* neiInfo = NULL;

    Address sourceAddress;
    Address destinationAddress;
    BOOL IPV6 = FALSE;
    UInt32 dseqNum = 0;




    int routingProtocol = 0;





	tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
								node,
								ROUTING_PROTOCOL_TBCR,
								NETWORK_IPV4);
	routingProtocol = ROUTING_PROTOCOL_TBCR;
	ParentClaimPkt = (TbcrParentClaimPacket *) MESSAGE_ReturnPacket(msg);


	SetIPv4AddressInfo(&sourceAddress,ParentClaimPkt->sourceAddr);
	SetIPv4AddressInfo(&destinationAddress,
			ParentClaimPkt->destination);
	// clocktype must be copied to access the field of that type
	lifetime = (clocktype) ParentClaimPkt->lifetime * MILLI_SECOND;
	dseqNum = 0;
/*    if (lifetime == 0)
    {

        ActionData acnData;
        acnData.actionType = DROP;
        acnData.actionComment = DROP_LIFETIME_EXPIRY;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData,
                         tbcr->defaultInterfaceAddr.networkType);
        return;
    }
*/
    if (TBCR_DEBUG)
    {
        char address[MAX_STRING_LENGTH];
        char clockStr[MAX_STRING_LENGTH];

        TIME_PrintClockInSecond(getSimTime(node), clockStr);

        IO_ConvertIpAddressToString(&sourceAddress, address);

        printf("\tParentClaimPkt->srcAddr = %s\n", address);


    }






        if (TBCR_DEBUG_PARENTCLAIM)
        {
            char clockStr[MAX_STRING_LENGTH];

            TIME_PrintClockInSecond(getSimTime(node), clockStr);

            printf("Received Parent Claim message at %s\n", clockStr);
        }

        TbcrNeighborInfo* existedNei;//stors the neigbor that already existed in neighbor list.
        existedNei=TbcrLookupNeibor(node,srcAddr,tbcr->NeiList,interfaceIndex);
        if(existedNei!=NULL){
        	 existedNei->IsParentCand=TRUE;
        	 existedNei->NumOfChd=ParentClaimPkt->NumOfChd;
        	 existedNei->PowerLevel=ParentClaimPkt->PowerLevel;
        	 existedNei->gen=ParentClaimPkt->gen;
        	 existedNei->lastHeardTime=getSimTime(node);

        }
        else{
        TbcrNeighborInfo* newNei=(TbcrNeighborInfo* )TbcrNeiListInit();
        	        newNei->Addr=srcAddr;
        	        newNei->IsParentCand=TRUE;
        	        newNei->NumOfChd=ParentClaimPkt->NumOfChd;
        	        newNei->PowerLevel=ParentClaimPkt->PowerLevel;
        	        newNei->gen=ParentClaimPkt->gen;
        	        newNei->lastHeardTime=getSimTime(node);
        	        	//Link delay=getSimTime(node)-ParentClaimPkt->sendtime;
        int ref=TbcrAddNeibor(node,
        		      newNei,
        		      tbcr->NeiList,
        		      interfaceIndex);
        MEM_free(newNei);
        }
        //printf("received hello from address: %u\n",srcAddr.interfaceAddr.ipv4);






        tbcr->stats.numParentClaimRecved++;

        return;


}
// /*
// FUNCTION :: TbcrInit.
// LAYER    :: NETWORK.
// PURPOSE  :: Initialization function for TBCR protocol.
// PARAMETERS ::
// + node : Node* : Pointer to Node.
// + tbcrPtr : TbcrData** : Pointer to pointer to TBCR data.
// + nodeInput : const NodeInput* : Pointer to chached config file.
// + interfaceIndex : int : Interface Index.
// RETURN   :: void : NULL.
// **/
void
TbcrInit(
    Node* node,
    TbcrData** tbcrPtr,
    const NodeInput* nodeInput,
    int interfaceIndex,
    NetworkRoutingProtocolType tbcrProtocolType)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    TbcrData* tbcr = (TbcrData *) MEM_malloc(sizeof(TbcrData));

    BOOL retVal;
    char buf[MAX_STRING_LENGTH];
    int i = 0;
    Address destAddr;
    NetworkRoutingProtocolType protocolType;
    destAddr.networkType = NETWORK_INVALID;

    (*tbcrPtr) = tbcr;

    memset(tbcr, 0, sizeof(TbcrData));

    tbcr->iface = (TbcrInterfaceInfo *) MEM_malloc(
                                            sizeof(TbcrInterfaceInfo)
                                            * node->numberInterfaces);

    memset(
        tbcr->iface,
        0,
        sizeof(TbcrInterfaceInfo) * node->numberInterfaces);



        SetIPv4AddressInfo(&tbcr->broadcastAddr, ANY_DEST);



    // Read whether statistics needs to be collected for the protocol
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ROUTING-STATISTICS",
        &retVal,
        buf);

    if ((retVal == FALSE) || (strcmp(buf, "NO") == 0))
    {
        tbcr->statsCollected = FALSE;
    }
    else if (strcmp(buf, "YES") == 0)
    {
        tbcr->statsCollected = TRUE;
    }
    else
    {
        ERROR_ReportError("Needs YES/NO against STATISTICS");
    }

    tbcr->statsPrinted = FALSE;

    // Check enability of TBCR on particular interface and set respective
    // TBCR flag for further use.
    for (i = 0; i < node->numberInterfaces; i++)
    {
        tbcr->iface[i].AFlag = FALSE;


        if(tbcrProtocolType == ROUTING_PROTOCOL_TBCR
            && (NetworkIpGetInterfaceType(node, i) == NETWORK_IPV4
            || NetworkIpGetInterfaceType(node, i) == NETWORK_DUAL)
            && ip->interfaceInfo[i]->routingProtocolType ==
                                    ROUTING_PROTOCOL_TBCR)
        {
            tbcr->iface[i].address.networkType = NETWORK_IPV4;
            tbcr->iface[i].ip_version = NETWORK_IPV4;

            tbcr->iface[i].address.interfaceAddr.ipv4 =
                        NetworkIpGetInterfaceAddress(node, i);

            tbcr->iface[i].tbcr4eligible = TRUE;
            tbcr->iface[i].tbcr6eligible = FALSE;
        }
    }


    TbcrInitTrace(node, nodeInput);

    TbcrInitializeConfigurableParameters(
        node,
        nodeInput,
        tbcr,
        tbcr->iface[interfaceIndex].address);


    tbcr->stats.numParentClaimRecved=0;
    tbcr->stats.numParentClaimSent=0;

    tbcr->ENI=TBCR_DEFAULT_HELLO_INTERVAL;
    tbcr->HasChildIn=false;
    tbcr->HasChildOut=false;

    if(tbcr->iface[interfaceIndex].ip_version == NETWORK_IPV4)
    {
        // Set the mac status handler function
        NetworkIpSetMacLayerStatusEventHandlerFunction(
            node,
            &Tbcr4MacLayerStatusHandler,
            interfaceIndex);

        // Set the router function
        NetworkIpSetRouterFunction(
            node,
            &Tbcr4RouterFunction,
            interfaceIndex);

        destAddr.networkType = NETWORK_IPV4;
        destAddr.interfaceAddr.ipv4 = ANY_DEST;
        protocolType = ROUTING_PROTOCOL_TBCR;

        // Set default Interface Info
        tbcr->defaultInterface = interfaceIndex;

        SetIPv4AddressInfo(
            &tbcr->defaultInterfaceAddr,
            NetworkIpGetInterfaceAddress(node, interfaceIndex));
    }

    if (tbcr->processHello)

    {
        if (TBCR_DEBUG)
        {
            printf("Node %u is setting timer "
                "MSG_NETWORK_SendHello\n", node->nodeId);
        }

        TbcrSetTimer(
            node,
            MSG_NETWORK_SendHello,//defined in api.h
            destAddr,
            TBCR_HELLO_INTERVAL);
    }

       if(tbcr->isSource){
    	   tbcr->gen=0;
       }
    	if (TBCR_DEBUG)
    	        {
    	            printf("Node %u is setting timer as source for "
    	                "MSG_PARENT_CLAIM_BROADCAST\n", node->nodeId);
    	        }

		TbcrSetTimer(
			node,
			MSG_PARENT_CLAIM_BROADCAST,//defined in api.h
			destAddr,
			TBCR_HELLO_INTERVAL);


		TbcrSetTimer(
			node,
			MSG_PARENT_REQUEST_BROADCAST,//defined in api.h
			destAddr,
			TBCR_HELLO_INTERVAL);


		TbcrSetTimer(
			node,
			MSG_SELECT_PARENT,//defined in api.h
			destAddr,
			TBCR_SELECT_PARENT_INTERVAL);//TBCR_SELECT_PARENT_INTERVAL

		TbcrSetTimer(
			node,
			MSG_FLUSH_TABLE,//defined in api.h
			destAddr,
			TBCR_FLUSH_TABLE_INTERVAL);//TBCR_SELECT_PARENT_INTERVAL

		TbcrSetTimer(
			node,
			MSG_HEART_BEAT,//defined in api.h
			destAddr,
			TBCR_HELLO_INTERVAL);
    printf("Node Init!\n");
}//TBD



// /**
// FUNCTION: Tbcr4RouterFunction
// LAYER   : NETWROK
// PURPOSE : Determine the routing action to take for a the given data packet
//          set the PacketWasRouted variable to TRUE if no further handling
//          of this packet by IP is necessary
// PARAMETERS:
// +node:Node *::Pointer to node
// + msg:Message*:The packet to route to the destination
// +destAddr:Address:The destination of the packet
// +previousHopAddress:Address:Last hop of this packet
// +packetWasRouted:BOOL*:set to FALSE if ip is supposed to handle the
//                        routing otherwise TRUE
// RETURN   ::void:NULL
// **/

void
Tbcr4RouterFunction(
    Node* node,
    Message* msg,
    NodeAddress destAddr,
    NodeAddress previousHopAddress,
    BOOL* packetWasRouted)
{


    Address destAddress;
    Address previousHopAddr;

    destAddress.networkType=NETWORK_IPV4;
    destAddress.interfaceAddr.ipv4=destAddr;
    previousHopAddr.interfaceAddr.ipv4 = previousHopAddress;

   if(previousHopAddress)
   {
    previousHopAddr.networkType=NETWORK_IPV4;

   }
   else
   {
      //do nothing
       previousHopAddr.networkType = NETWORK_INVALID;
   }
   //end

    TbcrRouterFunction(node,msg,destAddress,previousHopAddr,packetWasRouted);
}


// /**
// FUNCTION: TbcrRouterFunction
// LAYER   : NETWROK
// PURPOSE : Determine the routing action to take for the given data packet
//          set the PacketWasRouted variable to TRUE if no further handling
//          of this packet by IP is necessary
// PARAMETERS:
// +node:Node *::Pointer to node
// + msg:Message*:The packet to route to the destination
// +destAddr:Address:The destination of the packet
// +previousHopAddress:Address:Last hop of this packet
// +packetWasRouted:BOOL*:set to FALSE if ip is supposed to handle the
//                        routing otherwise TRUE
// RETURN   ::void:NULL
// **/

void TbcrRouterFunction(
    Node* node,
    Message* msg,
    Address destAddr,
    Address previousHopAddress,
    BOOL* packetWasRouted)
{

		TbcrData* tbcr=NULL;
		IpHeaderType* ipHeader = NULL;
		Address sourceAddress;
		Address nextHop;
		UInt32 InterfaceOfNextHop;
		BOOL IPV6 = FALSE;
		BOOL HaveRoute;
		//printf("handle data by routing function\n");

		tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
								node,
								ROUTING_PROTOCOL_TBCR,
								NETWORK_IPV4);
		ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
		SetIPv4AddressInfo(&sourceAddress,
							  ipHeader->ip_src);

		 // Control packets
	    if ((ipHeader && (ipHeader->ip_p == IPPROTO_TBCR)))
	    {
	        return;
	    }

	    if (TBCR_DEBUG)
	    {
	        char clockStr[MAX_STRING_LENGTH];
	        TIME_PrintClockInSecond(getSimTime(node), clockStr);
	        printf("Node %u got packet\n", node->nodeId);
	    }

	    if (TbcrIpIsMyIP(node, destAddr))
	    {
	        *packetWasRouted = false;

	    }
	    else
	    {
	    	*packetWasRouted = true;

	    }

	    if(!TbcrIpIsMyIP(node, sourceAddress)){

	    	TbcrHandleData(node, msg, destAddr, previousHopAddress);

	    }
	    else
	    {
	    	if(!(*packetWasRouted)){
	    		return;
	    	}

	    	if(TbcrCheckRoute(node, destAddr,nextHop, InterfaceOfNextHop)){
	    		TbcrTransmitData(node, msg, destAddr, previousHopAddress,nextHop,InterfaceOfNextHop);

	    	}

	    	else{


	    		TbcrInsertBuffer(
	    		                node,
	    		                msg,
	    		                destAddr,
	    		                previousHopAddress,
	    		                &tbcr->msgBuffer);

	    	}

			if (TBCR_DEBUG)
			{
				char clockStr[MAX_STRING_LENGTH];
				TIME_PrintClockInSecond(getSimTime(node), clockStr);
				printf("\thas route to destination, so send immediately\n");
			}

	    }



}

// /**
// FUNCTION: TbcrMacLayerStatusHandler
// LAYER: NETWORK
// PURPOSE:  Reacts to the signal sent by the MAC protocol after link
//           failure
// PARAMETERS:
// +node:Node*:Pointer to Node
// +msg:Message*:Pointer to message,the message not delivered
// +nextHopAddress:Address:Next Hop Address
// +incomingInterface:int:The interface in which the message was sent
// RETURN   ::void:Null
// **/

void
TbcrMacLayerStatusHandler(
    Node* node,
    const Message* msg,
    const Address genNextHopAddress,
    const int incomingInterface)
{

}
// /**
// FUNCTION: Tbcr4MacLayerStatusHandler
// LAYER: NETWORK
// PURPOSE:  Reacts to the signal sent by the MAC protocol after link
//           failure for IPv4 and in turns call TbcrMacLayerStatusHandler
// PARAMETERS:
// +node:Node*:Pointer to Node
// +msg:Message*:Pointer to message,the message not delivered
// +nextHopAddress:Address:Next Hop Address
// +incomingInterface:int:The interface in which the message was sent
// RETURN   ::void:Null
// **/
void Tbcr4MacLayerStatusHandler(
                                Node* node,
                                const Message* msg,
                                const NodeAddress genNextHopAddress,
                                const int incomingInterface)
{
	}

// /**
// FUNCTION : TbcrHandleProtocolPacket
// LAYER    : NETWORK
// PURPOSE  : Called when Tbcr packet is received from MAC, the packets
//            may be of following types, Route Request, Route Reply,
//            Route Error, Route Acknowledgement
// PARAMETERS:
//    +node: Node*: The node received message
//    +msg: Message*:The message received
//    +srcAddr: Address:Source Address of the message
//    +destAddr: Address: Destination Address of the message
//    +ttl: int: Time to leave
//    +interfaceIndex: int :Receiving interface
// RETURN   : None
// **/

void
TbcrHandleProtocolPacket(
    Node* node,
    Message* msg,
    Address srcAddr,
    Address destAddr,
    int ttl,
    int interfaceIndex)
{

    UInt32* packetType = (UInt32* )MESSAGE_ReturnPacket(msg);
    BOOL IPV6 = FALSE;

    if(srcAddr.networkType == NETWORK_IPV6)
    {
        IPV6 = TRUE;
    }

      //trace recd pkt
      ActionData acnData;
      acnData.actionType = RECV;
      acnData.actionComment = NO_COMMENT;
      TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER,
          PACKET_IN, &acnData , srcAddr.networkType);
      TbcrData* tbcr=NULL;
      tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
     							node,
     							ROUTING_PROTOCOL_TBCR,
     							NETWORK_IPV4);
      TbcrNeighborInfo* existedNei;
      existedNei=TbcrLookupNeibor(node,srcAddr,tbcr->NeiList,interfaceIndex);
	  if(existedNei!=NULL){
			 existedNei->lastHeardTime=getSimTime(node);

	   }

    if (TBCR_DEBUG_TBCR_TRACE)
    {
        TbcrPrintTrace(node, msg, 'R',IPV6);
    }
    int i=*packetType >> 24;
    switch (*packetType >> 24)
    {


        case TBCR_HELLO:
        {
            if (TBCR_DEBUG)
            {
                char clockStr[MAX_STRING_LENGTH];
                char address[MAX_STRING_LENGTH];

                TIME_PrintClockInSecond(getSimTime(node), clockStr);

                printf("Node %u got Hello at time %s\n", node->nodeId,
                    clockStr);

                IO_ConvertIpAddressToString(&srcAddr, address);

                printf("\tfrom: %s\n", address);

                IO_ConvertIpAddressToString(&destAddr, address);

                printf("\tdestination: %s\n", address);
            }


            TbcrHandleHello(
                node,
                msg,
                srcAddr,
                interfaceIndex,
                destAddr);

            MESSAGE_Free(node, msg);

            break;
        }
        case TBCR_PARENT_ACCT:
        {
        	if (TBCR_DEBUG)
			{
				char clockStr[MAX_STRING_LENGTH];
				char address[MAX_STRING_LENGTH];

				TIME_PrintClockInSecond(getSimTime(node), clockStr);

				printf("Node %u got Accept at time %s\n", node->nodeId,
					clockStr);

				IO_ConvertIpAddressToString(&srcAddr, address);

				printf("\tfrom: %s\n", address);

				IO_ConvertIpAddressToString(&destAddr, address);

				printf("\tdestination: %s\n", address);
			}


			TbcrHandleAccept(
				node,
				msg,
				srcAddr,
				interfaceIndex,
				destAddr);



			MESSAGE_Free(node, msg);

			break;
        }
        case TBCR_BST_PARENT_REQUEST:
        {
        	if (TBCR_DEBUG)
			{
				char clockStr[MAX_STRING_LENGTH];
				char address[MAX_STRING_LENGTH];

				TIME_PrintClockInSecond(getSimTime(node), clockStr);

				printf("Node %u got bst request at time %s\n", node->nodeId,
					clockStr);

				IO_ConvertIpAddressToString(&srcAddr, address);

				printf("\tfrom: %s\n", address);

				IO_ConvertIpAddressToString(&destAddr, address);

				printf("\tdestination: %s\n", address);
			}


			TbcrHandleBSTParentRequest(
				node,
				msg,
				srcAddr,
				interfaceIndex,
				destAddr);

			MESSAGE_Free(node, msg);

			break;
		}


        case TBCR_PARENT_CLAIM:
		{
			if (TBCR_DEBUG)
			{
				char clockStr[MAX_STRING_LENGTH];
				char address[MAX_STRING_LENGTH];

				TIME_PrintClockInSecond(getSimTime(node), clockStr);

				printf("Node %u got Parent at time %s\n", node->nodeId,
					clockStr);

				IO_ConvertIpAddressToString(&srcAddr, address);

				printf("\tfrom: %s\n", address);

				IO_ConvertIpAddressToString(&destAddr, address);

				printf("\tdestination: %s\n", address);
			}


			TbcrHandleParentClaim(
				node,
				msg,
				srcAddr,
				interfaceIndex,
				destAddr);

			MESSAGE_Free(node, msg);

			break;
		}
        case TBCR_PARENT_REQUEST:
		{
			if (TBCR_DEBUG)
			{
				char clockStr[MAX_STRING_LENGTH];
				char address[MAX_STRING_LENGTH];

				TIME_PrintClockInSecond(getSimTime(node), clockStr);

				printf("Node %u got Parent Request at time %s\n", node->nodeId,
					clockStr);

				IO_ConvertIpAddressToString(&srcAddr, address);

				printf("\tfrom: %s\n", address);

				IO_ConvertIpAddressToString(&destAddr, address);

				printf("\tdestination: %s\n", address);
			}


		/*	 if(srcAddr==){
								char address[MAX_STRING_LENGTH];
								IO_ConvertIpAddressToString(BestParentAddress.interfaceAddr.ipv4, address);
								printf("node 6 sent request to %d. ",address);
				}
*/
			TbcrHandleParentRequest(
				node,
				msg,
				srcAddr,
				interfaceIndex,
				destAddr);

			MESSAGE_Free(node, msg);

			break;
		}
        case TBCR_PARENT_CONFIRM:
        		{
        			if (TBCR_DEBUG)
        			{
        				char clockStr[MAX_STRING_LENGTH];
        				char address[MAX_STRING_LENGTH];

        				TIME_PrintClockInSecond(getSimTime(node), clockStr);

        				printf("Node %u got Parent Confirm at time %s\n", node->nodeId,
        					clockStr);

        				IO_ConvertIpAddressToString(&srcAddr, address);

        				printf("\tfrom: %s\n", address);

        				IO_ConvertIpAddressToString(&destAddr, address);

        				printf("\tdestination: %s\n", address);
        			}


        			TbcrHandleParentconfirm(
        				node,
        				msg,
        				srcAddr,
        				interfaceIndex,
        				destAddr);

        			MESSAGE_Free(node, msg);

        			break;
        		}
        case TBCR_DESCENDANT_REPORT:
		{
			if (TBCR_DEBUG)
			{
				char clockStr[MAX_STRING_LENGTH];
				char address[MAX_STRING_LENGTH];

				TIME_PrintClockInSecond(getSimTime(node), clockStr);

				printf("Node %u got descendant report at time %s\n", node->nodeId,
					clockStr);

				IO_ConvertIpAddressToString(&srcAddr, address);

				printf("\tfrom: %s\n", address);

				IO_ConvertIpAddressToString(&destAddr, address);

				printf("\tdestination: %s\n", address);
			}


			TbcrHandleDescendantMessage(
				node,
				msg,
				srcAddr,
				interfaceIndex,
				destAddr);

			MESSAGE_Free(node, msg);

			break;
		}
        case TBCR_PARENT_FAILED:
        {
        	TbcrHandleParentFailed(
        					node,
        					msg,
        					srcAddr,
        					interfaceIndex,
        					destAddr);

        				MESSAGE_Free(node, msg);

        				break;
        }

        case TBCR_HEART_BEAT:
	   {
		TbcrHandleHeartBeat(
						node,
						msg,
						srcAddr,
						interfaceIndex,
						destAddr);

		MESSAGE_Free(node, msg);

		break;
	   }

        default:
        {
           ERROR_Assert(FALSE, "Unknown packet type for Tbcr");
           break;
        }
    }

}





// /**
// FUNCTION   :: TbcrHandleProtocolEvent
// LAYER      :: NETWORK
// PURPOSE    :: Handles all the protocol events.
// PARAMETERS ::
//  +node:  Node* : Pointer to node.
//  +msg:  Message* : Pointer to message.
// RETURN     :: void : NULL.
// **/
void
TbcrHandleProtocolEvent(
    Node* node,
    Message* msg)
{

    TbcrData* tbcr = NULL;


    tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
                                node,
                                ROUTING_PROTOCOL_TBCR,
                                NETWORK_IPV4);

    int i =MESSAGE_GetEvent(msg);
    switch (MESSAGE_GetEvent(msg))
    {

    	case MSG_NETWORK_SendHello:
    	{
    		Address* destAddr;
    		clocktype delay = (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);

        	if (tbcr->lastBroadcastSent < (getSimTime(node) -
        			TBCR_HELLO_INTERVAL))
        		{
        		destAddr = (Address* ) MESSAGE_ReturnInfo(msg);

        		TbcrBroadcastHelloMessage(node, tbcr, destAddr);
        		//printf("Handle Hello Message!\n");

        		tbcr->lastBroadcastSent = getSimTime(node);
        		}

        	MESSAGE_Send(node, msg, (clocktype) TBCR_HELLO_INTERVAL + delay);

        	break;
    	}

    	case MSG_PARENT_CLAIM_BROADCAST:
		{

			Address* destAddr;
			clocktype delay = (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);
			if (tbcr->lastBroadcastSent < (getSimTime(node) -
				TBCR_HELLO_INTERVAL))
			{
			destAddr = (Address* ) MESSAGE_ReturnInfo(msg);
		    if((!tbcr->ClaimDone)){
				TbcrBroadcastParentClaimMessage(node, tbcr, destAddr);
                tbcr->ClaimDone=true;
                tbcr->lastBroadcastSent = getSimTime(node);
				  
			}
				//printf("Handle Hello Message!\n");

				}

			   MESSAGE_Send(node, msg, (clocktype) TBCR_HELLO_INTERVAL + delay);


			break;
		}
    	case MSG_PARENT_REQUEST_BROADCAST:
	    {
    		Address* destAddr;
			clocktype delay = (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);
			if (tbcr->lastBroadcastSent < (getSimTime(node) -
				TBCR_HELLO_INTERVAL))
			{
			destAddr = (Address* ) MESSAGE_ReturnInfo(msg);

			if(!(tbcr->ParentIsAlive)&&!(tbcr->isSource)){
				TbcrBroadcastParentRequestMessage(node, tbcr, destAddr);
				tbcr->lastBroadcastSent = getSimTime(node);}
			}
			MESSAGE_Send(node, msg, (clocktype) TBCR_HELLO_INTERVAL + delay);
           // if(node->nodeId==6)
			//printf("Node 6 brocast request\n");
			break;
	    }
    	case MSG_SELECT_PARENT:
    	{
            
    		clocktype delay = (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);
			TbcrNeighborInfo *ptr=NULL;
			Address BestParentAddress;
			BestParentAddress.networkType=NETWORK_IPV4;
			UInt32 interfaceIndex=0;
			UInt32 MinGen=200;
			ptr=tbcr->NeiList;
//ParentIsAlive

			
			clocktype CurrentHeadBestParent;
			if(ptr!=NULL){
				while(ptr!=NULL){//gen is the metric to choose best parent
					if ((ptr->gen<MinGen)&&(ptr->IsParentCand)&&!(ptr->IsChild)){
						MinGen=ptr->gen;
						BestParentAddress.interfaceAddr.ipv4=ptr->Addr.interfaceAddr.ipv4;
						interfaceIndex=ptr->outInterface;
						CurrentHeadBestParent=ptr->lastHeardTime;
					}
				ptr=ptr->next;

				}
			}

			if((BestParentAddress.interfaceAddr.ipv4==
				OldBestParentAddress.interfaceAddr.ipv4)&&(
						LastHeardBestParent==CurrentHeadBestParent)&&
						(BestParentAddress.interfaceAddr.ipv4!=SOURCE_NODE))
				tbcr->trytime++;
			if(tbcr->trytime<2){
				if(!(tbcr->ParentIsAlive)&&!(tbcr->isSource)&&MinGen<200){
					TbrcUnicastParentRequestMessage(node, tbcr, &BestParentAddress, interfaceIndex);
					OldBestParentAddress.interfaceAddr.ipv4=BestParentAddress.interfaceAddr.ipv4;
					LastHeardBestParent=CurrentHeadBestParent;
					 char address[MAX_STRING_LENGTH];
	                 IO_ConvertIpAddressToString(BestParentAddress.interfaceAddr.ipv4, address);
					if(node->nodeId==6)
						printf("6 sends request to%s\n",address);
				}
			}
			else{
				ptr=tbcr->NeiList;
				if(ptr!=NULL){
					while(ptr!=NULL){//gen is the metric to choose best parent
						if (ptr->Addr.interfaceAddr.ipv4==OldBestParentAddress.interfaceAddr.ipv4){
							ptr->IsParentCand=false;
						}
					ptr=ptr->next;
					}
			    }
				tbcr->trytime=0;
			}
			MESSAGE_Send(node, msg, (clocktype) TBCR_SELECT_PARENT_INTERVAL + delay);

			break;

    	}

    	case MSG_FLUSH_TABLE:
    	{
    		clocktype delay = (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);

    		if(!tbcr->isSource)
    			TbcrFlushNeibor(node, tbcr->NeiList);//every time triggered by select parent,
    														//flush neighbor list.
    		MESSAGE_Send(node, msg, (clocktype) TBCR_FLUSH_TABLE_INTERVAL + delay);

    		break;
    	}

    	case MSG_HEART_BEAT:
    	{
    		Address* destAddr;
			//if (tbcr->lastBroadcastSent < (getSimTime(node) -
			//	TBCR_HELLO_INTERVAL*5))
			//{
			destAddr = (Address* ) MESSAGE_ReturnInfo(msg);

			//TbcrNeighborInfor* NeiList=tbcr->NeiList;

			//for(NeiList;NeiList!=null;NeiList=NeiList->next)
			clocktype DecInt=tbcr->ENI;
			clocktype IncInt=tbcr->ENI;
			if(DecInt/2>TBCR_HEART_BEAT_INTERVAL)
				DecInt=DecInt/2;
			else
				DecInt=TBCR_HEART_BEAT_INTERVAL;

			if(tbcr->HasChildIn||tbcr->HasChildOut)
				tbcr->ENI=DecInt;// decrease intervel hence increase rate
			else
				tbcr->ENI=IncInt+SECOND*1;// increase interval hence decrease rate

			if((tbcr->hasChild)&&(tbcr->ParentIsAlive)&&!(tbcr->isSource))
				TbcrBroadcastHeartBeat(node,tbcr,destAddr,tbcr->ENI);


    		clocktype delay = (clocktype) TBCR_PC_ERAND(tbcr->tbcrJitterSeed);

			MESSAGE_Send(node, msg, tbcr->ENI + delay);
			tbcr->HasChildIn=false;
			tbcr->HasChildOut=false;
//consistent with the flush table rate
		//	}
			break;

    	}

    	default:
    	{

    		ERROR_Assert(FALSE, "Tbcr: Unknown MSG type!\n");
    		break;
    	}
    }

	}

// /**
// FUNCTION : TbcrFinalize
// LAYER    : NETWORK
// PURPOSE  :  Called at the end of the simulation to collect the results
// PARAMETERS:
//    +node: Node *:Pointer to Node
//    +i : int: The node for which the statistics are to be printed
// RETURN:    None
// **/

void
TbcrFinalize(Node* node, int i, NetworkType networkType)
{
	    TbcrData* tbcr = NULL;
	    char buf[MAX_STRING_LENGTH];
	    char aodvVerBuf[MAX_STRING_LENGTH];



	    tbcr = (TbcrData *) NetworkIpGetRoutingProtocol(
	                                node,
	                                ROUTING_PROTOCOL_TBCR,
	                                NETWORK_IPV4);

	        sprintf(aodvVerBuf, "TBCR for IPv4");


	    //AodvPrintRoutingTable(node, &aodv->routeTable);

	    if (tbcr->statsCollected && !tbcr->statsPrinted)
	    {
	        tbcr->statsPrinted = TRUE;



	        sprintf(buf, "Number of Hello Packets Sent = %u",
	             tbcr->stats.numHelloSent);

	        IO_PrintStat(
	            node,
	            "Network",
	            aodvVerBuf,
	            ANY_DEST,
	            -1,
	            buf);

	        sprintf(buf, "Number of Hello Packets Received = %u",
	            tbcr->stats.numHelloRecved);
	        IO_PrintStat(
	       	            node,
	       	            "Network",
	       	            aodvVerBuf,
	       	            ANY_DEST,
	       	            -1,
	       	            buf);

	        sprintf(buf, "Number of Parent Claim Packets Received = %u",
	        	            tbcr->stats.numParentClaimRecved);
	        IO_PrintStat(
						node,
						"Network",
						aodvVerBuf,
						ANY_DEST,
						-1,
						buf);

	        sprintf(buf, "Number of Parent Claim Sent = %u",
	        	        	            tbcr->stats.numParentClaimSent);
			IO_PrintStat(
						node,
						"Network",
						aodvVerBuf,
						ANY_DEST,
						-1,
						buf);
			sprintf(buf, "Number of Parent request Received = %u",
				        	        	            tbcr->stats.numParentRequestReceived);
			IO_PrintStat(
						node,
						"Network",
						aodvVerBuf,
						ANY_DEST,
						-1,
						buf);

			sprintf(buf, "Number of Parent request Sent = %u",
							        	         tbcr->stats.numParentRequestSent);
			IO_PrintStat(
						node,
						"Network",
						aodvVerBuf,
						ANY_DEST,
						-1,
						buf);

			sprintf(buf, "Number of Parent confirm received = %u",
										        	tbcr->stats.numParentConfirmReceived);
			IO_PrintStat(
						node,
						"Network",
						aodvVerBuf,
						ANY_DEST,
						-1,
						buf);
			sprintf(buf, "Number of Parent confirm Sent = %u",
										        	tbcr->stats.numParentConfirmSent);
			IO_PrintStat(
						node,
						"Network",
						aodvVerBuf,
						ANY_DEST,
						-1,
						buf);
			sprintf(buf, "Number of Descendant Message Sent = %u",
													tbcr->stats.numDescendantReportSent);
			IO_PrintStat(
						node,
						"Network",
						aodvVerBuf,
						ANY_DEST,
						-1,
						buf);

			sprintf(buf, "Number of Descendant Message received = %u",
													 tbcr->stats.numDescendantReportReceived);
			IO_PrintStat(
						node,
						"Network",
						aodvVerBuf,
						ANY_DEST,
						-1,
						buf);
			sprintf(buf, "Number of Parent Failed Message received = %u",
													 tbcr->stats.numParentfailedReceived);
			IO_PrintStat(
						node,
						"Network",
						aodvVerBuf,
						ANY_DEST,
						-1,
						buf);
			sprintf(buf, "Number of Parent Failed Message sent = %u",
													tbcr->stats.numParentfailedSent);
			IO_PrintStat(
						node,
						"Network",
						aodvVerBuf,
						ANY_DEST,
						-1,
						buf);
			sprintf(buf, "Number of data received  = %u",
												tbcr->stats.numDataRecved);
						IO_PrintStat(
									node,
									"Network",
									aodvVerBuf,
									ANY_DEST,
									-1,
									buf);
		    sprintf(buf, "Number of data forwarded  = %u",
												tbcr->stats.numDataForward);
						IO_PrintStat(
										node,
										"Network",
										aodvVerBuf,
										ANY_DEST,
										-1,
										buf);
			 sprintf(buf, "Number of data Buffered  = %u",
											tbcr->stats.numBufferedData);
			            IO_PrintStat(
									node,
									"Network",
									aodvVerBuf,
									ANY_DEST,
									-1,
									buf);
			sprintf(buf, "Number of Accept Received  = %u",
						tbcr->stats.numAcceptReceived);
			IO_PrintStat(
							node,
							"Network",
							aodvVerBuf,
							ANY_DEST,
							-1,
							buf);
			sprintf(buf, "Number of Accept Sent  = %u",
						tbcr->stats.numAcceptSent);
			IO_PrintStat(
							node,
							"Network",
							aodvVerBuf,
							ANY_DEST,
							-1,
							buf);
			sprintf(buf, "Number of BroadCast Request Received  = %u",
						tbcr->stats.numBSTParentRequestRecved);
			IO_PrintStat(
							node,
							"Network",
							aodvVerBuf,
							ANY_DEST,
							-1,
							buf);
			sprintf(buf, "Number of BroadCast Request Sent  = %u",
						tbcr->stats.numBstParentRequestSent);
			IO_PrintStat(
				node,
				"Network",
				aodvVerBuf,
				ANY_DEST,
				-1,
				buf);

			sprintf(buf, "Number of HeartBeat Received  = %u",
						tbcr->stats.numHeatBeatReceived);
			IO_PrintStat(
							node,
							"Network",
							aodvVerBuf,
							ANY_DEST,
							-1,
							buf);
			sprintf(buf, "Number of HeartBeat Sent  = %u",
						tbcr->stats.numHeatBeatSent);
			IO_PrintStat(
				node,
				"Network",
				aodvVerBuf,
				ANY_DEST,
				-1,
				buf);
}

	    //printf("test:%u\n",tbcr->NeiList->Addr.interfaceAddr.ipv4);
	    TbcrPrintNeibor(node, tbcr->NeiList);
	    if(tbcr->isSource){

	        TbcrPrintDescendant(node,tbcr);

	    }
}



