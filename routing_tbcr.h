/*This file contains the functions amd constant definition for Tree Based Converge Routing 
 * Protocol and used under the Quanlnet License and agreement.
 * Author1: Zhijing Qin
 * Email: zhijing.qin@gmail.com
 */

#ifndef TBCR_H
#define TBCR_H

#define TBCR_HELLO_INTERVAL            (tbcr->helloInterval)
#define TBCR_PARENT_CLAIM_INTERVAL     (tbcr->parentClaimInterval)
#define TBCR_BROADCAST_JITTER          (20 * MILLI_SECOND)

#define TBCR_ALLOWED_HELLO_LOSS        (tbcr->allowedHelloLoss)
#define TBCR_DEFAULT_ALLOWED_HELLO_LOSS        (2)



#define TBCR_HELLO     1   // hello packet type
#define TBCR_PARENT_CLAIM     2   // parent claim packet type
#define TBCR_PARENT_REQUEST   3   // parent request packet type
#define TBCR_PARENT_CONFIRM   4   // parent confirm packet type
#define TBCR_DESCENDANT_REPORT 5  // report descendant to parent
#define TBCR_PARENT_FAILED    6   // parent failed packet type
#define TBCR_BST_PARENT_REQUEST 7// broad cast parent request when lose old parent
#define TBCR_PARENT_ACCT 8
#define TBCR_HEART_BEAT 9
#define SOURCE_NODE 3187671297 // address of source node
// /**
// Macro that return type of TBCR Message.
// **/
#define TBCR_GetType(bits) ((bits & 0xff000000) >> 24)

// /**
// TBCR HELLO Generation Number.
// **/
#define TBCR_HELLO_GEN typeBitsPrefixSizeHop&0x000000ff

// /**
// TBCR Hop Count Bits.
// **/
#define TBCR_HOP_COUNT_BITS 0x000000ff

typedef struct struct_network_tbcr_str TbcrData;



class D_TbcrPrint : public D_Command
{
    private:
        TbcrData *tbcr;

    public:
        D_TbcrPrint(TbcrData *newTbcr) { tbcr = newTbcr; }

        virtual void ExecuteAsString(const std::string& in, std::string& out);
};


typedef struct descendant_list
{
	Address Addr;
	descendant_list* next;

} DescendantList;

// /**
// STRUCT         ::    TbcrNeighborInfo
// DESCRIPTION    ::    Neighbor list
// **/
typedef struct struct_tbcr_neighbor_info
{
    Address Addr;
    clocktype lastHeardTime;
    bool IsParentCand;
    bool IsParent;
    bool IsChild;
    clocktype ENI;//Expected Next Interval 1 nanosec = clocktype 1
    UInt32 gen;
    UInt32 outInterface;
    UInt32 NumOfChd;
    UInt32 PowerLevel;
    DescendantList* DesdtList;

    struct struct_tbcr_neighbor_info* next;
} TbcrNeighborInfo;


// /**
// STRUCT         ::    TbcrBufferNode
// DESCRIPTION    ::    TBCR for IPv4/IPv6 Structure to store packets
//                      temporarily until one route to the destination
//                      of the packet is found or the packets are timed out
//                      to find a route
// **/
typedef struct str_tbcr_fifo_buffer
{
   // Destination address of the packet
   Address destAddr;

    // The time when the packet was inserted in the buffer
    clocktype timestamp;

    // The last hop which sent the data
    Address previousHop;

    // The packet to be sent
    Message *msg;

    // Pointer to the next message.
    struct str_tbcr_fifo_buffer *next;
} TbcrBufferNode;

// /**
// STRUCT         ::    TbcrMessageBuffer
// DESCRIPTION    ::    Link list for message buffer
// **/
typedef struct
{
    TbcrBufferNode *head;
    int size;
    int numByte;
} TbcrMessageBuffer;

// /**
// STRUCT         ::    TbcrInterfaceInfo
// DESCRIPTION    ::    Tbcr IPv4/IPv6 InterfaceInfo
// **/
typedef struct str_tbcr_interface_info
{
    Address address;
    UInt32 ip_version;
    BOOL tbcr4eligible;
    BOOL tbcr6eligible;
    BOOL AFlag;
} TbcrInterfaceInfo;
// /**
// STRUCT         ::    TbcrStats
// DESCRIPTION    ::    TBCR IPv4/IPv6 Structure to store the statistical
//                      informations.
// **/
typedef struct
{

    UInt32 numHelloSent;
    UInt32 numHelloRecved;
    UInt32 numParentClaimRecved;
    UInt32 numParentClaimSent;
    UInt32 numParentQuestSent;
    UInt32 numParentRequestSent;
    UInt32 numParentRequestReceived;
    UInt32 numParentConfirmSent;
    UInt32 numParentConfirmReceived;
    UInt32 numDescendantReportSent;
    UInt32 numDescendantReportReceived;
    UInt32 numParentfailedSent;
    UInt32 numParentfailedReceived;
    UInt32 numDataRecved;
    UInt32 numDataDroppedForOverlimit;
    UInt32 numDataForward;
    UInt32 numBufferedData;
    UInt32 numBstParentRequestSent;
    UInt32 numBSTParentRequestRecved;
    UInt32 numAcceptSent;
    UInt32 numAcceptReceived;
    UInt32 numHeatBeatSent;
    UInt32 numHeatBeatReceived;


} TbcrStats;

// /**
// STRUCT         ::    TbcrData
// DESCRIPTION    ::    TBCR IPv4/IPv6 structure to store all necessary
//                      informations.
// **/
typedef struct struct_network_tbcr_str
{
	TbcrNeighborInfo* neighborinfo;
	DescendantList* descendantlist;

	BOOL statsCollected;
	BOOL statsPrinted;
	TbcrStats stats;
	BOOL processHello;//0
	BOOL isSource;
	RandomSeed  tbcrJitterSeed;
	Int32 allowedHelloLoss;
	Int32 gen;
	Int32 NumOfChd;
	Int32 PowerLevel;
	bool ClaimDone;
	bool hasChild;
	int trytime;

    clocktype helloInterval;//100
    clocktype parentClaimInterval;

    //data structure for ENI
    clocktype ENI;
    bool HasChildIn;
    bool HasChildOut;

	TbcrInterfaceInfo* iface;
	Address broadcastAddr;
	int defaultInterface;
	Address defaultInterfaceAddr;
	TbcrNeighborInfo* NeiList;
	clocktype lastBroadcastSent;
	clocktype lastParentClaimSent;
	bool ParentIsAlive;
	bool AllowMoreChild;
	Address Parent;
	UInt32 ParentInterface;
	TbcrMessageBuffer msgBuffer;
    Int32 bufferSizeInNumPacket;
	Int32 bufferSizeInByte;
} TbcrData;

// /**
// STRUCT         ::    TbcrAddrSeqInfo
// DESCRIPTION    ::    Address and sequence number for TBCR for IPv4
//                      to be used in Packets.
// **/
typedef struct
{
    NodeAddress address;
    UInt32 seqNum;
} TbcrAddrSeqInfo;


typedef struct
{
	// Next 32-bit variable will be used as
	    // First 8-bits for type
	    // next bit is R-bit
	    // next bit is A-bit
	    // if IPv4 then next 9-bits are reserved and set to zero
	    // else if IPv6 then next 7-bits are reserved and set to zero
	    // if IPv4 then next 5-bit is prefix size
	    // else if IPv6 then next 8-bits is prefix size
	    // last 8-bits is hop count
	    UInt32 typeBitsHopcounts;

	    // destination address and sequence
	    TbcrAddrSeqInfo  destination;

	    // address of the source node which issued the request
	    NodeAddress sourceAddr;
	    UInt32 lifetime;
} TbcrHelloInfo;



// /**
// STRUCT         ::    TbcrHelloPacket
// DESCRIPTION    ::    TBCR for IPv4 route request message format.
// **/
typedef struct
{
	UInt32 typeBitsPrefixSizeHop;
    TbcrHelloInfo info;

    // destination address and sequence
    TbcrAddrSeqInfo destination;

    // source address and sequence
    TbcrAddrSeqInfo source;

        // address of the source node which issued the request
    NodeAddress sourceAddr;
        UInt32 lifetime;
} TbcrHelloPacket;

typedef struct
{
		// Next 32-bit variable will be used as
		    // First 8-bits for type
		    //
		    UInt32 typeBits;

		    // destination address
		    NodeAddress  destination;

		    // address of the source node which issued the request
		    NodeAddress sourceAddr;
		    Int32 gen;
		    Int32 NumOfChd;
		    Int32 PowerLevel;
		    clocktype sendtime;
		    UInt32 lifetime;
} TbcrBSTParentRequestPacket;

typedef struct
{
	// Next 32-bit variable will be used as
	    // First 8-bits for type
	    //
	    UInt32 typeBits;

	    // destination address
	    NodeAddress  destination;

	    // address of the source node which issued the request
	    NodeAddress sourceAddr;
	    Int32 gen;
	    Int32 NumOfChd;
	    Int32 PowerLevel;
	    clocktype sendtime;
	    UInt32 lifetime;
} TbcrParentClaimPacket;
typedef struct
{
	// Next 32-bit variable will be used as
	    // First 8-bits for type
	    //
	    UInt32 typeBits;

	    // destination address
	    NodeAddress  destination;

	    // address of the source node which issued the request
	    NodeAddress sourceAddr;
	    Int32 PowerLevel;
	    clocktype sendtime;
	    UInt32 lifetime;
} TbcrParentRequestAndConfirmPacket;

typedef struct
{

	    UInt32 typeBits;
	    NodeAddress  destination;
	    NodeAddress sourceAddr;
	    Int32 PowerLevel;
	    Int32 gen;
	    clocktype sendtime;
	    UInt32 lifetime;
	    clocktype eni;
} TbcrHeartBeatPacket;

typedef struct
{
	// Next 32-bit variable will be used as
	    // First 8-bits for type
	    //
	    UInt32 typeBits;

	    // destination address
	    NodeAddress  destination;

	    // address of the source node which issued the request
	    NodeAddress sourceAddr;

	    Address descendant;
	    clocktype sendtime;
	    UInt32 lifetime;
} TbcrDescendantReportPacket;

typedef struct
{
		UInt32 typeBits;
		NodeAddress destination;
		NodeAddress sourceAddr;
		clocktype sendtime;
		UInt32 lifetime;
} TbcrParentFailedPacket;




BOOL
TbcrConfigureAFlag(
    Node* node,
    const NodeInput* nodeInput,
    int interfaceIndex);

void TbcrInit(
    Node *node,
    TbcrData **tbcrPtr,
    const NodeInput *nodeInput,
    int interfaceIndex,
    NetworkRoutingProtocolType tbcrProtocolType);

void TbcrFinalize(Node *node, int i, NetworkType networkType);

void TbcrRouterFunction(
    Node *node,
    Message *msg,
    Address destAddr,
    Address previousHopAddress,
    BOOL *packetWasRouted);

void Tbcr4RouterFunction(
    Node* node,
    Message* msg,
    NodeAddress destAddr,
    NodeAddress previousHopAddress,
    BOOL* packetWasRouted);

void TbcrHandleProtocolPacket(
    Node *node,
    Message *msg,
    Address srcAddr,
    Address destAddr,
    int ttl,
    int interfaceIndex);

void
TbcrHandleProtocolEvent(
    Node *node,
    Message *msg);

void
TbcrMacLayerStatusHandler(
    Node *node,
    const Message* msg,
    const Address nextHopAddress,
    const int incommingInterfaceIndex);

void
Tbcr4MacLayerStatusHandler(
    Node *node,
    const Message* msg,
    const NodeAddress nextHopAddress,
    const int incommingInterfaceIndex);

#endif
