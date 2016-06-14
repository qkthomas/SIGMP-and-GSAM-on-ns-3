/*
 * gsam-l4-protocol.cc
 *
 *  Created on: Jun 6, 2016
 *      Author: lim
 */

/*
 * Icmpv3-l4-protocol.cc
 *
 *  Created on: Jan 27, 2016
 *      Author: lin
 */

#include "gsam-l4-protocol.h"

#include "ipv4-raw-socket-factory-impl-multicast.h"
#include "ipv4-interface-multicast.h"
#include "ipv4-l3-protocol-multicast.h"
#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/boolean.h"
#include "ns3/ipv4-route.h"
#include "loopback-net-device.h"
#include "ns3/core-module.h"
#include "ns3/nstime.h"
#include "ipv4-raw-socket-impl-multicast.h"
#include <cstdlib>
#include <ctime>
#include "ns3/socket-factory.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("GsamL4Protocol");

/********************************************************
 *        GsamL4Protocol
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (GsamL4Protocol);

// see rfc 5996
const uint16_t GsamL4Protocol::PROT_NUMBER = 500;

TypeId
GsamL4Protocol::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::GsamL4Protocol")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<GsamL4Protocol> ()
			;
	return tid;
}

GsamL4Protocol::GsamL4Protocol()
  : m_node (0),
	m_socket (0),
	m_ptr_database (0)
{
	// TODO Auto-generated constructor stub
	NS_LOG_FUNCTION (this);
}

GsamL4Protocol::~GsamL4Protocol()
{
	// TODO Auto-generated destructor stub
	NS_LOG_FUNCTION (this);
	NS_ASSERT (m_node == 0);
}

void
GsamL4Protocol::SetNode(Ptr<Node> node)
{
	NS_LOG_FUNCTION (this << node);
	m_node = node;
}

/*
 * This method is called by AddAgregate and completes the aggregation
 * by setting the node in the ICMP stack and adding ICMP factory to
 * IPv4 stack connected to the node
 */
void
GsamL4Protocol::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
	if (m_node == 0)
	{
		Ptr<Node> node = this->GetObject<Node> ();
		if (node != 0)
		{
			Ptr<Ipv4Multicast> ipv4 = this->GetObject<Ipv4Multicast> ();
			if (ipv4 != 0)
			{
				this->SetNode (node);

				Initialization();
			}
		}

	}
	Object::NotifyNewAggregate ();
}

void
GsamL4Protocol::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
	m_node = 0;
	Object::DoDispose ();
}

TypeId
GsamL4Protocol::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return GsamL4Protocol::GetTypeId();
}

void
GsamL4Protocol::Initialization (void)
{
	NS_LOG_FUNCTION (this);
	if (this->m_socket == 0)
	{
		TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
		this->m_socket = Socket::CreateSocket(this->m_node, tid);
	}

	InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), GsamL4Protocol::PROT_NUMBER);
	this->m_socket->Bind(local);
	this->m_socket->SetRecvCallback (MakeCallback (&GsamL4Protocol::HandleRead, this));
	this->m_socket->SetAllowBroadcast (true);
}

void
GsamL4Protocol::HandleRead (Ptr<Socket> socket)
{
	NS_LOG_FUNCTION (this << socket);
	Ptr<Packet> packet;
	Address from;

	packet = socket->RecvFrom (from);

	IkeHeader ikeheader;
	packet->RemoveHeader(ikeheader);

	if (ikeheader.GetInstanceTypeId() != IkeHeader::GetTypeId())
	{
		NS_ASSERT (false);
	}

	//distinguish first whether this is a first incoming message from the initiator, rewrite the code below

	if ((true == ikeheader.IsInitiator()) &&
			(false == ikeheader.IsResponder()))
	{
		//incoming message marked as initiator
		if (0 == ikeheader.GetMessageId())
		{
			//first incoming message send by an initiator
			this->HandlePacketWithoutSession(packet, ikeheader);
		}
		else
		{
			//find session
			this->HandlePacketWithSession(packet, ikeheader);
		}
	}
	else if ((false == ikeheader.IsInitiator()) &&
			(true == ikeheader.IsResponder()))
	{
		//incoming message marked as responder
		this->HandlePacketWithSession(packet, ikeheader);
	}
	else
	{
		//something went wrong
		NS_ASSERT (false);
	}
}

void
GsamL4Protocol::Send_IKE_SA_INIT (Ipv4Address dest)
{
	//rfc 5996 page 10
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = this->m_ptr_database->CreateSession();

	//setting up Ni
	IkePayload nonce_payload_init;
	nonce_payload_init.SetPayload(IkeNonceSubstructure::GenerateNonceSubstructure());
	//setting up KEi
	IkePayload key_payload_init;
	key_payload_init.SetPayload(IkeKeyExchangeSubStructure::GetDummySubstructure());
	key_payload_init.SetNextPayloadType(nonce_payload_init.GetPayloadType());
	//setting up SAi1
	IkePayload sa_payload_init;
	sa_payload_init.SetPayload(IkeSAPayloadSubstructure::GenerateDefaultIkeProposal(this->m_ptr_database->GetInfo()));
	sa_payload_init.SetNextPayloadType(key_payload_init.GetPayloadType());
	//setting up HDR
	IkeHeader ikeheader;
	uint64_t initiator_spi = this->m_ptr_database->GetInfo()->GetLocalAvailableGsamSpi();
	ikeheader.SetInitiatorSpi(initiator_spi);
	ikeheader.SetResponderSpi(0);
	ikeheader.SetIkev2Version();
	ikeheader.SetExchangeType(IkeHeader::IKE_SA_INIT);
	ikeheader.SetAsInitiator();
	//pause setting up HDR, start setting up a new session
	session->SetRole(GsamSession::INITIATOR);
	session->EtablishGsamSa();
	session->SetInitiatorSpi(initiator_spi);
	//continue setting HDR
	ikeheader.SetMessageId(session->GetCurrentMessageId());
	ikeheader.SetNextPayloadType(sa_payload_init.GetPayloadType());
	ikeheader.SetLength(ikeheader.GetSerializedSize() +
						sa_payload_init.GetSerializedSize() +
						key_payload_init.GetSerializedSize() +
						nonce_payload_init.GetSerializedSize());

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(nonce_payload_init);
	packet->AddHeader(key_payload_init);
	packet->AddHeader(sa_payload_init);
	packet->AddHeader(ikeheader);

	this->SendMessage(packet, dest);

	session->GetTimer().SetFunction(&GsamL4Protocol::SendMessage, this);
	session->GetTimer().SetArguments(packet, dest);
}

void
GsamL4Protocol::SendMessage (Ptr<Packet> packet, Ipv4Address dest)
{
	NS_LOG_FUNCTION (this);

	m_socket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(dest), GsamL4Protocol::PROT_NUMBER));

	m_socket->Send(packet);
}

void
GsamL4Protocol::HandlePacketWithoutSession (Ptr<Packet> packet, const IkeHeader& ikeheader)
{
	NS_LOG_FUNCTION (this << packet);

	uint8_t exchange_type = ikeheader.GetExchangeType();

	if (exchange_type == IkeHeader::IKE_SA_INIT)
	{

	}
	else
	{
		//message id == 0, but not IKE_SA_INIT????????
		//dropping
		NS_ASSERT (false);
	}

}

void
GsamL4Protocol::HandlePacketWithSession (Ptr<Packet> packet, const IkeHeader& ikeheader)
{
	NS_LOG_FUNCTION (this << packet);

	//find session
	Ptr<GsamSession> session = this->m_ptr_database->GetSession(ikeheader);

	if (0 != session)
	{

	}
	else
	{
		//message from initiator or message is a reply
	}
}

void
GsamL4Protocol::HandleIkeSaInit (Ptr<Packet> packet, const IkeHeader& ikeheader)
{
	NS_LOG_FUNCTION (this << packet);

//	seal for passing compilation
//	uint64_t initiator_spi = ikeheader.GetInitiatorSpi();
//	uint32_t message_id = ikeheader.GetMessageId();
//
//	IkePayloadHeader::PAYLOAD_TYPE first_payload_type = ikeheader.GetNextPayloadType();
//
//	IkePayload sa_i_1 = IkePayload::GetEmptyPayloadFromPayloadType(first_payload_type);
//	packet->RemoveHeader(sa_i_1);
}

} /* namespace ns3 */
