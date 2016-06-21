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

	//incoming message marked as initiator
	if ((true == ikeheader.IsInitiator()) &&
			(false == ikeheader.IsResponder()))
	{
		//first incoming message send by an initiator
		if (0 == ikeheader.GetMessageId())
		{
			this->HandlePacketWithoutSession(packet, ikeheader);
		}
		else
		{
			//find session
			this->HandlePacketWithSession(packet, ikeheader);
		}
	}
	//incoming message marked as responder
	else if ((false == ikeheader.IsInitiator()) &&
			(true == ikeheader.IsResponder()))
	{
		this->HandlePacketWithSession(packet, ikeheader);
	}
	//both initiator and response flags are marked or unmarked
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
	sa_payload_init.SetPayload(IkeSAPayloadSubstructure::GenerateInitIkeProposal());
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
	session->EtablishGsamInitSa();
	session->SetInitSaInitiatorSpi(initiator_spi);
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

	this->SendMessage(session, packet, dest, true);

	session->GetTimer().SetFunction(&GsamL4Protocol::SendMessage, this);
	session->GetTimer().SetArguments(session, packet, dest, true);
	session->GetTimer().Schedule(session->GetDefaultDelay());
}

void
GsamL4Protocol::SendMessage (Ptr<GsamSession> session, Ptr<Packet> packet, Ipv4Address dest, bool retransmit)
{
	NS_LOG_FUNCTION (this);

	m_socket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(dest), GsamL4Protocol::PROT_NUMBER));

	m_socket->Send(packet);

	if (true == retransmit)
	{
		bool session_retransmit = session->IsRetransmit();
		session->GetTimer().SetFunction(&GsamL4Protocol::SendMessage, this);
		session->GetTimer().SetArguments(session, packet, dest, session_retransmit);
		session->GetTimer().Schedule(session->GetDefaultDelay());
	}
}

void
GsamL4Protocol::HandlePacketWithoutSession (Ptr<Packet> packet, const IkeHeader& ikeheader)
{
	NS_LOG_FUNCTION (this << packet);

	IkeHeader::EXCHANGE_TYPE exchange_type = ikeheader.GetExchangeType();

	if (exchange_type == IkeHeader::IKE_SA_INIT)
	{
		this->HandleIkeSaInit(packet, ikeheader);
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

	uint64_t initiator_spi = ikeheader.GetInitiatorSpi();

	//
	IkePayloadHeader::PAYLOAD_TYPE sa_payload_type = ikeheader.GetNextPayloadType();
	if (sa_payload_type != IkePayloadHeader::SECURITY_ASSOCIATION)
	{
		NS_ASSERT (false);
	}
	IkePayload sa_i_1 = IkePayload::GetEmptyPayloadFromPayloadType(sa_payload_type);
	packet->RemoveHeader(sa_i_1);

	//
	IkePayloadHeader::PAYLOAD_TYPE ke_payload_type = sa_i_1.GetNextPayloadType();
	if (ke_payload_type != IkePayloadHeader::KEY_EXCHANGE)
	{
		NS_ASSERT (false);
	}
	IkePayload ke_i = IkePayload::GetEmptyPayloadFromPayloadType(ke_payload_type);
	packet->RemoveHeader(ke_i);

	//
	IkePayloadHeader::PAYLOAD_TYPE nonce_payload_type = ke_i.GetNextPayloadType();
	if (nonce_payload_type != IkePayloadHeader::NONCE)
	{
		NS_ASSERT (false);
	}
	IkePayload n_i = IkePayload::GetEmptyPayloadFromPayloadType(nonce_payload_type);
	packet->RemoveHeader(n_i);

	uint64_t responder_spi = this->m_ptr_database->GetInfo()->GetLocalAvailableGsamSpi();
	Ptr<GsamSession> session = this->m_ptr_database->CreateSession();
	session->SetRole(GsamSession::RESPONDER);
	session->EtablishGsamInitSa();
	session->SetInitSaInitiatorSpi(initiator_spi);
	session->SetInitSaResponderSpi(responder_spi);
}

void
GsamL4Protocol::RespondIkeSaInit (Ptr<GsamSession> session, Ipv4Address dest)
{
	NS_LOG_FUNCTION (this);

	//setting up Nr
	IkePayload n_r;
	n_r.SetPayload(IkeNonceSubstructure::GenerateNonceSubstructure());

	//setting up KEr
	IkePayload ke_r;
	ke_r.SetPayload(IkeKeyExchangeSubStructure::GetDummySubstructure());
	ke_r.SetNextPayloadType(n_r.GetPayloadType());

	//setting up SAr1
	IkePayload sa_r_1;
	sa_r_1.SetPayload(IkeSAPayloadSubstructure::GenerateInitIkeProposal());
	sa_r_1.SetNextPayloadType(ke_r.GetPayloadType());

	IkeHeader header;
	header.SetAsResponder();
	header.SetInitiatorSpi(session->GetInitSaInitiatorSpi());
	header.SetResponderSpi(session->GetInitSaResponderSpi());
	header.SetMessageId(session->GetCurrentMessageId());
	header.SetIkev2Version();
	header.SetExchangeType(IkeHeader::IKE_AUTH);
	header.SetNextPayloadType(sa_r_1.GetPayloadType());
	header.SetLength(	n_r.GetSerializedSize() +
						ke_r.GetSerializedSize() +
						sa_r_1.GetSerializedSize() +
						header.GetSerializedSize());

	//adding to packet
	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(n_r);
	packet->AddHeader(ke_r);
	packet->AddHeader(sa_r_1);
	packet->AddHeader(header);

	//ready to send
	this->SendMessage(session, packet, dest, true);

	//setting up retransmission
	session->GetTimer().SetFunction(&GsamL4Protocol::SendMessage, this);
	session->GetTimer().SetArguments(session, packet, dest, false);
	session->GetTimer().Schedule(session->GetDefaultDelay());
}

} /* namespace ns3 */
