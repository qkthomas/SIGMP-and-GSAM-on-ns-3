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

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("GsamL4Protocol");

/********************************************************
 *        GsamSa
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (GsamSa);

TypeId
GsamSa::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::GsamSa")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<GsamSa> ()
			;
	return tid;
}

GsamSa::GsamSa ()
  :  m_initiator_spi (0),
	 m_responder_spi (0),
	 m_etablished (false),
	 m_ptr_session (0)
{
	NS_LOG_FUNCTION (this);
}

GsamSa::~GsamSa()
{
	NS_LOG_FUNCTION (this);
}

TypeId
GsamSa::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return GsamSa::GetTypeId();
}

void
GsamSa::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
GsamSa::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

uint64_t
GsamSa::GetInitiatorSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_initiator_spi;
}

uint64_t
GsamSa::GetResponderSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_responder_spi;
}

bool
GsamSa::IsEtablished (void) const
{
	NS_LOG_FUNCTION (this);
	return this->IsEtablished();
}

/********************************************************
 *        GsamSession
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (GsamSession);

TypeId
GsamSession::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::GsamSession")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<GsamSession> ()
			;
	return tid;
}

GsamSession::GsamSession ()
  :  m_message_id (0),
	 m_role (GsamSession::UNINITIALIZED),
	 m_ptr_sa (0),
	 m_ptr_database (0)
{
	NS_LOG_FUNCTION (this);
}

GsamSession::~GsamSession()
{
	NS_LOG_FUNCTION (this);
}

TypeId
GsamSession::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return GsamSession::GetTypeId();
}

void
GsamSession::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
GsamSession::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

uint32_t
GsamSession::GetMessageId (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_message_id;
}

uint64_t
GsamSession::GetLocalSpi (void) const
{
	NS_LOG_FUNCTION (this);

	if (0 == this->m_ptr_sa)
	{
		NS_ASSERT (false);
	}

	uint64_t spi = 0;

	if (GsamSession::UNINITIALIZED == this->m_role)
	{
		NS_ASSERT (false);
	}
	else if (GsamSession::INITIATOR == this->m_role)
	{
		spi = this->m_ptr_sa->GetInitiatorSpi();
	}
	else if (GsamSession::RESPONDER == this->m_role)
	{
		spi = this->m_ptr_sa->GetResponderSpi();
	}

	return spi;
}

GsamSession::ROLE
GsamSession::GetRole (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_role;
}

uint64_t
GsamSession::GetInitiatorSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_sa->GetInitiatorSpi();
}

uint64_t
GsamSession::GetResponderSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_sa->GetResponderSpi();
}

/********************************************************
 *        GsamDatabase
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (GsamDatabase);

TypeId
GsamDatabase::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::GsamDatabase")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<GsamDatabase> ()
			;
	return tid;
}

GsamDatabase::GsamDatabase ()
  :  m_window_size (0)
{
	NS_LOG_FUNCTION (this);
	srand(time(0));	//random
}

GsamDatabase::~GsamDatabase()
{
	NS_LOG_FUNCTION (this);
}

TypeId
GsamDatabase::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return GsamDatabase::GetTypeId();
}

void
GsamDatabase::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
GsamDatabase::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

uint64_t
GsamDatabase::GetLocalAvailableSpi (void) const
{
	NS_LOG_FUNCTION (this);

	uint64_t spi = 0;

	std::set<uint64_t>::const_iterator const_it = this->m_set_occupied_spis.find(spi);

	do {
		spi = rand();
	} while (this->m_set_occupied_spis.find(spi) != this->m_set_occupied_spis.end());

	return spi;
}

Ptr<GsamSession>
GsamDatabase::GetSession (GsamSession::ROLE role, uint64_t initiator_spi, uint64_t responder_spi) const
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = 0;

	for (	std::list<Ptr<GsamSession> >::const_iterator const_it = this->m_lst_ptr_sessions.begin();
			const_it != this->m_lst_ptr_sessions.end();
			const_it++)
	{
		Ptr<GsamSession> session_it = (*const_it);
		if (	(session_it->GetRole() == role) &&
				(session_it->GetInitiatorSpi() == initiator_spi &&
				(session_it->GetResponderSpi() == responder_spi))
			)
		{
			session = session_it;
		}
	}

	return session;
}

Ptr<GsamSession>
GsamDatabase::CreateSession (void)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = Create<GsamSession>();
	this->m_lst_ptr_sessions.push_back(session);

	return session;
}

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
	if (m_socket == 0)
	{
		m_socket->Bind();
		m_socket->SetRecvCallback (MakeCallback (&GsamL4Protocol::HandleRead, this));
		m_socket->SetAllowBroadcast (true);
	}
}

void
GsamL4Protocol::HandleRead (Ptr<Socket> socket)
{
	NS_LOG_FUNCTION (this << socket);
	Ptr<Packet> packet;
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
	sa_payload_init.SetPayload();

	IkeHeader ikeheader;
	uint64_t initiator_spi = this->m_ptr_database->GetLocalAvailableSpi();
	ikeheader.SetInitiatorSpi(initiator_spi);
	ikeheader.SetResponderSpi(0);
	ikeheader.SetIkev2Version();
	ikeheader.SetExchangeType(IkeHeader::IKE_SA_INIT);
	ikeheader.SetAsInitiator();


}

void
GsamL4Protocol::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
	m_node = 0;
	Object::DoDispose ();
}

} /* namespace ns3 */
