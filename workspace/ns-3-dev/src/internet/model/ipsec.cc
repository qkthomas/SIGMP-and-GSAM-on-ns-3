/*
 * ipsec.cc
 *
 *  Created on: Jun 9, 2016
 *      Author: lim
 */

#include "ipsec.h"

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

/********************************************************
 *        IpSecSa
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IpSecSa);

TypeId
IpSecSa::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::GsamSa")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<IpSecSa> ()
			;
	return tid;
}

IpSecSa::IpSecSa ()
  :  m_initiator_spi (0),
	 m_responder_spi (0),
	 m_etablished (false),
	 m_ptr_session (0)
{
	NS_LOG_FUNCTION (this);
}

IpSecSa::~IpSecSa()
{
	NS_LOG_FUNCTION (this);
}

TypeId
IpSecSa::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IpSecSa::GetTypeId();
}

void
IpSecSa::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
IpSecSa::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

uint64_t
IpSecSa::GetInitiatorSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_initiator_spi;
}

uint64_t
IpSecSa::GetResponderSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_responder_spi;
}

bool
IpSecSa::IsEtablished (void) const
{
	NS_LOG_FUNCTION (this);
	return this->IsEtablished();
}

/********************************************************
 *        IpSecSession
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IpSecSession);

TypeId
IpSecSession::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::GsamSession")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<IpSecSession> ()
			;
	return tid;
}

IpSecSession::IpSecSession ()
  :  m_message_id (0),
	 m_role (IpSecSession::UNINITIALIZED),
	 m_ptr_sa (0),
	 m_ptr_database (0)
{
	NS_LOG_FUNCTION (this);
}

IpSecSession::~IpSecSession()
{
	NS_LOG_FUNCTION (this);
}

TypeId
IpSecSession::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IpSecSession::GetTypeId();
}

void
IpSecSession::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
IpSecSession::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

uint32_t
IpSecSession::GetMessageId (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_message_id;
}

uint64_t
IpSecSession::GetLocalSpi (void) const
{
	NS_LOG_FUNCTION (this);

	if (0 == this->m_ptr_sa)
	{
		NS_ASSERT (false);
	}

	uint64_t spi = 0;

	if (IpSecSession::UNINITIALIZED == this->m_role)
	{
		NS_ASSERT (false);
	}
	else if (IpSecSession::INITIATOR == this->m_role)
	{
		spi = this->m_ptr_sa->GetInitiatorSpi();
	}
	else if (IpSecSession::RESPONDER == this->m_role)
	{
		spi = this->m_ptr_sa->GetResponderSpi();
	}

	return spi;
}

IpSecSession::ROLE
IpSecSession::GetRole (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_role;
}

uint64_t
IpSecSession::GetInitiatorSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_sa->GetInitiatorSpi();
}

uint64_t
IpSecSession::GetResponderSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_sa->GetResponderSpi();
}

/********************************************************
 *        IpSecDatabase
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IpSecDatabase);

TypeId
IpSecDatabase::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::GsamDatabase")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<IpSecDatabase> ()
			;
	return tid;
}

IpSecDatabase::IpSecDatabase ()
  :  m_window_size (0)
{
	NS_LOG_FUNCTION (this);
	srand(time(0));	//random
}

IpSecDatabase::~IpSecDatabase()
{
	NS_LOG_FUNCTION (this);
}

TypeId
IpSecDatabase::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IpSecDatabase::GetTypeId();
}

void
IpSecDatabase::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
IpSecDatabase::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

uint64_t
IpSecDatabase::GetLocalAvailableSpi (void) const
{
	NS_LOG_FUNCTION (this);

	uint64_t spi = 0;

	std::set<uint64_t>::const_iterator const_it = this->m_set_occupied_spis.find(spi);

	do {
		spi = rand();
	} while (this->m_set_occupied_spis.find(spi) != this->m_set_occupied_spis.end());

	return spi;
}

Ptr<IpSecSession>
IpSecDatabase::GetSession (IpSecSession::ROLE role, uint64_t initiator_spi, uint64_t responder_spi) const
{
	NS_LOG_FUNCTION (this);

	Ptr<IpSecSession> session = 0;

	for (	std::list<Ptr<IpSecSession> >::const_iterator const_it = this->m_lst_ptr_sessions.begin();
			const_it != this->m_lst_ptr_sessions.end();
			const_it++)
	{
		Ptr<IpSecSession> session_it = (*const_it);
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

Ptr<IpSecSession>
IpSecDatabase::CreateSession (void)
{
	NS_LOG_FUNCTION (this);

	Ptr<IpSecSession> session = Create<IpSecSession>();
	this->m_lst_ptr_sessions.push_back(session);

	return session;
}

} /* namespace ns3 */


