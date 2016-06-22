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

NS_LOG_COMPONENT_DEFINE ("GsamSa");

/********************************************************
 *        GsamConfig
 ********************************************************/


Ipv4Address
GsamConfig::GetSecGrpAddressStart (void)
{
	return Ipv4Address ("224.0.0.100");
}

Ipv4Address
GsamConfig::GetSecGrpAddressEnd (void)
{
	return Ipv4Address ("224.0.0.255");
}

/********************************************************
 *        GsamInfo
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (GsamInfo);

TypeId
GsamInfo::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::GsamInfo")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<GsamInfo> ()
			;
	return tid;
}

GsamInfo::GsamInfo ()
  :  m_retransmission_delay (Seconds(0.0)),
	 m_sec_group_start ("0.0.0.0"),
	 m_sec_group_end ("0.0.0.0")
{
	NS_LOG_FUNCTION (this);
}

GsamInfo::~GsamInfo()
{
	NS_LOG_FUNCTION (this);
	this->m_set_occupied_gsam_spis.clear();
	this->m_set_occupied_ipsec_spis.clear();
}

TypeId
GsamInfo::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return GsamInfo::GetTypeId();
}

void
GsamInfo::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
GsamInfo::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

uint32_t
GsamInfo::GetLocalAvailableIpsecSpi (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t spi = 0;

	std::set<uint32_t>::const_iterator const_it = this->m_set_occupied_ipsec_spis.find(spi);

	do {
		spi = rand();
	} while (	(0 != spi) &&
				(this->m_set_occupied_ipsec_spis.find(spi) != this->m_set_occupied_ipsec_spis.end()));

	return spi;
}

uint64_t
GsamInfo::GetLocalAvailableGsamSpi (void) const
{
	NS_LOG_FUNCTION (this);

	uint64_t spi = 0;

	std::set<uint64_t>::const_iterator const_it = this->m_set_occupied_gsam_spis.find(spi);

	do {
		spi = rand();
	} while (	(0 != spi) &&
				(this->m_set_occupied_gsam_spis.find(spi) != this->m_set_occupied_gsam_spis.end()));

	return spi;
}

uint64_t
GsamInfo::RegisterGsamSpi (void)
{
	uint64_t retval = this->GetLocalAvailableGsamSpi();

	this->OccupyGsamSpi(retval);

	return retval;
}
uint32_t
GsamInfo::RegisterIpsecSpi (void)
{
	uint32_t retval = this->GetLocalAvailableIpsecSpi();

	this->OccupyIpsecSpi(retval);

	return retval;
}

Time
GsamInfo::GetRetransmissionDelay (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_retransmission_delay;
}

void
GsamInfo::SetRetransmissionDelay (Time time)
{
	NS_LOG_FUNCTION (this);
	this->m_retransmission_delay = time;
}

void
GsamInfo::OccupyGsamSpi (uint64_t spi)
{
	NS_LOG_FUNCTION (this);
	std::pair<std::set<uint64_t>::iterator, bool> result = this->m_set_occupied_gsam_spis.insert(spi);

	if (result.second == false)
	{
		//there is already a element of the same value of spi in the set
		NS_ASSERT (false);
	}
}

void
GsamInfo::OccupyIpsecSpi (uint32_t spi)
{
	NS_LOG_FUNCTION (this);
	std::pair<std::set<uint32_t>::iterator, bool> result = this->m_set_occupied_ipsec_spis.insert(spi);

	if (result.second == false)
	{
		//there is already a element of the same value of spi in the set
		NS_ASSERT (false);
	}
}

void
GsamInfo::FreeGsamSpi (uint64_t spi)
{
	NS_LOG_FUNCTION (this);

	uint8_t deleted_num_spis = 0;

	deleted_num_spis = this->m_set_occupied_gsam_spis.erase(spi);

	NS_ASSERT (deleted_num_spis == 1);
}
void
GsamInfo::FreeIpsecSpi (uint32_t spi)
{
	NS_LOG_FUNCTION (this);

	uint8_t deleted_num_spis = 0;

	deleted_num_spis = this->m_set_occupied_ipsec_spis.erase(spi);

	NS_ASSERT (deleted_num_spis == 1);
}

void
GsamInfo::SetSecGrpStart (Ipv4Address address)
{
	NS_LOG_FUNCTION (this);
	this->m_sec_group_start = address;
}

void
GsamInfo::SetSecGrpEnd (Ipv4Address address)
{
	NS_LOG_FUNCTION (this);
	this->m_sec_group_end = address;
}

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
  :  m_type (GsamSa::NOT_INITIATED),
	 m_initiator_spi (0),
	 m_responder_spi (0),
	 m_ptr_session (0),
	 m_ptr_encrypt_fn (0)
{
	NS_LOG_FUNCTION (this);
}

GsamSa::~GsamSa()
{
	NS_LOG_FUNCTION (this);

	this->FreeLocalSpi();

	this->m_ptr_session = 0;
	this->m_ptr_encrypt_fn = 0;
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

bool
operator == (GsamSa const& lhs, GsamSa const& rhs)
{
	bool retval = true;

	if (lhs.m_initiator_spi != rhs.m_initiator_spi)
	{
		retval = false;
	}

	if (lhs.m_responder_spi != rhs.m_responder_spi)
	{
		retval = false;
	}

	return retval;
}

GsamSa::SA_TYPE
GsamSa::GetType (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_type;
}
void
GsamSa::SetType (GsamSa::SA_TYPE type)
{
	NS_LOG_FUNCTION (this);
	this->m_type = type;
}

uint64_t
GsamSa::GetInitiatorSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_initiator_spi;
}

void
GsamSa::SetInitiatorSpi (uint64_t spi)
{
	NS_LOG_FUNCTION (this);
	this->m_initiator_spi = spi;
}

uint64_t
GsamSa::GetResponderSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_responder_spi;
}

void
GsamSa::SetResponderSpi (uint64_t spi)
{
	NS_LOG_FUNCTION (this);
	this->m_responder_spi = spi;
}

bool
GsamSa::IsHalfOpen (void) const
{
	NS_LOG_FUNCTION (this);

	bool retval = false;

	if (0 == this->m_initiator_spi)
	{
		retval = true;
	}

	if (0 == this->m_responder_spi)
	{
		retval = true;
	}

	return retval;
}

void
GsamSa::FreeLocalSpi (void)
{
	NS_LOG_FUNCTION (this);

	uint64_t local_spi = this->m_ptr_session->GetLocalSpi();

	this->m_ptr_session->GetInfo()->FreeGsamSpi(local_spi);
}

/********************************************************
 *        EncryptionFunction
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (EncryptionFunction);

TypeId
EncryptionFunction::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::EncryptionFunction")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<EncryptionFunction> ()
			;
	return tid;
}

EncryptionFunction::EncryptionFunction ()
{
	NS_LOG_FUNCTION (this);
}

EncryptionFunction::~EncryptionFunction()
{
	NS_LOG_FUNCTION (this);
}

TypeId
EncryptionFunction::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return EncryptionFunction::GetTypeId();
}

void
EncryptionFunction::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
EncryptionFunction::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

/********************************************************
 *        IpSecSession
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
  :  m_current_message_id (0),
	 m_peer_address (Ipv4Address ("0.0.0.0")),
	 m_role (GsamSession::UNINITIALIZED),
	 m_ptr_init_sa (0),
	 m_ptr_kek_sa (0),
	 m_ptr_database (0)
{
	NS_LOG_FUNCTION (this);
}

GsamSession::~GsamSession()
{
	NS_LOG_FUNCTION (this);
	this->m_ptr_init_sa = 0;
	this->m_ptr_database = 0;
	this->m_ptr_kek_sa = 0;
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

	if (this->m_ptr_database != 0)
	{
		this->m_ptr_database->RemoveSession(this);
	}
}

uint32_t
GsamSession::GetCurrentMessageId (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_current_message_id;
}

bool
operator == (GsamSession const& lhs, GsamSession const& rhs)
{
	bool retval = true;

	if (lhs.m_ptr_init_sa != rhs.m_ptr_init_sa)
	{
		retval = false;
	}

	if (lhs.m_role != rhs.m_role)
	{
		retval = false;
	}

	if (lhs.m_current_message_id != rhs.m_current_message_id)
	{
		retval = false;
	}

	return retval;
}

uint64_t
GsamSession::GetLocalSpi (void) const
{
	NS_LOG_FUNCTION (this);

	if (0 == this->m_ptr_init_sa)
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
		spi = this->m_ptr_init_sa->GetInitiatorSpi();
	}
	else if (GsamSession::RESPONDER == this->m_role)
	{
		spi = this->m_ptr_init_sa->GetResponderSpi();
	}

	return spi;
}

GsamSession::ROLE
GsamSession::GetRole (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_role;
}

void
GsamSession::SetRole (GsamSession::ROLE role)
{
	NS_LOG_FUNCTION (this);
	this->m_role = role;
}

uint64_t
GsamSession::GetInitSaInitiatorSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_init_sa->GetInitiatorSpi();
}

void
GsamSession::SetInitSaInitiatorSpi (uint64_t spi)
{
	NS_LOG_FUNCTION (this);
	if (0 == this->m_ptr_init_sa)
	{
		NS_ASSERT (false);
	}
	else
	{
		this->m_ptr_init_sa->SetInitiatorSpi(spi);
	}
}

uint64_t
GsamSession::GetInitSaResponderSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_init_sa->GetResponderSpi();
}

void
GsamSession::SetInitSaResponderSpi (uint64_t spi)
{
	NS_LOG_FUNCTION (this);
	if (0 == this->m_ptr_init_sa)
	{
		NS_ASSERT (false);
	}
	else
	{
		this->m_ptr_init_sa->SetResponderSpi(spi);
	}
}

void
GsamSession::SetDatabase (Ptr<IpSecDatabase> database)
{
	NS_LOG_FUNCTION (this);
	this->m_ptr_database = database;
}

void
GsamSession::EtablishGsamInitSa (void)
{
	NS_LOG_FUNCTION (this);
	if (0 == this->m_ptr_init_sa)
	{
		this->m_ptr_init_sa = Create<GsamSa>();
		this->m_ptr_init_sa->SetType(GsamSa::GSAM_INIT_SA);
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
GsamSession::IncrementMessageId (void)
{
	NS_LOG_FUNCTION (this);
	this->m_current_message_id++;
}

void
GsamSession::SetMessageId (uint32_t message_id)
{
	NS_LOG_FUNCTION (this);

	if (this->m_role == GsamSession::RESPONDER)
	{
		if (message_id > this->m_current_message_id)
		{
			this->m_current_message_id = message_id;
		}
		else
		{
			NS_ASSERT (false);
		}
	}
	else
	{
		NS_ASSERT (false);
	}
}

Timer&
GsamSession::GetTimer (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_timer;
}

bool
GsamSession::IsRetransmit (void)
{
	NS_LOG_FUNCTION (this);
	//place holder

	bool retval = false;

	if (GsamSession::INITIATOR == this->m_role)
	{
		retval = false;
	}
	else if (GsamSession::RESPONDER == this->m_role)
	{
		retval = false;
	}
	else
	{
		NS_ASSERT (false);
	}

	return retval;
}

Ipv4Address
GsamSession::GetPeerAddress (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_peer_address;
}

void
GsamSession::SetPeerAddress (Ipv4Address peer_address)
{
	NS_LOG_FUNCTION (this);
	this->m_peer_address = peer_address;
}

Ptr<GsamInfo>
GsamSession::GetInfo (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_database->GetInfo();
}

/********************************************************
 *        IpSecSAEntry
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IpSecSAEntry);

TypeId
IpSecSAEntry::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IpSecSAEntry")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<IpSecSAEntry> ()
			;
	return tid;
}

IpSecSAEntry::IpSecSAEntry ()
  :  m_id (0),
	 m_spi (0),
	 m_dest_address (Ipv4Address("0.0.0.0")),
	 m_ipsec_protocol (IPsec::RESERVED),
	 m_ipsec_mode (IPsec::NONE),
	 m_ptr_encrypt_fn (0)
{
	NS_LOG_FUNCTION (this);
}

IpSecSAEntry::~IpSecSAEntry()
{
	NS_LOG_FUNCTION (this);
	this->m_ptr_encrypt_fn = 0;
}

TypeId
IpSecSAEntry::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IpSecSAEntry::GetTypeId();
}

void
IpSecSAEntry::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
IpSecSAEntry::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

bool
operator == (IpSecSAEntry const& lhs, IpSecSAEntry const& rhs)
{
	return lhs.m_id == rhs.m_id;
}

bool
operator < (IpSecSAEntry const& lhs, IpSecSAEntry const& rhs)
{
	return lhs.m_id < rhs.m_id;
}

/********************************************************
 *        IpSecSADatabase
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IpSecSADatabase);

TypeId
IpSecSADatabase::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IpSecSADatabase")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<IpSecSADatabase> ()
			;
	return tid;
}

IpSecSADatabase::IpSecSADatabase ()
  :  m_ptr_info (0)
{
	NS_LOG_FUNCTION (this);
}

IpSecSADatabase::~IpSecSADatabase()
{
	NS_LOG_FUNCTION (this);
	this->m_ptr_info = 0;
}

TypeId
IpSecSADatabase::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IpSecSADatabase::GetTypeId();
}

void
IpSecSADatabase::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
IpSecSADatabase::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

/********************************************************
 *        IpSecPolicyEntry
 ********************************************************/

/********************************************************
 *        IpSecPolicyEntry::AddressEntry
 ********************************************************/

IpSecPolicyEntry::AddressEntry::AddressEntry()
  :  m_type(IpSecPolicyEntry::AddressEntry::NONE),
	 m_single_address (Ipv4Address("0.0.0.0")),
	 m_address_range_start (Ipv4Address("0.0.0.0")),
	 m_address_range_end (Ipv4Address("0.0.0.0"))
{

}

NS_OBJECT_ENSURE_REGISTERED (IpSecPolicyEntry);

TypeId
IpSecPolicyEntry::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IpSecPolicyEntry")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<IpSecPolicyEntry> ()
			;
	return tid;
}

IpSecPolicyEntry::IpSecPolicyEntry ()
  :  m_id (0),
	 m_direction (IpSecPolicyEntry::BOTH),
	 m_ip_protocol_num (0),
	 m_src_transport_protocol_num (0),
	 m_dest_transport_protocol_num (0),
	 m_process_choise (IpSecPolicyEntry::BYPASS),
	 m_ptr_sad (0)
{
	NS_LOG_FUNCTION (this);
}

IpSecPolicyEntry::~IpSecPolicyEntry()
{
	NS_LOG_FUNCTION (this);
	this->m_ptr_sad = 0;
}

TypeId
IpSecPolicyEntry::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IpSecSADatabase::GetTypeId();
}

void
IpSecPolicyEntry::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
IpSecPolicyEntry::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

bool
operator == (IpSecPolicyEntry const& lhs, IpSecPolicyEntry const& rhs)
{
	return lhs.m_id == rhs.m_id;
}

bool
operator < (IpSecPolicyEntry const& lhs, IpSecPolicyEntry const& rhs)
{
	return lhs.m_id < rhs.m_id;
}

/********************************************************
 *        IpSecPolicyDatabase
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IpSecPolicyDatabase);

TypeId
IpSecPolicyDatabase::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IpSecPolicyDatabase")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<IpSecPolicyDatabase> ()
			;
	return tid;
}

IpSecPolicyDatabase::IpSecPolicyDatabase ()
{
	NS_LOG_FUNCTION (this);
}

IpSecPolicyDatabase::~IpSecPolicyDatabase()
{
	NS_LOG_FUNCTION (this);
}

TypeId
IpSecPolicyDatabase::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IpSecPolicyDatabase::GetTypeId();
}

void
IpSecPolicyDatabase::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
IpSecPolicyDatabase::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
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
  :  m_window_size (0),
	 m_ptr_spd (0),
	 m_ptr_sad (0),
	 m_ptr_info (0)
{
	NS_LOG_FUNCTION (this);
	srand(time(0));	//random
}

IpSecDatabase::~IpSecDatabase()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_ptr_sessions.clear();
	this->m_ptr_spd = 0;
	this->m_ptr_sad = 0;
	this->m_ptr_info = 0;
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

Ptr<GsamSession>
IpSecDatabase::GetSession (GsamSession::ROLE role, uint64_t initiator_spi, uint64_t responder_spi, uint32_t message_id) const
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = 0;

	for (	std::list<Ptr<GsamSession> >::const_iterator const_it = this->m_lst_ptr_sessions.begin();
			const_it != this->m_lst_ptr_sessions.end();
			const_it++)
	{
		Ptr<GsamSession> session_it = (*const_it);
		if (	(session_it->GetRole() == role) &&
				(session_it->GetInitSaInitiatorSpi() == initiator_spi &&
				(session_it->GetInitSaResponderSpi() == responder_spi) &&
				 session_it->GetCurrentMessageId() == message_id)
			)
		{
			session = session_it;
		}
	}

	return session;
}

Ptr<GsamSession>
IpSecDatabase::GetSession (GsamSession::ROLE role, uint64_t initiator_spi, uint32_t message_id) const
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = 0;

	for (	std::list<Ptr<GsamSession> >::const_iterator const_it = this->m_lst_ptr_sessions.begin();
			const_it != this->m_lst_ptr_sessions.end();
			const_it++)
	{
		Ptr<GsamSession> session_it = (*const_it);
		if (	(session_it->GetRole() == role) &&
				(session_it->GetInitSaInitiatorSpi() == initiator_spi &&
				 session_it->GetCurrentMessageId() <= message_id)
			)
		{
			session = session_it;
		}
	}

	return session;
}

Ptr<GsamSession>
IpSecDatabase::GetSession (const IkeHeader& ikeheader) const
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = 0;

	GsamSession::ROLE role = GsamSession::UNINITIALIZED;

	if ((true == ikeheader.IsInitiator()) &&
			(false == ikeheader.IsResponder()))
	{
		role = GsamSession::INITIATOR;
	}
	else if ((false == ikeheader.IsInitiator()) &&
			(true == ikeheader.IsResponder()))
	{
		role = GsamSession::RESPONDER;
	}
	else
	{
		NS_ASSERT (false);
	}

	session = this->GetSession(role, ikeheader.GetInitiatorSpi(), ikeheader.GetResponderSpi(), ikeheader.GetMessageId());

	return session;
}

Ptr<GsamInfo>
IpSecDatabase::GetInfo () const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_info;
}

Ptr<GsamSession>
IpSecDatabase::CreateSession (void)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = Create<GsamSession>();
	session->SetDatabase(this);
	this->m_lst_ptr_sessions.push_back(session);

	return session;
}

void
IpSecDatabase::RemoveSession (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	for (	std::list<Ptr<GsamSession> >::iterator it = this->m_lst_ptr_sessions.begin();
			it != this->m_lst_ptr_sessions.end();
			it++)
	{
		Ptr<GsamSession> session_it = (*it);

		if (session_it == session_it)
		{
			it = this->m_lst_ptr_sessions.erase(it);
			break;
		}
	}
}

Time
IpSecDatabase::GetRetransmissionDelay (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_info->GetRetransmissionDelay();
}

} /* namespace ns3 */


