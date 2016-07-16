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
#include "igmpv3-l4-protocol.h"
#include "gsam-l4-protocol.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("GsamSa");

/********************************************************
 *        GsamUtility
 ********************************************************/

uint32_t
GsamUtility::BytesToUint32 (const std::list<uint8_t>& lst_bytes)
{
	uint32_t retval = 0;

	if (4 != lst_bytes.size())
	{
		NS_ASSERT (false);
	}

	uint8_t bits_to_shift = 0;

	for (	std::list<uint8_t>::const_iterator const_it = lst_bytes.begin();
			const_it != lst_bytes.end();
			const_it++)
	{
		uint32_t temp = (*const_it);
		retval += (temp << bits_to_shift);
		bits_to_shift += 8;
	}

	return retval;
}

uint64_t
GsamUtility::BytesToUint64 (const std::list<uint8_t>& lst_bytes)
{
	uint64_t retval = 0;

	if (8 != lst_bytes.size())
	{
		NS_ASSERT (false);
	}

	uint8_t bits_to_shift = 0;

	for (	std::list<uint8_t>::const_iterator const_it = lst_bytes.begin();
			const_it != lst_bytes.end();
			const_it++)
	{
		uint64_t temp = (*const_it);
		retval += (temp << bits_to_shift);
		bits_to_shift += 8;
	}

	return retval;
}

void
GsamUtility::Uint32ToBytes (std::list<uint8_t>& lst_retval, uint32_t input_value)
{
	lst_retval.clear();

	uint32_t mask = 0x000000ff;

	uint8_t bits_to_shift = 0;

	for (	uint8_t it = 1;
			it <= 4;
			it++)
	{
		uint8_t temp = 0;
		mask = mask << bits_to_shift;
		temp = ((input_value & mask) >> bits_to_shift);
		lst_retval.push_back(temp);

		bits_to_shift += 8;
	}
}

void
GsamUtility::Uint64ToBytes (std::list<uint8_t>& lst_retval, uint64_t input_value)
{
	lst_retval.clear();

	uint64_t mask = 0x00000000000000ff;

	uint8_t bits_to_shift = 0;

	for (	uint8_t it = 1;
			it <= 8;
			it++)
	{
		uint8_t temp = 0;
		mask = mask << bits_to_shift;
		temp = ((input_value & mask) >> bits_to_shift);
		lst_retval.push_back(temp);

		bits_to_shift += 8;
	}
}

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

Time
GsamConfig::GetDefaultSessionTimeout (void)
{
	return Seconds(2.0);
}

IPsec::MODE
GsamConfig::GetDefaultIpsecMode (void)
{
	return IPsec::TRANSPORT;
}

uint8_t
GsamConfig::GetDefaultIpsecProtocolId (void)
{
	return IpSecPolicyEntry::AH;
}

IPsec::SA_Proposal_PROTOCOL_ID
GsamConfig::GetDefaultGSAProposalId (void)
{
	return IPsec::AH;
}

Time
GsamConfig::GetDefaultRetransmitTimeout (void)
{
	return Seconds(2.0);
}

Ipv4Address
GsamConfig::GetIgmpv3DestGrpReportAddress (void)
{
	return Ipv4Address ("224.0.0.22");
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

uint32_t
GsamInfo::GenerateIpsecSpi (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t spi = 0;

	spi = rand();

	return spi;
}

bool
GsamInfo::IsIpsecSpiOccupied (uint32_t spi) const
{
	bool retval = (this->m_set_occupied_ipsec_spis.find(spi) != this->m_set_occupied_ipsec_spis.end());

	return retval;
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
GsamSa::GetType (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_type;
}

void
GsamSa::SetSession (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_session != 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_session = session;
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

	uint64_t local_spi = 0;
	GsamSession::PHASE_ONE_ROLE role = GsamSession::P1_UNINITIALIZED;

//	if (this->m_type == GsamSa::GSAM_INIT_SA)
//	{
//		role = this->m_ptr_session->GetPhaseOneRole();
//	}
//	else if (this->m_type == GsamSa::GSAM_KEK_SA)
//	{
//		role = this->m_ptr_session->GetPhaseTwoRole();
//	}

	role = this->m_ptr_session->GetPhaseOneRole();

	if (role == GsamSession::INITIATOR)
	{
		local_spi = this->m_initiator_spi;
	}
	else if (role == GsamSession::RESPONDER)
	{
		local_spi = this->m_responder_spi;
	}

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
	 m_ptr_session_group (0),
	 m_p1_role (GsamSession::P1_UNINITIALIZED),
	 m_ptr_init_sa (0),
	 m_ptr_kek_sa (0),
	 m_ptr_database (0),
	 m_ptr_related_gsa_r (0)
{
	NS_LOG_FUNCTION (this);

	this->m_timer_timeout.SetFunction(&GsamSession::TimeoutAction, this);
}

GsamSession::~GsamSession()
{
	NS_LOG_FUNCTION (this);

	if(this->m_ptr_database != 0)
	{
		this->m_ptr_database->RemoveSession(this);
	}

	if (this->m_ptr_session_group != 0)
	{
		this->m_ptr_session_group->RemoveSession(this);
	}

	this->m_ptr_init_sa = 0;
	this->m_ptr_database = 0;
	this->m_ptr_kek_sa = 0;
	this->m_ptr_session_group = 0;

	this->m_timer_retransmit.Cancel();
	this->m_timer_timeout.Cancel();

	this->m_ptr_related_gsa_r = 0;
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

	this->m_ptr_database = 0;

	if (this->m_ptr_session_group != 0)
	{
		this->m_ptr_session_group->RemoveSession(this);
	}

	this->m_ptr_session_group = 0;
}

GsamSession::PHASE_ONE_ROLE
GsamSession::GetLocalRole (const IkeHeader& incoming_header)
{
	if (incoming_header.IsInitiator() && incoming_header.IsResponder())
	{
		NS_ASSERT (false);
	}

	if ((!incoming_header.IsInitiator()) && (!incoming_header.IsResponder()))
	{
		NS_ASSERT (false);
	}

	GsamSession::PHASE_ONE_ROLE role = GsamSession::P1_UNINITIALIZED;

	if (incoming_header.IsInitiator())
	{
		role = GsamSession::RESPONDER;
	}
	else
	{
		role = GsamSession::INITIATOR;
	}

	return role;
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

	if (lhs.m_peer_address != rhs.m_peer_address)
	{
		retval = false;
	}

	if (lhs.m_ptr_init_sa != rhs.m_ptr_init_sa)
	{
		retval = false;
	}

	if (lhs.m_ptr_kek_sa != rhs.m_ptr_kek_sa)
	{
		retval = false;
	}

	if (lhs.m_p1_role != rhs.m_p1_role)
	{
		retval = false;
	}

	if (lhs.m_current_message_id != rhs.m_current_message_id)
	{
		retval = false;
	}

	return retval;
}

GsamSession::PHASE_ONE_ROLE
GsamSession::GetPhaseOneRole (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_p1_role;
}

void
GsamSession::SetPhaseOneRole (GsamSession::PHASE_ONE_ROLE role)
{
	NS_LOG_FUNCTION (this);
	if (this->m_p1_role != GsamSession::P1_UNINITIALIZED)
	{
		NS_ASSERT (false);
	}

	this->m_p1_role = role;
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

uint64_t
GsamSession::GetKekSaInitiatorSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_kek_sa->GetInitiatorSpi();
}

void
GsamSession::SetKekSaInitiatorSpi (uint64_t spi)
{
	NS_LOG_FUNCTION (this);
	if (0 == this->m_ptr_kek_sa)
	{
		NS_ASSERT (false);
	}
	else
	{
		this->m_ptr_kek_sa->SetInitiatorSpi(spi);
	}
}

uint64_t
GsamSession::GetKekSaResponderSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_kek_sa->GetResponderSpi();
}

void
GsamSession::SetKekSaResponderSpi (uint64_t spi)
{
	NS_LOG_FUNCTION (this);
	if (0 == this->m_ptr_kek_sa)
	{
		NS_ASSERT (false);
	}
	else
	{
		this->m_ptr_kek_sa->SetResponderSpi(spi);
	}
}

void
GsamSession::SetDatabase (Ptr<IpSecDatabase> database)
{
	NS_LOG_FUNCTION (this);

	if (database == 0)
	{
		NS_ASSERT (false);
	}

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
		this->m_ptr_init_sa->SetSession(this);
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
GsamSession::EtablishGsamKekSa (void)
{
	NS_LOG_FUNCTION (this);
		if (0 == this->m_ptr_kek_sa)
		{
			this->m_ptr_kek_sa = Create<GsamSa>();
			this->m_ptr_kek_sa->SetType(GsamSa::GSAM_KEK_SA);
			this->m_ptr_kek_sa->SetSession(this);
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

	if (this->m_p1_role == GsamSession::RESPONDER)
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
GsamSession::GetRetransmitTimer (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_timer_retransmit;
}

void
GsamSession::SceduleTimeout (Time delay)
{
	NS_LOG_FUNCTION (this);
	this->m_timer_timeout.Cancel();
	this->m_timer_timeout.Schedule(delay);
}

bool
GsamSession::IsRetransmit (void)
{
	NS_LOG_FUNCTION (this);
	//place holder

	bool retval = false;

	if (GsamSession::INITIATOR == this->m_p1_role)
	{
		retval = false;
	}
	else if (GsamSession::RESPONDER == this->m_p1_role)
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
GsamSession::GetPeerAddress (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_peer_address.Get() == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_peer_address;
}

Ipv4Address
GsamSession::GetGroupAddress (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_session_group == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_session_group->GetGroupAddress();
}

void
GsamSession::SetPeerAddress (Ipv4Address peer_address)
{
	NS_LOG_FUNCTION (this);

	if (peer_address.Get() == 0)
	{
		NS_ASSERT (false);
	}

	if (this->m_peer_address.Get() != 0)
	{
		NS_ASSERT (false);
	}

	this->m_peer_address = peer_address;
}

void
GsamSession::SetGroupAddress (Ipv4Address group_address)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_session_group == 0)
	{
		this->m_ptr_session_group = this->m_ptr_database->GetSessionGroup(group_address);
		this->m_ptr_session_group->PushBackSession(this);
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
GsamSession::SetRelatedGsaR (Ptr<IpSecSAEntry> gsa_r)
{
	NS_LOG_FUNCTION (this);
	if (gsa_r == 0)
	{
		NS_ASSERT (false);
	}
	this->m_ptr_related_gsa_r = gsa_r;
}

void
GsamSession::AssociateGsaQ (Ptr<IpSecSAEntry> gsa_q)
{
	NS_LOG_FUNCTION (this);
	if (gsa_q == 0)
	{
		NS_ASSERT (false);
	}
	this->m_ptr_session_group->AssociateWithGsaQ(gsa_q);
}

void
GsamSession::AssociateWithSessionGroup (Ptr<GsamSessionGroup> session_group)
{
	NS_LOG_FUNCTION (this);

	if (session_group == 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_session_group = session_group;
}

void
GsamSession::AssociateWithPolicy (Ptr<IpSecPolicyEntry> policy)
{
	if (policy == 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_session_group->AssociateWithPolicy (policy);
}

Ptr<GsamInfo>
GsamSession::GetInfo (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_database->GetInfo();
}

Ptr<IpSecDatabase>
GsamSession::GetDatabase (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_database == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_database;
}

bool
GsamSession::HaveInitSa (void) const
{
	NS_LOG_FUNCTION (this);
	return (this->m_ptr_init_sa != 0);
}
bool
GsamSession::HaveKekSa (void) const
{
	NS_LOG_FUNCTION (this);
	return (this->m_ptr_kek_sa != 0);
}

void
GsamSession::TimeoutAction (void)
{
	NS_LOG_FUNCTION (this);

	std::cout << "GsamSession: " << this << " time out.";
}

Ptr<IpSecSAEntry>
GsamSession::GetRelatedGsaR (void) const
{
	NS_LOG_FUNCTION (this);

	//return value is allowed to be 0
	return this->m_ptr_related_gsa_r;
}
Ptr<IpSecSAEntry>
GsamSession::GetRelatedGsaQ (void) const
{
	NS_LOG_FUNCTION (this);
	if (this->m_ptr_session_group == 0)
	{
		NS_ASSERT (false);
	}

	//return value is allowed to be 0
	return this->m_ptr_session_group->GetRelatedGsaQ();
}

Ptr<IpSecPolicyEntry>
GsamSession::GetRelatedPolicy (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_session_group == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_session_group->GetRelatedPolicy();
}

bool
GsamSession::IsHostQuerier (void) const
{
	NS_LOG_FUNCTION (this);

	bool retval = false;
	Ptr<Igmpv3L4Protocol> igmp = this->m_ptr_database->GetIgmp();

	if (igmp->GetRole() == Igmpv3L4Protocol::QUERIER)
	{
		retval = true;
	}

	return retval;
}

bool
GsamSession::IsHostHost (void) const
{
	NS_LOG_FUNCTION (this);

	bool retval = false;
	Ptr<Igmpv3L4Protocol> igmp = this->m_ptr_database->GetIgmp();

	if (igmp->GetRole() == Igmpv3L4Protocol::HOST)
	{
		retval = true;
	}

	return retval;
}

bool
GsamSession::IsHostNonQuerier (void) const
{
	NS_LOG_FUNCTION (this);

	bool retval = false;
	Ptr<Igmpv3L4Protocol> igmp = this->m_ptr_database->GetIgmp();

	if (igmp->GetRole() == Igmpv3L4Protocol::NONQUERIER)
	{
		retval = true;
	}

	return retval;
}

/********************************************************
 *        GsamSessionGroup
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (GsamSessionGroup);

TypeId
GsamSessionGroup::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::GsamSessionGroup")
	    		.SetParent<Object> ()
				.SetGroupName ("Internet")
				.AddConstructor<GsamSessionGroup> ()
				;
		return tid;
}

GsamSessionGroup::GsamSessionGroup ()
  :  m_group_address (Ipv4Address ("0.0.0.0")),
	 m_ptr_database (0),
	 m_ptr_related_gsa_q (0),
	 m_ptr_related_policy (0)
{
	NS_LOG_FUNCTION (this);
}

GsamSessionGroup::~GsamSessionGroup()
{
	NS_LOG_FUNCTION (this);
	if (this->m_ptr_database != 0)
	{
		this->m_ptr_database->RemoveSessionGroup(this);
	}
	this->m_ptr_related_gsa_q = 0;
	this->m_ptr_related_policy = 0;
	this->m_lst_sessions.clear();
}

TypeId
GsamSessionGroup::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);

	return GsamSessionGroup::GetTypeId();
}

void
GsamSessionGroup::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
GsamSessionGroup::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
	if (this->m_ptr_database != 0)
	{
		this->m_ptr_database->RemoveSessionGroup(this);
	}
	this->m_ptr_database = 0;
}

bool
operator == (GsamSessionGroup const& lhs, GsamSessionGroup const& rhs)
{
	return lhs.GetGroupAddress() == rhs.GetGroupAddress();
}

void
GsamSessionGroup::SetGroupAddress (Ipv4Address group_address)
{
	NS_LOG_FUNCTION (this);
	this->m_group_address = group_address;
}

void
GsamSessionGroup::SetDatabase (Ptr<IpSecDatabase> database)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_database != 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_database = database;
}

void
GsamSessionGroup::AssociateWithGsaQ (Ptr<IpSecSAEntry> gsa_q)
{
	NS_LOG_FUNCTION (this);

	if (gsa_q == 0)
	{
		NS_ASSERT (false);
	}

	if (this->m_ptr_related_gsa_q != 0)
	{
		NS_ASSERT(false);
	}

	this->m_ptr_related_gsa_q = gsa_q;
}

void
GsamSessionGroup::AssociateWithPolicy (Ptr<IpSecPolicyEntry> policy)
{
	NS_LOG_FUNCTION (this);

	if (policy == 0)
	{
		NS_ASSERT (false);
	}

	if (this->m_ptr_related_policy != 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_related_policy = policy;
}

void
GsamSessionGroup::PushBackSession (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_sessions.push_back(session);
	session->AssociateWithSessionGroup(this);
}

void
GsamSessionGroup::RemoveSession (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_sessions.remove(session);
}

Ipv4Address
GsamSessionGroup::GetGroupAddress (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_group_address;
}

Ptr<IpSecDatabase>
GsamSessionGroup::GetDatabase (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_database == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_database;
}

Ptr<IpSecSAEntry>
GsamSessionGroup::GetRelatedGsaQ (void) const
{
	NS_LOG_FUNCTION (this);

	//return value is allowed to be 0
	return this->m_ptr_related_gsa_q;
}

Ptr<IpSecPolicyEntry>
GsamSessionGroup::GetRelatedPolicy (void) const
{
	NS_LOG_FUNCTION (this);

	//return value can be zero. For the use of judging the need of creating policy
	return this->m_ptr_related_policy;
}

const std::list<Ptr<GsamSession> >&
GsamSessionGroup::GetSessions (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_lst_sessions;
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
  :  m_spi (0),
	 m_ptr_encrypt_fn (0),
	 m_ptr_sad (0),
     m_ptr_policy (0)
{
	NS_LOG_FUNCTION (this);
}

IpSecSAEntry::~IpSecSAEntry()
{
	NS_LOG_FUNCTION (this);
	if (this->m_ptr_sad != 0)
	{
		this->m_ptr_sad->RemoveEntry(this);
	}
	this->m_ptr_encrypt_fn = 0;
	this->m_ptr_sad = 0;
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
	if (this->m_ptr_sad != 0)
	{
		this->m_ptr_sad->RemoveEntry(this);
	}

	this->m_ptr_sad = 0;
}

bool
operator == (IpSecSAEntry const& lhs, IpSecSAEntry const& rhs)
{
	return lhs.m_spi == rhs.m_spi;
}

bool
operator < (IpSecSAEntry const& lhs, IpSecSAEntry const& rhs)
{
	return lhs.m_spi < rhs.m_spi;
}

void
IpSecSAEntry::SetSpi (uint32_t spi)
{
	NS_LOG_FUNCTION (this);
	this->m_spi = spi;
}

void
IpSecSAEntry::SetSAD (Ptr<IpSecSADatabase> sad)
{
	NS_LOG_FUNCTION (this);
	if (this->m_ptr_sad != 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_sad = sad;
}

void
IpSecSAEntry::AssociatePolicy (Ptr<IpSecPolicyEntry> policy)
{
	NS_LOG_FUNCTION (this);
	if (this->m_ptr_policy != 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_policy = policy;
}

uint32_t
IpSecSAEntry::GetSpi (void) const
{
	NS_LOG_FUNCTION (this);
	if (0 == this->m_spi)
	{
		NS_ASSERT (false);
	}

	return this->m_spi;
}

Ptr<IpSecPolicyEntry>
IpSecSAEntry::GetPolicyEntry (void) const
{
	NS_LOG_FUNCTION (this);
	if (this->m_ptr_policy == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_policy;
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
  :  m_ptr_root_database (0),
	 m_ptr_policy_entry (0)
{
	NS_LOG_FUNCTION (this);
}

IpSecSADatabase::~IpSecSADatabase()
{
	NS_LOG_FUNCTION (this);
	this->m_ptr_policy_entry = 0;
	this->m_ptr_root_database = 0;
	this->m_lst_entries.clear();
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

void
IpSecSADatabase::PushBackEntry (Ptr<IpSecSAEntry> entry)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_entries.push_back(entry);
}

void
IpSecSADatabase::RemoveEntry (Ptr<IpSecSAEntry> entry)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_entries.remove(entry);
}

void
IpSecSADatabase::AssociatePolicyEntry (Ptr<IpSecPolicyEntry> policy)
{
	NS_LOG_FUNCTION (this);
	if (this->m_ptr_policy_entry != 0)
	{
		NS_ASSERT (false);
	}
	this->m_ptr_policy_entry = policy;
}

void
IpSecSADatabase::SetRootDatabase (Ptr<IpSecDatabase> database)
{
	NS_LOG_FUNCTION (this);
	this->m_ptr_root_database = database;
}

Ptr<IpSecDatabase>
IpSecSADatabase::GetRootDatabase (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_root_database == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_root_database;
}

Ptr<IpSecSAEntry>
IpSecSADatabase::GetIpsecSAEntry (uint32_t spi) const
{
	NS_LOG_FUNCTION (this);

	if (spi == 0)
	{
		NS_ASSERT (false);
	}

	Ptr<IpSecSAEntry> retval = 0;

	for (	std::list<Ptr<IpSecSAEntry> >::const_iterator const_it = this->m_lst_entries.begin();
			const_it != this->m_lst_entries.end();
			const_it++)
	{
		Ptr<IpSecSAEntry> value_const_it = (*const_it);

		if (value_const_it->GetSpi() == spi)
		{
			retval = value_const_it;
		}
	}

	return retval;
}

Ptr<GsamInfo>
IpSecSADatabase::GetInfo (void) const
{
	NS_LOG_FUNCTION (this);

	return this->GetRootDatabase()->GetInfo();
}

Ptr<IpSecSAEntry>
IpSecSADatabase::CreateIpSecSAEntry (Spi spi)
{
	Ptr<IpSecSAEntry> retval = 0;
	if (this->m_ptr_policy_entry == 0)
	{
		//this database is a sad-i or sad-o that bound to an entry. And it's just a logical database which is a part of the real database;
		retval = Create<IpSecSAEntry>();
		retval->SetSAD(this);
		retval->SetSpi(spi.ToUint32());
	}
	else
	{
		retval = this->m_ptr_policy_entry->GetSPD()->GetRootDatabase()->GetSAD()->CreateIpSecSAEntry(spi);
		retval->AssociatePolicy(this->m_ptr_policy_entry);
	}
	this->PushBackEntry(retval);
	return retval;
}

/********************************************************
 *        IpSecPolicyEntry
 ********************************************************/

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
  :  m_src_starting_address (Ipv4Address ("0.0.0.0")),
	 m_src_ending_address (Ipv4Address ("0.0.0.0")),
	 m_dest_starting_address (Ipv4Address ("0.0.0.0")),
	 m_dest_ending_address (Ipv4Address ("0.0.0.0")),
	 m_ip_protocol_num (0),
	 m_ipsec_mode (IPsec::NONE),
	 m_src_transport_protocol_starting_num (0),
	 m_src_transport_protocol_ending_num (0),
	 m_dest_transport_protocol_starting_num (0),
	 m_dest_transport_protocol_ending_num (0),
	 m_process_choise (IpSecPolicyEntry::BYPASS),
	 m_ptr_spd (0),
	 m_ptr_outbound_sad (0)
{
	NS_LOG_FUNCTION (this);
}

IpSecPolicyEntry::~IpSecPolicyEntry()
{
	NS_LOG_FUNCTION (this);
	if (this->m_ptr_spd != 0)
	{
		this->m_ptr_spd->RemoveEntry(this);
	}
	this->m_ptr_spd = 0;
	this->m_ptr_outbound_sad = 0;
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
	if (this->m_ptr_spd != 0)
	{
		this->m_ptr_spd->RemoveEntry(this);
	}

	this->m_ptr_spd = 0;
}

void
IpSecPolicyEntry::SetProcessChoice (IpSecPolicyEntry::PROCESS_CHOICE process_choice)
{
	NS_LOG_FUNCTION (this);
	this->m_process_choise = process_choice;
}

IpSecPolicyEntry::PROCESS_CHOICE
IpSecPolicyEntry::GetProcessChoice (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_process_choise;
}

void
IpSecPolicyEntry::SetProtocolNum (uint8_t protocol_id)
{
	NS_LOG_FUNCTION (this);
	this->m_ip_protocol_num = protocol_id;
}

void
IpSecPolicyEntry::SetIpsecMode (IPsec::MODE mode)
{
	NS_LOG_FUNCTION (this);
	this->m_ipsec_mode = mode;
}

uint8_t
IpSecPolicyEntry::GetProtocolNum () const
{
	NS_LOG_FUNCTION (this);
	return this->m_ip_protocol_num;
}

IPsec::MODE
IpSecPolicyEntry::GetIpsecMode (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ipsec_mode;
}

void
IpSecPolicyEntry::SetTranSrcStartingPort (uint16_t port_num)
{
	NS_LOG_FUNCTION (this);
	this->m_src_transport_protocol_starting_num = port_num;
}

uint16_t
IpSecPolicyEntry::GetTranSrcStartingPort (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_src_transport_protocol_starting_num;
}

void
IpSecPolicyEntry::SetTranSrcEndingPort (uint16_t port_num)
{
	NS_LOG_FUNCTION (this);
	this->m_src_transport_protocol_ending_num = port_num;
}

uint16_t
IpSecPolicyEntry::GetTranSrcEndingPort (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_src_transport_protocol_ending_num;
}

void
IpSecPolicyEntry::SetTranDestStartingPort (uint16_t port_num)
{
	NS_LOG_FUNCTION (this);
	this->m_dest_transport_protocol_starting_num = port_num;
}

uint16_t
IpSecPolicyEntry::GetTranDestStartingPort (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_dest_transport_protocol_starting_num;
}

void
IpSecPolicyEntry::SetTranDestEndingPort (uint16_t port_num)
{
	NS_LOG_FUNCTION (this);
	this->m_dest_transport_protocol_ending_num = port_num;
}

uint16_t
IpSecPolicyEntry::GetTranDestEndingPort (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_dest_transport_protocol_ending_num;
}

void
IpSecPolicyEntry::SetTranSrcPortRange (uint16_t range_start, uint16_t range_end)
{
	NS_LOG_FUNCTION (this);
	this->SetTranSrcStartingPort(range_start);
	this->SetTranSrcEndingPort(range_end);
}

void
IpSecPolicyEntry::SetTranDestPortRange (uint16_t range_start, uint16_t range_end)
{
	NS_LOG_FUNCTION (this);
	this->SetTranDestStartingPort(range_start);
	this->SetTranDestEndingPort(range_end);
}

void
IpSecPolicyEntry::SetSrcAddressRange (Ipv4Address range_start, Ipv4Address range_end)
{
	NS_LOG_FUNCTION (this);
	this->m_src_starting_address = range_start;
	this->m_dest_ending_address = range_end;
}

Ipv4Address
IpSecPolicyEntry::GetSrcAddressRangeStart (void) const
{
	NS_LOG_FUNCTION (this);

	return this->m_src_starting_address;
}

Ipv4Address
IpSecPolicyEntry::GetSrcAddressRangeEnd (void) const
{
	NS_LOG_FUNCTION (this);

	return this->m_src_ending_address;
}

void
IpSecPolicyEntry::SetDestAddressRange (Ipv4Address range_start, Ipv4Address range_end)
{
	NS_LOG_FUNCTION (this);
	this->m_dest_starting_address = range_start;
	this->m_dest_ending_address = range_end;
}

Ipv4Address
IpSecPolicyEntry::GetDestAddressRangeStart (void) const
{
	NS_LOG_FUNCTION (this);

	return this->m_dest_starting_address;
}

Ipv4Address
IpSecPolicyEntry::GetDestAddressRangeEnd (void) const
{
	NS_LOG_FUNCTION (this);

	return this->m_dest_ending_address;
}

void
IpSecPolicyEntry::SetSingleSrcAddress (Ipv4Address address)
{
	NS_LOG_FUNCTION (this);

	this->SetSrcAddressRange(address, address);
}

Ipv4Address
IpSecPolicyEntry::GetSrcAddress (void) const
{
	NS_LOG_FUNCTION (this);
	if (this->m_src_starting_address != this->m_src_ending_address)
	{
		NS_ASSERT (false);
	}

	return this->m_src_starting_address;
}

void
IpSecPolicyEntry::SetSingleDestAddress (Ipv4Address address)
{
	NS_LOG_FUNCTION (this);

	this->SetDestAddressRange(address, address);
}

Ipv4Address
IpSecPolicyEntry::GetDestAddress (void) const
{
	NS_LOG_FUNCTION (this);
	if (this->m_dest_starting_address != this->m_dest_ending_address)
	{
		NS_ASSERT (false);
	}

	return this->m_dest_starting_address;
}

Ptr<IpSecPolicyDatabase>
IpSecPolicyEntry::GetSPD (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_spd == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_spd;
}

void
IpSecPolicyEntry::SetSPD (Ptr<IpSecPolicyDatabase> spd)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_spd != 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_spd = spd;
}

Ptr<IpSecSADatabase>
IpSecPolicyEntry::GetOutboundSAD (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_outbound_sad == 0)
	{
		this->m_ptr_outbound_sad = Create<IpSecSADatabase>();
		this->m_ptr_outbound_sad->AssociatePolicyEntry(this);
		this->m_ptr_outbound_sad->SetRootDatabase(this->GetSPD()->GetRootDatabase());
	}

	return this->m_ptr_outbound_sad;
}

Ptr<IpSecSADatabase>
IpSecPolicyEntry::GetInboundSAD (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_inbound_sad == 0)
	{
		this->m_ptr_inbound_sad = Create<IpSecSADatabase>();
		this->m_ptr_inbound_sad->AssociatePolicyEntry(this);
		this->m_ptr_outbound_sad->SetRootDatabase(this->GetSPD()->GetRootDatabase());
	}

	return this->m_ptr_inbound_sad;
}

bool operator == (IpSecPolicyEntry const& lhs, IpSecPolicyEntry const& rhs)
{
	bool retval = true;

	if (lhs.m_src_starting_address != rhs.m_src_starting_address)
	{
		retval = false;
	}

	if (lhs.m_src_ending_address != rhs.m_src_ending_address)
	{
		retval = false;
	}

	if (lhs.m_dest_starting_address != rhs.m_dest_starting_address)
	{
		retval = false;
	}

	if (lhs.m_dest_ending_address != rhs.m_dest_ending_address)
	{
		retval = false;
	}

	if (lhs.m_ip_protocol_num != rhs.m_ip_protocol_num)
	{
		retval = false;
	}

	if (lhs.m_src_transport_protocol_starting_num != rhs.m_src_transport_protocol_starting_num)
	{
		retval = false;
	}

	if (lhs.m_src_transport_protocol_ending_num != rhs.m_src_transport_protocol_ending_num)
	{
		retval = false;
	}

	if (lhs.m_dest_transport_protocol_starting_num != rhs.m_dest_transport_protocol_starting_num)
	{
		retval = false;
	}

	if (lhs.m_dest_transport_protocol_ending_num != rhs.m_dest_transport_protocol_ending_num)
	{
		retval = false;
	}

	if (lhs.m_process_choise != rhs.m_process_choise)
	{
		retval = false;
	}

	if (lhs.m_ptr_spd != rhs.m_ptr_spd)
	{
		retval = false;
	}

	return retval;
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
  :  m_ptr_root_database (0)
{
	NS_LOG_FUNCTION (this);
}

IpSecPolicyDatabase::~IpSecPolicyDatabase()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_entries.clear();
	this->m_ptr_root_database = 0;
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

void
IpSecPolicyDatabase::PushBackEntry (Ptr<IpSecPolicyEntry> entry)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_entries.push_back(entry);
}

void
IpSecPolicyDatabase::RemoveEntry (Ptr<IpSecPolicyEntry> entry)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_entries.remove(entry);
}

Ptr<IpSecPolicyEntry>
IpSecPolicyDatabase::CreatePolicyEntry (void)
{
	NS_LOG_FUNCTION (this);
	Ptr<IpSecPolicyEntry> retval = Create<IpSecPolicyEntry>();

	retval->SetSPD(this);

	return retval;
}

void
IpSecPolicyDatabase::SetRootDatabase (Ptr<IpSecDatabase> database)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_root_database !=0 )
	{
		NS_ASSERT (false);
	}

	this->m_ptr_root_database = database;
}

Ptr<IpSecDatabase>
IpSecPolicyDatabase::GetRootDatabase (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_root_database == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_root_database;
}

Ptr<GsamInfo>
IpSecPolicyDatabase::GetInfo (void) const
{
	NS_LOG_FUNCTION (this);

	return this->GetRootDatabase()->GetInfo();
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

	this->m_ptr_spd = Create<IpSecPolicyDatabase>();
	this->m_ptr_spd->SetRootDatabase(this);
	this->m_ptr_sad = Create<IpSecSADatabase>();
	this->m_ptr_sad->SetRootDatabase(this);
	this->m_ptr_info = Create<GsamInfo>();
}

IpSecDatabase::~IpSecDatabase()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_ptr_all_sessions.clear();
	this->m_ptr_spd = 0;
	this->m_ptr_sad = 0;
	this->m_ptr_info = 0;
	this->m_lst_ptr_session_groups.clear();
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
IpSecDatabase::GetPhaseOneSession (GsamSession::PHASE_ONE_ROLE local_p1_role, uint64_t initiator_spi, uint64_t responder_spi, uint32_t message_id, Ipv4Address peer_address) const
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = 0;

	for (	std::list<Ptr<GsamSession> >::const_iterator const_it = this->m_lst_ptr_all_sessions.begin();
			const_it != this->m_lst_ptr_all_sessions.end();
			const_it++)
	{
		Ptr<GsamSession> session_it = (*const_it);
		if (	(session_it->GetPhaseOneRole() == local_p1_role) &&
				(session_it->GetInitSaInitiatorSpi() == initiator_spi &&
				(session_it->GetInitSaResponderSpi() == responder_spi) &&
				 session_it->GetCurrentMessageId() == message_id &&
				 session_it->GetPeerAddress() == peer_address)
			)
		{
			session = session_it;
		}
	}

	return session;
}

Ptr<GsamSession>
IpSecDatabase::GetPhaseOneSession (GsamSession::PHASE_ONE_ROLE local_p1_role, uint64_t initiator_spi, uint32_t message_id, Ipv4Address peer_address) const
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = 0;

	for (	std::list<Ptr<GsamSession> >::const_iterator const_it = this->m_lst_ptr_all_sessions.begin();
			const_it != this->m_lst_ptr_all_sessions.end();
			const_it++)
	{
		Ptr<GsamSession> session_it = (*const_it);
		if (	(session_it->GetPhaseOneRole() == local_p1_role) &&
				(session_it->GetInitSaInitiatorSpi() == initiator_spi &&
						//the responder maybe 1 behind of message id
				 session_it->GetCurrentMessageId() <= message_id &&
				 session_it->GetPeerAddress() == peer_address)
			)
		{
			session = session_it;
		}
	}

	return session;
}

Ptr<GsamSession>
IpSecDatabase::GetPhaseTwoSession (uint64_t initiator_spi, uint64_t responder_spi, uint32_t message_id, Ipv4Address peer_address) const
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = 0;

	for (	std::list<Ptr<GsamSession> >::const_iterator const_it = this->m_lst_ptr_all_sessions.begin();
			const_it != this->m_lst_ptr_all_sessions.end();
			const_it++)
	{
		Ptr<GsamSession> session_it = (*const_it);
		if (	(session_it->GetKekSaInitiatorSpi() == initiator_spi &&
				(session_it->GetKekSaResponderSpi() == responder_spi) &&
					//the responder maybe 1 behind of message id
				 session_it->GetCurrentMessageId() <= message_id &&
				 session_it->GetPeerAddress() == peer_address)
			)
		{
			session = session_it;
		}
	}

	return session;
}

Ptr<GsamSession>
IpSecDatabase::GetSession (const IkeHeader& header, Ipv4Address peer_address) const
{
	Ptr<GsamSession> retval = 0;

	GsamSession::PHASE_ONE_ROLE local_role = GsamSession::GetLocalRole(header);
	uint32_t header_message_id = header.GetMessageId();

	switch (header_message_id)
	{
	case 0:
		retval = this->GetPhaseOneSession(local_role, header.GetInitiatorSpi(), header_message_id, peer_address);
		break;
	case 1:
		retval = this->GetPhaseOneSession(local_role, header.GetInitiatorSpi(), header.GetResponderSpi(), header_message_id, peer_address);
		break;
	default:
		if (header_message_id >= 2)
		{
			retval = this->GetPhaseTwoSession(header.GetInitiatorSpi(), header.GetResponderSpi(), header_message_id, peer_address);
			break;
		}
		else if (header_message_id < 0)
		{
			//something went wrong
			NS_ASSERT (false);
		}
		else
		{

		}
	}

	return retval;
}

Ptr<GsamSessionGroup>
IpSecDatabase::GetSessionGroup (Ipv4Address group_address)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSessionGroup> retval = 0;

	for (	std::list<Ptr<GsamSessionGroup> >::const_iterator const_it = this->m_lst_ptr_session_groups.begin();
			const_it != this->m_lst_ptr_session_groups.end();
			const_it++)
	{
		Ptr<GsamSessionGroup> value_const_it = (*const_it);
		if (value_const_it->GetGroupAddress() == group_address)
		{
			retval = value_const_it;
		}
	}

	if (retval == 0)
	{
		retval = this->CreateSessionGroup(group_address);
	}

	return retval;
}

Ptr<GsamInfo>
IpSecDatabase::GetInfo (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_info == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_info;
}

Ptr<IpSecPolicyDatabase>
IpSecDatabase::GetPolicyDatabase (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_spd == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_spd;
}

Ptr<IpSecSADatabase>
IpSecDatabase::GetIpSecSaDatabase (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_sad == 0)
	{
		NS_ASSERT (false);
	}


	return this->m_ptr_sad;
}

Ptr<Igmpv3L4Protocol>
IpSecDatabase::GetIgmp (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_gsam == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_gsam->GetIgmp();
}

Ptr<GsamSession>
IpSecDatabase::CreateSession (void)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = Create<GsamSession>();
	session->SetDatabase(this);
	this->m_lst_ptr_all_sessions.push_back(session);

	return session;
}

Ptr<GsamSession>
IpSecDatabase::CreateSession (Ipv4Address group_address, Ipv4Address peer_address)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = Create<GsamSession>();
	session->SetDatabase(this);
	session->SetGroupAddress(group_address);
	session->SetPeerAddress(peer_address);

	Ptr<GsamSessionGroup> session_group = this->GetSessionGroup(group_address);

	session_group->PushBackSession(session);

	this->m_lst_ptr_all_sessions.push_back(session);

	return session;
}

Ptr<GsamSessionGroup>
IpSecDatabase::CreateSessionGroup (Ipv4Address group_address)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSessionGroup> session_group = Create<GsamSessionGroup>();
	session_group->SetDatabase(this);
	this->m_lst_ptr_session_groups.push_back(session_group);

	return session_group;
}

void
IpSecDatabase::RemoveSession (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	for (	std::list<Ptr<GsamSession> >::iterator it = this->m_lst_ptr_all_sessions.begin();
			it != this->m_lst_ptr_all_sessions.end();
			it++)
	{
		Ptr<GsamSession> session_it = (*it);

		if (session_it == session_it)
		{
			it = this->m_lst_ptr_all_sessions.erase(it);
			break;
		}
	}
}

void
IpSecDatabase::RemoveSessionGroup (Ptr<GsamSessionGroup> session_group)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_ptr_session_groups.remove(session_group);
}

Time
IpSecDatabase::GetRetransmissionDelay (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_info->GetRetransmissionDelay();
}

Ptr<IpSecPolicyDatabase>
IpSecDatabase::GetSPD (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_spd == 0)
	{
		this->m_ptr_spd = Create<IpSecPolicyDatabase>();
		this->m_ptr_spd->SetRootDatabase(this);
	}

	return this->m_ptr_spd;
}

Ptr<IpSecSADatabase>
IpSecDatabase::GetSAD (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_sad == 0)
	{
		this->m_ptr_sad = Create<IpSecSADatabase>();
		this->m_ptr_sad->SetRootDatabase(this);
	}

	return this->m_ptr_sad;
}

void
IpSecDatabase::SetGsam (Ptr<GsamL4Protocol> gsam)
{
	NS_LOG_FUNCTION (this);
	if (gsam == 0)
	{
		NS_ASSERT (false);
	}
	this->m_ptr_gsam = gsam;
}

} /* namespace ns3 */


