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
#include "ns3/ptr.h"
#include <cstdlib>

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
GsamUtility::Uint32ToBytes (std::list<uint8_t>& lst_retval, const uint32_t input_value)
{
	lst_retval.clear();

	uint32_t mask = 0x000000ff;

	uint8_t bits_to_shift = 0;

	for (	uint8_t it = 1;
			it <= 4;
			it++)
	{
		uint8_t temp = 0;
		uint32_t shifted_mask = mask << bits_to_shift;
		temp = ((input_value & shifted_mask) >> bits_to_shift);
		lst_retval.push_back(temp);

		bits_to_shift += 8;
	}
}

void
GsamUtility::Uint64ToBytes (std::list<uint8_t>& lst_retval, const uint64_t input_value)
{
	lst_retval.clear();

	uint64_t mask = 0x00000000000000ff;

	uint8_t bits_to_shift = 0;

	for (	uint8_t it = 1;
			it <= 8;
			it++)
	{
		uint8_t temp = 0;
		uint64_t shifted_mask = mask << bits_to_shift;
		temp = ((input_value & shifted_mask) >> bits_to_shift);
		lst_retval.push_back(temp);

		bits_to_shift += 8;
	}
}

Ipv4Address
GsamUtility::CheckAndGetGroupAddressFromTrafficSelectors (const IkeTrafficSelector& ts_src, const IkeTrafficSelector& ts_dest)
{
	if (ts_src.GetStartingAddress() == ts_src.GetEndingAddress())
	{
		//ok
	}
	else
	{
		NS_ASSERT (false);
	}

	if (ts_src.GetStartingAddress().Get() == 0)
	{
		//ok
	}
	else
	{
		NS_ASSERT (false);
	}

	if (ts_src.GetStartPort() == ts_src.GetEndPort())
	{
		//ok
	}
	else
	{
		NS_ASSERT (false);
	}

	if (ts_src.GetStartPort() == 0)
	{
		//ok
	}
	else
	{
		NS_ASSERT (false);
	}

	if (ts_dest.GetStartingAddress() == ts_dest.GetEndingAddress())
	{
		//ok
	}
	else
	{
		NS_ASSERT (false);
	}

	if (ts_dest.GetStartPort() == ts_dest.GetEndPort())
	{
		//ok
	}
	else
	{
		NS_ASSERT (false);
	}

	if (ts_dest.GetStartPort() == 0)
	{
		//ok
	}
	else
	{
		NS_ASSERT (false);
	}

	Ipv4Address group_address = ts_dest.GetStartingAddress();

	if (true == group_address.IsMulticast())
	{
		//ok
	}
	else
	{
		NS_ASSERT (false);
	}

	return group_address;
}

std::pair<IkeTrafficSelector, IkeTrafficSelector>
GsamUtility::GetTsPairFromGroupAddress (Ipv4Address group_address)
{
	std::pair<IkeTrafficSelector, IkeTrafficSelector> retval;
	retval.second.SetStartingAddress(group_address);
	retval.second.SetEndingAddress(group_address);
	return retval;
}

void
GsamUtility::LstSpiToLstU32 (const std::list<Ptr<Spi> >& lst_spi, std::list<uint32_t>& retval_lst_u32)
{
	for (std::list<Ptr<Spi> >::const_iterator const_it = lst_spi.begin();
			const_it != lst_spi.end();
			const_it++)
	{
		retval_lst_u32.push_back((*const_it)->ToUint32());
	}
}

void
GsamUtility::LstSpiToSetU32 (const std::list<Ptr<Spi> >& lst_spi, std::set<uint32_t>& retval_lst_u32)
{
	for (std::list<Ptr<Spi> >::const_iterator const_it = lst_spi.begin();
			const_it != lst_spi.end();
			const_it++)
	{
		retval_lst_u32.insert((*const_it)->ToUint32());
	}
}

uint8_t
GsamUtility::ConvertSaProposalIdToIpProtocolNum (IPsec::SA_Proposal_PROTOCOL_ID sa_protocol_id)
{
	uint8_t retval = 0;
	switch (sa_protocol_id)
	{
		case IPsec::SA_PROPOSAL_IKE:
			NS_ASSERT (false);
			break;
		case IPsec::SA_PROPOSAL_AH:
			retval = IPsec::IP_ID_AH;
			break;
		case IPsec::SA_PROPOSAL_ESP:
			retval = IPsec::IP_ID_ESP;
			break;
		default:
			NS_ASSERT (false);
	}

	return retval;
}

/********************************************************
 *        GsamConfig
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (GsamConfig);

Ptr<GsamConfig> GsamConfig::m_ptr_config_instance = Create<GsamConfig>();

TypeId
GsamConfig::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::GsamConfig")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<GsamConfig> ()
			;
	return tid;
}

GsamConfig::GsamConfig ()
  :  m_spi_rejection_propability (0),
	 m_q_unicast_address (Ipv4Address("0.0.0.0")),
	 m_default_session_timeout (Seconds(2.0)),
	 m_default_retransmit_timeout (Seconds(2.0))
{
	NS_LOG_FUNCTION (this);
	this->m_sec_grp_addr_range.first = Ipv4Address ("230.0.0.0").Get();
	this->m_sec_grp_addr_range.second = Ipv4Address ("235.0.0.0").Get();
	srand(time(NULL));
}

GsamConfig::~GsamConfig()
{
	NS_LOG_FUNCTION (this);
	this->m_set_used_sec_grp_addresses.clear();

}

TypeId
GsamConfig::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return GsamConfig::GetTypeId();
}

IPsec::MODE
GsamConfig::GetDefaultIpsecMode (void)
{
	return IPsec::TRANSPORT;
}

uint8_t
GsamConfig::GetDefaultIpsecProtocolId (void)
{
	return IPsec::IP_ID_AH;
}

IPsec::SA_Proposal_PROTOCOL_ID
GsamConfig::GetDefaultGSAProposalId (void)
{
	return IPsec::SA_PROPOSAL_AH;
}

Ipv4Address
GsamConfig::GetIgmpv3DestGrpReportAddress (void)
{
	return Ipv4Address ("224.0.0.22");
}

uint8_t
GsamConfig::GetSpiRejectPropability (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_spi_rejection_propability;
}

void
GsamConfig::SetSpiRejectPropability (uint8_t between_0_and_100)
{
	NS_LOG_FUNCTION (this);
	this->m_spi_rejection_propability = between_0_and_100;
}

Ptr<GsamConfig>
GsamConfig::GetSingleton (void)
{
	if (0 == GsamConfig::m_ptr_config_instance)
	{
		GsamConfig::m_ptr_config_instance = Create<GsamConfig>();
	}
	return GsamConfig::m_ptr_config_instance;
}

bool
GsamConfig::IsFalseByPercentage (uint8_t percentage_0_to_100)
{
	bool retval = true;
	uint8_t random_num = rand() % 100;
	if (random_num < percentage_0_to_100)
	{
		retval = false;
	}
	else
	{
		retval = true;
	}
	return retval;
}

void
GsamConfig::SetQAddress (Ipv4Address address)
{
	NS_LOG_FUNCTION (this);
	if (address.Get() == 0)
	{
		NS_ASSERT (false);
	}
	this->m_q_unicast_address = address;
}

Ipv4Address
GsamConfig::GetQAddress (void) const
{
	NS_LOG_FUNCTION (this);
	if (this->m_q_unicast_address.Get() == 0)
	{
		NS_ASSERT (false);
	}
	return this->m_q_unicast_address;
}


Time
GsamConfig::GetDefaultSessionTimeout (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_default_session_timeout;
}

void
GsamConfig::SetDefaultSessionTimeout (Time time)
{
	NS_LOG_FUNCTION (this);
	this->m_default_session_timeout = time;
}

Time
GsamConfig::GetDefaultRetransmitTimeout (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_default_retransmit_timeout;
}

void
GsamConfig::SetDefaultRetransmitTimeout (Time time)
{
	NS_LOG_FUNCTION (this);
	this->m_default_retransmit_timeout = time;
}

Ipv4Address
GsamConfig::GetAnUnusedSecGrpAddress (void)
{
	NS_LOG_FUNCTION (this);
	uint32_t u32_addr = this->m_sec_grp_addr_range.first + (rand() % (this->m_sec_grp_addr_range.second - this->m_sec_grp_addr_range.first));
	while (this->m_set_used_sec_grp_addresses.end() != this->m_set_used_sec_grp_addresses.find(u32_addr))
	{
		u32_addr = this->m_sec_grp_addr_range.first + (rand() % (this->m_sec_grp_addr_range.second - this->m_sec_grp_addr_range.first));
	}
	this->m_set_used_sec_grp_addresses.insert(u32_addr);
	return Ipv4Address (u32_addr);
}

Ipv4Address
GsamConfig::GetAUsedSecGrpAddress (void) const
{
	NS_LOG_FUNCTION (this);
	uint8_t set_size = this->m_set_used_sec_grp_addresses.size();
	uint8_t index = rand() % set_size;
	std::set<uint32_t>::const_iterator const_it = this->m_set_used_sec_grp_addresses.begin();
	std::advance(const_it, index);
	return Ipv4Address(*const_it);
}

void
GsamConfig::SetupIgmpAndGsam (const Ipv4InterfaceContainerMulticast& interfaces, uint8_t num_nqs)
{
	NS_LOG_FUNCTION (this);

	if (num_nqs > (interfaces.GetN() - 2))
	{
		//There have to be one q and at least one gm
		NS_ASSERT (false);
	}

	for (Ipv4InterfaceContainerMulticast::Iterator it = interfaces.Begin();
			it != interfaces.End();
			it++)
	{
		Ptr<Ipv4L3ProtocolMulticast> ipv4 = DynamicCast<Ipv4L3ProtocolMulticast>(it->first);
		uint32_t ifindex = it->second;

		uint32_t n_addr = ipv4->GetNAddresses(ifindex);
		std::cout << "Printing address of interface: " << ifindex << " of Node" << ipv4->GetNetDevice(ifindex)->GetNode()->GetId() << std::endl;
		for (	uint32_t n_addr_it = 0;
				n_addr_it < n_addr;
				n_addr_it++)
		{
			Ipv4Address if_ipv4_addr = ipv4->GetAddress(ifindex, n_addr_it).GetLocal();
			if_ipv4_addr.Print(std::cout);
			std::cout << std::endl;

			static uint8_t count = 0;
			if (0 == count)
			{
				//set q
				GsamConfig::GetSingleton()->SetQAddress(if_ipv4_addr);
				ipv4->GetIgmp()->SetRole(Igmpv3L4Protocol::QUERIER);
			}
			else if ((0 < count) && (count < 3))
			{
				//set nqs
				ipv4->GetIgmp()->SetRole(Igmpv3L4Protocol::NONQUERIER);
			}
			else
			{
				//set gms
				ipv4->GetIgmp()->SetRole(Igmpv3L4Protocol::GROUP_MEMBER);
			}
			count++;
		}
		std::cout << std::endl;

	}
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
	this->m_set_occupied_gsa_push_ids.clear();
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

uint32_t
GsamInfo::GetLocalAvailableIpsecSpi (const std::set<uint32_t>& external_occupied_u32_set) const
{
	NS_LOG_FUNCTION (this);

	uint32_t spi = 0;

	std::set<uint32_t> set_u32_merged;
	set_u32_merged.insert(this->m_set_occupied_ipsec_spis.begin(), this->m_set_occupied_ipsec_spis.end());
	set_u32_merged.insert(external_occupied_u32_set.begin(), external_occupied_u32_set.end());

	do {
		spi = rand();
	} while (	(0 != spi) &&
			(set_u32_merged.find(spi) != set_u32_merged.end()));

	return spi;
}

uint32_t
GsamInfo::GetLocalAvailableGsaPushId (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t spi = 0;

	do {
		spi = rand();
	} while (	(0 != spi) &&
				(this->m_set_occupied_gsa_push_ids.find(spi) != this->m_set_occupied_gsa_push_ids.end()));

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

uint32_t
GsamInfo::RegisterGsaPushId (void)
{
	uint32_t retval = this->GetLocalAvailableGsaPushId();

	this->OccupyGsaPushId(retval);

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
GsamInfo::OccupyGsaPushId (uint32_t gsa_push_id)
{
	NS_LOG_FUNCTION (this);
	std::pair<std::set<uint32_t>::iterator, bool> result = this->m_set_occupied_gsa_push_ids.insert(gsa_push_id);

	if (result.second == false)
	{
		//there is already a element of the same value of spi in the set
		NS_ASSERT (false);
	}
}

uint32_t
GsamInfo::GetNotOccupiedU32 (const std::set<uint32_t>& set_u32_occupied)
{
	uint32_t retval = 0;

	do {
		retval = rand();
	} while (	(0 != retval) &&
			(set_u32_occupied.find(retval) != set_u32_occupied.end()));

	return retval;
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
GsamInfo::FreeGsaPushId (uint32_t gsa_push_id)
{
	NS_LOG_FUNCTION (this);

	uint8_t deleted_num_spis = 0;

	deleted_num_spis = this->m_set_occupied_gsa_push_ids.erase(gsa_push_id);

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
	bool retval = false;

	if (false == GsamConfig::GetSingleton()->IsFalseByPercentage(GsamConfig::GetSingleton()->GetSpiRejectPropability()))
	{
		retval = true;
		return retval;
	}

	retval = (this->m_set_occupied_ipsec_spis.find(spi) != this->m_set_occupied_ipsec_spis.end());

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
 *        GsaPushSession
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (GsaPushSession);

TypeId
GsaPushSession::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::GsaPushSession")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<GsaPushSession> ()
			;
	return tid;
}

GsaPushSession::GsaPushSession ()
  :  m_id (0),
	 m_status (GsaPushSession::NONE),
	 m_flag_gms_spi_requested (false),
	 m_flag_nqs_spi_requested (false),
	 m_ptr_database (0),
	 m_ptr_gm_session (0),
	 m_flag_gm_session_acked_notified (false),
	 m_ptr_gsa_q_to_install (0),
	 m_gsa_q_spi_before_revision (0),
	 m_ptr_gsa_r_to_install (0),
	 m_gsa_r_spi_before_revision (0)
{
	NS_LOG_FUNCTION (this);
}

GsaPushSession::~GsaPushSession()
{
	NS_LOG_FUNCTION (this);
	this->m_ptr_database->GetInfo()->FreeGsaPushId(this->m_id);
	this->m_ptr_gm_session = 0;
	this->m_lst_ptr_nq_sessions_sent_unreplied.clear();
	this->m_lst_ptr_nq_sessions_acked_notified.clear();
	this->m_lst_ptr_other_gm_sessions_sent_unreplied.clear();
	this->m_lst_ptr_other_gm_sessions_replied_notified.clear();
	this->m_ptr_gsa_q_to_install = 0;
	this->m_ptr_gsa_r_to_install = 0;
	this->m_ptr_database = 0;
	this->m_set_aggregated_gsa_q_spi_notification.clear();
	this->m_set_aggregated_gsa_r_spi_notification.clear();
	this->m_lst_nq_rejected_spis_subs.clear();
}

TypeId
GsaPushSession::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return GsaPushSession::GetTypeId();
}

void
GsaPushSession::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
GsaPushSession::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

bool
operator < (GsaPushSession const& lhs, GsaPushSession const& rhs)
{
	return lhs.m_id < rhs.m_id;
}

bool
operator == (GsaPushSession const& lhs, GsaPushSession const& rhs)
{
	bool retval = true;

	if (lhs.m_id != rhs.m_id)
	{
		retval = false;
	}

//	if (lhs.m_ptr_database == 0)
//	{
//		NS_ASSERT (false);
//	}
//
//	if (rhs.m_ptr_database == 0)
//	{
//		NS_ASSERT (false);
//	}
//
//
//	if (lhs.m_ptr_gm_session != rhs.m_ptr_gm_session)
//	{
//		retval = false;
//	}
//
//	if (lhs.m_lst_ptr_nq_sessions_sent_unreplied.size() != rhs.m_lst_ptr_nq_sessions_sent_unreplied.size())
//	{
//		retval = false;
//	}
//
//	if (lhs.m_lst_ptr_nq_sessions_replied.size() != rhs.m_lst_ptr_nq_sessions_replied.size())
//	{
//		retval = false;
//	}

	return retval;
}

Ptr<GsaPushSession>
GsaPushSession::CreatePushSession (uint32_t id)
{
	if (id == 0)
	{
		NS_ASSERT (false);
	}

	Ptr<GsaPushSession> retval = Create<GsaPushSession>();
	retval->m_id = id;

	return retval;
}

void
GsaPushSession::SetStatus (GsaPushSession::GSA_PUSH_STATUS status)
{
	NS_LOG_FUNCTION (this);

	if (status == GsaPushSession::NONE)
	{
		NS_ASSERT (false);
	}

	this->m_status = status;
}

void
GsaPushSession::SetDatabase (Ptr<IpSecDatabase> database)
{
	NS_LOG_FUNCTION (this);

	if (database == 0)
	{
		NS_ASSERT (false);
	}

	if (this->m_ptr_database != 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_database = database;
}

void
GsaPushSession::SetGmSession (Ptr<GsamSession> gsam_gm_session)
{
	NS_LOG_FUNCTION (this);

	if (gsam_gm_session == 0)
	{
		NS_ASSERT (false);
	}

	if (this->m_ptr_gm_session != 0)
	{
		NS_ASSERT (0);
	}

	this->m_ptr_gm_session = gsam_gm_session;
}

void
GsaPushSession::SelfRemoval (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_database == 0)
	{
		NS_ASSERT (false);
	}

	if (this->m_lst_ptr_nq_sessions_sent_unreplied.size() != 0)
	{
		NS_ASSERT (false);
	}

	for (	std::list<Ptr<GsamSession> >::iterator it = this->m_lst_ptr_nq_sessions_acked_notified.begin();
			it != this->m_lst_ptr_nq_sessions_acked_notified.end();
			it++)
	{
		(*it)->ClearGsaPushSession();
	}

	this->m_ptr_gm_session->ClearGsaPushSession();

	this->m_ptr_database->RemoveGsaPushSession(this);
}

void
GsaPushSession::MarkGmSessionReplied (void)
{
	NS_LOG_FUNCTION (this);

	this->m_flag_gm_session_acked_notified = true;
}

void
GsaPushSession::MarkNqSessionReplied (Ptr<GsamSession> nq_session)
{
	NS_LOG_FUNCTION (this);

	if (nq_session == 0)
	{
		NS_ASSERT (false);
	}

	std::size_t total_size = this->m_lst_ptr_nq_sessions_sent_unreplied.size() + this->m_lst_ptr_nq_sessions_acked_notified.size();

	this->m_lst_ptr_nq_sessions_sent_unreplied.remove(nq_session);

	this->m_lst_ptr_nq_sessions_acked_notified.push_back(nq_session);

	if (total_size != (this->m_lst_ptr_nq_sessions_sent_unreplied.size() + this->m_lst_ptr_nq_sessions_acked_notified.size()))
	{
		NS_ASSERT (false);
	}
}

void
GsaPushSession::MarkOtherGmSessionReplied (Ptr<GsamSession> other_gm_session)
{
	NS_LOG_FUNCTION (this);

	if (other_gm_session == 0)
	{
		NS_ASSERT (false);
	}

	std::size_t total_size = this->m_lst_ptr_other_gm_sessions_sent_unreplied.size() + this->m_lst_ptr_other_gm_sessions_replied_notified.size();

	this->m_lst_ptr_other_gm_sessions_sent_unreplied.remove(other_gm_session);

	this->m_lst_ptr_other_gm_sessions_replied_notified.push_back(other_gm_session);

	if (total_size != (this->m_lst_ptr_other_gm_sessions_sent_unreplied.size() + this->m_lst_ptr_other_gm_sessions_replied_notified.size()))
	{
		NS_ASSERT (false);
	}
}

void
GsaPushSession::PushBackNqSession (Ptr<GsamSession> nq_session)
{
	NS_LOG_FUNCTION (this);
	if (nq_session == 0)
	{
		NS_ASSERT (false);
	}

	this->m_lst_ptr_nq_sessions_sent_unreplied.push_back(nq_session);
}

void
GsaPushSession::PushBackOtherGmSession (Ptr<GsamSession> other_gm_session)
{
	NS_LOG_FUNCTION (this);
	if (other_gm_session == 0)
	{
		NS_ASSERT (false);
	}

	this->m_lst_ptr_other_gm_sessions_sent_unreplied.push_back(other_gm_session);
}

Ptr<IpSecSAEntry>
GsaPushSession::CreateGsaQ (uint32_t spi)
{
	NS_LOG_FUNCTION (this);

	Ptr<IpSecSAEntry> retval = Create<IpSecSAEntry>();
	retval->SetSpi(spi);

	if (this->m_ptr_gsa_q_to_install != 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_gsa_q_to_install = retval;

	return retval;
}

Ptr<IpSecSAEntry>
GsaPushSession::CreateGsaR (uint32_t spi)
{
	NS_LOG_FUNCTION (this);

	Ptr<IpSecSAEntry> retval = Create<IpSecSAEntry>();
	retval->SetSpi(spi);

	if (this->m_ptr_gsa_r_to_install != 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_gsa_r_to_install = retval;

	return retval;
}

void
GsaPushSession::InstallGsaPair (void)
{
	NS_LOG_FUNCTION (this);

	if (false == this->m_ptr_gm_session->IsHostQuerier())
	{
		NS_ASSERT (false);
	}

	Ptr<IpSecPolicyEntry> policy = this->m_ptr_gm_session->GetRelatedPolicy();
	Ptr<GsamSessionGroup> session_group = this->m_ptr_gm_session->GetSessionGroup();
	Ptr<IpSecSAEntry> gsa_q = 0;
	if (0 != session_group)
	{
		if (0 != session_group->GetRelatedGsaQ())
		{
			gsa_q = session_group->GetRelatedGsaQ();
		}
		else
		{
			//ignore
		}
	}
	else
	{
		//ignore
	}

	if (policy == 0)
	{
		NS_ASSERT (false);
	}

	//the new gm session can already have Gsa Q because there is a existing gm session group for that group address
	if (0 == gsa_q)
	{
		gsa_q = policy->GetOutboundSAD()->CreateIpSecSAEntry(this->m_ptr_gsa_q_to_install->GetSpi());
		this->m_ptr_gm_session->AssociateGsaQ(gsa_q);
	}
	else
	{
		gsa_q->SetSpi(this->m_ptr_gsa_q_to_install->GetSpi());
	}

	//gsa_r must be completely new
	Ptr<IpSecSAEntry> gsa_r = policy->GetInboundSAD()->CreateIpSecSAEntry(this->m_ptr_gsa_r_to_install->GetSpi());
	this->m_ptr_gm_session->SetRelatedGsaR(gsa_r);

	Ptr<GsamInfo> info = this->m_ptr_database->GetInfo();
	info->OccupyIpsecSpi(this->m_ptr_gsa_r_to_install->GetSpi());

	this->SelfRemoval();
}

void
GsaPushSession::SwitchStatus (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_status == GsaPushSession::NONE)
	{
		NS_ASSERT (false);
	}

	this->m_flag_gm_session_acked_notified = false;
	this->ClearNqSessions();
	this->m_flag_gms_spi_requested = false;
	this->m_flag_nqs_spi_requested = false;

	if (this->m_status == GsaPushSession::GSA_PUSH_ACK)
	{
		this->m_status = GsaPushSession::SPI_REQUEST_RESPONSE;
	}
	else if (this->m_status == GsaPushSession::SPI_REQUEST_RESPONSE)
	{
		this->m_status = GsaPushSession::GSA_PUSH_ACK;
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
GsaPushSession::AggregateGsaQSpiNotification (const std::set<uint32_t>& set_spi_notification)
{
	NS_LOG_FUNCTION (this);

	this->m_set_aggregated_gsa_q_spi_notification.insert (set_spi_notification.begin(), set_spi_notification.end());
}

void
GsaPushSession::AggregateGsaRSpiNotification (const std::set<uint32_t>& set_spi_notification)
{
	NS_LOG_FUNCTION (this);

	this->m_set_aggregated_gsa_r_spi_notification.insert(set_spi_notification.begin(), set_spi_notification.end());
}

void
GsaPushSession::GenerateNewSpisAndModitySa (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_status != GsaPushSession::SPI_REQUEST_RESPONSE)
	{
		NS_ASSERT (false);
	}

	if (false == this->IsAllReplied())
	{
		NS_ASSERT (false);
	}

	if (this->m_ptr_gm_session != 0)
	{
		if (this->m_ptr_gsa_q_to_install == 0)
		{
			NS_ASSERT (false);
		}

		if (this->m_ptr_gsa_r_to_install == 0)
		{
			NS_ASSERT (false);
		}

		if ((this->m_set_aggregated_gsa_q_spi_notification.size() == 0) &&
				(this->m_set_aggregated_gsa_r_spi_notification.size() == 0))
		{
			NS_ASSERT (false);
		}

		//gm session driven spi notification request response

		if (this->m_set_aggregated_gsa_q_spi_notification.size() > 0)
		{
			//GM rejected stored but not yet installed gsa_q

			uint32_t revised_gsa_q_spi = GsamInfo::GetNotOccupiedU32(this->m_set_aggregated_gsa_q_spi_notification);
			this->m_gsa_q_spi_before_revision = this->m_ptr_gsa_q_to_install->GetSpi();
			this->m_ptr_gsa_q_to_install->SetSpi(revised_gsa_q_spi);
		}

		if (this->m_set_aggregated_gsa_r_spi_notification.size() > 0)
		{
			//nq rejected stored but not yet installed gsa_r
			Ptr<GsamInfo> info = this->m_ptr_database->GetInfo();
			uint32_t revised_gsa_r_spi = info->GetLocalAvailableIpsecSpi(this->m_set_aggregated_gsa_r_spi_notification);
			this->m_gsa_r_spi_before_revision = this->m_ptr_gsa_r_to_install->GetSpi();
			this->m_ptr_gsa_r_to_install->SetSpi(revised_gsa_r_spi);
		}

		this->InstallGsaPair();

	}
	else
	{
		NS_ASSERT (false);
	}
}

void
GsaPushSession::AlterRejectedGsaAndAggregatePacket (Ptr<Packet> retval_packet_for_nqs,
													std::list<std::pair<Ptr<GsamSession>, Ptr<Packet> > >& retval_lst_gm_session_packet_bundles)
{
	NS_LOG_FUNCTION (this);
	//nq sessions driven spi notification request response

	if (this->m_status != GsaPushSession::SPI_REQUEST_RESPONSE)
	{
		NS_ASSERT (false);
	}

	if (false == this->IsAllReplied())
	{
		NS_ASSERT (false);
	}


	if (this->m_lst_nq_rejected_spis_subs.size() != 0)
	{
		NS_ASSERT (false);
	}

	if(this->m_set_aggregated_gsa_r_spi_notification.size() == 0)
	{
		NS_ASSERT (false);
	}

	if (this->m_ptr_gm_session == 0)
	{
		//nq sessions driven spi notification request response
		if (this->m_ptr_gsa_q_to_install != 0)
		{
			NS_ASSERT (false);
		}

		if (this->m_ptr_gsa_r_to_install != 0)
		{
			NS_ASSERT (false);
		}

		if (this->m_lst_nq_rejected_spis_subs.size() == 0)
		{
			NS_ASSERT (false);
		}

		if (this->m_set_aggregated_gsa_r_spi_notification.size() == 0)
		{
			NS_ASSERT (false);
		}

		Ptr<GsamInfo> info = this->m_ptr_database->GetInfo();
		IkePayloadHeader::PAYLOAD_TYPE next_payload_type = IkePayloadHeader::NO_NEXT_PAYLOAD;

		for (	std::list<Ptr<IkeGroupNotifySubstructure> >::const_iterator const_sub_it = this->m_lst_nq_rejected_spis_subs.begin();
				const_sub_it != this->m_lst_nq_rejected_spis_subs.end();
				const_sub_it++)
		{
			const Ptr<IkeGroupNotifySubstructure> value_const_it = *const_sub_it;

			if (value_const_it->GetNotifyMessageType() != IkeGroupNotifySubstructure::GSA_R_SPI_REJECTION)
			{
				NS_ASSERT (false);
			}

			if (value_const_it->GetSpiSize() != IPsec::AH_ESP_SPI_SIZE)
			{
				NS_ASSERT (false);
			}

			IkeTrafficSelector ts_src = value_const_it->GetTrafficSelectorSrc();
			IkeTrafficSelector ts_dest = value_const_it->GetTrafficSelectorDest();
			//find policy
			Ptr<IpSecPolicyEntry> policy = this->m_ptr_database->GetPolicyDatabase()->GetPolicy(ts_src, ts_dest);
			if (policy == 0)
			{
				NS_ASSERT (false);
			}

			Ptr<GsamSessionGroup> gm_session_group = this->m_ptr_database->GetSessionGroup(GsamUtility::CheckAndGetGroupAddressFromTrafficSelectors(ts_src, ts_dest));
			if (0 == gm_session_group)
			{
				NS_ASSERT (false);
			}

			Ptr<IkeGsaPayloadSubstructure> new_gsa_payload_sub = IkeGsaPayloadSubstructure::GenerateEmptyGsaPayload(this->GetId(),
																													ts_src,
																													ts_dest,
																													true);

			Ptr<IpSecSADatabase> inbound_sad = policy->GetInboundSAD();
			const std::set<uint32_t>& reject_spis_const_it = value_const_it->GetSpis();
			for (std::set<uint32_t>::const_iterator const_spi_it = reject_spis_const_it.begin();
					const_spi_it != reject_spis_const_it.end();
					const_spi_it++)
			{
				uint32_t value_const_spi_it = (*const_spi_it);
				//find sa
				Ptr<IpSecSAEntry> gsa_r_to_modify = inbound_sad->GetIpsecSAEntry(value_const_spi_it);
				if (gsa_r_to_modify == 0)
				{
					NS_ASSERT (false);
				}
				uint32_t gsa_r_old_spi = gsa_r_to_modify->GetSpi();
				uint32_t gsa_r_new_spi = info->GetLocalAvailableIpsecSpi(this->m_set_aggregated_gsa_r_spi_notification);
				//aggregate new_gsa_payload_sub
				new_gsa_payload_sub->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(	Create<Spi>(gsa_r_old_spi),
																							IkeGsaProposal::GSA_R_TO_BE_MODIFIED));
				new_gsa_payload_sub->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(	Create<Spi>(gsa_r_new_spi),
																							IkeGsaProposal::GSA_R_REPLACEMENT));

				//aggregate packet to send to gm session because of change of gsa_r;
				Ptr<GsamSession> gsa_r_related_gm_session = gm_session_group->GetSessionByGsaRSpi(gsa_r_old_spi);
				if (0 == gsa_r_related_gm_session)
				{
					NS_ASSERT (false);
				}

				Ptr<IkeGsaPayloadSubstructure> gsa_payload_sub_to_gm = IkeGsaPayloadSubstructure::GenerateEmptyGsaPayload(this->GetId(),
																														ts_src,
																														ts_dest,
																														true);
				gsa_payload_sub_to_gm->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(	Create<Spi>(gsa_r_old_spi),
																							IkeGsaProposal::GSA_R_TO_BE_MODIFIED));
				gsa_payload_sub_to_gm->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(	Create<Spi>(gsa_r_new_spi),
																							IkeGsaProposal::GSA_R_REPLACEMENT));
				IkePayload gsa_payload_to_gm;
				gsa_payload_to_gm.SetSubstructure(gsa_payload_sub_to_gm);
				Ptr<Packet> packet_to_gm_session = Create<Packet>();
				packet_to_gm_session->AddHeader(gsa_payload_to_gm);
				std::pair<Ptr<GsamSession>, Ptr<Packet> > gm_session_packet_bundle = std::make_pair(gsa_r_related_gm_session, packet_to_gm_session);
				retval_lst_gm_session_packet_bundles.push_back(gm_session_packet_bundle);

				//alter local gsa r spi
				gsa_r_to_modify->SetSpi(gsa_r_new_spi);
				info->OccupyIpsecSpi(gsa_r_new_spi);
			}

			//aggregate payload to packet
			IkePayload new_gsa_payload;
			new_gsa_payload.SetSubstructure(new_gsa_payload_sub);
			new_gsa_payload.SetNextPayloadType(next_payload_type);
			next_payload_type = new_gsa_payload.GetPayloadType();
			retval_packet_for_nqs->AddHeader(new_gsa_payload);
		}
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
GsaPushSession::PushBackNqRejectionGroupNotifySub (Ptr<IkeGroupNotifySubstructure> sub)
{
	if (0 == sub)
	{
		NS_ASSERT (false);
	}

	Ptr<IkeGroupNotifySubstructure> sub_with_same_ts_in_the_list = 0;

	for (	std::list<Ptr<IkeGroupNotifySubstructure> >::iterator it = this->m_lst_nq_rejected_spis_subs.begin();
			it != this->m_lst_nq_rejected_spis_subs.end();
			it++)
	{
		if ((*it)->GetNotifyMessageType() != IkeGroupNotifySubstructure::GSA_R_SPI_REJECTION)
		{
			NS_ASSERT (false);
		}

		if ((*it)->GetTrafficSelectorSrc() == sub->GetTrafficSelectorSrc())
		{
			if ((*it)->GetTrafficSelectorDest() == sub->GetTrafficSelectorDest())
			{
				sub_with_same_ts_in_the_list = (*it);
				break;
			}
		}
	}

	if (0 == sub_with_same_ts_in_the_list)
	{
		this->m_lst_nq_rejected_spis_subs.push_back(sub);
	}
	else
	{
		//merge spis
		sub_with_same_ts_in_the_list->InsertSpis(sub->GetSpis());
	}
}

void
GsaPushSession::SetFlagGmsSpiRequested (void)
{
	NS_LOG_FUNCTION (this);
	this->m_flag_gms_spi_requested = true;
}

void
GsaPushSession::SetFlagNqsSpiRequested (void)
{
	NS_LOG_FUNCTION (this);
	this->m_flag_nqs_spi_requested = true;
}

uint32_t
GsaPushSession::GetId (void) const
{
	NS_LOG_FUNCTION (this);

	if (0 == this->m_id)
	{
		NS_ASSERT (false);
	}

	return this->m_id;
}

GsaPushSession::GSA_PUSH_STATUS
GsaPushSession::GetStatus (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_status == GsaPushSession::NONE)
	{
		NS_ASSERT (false);
	}

	return this->m_status;
}

bool
GsaPushSession::IsAllReplied (void) const
{
	NS_LOG_FUNCTION (this);

	bool retval = true;

	if (0 != this->m_ptr_gm_session)
	{
		//gm_session may be zero in phase of spi request of new incoming nq
		if (false == this->m_flag_gm_session_acked_notified)
		{
			retval = false;
		}
	}

	std::size_t size_nq_sessions_sent_unreplied = this->m_lst_ptr_nq_sessions_sent_unreplied.size();
	if (size_nq_sessions_sent_unreplied != 0)
	{
		retval = false;
	}

	std::size_t size_other_gm_sessions_sent_unreplied = this->m_lst_ptr_other_gm_sessions_sent_unreplied.size();
	if (size_other_gm_sessions_sent_unreplied != 0)
	{
		retval = false;
	}

	return retval;
}

const Ptr<IpSecSAEntry>
GsaPushSession::GetGsaQ (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_gsa_q_to_install == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_gsa_q_to_install;
}
const Ptr<IpSecSAEntry>
GsaPushSession::GetGsaR (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_gsa_r_to_install == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_gsa_r_to_install;
}

uint32_t
GsaPushSession::GetOldGsaQSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_gsa_q_spi_before_revision;
}

uint32_t
GsaPushSession::GetOldGsaRSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_gsa_r_spi_before_revision;
}

void
GsaPushSession::ClearNqSessions (void)
{
	NS_LOG_FUNCTION (this);

	this->m_lst_ptr_nq_sessions_sent_unreplied.clear();
	this->m_lst_ptr_nq_sessions_acked_notified.clear();
}

Ptr<GsamSession>
GsaPushSession::GetGmSession (void) const
{
	NS_LOG_FUNCTION (this);

	return this->m_ptr_gm_session;
}

bool
GsaPushSession::IsGmsSpiRequested (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_flag_gms_spi_requested;
}

bool
GsaPushSession::IsNqsSpiRequested (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_flag_nqs_spi_requested;
}

const std::list<Ptr<GsamSession> >&
GsaPushSession::GetNqSessions (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_lst_ptr_nq_sessions_acked_notified;
}

const std::list<Ptr<GsamSession> >&
GsaPushSession::GetOtherGmSessions (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_lst_ptr_other_gm_sessions_replied_notified;
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
  :  m_current_message_id (0),
	 m_peer_address (Ipv4Address ("0.0.0.0")),
	 m_ptr_session_group (0),
	 m_p1_role (GsamSession::P1_UNINITIALIZED),
	 m_ptr_init_sa (0),
	 m_ptr_kek_sa (0),
	 m_ptr_database (0),
	 m_ptr_related_gsa_r (0),
	 m_ptr_push_session (0),
	 m_last_sent_packet (0)
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
	this->m_ptr_push_session = 0;
	this->m_last_sent_packet = 0;
	this->m_set_ptr_push_sessions.clear();
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
			if (0 == message_id)
			{
				//ok
			}
			else

			{
				NS_ASSERT (false);
			}
		}
	}
	else
	{
		if ((0 == message_id) || (1 == message_id))
		{
			if (this->m_p1_role == GsamSession::INITIATOR)
			{
				//phase 1
				//ok
				this->m_current_message_id = message_id;
			}
		}
		else if (message_id < 0)
		{
			NS_ASSERT (false);
		}
		else
		{
			if (this->m_p1_role == GsamSession::INITIATOR)
			{
				//phase 2
				//ok
				this->m_current_message_id = message_id;
			}
			else
			{
				NS_ASSERT (false);
			}
		}
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
		this->m_group_address = group_address;
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
	NS_LOG_FUNCTION (this);
	if (policy == 0)
	{
		NS_ASSERT (false);
	}

	if (this->m_ptr_session_group == 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_session_group->AssociateWithPolicy (policy);
}

void
GsamSession::SetGsaPushSession (Ptr<GsaPushSession> gsa_push_session)
{
	NS_LOG_FUNCTION (this);

	if (this->GetGroupAddress() == GsamConfig::GetIgmpv3DestGrpReportAddress())
	{
		//make sure it is a gm session on Q
		NS_ASSERT (false);
	}

	if (gsa_push_session == 0)
	{
		NS_ASSERT (false);
	}

	if (this->m_ptr_push_session != 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_push_session = gsa_push_session;

	gsa_push_session->SetGmSession(this);

}

void
GsamSession::InsertGsaPushSession (Ptr<GsaPushSession> gsa_push_session)
{

	std::pair<std::set<Ptr<GsaPushSession> >::iterator, bool> insert_result = this->m_set_ptr_push_sessions.insert(gsa_push_session);

	if (insert_result.second == true)
	{
		//what to do?
	}
	else
	{
		//what to do if there is already an existing element?
		NS_ASSERT (false);
	}
}

void
GsamSession::ClearGsaPushSession (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_push_session == 0)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_push_session = 0;
}

Ptr<GsaPushSession>
GsamSession::CreateAndSetGsaPushSession (void)
{
	if (false == this->IsHostQuerier())
	{
		NS_ASSERT (false);
	}

	Ptr<GsaPushSession> retval = this->GetDatabase()->CreateGsaPushSession();
	this->SetGsaPushSession(retval);
	return retval;
}

void
GsamSession::SetCachePacket (Ptr<Packet> packet)
{
	NS_LOG_FUNCTION (this);
	if (packet == 0)
	{
		NS_ASSERT (false);
	}
	this->m_last_sent_packet = 0;
	this->m_last_sent_packet = packet;
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

	std::cout << "Node: " << this->GetDatabase()->GetGsam()->GetNode()->GetId() << ", ";
	if (true == this->IsHostGroupMember())
	{
		std::cout << "Q, ";
	}
	else if (true == this->IsHostNonQuerier())
	{
		std::cout << "NQ, ";
	}
	else if (true == this->IsHostQuerier())
	{
		std::cout << "GM, ";
	}
	else
	{
		NS_ASSERT (false);
	}

	std::cout << "GsamSession: " << this << " time out." << std::endl;
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

	bool retval = this->GetDatabase()->IsHostQuerier();

	return retval;
}

bool
GsamSession::IsHostGroupMember (void) const
{
	NS_LOG_FUNCTION (this);

	bool retval = this->GetDatabase()->IsHostGroupMember();

	return retval;
}

bool
GsamSession::IsHostNonQuerier (void) const
{
	NS_LOG_FUNCTION (this);

	bool retval = this->GetDatabase()->IsHostNonQuerier();

	if (true == retval)
	{
		if (	(this->GetGroupAddress().Get() != 0) &&
				(this->GetGroupAddress().Get() != GsamConfig::GetIgmpv3DestGrpReportAddress().Get()))
		{
			NS_ASSERT (false);
		}

	}

	return retval;
}

Ptr<GsaPushSession>
GsamSession::GetGsaPushSession (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_push_session == 0)
	{
		NS_ASSERT (false);
	}

	if (this->GetGroupAddress() == GsamConfig::GetIgmpv3DestGrpReportAddress())
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_push_session;
}

Ptr<GsaPushSession>
GsamSession::GetGsaPushSession (uint32_t gsa_push_id)
{
	if (this->GetGroupAddress() != GsamConfig::GetIgmpv3DestGrpReportAddress())
	{
		NS_ASSERT (false);
	}

	Ptr<GsaPushSession> retval = 0;

	if (gsa_push_id == 0)
	{
		//not gsa push session
		//ok for newly joined nq session
		this->m_ptr_push_session = this->GetDatabase()->CreateGsaPushSession();
	}
	else
	{
		for (std::set<Ptr<GsaPushSession> >::iterator it = this->m_set_ptr_push_sessions.begin();
				it != this->m_set_ptr_push_sessions.end();
				it++)
		{
			Ptr<GsaPushSession> value_it = *it;

			if (value_it->GetId() == gsa_push_id)
			{
				retval = value_it;
			}
		}
	}

	if (retval == 0)
	{
		NS_ASSERT (false);
	}

	return retval;
}

Ptr<Packet>
GsamSession::GetCachePacket (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_last_sent_packet == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_last_sent_packet;
}

Ptr<GsamSessionGroup>
GsamSession::GetSessionGroup (void) const
{
	NS_LOG_FUNCTION (this);

	//return value is allowed to be zero
	return this->m_ptr_session_group;
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

std::list<Ptr<GsamSession> >&
GsamSessionGroup::GetSessions (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_lst_sessions;
}

void
GsamSessionGroup::EtablishPolicy (Ipv4Address group_address,
									uint8_t protocol_id,
									IPsec::PROCESS_CHOICE policy_process_choice,
									IPsec::MODE ipsec_mode)
{
	NS_LOG_FUNCTION (this);
	if (group_address.Get() == 0)
	{
		NS_ASSERT (false);
	}

	Ptr<IpSecPolicyEntry> policy = this->GetDatabase()->GetPolicyDatabase()->CreatePolicyEntry();
	policy->SetSingleDestAddress(group_address);
	policy->SetProtocolNum(protocol_id);
	policy->SetProcessChoice(policy_process_choice);
	policy->SetIpsecMode(ipsec_mode);

	this->AssociateWithPolicy(policy);
}

void
GsamSessionGroup::EtablishPolicy (	const IkeTrafficSelector& ts_src,
									const IkeTrafficSelector& ts_dest,
									uint8_t protocol_id,
									IPsec::PROCESS_CHOICE policy_process_choice,
									IPsec::MODE ipsec_mode)
{
	NS_LOG_FUNCTION (this);

	Ipv4Address group_address = GsamUtility::CheckAndGetGroupAddressFromTrafficSelectors(ts_src, ts_dest);

	this->EtablishPolicy(group_address, protocol_id, policy_process_choice, ipsec_mode);
}

void
GsamSessionGroup::InstallGsaQ (uint32_t spi)
{
	NS_LOG_FUNCTION (this);

	if (this->GetDatabase()->IsHostQuerier())
	{
		//Q should not invoke this method
		NS_ASSERT (false);
	}

	Ptr<IpSecSAEntry> gsa_q = 0;

	if (this->GetDatabase()->IsHostNonQuerier())
	{
		gsa_q = this->InstallOutboundGsa(spi);
	}
	else if (this->GetDatabase()->IsHostGroupMember())
	{
		gsa_q = this->InstallInboundGsa(spi);
	}

	this->AssociateWithGsaQ(gsa_q);
}
void
GsamSessionGroup::InstallGsaR (uint32_t spi)
{
	NS_LOG_FUNCTION (this);

	if (this->GetDatabase()->IsHostQuerier())
	{
		//Q should not invoke this method
		NS_ASSERT (false);
	}

	if (this->GetDatabase()->IsHostNonQuerier())
	{
		this->InstallInboundGsa(spi);
	}
	else if (this->GetDatabase()->IsHostGroupMember())
	{
		this->InstallOutboundGsa(spi);
	}
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
GsamSessionGroup::GetRelatedPolicy (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_group_address == GsamConfig::GetIgmpv3DestGrpReportAddress())
	{
		//nq session on Q or on NQ
		NS_ASSERT (false);
	}

	Ptr<IpSecPolicyEntry> retval = 0;

	if (0 != this->m_ptr_related_policy)
	{
		retval = this->m_ptr_related_policy;
	}
	else
	{
		std::pair<IkeTrafficSelector, IkeTrafficSelector> tss = GsamUtility::GetTsPairFromGroupAddress(this->m_group_address);
		retval = this->m_ptr_database->GetPolicyDatabase()->GetPolicy(tss.first, tss.second);
		if (0 != retval)
		{
			this->m_ptr_related_policy = retval;
		}
	}

	//return value can be zero. For the use of judging the need of creating policy
	return retval;
}

const std::list<Ptr<GsamSession> >&
GsamSessionGroup::GetSessionsConst (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_lst_sessions;
}

Ptr<GsamSession>
GsamSessionGroup::GetSessionByGsaRSpi (uint32_t gsa_r_spi)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> retval = 0;
	bool flag_guard_second_session_found = false;

	for (	std::list<Ptr<GsamSession> >::iterator it = this->m_lst_sessions.begin();
			it != this->m_lst_sessions.end();
			it++)
	{
		Ptr<GsamSession> value_it = (*it);
		Ptr<IpSecSAEntry> gsa_r = value_it->GetRelatedGsaR();

		if (0 != gsa_r)
		{
			if (gsa_r->GetSpi() == gsa_r_spi)
			{
				if (true == flag_guard_second_session_found)
				{
					NS_ASSERT (false);
				}
				retval = value_it;
				flag_guard_second_session_found = true;
			}
		}
		else //0 == gsa_r, skip
		{

		}
	}

	return retval;
}

Ptr<IpSecSAEntry>
GsamSessionGroup::InstallInboundGsa (uint32_t spi)
{
	NS_LOG_FUNCTION (this);

	if (0 == this->GetRelatedPolicy())
	{
		NS_ASSERT (false);
	}

	Ptr<IpSecSAEntry> retval = this->GetRelatedPolicy()->GetInboundSAD()->CreateIpSecSAEntry(spi);

	return retval;
}

Ptr<IpSecSAEntry>
GsamSessionGroup::InstallOutboundGsa (uint32_t spi)
{
	NS_LOG_FUNCTION (this);

	if (0 == this->GetRelatedPolicy())
	{
		NS_ASSERT (false);
	}

	Ptr<IpSecSAEntry> retval = this->GetRelatedPolicy()->GetOutboundSAD()->CreateIpSecSAEntry(spi);

	return retval;
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
  :  m_direction (IpSecSAEntry::NO_DIRECTION),
	 m_spi (0),
	 m_ptr_encrypt_fn (0),
	 m_ptr_sad (0),
     m_ptr_policy (0)
{
	NS_LOG_FUNCTION (this);
}

IpSecSAEntry::~IpSecSAEntry()
{
	NS_LOG_FUNCTION (this);
	if (IpSecSAEntry::INBOUND == this->m_direction)
	{
		this->m_ptr_sad->GetRootDatabase()->GetInfo()->FreeIpsecSpi(this->m_spi);
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
	bool retval = true;

	if (lhs.m_direction != rhs.m_direction)
	{
		retval = false;
	}

	if (lhs.m_spi != rhs.m_spi)
	{
		retval = false;
	}

	return retval;
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

void
IpSecSAEntry::SetInbound (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_direction != IpSecSAEntry::NO_DIRECTION)
	{
		NS_LOG_FUNCTION (false);
	}

	this->m_direction = IpSecSAEntry::INBOUND;
}

void
IpSecSAEntry::SetOutbound (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_direction != IpSecSAEntry::NO_DIRECTION)
	{
		NS_LOG_FUNCTION (false);
	}

	this->m_direction = IpSecSAEntry::OUTBOUND;
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

bool
IpSecSAEntry::IsInbound (void) const
{
	NS_LOG_FUNCTION (this);

	bool retval = false;

	if (this->m_direction == IpSecSAEntry::INBOUND)
	{
		retval = true;
	}

	return retval;
}

bool
IpSecSAEntry::IsOutbound (void) const
{
	NS_LOG_FUNCTION (this);

	bool retval = false;

	if (this->m_direction == IpSecSAEntry::OUTBOUND)
	{
		retval = true;
	}

	return retval;
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
  :  m_direction (IpSecSADatabase::NO_DIRECTION),
	 m_ptr_root_database (0),
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

void
IpSecSADatabase::SetDirection (IpSecSADatabase::DIRECTION sad_direction)
{
	NS_LOG_FUNCTION (this);

	if (this->m_direction != IpSecSADatabase::NO_DIRECTION)
	{
		NS_ASSERT (false);
	}

	this->m_direction = sad_direction;
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

void
IpSecSADatabase::GetSpis (std::list<Ptr<Spi> >& retval) const
{
	NS_LOG_FUNCTION (this);

	for (	std::list<Ptr<IpSecSAEntry> >::const_iterator const_it = this->m_lst_entries.begin();
			const_it != this->m_lst_entries.end();
			const_it++)
	{
		Ptr<Spi> spi = Create<Spi>();
		spi->SetValueFromUint32((*const_it)->GetSpi());
		retval.push_back(spi);
	}
}

IpSecSADatabase::DIRECTION
IpSecSADatabase::GetDirection (void) const
{
	NS_LOG_FUNCTION (this);

	return this->m_direction;
}

Ptr<IpSecSAEntry>
IpSecSADatabase::CreateIpSecSAEntry (uint32_t spi)
{
	Ptr<IpSecSAEntry> retval = 0;
	if (this->m_ptr_policy_entry == 0)
	{
		//this database is a sad-i or sad-o that bound to an entry. And it's just a logical database which is a part of the real database;
		retval = Create<IpSecSAEntry>();
		retval->SetSAD(this);
		retval->SetSpi(spi);
	}
	else
	{
		retval = this->m_ptr_policy_entry->GetSPD()->GetRootDatabase()->GetSAD()->CreateIpSecSAEntry(spi);
		retval->AssociatePolicy(this->m_ptr_policy_entry);

		if (this->m_direction == IpSecSADatabase::INBOUND)
		{
			retval->SetInbound();
		}
		else if (this->m_direction == IpSecSADatabase::OUTBOUND)
		{
			retval->SetOutbound();
		}
		else
		{
			//do nothing
		}
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
	 m_process_choise (IPsec::BYPASS),
	 m_ptr_spd (0),
	 m_ptr_outbound_sad (0)
{
	NS_LOG_FUNCTION (this);
}

IpSecPolicyEntry::~IpSecPolicyEntry()
{
	NS_LOG_FUNCTION (this);

	this->m_ptr_spd = 0;
	this->m_ptr_outbound_sad = 0;
	this->m_ptr_inbound_sad = 0;
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
IpSecPolicyEntry::SetProcessChoice (IPsec::PROCESS_CHOICE process_choice)
{
	NS_LOG_FUNCTION (this);
	this->m_process_choise = process_choice;
}

IPsec::PROCESS_CHOICE
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

void
IpSecPolicyEntry::SetTrafficSelectors (const IkeTrafficSelector& ts_src, const IkeTrafficSelector& ts_dest)
{
	NS_LOG_FUNCTION (this);

	if (ts_src.GetProtocolId() != ts_dest.GetProtocolId())
	{
		NS_ASSERT (false);
	}

	if (ts_src.GetTsType() != IkeTrafficSelector::TS_IPV4_ADDR_RANGE)
	{
		NS_ASSERT (false);
	}

	if (ts_dest.GetTsType() != IkeTrafficSelector::TS_IPV4_ADDR_RANGE)
	{
		NS_ASSERT (false);
	}

	this->SetSrcAddressRange(ts_src.GetStartingAddress(), ts_src.GetEndingAddress());
	this->SetTranSrcPortRange(ts_src.GetStartPort(), ts_src.GetEndPort());
	this->SetDestAddressRange(ts_dest.GetStartingAddress(), ts_dest.GetEndingAddress());
	this->SetTranDestPortRange(ts_dest.GetStartPort(), ts_dest.GetEndPort());
	this->SetProtocolNum(ts_src.GetProtocolId());
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
		this->m_ptr_outbound_sad->SetDirection(IpSecSADatabase::OUTBOUND);
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
		this->m_ptr_inbound_sad->SetDirection(IpSecSADatabase::INBOUND);
		this->m_ptr_inbound_sad->AssociatePolicyEntry(this);
		this->m_ptr_inbound_sad->SetRootDatabase(this->GetSPD()->GetRootDatabase());
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

IkeTrafficSelector
IpSecPolicyEntry::GetTrafficSelectorSrc (void) const
{
	NS_LOG_FUNCTION (this);

	IkeTrafficSelector retval;
	retval.SetStartingAddress(this->m_src_starting_address);
	retval.SetEndingAddress(this->m_src_ending_address);
	retval.SetStartPort(this->m_src_transport_protocol_starting_num);
	retval.SetEndPort(this->m_src_transport_protocol_ending_num);
	retval.SetProtocolId(this->m_ip_protocol_num);
	retval.SetTsType(IkeTrafficSelector::TS_IPV4_ADDR_RANGE);

	return retval;
}

IkeTrafficSelector
IpSecPolicyEntry::GetTrafficSelectorDest (void) const
{
	NS_LOG_FUNCTION (this);

	IkeTrafficSelector retval;
	retval.SetStartingAddress(this->m_dest_starting_address);
	retval.SetEndingAddress(this->m_dest_ending_address);
	retval.SetStartPort(this->m_dest_transport_protocol_starting_num);
	retval.SetEndPort(this->m_dest_transport_protocol_ending_num);
	retval.SetProtocolId(this->m_ip_protocol_num);
	retval.SetTsType(IkeTrafficSelector::TS_IPV4_ADDR_RANGE);

	return retval;
}

void
IpSecPolicyEntry::GetInboundSpis (std::list<Ptr<Spi> >& retval) const
{
	NS_LOG_FUNCTION (this);

	Ptr<IpSecSADatabase> inbound_sad = this->m_ptr_inbound_sad;
	inbound_sad->GetSpis(retval);
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

void
IpSecPolicyDatabase::GetInboundSpis (std::list<Ptr<Spi> >& retval) const
{
	NS_LOG_FUNCTION (this);

	for (	std::list<Ptr<IpSecPolicyEntry> >::const_iterator const_it = this->m_lst_entries.begin();
			const_it != this->m_lst_entries.end();
			const_it++)
	{
		(*const_it)->GetInboundSpis(retval);
	}
}

Ptr<IpSecPolicyEntry>
IpSecPolicyDatabase::GetPolicy (const IkeTrafficSelector& ts_src, const IkeTrafficSelector& ts_dest)
{
	NS_LOG_FUNCTION (this);

	Ptr<IpSecPolicyEntry> retval = 0;

	for (std::list<Ptr<IpSecPolicyEntry> >::iterator it = this->m_lst_entries.begin();
			it != this->m_lst_entries.end();
			it++)
	{
		if (((*it)->GetTrafficSelectorSrc() == ts_src) &&
				((*it)->GetTrafficSelectorDest() == ts_dest))
		{
			retval = (*it);
		}
	}

	//retval is allowed to be zero
	return retval;
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
	this->m_lst_ptr_gsa_push_sessions.clear();
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
				 session_it->GetInitSaResponderSpi() == 0 &&
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
		if (true == session_it->HaveKekSa())
		{
			if (	(session_it->GetKekSaInitiatorSpi() == initiator_spi &&
					(session_it->GetKekSaResponderSpi() == responder_spi) &&
					 session_it->GetPeerAddress() == peer_address)
				)
			{
				session = session_it;
				break;
			}
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

std::list<Ptr<GsamSessionGroup> >&
IpSecDatabase::GetSessionGroups (void)
{
	NS_LOG_FUNCTION (this);

	return this->m_lst_ptr_session_groups;
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

const Ptr<Igmpv3L4Protocol>
IpSecDatabase::GetIgmp (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_gsam == 0)
	{
		NS_ASSERT (false);
	}

	return this->m_ptr_gsam->GetIgmp();
}

const Ptr<GsamL4Protocol>
IpSecDatabase::GetGsam (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_gsam;
}

bool
IpSecDatabase::IsHostQuerier (void) const
{
	NS_LOG_FUNCTION (this);

	bool retval = false;
	Ptr<Igmpv3L4Protocol> igmp = this->GetIgmp();

	if (igmp->GetRole() == Igmpv3L4Protocol::QUERIER)
	{
		retval = true;
	}

	return retval;
}

bool
IpSecDatabase::IsHostGroupMember (void) const
{
	NS_LOG_FUNCTION (this);

	bool retval = false;
	Ptr<Igmpv3L4Protocol> igmp = this->GetIgmp();

	if (igmp->GetRole() == Igmpv3L4Protocol::GROUP_MEMBER)
	{
		retval = true;
	}

	return retval;
}

bool
IpSecDatabase::IsHostNonQuerier (void) const
{
	NS_LOG_FUNCTION (this);

	bool retval = false;
	Ptr<Igmpv3L4Protocol> igmp = this->GetIgmp();

	if (igmp->GetRole() == Igmpv3L4Protocol::NONQUERIER)
	{
		retval = true;
	}

	return retval;
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

Ptr<GsaPushSession>
IpSecDatabase::CreateGsaPushSession (void)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsaPushSession> retval = GsaPushSession::CreatePushSession(this->m_ptr_info->RegisterGsaPushId());
	retval->SetDatabase(this);
	return retval;
}

Ptr<GsamSessionGroup>
IpSecDatabase::CreateSessionGroup (Ipv4Address group_address)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSessionGroup> session_group = Create<GsamSessionGroup>();
	session_group->SetGroupAddress(group_address);
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

void
IpSecDatabase::RemoveGsaPushSession (Ptr<GsaPushSession> gsa_push_session)
{
	NS_LOG_FUNCTION (this);

	this->m_lst_ptr_gsa_push_sessions.remove(gsa_push_session);
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


