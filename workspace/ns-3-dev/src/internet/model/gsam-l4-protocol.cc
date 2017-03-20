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
#include "ns3/udp-l4-protocol-multicast.h"
#include "ns3/nstime.h"

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
	m_ptr_database (0),
	m_ptr_gsam_filter (0)
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
			Ptr<Igmpv3L4Protocol> igmp = this->GetObject<Igmpv3L4Protocol> ();
			if ((ipv4 != 0) && (igmp != 0))
			{
				this->SetNode (node);
				igmp->SetGsam(this);
				Initialization();
			}
			else
			{
				NS_ASSERT (false);
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
	if (this->m_ptr_database == 0)
	{
		this->m_ptr_database = Create<IpSecDatabase>();
		this->m_ptr_database->SetGsam(this);
	}

	if (this->m_socket == 0)
	{
		TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
		this->m_socket = Socket::CreateSocket(this->m_node, tid);
	}

	if (this->m_ptr_gsam_filter == 0)
	{
		this->m_ptr_gsam_filter = Create<GsamFilter>();
		this->m_ptr_gsam_filter->SetGsam(this);
		Ptr<Ipv4Multicast> ipv4 = this->GetObject<Ipv4Multicast> ();
		if(0 == ipv4)
		{
			NS_ASSERT (false);
		}
		this->m_ptr_gsam_filter->SetDownTarget(MakeCallback (&Ipv4Multicast::Send, ipv4));

	}

	InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), GsamL4Protocol::PROT_NUMBER);
	this->m_socket->Bind(local);
	this->m_socket->SetRecvCallback (MakeCallback (&GsamL4Protocol::HandleRead, this));
	this->m_socket->SetAllowBroadcast (true);

	//Create by pass policy
	Ptr<IpSecPolicyEntry> gsam_bypass_policy = this->m_ptr_database->GetPolicyDatabase()->CreatePolicyEntry();
	gsam_bypass_policy->SetSrcAddressRange(Ipv4Address::GetAny(), Ipv4Address::GetBroadcast());
	gsam_bypass_policy->SetProcessChoice(IpSec::BYPASS);
	gsam_bypass_policy->SetProtocolNum(UdpL4ProtocolMulticast::PROT_NUMBER);
	gsam_bypass_policy->SetTranSrcPortRange(GsamL4Protocol::PROT_NUMBER, GsamL4Protocol::PROT_NUMBER);
	gsam_bypass_policy->SetTranDestPortRange(GsamL4Protocol::PROT_NUMBER, GsamL4Protocol::PROT_NUMBER);
}

void
GsamL4Protocol::HandleRead (Ptr<Socket> socket)
{
	NS_LOG_FUNCTION (this << socket);
	Ptr<Packet> packet;
	Address from;

	packet = socket->RecvFrom (from);

	GsamConfig::GetSingleton()->LogMsgReceived("gsam", this->m_node->GetId(), packet, InetSocketAddress::ConvertFrom (from).GetIpv4 ());

	IkeHeader ikeheader;
	packet->RemoveHeader(ikeheader);

	if (ikeheader.GetInstanceTypeId() != IkeHeader::GetTypeId())
	{
		NS_ASSERT (false);
	}

	Ipv4Address peer_address = InetSocketAddress::ConvertFrom (from).GetIpv4 ();

	IkeHeader::EXCHANGE_TYPE exchange_type = ikeheader.GetExchangeType();

	switch (exchange_type)
	{
	case IkeHeader::IKE_SA_INIT:
		this->HandleIkeSaInit(packet, ikeheader, peer_address);
		break;
	case IkeHeader::IKE_AUTH:
		this->HandleIkeSaAuth(packet, ikeheader, peer_address);
		break;
	case IkeHeader::CREATE_CHILD_SA:
		this->HandleCreateChildSa(packet, ikeheader, peer_address);
		break;
	case IkeHeader::INFORMATIONAL:
		this->HandleGsaInformational(packet, ikeheader, peer_address);
		break;
	default:
		break;
	}
}

void
GsamL4Protocol::Send_IKE_SA_INIT (Ptr<GsamInitSession> init_session)
{
	//rfc 5996 page 10
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), init_session);

	//setting up Ni
	IkePayload nonce_payload_init;
	nonce_payload_init.SetSubstructure(IkeNonceSubstructure::GenerateRandomNonceSubstructure());
	//setting up KEi
	IkePayload key_payload_init;
	key_payload_init.SetSubstructure(IkeKeyExchangeSubStructure::GetDummySubstructure());
	key_payload_init.SetNextPayloadType(nonce_payload_init.GetPayloadType());
	//setting up SAi1
	IkePayload sa_payload_init;
	sa_payload_init.SetSubstructure(IkeSaPayloadSubstructure::GenerateInitIkePayload());
	sa_payload_init.SetNextPayloadType(key_payload_init.GetPayloadType());
	//setting up HDR
	IkeHeader ikeheader;
	uint64_t initiator_spi = this->GetIpSecDatabase()->GetInfo()->RegisterGsamSpi();
	ikeheader.SetInitiatorSpi(initiator_spi);
	ikeheader.SetResponderSpi(0);
	ikeheader.SetIkev2Version();
	ikeheader.SetExchangeType(IkeHeader::IKE_SA_INIT);
	ikeheader.SetAsInitiator();
	//pause setting up HDR, start setting up a new session
	init_session->SetSessionRole(GsamInitSession::INITIATOR);
	init_session->EtablishGsamInitSa();
	init_session->SetInitSaInitiatorSpi(initiator_spi);
	//continue setting HDR
	ikeheader.SetMessageId(init_session->GetCurrentMessageId());
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

	init_session->SetCachePacket(packet);
	init_session->SetNumberRetransmission(GsamConfig::GetSingleton()->GetNumberOfRetransmission());
	this->DoSendInitMessage(init_session, true);
}

void
GsamL4Protocol::Send_IKE_SA_AUTH (Ptr<GsamInitSession> init_session, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);

	if (1 < init_session->GetCurrentMessageId())
	{
		NS_ASSERT (false);
	}
	else
	{
		init_session->SetMessageId(1);
	}

	//Setting up TSr
	IkePayload tsr;

	if (init_session->IsHostNonQuerier())
	{
		tsr.SetSubstructure(IkeTrafficSelectorSubstructure::GenerateEmptySubstructure(true));
	}
	else
	{
		tsr.SetSubstructure(IkeTrafficSelectorSubstructure::GetSecureGroupSubstructure(session->GetGroupAddress(), true));
	}
	//settuping up tsi
	IkePayload tsi;
	if (init_session->IsHostNonQuerier())
	{
		tsi.SetSubstructure(IkeTrafficSelectorSubstructure::GenerateEmptySubstructure(false));
	}
	else
	{
		tsi.SetSubstructure(IkeTrafficSelectorSubstructure::GetSecureGroupSubstructure(Ipv4Address("0.0.0.0"), false));
	}
	tsi.SetNextPayloadType(tsr.GetPayloadType());
	//setting up sai2
	IkePayload sai2;
	Ptr<Spi> initiator_kek_sa_spi = Create<Spi>();
	initiator_kek_sa_spi->SetValueFromUint64(session->GetInfo()->RegisterGsamSpi());
	sai2.SetSubstructure(IkeSaPayloadSubstructure::GenerateAuthIkePayload(initiator_kek_sa_spi));
	sai2.SetNextPayloadType(tsi.GetPayloadType());
	//setting up auth
	IkePayload auth;
	auth.SetSubstructure(IkeAuthSubstructure::GenerateEmptyAuthSubstructure());
	auth.SetNextPayloadType(sai2.GetPayloadType());
	//setting up id
	IkePayload id;
	id.SetSubstructure(IkeIdSubstructure::GenerateIpv4Substructure(session->GetGroupAddress(), false));
	id.SetNextPayloadType(auth.GetPayloadType());

	//pause setting up HDR, start setting up a kek sa
	session->EtablishGsamKekSa();
	session->SetKekSaInitiatorSpi(initiator_kek_sa_spi->ToUint64());

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(tsr);
	packet->AddHeader(tsi);
	packet->AddHeader(sai2);
	packet->AddHeader(auth);
	packet->AddHeader(id);

	uint32_t length_beside_hedaer = id.GetSerializedSize() +
									auth.GetSerializedSize() +
									sai2.GetSerializedSize() +
									tsi.GetSerializedSize() +
									tsr.GetSerializedSize();

	this->SendPhaseOneMessage(	init_session,
						IkeHeader::IKE_AUTH,
						false,
						id.GetPayloadType(),
						length_beside_hedaer,
						packet,
						true);
}

void
GsamL4Protocol::Send_GSA_PUSH (Ptr<GsamSession> session)
{
	//only Q will invoke this function

	NS_LOG_FUNCTION (this);

	if (1 < session->GetCurrentMessageId())
	{
		NS_ASSERT (false);
	}
	else
	{
		//do nothing
	}

	if (false == session->IsHostQuerier())
	{
		NS_ASSERT(false);
	}

	if (session->GetGroupAddress() == GsamConfig::GetIgmpv3DestGrpReportAddress())
	{
		//There is a NQ on the other side of the session
		this->Send_GSA_PUSH_NQ(session);
	}
	else
	{
		//There is a GM on the other side of the session
		this->Send_GSA_PUSH_GM(session);
	}
}

void
GsamL4Protocol::Send_GSA_PUSH_GM (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsaPushSession> gsa_push_session = session->CreateAndSetGsaPushSession();
	gsa_push_session->SetStatus(GsaPushSession::GSA_PUSH_ACK);

	//setting up gsa_q
	Ptr<Spi> suggested_gsa_q_spi = Create<Spi>();
	Ptr<IpSecSAEntry> gsa_q = session->GetRelatedGsaQ();
	if (gsa_q == 0)
	{
		suggested_gsa_q_spi->SetValueFromUint32(session->GetInfo()->GetLocalAvailableIpsecSpi());
		gsa_q = gsa_push_session->CreateGsaQ(suggested_gsa_q_spi->ToUint32());
	}
	else
	{
		suggested_gsa_q_spi->SetValueFromUint32(gsa_q->GetSpi());
	}

	//setting up gsa_r
	Ptr<Spi> suggested_gsa_r_spi = Create<Spi>();	//needed to be unique in Qs and NQs
	Ptr<IpSecSAEntry> gsa_r = session->GetRelatedGsaR();
	if (gsa_r == 0)
	{
		suggested_gsa_r_spi->SetValueFromUint32(session->GetInfo()->GetLocalAvailableIpsecSpi());
		gsa_r = gsa_push_session->CreateGsaR(suggested_gsa_r_spi->ToUint32());
	}
	else
	{
		//it already has a gsa_r, why?
		//weird, it should not the case of retransmission when code run reach here
		NS_ASSERT (false);
		suggested_gsa_r_spi->SetValueFromUint32(gsa_r->GetSpi());
	}

	//setting up remote spi notification proposal payload
	Ptr<IpSecPolicyEntry> policy = session->GetRelatedPolicy();
	Ptr<IkeGsaPayloadSubstructure> gsa_payload_substructure = IkeGsaPayloadSubstructure::GenerateEmptyGsaPayload(	gsa_push_session->GetId(),
																													policy->GetTrafficSelectorSrc(),
																													policy->GetTrafficSelectorDest());
	gsa_payload_substructure->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(suggested_gsa_q_spi, IkeGsaProposal::NEW_GSA_Q));
	gsa_payload_substructure->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(suggested_gsa_r_spi, IkeGsaProposal::NEW_GSA_R));
	IkePayload gsa_push_proposal_payload;
	gsa_push_proposal_payload.SetSubstructure(gsa_payload_substructure);

	uint32_t length_beside_ikeheader = gsa_push_proposal_payload.GetSerializedSize();

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(gsa_push_proposal_payload);

//	std::cout << "GsamL4Protocol::Send_GSA_PUSH_GM, Node: " << this->m_node->GetId() << ", GsamSession: " << session;
//	std::cout << " GsaPush Id: " << gsa_push_session->GetId() << std::endl;
//	std::cout << " Gsa Q: " << suggested_gsa_q_spi->ToUint32();
//	std::cout << " Gsa R: " << suggested_gsa_r_spi->ToUint32();
	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session, gsa_push_session->GetId(), suggested_gsa_q_spi->ToUint32(), suggested_gsa_r_spi->ToUint32());

	this->SendPhaseTwoMessage(	session,
						IkeHeader::INFORMATIONAL,
						false,
						gsa_push_proposal_payload.GetPayloadType(),
						length_beside_ikeheader,
						packet,
						true);

	this->DeliverToNQs(gsa_push_session, gsa_push_proposal_payload);
}

void
GsamL4Protocol::Send_GSA_RE_PUSH (Ptr<GsaPushSession> gsa_push_session)
{
	NS_LOG_FUNCTION (this);
	if (gsa_push_session == 0)
	{
		NS_ASSERT (false);
	}

	Ptr<GsamSession> gm_session = gsa_push_session->GetGmSession();

	uint32_t old_gsa_q_spi = gsa_push_session->GetOldGsaQSpi();

	Ptr<IpSecSAEntry> installed_gsa_q = gm_session->GetRelatedGsaQ();
	if (installed_gsa_q == 0)
	{
		//the revise gsa pair should have already been installed
		NS_ASSERT (false);
	}
	uint32_t old_gsa_r_spi = gsa_push_session->GetOldGsaRSpi();

	Ptr<IpSecSAEntry> installed_gsa_r = gm_session->GetRelatedGsaR();
	if (installed_gsa_r == 0)
	{
		//the revise gsa pair should have already been installed
		NS_ASSERT (false);
	}
//**********************************************
	//send to the gm and nqs
	Ptr<IkeGsaPayloadSubstructure> re_push_gm_nqs_payload_sub = IkeGsaPayloadSubstructure::GenerateEmptyGsaPayload(gsa_push_session->GetId(),
																											gm_session->GetGroupAddress(),
																											true);
	uint32_t gsa_q_spi_to_be_modified = old_gsa_q_spi;
	uint32_t gsa_r_spi_to_be_modified = old_gsa_r_spi;
	if (0 == old_gsa_r_spi)
	{
		if (0 == old_gsa_q_spi)
		{
			//nothing to repush, when reached here?
			NS_ASSERT (false);
		}
		else
		{
			//ok only gsa q rejected, no gsa r rejection
		}
		gsa_r_spi_to_be_modified = installed_gsa_r->GetSpi();
	}
	else
	{
		if (0 == old_gsa_q_spi)
		{
			//ok only gsa r rejected, no gsa q rejection
			gsa_q_spi_to_be_modified = installed_gsa_q->GetSpi();
		}
		else
		{
			//both got rejected, ok
		}
	}

	re_push_gm_nqs_payload_sub->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(	Create<Spi>(gsa_q_spi_to_be_modified),
																				IkeGsaProposal::GSA_Q_TO_BE_MODIFIED));
	re_push_gm_nqs_payload_sub->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(	Create<Spi>(installed_gsa_q->GetSpi()),
																				IkeGsaProposal::GSA_Q_REPLACEMENT));
	re_push_gm_nqs_payload_sub->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(	Create<Spi>(gsa_r_spi_to_be_modified),
																			IkeGsaProposal::GSA_R_TO_BE_MODIFIED));
	re_push_gm_nqs_payload_sub->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(	Create<Spi>(installed_gsa_r->GetSpi()),
																			IkeGsaProposal::GSA_R_REPLACEMENT));

	IkePayload re_push_gm_nqs_payload;
	re_push_gm_nqs_payload.SetSubstructure(re_push_gm_nqs_payload_sub);
	uint32_t length_beside_ikeheader_gm_nqs = re_push_gm_nqs_payload.GetSerializedSize();
	Ptr<Packet> packet_gm_nqs = Create<Packet>();
	packet_gm_nqs->AddHeader(re_push_gm_nqs_payload);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), gsa_push_session->GetId());

	this->SendPhaseTwoMessage(	gm_session,
			IkeHeader::CREATE_CHILD_SA,
			false,
			re_push_gm_nqs_payload.GetPayloadType(),
			length_beside_ikeheader_gm_nqs,
			packet_gm_nqs,
			true);
	//sending packet copies to nq sessions
	for (	std::set<Ptr<GsamSession> >::const_iterator const_it = gsa_push_session->GetNqSessions().begin();
			const_it != gsa_push_session->GetNqSessions().end();
			const_it++)
	{
		Ptr<GsamSession> nq_session = *const_it;
		this->SendPhaseTwoMessage(	nq_session,
					IkeHeader::CREATE_CHILD_SA,
					false,
					re_push_gm_nqs_payload.GetPayloadType(),
					length_beside_ikeheader_gm_nqs,
					packet_gm_nqs,
					true);

	}
//*********************************************************
	//send to other gms
	if (0 == old_gsa_q_spi)
	{
		//not gsa q rejection
	}
	else
	{
		//ok only gsa q rejected
		Ptr<IkeGsaPayloadSubstructure> re_push_other_gms_payload_sub = IkeGsaPayloadSubstructure::GenerateEmptyGsaPayload(gsa_push_session->GetId(),
																												gm_session->GetGroupAddress(),
																												true);
		re_push_other_gms_payload_sub->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(Create<Spi>(old_gsa_q_spi),
																							IkeGsaProposal::GSA_Q_TO_BE_MODIFIED));
		re_push_other_gms_payload_sub->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(Create<Spi>(installed_gsa_q->GetSpi()),
																							IkeGsaProposal::GSA_Q_REPLACEMENT));

		IkePayload re_push_other_gms_payload;
		re_push_other_gms_payload.SetSubstructure(re_push_other_gms_payload_sub);

		uint32_t length_beside_ikeheader_other_gms = re_push_other_gms_payload.GetSerializedSize();

		Ptr<Packet> packet_other_gms = Create<Packet>();
		packet_other_gms->AddHeader(re_push_other_gms_payload);

		for (	std::set<Ptr<GsamSession> >::const_iterator const_it = gsa_push_session->GetOtherGmSessions().begin();
				const_it != gsa_push_session->GetOtherGmSessions().end();
				const_it++)
		{
			Ptr<GsamSession> other_gm_session = *const_it;
			this->SendPhaseTwoMessage(	other_gm_session,
										IkeHeader::CREATE_CHILD_SA,
										false,
										re_push_other_gms_payload.GetPayloadType(),
										length_beside_ikeheader_other_gms,
										packet_other_gms,
										true);

		}
	}

	gsa_push_session->SelfRemoval();
	Ptr<Igmpv3L4Protocol> igmp = Igmpv3L4Protocol::GetIgmp(this->m_node);
	if (0 == igmp)
	{
		NS_ASSERT (false);
	}
	if (0 != gsa_push_session->GetGmSession())
	{
		Ipv4Address group_address = gsa_push_session->GetGmSession()->GetGroupAddress();
		igmp->SendSecureGroupSpecificQuery(group_address);
	}
}

void
GsamL4Protocol::Send_GSA_PUSH_NQ (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);

	Ptr<IpSecDatabase> ipsec_root_db = session->GetDatabase();
	const std::list<Ptr<GsamSessionGroup> >& lst_session_groups = ipsec_root_db->GetSessionGroups();

	uint32_t length_beside_ikheader = 0;
	Ptr<Packet> packet = Create<Packet>();

	IkePayloadHeader::PAYLOAD_TYPE next_payload_type = IkePayloadHeader::NO_NEXT_PAYLOAD;

	for (	std::list<Ptr<GsamSessionGroup> >::const_iterator const_it = lst_session_groups.begin();
			const_it != lst_session_groups.end();
			const_it++)
	{
		Ptr<GsamSessionGroup> session_group = (*const_it);
		if (session_group->GetGroupAddress() != GsamConfig::GetIgmpv3DestGrpReportAddress())
		{
			Ipv4Address group_address = session_group->GetGroupAddress();
			if (group_address.Get() == 0)
			{
				NS_ASSERT (false);
			}

			//non nq session group
			Ptr<IpSecPolicyEntry> policy = session_group->GetRelatedPolicy();
			Ptr<IpSecSAEntry> gsa_q = session_group->GetRelatedGsaQ();

			if (gsa_q == 0)
			{
				//do nothing
				//nothing to push


//				//no gsa_q but there is an established session group
//				if (0 != session_group->GetSessionsConst().size())
//				{
//					//has no established gsa_q but has established gsa_r?
//					NS_ASSERT (false);
//				}
//				else
//				{
//					//ok
//					//maybe there the q is waiting for reply of GSA_PUSH from the first member joining that group
//				}
			}
			else
			{
				Ptr<IkeGsaPayloadSubstructure> session_group_sa_payload_substructure = IkeGsaPayloadSubstructure::GenerateEmptyGsaPayload(0, group_address);
				GsamConfig::LogGsaQ(__FUNCTION__, gsa_q->GetSpi());
				session_group_sa_payload_substructure->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(Create<Spi>(gsa_q->GetSpi()), IkeGsaProposal::NEW_GSA_Q));

				const std::list<Ptr<GsamSession> > lst_sessions = session_group->GetSessionsConst();

				for (	std::list<Ptr<GsamSession> >::const_iterator const_it = lst_sessions.begin();
						const_it != lst_sessions.end();
						const_it++)
				{
					const Ptr<GsamSession> gm_session = (*const_it);
					Ptr<IpSecSAEntry> gsa_r = gm_session->GetRelatedGsaR();
					if (gsa_r == 0)
					{
						//no gsa_r but there is an established session group
						//maybe there the q is waiting for reply of GSA_PUSH from the gm joining that group
					}
					else
					{
						GsamConfig::LogGsaR(__FUNCTION__, gsa_r->GetSpi());
						session_group_sa_payload_substructure->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(Create<Spi>(gsa_r->GetSpi()), IkeGsaProposal::NEW_GSA_R));
					}
				}

				IkePayload session_group_sa_payload;
				session_group_sa_payload.SetSubstructure(session_group_sa_payload_substructure);
				session_group_sa_payload.SetNextPayloadType(next_payload_type);

				packet->AddHeader(session_group_sa_payload);
				length_beside_ikheader += session_group_sa_payload.GetSerializedSize();

				next_payload_type = session_group_sa_payload.GetPayloadType();
			}
		}
	}

	if (next_payload_type == IkePayloadHeader::NO_NEXT_PAYLOAD)
	{
		//still put an empty group notify pyaload?
		Ptr<IkeGsaPayloadSubstructure> session_group_sa_payload_substructure = Create<IkeGsaPayloadSubstructure>();
		IkePayload session_group_sa_payload;
		session_group_sa_payload.SetSubstructure(session_group_sa_payload_substructure);
		session_group_sa_payload.SetNextPayloadType(next_payload_type);

		packet->AddHeader(session_group_sa_payload);
		length_beside_ikheader += session_group_sa_payload.GetSerializedSize();

		next_payload_type = session_group_sa_payload.GetPayloadType();
	}

	//now we have a SA payload with  spis from all GMs' sessions
	this->SendPhaseTwoMessage(session,
			IkeHeader::INFORMATIONAL,
			false,
			next_payload_type,
			length_beside_ikheader,
			packet,
			true);
}

void
GsamL4Protocol::Send_SPI_REQUEST (Ptr<GsaPushSession> gsa_push_session, GsaPushSession::SPI_REQUEST_TYPE spi_request_type)
{
	NS_LOG_FUNCTION (this);

//	Ptr<GsaPushSession> gsa_push_session = 0;
//	if (session->GetGroupAddress() == GsamConfig::GetIgmpv3DestGrpReportAddress())
//	{
//		//nq session
//		//case 1: solo newly join session and gsa_push_id == 0, the nq session will create and attach to a new gsa push session on its own
//		//cast 2: multiple nq sessions accompanying a gm session, gsa_push_id != 0.
//		//do nothing
//	}
//	else
//	{
//		//gm session
//		gsa_push_session = session->GetGsaPushSession();
//	}
	if (0 != gsa_push_session)
	{
		GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), gsa_push_session->GetId());

		IkePayload spi_request_payload;
		IkeTrafficSelector dummy_ts = IkeTrafficSelector::GetIpv4DummyTs();
		Ptr<IkeGroupNotifySubstructure> spi_request_sub = IkeGroupNotifySubstructure::GenerateEmptyGroupNotifySubstructure(GsamConfig::GetDefaultGSAProposalId(),
				IpSec::AH_ESP_SPI_SIZE,
				IkeGroupNotifySubstructure::SPI_REQUEST,
				gsa_push_session->GetId(),
				dummy_ts,
				dummy_ts);
		spi_request_payload.SetSubstructure(spi_request_sub);

		Ptr<Packet> packet = Create<Packet>();
		packet->AddHeader(spi_request_payload);

		if (gsa_push_session->GetStatus() == GsaPushSession::GSA_PUSH_ACK)
		{
			gsa_push_session->SwitchStatus();

			Ptr<GsamSession> gm_session = gsa_push_session->GetGmSession();

			if (spi_request_type == GsaPushSession::GSA_Q_SPI_REQUEST)
			{
				if (0 != gm_session)
				{
					Ptr<GsamSessionGroup> gm_session_group = gm_session->GetSessionGroup();
					if (0 == gm_session_group)
					{
						NS_ASSERT (false);
					}
					//gm session
					this->SendPhaseTwoMessage(gm_session,
											IkeHeader::INFORMATIONAL,
											false,
											spi_request_payload.GetPayloadType(),
											spi_request_payload.GetSerializedSize(),
											packet,
											true);
					//other gm session with the same group address
					for (	std::list<Ptr<GsamSession> >::iterator it_other_gm_session = gm_session_group->GetSessions().begin();
							it_other_gm_session != gm_session_group->GetSessions().end();
							it_other_gm_session++)
					{
						Ptr<GsamSession> other_gm_session = *it_other_gm_session;
						if (other_gm_session != gm_session)
						{
							gsa_push_session->PushBackOtherGmSession(*it_other_gm_session);
							(*it_other_gm_session)->InsertGsaPushSession(gsa_push_session);
							this->SendPhaseTwoMessage((*it_other_gm_session),
													IkeHeader::INFORMATIONAL,
													false,
													spi_request_payload.GetPayloadType(),
													spi_request_payload.GetSerializedSize(),
													packet,
													true);
						}
					}
					gsa_push_session->SetFlagGmsSpiRequested();
					this->DeliverToNQs(gsa_push_session, spi_request_payload);
					gsa_push_session->SetFlagNqsSpiRequested();
				}
				else
				{
					NS_ASSERT (false);
				}
			}
			else if (spi_request_type == GsaPushSession::GSA_R_SPI_REQUEST)
			{
				this->DeliverToNQs(gsa_push_session, spi_request_payload);
				gsa_push_session->SetFlagNqsSpiRequested();
			}
			else
			{
				NS_ASSERT (false);
			}
		}
		else if (gsa_push_session->GetStatus() == GsaPushSession::SPI_CONFLICT_RESOLVE)
		{
			//switch status may have been invoked by other sessions (nq or gm) which belongs to the same gsa_push_session
			if (spi_request_type == GsaPushSession::GSA_Q_SPI_REQUEST)
			{
				if (false == gsa_push_session->IsGmsSpiRequested())
				{
					Ptr<GsamSession> gm_session = gsa_push_session->GetGmSession();
					if (0 != gm_session)
					{
						Ptr<GsamSessionGroup> gm_session_group = gm_session->GetSessionGroup();
						if (0 == gm_session_group)
						{
							NS_ASSERT (false);
						}
						//gm session
						this->SendPhaseTwoMessage(gm_session,
								IkeHeader::INFORMATIONAL,
								false,
								spi_request_payload.GetPayloadType(),
								spi_request_payload.GetSerializedSize(),
								packet,
								true);
						//other gm session with the same group address
						for (	std::list<Ptr<GsamSession> >::iterator it_other_gm_session = gm_session_group->GetSessions().begin();
								it_other_gm_session != gm_session_group->GetSessions().end();
								it_other_gm_session++)
						{
							Ptr<GsamSession> other_gm_session = *it_other_gm_session;
							if (other_gm_session != gm_session)
							{
								gsa_push_session->PushBackOtherGmSession(*it_other_gm_session);
								(*it_other_gm_session)->InsertGsaPushSession(gsa_push_session);
								this->SendPhaseTwoMessage((*it_other_gm_session),
														IkeHeader::INFORMATIONAL,
														false,
														spi_request_payload.GetPayloadType(),
														spi_request_payload.GetSerializedSize(),
														packet,
														true);
							}
						}
						gsa_push_session->SetFlagGmsSpiRequested();
					}
					else
					{
						NS_ASSERT (false);
					}
				}
				else
				{
					//ignore
				}

				if (false == gsa_push_session->IsNqsSpiRequested())
				{
					this->DeliverToNQs(gsa_push_session, spi_request_payload);
					gsa_push_session->SetFlagNqsSpiRequested();
				}
				else
				{
					//ignore
				}
			}
			else if (spi_request_type == GsaPushSession::GSA_R_SPI_REQUEST)
			{
				if (false == gsa_push_session->IsNqsSpiRequested())
				{
					this->DeliverToNQs(gsa_push_session, spi_request_payload);
					gsa_push_session->SetFlagNqsSpiRequested();
				}
				else
				{
					//ignore
				}
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
	else
	{
		NS_ASSERT (false);
	}
}

void
GsamL4Protocol::DeliverToNQs (	Ptr<GsaPushSession> gsa_push_session,
								const IkePayload& payload_without_header,
								IkeHeader::EXCHANGE_TYPE exchange_type)
{
	NS_LOG_FUNCTION (this);

//	if (gsa_push_session == 0)
//	{
//		//method is invoked by a nq session
//		gsa_push_session = this->m_ptr_database->CreateGsaPushSession();
//	}
//	else
//	{
//		//method is invoked by a gm session
//		//do nothing
//	}

	if (gsa_push_session == 0)
	{
		NS_ASSERT (false);
		//why changed?
		//see GsamL4Protocol::HandleGsaRejectionFromNQ
	}

	Ptr<GsamSessionGroup> session_group_nq = this->GetIpSecDatabase()->GetSessionGroup(GsamConfig::GetIgmpv3DestGrpReportAddress());

	std::list<Ptr<GsamSession> >& lst_sessions_nq = session_group_nq->GetSessions();

	for (	std::list<Ptr<GsamSession> >::const_iterator const_it = lst_sessions_nq.begin();
			const_it != lst_sessions_nq.end();
			const_it++)
	{
		Ptr<GsamSession> nq_session = (*const_it);
		gsa_push_session->PushBackNqSession(nq_session);
		nq_session->InsertGsaPushSession(gsa_push_session);

		uint32_t length_beside_ikeheader = payload_without_header.GetSerializedSize();

		Ptr<Packet> packet = Create<Packet>();
		packet->AddHeader(payload_without_header);

		this->SendPhaseTwoMessage(		nq_session,
								exchange_type,
								false,
								payload_without_header.GetPayloadType(),
								length_beside_ikeheader,
								packet,
								true);
	}
}

void
GsamL4Protocol::DeliverToNQs (	Ptr<GsaPushSession> gsa_push_session,
					Ptr<Packet> packet_without_ikeheader,
					IkePayloadHeader::PAYLOAD_TYPE first_payload_type,
					IkeHeader::EXCHANGE_TYPE exchange_type)
{
	NS_LOG_FUNCTION (this);

	if (gsa_push_session == 0)
	{
		NS_ASSERT (false);
	}

	Ptr<GsamSessionGroup> session_group_nq = this->GetIpSecDatabase()->GetSessionGroup(GsamConfig::GetIgmpv3DestGrpReportAddress());

	std::list<Ptr<GsamSession> > lst_sessions_nq = session_group_nq->GetSessions();

	for (	std::list<Ptr<GsamSession> >::iterator it = lst_sessions_nq.begin();
			it != lst_sessions_nq.end();
			it++)
	{
		Ptr<GsamSession> nq_session = (*it);

		if (0 == nq_session->GetGsaPushSession(gsa_push_session->GetId()))
		{
			NS_ASSERT (false);
			gsa_push_session->PushBackNqSession(nq_session);
			nq_session->InsertGsaPushSession(gsa_push_session);
		}
		else
		{
			//do nothing
		}

		uint32_t length_beside_ikeheader = packet_without_ikeheader->GetSize();

		this->SendPhaseTwoMessage(nq_session,
								exchange_type,
								false,
								first_payload_type,
								length_beside_ikeheader,
								packet_without_ikeheader,
								true);
	}
}

void
GsamL4Protocol::SendPhaseOneMessage (	Ptr<GsamSession> session,
								IkeHeader::EXCHANGE_TYPE exchange_type,
								bool is_responder,
								IkePayloadHeader::PAYLOAD_TYPE first_payload_type,
								uint32_t length_beside_ikeheader,
								Ptr<Packet> packet,
								bool retransmit)
{
	NS_LOG_FUNCTION (this);

	Ptr<Packet> cache_packet = packet->Copy();

	//setting up HDR
	IkeHeader ikeheader;
	ikeheader.SetInitiatorSpi(session->GetInitSaInitiatorSpi());
	ikeheader.SetResponderSpi(session->GetInitSaResponderSpi());
	ikeheader.SetIkev2Version();
	ikeheader.SetExchangeType(exchange_type);
	if (true == is_responder)
	{
		ikeheader.SetAsResponder();
	}
	else
	{
		ikeheader.SetAsInitiator();
	}
	ikeheader.SetMessageId(session->GetCurrentMessageId());
	ikeheader.SetNextPayloadType(first_payload_type);
	ikeheader.SetLength(ikeheader.GetSerializedSize() + length_beside_ikeheader);

	cache_packet->AddHeader(ikeheader);

	bool actual_retransmit = false;

	if (false == is_responder)
	{
		actual_retransmit = retransmit;
	}

	session->SetCachePacket(cache_packet);

	session->SetNumberRetransmission(GsamConfig::GetSingleton()->GetNumberOfRetransmission());
	this->DoSendMessage(session, actual_retransmit);
}

void
GsamL4Protocol::SendPhaseOneMessage (	Ptr<GsamInitSession> session,
								IkeHeader::EXCHANGE_TYPE exchange_type,
								bool is_responder,
								IkePayloadHeader::PAYLOAD_TYPE first_payload_type,
								uint32_t length_beside_ikeheader,
								Ptr<Packet> packet,
								bool retransmit)
{
	NS_LOG_FUNCTION (this);

	Ptr<Packet> cache_packet = packet->Copy();

	//setting up HDR
	IkeHeader ikeheader;
	ikeheader.SetInitiatorSpi(session->GetInitSaInitiatorSpi());
	ikeheader.SetResponderSpi(session->GetInitSaResponderSpi());
	ikeheader.SetIkev2Version();
	ikeheader.SetExchangeType(exchange_type);
	if (true == is_responder)
	{
		ikeheader.SetAsResponder();
	}
	else
	{
		ikeheader.SetAsInitiator();
	}
	ikeheader.SetMessageId(session->GetExchangeMessageId(exchange_type));
	ikeheader.SetNextPayloadType(first_payload_type);
	ikeheader.SetLength(ikeheader.GetSerializedSize() + length_beside_ikeheader);

	cache_packet->AddHeader(ikeheader);

	bool actual_retransmit = false;

	if (false == is_responder)
	{
		actual_retransmit = retransmit;
	}

	session->SetCachePacket(cache_packet);

	session->SetNumberRetransmission(GsamConfig::GetSingleton()->GetNumberOfRetransmission());
	this->DoSendInitMessage(session, actual_retransmit);
}

void
GsamL4Protocol::SendPhaseTwoMessage (	Ptr<GsamSession> session,
								IkeHeader::EXCHANGE_TYPE exchange_type,
								bool is_responder,
								IkePayloadHeader::PAYLOAD_TYPE first_payload_type,
								uint32_t length_beside_ikeheader,
								Ptr<Packet> packet,
								bool retransmit)
{
	NS_LOG_FUNCTION (this);

	//setting up HDR
	IkeHeader ikeheader;
	if (true == is_responder)
	{
		ikeheader.SetAsResponder();
	}
	else
	{
		ikeheader.SetAsInitiator();
		session->IncrementMessageId();
	}

	Ptr<Packet> cache_packet = packet->Copy();

	ikeheader.SetInitiatorSpi(session->GetKekSaInitiatorSpi());
	ikeheader.SetResponderSpi(session->GetKekSaResponderSpi());
	ikeheader.SetIkev2Version();
	ikeheader.SetExchangeType(exchange_type);
	ikeheader.SetMessageId(session->GetCurrentMessageId());
	ikeheader.SetNextPayloadType(first_payload_type);
	ikeheader.SetLength(ikeheader.GetSerializedSize() + length_beside_ikeheader);

	cache_packet->AddHeader(ikeheader);

	bool actual_retransmit = false;

	if (false == is_responder)
	{
		actual_retransmit = retransmit;
	}

	session->SetCachePacket(cache_packet);
	session->SetNumberRetransmission(GsamConfig::GetSingleton()->GetNumberOfRetransmission());
	this->DoSendMessage(session, actual_retransmit);
}

void
GsamL4Protocol::DoSendMessage (Ptr<GsamSession> session, bool retransmit)
{
	NS_LOG_FUNCTION (this);

	bool session_retransmit = session->IsRetransmit();

	//bool retransmit is for identifying initiator or responder
	if (session->GetRemainingRetransmissionCount() < GsamConfig::GetSingleton()->GetNumberOfRetransmission())
	{
		std::cout << "Retransmitting." << std::endl;
	}

	Ptr<Packet> packet = session->GetCachePacket();

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session, (session_retransmit && retransmit), packet);

	m_socket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(session->GetPeerAddress()), GsamL4Protocol::PROT_NUMBER));

	GsamConfig::GetSingleton()->LogMsgSent("gsam", this->m_node->GetId(), packet, session->GetPeerAddress());

	m_socket->Send(packet);

	//Cancel retransmission
	session->GetRetransmitTimer().Cancel();

	if (true == session_retransmit)
	{
		if (true == retransmit)
		{
			//*******************legacy codes, not understand why, saved for archived**********************
			//		if (true == session->GetRetransmitTimer().IsRunning())
			//		{
			//			//something may went wrong.
			//			NS_ASSERT (false);
			//		}
			//		else
			//		{
			//			session->GetRetransmitTimer().Cancel();
			//		}
			//*******************legacy codes, not understand why, saved for archived**********************

			//schedule retransmission
			session->GetRetransmitTimer().SetFunction(&GsamL4Protocol::DoSendMessage, this);
			session->GetRetransmitTimer().SetArguments(session, session_retransmit);
			session->GetRetransmitTimer().Schedule(GsamConfig::GetSingleton()->GetDefaultRetransmitTimeoutInSeconds());
			//decrement retransmission count
			session->DecrementNumberRetransmission();
		}
		else
		{
			//do nothing
		}
	}
	//scheudle timeout
	session->SceduleTimeout(GsamConfig::GetSingleton()->GetDefaultSessionTimeoutSeconds());
}

void
GsamL4Protocol::DoSendInitMessage (Ptr<GsamInitSession> session, bool retransmit)
{
	NS_LOG_FUNCTION (this);

	bool session_retransmit = session->IsRetransmit();

	//bool retransmit is for identifying initiator or responder
	if (session->GetRemainingRetransmissionCount() < GsamConfig::GetSingleton()->GetNumberOfRetransmission())
	{
		std::cout << "Retransmitting." << std::endl;
	}

	Ptr<Packet> packet = session->GetCachePacket();

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session, (session_retransmit && retransmit), packet);

	m_socket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(session->GetPeerAddress()), GsamL4Protocol::PROT_NUMBER));

	GsamConfig::GetSingleton()->LogMsgSent("gsam", this->m_node->GetId(), packet, session->GetPeerAddress());

	m_socket->Send(packet);

	//Cancel retransmission
	session->GetRetransmitTimer().Cancel();

	if (true == session_retransmit)
	{
		if (true == retransmit)
		{
			//*******************legacy codes, not understand why, saved for archived**********************
			//		if (true == session->GetRetransmitTimer().IsRunning())
			//		{
			//			//something may went wrong.
			//			NS_ASSERT (false);
			//		}
			//		else
			//		{
			//			session->GetRetransmitTimer().Cancel();
			//		}
			//*******************legacy codes, not understand why, saved for archived**********************

			//schedule retransmission
			session->GetRetransmitTimer().SetFunction(&GsamL4Protocol::DoSendInitMessage, this);
			session->GetRetransmitTimer().SetArguments(session, session_retransmit);
			session->GetRetransmitTimer().Schedule(GsamConfig::GetSingleton()->GetDefaultRetransmitTimeoutInSeconds());
			//decrement retransmission count
			session->DecrementNumberRetransmission();
		}
		else
		{
			//do nothing
		}
	}
	//scheudle timeout
	session->SceduleTimeout(GsamConfig::GetSingleton()->GetDefaultSessionTimeoutSeconds());
}

void
GsamL4Protocol::HandleIkeSaInit (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address)
{
	NS_LOG_FUNCTION (this << packet);


	bool is_invitation = ikeheader.IsInitiator();
	bool is_response = ikeheader.IsResponder();

	if (	(true == is_invitation) &&
			(false == is_response))
	{
		//invitation
		this->HandleIkeSaInitInvitation(packet, ikeheader, peer_address);

	}
	else if ((false == is_invitation) &&
			(true == is_response))
	{
		//response
		this->HandleIkeSaInitResponse(packet, ikeheader, peer_address);
	}
	else
	{
		//error
		NS_ASSERT (false);
	}
}

void
GsamL4Protocol::HandleIkeSaInitInvitation (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address)
{
	NS_LOG_FUNCTION (this << packet);

	uint64_t initiator_spi = ikeheader.GetInitiatorSpi();
	uint32_t message_id = ikeheader.GetMessageId();

	NS_ASSERT (message_id == 0);

	Ptr<GsamInitSession> init_session = this->GetIpSecDatabase()->GetInitSession(ikeheader, peer_address);

	if (init_session == 0)
	{
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

		init_session = this->GetIpSecDatabase()->CreateInitSession(peer_address);
		init_session->SetSessionRole(GsamInitSession::RESPONDER);
		init_session->SetPeerAddress(peer_address);
		init_session->EtablishGsamInitSa();
		init_session->SetInitSaInitiatorSpi(initiator_spi);
		uint64_t responder_spi = this->GetIpSecDatabase()->GetInfo()->RegisterGsamSpi();
		init_session->SetInitSaResponderSpi(responder_spi);

		GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), init_session);

		this->RespondIkeSaInit(init_session);
	}
	else
	{
		GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), init_session);
		if (init_session->GetCurrentMessageId() == message_id)
		{
			//duplicate received
			GsamConfig::LogMsg("Respond to duplicate ");
			this->DoSendInitMessage(init_session, false);
		}
		else
		{
			NS_ASSERT (false);
		}
	}
}

void
GsamL4Protocol::HandleIkeSaInitResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address)
{
	NS_LOG_FUNCTION (this << packet);

	Ptr<GsamInitSession> init_session = this->GetIpSecDatabase()->GetInitSession(ikeheader, peer_address);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), init_session);

	if (0 == init_session)
	{
		//no session
		//unsolicited response
		//assert for debug use
		NS_ASSERT (false);
	}
	else
	{
		uint32_t message_id = ikeheader.GetMessageId();

		if (init_session->GetCurrentMessageId() == message_id)
		{
			//response with matched message id received
			NS_ASSERT (message_id == 0);

			//
			IkePayloadHeader::PAYLOAD_TYPE sa_payload_type = ikeheader.GetNextPayloadType();
			if (sa_payload_type != IkePayloadHeader::SECURITY_ASSOCIATION)
			{
				NS_ASSERT (false);
			}
			IkePayload sa_r_1 = IkePayload::GetEmptyPayloadFromPayloadType(sa_payload_type);
			packet->RemoveHeader(sa_r_1);

			//
			IkePayloadHeader::PAYLOAD_TYPE ke_payload_type = sa_r_1.GetNextPayloadType();
			if (ke_payload_type != IkePayloadHeader::KEY_EXCHANGE)
			{
				NS_ASSERT (false);
			}
			IkePayload ke_r = IkePayload::GetEmptyPayloadFromPayloadType(ke_payload_type);
			packet->RemoveHeader(ke_r);

			//
			IkePayloadHeader::PAYLOAD_TYPE nonce_payload_type = ke_r.GetNextPayloadType();
			if (nonce_payload_type != IkePayloadHeader::NONCE)
			{
				NS_ASSERT (false);
			}
			IkePayload n_r = IkePayload::GetEmptyPayloadFromPayloadType(nonce_payload_type);
			packet->RemoveHeader(n_r);

			init_session->GetRetransmitTimer().Cancel();

			uint64_t responder_spi = ikeheader.GetResponderSpi();

			if (0 == responder_spi)
			{
				//somthing went wrong
				NS_ASSERT (false);
			}

			init_session->SetInitSaResponderSpi(responder_spi);

			this->Send_IKE_SA_AUTH(init_session, init_session->GetFirstJoinSession());
		}
		else if (init_session->GetCurrentMessageId() > message_id)
		{
			//behindhand response
			//do nothing
			//ASSERT init_session's message id is always 0
			NS_ASSERT (false);
		}
		else	//session->GetCurrentMessageId() < message_id
		{
			//unsolicited response
			//ignore or assert?
			NS_ASSERT (false);
		}
	}
}

void
GsamL4Protocol::RespondIkeSaInit (Ptr<GsamInitSession> session)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);

	//setting up Nr
	IkePayload n_r;
	n_r.SetSubstructure(IkeNonceSubstructure::GenerateRandomNonceSubstructure());

	//setting up KEr
	IkePayload ke_r;
	ke_r.SetSubstructure(IkeKeyExchangeSubStructure::GetDummySubstructure());
	ke_r.SetNextPayloadType(n_r.GetPayloadType());

	//setting up SAr1
	IkePayload sa_r_1;
	sa_r_1.SetSubstructure(IkeSaPayloadSubstructure::GenerateInitIkePayload());
	sa_r_1.SetNextPayloadType(ke_r.GetPayloadType());

	uint32_t length_beside_ikeheader = 	n_r.GetSerializedSize() +
										ke_r.GetSerializedSize() +
										sa_r_1.GetSerializedSize();

	//adding to packet
	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(n_r);
	packet->AddHeader(ke_r);
	packet->AddHeader(sa_r_1);

	//ready to send
	this->SendPhaseOneMessage(	session,
						IkeHeader::IKE_SA_INIT,
						true,
						sa_r_1.GetPayloadType(),
						length_beside_ikeheader,
						packet,
						true);
}

void
GsamL4Protocol::HandleIkeSaAuth (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamInitSession> init_session = this->GetIpSecDatabase()->GetInitSession(ikeheader, peer_address);

	if (init_session == 0)
	{
		//unsolicited
		NS_ASSERT (false);
	}
	else
	{
		bool is_invitation = ikeheader.IsInitiator();
		bool is_response = ikeheader.IsResponder();

		if (	(true == is_invitation) &&
				(false == is_response))
		{
			//invitation
			this->HandleIkeSaAuthInvitation(packet, ikeheader, init_session);

		}
		else if ((false == is_invitation) &&
				(true == is_response))
		{
			//response
			this->HandleIkeSaAuthResponse(packet, ikeheader, init_session);
		}
		else
		{
			//error
			NS_ASSERT (false);
		}
	}

}
void
GsamL4Protocol::HandleIkeSaAuthInvitation (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamInitSession> init_session)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), init_session);

	uint32_t message_id = ikeheader.GetMessageId();

	NS_ASSERT (message_id == 1);

	if (init_session->GetCurrentMessageId() <= message_id)
	{
		//picking up id payload
		IkePayloadHeader::PAYLOAD_TYPE id_payload_type = ikeheader.GetNextPayloadType();
		if (id_payload_type != IkePayloadHeader::IDENTIFICATION_INITIATOR)
		{
			NS_ASSERT (false);
		}
		IkePayload id = IkePayload::GetEmptyPayloadFromPayloadType(id_payload_type);
		packet->RemoveHeader(id);

		//picking up auth payload
		IkePayloadHeader::PAYLOAD_TYPE auth_payload_type = id.GetNextPayloadType();
		if (auth_payload_type != IkePayloadHeader::AUTHENTICATION)
		{
			NS_ASSERT (false);
		}
		IkePayload auth = IkePayload::GetEmptyPayloadFromPayloadType(auth_payload_type);
		packet->RemoveHeader(auth);

		//picking up SAi2 payload
		IkePayloadHeader::PAYLOAD_TYPE sai2_payload_type = auth.GetNextPayloadType();
		if (sai2_payload_type != IkePayloadHeader::SECURITY_ASSOCIATION)
		{
			NS_ASSERT (false);
		}
		IkePayload sai2 = IkePayload::GetEmptyPayloadFromPayloadType(sai2_payload_type);
		packet->RemoveHeader(sai2);

		//picking up TSi payload
		IkePayloadHeader::PAYLOAD_TYPE tsi_payload_type = sai2.GetNextPayloadType();
		if (tsi_payload_type != IkePayloadHeader::TRAFFIC_SELECTOR_INITIATOR)
		{
			NS_ASSERT (false);
		}
		IkePayload tsi = IkePayload::GetEmptyPayloadFromPayloadType(tsi_payload_type);
		packet->RemoveHeader(tsi);

		//picking up TSr payload
		IkePayloadHeader::PAYLOAD_TYPE tsr_payload_type = tsi.GetNextPayloadType();
		if (tsr_payload_type != IkePayloadHeader::TRAFFIC_SELECTOR_RESPONDER)
		{
			NS_ASSERT (false);
		}
		IkePayload tsr = IkePayload::GetEmptyPayloadFromPayloadType(tsr_payload_type);
		packet->RemoveHeader(tsr);

		Ptr<IkeSaPayloadSubstructure> sai2_sub = DynamicCast<IkeSaPayloadSubstructure>(sai2.GetSubstructure());
		Ptr<IkeSaProposal> chosen_proposal = GsamL4Protocol::ChooseSAProposalOffer(sai2_sub->GetProposals());

		std::list<IkeTrafficSelector> narrowed_tssi;
		Ptr<IkeTrafficSelectorSubstructure> tsi_sub = DynamicCast<IkeTrafficSelectorSubstructure>(tsi.GetSubstructure());
		GsamL4Protocol::NarrowTrafficSelectors(tsi_sub->GetTrafficSelectors(), narrowed_tssi);
		std::list<IkeTrafficSelector> narrowed_tssr;
		Ptr<IkeTrafficSelectorSubstructure> tsr_sub = DynamicCast<IkeTrafficSelectorSubstructure>(tsr.GetSubstructure());
		GsamL4Protocol::NarrowTrafficSelectors(tsr_sub->GetTrafficSelectors(), narrowed_tssr);

		Ptr<IkeIdSubstructure> id_substructure = DynamicCast<IkeIdSubstructure>(id.GetSubstructure());

		Ptr<GsamSession> session = 0;
		bool new_session_created = this->ProcessIkeSaAuthInvitation(	init_session,
														id_substructure->GetIpv4AddressFromData(),
														chosen_proposal,
														narrowed_tssi,
														narrowed_tssr,
														session);

//		if (!init_session->HaveKekSa())
//		{
//			//not duplicated packet
//			this->ProcessIkeSaAuthInvitation(	init_session,
//												id_substructure->GetIpv4AddressFromData(),
//												chosen_proposal,
//												narrowed_tssi,
//												narrowed_tssr);
//		}
//		else
//		{
//			//it has already receive a same auth invitation for the same session before
//			//this assert is set because we have set an if (current_session_id < message_id) or (current_session_id == message_id) guard ahead
//			NS_ASSERT (false);
//		}

		if (true == new_session_created)
		{
			init_session->SetMessageId(message_id);

			this->RespondIkeSaAuth(session, chosen_proposal, narrowed_tssi, narrowed_tssr);
		}
		else
		{
			//incoming duplicate invitation
			GsamConfig::LogMsg("Respond to duplicate ");
			this->DoSendMessage(session, false);
		}
	}
//	@commented, moved codes
//	else if (init_session->GetCurrentMessageId() == message_id)
//	{
//		//incoming duplicate invitation
//		GsamConfig::LogMsg("Respond to duplicate ");
//		this->DoSendMessage(init_session, false);
//	}
	else	//(session->GetCurrentMessageId() > message_id)
	{
		//discard
	}

}

bool
GsamL4Protocol::ProcessIkeSaAuthInvitation(	Ptr<GsamInitSession> init_session,
											Ipv4Address group_address,
											const Ptr<IkeSaProposal> proposal,
											const std::list<IkeTrafficSelector>& tsi_selectors,
											const std::list<IkeTrafficSelector>& tsr_selectors,
											Ptr<GsamSession>& found_or_created_session)
{
	NS_LOG_FUNCTION (this);

	found_or_created_session = this->GetIpSecDatabase()->GetSession(init_session, group_address, proposal->GetSpi()->ToUint64());

	bool retval = true;

	if (0 == found_or_created_session)
	{
		found_or_created_session = this->GetIpSecDatabase()->CreateSession(init_session, group_address);
		found_or_created_session->EtablishGsamKekSa();
		found_or_created_session->SetKekSaInitiatorSpi(proposal->GetSpi()->ToUint64());
		found_or_created_session->SetKekSaResponderSpi(init_session->GetInfo()->RegisterGsamSpi());

		if (group_address == GsamConfig::GetIgmpv3DestGrpReportAddress())
		{
			//incoming invitation from NQ
			//do nothing
		}
		else
		{
			//according to gsam's rule, a GM can only join one group at a time using a session

			if (tsi_selectors.size() != 1)
			{
				NS_ASSERT (false);
			}

			if (tsr_selectors.size() != 1)
			{
				NS_ASSERT (false);
			}

			if (0 != found_or_created_session->GetRelatedPolicy())
			{
				//not ok, duplicate check should have been performed in caller method
				NS_ASSERT (false);
			}
			else
			{
				this->CreateIpSecPolicy(found_or_created_session, tsi_selectors, tsr_selectors);
			}
		}
		retval = true;
	}
	else
	{
		//existing session found
		/*
		 * @return value: whether a new session is created
		 */
		retval = false;
	}

	return retval;
}

void
GsamL4Protocol::HandleIkeSaAuthResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamInitSession> init_session)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), init_session);

	uint32_t message_id = ikeheader.GetMessageId();

	if (init_session->GetCurrentMessageId() == message_id)
	{

		NS_ASSERT (message_id == 1);

		//response with matched message id
		init_session->GetRetransmitTimer().Cancel();

		//picking up auth payload
		IkePayloadHeader::PAYLOAD_TYPE auth_payload_type = ikeheader.GetNextPayloadType();
		if (auth_payload_type != IkePayloadHeader::AUTHENTICATION)
		{
			NS_ASSERT (false);
		}
		IkePayload auth = IkePayload::GetEmptyPayloadFromPayloadType(auth_payload_type);
		packet->RemoveHeader(auth);

		//picking up SAr2 payload
		IkePayloadHeader::PAYLOAD_TYPE sar2_payload_type = auth.GetNextPayloadType();
		if (sar2_payload_type != IkePayloadHeader::SECURITY_ASSOCIATION)
		{
			NS_ASSERT (false);
		}
		IkePayload sar2 = IkePayload::GetEmptyPayloadFromPayloadType(sar2_payload_type);
		packet->RemoveHeader(sar2);

		//picking up nonce payload that contains kek initiator spi
		IkePayloadHeader::PAYLOAD_TYPE nonce_payload_type = sar2.GetNextPayloadType();
		if (nonce_payload_type != IkePayloadHeader::NONCE)
		{
			NS_ASSERT (false);
		}
		IkePayload nonce_payload = IkePayload::GetEmptyPayloadFromPayloadType(nonce_payload_type);
		packet->RemoveHeader(nonce_payload);

		//picking up TSi payload
		IkePayloadHeader::PAYLOAD_TYPE tsi_payload_type = nonce_payload.GetNextPayloadType();
		if (tsi_payload_type != IkePayloadHeader::TRAFFIC_SELECTOR_INITIATOR)
		{
			NS_ASSERT (false);
		}
		IkePayload tsi = IkePayload::GetEmptyPayloadFromPayloadType(tsi_payload_type);
		packet->RemoveHeader(tsi);

		//picking up TSr payload
		IkePayloadHeader::PAYLOAD_TYPE tsr_payload_type = tsi.GetNextPayloadType();
		if (tsr_payload_type != IkePayloadHeader::TRAFFIC_SELECTOR_RESPONDER)
		{
			NS_ASSERT (false);
		}
		IkePayload tsr = IkePayload::GetEmptyPayloadFromPayloadType(tsr_payload_type);
		packet->RemoveHeader(tsr);

		Ptr<IkeSaPayloadSubstructure> sar2_sub = DynamicCast<IkeSaPayloadSubstructure>(sar2.GetSubstructure());
		Ptr<IkeTrafficSelectorSubstructure> tsi_sub = DynamicCast<IkeTrafficSelectorSubstructure>(tsi.GetSubstructure());
		Ptr<IkeTrafficSelectorSubstructure> tsr_sub = DynamicCast<IkeTrafficSelectorSubstructure>(tsr.GetSubstructure());
		Ptr<IkeNonceSubstructure> nonce_sub = DynamicCast<IkeNonceSubstructure>(nonce_payload.GetSubstructure());

		this->ProcessIkeSaAuthResponse(init_session, nonce_sub->GetDataToU64(), sar2_sub->GetProposals(), tsi_sub->GetTrafficSelectors(), tsr_sub->GetTrafficSelectors());
	}
	else if (init_session->GetCurrentMessageId() > message_id)
	{
		//behindhand response
		//do nothing
	}
	else	//session->GetCurrentMessageId() < message_id
	{
		//unsolicited response
		//ignore or assert?
		NS_ASSERT (false);
	}

}

void
GsamL4Protocol::ProcessIkeSaAuthResponse (	const Ptr<const GsamInitSession> init_session,
											uint64_t kek_initiator_spi,
											const std::list<Ptr<IkeSaProposal> >& sar2_proposals,
											const std::list<IkeTrafficSelector>& tsi_selectors,
											const std::list<IkeTrafficSelector>& tsr_selectors)
{
	NS_LOG_FUNCTION (this);

	if (sar2_proposals.size() != 1)
	{
		NS_ASSERT (false);
	}

	Ptr<GsamSession> session = this->GetIpSecDatabase()->GetSession(init_session, kek_initiator_spi);

	if (0 == session)
	{
		NS_ASSERT (false);
	}
	else
	{
		//do nothing
	}

	if (0 == session->GetKekSaResponderSpi())
	{
		Ptr<IkeSaProposal> proposal = sar2_proposals.front();

		Ptr<Spi> spi_responder = proposal->GetSpi();

		session->SetKekSaResponderSpi(spi_responder->ToUint64());

		if (true == session->IsHostNonQuerier())
		{
			//do not crate any policy
		}
		else
		{
			//according to gsam's rule, a GM can only join one group at a time using a session
			if (tsi_selectors.size() != 1)
			{
				NS_ASSERT (false);
			}

			if (tsr_selectors.size() != 1)
			{
				NS_ASSERT (false);
			}

			this->CreateIpSecPolicy(session, tsi_selectors, tsr_selectors);
		}
	}
	else
	{
		//duplicate received packet
	}
}

void
GsamL4Protocol::RespondIkeSaAuth (	Ptr<GsamSession> session,
									const Ptr<IkeSaProposal> chosen_proposal,
									const std::list<IkeTrafficSelector>& narrowed_tssi,
									const std::list<IkeTrafficSelector>& narrowed_tssr)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);

	//Setting up TSr
	IkePayload tsr = IkePayload::GetEmptyPayloadFromPayloadType(IkePayloadHeader::TRAFFIC_SELECTOR_RESPONDER);
	Ptr<IkeTrafficSelectorSubstructure> tsr_payload_sub = DynamicCast<IkeTrafficSelectorSubstructure>(tsr.GetSubstructure());
	tsr_payload_sub->PushBackTrafficSelectors(narrowed_tssr);
	//settuping up tsi
	IkePayload tsi = IkePayload::GetEmptyPayloadFromPayloadType(IkePayloadHeader::TRAFFIC_SELECTOR_INITIATOR);
	Ptr<IkeTrafficSelectorSubstructure> tsi_payload_sub = DynamicCast<IkeTrafficSelectorSubstructure>(tsi.GetSubstructure());
	tsi_payload_sub->PushBackTrafficSelectors(narrowed_tssi);
	tsi.SetNextPayloadType(tsr.GetPayloadType());
	//setting up initiator's kek spi as nonce
	IkePayload nonce_payload_init;
	nonce_payload_init.SetSubstructure(IkeNonceSubstructure::GenerateNonceSubstructure(session->GetKekSaInitiatorSpi()));
	nonce_payload_init.SetNextPayloadType(tsi.GetPayloadType());
	//setting up sar2
	IkePayload sar2;
	Ptr<Spi> responder_kek_sa_spi = Create<Spi>();
	responder_kek_sa_spi->SetValueFromUint64(session->GetKekSaResponderSpi());
	sar2.SetSubstructure(IkeSaPayloadSubstructure::GenerateAuthIkePayload(responder_kek_sa_spi));
	sar2.SetNextPayloadType(nonce_payload_init.GetPayloadType());
	//setting up auth
	IkePayload auth;
	auth.SetSubstructure(IkeAuthSubstructure::GenerateEmptyAuthSubstructure());
	auth.SetNextPayloadType(sar2.GetPayloadType());

	uint32_t length_beside_ikeheader = 	auth.GetSerializedSize() +
										sar2.GetSerializedSize() +
										nonce_payload_init.GetSerializedSize() +
										tsi.GetSerializedSize() +
										tsr.GetSerializedSize();

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(tsr);
	packet->AddHeader(tsi);
	packet->AddHeader(nonce_payload_init);
	packet->AddHeader(sar2);
	packet->AddHeader(auth);

	this->SendPhaseOneMessage(	session,
						IkeHeader::IKE_AUTH,
						true,
						auth.GetPayloadType(),
						length_beside_ikeheader,
						packet,
						false);
	this->Send_GSA_PUSH(session);
}

void
GsamL4Protocol::HandleGsaInformational (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = this->GetIpSecDatabase()->GetSession(ikeheader, peer_address);

	if (session == 0)
	{
		NS_ASSERT (false);
	}
	else
	{
		bool is_invitation = ikeheader.IsInitiator();
		bool is_response = ikeheader.IsResponder();

		if (	(true == is_invitation) &&
				(false == is_response))
		{
			if ((true == session->IsHostGroupMember()) ||
					(true == session->IsHostNonQuerier()))
			{
				this->HandleGsaPushSpiRequest(packet, ikeheader, session);
			}
			else
			{
				NS_ASSERT (false);
			}
		}
		else if ((false == is_invitation) &&
				(true == is_response))
		{
			if (true == session->IsHostQuerier())
			{
				this->HandleGsaAckRejectSpiResponse(packet, ikeheader, session);
			}
			else
			{
				NS_ASSERT (false);
			}
		}
		else
		{
			//error
			NS_ASSERT (false);
		}
	}
}

void
GsamL4Protocol::HandleGsaPushSpiRequest (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	uint32_t message_id = ikeheader.GetMessageId();

	NS_ASSERT (message_id >= 2);

	if (session->GetCurrentMessageId() < message_id)
	{
		if (true == session->IsHostNonQuerier())
		{
			this->HandleGsaPushSpiRequestNQ(packet, ikeheader, session);
		}
		else if (true == session->IsHostGroupMember())
		{
			this->HandleGsaPushSpiRequestGM(packet, ikeheader, session);
		}
		else if (true == session->IsHostQuerier())
		{
			NS_ASSERT (false);
		}
		else
		{
			NS_ASSERT (false);
		}
	}
	else if (session->GetCurrentMessageId() == message_id)
	{
		//duplicate received
		if (true == session->IsHostNonQuerier())
		{
			this->DoSendMessage (session, false);
		}
		else if (true == session->IsHostGroupMember())
		{
			this->DoSendMessage (session, false);
		}
		else if (true == session->IsHostQuerier())
		{
			NS_ASSERT (false);
		}
		else
		{
			NS_ASSERT (false);
		}
	}
	else if (session->GetCurrentMessageId() > message_id)
	{
		//behindhand retransmission
		//or
		//unsolicited packet
		NS_ASSERT (false);
	}
	else if (session->GetCurrentMessageId() == (message_id - 1))
	{
		//ok for spi request
		//this condition is included in the first if
	}
	else
	{
		//unsolicited packet
		NS_ASSERT (false);
	}
}

void
GsamL4Protocol::HandleSpiRequestGMNQ (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);

	IkePayloadHeader::PAYLOAD_TYPE first_payload_type = ikeheader.GetNextPayloadType();

	if (first_payload_type != IkePayloadHeader::GROUP_NOTIFY)
	{
		NS_ASSERT (false);
	}

	IkePayload spi_request_payload = IkePayload::GetEmptyPayloadFromPayloadType(first_payload_type);
	packet->RemoveHeader(spi_request_payload);
	Ptr<IkeGroupNotifySubstructure> spi_request_payload_sub = DynamicCast<IkeGroupNotifySubstructure>(spi_request_payload.GetSubstructure());

	if (spi_request_payload_sub->GetTrafficSelectorSrc().GetStartingAddress().Get() != 0)
	{
		NS_ASSERT (false);
	}
	if (spi_request_payload_sub->GetTrafficSelectorSrc().GetEndingAddress().Get() != 0)
	{
		NS_ASSERT (false);
	}
	if (spi_request_payload_sub->GetTrafficSelectorDest().GetStartingAddress().Get() != 0)
	{
		NS_ASSERT (false);
	}
	if (spi_request_payload_sub->GetTrafficSelectorDest().GetEndingAddress().Get() != 0)
	{
		NS_ASSERT (false);
	}

	this->SendSpiReportGMNQ(session, spi_request_payload_sub->GetGsaPushId());
}

void
GsamL4Protocol::SendSpiReportGMNQ (Ptr<GsamSession> session, uint32_t gsa_push_id)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session, gsa_push_id);

	Ptr<IpSecPolicyDatabase> session_spd = session->GetDatabase()->GetPolicyDatabase();
	std::list<Ptr<Spi> > session_spd_spis;
	session_spd->GetInboundSpis(session_spd_spis);

	IkePayload spi_report_payload;
	IkeGroupNotifySubstructure::NOTIFY_MESSAGE_TYPE type = IkeGroupNotifySubstructure::NONE;

	if (true == session->IsHostGroupMember())
	{
		type = IkeGroupNotifySubstructure::GSA_Q_SPI_NOTIFICATION;
	}
	else if (true == session->IsHostNonQuerier())
	{
		type = IkeGroupNotifySubstructure::GSA_R_SPI_NOTIFICATION;
	}
	else
	{
		NS_ASSERT (false);
	}

	Ptr<IkeGroupNotifySubstructure> spi_report_payload_sub = IkeGroupNotifySubstructure::GenerateEmptyGroupNotifySubstructure(GsamConfig::GetDefaultGSAProposalId(),
																																IpSec::AH_ESP_SPI_SIZE,
																																type,
																																gsa_push_id,
																																IkeTrafficSelector::GetIpv4DummyTs(),
																																IkeTrafficSelector::GetIpv4DummyTs());
	if (0 == session_spd_spis.size())
	{
		//NS_ASSERT (false);
		//ok no inbound spi, send empty report
	}
	spi_report_payload_sub->InertSpis(session_spd_spis);
	spi_report_payload.SetSubstructure(spi_report_payload_sub);

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(spi_report_payload);
	this->SendPhaseTwoMessage(session,
						IkeHeader::INFORMATIONAL,
						true,
						spi_report_payload.GetPayloadType(),
						spi_report_payload.GetSerializedSize(),
						packet,
						false);
}

void
GsamL4Protocol::HandleCreateChildSa (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address)
{
	NS_LOG_FUNCTION (this);

	Ptr<GsamSession> session = this->GetIpSecDatabase()->GetSession(ikeheader, peer_address);

	if (session == 0)
	{
		NS_ASSERT (false);
	}
	else
	{
		bool is_invitation = ikeheader.IsInitiator();
		bool is_response = ikeheader.IsResponder();

		if (	(true == is_invitation) &&
				(false == is_response))
		{
			if ((true == session->IsHostGroupMember()) ||
					(true == session->IsHostNonQuerier()))
			{
				this->HandleGsaRepush(packet, ikeheader, session);
			}
			else
			{
				NS_ASSERT (false);
			}
		}
		else
		{
			//error
			//only GM or NQ would get to this, not Q
			NS_ASSERT (false);
		}
	}
}

void
GsamL4Protocol::HandleGsaRepush (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	if (session->GetCurrentMessageId() == (ikeheader.GetMessageId() - 1))
	{
		session->SetMessageId(ikeheader.GetMessageId());
		if (true == session->IsHostGroupMember())
		{
			this->HandleGsaRepushGM(packet, ikeheader, session);
		}
		else if (true == session->IsHostNonQuerier())
		{
			this->HandleGsaRepushNQ(packet, ikeheader, session);
		}
		else
		{
			NS_ASSERT (false);
		}
	}
	else
	{
		if (session->GetCurrentMessageId() == ikeheader.GetMessageId())
		{
			//maybe retransmission
			//ignore
		}
		else
		{
			//NS_ASSERT (false);
			//unknown cause
			//ignore for getting result
		}
	}
}

void
GsamL4Protocol::HandleGsaRepushGM (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);

	IkePayloadHeader::PAYLOAD_TYPE next_payload_type = ikeheader.GetNextPayloadType();

	while (next_payload_type != IkePayloadHeader::NO_NEXT_PAYLOAD)
	{
		if (next_payload_type != IkePayloadHeader::GSA_REPUSH)
		{
			NS_ASSERT (false);
		}

		IkePayload gsa_repush_payload = IkePayload::GetEmptyPayloadFromPayloadType(next_payload_type);
		packet->RemoveHeader(gsa_repush_payload);
		Ptr<IkeGsaPayloadSubstructure> gsa_repush_sub = DynamicCast<IkeGsaPayloadSubstructure>(gsa_repush_payload.GetSubstructure());

		const IkeTrafficSelector& ts_src = gsa_repush_sub->GetSourceTrafficSelector();
		const IkeTrafficSelector& ts_dest = gsa_repush_sub->GetDestTrafficSelector();

		if (session->GetGroupAddress() != GsamUtility::CheckAndGetGroupAddressFromTrafficSelectors(ts_src, ts_dest))
		{
			NS_ASSERT (false);
		}

		if (0 != (gsa_repush_sub->GetProposals().size() % 2))
		{
			//must be even number
			NS_ASSERT (false);
		}

		for (	std::list<Ptr<IkeSaProposal> >::const_iterator const_it_proposals = gsa_repush_sub->GetProposals().begin();
				const_it_proposals != gsa_repush_sub->GetProposals().end();
				const_it_proposals++)
		{
			Ptr<IkeGsaProposal> gsa_proposal_to_modify = DynamicCast<IkeGsaProposal>(*const_it_proposals);

			if (gsa_proposal_to_modify->GetGsaType() == IkeGsaProposal::GSA_Q_TO_BE_MODIFIED)
			{
				Ptr<GsamSessionGroup> session_group = session->GetSessionGroup();
				if (0 == session_group)
				{
					NS_ASSERT (false);
				}
				GsamConfig::LogGsaQ("IkeGsaProposal::GSA_Q_TO_BE_MODIFIED", gsa_proposal_to_modify->GetSpi()->ToUint32());

				const_it_proposals++;

				Ptr<IkeGsaProposal> gsa_proposal_replacement = DynamicCast<IkeGsaProposal>(*const_it_proposals);

				if (gsa_proposal_replacement->GetGsaType() == IkeGsaProposal::GSA_Q_REPLACEMENT)
				{
					GsamConfig::LogGsaQ("IkeGsaProposal::GSA_Q_REPLACEMENT", gsa_proposal_replacement->GetSpi()->ToUint32());
					Ptr<IpSecSAEntry> session_gsa_q = session->GetRelatedGsaQ();
					if (0 == session_gsa_q)
					{
						//The reason why (0 == session_gsa_q) is that it was rejected?
						//install a new gsa q with the incoming spi replacement
						Ptr<IpSecSADatabase> inbound_sad = session->GetRelatedPolicy()->GetInboundSAD();
						Ptr<IpSecSAEntry> new_gsa_q = inbound_sad->CreateIpSecSAEntry(gsa_proposal_replacement->GetSpi()->ToUint32());
						session->AssociateGsaQ(new_gsa_q);
					}
					else
					{
						//change spi
						if (session_gsa_q->GetSpi() != gsa_proposal_to_modify->GetSpi()->ToUint32())
						{
							NS_ASSERT (false);
						}
						session_gsa_q->SetSpi(gsa_proposal_replacement->GetSpi()->ToUint32());
					}
				}
				else
				{
					NS_ASSERT (false);
				}
			}
			else if (gsa_proposal_to_modify->GetGsaType() == IkeGsaProposal::GSA_R_TO_BE_MODIFIED)
			{
				Ptr<GsamSessionGroup> session_group = session->GetSessionGroup();
				if (0 == session_group)
				{
					NS_ASSERT (false);
				}
				GsamConfig::LogGsaR("IkeGsaProposal::GSA_R_TO_BE_MODIFIED", gsa_proposal_to_modify->GetSpi()->ToUint32());

				const_it_proposals++;

				Ptr<IkeGsaProposal> gsa_proposal_replacement = DynamicCast<IkeGsaProposal>(*const_it_proposals);

				if (gsa_proposal_replacement->GetGsaType() == IkeGsaProposal::GSA_R_REPLACEMENT)
				{
					GsamConfig::LogGsaR("IkeGsaProposal::GSA_R_REPLACEMENT", gsa_proposal_replacement->GetSpi()->ToUint32());
					Ptr<IpSecSAEntry> session_gsa_r = session->GetRelatedGsaR();
					if (0 == session_gsa_r)
					{
						//The reason why (0 == session_gsa_r) is that it was rejected?
						//install a new gsa q with the incoming spi replacement
						Ptr<IpSecSADatabase> outbound_sad = session->GetRelatedPolicy()->GetOutboundSAD();
						Ptr<IpSecSAEntry> new_gsa_r = outbound_sad->CreateIpSecSAEntry(gsa_proposal_replacement->GetSpi()->ToUint32());
						session->SetRelatedGsaR(new_gsa_r);
					}
					else
					{
						//change spi
						if (session_gsa_r->GetSpi() != gsa_proposal_to_modify->GetSpi()->ToUint32())
						{
							NS_ASSERT (false);
						}
						session_gsa_r->SetSpi(gsa_proposal_replacement->GetSpi()->ToUint32());
					}
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
		next_payload_type = gsa_repush_payload.GetNextPayloadType();
	}

	Ptr<Igmpv3L4Protocol> igmp = Igmpv3L4Protocol::GetIgmp(this->m_node);
	Time dt = GsamConfig::GetSingleton()->GetSigmpReportDelayAfterGsamInMilliSeconds();
	Simulator::Schedule (dt,
							&Igmpv3L4Protocol::SendSecureStateChangesReport,
							igmp,
							igmp->GetManager()->GetIfStateManager(session->GetIgmpInterface()),
							session->GetGroupAddress());
}

void
GsamL4Protocol::HandleGsaRepushNQ (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);

	IkePayloadHeader::PAYLOAD_TYPE next_payload_type = ikeheader.GetNextPayloadType();

	while (next_payload_type != IkePayloadHeader::NO_NEXT_PAYLOAD)
	{
		if (next_payload_type != IkePayloadHeader::GSA_REPUSH)
		{
			NS_ASSERT (false);
		}

		IkePayload gsa_repush_payload = IkePayload::GetEmptyPayloadFromPayloadType(next_payload_type);
		packet->RemoveHeader(gsa_repush_payload);
		Ptr<IkeGsaPayloadSubstructure> gsa_repush_sub = DynamicCast<IkeGsaPayloadSubstructure>(gsa_repush_payload.GetSubstructure());

		const IkeTrafficSelector& ts_src = gsa_repush_sub->GetSourceTrafficSelector();
		const IkeTrafficSelector& ts_dest = gsa_repush_sub->GetDestTrafficSelector();

		Ipv4Address group_address = GsamUtility::CheckAndGetGroupAddressFromTrafficSelectors(ts_src, ts_dest);

		Ptr<IpSecPolicyDatabase> spd = session->GetDatabase()->GetPolicyDatabase();
		Ptr<IpSecPolicyEntry> policy = spd->GetExactMatchedPolicy(ts_src, ts_dest);
		if (0 == policy)
		{
			GsamConfig::LogMsg("No Policy Exists");
			//nq should have what Q has
			//but may be it's a policy of a rejected spi
			Ptr<GsamSessionGroup> session_group = this->m_ptr_database->GetSessionGroup(group_address);
			if (0 != session_group->GetRelatedPolicy())
			{
				NS_ASSERT (false);
			}
			else
			{
				//etablish policy
				session_group->EtablishPolicy(ts_src, ts_dest, GsamConfig::GetDefaultIpsecProtocolId(), IpSec::PROTECT, GsamConfig::GetDefaultIpsecMode());
				policy = spd->GetExactMatchedPolicy(ts_src, ts_dest);
				if (0 == policy)
				{
					NS_ASSERT (false);
				}
			}
			//policy isn't 0 any more
			//install gsa, q or r
			for (	std::list<Ptr<IkeSaProposal> >::const_iterator const_it_proposals = gsa_repush_sub->GetProposals().begin();
					const_it_proposals != gsa_repush_sub->GetProposals().end();
					const_it_proposals++)
			{
				Ptr<IkeGsaProposal> gsa_proposal_const_it = DynamicCast<IkeGsaProposal>(*const_it_proposals);

				if (gsa_proposal_const_it->GetGsaType() == IkeGsaProposal::GSA_Q_TO_BE_MODIFIED)
				{
					//do nothing
					GsamConfig::LogGsaQ("IkeGsaProposal::GSA_Q_TO_BE_MODIFIED", gsa_proposal_const_it->GetSpi()->ToUint32());
				}
				else if (gsa_proposal_const_it->GetGsaType() == IkeGsaProposal::GSA_Q_REPLACEMENT)
				{
					GsamConfig::LogGsaQ("IkeGsaProposal::GSA_Q_REPLACEMENT", gsa_proposal_const_it->GetSpi()->ToUint32());
					Ptr<IpSecSADatabase> sad_outbound = policy->GetOutboundSAD();
					Ptr<IpSecSAEntry> gsa_q = sad_outbound->CreateIpSecSAEntry(gsa_proposal_const_it->GetSpi()->ToUint32());
				}
				else if (gsa_proposal_const_it->GetGsaType() == IkeGsaProposal::GSA_R_TO_BE_MODIFIED)
				{
					//do nothing
					GsamConfig::LogGsaR("IkeGsaProposal::GSA_R_TO_BE_MODIFIED", gsa_proposal_const_it->GetSpi()->ToUint32());
				}
				else if (gsa_proposal_const_it->GetGsaType() == IkeGsaProposal::GSA_R_REPLACEMENT)
				{
					GsamConfig::LogGsaR("IkeGsaProposal::GSA_R_REPLACEMENT", gsa_proposal_const_it->GetSpi()->ToUint32());
					Ptr<IpSecSADatabase> sad_inbound = policy->GetInboundSAD();
					Ptr<IpSecSAEntry> gsa_r = sad_inbound->CreateIpSecSAEntry(gsa_proposal_const_it->GetSpi()->ToUint32());
				}
				else
				{
					NS_ASSERT (false);
				}
			}



		}
		else
		{
			GsamConfig::LogMsg("Policy Exists");
			Ptr<GsamSessionGroup> session_group = this->m_ptr_database->GetSessionGroup(group_address);
			if (0 == session_group)
			{
				NS_ASSERT (false);
			}
			//find gsa r or gsa q to modify
			for (	std::list<Ptr<IkeSaProposal> >::const_iterator const_it_proposals = gsa_repush_sub->GetProposals().begin();
					const_it_proposals != gsa_repush_sub->GetProposals().end();
					const_it_proposals++)
			{
				Ptr<IkeGsaProposal> gsa_proposal_to_modify = DynamicCast<IkeGsaProposal>(*const_it_proposals);

				if (gsa_proposal_to_modify->GetGsaType() == IkeGsaProposal::GSA_Q_TO_BE_MODIFIED)
				{
					GsamConfig::LogGsaQ("IkeGsaProposal::GSA_Q_TO_BE_MODIFIED", gsa_proposal_to_modify->GetSpi()->ToUint32());
					const_it_proposals++;

					Ptr<IkeGsaProposal> gsa_proposal_replacement = DynamicCast<IkeGsaProposal>(*const_it_proposals);

					if (gsa_proposal_replacement->GetGsaType() == IkeGsaProposal::GSA_Q_REPLACEMENT)
					{
						GsamConfig::LogGsaQ("IkeGsaProposal::GSA_Q_REPLACEMENT", gsa_proposal_replacement->GetSpi()->ToUint32());
						Ptr<IpSecSADatabase> outbound_sad = policy->GetOutboundSAD();
						Ptr<IpSecSAEntry> gsa_q_in_sad = outbound_sad->GetIpsecSAEntry(gsa_proposal_to_modify->GetSpi()->ToUint32());
						if (0 == gsa_q_in_sad)
						{
							//The reason why (0 == gsa_q_in_sad) is that it was rejected?
							//install a new gsa q with the incoming spi replacement
							Ptr<IpSecSAEntry> new_gsa_q = outbound_sad->CreateIpSecSAEntry(gsa_proposal_replacement->GetSpi()->ToUint32());
						}
						else
						{
							//change spi
							if (gsa_q_in_sad->GetSpi() != gsa_proposal_to_modify->GetSpi()->ToUint32())
							{
								NS_ASSERT (false);
							}
							gsa_q_in_sad->SetSpi(gsa_proposal_replacement->GetSpi()->ToUint32());
						}
					}
					else
					{
						NS_ASSERT (false);
					}
				}
				else if (gsa_proposal_to_modify->GetGsaType() == IkeGsaProposal::GSA_R_TO_BE_MODIFIED)
				{
					GsamConfig::LogGsaR("IkeGsaProposal::GSA_R_TO_BE_MODIFIED", gsa_proposal_to_modify->GetSpi()->ToUint32());
					const_it_proposals++;

					Ptr<IkeGsaProposal> gsa_proposal_replacement = DynamicCast<IkeGsaProposal>(*const_it_proposals);

					if (gsa_proposal_replacement->GetGsaType() == IkeGsaProposal::GSA_R_REPLACEMENT)
					{
						GsamConfig::LogGsaR("IkeGsaProposal::GSA_R_REPLACEMENT", gsa_proposal_replacement->GetSpi()->ToUint32());
						Ptr<IpSecSADatabase> inbound_sad = policy->GetInboundSAD();
						Ptr<IpSecSAEntry> gsa_r_in_sad = inbound_sad->GetIpsecSAEntry(gsa_proposal_to_modify->GetSpi()->ToUint32());
						if (0 == gsa_r_in_sad)
						{
							//The reason why (0 == gsa_r_in_sad) is that it was rejected?
							//install a new gsa q with the incoming spi replacement
							Ptr<IpSecSAEntry> new_gsa_r = inbound_sad->CreateIpSecSAEntry(gsa_proposal_replacement->GetSpi()->ToUint32());
						}
						else
						{
							//change spi
							if (gsa_r_in_sad->GetSpi() != gsa_proposal_to_modify->GetSpi()->ToUint32())
							{
								NS_ASSERT (false);
							}
							gsa_r_in_sad->SetSpi(gsa_proposal_replacement->GetSpi()->ToUint32());
						}
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
		}


		next_payload_type = gsa_repush_payload.GetNextPayloadType();
	}
}

void
GsamL4Protocol::RejectGsaR (Ptr<GsamSession> session,
							uint32_t gsa_push_id,
							const IkeTrafficSelector& ts_src,
							const IkeTrafficSelector& ts_dest,
							const std::list<uint32_t>& gsa_r_spis_to_reject,
							std::list<Ptr<IkePayloadSubstructure> >& retval_payload_subs)
{
	NS_LOG_FUNCTION (this);

	Ptr<IkeGroupNotifySubstructure> gsa_r_spis_to_reject_substructure = IkeGroupNotifySubstructure::GenerateEmptyGroupNotifySubstructure(IpSec::SA_PROPOSAL_AH,
																																				IpSec::AH_ESP_SPI_SIZE,
																																				IkeGroupNotifySubstructure::GSA_R_SPI_REJECTION,
																																				gsa_push_id,
																																				ts_src,
																																				ts_dest);
	gsa_r_spis_to_reject_substructure->InsertSpis(gsa_r_spis_to_reject);

	retval_payload_subs.push_back(gsa_r_spis_to_reject_substructure);

}

void
GsamL4Protocol::ProcessNQRejectResult (Ptr<GsamSession> session, std::list<Ptr<IkePayloadSubstructure> >& retval_payload_subs)
{
	NS_LOG_FUNCTION (this);

	Ptr<Packet> packet = Create<Packet>();
	uint32_t length_beside_ikeheader = 0;

	IkePayloadHeader::PAYLOAD_TYPE next_payload_type = IkePayloadHeader::NO_NEXT_PAYLOAD;
	for (std::list<Ptr<IkePayloadSubstructure> >::iterator it = retval_payload_subs.begin();
			it != retval_payload_subs.end();
			it++)
	{
		IkePayload reject_gsa_r_payload;
		reject_gsa_r_payload.SetSubstructure(*it);
		reject_gsa_r_payload.SetNextPayloadType(next_payload_type);

		packet->AddHeader(reject_gsa_r_payload);

		next_payload_type = reject_gsa_r_payload.GetPayloadType();
		length_beside_ikeheader += reject_gsa_r_payload.GetSerializedSize();
	}

	this->SendPhaseTwoMessage(session,
						IkeHeader::INFORMATIONAL,
						true,
						next_payload_type,
						length_beside_ikeheader,
						packet,
						false);
}

void
GsamL4Protocol::SendAcceptAck (Ptr<GsamSession> session,  uint32_t gsa_push_id)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session, gsa_push_id);

	IkeTrafficSelector empty_ts = IkeTrafficSelector::GetIpv4DummyTs();

	Ptr<IkeGroupNotifySubstructure> ack_notify_substructure = IkeGroupNotifySubstructure::GenerateEmptyGroupNotifySubstructure(	GsamConfig::GetDefaultGSAProposalId(),
																																	IpSec::AH_ESP_SPI_SIZE,
																																	IkeGroupNotifySubstructure::GSA_ACKNOWLEDGEDMENT,
																																	gsa_push_id,
																																	empty_ts,
																																	empty_ts);

	IkePayload ack_notify_payload;
	ack_notify_payload.SetSubstructure(ack_notify_substructure);

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(ack_notify_payload);

	this->SendPhaseTwoMessage(session,
				IkeHeader::INFORMATIONAL,
				true,
				ack_notify_payload.GetPayloadType(),
				ack_notify_payload.GetSerializedSize(),
				packet,
				false);
}

void
GsamL4Protocol::FakeRejection (Ptr<GsamSession> session, uint32_t u32_spi)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);

	Ptr<GsamInfo> info = session->GetInfo();
	info->OccupyIpsecSpi(u32_spi);

	Ptr<IpSecPolicyDatabase> spd = session->GetDatabase()->GetPolicyDatabase();
	Ptr<IpSecPolicyEntry> policy = spd->CreatePolicyEntry();
	Ptr<IpSecSADatabase> inbound_sad = policy->GetInboundSAD();
	inbound_sad->CreateIpSecSAEntry(u32_spi);
}

void
GsamL4Protocol::HandleGsaPushSpiRequestGM (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	uint32_t message_id = ikeheader.GetMessageId();

	IkePayload first_payload;
	IkePayloadHeader::PAYLOAD_TYPE first_payload_type = ikeheader.GetNextPayloadType();

	if (first_payload_type == IkePayloadHeader::GSA_PUSH)
	{
		if (session->GetCurrentMessageId() == (message_id - 1))
		{
			session->SetMessageId(message_id);
			this->HandleGsaPushGM (packet, ikeheader, session);
		}
		else
		{
			NS_ASSERT (false);
		}
	}
	else if (first_payload_type == IkePayloadHeader::GROUP_NOTIFY)
	{
		session->SetMessageId(message_id);
		this->HandleSpiRequestGMNQ (packet, ikeheader, session);
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
GsamL4Protocol::HandleGsaPushGM (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);

	IkePayloadHeader::PAYLOAD_TYPE first_payload_type = ikeheader.GetNextPayloadType();

	if (first_payload_type != IkePayloadHeader::GSA_PUSH)
	{
		NS_ASSERT (false);
	}

	IkePayload pushed_gsa_payload = IkePayload::GetEmptyPayloadFromPayloadType(first_payload_type);
	packet->RemoveHeader(pushed_gsa_payload);
	Ptr<IkeGsaPayloadSubstructure> gsa_payload_substructure = DynamicCast<IkeGsaPayloadSubstructure>(pushed_gsa_payload.GetSubstructure());

	const std::list<Ptr<IkeSaProposal> >& proposals = gsa_payload_substructure->GetProposals();

	if (proposals.size() != 2)
	{
		NS_ASSERT (false);
	}

	IkeTrafficSelector ts_src = gsa_payload_substructure->GetSourceTrafficSelector();
	IkeTrafficSelector ts_dest = gsa_payload_substructure->GetDestTrafficSelector();
	Ptr<IkeSaProposal> gsa_q_proposal = proposals.front();
	Ptr<IkeSaProposal> gsa_r_proposal = proposals.back();
	uint32_t gsa_push_id = gsa_payload_substructure->GetGsaPushId();

	this->ProcessGsaPushGM(session, gsa_push_id, ts_src, ts_dest, gsa_q_proposal, gsa_r_proposal);
}

void
GsamL4Protocol::HandleGsaPushSpiRequestNQ (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	uint32_t message_id = ikeheader.GetMessageId();

	IkePayload first_payload;
	IkePayloadHeader::PAYLOAD_TYPE first_payload_type = ikeheader.GetNextPayloadType();

	if (first_payload_type == IkePayloadHeader::GSA_PUSH)
	{
		if (session->GetCurrentMessageId() == (message_id - 1))
		{
			session->SetMessageId(message_id);
			this->HandleGsaPushNQ (packet, ikeheader, session);
		}
		else
		{
			//NS_ASSERT (false);
			//ignore for getting result
		}
	}
	else if (first_payload_type == IkePayloadHeader::GROUP_NOTIFY)
	{
		session->SetMessageId(message_id);
		this->HandleSpiRequestGMNQ (packet, ikeheader, session);
	}
	else
	{
		NS_ASSERT (false);
	}

}

void
GsamL4Protocol::HandleGsaPushNQ (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	IkePayloadHeader::PAYLOAD_TYPE next_payload_type = ikeheader.GetNextPayloadType();

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);

	if (next_payload_type == IkePayloadHeader::GSA_PUSH)
	{
		//ok
	}
	else
	{
		NS_ASSERT (false);
	}

	bool go_on = false;

	std::list<Ptr<IkePayloadSubstructure> > retval_toreject_payload_subs;

	uint32_t previous_gsa_push_id = 0;	//temp save valuable

	do {
		IkePayload pushed_gsa_payload = IkePayload::GetEmptyPayloadFromPayloadType(next_payload_type);
		packet->RemoveHeader(pushed_gsa_payload);
		Ptr<IkeGsaPayloadSubstructure> gsa_payload_substructure = DynamicCast<IkeGsaPayloadSubstructure>(pushed_gsa_payload.GetSubstructure());

		if ((gsa_payload_substructure->GetSourceTrafficSelector().GetStartingAddress().Get() == 0) &&
				(gsa_payload_substructure->GetSourceTrafficSelector().GetEndingAddress().Get() == 0) &&
				(gsa_payload_substructure->GetDestTrafficSelector().GetStartingAddress().Get() == 0) &&
				(gsa_payload_substructure->GetDestTrafficSelector().GetEndingAddress().Get() == 0))
		{
			//the Q has nothing to push
			uint32_t gsa_push_id = gsa_payload_substructure->GetGsaPushId();
			if (0 != gsa_push_id)
			{
				NS_ASSERT (false);
			}
			if (0 != gsa_payload_substructure->GetProposals().size())
			{
				NS_ASSERT (false);
			}
			if (pushed_gsa_payload.GetNextPayloadType() != IkePayloadHeader::NO_NEXT_PAYLOAD)
			{
				NS_ASSERT (false);
			}
			//send ack
			this->SendAcceptAck(session, previous_gsa_push_id);
		}
		else
		{
			/*
			 * We base the process onto each individual group.
			 * If there is one or more spi of a group get rejected, we collect those rejected spis and pack them into a payload substructure
			 * If there is no rejection for that group. A policy will be established and those spis of that group will be installed
			 */
			this->ProcessGsaPushNQForOneGrp(	session,
									gsa_payload_substructure->GetGsaPushId(),
									gsa_payload_substructure->GetSourceTrafficSelector(),
									gsa_payload_substructure->GetDestTrafficSelector(),
									gsa_payload_substructure->GetProposals(),
									retval_toreject_payload_subs);

			/*********************debug*************************/
			if (0 == previous_gsa_push_id)
			{
				//debug code, gsa push id should either be all 0 or all of the same value
			}
			else if (previous_gsa_push_id == gsa_payload_substructure->GetGsaPushId())
			{
				//debug code, gsa push id should either be all 0 or all of the same value
			}
			else
			{
				//no ok
				NS_ASSERT (false);
			}
			previous_gsa_push_id = gsa_payload_substructure->GetGsaPushId();
			/********************debug**************************/

			next_payload_type = pushed_gsa_payload.GetNextPayloadType();
			if (next_payload_type == IkePayloadHeader::GSA_PUSH)
			{
				go_on = true;
			}
			else if (next_payload_type == IkePayloadHeader::NO_NEXT_PAYLOAD)
			{
				go_on = false;
			}
			else
			{
				NS_ASSERT (false);
			}
		}
	} while (true == go_on);

	if (retval_toreject_payload_subs.size() > 0)
	{
		//reject
		this->ProcessNQRejectResult(session, retval_toreject_payload_subs);
	}
	else
	{
		//send ack
		this->SendAcceptAck(session, previous_gsa_push_id);
	}
}

void
GsamL4Protocol::ProcessGsaPushGM (	Ptr<GsamSession> session,
									uint32_t gsa_push_id,
									const IkeTrafficSelector& ts_src,
									const IkeTrafficSelector& ts_dest,
									const Ptr<IkeSaProposal> gsa_q_proposal,
									const Ptr<IkeSaProposal> gsa_r_proposal)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);
	GsamConfig::LogGsaQ(__FUNCTION__, gsa_q_proposal->GetSpi()->ToUint32());
	GsamConfig::LogGsaR(__FUNCTION__, gsa_r_proposal->GetSpi()->ToUint32());

	Ptr<IpSecSAEntry> local_gsa_q = session->GetRelatedGsaQ();
	Ptr<IpSecSAEntry> local_gsa_r = session->GetRelatedGsaR();

	uint32_t pushed_gsa_q_spi = gsa_q_proposal->GetSpi()->ToUint32();

	//checking received gsa_q
	if (local_gsa_q == 0)
	{
		//checking received gsa_r
		if (local_gsa_r == 0)
		{
			//new GM
			//process received gsa_q
			if (true == session->GetInfo()->IsIpsecSpiOccupied(pushed_gsa_q_spi))
			{
				//reject gsa_q
				this->RejectGsaQ(session, gsa_push_id, ts_src, ts_dest, gsa_q_proposal);
			}
			else
			{
				//Fake Reject
				if (false == GsamConfig::IsFalseByPercentage(GsamConfig::GetSingleton()->GetSpiRejectPropability()))
				{
					this->FakeRejection(session, pushed_gsa_q_spi);
					this->RejectGsaQ(session, gsa_push_id, ts_src, ts_dest, gsa_q_proposal);
				}
				else
				{
					//no reject and install gsa pair
					this->AcceptGsaPair(session, gsa_push_id, ts_src, ts_dest, gsa_q_proposal, gsa_r_proposal);
				}
			}
		}
		else
		{
			//weird
			NS_ASSERT (false);
		}
	}
	else
	{
		if (local_gsa_r == 0)
		{
			//weird
			NS_ASSERT (false);
		}
		else
		{
			if (local_gsa_q->GetSpi() != gsa_q_proposal->GetSpi()->ToUint32())
			{
				//weird
				NS_ASSERT (false);
			}

			if (local_gsa_r->GetSpi() != gsa_r_proposal->GetSpi()->ToUint32())
			{
				//weird
				NS_ASSERT (false);
			}
		}
	}
}

void
GsamL4Protocol::RejectGsaQ (Ptr<GsamSession> session,
							uint32_t gsa_push_id,
							const IkeTrafficSelector& ts_src,
							const IkeTrafficSelector& ts_dest,
							const Ptr<IkeSaProposal> gsa_q_proposal)
{
	NS_LOG_FUNCTION (this);

	//setting up payload contains rejected spi
	Ptr<IkeGroupNotifySubstructure> reject_gsa_q_spi_notify_substructure = IkeGroupNotifySubstructure::GenerateEmptyGroupNotifySubstructure(GsamConfig::GetDefaultGSAProposalId(),
																															IpSec::AH_ESP_SPI_SIZE,
																															IkeGroupNotifySubstructure::GSA_Q_SPI_REJECTION,
																															gsa_push_id,
																															ts_src,
																															ts_dest);
	Ptr<Spi> reject_gsa_q_spi = Create<Spi>();
	reject_gsa_q_spi->SetValueFromUint32(gsa_q_proposal->GetSpi()->ToUint32());
	reject_gsa_q_spi_notify_substructure->InsertSpi(reject_gsa_q_spi);
	IkePayload reject_gsa_q_spi_notify_payload;
	reject_gsa_q_spi_notify_payload.SetSubstructure(reject_gsa_q_spi_notify_substructure);

	uint32_t length_beside_ikeheader = reject_gsa_q_spi_notify_payload.GetSerializedSize();

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(reject_gsa_q_spi_notify_payload);

	this->SendPhaseTwoMessage(session,
			IkeHeader::INFORMATIONAL,
			true,
			reject_gsa_q_spi_notify_payload.GetPayloadType(),
			length_beside_ikeheader,
			packet, false);
}

void
GsamL4Protocol::AcceptGsaPair (	Ptr<GsamSession> session,
								uint32_t gsa_push_id,
								const IkeTrafficSelector& ts_src,
								const IkeTrafficSelector& ts_dest,
								const Ptr<IkeSaProposal> gsa_q_proposal,
								const Ptr<IkeSaProposal> gsa_r_proposal)
{
	NS_LOG_FUNCTION (this);
	this->InstallGsaPair(session, ts_src, ts_dest, gsa_q_proposal, gsa_r_proposal);
	this->SendAcceptAck(session, gsa_push_id, ts_src, ts_dest, gsa_q_proposal, gsa_r_proposal);
}

void
GsamL4Protocol::InstallGsaPair (Ptr<GsamSession> session,
								const IkeTrafficSelector& ts_src,
								const IkeTrafficSelector& ts_dest,
								const Ptr<IkeSaProposal> gsa_q_proposal,
								const Ptr<IkeSaProposal> gsa_r_proposal)
{
	NS_LOG_FUNCTION (this);
	Ipv4Address group_address = session->GetGroupAddress();
	if (ts_dest.GetStartingAddress() != group_address)
	{
		NS_ASSERT (false);
	}
	if (ts_dest.GetEndingAddress() != group_address)
	{
		NS_ASSERT (false);
	}
	Ptr<Spi> gsa_q_spi = gsa_q_proposal->GetSpi();
	Ptr<Spi> gsa_r_spi = gsa_r_proposal->GetSpi();
	Ptr<IpSecPolicyEntry> policy = session->GetRelatedPolicy();

	if (policy == 0)
	{
		//policy should be created during phase 1 auth
		NS_ASSERT (false);
	}
	else
	{
		IkeTrafficSelector policy_ts_src = policy->GetTrafficSelectorSrc();
		if (policy_ts_src != ts_src)
		{
			NS_ASSERT (false);
		}
		IkeTrafficSelector policy_ts_dest = policy->GetTrafficSelectorDest();
		if (policy_ts_dest != ts_dest)
		{
			NS_ASSERT (false);
		}

		Ptr<IpSecSAEntry> gsa_q = policy->GetInboundSAD()->CreateIpSecSAEntry(gsa_q_spi->ToUint32());
		session->AssociateGsaQ(gsa_q);

		Ptr<IpSecSAEntry> gsa_r = policy->GetOutboundSAD()->CreateIpSecSAEntry(gsa_r_spi->ToUint32());
		session->SetRelatedGsaR(gsa_r);
	}

}

void
GsamL4Protocol::SendAcceptAck (	Ptr<GsamSession> session,
								uint32_t gsa_push_id,
								const IkeTrafficSelector& ts_src,
								const IkeTrafficSelector& ts_dest,
								const Ptr<IkeSaProposal> gsa_q_proposal,
								const Ptr<IkeSaProposal> gsa_r_proposal)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session, gsa_push_id);

	Ptr<IkeGroupNotifySubstructure> ack_notify_substructure = IkeGroupNotifySubstructure::GenerateEmptyGroupNotifySubstructure(	GsamConfig::GetDefaultGSAProposalId(),
																																IpSec::AH_ESP_SPI_SIZE,
																																IkeGroupNotifySubstructure::GSA_ACKNOWLEDGEDMENT,
																																gsa_push_id,
																																ts_src,
																																ts_dest);
	IkePayload ack_notify_payload;
	ack_notify_payload.SetSubstructure(ack_notify_substructure);

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(ack_notify_payload);

	this->SendPhaseTwoMessage(session,
			IkeHeader::INFORMATIONAL,
			true,
			ack_notify_payload.GetPayloadType(),
			ack_notify_payload.GetSerializedSize(),
			packet,
			false);

	Ptr<Igmpv3L4Protocol> igmp = Igmpv3L4Protocol::GetIgmp(this->m_node);
	Time dt = GsamConfig::GetSingleton()->GetSigmpReportDelayAfterGsamInMilliSeconds();
	Simulator::Schedule (dt,
						&Igmpv3L4Protocol::SendSecureStateChangesReport,
						igmp,
						igmp->GetManager()->GetIfStateManager(session->GetIgmpInterface()),
						session->GetGroupAddress());
//	igmp->SendStateChangesReport(igmp->GetManager()->GetIfStateManager(session->GetIgmpInterface()), session->GetGroupAddress());

}

void
GsamL4Protocol::ProcessGsaPushNQForOneGrp (	Ptr<GsamSession> session,
									uint32_t gsa_push_id,
									const IkeTrafficSelector& ts_src,
									const IkeTrafficSelector& ts_dest,
									const std::list<Ptr<IkeSaProposal> >& gsa_proposals,
									std::list<Ptr<IkePayloadSubstructure> >& retval_toreject_payload_subs)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session, gsa_push_id);

	if (gsa_proposals.size() == 0)
	{
		//Maybe ok?
		//empty session group
		//probably Q is waiting for reply from designated GM
	}
	else if ((gsa_proposals.size() % 2) == 1)
	{
		//not ok
		NS_ASSERT (false);
	}
	else //(gsa_proposals.size() >= 2)
	{
		//ok
	}

	//intermediate results
	std::list<uint32_t> lst_u32_gsa_q_spis_to_install;
	std::list<uint32_t> lst_u32_gsa_r_spis_to_reject;
	std::list<uint32_t> lst_u32_gsa_r_spis_to_install;

	for (	std::list<Ptr<IkeSaProposal> >::const_iterator const_it = gsa_proposals.begin();
			const_it != gsa_proposals.end();
			const_it++)
	{
		const Ptr<IkeGsaProposal> gsa_proposal = DynamicCast<IkeGsaProposal>(*const_it);

		if (true == gsa_proposal->IsNewGsaQ())
		{
			Ptr<Spi> gsa_q_proposal_spi = gsa_proposal->GetSpi();
			lst_u32_gsa_q_spis_to_install.push_back(gsa_q_proposal_spi->ToUint32());
			GsamConfig::LogGsaQ ("Accepting", gsa_q_proposal_spi->ToUint32());
		}
		else if (true == gsa_proposal->IsNewGsaR())
		{
			//check whether incoming spi is in conflict
			Ptr<Spi> gsa_r_proposal_spi = gsa_proposal->GetSpi();
			Ptr<GsamInfo> local_gsam_info = session->GetDatabase()->GetInfo();
			if (true == local_gsam_info->IsIpsecSpiOccupied(gsa_r_proposal_spi->ToUint32()))
			{
				//spis to reject
				lst_u32_gsa_r_spis_to_reject.push_back(gsa_r_proposal_spi->ToUint32());
			}
			else
			{
				//Fake Reject
				if (false == GsamConfig::IsFalseByPercentage(GsamConfig::GetSingleton()->GetSpiRejectPropability()))
				{
					this->FakeRejection(session, gsa_r_proposal_spi->ToUint32());
					lst_u32_gsa_r_spis_to_reject.push_back(gsa_r_proposal_spi->ToUint32());
				}
				else
				{
					//spis to install
					lst_u32_gsa_r_spis_to_install.push_back(gsa_r_proposal_spi->ToUint32());
					GsamConfig::LogGsaR("Accepting", gsa_r_proposal_spi->ToUint32());
				}
			}
		}
		else
		{
			NS_ASSERT (false);
		}
	}

	//check the number of 3 spi list
	if (lst_u32_gsa_q_spis_to_install.size() != 1)
	{
		//has more than 1 gsa_q, error
		NS_ASSERT (false);
	}

	if (lst_u32_gsa_r_spis_to_reject.size() > 0)
	{
		//has conflict spis
		//add spis to reject to retval
		this->RejectGsaR(session, gsa_push_id, ts_src, ts_dest, lst_u32_gsa_r_spis_to_reject, retval_toreject_payload_subs);
	}
	else
	{
		//no conflict spis

		//establish session_group and policy
		Ipv4Address group_address = ts_dest.GetEndingAddress();
		Ptr<GsamSessionGroup> session_group = session->GetDatabase()->GetSessionGroup(group_address);

		if (session_group->GetRelatedPolicy() != 0)
		{
			//nq should not have policy of that group address installed
			//duplicate check should have been performed by caller method
			//NS_ASSERT (false);
			//aserrt had been reached here
			//maybe a join for the same group has been invoked
			//**************************************
			if (session_group->GetRelatedGsaQ() == 0)
			{
				NS_ASSERT (false);
			}
		}
		else
		{
			if (session_group->GetRelatedGsaQ() != 0)
			{
				NS_ASSERT (false);
			}
			session_group->EtablishPolicy(ts_src, ts_dest, GsamConfig::GetDefaultIpsecProtocolId(), IpSec::PROTECT, GsamConfig::GetDefaultIpsecMode());
			for (std::list<uint32_t>::const_iterator const_it = lst_u32_gsa_q_spis_to_install.begin();
					const_it != lst_u32_gsa_q_spis_to_install.end();
					const_it++)
			{
				session_group->InstallGsaQ(*const_it);
			}
		}

		//install gsa_q and gsa_r(s)

		if (session_group->GetSessionsConst().size() != 0)
		{
			NS_ASSERT (false);
		}

		for (std::list<uint32_t>::const_iterator const_it = lst_u32_gsa_r_spis_to_install.begin();
				const_it != lst_u32_gsa_r_spis_to_install.end();
				const_it++)
		{
			session_group->InstallGsaR(*const_it);
		}
	}
}

void
GsamL4Protocol::HandleGsaAckRejectSpiResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	session->GetRetransmitTimer().Cancel();

	if (session->GetGroupAddress() == GsamConfig::GetIgmpv3DestGrpReportAddress())
	{
		this->HandleGsaAckRejectSpiResponseFromNQ(packet, ikeheader, session);
	}
	else
	{
		this->HandleGsaAckRejectSpiResponseFromGM(packet, ikeheader, session);
	}
}

void
GsamL4Protocol::HandleGsaAckRejectSpiResponseFromGM (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	IkePayloadHeader::PAYLOAD_TYPE first_payload_type = ikeheader.GetNextPayloadType();

	if (first_payload_type == IkePayloadHeader::GROUP_NOTIFY)
	{
		IkePayload fisrt_group_notify_payload = IkePayload::GetEmptyPayloadFromPayloadType(IkePayloadHeader::GROUP_NOTIFY);
		packet->RemoveHeader(fisrt_group_notify_payload);
		Ptr<IkeGroupNotifySubstructure> fisrt_group_notify_sub = DynamicCast<IkeGroupNotifySubstructure>(fisrt_group_notify_payload.GetSubstructure());

		uint8_t first_group_notify_type = fisrt_group_notify_sub->GetNotifyMessageType();
		if (first_group_notify_type == IkeGroupNotifySubstructure::GSA_ACKNOWLEDGEDMENT)
		{
			Ipv4Address group_address = GsamUtility::CheckAndGetGroupAddressFromTrafficSelectors(fisrt_group_notify_sub->GetTrafficSelectorSrc(),
																									fisrt_group_notify_sub->GetTrafficSelectorDest());
			if (group_address.Get() != session->GetGroupAddress().Get())
			{
				NS_ASSERT(false);
			}
			this->HandleGsaAckFromGM(packet, fisrt_group_notify_payload, session);
		}
		else if (first_group_notify_type == IkeGroupNotifySubstructure::GSA_Q_SPI_REJECTION)
		{
			Ipv4Address group_address = GsamUtility::CheckAndGetGroupAddressFromTrafficSelectors(fisrt_group_notify_sub->GetTrafficSelectorSrc(),
																									fisrt_group_notify_sub->GetTrafficSelectorDest());
			if (group_address.Get() != session->GetGroupAddress().Get())
			{
				NS_ASSERT(false);
			}
			this->HandleGsaRejectionFromGM(packet, fisrt_group_notify_payload, session);
		}
		else if (first_group_notify_type == IkeGroupNotifySubstructure::GSA_Q_SPI_NOTIFICATION)
		{
			this->HandleGsaSpiNotificationFromGM(packet, fisrt_group_notify_payload, session);
		}
		else
		{
			NS_LOG_FUNCTION (false);
		}
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
GsamL4Protocol::HandleGsaAckFromGM (Ptr<Packet> packet, const IkePayload& first_payload, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	if (first_payload.GetNextPayloadType() != IkePayloadHeader::NO_NEXT_PAYLOAD)
	{
		NS_ASSERT (false);
	}

	Ptr<IkeGroupNotifySubstructure> first_payload_sub = DynamicCast<IkeGroupNotifySubstructure>(first_payload.GetSubstructure());

	uint32_t first_payload_gsa_push_id = first_payload_sub->GetGsaPushId();

	if (true == session->GetInfo()->IsGsaPushIdDeleted(first_payload_gsa_push_id))
	{
		GsamConfig::GetSingleton()->LogMsg("Incoming gsa push id belongs was deleted");
		return;
	}
	else
	{

	}

	if (false == session->GetInfo()->IsGsaPushIdDeleted(first_payload_gsa_push_id))
	{
		Ptr<GsaPushSession> gsa_push_session = session->GetGsaPushSession();
		if (gsa_push_session->GetStatus() == GsaPushSession::GSA_PUSH_ACK)
		{
			gsa_push_session->MarkGmSessionReplied();

			if (true == gsa_push_session->IsAllReplied())
			{
				GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session, gsa_push_session->GetId());
				gsa_push_session->InstallGsaPair();
				gsa_push_session->SelfRemoval();
				Ptr<Igmpv3L4Protocol> igmp = Igmpv3L4Protocol::GetIgmp(this->m_node);
				if (0 == igmp)
				{
					NS_ASSERT (false);
				}
				Ipv4Address group_address = session->GetGroupAddress();
				igmp->SendSecureGroupSpecificQuery(group_address);
			}
		}
		else if (gsa_push_session->GetStatus() == GsaPushSession::SPI_CONFLICT_RESOLVE)
		{
			//do nothing
		}
		else
		{
			NS_ASSERT (false);
		}
	}
	else
	{
		//ignore
	}
}

void
GsamL4Protocol::HandleGsaRejectionFromGM (Ptr<Packet> packet, const IkePayload& first_payload, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	if (first_payload.GetNextPayloadType() != IkePayloadHeader::NO_NEXT_PAYLOAD)
	{
		NS_ASSERT (false);
	}

	Ptr<IkeGroupNotifySubstructure> first_payload_sub = DynamicCast<IkeGroupNotifySubstructure>(first_payload.GetSubstructure());

	if (first_payload_sub->GetSpiSize() != IpSec::AH_ESP_SPI_SIZE)
	{
		NS_ASSERT (false);
	}

	const std::set<uint32_t>& lst_spi_first_payload_sub = first_payload_sub->GetSpis();

	if (lst_spi_first_payload_sub.size() != 1)
	{
		NS_ASSERT (false);
	}

	if (false == session->GetInfo()->IsGsaPushIdDeleted(first_payload_sub->GetGsaPushId()))
	{
		Ptr<GsaPushSession> gsa_push_session = session->GetGsaPushSession();
		GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session, gsa_push_session->GetId());
		uint32_t gsa_q = *(lst_spi_first_payload_sub.begin());

		if (gsa_q != gsa_push_session->GetGsaQ()->GetSpi())
		{
			NS_ASSERT (false);
		}

		if (gsa_push_session->GetId() != first_payload_sub->GetGsaPushId())
		{
			NS_ASSERT (false);
		}
		this->Send_SPI_REQUEST(session->GetGsaPushSession(), GsaPushSession::GSA_Q_SPI_REQUEST);
	}
	else
	{
		//ignore
	}
}

void
GsamL4Protocol::HandleGsaSpiNotificationFromGM (Ptr<Packet> packet, const IkePayload& first_payload, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	Ptr<IkeGroupNotifySubstructure> first_payload_sub = DynamicCast<IkeGroupNotifySubstructure>(first_payload.GetSubstructure());

	if (first_payload_sub->GetTrafficSelectorSrc().GetStartingAddress().Get() != 0)
	{
		//has to be 0
		NS_ASSERT (false);
	}
	if (first_payload_sub->GetTrafficSelectorSrc().GetEndingAddress().Get() != 0)
	{
		//has to be 0
		NS_ASSERT (false);
	}
	if (first_payload_sub->GetTrafficSelectorDest().GetStartingAddress().Get() != 0)
	{
		//has to be 0
		NS_ASSERT (false);
	}
	if (first_payload_sub->GetTrafficSelectorDest().GetEndingAddress().Get() != 0)
	{
		//has to be 0
		NS_ASSERT (false);
	}

	if (IpSec::AH_ESP_SPI_SIZE != first_payload_sub->GetSpiSize())
	{
		NS_ASSERT (false);
	}

	const std::set<uint32_t> first_payload_spis = first_payload_sub->GetSpis();

	Ptr<GsaPushSession> gsa_push_session = 0;
	uint32_t payload_gsa_push_id = first_payload_sub->GetGsaPushId();
	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session, payload_gsa_push_id);

	if (true == session->GetInfo()->IsGsaPushIdDeleted(payload_gsa_push_id))
	{
		GsamConfig::GetSingleton()->LogMsg("Incoming gsa push id belongs was deleted");
		return;
	}
	else
	{
		//ok
	}

	if (false == session->GetInfo()->IsGsaPushIdDeleted(payload_gsa_push_id))
	{
		if (payload_gsa_push_id == session->GetGsaPushSession()->GetId())
		{
			//gm session
			gsa_push_session = session->GetGsaPushSession();
			if (gsa_push_session->GetStatus() == GsaPushSession::GSA_PUSH_ACK)
			{
				NS_ASSERT (false);
			}

			gsa_push_session->MarkGmSessionReplied();
		}
		else
		{
			//other gm session for gsa q spi request
			gsa_push_session = session->GetGsaPushSession(payload_gsa_push_id);
			if (0 == gsa_push_session)
			{
				return;
			}
			else
			{
				//ok
			}
			if (gsa_push_session->GetStatus() == GsaPushSession::GSA_PUSH_ACK)
			{
				NS_ASSERT (false);
			}
			gsa_push_session->MarkOtherGmSessionReplied(session);
		}

		gsa_push_session->AggregateGsaQSpiNotification(first_payload_spis);

		if (gsa_push_session->IsAllReplied())
		{
			//create new spis base on what is received and modify those IpSecSAEntry
			gsa_push_session->GenerateNewSpisAndModifySa();
			//and then send Gsa repush
			this->Send_GSA_RE_PUSH(gsa_push_session);
		}
	}
	else
	{
		//ignore
	}
}

void
GsamL4Protocol::HandleGsaAckRejectSpiResponseFromNQ (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	IkePayloadHeader::PAYLOAD_TYPE first_payload_type = ikeheader.GetNextPayloadType();

	if (first_payload_type == IkePayloadHeader::GROUP_NOTIFY)
	{
		IkePayload fisrt_group_notify_payload = IkePayload::GetEmptyPayloadFromPayloadType(first_payload_type);
		packet->RemoveHeader(fisrt_group_notify_payload);
		Ptr<IkeGroupNotifySubstructure> fisrt_group_notify_sub = DynamicCast<IkeGroupNotifySubstructure>(fisrt_group_notify_payload.GetSubstructure());

		uint8_t first_group_notify_type = fisrt_group_notify_sub->GetNotifyMessageType();
		uint32_t gsa_push_id = fisrt_group_notify_sub->GetGsaPushId();

		packet->AddHeader(fisrt_group_notify_payload);
		if (first_group_notify_type == IkeGroupNotifySubstructure::GSA_ACKNOWLEDGEDMENT)
		{
			if (0 == gsa_push_id)
			{
				this->HandleGsaAckFromNQ(packet, session);
			}
			else
			{
				Ptr<GsaPushSession> gsa_push_session = session->GetGsaPushSession(gsa_push_id);
				if (0 == gsa_push_session)
				{
					return;
				}
				else
				{
					//ok
				}
				this->HandleGsaAckFromNQ (packet, session, gsa_push_session);
			}

		}
		else if (first_group_notify_type == IkeGroupNotifySubstructure::GSA_R_SPI_REJECTION)
		{
			if (0 == gsa_push_id)
			{
				this->HandleGsaRejectionFromNQ(packet, session);
			}
			else
			{
				Ptr<GsaPushSession> gsa_push_session = session->GetGsaPushSession(gsa_push_id);
				if (0 == gsa_push_session)
				{
					return;
				}
				else
				{
					//ok
				}
				this->HandleGsaRejectionFromNQ(packet, session, gsa_push_session);
			}
		}
		else if (first_group_notify_type == IkeGroupNotifySubstructure::GSA_R_SPI_NOTIFICATION)
		{
			if (0 == gsa_push_id)
			{
				NS_ASSERT (false);
			}
			else
			{
				this->HandleGsaSpiNotificationFromNQ(packet, session);
			}
		}
		else
		{
			NS_LOG_FUNCTION (false);
		}
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
GsamL4Protocol::HandleGsaAckFromNQ (Ptr<Packet> packet, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);
	IkePayload ack_payload = IkePayload::GetEmptyPayloadFromPayloadType(IkePayloadHeader::GROUP_NOTIFY);
	packet->RemoveHeader(ack_payload);

	Ptr<IkeGroupNotifySubstructure> ack_payload_sub = DynamicCast<IkeGroupNotifySubstructure>(ack_payload.GetSubstructure());


		//do nothing
		//Q just sends what it already has to NQ

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);
}

void
GsamL4Protocol::HandleGsaAckFromNQ (Ptr<Packet> packet, Ptr<GsamSession> session, Ptr<GsaPushSession> gsa_push_session)
{
	NS_LOG_FUNCTION (this);
	IkePayload ack_payload = IkePayload::GetEmptyPayloadFromPayloadType(IkePayloadHeader::GROUP_NOTIFY);
	packet->RemoveHeader(ack_payload);

	Ptr<IkeGroupNotifySubstructure> ack_payload_sub = DynamicCast<IkeGroupNotifySubstructure>(ack_payload.GetSubstructure());

	if (gsa_push_session->GetStatus() == GsaPushSession::GSA_PUSH_ACK)
	{
		gsa_push_session->MarkNqSessionReplied(session);
		if (true == gsa_push_session->IsAllReplied())
		{
			GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session, gsa_push_session->GetId());
			gsa_push_session->InstallGsaPair();
			gsa_push_session->SelfRemoval();
			Ptr<Igmpv3L4Protocol> igmp = Igmpv3L4Protocol::GetIgmp(this->m_node);
			if (0 == igmp)
			{
				NS_ASSERT (false);
			}
			Ipv4Address group_address = gsa_push_session->GetGmSession()->GetGroupAddress();
			igmp->SendSecureGroupSpecificQuery(group_address);
		}
	}
	else if (gsa_push_session->GetStatus() == GsaPushSession::SPI_CONFLICT_RESOLVE)
	{
		//ignore
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
GsamL4Protocol::HandleGsaRejectionFromNQ (Ptr<Packet> packet, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);
	//There should be no gsa push session attached to the nq session on the Q, yet.
	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);
	Ptr<GsaPushSession> gsa_push_session = this->m_ptr_database->CreateGsaPushSession();
	gsa_push_session->SetStatus(GsaPushSession::GSA_PUSH_ACK);

	IkePayloadHeader::PAYLOAD_TYPE next_payload_type = IkePayloadHeader::NO_NEXT_PAYLOAD;

	do {
		IkePayload gsa_rejection_payload = IkePayload::GetEmptyPayloadFromPayloadType(IkePayloadHeader::GROUP_NOTIFY);
		packet->RemoveHeader(gsa_rejection_payload);
		IkePayloadHeader::PAYLOAD_TYPE this_payload_type = gsa_rejection_payload.GetPayloadType();

		if (this_payload_type != IkePayloadHeader::GROUP_NOTIFY)
		{
			NS_ASSERT (false);
		}

		Ptr<IkeGroupNotifySubstructure> gsa_rejection_sub = DynamicCast<IkeGroupNotifySubstructure>(gsa_rejection_payload.GetSubstructure());

		if (0 == gsa_rejection_sub->GetSpiNum())
		{
			NS_ASSERT (false);
		}

		if (IpSec::AH_ESP_SPI_SIZE != gsa_rejection_sub->GetSpiSize())
		{
			NS_ASSERT (false);
		}

		if (0 != gsa_rejection_sub->GetGsaPushId())
		{
			NS_ASSERT (false);
		}

		gsa_push_session->PushBackNqRejectionGroupNotifySub(gsa_rejection_sub);

		next_payload_type = gsa_rejection_payload.GetNextPayloadType();
	} while (next_payload_type != IkePayloadHeader::NO_NEXT_PAYLOAD);

	this->Send_SPI_REQUEST(gsa_push_session, GsaPushSession::GSA_R_SPI_REQUEST);
}

void
GsamL4Protocol::HandleGsaRejectionFromNQ (Ptr<Packet> packet, Ptr<GsamSession> session, Ptr<GsaPushSession> gsa_push_session)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session, gsa_push_session->GetId());

	IkePayloadHeader::PAYLOAD_TYPE next_payload_type = IkePayloadHeader::GROUP_NOTIFY;

	do {
		IkePayload gsa_rejection_payload = IkePayload::GetEmptyPayloadFromPayloadType(next_payload_type);
		packet->RemoveHeader(gsa_rejection_payload);

		Ptr<IkeGroupNotifySubstructure> gsa_rejection_sub = DynamicCast<IkeGroupNotifySubstructure>(gsa_rejection_payload.GetSubstructure());

		if (0 == gsa_rejection_sub->GetSpiNum())
		{
			NS_ASSERT (false);
		}

		if (IpSec::AH_ESP_SPI_SIZE != gsa_rejection_sub->GetSpiSize())
		{
			NS_ASSERT (false);
		}

		if (gsa_push_session->GetId() != gsa_rejection_sub->GetGsaPushId())
		{
			NS_ASSERT (false);
		}

		gsa_push_session->PushBackNqRejectionGroupNotifySub(gsa_rejection_sub);

		next_payload_type = gsa_rejection_payload.GetNextPayloadType();
	} while (next_payload_type != IkePayloadHeader::NO_NEXT_PAYLOAD);

	this->Send_SPI_REQUEST(gsa_push_session, GsaPushSession::GSA_R_SPI_REQUEST);
}

void
GsamL4Protocol::HandleGsaSpiNotificationFromNQ (Ptr<Packet> packet, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), session);

	IkePayloadHeader::PAYLOAD_TYPE next_payload_type = IkePayloadHeader::NO_NEXT_PAYLOAD;
	uint32_t gsa_push_id = 0;
	Ptr<GsaPushSession> gsa_push_session = 0;
	do {
		IkePayload spi_notify_payload = IkePayload::GetEmptyPayloadFromPayloadType(IkePayloadHeader::GROUP_NOTIFY);
		packet->RemoveHeader(spi_notify_payload);

		Ptr<IkeGroupNotifySubstructure> gsa_rejection_sub = DynamicCast<IkeGroupNotifySubstructure>(spi_notify_payload.GetSubstructure());

		if (0 == gsa_push_id)
		{
			//ok
			//1st while iterration
			gsa_push_id = gsa_rejection_sub->GetGsaPushId();
		}
		else if (gsa_push_id == gsa_rejection_sub->GetGsaPushId())
		{
			//ok
		}
		else
		{
			NS_ASSERT (false);
		}

		if (0 == gsa_push_session)
		{
			gsa_push_session = session->GetGsaPushSession(gsa_push_id);
			if (0 == gsa_push_session)
			{
				return;
			}
			else
			{
				//ok
			}
			std::cout << " GsaPush Id: " << gsa_push_session->GetId() << std::endl;
		}

		if (gsa_push_session->GetStatus() == GsaPushSession::GSA_PUSH_ACK)
		{
			NS_ASSERT (false);
		}

		gsa_push_session->AggregateGsaRSpiNotification(gsa_rejection_sub->GetSpis());

		next_payload_type = spi_notify_payload.GetNextPayloadType();
	} while (next_payload_type != IkePayloadHeader::NO_NEXT_PAYLOAD);

	gsa_push_session->MarkNqSessionReplied(session);
	if (true == gsa_push_session->IsAllReplied())
	{
		this->ProcessGsaSpiNotificationFromNQ(gsa_push_session);
	}
}

void
GsamL4Protocol::ProcessGsaSpiNotificationFromNQ (Ptr<GsaPushSession> gsa_push_session)
{
	NS_LOG_FUNCTION (this);

	GsamConfig::Log(__FUNCTION__, this->m_node->GetId(), gsa_push_session->GetId());

	if (0 == gsa_push_session)
	{
		NS_ASSERT (false);
	}

	if (0 == gsa_push_session->GetGmSession())
	{
		//send all info update to NQs sessions
		//send GM related parts of info to GM sessions
		Ptr<Packet> retval_packet_without_ikeheader_for_nqs = Create<Packet>();
		std::list<std::pair<Ptr<GsamSession>, Ptr<Packet> > > retval_lst_gm_session_packet_without_ikeheader_bundles;

		gsa_push_session->AlterRejectedGsaAndAggregatePacket(	retval_packet_without_ikeheader_for_nqs,
																retval_lst_gm_session_packet_without_ikeheader_bundles);

		for(std::list<std::pair<Ptr<GsamSession>, Ptr<Packet> > >::const_iterator const_it = retval_lst_gm_session_packet_without_ikeheader_bundles.begin();
				const_it != retval_lst_gm_session_packet_without_ikeheader_bundles.end();
				const_it++)
		{
			Ptr<GsamSession> gm_session = const_it->first;
			Ptr<Packet> packet_to_gm = const_it->second;

			if (0 == gm_session)
			{
				NS_ASSERT (false);
			}

			if (0 == packet_to_gm)
			{
				NS_ASSERT (false);
			}

			this->SendPhaseTwoMessage(	gm_session,
										IkeHeader::CREATE_CHILD_SA,
										false,
										IkePayloadHeader::GSA_REPUSH,
										packet_to_gm->GetSize(),
										packet_to_gm,
										true);
		}

		for (std::set<Ptr<GsamSession> >::const_iterator const_it = gsa_push_session->GetNqSessions().begin();
				const_it != gsa_push_session->GetNqSessions().end();
				const_it++)
		{
			Ptr<GsamSession> nq_session = *const_it;

			if (0 == nq_session)
			{
				NS_ASSERT (false);
			}

			this->SendPhaseTwoMessage(	nq_session,
										IkeHeader::CREATE_CHILD_SA,
										false,
										IkePayloadHeader::GSA_REPUSH,
										retval_packet_without_ikeheader_for_nqs->GetSize(),
										retval_packet_without_ikeheader_for_nqs,
										true);
		}
	}
	else
	{
		//install Gsa
		//send revised spi q, spi r, if exists, to new GM and all other GMs of the same group, if they exist.
		//send revised spi q, spi r to all NQs
		gsa_push_session->GenerateNewSpisAndModifySa();
		this->Send_GSA_RE_PUSH(gsa_push_session);
	}
}

Ptr<Igmpv3L4Protocol>
GsamL4Protocol::GetIgmp (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->m_node == 0)
	{
		NS_ASSERT (false);
	}

	Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);

	return ipv4l3->GetIgmp();
}

Ptr<IpSecDatabase>
GsamL4Protocol::GetIpSecDatabase (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_database == 0)
	{
		this->m_ptr_database = Create<IpSecDatabase>();
		this->m_ptr_database->SetGsam(this);
	}

	return this->m_ptr_database;
}

void
GsamL4Protocol::CreateIpSecPolicy (Ptr<GsamSession> session, const IkeTrafficSelector& tsi, const IkeTrafficSelector& tsr)
{
	NS_LOG_FUNCTION (this);

	if (tsi.GetProtocolId() != tsr.GetProtocolId())
	{
		NS_ASSERT (false);
	}

	Ptr<IpSecPolicyDatabase> spd = session->GetDatabase()->GetPolicyDatabase();
	Ptr<IpSecPolicyEntry> policy_entry = spd->CreatePolicyEntry();
	policy_entry->SetProcessChoice(IpSec::PROTECT);
	policy_entry->SetIpsecMode(GsamConfig::GetDefaultIpsecMode());
	policy_entry->SetSrcAddressRange(tsi.GetStartingAddress(), tsi.GetEndingAddress());
	policy_entry->SetTranSrcPortRange(tsi.GetStartPort(), tsi.GetEndPort());
	policy_entry->SetProtocolNum(tsr.GetProtocolId());
	policy_entry->SetDestAddressRange(tsr.GetStartingAddress(), tsr.GetStartingAddress());
	policy_entry->SetTranDestPortRange(tsr.GetStartPort(), tsr.GetEndPort());

	if (policy_entry->GetDestAddress() == session->GetGroupAddress())
	{
		if (session->GetGroupAddress() == GsamConfig::GetIgmpv3DestGrpReportAddress())
		{
			NS_ASSERT (false);
		}
		else
		{
			session->AssociateWithPolicy(policy_entry);
		}
	}
	else
	{
		if (session->IsHostNonQuerier())
		{
			Ptr<IpSecDatabase> root_database = session->GetDatabase();
			Ptr<GsamSessionGroup> session_group = root_database->GetSessionGroup(policy_entry->GetDestAddress());
			Ptr<IpSecPolicyEntry> session_group_policy = session_group->GetRelatedPolicy();
			if (session_group_policy == 0)
			{
				//it means this NQs first time receive a GSA_PUSH about this group address
				session_group->AssociateWithPolicy(policy_entry);
			}
			else
			{
				//it means that this session_group is already bound to a policy
				//this is irrelevant to this session_group's GSA_Q or any GSA_R bound to this session_group
			}
		}
		else
		{
			//something went wrong
			NS_ASSERT (false);
		}
	}
}

void
GsamL4Protocol::CreateIpSecPolicy (	Ptr<GsamSession> session,
									const std::list<IkeTrafficSelector>& tsi_selectors,
									const std::list<IkeTrafficSelector>& tsr_selectors)
{
	NS_LOG_FUNCTION (this);

	for (	std::list<IkeTrafficSelector>::const_iterator const_it_tsi_selector = tsi_selectors.begin();
			const_it_tsi_selector != tsi_selectors.end();
			const_it_tsi_selector++)
	{
		for (	std::list<IkeTrafficSelector>::const_iterator const_it_tsr_selector = tsr_selectors.begin();
				const_it_tsr_selector != tsr_selectors.end();
				const_it_tsr_selector++)
		{
			session->GetSessionGroup()->EtablishPolicy(*const_it_tsi_selector,
														*const_it_tsr_selector,
														IpSec::IP_ID_AH,
														IpSec::PROTECT,
														GsamConfig::GetDefaultIpsecMode());
		}
	}
}

Ptr<IkeSaProposal>
GsamL4Protocol::ChooseSAProposalOffer (	const std::list<Ptr<IkeSaProposal> >& proposals)
{
	if (proposals.size() == 0)
	{
		NS_ASSERT(false);
	}

	return proposals.front();
}

void
GsamL4Protocol::NarrowTrafficSelectors (const std::list<IkeTrafficSelector>& tsi_selectors,
												std::list<IkeTrafficSelector>& retval_narrowed_tsi_selectors)
{
	std::copy(tsi_selectors.begin(), tsi_selectors.end(),
	          std::back_insert_iterator<std::list<IkeTrafficSelector> >(retval_narrowed_tsi_selectors));
}

const Ptr<Node>
GsamL4Protocol::GetNode (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_node;
}

Ptr<GsamFilter>
GsamL4Protocol::GetGsamFilter (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_gsam_filter;
}

Ptr<GsamL4Protocol>
GsamL4Protocol::GetGsam (Ptr<Node> node)
{
	Ptr<GsamL4Protocol> retval = Igmpv3L4Protocol::GetIgmp(node)->GetGsam();
	return retval;
}

} /* namespace ns3 */
