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
		break;
	case IkeHeader::INFORMATIONAL:
		this->HandleGsaInformational(packet, ikeheader, peer_address);
		break;
	default:
		break;
	}
}

void
GsamL4Protocol::Send_IKE_SA_INIT (Ptr<GsamSession> session)
{
	//rfc 5996 page 10
	NS_LOG_FUNCTION (this);

	if (0 != session->GetCurrentMessageId())
	{
		NS_ASSERT (false);
	}
	else
	{
		session->SetMessageId(0);
	}

	//setting up Ni
	IkePayload nonce_payload_init;
	nonce_payload_init.SetSubstructure(IkeNonceSubstructure::GenerateNonceSubstructure());
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
	session->SetPhaseOneRole(GsamSession::INITIATOR);
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

	this->DoSendMessage(session, packet, true);
}

void
GsamL4Protocol::Send_IKE_SA_AUTH (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	if (0 != session->GetCurrentMessageId())
	{
		NS_ASSERT (false);
	}
	else
	{
		session->SetMessageId(1);
	}

	//Setting up TSr
	IkePayload tsr;
	tsr.SetSubstructure(IkeTrafficSelectorSubstructure::GenerateEmptySubstructure(true));
	//settuping up tsi
	IkePayload tsi;
	tsi.SetSubstructure(IkeTrafficSelectorSubstructure::GenerateEmptySubstructure(false));
	tsi.SetNextPayloadType(tsr.GetPayloadType());
	//setting up sai2
	IkePayload sai2;
	Spi kek_sa_spi;
	kek_sa_spi.SetValueFromUint64(session->GetInfo()->RegisterGsamSpi());
	sai2.SetSubstructure(IkeSaPayloadSubstructure::GenerateAuthIkePayload(kek_sa_spi));
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
	session->SetKekSaInitiatorSpi(kek_sa_spi.ToUint64());

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(tsr);
	packet->AddHeader(tsi);
	packet->AddHeader(sai2);
	packet->AddHeader(auth);

	uint32_t length_beside_hedaer = auth.GetSerializedSize() +
									sai2.GetSerializedSize() +
									tsi.GetSerializedSize() +
									tsr.GetSerializedSize();

	this->SendMessage(	session,
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
		session->IncrementMessageId();
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

	Ptr<GsaPushSession> gsa_push_session = this->m_ptr_database->CreateGsaPushSession();
	session->SetGsaPushSession(gsa_push_session);

	//need to setup policy from gsa_push_session first
	//**********************************
	//but when?
	Ptr<IpSecPolicyEntry> policy = gsa_push_session->CreateAndInitializePolicy(session->GetGroupAddress());

	//setting up gsa_q
	Spi suggested_gsa_q_spi;
	Ptr<IpSecSAEntry> gsa_q = session->GetRelatedGsaQ();
	if (gsa_q == 0)
	{
		suggested_gsa_q_spi.SetValueFromUint32(session->GetInfo()->GetLocalAvailableIpsecSpi());
		gsa_q = gsa_push_session->CreateGsaQ(suggested_gsa_q_spi.ToUint32());
	}
	else
	{
		suggested_gsa_q_spi.SetValueFromUint32(gsa_q->GetSpi());
	}

	//setting up gsa_r
	Spi suggested_gsa_r_spi;	//needed to be unique in Qs and NQs
	Ptr<IpSecSAEntry> gsa_r = session->GetRelatedGsaR();
	if (gsa_r == 0)
	{
		suggested_gsa_r_spi.SetValueFromUint32(session->GetInfo()->GetLocalAvailableIpsecSpi());
		gsa_r = gsa_push_session->CreateGsaR(suggested_gsa_r_spi.ToUint32());
	}
	else
	{
		//it already has a gsa_r, why?
		//weird, it should not the case of retransmission when code run reach here
		NS_ASSERT (false);
		suggested_gsa_r_spi.SetValueFromUint32(gsa_r->GetSpi());
	}

	//setting up remote spi notification proposal payload
	Ptr<IkeGsaPayloadSubstructure> gsa_payload_substructure = IkeGsaPayloadSubstructure::GenerateEmptyGsaPayload(	policy->GetTrafficSelectorSrc(),
																													policy->GetTrafficSelectorDest());
	gsa_payload_substructure->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(suggested_gsa_q_spi, IkeGsaProposal::GSA_Q));
	gsa_payload_substructure->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(suggested_gsa_r_spi, IkeGsaProposal::GSA_R));
	IkePayload gsa_push_proposal_payload;
	gsa_push_proposal_payload.SetSubstructure(gsa_payload_substructure);

	uint32_t length_beside_ikeheader = gsa_push_proposal_payload.GetSerializedSize();

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(gsa_push_proposal_payload);

	this->SendMessage(	session,
						IkeHeader::INFORMATIONAL,
						false,
						gsa_push_proposal_payload.GetPayloadType(),
						length_beside_ikeheader,
						packet,
						true);

	this->DeliverToNQs(gsa_push_session, gsa_push_proposal_payload);
}

void
GsamL4Protocol::Send_GSA_PUSH_NQ (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);
	Ptr<IpSecDatabase> ipsec_root_db = session->GetDatabase();
	std::list<Ptr<GsamSessionGroup> > lst_session_groups = ipsec_root_db->GetSessionGroups();

	uint32_t length_beside_ikheader = 0;
	Ptr<Packet> packet = Create<Packet>();

	IkePayload previous_session_group_sa_payload;

	for (	std::list<Ptr<GsamSessionGroup> >::iterator it = lst_session_groups.begin();
			it != lst_session_groups.end();
			it++)
	{
		Ptr<GsamSessionGroup> session_group = (*it);
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
				//no gsa_q but there is an established session group
				if (0 != session_group->GetSessionsConst().size())
				{
					//has no established gsa_q but has established gsa_r?
					NS_ASSERT (false);
				}
				else
				{
					//ok
					//maybe there the q is waiting for reply of GSA_PUSH from the first member joining that group
				}
			}
			else
			{
				Ptr<IkeGsaPayloadSubstructure> session_group_sa_payload_substructure = IkeGsaPayloadSubstructure::GenerateEmptyGsaPayload(group_address);
				session_group_sa_payload_substructure->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(Spi(gsa_q->GetSpi()), IkeGsaProposal::GSA_Q));

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
						session_group_sa_payload_substructure->PushBackProposal(IkeGsaProposal::GenerateGsaProposal(Spi(gsa_r->GetSpi()), IkeGsaProposal::GSA_R));
					}
				}

				IkePayload session_group_sa_payload;
				session_group_sa_payload.SetSubstructure(session_group_sa_payload_substructure);

				if (true == previous_session_group_sa_payload.HasPayloadSubstructure())
				{
					previous_session_group_sa_payload.SetNextPayloadType(session_group_sa_payload.GetPayloadType());
				}

				packet->AddHeader(session_group_sa_payload);
				length_beside_ikheader += session_group_sa_payload.GetSerializedSize();

				previous_session_group_sa_payload = session_group_sa_payload;
			}
		}
	}

	//now we have a SA payload with  spis from all GMs' sessions

	this->SendMessage(session,
			IkeHeader::INFORMATIONAL,
			false,
			previous_session_group_sa_payload.GetPayloadType(),
			length_beside_ikheader,
			packet,
			true);
}

void
GsamL4Protocol::DeliverToNQs (Ptr<GsaPushSession> gsa_push_session, const IkePayload& gsa_push_proposal_payload)
{
	NS_LOG_FUNCTION (this);
	Ptr<GsamSessionGroup> session_group_nq = this->GetIpSecDatabase()->GetSessionGroup(GsamConfig::GetIgmpv3DestGrpReportAddress());

	std::list<Ptr<GsamSession> > lst_sessions_nq = session_group_nq->GetSessions();

	for (	std::list<Ptr<GsamSession> >::iterator it = lst_sessions_nq.begin();
			it != lst_sessions_nq.end();
			it++)
	{
		Ptr<GsamSession> nq_session = (*it);
		gsa_push_session->PushBackNqSession(nq_session);
		nq_session->SetGsaPushSession(gsa_push_session);

		uint32_t length_beside_ikeheader = gsa_push_proposal_payload.GetSerializedSize();

		Ptr<Packet> packet = Create<Packet>();
		packet->AddHeader(gsa_push_proposal_payload);

		this->SendMessage(		nq_session,
								IkeHeader::INFORMATIONAL,
								false,
								gsa_push_proposal_payload.GetPayloadType(),
								length_beside_ikeheader,
								packet,
								true);
	}


}

void
GsamL4Protocol::SendMessage (	Ptr<GsamSession> session,
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
	ikeheader.SetInitiatorSpi(session->GetKekSaInitiatorSpi());
	ikeheader.SetResponderSpi(session->GetKekSaResponderSpi());
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

	packet->AddHeader(ikeheader);

	bool actual_retransmit = false;

	if (false == is_responder)
	{
		actual_retransmit = retransmit;
	}

	this->DoSendMessage(session, packet, actual_retransmit);
}

void
GsamL4Protocol::DoSendMessage (Ptr<GsamSession> session, Ptr<Packet> packet, bool retransmit)
{
	NS_LOG_FUNCTION (this);

	m_socket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(session->GetPeerAddress()), GsamL4Protocol::PROT_NUMBER));

	m_socket->Send(packet);

	if (true == retransmit)
	{
		bool session_retransmit = session->IsRetransmit();
		if (true == session->GetRetransmitTimer().IsRunning())
		{
			//something may went wrong.
			NS_ASSERT (false);
		}
		else
		{
			session->GetRetransmitTimer().Cancel();
		}
		session->GetRetransmitTimer().SetFunction(&GsamL4Protocol::DoSendMessage, this);
		session->GetRetransmitTimer().SetArguments(session, packet, session_retransmit);
		session->GetRetransmitTimer().Schedule(GsamConfig::GetDefaultRetransmitTimeout());
	}
	else
	{
		session->SceduleTimeout(GsamConfig::GetDefaultSessionTimeout());
	}
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

	Ptr<GsamSession> session = this->GetIpSecDatabase()->GetSession(ikeheader, peer_address);

	if (session == 0)
	{
		session = this->GetIpSecDatabase()->CreateSession();
		session->SetPhaseOneRole(GsamSession::RESPONDER);
		session->SetPeerAddress(peer_address);
		session->EtablishGsamInitSa();
		session->SetInitSaInitiatorSpi(initiator_spi);
		uint64_t responder_spi = this->GetIpSecDatabase()->GetInfo()->RegisterGsamSpi();
		session->SetInitSaResponderSpi(responder_spi);
	}
	session->SetMessageId(message_id);

	this->RespondIkeSaInit(session);
}

void
GsamL4Protocol::HandleIkeSaInitResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address)
{
	NS_LOG_FUNCTION (this << packet);

	uint32_t message_id = ikeheader.GetMessageId();

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

	Ptr<GsamSession> session = this->GetIpSecDatabase()->GetSession(ikeheader, peer_address);

	if (0 == session)
	{
		//no session
		//reason 1, replayed msg
		//reason 2, unsolicited response msg

		//action = do nothing
	}
	else
	{
		session->GetRetransmitTimer().Cancel();

		uint64_t responder_spi = ikeheader.GetResponderSpi();

		if (0 == responder_spi)
		{
			//somthing went wrong
			NS_ASSERT (false);
		}

		session->SetInitSaResponderSpi(responder_spi);

		this->Send_IKE_SA_AUTH(session);
	}
}

void
GsamL4Protocol::RespondIkeSaInit (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	//setting up Nr
	IkePayload n_r;
	n_r.SetSubstructure(IkeNonceSubstructure::GenerateNonceSubstructure());

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
	this->SendMessage(	session,
						IkeHeader::INFORMATIONAL,
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

	Ptr<GsamSession> session = this->GetIpSecDatabase()->GetSession(ikeheader, peer_address);

	if (session == 0)
	{
		NS_ASSERT (false);
	}

	bool is_invitation = ikeheader.IsInitiator();
	bool is_response = ikeheader.IsResponder();

	if (	(true == is_invitation) &&
			(false == is_response))
	{
		//invitation
		this->HandleIkeSaAuthInvitation(packet, ikeheader, session);

	}
	else if ((false == is_invitation) &&
			(true == is_response))
	{
		//response
		this->HandleIkeSaAuthResponse(packet, ikeheader, session);
	}
	else
	{
		//error
		NS_ASSERT (false);
	}

}
void
GsamL4Protocol::HandleIkeSaAuthInvitation (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	uint32_t message_id = ikeheader.GetMessageId();

	NS_ASSERT (message_id == 1);

	//picking up id payload
	IkePayloadHeader::PAYLOAD_TYPE id_payload_type = ikeheader.GetNextPayloadType();
	if (id_payload_type != IkePayloadHeader::IDENTIFICATION_INITIATOR)
	{
		NS_ASSERT (false);
	}
	IkePayload id = IkePayload::GetEmptyPayloadFromPayloadType(id_payload_type);
	packet->RemoveHeader(id);

	//picking up auth payload
	IkePayloadHeader::PAYLOAD_TYPE auth_payload_type = ikeheader.GetNextPayloadType();
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

	Ptr<IkeSaProposal> chosen_proposal = Create<IkeSaProposal>();
	GsamL4Protocol::ChooseSAProposalOffer(sai2.GetSAProposals(), chosen_proposal);

	std::list<IkeTrafficSelector> narrowed_tssi;
	GsamL4Protocol::NarrowTrafficSelectors(tsi.GetTrafficSelectors(), narrowed_tssi);
	std::list<IkeTrafficSelector> narrowed_tssr;
	GsamL4Protocol::NarrowTrafficSelectors(tsr.GetTrafficSelectors(), narrowed_tssr);

	if (!session->HaveKekSa())
	{
		this->ProcessIkeSaAuthInvitation(	session,
											id.GetIpv4AddressId(),
											chosen_proposal,
											narrowed_tssi,
											narrowed_tssr);
	}
	else
	{
		//it has already receive a same auth invitation for the same session before
	}

	session->SetMessageId(message_id);

	this->RespondIkeSaAuth(session, chosen_proposal, narrowed_tssi, narrowed_tssr);

}

void
GsamL4Protocol::ProcessIkeSaAuthInvitation(	Ptr<GsamSession> session,
											Ipv4Address group_address,
											const Ptr<IkeSaProposal> proposal,
											const std::list<IkeTrafficSelector>& tsi_selectors,
											const std::list<IkeTrafficSelector>& tsr_selectors)
{
	NS_LOG_FUNCTION (this);

	session->SetGroupAddress(group_address);

	session->EtablishGsamKekSa();
	session->SetKekSaInitiatorSpi(proposal->GetSpi().ToUint64());
	session->SetKekSaResponderSpi(session->GetInfo()->RegisterGsamSpi());

	if (0 == session->GetRelatedPolicy())
	{
		this->CreateIpSecPolicy(session, tsi_selectors, tsr_selectors);
	}
}

void
GsamL4Protocol::HandleIkeSaAuthResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	session->GetRetransmitTimer().Cancel();

	uint32_t message_id = ikeheader.GetMessageId();

	NS_ASSERT (message_id == 1);

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

	//picking up TSi payload
	IkePayloadHeader::PAYLOAD_TYPE tsi_payload_type = sar2.GetNextPayloadType();
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

	this->ProcessIkeSaAuthResponse(session, sar2.GetSAProposals(), tsi.GetTrafficSelectors(), tsr.GetTrafficSelectors());

}

void
GsamL4Protocol::ProcessIkeSaAuthResponse (	Ptr<GsamSession> session,
											const std::list<Ptr<IkeSaProposal> >& sar2_proposals,
											const std::list<IkeTrafficSelector>& tsi_selectors,
											const std::list<IkeTrafficSelector>& tsr_selectors)
{
	NS_LOG_FUNCTION (this);

	if (sar2_proposals.size() != 1)
	{
		NS_ASSERT (false);
	}

	Ptr<IkeSaProposal> proposal = sar2_proposals.front();

	Spi spi_responder = proposal->GetSpi();

	session->SetKekSaResponderSpi(spi_responder.ToUint64());

	this->CreateIpSecPolicy(session, tsi_selectors, tsr_selectors);
}

void
GsamL4Protocol::RespondIkeSaAuth (	Ptr<GsamSession> session,
									Ptr<IkeSaProposal> chosen_proposal,
									const std::list<IkeTrafficSelector>& narrowed_tssi,
									const std::list<IkeTrafficSelector>& narrowed_tssr)
{
	NS_LOG_FUNCTION (this);

	//Setting up TSr
	IkePayload tsr;
	tsr.GetEmptyPayloadFromPayloadType(IkePayloadHeader::TRAFFIC_SELECTOR_RESPONDER);
	Ptr<IkeTrafficSelectorSubstructure> tsr_payload_sub = DynamicCast<IkeTrafficSelectorSubstructure>(tsr.GetSubstructure());
	tsr_payload_sub->PushBackTrafficSelectors(narrowed_tssr);
	//settuping up tsi
	IkePayload tsi;
	tsi.GetEmptyPayloadFromPayloadType(IkePayloadHeader::TRAFFIC_SELECTOR_INITIATOR);
	Ptr<IkeTrafficSelectorSubstructure> tsi_payload_sub = DynamicCast<IkeTrafficSelectorSubstructure>(tsi.GetSubstructure());
	tsi_payload_sub->PushBackTrafficSelectors(narrowed_tssi);
	tsi.SetNextPayloadType(tsr.GetPayloadType());
	//setting up sar2
	IkePayload sar2;
	sar2.GetEmptyPayloadFromPayloadType(IkePayloadHeader::SECURITY_ASSOCIATION);
	Ptr<IkeSaPayloadSubstructure> sar2_payload_sub = DynamicCast<IkeSaPayloadSubstructure>(sar2.GetSubstructure());
	sar2_payload_sub->PushBackProposal(chosen_proposal);
	sar2.SetNextPayloadType(tsi.GetPayloadType());
	//setting up auth
	IkePayload auth;
	auth.SetSubstructure(IkeAuthSubstructure::GenerateEmptyAuthSubstructure());
	auth.SetNextPayloadType(sar2.GetPayloadType());

	uint32_t length_beside_ikeheader = 	auth.GetSerializedSize() +
										sar2.GetSerializedSize() +
										tsi.GetSerializedSize() +
										tsr.GetSerializedSize();

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(tsr);
	packet->AddHeader(tsi);
	packet->AddHeader(sar2);
	packet->AddHeader(auth);

	this->SendMessage(	session,
						IkeHeader::IKE_AUTH,
						true,
						auth.GetPayloadType(),
						length_beside_ikeheader,
						packet,
						false);
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

	bool is_invitation = ikeheader.IsInitiator();
	bool is_response = ikeheader.IsResponder();

	if (	(true == is_invitation) &&
			(false == is_response))
	{
		this->HandleGsaPush(packet, ikeheader, session);

	}
	else if ((false == is_invitation) &&
			(true == is_response))
	{
		this->HandleGsaAck(packet, ikeheader, session);
	}
	else
	{
		//error
		NS_ASSERT (false);
	}
}

void
GsamL4Protocol::HandleGsaPush (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	uint32_t message_id = ikeheader.GetMessageId();
	session->SetMessageId(ikeheader.GetMessageId());

	NS_ASSERT (message_id >= 2);

	if (true == session->IsHostNonQuerier())
	{
		this->HandleGsaPushNQ(packet, ikeheader, session);
	}
	else if (true == session->IsHostGroupMember())
	{
		this->HandleGsaPushGM(packet, ikeheader, session);
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

void
GsamL4Protocol::RejectGsaR (Ptr<GsamSession> session, Ipv4Address group_address, uint32_t spi)
{
	NS_LOG_FUNCTION (this);
}

void
GsamL4Protocol::HandleGsaPushGM (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	IkePayload pushed_gsa_payload;
	pushed_gsa_payload.GetEmptyPayloadFromPayloadType(IkePayloadHeader::SECURITY_ASSOCIATION);

	packet->RemoveHeader(pushed_gsa_payload);

	Ptr<IkeGsaPayloadSubstructure> gsa_payload_substructure = DynamicCast<IkeGsaPayloadSubstructure>(pushed_gsa_payload.GetSubstructure());

	std::list<Ptr<IkeSaProposal> > proposals = gsa_payload_substructure->GetProposals();

	if (proposals.size() != 2)
	{
		NS_ASSERT (false);
	}

	IkeTrafficSelector ts_src = gsa_payload_substructure->GetSourceTrafficSelector();
	IkeTrafficSelector ts_dest = gsa_payload_substructure->GetDestTrafficSelector();
	Ptr<IkeSaProposal> gsa_q_proposal = proposals.front();
	Ptr<IkeSaProposal> gsa_r_proposal = proposals.back();

	this->ProcessGsaPushGM(session, ts_src, ts_dest, gsa_q_proposal, gsa_r_proposal);
}
void
GsamL4Protocol::HandleGsaPushNQ (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	IkePayloadHeader::PAYLOAD_TYPE ikeheader_next_payloadtype = ikeheader.GetNextPayloadType();

	if (ikeheader.GetNextPayloadType() == IkePayloadHeader::GROUP_SECURITY_ASSOCIATION)
	{
		//ok
	}
	else if (ikeheader.GetNextPayloadType() == IkePayloadHeader::NO_NEXT_PAYLOAD)
	{
		//empty ike packet, ok
	}
	else
	{
		NS_ASSERT (false);
	}

	bool go_on = false;

	do {
		IkePayload pushed_gsa_payload;
		pushed_gsa_payload.GetEmptyPayloadFromPayloadType(ikeheader_next_payloadtype);

		packet->RemoveHeader(pushed_gsa_payload);

		Ptr<IkeGsaPayloadSubstructure> gsa_payload_substructure = DynamicCast<IkeGsaPayloadSubstructure>(pushed_gsa_payload.GetSubstructure());

		this->ProcessGsaPushNQ(	session,
								gsa_payload_substructure->GetSourceTrafficSelector(),
								gsa_payload_substructure->GetDestTrafficSelector(),
								gsa_payload_substructure->GetProposals());

		if (pushed_gsa_payload.GetNextPayloadType() == IkePayloadHeader::GROUP_SECURITY_ASSOCIATION)
		{
			go_on = true;
		}
		else if (pushed_gsa_payload.GetNextPayloadType() ==IkePayloadHeader::NO_NEXT_PAYLOAD)
		{
			go_on = false;
		}
		else
		{
			NS_ASSERT (false);
		}
	} while (true == go_on);
}

void
GsamL4Protocol::ProcessGsaPushGM (	Ptr<GsamSession> session,
									IkeTrafficSelector ts_src,
									IkeTrafficSelector ts_dest,
									const Ptr<IkeSaProposal> gsa_q_proposal,
									const Ptr<IkeSaProposal> gsa_r_proposal)
{
	NS_LOG_FUNCTION (this);

	Ptr<IpSecSAEntry> local_gsa_q = session->GetRelatedGsaQ();
	Ptr<IpSecSAEntry> local_gsa_r = session->GetRelatedGsaR();

	uint32_t pushed_gsa_q_spi = gsa_q_proposal->GetSpi().ToUint32();
	uint32_t pushed_gsa_r_spi = gsa_r_proposal->GetSpi().ToUint32();

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
				this->RejectGsaQ(session, ts_src, ts_dest, gsa_q_proposal);
			}
			else
			{
				//no reject and install gsa pair
				this->AcceptGsaPair(session, ts_src, ts_dest, gsa_q_proposal, gsa_r_proposal);
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
			//duplicate gsa push?

			if (local_gsa_q->GetSpi() != gsa_q_proposal->GetSpi().ToUint32())
			{
				//weird
				NS_ASSERT (false);
			}

			if (local_gsa_r->GetSpi() != gsa_r_proposal->GetSpi().ToUint32())
			{
				//weird
				NS_ASSERT (false);
			}

			//have to respond
			this->SendAcceptAck(session, ts_src, ts_dest, gsa_q_proposal, gsa_r_proposal);
		}
	}
}

void
GsamL4Protocol::RejectGsaQ (Ptr<GsamSession> session,
							IkeTrafficSelector ts_src,
							IkeTrafficSelector ts_dest,
							const Ptr<IkeSaProposal> gsa_q_proposal,)
{
	NS_LOG_FUNCTION (this);

	//setting up payload contains current used spis
	Ptr<IkeGroupNotifySubstructure> gsa_q_spis_report_notify_substructure = IkeGroupNotifySubstructure::GenerateEmptyGroupNotifySubstructure(GsamConfig::GetDefaultGSAProposalId(),
																																IPsec::AH_ESP_SPI_SIZE,
																																IkeGroupNotifySubstructure::GSA_Q_SPI_NOTIFICATION,
																																ts_src,
																																ts_dest);
	std::list<Ptr<Spi> > lst_ptr_gsa_q_spis_report;
	session->GetDatabase()->GetPolicyDatabase()->GetInboundSpis(lst_ptr_gsa_q_spis_report);
	gsa_q_spis_report_notify_substructure->PushBackSpis(lst_ptr_gsa_q_spis_report);
	IkePayload gsa_q_spis_report_notify_payload;
	gsa_q_spis_report_notify_payload.SetSubstructure(gsa_q_spis_report_notify_substructure);

	//setting up payload contains rejected spi
	Ptr<IkeGroupNotifySubstructure> reject_gsa_q_spi_notify_substructure = IkeGroupNotifySubstructure::GenerateEmptyGroupNotifySubstructure(GsamConfig::GetDefaultGSAProposalId(),
																															IPsec::AH_ESP_SPI_SIZE,
																															IkeGroupNotifySubstructure::GSA_Q_SPI_REJECTION,
																															ts_src,
																															ts_dest);
	Ptr<Spi> reject_gsa_q_spi = Create<Spi>();
	reject_gsa_q_spi->SetValueFromUint32(gsa_q_proposal->GetSpi().ToUint32());
	reject_gsa_q_spi_notify_substructure->PushBackSpi(reject_gsa_q_spi);
	IkePayload reject_gsa_q_spi_notify_payload;
	reject_gsa_q_spi_notify_payload.SetSubstructure(reject_gsa_q_spi_notify_substructure);
	reject_gsa_q_spi_notify_payload.SetNextPayloadType(gsa_q_spis_report_notify_payload.GetPayloadType());

	uint32_t length_beside_ikeheader = reject_gsa_q_spi_notify_payload.GetSerializedSize() +
										gsa_q_spis_report_notify_payload.GetSerializedSize();

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(gsa_q_spis_report_notify_payload);
	packet->AddHeader(reject_gsa_q_spi_notify_payload);

	this->SendMessage(session,
			IkeHeader::INFORMATIONAL,
			true,
			reject_gsa_q_spi_notify_payload.GetPayloadType(),
			length_beside_ikeheader,
			packet, false);
}

void
GsamL4Protocol::AcceptGsaPair (	Ptr<GsamSession> session,
								IkeTrafficSelector ts_src,
								IkeTrafficSelector ts_dest,
								const Ptr<IkeSaProposal> gsa_q_proposal,
								const Ptr<IkeSaProposal> gsa_r_proposal)
{
	NS_LOG_FUNCTION (this);
	this->InstallGsaPair(session, ts_src, ts_dest, gsa_q_proposal, gsa_r_proposal);
	this->SendAcceptAck(session, ts_src, ts_dest, gsa_q_proposal, gsa_r_proposal);
}

void
GsamL4Protocol::InstallGsaPair (Ptr<GsamSession> session,
								IkeTrafficSelector ts_src,
								IkeTrafficSelector ts_dest,
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
	Spi gsa_q_spi = gsa_q_proposal->GetSpi();
	Spi gsa_r_spi = gsa_r_proposal->GetSpi();
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

		Ptr<IpSecSAEntry> gsa_q = policy->GetInboundSAD()->CreateIpSecSAEntry(gsa_q_spi);
		session->AssociateGsaQ(gsa_q);

		Ptr<IpSecSAEntry> gsa_r = policy->GetOutboundSAD()->CreateIpSecSAEntry(gsa_r_spi);
		session->SetRelatedGsaR(gsa_r);
	}

}

void
GsamL4Protocol::SendAcceptAck (	Ptr<GsamSession> session,
								IkeTrafficSelector ts_src,
								IkeTrafficSelector ts_dest,
								const Ptr<IkeSaProposal> gsa_q_proposal,
								const Ptr<IkeSaProposal> gsa_r_proposal)
{
	NS_LOG_FUNCTION (this);
	Ptr<IkeGroupNotifySubstructure> ack_notify_substructure = IkeGroupNotifySubstructure::GenerateEmptyGroupNotifySubstructure(	GsamConfig::GetDefaultGSAProposalId(),
																																IPsec::AH_ESP_SPI_SIZE,
																																IkeGroupNotifySubstructure::GSA_ACKNOWLEDGEDMENT,
																																ts_src,
																																ts_dest);
	IkePayload ack_notify_payload;
	ack_notify_payload.SetSubstructure(ack_notify_substructure);

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(ack_notify_payload);

	this->SendMessage(session,
			IkeHeader::INFORMATIONAL,
			true,
			ack_notify_payload.GetPayloadType(),
			ack_notify_payload.GetSerializedSize(),
			packet,
			false);
}

void
GsamL4Protocol::ProcessGsaPushNQ (	Ptr<GsamSession> session,
									IkeTrafficSelector ts_src,
									IkeTrafficSelector ts_dest,
									const std::list<Ptr<IkeSaProposal> >& gsa_proposals)
{
	NS_LOG_FUNCTION (this);

	if (ts_src.GetStartingAddress() == ts_src.GetEndingAddress())
	{
		//ok
		if (ts_src.GetStartingAddress().Get() == 0)
		{
			//ok
		}
		else
		{
			//not ok
			NS_ASSERT (false);
		}
	}
	else
	{
		//not ok
		NS_ASSERT (false);
	}

	if (ts_dest.GetStartingAddress() == ts_dest.GetEndingAddress())
	{
		//ok
	}
	else
	{
		//not ok
		NS_ASSERT (false);
	}

	Ipv4Address group_address = ts_dest.GetEndingAddress();

	if (gsa_proposals.size() == 0)
	{
		//Maybe ok?
		//empty session group
		//probably Q is waiting for reply from designated GM
	}
	else if (gsa_proposals.size() == 1)
	{
		//not ok
		NS_ASSERT (false);
	}
	else //(gsa_proposals.size() >= 2)
	{
		//ok
	}

	for (	std::list<Ptr<IkeSaProposal> >::const_iterator const_it = gsa_proposals.begin();
			const_it != gsa_proposals.end();
			const_it++)
	{
		const Ptr<IkeGsaProposal> gsa_proposal = DynamicCast<IkeGsaProposal>(*const_it);
	}
}

void
GsamL4Protocol::HandleGsaAck (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);
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
	policy_entry->SetProcessChoice(IpSecPolicyEntry::PROTECT);
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
	//this method need to be refactored, according to gsam's rule, a GM can only join one group at a time using a session

	if (tsi_selectors.size() > 1)
	{
		NS_ASSERT (false);
	}

	if (tsr_selectors.size() > 1)
	{
		NS_ASSERT (false);
	}

	for (	std::list<IkeTrafficSelector>::const_iterator const_it_tsi_selectors = tsi_selectors.begin();
			const_it_tsi_selectors != tsi_selectors.end();
			const_it_tsi_selectors++)
	{
		for (	std::list<IkeTrafficSelector>::const_iterator const_it_tsr_selectors = tsr_selectors.begin();
				const_it_tsr_selectors != tsr_selectors.end();
				const_it_tsr_selectors++)
		{
			this->CreateIpSecPolicy(session, (*const_it_tsi_selectors), (*const_it_tsr_selectors));
		}
	}
}

Ptr<IpSecSAEntry>
GsamL4Protocol::CreateOutboundSa (Ptr<GsamSession> session, Spi spi)
{
	NS_LOG_FUNCTION (this);

	Ptr<IpSecSAEntry> retval = 0;

	Ptr<IpSecPolicyEntry> policy = session->GetRelatedPolicy();
	Ptr<IpSecSADatabase> outbound_sad = policy->GetOutboundSAD();

	retval = outbound_sad->CreateIpSecSAEntry(spi);

	return retval;
}

Ptr<IpSecSAEntry>
GsamL4Protocol::CreateInboundSa (Ptr<GsamSession> session, Spi spi)
{
	NS_LOG_FUNCTION (this);

	Ptr<IpSecSAEntry> retval = 0;

	Ptr<IpSecPolicyEntry> policy = session->GetRelatedPolicy();
	Ptr<IpSecSADatabase> inbound_sad = policy->GetInboundSAD();

	retval = inbound_sad->CreateIpSecSAEntry(spi);

	return retval;
}

void
GsamL4Protocol::SetOutbountSa (Ptr<GsamSession> session, Ptr<IpSecSAEntry> outbound_sa)
{
	NS_LOG_FUNCTION (this);

	Ptr<IpSecPolicyEntry> policy = session->GetRelatedPolicy();
	Ptr<IpSecSADatabase> outbound_sad = policy->GetOutboundSAD();

	outbound_sad->PushBackEntry(outbound_sa);
}

void
GsamL4Protocol::SetInbountSa (Ptr<GsamSession> session, Ptr<IpSecSAEntry> inbound_sa)
{
	NS_LOG_FUNCTION (this);

	NS_LOG_FUNCTION (this);

	Ptr<IpSecPolicyEntry> policy = session->GetRelatedPolicy();
	Ptr<IpSecSADatabase> inbound_sad = policy->GetInboundSAD();

	inbound_sad->PushBackEntry(inbound_sa);
}

void
GsamL4Protocol::ChooseSAProposalOffer (	const std::list<Ptr<IkeSaProposal> >& proposals,
										Ptr<IkeSaProposal> retval_chosen_proposal)
{
	if (proposals.size() == 0)
	{
		NS_ASSERT(false);
	}

	retval_chosen_proposal = proposals.front();
}

void
GsamL4Protocol::NarrowTrafficSelectors (const std::list<IkeTrafficSelector>& tsi_selectors,
												std::list<IkeTrafficSelector>& retval_narrowed_tsi_selectors)
{
	retval_narrowed_tsi_selectors = tsi_selectors;
}

} /* namespace ns3 */
