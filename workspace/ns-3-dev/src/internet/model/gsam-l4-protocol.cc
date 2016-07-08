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
		break;
	default:
		break;
	}
}

void
GsamL4Protocol::Send_IKE_SA_INIT (Ptr<GsamSession> session, Ipv4Address dest)
{
	//rfc 5996 page 10
	NS_LOG_FUNCTION (this);

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
	session->SetPeerAddress(dest);
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

	this->SendMessage(session, packet, true);
}

void
GsamL4Protocol::Send_IKE_SA_AUTH (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	//Setting up TSr
	IkePayload tsr;
	tsr.SetPayload(IkeTrafficSelectorSubstructure::GetSecureGroupSubstructure(session->GetGroupAddress()));
	//settuping up tsi
	IkePayload tsi;
	tsi.SetPayload(IkeTrafficSelectorSubstructure::GetSecureGroupSubstructure(Ipv4Address("0.0.0.0")));
	tsi.SetNextPayloadType(tsr.GetPayloadType());
	//setting up sai2
	IkePayload sai2;
	Spi kek_sa_spi;
	kek_sa_spi.SetValueFromUint64(session->GetInfo()->RegisterGsamSpi());
	sai2.SetPayload(IkeSAPayloadSubstructure::GenerateAuthIkeProposal(kek_sa_spi));
	sai2.SetNextPayloadType(tsi.GetPayloadType());
	//setting up auth
	IkePayload auth;
	auth.SetPayload(IkeAuthSubstructure::GenerateEmptyAuthSubstructure());
	auth.SetNextPayloadType(sai2.GetPayloadType());
	//setting up id
	IkePayload id;
	id.SetPayload(IkeIdSubstructure::GenerateIpv4Substructure(session->GetGroupAddress()));
	id.SetNextPayloadType(auth.GetPayloadType());
	//setting up HDR
	IkeHeader ikeheader;
	ikeheader.SetInitiatorSpi(session->GetInitSaInitiatorSpi());
	ikeheader.SetResponderSpi(session->GetInitSaResponderSpi());
	ikeheader.SetIkev2Version();
	ikeheader.SetExchangeType(IkeHeader::IKE_AUTH);
	ikeheader.SetAsInitiator();
	//pause setting up HDR, start setting up a kek sa
	session->EtablishGsamKekSa();
	session->SetKekSaInitiatorSpi(kek_sa_spi.ToUint64());
	//continue setting up hdr
	ikeheader.SetMessageId(session->GetCurrentMessageId());
	ikeheader.SetNextPayloadType(id.GetPayloadType());
	ikeheader.SetLength(ikeheader.GetSerializedSize() +
			auth.GetSerializedSize() +
			sai2.GetSerializedSize() +
			tsi.GetSerializedSize() +
			tsr.GetSerializedSize());

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(tsr);
	packet->AddHeader(tsi);
	packet->AddHeader(sai2);
	packet->AddHeader(auth);
	packet->AddHeader(ikeheader);

	this->SendMessage(session, packet, true);
}

void
GsamL4Protocol::Send_GSA_Notification (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

	session->SetPhaseTwoRole(GsamSession::INITIATOR);

	Spi gsa_spi = session->GetGsaSpi();

	//setting up remote spi notification (remote to peer which is local for this host)
	IkePayload remote_spi_notification;
	remote_spi_notification.SetPayload(IkeNotifySubstructure::GenerateGsaRemoteSpiNotification(gsa_spi));

	//setting up local spi notification (the one that may be rejected)
	IkePayload local_spi_notification;
	local_spi_notification.SetPayload(IkeNotifySubstructure::GenerateGsaLocalSpiNotification(session->GetInfo()->GenerateIpsecSpi()));
	local_spi_notification.SetNextPayloadType(remote_spi_notification.GetPayloadType());

	//setting up HDR
	IkeHeader ikeheader;
	ikeheader.SetInitiatorSpi(session->GetKekSaInitiatorSpi());
	ikeheader.SetResponderSpi(session->GetKekSaResponderSpi());
	ikeheader.SetIkev2Version();
	ikeheader.SetExchangeType(IkeHeader::INFORMATIONAL);
	ikeheader.SetAsResponder();

	ikeheader.SetMessageId(session->GetCurrentMessageId());
	ikeheader.SetNextPayloadType(remote_spi_notification.GetPayloadType());
	ikeheader.SetLength(ikeheader.GetSerializedSize() +
			local_spi_notification.GetSerializedSize() +
			remote_spi_notification.GetSerializedSize());

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(remote_spi_notification);
	packet->AddHeader(local_spi_notification);
	packet->AddHeader(ikeheader);
}

void
GsamL4Protocol::Send_GSA_Acknowledgedment (Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);
}

void
GsamL4Protocol::SendMessage (Ptr<GsamSession> session, Ptr<Packet> packet, bool retransmit)
{
	NS_LOG_FUNCTION (this);

	m_socket->Connect (InetSocketAddress (Ipv4Address::ConvertFrom(session->GetPeerAddress()), GsamL4Protocol::PROT_NUMBER));

	m_socket->Send(packet);

	if (true == retransmit)
	{
		bool session_retransmit = session->IsRetransmit();
		session->GetRetransmitTimer().SetFunction(&GsamL4Protocol::SendMessage, this);
		session->GetRetransmitTimer().SetArguments(session, packet, session_retransmit);
		session->GetRetransmitTimer().Schedule(session->GetInfo()->GetRetransmissionDelay());
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
		uint64_t responder_spi = ikeheader.GetResponderSpi();

		if (0 == responder_spi)
		{
			//somthing went wrong
			NS_ASSERT (false);
		}

		session->SetInitSaResponderSpi(responder_spi);
		session->IncrementMessageId();

		this->Send_IKE_SA_AUTH(session);
	}
}

void
GsamL4Protocol::RespondIkeSaInit (Ptr<GsamSession> session)
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
	header.SetExchangeType(IkeHeader::IKE_SA_INIT);
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
	this->SendMessage(session, packet, true);

	//setting up retransmission
	session->GetRetransmitTimer().SetFunction(&GsamL4Protocol::SendMessage, this);
	session->GetRetransmitTimer().SetArguments(session, packet, false);
	session->GetRetransmitTimer().Schedule(session->GetInfo()->GetRetransmissionDelay());
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

	IkeSAProposal chosen_proposal;
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
											const IkeSAProposal& proposal,
											const std::list<IkeTrafficSelector>& tsi_selectors,
											const std::list<IkeTrafficSelector>& tsr_selectors)
{
	NS_LOG_FUNCTION (this);

	session->SetGroupAddress(group_address);

	session->EtablishGsamKekSa();
	session->SetKekSaInitiatorSpi(proposal.GetSpi().ToUint64());
	session->SetKekSaResponderSpi(session->GetInfo()->RegisterGsamSpi());

	this->CreateIpSecPolicy(session, tsi_selectors, tsr_selectors);
}

void
GsamL4Protocol::HandleIkeSaAuthResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session)
{
	NS_LOG_FUNCTION (this);

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

	session->IncrementMessageId();
}

void
GsamL4Protocol::ProcessIkeSaAuthResponse (	Ptr<GsamSession> session,
											const std::list<IkeSAProposal>& sar2_proposals,
											const std::list<IkeTrafficSelector>& tsi_selectors,
											const std::list<IkeTrafficSelector>& tsr_selectors)
{
	NS_LOG_FUNCTION (this);

	if (sar2_proposals.size() != 1)
	{
		NS_ASSERT (false);
	}

	IkeSAProposal proposal = sar2_proposals.front();

	Spi spi_responder = proposal.GetSpi();

	session->SetKekSaResponderSpi(spi_responder.ToUint64());

	this->CreateIpSecPolicy(session, tsi_selectors, tsr_selectors);
}

void
GsamL4Protocol::RespondIkeSaAuth (	Ptr<GsamSession> session,
									IkeSAProposal chosen_proposal,
									const std::list<IkeTrafficSelector>& narrowed_tssi,
									const std::list<IkeTrafficSelector>& narrowed_tssr)
{
	NS_LOG_FUNCTION (this);

	//Setting up TSr
	IkePayload tsr;
	tsr.GetEmptyPayloadFromPayloadType(IkePayloadHeader::TRAFFIC_SELECTOR_RESPONDER);
	tsr.PushBackTrafficSelectors(narrowed_tssr);
	//settuping up tsi
	IkePayload tsi;
	tsi.GetEmptyPayloadFromPayloadType(IkePayloadHeader::TRAFFIC_SELECTOR_INITIATOR);
	tsi.PushBackTrafficSelectors(narrowed_tssi);
	tsi.SetNextPayloadType(tsr.GetPayloadType());
	//setting up sar2
	IkePayload sar2;
	sar2.GetEmptyPayloadFromPayloadType(IkePayloadHeader::SECURITY_ASSOCIATION);
	sar2.PushBackProposal(chosen_proposal);
	sar2.SetNextPayloadType(tsi.GetPayloadType());
	//setting up auth
	IkePayload auth;
	auth.SetPayload(IkeAuthSubstructure::GenerateEmptyAuthSubstructure());
	auth.SetNextPayloadType(sar2.GetPayloadType());
	//setting up HDR
	IkeHeader ikeheader;
	ikeheader.SetInitiatorSpi(session->GetInitSaInitiatorSpi());
	ikeheader.SetResponderSpi(session->GetInitSaResponderSpi());
	ikeheader.SetIkev2Version();
	ikeheader.SetExchangeType(IkeHeader::IKE_AUTH);
	ikeheader.SetAsResponder();
	//pause setting up HDR, start setting up a kek sa
	//continue setting up hdr
	ikeheader.SetMessageId(session->GetCurrentMessageId());
	ikeheader.SetNextPayloadType(auth.GetPayloadType());
	ikeheader.SetLength(ikeheader.GetSerializedSize() +
			auth.GetSerializedSize() +
			sar2.GetSerializedSize() +
			tsi.GetSerializedSize() +
			tsr.GetSerializedSize());

	Ptr<Packet> packet = Create<Packet>();
	packet->AddHeader(tsr);
	packet->AddHeader(tsi);
	packet->AddHeader(sar2);
	packet->AddHeader(auth);
	packet->AddHeader(ikeheader);

	this->SendMessage(session, packet, true);
}

Ptr<IpSecDatabase>
GsamL4Protocol::GetIpSecDatabase (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_ptr_database == 0)
	{
		this->m_ptr_database = Create<IpSecDatabase>();
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
	policy_entry->SetTranSrcPortRange(tsr.GetStartPort(), tsr.GetEndPort());
}

void
GsamL4Protocol::CreateIpSecPolicy (	Ptr<GsamSession> session,
									const std::list<IkeTrafficSelector>& tsi_selectors,
									const std::list<IkeTrafficSelector>& tsr_selectors)
{
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

void
GsamL4Protocol::ChooseSAProposalOffer (	const std::list<IkeSAProposal> proposals,
										IkeSAProposal& retval_chosen_proposal)
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
