/*
 * Igmpv3-l4-protocol.h
 *
 *  Created on: Jan 27, 2016
 *      Author: lin
 */

#ifndef GSAM_L4_PROTOCOL_MULTICAST_H
#define GSAM_L4_PROTOCOL_MULTICAST_H

#include "ns3/object.h"
#include "ipsec.h"
#include "ns3/socket.h"
#include <list>
#include <set>
#include "igmpv3-l4-protocol.h"

namespace ns3 {

class Node;
class Ipv4InterfaceMulticast;
class Ipv4Route;

class GsamL4Protocol : public Object {

public:	//Object override
	/**
	 * \brief Get the type ID.
	 * \return the object TypeId
	 */
	static TypeId GetTypeId (void);

	static const uint16_t PROT_NUMBER;	//udp port number 500s

	GsamL4Protocol();
	virtual ~GsamL4Protocol();

	/**
	 * \brief Set the node the protocol is associated with.
	 * \param node the node
	 */
	void SetNode (Ptr<Node> node);

	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:

	virtual void DoDispose (void);
public:	//added by Lin Chen
	void Initialization (void);
	void HandleRead (Ptr<Socket> socket);
public:	//exchanges, added by Lin Chen
	//create session somewhere first
	void Send_IKE_SA_INIT (Ptr<GsamSession> session);
	void Send_IKE_SA_AUTH (Ptr<GsamSession> session);
	void Send_GSA_PUSH (Ptr<GsamSession> session);
	void Send_GSA_PUSH_GM (Ptr<GsamSession> session);
	void Send_GSA_PUSH_NQ (Ptr<GsamSession> session);
private:	//Sending, added by Lin Chen,
	void SendMessage (	Ptr<GsamSession> session,
						IkeHeader::EXCHANGE_TYPE exchange_type,
						bool is_responder,
						IkePayloadHeader::PAYLOAD_TYPE first_payload_type,
						uint32_t length_beside_ikeheader,
						Ptr<Packet> packet,
						bool retransmit);
	void DoSendMessage (Ptr<GsamSession> session, Ptr<Packet> packet, bool retransmit);
private:	//phase 1, initiator
	void HandleIkeSaInitResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void HandleIkeSaAuthResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void ProcessIkeSaAuthResponse (	Ptr<GsamSession> session,
									const std::list<Ptr<IkeSaProposal> >& sar2_proposals,
									const std::list<IkeTrafficSelector>& tsi_selectors,
									const std::list<IkeTrafficSelector>& tsr_selectors);
private:	//phase 1, responder
	void HandleIkeSaInit (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void HandleIkeSaInitInvitation (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void RespondIkeSaInit (Ptr<GsamSession> session);
	void HandleIkeSaAuth (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void HandleIkeSaAuthInvitation (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void ProcessIkeSaAuthInvitation (	Ptr<GsamSession> session,
										Ipv4Address group_address,
										const Ptr<IkeSaProposal> proposal,
										const std::list<IkeTrafficSelector>& tsi_selectors,
										const std::list<IkeTrafficSelector>& tsr_selectors);
	void RespondIkeSaAuth (	Ptr<GsamSession> session,
							Ptr<IkeSaProposal> chosen_proposal,
							const std::list<IkeTrafficSelector>& narrowed_tssi,
							const std::list<IkeTrafficSelector>& narrowed_tssr);
private:	//phase 2, Q
	void HandleGsaAck (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void DeliverToNQs (Ptr<GsaPushSession> gsa_push_session, const IkePayload& gsa_push_proposal_payload);
private:	//phase 2, GM, NQ
	void HandleGsaInformational (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void HandleGsaPush (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
private:	//phase 2, GM
	void HandleGsaPushGM (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void ProcessGsaPushGM (	Ptr<GsamSession> session,
							IkeTrafficSelector ts_src,
							IkeTrafficSelector ts_dest,
							const Ptr<IkeSaProposal> gsa_q_proposal,
							const Ptr<IkeSaProposal> gsa_r_proposal);
	void RejectGsaQ (	Ptr<GsamSession> session,
						IkeTrafficSelector ts_src,
						IkeTrafficSelector ts_dest,
						const Ptr<IkeSaProposal> gsa_q_proposal);
	void AcceptGsaPair (Ptr<GsamSession> session,
						IkeTrafficSelector ts_src,
						IkeTrafficSelector ts_dest,
						const Ptr<IkeSaProposal> gsa_q_proposal,
						const Ptr<IkeSaProposal> gsa_r_proposal);
	void InstallGsaPair (	Ptr<GsamSession> session,
							IkeTrafficSelector ts_src,
							IkeTrafficSelector ts_dest,
							const Ptr<IkeSaProposal> gsa_q_proposal,
							const Ptr<IkeSaProposal> gsa_r_proposal);
	void SendAcceptAck (Ptr<GsamSession> session,
						IkeTrafficSelector ts_src,
						IkeTrafficSelector ts_dest,
						const Ptr<IkeSaProposal> gsa_q_proposal,
						const Ptr<IkeSaProposal> gsa_r_proposal);
private:	//phase 2, NQ
	void HandleGsaPushNQ (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void ProcessGsaPushNQ (	Ptr<GsamSession> session,
							IkeTrafficSelector ts_src,
							IkeTrafficSelector ts_dest,
							const std::list<Ptr<IkeSaProposal> >& gsa_proposals);
	void RejectGsaR (Ptr<GsamSession> session, Ipv4Address group_address, uint32_t spi);
public:	//const
	Ptr<Igmpv3L4Protocol> GetIgmp (void) const;
private:	//private staitc
	static void ChooseSAProposalOffer (	const std::list<Ptr<IkeSaProposal> >& proposals,
										Ptr<IkeSaProposal> retval_chosen_proposal);
	static void NarrowTrafficSelectors (const std::list<IkeTrafficSelector>& tsi_selectors,
												std::list<IkeTrafficSelector>& retval_narrowed_tsi_selectors);
private:	//database operation
	Ptr<IpSecDatabase> GetIpSecDatabase (void);
	/*
	 * \brief CreateIpSecPolicy
	 * \Deprecated
	 */
	void CreateIpSecPolicy (Ptr<GsamSession> session, const IkeTrafficSelector& tsi, const IkeTrafficSelector& tsr);
	/*
	 * \brief CreateIpSecPolicy
	 * Deprecated
	 */
	void CreateIpSecPolicy (Ptr<GsamSession> session,
							const std::list<IkeTrafficSelector>& tsi_selectors,
							const std::list<IkeTrafficSelector>& tsr_selectors);
	Ptr<IpSecSAEntry> CreateOutboundSa (Ptr<GsamSession> session, Spi spi);
	Ptr<IpSecSAEntry> CreateInboundSa (Ptr<GsamSession> session, Spi spi);
	void SetOutbountSa (Ptr<GsamSession> session, Ptr<IpSecSAEntry> outbound_sa);
	void SetInbountSa (Ptr<GsamSession> session, Ptr<IpSecSAEntry> inbound_sa);
private:	//fields
	Ptr<Node> m_node; //!< the node this protocol is associated with
	Ptr<Socket> m_socket;
	Ptr<IpSecDatabase> m_ptr_database;
};

} /* namespace ns3 */

#endif /* SRC_INTERNET_MODEL_GSAM_L4_PROTOCOL_H_ */
