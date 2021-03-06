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
	void HandleRead (Ptr<Socket> socket);
public:	//exchanges, added by Lin Chen
	//create session somewhere first
	void Send_IKE_SA_INIT (Ptr<GsamInitSession> init_session);
	void Send_IKE_SA_AUTH (Ptr<GsamInitSession> init_session, Ptr<GsamSession> session);
private:	//Sending, added by Lin Chen,
	void SendPhaseOneMessage (Ptr<GsamSession> session,
								IkeHeader::EXCHANGE_TYPE exchange_type,
								bool is_responder,
								IkePayloadHeader::PAYLOAD_TYPE first_payload_type,
								uint32_t length_beside_ikeheader,
								Ptr<Packet> packet,
								bool retransmit);
	void SendPhaseOneMessage (Ptr<GsamInitSession> session,
								IkeHeader::EXCHANGE_TYPE exchange_type,
								bool is_responder,
								IkePayloadHeader::PAYLOAD_TYPE first_payload_type,
								uint32_t length_beside_ikeheader,
								Ptr<Packet> packet,
								bool retransmit);
	void SendPhaseTwoMessage (	Ptr<GsamSession> session,
						IkeHeader::EXCHANGE_TYPE exchange_type,
						bool is_responder,
						IkePayloadHeader::PAYLOAD_TYPE first_payload_type,
						uint32_t length_beside_ikeheader,
						Ptr<Packet> packet,
						bool retransmit);
	void DoSendMessage (Ptr<GsamSession> session, bool retransmit);
	void DoSendInitMessage (Ptr<GsamInitSession> session, bool retransmit);
private:	//phase 1, initiator
	void HandleIkeSaInitResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void HandleIkeSaAuthResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamInitSession> init_session);
	void ProcessIkeSaAuthResponse (	const Ptr<const GsamInitSession> init_session,
									uint64_t kek_initiator_spi,
									const std::list<Ptr<IkeSaProposal> >& sar2_proposals,
									const std::list<IkeTrafficSelector>& tsi_selectors,
									const std::list<IkeTrafficSelector>& tsr_selectors);
private:	//phase 1, responder
	void HandleIkeSaInit (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void HandleIkeSaInitInvitation (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void RespondIkeSaInit (Ptr<GsamInitSession> session);
	void HandleIkeSaAuth (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void HandleIkeSaAuthInvitation (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamInitSession> init_session);
	/*
	 * @return value: whether a new session is created
	 */
	bool ProcessIkeSaAuthInvitation (	Ptr<GsamInitSession> init_session,
										Ipv4Address group_address,
										const Ptr<IkeSaProposal> proposal,
										const std::list<IkeTrafficSelector>& tsi_selectors,
										const std::list<IkeTrafficSelector>& tsr_selectors,
										Ptr<GsamSession>& found_or_created_session);
	void RespondIkeSaAuth (	Ptr<GsamSession> session,
							const Ptr<IkeSaProposal> chosen_proposal,
							const std::list<IkeTrafficSelector>& narrowed_tssi,
							const std::list<IkeTrafficSelector>& narrowed_tssr);
private:	//phase 2, Q
	void Send_GSA_PUSH (Ptr<GsamSession> session);
	void Send_GSA_PUSH_GM (Ptr<GsamSession> session);
	void Send_GSA_RE_PUSH (Ptr<GsaPushSession> gsa_push_session);
	void Send_GSA_PUSH_NQ (Ptr<GsamSession> session);
	void Send_SPI_REQUEST (Ptr<GsaPushSession> gsa_push_session, GsaPushSession::SPI_REQUEST_TYPE spi_request_type);
	void HandleGsaAckRejectSpiResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void HandleGsaAckRejectSpiResponseFromGM (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void HandleGsaAckFromGM (Ptr<Packet> packet, const IkePayload& pushed_gsa_payload, Ptr<GsamSession> session);
	void HandleGsaRejectionFromGM (Ptr<Packet> packet, const IkePayload& first_payload, Ptr<GsamSession> session);
	void HandleGsaSpiNotificationFromGM (Ptr<Packet> packet, const IkePayload& first_payload, Ptr<GsamSession> session);
	void HandleGsaAckRejectSpiResponseFromNQ (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void HandleGsaAckFromNQ (Ptr<Packet> packet, Ptr<GsamSession> session);
	void HandleGsaAckFromNQ (Ptr<Packet> packet, Ptr<GsamSession> session, Ptr<GsaPushSession> gsa_push_session);
	void HandleGsaRejectionFromNQ (Ptr<Packet> packet, Ptr<GsamSession> session);
	void HandleGsaRejectionFromNQ (Ptr<Packet> packet, Ptr<GsamSession> session, Ptr<GsaPushSession> gsa_push_session);
	void HandleGsaSpiNotificationFromNQ (Ptr<Packet> packet, Ptr<GsamSession> session);
	void ProcessGsaSpiNotificationFromNQ (Ptr<GsaPushSession> gsa_push_session);
	void DeliverToNQs (	Ptr<GsaPushSession> gsa_push_session,
						const IkePayload& payload_without_header,
						IkeHeader::EXCHANGE_TYPE exchange_type = IkeHeader::INFORMATIONAL);
	void DeliverToNQs (	Ptr<GsaPushSession> gsa_push_session,
						Ptr<Packet> packet_without_ikeheader,
						IkePayloadHeader::PAYLOAD_TYPE first_payload_type,
						IkeHeader::EXCHANGE_TYPE exchange_type);
private:	//phase 2, GM, NQ
	void HandleGsaInformational (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void HandleGsaPushSpiRequest (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void HandleSpiRequestGMNQ (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void SendSpiReportGMNQ (Ptr<GsamSession> session, uint32_t gsa_push_id);
	void HandleCreateChildSa (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void HandleGsaRepush (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void HandleGsaRepushGM (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void HandleGsaRepushNQ (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
private:	//phase 2, GM
	void HandleGsaPushSpiRequestGM (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void HandleGsaPushGM (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void ProcessGsaPushGM (	Ptr<GsamSession> session,
							uint32_t gsa_push_id,
							const IkeTrafficSelector& ts_src,
							const IkeTrafficSelector& ts_dest,
							const Ptr<IkeSaProposal> gsa_q_proposal,
							const Ptr<IkeSaProposal> gsa_r_proposal);
	void RejectGsaQ (	Ptr<GsamSession> session,
						uint32_t gsa_push_id,
						const IkeTrafficSelector& ts_src,
						const IkeTrafficSelector& ts_dest,
						const Ptr<IkeSaProposal> gsa_q_proposal);
	void AcceptGsaPair (Ptr<GsamSession> session,
						uint32_t gsa_push_id,
						const IkeTrafficSelector& ts_src,
						const IkeTrafficSelector& ts_dest,
						const Ptr<IkeSaProposal> gsa_q_proposal,
						const Ptr<IkeSaProposal> gsa_r_proposal);
	void InstallGsaPair (	Ptr<GsamSession> session,
							const IkeTrafficSelector& ts_src,
							const IkeTrafficSelector& ts_dest,
							const Ptr<IkeSaProposal> gsa_q_proposal,
							const Ptr<IkeSaProposal> gsa_r_proposal);
	void SendAcceptAck (Ptr<GsamSession> session,
						uint32_t gsa_push_id,
						const IkeTrafficSelector& ts_src,
						const IkeTrafficSelector& ts_dest,
						const Ptr<IkeSaProposal> gsa_q_proposal,
						const Ptr<IkeSaProposal> gsa_r_proposal);
private:	//phase 2, NQ
	void HandleGsaPushSpiRequestNQ (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void HandleGsaPushNQ (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void ProcessGsaPushNQForOneGrp (	Ptr<GsamSession> session,
							uint32_t gsa_push_id,
							const IkeTrafficSelector& ts_src,
							const IkeTrafficSelector& ts_dest,
							const std::list<Ptr<IkeSaProposal> >& gsa_proposals,
							std::list<Ptr<IkePayloadSubstructure> >& retval_toreject_payload_subs);
	void RejectGsaR (	Ptr<GsamSession> session,
						uint32_t gsa_push_id,
						const IkeTrafficSelector& ts_src,
						const IkeTrafficSelector& ts_dest,
						const std::list<uint32_t>& gsa_r_spis_to_reject,
						std::list<Ptr<IkePayloadSubstructure> >& retval_payload_subs);
	void ProcessNQRejectResult (Ptr<GsamSession> session, std::list<Ptr<IkePayloadSubstructure> >& retval_payload_subs);
	void SendAcceptAck (Ptr<GsamSession> session, uint32_t gsa_push_id);
private://experiencement
	void FakeRejection (Ptr<GsamSession> session, uint32_t u32_spi);
public:	//const
	Ptr<Igmpv3L4Protocol> GetIgmp (void) const;
	Ptr<IpSecDatabase> GetIpSecDatabase (void);
private:	//private staitc
	static Ptr<IkeSaProposal> ChooseSAProposalOffer (	const std::list<Ptr<IkeSaProposal> >& proposals);
	static void NarrowTrafficSelectors (const std::list<IkeTrafficSelector>& tsi_selectors,
												std::list<IkeTrafficSelector>& retval_narrowed_tsi_selectors);
private:	//database operation
	void Initialization (void);
	/*
	 * \brief CreateIpSecPolicy
	 * \Deprecated
	 */
	void CreateIpSecPolicy (Ptr<GsamSession> session, const IkeTrafficSelector& tsi, const IkeTrafficSelector& tsr);
	void CreateIpSecPolicy (Ptr<GsamSession> session,
							const std::list<IkeTrafficSelector>& tsi_selectors,
							const std::list<IkeTrafficSelector>& tsr_selectors);
public:	//utilities
	const Ptr<Node> GetNode (void) const;
	Ptr<GsamFilter> GetGsamFilter (void) const;
	static Ptr<GsamL4Protocol> GetGsam (Ptr<Node> node);
private:	//fields
	Ptr<Node> m_node; //!< the node this protocol is associated with
	Ptr<Socket> m_socket;
	Ptr<IpSecDatabase> m_ptr_database;
	Ptr<GsamFilter> m_ptr_gsam_filter;
};

} /* namespace ns3 */

#endif /* SRC_INTERNET_MODEL_GSAM_L4_PROTOCOL_H_ */
