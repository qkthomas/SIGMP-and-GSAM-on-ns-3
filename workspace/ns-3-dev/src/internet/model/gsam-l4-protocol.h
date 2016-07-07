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
	void Send_IKE_SA_INIT (Ptr<GsamSession> session, Ipv4Address dest);
	void Send_IKE_SA_AUTH (Ptr<GsamSession> session);
	void Send_GSA_Notification (Ptr<GsamSession> session);
	void Send_GSA_Acknowledgedment (Ptr<GsamSession> session);
private:	//Sending, added by Lin Chen,
	void SendMessage (Ptr<GsamSession> session, Ptr<Packet> packet, bool retransmit);
private:	//responing, added by Lin Chen
	//HandleIkeSaInit
	void HandleIkeSaInit (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void HandleIkeSaInitInvitation (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void HandleIkeSaInitResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void RespondIkeSaInit (Ptr<GsamSession> session);
	//HandleIkeSaAuth
	void HandleIkeSaAuth (Ptr<Packet> packet, const IkeHeader& ikeheader, Ipv4Address peer_address);
	void HandleIkeSaAuthInvitation (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void ProcessIkeSaAuthInvitation (Ptr<GsamSession> session, const IkePayload& id, const IkePayload& sai2, const IkePayload& tsi, const IkePayload& tsr);
	void ProcessIkeSaAuthResponse (Ptr<GsamSession> session, const IkePayload& sar2, const IkePayload& tsi, const IkePayload& tsr);
	void HandleIkeSaAuthResponse (Ptr<Packet> packet, const IkeHeader& ikeheader, Ptr<GsamSession> session);
	void RespondIkeSaAuth (Ptr<GsamSession> session);
private:	//database operation
	Ptr<IpSecDatabase> GetIpSecDatabase (void);
	void CreateIpsecPolicy (Ptr<GsamSession> session);
private:	//fields
	Ptr<Node> m_node; //!< the node this protocol is associated with
	Ptr<Socket> m_socket;
	Ptr<IpSecDatabase> m_ptr_database;
};

} /* namespace ns3 */

#endif /* SRC_INTERNET_MODEL_GSAM_L4_PROTOCOL_H_ */
