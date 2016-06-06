/*
 * Igmpv3-l4-protocol.h
 *
 *  Created on: Jan 27, 2016
 *      Author: lin
 */

#ifndef GSAM_L4_PROTOCOL_MULTICAST_H
#define GSAM_L4_PROTOCOL_MULTICAST_H

#include "ip-l4-protocol-multicast.h"
#include "gsam.h"

namespace ns3 {

class Node;
class Ipv4InterfaceMulticast;
class Ipv4Route;

class GsamL4Protocol: public IpL4ProtocolMulticast {

public:
	/**
	 * \brief Get the type ID.
	 * \return the object TypeId
	 */
	static TypeId GetTypeId (void);
	static const uint8_t PROT_NUMBER; //!< using UDP (0x11)

	GsamL4Protocol();
	virtual ~GsamL4Protocol();

	/**
	 * \brief Set the node the protocol is associated with.
	 * \param node the node
	 */
	void SetNode (Ptr<Node> node);

	/**
	 * Get the protocol number
	 * \returns the protocol number
	 */
	static uint16_t GetStaticProtocolNumber (void);

	/**
	 * Get the protocol number
	 * \returns the protocol number
	 */
	virtual int GetProtocolNumber (void) const;

	/**
	 * \brief Receive method.
	 * \param p the packet
	 * \param header the IPv4 header
	 * \param incomingInterface the interface from which the packet is coming
	 * \returns the receive status
	 */
	virtual enum IpL4ProtocolMulticast::RxStatus Receive (Ptr<Packet> p,
			Ipv4Header const &header,
			Ptr<Ipv4InterfaceMulticast> incomingInterface);

	/**
	 * \brief Receive method.
	 * \param p the packet
	 * \param header the IPv6 header
	 * \param incomingInterface the interface from which the packet is coming
	 * \returns the receive status
	 */
	virtual enum IpL4ProtocolMulticast::RxStatus Receive (Ptr<Packet> p,
			Ipv6Header const &header,
			Ptr<Ipv6Interface> incomingInterface);

	// From IpL4ProtocolMulticast
	virtual void SetDownTarget (IpL4ProtocolMulticast::DownTargetCallback cb);
	virtual void SetDownTarget6 (IpL4ProtocolMulticast::DownTargetCallback6 cb);
	// From IpL4ProtocolMulticast
	virtual IpL4ProtocolMulticast::DownTargetCallback GetDownTarget (void) const;
	virtual IpL4ProtocolMulticast::DownTargetCallback6 GetDownTarget6 (void) const;

public:	//added by Lin Chen
	void Initialization (void);
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:

	virtual void DoDispose (void);

	Ptr<Node> m_node; //!< the node this protocol is associated with
	IpL4ProtocolMulticast::DownTargetCallback m_downTarget; //!< callback to Ipv4::Send
};

} /* namespace ns3 */

#endif /* SRC_INTERNET_MODEL_GSAM_L4_PROTOCOL_H_ */
