/*
 * Igmpv3-l4-protocol.h
 *
 *  Created on: Jan 27, 2016
 *      Author: lin
 */

#ifndef IGMPV3_L4_PROTOCOL_MULTICAST_H
#define IGMPV3_L4_PROTOCOL_MULTICAST_H

#include "ip-l4-protocol-multicast.h"
#include "igmpv3.h"

namespace ns3 {

class Node;
class Ipv4InterfaceMulticast;
class Ipv4Route;

class Igmpv3L4Protocol: public IpL4ProtocolMulticast {
public:
	/**
	 * \brief Get the type ID.
	 * \return the object TypeId
	 */
	static TypeId GetTypeId (void);
	static const uint8_t PROT_NUMBER; //!< IGMP protocol number (0x2)

	Igmpv3L4Protocol();
	virtual ~Igmpv3L4Protocol();

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
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	/**
	 * \brief Send a generic IGMPv3 packet
	 *
	 * \param packet the packet
	 * \param dest the destination
	 * \param type the IGMPv3 type
	 * \param code the IGMPv3 code
	 */
	void SendMessage (Ptr<Packet> packet, Ipv4Address dest, uint8_t type, uint8_t code);
	/**
	 * \brief Send a generic IGMPv3 packet
	 *
	 * \param packet the packet
	 * \param source the source
	 * \param dest the destination
	 * \param type the IGMPv3 type
	 * \param code the IGMPv3 code
	 * \param route the route to be used
	 */
	void SendMessage (Ptr<Packet> packet, Ipv4Address source, Ipv4Address dest, uint8_t type, uint8_t code, Ptr<Ipv4Route> route);

	virtual void DoDispose (void);

	Ptr<Node> m_node; //!< the node this protocol is associated with
	IpL4ProtocolMulticast::DownTargetCallback m_downTarget; //!< callback to Ipv4::Send
};

} /* namespace ns3 */

#endif /* SRC_INTERNET_MODEL_IGMPV3_L4_PROTOCOL_H_ */