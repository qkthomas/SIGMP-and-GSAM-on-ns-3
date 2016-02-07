/*
 * Icmpv3-l4-protocol.cc
 *
 *  Created on: Jan 27, 2016
 *      Author: lin
 */

#include "igmpv3-l4-protocol.h"
#include "ipv4-raw-socket-factory-impl-multicast.h"
#include "ipv4-interface-multicast.h"
#include "ipv4-l3-protocol-multicast.h"
#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/boolean.h"
#include "ns3/ipv4-route.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("Igmpv3L4Protocol");

NS_OBJECT_ENSURE_REGISTERED (Igmpv3L4Protocol);

// see rfc 792
const uint8_t Igmpv3L4Protocol::PROT_NUMBER = 2;

TypeId
Igmpv3L4Protocol::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::Igmpv3L4Protocol")
    .SetParent<IpL4ProtocolMulticast> ()
    .SetGroupName ("Internet")
    .AddConstructor<Igmpv3L4Protocol> ()
  ;
  return tid;
}

Igmpv3L4Protocol::Igmpv3L4Protocol()
: m_node (0)
{
	// TODO Auto-generated constructor stub
	NS_LOG_FUNCTION (this);
}

Igmpv3L4Protocol::~Igmpv3L4Protocol()
{
	// TODO Auto-generated destructor stub
	NS_LOG_FUNCTION (this);
	NS_ASSERT (m_node == 0);
}

void
Igmpv3L4Protocol::SetNode(Ptr<Node> node)
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
Igmpv3L4Protocol::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
	if (m_node == 0)
	{
		Ptr<Node> node = this->GetObject<Node> ();
		if (node != 0)
		{
			Ptr<Ipv4Multicast> ipv4 = this->GetObject<Ipv4Multicast> ();
			if (ipv4 != 0 && m_downTarget.IsNull ())
			{
				this->SetNode (node);
				ipv4->Insert (this);
				//the Icmpv3L4Protocol should have aggregate Ipv4RawSocketFactoryImplMulticast already.
				//				Ptr<Ipv4RawSocketFactoryImplMulticast> rawFactory = CreateObject<Ipv4RawSocketFactoryImplMulticast> ();
				//				ipv4->AggregateObject (rawFactory);
				this->SetDownTarget (MakeCallback (&Ipv4Multicast::Send, ipv4));
			}
		}
	}
	IpL4ProtocolMulticast::NotifyNewAggregate ();
}

uint16_t
Igmpv3L4Protocol::GetStaticProtocolNumber (void)
{
	NS_LOG_FUNCTION_NOARGS ();
	return PROT_NUMBER;
}

int
Igmpv3L4Protocol::GetProtocolNumber (void) const
{
	NS_LOG_FUNCTION (this);
	return PROT_NUMBER;
}

void
Igmpv3L4Protocol::SendMessage (Ptr<Packet> packet, Ipv4Address dest, uint8_t type, uint8_t code)
{
  NS_LOG_FUNCTION (this << packet << dest << static_cast<uint32_t> (type) << static_cast<uint32_t> (code));
  Ptr<Ipv4Multicast> ipv4 = m_node->GetObject<Ipv4Multicast> ();
  NS_ASSERT (ipv4 != 0 && ipv4->GetRoutingProtocol () != 0);
  Ipv4Header header;
  header.SetDestination (dest);
  header.SetProtocol (PROT_NUMBER);
  Socket::SocketErrno errno_;
  Ptr<Ipv4Route> route;
  Ptr<NetDevice> oif (0); //specify non-zero if bound to a source address
  route = ipv4->GetRoutingProtocol ()->RouteOutput (packet, header, oif, errno_);
  if (route != 0)
    {
      NS_LOG_LOGIC ("Route exists");
      Ipv4Address source = route->GetSource ();
      SendMessage (packet, source, dest, type, code, route);
    }
  else
    {
      NS_LOG_WARN ("drop icmp message");
    }
}

void
Igmpv3L4Protocol::SendMessage (Ptr<Packet> packet, Ipv4Address source, Ipv4Address dest, uint8_t type, uint8_t code, Ptr<Ipv4Route> route)
{
  NS_LOG_FUNCTION (this << packet << source << dest << static_cast<uint32_t> (type) << static_cast<uint32_t> (code) << route);
  Icmpv4Header icmp;
  icmp.SetType (type);
  icmp.SetCode (code);
  if (Node::ChecksumEnabled ())
    {
      icmp.EnableChecksum ();
    }
  packet->AddHeader (icmp);

  m_downTarget (packet, source, dest, PROT_NUMBER, route);
}

enum IpL4ProtocolMulticast::RxStatus
Igmpv3L4Protocol::Receive (Ptr<Packet> p,
		Ipv4Header const &header,
		Ptr<Ipv4InterfaceMulticast> incomingInterface)
{
	NS_LOG_FUNCTION (this << p << header << incomingInterface);
	return IpL4ProtocolMulticast::RX_OK;
}
enum IpL4ProtocolMulticast::RxStatus
Igmpv3L4Protocol::Receive (Ptr<Packet> p,
		Ipv6Header const &header,
		Ptr<Ipv6Interface> incomingInterface)
{
	NS_LOG_FUNCTION (this << p << header.GetSourceAddress () << header.GetDestinationAddress () << incomingInterface);
	return IpL4ProtocolMulticast::RX_ENDPOINT_UNREACH;
}
void
Igmpv3L4Protocol::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
	m_node = 0;
	m_downTarget.Nullify ();
	IpL4ProtocolMulticast::DoDispose ();
}

void
Igmpv3L4Protocol::SetDownTarget (IpL4ProtocolMulticast::DownTargetCallback callback)
{
	NS_LOG_FUNCTION (this << &callback);
	m_downTarget = callback;
}

void
Igmpv3L4Protocol::SetDownTarget6 (IpL4ProtocolMulticast::DownTargetCallback6 callback)
{
	NS_LOG_FUNCTION (this << &callback);
}

IpL4ProtocolMulticast::DownTargetCallback
Igmpv3L4Protocol::GetDownTarget (void) const
{
	NS_LOG_FUNCTION (this);
	return m_downTarget;
}

IpL4ProtocolMulticast::DownTargetCallback6
Igmpv3L4Protocol::GetDownTarget6 (void) const
{
	NS_LOG_FUNCTION (this);
	return (IpL4ProtocolMulticast::DownTargetCallback6)NULL;
}

} /* namespace ns3 */
