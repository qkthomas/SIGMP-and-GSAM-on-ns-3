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
#include "loopback-net-device.h"
#include "ns3/core-module.h"
#include "ns3/nstime.h"
#include "ipv4-raw-socket-impl-multicast.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("GsamL4Protocol");

NS_OBJECT_ENSURE_REGISTERED (GsamL4Protocol);

// see rfc 792
const uint8_t Igmpv3L4Protocol::PROT_NUMBER = 17;

TypeId
GsamL4Protocol::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::GsamL4Protocol")
    		.SetParent<IpL4ProtocolMulticast> ()
			.SetGroupName ("Internet")
			.AddConstructor<GsamL4Protocol> ()
			;
	return tid;
}

GsamL4Protocol::GsamL4Protocol()
: m_node (0),
  m_default_s_flag (false),		//assumed default
  m_default_qqic (125),			//125sec, cisco default
  m_default_qrv (2),			//cisco default
  m_default_max_resp_code (100),	//10sec, cisco default
  m_GenQueAddress ("224.0.0.1"),
  m_RptAddress ("224.0.0.22"),
  m_role (Igmpv3L4Protocol::HOST)
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
			if (ipv4 != 0 && m_downTarget.IsNull ())
			{
				this->SetNode (node);
				ipv4->Insert (this);
				//the Icmpv3L4Protocol should have aggregate Ipv4RawSocketFactoryImplMulticast already.
				//				Ptr<Ipv4RawSocketFactoryImplMulticast> rawFactory = CreateObject<Ipv4RawSocketFactoryImplMulticast> ();
				//				ipv4->AggregateObject (rawFactory);
				this->SetDownTarget (MakeCallback (&Ipv4Multicast::Send, ipv4));

				Initialization();
			}
		}

	}
	IpL4ProtocolMulticast::NotifyNewAggregate ();
}

void
GsamL4Protocol::Initialization (void)
{
	NS_LOG_FUNCTION (this);

	//place holder, just set the first node as the querier.
	//But in fact, That who plays the querier decided by negotiation between routers
	if (0 == m_node->GetId())
	{
		this->m_role = Igmpv3L4Protocol::QUERIER;
	}
}

uint16_t
GsamL4Protocol::GetStaticProtocolNumber (void)
{
	NS_LOG_FUNCTION_NOARGS ();
	return PROT_NUMBER;
}

int
GsamL4Protocol::GetProtocolNumber (void) const
{
	NS_LOG_FUNCTION (this);
	return PROT_NUMBER;
}

enum IpL4ProtocolMulticast::RxStatus
GsamL4Protocol::Receive (Ptr<Packet> p,
		Ipv4Header const &header,
		Ptr<Ipv4InterfaceMulticast> incomingInterface)
{
	NS_LOG_FUNCTION (this << p << header << incomingInterface);

	Igmpv3Header igmp;
	p->RemoveHeader (igmp);
	switch (igmp.GetType ()) {
	case Igmpv3Header::MEMBERSHIP_QUERY:
		//HandleEcho (p, igmp, header.GetSource (), header.GetDestination ());
		std::cout << "Node: " << m_node->GetId() << " received a query" << std::endl;
		if (Igmpv3L4Protocol::HOST == this->m_role) {
			this->HandleQuery(p, igmp.GetMaxRespCode(), incomingInterface);
		}
		else if (Igmpv3L4Protocol::NONQUERIER == this->m_role)
		{
			this->NonQHandleQuery(p, igmp.GetMaxRespCode(), incomingInterface);
		}
		break;
	case Igmpv3Header::V1_MEMBERSHIP_REPORT:
		//HandleTimeExceeded (p, igmp, header.GetSource (), header.GetDestination ());
		std::cout << "Node: " << m_node->GetId() << " received a v1 report" << std::endl;
		if (Igmpv3L4Protocol::QUERIER == this->m_role) {
			//dummy
			this->HandleV1MemReport ();
		}
		break;
	case Igmpv3Header::V2_MEMBERSHIP_REPORT:
		std::cout << "Node: " << m_node->GetId() << " received a v2 report" << std::endl;
		if (Igmpv3L4Protocol::QUERIER == this->m_role) {
			//dummy
			this->HandleV2MemReport ();
		}
		break;
	case Igmpv3Header::V3_MEMBERSHIP_REPORT:
		std::cout << "Node: " << m_node->GetId() << " received a v3 report" << std::endl;
		if (Igmpv3L4Protocol::QUERIER == this->m_role) {
			this->HandleV3MemReport (p, incomingInterface);
		}
		break;
	default:
		NS_LOG_DEBUG (igmp << " " << *p);
		std::cout << "Node: " << m_node->GetId() << " did not find a appropriate type in IGMP header" << std::endl;
		break;
	}

	return IpL4ProtocolMulticast::RX_OK;
}
enum IpL4ProtocolMulticast::RxStatus
GsamL4Protocol::Receive (Ptr<Packet> p,
		Ipv6Header const &header,
		Ptr<Ipv6Interface> incomingInterface)
{
	NS_LOG_FUNCTION (this << p << header.GetSourceAddress () << header.GetDestinationAddress () << incomingInterface);
	return IpL4ProtocolMulticast::RX_ENDPOINT_UNREACH;
}
void
GsamL4Protocol::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
	m_node = 0;
	m_downTarget.Nullify ();
	IpL4ProtocolMulticast::DoDispose ();
}

void
GsamL4Protocol::SetDownTarget (IpL4ProtocolMulticast::DownTargetCallback callback)
{
	NS_LOG_FUNCTION (this << &callback);
	m_downTarget = callback;
}

void
GsamL4Protocol::SetDownTarget6 (IpL4ProtocolMulticast::DownTargetCallback6 callback)
{
	NS_LOG_FUNCTION (this << &callback);
}

IpL4ProtocolMulticast::DownTargetCallback
GsamL4Protocol::GetDownTarget (void) const
{
	NS_LOG_FUNCTION (this);
	return m_downTarget;
}

IpL4ProtocolMulticast::DownTargetCallback6
GsamL4Protocol::GetDownTarget6 (void) const
{
	NS_LOG_FUNCTION (this);
	return (IpL4ProtocolMulticast::DownTargetCallback6)NULL;
}

} /* namespace ns3 */
