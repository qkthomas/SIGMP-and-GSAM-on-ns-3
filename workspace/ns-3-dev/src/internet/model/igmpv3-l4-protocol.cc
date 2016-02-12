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

				Initialization();
			}
		}

	}
	IpL4ProtocolMulticast::NotifyNewAggregate ();
}

void
Igmpv3L4Protocol::Initialization (void)
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
Igmpv3L4Protocol::HandleQuery (Ptr<Packet> packet, uint8_t max_resp_code, Ptr<Ipv4InterfaceMulticast> incomingInterface)
{
	NS_LOG_FUNCTION (this << packet << max_resp_code << incomingInterface);
	Igmpv3Query query_header;
	packet->RemoveHeader(query_header);

	Ptr<UniformRandomVariable> rand = CreateObject<UniformRandomVariable> ();
	Time resp_time = Seconds(0.0);

	if (128 > max_resp_code) {
		uint8_t rand_resp_time = rand->GetInteger(0, max_resp_code);
		resp_time = Seconds((double)rand_resp_time / (double)10);
	}
	else
	{
		uint8_t exp = (max_resp_code >> 4) & 0x07;
		uint8_t mant = max_resp_code & 0x0f;
		uint8_t rand_resp_time = rand->GetInteger(0, ((mant | 0x10) << (exp + 3)));
		resp_time = Seconds((double)rand_resp_time / (double)10);
	}

	if (0 == query_header.GetGroupAddress())
	{
		this->HandleGeneralQuery (incomingInterface, resp_time);
	}
	else
	{
		this->HandleGroupSpecificQuery ();
	}
}

void
Igmpv3L4Protocol::HandleV1MemReport (void)
{
	//dummy
}

void
Igmpv3L4Protocol::HandleV2MemReport (void)
{
	//dummy
}

void
Igmpv3L4Protocol::HandleV3MemReport (Ptr<Packet> packet, Ptr<Ipv4InterfaceMulticast> incomingInterface)
{
	NS_LOG_FUNCTION (this << packet << incomingInterface);
}

void
Igmpv3L4Protocol::HandleGeneralQuery (Ptr<Ipv4InterfaceMulticast> incomingInterface, Time resp_time)
{
	NS_LOG_FUNCTION (this << incomingInterface << &resp_time);
	if (this->m_lst_per_interface_timers.empty())
	{
		std::cout << "Node id: " << this->m_node->GetId() << "'s has no per-interface-timer" << std::endl;
		std::cout << "Node id: " << this->m_node->GetId() << " creating a new timer for handling incoming General Query" << std::endl;
		Ptr<PerInterfaceTimer> pintimer = Create<PerInterfaceTimer>();
		Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast>();
		Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
		pintimer->m_interface = incomingInterface;
		std::cout << "Node id: " << this->m_node->GetId() << " biding time interface " << &(*(pintimer->m_interface)) << std::endl;
		pintimer->m_softTimer.SetFunction(&Igmpv3L4Protocol::SendCurrentStateReport, this);
		pintimer->m_softTimer.SetArguments(incomingInterface, pintimer);
		std::cout << "Node id: " << this->m_node->GetId() << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
		pintimer->m_softTimer.Schedule(resp_time);
		this->m_lst_per_interface_timers.push_back(pintimer);
	}

	else
	{
		for (	std::list<Ptr<PerInterfaceTimer> >::iterator it = this->m_lst_per_interface_timers.begin();
				it != this->m_lst_per_interface_timers.end();
				it++)
		{
			if (incomingInterface == (*it)->m_interface)
			{
				//there is timer for that interface in the maintained list of per interface timers
				//which means there is a pending query?
				std::cout << "Node id: " << this->m_node->GetId() << " has per-interface-timer of the same incoming interface" << std::endl;
				Ptr<PerInterfaceTimer> pintimer = (*it);
				if (resp_time > pintimer->m_softTimer.GetDelayLeft())
				{
					std::cout << "Node id: " << this->m_node->GetId() << " delay for next response is smaller than resp_time, need to schedule a new response" << std::endl;
					std::cout << "Node id: " << this->m_node->GetId() << " creating a new timer for handling incoming General Query" << std::endl;
					Ptr<PerInterfaceTimer> pintimer = Create<PerInterfaceTimer>();
					Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast>();
					Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
					pintimer->m_interface = incomingInterface;
					std::cout << "Node id: " << this->m_node->GetId() << " biding time interface " << &(*(pintimer->m_interface)) << std::endl;
					pintimer->m_softTimer.SetFunction(&Igmpv3L4Protocol::SendCurrentStateReport, this);
					pintimer->m_softTimer.SetArguments(incomingInterface, pintimer);
					std::cout << "Node id: " << this->m_node->GetId() << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
					pintimer->m_softTimer.Schedule(resp_time);
					//todo when the timer expires, it has to be removed from m_lst_per_interface_timers
					this->m_lst_per_interface_timers.push_back(pintimer);
				}
			}
			else
			{
				std::cout << "Node id: " << this->m_node->GetId() << "'s has no per-interface-timer matching the incoming interface" << std::endl;
				std::cout << "Node id: " << this->m_node->GetId() << " creating a new timer for handling incoming General Query" << std::endl;
				Ptr<PerInterfaceTimer> pintimer = Create<PerInterfaceTimer>();
				Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast>();
				Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
				pintimer->m_interface = incomingInterface;
				std::cout << "Node id: " << this->m_node->GetId() << " biding time interface " << &(*(pintimer->m_interface)) << std::endl;
				pintimer->m_softTimer.SetFunction(&Igmpv3L4Protocol::SendCurrentStateReport, this);
				pintimer->m_softTimer.SetArguments(incomingInterface, pintimer);
				std::cout << "Node id: " << this->m_node->GetId() << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
				pintimer->m_softTimer.Schedule(resp_time);
				this->m_lst_per_interface_timers.push_back(pintimer);
			}
		}
	}
}

void
Igmpv3L4Protocol::HandleGroupSpecificQuery (void)
{
	//Place Holder
}

void
Igmpv3L4Protocol::SendDefaultGeneralQuery (void)
{
	//testing, the following code has no meaning.
	Ptr<Ipv4Multicast> ipv4 = m_node->GetObject<Ipv4Multicast> ();
	for (uint32_t i = 0; i < this->m_node->GetNDevices(); i++)
	{
		Ptr<NetDevice> device = this->m_node->GetDevice(i);
		if (device->GetInstanceTypeId() != LoopbackNetDevice::GetTypeId())
		{
			Ptr<Packet> packet = Create<Packet> ();

			Igmpv3Query query;
			query.SetGroupAddress(0);
			query.SetSFlag(this->m_default_s_flag);
			query.SetQRV(this->m_default_qrv);
			query.SetQQIC(this->m_default_qqic);
			std::list<Ipv4Address> empty_lst__addresses;
			query.PushBackSrcAddresses(empty_lst__addresses);

			packet->AddHeader(query);

			Igmpv3Header header;
			header.SetType(Igmpv3Header::MEMBERSHIP_QUERY);
			header.SetMaxRespCode(this->m_default_max_resp_code);
			if (Node::ChecksumEnabled ())
			{
				header.EnableChecksum ();
			}

			packet->AddHeader(header);


			this->SendMessage (packet, this->m_GenQueAddress, 0);
		}
	}
}

void
Igmpv3L4Protocol::SendCurrentStateReport (Ptr<Ipv4InterfaceMulticast> incomingInterface, Ptr<PerInterfaceTimer> pintimer)
{
	NS_LOG_FUNCTION (this << incomingInterface);

	Ptr<Packet> packet = Create<Packet>();

	std::list<Igmpv3GrpRecord> lst_grp_records;

	for (	std::list<IGMPv3InterfaceState>::iterator it = this->m_lst_interface_states.begin();
			it != this->m_lst_interface_states.end();
			it++)
	{
		if (incomingInterface == (*it).m_interface)
		{
			Igmpv3GrpRecord record;
			if ((*it).m_filter_mode == /*FILTER_MODE::*/EXCLUDE)
			{
				record.SetType(Igmpv3GrpRecord::MODE_IS_EXCLUDE);
			}
			else
			{
				record.SetType(Igmpv3GrpRecord::MODE_IS_INCLUDE);
			}
			record.SetAuxDataLen(0);
			record.SetNumSrcs((*it).m_lst_source_list.size());
			record.SetMulticastAddress((*it).m_multicast_address);
			record.PushBackSrcAddresses((*it).m_lst_source_list);

			lst_grp_records.push_back(record);
		}
	}

	Igmpv3Report report;
	report.SetNumGrpRecords(lst_grp_records.size());
	report.PushBackGrpRecords(lst_grp_records);

	packet->AddHeader(report);

	Igmpv3Header igmpv3;
	igmpv3.SetType(Igmpv3Header::V3_MEMBERSHIP_REPORT);
	igmpv3.SetMaxRespCode(this->m_default_max_resp_code);

	if (Node::ChecksumEnabled ()) {
		igmpv3.EnableChecksum();
	}

	packet->AddHeader(igmpv3);

	std::cout << "Node: " << this->m_node->GetId() << " reporting a general query to the querier" << std::endl;

	Ptr<Ipv4Multicast> ipv4 = m_node->GetObject<Ipv4Multicast> ();
	NS_ASSERT (ipv4 != 0 && ipv4->GetRoutingProtocol () != 0);
	Ipv4Header header;
	header.SetProtocol (PROT_NUMBER);
	Socket::SocketErrno errno_;
	Ptr<Ipv4Route> route;
	Ptr<NetDevice> oif = incomingInterface->GetDevice();
	route = ipv4->GetRoutingProtocol ()->RouteOutput (packet, header, oif, errno_);
	if (route != 0)
	{
		NS_LOG_LOGIC ("Route exists");
		//Ipv4Address source = route->GetSource ();
		SendMessage (packet, this->m_RptAddress, route);
	}
	else
	{
		NS_LOG_WARN ("drop icmp repoty");
	}

	//dequeue timer from m_lst_per_interface_timers
	for (	std::list<Ptr<PerInterfaceTimer> >::iterator it = this->m_lst_per_interface_timers.begin();
			it != this->m_lst_per_interface_timers.end();
			it++)
	{
		if (pintimer == (*it))
		{
			this->m_lst_per_interface_timers.erase(it);
			break;
		}
	}

}

void
Igmpv3L4Protocol::SendMessage (Ptr<Packet> packet, Ipv4Address dest, Ptr<Ipv4Route> route)
{
	NS_LOG_FUNCTION (this << packet << dest << route);
	//Ptr<Ipv4Multicast> ipv4 = m_node->GetObject<Ipv4Multicast> ();
	//NS_ASSERT (ipv4 != 0 && ipv4->GetRoutingProtocol () != 0);
	//  Ipv4Header header;
	//  header.SetDestination (dest);
	//  header.SetProtocol (PROT_NUMBER);
	//  Socket::SocketErrno errno_;
	//  Ptr<Ipv4Route> route;
	//  Ptr<NetDevice> oif (0); //specify non-zero if bound to a source address
	//  route = ipv4->GetRoutingProtocol ()->RouteOutput (packet, header, oif, errno_);
	//  if (route != 0)
	//    {
	//      NS_LOG_LOGIC ("Route exists");
	//      Ipv4Address source = route->GetSource ();
	//      SendMessage (packet, source, dest, type, code, route);
	//    }
	//  else
	//    {
	//      NS_LOG_WARN ("drop icmp message");
	//    }

	if (0 == route) {
		//for query
		NS_LOG_LOGIC ("Route exists");
		Ipv4Address source = "0.0.0.0";

		//ttl == 1, igmp packet
		SocketIpTtlTag ttltag;
		ttltag.SetTtl (1);
		packet->AddPacketTag(ttltag);

		m_downTarget (packet, source, dest, PROT_NUMBER, route);
	}
	else
	{
		//todo for report
		Ipv4Address source = route->GetSource();

		//ttl == 1, igmp packet
		SocketIpTtlTag ttltag;
		ttltag.SetTtl (1);
		packet->AddPacketTag(ttltag);

		m_downTarget (packet, source, dest, PROT_NUMBER, route);
	}

}

//void
//Igmpv3L4Protocol::SendMessage (Ptr<Packet> packet, Ipv4Address source, Ipv4Address dest, uint8_t type, uint8_t code, Ptr<Ipv4Route> route)
//{
//  NS_LOG_FUNCTION (this << packet << source << dest << static_cast<uint32_t> (type) << static_cast<uint32_t> (code) << route);
//  Icmpv4Header icmp;
//  icmp.SetType (type);
//  icmp.SetCode (code);
//  if (Node::ChecksumEnabled ())
//    {
//      icmp.EnableChecksum ();
//    }
//  packet->AddHeader (icmp);
//
//  m_downTarget (packet, source, dest, PROT_NUMBER, route);
//}

enum IpL4ProtocolMulticast::RxStatus
Igmpv3L4Protocol::Receive (Ptr<Packet> p,
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
