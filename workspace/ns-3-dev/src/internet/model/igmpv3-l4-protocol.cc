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
#include "gsam-l4-protocol.h"

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
  m_role (Igmpv3L4Protocol::HOST),
  m_gsam (0)
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
Igmpv3L4Protocol::SetRole (Igmpv3L4Protocol::ROLE role)
{
	this->m_role = role;
}

Igmpv3L4Protocol::ROLE
Igmpv3L4Protocol::GetRole (void)
{
	return this->m_role;
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

//	Ptr<UniformRandomVariable> rand = CreateObject<UniformRandomVariable> ();
//	Time resp_time = Seconds(0.0);
//
//	if (128 > max_resp_code) {
//		uint8_t rand_resp_time = rand->GetInteger(0, max_resp_code);
//		resp_time = Seconds((double)rand_resp_time / (double)10);
//	}
//	else
//	{
//		uint8_t exp = (max_resp_code >> 4) & 0x07;
//		uint8_t mant = max_resp_code & 0x0f;
//		uint8_t rand_resp_time = rand->GetInteger(0, ((mant | 0x10) << (exp + 3)));
//		resp_time = Seconds((double)rand_resp_time / (double)10);
//	}

	Time resp_time = this->GetRandomTime(this->GetMaxRespTime(max_resp_code));

	if (0 == query_header.GetGroupAddress())
	{
		incomingInterface->HandleGeneralQuery(resp_time);
		//this->HandleGeneralQuery (incomingInterface, resp_time);
	}
	else
	{
		if (0 == query_header.GetNumSrc())
		{
			incomingInterface->HandleGroupSpecificQuery (resp_time, Ipv4Address(query_header.GetGroupAddress()));
		}
		else
		{
			std::list<Ipv4Address> src_addresses;
			uint16_t num_src_addresses = query_header.GetSrcAddresses(src_addresses);
			if (num_src_addresses != src_addresses.size())
			{
				NS_ASSERT (false);
			}
			incomingInterface->HandleGroupNSrcSpecificQuery(resp_time, Ipv4Address(query_header.GetGroupAddress()), src_addresses);
		}
	}
}

void
Igmpv3L4Protocol::NonQHandleQuery (Ptr<Packet> packet, uint8_t max_resp_code, Ptr<Ipv4InterfaceMulticast> incomingInterface)
{
	NS_LOG_FUNCTION (this << packet << max_resp_code << incomingInterface);
	Igmpv3Query query_header;
	packet->RemoveHeader(query_header);

	if (true == query_header.isSFlagSet())
	{
		if (0 == query_header.GetGroupAddress())
		{
			//ignore, this is a non querier
		}
		else
		{
			if (0 == query_header.GetNumSrc())
			{
				incomingInterface->NonQHandleGroupSpecificQuery (Ipv4Address(query_header.GetGroupAddress()));
			}
			else
			{
				std::list<Ipv4Address> src_addresses;
				uint16_t num_src_addresses = query_header.GetSrcAddresses(src_addresses);
				if (num_src_addresses != src_addresses.size())
				{
					NS_ASSERT (false);
				}
				incomingInterface->NonQHandleGroupNSrcSpecificQuery(Ipv4Address(query_header.GetGroupAddress()), src_addresses);
			}
		}
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

	Igmpv3Report report;
	packet->RemoveHeader(report);

	std::list<Igmpv3GrpRecord> records;
	uint16_t num_records = report.GetGrpRecords(records);

	if (num_records != report.GetNumGrpRecords())
	{
		NS_ASSERT (false);
	}

	if (num_records != records.size())
	{
		NS_ASSERT (false);
	}

	incomingInterface->HandleV3Records(records);
}

//void
//Igmpv3L4Protocol::HandleGeneralQuery (Ptr<Ipv4InterfaceMulticast> incomingInterface, Time resp_time)
//{
//	NS_LOG_FUNCTION (this << incomingInterface << &resp_time);
//	if (this->m_lst_per_interface_timers.empty())
//	{
//		std::cout << "Node id: " << this->m_node->GetId() << "'s has no per-interface-timer" << std::endl;
//		std::cout << "Node id: " << this->m_node->GetId() << " creating a new timer for handling incoming General Query" << std::endl;
//		Ptr<PerInterfaceTimer> pintimer = Create<PerInterfaceTimer>();
//		Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast>();
//		Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
//		pintimer->m_interface = incomingInterface;
//		std::cout << "Node id: " << this->m_node->GetId() << " biding time interface " << &(*(pintimer->m_interface)) << std::endl;
//		pintimer->m_softTimer.SetFunction(&Igmpv3L4Protocol::SendCurrentStateReport, this);
//		pintimer->m_softTimer.SetArguments(incomingInterface, pintimer);
//		std::cout << "Node id: " << this->m_node->GetId() << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
//		pintimer->m_softTimer.Schedule(resp_time);
//		this->m_lst_per_interface_timers.push_back(pintimer);
//	}
//
//	else
//	{
//		for (	std::list<Ptr<PerInterfaceTimer> >::iterator it = this->m_lst_per_interface_timers.begin();
//				it != this->m_lst_per_interface_timers.end();
//				it++)
//		{
//			if (incomingInterface == (*it)->m_interface)
//			{
//				//there is timer for that interface in the maintained list of per interface timers
//				//which means there is a pending query?
//				std::cout << "Node id: " << this->m_node->GetId() << " has per-interface-timer of the same incoming interface" << std::endl;
//				Ptr<PerInterfaceTimer> pintimer = (*it);
//				if (resp_time > pintimer->m_softTimer.GetDelayLeft())
//				{
//					std::cout << "Node id: " << this->m_node->GetId() << " delay for next response is smaller than resp_time, need to schedule a new response" << std::endl;
//					std::cout << "Node id: " << this->m_node->GetId() << " creating a new timer for handling incoming General Query" << std::endl;
//					Ptr<PerInterfaceTimer> pintimer = Create<PerInterfaceTimer>();
//					Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast>();
//					Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
//					pintimer->m_interface = incomingInterface;
//					std::cout << "Node id: " << this->m_node->GetId() << " biding time interface " << &(*(pintimer->m_interface)) << std::endl;
//					pintimer->m_softTimer.SetFunction(&Igmpv3L4Protocol::SendCurrentStateReport, this);
//					pintimer->m_softTimer.SetArguments(incomingInterface, pintimer);
//					std::cout << "Node id: " << this->m_node->GetId() << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
//					pintimer->m_softTimer.Schedule(resp_time);
//					//todo when the timer expires, it has to be removed from m_lst_per_interface_timers
//					this->m_lst_per_interface_timers.push_back(pintimer);
//				}
//			}
//			else
//			{
//				std::cout << "Node id: " << this->m_node->GetId() << "'s has no per-interface-timer matching the incoming interface" << std::endl;
//				std::cout << "Node id: " << this->m_node->GetId() << " creating a new timer for handling incoming General Query" << std::endl;
//				Ptr<PerInterfaceTimer> pintimer = Create<PerInterfaceTimer>();
//				Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast>();
//				Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
//				pintimer->m_interface = incomingInterface;
//				std::cout << "Node id: " << this->m_node->GetId() << " biding time interface " << &(*(pintimer->m_interface)) << std::endl;
//				pintimer->m_softTimer.SetFunction(&Igmpv3L4Protocol::SendCurrentStateReport, this);
//				pintimer->m_softTimer.SetArguments(incomingInterface, pintimer);
//				std::cout << "Node id: " << this->m_node->GetId() << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
//				pintimer->m_softTimer.Schedule(resp_time);
//				this->m_lst_per_interface_timers.push_back(pintimer);
//			}
//		}
//	}
//}

void
Igmpv3L4Protocol::HandleGroupSpecificQuery (void)
{
	//Place Holder
}

//void
//Igmpv3L4Protocol::IPMulticastListen (Ptr<Socket> socket,
//									 Ptr<Ipv4InterfaceMulticast> interface,
//									 Ipv4Address multicast_address,
//									 ns3::FILTER_MODE filter_mode,
//									 std::list<Ipv4Address> &source_list)
//{
//	std::list<Ptr<Socket> >::iterator it = this->m_lst_socket_accessors.begin();
//	while(it != this->m_lst_socket_accessors.end())
//	{
//		if ((socket == (*it)))
//		{
//			Ptr<Ipv4RawSocketImplMulticast> raw_socket = DynamicCast<Ipv4RawSocketImplMulticast> (socket);
//			//Ipv4RawSocketImplMulticast::IPMCL_STATUS ipmcl_status =
//			raw_socket->IPMulticastListen (interface, multicast_address, filter_mode, source_list);
//			if (ipmcl_status == Ipv4RawSocketImplMulticast::DELETED)
//			{
//				it = this->m_lst_socket_accessors.erase(it);
//				continue;
//			}
//		}
//		else
//		{
//			//continue;
//		}
//		it++;
//	}
//}

void
Igmpv3L4Protocol::IPMulticastListen (Ptr<Ipv4InterfaceMulticast> interface,
									 Ipv4Address multicast_address,
									 ns3::FILTER_MODE filter_mode,
									 std::list<Ipv4Address> &source_list)
{
	for (std::list<Ptr<Ipv4InterfaceMulticast> >::iterator it = this->m_lst_interface_accessors.begin();
		 it != this->m_lst_interface_accessors.end();
		 it++)
	{

	}
}

//void
//Igmpv3L4Protocol::SendStateChangeReport (std::list<Igmpv3GrpRecord> &records)
//{
//	//Igmpv3Report.
//
//	//todo take a bunch of state change records and send them out
//	//top entry (invocation) should be from sockets
//}

void
Igmpv3L4Protocol::SendDefaultGeneralQuery (void)
{
//	//testing, the following code has no meaning.
//	Ptr<Ipv4Multicast> ipv4 = m_node->GetObject<Ipv4Multicast> ();
//	for (uint32_t i = 0; i < this->m_node->GetNDevices(); i++)
//	{
//		Ptr<NetDevice> device = this->m_node->GetDevice(i);
//		if (device->GetInstanceTypeId() != LoopbackNetDevice::GetTypeId())
//		{
//			Ptr<Packet> packet = Create<Packet> ();
//
//			Igmpv3Query query;
//			query.SetGroupAddress(0);
//			query.SetSFlag(this->m_default_s_flag);
//			query.SetQRV(this->m_default_qrv);
//			query.SetQQIC(this->m_default_qqic);
//			std::list<Ipv4Address> empty_lst__addresses;
//			query.PushBackSrcAddresses(empty_lst__addresses);
//
//			packet->AddHeader(query);
//
//			Igmpv3Header header;
//			header.SetType(Igmpv3Header::MEMBERSHIP_QUERY);
//			header.SetMaxRespCode(this->m_default_max_resp_code);
//			if (Node::ChecksumEnabled ())
//			{
//				header.EnableChecksum ();
//			}
//
//			packet->AddHeader(header);
//
//
//			this->SendMessage (packet, this->m_GenQueAddress, 0);
//		}
//	}

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

	std::cout << "Node: " << m_node->GetId() << " sending a default general query" << std::endl;

	this->SendMessage (packet, this->m_GenQueAddress, 0);

}

void
Igmpv3L4Protocol::SendReport (Ptr<Ipv4InterfaceMulticast> incomingInterface, Ptr<Packet> packet)
{
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
}


// *Obsolete* Move to Ipv4InterfaceMulticast
//void
//Igmpv3L4Protocol::SendCurrentStateReport (Ptr<Ipv4InterfaceMulticast> incomingInterface, Ptr<PerInterfaceTimer> pintimer)
//{
//	NS_LOG_FUNCTION (this << incomingInterface);
//
//	Ptr<Packet> packet = Create<Packet>();
//
//	std::list<Igmpv3GrpRecord> lst_grp_records;
//
//	for (	std::list<Ptr<Ipv4InterfaceMulticast> >::iterator it = this->m_lst_interface_accessors.begin();
//			it != this->m_lst_interface_accessors.end();
//			it++)
//	{
//		if (incomingInterface == (*it))
//		{
//			std::list<Ptr<IGMPv3InterfaceState> > ifstates = (*it)->GetInterfaceStates();
//
//			for (std::list<Ptr<IGMPv3InterfaceState> >::iterator ifstate_it = ifstates.begin();
//					ifstate_it != ifstates.end();
//					ifstate_it++)
//			{
//				Ptr<IGMPv3InterfaceState> if_state = (*ifstate_it);
//
//				Igmpv3GrpRecord record;
//				if (if_state->GetFilterMode() == /*FILTER_MODE::*/EXCLUDE)
//				{
//					record.SetType(Igmpv3GrpRecord::MODE_IS_EXCLUDE);
//				}
//				else
//				{
//					record.SetType(Igmpv3GrpRecord::MODE_IS_INCLUDE);
//				}
//				record.SetAuxDataLen(0);
//				record.SetNumSrcs(if_state->GetSrcNum());
//				record.SetMulticastAddress(if_state->GetGroupAddress());
//				record.PushBackSrcAddresses(if_state->GetSrcList());
//
//				lst_grp_records.push_back(record);
//			}
//		}
//	}
//
//	Igmpv3Report report;
//	report.SetNumGrpRecords(lst_grp_records.size());
//	report.PushBackGrpRecords(lst_grp_records);
//
//	packet->AddHeader(report);
//
//	Igmpv3Header igmpv3;
//	igmpv3.SetType(Igmpv3Header::V3_MEMBERSHIP_REPORT);
//	igmpv3.SetMaxRespCode(this->m_default_max_resp_code);
//
//	if (Node::ChecksumEnabled ()) {
//		igmpv3.EnableChecksum();
//	}
//
//	packet->AddHeader(igmpv3);
//
//	std::cout << "Node: " << this->m_node->GetId() << " reporting a general query to the querier" << std::endl;
//
//	this->SendReport(incomingInterface, packet);
//
//	//dequeue timer from m_lst_per_interface_timers
//	for (	std::list<Ptr<PerInterfaceTimer> >::iterator it = this->m_lst_per_interface_timers.begin();
//			it != this->m_lst_per_interface_timers.end();
//			it++)
//	{
//		if (pintimer == (*it))
//		{
//			this->m_lst_per_interface_timers.erase(it);
//			break;
//		}
//	}
//
//}

void
Igmpv3L4Protocol::SendStateChangesReport (Ptr<Ipv4InterfaceMulticast> incomingInterface)
{
	for (std::list<Ptr<Ipv4InterfaceMulticast> >::iterator it = this->m_lst_interface_accessors.begin();
		 it != this->m_lst_interface_accessors.end();
		 it++)
	{
		if ((*it) == incomingInterface)
		{
			Igmpv3Report report;

			incomingInterface->AddPendingRecordsToReport(report);

			if (0 < report.GetNumGrpRecords())
			{
				Ptr<Packet> packet = Create<Packet>();
				packet->AddHeader(report);

				Igmpv3Header header;
				header.SetType(Igmpv3Header::V3_MEMBERSHIP_REPORT);
				if (true == incomingInterface->GetDevice()->GetNode()->ChecksumEnabled())
				{
					header.EnableChecksum();
				}

				packet->AddHeader(header);

				this->SendReport(incomingInterface, packet);
			}
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
		//for general query
		NS_LOG_LOGIC ("Route exists");
		Ipv4Address source = "0.0.0.0";	//place holder

		//ttl == 1, igmp packet
		SocketIpTtlTag ttltag;
		ttltag.SetTtl (1);
		packet->AddPacketTag(ttltag);

		m_downTarget (packet, source, dest, PROT_NUMBER, route);
	}
	else
	{
		//todo for report, group specific and group and sources specific query
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

Time
Igmpv3L4Protocol::GetUnsolicitedReportInterval (void)
{
	//default one
	Time default_interval = Seconds (1.0);

	return this->GetRandomTime(default_interval);
}

uint8_t
Igmpv3L4Protocol::GetRobustnessValue (void)
{
	return this->m_default_qrv;
}

uint8_t
Igmpv3L4Protocol::GetMaxRespCode (void)
{
	return this->m_default_max_resp_code;
}

Time
Igmpv3L4Protocol::GetRandomTime (Time max)
{
	int64_t ms = max.GetMilliSeconds();

	if (ms <= 0)
	{
		NS_ASSERT(false);
	}

	Ptr<UniformRandomVariable> rand = CreateObject<UniformRandomVariable> ();

	Time retval = MilliSeconds(rand->GetInteger(0, ms));

	return retval;
}

Time
Igmpv3L4Protocol::GetMaxRespTime (uint8_t max_resp_code)
{
	Ptr<UniformRandomVariable> rand = CreateObject<UniformRandomVariable> ();
	Time resp_time = Seconds(0.0);

	if (128 > max_resp_code)
	{
		resp_time = Seconds((double)max_resp_code / (double)10);
	}
	else
	{
		uint8_t exp = (max_resp_code >> 4) & 0x07;
		uint8_t mant = max_resp_code & 0x0f;
		resp_time = Seconds((double)((mant | 0x10) << (exp + 3)) / (double)10);
	}

	return resp_time;

}

Time
Igmpv3L4Protocol::GetQueryInterval (void)
{
	return Seconds (this->GetQQIC());
}

Time
Igmpv3L4Protocol::GetQueryReponseInterval (void)
{
	return this->GetMaxRespTime(this->m_default_max_resp_code);
}

Time
Igmpv3L4Protocol::GetGroupMembershipIntervalGMI (void)
{
	Time query_interval =  this->GetQueryInterval();

	uint8_t robutness = this->m_default_qrv;

	Time query_response_interval = this->GetQueryReponseInterval();

	return (robutness * query_interval) + query_response_interval;
}

Time
Igmpv3L4Protocol::GetLastMemberQueryTimeLMQT (void)
{
	return (this->GetLastMemberQueryCount() * this->GetLastMemberQueryInterval());
}

Time
Igmpv3L4Protocol::GetLastMemberQueryInterval (void)
{
	return this->GetMaxRespTime(this->GetMaxRespCode());
}

Time
Igmpv3L4Protocol::GetOtherQuerierPresentInterval (void)
{
	Time query_interval =  this->GetQueryInterval();

	uint8_t robutness = this->m_default_qrv;

	Time query_response_interval = this->GetQueryReponseInterval();

	return (robutness * query_interval) + (0.5 * query_response_interval);
}

Time
Igmpv3L4Protocol::GetStartupQueryInterval (void)
{
	Time query_interval =  this->GetQueryInterval();

	return (0.25 * query_interval);
}

uint8_t
Igmpv3L4Protocol::GetLastMemberQueryCount (void)
{
	return this->GetRobustnessValue();
}

uint8_t
Igmpv3L4Protocol::GetQQIC (void)
{
	return this->m_default_qqic;
}

uint8_t
Igmpv3L4Protocol::GetQRV (void)
{
	return this->m_default_qrv;
}

uint8_t
Igmpv3L4Protocol::GetStartupQueryCount (void)
{
	return this->GetQRV();
}

void
Igmpv3L4Protocol::SendQuery (Ipv4Address group_address, Ptr<Ipv4InterfaceMulticast> incomingInterface, Ptr<Packet> packet)
{
	Igmpv3Header header;
	header.SetType(Igmpv3Header::MEMBERSHIP_QUERY);
	if (true == incomingInterface->GetDevice()->GetNode()->ChecksumEnabled())
	{
		header.EnableChecksum();
	}

	packet->AddHeader(header);

	this->DoSendQuery(group_address, incomingInterface, packet);
}

void
Igmpv3L4Protocol::DoSendQuery (Ipv4Address group_address, Ptr<Ipv4InterfaceMulticast> incomingInterface, Ptr<Packet> packet)
{
	Ptr<Ipv4Multicast> ipv4 = m_node->GetObject<Ipv4Multicast> ();
	NS_ASSERT (ipv4 != 0 && ipv4->GetRoutingProtocol () != 0);
	Ipv4Header header;
	header.SetProtocol (PROT_NUMBER);
	header.SetSource(incomingInterface->GetAddress(0).GetLocal());
	header.SetDestination(group_address);
	Socket::SocketErrno errno_;
	Ptr<Ipv4Route> route;
	Ptr<NetDevice> oif = incomingInterface->GetDevice();
	route = ipv4->GetRoutingProtocol ()->RouteOutput (packet, header, oif, errno_);
	if (route != 0)
	{
		NS_LOG_LOGIC ("Route exists");
		//Ipv4Address source = route->GetSource ();
		SendMessage (packet, group_address, route);
	}
	else
	{
		NS_LOG_WARN ("drop icmp query");
	}
}

void
Igmpv3L4Protocol::SetGsam (Ptr<GsamL4Protocol> gsam)
{
	NS_LOG_FUNCTION (this);
	if (0 == gsam)
	{
		NS_ASSERT (false);
	}
	this->m_gsam = gsam;
}

Ptr<GsamL4Protocol>
Igmpv3L4Protocol::GetGsam (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_gsam;
}

} /* namespace ns3 */
