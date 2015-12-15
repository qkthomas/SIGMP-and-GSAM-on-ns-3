/*
 * IGMPApp.cc
 *
 *  Created on: May 12, 2015
 *      Author: lim
 */

#include "IGMPApp.h"
#include "ns3/log.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/nstime.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("IGMPApp");

NS_OBJECT_ENSURE_REGISTERED (IGMPApp);

/********************************************************
 *        IGMPApp
 ********************************************************/

TypeId
IGMPApp::GetTypeId(void)
{
	static TypeId tid = TypeId ("ns3::IGMPApp")
	    .SetParent<Application> ()
		//.SetGroupName("Applications")
	    .AddConstructor<IGMPApp> ();
	return tid;
}

IGMPApp::IGMPApp()
  : m_role (IGMPApp::QUERIER),
	m_sendEvent (EventId()),
	m_GenQueAddress (Ipv4Address ("0.0.0.0")),
	m_LvGrpAddress (Ipv4Address ("0.0.0.0")),
	m_RptAddress (Ipv4Address ("0.0.0.0")),
	m_portnumber (0),
	m_s_flag (false),
	m_qqic (0),
	m_qrv (0),
	m_max_resp_code (0)
{
	NS_LOG_FUNCTION (this);
	//m_socket = 0;
}

IGMPApp::~IGMPApp()
{
	NS_LOG_FUNCTION (this);
	for (std::list<Ptr<Socket> >::iterator it = this->m_lst_sending_sockets.begin(); it != this->m_lst_sending_sockets.end(); it++)
	{
		(*it) = 0;
	}
	//m_socket = 0;
}

void
IGMPApp::DoDispose(void)
{
	NS_LOG_FUNCTION (this);
	Application::DoDispose ();
}

void
IGMPApp::StartApplication(void)
{
	//this->m_GenQueAddress = InetSocketAddress(Ipv4Address("224.0.0.1")); // when m_GenQueAddress is only Address, not Ipv4Address
//	this->m_GenQueAddress = Ipv4Address("224.0.0.1");
//
//	if(this->m_socket == 0)
//	{
//		TypeId tid = TypeId::LookupByName ("ns3::Ipv4RawSocketFactory");
//		m_socket = Socket::CreateSocket (GetNode (), tid);
//	}
//
//	if(this->m_socket != 0)
//	{
//		m_socket->SetRecvCallback (MakeCallback (&IGMPApp::HandleRead, this));
//	}
	this->Initialization();

	Time dt = Seconds(0.);

	//static int run = 0 is to make sure codes in if block will only run once.
	static int run = 0;

	if(0 == run)
	{
		this->m_sendEvent = Simulator::Schedule (dt, &IGMPApp::SendDefaultGeneralQuery, this);
		run++;
	}

}

void
IGMPApp::StopApplication (void)
{

}

void
IGMPApp::Initialization (void)
{
	NS_LOG_FUNCTION (this);

	this->m_GenQueAddress = Ipv4Address("224.0.0.1");
	this->m_RptAddress = Ipv4Address("224.0.0.22");
	this->m_portnumber = 2;

	if (0 < this->GetNode()->GetNDevices())
	{
		if (true == this->m_lst_sending_sockets.empty())
		{
			//creating and binding a socket for each device (interface)
			for (uint32_t i = this->GetNode()->GetNDevices(); i > 0; i--)
			{
				uint32_t device_id = i - 1;

				Ptr<NetDevice> device = this->GetNode()->GetDevice(device_id);
				if (device->GetInstanceTypeId() != LoopbackNetDevice::GetTypeId())
				{
					TypeId tid = TypeId::LookupByName ("ns3::Ipv4RawSocketFactory");

					//plug in a sending socket
					Ptr<Socket> socket_send = Socket::CreateSocket (this->GetNode (), tid);
					socket_send->BindToNetDevice(device);
					socket_send->Bind();	//receiving from any address
					socket_send->SetRecvCallback(MakeCallback (&IGMPApp::HandleRead, this));
					this->m_lst_sending_sockets.push_back(socket_send);

					//plugin a receiving socket
//					Ptr<Socket> socket_recv = Socket::CreateSocket (this->GetNode (), tid);
//					socket_recv->BindToNetDevice(device);
//					socket_recv->Bind();	//receiving from any address
//					socket_recv->SetRecvCallback(MakeCallback (&IGMPApp::HandleRead, this));
//					this->m_lst_receiving_sockets.push_back(socket_recv);
				}
			}
		}
	}

	this->m_s_flag = false;			//assumed default
	this->m_qqic = 125;				//125sec, cisco default
	this->m_qrv = 2;				//cisco default
	this->m_max_resp_code = 100; 	//10sec, cisco default

	static bool flag_querier_set = false;

	if (false == flag_querier_set)
	{
		this->m_role = IGMPApp::QUERIER;
		flag_querier_set = true;
	}
	else
	{
		this->m_role = IGMPApp::HOST;
	}
}

void
IGMPApp::DoSendGeneralQuery (Ptr<Packet> packet)
{
	NS_LOG_FUNCTION (this);

	for (std::list<Ptr<Socket> >::const_iterator it = this->m_lst_sending_sockets.begin(); it != this->m_lst_sending_sockets.end(); it++)
	{
		(*it)->Connect(InetSocketAddress(this->m_GenQueAddress, this->m_portnumber));
		std::cout << "Node: " << this->GetNode()->GetId() << " sends a general query" << std::endl;
		(*it)->Send(packet);

		//reset m_dst of socket.
		(*it)->Connect(InetSocketAddress(Ipv4Address::GetAny (), this->m_portnumber));
	}

//	for (uint32_t i = this->GetNode()->GetNDevices(); i > 0; i--)
//	{
//		uint32_t device_id = i - 1;
//
//		Ptr<NetDevice> device = this->GetNode()->GetDevice(device_id);
//		if (device->GetInstanceTypeId() != LoopbackNetDevice::GetTypeId())
//		{
//			this->m_socket->BindToNetDevice(device);
//			this->m_socket->Bind();
//			this->m_socket->Connect(InetSocketAddress(this->m_GenQueAddress, 2));
//
//			std::cout << "Node: " << this->GetNode()->GetId() << " sends a general query" << std::endl;
//
//			this->m_socket->Send(packet);
//		}
//	}
}

//old test code for weather packets can be sent to every node in the network.
//void
//IGMPApp::SendGeneralQuery (void)
//{
//	uint32_t dataSize = 8;
//	uint8_t* data = new uint8_t[dataSize];
//
//	Ptr<Packet> p = Create<Packet>(data, dataSize);
//
//	this->m_socket->BindToNetDevice(this->GetNode()->GetDevice(1));
//	this->m_socket->Bind();
//	this->m_socket->Connect(InetSocketAddress(this->m_GenQueAddress));
//
//	m_socket->Send (p);
//
//	delete[] data;
//}

void
IGMPApp::SendDefaultGeneralQuery (void)
{
	NS_LOG_FUNCTION (this);

	Ptr<Packet> packet = Create<Packet> ();

	Igmpv3Query query;
	query.SetGroupAddress(0);
	query.SetSFlag(this->m_s_flag);
	query.SetQRV(this->m_qrv);
	query.SetQQIC(this->m_qqic);
	std::list<Ipv4Address> empty_lst__addresses;
	query.PushBackSrcAddresses(empty_lst__addresses);

	packet->AddHeader(query);

	Igmpv3Header igmpv3;
	igmpv3.SetType(Igmpv3Header::MEMBERSHIP_QUERY);
	igmpv3.SetMaxRespCode(this->m_max_resp_code);
	igmpv3.EnableChecksum();

	packet->AddHeader(igmpv3);

	this->DoSendGeneralQuery(packet);
}

void
IGMPApp::SendGeneralQuery (bool s_flag, //= false, assumed default
							uint8_t qqic, //= 125, 12sec, cisco default
							uint8_t qrv, //= 2, cisco default
							uint8_t max_resp_code //= 100, 10sec, cisco default
					)
{
	NS_LOG_FUNCTION (this);

	Ptr<Packet> packet = Create<Packet> ();

	Igmpv3Query query;
	query.SetGroupAddress(0);
	query.SetSFlag(s_flag);
	query.SetQRV(qrv);
	query.SetQQIC(qqic);
	std::list<Ipv4Address> empty_lst__addresses;
	query.PushBackSrcAddresses(empty_lst__addresses);

	packet->AddHeader(query);

	Igmpv3Header igmpv3;
	igmpv3.SetType(Igmpv3Header::MEMBERSHIP_QUERY);
	igmpv3.SetMaxRespCode(max_resp_code);
	igmpv3.EnableChecksum();

	packet->AddHeader(igmpv3);

	this->DoSendGeneralQuery(packet);
}

void
IGMPApp::SendCurrentStateReport(Ptr<Socket> socket)
{
	Ptr<NetDevice> bound_device = socket->GetBoundNetDevice();

	Ptr<Packet> packet = Create<Packet>();

	std::list<Igmpv3GrpRecord> lst_grp_records;

	for (	std::list<IGMPv3InterfaceState>::iterator it = this->m_lst_interface_states.begin();
			it != this->m_lst_interface_states.end();
			it++)
	{
		if (bound_device->GetIfIndex() == (*it).m_interface->GetIfIndex())
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
	igmpv3.SetMaxRespCode(this->m_max_resp_code);
	igmpv3.EnableChecksum();

	packet->AddHeader(igmpv3);

	socket->Connect(InetSocketAddress(this->m_RptAddress, this->m_portnumber));
	std::cout << "Node: " << this->GetNode()->GetId() << " reporting a general query to the querier" << std::endl;
	socket->Send(packet);

	//reset m_dst of socket. weird thinking, does not match what happens in really network.
	socket->Connect(InetSocketAddress(Ipv4Address::GetAny (), this->m_portnumber));
}

void
IGMPApp::HandleRead (Ptr<Socket> socket)
{
	NS_LOG_FUNCTION (this);

	Ptr<NetDevice> boundnetdevice = socket->GetBoundNetDevice();

	if (0 == boundnetdevice)
	{
		std::cout << "Node " << this->GetNode()->GetId() << " , Method: HandleRead (), Receving from socket with no boundnetdevice." << std::endl;
	}

	Address from;
	Ptr<Packet> packet = socket->RecvFrom(from);

	// Old code, before writing any igmpv3 structure
//	std::cout << "Node Id: " << this->GetNode()->GetId() << " Packet received" << std::endl;
//	std::cout << "Packet size = " << packet->GetSize() << " bytes " << std::endl;
//	std::cout << "From Address: " << InetSocketAddress::ConvertFrom (from).GetIpv4 () << std::endl;
	//

	// new code, currently being writen.
	Ipv4Header ipv4header;
	packet->RemoveHeader (ipv4header);
	std::cout << "Node " << this->GetNode()->GetId() << ", receving packet from src address: ";
	ipv4header.GetSource().Print(std::cout);
	std::cout << std::endl;

	Igmpv3Header igmpv3_header;
	packet->RemoveHeader (igmpv3_header);
	switch (igmpv3_header.GetType ()) {
		case Igmpv3Header::MEMBERSHIP_QUERY:
	      //HandleEcho (p, igmp, header.GetSource (), header.GetDestination ());
			std::cout << "Node: " << this->GetNode()->GetId() << " received a query" << std::endl;
			if (IGMPApp::HOST == this->m_role) {
				this->HandleQuery(socket, igmpv3_header, packet);
			}
			break;
	    case Igmpv3Header::V1_MEMBERSHIP_REPORT:
	      //HandleTimeExceeded (p, igmp, header.GetSource (), header.GetDestination ());
	    	std::cout << "Node: " << this->GetNode()->GetId() << " received a v1 report" << std::endl;
			if (IGMPApp::QUERIER == this->m_role) {
				this->HandleV1MemReport(socket, igmpv3_header, packet);
			}
	    	break;
	    case Igmpv3Header::V2_MEMBERSHIP_REPORT:
	    	std::cout << "Node: " << this->GetNode()->GetId() << " received a v2 report" << std::endl;
			if (IGMPApp::QUERIER == this->m_role) {
				this->HandleV2MemReport(socket, igmpv3_header, packet);
			}
	    	break;
	    case Igmpv3Header::V3_MEMBERSHIP_REPORT:
	    	std::cout << "Node: " << this->GetNode()->GetId() << " received a v3 report" << std::endl;
			if (IGMPApp::QUERIER == this->m_role) {
				this->HandleV3MemReport(socket, igmpv3_header, packet);
			}
	    	break;
	    default:
	      NS_LOG_DEBUG (igmpv3_header << " " << *packet);
	      std::cout << "Node: " << this->GetNode()->GetId() << " did not find a appropriate type in IGMP header" << std::endl;
	      break;
	}
	//
}

void
IGMPApp::HandleReadDummy (Ptr<Socket> socket)
{
	std::cout << "Node: " << this->GetNode()->GetId() << " trigger the HandleReadDummy()" << std::endl;
}

void
IGMPApp::HandleQuery (Ptr<Socket> socket, Igmpv3Header igmpv3_header, Ptr<Packet> packet)
{
	NS_LOG_FUNCTION (this);
	Igmpv3Query query_header;
	packet->RemoveHeader(query_header);

	uint8_t max_resp_code = igmpv3_header.GetMaxRespCode();
	Ptr<UniformRandomVariable> rand = CreateObject<UniformRandomVariable> ();
	Time max_resp_time = Seconds(0.0);

	if (128 > max_resp_code) {
		uint8_t rand_max_resp_time = rand->GetInteger(0, max_resp_code);
		max_resp_time = Seconds((double)rand_max_resp_time / (double)10);
	}
	else
	{
		uint8_t exp = (max_resp_code >> 4) & 0x07;
		uint8_t mant = max_resp_code & 0x0f;
		uint8_t rand_max_resp_time = rand->GetInteger(0, ((mant | 0x10) << (exp + 3)));
		max_resp_time = Seconds((double)rand_max_resp_time / (double)10);
	}

	if (0 == query_header.GetGroupAddress())
	{
		this->HandleGeneralQuery (socket, max_resp_time, query_header, packet);
	}
	else
	{
		this->HandleGroupSpecificQuery(socket, max_resp_time, query_header, packet);
	}
}

void
IGMPApp::HandleGeneralQuery (Ptr<Socket> socket, Time max_resp_time, Igmpv3Query query_header, Ptr<Packet> packet)
{
	NS_LOG_FUNCTION (this);

	Ptr<NetDevice> bound_device = socket->GetBoundNetDevice();

	for (	std::list<PerInterfaceTimer>::const_iterator it = this->m_lst_per_interface_timers.begin();
			it != this->m_lst_per_interface_timers.end();
			it++)
	{
		if (bound_device->GetIfIndex() == (*it).m_interface->GetIfIndex())
		{
			//there is timer for that interface in the maintained list of per interface timers
			//which means there is a pending query?
		}
		else
		{

		}
	}

	this->SendCurrentStateReport(socket);


}

void
IGMPApp::HandleGroupSpecificQuery (Ptr<Socket> socket, Time max_resp_time, Igmpv3Query query_header, Ptr<Packet> packet)
{
	NS_LOG_FUNCTION (this);

}

void
IGMPApp::HandleV1MemReport (Ptr<Socket> socket, Igmpv3Header igmpv3_header, Ptr<Packet> packet)
{

}

void
IGMPApp::HandleV2MemReport (Ptr<Socket> socket, Igmpv3Header igmpv3_header, Ptr<Packet> packet)
{

}

void
IGMPApp::HandleV3MemReport (Ptr<Socket> socket, Igmpv3Header igmpv3_header, Ptr<Packet> packet)
{

}

void
IGMPApp::IPMulticastListen (Ptr<Socket> socket, Ptr<NetDevice> interface, Ipv4Address multicast_address, FILTER_MODE filter_mode)
{

}

//
///********************************************************
// *        Igmpv3L4Protocol
// ********************************************************/
//
//NS_OBJECT_ENSURE_REGISTERED (Igmpv3L4Protocol);
//
//// see rfc 792
//const uint8_t Igmpv3L4Protocol::PROT_NUMBER = 2;
//
//TypeId
//Igmpv3L4Protocol::GetTypeId (void)
//{
//	static TypeId tid = TypeId ("ns3::Igmpv3L4Protocol")
//	    .SetParent<IpL4Protocol> ()
//	    //.SetGroupName ("Internet")
//	    .AddConstructor<Igmpv3L4Protocol> ()
//		;
//	  return tid;
//}
//
//Igmpv3L4Protocol::Igmpv3L4Protocol ()
//  :  m_node (0)
//{
//	NS_LOG_FUNCTION (this);
//}
//
//Igmpv3L4Protocol::~Igmpv3L4Protocol ()
//{
//	NS_LOG_FUNCTION (this);
//	NS_ASSERT (this->m_node == 0);
//}
//
//void
//Igmpv3L4Protocol::DoDispose (void)
//{
//	  NS_LOG_FUNCTION (this);
//	  m_node = 0;
//	  m_downTarget.Nullify ();
//	  IpL4Protocol::DoDispose ();
//}
//
///*
// * Copied from ICMPL4Protocol:
// *
// * This method is called by AddAgregate and completes the aggregation
// * by setting the node in the IGMPv3 stack and adding IGMPv3 factory to
// * IPv4 stack connected to the node
// */
//void
//Igmpv3L4Protocol::NotifyNewAggregate ()
//{
//	  NS_LOG_FUNCTION (this);
//	  if (m_node == 0)
//	    {
//	      Ptr<Node> node = this->GetObject<Node> ();
//	      if (node != 0)
//	        {
//	          Ptr<Ipv4> ipv4 = this->GetObject<Ipv4> ();
//	          if (ipv4 != 0 && m_downTarget.IsNull ())
//	            {
//	              this->SetNode (node);
//	              ipv4->Insert (this);
//	              Ptr<Ipv4RawSocketFactoryImpl> rawFactory = CreateObject<Ipv4RawSocketFactoryImpl> ();
//	              ipv4->AggregateObject (rawFactory);
//	              this->SetDownTarget (MakeCallback (&Ipv4::Send, ipv4));
//	            }
//	        }
//	    }
//	  Object::NotifyNewAggregate ();
//}
//
//int
//Igmpv3L4Protocol::GetProtocolNumber (void) const
//{
//	NS_LOG_FUNCTION (this);
//	return Igmpv3L4Protocol::PROT_NUMBER;
//}
//
//void
//Igmpv3L4Protocol::SetNode (Ptr<Node> node)
//{
//	NS_LOG_FUNCTION (this << node);
//	this->m_node = node;
//}
//
//uint16_t
//Igmpv3L4Protocol::GetStaticProtocolNumber (void)
//{
//	NS_LOG_FUNCTION_NOARGS ();
//	return PROT_NUMBER;
//}
//
//void
//Igmpv3L4Protocol::SetDownTarget (IpL4Protocol::DownTargetCallback callback)
//{
//  NS_LOG_FUNCTION (this << &callback);
//  m_downTarget = callback;
//}
//
//IpL4Protocol::DownTargetCallback
//Igmpv3L4Protocol::GetDownTarget (void) const
//{
//  NS_LOG_FUNCTION (this);
//  return m_downTarget;
//}
//
//double
//Igmpv3L4Protocol::MaxRespCodeQQICConvert (uint8_t max_resp_code)
//{
//	/*
//	 *
//	 * If Max Resp Code < 128, Max Resp Time = Max Resp Code
//
//   	   If Max Resp Code >= 128, Max Resp Code represents a floating-point
//   	   value as follows:
//
//       0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+
//      |1| exp | mant  |
//      +-+-+-+-+-+-+-+-+
//
//   	   Max Resp Time = (mant | 0x10) << (exp + 3)
//	 *
//	 */
//
//	/*
//	 * The actual time allowed, called the Max Resp Time, is represented in units of 1/10 second
//	 */
//	double base = 0.1;
//	double max_resp_time = 0.0;	//initialization
//
//	if ((max_resp_code & 0x80) == 0)	//max_resp_code < 128
//	{
//		max_resp_time = base * max_resp_code;
//	}
//	else
//	{
//		uint8_t exp = ((max_resp_code & 0x70) >> 4);
//		uint8_t mant = max_resp_code & 0x0f;
//		max_resp_time = ((mant | 0x10) << (exp + 3));
//	}
//	return max_resp_time;
//}
//
//enum IpL4Protocol::RxStatus
//Igmpv3L4Protocol::Receive (Ptr<Packet> p,
//                           Ipv4Header const &header,
//                           Ptr<Ipv4Interface> incomingInterface)
//{
//  NS_LOG_FUNCTION (this << p << header << incomingInterface);
//
//  Igmpv3Header igmp;
//  p->RemoveHeader (igmp);
//  switch (igmp.GetType ()) {
//    case Igmpv3Header::MEMBERSHIP_QUERY:
//      //HandleEcho (p, igmp, header.GetSource (), header.GetDestination ());
//      break;
//    case Igmpv3Header::V1_MEMBERSHIP_REPORT:
//      //HandleTimeExceeded (p, igmp, header.GetSource (), header.GetDestination ());
//      break;
//    case Igmpv3Header::V2_MEMBERSHIP_REPORT:
//    	break;
//    case Igmpv3Header::V3_MEMBERSHIP_REPORT:
//    	break;
//    default:
//      NS_LOG_DEBUG (igmp << " " << *p);
//      break;
//    }
//  return IpL4Protocol::RX_OK;
//}
//
//void
//Igmpv3L4Protocol::HandleQuery (Ptr<Packet> p,
//              	  	    	   Icmpv4Header header,
//							   Ipv4Address source,
//							   Ipv4Address destination)
//{
//
//}
//
//void
//Igmpv3L4Protocol::HandleV1Report (Ptr<Packet> p,
//        	  	  	   	          Icmpv4Header header,
//								  Ipv4Address source,
//								  Ipv4Address destination)
//{
//
//}
//
//void
//Igmpv3L4Protocol::HandleV2Report (Ptr<Packet> p,
//        	  	  	   	   	      Icmpv4Header header,
//								  Ipv4Address source,
//								  Ipv4Address destination)
//{
//
//}
//
//void
//Igmpv3L4Protocol::HandleV3Report (Ptr<Packet> p,
//		  	  	  	   	   	      Icmpv4Header header,
//								  Ipv4Address source,
//								  Ipv4Address destination)
//{
//
//}
//
//void
//Igmpv3L4Protocol::SendQuery (Ipv4Address group_address,
//							 bool s_flag /*= false /*assumed default*/,
//							 uint8_t qqic /*= /*125 /*cisco default*/,
//							 uint8_t qrv /*= 2 /*cisco default*/,
//							 uint16_t num_src,
//							 std::list<Ipv4Address> &lst_src_addresses,
//							 uint8_t max_resp_code /*= 100 /* 10sec, cisco default**/)
//{
//	Igmpv3Query query;
//	query.SetGroupAddress(group_address.Get());
//	query.SetSFlag(s_flag);
//	query.SetQRV(qrv);
//	query.SetQQIC(qqic);
//	query.SetNumSrc(num_src);
//	query.PushBackSrcAddresses(lst_src_addresses);
//
//	Ptr<Packet> packet = Create<Packet>();
//
//	packet->AddHeader(query);
//
//	this->SendMessage(packet, Ipv4Address(Igmpv3L4Protocol::GENERALQUERYDEST), Igmpv3Header::MEMBERSHIP_QUERY, max_resp_code);
//
//}
//
//void
//Igmpv3L4Protocol::SendMessage (Ptr<Packet> packet,
//							   /*Ipv4Address source,*/
//							   Ipv4Address dest,
//							   uint8_t type,
//							   uint8_t max_resp_code)
//{
//	NS_LOG_FUNCTION (this << packet << dest << static_cast<uint32_t> (type) << static_cast<uint32_t> (max_resp_code));
//	Ptr<Ipv4> ipv4 = m_node->GetObject<Ipv4> ();
//	NS_ASSERT (ipv4 != 0 && ipv4->GetRoutingProtocol () != 0);
//	Ipv4Header header;
//	header.SetDestination (dest);
//	header.SetProtocol (PROT_NUMBER);
//	Socket::SocketErrno errno_;
//	Ptr<Ipv4Route> route;
//
//	//sending through every interface
//	for (uint32_t i = 0; i < this->m_node->GetNDevices(); i++)
//	{
//
//		Ptr<NetDevice> oif = Ptr<NetDevice> (this->m_node->GetDevice(i));
//
//		if (oif->GetInstanceTypeId() != LoopbackNetDevice::GetTypeId())
//		{
//			//sending out
//			//specify non-zero if bound to a source address
//			//bound to interface address
//			route = ipv4->GetRoutingProtocol ()->RouteOutput (packet, header, oif, errno_);
//
//			Ipv4Address source = oif->GetAddress();
//
//			if (route != 0)
//			{
//				NS_LOG_LOGIC ("Route exists");
//				SendMessage (packet, source, dest, type, max_resp_code, route);
//			}
//			else
//			{
//				NS_LOG_WARN ("drop igmpv3 message");
//			}
//		}
//	}
//
//	/*
//	 *
//	//to find the right device? why circle around??
//	Ptr<NetDevice> oif (0);
//	//there have to be a interface specified, according to ipv4
//	for (uint32_t i = 0; i < this->m_node->GetNDevices(); i++)
//	{
//		if (this->m_node->GetDevice(i)->GetAddress() == source)
//		{
//			oif = Ptr<NetDevice> (this->m_node->GetDevice(i));
//		}
//	}
//
//	//specify non-zero if bound to a source address
//	//bound to interface address
//	route = ipv4->GetRoutingProtocol ()->RouteOutput (packet, header, oif, errno_);
//
//	if (route != 0)
//	{
//		NS_LOG_LOGIC ("Route exists");
//		SendMessage (packet, source, dest, type, max_resp_code, route);
//	}
//	else
//	{
//		NS_LOG_WARN ("drop igmpv3 message");
//	}
//	*
//	*/
//}
//
//void
//Igmpv3L4Protocol::SendMessage (Ptr<Packet> packet,
//							   Ipv4Address source,
//							   Ipv4Address dest,
//							   uint8_t type,
//							   uint8_t max_resp_code,
//							   Ptr<Ipv4Route> route)
//{
//	  NS_LOG_FUNCTION (this << packet << source << dest << static_cast<uint32_t> (type) << static_cast<uint32_t> (max_resp_code) << route);
//	  Igmpv3Header igmp;
//	  igmp.SetType (type);
//	  igmp.SetMaxRespCode(max_resp_code);
//	  if (Node::ChecksumEnabled ())
//	  {
//		  igmp.EnableChecksum ();
//	  }
//	  packet->AddHeader (igmp);
//
//	  m_downTarget (packet, source, dest, PROT_NUMBER, route);
//}

} /* namespace ns3 */

using namespace ns3;

int main()
{
	Time::SetResolution (Time::NS);

	NodeContainer nodes;
	nodes.Create (5);

	//Mistaken for stars topology for a lan without a switch. Use CSMA instead
	//PointToPointHelper pointToPoint;
	//pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
	//pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));

	/* to be move down
	NetDeviceContainer devices;
	if (nodes.GetN() > 1) {
		for (uint32_t i = 1; i < nodes.GetN(); i++)
		{
			devices.Add(pointToPoint.Install(nodes.Get(0), nodes.Get(i)));
		}
	}
	*/

	CsmaHelper csma;
	csma.SetChannelAttribute ("DataRate", StringValue ("5Mbps"));
	csma.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (2)));


	InternetStackHelper stack;
	stack.Install (nodes);

	Ipv4AddressHelper address;
	address.SetBase ("10.1.1.0", "255.255.255.0");

	NetDeviceContainer devices;

	/* used for p2p devices, not valid any more
	if (nodes.GetN() > 1) {
		for (uint32_t i = 1; i < nodes.GetN(); i++)
		{
			devices.Add(csma.Install(nodes.Get(0), nodes.Get(i)));
		}
	}
	*/

	devices.Add(csma.Install(nodes));

	Ipv4InterfaceContainer interfaces = address.Assign (devices);

	if (nodes.GetN() > 0)
	{

		for (uint32_t i = 0; i < nodes.GetN(); i++)
		{
			ObjectFactory factory;
			factory.SetTypeId(IGMPApp::GetTypeId());
			Ptr<Application> app = factory.Create<IGMPApp>();
			app->SetStartTime(Seconds(0.));
			app->SetStopTime(Seconds(10.0));
			nodes.Get(i)->AddApplication(app);
		}

		/* The follow chunk will cause nodes other than node1 dont have any socket
		uint32_t i = 0;
		ObjectFactory factory;
		factory.SetTypeId(IGMPApp::GetTypeId());
		Ptr<Application> app = factory.Create<IGMPApp>();
		app->SetStartTime(Seconds(0.));
		app->SetStopTime(Seconds(10.0));
		nodes.Get(i)->AddApplication(app);
		*/
	}

	Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

	Simulator::Run ();
	Simulator::Destroy ();
	return 0;
}
