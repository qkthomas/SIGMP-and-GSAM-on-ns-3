/*
 * igmpv3-application.cc
 *
 *  Created on: Feb 9, 2016
 *      Author: lim
 */

#include "igmpv3-application.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/nstime.h"
#include "ns3/ipv4-l3-protocol-multicast.h"
#include "ns3/ipsec.h"
#include "gsam-application.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("Igmpv3Application");

NS_OBJECT_ENSURE_REGISTERED (Igmpv3Application);

TypeId
Igmpv3Application::GetTypeId(void)
{
	static TypeId tid = TypeId ("ns3::Igmpv3Application")
	    		.SetParent<Application> ()
				//.SetGroupName("Applications")
				.AddConstructor<Igmpv3Application> ();
	return tid;
}

Igmpv3Application::Igmpv3Application() {
	// TODO Auto-generated constructor stub
	this->m_default_query_interval = Seconds(60.0);
	this->m_flag_nq_joined = false;
}

Igmpv3Application::~Igmpv3Application() {
	// TODO Auto-generated destructor stub
}

void
Igmpv3Application::DoDispose(void)
{
	NS_LOG_FUNCTION (this);
	Application::DoDispose ();
}

void
Igmpv3Application::StartApplication(void)
{
	Time dt = Seconds(0.0);

	Ptr<Igmpv3L4Protocol> igmp = this->GetIgmp();

	if (igmp->GetRole() == Igmpv3L4Protocol::QUERIER)
	{

	}
	else if (igmp->GetRole() == Igmpv3L4Protocol::NONQUERIER)
	{
		dt = GsamConfig::GetSingleton()->GetNqJoinTimeInSeconds();
	}
	else if (igmp->GetRole() == Igmpv3L4Protocol::GROUP_MEMBER)
	{
		dt = GsamConfig::GetSingleton()->GetGmJoinTimePlusRandomIntervalInSeconds();
	}
	else
	{
		NS_ASSERT (false);
	}


	this->m_currentEvent = Simulator::Schedule (dt, &Igmpv3Application::GenerateNextEvent, this);

//	//static int run = 0 is to make sure codes in if block will only run once.
//	static bool firstnode = true;
//
//	if(true == firstnode)
//	{
//		this->m_currentEvent = Simulator::Schedule (dt, &Igmpv3Application::GenerateNextEvent, this);
//		firstnode = false;
//	}

}

void
Igmpv3Application::StopApplication (void)
{
	Simulator::Cancel(this->m_currentEvent);
	Ptr<Igmpv3L4Protocol> igmp = Igmpv3L4Protocol::GetIgmp(this->m_node);
	igmp->GetManager()->StopEverything();
}

Ptr<Igmpv3L4Protocol>
Igmpv3Application::GetIgmp (void) const
{
	Ptr<Ipv4Multicast> ipv4 = this->GetNode()->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);

	return ipv4l3->GetIgmp();
}

Ptr<Ipv4L3ProtocolMulticast>
Igmpv3Application::GetIpv4L3 (void) const
{
	Ptr<Ipv4Multicast> ipv4 = this->GetNode()->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
	return ipv4l3;
}

uint32_t
Igmpv3Application::GetRandomNumber (uint32_t min, uint32_t max)
{
	Ptr<UniformRandomVariable> rand = CreateObject<UniformRandomVariable> ();

	return rand->GetInteger(min, max);
}

bool
Igmpv3Application::IsSkip (uint32_t percentage)
{
	if (percentage > 100)
	{
		NS_ASSERT (false);
	}

	uint32_t num = this->GetRandomNumber(0, 100);

	if (num <= percentage)
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool
Igmpv3Application::IsSkip (void)
{
	return this->IsSkip(50);
}

Ipv4Address
Igmpv3Application::GetRandomMulticastAddress (void)
{
	//The multicast addresses are in the range 224.0.0.0 through 239.255.255.255

	return Ipv4Address (this->GetRandomNumber(3758096384, 4026531839));
}

void
Igmpv3Application::GenerateNextEvent (void)
{
	Ptr<Igmpv3L4Protocol> igmp = this->GetIgmp();

	if (Igmpv3L4Protocol::QUERIER == igmp->GetRole())
	{
		if (this->IsSkip())
		{
			//do nothing
		}
		else
		{
			this->GenerateGeneralQueryEvent();
		}

		this->m_currentEvent = Simulator::Schedule (this->m_default_query_interval, &Igmpv3Application::GenerateNextEvent, this);
	}
	else if (Igmpv3L4Protocol::GROUP_MEMBER == igmp->GetRole())
	{
		if (this->IsSkip() && !this->m_lst_sockets.empty())
		{
			this->GenerateHostLeaveEvent();
		}
		else
		{
			//only 10 sockets at a time max
			if (this->m_lst_sockets.size() < 10)
			{
				this->GenerateHostJoinEvent();
			}
		}
		this->m_currentEvent = Simulator::Schedule (GsamConfig::GetSingleton()->GetGmJoinIntervalInSeconds(), &Igmpv3Application::GenerateNextEvent, this);
	}
	else if (Igmpv3L4Protocol::NONQUERIER == igmp->GetRole())
	{
		if (false == this->m_flag_nq_joined)
		{
			Ptr<GsamL4Protocol> gsam = GsamL4Protocol::GetGsam(this->m_node);
			Ipv4Address group_address = GsamConfig::GetSingleton()->GetIgmpv3DestGrpReportAddress();
			Ipv4Address q_address = GsamConfig::GetSingleton()->GetQAddress();
			Ptr<GsamInitSession> init_session = gsam->GetIpSecDatabase()->CreateInitSession(q_address, group_address);
			Ptr<GsamSession> session = gsam->GetIpSecDatabase()->CreateSession(init_session, group_address);
			gsam->Send_IKE_SA_INIT(init_session);

			this->m_flag_nq_joined = true;
		}
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
Igmpv3Application::GenerateGeneralQueryEvent (void)
{
	Ptr<Igmpv3L4Protocol> igmp = this->GetIgmp();
	igmp->SendDefaultGeneralQuery();
}

void
Igmpv3Application::GenerateHostJoinEvent (void)
{
	Ptr<NetDevice> device;

	for (uint32_t i = this->GetNode()->GetNDevices(); i > 0; i--)
	{
		uint32_t device_id = i - 1;

		device = this->GetNode()->GetDevice(device_id);

		if (device->GetInstanceTypeId() != LoopbackNetDevice::GetTypeId())
		{
			//find the first real device
			break;
		}

	}

	TypeId tid = TypeId::LookupByName ("ns3::Ipv4RawSocketFactory");
	//plug in a socket
	Ptr<Socket> socket = Socket::CreateSocket (this->GetNode (), tid);
	socket->Bind();	//receiving from any address

	//set igmg protocol number
	Ptr<Ipv4RawSocketImplMulticast> rawsocket = DynamicCast<Ipv4RawSocketImplMulticast>(socket);
	rawsocket->SetProtocol(2);
	this->m_lst_sockets.push_back(rawsocket);

	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = this->GetIpv4L3();

	std::list<Ipv4Address> src_list;

	Ipv4Address group_address("0.0.0.0");

	if (false == GsamConfig::GetSingleton()->IsFalseByPercentage(GsamConfig::GetSingleton()->GetJoinSecureGroupProbability()))
	{
		group_address = GsamConfig::GetSingleton()->GetAnUnusedSecGrpAddress();
	}
	else
	{
		group_address = GsamConfig::GetSingleton()->GetAnUnusedUnsecGrpAddress();
	}

	GsamConfig::GetSingleton()->LogJoinStart(this->m_node->GetId(), group_address);

	rawsocket->IPMulticastListen(ipv4l3->GetInterface(ipv4l3->GetInterfaceForDevice(device)),
								 group_address,
								 ns3::EXCLUDE,
								 src_list,
								GsamConfig::GetSingleton()->IsGroupAddressSecureGroup(group_address));
}

void
Igmpv3Application::GenerateHostLeaveEvent (void)
{
	Ptr<Ipv4RawSocketImplMulticast> rawsocket = this->m_lst_sockets.front();
	rawsocket->UnSubscribeIGMP();

	this->m_lst_sockets.pop_front();

}

} /* namespace ns3 */
