/*
 * gsam-application.cc
 *
 *  Created on: Sep 20, 2016
 *      Author: lim
 */

#include "gsam-application.h"
#include "ns3/ipsec.h"
#include <iostream>

namespace ns3 {


NS_LOG_COMPONENT_DEFINE ("GsamApplication");

NS_OBJECT_ENSURE_REGISTERED (GsamApplication);

TypeId
GsamApplication::GetTypeId(void)
{
	static TypeId tid = TypeId ("ns3::GsamApplication")
	    		.SetParent<Application> ()
				//.SetGroupName("Applications")
				.AddConstructor<GsamApplication> ();
	return tid;
}

GsamApplication::GsamApplication()
  :  m_ptr_igmp (0),
	 m_ptr_gsam (0),
	 m_num_events (0)
{
	// TODO Auto-generated constructor stub

}

GsamApplication::~GsamApplication()
{
	// TODO Auto-generated destructor stub
}

void
GsamApplication::StartApplication (void)
{
	NS_LOG_FUNCTION (this);
	this->Initialization();
	if (this->m_ptr_igmp->GetRole() == Igmpv3L4Protocol::QUERIER)
	{
		Time delay = Seconds (0.1);
		this->m_event_current = Simulator::Schedule(delay, &GsamApplication::GenerateEvent, this);
	}
	else if (this->m_ptr_igmp->GetRole() == Igmpv3L4Protocol::NONQUERIER)
	{
		Time delay = GsamConfig::GetSingleton()->GetNqJoinTimePlusRandomIntervalInSeconds();
		this->m_event_current = Simulator::Schedule(delay, &GsamApplication::GenerateEvent, this);
	}
	else if (this->m_ptr_igmp->GetRole() == Igmpv3L4Protocol::GROUP_MEMBER)
	{
		Time delay = GsamConfig::GetSingleton()->GetGmJoinTimePlusRandomIntervalInSeconds();
		this->m_event_current = Simulator::Schedule(delay, &GsamApplication::GenerateEvent, this);
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
GsamApplication::StopApplication (void)
{
	NS_LOG_FUNCTION (this);
	this->m_event_current.Cancel();
}

void
GsamApplication::SetEventsNumber (uint8_t events_number)
{
	NS_LOG_FUNCTION (this);
	this->m_num_events = events_number;
}

uint8_t
GsamApplication::GetEventsNumber (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_num_events;
}

void
GsamApplication::Initialization (void)
{
	this->m_ptr_gsam = this->GetGsam();
	this->m_ptr_igmp = this->GetIgmp();

	std::cout << "Node id: " << this->m_node->GetId() << ", ";
	if (this->m_ptr_igmp->GetRole() == Igmpv3L4Protocol::QUERIER)
	{
		std::cout << "is a querier." << std::endl;
	}
	else if (this->m_ptr_igmp->GetRole() == Igmpv3L4Protocol::NONQUERIER)
	{
		std::cout << "is a non-querier." << std::endl;
	}
	else if (this->m_ptr_igmp->GetRole() == Igmpv3L4Protocol::GROUP_MEMBER)
	{
		std::cout << "is a group member." << std::endl;
	}
	else
	{
		NS_ASSERT (false);
	}
}

Ptr<GsamL4Protocol>
GsamApplication::GetGsam (void) const
{
	NS_LOG_FUNCTION (this);
	Ptr<GsamL4Protocol> retval = 0;
	if (0 == this->m_ptr_gsam)
	{
		retval = this->GetNode()->GetObject<GsamL4Protocol> ();

		if (0 == retval)
		{
			std::cout << "Node id: " << this->m_node->GetId() << ", ";
			std::cout << "does not have gsam." << std::endl;
			NS_ASSERT (false);
		}
	}
	else
	{
		retval = this->m_ptr_gsam;
	}

	return retval;
}

Ptr<Igmpv3L4Protocol>
GsamApplication::GetIgmp (void) const
{
	NS_LOG_FUNCTION (this);
	Ptr<Igmpv3L4Protocol> retval = 0;
	if (0 == this->m_ptr_igmp)
	{
		retval = this->GetNode()->GetObject<Igmpv3L4Protocol> ();

		if (0 == retval)
		{
			std::cout << "Node id: " << this->m_node->GetId() << ", ";
			std::cout << "does not have igmp." << std::endl;
			NS_ASSERT (false);
		}
	}
	else
	{
		retval = this->m_ptr_igmp;
	}

	return retval;
}

void
GsamApplication::GenerateEvent (void)
{
	NS_LOG_FUNCTION (this);
	if (this->m_ptr_igmp->GetRole() == Igmpv3L4Protocol::QUERIER)
	{

	}
	else if (this->m_ptr_igmp->GetRole() == Igmpv3L4Protocol::NONQUERIER)
	{
		Ptr<GsamL4Protocol> gsam = this->GetGsam();
		Ipv4Address group_address = GsamConfig::GetSingleton()->GetIgmpv3DestGrpReportAddress();
		Ipv4Address q_address = GsamConfig::GetSingleton()->GetQAddress();
		Ptr<GsamInitSession> init_session = gsam->GetIpSecDatabase()->CreateInitSession(q_address, group_address);
		Ptr<GsamSession> session = gsam->GetIpSecDatabase()->CreateSession(init_session, group_address);
		gsam->Send_IKE_SA_INIT(init_session);
	}
	else if (this->m_ptr_igmp->GetRole() == Igmpv3L4Protocol::GROUP_MEMBER)
	{
		if (0 < this->m_num_events)
		{
			//join
			Ptr<GsamL4Protocol> gsam = this->GetGsam();
			Ipv4Address group_address = GsamConfig::GetSingleton()->GetAnUnusedSecGrpAddress();
			Ipv4Address q_address = GsamConfig::GetSingleton()->GetQAddress();
			Ptr<GsamInitSession> init_session = gsam->GetIpSecDatabase()->GetInitSession(GsamInitSession::INITIATOR, q_address);
			if (0 == init_session)
			{
				init_session = gsam->GetIpSecDatabase()->CreateInitSession(q_address, group_address);
				Ptr<GsamSession> session = gsam->GetIpSecDatabase()->CreateSession(init_session, group_address);
				gsam->Send_IKE_SA_INIT(init_session);
			}
			else
			{
				Ptr<GsamSession> session = gsam->GetIpSecDatabase()->CreateSession(init_session, group_address);
				gsam->Send_IKE_SA_AUTH(init_session, session);
			}
			this->m_num_events--;
			if (0 < this->m_num_events)
			{
				Time delay = GsamConfig::GetSingleton()->GetGmJoinIntervalInSeconds();
				this->m_event_current = Simulator::Schedule(delay, &GsamApplication::GenerateEvent, this);
			}
		}
	}
	else
	{
		NS_ASSERT (false);
	}

}

} /* namespace ns3 */
