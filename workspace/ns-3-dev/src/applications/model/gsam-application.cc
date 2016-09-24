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
	Ptr<GsamL4Protocol> gsam = this->GetGsam();
	Ptr<Igmpv3L4Protocol> igmp = this->m_node->GetObject<Igmpv3L4Protocol>();
	std::cout << "Node id: " << this->m_node->GetId() << ", ";
	if (0 == igmp)
	{
		std::cout << "does not have igmp." << std::endl;
	}
	else
	{
		if (igmp->GetRole() == Igmpv3L4Protocol::QUERIER)
		{
			std::cout << "is a querier." << std::endl;
		}
		else if (igmp->GetRole() == Igmpv3L4Protocol::NONQUERIER)
		{
			std::cout << "is a non-querier." << std::endl;
		}
		else if (igmp->GetRole() == Igmpv3L4Protocol::GROUP_MEMBER)
		{
			std::cout << "is a group member." << std::endl;
		}
		else
		{
			NS_ASSERT (false);
		}
	}

	Time delay = Seconds (1.0);
	this->m_current_event = Simulator::Schedule(delay, &GsamApplication::GenerateEvent, this);
}

void
GsamApplication::StopApplication (void)
{

}

Ptr<GsamL4Protocol>
GsamApplication::GetGsam (void) const
{
	NS_LOG_FUNCTION (this);
	Ptr<GsamL4Protocol> retval = 0;
	retval = this->GetNode()->GetObject<GsamL4Protocol> ();

	if (0 == retval)
	{
		NS_ASSERT (false);
	}

	return retval;
}

void
GsamApplication::GenerateEvent (void)
{
	NS_LOG_FUNCTION (this);
}

} /* namespace ns3 */
