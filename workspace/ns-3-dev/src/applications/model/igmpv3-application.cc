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

	Time dt = Seconds(0.);

	//static int run = 0 is to make sure codes in if block will only run once.
	static bool firstnode = true;

	if(true == firstnode)
	{
		this->m_sendEvent = Simulator::Schedule (dt, &Igmpv3Application::SendGeneralQuery, this);
		firstnode = false;
	}

}

void
Igmpv3Application::StopApplication (void)
{

}

void
Igmpv3Application::SendGeneralQuery (void)
{
	Ptr<Ipv4Multicast> ipv4 = this->GetNode()->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);

	ipv4l3->SendIgmpGeneralQuery ();

	this->m_sendEvent = Simulator::Schedule (this->m_default_query_interval, &Igmpv3Application::SendGeneralQuery, this);
}

} /* namespace ns3 */
