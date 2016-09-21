/*
 * gsam-application.cc
 *
 *  Created on: Sep 20, 2016
 *      Author: lim
 */

#include "gsam-application.h"
#include "ns3/ipsec.h"

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
}

void
GsamApplication::StopApplication (void)
{

}

Ptr<GsamL4Protocol>
GsamApplication::GetGsam (void) const
{
	Ptr<GsamL4Protocol> retval = 0;
	retval = this->GetNode()->GetObject<GsamL4Protocol> ();

	if (0 == retval)
	{
		NS_ASSERT (false);
	}

	return retval;
}

} /* namespace ns3 */
