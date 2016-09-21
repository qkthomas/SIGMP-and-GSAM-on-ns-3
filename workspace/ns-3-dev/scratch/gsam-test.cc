/*
 * gsam-test.cc
 *
 *  Created on: Sep 20, 2016
 *      Author: lim
 */

/*
 * igmpv3-application-test.cc
 *
 *  Created on: Feb 9, 2016
 *      Author: lim
 */

#include "ns3/applications-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/command-line.h"

using namespace ns3;

int
main (int argc, char *argv[])
{

	CommandLine cmd;

	cmd.Parse (argc, argv);

	int simulation_seconds = 60000;

	//std::cout << "Input simulation time (Seconds): ";
	//std::cin >> simulation_seconds;

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


	InternetStackHelperMulticast stack;
	stack.Install (nodes);

	Ipv4AddressHelperMulticast address;
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

	Ipv4InterfaceContainerMulticast interfaces = address.Assign (devices);

	//Get Addresses
	for (Ipv4InterfaceContainerMulticast::Iterator it = interfaces.Begin();
			it != interfaces.End();
			it++)
	{
		static bool first = true;
		Ptr<Ipv4Multicast> ipv4 = it->first;
		uint32_t ifindex = it->second;
		Ipv4Address if_ipv4_addr = ipv4->GetAddress(ifindex, 0).GetLocal();
		if (true == first)
		{
			//set it as Q address
		}
		else
		{
			//set them as nq or gm address
		}
	}

	if (nodes.GetN() > 0)
	{

		for (uint32_t i = 0; i < nodes.GetN(); i++)
		{
			ObjectFactory factory;
			factory.SetTypeId(GsamApplication::GetTypeId());
			Ptr<Application> app = factory.Create<GsamApplication>();
			app->SetStartTime(Seconds(0.));
			app->SetStopTime(Seconds(double(simulation_seconds)));
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

	Ipv4GlobalRoutingHelperMulticast::PopulateRoutingTables ();

	Simulator::Run ();
	Simulator::Destroy ();
	return 0;
}
