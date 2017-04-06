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

	GsamConfig::GetSingleton()->ClearResultFile();
//	GsamConfig::GetSingleton()->ClearWorstDelayFile();

	//std::cout << "Input simulation time (Seconds): ";
	//std::cin >> simulation_seconds;

	Time::SetResolution (Time::NS);

	NodeContainer nodes;
	nodes.Create (GsamConfig::GetSingleton()->GetNumberOfNodes());

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
	csma.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
	csma.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (10)));


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

	GsamConfig::GetSingleton()->SetupIgmpAndGsam(interfaces, GsamConfig::GetSingleton()->GetNumberOfNqs());

	if (nodes.GetN() > 0)
	{

		for (uint32_t i = 0; i < nodes.GetN(); i++)
		{
			ObjectFactory factory;
			factory.SetTypeId(Igmpv3Application::GetTypeId());
			Ptr<Application> app = factory.Create<Igmpv3Application>();
			app->SetStartTime(Seconds(0.));
			app->SetStopTime(GsamConfig::GetSingleton()->GetSimulationTimeInSeconds());
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
	GsamConfig::GetSingleton()->LogNonsecGroupAverageDelay();
	GsamConfig::GetSingleton()->LogSecGroupAverageDelay();
	GsamConfig::GetSingleton()->PlotSecGroupDelay();
	GsamConfig::GetSingleton()->PlotSecGroupDelayInRange (Seconds (10.0));
	GsamConfig::GetSingleton()->PlotSecGroupDelayInRange (Seconds (1.0));
	GsamConfig::GetSingleton()->PlotNonsecGroupDelay();
//	GsamConfig::GetSingleton()->LogALlJoinWorstDelay(GsamConfig::GetSingleton()->GetNumberOfNodes() - GsamConfig::GetSingleton()->GetNumberOfNqs() - 1);
	GsamConfig::GetSingleton()->LogALlJoinAverageAndWorstDelay(GsamConfig::GetSingleton()->GetSpiRejectPropability());
	return 0;
}


