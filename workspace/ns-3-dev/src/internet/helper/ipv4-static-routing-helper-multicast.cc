/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 University of Washington
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <vector>
#include "ns3/log.h"
#include "ns3/ptr.h"
#include "ns3/names.h"
#include "ns3/node.h"
#include "ns3/ipv4-multicast.h"
#include "ns3/ipv4-route.h"
#include "ns3/ipv4-list-routing-multicast.h"
#include "ns3/assert.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-routing-protocol-multicast.h"
#include "ipv4-static-routing-helper-multicast.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("Ipv4StaticRoutingHelperMulticast");

Ipv4StaticRoutingHelperMulticast::Ipv4StaticRoutingHelperMulticast()
{
}

Ipv4StaticRoutingHelperMulticast::Ipv4StaticRoutingHelperMulticast (const Ipv4StaticRoutingHelperMulticast &o)
{
}

Ipv4StaticRoutingHelperMulticast*
Ipv4StaticRoutingHelperMulticast::Copy (void) const
{
  return new Ipv4StaticRoutingHelperMulticast (*this);
}

Ptr<Ipv4RoutingProtocolMulticast>
Ipv4StaticRoutingHelperMulticast::Create (Ptr<Node> node) const
{
  return CreateObject<Ipv4StaticRoutingMulticast> ();
}


Ptr<Ipv4StaticRoutingMulticast>
Ipv4StaticRoutingHelperMulticast::GetStaticRouting (Ptr<Ipv4Multicast> ipv4) const
{
  NS_LOG_FUNCTION (this);
  Ptr<Ipv4RoutingProtocolMulticast> ipv4rp = ipv4->GetRoutingProtocol ();
  NS_ASSERT_MSG (ipv4rp, "No routing protocol associated with Ipv4Multicast");
  if (DynamicCast<Ipv4StaticRoutingMulticast> (ipv4rp))
    {
      NS_LOG_LOGIC ("Static routing found as the main IPv4 routing protocol.");
      return DynamicCast<Ipv4StaticRoutingMulticast> (ipv4rp); 
    } 
  if (DynamicCast<Ipv4ListRoutingMulticast> (ipv4rp))
    {
      Ptr<Ipv4ListRoutingMulticast> lrp = DynamicCast<Ipv4ListRoutingMulticast> (ipv4rp);
      int16_t priority;
      for (uint32_t i = 0; i < lrp->GetNRoutingProtocols ();  i++)
        {
          NS_LOG_LOGIC ("Searching for static routing in list");
          Ptr<Ipv4RoutingProtocolMulticast> temp = lrp->GetRoutingProtocol (i, priority);
          if (DynamicCast<Ipv4StaticRoutingMulticast> (temp))
            {
              NS_LOG_LOGIC ("Found static routing in list");
              return DynamicCast<Ipv4StaticRoutingMulticast> (temp);
            }
        }
    }
  NS_LOG_LOGIC ("Static routing not found");
  return 0;
}

void
Ipv4StaticRoutingHelperMulticast::AddMulticastRoute (
  Ptr<Node> n,
  Ipv4Address source, 
  Ipv4Address group,
  Ptr<NetDevice> input, 
  NetDeviceContainer output)
{
  Ptr<Ipv4Multicast> ipv4 = n->GetObject<Ipv4Multicast> ();

  // We need to convert the NetDeviceContainer to an array of interface 
  // numbers
  std::vector<uint32_t> outputInterfaces;
  for (NetDeviceContainer::Iterator i = output.Begin (); i != output.End (); ++i)
    {
      Ptr<NetDevice> nd = *i;
      int32_t interface = ipv4->GetInterfaceForDevice (nd);
      NS_ASSERT_MSG (interface >= 0,
                     "Ipv4StaticRoutingHelperMulticast::AddMulticastRoute(): "
                     "Expected an interface associated with the device nd");
      outputInterfaces.push_back (interface);
    }

  int32_t inputInterface = ipv4->GetInterfaceForDevice (input);
  NS_ASSERT_MSG (inputInterface >= 0,
                 "Ipv4StaticRoutingHelperMulticast::AddMulticastRoute(): "
                 "Expected an interface associated with the device input");
  Ipv4StaticRoutingHelperMulticast helper;
  Ptr<Ipv4StaticRoutingMulticast> ipv4StaticRouting = helper.GetStaticRouting (ipv4);
  if (!ipv4StaticRouting)
    {
      NS_ASSERT_MSG (ipv4StaticRouting,
                     "Ipv4StaticRoutingHelperMulticast::SetDefaultMulticastRoute(): "
                     "Expected an Ipv4StaticRoutingMulticast associated with this node");
    }
  ipv4StaticRouting->AddMulticastRoute (source, group, inputInterface, outputInterfaces);
}

void
Ipv4StaticRoutingHelperMulticast::AddMulticastRoute (
  Ptr<Node> n,
  Ipv4Address source, 
  Ipv4Address group,
  std::string inputName, 
  NetDeviceContainer output)
{
  Ptr<NetDevice> input = Names::Find<NetDevice> (inputName);
  AddMulticastRoute (n, source, group, input, output);
}

void
Ipv4StaticRoutingHelperMulticast::AddMulticastRoute (
  std::string nName,
  Ipv4Address source, 
  Ipv4Address group,
  Ptr<NetDevice> input, 
  NetDeviceContainer output)
{
  Ptr<Node> n = Names::Find<Node> (nName);
  AddMulticastRoute (n, source, group, input, output);
}

void
Ipv4StaticRoutingHelperMulticast::AddMulticastRoute (
  std::string nName,
  Ipv4Address source, 
  Ipv4Address group,
  std::string inputName, 
  NetDeviceContainer output)
{
  Ptr<NetDevice> input = Names::Find<NetDevice> (inputName);
  Ptr<Node> n = Names::Find<Node> (nName);
  AddMulticastRoute (n, source, group, input, output);
}

void
Ipv4StaticRoutingHelperMulticast::SetDefaultMulticastRoute (
  Ptr<Node> n, 
  Ptr<NetDevice> nd)
{
  Ptr<Ipv4Multicast> ipv4 = n->GetObject<Ipv4Multicast> ();
  int32_t interfaceSrc = ipv4->GetInterfaceForDevice (nd);
  NS_ASSERT_MSG (interfaceSrc >= 0,
                 "Ipv4StaticRoutingHelperMulticast::SetDefaultMulticastRoute(): "
                 "Expected an interface associated with the device");
  Ipv4StaticRoutingHelperMulticast helper;
  Ptr<Ipv4StaticRoutingMulticast> ipv4StaticRouting = helper.GetStaticRouting (ipv4);
  if (!ipv4StaticRouting)
    {
      NS_ASSERT_MSG (ipv4StaticRouting, 
                     "Ipv4StaticRoutingHelperMulticast::SetDefaultMulticastRoute(): "
                     "Expected an Ipv4StaticRoutingMulticast associated with this node");
    }
  ipv4StaticRouting->SetDefaultMulticastRoute (interfaceSrc);
}

void
Ipv4StaticRoutingHelperMulticast::SetDefaultMulticastRoute (
  Ptr<Node> n, 
  std::string ndName)
{
  Ptr<NetDevice> nd = Names::Find<NetDevice> (ndName);
  SetDefaultMulticastRoute (n, nd);
}

void
Ipv4StaticRoutingHelperMulticast::SetDefaultMulticastRoute (
  std::string nName, 
  Ptr<NetDevice> nd)
{
  Ptr<Node> n = Names::Find<Node> (nName);
  SetDefaultMulticastRoute (n, nd);
}

void
Ipv4StaticRoutingHelperMulticast::SetDefaultMulticastRoute (
  std::string nName, 
  std::string ndName)
{
  Ptr<Node> n = Names::Find<Node> (nName);
  Ptr<NetDevice> nd = Names::Find<NetDevice> (ndName);
  SetDefaultMulticastRoute (n, nd);
}

} // namespace ns3
