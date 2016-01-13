/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2008 INRIA
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
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#include "ns3/node.h"
#include "ns3/node-list.h"
#include "ns3/simulator.h"
#include "ns3/ipv4-routing-protocol-multicast.h"
#include "ns3/ipv4-list-routing-multicast.h"
#include "ns3/ipv4-l3-protocol-multicast.h"
#include "ns3/ipv4-interface-multicast.h"
#include "ns3/arp-cache-multicast.h"
#include "ns3/names.h"
#include "ipv4-routing-helper-multicast.h"

namespace ns3 {

Ipv4RoutingHelperMulticast::~Ipv4RoutingHelperMulticast ()
{
}

void
Ipv4RoutingHelperMulticast::PrintRoutingTableAllAt (Time printTime, Ptr<OutputStreamWrapper> stream)
{
  for (uint32_t i = 0; i < NodeList::GetNNodes (); i++)
    {
      Ptr<Node> node = NodeList::GetNode (i);
      Simulator::Schedule (printTime, &Ipv4RoutingHelperMulticast::Print, node, stream);
    }
}

void
Ipv4RoutingHelperMulticast::PrintRoutingTableAllEvery (Time printInterval, Ptr<OutputStreamWrapper> stream)
{
  for (uint32_t i = 0; i < NodeList::GetNNodes (); i++)
    {
      Ptr<Node> node = NodeList::GetNode (i);
      Simulator::Schedule (printInterval, &Ipv4RoutingHelperMulticast::PrintEvery, printInterval, node, stream);
    }
}

void
Ipv4RoutingHelperMulticast::PrintRoutingTableAt (Time printTime, Ptr<Node> node, Ptr<OutputStreamWrapper> stream)
{
  Simulator::Schedule (printTime, &Ipv4RoutingHelperMulticast::Print, node, stream);
}

void
Ipv4RoutingHelperMulticast::PrintRoutingTableEvery (Time printInterval,Ptr<Node> node, Ptr<OutputStreamWrapper> stream)
{
  Simulator::Schedule (printInterval, &Ipv4RoutingHelperMulticast::PrintEvery, printInterval, node, stream);
}

void
Ipv4RoutingHelperMulticast::Print (Ptr<Node> node, Ptr<OutputStreamWrapper> stream)
{
  Ptr<Ipv4Multicast> ipv4 = node->GetObject<Ipv4Multicast> ();
  if (ipv4)
    {
      Ptr<Ipv4RoutingProtocolMulticast> rp = ipv4->GetRoutingProtocol ();
      NS_ASSERT (rp);
      rp->PrintRoutingTable (stream);
    }
}

void
Ipv4RoutingHelperMulticast::PrintEvery (Time printInterval, Ptr<Node> node, Ptr<OutputStreamWrapper> stream)
{
  Ptr<Ipv4Multicast> ipv4 = node->GetObject<Ipv4Multicast> ();
  if (ipv4)
    {
      Ptr<Ipv4RoutingProtocolMulticast> rp = ipv4->GetRoutingProtocol ();
      NS_ASSERT (rp);
      rp->PrintRoutingTable (stream);
      Simulator::Schedule (printInterval, &Ipv4RoutingHelperMulticast::PrintEvery, printInterval, node, stream);
    }
}

void
Ipv4RoutingHelperMulticast::PrintNeighborCacheAllAt (Time printTime, Ptr<OutputStreamWrapper> stream)
{
  for (uint32_t i = 0; i < NodeList::GetNNodes (); i++)
    {
      Ptr<Node> node = NodeList::GetNode (i);
      Simulator::Schedule (printTime, &Ipv4RoutingHelperMulticast::PrintArpCache, node, stream);
    }
}

void
Ipv4RoutingHelperMulticast::PrintNeighborCacheAllEvery (Time printInterval, Ptr<OutputStreamWrapper> stream)
{
  for (uint32_t i = 0; i < NodeList::GetNNodes (); i++)
    {
      Ptr<Node> node = NodeList::GetNode (i);
      Simulator::Schedule (printInterval, &Ipv4RoutingHelperMulticast::PrintArpCacheEvery, printInterval, node, stream);
    }
}

void
Ipv4RoutingHelperMulticast::PrintNeighborCacheAt (Time printTime, Ptr<Node> node, Ptr<OutputStreamWrapper> stream)
{
  Simulator::Schedule (printTime, &Ipv4RoutingHelperMulticast::PrintArpCache, node, stream);
}

void
Ipv4RoutingHelperMulticast::PrintNeighborCacheEvery (Time printInterval,Ptr<Node> node, Ptr<OutputStreamWrapper> stream)
{
  Simulator::Schedule (printInterval, &Ipv4RoutingHelperMulticast::PrintArpCacheEvery, printInterval, node, stream);
}

void
Ipv4RoutingHelperMulticast::PrintArpCache (Ptr<Node> node, Ptr<OutputStreamWrapper> stream)
{
  Ptr<Ipv4L3ProtocolMulticast> ipv4 = node->GetObject<Ipv4L3ProtocolMulticast> ();
  if (ipv4)
    {
      std::ostream* os = stream->GetStream ();

      *os << "ARP Cache of node ";
      std::string found = Names::FindName (node);
      if (Names::FindName (node) != "")
        {
          *os << found;
        }
      else
        {
          *os << static_cast<int> (node->GetId ());
        }
      *os << " at time " << Simulator::Now ().GetSeconds () << "\n";

      for (uint32_t i=0; i<ipv4->GetNInterfaces(); i++)
        {
          Ptr<ArpCacheMulticast> arpCache = ipv4->GetInterface (i)->GetArpCache ();
          if (arpCache)
            {
              arpCache->PrintArpCache (stream);
            }
        }
    }
}

void
Ipv4RoutingHelperMulticast::PrintArpCacheEvery (Time printInterval, Ptr<Node> node, Ptr<OutputStreamWrapper> stream)
{
  Ptr<Ipv4L3ProtocolMulticast> ipv4 = node->GetObject<Ipv4L3ProtocolMulticast> ();
  if (ipv4)
    {
      std::ostream* os = stream->GetStream ();

      *os << "ARP Cache of node ";
      std::string found = Names::FindName (node);
      if (Names::FindName (node) != "")
        {
          *os << found;
        }
      else
        {
          *os << static_cast<int> (node->GetId ());
        }
      *os << " at time " << Simulator::Now ().GetSeconds () << "\n";

      for (uint32_t i=0; i<ipv4->GetNInterfaces(); i++)
        {
          Ptr<ArpCacheMulticast> arpCache = ipv4->GetInterface (i)->GetArpCache ();
          if (arpCache)
            {
              arpCache->PrintArpCache (stream);
            }
        }
      Simulator::Schedule (printInterval, &Ipv4RoutingHelperMulticast::PrintArpCacheEvery, printInterval, node, stream);
    }
}

} // namespace ns3
