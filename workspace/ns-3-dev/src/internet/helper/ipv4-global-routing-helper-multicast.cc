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
#include "ipv4-global-routing-helper-multicast.h"
#include "ns3/global-router-interface-multicast.h"
#include "ns3/ipv4-global-routing-multicast.h"
#include "ns3/ipv4-list-routing-multicast.h"
#include "ns3/log.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("GlobalRoutingHelperMulticast");

Ipv4GlobalRoutingHelperMulticast::Ipv4GlobalRoutingHelperMulticast ()
{
}

Ipv4GlobalRoutingHelperMulticast::Ipv4GlobalRoutingHelperMulticast (const Ipv4GlobalRoutingHelperMulticast &o)
{
}

Ipv4GlobalRoutingHelperMulticast*
Ipv4GlobalRoutingHelperMulticast::Copy (void) const
{
  return new Ipv4GlobalRoutingHelperMulticast (*this);
}

Ptr<Ipv4RoutingProtocolMulticast>
Ipv4GlobalRoutingHelperMulticast::Create (Ptr<Node> node) const
{
  NS_LOG_LOGIC ("Adding GlobalRouterMulticast interface to node " <<
                node->GetId ());

  Ptr<GlobalRouterMulticast> globalRouter = CreateObject<GlobalRouterMulticast> ();
  node->AggregateObject (globalRouter);

  NS_LOG_LOGIC ("Adding GlobalRouting Protocol to node " << node->GetId ());
  Ptr<Ipv4GlobalRoutingMulticast> globalRouting = CreateObject<Ipv4GlobalRoutingMulticast> ();
  globalRouter->SetRoutingProtocol (globalRouting);

  return globalRouting;
}

void 
Ipv4GlobalRoutingHelperMulticast::PopulateRoutingTables (void)
{
  GlobalRouteManagerMulticast::BuildGlobalRoutingDatabase ();
  GlobalRouteManagerMulticast::InitializeRoutes ();
}
void 
Ipv4GlobalRoutingHelperMulticast::RecomputeRoutingTables (void)
{
  GlobalRouteManagerMulticast::DeleteGlobalRoutes ();
  GlobalRouteManagerMulticast::BuildGlobalRoutingDatabase ();
  GlobalRouteManagerMulticast::InitializeRoutes ();
}


} // namespace ns3
