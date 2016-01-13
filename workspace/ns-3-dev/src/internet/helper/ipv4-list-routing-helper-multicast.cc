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
#include "ipv4-list-routing-helper-multicast.h"
#include "ns3/ipv4-list-routing-multicast.h"
#include "ns3/node.h"

namespace ns3 {

Ipv4ListRoutingHelperMulticast::Ipv4ListRoutingHelperMulticast()
{
}

Ipv4ListRoutingHelperMulticast::~Ipv4ListRoutingHelperMulticast()
{
  for (std::list<std::pair<const Ipv4RoutingHelperMulticast *, int16_t> >::iterator i = m_list.begin ();
       i != m_list.end (); ++i)
    {
      delete i->first;
    }
}

Ipv4ListRoutingHelperMulticast::Ipv4ListRoutingHelperMulticast (const Ipv4ListRoutingHelperMulticast &o)
{
  std::list<std::pair<const Ipv4RoutingHelperMulticast *, int16_t> >::const_iterator i;
  for (i = o.m_list.begin (); i != o.m_list.end (); ++i)
    {
      m_list.push_back (std::make_pair (const_cast<const Ipv4RoutingHelperMulticast *> (i->first->Copy ()), i->second));
    }
}

Ipv4ListRoutingHelperMulticast* 
Ipv4ListRoutingHelperMulticast::Copy (void) const 
{
  return new Ipv4ListRoutingHelperMulticast (*this); 
}

void 
Ipv4ListRoutingHelperMulticast::Add (const Ipv4RoutingHelperMulticast &routing, int16_t priority)
{
  m_list.push_back (std::make_pair (const_cast<const Ipv4RoutingHelperMulticast *> (routing.Copy ()), priority));
}

Ptr<Ipv4RoutingProtocolMulticast> 
Ipv4ListRoutingHelperMulticast::Create (Ptr<Node> node) const
{
  Ptr<Ipv4ListRoutingMulticast> list = CreateObject<Ipv4ListRoutingMulticast> ();
  for (std::list<std::pair<const Ipv4RoutingHelperMulticast *, int16_t> >::const_iterator i = m_list.begin ();
       i != m_list.end (); ++i)
    {
      Ptr<Ipv4RoutingProtocolMulticast> prot = i->first->Create (node);
      list->AddRoutingProtocol (prot,i->second);
    }
  return list;
}

} // namespace ns3
