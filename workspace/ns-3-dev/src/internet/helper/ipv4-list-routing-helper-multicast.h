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
#ifndef IPV4_LIST_ROUTING_HELPER_MULTICAST_H
#define IPV4_LIST_ROUTING_HELPER_MULTICAST_H

#include "ns3/ipv4-routing-helper-multicast.h"
#include <stdint.h>
#include <list>

namespace ns3 {

/**
 * \brief Helper class that adds ns3::Ipv4ListRoutingMulticast objects
 *
 * This class is expected to be used in conjunction with 
 * ns3::InternetStackHelperMulticast::SetRoutingHelper
 */
class Ipv4ListRoutingHelperMulticast : public Ipv4RoutingHelperMulticast
{
public:
  /*
   * Construct an Ipv4ListRoutingHelperMulticast used to make installing routing
   * protocols easier.
   */
  Ipv4ListRoutingHelperMulticast ();

  /*
   * Destroy an Ipv4ListRoutingHelperMulticast.
   */
  virtual ~Ipv4ListRoutingHelperMulticast ();

  /**
   * \brief Construct an Ipv4ListRoutingHelperMulticast from another previously 
   * initialized instance (Copy Constructor).
   */
  Ipv4ListRoutingHelperMulticast (const Ipv4ListRoutingHelperMulticast &);

  /**
   * \returns pointer to clone of this Ipv4ListRoutingHelperMulticast 
   * 
   * This method is mainly for internal use by the other helpers;
   * clients are expected to free the dynamic memory allocated by this method
   */
  Ipv4ListRoutingHelperMulticast* Copy (void) const;

  /**
   * \param routing a routing helper
   * \param priority the priority of the associated helper
   *
   * Store in the internal list a reference to the input routing helper
   * and associated priority. These helpers will be used later by
   * the ns3::Ipv4ListRoutingHelperMulticast::Create method to create
   * an ns3::Ipv4ListRoutingMulticast object and add in it routing protocols
   * created with the helpers.
   */
  void Add (const Ipv4RoutingHelperMulticast &routing, int16_t priority);
  /**
   * \param node the node on which the routing protocol will run
   * \returns a newly-created routing protocol
   *
   * This method will be called by ns3::InternetStackHelperMulticast::Install
   */
  virtual Ptr<Ipv4RoutingProtocolMulticast> Create (Ptr<Node> node) const;
private:
  /**
   * \brief Assignment operator declared private and not implemented to disallow
   * assignment and prevent the compiler from happily inserting its own.
   * \return
   */
  Ipv4ListRoutingHelperMulticast &operator = (const Ipv4ListRoutingHelperMulticast &);

  /**
   * \brief Container for pairs of Ipv4RoutingHelperMulticast pointer / priority.
   */
  std::list<std::pair<const Ipv4RoutingHelperMulticast *,int16_t> > m_list;
};

} // namespace ns3

#endif /* IPV4_LIST_ROUTING_HELPER_H */
