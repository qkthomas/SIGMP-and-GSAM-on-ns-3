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

#ifndef IPV4_ROUTING_HELPER_MULTICAST_H
#define IPV4_ROUTING_HELPER_MULTICAST_H

#include "ns3/ptr.h"
#include "ns3/nstime.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/ipv4-list-routing-multicast.h"

namespace ns3 {

class Ipv4RoutingProtocolMulticast;
class Node;

/**
 * \brief a factory to create ns3::Ipv4RoutingProtocolMulticast objects
 *
 * For each new routing protocol created as a subclass of 
 * ns3::Ipv4RoutingProtocolMulticast, you need to create a subclass of 
 * ns3::Ipv4RoutingHelperMulticast which can be used by 
 * ns3::InternetStackHelperMulticast::SetRoutingHelper and 
 * ns3::InternetStackHelperMulticast::Install.
 */
class Ipv4RoutingHelperMulticast
{
public:
  /*
   * Destroy an instance of an Ipv4RoutingHelperMulticast
   */
  virtual ~Ipv4RoutingHelperMulticast ();

  /**
   * \brief virtual constructor
   * \returns pointer to clone of this Ipv4RoutingHelperMulticast 
   * 
   * This method is mainly for internal use by the other helpers;
   * clients are expected to free the dynamic memory allocated by this method
   */
  virtual Ipv4RoutingHelperMulticast* Copy (void) const = 0;

  /**
   * \param node the node within which the new routing protocol will run
   * \returns a newly-created routing protocol
   */
  virtual Ptr<Ipv4RoutingProtocolMulticast> Create (Ptr<Node> node) const = 0;

  /**
   * \brief prints the routing tables of all nodes at a particular time.
   * \param printTime the time at which the routing table is supposed to be printed.
   * \param stream The output stream object to use 
   *
   * This method calls the PrintRoutingTable() method of the 
   * Ipv4RoutingProtocolMulticast stored in the Ipv4Multicast object, for all nodes at the
   * specified time; the output format is routing protocol-specific.
   */
  static void PrintRoutingTableAllAt (Time printTime, Ptr<OutputStreamWrapper> stream);

  /**
   * \brief prints the routing tables of all nodes at regular intervals specified by user.
   * \param printInterval the time interval for which the routing table is supposed to be printed.
   * \param stream The output stream object to use
   *
   * This method calls the PrintRoutingTable() method of the 
   * Ipv4RoutingProtocolMulticast stored in the Ipv4Multicast object, for all nodes at the
   * specified time interval; the output format is routing protocol-specific.
   */
  static void PrintRoutingTableAllEvery (Time printInterval, Ptr<OutputStreamWrapper> stream);

  /**
   * \brief prints the routing tables of a node at a particular time.
   * \param printTime the time at which the routing table is supposed to be printed.
   * \param node The node ptr for which we need the routing table to be printed
   * \param stream The output stream object to use
   *
   * This method calls the PrintRoutingTable() method of the 
   * Ipv4RoutingProtocolMulticast stored in the Ipv4Multicast object, for the selected node 
   * at the specified time; the output format is routing protocol-specific.
   */
  static void PrintRoutingTableAt (Time printTime, Ptr<Node> node, Ptr<OutputStreamWrapper> stream);

  /**
   * \brief prints the routing tables of a node at regular intervals specified by user.
   * \param printInterval the time interval for which the routing table is supposed to be printed.
   * \param node The node ptr for which we need the routing table to be printed
   * \param stream The output stream object to use
   *
   * This method calls the PrintRoutingTable() method of the 
   * Ipv4RoutingProtocolMulticast stored in the Ipv4Multicast object, for the selected node 
   * at the specified interval; the output format is routing protocol-specific.
   */
  static void PrintRoutingTableEvery (Time printInterval, Ptr<Node> node, Ptr<OutputStreamWrapper> stream);

  /**
   * \brief prints the neighbor cache of all nodes at a particular time.
   * \param printTime the time at which the neighbor cache is supposed to be printed.
   * \param stream The output stream object to use
   *
   * This method calls the PrintArpCache() method of the
   * ArpCacheMulticast associated with each Ipv4InterfaceMulticast stored in the Ipv4Multicast object, for all nodes at the
   * specified time. The output format is similar to:
   * \verbatim
     10.1.1.2 dev 1 lladdr 00-06-00:00:00:00:00:02 REACHABLE
     \endverbatim
   * Note that the MAC address is printed as "type"-"size"-"actual address"
   */
  static void PrintNeighborCacheAllAt (Time printTime, Ptr<OutputStreamWrapper> stream);

  /**
   * \brief prints the neighbor cache of all nodes at regular intervals specified by user.
   * \param printInterval the time interval for which the neighbor cache is supposed to be printed.
   * \param stream The output stream object to use
   *
   * This method calls the PrintArpCache() method of the
   * ArpCacheMulticast associated with each Ipv4InterfaceMulticast stored in the Ipv4Multicast object, for all nodes at the
   * specified time. The output format is similar to:
   * \verbatim
     10.1.1.2 dev 1 lladdr 00-06-00:00:00:00:00:02 REACHABLE
     \endverbatim
   * Note that the MAC address is printed as "type"-"size"-"actual address"
   */
  static void PrintNeighborCacheAllEvery (Time printInterval, Ptr<OutputStreamWrapper> stream);

  /**
   * \brief prints the neighbor cache of a node at a particular time.
   * \param printTime the time at which the neighbor cache is supposed to be printed.
   * \param node The node ptr for which we need the neighbor cache to be printed
   * \param stream The output stream object to use
   *
   * This method calls the PrintArpCache() method of the
   * ArpCacheMulticast associated with each Ipv4InterfaceMulticast stored in the Ipv4Multicast object, for all nodes at the
   * specified time. The output format is similar to:
   * \verbatim
     10.1.1.2 dev 1 lladdr 00-06-00:00:00:00:00:02 REACHABLE
     \endverbatim
   * Note that the MAC address is printed as "type"-"size"-"actual address"
   */
  static void PrintNeighborCacheAt (Time printTime, Ptr<Node> node, Ptr<OutputStreamWrapper> stream);

  /**
   * \brief prints the neighbor cache of a node at regular intervals specified by user.
   * \param printInterval the time interval for which the neighbor cache is supposed to be printed.
   * \param node The node ptr for which we need the neighbor cache to be printed
   * \param stream The output stream object to use
   *
   * This method calls the PrintArpCache() method of the
   * ArpCacheMulticast associated with each Ipv4InterfaceMulticast stored in the Ipv4Multicast object, for all nodes at the
   * specified time. The output format is similar to:
   * \verbatim
     10.1.1.2 dev 1 lladdr 00-06-00:00:00:00:00:02 REACHABLE
     \endverbatim
   * Note that the MAC address is printed as "type"-"size"-"actual address"
   */
  static void PrintNeighborCacheEvery (Time printInterval, Ptr<Node> node, Ptr<OutputStreamWrapper> stream);

  /**
   * \brief Request a specified routing protocol &lt;T&gt; from Ipv4RoutingProtocolMulticast protocol
   *
   * If protocol is Ipv4ListRoutingMulticast, then protocol will be searched in the list,
   * otherwise a simple DynamicCast will be performed
   *
   * \param protocol Smart pointer to Ipv4RoutingProtocolMulticast object
   * \return a Smart Pointer to the requested protocol (zero if the protocol can't be found)
   */
  template<class T>
  static Ptr<T> GetRouting (Ptr<Ipv4RoutingProtocolMulticast> protocol);
  
private:
  /**
   * \brief prints the routing tables of a node.
   * \param node The node ptr for which we need the routing table to be printed
   * \param stream The output stream object to use
   *
   * This method calls the PrintRoutingTable() method of the
   * Ipv4RoutingProtocolMulticast stored in the Ipv4Multicast object;
   * the output format is routing protocol-specific.
   */
  static void Print (Ptr<Node> node, Ptr<OutputStreamWrapper> stream);

  /**
   * \brief prints the routing tables of a node at regular intervals specified by user.
   * \param printInterval the time interval for which the routing table is supposed to be printed.
   * \param node The node ptr for which we need the routing table to be printed
   * \param stream The output stream object to use
   *
   * This method calls the PrintRoutingTable() method of the
   * Ipv4RoutingProtocolMulticast stored in the Ipv4Multicast object, for the selected node
   * at the specified interval; the output format is routing protocol-specific.
   */
  static void PrintEvery (Time printInterval, Ptr<Node> node, Ptr<OutputStreamWrapper> stream);

  /**
   * \brief prints the neighbor cache of a node.
   * \param node The node ptr for which we need the neighbor cache to be printed
   * \param stream The output stream object to use
   *
   * This method calls the PrintArpCache() method of the
   * ArpCacheMulticast associated with each Ipv4InterfaceMulticast stored in the Ipv4Multicast object, for all nodes at the
   * specified time. The output format is similar to:
   * \verbatim
     10.1.1.2 dev 1 lladdr 00-06-00:00:00:00:00:02 REACHABLE
     \endverbatim
   * Note that the MAC address is printed as "type"-"size"-"actual address"
   */
  static void PrintArpCache (Ptr<Node> node, Ptr<OutputStreamWrapper> stream);

  /**
   * \brief prints the neighbor cache of a node at regular intervals specified by user.
   * \param printInterval the time interval for which the neighbor cache is supposed to be printed.
   * \param node The node ptr for which we need the neighbor cache to be printed
   * \param stream The output stream object to use
   *
   * This method calls the PrintArpCache() method of the
   * ArpCacheMulticast associated with each Ipv4InterfaceMulticast stored in the Ipv4Multicast object, for all nodes at the
   * specified time. The output format is similar to:
   * \verbatim
     10.1.1.2 dev 1 lladdr 00-06-00:00:00:00:00:02 REACHABLE
     \endverbatim
   * Note that the MAC address is printed as "type"-"size"-"actual address"
   */
  static void PrintArpCacheEvery (Time printInterval, Ptr<Node> node, Ptr<OutputStreamWrapper> stream);
};


/**
 * \brief Request a specified routing protocol &lt;T&gt; from Ipv4RoutingProtocolMulticast protocol
 *
 * If protocol is Ipv4ListRoutingMulticast, then protocol will be searched in the list,
 * otherwise a simple DynamicCast will be performed
 *
 * \param protocol Smart pointer to Ipv4RoutingProtocolMulticast object
 * \return a Smart Pointer to the requested protocol (zero if the protocol can't be found)
 */
template<class T>
Ptr<T> Ipv4RoutingHelperMulticast::GetRouting (Ptr<Ipv4RoutingProtocolMulticast> protocol)
{
  Ptr<T> ret = DynamicCast<T> (protocol);
  if (ret == 0)
    {
      // trying to check if protocol is a list routing
      Ptr<Ipv4ListRoutingMulticast> lrp = DynamicCast<Ipv4ListRoutingMulticast> (protocol);
      if (lrp != 0)
        {
          for (uint32_t i = 0; i < lrp->GetNRoutingProtocols ();  i++)
            {
              int16_t priority;
              ret = GetRouting<T> (lrp->GetRoutingProtocol (i, priority)); // potential recursion, if inside ListRouting is ListRouting
              if (ret != 0)
                break;
            }
        }
    }

  return ret;
}

} // namespace ns3


#endif /* IPV4_ROUTING_HELPER_H */
