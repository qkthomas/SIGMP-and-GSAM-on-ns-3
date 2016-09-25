/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2005,2006,2007 INRIA
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

#ifndef UDP_L4_PROTOCOL_H_MULTICAST
#define UDP_L4_PROTOCOL_H_MULTICAST

#include <stdint.h>

#include "ns3/packet.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/ptr.h"
#include "ns3/ip-l4-protocol-multicast.h"
#include "ipv6-interface.h"
#include "ipv6-header.h"

namespace ns3 {

class Node;
class Socket;
class Ipv4EndPointDemux;
class Ipv4EndPoint;
class Ipv6EndPointDemux;
class Ipv6EndPoint;
class UdpSocketImplMulticast;

/**
 * \ingroup udp
 * \brief Implementation of the UDP protocol
 */
class UdpL4ProtocolMulticast : public IpL4ProtocolMulticast {
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);
  static const uint8_t PROT_NUMBER; //!< protocol number (0x11)

  UdpL4ProtocolMulticast ();
  virtual ~UdpL4ProtocolMulticast ();

  /**
   * Set node associated with this stack
   * \param node the node
   */
  void SetNode (Ptr<Node> node);

  virtual int GetProtocolNumber (void) const;

  /**
   * \return A smart Socket pointer to a UdpSocket, allocated by this instance
   * of the UDP protocol
   */
  Ptr<Socket> CreateSocket (void);

  /**
   * \brief Allocate an IPv4 Endpoint
   * \return the Endpoint
   */
  Ipv4EndPoint *Allocate (void);
  /**
   * \brief Allocate an IPv4 Endpoint
   * \param address address to use
   * \return the Endpoint
   */
  Ipv4EndPoint *Allocate (Ipv4Address address);
  /**
   * \brief Allocate an IPv4 Endpoint
   * \param port port to use
   * \return the Endpoint
   */
  Ipv4EndPoint *Allocate (uint16_t port);
  /**
   * \brief Allocate an IPv4 Endpoint
   * \param address address to use
   * \param port port to use
   * \return the Endpoint
   */
  Ipv4EndPoint *Allocate (Ipv4Address address, uint16_t port);
  /**
   * \brief Allocate an IPv4 Endpoint
   * \param localAddress local address to use
   * \param localPort local port to use
   * \param peerAddress remote address to use
   * \param peerPort remote port to use
   * \return the Endpoint
   */
  Ipv4EndPoint *Allocate (Ipv4Address localAddress, uint16_t localPort,
                          Ipv4Address peerAddress, uint16_t peerPort);

  /**
   * \brief Allocate an IPv6 Endpoint
   * \return the Endpoint
   */
  Ipv6EndPoint *Allocate6 (void);
  /**
   * \brief Allocate an IPv6 Endpoint
   * \param address address to use
   * \return the Endpoint
   */
  Ipv6EndPoint *Allocate6 (Ipv6Address address);
  /**
   * \brief Allocate an IPv6 Endpoint
   * \param port port to use
   * \return the Endpoint
   */
  Ipv6EndPoint *Allocate6 (uint16_t port);
  /**
   * \brief Allocate an IPv6 Endpoint
   * \param address address to use
   * \param port port to use
   * \return the Endpoint
   */
  Ipv6EndPoint *Allocate6 (Ipv6Address address, uint16_t port);
  /**
   * \brief Allocate an IPv6 Endpoint
   * \param localAddress local address to use
   * \param localPort local port to use
   * \param peerAddress remote address to use
   * \param peerPort remote port to use
   * \return the Endpoint
   */
  Ipv6EndPoint *Allocate6 (Ipv6Address localAddress, uint16_t localPort,
                           Ipv6Address peerAddress, uint16_t peerPort);

  /**
   * \brief Remove an IPv4 Endpoint.
   * \param endPoint the end point to remove
   */
  void DeAllocate (Ipv4EndPoint *endPoint);
  /**
   * \brief Remove an IPv6 Endpoint.
   * \param endPoint the end point to remove
   */
  void DeAllocate (Ipv6EndPoint *endPoint);

  // called by UdpSocket.
  /**
   * \brief Send a packet via UDP (IPv4)
   * \param packet The packet to send
   * \param saddr The source Ipv4Address
   * \param daddr The destination Ipv4Address
   * \param sport The source port number
   * \param dport The destination port number
   */
  void Send (Ptr<Packet> packet,
             Ipv4Address saddr, Ipv4Address daddr, 
             uint16_t sport, uint16_t dport);
  /**
   * \brief Send a packet via UDP (IPv4)
   * \param packet The packet to send
   * \param saddr The source Ipv4Address
   * \param daddr The destination Ipv4Address
   * \param sport The source port number
   * \param dport The destination port number
   * \param route The route
   */
  void Send (Ptr<Packet> packet,
             Ipv4Address saddr, Ipv4Address daddr, 
             uint16_t sport, uint16_t dport, Ptr<Ipv4Route> route);
  /**
   * \brief Send a packet via UDP (IPv6)
   * \param packet The packet to send
   * \param saddr The source Ipv4Address
   * \param daddr The destination Ipv4Address
   * \param sport The source port number
   * \param dport The destination port number
   */
  void Send (Ptr<Packet> packet,
             Ipv6Address saddr, Ipv6Address daddr, 
             uint16_t sport, uint16_t dport);
  /**
   * \brief Send a packet via UDP (IPv6)
   * \param packet The packet to send
   * \param saddr The source Ipv4Address
   * \param daddr The destination Ipv4Address
   * \param sport The source port number
   * \param dport The destination port number
   * \param route The route
   */
  void Send (Ptr<Packet> packet,
             Ipv6Address saddr, Ipv6Address daddr, 
             uint16_t sport, uint16_t dport, Ptr<Ipv6Route> route);

  // inherited from Ipv4L4Protocol
  virtual enum IpL4ProtocolMulticast::RxStatus Receive (Ptr<Packet> p,
                                               Ipv4Header const &header,
                                               Ptr<Ipv4InterfaceMulticast> interface);
  virtual enum IpL4ProtocolMulticast::RxStatus Receive (Ptr<Packet> p,
                                               Ipv6Header const &header,
                                               Ptr<Ipv6Interface> interface);

  virtual void ReceiveIcmp (Ipv4Address icmpSource, uint8_t icmpTtl,
                            uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo,
                            Ipv4Address payloadSource,Ipv4Address payloadDestination,
                            const uint8_t payload[8]);
  virtual void ReceiveIcmp (Ipv6Address icmpSource, uint8_t icmpTtl,
                            uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo,
                            Ipv6Address payloadSource,Ipv6Address payloadDestination,
                            const uint8_t payload[8]);

  // From IpL4ProtocolMulticast
  virtual void SetDownTarget (IpL4ProtocolMulticast::DownTargetCallback cb);
  virtual void SetDownTarget6 (IpL4ProtocolMulticast::DownTargetCallback6 cb);
  // From IpL4ProtocolMulticast
  virtual IpL4ProtocolMulticast::DownTargetCallback GetDownTarget (void) const;
  virtual IpL4ProtocolMulticast::DownTargetCallback6 GetDownTarget6 (void) const;

protected:
  virtual void DoDispose (void);
  /*
   * This function will notify other components connected to the node that a new stack member is now connected
   * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
   */
  virtual void NotifyNewAggregate ();
private:
  Ptr<Node> m_node; //!< the node this stack is associated with
  Ipv4EndPointDemux *m_endPoints; //!< A list of IPv4 end points.
  Ipv6EndPointDemux *m_endPoints6; //!< A list of IPv6 end points.

  /**
   * \brief Copy constructor
   *
   * Defined and not implemented to avoid misuse
   */
  UdpL4ProtocolMulticast (const UdpL4ProtocolMulticast &);
  /**
   * \brief Copy constructor
   *
   * Defined and not implemented to avoid misuse
   * \returns
   */
  UdpL4ProtocolMulticast &operator = (const UdpL4ProtocolMulticast &);

  std::vector<Ptr<UdpSocketImplMulticast> > m_sockets;      //!< list of sockets
  IpL4ProtocolMulticast::DownTargetCallback m_downTarget;   //!< Callback to send packets over IPv4
  IpL4ProtocolMulticast::DownTargetCallback6 m_downTarget6; //!< Callback to send packets over IPv6

};

} // namespace ns3

#endif /* UDP_L4_PROTOCOL_H_MULTICAST */
