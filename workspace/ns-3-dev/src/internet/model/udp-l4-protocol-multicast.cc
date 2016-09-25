/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2005 INRIA
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

#include "ns3/log.h"
#include "ns3/assert.h"
#include "ns3/packet.h"
#include "ns3/node.h"
#include "ns3/boolean.h"
#include "ns3/object-vector.h"
#include "ns3/ipv6.h"
#include "ns3/ipv4-route.h"
#include "ns3/ipv6-route.h"
#include "ns3/ipv6-header.h"

#include "udp-l4-protocol-multicast.h"
#include "udp-header.h"
#include "udp-socket-factory-impl-multicast.h"
#include "ipv4-end-point-demux-multicast.h"
#include "ipv4-end-point-multicast.h"
#include "ipv6-end-point-demux.h"
#include "ipv6-end-point.h"
#include "ipv4-l3-protocol-multicast.h"
#include "ipv6-l3-protocol.h"
#include "udp-socket-impl-multicast.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("UdpL4ProtocolMulticast");

NS_OBJECT_ENSURE_REGISTERED (UdpL4ProtocolMulticast);

/* see http://www.iana.org/assignments/protocol-numbers */
const uint8_t UdpL4ProtocolMulticast::PROT_NUMBER = 17;

TypeId 
UdpL4ProtocolMulticast::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::UdpL4ProtocolMulticast")
    .SetParent<IpL4ProtocolMulticast> ()
    .SetGroupName ("Internet")
    .AddConstructor<UdpL4ProtocolMulticast> ()
    .AddAttribute ("SocketList", "The list of sockets associated to this protocol.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&UdpL4ProtocolMulticast::m_sockets),
                   MakeObjectVectorChecker<UdpSocketImplMulticast> ())
  ;
  return tid;
}

UdpL4ProtocolMulticast::UdpL4ProtocolMulticast ()
  : m_endPoints (new Ipv4EndPointDemuxMulticast ()), m_endPoints6 (new Ipv6EndPointDemux ())
{
  NS_LOG_FUNCTION_NOARGS ();
}

UdpL4ProtocolMulticast::~UdpL4ProtocolMulticast ()
{
  NS_LOG_FUNCTION_NOARGS ();
}

void 
UdpL4ProtocolMulticast::SetNode (Ptr<Node> node)
{
  m_node = node;
}

/*
 * This method is called by AddAgregate and completes the aggregation
 * by setting the node in the udp stack and link it to the ipv4 object
 * present in the node along with the socket factory
 */
void
UdpL4ProtocolMulticast::NotifyNewAggregate ()
{
  NS_LOG_FUNCTION (this);
  Ptr<Node> node = this->GetObject<Node> ();
  Ptr<Ipv4Multicast> ipv4 = this->GetObject<Ipv4Multicast> ();
  //Ptr<Ipv6> ipv6 = node->GetObject<Ipv6> ();

  if (m_node == 0)
    {
      if ((node != 0) && (ipv4 != 0))
        {
          this->SetNode (node);
          Ptr<UdpSocketFactoryImplMulticast> udpFactory = CreateObject<UdpSocketFactoryImplMulticast> ();
          udpFactory->SetUdp (this);
          node->AggregateObject (udpFactory);
        }
    }
  
  // We set at least one of our 2 down targets to the IPv4/IPv6 send
  // functions.  Since these functions have different prototypes, we
  // need to keep track of whether we are connected to an IPv4 or
  // IPv6 lower layer and call the appropriate one.
  
  if (ipv4 != 0 && m_downTarget.IsNull())
    {
      ipv4->Insert (this);
      this->SetDownTarget (MakeCallback (&Ipv4Multicast::Send, ipv4));
    }
//  if (ipv6 != 0 && m_downTarget6.IsNull())
//    {
//      ipv6->Insert (this);
//      this->SetDownTarget6 (MakeCallback (&Ipv6::Send, ipv6));
//    }
  IpL4ProtocolMulticast::NotifyNewAggregate ();
}

int 
UdpL4ProtocolMulticast::GetProtocolNumber (void) const
{
  return PROT_NUMBER;
}


void
UdpL4ProtocolMulticast::DoDispose (void)
{
  NS_LOG_FUNCTION_NOARGS ();
  for (std::vector<Ptr<UdpSocketImplMulticast> >::iterator i = m_sockets.begin (); i != m_sockets.end (); i++)
    {
      *i = 0;
    }
  m_sockets.clear ();

  if (m_endPoints != 0)
    {
      delete m_endPoints;
      m_endPoints = 0;
    }
  if (m_endPoints6 != 0)
    {
      delete m_endPoints6;
      m_endPoints6 = 0;
    }
  m_node = 0;
  m_downTarget.Nullify ();
  m_downTarget6.Nullify ();
/*
 = MakeNullCallback<void,Ptr<Packet>, Ipv4Address, Ipv4Address, uint8_t, Ptr<Ipv4Route> > ();
*/
  IpL4ProtocolMulticast::DoDispose ();
}

Ptr<Socket>
UdpL4ProtocolMulticast::CreateSocket (void)
{
  NS_LOG_FUNCTION_NOARGS ();
  Ptr<UdpSocketImplMulticast> socket = CreateObject<UdpSocketImplMulticast> ();
  socket->SetNode (m_node);
  socket->SetUdp (this);
  m_sockets.push_back (socket);
  return socket;
}

Ipv4EndPointMulticast *
UdpL4ProtocolMulticast::Allocate (void)
{
  NS_LOG_FUNCTION_NOARGS ();
  return m_endPoints->Allocate ();
}

Ipv4EndPointMulticast *
UdpL4ProtocolMulticast::Allocate (Ipv4Address address)
{
  NS_LOG_FUNCTION (this << address);
  return m_endPoints->Allocate (address);
}

Ipv4EndPointMulticast *
UdpL4ProtocolMulticast::Allocate (uint16_t port)
{
  NS_LOG_FUNCTION (this << port);
  return m_endPoints->Allocate (port);
}

Ipv4EndPointMulticast *
UdpL4ProtocolMulticast::Allocate (Ipv4Address address, uint16_t port)
{
  NS_LOG_FUNCTION (this << address << port);
  return m_endPoints->Allocate (address, port);
}
Ipv4EndPointMulticast *
UdpL4ProtocolMulticast::Allocate (Ipv4Address localAddress, uint16_t localPort,
                         Ipv4Address peerAddress, uint16_t peerPort)
{
  NS_LOG_FUNCTION (this << localAddress << localPort << peerAddress << peerPort);
  return m_endPoints->Allocate (localAddress, localPort,
                                peerAddress, peerPort);
}

void 
UdpL4ProtocolMulticast::DeAllocate (Ipv4EndPointMulticast *endPoint)
{
  NS_LOG_FUNCTION (this << endPoint);
  m_endPoints->DeAllocate (endPoint);
}

Ipv6EndPoint *
UdpL4ProtocolMulticast::Allocate6 (void)
{
  NS_LOG_FUNCTION_NOARGS ();
  return m_endPoints6->Allocate ();
}

Ipv6EndPoint *
UdpL4ProtocolMulticast::Allocate6 (Ipv6Address address)
{
  NS_LOG_FUNCTION (this << address);
  return m_endPoints6->Allocate (address);
}

Ipv6EndPoint *
UdpL4ProtocolMulticast::Allocate6 (uint16_t port)
{
  NS_LOG_FUNCTION (this << port);
  return m_endPoints6->Allocate (port);
}

Ipv6EndPoint *
UdpL4ProtocolMulticast::Allocate6 (Ipv6Address address, uint16_t port)
{
  NS_LOG_FUNCTION (this << address << port);
  return m_endPoints6->Allocate (address, port);
}
Ipv6EndPoint *
UdpL4ProtocolMulticast::Allocate6 (Ipv6Address localAddress, uint16_t localPort,
                         Ipv6Address peerAddress, uint16_t peerPort)
{
  NS_LOG_FUNCTION (this << localAddress << localPort << peerAddress << peerPort);
  return m_endPoints6->Allocate (localAddress, localPort,
                                peerAddress, peerPort);
}

void 
UdpL4ProtocolMulticast::DeAllocate (Ipv6EndPoint *endPoint)
{
  NS_LOG_FUNCTION (this << endPoint);
  m_endPoints6->DeAllocate (endPoint);
}

void 
UdpL4ProtocolMulticast::ReceiveIcmp (Ipv4Address icmpSource, uint8_t icmpTtl,
                            uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo,
                            Ipv4Address payloadSource,Ipv4Address payloadDestination,
                            const uint8_t payload[8])
{
  NS_LOG_FUNCTION (this << icmpSource << icmpTtl << icmpType << icmpCode << icmpInfo 
                        << payloadSource << payloadDestination);
  uint16_t src, dst;
  src = payload[0] << 8;
  src |= payload[1];
  dst = payload[2] << 8;
  dst |= payload[3];

  Ipv4EndPointMulticast *endPoint = m_endPoints->SimpleLookup (payloadSource, src, payloadDestination, dst);
  if (endPoint != 0)
    {
      endPoint->ForwardIcmp (icmpSource, icmpTtl, icmpType, icmpCode, icmpInfo);
    }
  else
    {
      NS_LOG_DEBUG ("no endpoint found source=" << payloadSource <<
                    ", destination="<<payloadDestination<<
                    ", src=" << src << ", dst=" << dst);
    }
}

void 
UdpL4ProtocolMulticast::ReceiveIcmp (Ipv6Address icmpSource, uint8_t icmpTtl,
                            uint8_t icmpType, uint8_t icmpCode, uint32_t icmpInfo,
                            Ipv6Address payloadSource,Ipv6Address payloadDestination,
                            const uint8_t payload[8])
{
  NS_LOG_FUNCTION (this << icmpSource << icmpTtl << icmpType << icmpCode << icmpInfo 
                        << payloadSource << payloadDestination);
  uint16_t src, dst;
  src = payload[0] << 8;
  src |= payload[1];
  dst = payload[2] << 8;
  dst |= payload[3];

  Ipv6EndPoint *endPoint = m_endPoints6->SimpleLookup (payloadSource, src, payloadDestination, dst);
  if (endPoint != 0)
    {
      endPoint->ForwardIcmp (icmpSource, icmpTtl, icmpType, icmpCode, icmpInfo);
    }
  else
    {
      NS_LOG_DEBUG ("no endpoint found source=" << payloadSource <<
                    ", destination="<<payloadDestination<<
                    ", src=" << src << ", dst=" << dst);
    }
}

enum IpL4ProtocolMulticast::RxStatus
UdpL4ProtocolMulticast::Receive (Ptr<Packet> packet,
                        Ipv4Header const &header,
                        Ptr<Ipv4InterfaceMulticast> interface)
{
  NS_LOG_FUNCTION (this << packet << header);
  UdpHeader udpHeader;
  if(Node::ChecksumEnabled ())
    {
      udpHeader.EnableChecksums ();
    }

  udpHeader.InitializeChecksum (header.GetSource (), header.GetDestination (), PROT_NUMBER);

  // We only peek at the header for now (instead of removing it) so that it will be intact
  // if we have to pass it to a IPv6 endpoint via:
  // 
  //   UdpL4ProtocolMulticast::Receive (Ptr<Packet> packet, Ipv6Address &src, Ipv6Address &dst, ...)

  packet->PeekHeader (udpHeader);

  if(!udpHeader.IsChecksumOk ())
    {
      NS_LOG_INFO ("Bad checksum : dropping packet!");
      return IpL4ProtocolMulticast::RX_CSUM_FAILED;
    }

  NS_LOG_DEBUG ("Looking up dst " << header.GetDestination () << " port " << udpHeader.GetDestinationPort ()); 
  Ipv4EndPointDemuxMulticast::EndPoints endPoints =
    m_endPoints->Lookup (header.GetDestination (), udpHeader.GetDestinationPort (),
                         header.GetSource (), udpHeader.GetSourcePort (), interface);
  if (endPoints.empty ())
    {
      if (this->GetObject<Ipv6L3Protocol> () != 0)
        {
          NS_LOG_LOGIC ("  No Ipv4Multicast endpoints matched on UdpL4ProtocolMulticast, trying Ipv6 "<<this);
          Ptr<Ipv6Interface> fakeInterface;
          Ipv6Header ipv6Header;
          Ipv6Address src = Ipv6Address::MakeIpv4MappedAddress (header.GetSource ());
          Ipv6Address dst = Ipv6Address::MakeIpv4MappedAddress (header.GetDestination ());
          ipv6Header.SetSourceAddress (src);
          ipv6Header.SetDestinationAddress (dst);
          return (this->Receive (packet, ipv6Header, fakeInterface));
        }

      NS_LOG_LOGIC ("RX_ENDPOINT_UNREACH");
      return IpL4ProtocolMulticast::RX_ENDPOINT_UNREACH;
    }

  packet->RemoveHeader(udpHeader);
  for (Ipv4EndPointDemuxMulticast::EndPointsI endPoint = endPoints.begin ();
       endPoint != endPoints.end (); endPoint++)
    {
      (*endPoint)->ForwardUp (packet->Copy (), header, udpHeader.GetSourcePort (), 
                              interface);
    }
  return IpL4ProtocolMulticast::RX_OK;
}

enum IpL4ProtocolMulticast::RxStatus
UdpL4ProtocolMulticast::Receive (Ptr<Packet> packet,
                        Ipv6Header const &header,
                        Ptr<Ipv6Interface> interface)
{
  NS_LOG_FUNCTION (this << packet << header.GetSourceAddress () << header.GetDestinationAddress ());
  UdpHeader udpHeader;
  if(Node::ChecksumEnabled ())
    {
      udpHeader.EnableChecksums ();
    }

  udpHeader.InitializeChecksum (header.GetSourceAddress (), header.GetDestinationAddress (), PROT_NUMBER);

  packet->RemoveHeader (udpHeader);

  if(!udpHeader.IsChecksumOk () && !header.GetSourceAddress ().IsIpv4MappedAddress ())
    {
      NS_LOG_INFO ("Bad checksum : dropping packet!");
      return IpL4ProtocolMulticast::RX_CSUM_FAILED;
    }

  NS_LOG_DEBUG ("Looking up dst " << header.GetDestinationAddress () << " port " << udpHeader.GetDestinationPort ()); 
  Ipv6EndPointDemux::EndPoints endPoints =
    m_endPoints6->Lookup (header.GetDestinationAddress (), udpHeader.GetDestinationPort (),
                         header.GetSourceAddress (), udpHeader.GetSourcePort (), interface);
  if (endPoints.empty ())
    {
      NS_LOG_LOGIC ("RX_ENDPOINT_UNREACH");
      return IpL4ProtocolMulticast::RX_ENDPOINT_UNREACH;
    }
  for (Ipv6EndPointDemux::EndPointsI endPoint = endPoints.begin ();
       endPoint != endPoints.end (); endPoint++)
    {
      (*endPoint)->ForwardUp (packet->Copy (), header, udpHeader.GetSourcePort (), interface);
    }
  return IpL4ProtocolMulticast::RX_OK;
}

void
UdpL4ProtocolMulticast::Send (Ptr<Packet> packet, 
                     Ipv4Address saddr, Ipv4Address daddr, 
                     uint16_t sport, uint16_t dport)
{
  NS_LOG_FUNCTION (this << packet << saddr << daddr << sport << dport);

  UdpHeader udpHeader;
  if(Node::ChecksumEnabled ())
    {
      udpHeader.EnableChecksums ();
      udpHeader.InitializeChecksum (saddr,
                                    daddr,
                                    PROT_NUMBER);
    }
  udpHeader.SetDestinationPort (dport);
  udpHeader.SetSourcePort (sport);

  packet->AddHeader (udpHeader);

  m_downTarget (packet, saddr, daddr, PROT_NUMBER, 0);
}

void
UdpL4ProtocolMulticast::Send (Ptr<Packet> packet, 
                     Ipv4Address saddr, Ipv4Address daddr, 
                     uint16_t sport, uint16_t dport, Ptr<Ipv4Route> route)
{
  NS_LOG_FUNCTION (this << packet << saddr << daddr << sport << dport << route);

  UdpHeader udpHeader;
  if(Node::ChecksumEnabled ())
    {
      udpHeader.EnableChecksums ();
      udpHeader.InitializeChecksum (saddr,
                                    daddr,
                                    PROT_NUMBER);
    }
  udpHeader.SetDestinationPort (dport);
  udpHeader.SetSourcePort (sport);

  packet->AddHeader (udpHeader);

  m_downTarget (packet, saddr, daddr, PROT_NUMBER, route);
}

void
UdpL4ProtocolMulticast::Send (Ptr<Packet> packet,
                     Ipv6Address saddr, Ipv6Address daddr,
                     uint16_t sport, uint16_t dport)
{
  NS_LOG_FUNCTION (this << packet << saddr << daddr << sport << dport);

  UdpHeader udpHeader;
  if(Node::ChecksumEnabled ())
    {
      udpHeader.EnableChecksums ();
      udpHeader.InitializeChecksum (saddr,
                                    daddr,
                                    PROT_NUMBER);
    }
  udpHeader.SetDestinationPort (dport);
  udpHeader.SetSourcePort (sport);

  packet->AddHeader (udpHeader);

  m_downTarget6 (packet, saddr, daddr, PROT_NUMBER, 0);
}

void
UdpL4ProtocolMulticast::Send (Ptr<Packet> packet,
                     Ipv6Address saddr, Ipv6Address daddr,
                     uint16_t sport, uint16_t dport, Ptr<Ipv6Route> route)
{
  NS_LOG_FUNCTION (this << packet << saddr << daddr << sport << dport << route);

  UdpHeader udpHeader;
  if(Node::ChecksumEnabled ())
    {
      udpHeader.EnableChecksums ();
      udpHeader.InitializeChecksum (saddr,
                                    daddr,
                                    PROT_NUMBER);
    }
  udpHeader.SetDestinationPort (dport);
  udpHeader.SetSourcePort (sport);

  packet->AddHeader (udpHeader);

  m_downTarget6 (packet, saddr, daddr, PROT_NUMBER, route);
}

void
UdpL4ProtocolMulticast::SetDownTarget (IpL4ProtocolMulticast::DownTargetCallback callback)
{
  NS_LOG_FUNCTION (this);
  m_downTarget = callback;
}

IpL4ProtocolMulticast::DownTargetCallback
UdpL4ProtocolMulticast::GetDownTarget (void) const
{
  return m_downTarget;
}

void
UdpL4ProtocolMulticast::SetDownTarget6 (IpL4ProtocolMulticast::DownTargetCallback6 callback)
{
  NS_LOG_FUNCTION (this);
  m_downTarget6 = callback;
}

IpL4ProtocolMulticast::DownTargetCallback6
UdpL4ProtocolMulticast::GetDownTarget6 (void) const
{
  return m_downTarget6;
}

} // namespace ns3

