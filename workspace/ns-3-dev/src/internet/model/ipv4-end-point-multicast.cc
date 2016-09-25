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

#include "ipv4-end-point-multicast.h"
#include "ns3/packet.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("Ipv4EndPointMulticast");

Ipv4EndPointMulticast::Ipv4EndPointMulticast (Ipv4Address address, uint16_t port)
  : m_localAddr (address), 
    m_localPort (port),
    m_peerAddr (Ipv4Address::GetAny ()),
    m_peerPort (0),
    m_rxEnabled (true)
{
  NS_LOG_FUNCTION (this << address << port);
}

Ipv4EndPointMulticast::~Ipv4EndPointMulticast ()
{
  NS_LOG_FUNCTION (this);
  if (!m_destroyCallback.IsNull ())
    {
      m_destroyCallback ();
    }
  m_rxCallback.Nullify ();
  m_icmpCallback.Nullify ();
  m_destroyCallback.Nullify ();
}

Ipv4Address 
Ipv4EndPointMulticast::GetLocalAddress (void)
{
  NS_LOG_FUNCTION (this);
  return m_localAddr;
}

void 
Ipv4EndPointMulticast::SetLocalAddress (Ipv4Address address)
{
  NS_LOG_FUNCTION (this << address);
  m_localAddr = address;
}

uint16_t 
Ipv4EndPointMulticast::GetLocalPort (void)
{
  NS_LOG_FUNCTION (this);
  return m_localPort;
}

Ipv4Address 
Ipv4EndPointMulticast::GetPeerAddress (void)
{
  NS_LOG_FUNCTION (this);
  return m_peerAddr;
}

uint16_t 
Ipv4EndPointMulticast::GetPeerPort (void)
{
  NS_LOG_FUNCTION (this);
  return m_peerPort;
}

void 
Ipv4EndPointMulticast::SetPeer (Ipv4Address address, uint16_t port)
{
  NS_LOG_FUNCTION (this << address << port);
  m_peerAddr = address;
  m_peerPort = port;
}

void
Ipv4EndPointMulticast::BindToNetDevice (Ptr<NetDevice> netdevice)
{
  NS_LOG_FUNCTION (this << netdevice);
  m_boundnetdevice = netdevice;
  return;
}

Ptr<NetDevice> 
Ipv4EndPointMulticast::GetBoundNetDevice (void)
{
  NS_LOG_FUNCTION (this);
  return m_boundnetdevice;
}

void 
Ipv4EndPointMulticast::SetRxCallback (Callback<void,Ptr<Packet>, Ipv4Header, uint16_t, Ptr<Ipv4InterfaceMulticast> > callback)
{
  NS_LOG_FUNCTION (this << &callback);
  m_rxCallback = callback;
}

void 
Ipv4EndPointMulticast::SetIcmpCallback (Callback<void,Ipv4Address,uint8_t,uint8_t,uint8_t,uint32_t> callback)
{
  NS_LOG_FUNCTION (this << &callback);
  m_icmpCallback = callback;
}

void 
Ipv4EndPointMulticast::SetDestroyCallback (Callback<void> callback)
{
  NS_LOG_FUNCTION (this << &callback);
  m_destroyCallback = callback;
}

void 
Ipv4EndPointMulticast::ForwardUp (Ptr<Packet> p, const Ipv4Header& header, uint16_t sport,
                         Ptr<Ipv4InterfaceMulticast> incomingInterface)
{
  NS_LOG_FUNCTION (this << p << &header << sport << incomingInterface);
  
  if (!m_rxCallback.IsNull ())
    {
      m_rxCallback (p, header, sport, incomingInterface);
    }
}

void 
Ipv4EndPointMulticast::ForwardIcmp (Ipv4Address icmpSource, uint8_t icmpTtl, 
                           uint8_t icmpType, uint8_t icmpCode,
                           uint32_t icmpInfo)
{
  NS_LOG_FUNCTION (this << icmpSource << (uint32_t)icmpTtl << (uint32_t)icmpType <<
                   (uint32_t)icmpCode << icmpInfo);
  if (!m_icmpCallback.IsNull ())
    {
      m_icmpCallback (icmpSource, icmpTtl, icmpType, icmpCode, icmpInfo);
    }
}

void
Ipv4EndPointMulticast::SetRxEnabled (bool enabled)
{
  m_rxEnabled = enabled;
}

bool
Ipv4EndPointMulticast::IsRxEnabled ()
{
  return m_rxEnabled;
}

} // namespace ns3
