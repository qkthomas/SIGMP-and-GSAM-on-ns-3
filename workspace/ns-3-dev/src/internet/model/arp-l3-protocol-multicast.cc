/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2006 INRIA
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
#include "ns3/packet.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/net-device.h"
#include "ns3/object-vector.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/pointer.h"
#include "ns3/string.h"

#include "ipv4-l3-protocol-multicast.h"
#include "arp-l3-protocol-multicast.h"
#include "arp-header.h"
#include "arp-cache-multicast.h"
#include "ipv4-interface-multicast.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("ArpL3ProtocolMulticast");

const uint16_t ArpL3ProtocolMulticast::PROT_NUMBER = 0x0806;

NS_OBJECT_ENSURE_REGISTERED (ArpL3ProtocolMulticast);

TypeId 
ArpL3ProtocolMulticast::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::ArpL3ProtocolMulticast")
    .SetParent<Object> ()
    .AddConstructor<ArpL3ProtocolMulticast> ()
    .SetGroupName ("Internet")
    .AddAttribute ("CacheList",
                   "The list of ARP caches",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&ArpL3ProtocolMulticast::m_cacheList),
                   MakeObjectVectorChecker<ArpCacheMulticast> ())
    .AddAttribute ("RequestJitter",
                   "The jitter in ms a node is allowed to wait "
                   "before sending an ARP request.  Some jitter aims "
                   "to prevent collisions. By default, the model "
                   "will wait for a duration in ms defined by "
                   "a uniform random-variable between 0 and RequestJitter",
                   StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=10.0]"),
                   MakePointerAccessor (&ArpL3ProtocolMulticast::m_requestJitter),
                   MakePointerChecker<RandomVariableStream> ())
    .AddTraceSource ("Drop",
                     "Packet dropped because not enough room "
                     "in pending queue for a specific cache entry.",
                     MakeTraceSourceAccessor (&ArpL3ProtocolMulticast::m_dropTrace),
                     "ns3::Packet::TracedCallback")
  ;
  return tid;
}

ArpL3ProtocolMulticast::ArpL3ProtocolMulticast ()
{
  NS_LOG_FUNCTION (this);
}

ArpL3ProtocolMulticast::~ArpL3ProtocolMulticast ()
{
  NS_LOG_FUNCTION (this);
}

int64_t
ArpL3ProtocolMulticast::AssignStreams (int64_t stream)
{
  NS_LOG_FUNCTION (this << stream);
  m_requestJitter->SetStream (stream);
  return 1;
}

void 
ArpL3ProtocolMulticast::SetNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION (this << node);
  m_node = node;
}

/*
 * This method is called by AddAgregate and completes the aggregation
 * by setting the node in the ipv4 stack
 */
void
ArpL3ProtocolMulticast::NotifyNewAggregate ()
{
  NS_LOG_FUNCTION (this);
  if (m_node == 0)
    {
      Ptr<Node>node = this->GetObject<Node> ();
      //verify that it's a valid node and that
      //the node was not set before
      if (node != 0)
        {
          this->SetNode (node);
        }
    }
  Object::NotifyNewAggregate ();
}

void 
ArpL3ProtocolMulticast::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  for (CacheList::iterator i = m_cacheList.begin (); i != m_cacheList.end (); ++i)
    {
      Ptr<ArpCacheMulticast> cache = *i;
      cache->Dispose ();
    }
  m_cacheList.clear ();
  m_node = 0;
  Object::DoDispose ();
}

Ptr<ArpCacheMulticast> 
ArpL3ProtocolMulticast::CreateCache (Ptr<NetDevice> device, Ptr<Ipv4InterfaceMulticast> interface)
{
  NS_LOG_FUNCTION (this << device << interface);
  Ptr<Ipv4L3ProtocolMulticast> ipv4 = m_node->GetObject<Ipv4L3ProtocolMulticast> ();
  Ptr<ArpCacheMulticast> cache = CreateObject<ArpCacheMulticast> ();
  cache->SetDevice (device, interface);
  NS_ASSERT (device->IsBroadcast ());
  device->AddLinkChangeCallback (MakeCallback (&ArpCacheMulticast::Flush, cache));
  cache->SetArpRequestCallback (MakeCallback (&ArpL3ProtocolMulticast::SendArpRequest, this));
  m_cacheList.push_back (cache);
  return cache;
}

Ptr<ArpCacheMulticast>
ArpL3ProtocolMulticast::FindCache (Ptr<NetDevice> device)
{
  NS_LOG_FUNCTION (this << device);
  for (CacheList::const_iterator i = m_cacheList.begin (); i != m_cacheList.end (); i++)
    {
      if ((*i)->GetDevice () == device)
        {
          return *i;
        }
    }
  NS_ASSERT (false);
  // quiet compiler
  return 0;
}

void 
ArpL3ProtocolMulticast::Receive (Ptr<NetDevice> device, Ptr<const Packet> p, uint16_t protocol, const Address &from,
                        const Address &to, NetDevice::PacketType packetType)
{
  NS_LOG_FUNCTION (this << device << p->GetSize () << protocol << from << to << packetType);

  Ptr<Packet> packet = p->Copy ();

  NS_LOG_LOGIC ("ARP: received packet of size "<< packet->GetSize ());

  Ptr<ArpCacheMulticast> cache = FindCache (device);

  // 
  // If we're connected to a real world network, then some of the fields sizes 
  // in an ARP packet can vary in ways not seen in simulations.  We need to be
  // able to detect ARP packets with headers we don't recongnize and not process
  // them instead of crashing.  The ArpHeader will return 0 if it can't deal
  // with the received header.
  //
  ArpHeader arp;
  uint32_t size = packet->RemoveHeader (arp);
  if (size == 0)
    {
      NS_LOG_LOGIC ("ARP: Cannot remove ARP header");
      return;
    }
  NS_LOG_LOGIC ("ARP: received "<< (arp.IsRequest () ? "request" : "reply") <<
                " node="<<m_node->GetId ()<<", got request from " <<
                arp.GetSourceIpv4Address () << " for address " <<
                arp.GetDestinationIpv4Address () << "; we have addresses: ");
  for (uint32_t i = 0; i < cache->GetInterface ()->GetNAddresses (); i++)
    {
      NS_LOG_LOGIC (cache->GetInterface ()->GetAddress (i).GetLocal () << ", ");
    }

  /**
   * \internal
   * Note: we do not update the ARP cache when we receive an ARP request
   *  from an unknown node. See \bugid{107}
   */
  bool found = false;
  for (uint32_t i = 0; i < cache->GetInterface ()->GetNAddresses (); i++)
    {
      if (arp.IsRequest () && arp.GetDestinationIpv4Address () == 
          cache->GetInterface ()->GetAddress (i).GetLocal ())
        {
          found = true;
          NS_LOG_LOGIC ("node="<<m_node->GetId () <<", got request from " << 
                        arp.GetSourceIpv4Address () << " -- send reply");
          SendArpReply (cache, arp.GetDestinationIpv4Address (), arp.GetSourceIpv4Address (),
                        arp.GetSourceHardwareAddress ());
          break;
        } 
      else if (arp.IsReply () && 
               arp.GetDestinationIpv4Address ().IsEqual (cache->GetInterface ()->GetAddress (i).GetLocal ()) &&
               arp.GetDestinationHardwareAddress () == device->GetAddress ())
        {
          found = true;
          Ipv4Address from = arp.GetSourceIpv4Address ();
          ArpCacheMulticast::Entry *entry = cache->Lookup (from);
          if (entry != 0)
            {
              if (entry->IsWaitReply ()) 
                {
                  NS_LOG_LOGIC ("node="<< m_node->GetId () << 
                                ", got reply from " << arp.GetSourceIpv4Address ()
                                       << " for waiting entry -- flush");
                  Address from_mac = arp.GetSourceHardwareAddress ();
                  entry->MarkAlive (from_mac);
                  Ptr<Packet> pending = entry->DequeuePending ();
                  while (pending != 0)
                    {
                      cache->GetInterface ()->Send (pending,
                                                    arp.GetSourceIpv4Address ());
                      pending = entry->DequeuePending ();
                    }
                } 
              else 
                {
                  // ignore this reply which might well be an attempt 
                  // at poisening my arp cache.
                  NS_LOG_LOGIC ("node="<<m_node->GetId ()<<", got reply from " <<
                                arp.GetSourceIpv4Address () <<
                                " for non-waiting entry -- drop");
                  m_dropTrace (packet);
                }
            } 
          else 
            {
              NS_LOG_LOGIC ("node="<<m_node->GetId ()<<", got reply for unknown entry -- drop");
              m_dropTrace (packet);
            }
          break;
        }
    }
  if (found == false)
    {
      NS_LOG_LOGIC ("node="<<m_node->GetId ()<<", got request from " <<
                    arp.GetSourceIpv4Address () << " for unknown address " <<
                    arp.GetDestinationIpv4Address () << " -- drop");
    }
}

bool 
ArpL3ProtocolMulticast::Lookup (Ptr<Packet> packet, Ipv4Address destination, 
                       Ptr<NetDevice> device,
                       Ptr<ArpCacheMulticast> cache,
                       Address *hardwareDestination)
{
  NS_LOG_FUNCTION (this << packet << destination << device << cache << hardwareDestination);
  ArpCacheMulticast::Entry *entry = cache->Lookup (destination);
  if (entry != 0)
    {
      if (entry->IsExpired ()) 
        {
          if (entry->IsDead ()) 
            {
              NS_LOG_LOGIC ("node="<<m_node->GetId ()<<
                            ", dead entry for " << destination << " expired -- send arp request");
              entry->MarkWaitReply (packet);
              Simulator::Schedule (Time (MilliSeconds (m_requestJitter->GetValue ())), &ArpL3ProtocolMulticast::SendArpRequest, this, cache, destination);
            } 
          else if (entry->IsAlive ()) 
            {
              NS_LOG_LOGIC ("node="<<m_node->GetId ()<<
                            ", alive entry for " << destination << " expired -- send arp request");
              entry->MarkWaitReply (packet);
              Simulator::Schedule (Time (MilliSeconds (m_requestJitter->GetValue ())), &ArpL3ProtocolMulticast::SendArpRequest, this, cache, destination);
            } 
          else
            {
              NS_FATAL_ERROR ("Test for possibly unreachable code-- please file a bug report, with a test case, if this is ever hit");
            }
        } 
      else 
        {
          if (entry->IsDead ()) 
            {
              NS_LOG_LOGIC ("node="<<m_node->GetId ()<<
                            ", dead entry for " << destination << " valid -- drop");
              m_dropTrace (packet);
            } 
          else if (entry->IsAlive ()) 
            {
              NS_LOG_LOGIC ("node="<<m_node->GetId ()<<
                            ", alive entry for " << destination << " valid -- send");
              *hardwareDestination = entry->GetMacAddress ();
              return true;
            } 
          else if (entry->IsWaitReply ()) 
            {
              NS_LOG_LOGIC ("node="<<m_node->GetId ()<<
                            ", wait reply for " << destination << " valid -- drop previous");
              if (!entry->UpdateWaitReply (packet))
                {
                  m_dropTrace (packet);
                }
            }
          else if (entry-> IsPermanent ())
            {
              NS_LOG_LOGIC ("node="<<m_node->GetId ()<<
                            ", permanent for " << destination << "valid -- send");
              *hardwareDestination = entry->GetMacAddress ();
              return true;
            }
          else
            {
              NS_LOG_LOGIC ("Test for possibly unreachable code-- please file a bug report, with a test case, if this is ever hit");
            }
        }
    }
  else
    {
      // This is our first attempt to transmit data to this destination.
      NS_LOG_LOGIC ("node="<<m_node->GetId ()<<
                    ", no entry for " << destination << " -- send arp request");
      entry = cache->Add (destination);
      entry->MarkWaitReply (packet);
      Simulator::Schedule (Time (MilliSeconds (m_requestJitter->GetValue ())), &ArpL3ProtocolMulticast::SendArpRequest, this, cache, destination);
    }
  return false;
}

void
ArpL3ProtocolMulticast::SendArpRequest (Ptr<const ArpCacheMulticast> cache, Ipv4Address to)
{
  NS_LOG_FUNCTION (this << cache << to);
  ArpHeader arp;
  // need to pick a source address; use routing implementation to select
  Ptr<Ipv4L3ProtocolMulticast> ipv4 = m_node->GetObject<Ipv4L3ProtocolMulticast> ();
  Ptr<NetDevice> device = cache->GetDevice ();
  NS_ASSERT (device != 0);
  Ipv4Header header;
  header.SetDestination (to);
  Ptr<Packet> packet = Create<Packet> ();
  Ipv4Address source = ipv4->SelectSourceAddress (device,  to, Ipv4InterfaceAddress::GLOBAL);
  NS_LOG_LOGIC ("ARP: sending request from node "<<m_node->GetId ()<<
                " || src: " << device->GetAddress () << " / " << source <<
                " || dst: " << device->GetBroadcast () << " / " << to);
  arp.SetRequest (device->GetAddress (), source, device->GetBroadcast (), to);
  packet->AddHeader (arp);
  cache->GetDevice ()->Send (packet, device->GetBroadcast (), PROT_NUMBER);
}

void
ArpL3ProtocolMulticast::SendArpReply (Ptr<const ArpCacheMulticast> cache, Ipv4Address myIp, Ipv4Address toIp, Address toMac)
{
  NS_LOG_FUNCTION (this << cache << myIp << toIp << toMac);
  ArpHeader arp;
  NS_LOG_LOGIC ("ARP: sending reply from node "<<m_node->GetId ()<<
                "|| src: " << cache->GetDevice ()->GetAddress () <<
                " / " << myIp <<
                " || dst: " << toMac << " / " << toIp);
  arp.SetReply (cache->GetDevice ()->GetAddress (), myIp, toMac, toIp);
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (arp);
  cache->GetDevice ()->Send (packet, toMac, PROT_NUMBER);
}

} // namespace ns3
