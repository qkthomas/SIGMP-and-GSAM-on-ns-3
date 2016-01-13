/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 University of Washington
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

#include <stdint.h>
#include <string>
#include <fstream>

#include "ns3/abort.h"
#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/ptr.h"
#include "ns3/node.h"
#include "ns3/names.h"
#include "ns3/net-device.h"
#include "ns3/pcap-file-wrapper.h"

#include "internet-trace-helper-multicast.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("InternetTraceHelperMulticast");

void 
PcapHelperForIpv4Multicast::EnablePcapIpv4 (std::string prefix, Ptr<Ipv4Multicast> ipv4, uint32_t interface, bool explicitFilename)
{
  EnablePcapIpv4Internal (prefix, ipv4, interface, explicitFilename);
}

void 
PcapHelperForIpv4Multicast::EnablePcapIpv4 (std::string prefix, std::string ipv4Name, uint32_t interface, bool explicitFilename)
{
  Ptr<Ipv4Multicast> ipv4 = Names::Find<Ipv4Multicast> (ipv4Name);
  EnablePcapIpv4 (prefix, ipv4, interface, explicitFilename);
}

void 
PcapHelperForIpv4Multicast::EnablePcapIpv4 (std::string prefix, Ipv4InterfaceContainerMulticast c)
{
  for (Ipv4InterfaceContainerMulticast::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      std::pair<Ptr<Ipv4Multicast>, uint32_t> pair = *i;
      EnablePcapIpv4 (prefix, pair.first, pair.second, false);
    }
}

void
PcapHelperForIpv4Multicast::EnablePcapIpv4 (std::string prefix, NodeContainer n)
{
  for (NodeContainer::Iterator i = n.Begin (); i != n.End (); ++i)
    {
      Ptr<Node> node = *i;
      Ptr<Ipv4Multicast> ipv4 = node->GetObject<Ipv4Multicast> ();
      if (ipv4)
        {
          for (uint32_t j = 0; j < ipv4->GetNInterfaces (); ++j)
            {
              EnablePcapIpv4 (prefix, ipv4, j, false);
            }
        }
    }
}

void
PcapHelperForIpv4Multicast::EnablePcapIpv4All (std::string prefix)
{
  EnablePcapIpv4 (prefix, NodeContainer::GetGlobal ());
}

void 
PcapHelperForIpv4Multicast::EnablePcapIpv4 (std::string prefix, uint32_t nodeid, uint32_t interface, bool explicitFilename)
{
  NodeContainer n = NodeContainer::GetGlobal ();

  for (NodeContainer::Iterator i = n.Begin (); i != n.End (); ++i)
    {
      Ptr<Node> node = *i;
      if (node->GetId () != nodeid) 
        {
          continue;
        }

      Ptr<Ipv4Multicast> ipv4 = node->GetObject<Ipv4Multicast> ();
      if (ipv4)
        {
          EnablePcapIpv4 (prefix, ipv4, interface, explicitFilename);
        }
      return;
    }
}

//
// Public API
//
void 
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4 (std::string prefix, Ptr<Ipv4Multicast> ipv4, uint32_t interface, bool explicitFilename)
{
  EnableAsciiIpv4Internal (Ptr<OutputStreamWrapper> (), prefix, ipv4, interface, explicitFilename);
}

//
// Public API
//
void 
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4 (Ptr<OutputStreamWrapper> stream, Ptr<Ipv4Multicast> ipv4, uint32_t interface)
{
  EnableAsciiIpv4Internal (stream, std::string (), ipv4, interface, false);
}

//
// Public API
//
void 
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4 (
  std::string prefix, 
  std::string ipv4Name, 
  uint32_t interface,
  bool explicitFilename)
{
  EnableAsciiIpv4Impl (Ptr<OutputStreamWrapper> (), prefix, ipv4Name, interface, explicitFilename);
}

//
// Public API
//
void 
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4 (Ptr<OutputStreamWrapper> stream, std::string ipv4Name, uint32_t interface)
{
  EnableAsciiIpv4Impl (stream, std::string (), ipv4Name, interface, false);
}

//
// Private API
//
void 
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4Impl (
  Ptr<OutputStreamWrapper> stream, 
  std::string prefix, 
  std::string ipv4Name, 
  uint32_t interface,
  bool explicitFilename)
{
  Ptr<Ipv4Multicast> ipv4 = Names::Find<Ipv4Multicast> (ipv4Name);
  EnableAsciiIpv4Internal (stream, prefix, ipv4, interface, explicitFilename);
}

//
// Public API
//
void 
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4 (std::string prefix, Ipv4InterfaceContainerMulticast c)
{
  EnableAsciiIpv4Impl (Ptr<OutputStreamWrapper> (), prefix, c);
}

//
// Public API
//
void 
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4 (Ptr<OutputStreamWrapper> stream, Ipv4InterfaceContainerMulticast c)
{
  EnableAsciiIpv4Impl (stream, std::string (), c);
}

//
// Private API
//
void 
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4Impl (Ptr<OutputStreamWrapper> stream, std::string prefix, Ipv4InterfaceContainerMulticast c)
{
  for (Ipv4InterfaceContainerMulticast::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      std::pair<Ptr<Ipv4Multicast>, uint32_t> pair = *i;
      EnableAsciiIpv4Internal (stream, prefix, pair.first, pair.second, false);
    }
}

//
// Public API
//
void
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4 (std::string prefix, NodeContainer n)
{
  EnableAsciiIpv4Impl (Ptr<OutputStreamWrapper> (), prefix, n);
}

//
// Public API
//
void
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4 (Ptr<OutputStreamWrapper> stream, NodeContainer n)
{
  EnableAsciiIpv4Impl (stream, std::string (), n);
}

//
// Private API
//
void
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4Impl (Ptr<OutputStreamWrapper> stream, std::string prefix, NodeContainer n)
{
  for (NodeContainer::Iterator i = n.Begin (); i != n.End (); ++i)
    {
      Ptr<Node> node = *i;
      Ptr<Ipv4Multicast> ipv4 = node->GetObject<Ipv4Multicast> ();
      if (ipv4)
        {
          for (uint32_t j = 0; j < ipv4->GetNInterfaces (); ++j)
            {
              EnableAsciiIpv4Internal (stream, prefix, ipv4, j, false);
            }
        }
    }
}

//
// Public API
//
void
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4All (std::string prefix)
{
  EnableAsciiIpv4Impl (Ptr<OutputStreamWrapper> (), prefix, NodeContainer::GetGlobal ());
}

//
// Public API
//
void
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4All (Ptr<OutputStreamWrapper> stream)
{
  EnableAsciiIpv4Impl (stream, std::string (), NodeContainer::GetGlobal ());
}

//
// Public API
//
void 
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4 (
  Ptr<OutputStreamWrapper> stream, 
  uint32_t nodeid, 
  uint32_t interface,
  bool explicitFilename)
{
  EnableAsciiIpv4Impl (stream, std::string (), nodeid, interface, explicitFilename);
}

//
// Public API
//
void 
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4 (std::string prefix, uint32_t nodeid, uint32_t interface, bool explicitFilename)
{
  EnableAsciiIpv4Impl (Ptr<OutputStreamWrapper> (), prefix, nodeid, interface, explicitFilename);
}

//
// Private API
//
void 
AsciiTraceHelperForIpv4Multicast::EnableAsciiIpv4Impl (
  Ptr<OutputStreamWrapper> stream, 
  std::string prefix, 
  uint32_t nodeid, 
  uint32_t interface,
  bool explicitFilename)
{
  NodeContainer n = NodeContainer::GetGlobal ();

  for (NodeContainer::Iterator i = n.Begin (); i != n.End (); ++i)
    {
      Ptr<Node> node = *i;
      if (node->GetId () != nodeid) 
        {
          continue;
        }

      Ptr<Ipv4Multicast> ipv4 = node->GetObject<Ipv4Multicast> ();
      if (ipv4)
        {
          EnableAsciiIpv4Internal (stream, prefix, ipv4, interface, explicitFilename);
        }

      return;
    }
}

} // namespace ns3

