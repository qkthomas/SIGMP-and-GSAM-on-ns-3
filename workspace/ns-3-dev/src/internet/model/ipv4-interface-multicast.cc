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

#include "ipv4-interface-multicast.h"
#include "loopback-net-device.h"
#include "ns3/ipv4-address.h"
#include "ipv4-l3-protocol-multicast.h"
#include "arp-l3-protocol-multicast.h"
#include "arp-cache-multicast.h"
#include "ns3/net-device.h"
#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/node.h"
#include "ns3/pointer.h"
#include "ns3/assert.h"
#include "igmpv3-l4-protocol.h"
#include "ns3/nstime.h"
#include "ns3/packet.h"

//addby Lin Chen, solving cyclic inclusion
//#include "ns3/igmpv3.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("Ipv4InterfaceMulticast");

NS_OBJECT_ENSURE_REGISTERED (Ipv4InterfaceMulticast);

TypeId 
Ipv4InterfaceMulticast::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::Ipv4InterfaceMulticast")
    .SetParent<Object> ()
    .SetGroupName ("Internet")
    .AddAttribute ("ArpCacheMulticast",
                   "The arp cache for this ipv4 interface",
                   PointerValue (0),
                   MakePointerAccessor (&Ipv4InterfaceMulticast::SetArpCache, 
                                        &Ipv4InterfaceMulticast::GetArpCache),
                   MakePointerChecker<ArpCacheMulticast> ())
  ;
  ;
  return tid;
}

/** 
 * By default, Ipv4 interface are created in the "down" state
 *  with no IP addresses.  Before becoming useable, the user must 
 * invoke SetUp on them once an Ipv4 address and mask have been set.
 */
Ipv4InterfaceMulticast::Ipv4InterfaceMulticast () 
  : m_ifup (false),
    m_forwarding (true),
    m_metric (1),
    m_node (0), 
    m_device (0),
    m_cache (0)
{
  NS_LOG_FUNCTION (this);
}

Ipv4InterfaceMulticast::~Ipv4InterfaceMulticast ()
{
  NS_LOG_FUNCTION (this);
}

void
Ipv4InterfaceMulticast::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_node = 0;
  m_device = 0;
  Object::DoDispose ();
}

void 
Ipv4InterfaceMulticast::SetNode (Ptr<Node> node)
{
  NS_LOG_FUNCTION (this << node);
  m_node = node;
  DoSetup ();
}

void 
Ipv4InterfaceMulticast::SetDevice (Ptr<NetDevice> device)
{
  NS_LOG_FUNCTION (this << device);
  m_device = device;
  DoSetup ();
}

void
Ipv4InterfaceMulticast::DoSetup (void)
{
  NS_LOG_FUNCTION (this);
  if (m_node == 0 || m_device == 0)
    {
      return;
    }
  if (!m_device->NeedsArp ())
    {
      return;
    }
  Ptr<ArpL3ProtocolMulticast> arp = m_node->GetObject<ArpL3ProtocolMulticast> ();
  m_cache = arp->CreateCache (m_device, this);
}

Ptr<NetDevice>
Ipv4InterfaceMulticast::GetDevice (void) const
{
  NS_LOG_FUNCTION (this);
  return m_device;
}

void
Ipv4InterfaceMulticast::SetMetric (uint16_t metric)
{
  NS_LOG_FUNCTION (this << metric);
  m_metric = metric;
}

uint16_t
Ipv4InterfaceMulticast::GetMetric (void) const
{
  NS_LOG_FUNCTION (this);
  return m_metric;
}

void
Ipv4InterfaceMulticast::SetArpCache (Ptr<ArpCacheMulticast> a)
{
  NS_LOG_FUNCTION (this << a);
  m_cache = a;
}

Ptr<ArpCacheMulticast>
Ipv4InterfaceMulticast::GetArpCache () const
{
  NS_LOG_FUNCTION (this);
  return m_cache;
}

/**
 * These are IP interface states and may be distinct from 
 * NetDevice states, such as found in real implementations
 * (where the device may be down but IP interface state is still up).
 */
bool 
Ipv4InterfaceMulticast::IsUp (void) const
{
  NS_LOG_FUNCTION (this);
  return m_ifup;
}

bool 
Ipv4InterfaceMulticast::IsDown (void) const
{
  NS_LOG_FUNCTION (this);
  return !m_ifup;
}

void 
Ipv4InterfaceMulticast::SetUp (void)
{
  NS_LOG_FUNCTION (this);
  m_ifup = true;
}

void 
Ipv4InterfaceMulticast::SetDown (void)
{
  NS_LOG_FUNCTION (this);
  m_ifup = false;
}

bool 
Ipv4InterfaceMulticast::IsForwarding (void) const
{
  NS_LOG_FUNCTION (this);
  return m_forwarding;
}

void 
Ipv4InterfaceMulticast::SetForwarding (bool val)
{
  NS_LOG_FUNCTION (this << val);
  m_forwarding = val;
}

void
Ipv4InterfaceMulticast::Send (Ptr<Packet> p, Ipv4Address dest)
{
  NS_LOG_FUNCTION (this << *p << dest);
  if (!IsUp ())
    {
      return;
    }
  // Check for a loopback device
  if (DynamicCast<LoopbackNetDevice> (m_device))
    {
      /// \todo additional checks needed here (such as whether multicast
      /// goes to loopback)?
      m_device->Send (p, m_device->GetBroadcast (), 
                      Ipv4L3ProtocolMulticast::PROT_NUMBER);
      return;
    } 
  // is this packet aimed at a local interface ?
  for (Ipv4InterfaceAddressListCI i = m_ifaddrs.begin (); i != m_ifaddrs.end (); ++i)
    {
      if (dest == (*i).GetLocal ())
        {
          Ptr<Ipv4L3ProtocolMulticast> ipv4 = m_node->GetObject<Ipv4L3ProtocolMulticast> ();

          ipv4->Receive (m_device, p, Ipv4L3ProtocolMulticast::PROT_NUMBER, 
                         m_device->GetBroadcast (),
                         m_device->GetBroadcast (),
                         NetDevice::PACKET_HOST // note: linux uses PACKET_LOOPBACK here
                         );
          return;
        }
    }
  if (m_device->NeedsArp ())
    {
      NS_LOG_LOGIC ("Needs ARP" << " " << dest);
      Ptr<ArpL3ProtocolMulticast> arp = m_node->GetObject<ArpL3ProtocolMulticast> ();
      Address hardwareDestination;
      bool found = false;
      if (dest.IsBroadcast ())
        {
          NS_LOG_LOGIC ("All-network Broadcast");
          hardwareDestination = m_device->GetBroadcast ();
          found = true;
        }
      else if (dest.IsMulticast ())
        {
          NS_LOG_LOGIC ("IsMulticast");
          NS_ASSERT_MSG (m_device->IsMulticast (),
                         "ArpIpv4Interface::SendTo (): Sending multicast packet over "
                         "non-multicast device");

          hardwareDestination = m_device->GetMulticast (dest);
          found = true;
        }
      else
        {
          for (Ipv4InterfaceAddressListCI i = m_ifaddrs.begin (); i != m_ifaddrs.end (); ++i)
            {
              if (dest.IsSubnetDirectedBroadcast ((*i).GetMask ()))
                {
                  NS_LOG_LOGIC ("Subnetwork Broadcast");
                  hardwareDestination = m_device->GetBroadcast ();
                  found = true;
                  break;
                }
            }
          if (!found)
            {
              NS_LOG_LOGIC ("ARP Lookup");
              found = arp->Lookup (p, dest, m_device, m_cache, &hardwareDestination);
            }
        }

      if (found)
        {
          NS_LOG_LOGIC ("Address Resolved.  Send.");
          m_device->Send (p, hardwareDestination,
                          Ipv4L3ProtocolMulticast::PROT_NUMBER);
        }
    }
  else
    {
      NS_LOG_LOGIC ("Doesn't need ARP");
      m_device->Send (p, m_device->GetBroadcast (), 
                      Ipv4L3ProtocolMulticast::PROT_NUMBER);
    }
}

uint32_t
Ipv4InterfaceMulticast::GetNAddresses (void) const
{
  NS_LOG_FUNCTION (this);
  return m_ifaddrs.size ();
}

bool
Ipv4InterfaceMulticast::AddAddress (Ipv4InterfaceAddress addr)
{
  NS_LOG_FUNCTION (this << addr);
  m_ifaddrs.push_back (addr);
  return true;
}

Ipv4InterfaceAddress
Ipv4InterfaceMulticast::GetAddress (uint32_t index) const
{
  NS_LOG_FUNCTION (this << index);
  if (index < m_ifaddrs.size ())
    {
      uint32_t tmp = 0;
      for (Ipv4InterfaceAddressListCI i = m_ifaddrs.begin (); i!= m_ifaddrs.end (); i++)
        {
          if (tmp  == index)
            {
              return *i;
            }
          ++tmp;
        }
    }
  NS_ASSERT (false);  // Assert if not found
  Ipv4InterfaceAddress addr;
  return (addr);  // quiet compiler
}

Ipv4InterfaceAddress
Ipv4InterfaceMulticast::RemoveAddress (uint32_t index)
{
  NS_LOG_FUNCTION (this << index);
  if (index >= m_ifaddrs.size ())
    {
      NS_ASSERT_MSG (false, "Bug in Ipv4InterfaceMulticast::RemoveAddress");
    }
  Ipv4InterfaceAddressListI i = m_ifaddrs.begin ();
  uint32_t tmp = 0;
  while (i != m_ifaddrs.end ())
    {
      if (tmp  == index)
        {
          Ipv4InterfaceAddress addr = *i;
          m_ifaddrs.erase (i);
          return addr;
        }
      ++tmp;
      ++i;
    }
  NS_ASSERT_MSG (false, "Address " << index << " not found");
  Ipv4InterfaceAddress addr;
  return (addr);  // quiet compiler
}

Ipv4InterfaceAddress
Ipv4InterfaceMulticast::RemoveAddress(Ipv4Address address)
{
  NS_LOG_FUNCTION(this << address);

  if (address == address.GetLoopback())
    {
      NS_LOG_WARN ("Cannot remove loopback address.");
      return Ipv4InterfaceAddress();
    }

  for(Ipv4InterfaceAddressListI it = m_ifaddrs.begin(); it != m_ifaddrs.end(); it++)
    {
      if((*it).GetLocal() == address)
        {
          Ipv4InterfaceAddress ifAddr = *it;
          m_ifaddrs.erase(it);
          return ifAddr;
        }
    }
  return Ipv4InterfaceAddress();
}

//Ipv4InterfaceMulticast::IPMCL_STATUS
void
Ipv4InterfaceMulticast::IPMulticastListen (Ptr<IGMPv3SocketState> socket_state)
{
	Ipv4Address multicast_address = socket_state->GetGroupAddress();

	if (true == this->m_lst_interfacestates.empty())
	{
		Ptr<IGMPv3InterfaceState> interfacestate = Create<IGMPv3InterfaceState>();
		interfacestate->Initialize(this, multicast_address);
		interfacestate->AssociateSocketStateInterfaceState (socket_state);
		interfacestate->ComputeState ();
		this->m_lst_interfacestates.push_back(interfacestate);

		return; //Ipv4InterfaceMulticast::ADDED;
	}

	else
	{
		std::list<Ptr<IGMPv3InterfaceState> >::iterator it = this->m_lst_interfacestates.begin();

		while (it != this->m_lst_interfacestates.end())
		{
			Ptr<IGMPv3InterfaceState> it_interface_state = *it;

			//note: the socket_state->m_associated_interfacestate might be 0 (null)
			if (socket_state->GetGroupAddress() == it_interface_state->GetGroupAddress())
			{
				it_interface_state->AssociateSocketStateInterfaceState (socket_state);
				it_interface_state->ComputeState ();
				return;
			}
			else
			{
				//do nothing
				it++;
				continue;
			}
		}

		if (it == this->m_lst_interfacestates.end())
		{
			Ptr<IGMPv3InterfaceState> interfacestate = Create<IGMPv3InterfaceState>();
			interfacestate->Initialize(this, multicast_address);
			interfacestate->AssociateSocketStateInterfaceState (socket_state);
			interfacestate->ComputeState ();
			this->m_lst_interfacestates.push_back(interfacestate);
			return;
		}
		else
		{
			//only when it == this->m_lst_interfacestates.end(), the program would jump out of the while loop
			NS_ASSERT (false);
		}
	}
}

std::list<Ptr<IGMPv3InterfaceState> >
Ipv4InterfaceMulticast::GetInterfaceStates (void)
{
	return this->m_lst_interfacestates;
}

//void
//Ipv4InterfaceMulticast::AssociateSocketStateToInterfaceState (Ptr<IGMPv3SocketState> socket_state, Ptr<IGMPv3InterfaceState> interfacestate)
//{
//	for (std::list<Ptr<IGMPv3SocketState> >::iterator it = interfacestate->m_lst_associated_socket_state.begin();
//			it != interfacestate->m_lst_associated_socket_state.end();
//			it++)
//	{
//		//check whether the incoming socket has already in the list of sockets of interfacestate
//		if (socket_state == (*it))
//		{
//			//do nothing
//			return;
//		}
//	}
//
//	interfacestate->m_lst_associated_socket_state.push_back(socket_state);
//}
//
//bool
//Ipv4InterfaceMulticast::CheckSubscribedAllSocketsIncludeMode (Ptr<IGMPv3InterfaceState> interfacestate)
//{
//	std::list<Ptr<IGMPv3SocketState> > associated_socket_states = interfacestate->m_lst_associated_socket_state;
//	for (std::list<Ptr<IGMPv3SocketState> >::iterator it = associated_socket_states.begin();
//			it != associated_socket_states.end();
//			it++)
//	{
//		Ptr<IGMPv3SocketState> socket_state = *it;
//		if (ns3::EXCLUDE == socket_state->m_filter_mode)
//		{
//			return false;
//		}
//		else if (ns3::INCLUDE == socket_state->m_filter_mode)
//		{
//			continue;	//do nothing
//		}
//		else
//		{
//			//should not go here.
//			NS_ASSERT(false);
//		}
//	}
//
//	return true;
//}

void
Ipv4InterfaceMulticast::UnSubscribeIGMP (Ptr<Socket> socket)
{
//	if (socket != 0)
//	{
//		Ptr<Ipv4RawSocketImplMulticast> raw_socket = DynamicCast<Ipv4RawSocketImplMulticast> (socket);
//
//		std::list<IGMPv3SocketState> socket_states_associated_this_interface;
//
//		std::list<IGMPv3SocketState> all_socket_states = raw_socket->GetSocketState();
//
//		for (std::list<IGMPv3SocketState>::iterator it = all_socket_states.begin();
//				it != all_socket_states.end();
//				it++)
//		{
//			if (it->m_interface == this)
//			{
//				socket_states_associated_this_interface.push_back(*it);
//			}
//		}
//
//
//	}
//	else
//	{
//		NS_ASSERT(false);
//	}
}

void
Ipv4InterfaceMulticast::AddPendingRecordsToReport (Igmpv3Report &report)
{
	for (std::list<Ptr<IGMPv3InterfaceState> >::iterator it = this->m_lst_interfacestates.begin();
		 it != this->m_lst_interfacestates.end();
		 it++)
	{
		(*it)->AddPendingRecordsToReport(report);
	}
}

bool
Ipv4InterfaceMulticast::HasPendingRecords (void)
{
	for (std::list<Ptr<IGMPv3InterfaceState> >::iterator it = this->m_lst_interfacestates.begin();
		 it != this->m_lst_interfacestates.end();
		 it++)
	{
		Ptr<IGMPv3InterfaceState> interfacestate = (*it);
		if (true == interfacestate->HasPendingRecords())
		{
			return true;
		}
	}

	return false;
}

void
Ipv4InterfaceMulticast::ReportStateChanges (void)
{
	std::cout << "Node: " << this->m_node->GetId() << " Interface: " << this << " report state changes" << Simulator::Now() << std::endl;

	Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();

	if (true == this->m_event_robustness_retransmission.IsRunning())
	{
		//the previous scheduled robustness report sending event should cancled before that this method is invoked
		this->CancelReportStateChanges();
		igmp->SendStateChangesReport(this);
	}

	if (true == this->HasPendingRecords())
	{
		Time delay = igmp->GetUnsolicitedReportInterval();

		this->m_event_robustness_retransmission = Simulator::Schedule (delay, &Ipv4InterfaceMulticast::DoReportStateChanges, this);
	}

}

void
Ipv4InterfaceMulticast::DoReportStateChanges (void)
{
	std::cout << "Node: " << this->m_node->GetId() << " Interface: " << this << " report state changes " << Simulator::Now() << std::endl;

	Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();

	igmp->SendStateChangesReport(this);

	if (true == this->HasPendingRecords())
	{
		Time delay = igmp->GetUnsolicitedReportInterval();

		this->m_event_robustness_retransmission = Simulator::Schedule (delay, &Ipv4InterfaceMulticast::DoReportStateChanges, this);
	}

}

void
Ipv4InterfaceMulticast::ReportCurrentStates (void)
{
	NS_LOG_FUNCTION (this);

	std::cout << "Node: " << this->m_node->GetId() << " Interface: " << this << " report current state " << Simulator::Now() << std::endl;

	Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();

	Ptr<Packet> packet = Create<Packet>();

	std::list<Igmpv3GrpRecord> lst_grp_records;

	for (std::list<Ptr<IGMPv3InterfaceState> >::iterator ifstate_it = this->m_lst_interfacestates.begin();
			ifstate_it != this->m_lst_interfacestates.end();
			ifstate_it++)
	{
		Ptr<IGMPv3InterfaceState> if_state = (*ifstate_it);

		Igmpv3GrpRecord record = Igmpv3GrpRecord::GenerateGrpRecord(if_state);

		lst_grp_records.push_back(record);
	}

	Igmpv3Report report;
//	report.SetNumGrpRecords(lst_grp_records.size());
	report.PushBackGrpRecords(lst_grp_records);

	packet->AddHeader(report);

	Igmpv3Header igmpv3;
	igmpv3.SetType(Igmpv3Header::V3_MEMBERSHIP_REPORT);
	igmpv3.SetMaxRespCode(igmp->GetMaxRespCode());

	if (Node::ChecksumEnabled ()) {
		igmpv3.EnableChecksum();
	}

	packet->AddHeader(igmpv3);

	std::cout << "Node: " << this->m_node->GetId() << " reporting a general query to the querier" << std::endl;

	igmp->SendReport(this, packet);

}

void
Ipv4InterfaceMulticast::ReportCurrentGrpStates (Ipv4Address group_address)
{
	NS_LOG_FUNCTION (this);

	Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();

	Ptr<Packet> packet = Create<Packet>();

	std::list<Igmpv3GrpRecord> lst_grp_records;

	for (std::list<Ptr<IGMPv3InterfaceState> >::iterator ifstate_it = this->m_lst_interfacestates.begin();
			ifstate_it != this->m_lst_interfacestates.end();
			ifstate_it++)
	{
		Ptr<IGMPv3InterfaceState> if_state = (*ifstate_it);

		if (group_address == if_state->GetGroupAddress())
		{
			Igmpv3GrpRecord record = Igmpv3GrpRecord::GenerateGrpRecord(if_state);

			lst_grp_records.push_back(record);

			//only one state for a group on each interface;
			break;
		}
	}

	Igmpv3Report report;
	//report.SetNumGrpRecords(lst_grp_records.size());
	report.PushBackGrpRecords(lst_grp_records);

	packet->AddHeader(report);

	Igmpv3Header igmpv3;
	igmpv3.SetType(Igmpv3Header::V3_MEMBERSHIP_REPORT);
	igmpv3.SetMaxRespCode(igmp->GetMaxRespCode());

	if (Node::ChecksumEnabled ()) {
		igmpv3.EnableChecksum();
	}

	packet->AddHeader(igmpv3);

	std::cout << "Node: " << this->m_node->GetId() << " reporting a general query to the querier" << std::endl;

	igmp->SendReport(this, packet);

	this->RemovePerGroupTimer(group_address);
}

void
Ipv4InterfaceMulticast::ReportCurrentGrpNSrcStates (Ipv4Address group_address, std::list<Ipv4Address> const &src_list)
{
	NS_LOG_FUNCTION (this);

	Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();

	Ptr<Packet> packet = Create<Packet>();

	std::list<Igmpv3GrpRecord> lst_grp_records;

	for (std::list<Ptr<IGMPv3InterfaceState> >::iterator ifstate_it = this->m_lst_interfacestates.begin();
			ifstate_it != this->m_lst_interfacestates.end();
			ifstate_it++)
	{
		Ptr<IGMPv3InterfaceState> if_state = (*ifstate_it);

		if (group_address == if_state->GetGroupAddress())
		{
			Igmpv3GrpRecord record = Igmpv3GrpRecord::GenerateGrpRecord(if_state, src_list);

			if (0 == record.GetNumSrcs())
			{
				//INCLUDE mode + empty source list = no response to be sent.
				return;
			}
			lst_grp_records.push_back(record);

			//only one state for a group on each interface;
			break;
		}
	}

	Igmpv3Report report;
	//report.SetNumGrpRecords(lst_grp_records.size());
	report.PushBackGrpRecords(lst_grp_records);

	packet->AddHeader(report);

	Igmpv3Header igmpv3;
	igmpv3.SetType(Igmpv3Header::V3_MEMBERSHIP_REPORT);
	igmpv3.SetMaxRespCode(igmp->GetMaxRespCode());

	if (Node::ChecksumEnabled ()) {
		igmpv3.EnableChecksum();
	}

	packet->AddHeader(igmpv3);

	std::cout << "Node: " << this->m_node->GetId() << " reporting a general query to the querier" << std::endl;

	igmp->SendReport(this, packet);

	this->RemovePerGroupTimer(group_address);
}

void
Ipv4InterfaceMulticast::CancelReportStateChanges ()
{
	if (true == this->m_event_robustness_retransmission.IsRunning())
	{
		Simulator::Cancel(this->m_event_robustness_retransmission);
	}
	else
	{
		//No running event to cancel
		NS_ASSERT (false);
	}
}

void
Ipv4InterfaceMulticast::RemovePerGroupTimer (Ipv4Address group_address)
{
	//remove timer from m_lst_per_group_interface_timers
	for (	std::list<Ptr<PerGroupInterfaceTimer> >::iterator it = this->m_lst_per_group_interface_timers.begin();
			it != this->m_lst_per_group_interface_timers.end();
			it++)
	{
		Ptr<PerGroupInterfaceTimer> timer = (*it);

		if (timer->m_group_address == group_address)
		{
			this->m_lst_per_group_interface_timers.erase(it);
			//there should be only one timer for a particular group at a time.
			break;
		}
	}
}

bool
Ipv4InterfaceMulticast::IsReportStateChangesRunning (void)
{
	return this->m_event_robustness_retransmission.IsRunning();
}

void
Ipv4InterfaceMulticast::HandleGeneralQuery (Time resp_time)
{
	if (false == this->m_timer_gen_query.IsRunning())
	{
		std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << "'s has no per-interface-timer" << std::endl;
		std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << " creating a new timer for handling incoming General Query" << std::endl;
		this->m_timer_gen_query.SetFunction(&Ipv4InterfaceMulticast::ReportCurrentStates, this);
		std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
		this->m_timer_gen_query.Schedule(resp_time);
	}
	else
	{
		if (resp_time < this->m_timer_gen_query.GetDelayLeft())
		{
			this->m_timer_gen_query.Cancel();

			std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << "'s has a per-interface-timer, but delay time is smaller than resp time" << std::endl;
			std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << " creating a new timer for handling incoming General Query" << std::endl;
			this->m_timer_gen_query.SetFunction(&Ipv4InterfaceMulticast::ReportCurrentStates, this);
			std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
			this->m_timer_gen_query.Schedule(resp_time);
		}
		else
		{
			//do nothing
		}
	}
}

void
Ipv4InterfaceMulticast::HandleGroupSpecificQuery (Time resp_time, Ipv4Address group_address)
{
	for (std::list<Ptr<IGMPv3InterfaceState> >::iterator ifstate_it = this->m_lst_interfacestates.begin();
			ifstate_it != this->m_lst_interfacestates.end();
			ifstate_it++)
	{
		Ptr<IGMPv3InterfaceState> if_state = (*ifstate_it);

		if (group_address == if_state->GetGroupAddress())
		{
			this->DoHandleGroupSpecificQuery(resp_time, group_address);
		}
	}
}

void
Ipv4InterfaceMulticast::DoHandleGroupSpecificQuery (Time resp_time, Ipv4Address group_address)
{
	for (std::list<Ptr<PerGroupInterfaceTimer> >::iterator it = this->m_lst_per_group_interface_timers.begin();
		 it != this->m_lst_per_group_interface_timers.end();
		 it++)
	{
		Ptr<PerGroupInterfaceTimer> timer = (*it);
		if (timer->m_group_address == group_address)
		{
			Time delay;
			if (resp_time < timer->m_softTimer.GetDelayLeft())
			{
				delay = resp_time;
			}
			else
			{
				delay = timer->m_softTimer.GetDelayLeft();
			}

			std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << " there is a timer exist for group specific query with delaytime left smaller current resp time." << std::endl;
			std::cout << "Interface: " << this << ", Group Address: " << group_address << std::endl;
			std::cout << "Canceling previous report." << std::endl;
			timer->m_softTimer.Cancel();

			timer->m_softTimer.SetFunction(&Ipv4InterfaceMulticast::ReportCurrentGrpStates, this);
			timer->m_softTimer.SetArguments(group_address);
			std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << " scheduling new report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
			timer->m_softTimer.Schedule(delay);
			return;
		}
	}

	std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << " creating a new timer for handling incoming Group Specific Query" << std::endl;
	std::cout << "Interface: " << this << ", Group Address: " << group_address << std::endl;
	Ptr<PerGroupInterfaceTimer> new_timer = Create<PerGroupInterfaceTimer>();
	new_timer->m_interface = this;
	new_timer->m_group_address = group_address;
	new_timer->m_softTimer.SetFunction(&Ipv4InterfaceMulticast::ReportCurrentGrpStates, this);
	new_timer->m_softTimer.SetArguments(group_address);
	std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
	new_timer->m_softTimer.Schedule(resp_time);
	this->m_lst_per_group_interface_timers.push_back(new_timer);
}

void
Ipv4InterfaceMulticast::HandleGroupNSrcSpecificQuery (Time resp_time, Ipv4Address group_address, std::list<Ipv4Address> const &src_list)
{
	for (std::list<Ptr<IGMPv3InterfaceState> >::iterator ifstate_it = this->m_lst_interfacestates.begin();
			ifstate_it != this->m_lst_interfacestates.end();
			ifstate_it++)
	{
		Ptr<IGMPv3InterfaceState> if_state = (*ifstate_it);

		if (group_address == if_state->GetGroupAddress())
		{
			this->DoHandleGroupSpecificQuery(resp_time, group_address);
		}
	}
}

void
Ipv4InterfaceMulticast::DoHandleGroupNSrcSpecificQuery (Time resp_time, Ipv4Address group_address, std::list<Ipv4Address> const &src_list)
{
	for (std::list<Ptr<PerGroupInterfaceTimer> >::iterator it = this->m_lst_per_group_interface_timers.begin();
		 it != this->m_lst_per_group_interface_timers.end();
		 it++)
	{
		Ptr<PerGroupInterfaceTimer> timer = (*it);
		if (timer->m_group_address == group_address)
		{
			Time delay;
			if (resp_time < timer->m_softTimer.GetDelayLeft())
			{
				delay = resp_time;
			}
			else
			{
				delay = timer->m_softTimer.GetDelayLeft();
			}

			std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << " there is a timer exist for group specific query with delaytime left smaller current resp time." << std::endl;
			std::cout << "Interface: " << this << ", Group Address: " << group_address << std::endl;
			std::cout << "Canceling previous report." << std::endl;
			timer->m_softTimer.Cancel();

			timer->m_softTimer.SetFunction(&Ipv4InterfaceMulticast::ReportCurrentGrpNSrcStates, this);
			timer->m_softTimer.SetArguments(group_address, src_list);
			std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << " scheduling new report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
			timer->m_softTimer.Schedule(delay);
			return;
		}
	}

	std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << " creating a new timer for handling incoming Group Specific Query" << std::endl;
	std::cout << "Interface: " << this << ", Group Address: " << group_address << std::endl;
	Ptr<PerGroupInterfaceTimer> new_timer = Create<PerGroupInterfaceTimer>();
	new_timer->m_interface = this;
	new_timer->m_group_address = group_address;
	new_timer->m_softTimer.SetFunction(&Ipv4InterfaceMulticast::ReportCurrentGrpNSrcStates, this);
	new_timer->m_softTimer.SetArguments(group_address, src_list);
	std::cout << "Node id: " << this->GetDevice()->GetNode()->GetId() << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
	new_timer->m_softTimer.Schedule(resp_time);
	this->m_lst_per_group_interface_timers.push_back(new_timer);
}

void
Ipv4InterfaceMulticast::HandleV3Records (std::list<Igmpv3GrpRecord> &records)
{
	for (std::list<Igmpv3GrpRecord>::const_iterator record_it = records.begin();
		 record_it != records.end();
		 record_it++)
	{
		for (std::list<Ptr<IGMPv3MaintenanceState> >::iterator state_it = this->m_lst_maintenance_states.begin();
			 state_it != this->m_lst_maintenance_states.end();
			 state_it++)
		{
			Igmpv3GrpRecord record = (*record_it);
			Ptr<IGMPv3MaintenanceState> maintenance_state = (*state_it);

			if (record.GetMulticastAddress() == maintenance_state->GetMulticastAddress())
			{
				maintenance_state->HandleGrpRecord(record);
			}

		}
	}

}

void
Ipv4InterfaceMulticast::NonQHandleGroupSpecificQuery (Ipv4Address group_address)
{
	for (std::list<Ptr<IGMPv3MaintenanceState> >::iterator state_it = this->m_lst_maintenance_states.begin();
			state_it != this->m_lst_maintenance_states.end();
			state_it++)
	{
		Ptr<IGMPv3MaintenanceState> maintenance_state = (*state_it);

		if (group_address == maintenance_state->GetMulticastAddress())
		{
			maintenance_state->HandleQuery();
		}

	}
}
void
Ipv4InterfaceMulticast::NonQHandleGroupNSrcSpecificQuery (Ipv4Address group_address,
														  std::list<Ipv4Address> const &src_list)
{
	for (std::list<Ptr<IGMPv3MaintenanceState> >::iterator state_it = this->m_lst_maintenance_states.begin();
			state_it != this->m_lst_maintenance_states.end();
			state_it++)
	{
		Ptr<IGMPv3MaintenanceState> maintenance_state = (*state_it);

		if (group_address == maintenance_state->GetMulticastAddress())
		{
			maintenance_state->HandleQuery(src_list);
		}

	}

}

void
Ipv4InterfaceMulticast::SendQuery (Ipv4Address group_address, bool s_flag)
{
	NS_LOG_FUNCTION (this);

	Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();

	Igmpv3Query query;

	query.SetGroupAddress(group_address);
	query.SetSFlag(s_flag);
	query.SetQQIC(igmp->GetQQIC());
	query.SetQRV(igmp->GetQRV());

	Ptr<Packet> packet = Create<Packet>();

	packet->AddHeader(query);

	igmp->SendQuery(group_address, this, packet);
}

void
Ipv4InterfaceMulticast::SendQuery (Ipv4Address group_address, std::list<Ipv4Address> const &src_list, bool s_flag)
{
	NS_LOG_FUNCTION (this);

	Ptr<Ipv4Multicast> ipv4 = this->m_node->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();

	Igmpv3Query query;

	query.SetGroupAddress(group_address);
	query.SetSFlag(s_flag);
	query.SetQQIC(igmp->GetQQIC());
	query.SetQRV(igmp->GetQRV());
	query.PushBackSrcAddresses(src_list);

	Ptr<Packet> packet = Create<Packet>();

	packet->AddHeader(query);

	igmp->SendQuery(group_address, this, packet);

}

} // namespace ns3

