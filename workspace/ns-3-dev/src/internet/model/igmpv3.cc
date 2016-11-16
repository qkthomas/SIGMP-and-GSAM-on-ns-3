/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 CONCORDIA UNIVERSITY
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
 * Author: Lin Chen <c_lin13@encs.concordia.ca>
 */

#include "igmpv3.h"
#include "ns3/log.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/nstime.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/event-id.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("Igmpv3Header");

/********************************************************
 *        IGMPv3SocketState
 ********************************************************/

TypeId
IGMPv3SocketState::GetTypeId (void)
{
	  static TypeId tid = TypeId ("ns3::IGMPv3SocketState")
	    .SetParent<Object> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IGMPv3SocketState> ();
	  return tid;
}

IGMPv3SocketState::IGMPv3SocketState ()
:  m_socket (0),
   m_associated_if_state (0),
   m_multicast_address ("0.0.0.0"),
   m_filter_mode (ns3::INCLUDE)
{

}

void
IGMPv3SocketState::Initialize (Ptr<Socket> socket,
				   	   	   	   	   	  Ipv4Address multicast_address,
									  ns3::FILTER_MODE filter_mode,
									  std::list<Ipv4Address> const &lst_source_list)
{
	this->m_socket = socket;
	this->m_multicast_address = multicast_address;
	this->m_filter_mode = filter_mode;

	for (std::list<Ipv4Address>::const_iterator it = lst_source_list.begin();
			it != lst_source_list.end();
			it++)
	{
		this->m_lst_source_list.push_back(*it);
	}
}

IGMPv3SocketState::~IGMPv3SocketState (void)
{
	if (this->m_associated_if_state != 0)
	{
		this->m_associated_if_state->UnSubscribeIGMP (this);
		this->m_associated_if_state = 0;
	}
	else
	{
		//this->m_associated_if_state->UnSubscribeIGMP has been invoked
	}
	this->m_socket = 0;
	this->m_lst_source_list.clear();
}

void
IGMPv3SocketState::SetAssociatedInterfaceState (Ptr<IGMPv3InterfaceState> associated_if_state)
{
	this->m_associated_if_state = associated_if_state;
}

Ptr<IGMPv3InterfaceState>
IGMPv3SocketState::GetAssociatedInterfaceState (void) const
{
	return this->m_associated_if_state;
}

Ipv4Address
IGMPv3SocketState::GetGroupAddress (void) const
{
	return this->m_multicast_address;
}

ns3::FILTER_MODE
IGMPv3SocketState::GetFilterMode (void) const
{
	return this->m_filter_mode;
}

std::list<Ipv4Address> const &
IGMPv3SocketState::GetSrcList (void) const
{
	return this->m_lst_source_list;
}

void
IGMPv3SocketState::SetSrcList (std::list<Ipv4Address> const & src_list)
{
	this->m_lst_source_list = src_list;
}

Ptr<Socket>
IGMPv3SocketState::GetSockt (void) const
{
	if (0 == this->m_socket)
	{
		NS_ASSERT (false);
	}
	return this->m_socket;
}

bool
operator == (IGMPv3SocketState const& lhs, IGMPv3SocketState const& rhs)
{
	if (	(lhs.m_socket == lhs.m_socket) &&
			(lhs.m_associated_if_state == rhs.m_associated_if_state) &&
			(lhs.m_multicast_address == rhs.m_multicast_address))
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool
operator < (IGMPv3SocketState const& lhs, IGMPv3SocketState const& rhs)
{
	if ((lhs.m_filter_mode == ns3::EXCLUDE) &&
			(rhs.m_filter_mode == ns3::INCLUDE))
	{
		return true;
	}
	else
	{
		return false;
	}
}

void
IGMPv3SocketState::UnSubscribeIGMP ()
{
	if (this->m_associated_if_state != 0)
	{
		std::cout << "socket state: " << this << " UnSubscribeIGMP ()" << std::endl;
		this->m_associated_if_state->UnSubscribeIGMP (this);
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
IGMPv3SocketState::StateChange (ns3::FILTER_MODE filter_mode, std::list<Ipv4Address> const &src_list)
{
	std::cout << "Socket state change: ";
	if (filter_mode == ns3::INCLUDE)
	{
		std::cout << "filter mode: include" << std::endl;
	}
	else
	{
		std::cout << "filter mode: exclude" << std::endl;
	}

	if ((filter_mode == ns3::INCLUDE) && (true == src_list.empty()))
	{
		//rfc 3376, 3.1, should be removed instead of change
		NS_ASSERT(false);
	}
	else
	{
		this->m_filter_mode = filter_mode;
		this->m_lst_source_list = src_list;

		this->m_associated_if_state->ComputeState();
	}
}

/********************************************************
 *        IGMPv3SocketStateManager
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IGMPv3SocketStateManager);

TypeId
IGMPv3SocketStateManager::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IGMPv3SocketStateManager")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<IGMPv3SocketStateManager> ()
			;
	return tid;
}

IGMPv3SocketStateManager::IGMPv3SocketStateManager ()
{
	NS_LOG_FUNCTION (this);
}

IGMPv3SocketStateManager::~IGMPv3SocketStateManager()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_socket_states.clear();
}

TypeId
IGMPv3SocketStateManager::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IGMPv3SocketStateManager::GetTypeId();
}

void
IGMPv3SocketStateManager::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
IGMPv3SocketStateManager::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

Ptr<IGMPv3SocketState>
IGMPv3SocketStateManager::GetSocketState (Ptr<Socket> socket, Ptr<Ipv4InterfaceMulticast> interface, Ipv4Address multicast_address) const
{
	NS_LOG_FUNCTION (this);
	Ptr<IGMPv3SocketState> retval = 0;
	for (std::list<Ptr<IGMPv3SocketState> >::const_iterator const_it = this->m_lst_socket_states.begin();
			const_it != this->m_lst_socket_states.end();
			const_it++)
	{
		Ptr<IGMPv3SocketState> value_const_it = (*const_it);
		if ((value_const_it->GetSockt() == socket) &&
				(value_const_it->GetAssociatedInterfaceState()->GetInterface() == interface) &&
				(value_const_it->GetGroupAddress() == multicast_address))
		{
			retval = value_const_it;
			break;
		}
	}
	//return value can be 0
	return retval;
}

void
IGMPv3SocketStateManager::Sort (void)
{
	NS_LOG_FUNCTION (this);
	if (false == this->m_lst_socket_states.empty())
	{
		this->m_lst_socket_states.sort();
	}
}

/********************************************************
 *        IGMPv3InterfaceState
 ********************************************************/

TypeId
IGMPv3InterfaceState::GetTypeId (void)
{
	  static TypeId tid = TypeId ("ns3::IGMPv3InterfaceState")
	    .SetParent<Object> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IGMPv3InterfaceState> ();
	  return tid;
}

IGMPv3InterfaceState::IGMPv3InterfaceState (void)
  :  m_interface (0),
	 m_manager (0),
	 m_multicast_address ("0. 0. 0. 0"),
	 m_filter_mode (ns3::INCLUDE),
	 m_old_if_state (0)
{
	//this->m_old_if_state = IGMPv3InterfaceState::GetNonExistentState(this->m_interface, this->m_multicast_address);
}

void
IGMPv3InterfaceState::Initialize (Ptr<Ipv4InterfaceMulticast> interface, Ipv4Address multicast_address)
{
	this->m_interface = interface;
	this->m_multicast_address = multicast_address;
	this->m_filter_mode = ns3::INCLUDE;
	this->m_old_if_state = IGMPv3InterfaceState::GetNonExistentState(this->m_interface, this->m_multicast_address);
}

void
IGMPv3InterfaceState::Initialize (Ptr<IGMPv3InterfaceStateManager> manager, Ipv4Address multicast_address)
{
	this->m_manager = manager;
	this->m_multicast_address = multicast_address;
	this->m_filter_mode = ns3::INCLUDE;
	this->m_old_if_state = IGMPv3InterfaceState::GetNonExistentState(this->m_interface, this->m_multicast_address);
}

IGMPv3InterfaceState::~IGMPv3InterfaceState (void)
{
	this->m_interface = 0;
	this->m_lst_source_list.clear();
	this->m_lst_associated_socket_state.clear();
	this->m_old_if_state = 0;
}

Ptr<Ipv4InterfaceMulticast>
IGMPv3InterfaceState::GetInterface (void) const
{
	return this->m_interface;
}

Ipv4Address
IGMPv3InterfaceState::GetGroupAddress (void) const
{
	return this->m_multicast_address;
}

std::list<Ipv4Address> const &
IGMPv3InterfaceState::GetSrcList (void) const
{
	return this->m_lst_source_list;
}

std::list<Ipv4Address>::size_type
IGMPv3InterfaceState::GetSrcNum (void) const
{
	return this->m_lst_source_list.size();
}

void
IGMPv3InterfaceState::SetSrcList (std::list<Ipv4Address> const & src_list)
{
	this->m_lst_source_list = src_list;
}

ns3::FILTER_MODE
IGMPv3InterfaceState::GetFilterMode (void) const
{
	return this->m_filter_mode;
}

bool
operator == (IGMPv3InterfaceState const& lhs, IGMPv3InterfaceState const& rhs)
{
	if ((lhs.m_interface == rhs.m_interface) && (lhs.m_multicast_address == rhs.m_multicast_address))
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool
operator < (IGMPv3InterfaceState const& lhs, IGMPv3InterfaceState const& rhs)
{
	if ((lhs.m_filter_mode == ns3::EXCLUDE) &&
			(rhs.m_filter_mode == ns3::INCLUDE))
	{
		return true;
	}
	else
	{
		return false;
	}
}

void
IGMPv3InterfaceState::UnSubscribeIGMP (Ptr<IGMPv3SocketState> socket_state)
{
	for (std::list<Ptr<IGMPv3SocketState> >::iterator it = this->m_lst_associated_socket_state.begin();
			it != this->m_lst_associated_socket_state.end();
			it++)
	{
		if ((*it) == socket_state)
		{
			it = this->m_lst_associated_socket_state.erase(it);
			break;
		}
	}

	this->ComputeState();
}

//bool
//IGMPv3InterfaceState::IsEqual (ns3::FILTER_MODE filter_mode, std::list<Ipv4Address> const &src_list)
//{
//	std::list<Ipv4Address>::const_iterator src_lst_con_it = src_list.begin();
//	std::list<Ipv4Address>::const_iterator current_src_lst_con_it = this->m_lst_source_list.begin();
//
//	if (filter_mode == this->m_filter_mode)
//	{
//		while (src_lst_con_it != src_list.end())
//		{
//			//current source list (new computed source list)
//			//traverse ends before old source list.
//			if (current_src_lst_con_it == this->m_lst_source_list.end())
//			{
//				return false;
//			}
//
//			if ((*src_lst_con_it) != (*current_src_lst_con_it))
//			{
//				return false;
//			}
//			src_lst_con_it++;
//			current_src_lst_con_it++;
//		}
//	}
//	//current source list (new computed source list)
//	//traverse did not end after traverse of old source list ended.
//	else if (current_src_lst_con_it != m_lst_source_list.end())
//	{
//		return false;
//	}
//	else
//	{
//		return true;
//	}
//
//	//just for dismissing the warning
//	return true;
//}
//
//bool
//IGMPv3InterfaceState::IsEqual (IGMPv3InterfaceState if_state)
//{
//	Ipv4Address multicast_address = if_state.m_multicast_address;
//	ns3::FILTER_MODE filter_mode = if_state.m_filter_mode;
//	std::list<Ipv4Address> &src_list = if_state.m_lst_source_list;
//
//	if ((multicast_address == this->m_multicast_address) &&
//			(this->IsEqual(filter_mode, src_list)))
//	{
//		return true;
//	}
//	else
//	{
//		return false;
//	}
//}
//
//bool
//IGMPv3InterfaceState::IsEqual (Ptr<IGMPv3InterfaceState> if_state)
//{
//	Ipv4Address multicast_address = if_state->m_multicast_address;
//	ns3::FILTER_MODE filter_mode = if_state->m_filter_mode;
//	std::list<Ipv4Address> &src_list = if_state->m_lst_source_list;
//
//	if ((multicast_address == this->m_multicast_address) &&
//			(this->IsEqual(filter_mode, src_list)))
//	{
//		return true;
//	}
//	else
//	{
//		return false;
//	}
//}

bool
IGMPv3InterfaceState::IsFilterModeChanged (IGMPv3InterfaceState if_state) const
{
	if (this->m_filter_mode == if_state.m_filter_mode)
	{
		return false;
	}
	else
	{
		return true;
	}
}
bool
IGMPv3InterfaceState::IsFilterModeChanged (Ptr<IGMPv3InterfaceState> if_state) const
{
	if (this->m_filter_mode == (*if_state).m_filter_mode)
	{
		return false;
	}
	else
	{
		return true;
	}
}
bool
IGMPv3InterfaceState::IsFilterModeChanged (void) const	//comparing to old_state;
{
	return this->IsFilterModeChanged (this->GetOldInterfaceState());
}

bool
IGMPv3InterfaceState::IsSrcLstChanged (IGMPv3InterfaceState if_state)
{
	this->m_lst_source_list.sort();
	if_state.m_lst_source_list.sort();

	std::list<Ipv4Address> A_minus_B = Igmpv3L4Protocol::ListSubtraction(this->m_lst_source_list, if_state.m_lst_source_list);
	std::list<Ipv4Address> B_minus_A = Igmpv3L4Protocol::ListSubtraction(if_state.m_lst_source_list, this->m_lst_source_list);

	if ((true == A_minus_B.empty()) &&
			(true == B_minus_A.empty()))
	{
		return false;
	}
	else
	{
		return true;
	}
}
bool
IGMPv3InterfaceState::IsSrcLstChanged (Ptr<IGMPv3InterfaceState> if_state)
{
	this->m_lst_source_list.sort();
	if_state->m_lst_source_list.sort();

	std::list<Ipv4Address> A_minus_B = Igmpv3L4Protocol::ListSubtraction(this->m_lst_source_list, if_state->m_lst_source_list);
	std::list<Ipv4Address> B_minus_A = Igmpv3L4Protocol::ListSubtraction(if_state->m_lst_source_list, this->m_lst_source_list);

	if ((true == A_minus_B.empty()) &&
			(true == B_minus_A.empty()))
	{
		return false;
	}
	else
	{
		return true;
	}
}
bool
IGMPv3InterfaceState::IsSrcLstChanged (void)
{
	return this->IsSrcLstChanged(this->GetOldInterfaceState());
}

bool
IGMPv3InterfaceState::HasPendingRecords (void) const
{
	//allow records block records should always be paired
	if ((false == this->m_que_pending_allow_src_chg_records.empty()) &&
		(false == this->m_que_pending_block_src_chg_records.empty()))
	{
		return true;
	}
	else if (false == this->m_que_pending_filter_mode_chg_records.empty())
	{
		return true;
	}
	else
	{
		return false;
	}
}

// May trigger sending of reports
void
IGMPv3InterfaceState::ComputeState (void)
{
	//Is the following two lines reset correct?
	//updated: no, I dont think so. they should be set as the values of fields in first invoked sockt state
//	this->m_filter_mode = ns3::EXCLUDE;
//	this->m_lst_source_list.clear();

//	ns3::FILTER_MODE old_filter_mode = this->m_filter_mode;
//	std::list<Ipv4Address> old_src_list = this->m_lst_source_list;

	this->m_old_if_state = this->SaveOldInterfaceState ();	//saving the old state

	this->m_lst_associated_socket_state.sort();

	for (std::list<Ptr<IGMPv3SocketState> >::iterator it = this->m_lst_associated_socket_state.begin();
			it != this->m_lst_associated_socket_state.end();
			it++)
	{
		if (this->m_multicast_address != (*it)->GetGroupAddress())
		{
			//should not go here
			NS_ASSERT (false);
		}

		bool first_element = true;

		if (true == first_element)
		{
			this->m_filter_mode = (*it)->GetFilterMode();
			this->SetSrcList((*it)->GetSrcList());
		}
		else
		{
			this->Invoke (*it);
			first_element = false;
		}
	}

	//It is ethier case of change of source list or change or filter mode
	if (true == this->IsFilterModeChanged())
	{
		//todo generate state change records and send
		this->ReportFilterModeChange();
	}
	else if (true == this->IsSrcLstChanged())
	{
		//todo generate src list allow and block records and send
		this->ReportSrcLstChange();
	}
	else
	{
		//interface state is not alter by changes of socket states
	}
}

void
IGMPv3InterfaceState::ReportFilterModeChange (void)
{
	std::cout << "Interface state: " << this << " report filter mode change" << std::endl;

	Ptr<Igmpv3L4Protocol> igmp = this->GetIgmp();

	if (false == this->m_que_pending_filter_mode_chg_records.empty())
	{
		this->m_que_pending_filter_mode_chg_records = std::queue<Igmpv3GrpRecord>();
	}

	if ((false == this->m_que_pending_allow_src_chg_records.empty()) &&
			false == this->m_que_pending_block_src_chg_records.empty())
	{
		//clear both queues
		this->m_que_pending_allow_src_chg_records = std::queue<Igmpv3GrpRecord>();
		this->m_que_pending_block_src_chg_records = std::queue<Igmpv3GrpRecord>();
	}
	//two queues of records should be either that both of them are empty of or that neither of them is empty
	//ASSERT if not
	else if ((true == this->m_que_pending_allow_src_chg_records.empty()) &&
			false == this->m_que_pending_block_src_chg_records.empty())
	{
		NS_ASSERT (false);
	}
	else if ((false == this->m_que_pending_allow_src_chg_records.empty()) &&
			true == this->m_que_pending_block_src_chg_records.empty())
	{
		NS_ASSERT (false);
	}

	//create records for changes of source lists
	Igmpv3GrpRecord filter_mode_change_record = Igmpv3GrpRecord::CreateAllowRecord(this->GetOldInterfaceState(), this);

	//pushing records to queue for retransmission. One record of each queue will be pop out every time retransmission occurs
	uint8_t robustness_value = igmp->GetRobustnessValue();
	for (uint8_t count = 1; count <= robustness_value; count++)
	{
		//We push both allow and block records, even when one of them contain 0 source address for Symmetry.
		//Take them out while sending reports.
		this->m_que_pending_filter_mode_chg_records.push(filter_mode_change_record);
	}

	/*
	 * From rfc 3376
	 * To cover the possibility of the State-Change Report being missed by
   	 * one or more multicast routers, it is retransmitted [Robustness
   	 * Variable] - 1 more times, at intervals chosen at random from the
   	 * range (0, [Unsolicited Report Interval]).
	 */
	this->m_interface->ReportStateChanges();

//	*******Obsolete**********
//	if (true == this->m_event_pending_report.IsRunning())
//	{
//		//there is an un-expired sending event
//		//it means new state change occurred before all pending robustness reports are transmitted
//		Simulator::Cancel(this->m_event_pending_report);
//	}
//	else
//	{
//		//there is no pending report
//	}
//
//	std::list<Igmpv3GrpRecord> records;
//	Igmpv3GrpRecord::GenerateGrpRecords(this->m_old_if_state, this, records);
//
//	Igmpv3Report report;
//	Igmpv3Report pending_report;
//	if (this->m_lst_pending_reports.size() >= 2)
//	{
//		//there should be only pending report
//		NS_ASSERT (false);
//	}
//	else if (this->m_lst_pending_reports.size() == 1)
//	{
//		pending_report = this->m_lst_pending_reports.front();
//		this->m_lst_pending_reports.pop();
//		std::list<Igmpv3GrpRecord> pending_records;
//		uint16_t num_pending_records = pending_report.GetGrpRecords(pending_records);
//
//		if (num_pending_records != pending_records.size())
//		{
//			NS_ASSERT (false);
//		}
//
//		//not finished
//	}
//	else
//	{
//		report.SetNumGrpRecords(records.size());
//		report.PushBackGrpRecords(records);
//	}
//
//	Ptr<Packet> packet = Create<Packet>();
//	packet->AddHeader(report);
//	this->m_lst_pending_reports.push(report);
//
//	Igmpv3Header header;
//	header.SetType(Igmpv3Header::V3_MEMBERSHIP_REPORT);
//	if (true == this->m_interface->GetDevice()->GetNode()->ChecksumEnabled())
//	{
//		header.EnableChecksum();
//	}
//
//	packet->AddHeader(header);



}

//void
//IGMPv3InterfaceState::DoReportFilterModeChange (void)
//{
//
//}

void
IGMPv3InterfaceState::ReportSrcLstChange (void)
{
	std::cout << "Interface state: " << this << " report src list change" << std::endl;

	Ptr<Igmpv3L4Protocol> igmp = this->GetIgmp();

	if ((false == this->m_que_pending_allow_src_chg_records.empty()) &&
		 false == this->m_que_pending_block_src_chg_records.empty())
	{
//		*obsolete* let this->m_interface the work
//		//cancel next retransmission
//		if (true == this->m_interface->IsSendRobustnessReportRunning())
//		{
//			this->m_interface->CancelSendRobustnessReport();
//		}
//		else
//		{
//			//unknown situation
//			NS_ASSERT (false);
//		}
		//clear both queues
		this->m_que_pending_allow_src_chg_records = std::queue<Igmpv3GrpRecord>();
		this->m_que_pending_block_src_chg_records = std::queue<Igmpv3GrpRecord>();
	}
	//two queues of records should be either that both of them are empty of or that neither of them is empty
	//ASSERT if not
	else if ((true == this->m_que_pending_allow_src_chg_records.empty()) &&
			 false == this->m_que_pending_block_src_chg_records.empty())
	{
		NS_ASSERT (false);
	}
	else if ((false == this->m_que_pending_allow_src_chg_records.empty()) &&
			 true == this->m_que_pending_block_src_chg_records.empty())
	{
		NS_ASSERT (false);
	}

	//create records for changes of source lists
	Igmpv3GrpRecord allow_record = Igmpv3GrpRecord::CreateAllowRecord(this->GetOldInterfaceState(), this);
	Igmpv3GrpRecord block_record = Igmpv3GrpRecord::CreateBlockRecord(this->GetOldInterfaceState(), this);

	//pushing records to queue for retransmission. One record of each queue will be pop out every time retransmission occurs
	uint8_t robustness_value = igmp->GetRobustnessValue();
	for (uint8_t count = 1; count <= robustness_value; count++)
	{
		//We push both allow and block records, even when one of them contain 0 source address for Symmetry.
		//Take them out while sending reports.
		this->m_que_pending_allow_src_chg_records.push(allow_record);
		this->m_que_pending_block_src_chg_records.push(block_record);
	}

	//this->m_event_retransmission = Simulator::ScheduleNow (&IGMPv3InterfaceState::DoReportSrcLstChange, this);
	//this->DoReportSrcLstChange();

	/*
	 * From rfc 3376
	 * To cover the possibility of the State-Change Report being missed by
   	 * one or more multicast routers, it is retransmitted [Robustness
   	 * Variable] - 1 more times, at intervals chosen at random from the
   	 * range (0, [Unsolicited Report Interval]).
   	 *
   	 * For implementation, [Robustness Variable] records will be pushed into 3 queues (allow, block, filter mode change) of an interface state.
   	 * And then the interface will collect records, one for each queue, from all interface state it has and make them an report and send the out the report.
	 */
	this->m_interface->ReportStateChanges();
}

//void
//IGMPv3InterfaceState::DoReportSrcLstChange (void)
//{
//	Ptr<Ipv4Multicast> ipv4 = this->m_interface->GetObject<Ipv4Multicast> ();
//	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
//	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();
//
//	Igmpv3Report report;
//
//	Igmpv3GrpRecord allow_record = this->m_que_pending_allow_src_chg_records.front();
//	this->m_que_pending_allow_src_chg_records.pop();
//	Igmpv3GrpRecord block_record = this->m_que_pending_block_src_chg_records.front();
//	this->m_que_pending_block_src_chg_records.pop();
//
//	//only push records which contain source addresses into report
//	if (0 != allow_record.GetNumSrcs())
//	{
//		report.PushBackGrpRecord(allow_record);
//	}
//	if (0 != block_record.GetNumSrcs())
//	{
//		report.PushBackGrpRecord(block_record);
//	}
//	//also add previous filter mode change record into report for robustness
//	//????Question: Does the order of putting records matter, push filter mode change record at first or at last.
//	if (false == this->m_que_pending_filter_mode_chg_records.empty())
//	{
//		Igmpv3GrpRecord filter_mode_change_record = this->m_que_pending_filter_mode_chg_records.front();
//		this->m_que_pending_filter_mode_chg_records.pop();
//		report.PushBackGrpRecord(filter_mode_change_record);
//	}
//
//	Ptr<Packet> packet = Create<Packet>();
//	packet->AddHeader(report);
//
//	Igmpv3Header header;
//	header.SetType(Igmpv3Header::V3_MEMBERSHIP_REPORT);
//	if (true == this->m_interface->GetDevice()->GetNode()->ChecksumEnabled())
//	{
//		header.EnableChecksum();
//	}
//
//	packet->AddHeader(header);
//
//	igmp->SendReport(this->m_interface, packet);
//
//
//	/*
//	 * From rfc 3376
//	 * To cover the possibility of the State-Change Report being missed by
//   	 * one or more multicast routers, it is retransmitted [Robustness
//   	 * Variable] - 1 more times, at intervals chosen at random from the
//   	 * range (0, [Unsolicited Report Interval]).
//	 */
//	this->m_interface->ScheduleSendRobustnessReport();
//
////	if ((false == this->m_que_pending_allow_src_chg_records.empty()) &&
////			false == this->m_que_pending_block_src_chg_records.empty())
////	{
////		Time time_delay = igmp->GetUnsolicitedReportInterval();
////		this->m_event_robustness_retransmission = Simulator::Schedule (time_delay, &IGMPv3InterfaceState::DoReportSrcLstChange, this);
////	}
////	//two queues of records should be either that both of them are empty of or that neither of them is empty
////	//ASSERT if not
////	else if ((true == this->m_que_pending_allow_src_chg_records.empty()) &&
////			false == this->m_que_pending_block_src_chg_records.empty())
////	{
////		NS_ASSERT (false);
////	}
////	else if ((false == this->m_que_pending_allow_src_chg_records.empty()) &&
////			true == this->m_que_pending_block_src_chg_records.empty())
////	{
////		NS_ASSERT (false);
////	}
//}

//void
//IGMPv3InterfaceState::DoRobustnessRetransmission (void)
//{
//	Ptr<Ipv4Multicast> ipv4 = this->m_interface->GetObject<Ipv4Multicast> ();
//	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
//	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();
//
//	igmp->SendRobustnessReport(this->m_interface);
//
//	if (((false == this->m_que_pending_allow_src_chg_records.empty()) &&
//		  false == this->m_que_pending_block_src_chg_records.empty()) ||
//		  false == this->m_que_pending_filter_mode_chg_records.empty())
//	{
//		Time time_delay = igmp->GetUnsolicitedReportInterval();
//		this->m_event_robustness_retransmission = Simulator::Schedule (time_delay, &IGMPv3InterfaceState::DoRobustnessRetransmission, this);
//	}
//	//two queues of records should be either that both of them are empty of or that neither of them is empty
//	//ASSERT if not
//	else if ((true == this->m_que_pending_allow_src_chg_records.empty()) &&
//			false == this->m_que_pending_block_src_chg_records.empty())
//	{
//		NS_ASSERT (false);
//	}
//	else if ((false == this->m_que_pending_allow_src_chg_records.empty()) &&
//			true == this->m_que_pending_block_src_chg_records.empty())
//	{
//		NS_ASSERT (false);
//	}
//}

void
IGMPv3InterfaceState::AddPendingRecordsToReport (Igmpv3Report &report)
{
	if (false == this->m_que_pending_filter_mode_chg_records.empty())
	{
		Igmpv3GrpRecord filter_mode_change_record = this->m_que_pending_filter_mode_chg_records.front();
		this->m_que_pending_filter_mode_chg_records.pop();
		report.PushBackGrpRecord(filter_mode_change_record);
	}

	if (false == this->m_que_pending_allow_src_chg_records.empty())
	{
		Igmpv3GrpRecord allow_record = this->m_que_pending_allow_src_chg_records.front();
		this->m_que_pending_allow_src_chg_records.pop();
		report.PushBackGrpRecord(allow_record);
	}

	if (false == this->m_que_pending_block_src_chg_records.empty())
	{
		Igmpv3GrpRecord block_record = this->m_que_pending_block_src_chg_records.front();
		this->m_que_pending_block_src_chg_records.pop();
		report.PushBackGrpRecord(block_record);
	}
}

Igmpv3GrpRecord
IGMPv3InterfaceState::GenerateRecord ()
{
	Igmpv3GrpRecord record;

	return record;
}

Igmpv3GrpRecord
IGMPv3InterfaceState::GenerateRecord (ns3::FILTER_MODE old_filter_mode, std::list<Ipv4Address> const &old_src_list)
{
	Igmpv3GrpRecord record;
	if (this->m_filter_mode == old_filter_mode)
	{
		//todo generate a record of allow new source or block old source
	}
	else // this->m_filter_mode != old_filter_mode
	{
		//todo generate a record of state change
	}

	return record;
}

Ptr<IGMPv3InterfaceState>
IGMPv3InterfaceState::GetNonExistentState (Ptr<Ipv4InterfaceMulticast> interface, Ipv4Address multicast_address)
{
	/*
	 * If no interface
   	   state existed for that multicast address before the change (i.e., the
   	   change consisted of creating a new per-interface record), or if no
   	   state exists after the change (i.e., the change consisted of deleting
   	   a per-interface record), then the "non-existent" state is considered
   	   to have a filter mode of INCLUDE and an empty source list.
	 */
	Ptr<IGMPv3InterfaceState> if_state = Create<IGMPv3InterfaceState>();
	if_state->m_filter_mode = ns3::INCLUDE;
	if_state->m_multicast_address = multicast_address;
	if_state->m_interface = interface;

	return if_state;
}

void
IGMPv3InterfaceState::Invoke (Ptr<IGMPv3SocketState> socket_state)
{
	if (socket_state == 0)
	{
		NS_ASSERT (false);
	}

	Ipv4Address group_address = socket_state->GetGroupAddress();
	ns3::FILTER_MODE filter_mode = socket_state->GetFilterMode();
	std::list<Ipv4Address> source_list = socket_state->GetSrcList();

	if (group_address == this->m_multicast_address)
	{
		if (filter_mode == ns3::EXCLUDE)
		{
			if (this->m_filter_mode == ns3::EXCLUDE)	//invocation EXCLUDE, this EXCLUDE
			{
				if (true == source_list.empty())
				{
					this->m_lst_source_list.clear();
				}
				else
				{
					source_list.sort();
					this->m_lst_source_list.sort();
					std::list<Ipv4Address> new_src_lst = Igmpv3L4Protocol::ListIntersection(source_list, this->m_lst_source_list);
					this->m_lst_source_list = new_src_lst;
				}
			}
			else if (this->m_filter_mode == ns3::INCLUDE)	//invocation EXCLUDE, this INCLUDE
			{
				//may not reach here

				if (true == source_list.empty())
				{
					this->m_lst_source_list.clear();
					this->m_filter_mode = ns3::EXCLUDE;
				}
				else
				{
					source_list.sort();
					this->m_lst_source_list.sort();
					//incoming source list (EXCLUDE list) - this source list (INCLUDE list)
					std::list<Ipv4Address> new_src_lst = Igmpv3L4Protocol::ListSubtraction(source_list, this->m_lst_source_list);
					this->m_lst_source_list = new_src_lst;
					this->m_filter_mode = ns3::EXCLUDE;
				}
			}
			else
			{
				//should not go here.
				NS_ASSERT(false);
			}
		}
		else if (filter_mode == ns3::INCLUDE)
		{
			if (this->m_filter_mode == ns3::INCLUDE)	//invocation INCLUDE, this INCLUDE
			{
				//same action for true == source_list.empty() and false == source_list.empty()
				source_list.sort();
				this->m_lst_source_list.sort();
				std::list<Ipv4Address> new_src_lst = Igmpv3L4Protocol::ListUnion(source_list, this->m_lst_source_list);
				this->m_lst_source_list = new_src_lst;
			}
			else if (this->m_filter_mode == ns3::EXCLUDE)	//invocation INCLUDE, this EXCLUDE
			{
				//obsoleted, socket states that have filter mode EXCLUDE should and will always be invoked before ones have mode INCLUDE
				NS_ASSERT (false);

//				source_list.sort();
//				this->m_lst_source_list.sort();
//				//this source list (EXCLUDE list) - incoming source list (INCLUDE list)
//				std::list<Ipv4Address> new_src_lst = Igmpv3L4Protocol::ListSubtraction(source_list, this->m_lst_source_list);
//				this->m_lst_source_list = new_src_lst;

				//					//check whether all subscribed sockets are of INCLUDE mode
				//					if (this->CheckSubscribedAllSocketsIncludeMode())
				//					{
				//						//if true, change filter mode of this interface to INCLUDE
				//						this->m_filter_mode = ns3::INCLUDE;
				//					}
			}
			else	//filter_mode != INCLUDE and filter_mode != EXCLUDE
			{
				//should not go here.
				NS_ASSERT(false);
			}
		}
		else	//filter_mode != INCLUDE and filter_mode != EXCLUDE
		{
			//should not go here
			NS_ASSERT(false);
		}
	}
	else
	{
		//should not go here
		//group_address != this->m_multicast_address
		NS_ASSERT (false);
	}
}

void
IGMPv3InterfaceState::AssociateSocketStateInterfaceState (Ptr<IGMPv3SocketState> socket_state)
{
	if (true == this->IsSocketStateExist(socket_state))
	{
		return;
	}
	else
	{
		if (0 == socket_state->GetAssociatedInterfaceState())
		{
			socket_state->SetAssociatedInterfaceState(this);
		}
		else if (socket_state->GetAssociatedInterfaceState() == this)
		{
			//ok, when being used by this->RecomputeState()
			//do nothing
		}
		else
		{
			//should not go here
			NS_ASSERT (false);
		}

		this->m_lst_associated_socket_state.push_back(socket_state);
		return;
	}
}

bool
IGMPv3InterfaceState::IsSocketStateExist (Ptr<IGMPv3SocketState> socket_state) const
{

	for (std::list<Ptr<IGMPv3SocketState> >::const_iterator const_it = this->m_lst_associated_socket_state.begin();
			const_it != this->m_lst_associated_socket_state.end();
			const_it++)
	{
		//check whether the incoming socket has already in the list of sockets of interfacestate
		if (socket_state == (*const_it))
		{
			//do nothing
			return true;
		}
	}

	return false;

}

bool
IGMPv3InterfaceState::CheckSubscribedAllSocketsIncludeMode (void)
{
	for (std::list<Ptr<IGMPv3SocketState> >::iterator it = this->m_lst_associated_socket_state.begin();
			it != this->m_lst_associated_socket_state.end();
			it++)
	{
		Ptr<IGMPv3SocketState> socket_state = *it;
		if (ns3::EXCLUDE == socket_state->GetFilterMode())
		{
			return false;
		}
		else if (ns3::INCLUDE == socket_state->GetFilterMode())
		{
			continue;	//do nothing
		}
		else
		{
			//should not go here.
			NS_ASSERT(false);
		}
	}

	return true;
}


Ptr<IGMPv3InterfaceState>
IGMPv3InterfaceState::SaveOldInterfaceState (void)
{
	Ptr<IGMPv3InterfaceState> old_if_state = Create<IGMPv3InterfaceState>();
	old_if_state->m_filter_mode = this->m_filter_mode;
	old_if_state->m_interface = this->m_interface;
	old_if_state->m_lst_source_list = this->m_lst_source_list;
	old_if_state->m_multicast_address = this->m_multicast_address;
	//old state's m_old_if_state has to be 0;
	old_if_state->m_old_if_state = 0;
	//old_state"s socketstate list has no objects

	return old_if_state;
}

Ptr<IGMPv3InterfaceState>
IGMPv3InterfaceState::GetOldInterfaceState (void) const
{
	if (0 != this->m_old_if_state)
	{
		return this->m_old_if_state;
	}
	else
	{
		return IGMPv3InterfaceState::GetNonExistentState(this->m_interface, this->m_multicast_address);
	}
}

Ptr<Igmpv3L4Protocol>
IGMPv3InterfaceState::GetIgmp (void)
{
	Ptr<Ipv4Multicast> ipv4 = this->m_interface->GetDevice()->GetNode()->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();

	return igmp;
}

/********************************************************
 *        IGMPv3MaintenanceSrcRecord
 ********************************************************/
TypeId
IGMPv3MaintenanceSrcRecord::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IGMPv3MaintenanceSrcRecord")
		    		.SetParent<Object> ()
					//.SetGroupName("Internet")
					.AddConstructor<IGMPv3MaintenanceSrcRecord> ();
	return tid;
}

IGMPv3MaintenanceSrcRecord::IGMPv3MaintenanceSrcRecord (void)
  :  m_group_state (0),
	 m_source_address (Ipv4Address ("0.0.0.0")),
	 m_uint_retransmission_state (0)
{

}

IGMPv3MaintenanceSrcRecord::~IGMPv3MaintenanceSrcRecord (void)
{

}

Ipv4Address
IGMPv3MaintenanceSrcRecord::GetMulticastAddress (void) const
{
	return this->m_source_address;
}

uint8_t
IGMPv3MaintenanceSrcRecord::GetRetransmissionState (void)
{
	return this->m_uint_retransmission_state;
}

void
IGMPv3MaintenanceSrcRecord::DecreaseRetransmissionState (void)
{
	this->m_uint_retransmission_state--;
}

void
IGMPv3MaintenanceSrcRecord::SetRetransmissionState (uint8_t state)
{
	this->m_uint_retransmission_state = state;
}

bool
operator == (IGMPv3MaintenanceSrcRecord const& lhs, IGMPv3MaintenanceSrcRecord const& rhs)
{
	if (lhs.GetMulticastAddress() == rhs.GetMulticastAddress())
	{
		return true;
	}
	else
	{
		return false;
	}
}

void
IGMPv3MaintenanceSrcRecord::Initialize (Ptr<IGMPv3MaintenanceState> group_state, Ipv4Address src_address, Time delay)
{
	this->m_group_state = group_state;
	this->m_source_address = src_address;
	this->m_srcTimer.SetFunction(&IGMPv3MaintenanceSrcRecord::TimerExpire, this);
	this->m_srcTimer.Schedule(delay);
}

void
IGMPv3MaintenanceSrcRecord::TimerExpire (void)
{
	if (this->m_group_state->GetFilterMode() == ns3::INCLUDE) {
		this->m_group_state->DeleteSrcRecord(this->GetMulticastAddress());
	}
	else if(this->m_group_state->GetFilterMode() == ns3::EXCLUDE)
	{
		//do nothing
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
IGMPv3MaintenanceSrcRecord::UpdateTimer (Time delay)
{
	this->m_srcTimer.Cancel();
	this->m_srcTimer.SetDelay(delay);
	//only schedule delay > 0
	if (delay > Seconds(0.0))
	{
		this->m_srcTimer.Schedule();
	}
}

Time
IGMPv3MaintenanceSrcRecord::GetDelayLeft (void) const
{
	return this->m_srcTimer.GetDelayLeft();
}

bool
IGMPv3MaintenanceSrcRecord::IsTimerRunning (void)
{
	return this->m_srcTimer.IsRunning();
}

/********************************************************
 *        IGMPv3MaintenanceState
 ********************************************************/
TypeId
IGMPv3MaintenanceState::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IGMPv3MaintenanceState")
		    		.SetParent<Object> ()
					//.SetGroupName("Internet")
					.AddConstructor<IGMPv3MaintenanceState> ();
	return tid;
}

IGMPv3MaintenanceState::IGMPv3MaintenanceState ()
  :  m_multicast_address (Ipv4Address ("0.0.0.0")),
	 m_filter_mode (ns3::INCLUDE)
{

}
IGMPv3MaintenanceState::~IGMPv3MaintenanceState ()
{

}

void
IGMPv3MaintenanceState::Initialize (Ptr<Ipv4InterfaceMulticast> interface, Ipv4Address group_address, Time delay)
{
	this->m_filter_mode = ns3::INCLUDE;
	this->m_interface = interface;
	this->m_multicast_address = group_address;

	this->m_groupTimer.SetFunction(&IGMPv3MaintenanceState::TimerExpire, this);
	this->m_groupTimer.Schedule(delay);
}

Ipv4Address
IGMPv3MaintenanceState::GetMulticastAddress (void) const
{
	return this->m_multicast_address;
}

void
IGMPv3MaintenanceState::GetCurrentSrcLst (std::list<Ipv4Address> &retval) const
{
	for (std::list<Ptr<IGMPv3MaintenanceSrcRecord> >::const_iterator const_it = this->m_lst_src_records.begin();
		 const_it !=this->m_lst_src_records.end();
		 const_it++)
	{
		retval.push_back((*const_it)->GetMulticastAddress());
	}
}

void
IGMPv3MaintenanceState::GetCurrentSrcLstTimerGreaterThanZero (std::list<Ipv4Address> &retval) const
{
	for (std::list<Ptr<IGMPv3MaintenanceSrcRecord> >::const_iterator const_it = this->m_lst_src_records.begin();
		 const_it !=this->m_lst_src_records.end();
		 const_it++)
	{
		if ((*const_it)->GetDelayLeft() > Seconds(0.0))
		{
			retval.push_back((*const_it)->GetMulticastAddress());
		}
		else if ((*const_it)->GetDelayLeft() < Seconds(0.0))
		{
			NS_ASSERT (false);
		}
	}
}
void
IGMPv3MaintenanceState::GetCurrentSrcLstTimerEqualToZero (std::list<Ipv4Address> &retval) const
{
	for (std::list<Ptr<IGMPv3MaintenanceSrcRecord> >::const_iterator const_it = this->m_lst_src_records.begin();
		 const_it !=this->m_lst_src_records.end();
		 const_it++)
	{
		if ((*const_it)->GetDelayLeft() == Seconds(0.0))
		{
			retval.push_back((*const_it)->GetMulticastAddress());
		}
		else if ((*const_it)->GetDelayLeft() < Seconds(0.0))
		{
			NS_ASSERT (false);
		}
	}
}

ns3::FILTER_MODE
IGMPv3MaintenanceState::GetFilterMode (void)
{
	return this->m_filter_mode;
}

void
IGMPv3MaintenanceState::DeleteSrcRecord (Ipv4Address src)
{
	std::list<Ptr<IGMPv3MaintenanceSrcRecord> >::iterator it = this->m_lst_src_records.begin();

	while (it != this->m_lst_src_records.end())
	{
		if ((*it)->GetMulticastAddress() == src)
		{
			it = this->m_lst_src_records.erase(it);
			continue;
		}
		it++;
	}
}

void
IGMPv3MaintenanceState::DeleteSrcRecords (std::list<Ipv4Address> const &src_lst)
{
	for (std::list<Ipv4Address>::const_iterator const_it = src_lst.begin();
		 const_it != src_lst.end();
		 const_it++)
	{
		this->DeleteSrcRecord((*const_it));
	}
}

void
IGMPv3MaintenanceState::AddSrcRecord (Ipv4Address src_address, Time delay)
{
	Ptr<IGMPv3MaintenanceSrcRecord> src_record = Create<IGMPv3MaintenanceSrcRecord>();
	src_record->Initialize(this, src_address, delay);
	this->m_lst_src_records.push_back(src_record);
}

void
IGMPv3MaintenanceState::AddSrcRecords (std::list<Ipv4Address> const &src_lst, Time delay)
{
	for (std::list<Ipv4Address>::const_iterator const_it = src_lst.begin();
		 const_it != src_lst.end();
		 const_it++)
	{
		this->AddSrcRecord((*const_it), delay);
	}
}

void
IGMPv3MaintenanceState::UpdateGrpTimer (Time delay)
{
	this->m_groupTimer.Cancel();
	this->m_groupTimer.SetDelay(delay);
	//only schedule delay > 0
	if (delay > Seconds(0.0))
	{
		this->m_groupTimer.Schedule();
	}
}

void
IGMPv3MaintenanceState::SetFilterMode (ns3::FILTER_MODE filter_mode)
{
	if (filter_mode == ns3::INCLUDE)
	{

	}
	else if (filter_mode == ns3::EXCLUDE)
	{

	}
	else
	{
		NS_ASSERT (false);
	}

	this->m_filter_mode = filter_mode;
}

Time
IGMPv3MaintenanceState::GetGroupMembershipIntervalGMI (void)
{
	Ptr<Igmpv3L4Protocol> igmp = this->GetIgmp();

	return igmp->GetGroupMembershipIntervalGMI();
}

Time
IGMPv3MaintenanceState::GetLastMemberQueryTimeLMQT (void)
{
	Ptr<Igmpv3L4Protocol> igmp = this->GetIgmp();

	return igmp->GetLastMemberQueryTimeLMQT();
}

Time
IGMPv3MaintenanceState::GetLastMemberQueryInterval (void)
{
	Ptr<Igmpv3L4Protocol> igmp = this->GetIgmp();

	return igmp->GetLastMemberQueryInterval();
}

uint8_t
IGMPv3MaintenanceState::GetLastMemberQueryCount (void)
{
	Ptr<Igmpv3L4Protocol> igmp = this->GetIgmp();

	return igmp->GetLastMemberQueryCount();
}

void
IGMPv3MaintenanceState::HandleGrpRecord (const Igmpv3GrpRecord &record)
{

	if (this->GetFilterMode() == ns3::INCLUDE)
	{
		std::list<Ipv4Address> src_lst_A;
		this->GetCurrentSrcLst(src_lst_A);

		std::list<Ipv4Address> src_lst_B;
		uint16_t num_src_list_B = record.GetSrcAddresses(src_lst_B);
		if (num_src_list_B != src_lst_B.size())
		{
			NS_ASSERT (false);
		}

		//IGMPv3 section 6.4.1
		//Reception of Current-State Records
		if (record.GetType() == Igmpv3GrpRecord::MODE_IS_INCLUDE)
		{
			/*
			 * Router State   Report Rec'd  New Router State         Actions
   	   	   	 * ------------   ------------  ----------------         -------
   	   	   	 * INCLUDE (A)    IS_IN (B)     INCLUDE (A+B)            (B)=GMI
			 */

			this->UpdateSrcRecords(src_lst_B, this->GetGroupMembershipIntervalGMI());

		}
		else if (record.GetType() == Igmpv3GrpRecord::MODE_IS_EXCLUDE)
		{
			/*
			 * Router State   Report Rec'd  New Router State         Actions
			 * ------------   ------------  ----------------         -------
			 * INCLUDE (A)    IS_EX (B)     EXCLUDE (A*B,B-A)        (B-A)=0
			 *                                            	 	 	 Delete (A-B)
			 *                                            	 	 	 Group Timer=GMI
			 */

			this->SetFilterMode(ns3::EXCLUDE);

			//(B-A)=0
			std::list<Ipv4Address> src_lst_B_minus_A = Igmpv3L4Protocol::ListSubtraction (src_lst_B, src_lst_A);
			this->UpdateSrcRecords(src_lst_B_minus_A, Seconds(0.0));

			//Delete (A-B), (A*B) > 0
			std::list<Ipv4Address> src_lst_A_minus_B = Igmpv3L4Protocol::ListSubtraction (src_lst_A, src_lst_B);
			this->DeleteSrcRecords(src_lst_A_minus_B);

			//Group Timer=GMI
			this->UpdateGrpTimer(this->GetGroupMembershipIntervalGMI());
		}
		//Section: 6.4.2. Reception of Filter-Mode-Change and Source-List-Change Records
		else if (record.GetType() == Igmpv3GrpRecord::ALLOW_NEW_SOURCES)
		{
			/*
			 * Router State   Report Rec'd New Router State        Actions
			 * ------------   ------------ ----------------        -------
			 * INCLUDE (A)    ALLOW (B)    INCLUDE (A+B)           (B)=GMI
			 */

			//(B)=GMI
			this->UpdateSrcRecords(src_lst_B, this->GetGroupMembershipIntervalGMI());
		}
		else if (record.GetType() == Igmpv3GrpRecord::BLOCK_OLD_SOURCES)
		{
			/*
			 * Router State   Report Rec'd New Router State        Actions
			 * ------------   ------------ ----------------        -------
			 * INCLUDE (A)    BLOCK (B)    INCLUDE (A)             Send Q(G,A*B)
			 */

			//Send Q(G,A*B)
			std::list<Ipv4Address> src_lst_AxB = Igmpv3L4Protocol::ListIntersection(src_lst_B, src_lst_A);
			this->SendQuery(this->GetMulticastAddress(), src_lst_AxB);

		}
		else if (record.GetType() == Igmpv3GrpRecord::CHANGE_TO_EXCLUDE_MODE)
		{
			/*
			 * Router State   Report Rec'd New Router State        Actions
			 * ------------   ------------ ----------------        -------
			 * INCLUDE (A)    TO_EX (B)    EXCLUDE (A*B,B-A)       (B-A)=0
             *                                       			   Delete (A-B)
             *                                       			   Send Q(G,A*B)
             *                                       			   Group Timer=GMI
			 */

			this->SetFilterMode(ns3::EXCLUDE);

			//(B-A)=0
			std::list<Ipv4Address> src_lst_B_minus_A = Igmpv3L4Protocol::ListSubtraction(src_lst_B, src_lst_A);
			this->UpdateSrcRecords(src_lst_B_minus_A, Seconds(0.0));

			//Delete (A-B)
			std::list<Ipv4Address> src_lst_A_minus_B = Igmpv3L4Protocol::ListSubtraction(src_lst_A, src_lst_B);
			this->DeleteSrcRecords(src_lst_A_minus_B);

			//Send Q(G,A*B)
			std::list<Ipv4Address> src_lst_AxB = Igmpv3L4Protocol::ListIntersection(src_lst_B, src_lst_A);
			this->SendQuery(this->GetMulticastAddress(), src_lst_AxB);

			//Group Timer=GMI
			this->UpdateGrpTimer(this->GetGroupMembershipIntervalGMI());

		}
		else if (record.GetType() == Igmpv3GrpRecord::CHANGE_TO_INCLUDE_MODE)
		{
			/*
			 * Router State   Report Rec'd New Router State        Actions
			 * ------------   ------------ ----------------        -------
			 * INCLUDE (A)    TO_EX (B)    EXCLUDE (A*B,B-A)       (B)=GMI
			 *                                       			   Send Q(G,A-B)
			 */

			this->UpdateSrcRecords(src_lst_B, this->GetGroupMembershipIntervalGMI());

		}
		else
		{
			NS_ASSERT (false);
		}
	}
	else if (this->GetFilterMode() == ns3::EXCLUDE)
	{
		std::list<Ipv4Address> src_lst_A;
		uint16_t num_src_list_A = record.GetSrcAddresses(src_lst_A);
		if (num_src_list_A != src_lst_A.size())
		{
			NS_ASSERT (false);
		}

		std::list<Ipv4Address> src_lst_X;
		this->GetCurrentSrcLstTimerGreaterThanZero(src_lst_X);

		std::list<Ipv4Address> src_lst_Y;
		this->GetCurrentSrcLstTimerEqualToZero(src_lst_Y);

		//IGMPv3 section 6.4.1
		//Reception of Current-State Records
		if (record.GetType() == Igmpv3GrpRecord::MODE_IS_INCLUDE)
		{
			/*
			 * Router State   Report Rec'd  New Router State         Actions
			 * ------------   ------------  ----------------         -------
			 * EXCLUDE (X,Y)  IS_IN (A)     EXCLUDE (X+A,Y-A)        (A)=GMI
			 */

			this->UpdateSrcRecords(src_lst_A, this->GetGroupMembershipIntervalGMI());


		}
		else if (record.GetType() == Igmpv3GrpRecord::MODE_IS_EXCLUDE)
		{
			/*
			 * Router State   Report Rec'd  New Router State         Actions
			 * ------------   ------------  ----------------         -------
			 * EXCLUDE (X,Y)  IS_EX (A)     EXCLUDE (A-Y,Y*A)        (A-X-Y)=GMI
             *                                            	 	     Delete (X-A)
             *                                                   	 Delete (Y-A)
             *                                            			 Group Timer=GMI
			 */

			//(A-X-Y)=GMI

			std::list<Ipv4Address> src_lst_A_minus_X = Igmpv3L4Protocol::ListSubtraction (src_lst_A, src_lst_X);
			std::list<Ipv4Address> src_lst_A_minus_X_minus_Y = Igmpv3L4Protocol::ListSubtraction (src_lst_A_minus_X, src_lst_Y);
			this->UpdateSrcRecords(src_lst_A_minus_X_minus_Y, this->GetGroupMembershipIntervalGMI());

			//Delete (X-A)
			std::list<Ipv4Address> src_lst_X_minus_A = Igmpv3L4Protocol::ListSubtraction (src_lst_X, src_lst_A);
			this->DeleteSrcRecords(src_lst_X_minus_A);
			//Delete (Y-A)
			std::list<Ipv4Address> src_lst_Y_minus_A = Igmpv3L4Protocol::ListSubtraction (src_lst_Y, src_lst_A);
			this->DeleteSrcRecords(src_lst_Y_minus_A);

			//Group Timer=GMI
			this->UpdateGrpTimer(this->GetGroupMembershipIntervalGMI());
		}
		//6.4.2. Reception of Filter-Mode-Change and Source-List-Change Records
		else if (record.GetType() == Igmpv3GrpRecord::ALLOW_NEW_SOURCES)
		{
			/*
			 * Router State   Report Rec'd New Router State        Actions
			 * ------------   ------------ ----------------        -------
			 * EXCLUDE (X,Y)  ALLOW (A)    EXCLUDE (X+A,Y-A)       (A)=GMI
			 */

			//(A)=GMI
			this->UpdateSrcRecords(src_lst_A, this->GetGroupMembershipIntervalGMI());
		}
		else if (record.GetType() == Igmpv3GrpRecord::BLOCK_OLD_SOURCES)
		{
			/*
			 * Router State   Report Rec'd New Router State        Actions
			 * ------------   ------------ ----------------        -------
			 * EXCLUDE (X,Y)  BLOCK (A)    EXCLUDE (X+(A-Y),Y)     (A-X-Y)=Group Timer
			 * 													   Send Q(G,A-Y)
			 */

			//(A-X-Y)=Group Timer
			std::list<Ipv4Address> src_lst_A_minus_X = Igmpv3L4Protocol::ListSubtraction(src_lst_A, src_lst_X);
			std::list<Ipv4Address> src_lst_A_minus_X_minus_Y = Igmpv3L4Protocol::ListSubtraction(src_lst_A_minus_X, src_lst_Y);
			this->UpdateSrcRecords(src_lst_A_minus_X_minus_Y, this->m_groupTimer.GetDelayLeft());

			//Send Q(G,A-Y)
			std::list<Ipv4Address> src_lst_A_minus_Y = Igmpv3L4Protocol::ListSubtraction(src_lst_A, src_lst_Y);
			this->SendQuery(this->GetMulticastAddress(), src_lst_A_minus_Y);

		}
		else if (record.GetType() == Igmpv3GrpRecord::CHANGE_TO_EXCLUDE_MODE)
		{
			/*
			 * Router State   Report Rec'd New Router State        Actions
			 * ------------   ------------ ----------------        -------
			 * EXCLUDE (X,Y)  TO_EX (A)    EXCLUDE (A-Y,Y*A)       (A-X-Y)=Group Timer
			 * 													   Delete (X-A)
			 * 													   Delete (Y-A)
			 * 													   Send Q(G,A-Y)
			 * 													   Group Timer=GMI
			 */

			//(A-X-Y)=Group Timer
			std::list<Ipv4Address> src_lst_A_minus_X = Igmpv3L4Protocol::ListSubtraction(src_lst_A, src_lst_X);
			std::list<Ipv4Address> src_lst_A_minus_X_minus_Y = Igmpv3L4Protocol::ListSubtraction(src_lst_A_minus_X, src_lst_Y);
			this->UpdateSrcRecords(src_lst_A_minus_X_minus_Y, this->m_groupTimer.GetDelayLeft());

			//Delete (X-A)
			std::list<Ipv4Address> src_lst_X_minus_A = Igmpv3L4Protocol::ListSubtraction(src_lst_X, src_lst_A);
			this->DeleteSrcRecords(src_lst_X_minus_A);

			//Delete (Y-A)
			std::list<Ipv4Address> src_lst_Y_minus_A = Igmpv3L4Protocol::ListSubtraction(src_lst_Y, src_lst_A);
			this->DeleteSrcRecords(src_lst_Y_minus_A);

			//Send Q(G,A-Y)
			std::list<Ipv4Address> src_lst_A_minus_Y = Igmpv3L4Protocol::ListSubtraction(src_lst_A, src_lst_Y);
			this->SendQuery(this->GetMulticastAddress(), src_lst_A_minus_Y);

			//Group Timer=GMI
			this->UpdateGrpTimer(this->GetGroupMembershipIntervalGMI());

		}
		else if (record.GetType() == Igmpv3GrpRecord::CHANGE_TO_INCLUDE_MODE)
		{
			/*
			 * Router State   Report Rec'd New Router State        Actions
			 * ------------   ------------ ----------------        -------
			 * EXCLUDE (X,Y)  TO_IN (A)    EXCLUDE (X+A,Y-A)       (A)=GMI
			 * 													   Send Q(G,X-A)
			 * 													   Send Q(G)
			 */

			//(A)=GMI
			this->UpdateSrcRecords(src_lst_A, this->GetGroupMembershipIntervalGMI());

			//Send Q(G,X-A)
			std::list<Ipv4Address> src_lst_X_minus_A = Igmpv3L4Protocol::ListSubtraction(src_lst_X, src_lst_A);
			this->SendQuery(this->GetMulticastAddress(), src_lst_X_minus_A);

			//Send Q(G)
			this->SendQuery(this->GetMulticastAddress());

		}
		else
		{
			NS_ASSERT (false);
		}
	}
	else
	{
		NS_ASSERT (false);
	}
}

void
IGMPv3MaintenanceState::HandleQuery (void)
{
	this->LowerGrpTimer(this->GetLastMemberQueryTimeLMQT());
}
void
IGMPv3MaintenanceState::HandleQuery (std::list<Ipv4Address> const &src_lst)
{
	this->LowerSrcTimer(src_lst, this->GetLastMemberQueryTimeLMQT());
}

void
IGMPv3MaintenanceState::UpdateSrcTimers (std::list<Ipv4Address> const &src_lst, Time delay)
{
	for (std::list<Ptr<IGMPv3MaintenanceSrcRecord> >::iterator src_record_it = this->m_lst_src_records.begin();
		 src_record_it != this->m_lst_src_records.end();
		 src_record_it++)
	{
		for (std::list<Ipv4Address>::const_iterator const_src_it = src_lst.begin();
			 const_src_it != src_lst.end();
			 const_src_it++)
		{
			if ((*src_record_it)->GetMulticastAddress() == (*const_src_it))
			{
				(*src_record_it)->UpdateTimer(delay);
			}
		}
	}
}

void
IGMPv3MaintenanceState::UpdateSrcRecords (std::list<Ipv4Address> const &src_lst, Time delay)
{
	std::list<Ipv4Address> add_src_lst;
	for (std::list<Ipv4Address>::const_iterator const_it = src_lst.begin();
		 const_it != src_lst.end();
		 const_it++)
	{
		add_src_lst.push_back(*const_it);
	}
	
	std::list<Ipv4Address> current_src_lst;
	this->GetCurrentSrcLst(current_src_lst);

	std::list<Ipv4Address> change_src_lst;

	for (std::list<Ipv4Address>::const_iterator const_it = current_src_lst.begin();
		 const_it != current_src_lst.end();
		 const_it++)
	{
		std::list<Ipv4Address>::iterator it = add_src_lst.begin();

		while (it != add_src_lst.end())
		{
			if ((*it) == ((*const_it)))	//there is a match between incoming src list and current src list
			{
				change_src_lst.push_back(*it);
				it = add_src_lst.erase(it);
				continue;	//skip it++ below
			}
			it++;
		}
	}

	this->UpdateSrcTimers(change_src_lst, delay);
	this->AddSrcRecords(add_src_lst, delay);
}

void
IGMPv3MaintenanceState::SendQuery (Ipv4Address group_address, std::list<Ipv4Address> const &src_lst)
{
	/*
	 * o Set number of retransmissions for each source to [Last Member Query
     Count].

   	 * o Lower source timer to LMQT.
	 */
	this->SetSrcRecordsRetransmissionStates(src_lst, this->GetLastMemberQueryCount());
	this->LowerSrcTimer(src_lst, this->GetLastMemberQueryTimeLMQT());

	EventId event_retranmission = Simulator::ScheduleNow(&IGMPv3MaintenanceState::DoSendGroupNSrcSpecificQuery,
													  this,
													  group_address,
													  src_lst);

}

void
IGMPv3MaintenanceState::DoSendGroupNSrcSpecificQuery (Ipv4Address group_address, std::list<Ipv4Address> const &src_lst)
{
	std::list<Ipv4Address> src_lst_greater_LMQT;
	this->GetSrcRetransWTimerGreaterThanLMQT(src_lst_greater_LMQT);

	std::list<Ipv4Address> src_lst_smaller_equal_LMQT;
	this->GetSrcRetransWTimerLowerOrEqualToLMQT(src_lst_smaller_equal_LMQT);

	if ((false == src_lst_greater_LMQT.empty()) &&
		(false == src_lst_smaller_equal_LMQT.empty()))
	{
		this->m_interface->SendQuery(this->GetMulticastAddress(),
									 src_lst_greater_LMQT,
									 true);

		this->m_interface->SendQuery(this->GetMulticastAddress(),
									 src_lst_smaller_equal_LMQT,
									 false);

		this->DecreaseSrcRecordsRetransmissionStates(src_lst_greater_LMQT);
		this->DecreaseSrcRecordsRetransmissionStates(src_lst_smaller_equal_LMQT);

		EventId event_retranmission = Simulator::Schedule(this->GetLastMemberQueryInterval(),
														  &IGMPv3MaintenanceState::DoSendGroupNSrcSpecificQuery,
														  this,
														  group_address,
														  src_lst);

	}
	else
	{
		//do nothing suppress the transmission;
	}

}

void
IGMPv3MaintenanceState::SendQuery (Ipv4Address group_address)
{
	if (this->m_groupTimer.GetDelayLeft() > this->GetLastMemberQueryTimeLMQT())
	{
		this->m_interface->SendQuery(group_address, true);
	}
	else
	{
		this->m_interface->SendQuery(group_address, false);
	}

	this->LowerGrpTimer(this->GetLastMemberQueryTimeLMQT());

	this->m_uint_retransmission_state = this->GetLastMemberQueryCount() - 1;

	EventId event_retranmission = Simulator::Schedule(this->GetLastMemberQueryInterval(),
													  &IGMPv3MaintenanceState::DoSendGroupSpecificQuery,
													  this,
													  group_address);
}

void
IGMPv3MaintenanceState::DoSendGroupSpecificQuery (Ipv4Address group_address)
{
	if (this->m_uint_retransmission_state > 0)
	{
		if (this->m_groupTimer.GetDelayLeft() > this->GetLastMemberQueryTimeLMQT())
		{
			this->m_interface->SendQuery(group_address, true);
		}
		else
		{
			this->m_interface->SendQuery(group_address, false);
		}

		this->LowerGrpTimer(this->GetLastMemberQueryTimeLMQT());

		this->m_uint_retransmission_state--;
	}
}

void
IGMPv3MaintenanceState::TimerExpire (void)
{
	if (this->GetFilterMode() == ns3::EXCLUDE)
	{
		this->DeleteExpiredSrcRecords();
		this->SetFilterMode(ns3::INCLUDE);
	}
}

void
IGMPv3MaintenanceState::DeleteExpiredSrcRecords (void)
{
	std::list<Ptr<IGMPv3MaintenanceSrcRecord> >::iterator it = this->m_lst_src_records.begin();

	while (it != this->m_lst_src_records.end())
	{
		Ptr<IGMPv3MaintenanceSrcRecord> src_record = (*it);
		if (false == src_record->IsTimerRunning())
		{
			it = this->m_lst_src_records.erase(it);
			continue;	//skip it++
		}
		it++;
	}

}

void
IGMPv3MaintenanceState::LowerGrpTimer (Time delay)
{
	/*
	 * Query      Action
     * -----      ------
     * Q(G)       Group Timer is lowered to LMQT
	 */

	if (this->m_groupTimer.GetDelayLeft() < delay)
	{
		this->UpdateGrpTimer(delay);
	}
	else
	{
		//do nothing
	}
}

void
IGMPv3MaintenanceState::LowerSrcTimer (std::list<Ipv4Address> const &src_lst, Time delay)
{
	/*
	 * Query      Action
     * -----      ------
     * Q(G,A)     Source Timer for sources in A are lowered to LMQT
	 */

	for (std::list<Ptr<IGMPv3MaintenanceSrcRecord> >::iterator src_record_it = this->m_lst_src_records.begin();
			src_record_it != this->m_lst_src_records.end();
			src_record_it++)
	{
		for (std::list<Ipv4Address>::const_iterator const_src_it = src_lst.begin();
				const_src_it != src_lst.end();
				const_src_it++)
		{
			if ((*src_record_it)->GetMulticastAddress() == (*const_src_it))
			{
				if ((*src_record_it)->GetDelayLeft() < delay)
				{
					(*src_record_it)->UpdateTimer(delay);
				}
				else
				{
					//do nothing
				}
			}
		}
	}

	if (this->m_groupTimer.GetDelayLeft() < delay)
	{
		this->UpdateGrpTimer(delay);
	}
	else
	{
		//do nothing
	}
}

void
IGMPv3MaintenanceState::SetSrcRecordsRetransmissionStates (std::list<Ipv4Address> const &src_lst, uint8_t state)
{
	for (std::list<Ptr<IGMPv3MaintenanceSrcRecord> >::iterator src_record_it = this->m_lst_src_records.begin();
			src_record_it != this->m_lst_src_records.end();
			src_record_it++)
	{
		for (std::list<Ipv4Address>::const_iterator const_src_it = src_lst.begin();
				const_src_it != src_lst.end();
				const_src_it++)
		{
			if ((*src_record_it)->GetMulticastAddress() == (*const_src_it))
			{
				(*src_record_it)->SetRetransmissionState(state);
			}
		}
	}
}

void
IGMPv3MaintenanceState::DecreaseSrcRecordsRetransmissionStates (std::list<Ipv4Address> const &src_lst)
{
	for (std::list<Ptr<IGMPv3MaintenanceSrcRecord> >::const_iterator src_record_it = this->m_lst_src_records.begin();
			src_record_it != this->m_lst_src_records.end();
			src_record_it++)
	{
		for (std::list<Ipv4Address>::const_iterator const_src_it = src_lst.begin();
				const_src_it != src_lst.end();
				const_src_it++)
		{
			if ((*src_record_it)->GetMulticastAddress() == (*const_src_it))
			{
				(*src_record_it)->DecreaseRetransmissionState();
			}
		}
	}

}

void
IGMPv3MaintenanceState::GetSrcRetransWTimerGreaterThanLMQT (std::list<Ipv4Address>& retval)
{
	for (std::list<Ptr<IGMPv3MaintenanceSrcRecord> >::iterator src_record_it = this->m_lst_src_records.begin();
			src_record_it != this->m_lst_src_records.end();
			src_record_it++)
	{
		if (((*src_record_it)->GetRetransmissionState() > 0) &&
			((*src_record_it)->GetDelayLeft() > this->GetLastMemberQueryTimeLMQT()))
		{
			retval.push_back((*src_record_it)->GetMulticastAddress());
		}
	}

}

void
IGMPv3MaintenanceState::GetSrcRetransWTimerLowerOrEqualToLMQT (std::list<Ipv4Address>& retval)
{
	for (std::list<Ptr<IGMPv3MaintenanceSrcRecord> >::iterator src_record_it = this->m_lst_src_records.begin();
			src_record_it != this->m_lst_src_records.end();
			src_record_it++)
	{
		if (((*src_record_it)->GetRetransmissionState() > 0) &&
			((*src_record_it)->GetDelayLeft() <= this->GetLastMemberQueryTimeLMQT()))
		{
			retval.push_back((*src_record_it)->GetMulticastAddress());
		}
	}

}

Ptr<Igmpv3L4Protocol>
IGMPv3MaintenanceState::GetIgmp (void)
{
	Ptr<Ipv4Multicast> ipv4 = this->m_interface->GetDevice()->GetNode()->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();

	return igmp;
}

/********************************************************
 *        IGMPv3InterfaceStateManager
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IGMPv3InterfaceStateManager);

TypeId
IGMPv3InterfaceStateManager::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IGMPv3InterfaceStateManager")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<IGMPv3InterfaceStateManager> ()
			;
	return tid;
}

IGMPv3InterfaceStateManager::IGMPv3InterfaceStateManager ()
  :  m_interface (0)
{
	NS_LOG_FUNCTION (this);
}

IGMPv3InterfaceStateManager::~IGMPv3InterfaceStateManager()
{
	NS_LOG_FUNCTION (this);
	this->m_event_robustness_retransmission.Cancel();
	this->m_timer_gen_query.Cancel();
	this->m_lst_interfacestates.clear();
	this->m_lst_per_group_interface_timers.clear();
	this->m_lst_maintenance_states.clear();
}

TypeId
IGMPv3InterfaceStateManager::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IGMPv3InterfaceStateManager::GetTypeId();
}

void
IGMPv3InterfaceStateManager::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
IGMPv3InterfaceStateManager::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

Ptr<Ipv4InterfaceMulticast>
IGMPv3InterfaceStateManager::GetInterface (void) const
{
	NS_LOG_FUNCTION (this);
	if (0 == this->m_interface)
	{
		NS_ASSERT (false);
	}
	return this->m_interface;
}

Ptr<IGMPv3InterfaceState>
IGMPv3InterfaceStateManager::GetIfState (Ptr<Ipv4InterfaceMulticast> interface, Ipv4Address multicast_address) const
{
	NS_LOG_FUNCTION (this);
	Ptr<IGMPv3InterfaceState> retval = 0;
	for (std::list<Ptr<IGMPv3InterfaceState> >::const_iterator const_it = this->m_lst_interfacestates.begin();
			const_it != this->m_lst_interfacestates.end();
			const_it++)
	{
		Ptr<IGMPv3InterfaceState> value_const_it = (*const_it);
		if ((value_const_it->GetInterface() == interface) &&
				(value_const_it->GetGroupAddress() == multicast_address))
		{
			retval = value_const_it;
			break;
		}
	}
	//return value can be 0
	return retval;
}

const std::list<Ptr<IGMPv3InterfaceState> >&
IGMPv3InterfaceStateManager::GetInterfaceStates (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_lst_interfacestates;
}

bool
IGMPv3InterfaceStateManager::HasPendingRecords (void) const
{
	NS_LOG_FUNCTION (this);
	for (std::list<Ptr<IGMPv3InterfaceState> >::const_iterator const_it = this->m_lst_interfacestates.begin();
		 const_it != this->m_lst_interfacestates.end();
		 const_it++)
	{
		Ptr<IGMPv3InterfaceState> interfacestate = (*const_it);
		if (true == interfacestate->HasPendingRecords())
		{
			return true;
		}
	}

	return false;
}

bool
IGMPv3InterfaceStateManager::IsReportStateChangesRunning (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_event_robustness_retransmission.IsRunning();
}

Ptr<IGMPv3InterfaceState>
IGMPv3InterfaceStateManager::CreateIfState (Ipv4Address multicast_address)
{
	NS_LOG_FUNCTION (this);
	Ptr<IGMPv3InterfaceState> retval = Create<IGMPv3InterfaceState>();
	retval->Initialize(this, multicast_address);
	this->m_lst_interfacestates.push_back(retval);
	return retval;
}

void
IGMPv3InterfaceStateManager::Sort (void)
{
	NS_LOG_FUNCTION (this);
	if (false == this->m_lst_interfacestates.empty())
	{
		this->m_lst_interfacestates.sort();
	}
}

void
IGMPv3InterfaceStateManager::IPMulticastListen (Ptr<IGMPv3SocketState> socket_state)
{
	NS_LOG_FUNCTION (this);
	Ipv4Address multicast_address = socket_state->GetGroupAddress();

	if (true == this->m_lst_interfacestates.empty())
	{
		Ptr<IGMPv3InterfaceState> interfacestate = this->CreateIfState(multicast_address);
		interfacestate->AssociateSocketStateInterfaceState (socket_state);
		interfacestate->ComputeState ();

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
			Ptr<IGMPv3InterfaceState> interfacestate = this->CreateIfState(multicast_address);
			interfacestate->AssociateSocketStateInterfaceState (socket_state);
			interfacestate->ComputeState ();
			return;
		}
		else
		{
			//only when it == this->m_lst_interfacestates.end(), the program would jump out of the while loop
			NS_ASSERT (false);
		}
	}
}

void
IGMPv3InterfaceStateManager::UnSubscribeIGMP (Ptr<Socket> socket)
{
	NS_LOG_FUNCTION (this);
	//place holders
}

void
IGMPv3InterfaceStateManager::AddPendingRecordsToReport (Igmpv3Report &report)
{
	for (std::list<Ptr<IGMPv3InterfaceState> >::iterator it = this->m_lst_interfacestates.begin();
		 it != this->m_lst_interfacestates.end();
		 it++)
	{
		(*it)->AddPendingRecordsToReport(report);
	}
}

void
IGMPv3InterfaceStateManager::ReportStateChanges (void)
{
	std::cout << "Node: " << this->m_interface->GetDevice()->GetNode()->GetId() << " Interface: " << this << " report state changes" << Simulator::Now() << std::endl;

	Ptr<Ipv4Multicast> ipv4 = this->m_interface->GetDevice()->GetNode()->GetObject<Ipv4Multicast> ();
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

		this->m_event_robustness_retransmission = Simulator::Schedule (delay, &IGMPv3InterfaceStateManager::DoReportStateChanges, this);
	}
}

void
IGMPv3InterfaceStateManager::DoReportStateChanges (void)
{
	std::cout << "Node: " << this->m_interface->GetDevice()->GetNode()->GetId() << " Interface: " << this << " report state changes " << Simulator::Now() << std::endl;

	Ptr<Ipv4Multicast> ipv4 = this->m_interface->GetDevice()->GetNode()->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();

	igmp->SendStateChangesReport(this);

	if (true == this->HasPendingRecords())
	{
		Time delay = igmp->GetUnsolicitedReportInterval();

		this->m_event_robustness_retransmission = Simulator::Schedule (delay, &IGMPv3InterfaceStateManager::DoReportStateChanges, this);
	}
}

void
IGMPv3InterfaceStateManager::ReportCurrentStates (void)
{
	NS_LOG_FUNCTION (this);

	std::cout << "Node: " << this->m_interface->GetDevice()->GetNode()->GetId() << " Interface: " << this << " report current state " << Simulator::Now() << std::endl;

	Ptr<Ipv4Multicast> ipv4 = this->m_interface->GetDevice()->GetNode()->GetObject<Ipv4Multicast> ();
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

	std::cout << "Node: " << this->m_interface->GetDevice()->GetNode()->GetId() << " reporting a general query to the querier" << std::endl;

	igmp->SendReport(this->GetInterface(), packet);
}

void
IGMPv3InterfaceStateManager::ReportCurrentGrpStates (Ipv4Address group_address)
{
	NS_LOG_FUNCTION (this);

	Ptr<Ipv4Multicast> ipv4 = this->m_interface->GetDevice()->GetNode()->GetObject<Ipv4Multicast> ();
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

	std::cout << "Node: " << this->m_interface->GetDevice()->GetNode()->GetId() << " reporting a general query to the querier" << std::endl;

	igmp->SendReport(this->GetInterface(), packet);

	this->RemovePerGroupTimer(group_address);
}

void
IGMPv3InterfaceStateManager::ReportCurrentGrpNSrcStates (Ipv4Address group_address, std::list<Ipv4Address> const &src_list)
{
	NS_LOG_FUNCTION (this);

	Ptr<Ipv4Multicast> ipv4 = this->m_interface->GetDevice()->GetNode()->GetObject<Ipv4Multicast> ();
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

	std::cout << "Node: " << this->m_interface->GetDevice()->GetNode()->GetId() << " reporting a general query to the querier" << std::endl;

	igmp->SendReport(this->GetInterface(), packet);

	this->RemovePerGroupTimer(group_address);
}

void
IGMPv3InterfaceStateManager::CancelReportStateChanges ()
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
IGMPv3InterfaceStateManager::RemovePerGroupTimer (Ipv4Address group_address)
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

void
IGMPv3InterfaceStateManager::HandleGeneralQuery (Time resp_time)
{
	if (false == this->m_timer_gen_query.IsRunning())
	{
		std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId()  << "'s has no per-interface-timer" << std::endl;
		std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId()  << " creating a new timer for handling incoming General Query" << std::endl;
		this->m_timer_gen_query.SetFunction(&IGMPv3InterfaceStateManager::ReportCurrentStates, this);
		std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId()  << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
		this->m_timer_gen_query.Schedule(resp_time);
	}
	else
	{
		if (resp_time < this->m_timer_gen_query.GetDelayLeft())
		{
			this->m_timer_gen_query.Cancel();

			std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId()  << "'s has a per-interface-timer, but delay time is smaller than resp time" << std::endl;
			std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId()  << " creating a new timer for handling incoming General Query" << std::endl;
			this->m_timer_gen_query.SetFunction(&IGMPv3InterfaceStateManager::ReportCurrentStates, this);
			std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId()  << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
			this->m_timer_gen_query.Schedule(resp_time);
		}
		else
		{
			//do nothing
		}
	}
}

void
IGMPv3InterfaceStateManager::HandleGroupSpecificQuery (Time resp_time, Ipv4Address group_address)
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
IGMPv3InterfaceStateManager::DoHandleGroupSpecificQuery (Time resp_time, Ipv4Address group_address)
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

			std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId() << " there is a timer exist for group specific query with delaytime left smaller current resp time." << std::endl;
			std::cout << "Interface: " << this << ", Group Address: " << group_address << std::endl;
			std::cout << "Canceling previous report." << std::endl;
			timer->m_softTimer.Cancel();

			timer->m_softTimer.SetFunction(&IGMPv3InterfaceStateManager::ReportCurrentGrpStates, this);
			timer->m_softTimer.SetArguments(group_address);
			std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId() << " scheduling new report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
			timer->m_softTimer.Schedule(delay);
			return;
		}
	}

	std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId() << " creating a new timer for handling incoming Group Specific Query" << std::endl;
	std::cout << "Interface: " << this << ", Group Address: " << group_address << std::endl;
	Ptr<PerGroupInterfaceTimer> new_timer = Create<PerGroupInterfaceTimer>();
	new_timer->m_interface = this->GetInterface();
	new_timer->m_group_address = group_address;
	new_timer->m_softTimer.SetFunction(&IGMPv3InterfaceStateManager::ReportCurrentGrpStates, this);
	new_timer->m_softTimer.SetArguments(group_address);
	std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId() << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
	new_timer->m_softTimer.Schedule(resp_time);
	this->m_lst_per_group_interface_timers.push_back(new_timer);
}

void
IGMPv3InterfaceStateManager::HandleGroupNSrcSpecificQuery (Time resp_time, Ipv4Address group_address, std::list<Ipv4Address> const &src_list)
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
IGMPv3InterfaceStateManager::DoHandleGroupNSrcSpecificQuery (Time resp_time, Ipv4Address group_address, std::list<Ipv4Address> const &src_list)
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

			std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId() << " there is a timer exist for group specific query with delaytime left smaller current resp time." << std::endl;
			std::cout << "Interface: " << this << ", Group Address: " << group_address << std::endl;
			std::cout << "Canceling previous report." << std::endl;
			timer->m_softTimer.Cancel();

			timer->m_softTimer.SetFunction(&IGMPv3InterfaceStateManager::ReportCurrentGrpNSrcStates, this);
			timer->m_softTimer.SetArguments(group_address, src_list);
			std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId() << " scheduling new report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
			timer->m_softTimer.Schedule(delay);
			return;
		}
	}

	std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId() << " creating a new timer for handling incoming Group Specific Query" << std::endl;
	std::cout << "Interface: " << this << ", Group Address: " << group_address << std::endl;
	Ptr<PerGroupInterfaceTimer> new_timer = Create<PerGroupInterfaceTimer>();
	new_timer->m_interface = this->GetInterface();
	new_timer->m_group_address = group_address;
	new_timer->m_softTimer.SetFunction(&IGMPv3InterfaceStateManager::ReportCurrentGrpNSrcStates, this);
	new_timer->m_softTimer.SetArguments(group_address, src_list);
	std::cout << "Node id: " << this->m_interface->GetDevice()->GetNode()->GetId() << " scheduling report, delay time: " << resp_time.GetSeconds() << " seconds" << std::endl;
	new_timer->m_softTimer.Schedule(resp_time);
	this->m_lst_per_group_interface_timers.push_back(new_timer);
}

void
IGMPv3InterfaceStateManager::HandleV3Records (const std::list<Igmpv3GrpRecord> &records)
{
	for (std::list<Igmpv3GrpRecord>::const_iterator record_it = records.begin();
		 record_it != records.end();
		 record_it++)
	{
		const Igmpv3GrpRecord record = (*record_it);
		std::list<Ptr<IGMPv3MaintenanceState> >::iterator state_it;
		for (state_it = this->m_lst_maintenance_states.begin();
			 state_it != this->m_lst_maintenance_states.end();
			 state_it++)
		{
			Ptr<IGMPv3MaintenanceState> maintenance_state = (*state_it);

			if (record.GetMulticastAddress() == maintenance_state->GetMulticastAddress())
			{
				maintenance_state->HandleGrpRecord(record);
			}
		}
		if (state_it == this->m_lst_maintenance_states.end())
		{
			//no maintenance_state matched
			Ptr<IGMPv3MaintenanceState> maintenance_state = Create<IGMPv3MaintenanceState>();
			maintenance_state->Initialize(this->GetInterface(), record.GetMulticastAddress(), GsamConfig::GetSingleton()->GetDefaultGroupTimerDelayInSeconds());
			this->m_lst_maintenance_states.push_back(maintenance_state);
			maintenance_state->HandleGrpRecord(record);
		}
	}
}

void
IGMPv3InterfaceStateManager::NonQHandleGroupSpecificQuery (Ipv4Address group_address)
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
IGMPv3InterfaceStateManager::NonQHandleGroupNSrcSpecificQuery (Ipv4Address group_address,
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
IGMPv3InterfaceStateManager::SendQuery (Ipv4Address group_address, bool s_flag)
{
	NS_LOG_FUNCTION (this);

	Ptr<Ipv4Multicast> ipv4 = this->m_interface->GetDevice()->GetNode()->GetObject<Ipv4Multicast> ();
	Ptr<Ipv4L3ProtocolMulticast> ipv4l3 = DynamicCast<Ipv4L3ProtocolMulticast>(ipv4);
	Ptr<Igmpv3L4Protocol> igmp = ipv4l3->GetIgmp();

	Igmpv3Query query;

	query.SetGroupAddress(group_address);
	query.SetSFlag(s_flag);
	query.SetQQIC(igmp->GetQQIC());
	query.SetQRV(igmp->GetQRV());

	Ptr<Packet> packet = Create<Packet>();

	packet->AddHeader(query);

	igmp->SendQuery(group_address, this->GetInterface(), packet);
}

void
IGMPv3InterfaceStateManager::SendQuery (Ipv4Address group_address, std::list<Ipv4Address> const &src_list, bool s_flag)
{
	NS_LOG_FUNCTION (this);

	Ptr<Ipv4Multicast> ipv4 = this->m_interface->GetDevice()->GetNode()->GetObject<Ipv4Multicast> ();
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

	igmp->SendQuery(group_address, this->GetInterface(), packet);

}

/********************************************************
 *        Igmpv3Manager
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (Igmpv3Manager);

TypeId
Igmpv3Manager::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::Igmpv3Manager")
    		.SetParent<Object> ()
			.SetGroupName ("Internet")
			.AddConstructor<Igmpv3Manager> ()
			;
	return tid;
}

Igmpv3Manager::Igmpv3Manager ()
{
	NS_LOG_FUNCTION (this);
}

Igmpv3Manager::~Igmpv3Manager()
{
	NS_LOG_FUNCTION (this);
	this->m_map_socketstate_managers.clear();
	this->m_map_ifstate_managers.clear();
}

TypeId
Igmpv3Manager::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IGMPv3InterfaceStateManager::GetTypeId();
}

void
Igmpv3Manager::NotifyNewAggregate ()
{
	NS_LOG_FUNCTION (this);
}

void
Igmpv3Manager::DoDispose (void)
{
	NS_LOG_FUNCTION (this);
}

Ptr<IGMPv3SocketStateManager>
Igmpv3Manager::GetSocketStateManager (Ptr<Socket> key) const
{
	NS_LOG_FUNCTION (this);
	Ptr<IGMPv3SocketStateManager> retval = 0;
	std::map<Ptr<Socket>, Ptr<IGMPv3SocketStateManager> >::const_iterator const_it = this->m_map_socketstate_managers.find(key);
	if (this->m_map_socketstate_managers.end() != const_it)
	{
		retval = const_it->second;
	}
	return retval;
}

Ptr<IGMPv3InterfaceStateManager>
Igmpv3Manager::GetIfStateManager (Ptr<Ipv4InterfaceMulticast> key) const
{
	NS_LOG_FUNCTION (this);
	Ptr<IGMPv3InterfaceStateManager> retval = 0;
	std::map<Ptr<Ipv4InterfaceMulticast>, Ptr<IGMPv3InterfaceStateManager> >::const_iterator const_it = this->m_map_ifstate_managers.find(key);
	if (this->m_map_ifstate_managers.end() != const_it)
	{
		retval = const_it->second;
	}
	return retval;
}

/********************************************************
 *        Igmpv3Header
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (Igmpv3Header);

TypeId
Igmpv3Header::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::Igmpv3Header")
    .SetParent<Header> ()
    //.SetGroupName("Internet")
	.AddConstructor<Igmpv3Header> ();
  return tid;
}

Igmpv3Header::Igmpv3Header ()
  :	m_type (0),
	m_max_resp_code (0),
	m_checksum (0),
	m_calcChecksum (false)
{
	this->m_max_resp_code = 100;	//cisco default value 10sec
	NS_LOG_FUNCTION (this);
}

Igmpv3Header::~Igmpv3Header ()
{
	NS_LOG_FUNCTION (this);
}

void
Igmpv3Header::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	//**************warning*********
	//the following code may make the buffer resize, causing iterator to be invalidated
	i.WriteU8(this->m_type);
	i.WriteU8(this->m_max_resp_code);
	i.WriteHtonU16(0);	//fill up the checksum field with zero

	if (true == this->m_calcChecksum)
	{
		i = start;
		uint16_t checksum = i.CalculateIpChecksum(i.GetSize());
		i = start;
		i.Next(2);	//2 bytes, 16bits, after Type and Max Resp Code fields
		i.WriteU16(checksum);
	}

}

uint32_t
Igmpv3Header::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	this->m_type = start.ReadU8();
	this->m_max_resp_code = start.ReadU8();
	this->m_checksum = start.ReadNtohU16();
	return 4;
}

uint32_t
Igmpv3Header::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);
	return 4;	//followling RFC3376, length of fields including type, max resp code and checksum
}

TypeId
Igmpv3Header::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return Igmpv3Header::GetTypeId ();
}

void
Igmpv3Header::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "Type=" << this->m_type << ", Max Resp Code=" << this->m_max_resp_code << ", ";
	os << "Checksum=" << this->m_checksum << std::endl;
}

void
Igmpv3Header::SetType (uint8_t type)
{
	NS_LOG_FUNCTION (this);
	this->m_type = type;
}

uint8_t
Igmpv3Header::GetType (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_type;
}

void
Igmpv3Header::SetMaxRespCode (uint8_t max_resp_code)
{
	NS_LOG_FUNCTION (this);
	this->m_max_resp_code = max_resp_code;
}

uint8_t
Igmpv3Header::GetMaxRespCode (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_max_resp_code;
}

void
Igmpv3Header::EnableChecksum (void)
{
	NS_LOG_FUNCTION (this);
	this->m_checksum = true;
}

/********************************************************
 *        Igmpv3Query
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (Igmpv3Query);

TypeId
Igmpv3Query::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::Igmpv3Query")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<Igmpv3Query> ();
	  return tid;
}

Igmpv3Query::Igmpv3Query ()
  :  m_group_address (Ipv4Address("0.0.0.0")),
	 m_resv_s_qrv (0),
	 m_qqic (0),
	 m_num_srcs (0)
{
	this->m_resv_s_qrv.set_QRV (2);		//cisco default robustness value: 2
	this->m_qqic = 125; 	//cisco default query interval 125sec
	NS_LOG_FUNCTION (this);
}

Igmpv3Query::~Igmpv3Query ()
{
	NS_LOG_FUNCTION (this);
}

void
Igmpv3Query::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	//serializing group address
	uint8_t buf[4];	//4 == length of Ipv4 address in bytes
	this->m_group_address.Serialize(buf);
	i.Write(buf, 4);

	i.WriteU8(this->m_resv_s_qrv.toUint8_t());
	i.WriteU8(this->m_qqic);
	i.WriteHtonU16(this->m_lst_src_addresses.size());

	uint16_t count = 0;

	//totally wrong about for statement, it always checks the condition first then enter the code block
	//serializing source addresses
	/*
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		(*it).Serialize(buf);
		i.Write(buf, 4); //4 == length of Ipv4 address in bytes
		++count;
	}
	*/

	//serializing source addresses
	if (false == this->m_lst_src_addresses.empty()) {
		std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin();

		do {
			(*it).Serialize(buf);
			i.Write(buf, 4); //4 == length of Ipv4 address in bytes
			++count;

			it++;
		} while (it != this->m_lst_src_addresses.end());
	}

	//serializing source addresses

	NS_ASSERT(count == this->m_num_srcs);
}

uint32_t
Igmpv3Query::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	//count bytes read for return value
	uint32_t bytes_read = 0;

	this->m_group_address = Ipv4Address(i.ReadNtohU32());
	bytes_read += 4;	//4 == length of Ipv4 address in bytes

	this->m_resv_s_qrv = i.ReadU8();
	bytes_read++;

	this->m_qqic = i.ReadU8();
	bytes_read++;

	this->m_num_srcs = i.ReadNtohU16();
	bytes_read += 2;

	uint32_t size_bytes_unread = start.GetSize() - bytes_read;

	//abort if the size of rest of the data isn't a multiple of 4 (ipv4 address size)
	NS_ASSERT((size_bytes_unread % 4) == 0);

	uint8_t buf[4];
	for (uint16_t n = this->m_num_srcs; n > 0; --n)
	{
		Ipv4Address address;
		i.Read(buf, 4);
		address.Deserialize(buf);
		this->PushBackSrcAddress(address);
	}

	return bytes_read;
}

uint32_t
Igmpv3Query::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);
	uint32_t size = 0;
	size += sizeof(this->m_group_address.Get());	//size of the group address
	size += sizeof(this->m_resv_s_qrv.toUint8_t());
	size += sizeof(this->m_qqic);
	size += sizeof(this->m_num_srcs);
	//size += 4*this->m_num_srcs;	//4 bytes for eath source address

	//this way of counting is slow. but just in case.
	uint16_t count = 0;

	/* totally wrong about for statement
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		size += sizeof((*it).Get());
		count++;
	}
	*/

	if (false == this->m_lst_src_addresses.empty()) {
		std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin();
		do {
			size += sizeof((*it).Get());
			count++;

			it++;
		} while (it != this->m_lst_src_addresses.end());
	}

	NS_ASSERT(count == this->m_num_srcs);

	return size;
}

TypeId
Igmpv3Query::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return Igmpv3Query::GetTypeId ();
}

void
Igmpv3Query::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "Group Address=";
	this->m_group_address.Print(os);
	os << ", ";
	os << "S Flag=" << this->m_resv_s_qrv.get_S() << ", QRV=" << this->m_resv_s_qrv.get_QRV() << ", ";
	os << "QQIC=" << this->m_num_srcs << ", number of sources=" << this->m_num_srcs << ", ";
	os << "Source Addresses:" << std::endl;
	uint16_t count = 1;

	/*
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		os << "src address(" << count << "): ";
		(*it).Print(os);
		os << std::endl;
		count++;
	}
	*/

	if (false == this->m_lst_src_addresses.empty()) {
		std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin();

		do {
			os << "src address(" << count << "): ";
			(*it).Print(os);
			os << std::endl;
			count++;

			it++;
		} while (it != this->m_lst_src_addresses.end());
	}
}

void
Igmpv3Query::SetGroupAddress (uint32_t address)
{
	NS_LOG_FUNCTION (this << &address);
	this->m_group_address.Set(address);
}

void
Igmpv3Query::SetGroupAddress (Ipv4Address address)
{
	NS_LOG_FUNCTION (this << &address);
	this->m_group_address.Set(address.Get());
}

void
Igmpv3Query::SetSFlag (bool b)
{
	NS_LOG_FUNCTION (this);
//	if (true == b)
//	{
//		this->m_resv_s_qrv.S = 0x1;
//	}
//	else
//	{
//		this->m_resv_s_qrv.S = 0x0;
//	}
	this->m_resv_s_qrv.set_S (b);
}

void
Igmpv3Query::SetQRV (uint8_t qrv)
{
	NS_LOG_FUNCTION (this);
	this->m_resv_s_qrv.set_QRV (qrv);
}

void
Igmpv3Query::SetQQIC (uint8_t qqic)
{
	NS_LOG_FUNCTION (this);
	this->m_qqic = qqic;
}

/*
void
Igmpv3Query::SetNumSrc (uint16_t num_src)
{
	NS_LOG_FUNCTION (this);
	this->m_num_srcs = num_src;
}
*/

void
Igmpv3Query::PushBackSrcAddress (Ipv4Address address)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_src_addresses.push_back(address);
	this->m_num_srcs++;
}

void
Igmpv3Query::PushBackSrcAddresses (std::list<Ipv4Address> const &lst_addresses)
{
	NS_LOG_FUNCTION (this << &lst_addresses);
	for (std::list<Ipv4Address>::const_iterator it = lst_addresses.begin(); it != lst_addresses.end(); ++it)
	{
		this->m_lst_src_addresses.push_back((*it));
		this->m_num_srcs++;
	}
}

uint32_t
Igmpv3Query::GetGroupAddress (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_group_address.Get();
}

bool
Igmpv3Query::isSFlagSet (void)
{
	NS_LOG_FUNCTION (this);
//	if (1 == this->m_resv_s_qrv.S)
//	{
//		return true;
//	}
//	else
//	{
//		return false;
//	}
	return this->m_resv_s_qrv.get_S();
}

uint8_t
Igmpv3Query::GetQRV (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_resv_s_qrv.get_QRV();
}

uint8_t
Igmpv3Query::GetQQIC (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_qqic;
}

uint16_t
Igmpv3Query::GetNumSrc (void)
{
	return this->m_num_srcs;
}

uint16_t
Igmpv3Query::GetSrcAddresses (std::list<Ipv4Address> &payload_addresses) const
{
	NS_LOG_FUNCTION (this << &payload_addresses);
	uint8_t count = 0;
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		payload_addresses.push_back((*it));
		count++;
	}

	return count;
}

/********************************************************
 *        Igmpv3GrpRecord
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (Igmpv3GrpRecord);

TypeId
Igmpv3GrpRecord::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::Igmpv3GrpRecord")
    		.SetParent<Header> ()
			//.SetGroupName("Internet")
			.AddConstructor<Igmpv3GrpRecord> ();
	return tid;
}

Igmpv3GrpRecord::Igmpv3GrpRecord ()
  :  m_record_type (0x00),
	 m_aux_data_len (0),
	 m_num_srcs (0),
	 m_mul_address (Ipv4Address("0.0.0.0"))
{
	NS_LOG_FUNCTION (this);

}

Igmpv3GrpRecord::~Igmpv3GrpRecord ()
{
	NS_LOG_FUNCTION (this);
}

void
Igmpv3GrpRecord::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;
	i.WriteU8(this->m_record_type);
	i.WriteU8(this->m_lst_aux_data.size());
	i.WriteHtonU16(this->m_lst_src_addresses.size());
	i.WriteHtonU32(this->m_mul_address.Get());


	uint16_t count = 0;

	/*
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		i.WriteHtonU32((*it).Get());
		count++;
	}
	*/

	if (false == this->m_lst_src_addresses.empty()) {
		std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin();

		do {

			i.WriteHtonU32((*it).Get());
			count++;

			it++;
		} while (it != this->m_lst_src_addresses.end());
	}

	NS_ASSERT(count == this->m_num_srcs);

	count = 0;

	/*
	for (std::list<uint32_t>::const_iterator it = this->m_lst_aux_data.begin(); it != this->m_lst_aux_data.end(); ++it)
	{
		i.WriteHtonU32((*it));
		count++;
	}
	*/

	if (false == this->m_lst_aux_data.empty()) {
		std::list<uint32_t>::const_iterator it_u = this->m_lst_aux_data.begin();

		do {
			i.WriteHtonU32((*it_u));
			count++;

			it_u++;
		} while (it_u != this->m_lst_aux_data.end());
	}

	NS_ASSERT(count == this->m_aux_data_len);

}

uint32_t
Igmpv3GrpRecord::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	uint32_t bytes_read = 0;

	this->m_record_type = i.ReadU8();
	bytes_read += 1;

	this->m_aux_data_len = i.ReadU8();
	bytes_read += 1;

	this->m_num_srcs = i.ReadNtohU16();
	bytes_read += 2;

	this->m_mul_address = Ipv4Address(i.ReadNtohU32());
	bytes_read += 4;

	for (uint16_t n = this->m_num_srcs; n > 0; --n)
	{
		this->m_lst_src_addresses.push_back(Ipv4Address(i.ReadNtohU32()));
		bytes_read += 4;
	}

	for (uint16_t n = this->m_aux_data_len; n > 0; --n)
	{
		this->m_lst_aux_data.push_back(i.ReadNtohU32());
		bytes_read += 4;
	}

	return bytes_read;
}

uint32_t
Igmpv3GrpRecord::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);
	uint32_t size = 0;
	size += sizeof (this->m_record_type);
	size += sizeof (this->m_aux_data_len);
	size += sizeof (this->m_num_srcs);
	size += sizeof (this->m_mul_address.Get());


	//size += 4*this->m_num_srcs;	//4 bytes for each ipv4 address

	//this way of counting is slow. but just in case.
	uint16_t srcs_count = 0;

	/*
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		size += sizeof((*it).Get());
		srcs_count++;
	}
	*/

	if (false == this->m_lst_src_addresses.empty()) {
		std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin();

		do {
			size += sizeof((*it).Get());
			srcs_count++;

			it++;
		} while (it != this->m_lst_src_addresses.end());
	}

	NS_ASSERT(srcs_count == this->m_num_srcs);

	//size += 4*this->m_aux_data_len;	//4 bytes for each aux data

	uint16_t aux_count = 0;

	/*
	for (std::list<uint32_t>::const_iterator it = this->m_lst_aux_data.begin(); it != this->m_lst_aux_data.end(); ++it)
	{
		size += sizeof((*it));
		aux_count++;
	}
	*/

	if (false == this->m_lst_aux_data.empty()) {
		std::list<uint32_t>::const_iterator it_u = this->m_lst_aux_data.begin();

		do {
			size += sizeof((*it_u));
			aux_count++;

			it_u++;
		} while (it_u != this->m_lst_aux_data.end());
	}

	NS_ASSERT(aux_count == this->m_aux_data_len);

	return size;

}

TypeId
Igmpv3GrpRecord::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return Igmpv3GrpRecord::GetTypeId ();
}

void
Igmpv3GrpRecord::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "record type=" << this->m_record_type << ", ";
	os << "aux length=" << this->m_aux_data_len << ", ";
	os << "num of srcs" << this->m_num_srcs << ", ";
	os << "multicast address";this->m_mul_address.Print(os);os << ", ";

	uint16_t count = 1;
	/*
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		os << "src address(" << count << "): ";
		(*it).Print(os);
		os << std::endl;
		count++;
	}
	*/

	if (false == this->m_lst_src_addresses.empty()) {
		std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin();

		do {
			os << "src address(" << count << "): ";
			(*it).Print(os);
			os << std::endl;
			count++;

			it++;
		} while (it != this->m_lst_src_addresses.end());
	}
}

void
Igmpv3GrpRecord::SetType (uint8_t type)
{
	NS_LOG_FUNCTION (this);
	this->m_record_type = type;
}

//void
//Igmpv3GrpRecord::SetAuxDataLen (uint8_t aux_data_len)
//{
//	NS_LOG_FUNCTION (this);
//	this->m_aux_data_len = aux_data_len;
//}

//void
//Igmpv3GrpRecord::SetNumSrcs (uint16_t num_srcs)
//{
//	NS_LOG_FUNCTION (this);
//	this->m_num_srcs = num_srcs;
//}

void
Igmpv3GrpRecord::SetMulticastAddress (Ipv4Address address)
{
	NS_LOG_FUNCTION (this);
	this->m_mul_address.Set(address.Get());
}

void
Igmpv3GrpRecord::PushBackSrcAddress (Ipv4Address address)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_src_addresses.push_back(address);
	this->m_num_srcs++;
}

//void
//Igmpv3GrpRecord::PushBackSrcAddresses (std::list<uint32> &lst_addresses)
//{
//	NS_LOG_FUNCTION (this << &lst_addresses);
//	for (std::list<uint32>::const_iterator it = lst_addresses.begin(); it != lst_addresses.end(); ++it)
//	{
//		this->m_lst_src_addresses.push_back(Ipv4Address(*it));
//	}
//}

void
Igmpv3GrpRecord::PushBackSrcAddresses (std::list<Ipv4Address> const &lst_addresses)
{
	NS_LOG_FUNCTION (this << &lst_addresses);
	for (std::list<Ipv4Address>::const_iterator it = lst_addresses.begin(); it != lst_addresses.end(); ++it)
	{
		this->m_lst_src_addresses.push_back((*it));
	}
	this->m_num_srcs += lst_addresses.size();
}

void
Igmpv3GrpRecord::PushBackAuxData (uint32_t aux_data)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_aux_data.push_back(aux_data);
	this->m_aux_data_len++;
}

void
Igmpv3GrpRecord::PushBackAuxdata (std::list<uint32_t> &lst_aux_data)
{
	NS_LOG_FUNCTION (this << &lst_aux_data);
	for (std::list<uint32_t>::const_iterator it = lst_aux_data.begin(); it != lst_aux_data.end(); ++it)
	{
			this->m_lst_aux_data.push_back((*it));
	}
	this->m_aux_data_len += lst_aux_data.size();
}

uint8_t
Igmpv3GrpRecord::GetType (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_record_type;
}

uint8_t
Igmpv3GrpRecord::GetAuxDataLen (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_aux_data_len;
}

uint16_t
Igmpv3GrpRecord::GetNumSrcs (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_num_srcs;
}

Ipv4Address
Igmpv3GrpRecord::GetMulticastAddress (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_mul_address;
}

uint16_t
Igmpv3GrpRecord::GetSrcAddresses (std::list<Ipv4Address> &payload_addresses) const
{
	NS_LOG_FUNCTION (this);

	uint16_t count = 0;

	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		payload_addresses.push_back((*it));
		++count;
	}

	return count;
}

uint8_t
Igmpv3GrpRecord::GetAuxData (std::list<uint32_t> &payload_data) const
{
	NS_LOG_FUNCTION (this);

	uint16_t count = 0;

	for (std::list<uint32_t>::const_iterator it = this->m_lst_aux_data.begin(); it != this->m_lst_aux_data.end(); ++it)
	{
		payload_data.push_back((*it));
		++count;
	}

	return count;
}

Igmpv3GrpRecord
Igmpv3GrpRecord::CreateBlockRecord (Ipv4Address multicast_address,
									std::list<Ipv4Address> const &old_src_lst,
									std::list<Ipv4Address> const &new_src_lst)
{
	Igmpv3GrpRecord record;
	record.SetType(Igmpv3GrpRecord::BLOCK_OLD_SOURCES);
	record.SetMulticastAddress(multicast_address);
	std::list<Ipv4Address> src_lst_substracted = Igmpv3L4Protocol::ListSubtraction (new_src_lst, old_src_lst);
	//record.SetNumSrcs(src_lst_substracted.size());
	record.PushBackSrcAddresses(src_lst_substracted);

	return record;

}

Igmpv3GrpRecord
Igmpv3GrpRecord::CreateBlockRecord (Ptr<IGMPv3InterfaceState> old_state,
									Ptr<IGMPv3InterfaceState> new_state)
{
	if (old_state->GetGroupAddress() != new_state->GetGroupAddress())
	{
		NS_ASSERT (false);
	}

	Ipv4Address multicast_address = old_state->GetGroupAddress();
	return Igmpv3GrpRecord::CreateBlockRecord (multicast_address, old_state->GetSrcList(), new_state->GetSrcList());
}
Igmpv3GrpRecord
Igmpv3GrpRecord::CreateAllowRecord (Ipv4Address multicast_address,
									std::list<Ipv4Address> const &old_src_lst,
			   	   	   	   	   	   	std::list<Ipv4Address> const &new_src_lst)
{
	Igmpv3GrpRecord record;
	record.SetType(Igmpv3GrpRecord::ALLOW_NEW_SOURCES);
	record.SetMulticastAddress(multicast_address);
	std::list<Ipv4Address> src_lst_substracted = Igmpv3L4Protocol::ListSubtraction (new_src_lst, old_src_lst);
	//record.SetNumSrcs(src_lst_substracted.size());
	record.PushBackSrcAddresses(src_lst_substracted);

	return record;
}

Igmpv3GrpRecord
Igmpv3GrpRecord::CreateAllowRecord (Ptr<IGMPv3InterfaceState> old_state,
									Ptr<IGMPv3InterfaceState> new_state)
{
	if (old_state->GetGroupAddress() != new_state->GetGroupAddress())
	{
		NS_ASSERT (false);
	}

	Ipv4Address multicast_address = old_state->GetGroupAddress();
	return Igmpv3GrpRecord::CreateAllowRecord (multicast_address, old_state->GetSrcList(), new_state->GetSrcList());
}

Igmpv3GrpRecord
Igmpv3GrpRecord::CreateStateChangeRecord (Ipv4Address multicast_address,
										  ns3::FILTER_MODE filter_mode,
										  std::list<Ipv4Address> const &src_lst)
{
	Igmpv3GrpRecord record;
	if (filter_mode == ns3::EXCLUDE)
	{
		record.SetType(Igmpv3GrpRecord::CHANGE_TO_EXCLUDE_MODE);
	}
	else if (filter_mode == ns3::INCLUDE)
	{
		record.SetType(Igmpv3GrpRecord::CHANGE_TO_INCLUDE_MODE);
	}
	else	//filter_mode != ns3::EXCLUDE && filter_mode != ns3::INCLUDE
	{
		//should not go here
		NS_ASSERT (false);
	}

	record.SetMulticastAddress(multicast_address);
	//record.SetNumSrcs(src_lst.size());
	record.PushBackSrcAddresses(src_lst);

	return record;
}

Igmpv3GrpRecord
Igmpv3GrpRecord::CreateStateChangeRecord (Ptr<IGMPv3InterfaceState> old_state,
	  	  	  	  	  	  	  	  	  	  Ptr<IGMPv3InterfaceState> new_state)
{
	if (old_state->GetGroupAddress() != new_state->GetGroupAddress())
	{
		NS_ASSERT (false);
	}

	Ipv4Address multicast_address = old_state->GetGroupAddress();
	ns3::FILTER_MODE filter_mode = new_state->GetFilterMode();
	return Igmpv3GrpRecord::CreateStateChangeRecord (multicast_address, filter_mode, new_state->GetSrcList());
}

void
Igmpv3GrpRecord::GenerateGrpRecords (Ptr<IGMPv3InterfaceState> old_state,
									 Ptr<IGMPv3InterfaceState> new_state,
									 std::list<Igmpv3GrpRecord>& retval)
{
	ns3::FILTER_MODE old_filter_mode = old_state->GetFilterMode();
	ns3::FILTER_MODE new_filter_mode = new_state->GetFilterMode();

	if (old_state->GetGroupAddress() != new_state->GetGroupAddress())
	{
		NS_ASSERT (false);
	}

	Ipv4Address multicast_address = old_state->GetGroupAddress();

	if (old_filter_mode == new_filter_mode)
	{
		//todo create allow and block records

		Igmpv3GrpRecord allow_record = Igmpv3GrpRecord::CreateAllowRecord (multicast_address,
																		   old_state->GetSrcList(),
																		   new_state->GetSrcList());
		retval.push_back(allow_record);
		Igmpv3GrpRecord block_record = Igmpv3GrpRecord::CreateBlockRecord (multicast_address,
																		   old_state->GetSrcList(),
																		   new_state->GetSrcList());
		retval.push_back(block_record);
	}
	else
	{
		//todo create TO_EX or TO_IN record

		if ((new_filter_mode == ns3::EXCLUDE) || (new_filter_mode == ns3::INCLUDE))
		{
			Igmpv3GrpRecord state_chg_record = Igmpv3GrpRecord::CreateStateChangeRecord (new_state->GetGroupAddress(),
																					 new_filter_mode,
																					 new_state->GetSrcList());
			retval.push_back(state_chg_record);
		}
		else // new_filter_mode != ns3::EXCLUDE and new_filter_mode != ns3::INCLUDE
		{
			NS_ASSERT (false);
		}
	}
}

Igmpv3GrpRecord
Igmpv3GrpRecord::GenerateGrpRecord (Ptr<IGMPv3InterfaceState> if_state)
{
	Igmpv3GrpRecord record;
	if (if_state->GetFilterMode() == /*FILTER_MODE::*/EXCLUDE)
	{
		record.SetType(Igmpv3GrpRecord::MODE_IS_EXCLUDE);
	}
	else if (if_state->GetFilterMode() == /*FILTER_MODE::*/ns3::INCLUDE)
	{
		record.SetType(Igmpv3GrpRecord::MODE_IS_INCLUDE);
	}
	else
	{
		NS_ASSERT (false);
	}

	//record.SetAuxDataLen(0);
	//record.SetNumSrcs(if_state->GetSrcNum());
	record.SetMulticastAddress(if_state->GetGroupAddress());
	record.PushBackSrcAddresses(if_state->GetSrcList());

	return record;
}

Igmpv3GrpRecord
Igmpv3GrpRecord::GenerateGrpRecord (Ptr<IGMPv3InterfaceState> if_state, std::list<Ipv4Address> const &src_list)
{
	Igmpv3GrpRecord record;

	//for group and source specific query
	record.SetType(Igmpv3GrpRecord::MODE_IS_INCLUDE);

	std::list<Ipv4Address> new_src_list;

	if (if_state->GetFilterMode() == /*FILTER_MODE::*/ns3::EXCLUDE)
	{
		new_src_list = Igmpv3L4Protocol::ListSubtraction (if_state->GetSrcList(), src_list);
	}
	else if (if_state->GetFilterMode() == /*FILTER_MODE::*/ns3::INCLUDE)
	{
		new_src_list = Igmpv3L4Protocol::ListIntersection (if_state->GetSrcList(), src_list);
	}
	else
	{
		NS_ASSERT (false);
	}

	//record.SetAuxDataLen(0);
	//record.SetNumSrcs(if_state->GetSrcNum());
	record.SetMulticastAddress(if_state->GetGroupAddress());

	record.PushBackSrcAddresses(if_state->GetSrcList());

	return record;

}

/********************************************************
 *        Igmpv3Report
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (Igmpv3Report);

TypeId
Igmpv3Report::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::Igmpv3Report")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<Igmpv3Report> ();
	return tid;

}

Igmpv3Report::Igmpv3Report ()
  : m_reserved (0x0000),
	m_num_grp_record (0x0000)
{
	NS_LOG_FUNCTION (this);

}

Igmpv3Report::~Igmpv3Report ()
{
	NS_LOG_FUNCTION (this);
}

void
Igmpv3Report::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);

	Buffer::Iterator i = start;

	i.WriteHtonU16(this->m_reserved);
	i.WriteHtonU16(this->m_lst_grp_records.size());

	//size of data to be serialized can be huge
	//caution!!!!!!!!!!!!!!!!! this might cause buffer to resize.

	uint16_t count = 0;

	/*
	for (std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin(); it != this->m_lst_grp_records.end(); ++it)
	{
		(*it).Serialize(i);
		count++;
	}
	*/

	if (false == this->m_lst_grp_records.empty()) {
		std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin();

		do {
			(*it).Serialize(i);
			i.Next(it->GetSerializedSize());
			count++;

			it++;
		} while (it != this->m_lst_grp_records.end());
	}

	NS_ASSERT(count == this->m_num_grp_record);
}

uint32_t
Igmpv3Report::Deserialize (Buffer::Iterator start)
{
	//caution, need to verify.

	NS_LOG_FUNCTION (this << &start);

	Buffer::Iterator i = start;

	uint32_t size = 0;

	this->m_reserved = i.ReadNtohU16();

	size += 2;

	NS_ASSERT(this->m_reserved == 0);

	this->m_num_grp_record = i.ReadNtohU16();

	size += 2;

	for (uint16_t count_left = this->m_num_grp_record; count_left > 0; --count_left)
	{
		Igmpv3GrpRecord record;
		record.Deserialize(i);

		uint32_t record_size = record.GetSerializedSize();

		i.Next(record_size);		//not sure the iterator will move rightly.
		this->m_lst_grp_records.push_back(record);

		size += record_size;
	}

	return size;
}

uint32_t
Igmpv3Report::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t size = 0;

	size += sizeof(this->m_reserved);
	size += sizeof(this->m_num_grp_record);

	uint16_t count = 0;

	/*
	for (std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin(); it != this->m_lst_grp_records.end(); ++it)
	{
		size += (*it).GetSerializedSize();
	}
	*/

	if (false == this->m_lst_grp_records.empty()) {
		std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin();

		do {
			size += (*it).GetSerializedSize();

			it++;
			count++;
		} while (it != this->m_lst_grp_records.end());
	}

	NS_ASSERT(count == this->m_num_grp_record);

	return size;
}

TypeId
Igmpv3Report::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return Igmpv3Report::GetTypeId ();
}

void
Igmpv3Report::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "num of grprecord: " << this->m_num_grp_record << ", " << std::endl;

	/*
	for (std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin(); it != this->m_lst_grp_records.end(); ++it)
	{
		(*it).Print(os);
	}
	*/

	if (false == this->m_lst_grp_records.empty()) {
		std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin();

		do {
			(*it).Print(os);

			it++;
		} while (it != this->m_lst_grp_records.end());
	}
}

//void
//Igmpv3Report::SetNumGrpRecords (uint16_t num_grp_records)
//{
//	NS_LOG_FUNCTION (this);
//	this->m_num_grp_record = num_grp_records;
//}

uint16_t
Igmpv3Report::GetNumGrpRecords (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_num_grp_record;
}

void
Igmpv3Report::PushBackGrpRecord (Igmpv3GrpRecord grp_record)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_grp_records.push_back(grp_record);
	this->m_num_grp_record++;
}

void
Igmpv3Report::PushBackGrpRecords (std::list<Igmpv3GrpRecord> &grp_records)
{
	NS_LOG_FUNCTION (this);

	for (std::list<Igmpv3GrpRecord>::const_iterator it = grp_records.begin(); it != grp_records.end(); ++it)
	{
		this->m_lst_grp_records.push_back((*it));
	}
	this->m_num_grp_record += grp_records.size();
}

uint16_t
Igmpv3Report::GetGrpRecords (std::list<Igmpv3GrpRecord> &payload_grprecords) const
{
	NS_LOG_FUNCTION (this);

	uint16_t count = 0;

	for (std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin(); it != this->m_lst_grp_records.end(); ++it)
	{
		payload_grprecords.push_back((*it));
		++count;
	}

	return count;
}

Igmpv3Report
Igmpv3Report::MergeReports (Igmpv3Report &report1, Igmpv3Report &report2)
{
	std::list<Igmpv3GrpRecord> records1;
	uint16_t num_records1 = report1.GetGrpRecords(records1);
	if (num_records1 != records1.size())
	{
		NS_ASSERT (false);
	}

	std::list<Igmpv3GrpRecord> records2;
	uint16_t num_records2 = report2.GetGrpRecords(records2);
	if (num_records2 != records2.size())
	{
		NS_ASSERT (false);
	}

	Igmpv3Report retval;

	retval.PushBackGrpRecords(records1);
	retval.PushBackGrpRecords(records2);

	return retval;
}

}  // namespace ns3
