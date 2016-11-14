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

#ifndef IGMPV3_H
#define IGMPV3_H

#include "ns3/ipv4-address.h"
#include "ns3/network-module.h"
//#include "ns3/internet-module.h"
//#include "ns3/ipv4-interface-multicast.h"
#include "ns3/socket.h"
#include "ns3/header.h"
#include "ns3/nstime.h"
#include "ns3/timer.h"
#include "ns3/object.h"
#include <stdint.h>
#include <list>
#include <queue>
#include <set>

namespace ns3 {

class Ipv4InterfaceMulticast;
class IGMPv3InterfaceState;
class Igmpv3Header;
class Igmpv3Query;
class Igmpv3Report;
class Igmpv3GrpRecord;
class IGMPv3MaintenanceState;
class Igmpv3L4Protocol;

enum FILTER_MODE {
	INCLUDE = 0,
	EXCLUDE = 1
};

class IGMPv3SocketState : public Object {
private:
	Ptr<Socket> m_socket;
	//Ptr<Ipv4InterfaceMulticast> m_interface;
	Ptr<IGMPv3InterfaceState> m_associated_if_state;
	Ipv4Address m_multicast_address;
	ns3::FILTER_MODE m_filter_mode;
	std::list<Ipv4Address> m_lst_source_list;

public:
	static TypeId GetTypeId (void);

	IGMPv3SocketState ();

	void Initialize (Ptr<Socket> socket,
					   Ipv4Address multicast_address,
					   ns3::FILTER_MODE filter_mode,
					   std::list<Ipv4Address> const &lst_source_list);

	~IGMPv3SocketState (void);

	void SetAssociatedInterfaceState (Ptr<IGMPv3InterfaceState> associated_if_state);
	Ptr<IGMPv3InterfaceState> GetAssociatedInterfaceState (void);
	Ipv4Address GetGroupAddress (void);
	ns3::FILTER_MODE GetFilterMode (void);
	std::list<Ipv4Address> const & GetSrcList (void);
	void SetSrcList (std::list<Ipv4Address> const &src_list);

	friend bool operator == (IGMPv3SocketState const& lhs, IGMPv3SocketState const& rhs);
	friend bool operator < (IGMPv3SocketState const& lhs, IGMPv3SocketState const& rhs);
	void UnSubscribeIGMP (void);
	void StateChange (ns3::FILTER_MODE filter_mode, std::list<Ipv4Address> const &src_list);
};

class IGMPv3SocketStateList : public Object {
public:	//Object override
	static TypeId GetTypeId (void);
	IGMPv3SocketStateList ();
	virtual ~IGMPv3SocketStateList();
	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	virtual void DoDispose (void);
public:	//self-defined
	Ptr<IGMPv3InterfaceState> GetSocketState (Ptr<Socket> socket, Ptr<Ipv4InterfaceMulticast> interface, Ipv4Address multicast_address);
private:
	std::set<Ptr<IGMPv3InterfaceState> > m_set_socket_states;
};

class IGMPv3InterfaceState : public Object {
private:
	Ptr<Ipv4InterfaceMulticast> m_interface;
	Ipv4Address m_multicast_address;
	ns3::FILTER_MODE m_filter_mode;
	std::list<Ipv4Address> m_lst_source_list;
	//std::list<Ptr<Socket> > m_lst_sockets;
	std::list<Ptr<IGMPv3SocketState> > m_lst_associated_socket_state;

	//for generating records
	Ptr<IGMPv3InterfaceState> m_old_if_state;
//	*obsolete*/Just for retransmission of robustness whether there is not new state change
//	std::queue<Igmpv3Report> m_lst_pending_reports;
	//Pending block src changes records
	std::queue<Igmpv3GrpRecord> m_que_pending_block_src_chg_records;
	//Pending allow src changes records
	std::queue<Igmpv3GrpRecord> m_que_pending_allow_src_chg_records;
	//Pending filter mode changes records
	std::queue<Igmpv3GrpRecord> m_que_pending_filter_mode_chg_records;
//	*obsolete*/for check whether the a new state change occur during old state report is still being scheduled.
//	EventId m_event_robustness_retransmission;

public:
	static TypeId GetTypeId (void);

	IGMPv3InterfaceState (void);
	void Initialize (Ptr<Ipv4InterfaceMulticast> interface, Ipv4Address multicast_address);

	~IGMPv3InterfaceState (void);

	Ptr<Ipv4InterfaceMulticast> GetInterface (void);
	Ipv4Address GetGroupAddress (void);
	std::list<Ipv4Address> const & GetSrcList (void);
	std::list<Ipv4Address>::size_type GetSrcNum (void);
	void SetSrcList (std::list<Ipv4Address> const & src_list);
	ns3::FILTER_MODE GetFilterMode (void);

	friend bool operator == (IGMPv3InterfaceState const& lhs, IGMPv3InterfaceState const& rhs);
	friend bool operator < (IGMPv3InterfaceState const& lhs, IGMPv3InterfaceState const& rhs);
	void UnSubscribeIGMP (Ptr<IGMPv3SocketState> socket_state);
	/*
	 * \obsolete use IsFilterModeChanged() and IsSrcLstChanged() instead
	 * \breif Used for checking whether state changes occur
	 */
//	bool IsEqual (ns3::FILTER_MODE filter_mode, std::list<Ipv4Address> const &src_list);
//	bool IsEqual (IGMPv3InterfaceState if_state);
//	bool IsEqual (Ptr<IGMPv3InterfaceState> if_state);
	bool IsFilterModeChanged (IGMPv3InterfaceState if_state);
	bool IsFilterModeChanged (Ptr<IGMPv3InterfaceState> if_state);
	/*
	 * \breif Comparing to old state
	 */
	bool IsFilterModeChanged (void);
	bool IsSrcLstChanged (IGMPv3InterfaceState if_state);
	bool IsSrcLstChanged (Ptr<IGMPv3InterfaceState> if_state);
	/*
	 * \breif Comparing to old state
	 */
	bool IsSrcLstChanged (void);

	/*
	 * \breif Has pending records
	 */
	bool HasPendingRecords (void);

	/*
	 * \breif For reporting current State
	 */
	Igmpv3GrpRecord GenerateRecord (void);
	/*
	 * \breif For reporting state change
	 */
	Igmpv3GrpRecord GenerateRecord (ns3::FILTER_MODE old_filter_mode, std::list<Ipv4Address> const &old_src_list);

	/*
	 * \brief Compute interface state from socket states it associated with.
	 * \brief And also save old state
	 * \breif Trigger sending igmpv3 reports when state changes.
	 * \returns Whether the filter mode or the source list changed
	 * address or if loopback address was passed as argument
	 */
	void ComputeState (void);

	void ReportFilterModeChange (void);
//	void DoReportFilterModeChange (void);

	void ReportSrcLstChange (void);
//	void DoReportSrcLstChange (void);

	void AddPendingRecordsToReport (Igmpv3Report &report);

//	void DoRobustnessRetransmission (void);

	/*
	 * \brief Return a non-existent state defined by rfc 3376
	 */
	static Ptr<IGMPv3InterfaceState> GetNonExistentState (Ptr<Ipv4InterfaceMulticast> interface, Ipv4Address multicast_address);

	void AssociateSocketStateInterfaceState (Ptr<IGMPv3SocketState> socket_state);
private:
	void Invoke (Ptr<IGMPv3SocketState> socket_state);
	bool IsSocketStateExist (Ptr<IGMPv3SocketState> socket_state);
	bool CheckSubscribedAllSocketsIncludeMode (void);
	Ptr<IGMPv3InterfaceState> SaveOldInterfaceState (void);
	Ptr<IGMPv3InterfaceState> GetOldInterfaceState (void);
	Ptr<Igmpv3L4Protocol> GetIgmp (void);
};

class IGMPv3MaintenanceSrcRecord : public Object {
private:
	Ptr<IGMPv3MaintenanceState> m_group_state;
	Ipv4Address m_source_address;
	Timer m_srcTimer;
	uint8_t m_uint_retransmission_state;
public:
	static TypeId GetTypeId (void);
	explicit IGMPv3MaintenanceSrcRecord (void);
	~IGMPv3MaintenanceSrcRecord (void);
	friend bool operator == (IGMPv3MaintenanceSrcRecord const& lhs, IGMPv3MaintenanceSrcRecord const& rhs);
	Ipv4Address GetMulticastAddress (void) const;
	uint8_t GetRetransmissionState (void);
	void DecreaseRetransmissionState (void);
	void SetRetransmissionState (uint8_t state);
	void Initialize (Ptr<IGMPv3MaintenanceState> group_state, Ipv4Address src_address, Time delay);
	void UpdateTimer (Time delay);
	Time GetDelayLeft (void) const;
	bool IsTimerRunning (void);
private:
	void TimerExpire (void);
};

class IGMPv3MaintenanceState : public Object {
private:
	Ptr<Ipv4InterfaceMulticast> m_interface;
	Ipv4Address m_multicast_address;
	Timer m_groupTimer;
	ns3::FILTER_MODE m_filter_mode;
	std::list<Ptr<IGMPv3MaintenanceSrcRecord> > m_lst_src_records;
	uint8_t m_uint_retransmission_state;
public:
	static TypeId GetTypeId (void);
	explicit IGMPv3MaintenanceState (void);
	~IGMPv3MaintenanceState ();
	void Initialize (Ptr<Ipv4InterfaceMulticast> interface, Ipv4Address group_address, Time delay);
	Ipv4Address GetMulticastAddress (void) const;
	void GetCurrentSrcLst (std::list<Ipv4Address> &retval) const;
	void GetCurrentSrcLstTimerGreaterThanZero (std::list<Ipv4Address> &retval) const;
	void GetCurrentSrcLstTimerEqualToZero (std::list<Ipv4Address> &retval) const;
	ns3::FILTER_MODE GetFilterMode (void);
	void AddSrcRecord (Ptr<IGMPv3MaintenanceSrcRecord> src_record);
	void HandleGrpRecord (Igmpv3GrpRecord &record);
	void HandleQuery (void);
	void HandleQuery (std::list<Ipv4Address> const &src_lst);
	void DeleteSrcRecord (Ipv4Address src);
private:
	void SetFilterMode (ns3::FILTER_MODE filter_mode);
	Time GetGroupMembershipIntervalGMI (void);
	Time GetLastMemberQueryTimeLMQT (void);
	Time GetLastMemberQueryInterval (void);
	uint8_t GetLastMemberQueryCount (void);

	/*
	 * Update current src timers
	 */
	void UpdateSrcTimers (std::list<Ipv4Address> const &src_lst, Time delay);
	void DeleteSrcRecords (std::list<Ipv4Address> const &src_lst);
	void AddSrcRecord (Ipv4Address src, Time delay);
	void AddSrcRecords (std::list<Ipv4Address> const &src_lst, Time delay);
	void UpdateGrpTimer (Time delay);
	/*
	 * Update current src timers and add new src timers
	 */
	void UpdateSrcRecords (std::list<Ipv4Address> const &src_lst, Time delay);
	void SendQuery (Ipv4Address group_address, std::list<Ipv4Address> const &src_lst);
	void DoSendGroupNSrcSpecificQuery (Ipv4Address group_address, std::list<Ipv4Address> const &src_lst);
	void SendQuery (Ipv4Address group_address);
	void DoSendGroupSpecificQuery (Ipv4Address group_address);
	void TimerExpire (void);
	void DeleteExpiredSrcRecords (void);
	/*
	 * Lower group timer
	 */
	void LowerGrpTimer (Time delay);
	/*
	 * Lower group and source timers
	 */
	void LowerSrcTimer (std::list<Ipv4Address> const &src_lst, Time delay);
	void SetSrcRecordsRetransmissionStates (std::list<Ipv4Address> const &src_lst, uint8_t state);
	void DecreaseSrcRecordsRetransmissionStates (std::list<Ipv4Address> const &src_lst);
	void GetSrcRetransWTimerGreaterThanLMQT (std::list<Ipv4Address>& retval);
	void GetSrcRetransWTimerLowerOrEqualToLMQT (std::list<Ipv4Address>& retval);
	Ptr<Igmpv3L4Protocol> GetIgmp (void);
};

class PerInterfaceTimer : public Object {
public:
	Ptr<Ipv4InterfaceMulticast> m_interface;
	Timer m_softTimer;
};

class PerGroupInterfaceTimer : public Object {
public:
	Ptr<Ipv4InterfaceMulticast> m_interface;
	Ipv4Address m_group_address;
	Timer m_softTimer;
};

class Igmpv3Header: public Header {

/*	Igmpv3 Header format:
 *
	  0                   1                   2                   3
	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |  Type = 0x11  | Max Resp Code |           Checksum            |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 *
*/

public:
	enum TYPE {
		MEMBERSHIP_QUERY = (uint8_t)0x11,
		V3_MEMBERSHIP_REPORT = (uint8_t)0x22,
		V1_MEMBERSHIP_REPORT = (uint8_t)0x12,
		V2_MEMBERSHIP_REPORT = (uint8_t)0x16,
		V2_LEAVE_GROUP = (uint8_t)0x17
	};

public:
	static TypeId GetTypeId (void);
	Igmpv3Header ();
	virtual ~Igmpv3Header ();

public:
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;

public:	//minicing icmpv4

	void SetType (uint8_t type);
	uint8_t GetType (void);
	void SetMaxRespCode (uint8_t max_resp_code);
	uint8_t GetMaxRespCode (void);
	void EnableChecksum (void);

private:
	uint8_t m_type; //!< type of igmpv4 message
	uint8_t m_max_resp_code; //!< the maximum time allowed before sending a responding report
	uint16_t m_checksum;
	bool m_calcChecksum;	//!< mimicing ns3::icmpv4

};


class Igmpv3Query : public Header
{
	/*
	 * Query message format:
	 * 0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Group Address                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Source Address [1]                      |
      +-                                                             -+
      |                       Source Address [2]                      |
      +-                              .                              -+
      .                               .                               .
      .                               .                               .
      +-                                                             -+
      |                       Source Address [N]                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:	//Header override
	static TypeId GetTypeId (void);
	Igmpv3Query ();
	virtual ~Igmpv3Query ();

public:	//Header override
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;

public: //set
	void SetGroupAddress (uint32_t address);
	void SetGroupAddress (Ipv4Address address);
	void SetSFlag (bool b);
	void SetQRV (uint8_t qrv);
	void SetQQIC (uint8_t qqic);
	//void SetNumSrc (uint16_t num_src);
	void PushBackSrcAddress (Ipv4Address address);
	void PushBackSrcAddresses (std::list<Ipv4Address> const &lst_addresses);

public: //get
	uint32_t GetGroupAddress (void);
	bool isSFlagSet (void);
	uint8_t GetQRV (void);
	uint8_t GetQQIC (void);
	uint16_t GetNumSrc (void);
	uint16_t GetSrcAddresses (std::list<Ipv4Address> &payload_addresses) const;

private:
	Ipv4Address m_group_address; //!< group address

	struct Resv_S_Qrv {
	private:
		uint8_t Resv; //!< reserved field. Highest 4 bits must be empty according to format.
		uint8_t S; //!< suppress Router-side Processing, Only the 5th bit can be set
		uint8_t QRV; //!< querier's Robustness Variable. Lowest 5 bits must be empty

	public:
		Resv_S_Qrv (uint8_t i) {
			this->Resv = 0x00;
			this->S = (i&0x10);
			this->QRV = (i&0xe0);
		}

		uint8_t toUint8_t() const {
			return Resv + S + QRV;
		}

		void set_Resv (uint8_t i) {
			if (i > 0x0f)
			{
				//larger than 4 bits
				NS_ASSERT (false);
			}
			else
			{
				//must be smaller 4 bits
				this->Resv = (i & 0x0f);
			}
		}

		void set_S (bool flag) {
			if (true == flag)
			{
				this->S = 0x10;
			}
			else
			{
				this->S = 0x00;
			}
		}

		bool get_S (void) const {
			if (0x10 == this->S)
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		void set_QRV (uint8_t i) {
			if (i > 0x07)
			{
				//larger than 3 bits
				NS_ASSERT (false);
			}
			else
			{
				//must be smaller than 3 bits
				this->QRV = (i & 0x07) << 5;
			}
		}

		uint8_t get_QRV (void) const {
			return ((this->QRV) >> 5);
		}
	} m_resv_s_qrv;

	uint8_t m_qqic; //!< querier's Query Interval Code
	uint16_t m_num_srcs; //!< the number of sources

	std::list<Ipv4Address> m_lst_src_addresses;

};

class Igmpv3GrpRecord : public Header
{
	/*
	 * Igmpv3 group record format
	 *  0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Multicast Address                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Source Address [1]                      |
      +-                                                             -+
      |                       Source Address [2]                      |
      +-                                                             -+
      .                               .                               .
      .                               .                               .
      .                               .                               .
      +-                                                             -+
      |                       Source Address [N]                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                         Auxiliary Data                        .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:
	enum TYPE {
		MODE_IS_INCLUDE = (uint8_t)1,
		MODE_IS_EXCLUDE = (uint8_t)2,
		CHANGE_TO_INCLUDE_MODE = (uint8_t)3,
		CHANGE_TO_EXCLUDE_MODE = (uint8_t)4,
		ALLOW_NEW_SOURCES = (uint8_t)5,
		BLOCK_OLD_SOURCES = (uint8_t)6
	};

	static Igmpv3GrpRecord CreateBlockRecord (Ipv4Address multicast_address,
											  std::list<Ipv4Address> const &old_src_lst,
											  std::list<Ipv4Address> const &new_src_lst);
	static Igmpv3GrpRecord CreateBlockRecord (Ptr<IGMPv3InterfaceState> old_state,
											  Ptr<IGMPv3InterfaceState> new_state);
	static Igmpv3GrpRecord CreateAllowRecord (Ipv4Address multicast_address,
											  std::list<Ipv4Address> const &old_src_lst,
			   	   	   	   	   	   	   	   	  std::list<Ipv4Address> const &new_src_lst);
	static Igmpv3GrpRecord CreateAllowRecord (Ptr<IGMPv3InterfaceState> old_state,
			  	  	  	  	  	  	  	  	  Ptr<IGMPv3InterfaceState> new_state);
	static Igmpv3GrpRecord CreateStateChangeRecord (Ipv4Address multicast_address,
													ns3::FILTER_MODE filter_mode,
													std::list<Ipv4Address> const &src_lst);
	static Igmpv3GrpRecord CreateStateChangeRecord (Ptr<IGMPv3InterfaceState> old_state,
	  	  	  	  	  	  	  	  	  	  	  	  	Ptr<IGMPv3InterfaceState> new_state);
	static void GenerateGrpRecords (Ptr<IGMPv3InterfaceState> old_state,
									Ptr<IGMPv3InterfaceState> new_state,
									std::list<Igmpv3GrpRecord>& retval);
	static Igmpv3GrpRecord GenerateGrpRecord (Ptr<IGMPv3InterfaceState> if_state);
	//for group and source specific query
	static Igmpv3GrpRecord GenerateGrpRecord (Ptr<IGMPv3InterfaceState> if_state, std::list<Ipv4Address> const &src_list);


public:	//Header override
	static TypeId GetTypeId (void);
	Igmpv3GrpRecord ();
	virtual ~Igmpv3GrpRecord ();

public:	//Header override
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;

public:	//set
	void SetType (uint8_t type);
//	void SetAuxDataLen (uint8_t aux_data_len);
//	void SetNumSrcs (uint16_t num_srcs);
	void SetMulticastAddress (Ipv4Address address);
	void PushBackSrcAddress (Ipv4Address address);
	//void PushBackSrcAddresses (std::list<uint32> &lst_addresses);
	void PushBackSrcAddresses (std::list<Ipv4Address> const &lst_addresses);
	void PushBackAuxData (uint32_t aux_data);
	void PushBackAuxdata (std::list<uint32_t> &lst_aux_data);

public: //get
	uint8_t GetType (void) const;
	uint8_t GetAuxDataLen (void) const;
	uint16_t GetNumSrcs (void) const;
	Ipv4Address GetMulticastAddress (void) const;
	uint16_t GetSrcAddresses (std::list<Ipv4Address> &payload_addresses) const;
	uint8_t GetAuxData (std::list<uint32_t> &payload_data) const;

private:
	uint8_t m_record_type;
	uint8_t m_aux_data_len;	//in uintes of 32-bit word
	uint16_t m_num_srcs;
	Ipv4Address m_mul_address;
	std::list<Ipv4Address> m_lst_src_addresses;
	std::list<uint32_t> m_lst_aux_data;

};

class Igmpv3Report : public Header
{
	/*
	 * Igmpv3 report message format
	 *  0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |           Reserved            |  Number of Group Records (M)  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                        Group Record [1]                       .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                        Group Record [2]                       .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                               .                               |
      .                               .                               .
      |                               .                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                        Group Record [M]                       .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:	//Header override
	static TypeId GetTypeId (void);
	Igmpv3Report ();
	virtual ~Igmpv3Report ();

public:	//Header override
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;

public:
//	void SetNumGrpRecords (uint16_t num_grp_records);
	uint16_t GetNumGrpRecords (void) const;
	void PushBackGrpRecord (Igmpv3GrpRecord grp_record);
	void PushBackGrpRecords (std::list<Igmpv3GrpRecord> &lst_grp_records);
	uint16_t GetGrpRecords (std::list<Igmpv3GrpRecord> &payload_grprecords) const;
	static Igmpv3Report MergeReports (Igmpv3Report &report1, Igmpv3Report &report2);

private:
	uint16_t m_reserved;
	uint16_t m_num_grp_record;	//for reading
	std::list<Igmpv3GrpRecord> m_lst_grp_records;

};

} // namespace ns3

#endif /* IGMPV3_H */
