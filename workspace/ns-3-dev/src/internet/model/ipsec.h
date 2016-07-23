/*
 * ipsec.h
 *
 *  Created on: Jun 9, 2016
 *      Author: lim
 */

#ifndef SRC_INTERNET_MODEL_IPSEC_H_
#define SRC_INTERNET_MODEL_IPSEC_H_

#include "ns3/object.h"
#include "gsam.h"
#include "ns3/ipv4-address.h"
#include "ns3/log.h"
#include <list>
#include <set>
#include "ns3/timer.h"
#include "ns3/nstime.h"
#include "igmpv3-l4-protocol.h"

namespace ns3 {

class Node;
class Ipv4InterfaceMulticast;
class Ipv4Route;
class GsamSession;
class GsamSessionGroup;
class IpSecDatabase;
class IpSecSADatabase;
class IpSecPolicyEntry;
class IpSecPolicyDatabase;
class EncryptionFunction;
class IpSecSAEntry;
class GsamL4Protocol;

class GsamUtility {
public://static
	static uint32_t BytesToUint32 (const std::list<uint8_t>& lst_bytes);
	static uint64_t BytesToUint64 (const std::list<uint8_t>& lst_bytes);
	static void Uint32ToBytes (std::list<uint8_t>& lst_retval, uint32_t input_value);
	static void Uint64ToBytes (std::list<uint8_t>& lst_retval, uint64_t input_value);
};

class GsamConfig {
public:
	static Ipv4Address GetSecGrpAddressStart (void);
	static Ipv4Address GetSecGrpAddressEnd (void);
	static Time GetDefaultSessionTimeout (void);
	static IPsec::MODE GetDefaultIpsecMode (void);
	static uint8_t GetDefaultIpsecProtocolId (void);
	static IPsec::SA_Proposal_PROTOCOL_ID GetDefaultGSAProposalId (void);
	static Time GetDefaultRetransmitTimeout (void);
	static Ipv4Address GetIgmpv3DestGrpReportAddress (void);
};

class GsamInfo : public Object {

public:	//Object override
	static TypeId GetTypeId (void);
	GsamInfo ();
	virtual ~GsamInfo();
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
	uint64_t RegisterGsamSpi (void);
	uint32_t RegisterIpsecSpi (void);
	void SetRetransmissionDelay (Time time);
	void FreeGsamSpi (uint64_t spi);
	void FreeIpsecSpi (uint32_t spi);
	void SetSecGrpStart (Ipv4Address address);
	void SetSecGrpEnd (Ipv4Address address);
public: //const
	Time GetRetransmissionDelay (void) const;
	uint32_t GetLocalAvailableIpsecSpi (void) const;
	uint32_t GenerateIpsecSpi (void) const;
	bool IsIpsecSpiOccupied (uint32_t spi) const;
private:
	uint64_t GetLocalAvailableGsamSpi (void) const;
	void OccupyGsamSpi (uint64_t spi);
	void OccupyIpsecSpi (uint32_t spi);
private:	//fields
	std::set<uint64_t> m_set_occupied_gsam_spis;
	std::set<uint32_t> m_set_occupied_ipsec_spis;	//ah or esp
	Time m_retransmission_delay;
	Ipv4Address m_sec_group_start;
	Ipv4Address m_sec_group_end;
};

class GsamSa : public Object {
public:
	enum SA_TYPE {
		NOT_INITIATED = 0,
		GSAM_INIT_SA = 1,
		GSAM_KEK_SA = 2
	};

public:	//Object override
	static TypeId GetTypeId (void);
	GsamSa ();
	virtual ~GsamSa();
	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	virtual void DoDispose (void);
public:	//operator
	friend bool operator == (GsamSa const& lhs, GsamSa const& rhs);
public:	//self defined
	void SetSession (Ptr<GsamSession> session);
	void SetType (GsamSa::SA_TYPE type);
	void SetInitiatorSpi (uint64_t spi);
	void SetResponderSpi (uint64_t spi);
	bool IsHalfOpen (void) const;
public:	//const
	GsamSa::SA_TYPE GetType (void) const;
	uint64_t GetInitiatorSpi (void) const;
	uint64_t GetResponderSpi (void) const;
private:
	void FreeLocalSpi (void);
private:	//fields
	GsamSa::SA_TYPE m_type;
	uint64_t m_initiator_spi;
	uint64_t m_responder_spi;
	Ptr<GsamSession> m_ptr_session;
	Ptr<EncryptionFunction> m_ptr_encrypt_fn;
};

class EncryptionFunction : public Object {
public:	//Object override
	static TypeId GetTypeId (void);
	EncryptionFunction ();
	virtual ~EncryptionFunction();
	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	virtual void DoDispose (void);
};

class GsaPushSession : public Object {
public:	//Object override
	static TypeId GetTypeId (void);
	GsaPushSession ();
	virtual ~GsaPushSession();
	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	virtual void DoDispose (void);

private:	//fields
	std::list<Ptr<GsamSession> > m_lst_ptr_sessions_sent;
	Ptr<GsamSessionGroup> m_ptr_gsa_session_group;
};

class GsamSession : public Object {
public:
	enum PHASE_ONE_ROLE {
		P1_UNINITIALIZED = 0,
		INITIATOR = 1,
		RESPONDER = 2,
	};

	enum PHASE_TWO_ROLE {
		P2_UNINITIALIZED = 10,
		QUERIER = 11,
		NON_QUERIER = 12,
		GROUP_MEMBER = 13
	};

public:	//Object override
	static TypeId GetTypeId (void);
	GsamSession ();
	virtual ~GsamSession();
	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	virtual void DoDispose (void);
public:	//static
	static GsamSession::PHASE_ONE_ROLE GetLocalRole (const IkeHeader& incoming_header);
public:	//operator
	friend bool operator == (GsamSession const& lhs, GsamSession const& rhs);
public:	//self defined
	void SetPhaseOneRole (GsamSession::PHASE_ONE_ROLE role);
	//init sa
	void SetInitSaInitiatorSpi (uint64_t spi);
	void SetInitSaResponderSpi (uint64_t spi);
	//kek sa
	void SetKekSaInitiatorSpi (uint64_t spi);
	void SetKekSaResponderSpi (uint64_t spi);
	//
	void SetDatabase (Ptr<IpSecDatabase> database);
	void EtablishGsamInitSa (void);
	void EtablishGsamKekSa (void);
	void IncrementMessageId (void);
	void SetMessageId (uint32_t message_id);
	Timer& GetRetransmitTimer (void);
	void SceduleTimeout (Time delay);
	bool IsRetransmit (void);
	void SetPeerAddress (Ipv4Address peer_address);
	void SetGroupAddress (Ipv4Address group_address);
	void SetRelatedGsaR (Ptr<IpSecSAEntry> gsa_r);
	void AssociateGsaQ (Ptr<IpSecSAEntry> gsa_q);
	void AssociateWithSessionGroup (Ptr<GsamSessionGroup> session_group);
	void AssociateWithPolicy (Ptr<IpSecPolicyEntry> policy);
public: //const
	bool HaveInitSa (void) const;
	bool HaveKekSa (void) const;
	Ptr<GsamInfo> GetInfo (void) const;
	Ptr<IpSecDatabase> GetDatabase (void) const;
	uint64_t GetKekSaResponderSpi (void) const;
	uint64_t GetKekSaInitiatorSpi (void) const;
	uint64_t GetInitSaResponderSpi (void) const;
	uint64_t GetInitSaInitiatorSpi (void) const;
	GsamSession::PHASE_ONE_ROLE GetPhaseOneRole (void) const;
	uint32_t GetCurrentMessageId (void) const;
	Ipv4Address GetPeerAddress (void) const;
	Ipv4Address GetGroupAddress (void) const;
	Ptr<IpSecSAEntry> GetRelatedGsaR (void) const;
	Ptr<IpSecSAEntry> GetRelatedGsaQ (void) const;
	Ptr<IpSecPolicyEntry> GetRelatedPolicy (void) const;
	bool IsHostQuerier (void) const;
	bool IsHostGroupMember (void) const;
	bool IsHostNonQuerier (void) const;
private:
	void TimeoutAction (void);
private:	//fields
	uint32_t m_current_message_id;
	Ipv4Address m_peer_address;
	Ptr<GsamSessionGroup> m_ptr_session_group;
	Ipv4Address m_group_address;
	GsamSession::PHASE_ONE_ROLE m_p1_role;
	Ptr<GsamSa> m_ptr_init_sa;
	Ptr<GsamSa> m_ptr_kek_sa;
	Ptr<IpSecDatabase> m_ptr_database;
	Timer m_timer_retransmit;
	Timer m_timer_timeout;
	Ptr<IpSecSAEntry> m_ptr_related_gsa_r;
};

class GsamSessionGroup : public Object {
public:	//Object override
	static TypeId GetTypeId (void);
	GsamSessionGroup ();
	virtual ~GsamSessionGroup();
	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	virtual void DoDispose (void);
public:	//operators
	friend bool operator == (GsamSessionGroup const& lhs, GsamSessionGroup const& rhs);
public: //self-defined
	void SetGroupAddress (Ipv4Address group_address);
	void SetDatabase (Ptr<IpSecDatabase> database);
	void AssociateWithGsaQ (Ptr<IpSecSAEntry> gsa_q);
	void AssociateWithPolicy (Ptr<IpSecPolicyEntry> policy);
	void PushBackSession (Ptr<GsamSession> session);
	void RemoveSession (Ptr<GsamSession> session);
	std::list<Ptr<GsamSession> >& GetSessions (void);
public:	//const
	Ipv4Address GetGroupAddress (void) const;
	Ptr<IpSecDatabase> GetDatabase (void) const;
	Ptr<IpSecSAEntry> GetRelatedGsaQ (void) const;
	Ptr<IpSecPolicyEntry> GetRelatedPolicy (void) const;
	const std::list<Ptr<GsamSession> >& GetSessionsConst (void) const;
private:	//fields
	Ipv4Address m_group_address;
	Ptr<IpSecDatabase> m_ptr_database;
	Ptr<IpSecSAEntry> m_ptr_related_gsa_q;
	std::list<Ptr<GsamSession> > m_lst_sessions;
	Ptr<IpSecPolicyEntry> m_ptr_related_policy;
};

class IpSecSAEntry : public Object {
public:	//Object override
	static TypeId GetTypeId (void);
	IpSecSAEntry ();
	virtual ~IpSecSAEntry();
	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();
private:
	virtual void DoDispose (void);
public:	//self-defined, operators
	friend bool operator == (IpSecSAEntry const& lhs, IpSecSAEntry const& rhs);
	friend bool operator < (IpSecSAEntry const& lhs, IpSecSAEntry const& rhs);
public:
	void SetSpi (uint32_t spi);
	void SetSAD (Ptr<IpSecSADatabase> sad);
	void AssociatePolicy (Ptr<IpSecPolicyEntry> policy);
public:	//const
	uint32_t GetSpi (void) const;
	Ptr<IpSecPolicyEntry> GetPolicyEntry (void) const;
private:	//fields
	uint32_t m_spi;
	Ptr<EncryptionFunction> m_ptr_encrypt_fn;
	Ptr<IpSecSADatabase> m_ptr_sad;
	Ptr<IpSecPolicyEntry> m_ptr_policy;
};

class IpSecSADatabase : public Object {
public:	//Object override
	static TypeId GetTypeId (void);
	IpSecSADatabase ();
	virtual ~IpSecSADatabase();
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
	Ptr<IpSecSAEntry> CreateIpSecSAEntry (Spi spi);
	void RemoveEntry (Ptr<IpSecSAEntry> entry);
	void AssociatePolicyEntry (Ptr<IpSecPolicyEntry> policy);
	void SetRootDatabase (Ptr<IpSecDatabase> database);
public:	//const
	Ptr<IpSecDatabase> GetRootDatabase (void) const;
	Ptr<IpSecSAEntry> GetIpsecSAEntry (uint32_t spi) const;
	Ptr<GsamInfo> GetInfo (void) const;
private:
	void PushBackEntry (Ptr<IpSecSAEntry> entry);
private:	//fields
	Ptr<IpSecDatabase> m_ptr_root_database;
	Ptr<IpSecPolicyEntry> m_ptr_policy_entry;	//inbound, outbound logical database ptr in policy entry
	std::list<Ptr<IpSecSAEntry> > m_lst_entries;
};

class IpSecPolicyEntry : public Object {
public:
	enum PROCESS_CHOICE {
		DISCARD = 0,
		BYPASS = 1,
		PROTECT = 2
	};

	enum PROTOCOL_ID {
		IGMP = 2,
		ESP = 50,
		AH = 51
	};

public:	//Object override
	static TypeId GetTypeId (void);
	IpSecPolicyEntry ();
	virtual ~IpSecPolicyEntry();
	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	virtual void DoDispose (void);
public:	//const
	IpSecPolicyEntry::PROCESS_CHOICE GetProcessChoice (void) const;
	uint8_t GetProtocolNum (void) const;
	IPsec::MODE GetIpsecMode (void) const;
	uint16_t GetTranSrcStartingPort (void) const;
	uint16_t GetTranSrcEndingPort (void) const;
	uint16_t GetTranDestStartingPort (void) const;
	uint16_t GetTranDestEndingPort (void) const;
	Ipv4Address GetSrcAddressRangeStart (void) const;
	Ipv4Address GetSrcAddressRangeEnd (void) const;
	Ipv4Address GetDestAddressRangeStart (void) const;
	Ipv4Address GetDestAddressRangeEnd (void) const;
	Ipv4Address GetSrcAddress (void) const;
	Ipv4Address GetDestAddress () const;
	Ptr<IpSecPolicyDatabase> GetSPD (void) const;
public:
	void SetProcessChoice (IpSecPolicyEntry::PROCESS_CHOICE process_choice);
	void SetProtocolNum (uint8_t protocol_id);
	void SetIpsecMode (IPsec::MODE mode);
	void SetTranSrcStartingPort (uint16_t port_num);
	void SetTranSrcEndingPort (uint16_t port_num);
	void SetTranDestStartingPort (uint16_t port_num);
	void SetTranDestEndingPort (uint16_t port_num);
	void SetTranSrcPortRange (uint16_t range_start, uint16_t range_end);
	void SetTranDestPortRange (uint16_t range_start, uint16_t range_end);
	void SetSrcAddressRange (Ipv4Address range_start, Ipv4Address range_end);
	void SetDestAddressRange (Ipv4Address range_start, Ipv4Address range_end);
	void SetSingleSrcAddress (Ipv4Address address);
	void SetSingleDestAddress (Ipv4Address address);
	void SetSPD (Ptr<IpSecPolicyDatabase> spd);
	Ptr<IpSecSADatabase> GetOutboundSAD (void);
	Ptr<IpSecSADatabase> GetInboundSAD (void);
public:	//operator
	friend bool operator == (IpSecPolicyEntry const& lhs, IpSecPolicyEntry const& rhs);
private:
	Ipv4Address m_src_starting_address;
	Ipv4Address m_src_ending_address;
	Ipv4Address m_dest_starting_address;
	Ipv4Address m_dest_ending_address;
	uint8_t m_ip_protocol_num;
	IPsec::MODE m_ipsec_mode;
	uint16_t m_src_transport_protocol_starting_num;
	uint16_t m_src_transport_protocol_ending_num;
	uint16_t m_dest_transport_protocol_starting_num;
	uint16_t m_dest_transport_protocol_ending_num;
	IpSecPolicyEntry::PROCESS_CHOICE m_process_choise;
	Ptr<IpSecPolicyDatabase> m_ptr_spd;
	Ptr<IpSecSADatabase> m_ptr_outbound_sad;
	Ptr<IpSecSADatabase> m_ptr_inbound_sad;
};

class IpSecPolicyDatabase : public Object {

public:	//Object override
	static TypeId GetTypeId (void);
	IpSecPolicyDatabase ();
	virtual ~IpSecPolicyDatabase();
	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	virtual void DoDispose (void);
public:
	void PushBackEntry (Ptr<IpSecPolicyEntry> entry);
	void RemoveEntry (Ptr<IpSecPolicyEntry> entry);
	Ptr<IpSecPolicyEntry> CreatePolicyEntry (void);
	void SetRootDatabase (Ptr<IpSecDatabase> database);
public:	//const
	Ptr<IpSecDatabase> GetRootDatabase (void) const;
	Ptr<GsamInfo> GetInfo (void) const;
private:	//fields
	Ptr<IpSecDatabase> m_ptr_root_database;
	std::list<Ptr<IpSecPolicyEntry> > m_lst_entries;
};

class IpSecDatabase : public Object {

public:	//Object override
	static TypeId GetTypeId (void);
	IpSecDatabase ();
	virtual ~IpSecDatabase();
	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	virtual void DoDispose (void);

public:	//self defined
	Ptr<GsamSession> CreateSession (void);
	Ptr<GsamSession> CreateSession (Ipv4Address group_address, Ipv4Address peer_address);
	Ptr<GsamSessionGroup> GetSessionGroup (Ipv4Address group_address);
	std::list<Ptr<GsamSessionGroup> >& GetSessionGroups (void);
	void RemoveSession (Ptr<GsamSession> session);
	void RemoveSessionGroup (Ptr<GsamSessionGroup> session_group);
	Time GetRetransmissionDelay (void);
	Ptr<IpSecPolicyDatabase> GetSPD (void);
	Ptr<IpSecSADatabase> GetSAD (void);
	void SetGsam (Ptr<GsamL4Protocol> gsam);
public:	//const
	Ptr<GsamInfo> GetInfo (void) const;
	Ptr<GsamSession> GetPhaseOneSession (GsamSession::PHASE_ONE_ROLE local_p1_role, uint64_t initiator_spi, uint64_t responder_spi, uint32_t message_id, Ipv4Address peer_address) const;
	Ptr<GsamSession> GetPhaseOneSession (GsamSession::PHASE_ONE_ROLE local_p1_role, uint64_t initiator_spi, uint32_t message_id, Ipv4Address peer_address) const;
	Ptr<GsamSession> GetPhaseTwoSession (uint64_t initiator_spi, uint64_t responder_spi, uint32_t message_id, Ipv4Address peer_address) const;
	Ptr<GsamSession> GetSession (const IkeHeader& header, Ipv4Address peer_address) const;
	Ptr<IpSecPolicyDatabase> GetPolicyDatabase (void) const;
	Ptr<IpSecSADatabase> GetIpSecSaDatabase (void) const;
	Ptr<Igmpv3L4Protocol> GetIgmp (void) const;
private:
	Ptr<GsamSessionGroup> CreateSessionGroup (Ipv4Address group_address);
private:	//fields
	std::list<Ptr<GsamSession> > m_lst_ptr_all_sessions;
	std::list<Ptr<GsamSessionGroup> > m_lst_ptr_session_groups;
	uint32_t m_window_size;
	Ptr<IpSecPolicyDatabase> m_ptr_spd;
	Ptr<IpSecSADatabase> m_ptr_sad;
	Ptr<GsamInfo> m_ptr_info;
	Ptr<GsamL4Protocol> m_ptr_gsam;
};

} /* namespace ns3 */



#endif /* SRC_INTERNET_MODEL_IPSEC_H_ */
