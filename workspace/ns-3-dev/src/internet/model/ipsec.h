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
#include "ns3/ipv4-interface-container-multicast.h"
#include "igmpv3-l4-protocol.h"
#include <string>
#include <map>
#include "ns3/ip-l4-protocol-multicast.h"

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
	static void Uint32ToBytes (std::list<uint8_t>& lst_retval, const uint32_t input_value);
	static void Uint64ToBytes (std::list<uint8_t>& lst_retval, const uint64_t input_value);
	static Ipv4Address CheckAndGetGroupAddressFromTrafficSelectors (const IkeTrafficSelector& ts_src, const IkeTrafficSelector& ts_dest);
	static std::pair<IkeTrafficSelector, IkeTrafficSelector> GetTsPairFromGroupAddress (Ipv4Address group_address);
	static void LstSpiToLstU32 (const std::list<Ptr<Spi> >& lst_spi, std::list<uint32_t>& retval_lst_u32);
	static void LstSpiToSetU32 (const std::list<Ptr<Spi> >& lst_spi, std::set<uint32_t>& retval_lst_u32);
	static uint8_t ConvertSaProposalIdToIpProtocolNum (IpSec::SA_Proposal_PROTOCOL_ID sa_protocol_id);
};

class GsamConfig : public Object {
public:	//Object override
	static TypeId GetTypeId (void);
	GsamConfig ();
	virtual ~GsamConfig();
	virtual TypeId GetInstanceTypeId (void) const;
public:	//static methods
	static IpSec::MODE GetDefaultIpsecMode (void);
	static uint8_t GetDefaultIpsecProtocolId (void);
	static IpSec::SA_Proposal_PROTOCOL_ID GetDefaultGSAProposalId (void);
	static Ipv4Address GetIgmpv3DestGrpReportAddress (void);
	static Ptr<GsamConfig> GetSingleton (void);
	static bool IsFalseByPercentage (uint16_t percentage_0_to_100);
	static void ReadAndParse (Ptr<GsamConfig> singleton);
public:	//log method
	static void Log (	const std::string& func_name,
						uint32_t node_id,
						const Ptr<GsamSession> session,
						uint32_t gsa_push_id,
						uint32_t gsa_q_spi,
						uint32_t gsa_r_spi);
	static void Log (	const std::string& func_name,
							uint32_t node_id,
							const Ptr<GsamSession> session,
							bool retransmit = false,
							Ptr<Packet> packet = 0);
	static void Log (	const std::string& func_name,
						uint32_t node_id,
						const Ptr<GsamSession> session,
						uint32_t gsa_push_id);
	static void Log (	const std::string& func_name,
							uint32_t node_id,
							uint32_t gsa_push_id);
	static void LogGsaQ (const std::string& msg, uint32_t gsa_q_spi);
	static void LogGsaR (const std::string& msg, uint32_t gsa_r_spi);
	static void LogMsg (const std::string& msg);
public:	//
	Ipv4Address GetAnUnusedSecGrpAddress (void);
	Ipv4Address GetAnUnusedUnsecGrpAddress (void);
	void SetupIgmpAndGsam (const Ipv4InterfaceContainerMulticast& interfaces, uint16_t num_nqs = 2);
	void LogJoinStart (uint32_t node_id, Ipv4Address group_address);
	void LogJoinFinish (uint32_t node_id, Ipv4Address group_address);
	void LogIgmpMsgSent (uint32_t node_id, const Ptr<const Packet> packet, Ipv4Address dest);
	void LogIgmpMsgReceived (uint32_t node_id, const Ptr<const Packet> packet, Ipv4Address src);
public:	//const
	//Gsam Configs
	uint16_t GetSpiRejectPropability (void) const;
	Ipv4Address GetQAddress (void) const;
	Time GetDefaultRetransmitTimeoutInSeconds (void) const;
	Time GetDefaultSessionTimeoutSeconds (void) const;
	Ipv4Address GetAUsedSecGrpAddress (void) const;
	Ipv4Address GetAUsedUnsecGrpAddress (void) const;
	uint16_t GetNumberOfNodes (void) const;
	uint16_t GetNumberOfNqs (void) const;
	bool IsNodeIsNq (uint32_t node_id) const;
	Time GetNqJoinTimeInSeconds (void) const;
	Time GetGmJoinTimeInSeconds (void) const;
	uint16_t GetNumberOfRetransmission (void) const;
	bool IsRetransmissionDisable (void) const;
	uint16_t GetGmJoinEventNumber (void) const;
	Ipv4Address GetSecureGroupAddressRangeStart (void) const;
	Ipv4Address GetSecureGroupAddressRangeEnd (void) const;
	bool IsGroupAddressSecureGroup (Ipv4Address group_address) const;
	Time GetDefaultGroupTimerDelayInSeconds (void) const;
	//Igmp Configs
	Time GetUnsolicitedReportIntervalInSeconds (void) const;
	uint8_t GetRobustnessValue (void) const;
	uint8_t GetMaxRespCode (void) const;
	uint8_t GetQQIC (void) const;
	uint8_t GetQRV (void) const;
	bool GetDefaultSFlag (void) const;
	uint16_t GetJoinSecureGroupProbability (void) const;
	Ipv4Address GetDestinationAddressForIgmpv3UnsecuredQuery (void) const;
	Ipv4Address GetDestinationAddressForIgmpv3UnsecuredReport (void) const;
	uint32_t GetNodeIdByAddress (Ipv4Address node_interface_address) const;
private://private methods
	void SetQAddress (Ipv4Address address);
private:	//static member
	static Ptr<GsamConfig> m_ptr_config_instance;
	const static std::string m_path_config;
	const static std::string m_path_result;
private:
	std::map<std::string, std::string> m_map_settings;
	Ipv4Address m_q_unicast_address;
	std::set<uint32_t> m_set_used_sec_grp_addresses;
	std::set<uint32_t> m_set_used_unsec_grp_addresses;
	std::map<uint32_t, uint32_t> m_map_u32_ipv4addr_to_node_id;
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
	uint32_t RegisterGsaPushId (void);
	void SetRetransmissionDelay (Time time);
	void FreeGsamSpi (uint64_t spi);
	void FreeIpsecSpi (uint32_t spi);
	void FreeGsaPushId (uint32_t gsa_push_id);
	void SetSecGrpStart (Ipv4Address address);
	void SetSecGrpEnd (Ipv4Address address);
	void OccupyIpsecSpi (uint32_t spi);
	void InsertDeletedGsaPushId (uint32_t gsa_push_id);
public: //const
	Time GetRetransmissionDelay (void) const;
	uint32_t GetLocalAvailableIpsecSpi (void) const;
	uint32_t GetLocalAvailableIpsecSpi (const std::set<uint32_t>& external_occupied_u32_set) const;
	uint32_t GenerateIpsecSpi (void) const;
	bool IsIpsecSpiOccupied (uint32_t spi) const;
	bool IsGsaPushIdDeleted (uint32_t gsa_push_id) const;
private:
	uint64_t GetLocalAvailableGsamSpi (void) const;
	uint32_t GetLocalAvailableGsaPushId (void) const;
	void OccupyGsamSpi (uint64_t spi);
	void OccupyGsaPushId (uint32_t gsa_push_id);
public:
	static uint32_t GetNotOccupiedU32 (const std::set<uint32_t>& set_u32_occupied);
private:	//fields
	std::set<uint64_t> m_set_occupied_gsam_spis;
	std::set<uint32_t> m_set_occupied_ipsec_spis;	//ah or esp
	std::set<uint32_t> m_set_occupied_gsa_push_ids;
	Time m_retransmission_delay;
	Ipv4Address m_sec_group_start;
	Ipv4Address m_sec_group_end;
	std::set<uint32_t> m_set_deleted_gsa_push_id;
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
public:
	enum GSA_PUSH_STATUS {
		NONE = 0,
		GSA_PUSH_ACK = 1,
		SPI_CONFLICT_RESOLVE = 2
	};

	enum SPI_REQUEST_TYPE {
		GSA_Q_SPI_REQUEST = 1,
		GSA_R_SPI_REQUEST = 2
	};
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
public:	//operator
	friend bool operator < (GsaPushSession const& lhs, GsaPushSession const& rhs);
	friend bool operator == (GsaPushSession const& lhs, GsaPushSession const& rhs);
public:	//static
	static Ptr<GsaPushSession> CreatePushSession(uint32_t id);
public:	//non-const
	void SetStatus (GsaPushSession::GSA_PUSH_STATUS status);
	void SetDatabase (Ptr<IpSecDatabase> database);
	void SetGmSession (Ptr<GsamSession> gsam_gm_session);
	void SelfRemoval (void);
	void MarkGmSessionReplied (void);
	void MarkNqSessionReplied (Ptr<GsamSession> nq_session);
	void MarkOtherGmSessionReplied (Ptr<GsamSession> other_gm_session);
	void PushBackNqSession (Ptr<GsamSession> nq_session);
	void PushBackOtherGmSession (Ptr<GsamSession> other_gm_session);
	Ptr<IpSecSAEntry> CreateGsaQ (uint32_t spi);
	Ptr<IpSecSAEntry> CreateGsaR (uint32_t spi);
	void InstallGsaPair (void);
	void SwitchStatus (void);
	void AggregateGsaQSpiNotification (const std::set<uint32_t>& set_spi_notification);
	void AggregateGsaRSpiNotification (const std::set<uint32_t>& set_spi_notification);
	void GenerateNewSpisAndModifySa (void);	//this method may also invoke GsaPushSession::InstallGsaPair();
	void AlterRejectedGsaAndAggregatePacket (Ptr<Packet> retval_packet_for_nqs,
											 std::list<std::pair<Ptr<GsamSession>, Ptr<Packet> > >& retval_lst_gm_session_packet_bundles);
	void PushBackNqRejectionGroupNotifySub (Ptr<IkeGroupNotifySubstructure> sub);
	void SetFlagGmsSpiRequested (void);
	void SetFlagNqsSpiRequested (void);
public:	//const
	uint32_t GetId (void) const;
	GsaPushSession::GSA_PUSH_STATUS GetStatus (void) const;
	bool IsAllReplied (void) const;
	const Ptr<IpSecSAEntry> GetGsaQ (void) const;
	const Ptr<IpSecSAEntry> GetGsaR (void) const;
	uint32_t GetOldGsaQSpi (void) const;
	uint32_t GetOldGsaRSpi (void) const;
	Ptr<GsamSession> GetGmSession (void) const;
	bool IsGmsSpiRequested (void) const;
	bool IsNqsSpiRequested (void) const;
	const std::set<Ptr<GsamSession> >& GetNqSessions (void) const;
	const std::set<Ptr<GsamSession> >& GetOtherGmSessions (void) const;
private:
	void ClearNqSessions (void);
	void ClearOtherGmSessions (void);
private:	//fields
	uint32_t m_id;
	GsaPushSession::GSA_PUSH_STATUS m_status;
	bool m_flag_gms_spi_requested;
	bool m_flag_nqs_spi_requested;
	Ptr<IpSecDatabase> m_ptr_database;
	Ptr<GsamSession> m_ptr_gm_session;
	bool m_flag_gm_session_acked_notified;

	//nq sessions
	std::set<Ptr<GsamSession> > m_set_ptr_nq_sessions_sent_unreplied;
	std::set<Ptr<GsamSession> > m_set_ptr_nq_sessions_acked_notified;

	//other gm sessions that need updates, for spi request only
	std::set<Ptr<GsamSession> > m_set_ptr_other_gm_sessions_sent_unreplied;
	std::set<Ptr<GsamSession> > m_set_ptr_other_gm_sessions_replied_notified;

	Ptr<IpSecSAEntry> m_ptr_gsa_q_to_install;
	uint32_t m_gsa_q_spi_before_revision;
	Ptr<IpSecSAEntry> m_ptr_gsa_r_to_install;
	uint32_t m_gsa_r_spi_before_revision;
	std::set<uint32_t> m_set_aggregated_gsa_q_spi_notification;
	std::set<uint32_t> m_set_aggregated_gsa_r_spi_notification;
	std::list<Ptr<IkeGroupNotifySubstructure> > m_lst_nq_rejected_spis_subs;
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
//	friend bool operator == (GsamSession const& lhs, GsamSession const& rhs);
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
	void SetPeerAddress (Ipv4Address peer_address);
	void SetGroupAddress (Ipv4Address group_address);
	void SetRelatedGsaR (Ptr<IpSecSAEntry> gsa_r);
	void AssociateGsaQ (Ptr<IpSecSAEntry> gsa_q);
	void AssociateWithSessionGroup (Ptr<GsamSessionGroup> session_group);
	void AssociateWithPolicy (Ptr<IpSecPolicyEntry> policy);
	void SetGsaPushSession (Ptr<GsaPushSession> gsa_push_session);
	void InsertGsaPushSession (Ptr<GsaPushSession> gsa_push_session);
	void ClearGsaPushSession (void);
	void ClearGsaPushSession (const Ptr<GsaPushSession> gsa_push_session);
	Ptr<GsaPushSession> CreateAndSetGsaPushSession (void);
	void SetCachePacket (Ptr<Packet> packet);
	void SetNumberRetransmission (uint16_t number_retransmission);
	void DecrementNumberRetransmission (void);
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
	Ptr<GsaPushSession> GetGsaPushSession (void) const;
	Ptr<GsaPushSession> GetGsaPushSession (uint32_t gsa_push_id) const;
	Ptr<Packet> GetCachePacket (void) const;
	Ptr<GsamSessionGroup> GetSessionGroup (void) const;
	bool IsRetransmit (void) const;
	uint16_t GetRemainingRetransmissionCount (void) const;
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
	Ptr<GsaPushSession> m_ptr_push_session;
	//nq session or
	//other gm sessions for spi request
	std::set<Ptr<GsaPushSession> > m_set_ptr_push_sessions;
	uint16_t m_number_retranmission;
	Ptr<Packet> m_last_sent_packet;
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
	void EtablishPolicy (Ipv4Address group_address,
							uint8_t protocol_id,
							IpSec::PROCESS_CHOICE policy_process_choice,
							IpSec::MODE ipsec_mode);
	void EtablishPolicy (	const IkeTrafficSelector& ts_src,
							const IkeTrafficSelector& ts_dest,
							uint8_t protocol_id,
							IpSec::PROCESS_CHOICE policy_process_choice,
							IpSec::MODE ipsec_mode);
	void InstallGsaQ (uint32_t spi);
	void InstallGsaR (uint32_t spi);
	Ptr<IpSecPolicyEntry> GetRelatedPolicy (void);
public:	//const
	Ipv4Address GetGroupAddress (void) const;
	Ptr<IpSecDatabase> GetDatabase (void) const;
	Ptr<IpSecSAEntry> GetRelatedGsaQ (void) const;
	const std::list<Ptr<GsamSession> >& GetSessionsConst (void) const;
	Ptr<GsamSession> GetSessionByGsaRSpi (uint32_t gsa_r_spi);
private:
	Ptr<IpSecSAEntry> InstallInboundGsa (uint32_t spi);
	Ptr<IpSecSAEntry> InstallOutboundGsa (uint32_t spi);
private:	//fields
	Ipv4Address m_group_address;
	Ptr<IpSecDatabase> m_ptr_database;
	Ptr<IpSecSAEntry> m_ptr_related_gsa_q;
	std::list<Ptr<GsamSession> > m_lst_sessions;
	Ptr<IpSecPolicyEntry> m_ptr_related_policy;
};

class IpSecSAEntry : public Object {
public:
	enum DIRECTION {
		NO_DIRECTION = 0,
		INBOUND = 1,
		OUTBOUND = 2
	};
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
	void SetInbound (void);
	void SetOutbound (void);
public:	//const
	uint32_t GetSpi (void) const;
	Ptr<IpSecPolicyEntry> GetPolicyEntry (void) const;
	bool IsInbound (void) const;
	bool IsOutbound (void) const;
private:	//fields
	IpSecSAEntry::DIRECTION m_direction;
	uint32_t m_spi;
	Ptr<EncryptionFunction> m_ptr_encrypt_fn;
	Ptr<IpSecSADatabase> m_ptr_sad;
	Ptr<IpSecPolicyEntry> m_ptr_policy;
};

class IpSecSADatabase : public Object {
public:
	enum DIRECTION {
		NO_DIRECTION = 0,
		INBOUND = 1,
		OUTBOUND = 2
	};
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
	Ptr<IpSecSAEntry> CreateIpSecSAEntry (uint32_t spi);
	void RemoveEntry (Ptr<IpSecSAEntry> entry);
	void AssociatePolicyEntry (Ptr<IpSecPolicyEntry> policy);
	void SetRootDatabase (Ptr<IpSecDatabase> database);
	void SetDirection (IpSecSADatabase::DIRECTION sad_direction);
public:	//const
	Ptr<IpSecDatabase> GetRootDatabase (void) const;
	Ptr<IpSecSAEntry> GetIpsecSAEntry (uint32_t spi) const;
	Ptr<GsamInfo> GetInfo (void) const;
	void GetSpis (std::list<Ptr<Spi> >& retval) const;
	IpSecSADatabase::DIRECTION GetDirection (void) const;
private:
	void PushBackEntry (Ptr<IpSecSAEntry> entry);
private:	//fields
	IpSecSADatabase::DIRECTION m_direction;
	Ptr<IpSecDatabase> m_ptr_root_database;
	Ptr<IpSecPolicyEntry> m_ptr_policy_entry;	//inbound, outbound logical database ptr in policy entry
	std::list<Ptr<IpSecSAEntry> > m_lst_entries;
};

class IpSecPolicyEntry : public Object {
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
	IpSec::PROCESS_CHOICE GetProcessChoice (void) const;
	uint8_t GetProtocolNum (void) const;
	IpSec::MODE GetIpsecMode (void) const;
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
	IkeTrafficSelector GetTrafficSelectorSrc (void) const;
	IkeTrafficSelector GetTrafficSelectorDest (void) const;
	void GetInboundSpis (std::list<Ptr<Spi> >& retval) const;
public:
	void SetProcessChoice (IpSec::PROCESS_CHOICE process_choice);
	void SetProtocolNum (uint8_t protocol_id);
	void SetIpsecMode (IpSec::MODE mode);
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
	void SetTrafficSelectors (const IkeTrafficSelector& ts_src, const IkeTrafficSelector& ts_dest);
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
	IpSec::MODE m_ipsec_mode;
	uint16_t m_src_transport_protocol_starting_num;
	uint16_t m_src_transport_protocol_ending_num;
	uint16_t m_dest_transport_protocol_starting_num;
	uint16_t m_dest_transport_protocol_ending_num;
	IpSec::PROCESS_CHOICE m_process_choise;
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
	void RemoveEntry (Ptr<IpSecPolicyEntry> entry);
	Ptr<IpSecPolicyEntry> CreatePolicyEntry (void);
	void SetRootDatabase (Ptr<IpSecDatabase> database);
public:	//const
	Ptr<IpSecDatabase> GetRootDatabase (void) const;
	Ptr<GsamInfo> GetInfo (void) const;
	void GetInboundSpis (std::list<Ptr<Spi> >& retval) const;
	Ptr<IpSecPolicyEntry> GetExactMatchedPolicy (const IkeTrafficSelector& ts_src, const IkeTrafficSelector& ts_dest) const;
	Ptr<IpSecPolicyEntry> GetExactMatchedPolicy (Ipv4Address group_address) const;
	Ptr<IpSecPolicyEntry> GetFallInRangeMatchedPolicy (	Ipv4Address source,
														Ipv4Address destination,
														uint8_t protocol,
														Ptr<Packet> packet) const;
private:
	void PushBackEntry (Ptr<IpSecPolicyEntry> entry);
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
	Ptr<GsaPushSession> CreateGsaPushSession (void);
	Ptr<GsamSessionGroup> GetSessionGroup (Ipv4Address group_address);
	std::list<Ptr<GsamSessionGroup> >& GetSessionGroups (void);
	void RemoveSession (Ptr<GsamSession> session);
	void RemoveSessionGroup (Ptr<GsamSessionGroup> session_group);
	void RemoveGsaPushSession (Ptr<GsaPushSession> gsa_push_session);
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
	const Ptr<Igmpv3L4Protocol> GetIgmp (void) const;
	const Ptr<GsamL4Protocol> GetGsam (void) const;
	bool IsHostQuerier (void) const;
	bool IsHostGroupMember (void) const;
	bool IsHostNonQuerier (void) const;
private:
	Ptr<GsamSessionGroup> CreateSessionGroup (Ipv4Address group_address);
private:	//fields
	std::list<Ptr<GsamSession> > m_lst_ptr_all_sessions;
	std::list<Ptr<GsamSessionGroup> > m_lst_ptr_session_groups;
	std::set<Ptr<GsaPushSession> > m_set_ptr_gsa_push_sessions;
	uint32_t m_window_size;
	Ptr<IpSecPolicyDatabase> m_ptr_spd;
	Ptr<IpSecSADatabase> m_ptr_sad;
	Ptr<GsamInfo> m_ptr_info;
	Ptr<GsamL4Protocol> m_ptr_gsam;
};

class SimpleAuthenticationHeader : public Header {
	/*
	 *                      1                   2                   3
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |  Next Header  |  Payload Len  |           Reserved            |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                           SPI                                 |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                     Sequence Number                           |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
public:	//Header override
	static TypeId GetTypeId (void);
	SimpleAuthenticationHeader ();
	explicit SimpleAuthenticationHeader (	uint8_t next_header,
											uint8_t payload_len,
											uint32_t spi,
											uint32_t seq_number);
	virtual ~SimpleAuthenticationHeader ();
public:	//Header override
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;
public:	//self defined const
	uint32_t GetSpi (void) const;
	uint32_t GetSeqNumber (void) const;
	uint8_t GetNextHeader (void) const;
private:
	uint8_t m_next_header;
	uint8_t m_payload_len;
	uint32_t m_spi;
	uint32_t m_seq_number;
};

class GsamFilterCache : public Object {
public:	//Object override
	static TypeId GetTypeId (void);
	GsamFilterCache ();
	explicit GsamFilterCache (	Ptr<Packet> packet,
								Ipv4Address source,
								Ipv4Address destination,
								uint8_t protocol,
								Ptr<Ipv4Route> route);
	virtual ~GsamFilterCache();
	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	virtual void DoDispose (void);
public:	//self-defined non-const
	Ptr<Packet> GetPacket (void) const;
	Ipv4Address GetPacketSourceAddress (void) const;
	Ipv4Address GetPacketDestinationAddress (void) const;
	uint8_t GetIpProtocolId (void) const;
	Ptr<Ipv4Route> GetRoute (void) const;
private:
	Ptr<Packet> m_l4_packet;
	Ipv4Address m_addr_src;
	Ipv4Address m_addr_dest;
	uint8_t m_protocol;
	Ptr<Ipv4Route> m_route;
};

class GsamFilter : public Object {
public:	//Object override
	static TypeId GetTypeId (void);
	GsamFilter ();
	virtual ~GsamFilter();
	virtual TypeId GetInstanceTypeId (void) const;
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	virtual void DoDispose (void);

public:	//self-defined const
	Ptr<GsamL4Protocol> GetGsam (void) const;
	Ptr<Igmpv3L4Protocol> GetIgmp (void) const;
	Ptr<IpSecDatabase> GetDatabase (void) const;
	IpL4ProtocolMulticast::DownTargetCallback GetDownTarget (void) const;
public:	//self-defined non-const
	void SetGsam (Ptr<GsamL4Protocol> gsam);
	void SetDownTarget (IpL4ProtocolMulticast::DownTargetCallback cb);
	IpSec::PROCESS_CHOICE ProcessIncomingPacket (	Ptr<Packet> incoming_and_retval_packet);
	std::pair<IpSec::PROCESS_CHOICE, uint8_t> ProcessOutgoingPacket (	Ptr<Packet> packet,
													Ipv4Address source,
													Ipv4Address destination,
													uint8_t protocol,
													Ptr<Ipv4Route> route);
	void DoGsam (Ipv4Address group_address, const Ptr<GsamFilterCache> cache = 0);
	void GsamCallBack (Ptr<GsamSession> session);
private:
	Ptr<GsamL4Protocol> m_ptr_gsam;
	IpSec::PROCESS_CHOICE m_default_process_choice;
	IpL4ProtocolMulticast::DownTargetCallback m_downTarget;   //!< Callback to send packets over IPv4
	std::map<Ptr<GsamSession>, Ptr<GsamFilterCache> > m_map_sessions_to_packets;
};

} /* namespace ns3 */



#endif /* SRC_INTERNET_MODEL_IPSEC_H_ */
