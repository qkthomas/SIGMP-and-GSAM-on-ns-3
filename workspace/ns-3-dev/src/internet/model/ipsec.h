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

namespace ns3 {

class Node;
class Ipv4InterfaceMulticast;
class Ipv4Route;
class GsamSession;
class IpSecDatabase;
class IpSecSADatabase;
class IpSecPolicyDatabase;
class EncryptionFunction;

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
	Time GetRetransmissionDelay (void) const;
	void SetRetransmissionDelay (Time time);
	void FreeGsamSpi (uint64_t spi);
	void FreeIpsecSpi (uint32_t spi);
	void SetSecGrpStart (Ipv4Address address);
	void SetSecGrpEnd (Ipv4Address address);
private:
	uint64_t GetLocalAvailableGsamSpi (void) const;
	uint32_t GetLocalAvailableIpsecSpi (void) const;
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
	GsamSa::SA_TYPE GetType (void);
	void SetType (GsamSa::SA_TYPE type);
	uint64_t GetInitiatorSpi (void) const;
	void SetInitiatorSpi (uint64_t spi);
	uint64_t GetResponderSpi (void) const;
	void SetResponderSpi (uint64_t spi);
	bool IsHalfOpen (void) const;
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

class GsamSession : public Object {
public:
	enum ROLE {
		UNINITIALIZED = 0,
		INITIATOR = 1,
		RESPONDER = 2,
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
	static GsamSession::ROLE GetLocalRole (const IkeHeader& incoming_header);
public:	//operator
	friend bool operator == (GsamSession const& lhs, GsamSession const& rhs);
public:	//self defined
	uint32_t GetCurrentMessageId (void) const;
	uint64_t GetLocalSpi (void) const;
	GsamSession::ROLE GetRole (void) const;
	void SetRole (GsamSession::ROLE role);
	//init sa
	uint64_t GetInitSaInitiatorSpi (void) const;
	void SetInitSaInitiatorSpi (uint64_t spi);
	uint64_t GetInitSaResponderSpi (void) const;
	void SetInitSaResponderSpi (uint64_t spi);
	//kek sa
	uint64_t GetKekSaInitiatorSpi (void) const;
	void SetKekSaInitiatorSpi (uint64_t spi);
	uint64_t GetKekSaResponderSpi (void) const;
	void SetKekSaResponderSpi (uint64_t spi);
	//
	void SetDatabase (Ptr<IpSecDatabase> database);
	void EtablishGsamInitSa (void);
	void EtablishGsamKekSa (void);
	void IncrementMessageId (void);
	void SetMessageId (uint32_t message_id);
	Timer& GetTimer (void);
	bool IsRetransmit (void);
	Ipv4Address GetPeerAddress (void);
	void SetPeerAddress (Ipv4Address peer_address);
	Ptr<GsamInfo> GetInfo (void) const;
	Ptr<IpSecDatabase> GetDatabase (void) const;
private:	//fields
	uint32_t m_current_message_id;
	Ipv4Address m_peer_address;
	GsamSession::ROLE m_role;
	Ptr<GsamSa> m_ptr_init_sa;
	Ptr<GsamSa> m_ptr_kek_sa;
	Ptr<IpSecDatabase> m_ptr_database;
	Timer m_timer;
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
private:	//fields
	uint16_t m_id;
	uint32_t m_spi;
	Ipv4Address m_dest_address;
	IPsec::PROTOCOL_ID m_ipsec_protocol;
	IPsec::MODE m_ipsec_mode;
	Ptr<EncryptionFunction> m_ptr_encrypt_fn;
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

private:	//fields
	Ptr<GsamInfo> m_ptr_info;
};

class IpSecPolicyEntry : public Object {
public:
	enum DIRECTION {
		IN = 0,
		OUT = 1,
		BOTH = 2
	};

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
	IpSecPolicyEntry::DIRECTION GetDirection (void) const;
	IpSecPolicyEntry::PROCESS_CHOICE GetProcessChoice (void) const;
	uint8_t GetProtocolId () const;
	uint16_t GetTranSrcStartingPort (void) const;
	uint16_t GetTranSrcEndingPort (void) const;
	uint16_t GetTranDestStartingPort (void) const;
	uint16_t GetTranDestEndingPort (void) const;
	Ipv4Address GetSrcAddressRangeStart (void) const;
	Ipv4Address GetSrcAddressRangeEnd (void) const;
	Ipv4Address GetDestAddressRangeStart (void) const;
	Ipv4Address GetDestAddressRangeEnd (void) const;
	Ipv4Address GetSrcAddress (void) const;
	Ipv4Address GetDestAddress (Ipv4Address address) const;
public:
	void SetDirection (IpSecPolicyEntry::DIRECTION direction);
	void SetProcessChoice (IpSecPolicyEntry::PROCESS_CHOICE process_choice);
	void SetProtocolId (uint8_t protocol_id);
	void SetTranSrcStartingPort (uint16_t port_num);
	void SetTranSrcEndingPort (uint16_t port_num);
	void SetTranDestStartingPort (uint16_t port_num);
	void SetTranDestEndingPort (uint16_t port_num);
	void SetSrcAddressRange (Ipv4Address range_start, Ipv4Address range_end);
	void SetDestAddressRange (Ipv4Address range_start, Ipv4Address range_end);
	void SetSingleSrcAddress (Ipv4Address address);
	void SetSingleDestAddress (Ipv4Address address);
private:
	IpSecPolicyEntry::DIRECTION m_direction;
	Ipv4Address m_src_starting_address;
	Ipv4Address m_src_ending_address;
	Ipv4Address m_dest_starting_address;
	Ipv4Address m_dest_ending_address;
	uint8_t m_ip_protocol_num;
	uint16_t m_src_transport_protocol_starting_num;
	uint16_t m_src_transport_protocol_ending_num;
	uint16_t m_dest_transport_protocol_starting_num;
	uint16_t m_dest_transport_protocol_ending_num;
	IpSecPolicyEntry::PROCESS_CHOICE m_process_choise;
	Ptr<IpSecPolicyDatabase> m_ptr_sad;
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
private:	//fields
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
	Ptr<GsamSession> GetSession (GsamSession::ROLE local_role, uint64_t initiator_spi, uint64_t responder_spi, uint32_t message_id, Ipv4Address peer_address) const;
	Ptr<GsamSession> GetSession (GsamSession::ROLE local_role, uint64_t initiator_spi, uint32_t message_id, Ipv4Address peer_address) const;
	Ptr<GsamSession> GetSession (const IkeHeader& header, Ipv4Address peer_address) const;
	Ptr<GsamInfo> GetInfo () const;
	Ptr<IpSecPolicyDatabase> GetPolicyDatabase (void) const;
	Ptr<IpSecSADatabase> GetIpSecSaDatabase (void) const;
	Ptr<GsamSession> CreateSession (void);
	void RemoveSession (Ptr<GsamSession> session);
	Time GetRetransmissionDelay (void);
private:	//fields
	std::list<Ptr<GsamSession> > m_lst_ptr_sessions;
	uint32_t m_window_size;
	Ptr<IpSecPolicyDatabase> m_ptr_spd;
	Ptr<IpSecSADatabase> m_ptr_sad;
	Ptr<GsamInfo> m_ptr_info;
};

} /* namespace ns3 */



#endif /* SRC_INTERNET_MODEL_IPSEC_H_ */
