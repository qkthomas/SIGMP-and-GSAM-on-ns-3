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
	uint64_t GetLocalAvailableGsamSpi (void) const;
	uint32_t GetLocalAvailableIpSecSpi (void) const;
	Time GetRetransmissionDelay (void) const;
	void SetRetransmissionDelay (Time time);
	void OccupyGsamSpi (uint64_t spi);
private:	//fields
	std::set<uint64_t> m_set_occupied_gsam_spis;
	std::set<uint32_t> m_set_occupied_ipsec_spis;	//ah or esp
	Time m_retransmission_delay;
};

class GsamSa : public Object {
public:
	enum SA_TYPE {
		NOT_INITIATED = 0,
		GSAM_INIT_SA = 1,
		GSAM_IEK_SA = 2
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
public:	//operator
	friend bool operator == (GsamSession const& lhs, GsamSession const& rhs);
public:	//self defined
	uint32_t GetCurrentMessageId (void) const;
	uint64_t GetLocalSpi (void) const;
	GsamSession::ROLE GetRole (void) const;
	void SetRole (GsamSession::ROLE role);
	uint64_t GetInitSaInitiatorSpi (void) const;
	void SetInitSaInitiatorSpi (uint64_t spi);
	uint64_t GetInitSaResponderSpi (void) const;
	void SetInitSaResponderSpi (uint64_t spi);
	void SetDatabase (Ptr<IpSecDatabase> database);
	void EtablishGsamInitSa (void);
	void IncrementMessageId (void);
	Timer& GetTimer (void);
	Time GetDefaultDelay (void);
	bool IsRetransmit (void);
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
public:	//self-defined, operators
	friend bool operator == (IpSecPolicyEntry const& lhs, IpSecPolicyEntry const& rhs);
	friend bool operator < (IpSecPolicyEntry const& lhs, IpSecPolicyEntry const& rhs);
private:
	uint16_t m_id;
	IpSecPolicyEntry::DIRECTION m_direction;
	Ipv4Address m_src_address;
	Ipv4Address m_dest_address;
	uint8_t m_ip_protocol_num;
	uint16_t m_src_transport_protocol_num;
	uint16_t m_dest_transport_protocol_num;
	IpSecPolicyEntry::PROCESS_CHOICE m_process_choise;
	Ptr<IpSecSADatabase> m_ptr_sad;
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
	Ptr<GsamSession> GetSession (GsamSession::ROLE role, uint64_t initiator_spi, uint64_t responder_spi, uint32_t message_id) const;
	Ptr<GsamSession> GetSession (const IkeHeader& ikeheader) const;
	Ptr<GsamInfo> GetInfo () const;
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
