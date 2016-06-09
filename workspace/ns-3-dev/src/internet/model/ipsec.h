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
#include <list>
#include <set>

namespace ns3 {

class Node;
class Ipv4InterfaceMulticast;
class Ipv4Route;

class IpSecSa : public Object {

public:	//Object override
	static TypeId GetTypeId (void);
	IpSecSa ();
	virtual ~IpSecSa();
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
	uint64_t GetInitiatorSpi (void) const;
	uint64_t GetResponderSpi (void) const;
	bool IsEtablished (void) const;
private:	//fields
	uint64_t m_initiator_spi;
	uint64_t m_responder_spi;
	bool m_etablished;
	Ptr<IpSecSession> m_ptr_session;
};

class IpSecSession : public Object {

	enum ROLE {
		UNINITIALIZED = 0,
		INITIATOR = 1,
		RESPONDER = 2,
	};

public:	//Object override
	static TypeId GetTypeId (void);
	IpSecSession ();
	virtual ~IpSecSession();
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
	uint32_t GetMessageId (void) const;
	uint64_t GetLocalSpi (void) const;
	IpSecSession::ROLE GetRole (void) const;
	uint64_t GetInitiatorSpi (void) const;
	uint64_t GetResponderSpi (void) const;
private:	//fields
	uint32_t m_message_id;
	IpSecSession::ROLE m_role;
	Ptr<IpSecSa> m_ptr_sa;
	Ptr<IpSecDatabase> m_ptr_database;
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
	uint64_t GetLocalAvailableSpi (void) const;
	Ptr<IpSecSession> GetSession (IpSecSession::ROLE role, uint64_t initiator_spi, uint64_t responder_spi) const;
	Ptr<IpSecSession> CreateSession (void);

private:	//fields
	std::list<Ptr<IpSecSession> > m_lst_ptr_sessions;
	std::set<uint64_t> m_set_occupied_spis;
	uint32_t m_window_size;
};

} /* namespace ns3 */



#endif /* SRC_INTERNET_MODEL_IPSEC_H_ */
