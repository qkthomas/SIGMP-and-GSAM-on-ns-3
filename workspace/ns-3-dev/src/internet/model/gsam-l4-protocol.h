/*
 * Igmpv3-l4-protocol.h
 *
 *  Created on: Jan 27, 2016
 *      Author: lin
 */

#ifndef GSAM_L4_PROTOCOL_MULTICAST_H
#define GSAM_L4_PROTOCOL_MULTICAST_H

#include "ns3/object.h"
#include "gsam.h"
#include <list>
#include <set>

namespace ns3 {

class Node;
class Ipv4InterfaceMulticast;
class Ipv4Route;

class GsamSa : public Object {

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

public:	//self defined
	uint64_t GetInitiatorSpi (void) const;
	uint64_t GetResponderSpi (void) const;
	bool IsEtablished (void) const;
private:	//fields
	uint64_t m_initiator_spi;
	uint64_t m_responder_spi;
	bool m_etablished;
	Ptr<GsamSession> m_ptr_session;
};

class GsamSession : public Object {

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

public:	//self defined
	uint32_t GetMessageId (void) const;
	uint64_t GetLocalSpi (void) const;
	GsamSession::ROLE GetRole (void) const;
	uint64_t GetInitiatorSpi (void) const;
	uint64_t GetResponderSpi (void) const;
private:	//fields
	uint32_t m_message_id;
	GsamSession::ROLE m_role;
	Ptr<GsamSa> m_ptr_sa;
	Ptr<GsamDatabase> m_ptr_database;
};

class GsamDatabase : public Object {

public:	//Object override
	static TypeId GetTypeId (void);
	GsamDatabase ();
	virtual ~GsamDatabase();
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
	Ptr<GsamSession> GetSession (GsamSession::ROLE role, uint64_t initiator_spi, uint64_t responder_spi) const;
	Ptr<GsamSession> CreateSession (void);

private:	//fields
	std::list<Ptr<GsamSession> > m_lst_ptr_sessions;
	std::set<uint64_t> m_set_occupied_spis;
	uint32_t m_window_size;
};

class GsamL4Protocol : public Object {

public:	//Object override
	/**
	 * \brief Get the type ID.
	 * \return the object TypeId
	 */
	static TypeId GetTypeId (void);

	static const uint16_t PROT_NUMBER;	//udp port number 500s

	GsamL4Protocol();
	virtual ~GsamL4Protocol();

	/**
	 * \brief Set the node the protocol is associated with.
	 * \param node the node
	 */
	void SetNode (Ptr<Node> node);

	virtual TypeId GetInstanceTypeId (void) const;

public:	//added by Lin Chen
	void Initialization (void);
	void HandleRead (Ptr<Socket> socket);
public:	//exchanges, added by Lin Chen
	void Send_IKE_SA_INIT (Ipv4Address dest);
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:

	virtual void DoDispose (void);

	Ptr<Node> m_node; //!< the node this protocol is associated with
	Ptr<Socket> m_socket;
	Ptr<GsamDatabase> m_ptr_database;
};

} /* namespace ns3 */

#endif /* SRC_INTERNET_MODEL_GSAM_L4_PROTOCOL_H_ */
