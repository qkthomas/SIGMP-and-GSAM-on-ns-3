/*
 * igmpv3-application.h
 *
 *  Created on: Feb 9, 2016
 *      Author: lim
 */

#ifndef IGMPV3_APPLICATION_H
#define IGMPV3_APPLICATION_H

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include <list>

namespace ns3 {

class Igmpv3Application: public Application {
public:
	/**
	 * \brief Get the type ID.
	 * \return the object TypeId
	 */
	static TypeId GetTypeId (void);
	Igmpv3Application();
	virtual ~Igmpv3Application();

protected:
	virtual void DoDispose (void);

private:

	virtual void StartApplication (void);
	virtual void StopApplication (void);

	Ptr<Igmpv3L4Protocol> GetIgmp (void) const;
	Ptr<Ipv4L3ProtocolMulticast> GetIpv4L3 (void) const;
	uint32_t GetRandomNumber (uint32_t min, uint32_t max);
	bool IsSkip (uint32_t percentage);
	bool IsSkip (void);
	Ipv4Address GetRandomMulticastAddress (void);

	void GenerateNextEvent (void);
	void GenerateGeneralQueryEvent (void);
	void GenerateHostJoinEvent (void);
	void GenerateHostLeaveEvent (void);

	EventId m_currentEvent;

	Time m_default_query_interval;		//cisco default 60 sec

	std::list<Ptr<Ipv4RawSocketImplMulticast> > m_lst_sockets;
};

} /* namespace ns3 */

#endif /* IGMPV3_APPLICATION_H */
