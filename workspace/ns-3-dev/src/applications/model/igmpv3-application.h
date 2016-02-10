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

	void SendGeneralQuery (void);

	EventId m_sendEvent;

	Time m_default_query_interval;
};

} /* namespace ns3 */

#endif /* IGMPV3_APPLICATION_H */
