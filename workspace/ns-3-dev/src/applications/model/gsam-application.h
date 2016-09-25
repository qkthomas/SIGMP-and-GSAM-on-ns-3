/*
 * gsam-application.h
 *
 *  Created on: Sep 20, 2016
 *      Author: lim
 */

#include "ns3/gsam-l4-protocol.h"
#include "ns3/event-id.h"
#include <list>

#ifndef SRC_APPLICATIONS_MODEL_GSAM_APPLICATION_H_
#define SRC_APPLICATIONS_MODEL_GSAM_APPLICATION_H_

namespace ns3 {

class GsamApplication : public Application {
public:
	/**
	 * \brief Get the type ID.
	 * \return the object TypeId
	 */
	static TypeId GetTypeId (void);
	GsamApplication();
	virtual ~GsamApplication();
private:
  /**
   * \brief Application specific startup code
   *
   * The StartApplication method is called at the start time specified by Start
   * This method should be overridden by all or most application
   * subclasses.
   */
  virtual void StartApplication (void);

  /**
   * \brief Application specific shutdown code
   *
   * The StopApplication method is called at the stop time specified by Stop
   * This method should be overridden by all or most application
   * subclasses.
   */
  virtual void StopApplication (void);

private:	//self-defined
  void Initialization (void);
  Ptr<GsamL4Protocol> GetGsam (void) const;
  Ptr<Igmpv3L4Protocol> GetIgmp (void) const;
  void GenerateEvent (void);
private:
  Ptr<Igmpv3L4Protocol> m_ptr_igmp;
  Ptr<GsamL4Protocol> m_ptr_gsam;
  EventId m_event_current;

};

} /* namespace ns3 */

#endif /* SRC_APPLICATIONS_MODEL_GSAM_APPLICATION_H_ */
