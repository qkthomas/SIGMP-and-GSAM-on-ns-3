/*
 * IGMPApp.h
 *
 *  Created on: May 12, 2015
 *      Author: lim
 *      Experimental IGMPv2 Application
 */

#ifndef SCRATCH_IGMPAPP_H_
#define SCRATCH_IGMPAPP_H_

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ipv4-address.h"
#include "ns3/internet-module.h"
#include "ns3/header.h"
#include <stdint.h>
#include <list>

namespace ns3 {

class Socket;
class Packet;

//defined in this file
class Igmpv3Header;
class Igmpv3Query;

class IGMPApp: public Application {

	enum ROLE {
		QUERIER = 0, NONQUERIER = 1, HOST = 2
	};

public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  IGMPApp ();

  virtual ~IGMPApp ();

protected:
  virtual void DoDispose (void);

private:

  virtual void StartApplication (void);
  virtual void StopApplication (void);

  void Initialization (void);


  //sending
  void DoSendGeneralQuery (Ptr<Packet> packet);
  void SendDefaultGeneralQuery (void);
  void SendGeneralQuery (bool s_flag, uint8_t qqic, uint8_t qrv, uint8_t max_resp_code);
  void SendCurrentStateReport (Ptr<Socket> socket);

  //handling
  void HandleRead (Ptr<Socket> socket);
  void HandleReadDummy (Ptr<Socket> socket);	//for binding of sending sockets
  void HandleQuery (Ptr<Socket> socket, Igmpv3Header igmpv3_header, Ptr<Packet> packet);
  void HandleGeneralQuery (Ptr<Socket> socket, Time resp_time);
  void HandleGroupSpecificQuery (Ptr<Socket> socket, Time max_resp_time, Igmpv3Query query_header, Ptr<Packet> packet);
  void HandleV1MemReport (Ptr<Socket> socket, Igmpv3Header igmpv3_header, Ptr<Packet> packet);
  void HandleV2MemReport (Ptr<Socket> socket, Igmpv3Header igmpv3_header, Ptr<Packet> packet);
  void HandleV3MemReport (Ptr<Socket> socket, Igmpv3Header igmpv3_header, Ptr<Packet> packet);

  void IPMulticastListen (Ptr<Socket> socket, Ptr<Ipv4InterfaceMulticast> interface,
		  	  	  	  	  Ipv4Address multicast_address, FILTER_MODE filter_mode,
						  std::list<Ipv4Address> &src_list);

  //member variables
  ROLE m_role;

  std::list<Ptr<Socket> > m_lst_sockets; //!< sending Sockets, one for each interface
//waiting to delete //std::list<Ptr<Socket> > m_lst_receiving_sockets;	//!< receiving Sockets, one for eatch interface
  EventId m_sendEvent; //!< Event to send the next packet
  Ipv4Address m_GenQueAddress;	//!< Address to send for general query
  Ipv4Address m_LvGrpAddress;	//!< Address to send for leave group report	(non v3 report)
  Ipv4Address m_RptAddress;		//!< Address to send for group report
  uint16_t m_portnumber;

  //IGMPv3 Parameters Setting
  bool m_s_flag;
  uint8_t m_qqic;
  uint8_t m_qrv;
  uint8_t m_max_resp_code;

  //States
  std::list<IGMPv3SocketState> m_lst_socket_states;
  std::list<IGMPv3InterfaceState> m_lst_interface_states;

  //Timers
  std::list<Ptr<PerInterfaceTimer> > m_lst_per_interface_timers;
  std::list<Ptr<PerGroupInterfaceTimer> > m_lst_per_group_interface_timers;

};

//class Igmpv3L4Protocol : public IpL4Protocol
//{
//public:
//	static TypeId GetTypeId (void);
//	static const uint8_t PROT_NUMBER; //!< IGMP protocol number (0x02)
//
//	Igmpv3L4Protocol ();
//	virtual ~Igmpv3L4Protocol ();
//	virtual void DoDispose (void);
//
//protected:
//  /*
//   * This function will notify other components connected to the node that a new stack member is now connected
//   * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
//   */
//  virtual void NotifyNewAggregate ();
//
//public: //override IpL4Protocol
//	  virtual int GetProtocolNumber (void) const;
//
//	  virtual enum IpL4Protocol::RxStatus Receive (Ptr<Packet> p,
//	                                                 Ipv4Header const &header,
//	                                                 Ptr<Ipv4Interface> incomingInterface);
//
//	  virtual void SetDownTarget (IpL4Protocol::DownTargetCallback cb);
//	  virtual IpL4Protocol::DownTargetCallback GetDownTarget (void) const;
//
//public:	//copying from Icmpv4L4Protocol
//	  void SetNode (Ptr<Node> node);
//	  static uint16_t GetStaticProtocolNumber (void);
//
//public: //something new, on its own
//
//	  //algebraic calculation
//	  double MaxRespCodeQQICConvert (uint8_t max_resp_code);
//
//	  //handling receive
//	  void HandleQuery (Ptr<Packet> p,
//              	  	    Icmpv4Header header,
//						Ipv4Address source,
//						Ipv4Address destination);
//
//	  void HandleV1Report (Ptr<Packet> p,
//              	  	  	   Icmpv4Header header,
//						   Ipv4Address source,
//						   Ipv4Address destination);
//
//	  void HandleV2Report (Ptr<Packet> p,
//              	  	  	   Icmpv4Header header,
//						   Ipv4Address source,
//						   Ipv4Address destination);
//
//	  void HandleV3Report (Ptr<Packet> p,
//			  	  	  	   Icmpv4Header header,
//						   Ipv4Address source,
//						   Ipv4Address destination);
//
//	  //sending
//	  void SendQuery (Ipv4Address group_address,
//			  	  	  bool s_flag = false/*assumed default*/,
//					  uint8_t qqic = 125/* 125 sec, cisco default*/,
//					  uint8_t qrv = 2/*cisco default*/,
//					  uint16_t num_src,
//					  std::list<Ipv4Address> &lst_src_addresses,
//					  uint8_t max_resp_code = 100 /* 10sec, cisco default*/);
//
//	  //Warping ipv4 header
//	  void SendMessage (Ptr<Packet> packet,
//			  	  	  	/*Ipv4Address source,*/
//						Ipv4Address dest,
//						uint8_t type,
//						uint8_t max_resp_code);
//	  //Warping igmpv3 header
//	  void SendMessage (Ptr<Packet> packet,
//			  	  	  	Ipv4Address source,
//						Ipv4Address dest,
//						uint8_t type,
//						uint8_t max_resp_code,
//						Ptr<Ipv4Route> route);
//
//
//protected:
//	  /*
//	   * This function will notify other components connected to the node that a new stack member is now connected
//	   * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
//	   */
//	  virtual void NotifyNewAggregate ();
//
//private:
//	  virtual void DoDispose (void);
//
//public:
//	  static uint32_t GENERALQUERYDEST = Ipv4Address("224.0.0.1").Get();
//
//private:
//	  Ptr<Node> m_node; //!< the node this protocol is associated with
//	  IpL4Protocol::DownTargetCallback m_downTarget; //!< callback to Ipv4::Send
//};

} /* namespace ns3 */

#endif /* SCRATCH_IGMPAPP_H_ */
