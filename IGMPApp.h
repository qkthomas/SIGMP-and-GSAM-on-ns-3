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

class IGMPApp: public Application {

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

  void Broadcast (Ptr<Packet> packet);

//  void SendGeneralQuery (void);

  void SendQuery (Ipv4Address group_address,
				  std::list<Ipv4Address> &lst_src_addresses,
		  	  	  bool s_flag = false, //assumed default
				  uint8_t qqic = 125, //125sec, cisco default
				  uint8_t qrv = 2, //cisco default
				  uint8_t max_resp_code = 100 //10sec, cisco default
				  );

  void HandleRead (Ptr<Socket> socket);
  void HandleQuery (Ptr<Packet> packet);
  void HandleV1MemReport (Ptr<Packet> packet);
  void HandleV2MemReport (Ptr<Packet> packet);
  void HandleV3MemReport (Ptr<Packet> packet);

  Ptr<Socket> m_socket; //!< Socket
  EventId m_sendEvent; //!< Event to send the next packet
  Ipv4Address m_GenQueAddress;	//!< Address to send for general query
  Ipv4Address m_LvGrpAddress;	//!< Address to send for leave group report
};

class Igmpv3Header: public Header {

/*	Igmpv3 Header format:
 *
	  0                   1                   2                   3
	  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 |  Type = 0x11  | Max Resp Code |           Checksum            |
	 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 *
*/

public:
	enum TYPE {
		MEMBERSHIP_QUERY = (uint8_t)0x11,
		V3_MEMBERSHIP_REPORT = (uint8_t)0x22,
		V1_MEMBERSHIP_REPORT = (uint8_t)0x12,
		V2_MEMBERSHIP_REPORT = (uint8_t)0x16,
		V2_LEAVE_GROUP = (uint8_t)0x17
	};

public:
	static TypeId GetTypeId (void);
	Igmpv3Header ();
	virtual ~Igmpv3Header ();

public:
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;

public:	//minicing icmpv4

	void SetType (uint8_t type);
	uint8_t GetType (void);
	void SetMaxRespCode (uint8_t max_resp_code);
	uint8_t GetMaxRespCode (void);
	void EnableChecksum (void);

private:
	uint8_t m_type; //!< type of igmpv4 message
	uint8_t m_max_resp_code; //!< the maximum time allowed before sending a responding report
	uint16_t m_checksum;
	bool m_calcChecksum;	//!< mimicing ns3::icmpv4

};


class Igmpv3Query : public Header
{
	/*
	 * Query message format:
	 * 0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Group Address                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Source Address [1]                      |
      +-                                                             -+
      |                       Source Address [2]                      |
      +-                              .                              -+
      .                               .                               .
      .                               .                               .
      +-                                                             -+
      |                       Source Address [N]                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:	//Header override
	static TypeId GetTypeId (void);
	Igmpv3Query ();
	virtual ~Igmpv3Query ();

public:	//Header override
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;

public: //set
	void SetGroupAddress (uint32_t address);
	void SetSFlag (bool b);
	void SetQRV (uint8_t qrv);
	void SetQQIC (uint8_t qqic);
	//void SetNumSrc (uint16_t num_src);
	void PushBackSrcAddress (Ipv4Address address);
	void PushBackSrcAddresses (std::list<Ipv4Address> &lst_addresses);

public: //get
	uint32_t GetGroupAddress (void);
	bool isSFlagSet (void);
	uint8_t GetQRV (void);
	uint8_t GetQQIC (void);
	uint16_t GetNumSrc (void);
	uint16_t GetSrcAddresses (std::list<Ipv4Address> &payload_addresses) const;

private:
	Ipv4Address m_group_address; //!< group address

	struct Resv_S_Qrv {
		uint8_t QRV:3; //!< querier's Robustness Variable. This are the lowest 4 bits
		uint8_t S:1; //!< suppress Router-side Processing
		uint8_t Resv:4; //!< reserved field. This are the highest 4 bits.

		Resv_S_Qrv (uint8_t i) {
			this->Resv = 0x00;
			this->S = (i&0x08) >> 3;
			this->QRV = (i&0x07);
		}

		uint8_t toUint8_t() const {
			return (Resv<<4) + (S<<3) + (QRV);
		}
	} m_resv_s_qrv;

	uint8_t m_qqic; //!< querier's Query Interval Code
	uint16_t m_num_srcs; //!< the number of sources

	std::list<Ipv4Address> m_lst_src_addresses;

};

class Igmpv3GrpRecord : public Header
{
	/*
	 * Igmpv3 group record format
	 *  0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Multicast Address                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Source Address [1]                      |
      +-                                                             -+
      |                       Source Address [2]                      |
      +-                                                             -+
      .                               .                               .
      .                               .                               .
      .                               .                               .
      +-                                                             -+
      |                       Source Address [N]                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                         Auxiliary Data                        .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:
	enum TYPE {
		MODE_IS_INCLUDE = (uint8_t)1,
		MODE_IS_EXCLUDE = (uint8_t)2,
		CHANGE_TO_INCLUDE_MODE = (uint8_t)3,
		CHANGE_TO_EXCLUDE_MODE = (uint8_t)4,
		ALLOW_NEW_SOURCES = (uint8_t)5,
		BLOCK_OLD_SOURCES = (uint8_t)6
	};

public:	//Header override
	static TypeId GetTypeId (void);
	Igmpv3GrpRecord ();
	virtual ~Igmpv3GrpRecord ();

public:	//Header override
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;

public:	//set
	void SetType (uint8_t type);
	void SetAuxDataLen (uint8_t aux_data_len);
	void SetNumSrcs (uint16_t num_srcs);
	void SetMulticastAddress (uint32_t address);
	void PushBackSrcAddress (uint32_t address);
	void PushBackSrcAddresses (std::list<Ipv4Address> &lst_addresses);
	void PushBackAuxData (uint32_t aux_data);
	void PushBackAuxdata (std::list<uint32_t> &lst_aux_data);

public: //get
	uint8_t GetType (void) const;
	uint8_t GetAuxDataLen (void) const;
	uint16_t GetNumSrcs (void) const;
	uint32_t GetMulticastAddress (void) const;
	uint16_t GetSrcAddresses (std::list<Ipv4Address> &payload_addresses) const;
	uint8_t GetAuxData (std::list<uint32_t> &payload_data) const;

private:
	uint8_t m_record_type;
	uint8_t m_aux_data_len;	//in uintes of 32-bit word
	uint16_t m_num_srcs;
	Ipv4Address m_mul_address;
	std::list<Ipv4Address> m_lst_src_addresses;
	std::list<uint32_t> m_lst_aux_data;

};

class Igmpv3Report : public Header
{
	/*
	 * Igmpv3 report message format
	 *  0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |           Reserved            |  Number of Group Records (M)  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                        Group Record [1]                       .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                        Group Record [2]                       .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                               .                               |
      .                               .                               .
      |                               .                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                        Group Record [M]                       .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:	//Header override
	static TypeId GetTypeId (void);
	Igmpv3Report ();
	virtual ~Igmpv3Report ();

public:	//Header override
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;

public:
	void SetNumGrpRecords (uint16_t num_grp_records);
	uint16_t GetNumGrpRecords (void) const;
	void PushBackGrpRecord (Igmpv3GrpRecord grp_record);
	void PushBackGrpRecords (std::list<Igmpv3GrpRecord> &lst_grp_records);
	uint16_t GetGrpRecords (std::list<Igmpv3GrpRecord> &payload_grprecords) const;

private:
	uint16_t m_reserved;
	uint16_t m_num_grp_record;
	std::list<Igmpv3GrpRecord> m_lst_grp_records;

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
