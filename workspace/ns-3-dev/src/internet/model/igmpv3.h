/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 CONCORDIA UNIVERSITY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Lin Chen <c_lin13@encs.concordia.ca>
 */

#ifndef IGMPV3_H
#define IGMPV3_H

#include "ns3/ipv4-address.h"
#include "ns3/internet-module.h"
#include "ns3/header.h"
#include <stdint.h>
#include <list>

namespace ns3 {

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
	//void PushBackSrcAddresses (std::list<Ipv4Address> &lst_addresses);
	void PushBackSrcAddresses (std::list<uint32_t> &lst_addresses);
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

} // namespace ns3

#endif /* IGMPV3_H */
