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

#include "igmpv3.h"
#include "ns3/log.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv6-address.h"
#include "ns3/nstime.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("Igmpv3Header");

/********************************************************
 *        Igmpv3Header
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (Igmpv3Header);

TypeId
Igmpv3Header::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::Igmpv3Header")
    .SetParent<Header> ()
    //.SetGroupName("Internet")
	.AddConstructor<Igmpv3Header> ();
  return tid;
}

Igmpv3Header::Igmpv3Header ()
  :	m_type (0),
	m_max_resp_code (0),
	m_checksum (0),
	m_calcChecksum (false)
{
	this->m_max_resp_code = 100;	//cisco default value 10sec
	NS_LOG_FUNCTION (this);
}

Igmpv3Header::~Igmpv3Header ()
{
	NS_LOG_FUNCTION (this);
}

void
Igmpv3Header::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	//**************warning*********
	//the following code may make the buffer resize, causing iterator to be invalidated
	i.WriteU8(this->m_type);
	i.WriteU8(this->m_max_resp_code);
	i.WriteHtonU16(0);	//fill up the checksum field with zero

	if (true == this->m_calcChecksum)
	{
		i = start;
		uint16_t checksum = i.CalculateIpChecksum(i.GetSize());
		i = start;
		i.Next(2);	//2 bytes, 16bits, after Type and Max Resp Code fields
		i.WriteU16(checksum);
	}

}

uint32_t
Igmpv3Header::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	this->m_type = start.ReadU8();
	this->m_max_resp_code = start.ReadU8();
	this->m_checksum = start.ReadNtohU16();
	return 4;
}

uint32_t
Igmpv3Header::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);
	return 4;	//followling RFC3376, length of fields including type, max resp code and checksum
}

TypeId
Igmpv3Header::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return Igmpv3Header::GetTypeId ();
}

void
Igmpv3Header::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "Type=" << this->m_type << ", Max Resp Code=" << this->m_max_resp_code << ", ";
	os << "Checksum=" << this->m_checksum << std::endl;
}

void
Igmpv3Header::SetType (uint8_t type)
{
	NS_LOG_FUNCTION (this);
	this->m_type = type;
}

uint8_t
Igmpv3Header::GetType (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_type;
}

void
Igmpv3Header::SetMaxRespCode (uint8_t max_resp_code)
{
	NS_LOG_FUNCTION (this);
	this->m_max_resp_code = max_resp_code;
}

uint8_t
Igmpv3Header::GetMaxRespCode (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_max_resp_code;
}

void
Igmpv3Header::EnableChecksum (void)
{
	NS_LOG_FUNCTION (this);
	this->m_checksum = true;
}

/********************************************************
 *        Igmpv3Query
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (Igmpv3Query);

TypeId
Igmpv3Query::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::Igmpv3Query")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<Igmpv3Query> ();
	  return tid;
}

Igmpv3Query::Igmpv3Query ()
  :  m_group_address (Ipv4Address("0.0.0.0")),
	 m_resv_s_qrv (0),
	 m_qqic (0),
	 m_num_srcs (0)
{
	this->m_resv_s_qrv.QRV = 2;		//cisco default robustness value: 2
	this->m_qqic = 125; 	//cisco default query interval 125sec
	NS_LOG_FUNCTION (this);
}

Igmpv3Query::~Igmpv3Query ()
{
	NS_LOG_FUNCTION (this);
}

void
Igmpv3Query::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	//serializing group address
	uint8_t buf[4];	//4 == length of Ipv4 address in bytes
	this->m_group_address.Serialize(buf);
	i.Write(buf, 4);

	i.WriteU8(this->m_resv_s_qrv.toUint8_t());
	i.WriteU8(this->m_qqic);
	i.WriteHtonU16(this->m_num_srcs);

	uint16_t count = 0;

	//totally wrong about for statement, it always checks the condition first then enter the code block
	//serializing source addresses
	/*
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		(*it).Serialize(buf);
		i.Write(buf, 4); //4 == length of Ipv4 address in bytes
		++count;
	}
	*/

	//serializing source addresses
	if (false == this->m_lst_src_addresses.empty()) {
		std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin();

		do {
			(*it).Serialize(buf);
			i.Write(buf, 4); //4 == length of Ipv4 address in bytes
			++count;

			it++;
		} while (it != this->m_lst_src_addresses.end());
	}

	//serializing source addresses

	NS_ASSERT(count == this->m_num_srcs);
}

uint32_t
Igmpv3Query::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	//count bytes read for return value
	uint32_t bytes_read = 0;

	uint8_t buf[4];	//4 == length of Ipv4 address in bytes
	i.Read(buf, 4);
	bytes_read += 4;

	this->m_resv_s_qrv = i.ReadU8();
	bytes_read++;

	this->m_qqic = i.ReadU8();
	bytes_read++;

	this->m_num_srcs = i.ReadNtohU16();
	bytes_read += 2;

	uint32_t size_bytes_unread = start.GetSize() - bytes_read;

	//abort if the size of rest of the data isn't a multiple of 4 (ipv4 address size)
	NS_ASSERT((size_bytes_unread % 4) == 0);

	for (uint16_t n = this->m_num_srcs; n > 0; --n)
	{
		Ipv4Address address;
		i.Read(buf, 4);
		address.Deserialize(buf);
		this->PushBackSrcAddress(address);
	}

	return bytes_read;
}

uint32_t
Igmpv3Query::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);
	uint32_t size = 0;
	size += sizeof(this->m_group_address.Get());	//size of the group address
	size += sizeof(this->m_resv_s_qrv.toUint8_t());
	size += sizeof(this->m_qqic);
	size += sizeof(this->m_num_srcs);
	//size += 4*this->m_num_srcs;	//4 bytes for eath source address

	//this way of counting is slow. but just in case.
	uint16_t count = 0;

	/* totally wrong about for statement
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		size += sizeof((*it).Get());
		count++;
	}
	*/

	if (false == this->m_lst_src_addresses.empty()) {
		std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin();
		do {
			size += sizeof((*it).Get());
			count++;

			it++;
		} while (it != this->m_lst_src_addresses.end());
	}

	NS_ASSERT(count == this->m_num_srcs);

	return size;
}

TypeId
Igmpv3Query::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return Igmpv3Query::GetTypeId ();
}

void
Igmpv3Query::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "Group Address=";
	this->m_group_address.Print(os);
	os << ", ";
	os << "S Flag=" << this->m_resv_s_qrv.S << ", QRV=" << this->m_resv_s_qrv.QRV << ", ";
	os << "QQIC=" << this->m_num_srcs << ", number of sources=" << this->m_num_srcs << ", ";
	os << "Source Addresses:" << std::endl;
	uint16_t count = 1;

	/*
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		os << "src address(" << count << "): ";
		(*it).Print(os);
		os << std::endl;
		count++;
	}
	*/

	if (false == this->m_lst_src_addresses.empty()) {
		std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin();

		do {
			os << "src address(" << count << "): ";
			(*it).Print(os);
			os << std::endl;
			count++;

			it++;
		} while (it != this->m_lst_src_addresses.end());
	}
}

void
Igmpv3Query::SetGroupAddress (uint32_t address)
{
	NS_LOG_FUNCTION (this << &address);
	this->m_group_address.Set(address);
}

void
Igmpv3Query::SetSFlag (bool b)
{
	NS_LOG_FUNCTION (this);
	if (true == b)
	{
		this->m_resv_s_qrv.S = 0x1;
	}
	else
	{
		this->m_resv_s_qrv.S = 0x0;
	}
}

void
Igmpv3Query::SetQRV (uint8_t qrv)
{
	NS_LOG_FUNCTION (this);
	this->m_resv_s_qrv.QRV = qrv;
}

void
Igmpv3Query::SetQQIC (uint8_t qqic)
{
	NS_LOG_FUNCTION (this);
	this->m_qqic = qqic;
}

/*
void
Igmpv3Query::SetNumSrc (uint16_t num_src)
{
	NS_LOG_FUNCTION (this);
	this->m_num_srcs = num_src;
}
*/

void
Igmpv3Query::PushBackSrcAddress (Ipv4Address address)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_src_addresses.push_back(address);
	this->m_num_srcs++;
}

void
Igmpv3Query::PushBackSrcAddresses (std::list<Ipv4Address> &lst_addresses)
{
	NS_LOG_FUNCTION (this << &lst_addresses);
	for (std::list<Ipv4Address>::const_iterator it = lst_addresses.begin(); it != lst_addresses.end(); ++it)
	{
		this->m_lst_src_addresses.push_back((*it));
		this->m_num_srcs++;
	}
}

uint32_t
Igmpv3Query::GetGroupAddress (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_group_address.Get();
}

bool
Igmpv3Query::isSFlagSet (void)
{
	NS_LOG_FUNCTION (this);
	if (1 == this->m_resv_s_qrv.S)
	{
		return true;
	}
	else
	{
		return false;
	}
}

uint8_t
Igmpv3Query::GetQRV (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_resv_s_qrv.QRV;
}

uint8_t
Igmpv3Query::GetQQIC (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_qqic;
}

uint16_t
Igmpv3Query::GetNumSrc (void)
{
	return this->m_num_srcs;
}

uint16_t
Igmpv3Query::GetSrcAddresses (std::list<Ipv4Address> &payload_addresses) const
{
	NS_LOG_FUNCTION (this << &payload_addresses);
	uint8_t count = 0;
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		payload_addresses.push_back((*it));
		count++;
	}

	return count;
}

/********************************************************
 *        Igmpv3GrpRecord
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (Igmpv3GrpRecord);

TypeId
Igmpv3GrpRecord::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::Igmpv3GrpRecord")
    		.SetParent<Header> ()
			//.SetGroupName("Internet")
			.AddConstructor<Igmpv3GrpRecord> ();
	return tid;
}

Igmpv3GrpRecord::Igmpv3GrpRecord ()
  :  m_record_type (0x00),
	 m_aux_data_len (0),
	 m_num_srcs (0),
	 m_mul_address (Ipv4Address("0.0.0.0"))
{
	NS_LOG_FUNCTION (this);

}

Igmpv3GrpRecord::~Igmpv3GrpRecord ()
{
	NS_LOG_FUNCTION (this);
}

void
Igmpv3GrpRecord::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;
	i.WriteU8(this->m_record_type);
	i.WriteU8(this->m_aux_data_len);
	i.WriteHtonU16(this->m_num_srcs);
	i.WriteHtonU32(this->m_mul_address.Get());


	uint16_t count = 0;

	/*
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		i.WriteHtonU32((*it).Get());
		count++;
	}
	*/

	if (false == this->m_lst_src_addresses.empty()) {
		std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin();

		do {

			i.WriteHtonU32((*it).Get());
			count++;

			it++;
		} while (it != this->m_lst_src_addresses.end());
	}

	NS_ASSERT(count == this->m_num_srcs);

	count = 0;

	/*
	for (std::list<uint32_t>::const_iterator it = this->m_lst_aux_data.begin(); it != this->m_lst_aux_data.end(); ++it)
	{
		i.WriteHtonU32((*it));
		count++;
	}
	*/

	if (false == this->m_lst_aux_data.empty()) {
		std::list<uint32_t>::const_iterator it_u = this->m_lst_aux_data.begin();

		do {
			i.WriteHtonU32((*it_u));
			count++;

			it_u++;
		} while (it_u != this->m_lst_aux_data.end());
	}

	NS_ASSERT(count == this->m_aux_data_len);

}

uint32_t
Igmpv3GrpRecord::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	uint32_t bytes_read = 0;

	this->m_record_type = i.ReadU8();
	bytes_read += 1;

	this->m_aux_data_len = i.ReadU8();
	bytes_read += 1;

	this->m_num_srcs = i.ReadNtohU16();
	bytes_read += 2;

	this->m_mul_address = Ipv4Address(i.ReadNtohU32());
	bytes_read += 4;

	for (uint16_t n = this->m_num_srcs; n > 0; --n)
	{
		this->m_lst_src_addresses.push_back(Ipv4Address(i.ReadNtohU32()));
		bytes_read += 4;
	}

	for (uint16_t n = this->m_aux_data_len; n > 0; --n)
	{
		this->m_lst_aux_data.push_back(i.ReadNtohU32());
		bytes_read += 4;
	}

	return bytes_read;
}

uint32_t
Igmpv3GrpRecord::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);
	uint32_t size = 0;
	size += sizeof (this->m_record_type);
	size += sizeof (this->m_aux_data_len);
	size += sizeof (this->m_num_srcs);
	size += sizeof (this->m_mul_address.Get());


	//size += 4*this->m_num_srcs;	//4 bytes for each ipv4 address

	//this way of counting is slow. but just in case.
	uint16_t srcs_count = 0;

	/*
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		size += sizeof((*it).Get());
		srcs_count++;
	}
	*/

	if (false == this->m_lst_src_addresses.empty()) {
		std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin();

		do {
			size += sizeof((*it).Get());
			srcs_count++;

			it++;
		} while (it != this->m_lst_src_addresses.end());
	}

	NS_ASSERT(srcs_count == this->m_num_srcs);

	//size += 4*this->m_aux_data_len;	//4 bytes for each aux data

	uint16_t aux_count = 0;

	/*
	for (std::list<uint32_t>::const_iterator it = this->m_lst_aux_data.begin(); it != this->m_lst_aux_data.end(); ++it)
	{
		size += sizeof((*it));
		aux_count++;
	}
	*/

	if (false == this->m_lst_aux_data.empty()) {
		std::list<uint32_t>::const_iterator it_u = this->m_lst_aux_data.begin();

		do {
			size += sizeof((*it_u));
			aux_count++;

			it_u++;
		} while (it_u != this->m_lst_aux_data.end());
	}

	NS_ASSERT(aux_count == this->m_aux_data_len);

	return size;

}

TypeId
Igmpv3GrpRecord::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return Igmpv3GrpRecord::GetTypeId ();
}

void
Igmpv3GrpRecord::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "record type=" << this->m_record_type << ", ";
	os << "aux length=" << this->m_aux_data_len << ", ";
	os << "num of srcs" << this->m_num_srcs << ", ";
	os << "multicast address";this->m_mul_address.Print(os);os << ", ";

	uint16_t count = 1;
	/*
	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		os << "src address(" << count << "): ";
		(*it).Print(os);
		os << std::endl;
		count++;
	}
	*/

	if (false == this->m_lst_src_addresses.empty()) {
		std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin();

		do {
			os << "src address(" << count << "): ";
			(*it).Print(os);
			os << std::endl;
			count++;

			it++;
		} while (it != this->m_lst_src_addresses.end());
	}
}

void
Igmpv3GrpRecord::SetType (uint8_t type)
{
	NS_LOG_FUNCTION (this);
	this->m_record_type = type;
}

void
Igmpv3GrpRecord::SetAuxDataLen (uint8_t aux_data_len)
{
	NS_LOG_FUNCTION (this);
	this->m_aux_data_len = aux_data_len;
}

void
Igmpv3GrpRecord::SetNumSrcs (uint16_t num_srcs)
{
	NS_LOG_FUNCTION (this);
	this->m_num_srcs = num_srcs;
}

void
Igmpv3GrpRecord::SetMulticastAddress (uint32_t address)
{
	NS_LOG_FUNCTION (this);
	this->m_mul_address.Set(address);
}

void
Igmpv3GrpRecord::PushBackSrcAddress (uint32_t address)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_src_addresses.push_back(Ipv4Address(address));
}

//void
//Igmpv3GrpRecord::PushBackSrcAddresses (std::list<Ipv4Address> &lst_addresses)
//{
//	NS_LOG_FUNCTION (this << &lst_addresses);
//	for (std::list<Ipv4Address>::const_iterator it = lst_addresses.begin(); it != lst_addresses.end(); ++it)
//	{
//		this->m_lst_src_addresses.push_back((*it));
//	}
//}

void
Igmpv3GrpRecord::PushBackSrcAddresses (std::list<uint32_t> &lst_addresses)
{
	NS_LOG_FUNCTION (this << &lst_addresses);
	for (std::list<uint32_t>::const_iterator it = lst_addresses.begin(); it != lst_addresses.end(); ++it)
	{
		this->m_lst_src_addresses.push_back(Ipv4Address(*it));
	}
}

void
Igmpv3GrpRecord::PushBackAuxData (uint32_t aux_data)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_aux_data.push_back(aux_data);
}

void
Igmpv3GrpRecord::PushBackAuxdata (std::list<uint32_t> &lst_aux_data)
{
	NS_LOG_FUNCTION (this << &lst_aux_data);
	for (std::list<uint32_t>::const_iterator it = lst_aux_data.begin(); it != lst_aux_data.end(); ++it)
	{
			this->m_lst_aux_data.push_back((*it));
	}
}

uint8_t
Igmpv3GrpRecord::GetType (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_record_type;
}

uint8_t
Igmpv3GrpRecord::GetAuxDataLen (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_aux_data_len;
}

uint16_t
Igmpv3GrpRecord::GetNumSrcs (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_num_srcs;
}

uint32_t
Igmpv3GrpRecord::GetMulticastAddress (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_mul_address.Get();
}

uint16_t
Igmpv3GrpRecord::GetSrcAddresses (std::list<Ipv4Address> &payload_addresses) const
{
	NS_LOG_FUNCTION (this);

	uint16_t count = 0;

	for (std::list<Ipv4Address>::const_iterator it = this->m_lst_src_addresses.begin(); it != this->m_lst_src_addresses.end(); ++it)
	{
		payload_addresses.push_back((*it));
		++count;
	}

	return count;
}

uint8_t
Igmpv3GrpRecord::GetAuxData (std::list<uint32_t> &payload_data) const
{
	NS_LOG_FUNCTION (this);

	uint16_t count = 0;

	for (std::list<uint32_t>::const_iterator it = this->m_lst_aux_data.begin(); it != this->m_lst_aux_data.end(); ++it)
	{
		payload_data.push_back((*it));
		++count;
	}

	return count;
}


/********************************************************
 *        Igmpv3Report
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (Igmpv3Report);

TypeId
Igmpv3Report::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::Igmpv3Report")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<Igmpv3Report> ();
	return tid;

}

Igmpv3Report::Igmpv3Report ()
  : m_reserved (0x0000),
	m_num_grp_record (0x0000)
{
	NS_LOG_FUNCTION (this);

}

Igmpv3Report::~Igmpv3Report ()
{
	NS_LOG_FUNCTION (this);
}

void
Igmpv3Report::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);

	Buffer::Iterator i = start;

	i.WriteHtonU16(this->m_reserved);
	i.WriteHtonU16(this->m_num_grp_record);

	//size of data to be serialized can be huge
	//caution!!!!!!!!!!!!!!!!! this might cause buffer to resize.

	uint16_t count = 0;

	/*
	for (std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin(); it != this->m_lst_grp_records.end(); ++it)
	{
		(*it).Serialize(i);
		count++;
	}
	*/

	if (false == this->m_lst_grp_records.empty()) {
		std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin();

		do {
			(*it).Serialize(i);
			count++;

			it++;
		} while (it != this->m_lst_grp_records.end());
	}

	NS_ASSERT(count == this->m_num_grp_record);
}

uint32_t
Igmpv3Report::Deserialize (Buffer::Iterator start)
{
	//caution, need to verify.

	NS_LOG_FUNCTION (this << &start);

	Buffer::Iterator i = start;

	uint32_t size = 0;

	this->m_reserved = i.ReadNtohU16();

	size += 2;

	NS_ASSERT(this->m_reserved == 0);

	this->m_num_grp_record = i.ReadNtohU16();

	size += 2;

	for (uint16_t count_left = this->m_num_grp_record; count_left > 0; --count_left)
	{
		Igmpv3GrpRecord record;
		record.Deserialize(i);

		uint32_t record_size = record.GetSerializedSize();

		i.Next(record_size);		//not sure the iterator will move rightly.
		this->m_lst_grp_records.push_back(record);

		size += record_size;
	}

	return size;
}

uint32_t
Igmpv3Report::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t size = 0;

	size += sizeof(this->m_reserved);
	size += sizeof(this->m_num_grp_record);

	uint16_t count = 0;

	/*
	for (std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin(); it != this->m_lst_grp_records.end(); ++it)
	{
		size += (*it).GetSerializedSize();
	}
	*/

	if (false == this->m_lst_grp_records.empty()) {
		std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin();

		do {
			size += (*it).GetSerializedSize();

			it++;
		} while (it != this->m_lst_grp_records.end());
	}

	NS_ASSERT(count == this->m_num_grp_record);

	return size;
}

TypeId
Igmpv3Report::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return Igmpv3Report::GetTypeId ();
}

void
Igmpv3Report::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "num of grprecord: " << this->m_num_grp_record << ", " << std::endl;

	/*
	for (std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin(); it != this->m_lst_grp_records.end(); ++it)
	{
		(*it).Print(os);
	}
	*/

	if (false == this->m_lst_grp_records.empty()) {
		std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin();

		do {
			(*it).Print(os);

			it++;
		} while (it != this->m_lst_grp_records.end());
	}
}

void
Igmpv3Report::SetNumGrpRecords (uint16_t num_grp_records)
{
	NS_LOG_FUNCTION (this);
	this->m_num_grp_record = num_grp_records;
}

uint16_t
Igmpv3Report::GetNumGrpRecords (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_num_grp_record;
}

void
Igmpv3Report::PushBackGrpRecord (Igmpv3GrpRecord grp_record)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_grp_records.push_back(grp_record);
}

void
Igmpv3Report::PushBackGrpRecords (std::list<Igmpv3GrpRecord> &grp_records)
{
	NS_LOG_FUNCTION (this);

	for (std::list<Igmpv3GrpRecord>::const_iterator it = grp_records.begin(); it != grp_records.end(); ++it)
	{
		this->m_lst_grp_records.push_back((*it));
	}
}

uint16_t
Igmpv3Report::GetGrpRecords (std::list<Igmpv3GrpRecord> &payload_grprecords) const
{
	NS_LOG_FUNCTION (this);

	uint16_t count = 0;

	for (std::list<Igmpv3GrpRecord>::const_iterator it = this->m_lst_grp_records.begin(); it != this->m_lst_grp_records.end(); ++it)
	{
		payload_grprecords.push_back((*it));
		++count;
	}

	return count;
}

}  // namespace ns3
