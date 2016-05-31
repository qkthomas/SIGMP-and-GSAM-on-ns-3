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

#include "gsam.h"
#include "ns3/log.h"
#include "ns3/assert.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("IkeHeader");

/********************************************************
 *        IkeHeader
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeHeader);

TypeId
IkeHeader::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeHeader")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeHeader> ();
	  return tid;
}

IkeHeader::IkeHeader ()
  :  m_initiator_spi (0),
	 m_responder_spi (0),
	 m_next_payload (0),
	 m_version (2),
	 m_exchange_type (0),
	 m_flags (0),
	 m_message_id (0),
	 m_length (0)
{
	NS_LOG_FUNCTION (this);
}

IkeHeader::~IkeHeader ()
{
	NS_LOG_FUNCTION (this);
}

void
IkeHeader::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteHtonU64(this->m_initiator_spi);
	i.WriteHtonU64(this->m_responder_spi);
	i.WriteU8(this->m_next_payload);
	i.WriteU8(this->m_version.toUint8_t());
	i.WriteU8(this->m_exchange_type);
	i.WriteU8(this->m_flags);
	i.WriteHtonU32(this->m_message_id);
	i.WriteHtonU32(this->m_length);
}

uint32_t
IkeHeader::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	uint32_t byte_read = 0;
	Buffer::Iterator i = start;

	this->m_initiator_spi = i.ReadNtohU64();
	byte_read+=8;
	this->m_responder_spi = i.ReadNtohU64();
	byte_read+=8;
	this->m_next_payload = i.ReadU8();
	byte_read++;
	this->m_version = i.ReadU8();
	byte_read++;
	this->m_exchange_type = i.ReadU8();
	byte_read++;
	this->m_flags = i.ReadU8();
	byte_read++;
	this->m_message_id = i.ReadNtohU32();
	byte_read+=4;
	this->m_length = i.ReadNtohU32();
	byte_read+=4;

	return byte_read;
}

uint32_t
IkeHeader::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);
	return (8 + 8 + 1 + 1 + 1 + 1 + 4 + 4);
}

TypeId
IkeHeader::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeHeader::GetTypeId ();
}

void
IkeHeader::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "IKE Packet Header: " << this << ": ";
	os << "Initiator's SPI: " << this->m_initiator_spi << std::endl;
	os << "Responder's SPI: " << this->m_responder_spi << std::endl;
}

/********************************************************
 *        IkePayloadHeader
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkePayloadHeader);

TypeId
IkePayloadHeader::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkePayloadHeader")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkePayloadHeader> ();
	  return tid;
}

IkePayloadHeader::IkePayloadHeader ()
  :  m_next_payload (0),
	 m_critial_reserved (0),
	 m_payload_length (0)
{
	NS_LOG_FUNCTION (this);
}

IkePayloadHeader::~IkePayloadHeader ()
{
	NS_LOG_FUNCTION (this);
}

void
IkePayloadHeader::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteU8(this->m_next_payload);
	i.WriteU8(this->m_critial_reserved);
	i.WriteHtonU16(this->m_payload_length);
}

uint32_t
IkePayloadHeader::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	uint32_t byte_read = 0;
	Buffer::Iterator i = start;

	this->m_next_payload = i.ReadU8();
	byte_read++;
	this->m_critial_reserved = i.ReadU8();
	byte_read++;
	this->m_payload_length = i.ReadNtohU16();
	byte_read+=2;

	return byte_read;
}

uint32_t
IkePayloadHeader::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);
	return 4;
}

TypeId
IkePayloadHeader::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkePayloadHeader::GetTypeId ();
}

void
IkePayloadHeader::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "Ike Payload Header: " << this << ": ";
	os << "Next Payload: " << this->m_next_payload << std::endl;
	os << "Payload Length: " << this->m_payload_length << std::endl;
}

uint16_t
IkePayloadHeader::GetPayloadLength (void) const
{
	NS_LOG_FUNCTION (this);

	return this->m_payload_length;
}

/********************************************************
 *        IkeTransformAttribute
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeTransformAttribute);

TypeId
IkeTransformAttribute::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeSATransformAttribute")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeTransformAttribute> ();
	  return tid;
}

IkeTransformAttribute::IkeTransformAttribute ()
  :  m_TLV (false),
	 m_attribute_type (0),
	 m_attribute_length_or_value (0)
{
	NS_LOG_FUNCTION (this);
}

IkeTransformAttribute::~IkeTransformAttribute ()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_attribute_value.clear();
}

uint32_t
IkeTransformAttribute::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);
	return (4 + this->m_lst_attribute_value.size());
}

TypeId
IkeTransformAttribute::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeTransformAttribute::GetTypeId();
}

void
IkeTransformAttribute::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	// If the AF bit is zero (0), then
    // the attribute uses TLV format; if the AF bit is one (1), the TV
    // format (with two-byte value) is used.
	if (true == this->m_TLV)
	{
		uint16_t value = (this->m_attribute_type << 1) + 0x00;
		i.WriteHtonU16(value);
		i.WriteHtonU16(this->m_attribute_length_or_value);
		for (	std::list<uint8_t>::const_iterator const_it = this->m_lst_attribute_value.begin();
				const_it != this->m_lst_attribute_value.end();
				const_it++)
		{
			i.WriteU8(*const_it);
		}
	}
	else
	{
		uint16_t value = (this->m_attribute_type << 1) + 0x01;
		i.WriteHtonU16(value);
		i.WriteHtonU16(this->m_attribute_length_or_value);
	}

}

uint32_t
IkeTransformAttribute::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	uint32_t size = 0;

	uint16_t af_attribute_type = i.ReadNtohU16();
	size += 2;

	this->m_attribute_length_or_value = (af_attribute_type & 0xfffe) >> 1;
	if (0 == (af_attribute_type & 0x0001))
	{
		this->m_TLV = true;
	}
	else
	{
		this->m_TLV = false;
	}

	this->m_attribute_length_or_value = i.ReadNtohU16();
	size += 2;

	if (true == this->m_TLV)
	{
		for (	int it = 1;
				it <= this->m_attribute_length_or_value;
				it++)
		{
			this->m_lst_attribute_value.push_back(i.ReadU8());
			size++;
		}
	}
	else
	{
		//do nothing
	}

	return size;
}

void 
IkeTransformAttribute::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);

	os << "Tranform Attribute: " << this;
	os << " Type: " << this->m_attribute_type << std::endl;
}

/********************************************************
 *        IkeTransform
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeTransformSubStructure);

TypeId
IkeTransformSubStructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeTransformSubStructure")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeTransformSubStructure> ();
	  return tid;
}

IkeTransformSubStructure::IkeTransformSubStructure ()
  : m_last (true),
	m_transform_length (0),
	m_transform_type (0),
	m_transform_id (0)
{
	NS_LOG_FUNCTION (this);
}

IkeTransformSubStructure::~IkeTransformSubStructure ()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_transform_attributes.clear();
}

uint32_t
IkeTransformSubStructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);
	uint32_t size = 0;

	size += 8;

	for (	std::list<IkeTransformAttribute>::const_iterator const_it = this->m_lst_transform_attributes.begin();
			const_it != this->m_lst_transform_attributes.end();
			const_it++)
	{
		size += const_it->GetSerializedSize();
	}

	return size;
}

TypeId
IkeTransformSubStructure::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeTransformSubStructure::GetTypeId();
}

void
IkeTransformSubStructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteU8(this->m_last);

	//to write first RESERVED
	i.WriteU8(0);

	i.WriteHtonU16(this->m_transform_length);
	i.WriteU8(this->m_transform_type);

	//to write second RESERVED
	i.WriteU8(0);

	i.WriteHtonU16(this->m_transform_id);

	for (	std::list<IkeTransformAttribute>::const_iterator const_it = this->m_lst_transform_attributes.begin();
			const_it != this->m_lst_transform_attributes.end();
			const_it++)
	{
		const_it->Serialize(i);
		i.Next(const_it->GetSerializedSize());
	}
}

uint32_t
IkeTransformSubStructure::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	uint32_t size = 0;

	uint8_t field_last = i.ReadU8();
	size++;
	if (0 == field_last)
	{
		this->m_last = true;
	}
	else if (3 == field_last)
	{
		this->m_last = false;
	}
	else
	{
		NS_ASSERT (false);
	}

	//to skip first RESERVED
	i.Next();
	size++;

	this->m_transform_length = i.ReadNtohU16();
	size += 2;
	this->m_transform_type = i.ReadU8();
	size++;

	//to skip second RESERVED
	i.Next();
	size++;

	this->m_transform_id = i.ReadNtohU16();
	size += 2;

	while (size < this->m_transform_length)
	{
		IkeTransformAttribute attribute;
		uint32_t size_attribute = attribute.Deserialize(i);

		i.Next(attribute.GetSerializedSize());

		size += size_attribute;

		this->m_lst_transform_attributes.push_back(attribute);
	}

	NS_ASSERT (size == this->m_transform_length);

	return size;

}

void
IkeTransformSubStructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "Ike Transform Substructure: " << this << std::endl;
}

void
IkeTransformSubStructure::SetLast (void)
{
	NS_LOG_FUNCTION (this);

	this->m_last = true;
}

bool
IkeTransformSubStructure::IsLast (void)
{
	NS_LOG_FUNCTION (this);
	return this->m_last;
}

/********************************************************
 *        Spi
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (Spi);

TypeId
Spi::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::Spi")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<Spi> ();
	  return tid;
}

Spi::Spi ()
  : m_size (0)
{
	NS_LOG_FUNCTION (this);
}

Spi::~Spi ()
{
	NS_LOG_FUNCTION (this);
	m_lst_var.clear();
}

uint32_t
Spi::GetSerializedSize (void) const
{
	if (this->GetSize() <= 0)
	{
		NS_ASSERT (false);
	}
	else
	{
		//do nothing
	}

	return this->GetSize();
}

TypeId
Spi::GetInstanceTypeId (void) const
{
	return Spi::GetTypeId();
}

void
Spi::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	if (this->GetSize() <= 0)
	{
		NS_ASSERT (false);
	}
	else
	{
		//do nothing
	}

	Buffer::Iterator i = start;

	for (	std::list<uint8_t>::const_iterator const_it = this->m_lst_var.begin();
			const_it != this->m_lst_var.end();
			const_it++)
	{
		i.WriteU8(*const_it);
	}
}

uint32_t
Spi::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	if (this->m_size <= 0)
	{
		NS_ASSERT (false);
	}
	else
	{
		//do nothing
	}

	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	for (	uint16_t count = 1;
			count <= this->m_size;
			count++)
	{
		this->m_lst_var.push_back(i.ReadU8());
	}

	return this->GetSize();
}

void
Spi::Print (std::ostream &os) const
{

}

void
Spi::SetSize (uint8_t size)
{
	this->m_size = size;
}

uint8_t
Spi::GetSize (void) const
{
	return this->m_lst_var.size();
}

/********************************************************
 *        IkeSAProposal
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeSAProposal);

TypeId
IkeSAProposal::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeSAProposal")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeSAProposal> ();
	  return tid;
}

IkeSAProposal::IkeSAProposal ()
  :  m_last (true),
	 m_proposal_length (0),
	 m_proposal_num (0),
	 m_protocol_id (0),
	 m_spi_size (0),
	 m_num_transforms (0)
{
	NS_LOG_FUNCTION (this);
}

IkeSAProposal::~IkeSAProposal ()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_transforms.clear();
}

uint32_t
IkeSAProposal::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t size = 0;

	size += 8;
	size += this->m_spi.GetSerializedSize();

	for (	std::list<IkeTransformSubStructure>::const_iterator const_it = this->m_lst_transforms.begin();
			const_it != this->m_lst_transforms.end();
			const_it++)
	{
		size += const_it->GetSerializedSize();
	}

	return size;
}

TypeId
IkeSAProposal::GetInstanceTypeId (void) const
{
	return IkeSAProposal::GetTypeId();
}

void
IkeSAProposal::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	if (true == this->m_last)
	{
		i.WriteU8(0);
	}
	else if (false == this->m_last)
	{
		i.WriteU8(2);
	}
	else
	{
		NS_ASSERT (false);
	}

	//to write the RESERVED field
	i.WriteU8(0);

	i.WriteHtolsbU16(this->m_proposal_length);

	i.WriteU8(this->m_proposal_num);

	i.WriteU8(this->m_protocol_id);

	i.WriteU8(this->m_spi.GetSize());

	i.WriteU8(this->m_lst_transforms.size());

	this->m_spi.Serialize(i);

	for (	std::list<IkeTransformSubStructure>::const_iterator const_it = this->m_lst_transforms.begin();
			const_it != this->m_lst_transforms.end();
			const_it++)
	{
		const_it->Serialize(i);
		i.Next(const_it->GetSerializedSize());
	}
}

uint32_t
IkeSAProposal::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	uint32_t size = 0;

	uint8_t field_last = i.ReadU8();
	size++;

	if (0 == field_last)
	{
		this->m_last = true;
	}
	else if (2 == field_last)
	{
		this->m_last = false;
	}
	else
	{
		NS_ASSERT (false);
	}

	//skip first RESERVED
	i.Next();
	size++;

	this->m_proposal_length = i.ReadNtohU16();
	size += 2;

	this->m_proposal_num = i.ReadU8();
	size++;

	this->m_protocol_id = i.ReadU8();
	size++;

	this->m_spi_size = i.ReadU8();
	size++;

	this->m_num_transforms = i.ReadU8();
	size++;

	Spi spi;
	spi.SetSize(this->m_spi_size);

	spi.Deserialize(i);
	i.Next(spi.GetSerializedSize());

	for (	uint8_t it = 1;
			it <= this->m_num_transforms;
			it++)
	{
		IkeTransformSubStructure tranform;
		tranform.Deserialize(i);
		i.Next(tranform.GetSerializedSize());
		this->m_lst_transforms.push_back(tranform);
	}

	NS_ASSERT (size == this->m_proposal_length);

	return size;
}

void
IkeSAProposal::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "IkeSAProposal: " << this << std::endl;
}

/********************************************************
 *        IkeSAPayload
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeSAPayload);

TypeId
IkeSAPayload::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeSAPayload")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeSAPayload> ();
	  return tid;
}

IkeSAPayload::IkeSAPayload ()
{
	NS_LOG_FUNCTION (this);
}

IkeSAPayload::~IkeSAPayload ()
{
	NS_LOG_FUNCTION (this);
}

uint32_t
IkeSAPayload::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t size = 0;

	size += this->m_header.GetSerializedSize();

	for (	std::list<IkeSAProposal>::const_iterator const_it = this->m_lst_proposal.begin();
			const_it != this->m_lst_proposal.end();
			const_it++)
	{
		size += const_it->GetSerializedSize();
	}

	return size;
}

void
IkeSAPayload::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	this->m_header.Serialize(i);
	i.Next(this->m_header.GetSerializedSize());

	for (	std::list<IkeSAProposal>::iterator it = this->m_lst_proposal.begin();
			it != this->m_lst_proposal.end();
			it++)
	{
		it->Serialize(i);
		i.Next(it->GetSerializedSize());
	}
}

uint32_t
IkeSAPayload::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;
	uint32_t size = 0;

	this->m_header.Deserialize(i);
	i.Next(this->m_header.GetSerializedSize());
	size += this->m_header.GetSerializedSize();

	uint16_t payload_length = this->m_header.GetPayloadLength();
	uint16_t length_rest = payload_length - this->m_header.GetSerializedSize();

	while (length_rest > 0)
	{
		IkeSAProposal proposal;
		proposal.Deserialize(i);
		size += proposal.GetSerializedSize();
		length_rest -= proposal.GetSerializedSize();
	}

	NS_ASSERT (size == payload_length);

	return size;
}

void
IkeSAPayload::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);

	os << "IkeSAPayload: " << this << std::endl;
}

/********************************************************
 *        IkeKeyExchangeSubStructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeKeyExchangeSubStructure);

TypeId
IkeKeyExchangeSubStructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeKeyExchangeSubStructure")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeKeyExchangeSubStructure> ();
	  return tid;
}

IkeKeyExchangeSubStructure::IkeKeyExchangeSubStructure ()
  :  m_dh_group_num (0),
	 m_length (0)
{
	NS_LOG_FUNCTION (this);
}

IkeKeyExchangeSubStructure::~IkeKeyExchangeSubStructure ()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_data.clear();
}

uint32_t
IkeKeyExchangeSubStructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t size = 0;

	size += 4;

	for (	std::list<uint8_t>::const_iterator const_it = this->m_lst_data.begin();
			const_it != this->m_lst_data.end();
			const_it++)
	{
		size += sizeof(uint8_t);
	}
	return size;
}

void
IkeKeyExchangeSubStructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteU8(this->m_dh_group_num);

	//to skip field RESERVED 16 bits == 2 bytes
	i.WriteHtonU16(0);

	for (	std::list<uint8_t>::const_iterator const_it = this->m_lst_data.begin();
			const_it != this->m_lst_data.end();
			const_it++)
	{
		i.WriteU8((*const_it));
	}
}

uint32_t
IkeKeyExchangeSubStructure::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	if (0 == this->m_length)
	{
		NS_ASSERT (false);
	}
	else
	{
		//do nothing
	}

	uint32_t size = 0;

	this->m_dh_group_num = i.ReadNtohU16();
	size += 2;

	//to skipped to field RESERVED
	i.Next(2);
	size += 2;

	uint16_t length_rest = this->m_length - size;

	for (	uint16_t it = 1;
			it <= length_rest;
			it++)
	{
		this->m_lst_data.push_back(i.ReadU8());
		size++;
	}

	NS_ASSERT (size == this->m_length);

	return size;
}

void
IkeKeyExchangeSubStructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "IkeKeyExchangeSubStructure: " << this << std::endl;
}

void
IkeKeyExchangeSubStructure::SetLength (uint16_t length)
{
	NS_LOG_FUNCTION (this);
	this->m_length = length;
}

/********************************************************
 *        IkeKeyExchangePayload
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeKeyExchangePayload);

TypeId
IkeKeyExchangePayload::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeKeyExchangePayload")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeKeyExchangePayload> ();
	  return tid;
}

IkeKeyExchangePayload::IkeKeyExchangePayload ()
{
	NS_LOG_FUNCTION (this);
}

IkeKeyExchangePayload::~IkeKeyExchangePayload ()
{
	NS_LOG_FUNCTION (this);
}

uint32_t
IkeKeyExchangePayload::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	return this->m_header.GetSerializedSize() + this->m_substructure.GetSerializedSize();
}

void
IkeKeyExchangePayload::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	this->m_header.Serialize(i);
	i.Next(this->m_header.GetSerializedSize());

	this->m_substructure.Serialize(i);
	i.Next(this->m_substructure.GetSerializedSize());
}

uint32_t
IkeKeyExchangePayload::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);

	Buffer::Iterator i = start;
	uint32_t size = 0;

	this->m_header.Deserialize(i);
	i.Next(this->m_header.GetSerializedSize());
	size += this->m_header.GetSerializedSize();

	uint16_t total_length = this->m_header.GetPayloadLength();
	uint16_t length_rest = total_length - this->m_header.GetSerializedSize();

	this->m_substructure.SetLength(length_rest);
	this->m_substructure.Deserialize(i);
	i.Next(this->m_substructure.GetSerializedSize());
	size += this->m_substructure.GetSerializedSize();

	return size;
}

void
IkeKeyExchangePayload::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "IkeKeyExchangePayload: " << this << std::endl;
}

/********************************************************
 *        IkeIdSubstructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeIdSubstructure);

TypeId
IkeIdSubstructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeIdSubstructure")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeIdSubstructure> ();
	  return tid;
}

IkeIdSubstructure::IkeIdSubstructure ()
  : m_id_type (0),
	m_length (0)
{
	NS_LOG_FUNCTION (this);
}

IkeIdSubstructure::~IkeIdSubstructure ()
{
	NS_LOG_FUNCTION (this);
	m_lst_id_data.clear();
}

uint32_t
IkeIdSubstructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	return 4 + this->m_lst_id_data.size();
}

void
IkeIdSubstructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteU8(this->m_id_type);
	i.WriteU8(0, 3);

	for (	std::list<uint8_t>::const_iterator const_it = this->m_lst_id_data.begin();
			const_it != this->m_lst_id_data.end();
			const_it++)
	{
		i.WriteU8((*const_it));
	}
}

uint32_t
IkeIdSubstructure::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	if (0 == this->m_length)
	{
		NS_ASSERT (false);
	}
	else
	{
		//do nothing
	}

	uint32_t size = 0;

	this->m_id_type = i.ReadU8();
	size++;

	//to skip the field RESERVED
	i.Next(3);
	size += 3;

	uint16_t length_rest = this->m_length - size;

	for (	uint16_t it = 1;
			it <= length_rest;
			it++)
	{
		i.ReadU8();
		size++;
	}

	NS_ASSERT (size == this->m_length);

	return size;
}

void
IkeIdSubstructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "IkeIdSubstructure: " << this << std::endl;
}

void
IkeIdSubstructure::SetLength (uint16_t length)
{
	NS_LOG_FUNCTION (this);
	this->m_length = length;
}

/********************************************************
 *        IkeIdPayload
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeIdPayload);

TypeId
IkeIdPayload::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeIdPayload")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeIdPayload> ();
	  return tid;
}

IkeIdPayload::IkeIdPayload ()
{
	NS_LOG_FUNCTION (this);
}

IkeIdPayload::~IkeIdPayload ()
{
	NS_LOG_FUNCTION (this);
}

uint32_t
IkeIdPayload::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	return this->m_header.GetSerializedSize() + this->m_substructure.GetSerializedSize();
}

void
IkeIdPayload::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	this->m_header.Serialize(i);
	i.Next(this->m_header.GetSerializedSize());

	this->m_substructure.Serialize(i);
	i.Next(this->m_substructure.GetSerializedSize());
}

uint32_t
IkeIdPayload::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);

	Buffer::Iterator i = start;
	uint32_t size = 0;

	this->m_header.Deserialize(i);
	i.Next(this->m_header.GetSerializedSize());
	size += this->m_header.GetSerializedSize();

	uint16_t total_length = this->m_header.GetPayloadLength();
	uint16_t length_rest = total_length - this->m_header.GetSerializedSize();

	this->m_substructure.SetLength(length_rest);
	this->m_substructure.Deserialize(i);
	i.Next(this->m_substructure.GetSerializedSize());
	size += this->m_substructure.GetSerializedSize();

	return size;
}

void
IkeIdPayload::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "IkeIdPayload: " << this << std::endl;
}

/********************************************************
 *        IkeAuthSubstructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeAuthSubstructure);

TypeId
IkeAuthSubstructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeAuthSubstructure")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeAuthSubstructure> ();
	  return tid;
}

IkeAuthSubstructure::IkeAuthSubstructure ()
  : m_auth_method (0),
	m_length (0)
{
	NS_LOG_FUNCTION (this);
}

IkeAuthSubstructure::~IkeAuthSubstructure ()
{
	NS_LOG_FUNCTION (this);
	m_lst_id_data.clear();
}

uint32_t
IkeAuthSubstructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	return 4 + this->m_lst_id_data.size();
}

void
IkeAuthSubstructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteU8(this->m_auth_method);
	i.WriteU8(0, 3);

	for (	std::list<uint8_t>::const_iterator const_it = this->m_lst_id_data.begin();
			const_it != this->m_lst_id_data.end();
			const_it++)
	{
		i.WriteU8((*const_it));
	}
}

uint32_t
IkeAuthSubstructure::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	if (0 == this->m_length)
	{
		NS_ASSERT (false);
	}
	else
	{
		//do nothing
	}

	uint32_t size = 0;

	this->m_auth_method = i.ReadU8();
	size++;

	//to skip the field RESERVED
	i.Next(3);
	size += 3;

	uint16_t length_rest = this->m_length - size;

	for (	uint16_t it = 1;
			it <= length_rest;
			it++)
	{
		i.ReadU8();
		size++;
	}

	NS_ASSERT (size == this->m_length);

	return size;
}

void
IkeAuthSubstructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "IkeIdSubstructure: " << this << std::endl;
}

void
IkeAuthSubstructure::SetLength (uint16_t length)
{
	NS_LOG_FUNCTION (this);
	this->m_length = length;
}

/********************************************************
 *        IkeAuthPayload
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeAuthPayload);

TypeId
IkeAuthPayload::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeAuthPayload")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeAuthPayload> ();
	  return tid;
}

IkeAuthPayload::IkeAuthPayload ()
{
	NS_LOG_FUNCTION (this);
}

IkeAuthPayload::~IkeAuthPayload ()
{
	NS_LOG_FUNCTION (this);
}

uint32_t
IkeAuthPayload::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	return this->m_header.GetSerializedSize() + this->m_substructure.GetSerializedSize();
}

void
IkeAuthPayload::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	this->m_header.Serialize(i);
	i.Next(this->m_header.GetSerializedSize());

	this->m_substructure.Serialize(i);
	i.Next(this->m_substructure.GetSerializedSize());
}

uint32_t
IkeAuthPayload::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);

	Buffer::Iterator i = start;
	uint32_t size = 0;

	this->m_header.Deserialize(i);
	i.Next(this->m_header.GetSerializedSize());
	size += this->m_header.GetSerializedSize();

	uint16_t total_length = this->m_header.GetPayloadLength();
	uint16_t length_rest = total_length - this->m_header.GetSerializedSize();

	this->m_substructure.SetLength(length_rest);
	this->m_substructure.Deserialize(i);
	i.Next(this->m_substructure.GetSerializedSize());
	size += this->m_substructure.GetSerializedSize();

	return size;
}

void
IkeAuthPayload::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "IkeAuthPayload: " << this << std::endl;
}

}  // namespace ns3
