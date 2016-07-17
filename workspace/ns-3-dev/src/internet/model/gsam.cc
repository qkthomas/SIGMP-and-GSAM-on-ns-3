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
#include "ipsec.h"
#include <cstdlib>
#include <ctime>

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
     m_next_payload (IkePayloadHeader::NO_NEXT_PAYLOAD),
	 m_version (2),
	 m_exchange_type (IkeHeader::NONE),
	 m_flag_response (false),
	 m_flag_version (false),
	 m_flag_initiator (false),
	 m_message_id (0),
	 m_length (0)
{
	NS_LOG_FUNCTION (this);
}

IkeHeader::~IkeHeader ()
{
	NS_LOG_FUNCTION (this);
}

uint8_t
IkeHeader::ExchangeTypeToUint8 (IkeHeader::EXCHANGE_TYPE exchange_type)
{
	uint8_t retval = 0;

	switch (exchange_type)
	{
	case IkeHeader::IKE_SA_INIT:
		retval = 34;
		break;
	case IkeHeader::IKE_AUTH:
		retval = 35;
		break;
	case IkeHeader::CREATE_CHILD_SA:
		retval = 36;
		break;
	case IkeHeader::INFORMATIONAL:
		retval = 37;
		break;
	default:
		retval = 0;
		NS_ASSERT (false);
	}
	return retval;
}

IkeHeader::EXCHANGE_TYPE
IkeHeader::Uint8ToExchangeType (uint8_t value)
{
	IkeHeader::EXCHANGE_TYPE retval = IkeHeader::IKE_SA_INIT;

	switch (value)
	{
	case 34:
		retval = IkeHeader::IKE_SA_INIT;
		break;
	case 35:
		retval = IkeHeader::IKE_AUTH;
		break;
	case 36:
		retval = IkeHeader::CREATE_CHILD_SA;
		break;
	case 37:
		retval = IkeHeader::INFORMATIONAL;
		break;
	default:
		NS_ASSERT (false);
	}
	return retval;
}

void
IkeHeader::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteHtolsbU64(this->m_initiator_spi);
	i.WriteHtolsbU64(this->m_responder_spi);
	i.WriteU8(IkePayloadHeader::PayloadTypeToUnit8(this->m_next_payload));
	i.WriteU8(this->m_version.toUint8_t());
	i.WriteU8(ExchangeTypeToUint8(this->m_exchange_type));
	i.WriteU8(this->FlagsToU8());
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
	byte_read += sizeof(this->m_initiator_spi);

	this->m_responder_spi = i.ReadNtohU64();
	byte_read += sizeof (this->m_responder_spi);

	this->m_next_payload = IkePayloadHeader::Uint8ToPayloadType(i.ReadU8());
	byte_read ++;

	this->m_version = i.ReadU8();
	byte_read += sizeof (this->m_version);

	this->m_exchange_type = Uint8ToExchangeType(i.ReadU8());
	byte_read ++;

	this->U8ToFlags(i.ReadU8());
	byte_read++;

	this->m_message_id = i.ReadNtohU32();
	byte_read += sizeof (this->m_message_id);

	this->m_length = i.ReadNtohU32();
	byte_read += sizeof (this->m_length);

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
	os << "Initiator SPI: " << this->m_initiator_spi << ", ";
	os << "Responder SPI: " << this->m_responder_spi << std::endl;
}

uint8_t
IkeHeader::FlagsToU8 (void) const
{
	NS_LOG_FUNCTION (this);
	/*
	 * +-+-+-+-+-+-+-+-+
     * |X|X|R|V|I|X|X|X|
     * +-+-+-+-+-+-+-+-+
	 */

	uint8_t retval = 0;

	if (true == this->m_flag_response)
	{
		retval += 0x04;
	}

	if (true == this->m_flag_version)
	{
		retval += 0x08;
	}

	if (true == this->m_flag_initiator)
	{
		retval += 0x10;
	}

	return retval;
}

void
IkeHeader::U8ToFlags (uint8_t input)
{
	NS_LOG_FUNCTION (this);
	/*
	 * +-+-+-+-+-+-+-+-+
     * |X|X|R|V|I|X|X|X|
     * +-+-+-+-+-+-+-+-+
	 */

	if (0 != (input & 0x04))
	{
		this->m_flag_response = true;
	}

	if (0 != (input & 0x08))
	{
		this->m_flag_version = true;
	}

	if (0 != (input & 0x10))
	{
		this->m_initiator_spi = true;
	}
}

void
IkeHeader::SetIkev2Version (void)
{
	NS_LOG_FUNCTION (this);
	this->m_version.SetIkev2();
}

void
IkeHeader::SetInitiatorSpi (uint64_t spi)
{
	NS_LOG_FUNCTION (this);
	this->m_initiator_spi = spi;
}

uint64_t
IkeHeader::GetInitiatorSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_initiator_spi;
}

void
IkeHeader::SetResponderSpi (uint64_t spi)
{
	NS_LOG_FUNCTION (this);
	this->m_responder_spi = spi;
}

uint64_t
IkeHeader::GetResponderSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_responder_spi;
}

void
IkeHeader::SetNextPayloadType (IkePayloadHeader::PAYLOAD_TYPE payload_type)
{
	NS_LOG_FUNCTION (this);
	this->m_next_payload = payload_type;
}

IkePayloadHeader::PAYLOAD_TYPE
IkeHeader::GetNextPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_next_payload;
}

void
IkeHeader::SetExchangeType (IkeHeader::EXCHANGE_TYPE exchange_type)
{
	NS_LOG_FUNCTION (this);
	this->m_exchange_type = exchange_type;
}

IkeHeader::EXCHANGE_TYPE
IkeHeader::GetExchangeType (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_exchange_type;
}

void
IkeHeader::SetAsInitiator (void)
{
	NS_LOG_FUNCTION (this);
	this->m_flag_initiator = true;
}

bool
IkeHeader::IsInitiator (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_flag_initiator;
}

void
IkeHeader::SetAsResponder (void)
{
	NS_LOG_FUNCTION (this);
	this->m_flag_response = true;
}

bool
IkeHeader::IsResponder (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_flag_response;
}

void
IkeHeader::SetMessageId (uint32_t id)
{
	NS_LOG_FUNCTION (this);
	this->m_message_id = id;
}

uint32_t
IkeHeader::GetMessageId (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_message_id;
}

void
IkeHeader::SetLength (uint32_t length)
{
	NS_LOG_FUNCTION (this);
	this->m_length = length;
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
  :  m_next_payload (IkePayloadHeader::NO_NEXT_PAYLOAD),
	 m_flag_critical (false),
	 m_payload_length (0)
{
	NS_LOG_FUNCTION (this);
}

IkePayloadHeader::~IkePayloadHeader ()
{
	NS_LOG_FUNCTION (this);
}

uint8_t
IkePayloadHeader::PayloadTypeToUnit8 (IkePayloadHeader::PAYLOAD_TYPE payload_type)
{
	uint8_t retval = 0;

	switch (payload_type)
	{
	case IkePayloadHeader::NO_NEXT_PAYLOAD:
		retval = 0;
		break;
	case IkePayloadHeader::SECURITY_ASSOCIATION:
		retval = 33;
		break;
	case IkePayloadHeader::KEY_EXCHANGE:
		retval = 34;
		break;
	case IkePayloadHeader::IDENTIFICATION_INITIATOR:
		retval = 35;
		break;
	case IkePayloadHeader::IDENTIFICATION_RESPONDER:
		retval = 36;
		break;
	case IkePayloadHeader::CERTIFICATE:
		retval = 37;
		break;
	case IkePayloadHeader::CERTIFICATE_REQUEST:
		retval = 38;
		break;
	case IkePayloadHeader::AUTHENTICATION:
		retval = 39;
		break;
	case IkePayloadHeader::NONCE:
		retval = 40;
		break;
	case IkePayloadHeader::NOTIFY:
		retval = 41;
		break;
	case IkePayloadHeader::DELETE:
		retval = 42;
		break;
	case IkePayloadHeader::VENDOR_ID:
		retval = 43;
		break;
	case IkePayloadHeader::TRAFFIC_SELECTOR_INITIATOR:
		retval = 44;
		break;
	case IkePayloadHeader::TRAFFIC_SELECTOR_RESPONDER:
		retval = 45;
		break;
	case IkePayloadHeader::ENCRYPTED_AND_AUTHENTICATED:
		retval = 46;
		break;
	case IkePayloadHeader::CONFIGURATION:
		retval = 47;
		break;
	case IkePayloadHeader::EXTENSIBLE_AUTHENTICATION:
			retval = 48;
			break;
	default:
		retval = 0;
		NS_ASSERT (false);
	}
	return retval;
}

IkePayloadHeader::PAYLOAD_TYPE
IkePayloadHeader::Uint8ToPayloadType (uint8_t value)
{
	IkePayloadHeader::PAYLOAD_TYPE retval = IkePayloadHeader::NO_NEXT_PAYLOAD;

	switch (value)
	{
	case 0:
		retval = IkePayloadHeader::NO_NEXT_PAYLOAD;
		break;
	case 33:
		retval = IkePayloadHeader::SECURITY_ASSOCIATION;
		break;
	case 34:
		retval = IkePayloadHeader::KEY_EXCHANGE;
		break;
	case 35:
		retval = IkePayloadHeader::IDENTIFICATION_INITIATOR;
		break;
	case 36:
		retval = IkePayloadHeader::IDENTIFICATION_RESPONDER;
		break;
	case 37:
		retval = IkePayloadHeader::CERTIFICATE;
		break;
	case 38:
		retval = IkePayloadHeader::CERTIFICATE_REQUEST;
		break;
	case 39:
		retval = IkePayloadHeader::AUTHENTICATION;
		break;
	case 40:
		retval = IkePayloadHeader::NONCE;
		break;
	case 41:
		retval = IkePayloadHeader::NOTIFY;
		break;
	case 42:
		retval = IkePayloadHeader::DELETE;
		break;
	case 43:
		retval = IkePayloadHeader::VENDOR_ID;
		break;
	case 44:
		retval = IkePayloadHeader::TRAFFIC_SELECTOR_INITIATOR;
		break;
	case 45:
		retval = IkePayloadHeader::TRAFFIC_SELECTOR_RESPONDER;
		break;
	case 46:
		retval = IkePayloadHeader::ENCRYPTED_AND_AUTHENTICATED;
		break;
	case 47:
		retval = IkePayloadHeader::CONFIGURATION;
		break;
	case 48:
			retval = IkePayloadHeader::EXTENSIBLE_AUTHENTICATION;
			break;
	default:
		NS_ASSERT (false);
	}
	return retval;
}

void
IkePayloadHeader::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteU8(PayloadTypeToUnit8(this->m_next_payload));
	if (false == this->m_flag_critical)
	{
		i.WriteU8(0x00);
	}
	else
	{
		i.WriteU8(0x01);
	}
	i.WriteHtonU16(this->m_payload_length);
}

uint32_t
IkePayloadHeader::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	uint32_t byte_read = 0;
	Buffer::Iterator i = start;

	this->m_next_payload = Uint8ToPayloadType(i.ReadU8());
	byte_read ++;

	uint8_t critial_reserved = i.ReadU8();
	byte_read += sizeof (critial_reserved);

	if (0x00 == critial_reserved)
	{
		this->m_flag_critical = false;
	}
	else if (0x01 == critial_reserved)
	{
		this->m_flag_critical = true;
	}
	else
	{
		NS_ASSERT (false);
	}

	this->m_payload_length = i.ReadNtohU16();
	byte_read += sizeof (this->m_payload_length);

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

IkePayloadHeader::PAYLOAD_TYPE
IkePayloadHeader::GetNextPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_next_payload;
}

void
IkePayloadHeader::SetNextPayloadType (IkePayloadHeader::PAYLOAD_TYPE payload_type)
{
	NS_LOG_FUNCTION (this);
	this->m_next_payload = payload_type;
}
void
IkePayloadHeader::SetPayloadLength (uint16_t length)
{
	NS_LOG_FUNCTION (this);
	this->m_payload_length = length;
}

/********************************************************
 *        IkePayloadSubstructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkePayloadSubstructure);

TypeId
IkePayloadSubstructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkePayloadSubstructure")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkePayloadSubstructure> ();
	  return tid;
}

IkePayloadSubstructure::IkePayloadSubstructure ()
  :  m_length (0)
{
	NS_LOG_FUNCTION (this);
}

IkePayloadSubstructure::~IkePayloadSubstructure ()
{
	NS_LOG_FUNCTION (this);
}

void
IkePayloadSubstructure::SetLength (uint16_t length)
{
	NS_LOG_FUNCTION (this);
	this->m_length = length;
}

uint32_t
IkePayloadSubstructure::Deserialize (Buffer::Iterator start, uint16_t length)
{
	NS_LOG_FUNCTION (this << &start);

	this->SetLength(length);

	return this->Deserialize(start);
}

uint32_t
IkePayloadSubstructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	//should not be called
	NS_ASSERT (false);

	return 0;
}

TypeId
IkePayloadSubstructure::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);

	//should not be called
	NS_ASSERT (false);

	return IkePayloadSubstructure::GetTypeId();
}

void
IkePayloadSubstructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this);

	//should not be called
	NS_ASSERT (false);
}

uint32_t
IkePayloadSubstructure::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this);

	//should not be called
	NS_ASSERT (false);

	return 0;
}

void
IkePayloadSubstructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);

	os << "IkePayloadSubstructure: " << this << std::endl;
}

IkePayloadHeader::PAYLOAD_TYPE
IkePayloadSubstructure::GetPayloadType (void) const
{
	NS_LOG_FUNCTION (this);

	return IkePayloadHeader::NO_NEXT_PAYLOAD;
}

/********************************************************
 *        Spi
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (Spi);

TypeId
Spi::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::Spi")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<Spi> ();
	  return tid;
}

Spi::Spi ()
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
	return this->m_lst_var.size();
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
	if (this->m_lst_var.size() <= 0)
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
	if (this->m_length <= 0)
	{
		NS_ASSERT (false);
	}
	else
	{
		//do nothing
	}

	Buffer::Iterator i = start;
	uint32_t size = 0;

	for (	uint16_t count = 1;
			count <= this->m_length;
			count++)
	{
		this->m_lst_var.push_back(i.ReadU8());
		size++;
	}

	NS_ASSERT (size == this->m_length);

	return size;
}

void
Spi::Print (std::ostream &os) const
{

}

uint32_t
Spi::ToUint32 (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t retval = GsamUtility::BytesToUint32(this->m_lst_var);

	return retval;
}

uint64_t
Spi::ToUint64 (void) const
{
	NS_LOG_FUNCTION (this);

	uint64_t retval = GsamUtility::BytesToUint64(this->m_lst_var);

	return retval;
}

void
Spi::SetValueFromUint32 (uint32_t value)
{
	NS_LOG_FUNCTION (this);

	GsamUtility::Uint32ToBytes(this->m_lst_var, value);
}
void
Spi::SetValueFromUint64 (uint64_t value)
{
	NS_LOG_FUNCTION (this);

	GsamUtility::Uint64ToBytes(this->m_lst_var, value);
}

/********************************************************
 *        IkePayload
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkePayload);

TypeId
IkePayload::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkePayload")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkePayload> ();
	  return tid;
}

IkePayload::IkePayload ()
  :  m_ptr_substructure(0)
{
	NS_LOG_FUNCTION (this);
}

IkePayload::~IkePayload ()
{
	NS_LOG_FUNCTION (this);
	this->DeletePayloadSubstructure();
}

uint32_t
IkePayload::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	if (0 == this->m_ptr_substructure)
	{
		NS_ASSERT (false);
	}

	return this->m_header.GetSerializedSize() + this->m_ptr_substructure->GetSerializedSize();
}

TypeId
IkePayload::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkePayload::GetTypeId();
}

void
IkePayload::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	this->m_header.Serialize(i);
	i.Next(this->m_header.GetSerializedSize());

	if (0 == this->m_ptr_substructure)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_substructure->Serialize(i);
	i.Next(this->m_ptr_substructure->GetSerializedSize());
}

uint32_t
IkePayload::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);

	Buffer::Iterator i = start;
	uint32_t size = 0;

	this->m_header.Deserialize(i);
	i.Next(this->m_header.GetSerializedSize());
	size += this->m_header.GetSerializedSize();

	uint16_t total_length = this->m_header.GetPayloadLength();
	uint16_t length_rest = total_length - this->m_header.GetSerializedSize();

	if (0 == this->m_ptr_substructure)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_substructure->Deserialize(i, length_rest);
	i.Next(this->m_ptr_substructure->GetSerializedSize());
	size += this->m_ptr_substructure->GetSerializedSize();

	NS_ASSERT (size == total_length);

	return size;
}

void
IkePayload::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "IkePayload: " << this << std::endl;
	this->m_header.Print(os);

	if (0 == this->m_ptr_substructure)
	{
		NS_ASSERT (false);
	}

	this->m_ptr_substructure->Print(os);
}

bool
IkePayload::IsInitialized (void) const
{
	NS_LOG_FUNCTION (this);

	if (0 == this->m_ptr_substructure)
	{
		NS_ASSERT (false);
	}

	return (this->m_ptr_substructure->GetInstanceTypeId() != IkePayloadSubstructure::GetTypeId());
}

IkePayloadHeader::PAYLOAD_TYPE
IkePayload::GetPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_substructure->GetPayloadType();
}

IkePayloadHeader::PAYLOAD_TYPE
IkePayload::GetNextPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_header.GetNextPayloadType();
}

const IkePayloadSubstructure*
IkePayload::GetSubstructure (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ptr_substructure;
}

const std::list<IkeSAProposal>&
IkePayload::GetSAProposals (void) const
{
	NS_LOG_FUNCTION (this);

	if (this->GetPayloadType() != IkePayloadHeader::SECURITY_ASSOCIATION)
	{
		NS_ASSERT (false);
	}

	IkeSAPayloadSubstructure* ptr_derived = dynamic_cast<IkeSAPayloadSubstructure*>(this->m_ptr_substructure);

	return ptr_derived->GetProposals();
}

const std::list<IkeTrafficSelector>&
IkePayload::GetTrafficSelectors (void) const
{
	NS_LOG_FUNCTION (this);

	if ((this->GetPayloadType() != IkePayloadHeader::TRAFFIC_SELECTOR_INITIATOR) &&
			(this->GetPayloadType() != IkePayloadHeader::TRAFFIC_SELECTOR_RESPONDER))
	{
		NS_ASSERT (false);
	}

	IkeTrafficSelectorSubstructure* ptr_derived = dynamic_cast<IkeTrafficSelectorSubstructure*>(this->m_ptr_substructure);

	return ptr_derived->GetTrafficSelectors();
}

Ipv4Address
IkePayload::GetIpv4AddressId (void) const
{
	if (this->GetPayloadType() != IkePayloadHeader::IDENTIFICATION_INITIATOR)
	{
		NS_ASSERT (false);
	}

	IkeIdSubstructure* ptr_derived = dynamic_cast<IkeIdSubstructure*>(this->m_ptr_substructure);

	return ptr_derived->GetIpv4AddressFromData();
}

//void
//IkePayload::SetPayload (IkePayloadSubstructure substructure)
//{
//	NS_LOG_FUNCTION (this);
//	//sealed
//	NS_ASSERT (false);
////	this->m_ptr_substructure = substructure;
////	this->m_header.SetPayloadLength(substructure.GetSerializedSize() + this->m_header.GetSerializedSize());
//}

void
IkePayload::SetPayload (IkePayloadSubstructure* substructure)
{
	NS_LOG_FUNCTION (this);

	this->DeletePayloadSubstructure();

	this->m_ptr_substructure = substructure;
	this->m_header.SetPayloadLength(this->m_ptr_substructure->GetSerializedSize() + this->m_header.GetSerializedSize());
}

void
IkePayload::SetNextPayloadType (IkePayloadHeader::PAYLOAD_TYPE payload_type)
{
	NS_LOG_FUNCTION (this);
	this->m_header.SetNextPayloadType(payload_type);
}

void
IkePayload::PushBackProposal (IkeSAProposal proposal)
{
	NS_LOG_FUNCTION (this);
	if (this->GetPayloadType() != IkePayloadHeader::SECURITY_ASSOCIATION)
	{
		NS_ASSERT (false);
	}
	IkeSAPayloadSubstructure* ptr_derived = dynamic_cast<IkeSAPayloadSubstructure*>(this->m_ptr_substructure);
	ptr_derived->PushBackProposal(proposal);
}
void
IkePayload::PushBackProposals (const std::list<IkeSAProposal>& proposals)
{
	NS_LOG_FUNCTION (this);
	if (this->GetPayloadType() != IkePayloadHeader::SECURITY_ASSOCIATION)
	{
		NS_ASSERT (false);
	}
	IkeSAPayloadSubstructure* ptr_derived = dynamic_cast<IkeSAPayloadSubstructure*>(this->m_ptr_substructure);
	ptr_derived->PushBackProposals(proposals);
}

void
IkePayload::PushBackTrafficSelector (IkeTrafficSelector ts)
{
	NS_LOG_FUNCTION (this);

		if ((this->GetPayloadType() != IkePayloadHeader::TRAFFIC_SELECTOR_INITIATOR) &&
				(this->GetPayloadType() != IkePayloadHeader::TRAFFIC_SELECTOR_RESPONDER))
		{
			NS_ASSERT (false);
		}

		IkeTrafficSelectorSubstructure* ptr_derived = dynamic_cast<IkeTrafficSelectorSubstructure*>(this->m_ptr_substructure);
		ptr_derived->PushBackTrafficSelector(ts);
}

void
IkePayload::PushBackTrafficSelectors (const std::list<IkeTrafficSelector>& tss)
{
	NS_LOG_FUNCTION (this);

		if ((this->GetPayloadType() != IkePayloadHeader::TRAFFIC_SELECTOR_INITIATOR) &&
				(this->GetPayloadType() != IkePayloadHeader::TRAFFIC_SELECTOR_RESPONDER))
		{
			NS_ASSERT (false);
		}

		IkeTrafficSelectorSubstructure* ptr_derived = dynamic_cast<IkeTrafficSelectorSubstructure*>(this->m_ptr_substructure);
		ptr_derived->PushBackTrafficSelectors(tss);
}

IkePayload
IkePayload::GetEmptyPayloadFromPayloadType (IkePayloadHeader::PAYLOAD_TYPE payload_type)
{
	IkePayload retval;
	IkePayloadSubstructure* ptr_substructure = NULL;
	switch (payload_type)
	{
	case IkePayloadHeader::SECURITY_ASSOCIATION:
		retval.SetPayload(new IkeSAPayloadSubstructure());
		break;
	case IkePayloadHeader::KEY_EXCHANGE:
	retval.SetPayload(new IkeKeyExchangeSubStructure());
	break;
	case IkePayloadHeader::IDENTIFICATION_INITIATOR:
		retval.SetPayload(new IkeIdSubstructure());
		break;
	case IkePayloadHeader::IDENTIFICATION_RESPONDER:
		ptr_substructure = new IkeIdSubstructure();
		dynamic_cast<IkeIdSubstructure*>(ptr_substructure)->SetResponder();
		retval.SetPayload(ptr_substructure);
		break;
	case IkePayloadHeader::CERTIFICATE:
		//not implemented
		NS_ASSERT (false);
		break;
	case IkePayloadHeader::CERTIFICATE_REQUEST:
		//not implemented
		NS_ASSERT (false);
		break;
	case IkePayloadHeader::AUTHENTICATION:
		//not implemented
		retval.SetPayload(new IkeAuthSubstructure());
		break;
	case IkePayloadHeader::NONCE:
		//not implemented
		retval.SetPayload(new IkeNonceSubstructure());
		break;
	case IkePayloadHeader::NOTIFY:
		//not implemented
		retval.SetPayload(new IkeNotifySubstructure());
		break;
	case IkePayloadHeader::DELETE:
		//not implemented
		retval.SetPayload(new IkeDeletePayloadSubstructure());
		break;
	case IkePayloadHeader::VENDOR_ID:
		//not implemented
		NS_ASSERT (false);
		break;
	case IkePayloadHeader::TRAFFIC_SELECTOR_INITIATOR:
		retval.SetPayload(new IkeTrafficSelectorSubstructure());
		break;
	case IkePayloadHeader::TRAFFIC_SELECTOR_RESPONDER:
		ptr_substructure = new IkeTrafficSelectorSubstructure();
		dynamic_cast<IkeTrafficSelectorSubstructure*>(ptr_substructure)->SetResponder();
		retval.SetPayload(ptr_substructure);
		break;
	case IkePayloadHeader::ENCRYPTED_AND_AUTHENTICATED:
		//not implemented
		retval.SetPayload(new IkeEncryptedPayloadSubstructure());
		break;
	case IkePayloadHeader::CONFIGURATION:
		//not implemented
		retval.SetPayload(new IkeConfigPayloadSubstructure());
		break;
	case IkePayloadHeader::EXTENSIBLE_AUTHENTICATION:
		//not implemented
		NS_ASSERT (false);
		break;
	default:
		NS_ASSERT (false);
		break;
	}

	return retval;
}

void
IkePayload::DeletePayloadSubstructure (void)
{
	NS_LOG_FUNCTION (this);

	if (0 != this->m_ptr_substructure)
	{
		delete m_ptr_substructure;
	}
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
  :  m_flag_TLV (false),
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
	if (true == this->m_flag_TLV)
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
	size += sizeof (af_attribute_type);

	this->m_attribute_length_or_value = (af_attribute_type & 0xfffe) >> 1;
	if (0 == (af_attribute_type & 0x0001))
	{
		this->m_flag_TLV = true;
	}
	else
	{
		this->m_flag_TLV = false;
	}

	this->m_attribute_length_or_value = i.ReadNtohU16();
	size += sizeof (this->m_attribute_length_or_value);

	if (true == this->m_flag_TLV)
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

uint16_t
IkeTransformAttribute::GetAttributeType (void)
{
	NS_LOG_FUNCTION (this);

	return this->m_attribute_type;
}

void
IkeTransformAttribute::SetAttributeType (uint16_t type)
{
	NS_LOG_FUNCTION (this);

	this->m_attribute_type = type;
}

uint16_t
IkeTransformAttribute::GetAttributeValue (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_flag_TLV == true)
	{
		NS_ASSERT (false);
	}

	return this->m_attribute_length_or_value;
}
void
IkeTransformAttribute::SetAttributeValue (uint16_t value)
{
	NS_LOG_FUNCTION (this);

	if (this->m_flag_TLV == true)
	{
		NS_ASSERT (false);
	}

	if (value >= 0x8fff)	//larger than 2^15
	{
		NS_ASSERT (false);
	}

	this->m_attribute_length_or_value = value;
}

/********************************************************
 *        IkeTransform
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeTransformSubStructure);

TypeId
IkeTransformSubStructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeTransformSubStructure")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeTransformSubStructure> ();
	  return tid;
}

IkeTransformSubStructure::IkeTransformSubStructure ()
  : m_flag_last (false),
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

	i.WriteU8(this->m_flag_last);

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
	size += sizeof (field_last);

	if (0 == field_last)
	{
		this->m_flag_last = true;
	}
	else if (3 == field_last)
	{
		this->m_flag_last = false;
	}
	else
	{
		NS_ASSERT (false);
	}

	//to check whehter field RESERVED is 0
	uint8_t RESERVED1 = i.ReadU8();
	NS_ASSERT (RESERVED1 == 0);
	size ++;

	this->m_transform_length = i.ReadNtohU16();
	size += sizeof (this->m_transform_length);

	this->m_transform_type = i.ReadU8();
	size += sizeof (this->m_transform_type);

	//to check whehter field RESERVED is 0
	uint16_t RESERVED2 = i.ReadU8();
	NS_ASSERT (RESERVED2 == 0);
	size++;

	this->m_transform_id = i.ReadNtohU16();
	size += sizeof (this->m_transform_id);

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

	this->m_flag_last = true;
}

void
IkeTransformSubStructure::ClearLast (void)
{
	NS_LOG_FUNCTION (this);

	this->m_flag_last = false;
}

void
IkeTransformSubStructure::SetTransformType (IkeTransformSubStructure::TRANSFORM_TYPE transform_type)
{
	NS_LOG_FUNCTION (this);

	this->m_transform_type = transform_type;
}

void
IkeTransformSubStructure::SetTransformId (IkeTransformSubStructure::GENERIC_TRANSFORM_ID transform_id)
{
	NS_LOG_FUNCTION (this);

	this->m_transform_id = transform_id;
}

bool
IkeTransformSubStructure::IsLast (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_flag_last;
}

IkeTransformSubStructure
IkeTransformSubStructure::GetEmptyTransform (void)
{
	IkeTransformSubStructure retval;

	retval.SetLength(8);
	retval.SetTransformType(IkeTransformSubStructure::NO_TRANSFORM);
	retval.SetTransformId(IkeTransformSubStructure::NO_ID);
	return retval;
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
  :  m_flag_last (false),
	 m_gsa_type (IkeSAProposal::UNINITIALIZED),
	 m_proposal_length (12),	//12 bytes until filed SPI. increase by adding more transform
	 m_proposal_num (0),
	 m_protocol_id (0),
	 m_spi_size (4),	//ah or esp
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

	if (true == this->m_flag_last)
	{
		i.WriteU8(0);
	}
	else if (false == this->m_flag_last)
	{
		i.WriteU8(2);
	}
	else
	{
		NS_ASSERT (false);
	}



	uint16_t proposal_length = 0;
	proposal_length += 8;	//fields before SPI and Transforms
	proposal_length += this->m_spi.GetSerializedSize();
	for (	std::list<IkeTransformSubStructure>::const_iterator const_it = this->m_lst_transforms.begin();
			const_it != this->m_lst_transforms.end();
			const_it++)
	{
		proposal_length += const_it->GetSerializedSize();
	}

	//to write the RESERVED field and optional GSA type filed
	if (this->m_gsa_type == IkeSAProposal::UNINITIALIZED)
	{
		i.WriteU8(0);
	}
	else if (this->m_gsa_type == IkeSAProposal::GSA_Q)
	{
		i.WriteU8(1);
	}
	else if (this->m_gsa_type == IkeSAProposal::GSA_R)
	{
		i.WriteU8(2);
	}
	else
	{
		NS_ASSERT (false);
	}

	i.WriteHtolsbU16(proposal_length);

	i.WriteU8(this->m_proposal_num);

	i.WriteU8(this->m_protocol_id);

	i.WriteU8(this->m_spi.GetSerializedSize());

	i.WriteU8(this->m_lst_transforms.size());

	this->m_spi.Serialize(i);
	i.Next(this->m_spi.GetSerializedSize());

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
	size += sizeof (field_last);

	if (0 == field_last)
	{
		this->m_flag_last = true;
	}
	else if (2 == field_last)
	{
		this->m_flag_last = false;
	}
	else
	{
		NS_ASSERT (false);
	}

	//read first RESERVED or optional GSA type field
	uint8_t reserved_gsa_type = i.ReadU8();
	if (reserved_gsa_type == 0)
	{
		this->m_gsa_type = IkeSAProposal::UNINITIALIZED;
	}
	else if (reserved_gsa_type == 1)
	{
		this->m_gsa_type = IkeSAProposal::GSA_Q;
	}
	else if (reserved_gsa_type == 2)
	{
		this->m_gsa_type = IkeSAProposal::GSA_R;
	}
	else
	{
		NS_ASSERT (false);
	}
	size++;

	this->m_proposal_length = i.ReadNtohU16();
	size += sizeof (this->m_proposal_length);

	this->m_proposal_num = i.ReadU8();
	size += sizeof (this->m_proposal_num);

	this->m_protocol_id = i.ReadU8();
	size += sizeof (this->m_protocol_id);

	this->m_spi_size = i.ReadU8();

	size += sizeof (this->m_spi_size);

	this->m_num_transforms = i.ReadU8();
	size += sizeof (this->m_num_transforms);

	this->m_spi.Deserialize(i, this->m_spi_size);
	size += this->m_spi.GetSerializedSize();

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

void
IkeSAProposal::SetLast (void)
{
	NS_LOG_FUNCTION (this);
	this->m_flag_last = true;
}

void
IkeSAProposal::ClearLast (void)
{
	NS_LOG_FUNCTION (this);
	this->m_flag_last = false;
}

void
IkeSAProposal::SetProposalNumber (uint8_t proposal_num)
{
	NS_LOG_FUNCTION (this);
	this->m_proposal_num = proposal_num;
}

void
IkeSAProposal::SetProtocolId (IPsec::SA_Proposal_PROTOCOL_ID protocol_id)
{
	NS_LOG_FUNCTION (this);
	this->m_protocol_id = protocol_id;
}

void
IkeSAProposal::SetSPI (Spi spi)
{
	NS_LOG_FUNCTION (this);
	this->m_spi = spi;
	this->m_spi_size = this->m_spi.GetSerializedSize();
}

void
IkeSAProposal::PushBackTransform (IkeTransformSubStructure transform)
{
	NS_LOG_FUNCTION (this);

	this->ClearLastTranform();

	this->m_lst_transforms.push_back(transform);
	this->m_num_transforms++;
	this->m_proposal_length += transform.GetSerializedSize();

	this->SetLastTransform();
}

void
IkeSAProposal::SetAsGsaQ (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_gsa_type != IkeSAProposal::UNINITIALIZED)
	{
		NS_ASSERT (false);
	}

	this->m_gsa_type = IkeSAProposal::GSA_Q;
}

void
IkeSAProposal::SetAsGsaR (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_gsa_type != IkeSAProposal::UNINITIALIZED)
	{
		NS_ASSERT (false);
	}

	this->m_gsa_type = IkeSAProposal::GSA_R;
}

void
IkeSAProposal::SetGsaType (IkeSAProposal::GSA_TYPE gsa_type)
{
	NS_LOG_FUNCTION (this);
	this->m_gsa_type = gsa_type;
}

bool
IkeSAProposal::IsLast (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_flag_last;
}

Spi
IkeSAProposal::GetSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_spi;
}

bool
IkeSAProposal::IsGsa (void) const
{
	NS_LOG_FUNCTION (this);
	bool retval = true;

	if (this->m_gsa_type == IkeSAProposal::UNINITIALIZED)
	{
		retval = false;
	}

	return retval;
}

bool
IkeSAProposal::IsGsaQ (void) const
{
	NS_LOG_FUNCTION (this);
	bool retval = false;

	if (this->m_gsa_type == IkeSAProposal::GSA_Q)
	{
		retval = true;
	}

	return retval;
}

bool
IkeSAProposal::IsGsaR (void) const
{
	NS_LOG_FUNCTION (this);
	bool retval = false;

	if (this->m_gsa_type == IkeSAProposal::GSA_R)
	{
		retval = true;
	}

	return retval;
}

uint8_t
IkeSAProposal::GetSPISizeByProtocolId (IPsec::SA_Proposal_PROTOCOL_ID protocol_id)
{
	NS_LOG_FUNCTION (this);

	uint8_t size = 0;

	switch (protocol_id) {
	case IPsec::IKE:
		size = 8;	//8 bytes
		break;
	case IPsec::AH:
		size = 4;
		break;
	case IPsec::ESP:
		size = 4;
		break;
	default:
		NS_ASSERT(false);
	}

	return size;
}

void
IkeSAProposal::SetLastTransform (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_lst_transforms.begin() != this->m_lst_transforms.end())
	{
		this->m_lst_transforms.back().SetLast();
	}
}

void
IkeSAProposal::ClearLastTranform (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_lst_transforms.begin() != this->m_lst_transforms.end())
	{
		this->m_lst_transforms.back().ClearLast();
	}
}

IkeSAProposal
IkeSAProposal::GenerateInitIkeProposal ()
{
	IkeSAProposal retval;
	//set ike
	retval.SetProtocolId(IPsec::IKE);
	//no need to set spi, set transform
	IkeTransformSubStructure transform  = IkeTransformSubStructure::GetEmptyTransform();
	retval.PushBackTransform(transform);
	retval.SetLastTransform();
	return retval;
}

IkeSAProposal
IkeSAProposal::GenerateAuthIkeProposal (Spi spi)
{
	IkeSAProposal retval;
	//set ike
	retval.SetProtocolId(IPsec::IKE);
	//set spi
	retval.SetSPI(spi);
	//set trasform
	IkeTransformSubStructure transform  = IkeTransformSubStructure::GetEmptyTransform();
	retval.PushBackTransform(transform);
	retval.SetLastTransform();
	return retval;
}

IkeSAProposal
IkeSAProposal::GenerateGsaProposal (Spi spi, IkeSAProposal::GSA_TYPE gsa_type)
{
	IkeSAProposal retval;
	retval.SetProtocolId(GsamConfig::GetDefaultGSAProposalId());
	retval.SetGsaType(gsa_type);
	retval.SetSPI(spi);
	return retval;
}

/********************************************************
 *        IkeSAPayload
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeSAPayloadSubstructure);

TypeId
IkeSAPayloadSubstructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeSAPayload")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeSAPayloadSubstructure> ();
	  return tid;
}

IkeSAPayloadSubstructure::IkeSAPayloadSubstructure ()
{
	NS_LOG_FUNCTION (this);
}

IkeSAPayloadSubstructure::~IkeSAPayloadSubstructure ()
{
	NS_LOG_FUNCTION (this);
}

uint32_t
IkeSAPayloadSubstructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t size = 0;

	for (	std::list<IkeSAProposal>::const_iterator const_it = this->m_lst_proposal.begin();
			const_it != this->m_lst_proposal.end();
			const_it++)
	{
		size += const_it->GetSerializedSize();
	}

	return size;
}

TypeId
IkeSAPayloadSubstructure::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);

	return IkeSAPayloadSubstructure::GetTypeId();
}

void
IkeSAPayloadSubstructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	for (	std::list<IkeSAProposal>::const_iterator const_it = this->m_lst_proposal.begin();
			const_it != this->m_lst_proposal.end();
			const_it++)
	{
		const_it->Serialize(i);
		i.Next(const_it->GetSerializedSize());
	}
}

uint32_t
IkeSAPayloadSubstructure::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;
	uint32_t size = 0;

	uint16_t length_rest = this->m_length;

	while (length_rest > 0)
	{
		IkeSAProposal proposal;
		proposal.Deserialize(i);
		size += proposal.GetSerializedSize();
		length_rest -= proposal.GetSerializedSize();
		this->m_lst_proposal.push_back(proposal);

		if (length_rest == 0)
		{
			if (true != proposal.IsLast())
			{
				NS_ASSERT (false);
			}
		}
	}

	NS_ASSERT (size == this->m_length);

	return size;
}

void
IkeSAPayloadSubstructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);

	IkePayloadSubstructure::Print(os);

	os << "IkeSAPayloadSubstructure: " << this << std::endl;
}

IkeSAPayloadSubstructure*
IkeSAPayloadSubstructure::GenerateInitIkeProposal (void)
{
	IkeSAPayloadSubstructure* retval = new IkeSAPayloadSubstructure();
	retval->PushBackProposal(IkeSAProposal::GenerateInitIkeProposal());
	retval->SetLastProposal();
	retval->SetProposalNum();
	return retval;
}

IkeSAPayloadSubstructure*
IkeSAPayloadSubstructure::GenerateAuthIkeProposal (Spi spi)
{
	IkeSAPayloadSubstructure* retval = new IkeSAPayloadSubstructure();
	retval->PushBackProposal(IkeSAProposal::GenerateAuthIkeProposal(spi));
	retval->SetLastProposal();
	retval->SetProposalNum();
	return retval;
}

IkeSAPayloadSubstructure*
IkeSAPayloadSubstructure::GenerateGsaProposals (Spi spi_gsa_q, Spi spi_gsa_r)
{
	IkeSAPayloadSubstructure* retval = new IkeSAPayloadSubstructure();

	retval->PushBackProposal(IkeSAProposal::GenerateGsaProposal(spi_gsa_q, IkeSAProposal::GSA_Q));
	retval->PushBackProposal(IkeSAProposal::GenerateGsaProposal(spi_gsa_r, IkeSAProposal::GSA_R));

	retval->SetLastProposal();
	retval->SetProposalNum();
	return retval;
}

void
IkeSAPayloadSubstructure::PushBackProposal (IkeSAProposal proposal)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_proposal.push_back(proposal);
	this->m_length += proposal.GetSerializedSize();
}

void
IkeSAPayloadSubstructure::PushBackProposals (const std::list<IkeSAProposal>& proposals)
{
	NS_LOG_FUNCTION (this);
	for (	std::list<IkeSAProposal>::const_iterator const_it = proposals.begin();
			const_it != proposals.end();
			const_it++)
	{
		this->m_lst_proposal.push_back(*const_it);
	}
}

const std::list<IkeSAProposal>&
IkeSAPayloadSubstructure::GetProposals (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_lst_proposal;
}

IkePayloadHeader::PAYLOAD_TYPE
IkeSAPayloadSubstructure::GetPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	return IkePayloadHeader::SECURITY_ASSOCIATION;
}

void
IkeSAPayloadSubstructure::SetLastProposal (void)
{
	NS_LOG_FUNCTION (this);
	if (this->m_lst_proposal.begin() != this->m_lst_proposal.end())
	{
		this->m_lst_proposal.back().SetLast();
	}
}

void
IkeSAPayloadSubstructure::ClearLastProposal (void)
{
	NS_LOG_FUNCTION (this);
	if (this->m_lst_proposal.begin() != this->m_lst_proposal.end())
	{
		this->m_lst_proposal.back().ClearLast();
	}
}

void
IkeSAPayloadSubstructure::SetProposalNum (void)
{
	NS_LOG_FUNCTION (this);
	uint8_t proposal_num = 1;
	for (	std::list<IkeSAProposal>::iterator it = this->m_lst_proposal.begin();
			it != this->m_lst_proposal.end();
			it++)
	{
		it->SetProposalNumber(proposal_num);
		proposal_num++;
	}
}

/********************************************************
 *        IkeKeyExchangeSubStructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeKeyExchangeSubStructure);

TypeId
IkeKeyExchangeSubStructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeKeyExchangeSubStructure")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeKeyExchangeSubStructure> ();
	  return tid;
}

IkeKeyExchangeSubStructure::IkeKeyExchangeSubStructure ()
  :  m_dh_group_num (0)
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

TypeId
IkeKeyExchangeSubStructure::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeKeyExchangeSubStructure::GetTypeId();
}

void
IkeKeyExchangeSubStructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteHtonU16(this->m_dh_group_num);

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
	size += sizeof (this->m_dh_group_num);

	//to check whether field RESERVED is 0
	uint16_t reserved = i.ReadNtohU16();
	size += 2;
	NS_ASSERT (reserved == 0);

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
	IkePayloadSubstructure::Print(os);
	os << "IkeKeyExchangeSubStructure: " << this << std::endl;
}

IkeKeyExchangeSubStructure*
IkeKeyExchangeSubStructure::GetDummySubstructure (void)
{
	IkeKeyExchangeSubStructure* substructure = new IkeKeyExchangeSubStructure();
	substructure->m_dh_group_num = IkeKeyExchangeSubStructure::DH_32_BIT_MODP;
	substructure->SetLength(4);

	uint32_t rand_num = rand();
	uint32_t rand_odd = 0;
	if ((rand_num % 2) == 0)
	{
		if (rand_num == 0)
		{
			rand_odd = 1;
		}
		else
		{
			rand_odd = rand_num - 1;
		}
	}
	else
	{
		rand_odd = rand_num;
	}

	uint32_t mask = 0x000000ff;

	uint8_t bits_to_shift = 0;

	for (	uint8_t it = 1;
			it <= 4;
			it++)
	{
		uint8_t temp = 0;
		mask = mask << bits_to_shift;
		temp = ((rand_odd & mask) >> bits_to_shift);
		substructure->m_lst_data.push_back(temp);

		bits_to_shift += 8;
	}
	return substructure;
}

IkePayloadHeader::PAYLOAD_TYPE
IkeKeyExchangeSubStructure::GetPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	return IkePayloadHeader::KEY_EXCHANGE;
}

/********************************************************
 *        IkeIdSubstructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeIdSubstructure);

TypeId
IkeIdSubstructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeIdSubstructure")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeIdSubstructure> ();
	  return tid;
}

IkeIdSubstructure::IkeIdSubstructure ()
  : m_id_type (0),
	m_flag_initiator_responder (false)
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

TypeId
IkeIdSubstructure::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeIdSubstructure::GetTypeId();
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
	size += sizeof (this->m_id_type);

	//to check whether the field RESERVED is 0
	uint8_t RESERVED1 = i.ReadU8();
	NS_ASSERT (RESERVED1 == 0);
	uint16_t RESERVED2 = i.ReadNtohU16();
	NS_ASSERT (RESERVED2 == 0);
	size += 3;

	uint16_t length_rest = this->m_length - size;

	for (	uint16_t it = 1;
			it <= length_rest;
			it++)
	{
		this->m_lst_id_data.push_back(i.ReadU8());
		size++;
	}

	NS_ASSERT (size == this->m_length);

	return size;
}

void
IkeIdSubstructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	IkePayloadSubstructure::Print(os);
	os << "IkeIdSubstructure: " << this << std::endl;
}

void
IkeIdSubstructure::SetIpv4AddressData (Ipv4Address address)
{
	NS_LOG_FUNCTION (this);

	if (this->m_id_type != 0)
	{
		NS_ASSERT (false);
	}

	this->m_id_type = IkeIdSubstructure::ID_IPV4_ADDR;

	GsamUtility::Uint32ToBytes(this->m_lst_id_data, address.Get());
}

void
IkeIdSubstructure::SetResponder (void)
{
	NS_LOG_FUNCTION (this);
	this->m_flag_initiator_responder = true;
}

Ipv4Address
IkeIdSubstructure::GetIpv4AddressFromData (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t value = GsamUtility::BytesToUint32(this->m_lst_id_data);

	return Ipv4Address(value);
}

bool
IkeIdSubstructure::IsResponder (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_flag_initiator_responder;
}

IkePayloadHeader::PAYLOAD_TYPE
IkeIdSubstructure::GetPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	IkePayloadHeader::PAYLOAD_TYPE retval = IkePayloadHeader::IDENTIFICATION_INITIATOR;
	if (true == this->IsResponder())
	{
		retval = IkePayloadHeader::IDENTIFICATION_RESPONDER;
	}
	return retval;
}

IkeIdSubstructure*
IkeIdSubstructure::GenerateIpv4Substructure (Ipv4Address address, bool is_responder)
{
	IkeIdSubstructure* retval = new IkeIdSubstructure();

	retval->SetIpv4AddressData(address);
	if (true == is_responder)
	{
		retval->SetResponder();
	}
	retval->m_length = 8;

	return retval;
}

/********************************************************
 *        IkeAuthSubstructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeAuthSubstructure);

TypeId
IkeAuthSubstructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeAuthSubstructure")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkePayloadSubstructure> ();
	  return tid;
}

IkeAuthSubstructure::IkeAuthSubstructure ()
  : m_auth_method (IkeAuthSubstructure::EMPTY)
{
	NS_LOG_FUNCTION (this);
}

IkeAuthSubstructure::~IkeAuthSubstructure ()
{
	NS_LOG_FUNCTION (this);
	m_lst_id_data.clear();
}

uint8_t
IkeAuthSubstructure::AuthMethodToUint8 (IkeAuthSubstructure::AUTH_METHOD auth_method)
{
	uint8_t retval = 0;

	switch (auth_method)
	{
	case IkeAuthSubstructure::EMPTY:
		retval = 0;
		break;
	case IkeAuthSubstructure::RSA_DIGITAL_SIGNATURE:
		retval = 1;
		break;
	case IkeAuthSubstructure::SHARED_KEY_MESSAGE_INTEGRITY_CODE:
		retval = 2;
		break;
	case IkeAuthSubstructure::DSS_DIGITAL_SIGNATURE:
		retval = 3;
		break;
	default:
		retval = 0;
		NS_ASSERT (false);
	}
	return retval;
}
IkeAuthSubstructure::AUTH_METHOD
IkeAuthSubstructure::Uint8ToAuthMethod (uint8_t value)
{
	IkeAuthSubstructure::AUTH_METHOD retval = IkeAuthSubstructure::EMPTY;

	switch (value)
	{
	case 0:
		retval = IkeAuthSubstructure::EMPTY;
		break;
	case 1:
		retval = IkeAuthSubstructure::RSA_DIGITAL_SIGNATURE;
		break;
	case 2:
		retval = IkeAuthSubstructure::SHARED_KEY_MESSAGE_INTEGRITY_CODE;
		break;
	case 3:
		retval = IkeAuthSubstructure::DSS_DIGITAL_SIGNATURE;
		break;
	default:
		NS_ASSERT (false);
	}
	return retval;
}

uint32_t
IkeAuthSubstructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	return 4 + this->m_lst_id_data.size();
}

TypeId
IkeAuthSubstructure::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeAuthSubstructure::GetTypeId();
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
	size += sizeof (this->m_auth_method);

	//to check whehter 24bits field RESERVED is 0
	uint8_t RESERVED1 = i.ReadU8();
	NS_ASSERT (RESERVED1 == 0);
	uint16_t RESERVED2 = i.ReadNtohU16();
	NS_ASSERT (RESERVED2 == 0);
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
	IkePayloadSubstructure::Print(os);
	os << "IkeIdSubstructure: " << this << std::endl;
}

IkePayloadHeader::PAYLOAD_TYPE
IkeAuthSubstructure::GetPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	return IkePayloadHeader::AUTHENTICATION;
}

IkeAuthSubstructure*
IkeAuthSubstructure::GenerateEmptyAuthSubstructure (void)
{
	IkeAuthSubstructure* retval = new IkeAuthSubstructure();
	retval->m_auth_method = IkeAuthSubstructure::EMPTY;
	retval->m_length = 4;
	return retval;
}

/********************************************************
 *        IkeNonceSubstructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeNonceSubstructure);

TypeId
IkeNonceSubstructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeNonceSubstructure")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeNonceSubstructure> ();
	  return tid;
}

IkeNonceSubstructure::IkeNonceSubstructure ()
{
	NS_LOG_FUNCTION (this);
}

IkeNonceSubstructure::~IkeNonceSubstructure ()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_nonce_data.clear();
}

uint32_t
IkeNonceSubstructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	return this->m_lst_nonce_data.size();
}

TypeId
IkeNonceSubstructure::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeNonceSubstructure::GetTypeId();
}

void
IkeNonceSubstructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	for (	std::list<uint8_t>::const_iterator const_it = this->m_lst_nonce_data.begin();
			const_it != this->m_lst_nonce_data.end();
			const_it++)
	{
		i.WriteU8((*const_it));
	}
}

uint32_t
IkeNonceSubstructure::Deserialize (Buffer::Iterator start)
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

	uint16_t length_rest = this->m_length - size;

	for (	uint16_t it = 1;
			it <= length_rest;
			it++)
	{
		this->m_lst_nonce_data.push_back(i.ReadU8());
		size++;
	}

	NS_ASSERT (size == this->m_length);

	return size;
}

void
IkeNonceSubstructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	IkePayloadSubstructure::Print(os);
	os << "IkeNonceSubstructure: " << this << std::endl;
}

IkePayloadHeader::PAYLOAD_TYPE
IkeNonceSubstructure::GetPayloadType (void)
{
	NS_LOG_FUNCTION (this);

	return IkePayloadHeader::NONCE;
}

IkeNonceSubstructure*
IkeNonceSubstructure::GenerateNonceSubstructure (void)
{
	IkeNonceSubstructure* nonce = new IkeNonceSubstructure();

	//uint16_t length = rand();
	uint16_t length = 4;	//fix length 4
	nonce->SetLength(length);

	for (	uint16_t it = 1;
			it <= length;
			it++)
	{
		uint8_t data = rand();
		nonce->m_lst_nonce_data.push_back(data);
	}

	return nonce;
}

/********************************************************
 *        IkeNotifySubstructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeNotifySubstructure);

TypeId
IkeNotifySubstructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeNotifySubstructure")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeNotifySubstructure> ();
	  return tid;
}

IkeNotifySubstructure::IkeNotifySubstructure ()
  :  m_protocol_id (0),
	 m_spi_size (0),
	 m_notify_message_type (0)
{
	NS_LOG_FUNCTION (this);
}

IkeNotifySubstructure::~IkeNotifySubstructure ()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_notification_data.clear();
}

uint32_t
IkeNotifySubstructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t size = 0;

	size += this->m_lst_notification_data.size();

	return size;
}

TypeId
IkeNotifySubstructure::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeNotifySubstructure::GetTypeId();
}

void
IkeNotifySubstructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteU8(this->m_protocol_id);

	i.WriteU8(this->m_spi.GetSerializedSize());

	i.WriteHtonU16(this->m_notify_message_type);

	this->m_spi.Serialize(i);
	i.Next(this->m_spi.GetSerializedSize());

	for (	std::list<uint8_t>::const_iterator const_it = this->m_lst_notification_data.begin();
			const_it != this->m_lst_notification_data.end();
			const_it++)
	{
		i.WriteU8((*const_it));
	}
}

uint32_t
IkeNotifySubstructure::Deserialize (Buffer::Iterator start)
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

	this->m_protocol_id = i.ReadU8();
	size += sizeof (this->m_protocol_id);

	this->m_spi_size = i.ReadU8();
	size += sizeof (this->m_spi_size);

	this->m_notify_message_type = i.ReadNtohU16();
	size += sizeof (this->m_notify_message_type);

	this->m_spi.Deserialize(i, this->m_spi_size);
	i.Next(this->m_spi.GetSerializedSize());

	uint16_t length_rest = this->m_length - size;
	for (	uint16_t it = 1;
			it <= length_rest;
			it++)
	{
		this->m_lst_notification_data.push_back(i.ReadU8());
		size++;
	}

	NS_ASSERT (size == this->m_length);

	return size;
}

void
IkeNotifySubstructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	IkePayloadSubstructure::Print(os);
	os << "IkeNotifySubstructure: " << this << std::endl;
}

uint8_t
IkeNotifySubstructure::GetNotifyMessageType (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_notify_message_type;
}

Spi
IkeNotifySubstructure::GetSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_spi;
}

IkePayloadHeader::PAYLOAD_TYPE
IkeNotifySubstructure::GetPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	return IkePayloadHeader::NOTIFY;
}

IkeNotifySubstructure*
IkeNotifySubstructure::GenerateGsaQNotification (Spi spi)
{
	IkeNotifySubstructure* retval = new IkeNotifySubstructure();
	retval->m_protocol_id = IPsec::AH;
	retval->m_spi = spi;
	retval->m_notify_message_type = IkeNotifySubstructure::GSA_Q_SPI_NOTIFICATION;
	return retval;
}

IkeNotifySubstructure*
IkeNotifySubstructure::GenerateGsaRNotification (Spi spi)
{
	IkeNotifySubstructure* retval = new IkeNotifySubstructure();
	retval->m_protocol_id = IPsec::AH;
	retval->m_spi = spi;
	retval->m_notify_message_type = IkeNotifySubstructure::GSA_R_SPI_NOTIFICATION;
	return retval;
}

IkeNotifySubstructure*
IkeNotifySubstructure::GenerateGsaAcknowledgedment (void)
{
	IkeNotifySubstructure* retval = new IkeNotifySubstructure();
	retval->m_protocol_id = IPsec::AH;
	retval->m_notify_message_type = IkeNotifySubstructure::GSA_ACKNOWLEDGEDMENT;
	return retval;
}

/********************************************************
 *        IkeDeletePayloadSubstructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeDeletePayloadSubstructure);

TypeId
IkeDeletePayloadSubstructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeDeletePayloadSubstructure")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeDeletePayloadSubstructure> ();
	  return tid;
}

IkeDeletePayloadSubstructure::IkeDeletePayloadSubstructure ()
  :  m_protocol_id (0),
	 m_spi_size (0),
	 m_num_of_spis (0)
{
	NS_LOG_FUNCTION (this);
}

IkeDeletePayloadSubstructure::~IkeDeletePayloadSubstructure ()
{
	NS_LOG_FUNCTION (this);
}

uint32_t
IkeDeletePayloadSubstructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t size = 0;

	size += sizeof (this->m_protocol_id);
	size += sizeof (this->m_spi_size);
	size += sizeof (this->m_num_of_spis);

	for (	std::list<Spi>::const_iterator const_it = this->m_lst_spis.begin();
			const_it != this->m_lst_spis.end();
			const_it++)
	{
		size += const_it->GetSerializedSize();
	}

	return size;
}

TypeId
IkeDeletePayloadSubstructure::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeDeletePayloadSubstructure::GetTypeId();
}

void
IkeDeletePayloadSubstructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteU8(this->m_protocol_id);

	i.WriteU8(this->m_spi_size);

	i.WriteHtonU16(this->m_num_of_spis);

	for (	std::list<Spi>::const_iterator const_it = this->m_lst_spis.begin();
			const_it != this->m_lst_spis.end();
			const_it++)
	{
		const_it->Serialize(i);
		i.Next(const_it->GetSerializedSize());
	}
}

uint32_t
IkeDeletePayloadSubstructure::Deserialize (Buffer::Iterator start)
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

	this->m_protocol_id = i.ReadU8();
	size += sizeof (this->m_protocol_id);

	this->m_spi_size = i.ReadU8();
	size += sizeof(this->m_spi_size);

	this->m_num_of_spis = i.ReadNtohU16();
	size += sizeof (this->m_num_of_spis);

	for (	uint16_t it = 1;
			it <= this->m_num_of_spis;
			it++)
	{
		Spi spi;
		spi.Deserialize(i, m_spi_size);
		i.Next(spi.GetSerializedSize());
		this->m_lst_spis.push_back(spi);
		size += spi.GetSerializedSize();
	}

	NS_ASSERT (size == this->m_length);

	return size;
}

void
IkeDeletePayloadSubstructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	IkePayloadSubstructure::Print(os);
	os << "IkeDeletePayloadSubstructure: " << this << std::endl;
}

IkePayloadHeader::PAYLOAD_TYPE
IkeDeletePayloadSubstructure::GetPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	return IkePayloadHeader::DELETE;
}

/********************************************************
 *        IkeTrafficSelector
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeTrafficSelector);

TypeId
IkeTrafficSelector::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeTrafficSelector")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeTrafficSelector> ();
	  return tid;
}

IkeTrafficSelector::IkeTrafficSelector ()
  : m_ts_type (0),
	m_ip_protocol_id (0),
	m_selector_length (16),	//16 bytes
	m_start_port (0),
	m_end_port (0)
{
	NS_LOG_FUNCTION (this);
}

IkeTrafficSelector::~IkeTrafficSelector ()
{
	NS_LOG_FUNCTION (this);
}

uint32_t
IkeTrafficSelector::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);
	uint32_t size = 0;

	size += sizeof (this->m_ts_type);

	size += sizeof (this->m_ip_protocol_id);

	size += sizeof (this->m_selector_length);

	size += sizeof (this->m_start_port);

	size += sizeof (this->m_end_port);

	size += sizeof (this->m_starting_address.Get());

	size += sizeof (this->m_ending_address.Get());

	return size;
}

TypeId
IkeTrafficSelector::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeTrafficSelector::GetTypeId();
}

void
IkeTrafficSelector::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteU8(this->m_ts_type);

	i.WriteU8(this->m_ip_protocol_id);

	i.WriteHtonU16(this->m_selector_length);

	i.WriteHtonU16(this->m_start_port);

	i.WriteHtonU16(this->m_end_port);

	i.WriteHtonU32(this->m_starting_address.Get());

	i.WriteHtonU32(this->m_ending_address.Get());
}

uint32_t
IkeTrafficSelector::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	uint32_t size = 0;

	this->m_ts_type = i.ReadU8();
	size += sizeof (this->m_ts_type);

	this->m_ip_protocol_id = i.ReadU8();
	size += sizeof (this->m_ip_protocol_id);

	this->m_selector_length = i.ReadNtohU16();
	size += sizeof (this->m_selector_length);

	this->m_start_port = i.ReadNtohU16();
	size += sizeof (this->m_start_port);

	this->m_end_port = i.ReadNtohU16();
	size += sizeof (this->m_end_port);

	this->m_starting_address = Ipv4Address (i.ReadNtohU32());
	size += sizeof (this->m_starting_address.Get());

	this->m_ending_address = Ipv4Address (i.ReadNtohU32());
	size += sizeof (this->m_ending_address.Get());

	NS_ASSERT (size == this->m_selector_length);

	return size;

}

void
IkeTrafficSelector::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "IkeTrafficSelector: " << this << std::endl;
}

uint8_t
IkeTrafficSelector::GetTsType (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ts_type;
}

uint8_t
IkeTrafficSelector::GetProtocolId (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ip_protocol_id;
}

uint16_t
IkeTrafficSelector::GetStartPort (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_start_port;
}

uint16_t
IkeTrafficSelector::GetEndPort (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_end_port;
}

Ipv4Address
IkeTrafficSelector::GetStartingAddress (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_starting_address;
}

Ipv4Address
IkeTrafficSelector::GetEndingAddress (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_ending_address;
}

IkeTrafficSelector
IkeTrafficSelector::GenerateDefaultSigmpTs(void)
{
	IkeTrafficSelector retval;
	retval.m_ts_type = IkeTrafficSelector::TS_IPV4_ADDR_RANGE;
	retval.m_ip_protocol_id = IpSecPolicyEntry::IGMP;
	retval.m_start_port = 0;
	retval.m_end_port = 0;
	retval.m_starting_address = GsamConfig::GetSecGrpAddressStart();
	retval.m_ending_address = GsamConfig::GetSecGrpAddressEnd();

	//header = 4; 2 ports = 4; 2 ipv4 address = 8
	retval.m_selector_length = 16;	//16 bytes

	return retval;

}

IkeTrafficSelector
IkeTrafficSelector::GenerateDestSecureGroupTs(Ipv4Address grpup_adress)
{
	IkeTrafficSelector retval;
	retval.m_ts_type = IkeTrafficSelector::TS_IPV4_ADDR_RANGE;
	retval.m_ip_protocol_id = GsamConfig::GetDefaultIpsecProtocolId();
	retval.m_start_port = 0;
	retval.m_end_port = 0;
	retval.m_starting_address = grpup_adress;
	retval.m_ending_address = grpup_adress;

	//header = 4; 2 ports = 4; 2 ipv4 address = 8
	retval.m_selector_length = 16;	//16 bytes

	return retval;

}

/********************************************************
 *        IkeTrafficSelectorSubstructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeTrafficSelectorSubstructure);

TypeId
IkeTrafficSelectorSubstructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeTrafficSelectorSubstructure")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeTrafficSelectorSubstructure> ();
	  return tid;
}

IkeTrafficSelectorSubstructure::IkeTrafficSelectorSubstructure ()
  :  m_num_of_tss (0),
	 m_flag_initiator_responder (false)
{
	NS_LOG_FUNCTION (this);
}

IkeTrafficSelectorSubstructure::~IkeTrafficSelectorSubstructure ()
{
	NS_LOG_FUNCTION (this);
	m_lst_traffic_selectors.clear();
}

uint32_t
IkeTrafficSelectorSubstructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t size = 0;

	size += sizeof (this->m_num_of_tss);

	//24 bits field RESERVED
	size += 3;

	for (	std::list<IkeTrafficSelector>::const_iterator const_it = this->m_lst_traffic_selectors.begin();
			const_it != this->m_lst_traffic_selectors.end();
			const_it++)
	{
		size += const_it->GetSerializedSize();
	}

	return size;
}

TypeId
IkeTrafficSelectorSubstructure::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeTrafficSelectorSubstructure::GetTypeId();
}

void
IkeTrafficSelectorSubstructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteU8(this->m_lst_traffic_selectors.size());

	//24 bits field RESERVED
	i.WriteU8(0, 3);

	for (	std::list<IkeTrafficSelector>::const_iterator const_it = this->m_lst_traffic_selectors.begin();
			const_it != this->m_lst_traffic_selectors.end();
			const_it++)
	{
		const_it->Serialize(i);
		i.Next(const_it->GetSerializedSize());
	}
}

uint32_t
IkeTrafficSelectorSubstructure::Deserialize (Buffer::Iterator start)
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

	this->m_num_of_tss = i.ReadU8();
	size += sizeof (this->m_num_of_tss);

	//to check whehter 24bits field RESERVED is 0
	uint8_t RESERVED1 = i.ReadU8();
	NS_ASSERT (RESERVED1 == 0);
	uint16_t RESERVED2 = i.ReadNtohU16();
	NS_ASSERT (RESERVED2 == 0);
	size += 3;

	while (size < this->m_length)
	{
		IkeTrafficSelector selector;
		uint32_t selector_size = selector.Deserialize(i);
		this->m_lst_traffic_selectors.push_back(selector);
		i.Next(selector_size);
		size += selector_size;
	}

	NS_ASSERT (size == this->m_length);

	return size;
}

void
IkeTrafficSelectorSubstructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	IkePayloadSubstructure::Print(os);
	os << "IkeTrafficSelectorSubstructure: " << this << std::endl;
}

IkeTrafficSelectorSubstructure*
IkeTrafficSelectorSubstructure::GenerateEmptySubstructure (bool is_responder)
{
	IkeTrafficSelectorSubstructure* retval = new IkeTrafficSelectorSubstructure();

	if (true == is_responder)
	{
		retval->SetResponder();
	}

	return retval;
}

IkeTrafficSelectorSubstructure*
IkeTrafficSelectorSubstructure::GetSecureGroupSubstructure (Ipv4Address group_address, bool is_responder)
{
	IkeTrafficSelectorSubstructure* retval = new IkeTrafficSelectorSubstructure();

	retval->m_num_of_tss = 1;
	retval->m_lst_traffic_selectors.push_back(IkeTrafficSelector::GenerateDestSecureGroupTs(group_address));
	retval->m_length = 4;

	for (	std::list<IkeTrafficSelector>::const_iterator const_it = retval->m_lst_traffic_selectors.begin();
			const_it != retval->m_lst_traffic_selectors.end();
			const_it++)
	{
		retval->m_length += const_it->GetSerializedSize();
	}

	if (true == is_responder)
	{
		retval->SetResponder();
	}

	return retval;
}

IkeTrafficSelectorSubstructure*
IkeTrafficSelectorSubstructure::GenerateDefaultSubstructure (bool is_responder)
{
	IkeTrafficSelectorSubstructure* retval = new IkeTrafficSelectorSubstructure();

	retval->m_num_of_tss = 1;
	retval->m_lst_traffic_selectors.push_back(IkeTrafficSelector::GenerateDefaultSigmpTs());
	retval->m_length = 4;

	for (	std::list<IkeTrafficSelector>::const_iterator const_it = retval->m_lst_traffic_selectors.begin();
			const_it != retval->m_lst_traffic_selectors.end();
			const_it++)
	{
		retval->m_length += const_it->GetSerializedSize();
	}

	if (true == is_responder)
	{
		retval->SetResponder();
	}

	return retval;
}

void
IkeTrafficSelectorSubstructure::SetResponder (void)
{
	NS_LOG_FUNCTION (this);
	this->m_flag_initiator_responder = true;
}

bool
IkeTrafficSelectorSubstructure::IsResponder (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_flag_initiator_responder;
}

const std::list<IkeTrafficSelector>&
IkeTrafficSelectorSubstructure::GetTrafficSelectors (void) const
{
	NS_LOG_FUNCTION (this);

	return this->m_lst_traffic_selectors;
}

IkePayloadHeader::PAYLOAD_TYPE
IkeTrafficSelectorSubstructure::GetPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	IkePayloadHeader::PAYLOAD_TYPE retval = IkePayloadHeader::TRAFFIC_SELECTOR_INITIATOR;
	if (true == this->IsResponder())
	{
		retval = IkePayloadHeader::TRAFFIC_SELECTOR_RESPONDER;
	}
	return retval;
}

void
IkeTrafficSelectorSubstructure::PushBackTrafficSelector (IkeTrafficSelector ts)
{
	NS_LOG_FUNCTION (this);
	this->m_lst_traffic_selectors.push_back(ts);
}

void
IkeTrafficSelectorSubstructure::PushBackTrafficSelectors (const std::list<IkeTrafficSelector>& tss)
{
	NS_LOG_FUNCTION (this);
	for (	std::list<IkeTrafficSelector>::const_iterator const_it = tss.begin();
			const_it != tss.end();
			const_it++)
	{
		this->PushBackTrafficSelector(*const_it);
	}
}

/********************************************************
 *        IkeEncryptedPayloadSubstructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeEncryptedPayloadSubstructure);

TypeId
IkeEncryptedPayloadSubstructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeEncryptedPayloadSubstructure")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeEncryptedPayloadSubstructure> ();
	  return tid;
}

IkeEncryptedPayloadSubstructure::IkeEncryptedPayloadSubstructure ()
  :  m_ptr_encrypted_payload (0),
	 m_block_size (0),
	 m_checksum_length (0)
{
	NS_LOG_FUNCTION (this);
}

IkeEncryptedPayloadSubstructure::~IkeEncryptedPayloadSubstructure ()
{
	NS_LOG_FUNCTION (this);
	this->m_initialization_vector.clear();
	//this->m_lst_encrypted_payload.clear();
	this->m_lst_integrity_checksum_data.clear();
	this->DeleteEncryptedPayload ();
}

uint32_t
IkeEncryptedPayloadSubstructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t size = 0;

	size += this->m_lst_integrity_checksum_data.size();

	//size += this->m_lst_encrypted_payload.size();

	if (0 != this->m_ptr_encrypted_payload)
	{
		size += this->m_ptr_encrypted_payload->GetSerializedSize();
	}
	else
	{
		NS_ASSERT (false);
	}

	size += this->m_lst_integrity_checksum_data.size();

	return size;
}

TypeId
IkeEncryptedPayloadSubstructure::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeEncryptedPayloadSubstructure::GetTypeId();
}

void
IkeEncryptedPayloadSubstructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	for (	std::list<uint8_t>::const_iterator const_it = this->m_initialization_vector.begin();
			const_it != this->m_initialization_vector.end();
			const_it++)
	{
		i.WriteU8(*const_it);
	}

//	for (	std::list<uint8_t>::const_iterator const_it = this->m_lst_encrypted_payload.begin();
//			const_it != this->m_lst_encrypted_payload.end();
//			const_it++)
//	{
//		i.WriteU8(*const_it);
//	}

	if (0 != this->m_ptr_encrypted_payload)
	{
		this->m_ptr_encrypted_payload->Serialize(i);
		i.Next(this->m_ptr_encrypted_payload->GetSerializedSize());
	}
	else
	{
		NS_ASSERT (false);
	}

	for (std::list<uint8_t>::const_iterator const_it = this->m_lst_integrity_checksum_data.begin();
			const_it != this->m_lst_integrity_checksum_data.end();
			const_it++)
	{
		i.WriteU8(*const_it);
	}
}

uint32_t
IkeEncryptedPayloadSubstructure::Deserialize (Buffer::Iterator start)
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

	if (0 == this->m_block_size)
	{
		NS_ASSERT (false);
	}
	else
	{
		//do nothing
	}

	if (0 == this->m_checksum_length)
	{
		NS_ASSERT (false);
	}
	else
	{
		//do nothing
	}

	uint32_t size = 0;

	for (	uint8_t it = 1;
			it <= this->m_block_size;
			it++)
	{
		this->m_initialization_vector.push_back(i.ReadU8());
		size++;
	}

//	while ((this->m_length - size) > this->m_checksum_length)
//	{
//		this->m_lst_encrypted_payload.push_back(i.ReadU8());
//		size++;
//	}

	if (0 != this->m_ptr_encrypted_payload)
	{
		this->m_ptr_encrypted_payload->Deserialize(i);
		i.Next(this->m_ptr_encrypted_payload->GetSerializedSize());
	}
	else
	{
		NS_ASSERT (false);
	}

	while (size < this->m_length)
	{
		this->m_lst_integrity_checksum_data.push_back(i.ReadU8());
		size++;
	}

	NS_ASSERT (size == this->m_length);

	return size;
}

void
IkeEncryptedPayloadSubstructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	IkePayloadSubstructure::Print(os);
	os << "IkeEncryptedPayloadSubstructure: " << this << std::endl;
}

void
IkeEncryptedPayloadSubstructure::SetBlockSize (uint8_t block_size)
{
	NS_LOG_FUNCTION (this);
	this->m_block_size = block_size;
}

bool
IkeEncryptedPayloadSubstructure::IsInitialized (void) const
{
	NS_LOG_FUNCTION (this);
	return (this->m_length != 0) && (this->m_block_size != 0) && (this->m_checksum_length != 0);
}

IkePayloadHeader::PAYLOAD_TYPE
IkeEncryptedPayloadSubstructure::GetPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	return IkePayloadHeader::ENCRYPTED_AND_AUTHENTICATED;
}

void
IkeEncryptedPayloadSubstructure::DeleteEncryptedPayload (void)
{
	NS_LOG_FUNCTION (this);
	if (0 != this->m_ptr_encrypted_payload)
	{
		delete m_ptr_encrypted_payload;
	}
}

/********************************************************
 *        IkeConfigAttribute
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeConfigAttribute);

TypeId
IkeConfigAttribute::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeConfigAttribute")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeConfigAttribute> ();
	  return tid;
}

IkeConfigAttribute::IkeConfigAttribute ()
  :  m_attribute_type (0),
	 m_length (0)
{
	NS_LOG_FUNCTION (this);
}

IkeConfigAttribute::~IkeConfigAttribute ()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_value.clear();
}

uint32_t
IkeConfigAttribute::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);
	return (4 + this->m_lst_value.size());
}

TypeId
IkeConfigAttribute::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeConfigAttribute::GetTypeId();
}

void
IkeConfigAttribute::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	if (this->m_attribute_type > 0x7fff)
	{
		NS_ASSERT (false);
	}

	i.WriteHtolsbU16((this->m_attribute_type << 1));	//lowest bit for RESERVED

	i.WriteHtolsbU16(this->m_length);

	for (	std::list<uint8_t>::const_iterator const_it = this->m_lst_value.begin();
			const_it != this->m_lst_value.end();
			const_it++)
	{
		i.WriteU8(*const_it);
	}

}

uint32_t
IkeConfigAttribute::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	uint32_t size = 0;

	uint16_t field_r_attribute_type = i.ReadNtohU16();
	size += 2;

	if (0 != (field_r_attribute_type & 0x0001))
	{
		NS_ASSERT (false);	//R bit must be set to zero
	}

	this->m_attribute_type = (field_r_attribute_type >> 1);

	this->m_length = i.ReadNtohU16();
	size += sizeof (this->m_length);

	for (	uint16_t it = 1;
			it <= this->m_length;
			it++)
	{
		this->m_lst_value.push_back(i.ReadU8());
		size++;
	}

	return size;
}

void
IkeConfigAttribute::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);

	os << "IkeConfigAttribute: " << this;
	os << " Type: " << this->m_attribute_type << std::endl;
}

/********************************************************
 *        IkeConfigPayloadSubstructure
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeConfigPayloadSubstructure);

TypeId
IkeConfigPayloadSubstructure::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeConfigPayloadSubstructure")
	    .SetParent<IkePayloadSubstructure> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeConfigPayloadSubstructure> ();
	  return tid;
}

IkeConfigPayloadSubstructure::IkeConfigPayloadSubstructure ()
  :  m_cfg_type (0)
{
	NS_LOG_FUNCTION (this);
}

IkeConfigPayloadSubstructure::~IkeConfigPayloadSubstructure ()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_config_attributes.clear();
}

uint32_t
IkeConfigPayloadSubstructure::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t size = 0;

	size += 4;

	size += this->m_lst_config_attributes.size();

	return size;
}

TypeId
IkeConfigPayloadSubstructure::GetInstanceTypeId (void) const
{
	NS_LOG_FUNCTION (this);
	return IkeConfigPayloadSubstructure::GetTypeId();
}

void
IkeConfigPayloadSubstructure::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	i.WriteU8(this->m_cfg_type);

	//to write 24bits RESERVED field
	i.WriteU8(0, 3);

	for (	std::list<IkeConfigAttribute>::const_iterator const_it = this->m_lst_config_attributes.begin();
			const_it != this->m_lst_config_attributes.end();
			const_it++)
	{
		const_it->Serialize(i);
		i.Next(const_it->GetSerializedSize());
	}
}

uint32_t
IkeConfigPayloadSubstructure::Deserialize (Buffer::Iterator start)
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

	this->m_cfg_type = i.ReadU8();

	//to check whether the field RESERVED is 0
	uint8_t RESERVED1 = i.ReadU8();
	NS_ASSERT (RESERVED1 == 0);
	uint16_t RESERVED2 = i.ReadNtohU16();
	NS_ASSERT (RESERVED2 == 0);
	size += 3;

	while (size < this->m_length)
	{
		IkeConfigAttribute attribute;
		attribute.Serialize(i);
		uint32_t attribute_size = attribute.GetSerializedSize();
		i.Next(attribute_size);
		size += attribute_size;
	}

	NS_ASSERT (size == this->m_length);

	return size;
}

void
IkeConfigPayloadSubstructure::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	IkePayloadSubstructure::Print(os);
	os << "IkeConfigPayloadSubstructure: " << this << std::endl;
}

IkePayloadHeader::PAYLOAD_TYPE
IkeConfigPayloadSubstructure::GetPayloadType (void) const
{
	NS_LOG_FUNCTION (this);
	return IkePayloadHeader::CONFIGURATION;
}

/********************************************************
 *        IkeGSAProposal
 ********************************************************/

NS_OBJECT_ENSURE_REGISTERED (IkeGSAProposal);

TypeId
IkeGSAProposal::GetTypeId (void)
{
	static TypeId tid = TypeId ("ns3::IkeGSAProposal")
	    .SetParent<Header> ()
	    //.SetGroupName("Internet")
		.AddConstructor<IkeGSAProposal> ();
	  return tid;
}

IkeGSAProposal::IkeGSAProposal ()
  :  m_flag_last (false),
	 m_gsa_type (IkeGSAProposal::UNINITIALIZED),
	 m_proposal_length (12),	//12 bytes until filed SPI. increase by adding more transform
	 m_proposal_num (0),
	 m_protocol_id (0),
	 m_spi_size (4),	//ah or esp
	 m_num_transforms (0)
{
	NS_LOG_FUNCTION (this);
}

IkeGSAProposal::~IkeGSAProposal ()
{
	NS_LOG_FUNCTION (this);
	this->m_lst_transforms.clear();
}

uint32_t
IkeGSAProposal::GetSerializedSize (void) const
{
	NS_LOG_FUNCTION (this);

	uint32_t size = 0;

	size += 8;
	size += this->m_spi.GetSerializedSize();

	size += this->m_src_ts.GetSerializedSize();
	size += this->m_dest_ts.GetSerializedSize();

	for (	std::list<IkeTransformSubStructure>::const_iterator const_it = this->m_lst_transforms.begin();
			const_it != this->m_lst_transforms.end();
			const_it++)
	{
		size += const_it->GetSerializedSize();
	}

	return size;
}

TypeId
IkeGSAProposal::GetInstanceTypeId (void) const
{
	return IkeGSAProposal::GetTypeId();
}

void
IkeGSAProposal::Serialize (Buffer::Iterator start) const
{
	NS_LOG_FUNCTION (this << &start);

	Buffer::Iterator i = start;

	if (true == this->m_flag_last)
	{
		i.WriteU8(0);
	}
	else if (false == this->m_flag_last)
	{
		i.WriteU8(2);
	}
	else
	{
		NS_ASSERT (false);
	}

	uint16_t proposal_length = 0;
	proposal_length += 8;	//fields before SPI and Transforms
	proposal_length += this->m_spi.GetSerializedSize();
	for (	std::list<IkeTransformSubStructure>::const_iterator const_it = this->m_lst_transforms.begin();
			const_it != this->m_lst_transforms.end();
			const_it++)
	{
		proposal_length += const_it->GetSerializedSize();
	}

	//to write the RESERVED field and optional GSA type filed
	if (this->m_gsa_type == IkeGSAProposal::UNINITIALIZED)
	{
		i.WriteU8(0);
	}
	else if (this->m_gsa_type == IkeGSAProposal::GSA_Q)
	{
		i.WriteU8(1);
	}
	else if (this->m_gsa_type == IkeGSAProposal::GSA_R)
	{
		i.WriteU8(2);
	}
	else
	{
		NS_ASSERT (false);
	}

	i.WriteHtolsbU16(proposal_length);

	i.WriteU8(this->m_proposal_num);

	i.WriteU8(this->m_protocol_id);

	i.WriteU8(this->m_spi.GetSerializedSize());

	i.WriteU8(this->m_lst_transforms.size());

	this->m_spi.Serialize(i);
	i.Next(this->m_spi.GetSerializedSize());

	this->m_src_ts.Serialize(i);
	i.Next(this->m_src_ts.GetSerializedSize());

	this->m_dest_ts.Serialize(i);
	i.Next(this->m_dest_ts.GetSerializedSize());

	for (	std::list<IkeTransformSubStructure>::const_iterator const_it = this->m_lst_transforms.begin();
			const_it != this->m_lst_transforms.end();
			const_it++)
	{
		const_it->Serialize(i);
		i.Next(const_it->GetSerializedSize());
	}
}

uint32_t
IkeGSAProposal::Deserialize (Buffer::Iterator start)
{
	NS_LOG_FUNCTION (this << &start);
	Buffer::Iterator i = start;

	uint32_t size = 0;

	uint8_t field_last = i.ReadU8();
	size += sizeof (field_last);

	if (0 == field_last)
	{
		this->m_flag_last = true;
	}
	else if (2 == field_last)
	{
		this->m_flag_last = false;
	}
	else
	{
		NS_ASSERT (false);
	}

	//read first RESERVED or optional GSA type field
	uint8_t reserved_gsa_type = i.ReadU8();
	if (reserved_gsa_type == 0)
	{
		this->m_gsa_type = IkeGSAProposal::UNINITIALIZED;
	}
	else if (reserved_gsa_type == 1)
	{
		this->m_gsa_type = IkeGSAProposal::GSA_Q;
	}
	else if (reserved_gsa_type == 2)
	{
		this->m_gsa_type = IkeGSAProposal::GSA_R;
	}
	else
	{
		NS_ASSERT (false);
	}
	size++;

	this->m_proposal_length = i.ReadNtohU16();
	size += sizeof (this->m_proposal_length);

	this->m_proposal_num = i.ReadU8();
	size += sizeof (this->m_proposal_num);

	this->m_protocol_id = i.ReadU8();
	size += sizeof (this->m_protocol_id);

	this->m_spi_size = i.ReadU8();

	size += sizeof (this->m_spi_size);

	this->m_num_transforms = i.ReadU8();
	size += sizeof (this->m_num_transforms);

	this->m_spi.Deserialize(i, this->m_spi_size);
	uint32_t spi_serializedsize = this->m_spi.GetSerializedSize();
	i.Next(spi_serializedsize);
	size += spi_serializedsize;

	this->m_src_ts.Deserialize(i);
	uint32_t src_ts_serializedsize = this->m_src_ts.GetSerializedSize();
	i.Next(src_ts_serializedsize);
	size += src_ts_serializedsize;

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
IkeGSAProposal::Print (std::ostream &os) const
{
	NS_LOG_FUNCTION (this << &os);
	os << "IkeGSAProposal: " << this << std::endl;
}

void
IkeGSAProposal::SetLast (void)
{
	NS_LOG_FUNCTION (this);
	this->m_flag_last = true;
}

void
IkeGSAProposal::ClearLast (void)
{
	NS_LOG_FUNCTION (this);
	this->m_flag_last = false;
}

void
IkeGSAProposal::SetProposalNumber (uint8_t proposal_num)
{
	NS_LOG_FUNCTION (this);
	this->m_proposal_num = proposal_num;
}

void
IkeGSAProposal::SetProtocolId (IPsec::SA_Proposal_PROTOCOL_ID protocol_id)
{
	NS_LOG_FUNCTION (this);
	this->m_protocol_id = protocol_id;
}

void
IkeGSAProposal::SetSPI (Spi spi)
{
	NS_LOG_FUNCTION (this);
	this->m_spi = spi;
	this->m_spi_size = this->m_spi.GetSerializedSize();
}

void
IkeGSAProposal::PushBackTransform (IkeTransformSubStructure transform)
{
	NS_LOG_FUNCTION (this);

	this->ClearLastTranform();

	this->m_lst_transforms.push_back(transform);
	this->m_num_transforms++;
	this->m_proposal_length += transform.GetSerializedSize();

	this->SetLastTransform();
}

void
IkeGSAProposal::SetAsGsaQ (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_gsa_type != IkeGSAProposal::UNINITIALIZED)
	{
		NS_ASSERT (false);
	}

	this->m_gsa_type = IkeGSAProposal::GSA_Q;
}

void
IkeGSAProposal::SetAsGsaR (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_gsa_type != IkeGSAProposal::UNINITIALIZED)
	{
		NS_ASSERT (false);
	}

	this->m_gsa_type = IkeGSAProposal::GSA_R;
}

void
IkeGSAProposal::SetGsaType (IkeGSAProposal::GSA_TYPE gsa_type)
{
	NS_LOG_FUNCTION (this);
	this->m_gsa_type = gsa_type;
}

bool
IkeGSAProposal::IsLast (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_flag_last;
}

Spi
IkeGSAProposal::GetSpi (void) const
{
	NS_LOG_FUNCTION (this);
	return this->m_spi;
}

bool
IkeGSAProposal::IsGsa (void) const
{
	NS_LOG_FUNCTION (this);
	bool retval = true;

	if (this->m_gsa_type == IkeGSAProposal::UNINITIALIZED)
	{
		retval = false;
	}

	return retval;
}

bool
IkeGSAProposal::IsGsaQ (void) const
{
	NS_LOG_FUNCTION (this);
	bool retval = false;

	if (this->m_gsa_type == IkeGSAProposal::GSA_Q)
	{
		retval = true;
	}

	return retval;
}

bool
IkeGSAProposal::IsGsaR (void) const
{
	NS_LOG_FUNCTION (this);
	bool retval = false;

	if (this->m_gsa_type == IkeGSAProposal::GSA_R)
	{
		retval = true;
	}

	return retval;
}

uint8_t
IkeGSAProposal::GetSPISizeByProtocolId (IPsec::SA_Proposal_PROTOCOL_ID protocol_id)
{
	NS_LOG_FUNCTION (this);

	uint8_t size = 0;

	switch (protocol_id) {
	case IPsec::IKE:
		size = 8;	//8 bytes
		break;
	case IPsec::AH:
		size = 4;
		break;
	case IPsec::ESP:
		size = 4;
		break;
	default:
		NS_ASSERT(false);
	}

	return size;
}

void
IkeGSAProposal::SetLastTransform (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_lst_transforms.begin() != this->m_lst_transforms.end())
	{
		this->m_lst_transforms.back().SetLast();
	}
}

void
IkeGSAProposal::ClearLastTranform (void)
{
	NS_LOG_FUNCTION (this);

	if (this->m_lst_transforms.begin() != this->m_lst_transforms.end())
	{
		this->m_lst_transforms.back().ClearLast();
	}
}

IkeGSAProposal
IkeGSAProposal::GenerateInitIkeProposal ()
{
	IkeGSAProposal retval;
	//set ike
	retval.SetProtocolId(IPsec::IKE);
	//no need to set spi, set transform
	IkeTransformSubStructure transform  = IkeTransformSubStructure::GetEmptyTransform();
	retval.PushBackTransform(transform);
	retval.SetLastTransform();
	return retval;
}

IkeGSAProposal
IkeGSAProposal::GenerateAuthIkeProposal (Spi spi)
{
	IkeGSAProposal retval;
	//set ike
	retval.SetProtocolId(IPsec::IKE);
	//set spi
	retval.SetSPI(spi);
	//set trasform
	IkeTransformSubStructure transform  = IkeTransformSubStructure::GetEmptyTransform();
	retval.PushBackTransform(transform);
	retval.SetLastTransform();
	return retval;
}

IkeGSAProposal
IkeGSAProposal::GenerateGsaProposal (Spi spi, IkeGSAProposal::GSA_TYPE gsa_type)
{
	IkeGSAProposal retval;
	retval.SetProtocolId(GsamConfig::GetDefaultGSAProposalId());
	retval.SetGsaType(gsa_type);
	retval.SetSPI(spi);
	return retval;
}

}  // namespace ns3
