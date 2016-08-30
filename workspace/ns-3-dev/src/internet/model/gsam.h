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

#ifndef GSAM_H
#define GSAM_H

#include <stdint.h>
#include "ns3/header.h"
#include "ns3/trailer.h"
#include "ns3/ipv4-address.h"
#include <list>
#include "ns3/object.h"

namespace ns3 {

class GsamInfo;
class Spi;
class IkeSaProposal;
class IkeTrafficSelector;
class IkeGsaProposal;

class IPsec {
public:
	enum SA_Proposal_PROTOCOL_ID {
		RESERVED = 0,
		IKE = 1,
		AH = 2,
		ESP = 3
	};

	enum MODE {
		NONE = 0,
		TRANSPORT = 1,
		TUNNEL = 2
	};

	enum SPI_SIZE {
		IKE_SPI_SIZE = 8,
		AH_ESP_SPI_SIZE = 4
	};

	enum PROCESS_CHOICE {
		DISCARD = 0,
		BYPASS = 1,
		PROTECT = 2
	};
};

class IkePayloadHeader : public Header {
	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Next Payload  |C|  RESERVED   |         Payload Length        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
public:	//Header override
	static TypeId GetTypeId (void);
	IkePayloadHeader ();
	virtual ~IkePayloadHeader ();

	enum PAYLOAD_TYPE {
		NO_NEXT_PAYLOAD = 0,
		SECURITY_ASSOCIATION = 33,
		KEY_EXCHANGE = 34,
		IDENTIFICATION_INITIATOR = 35,
		IDENTIFICATION_RESPONDER = 36,
		CERTIFICATE = 37,
		CERTIFICATE_REQUEST = 38,
		AUTHENTICATION = 39,
		NONCE = 40,
		NOTIFY = 41,
		DELETE = 42,
		VENDOR_ID = 43,
		TRAFFIC_SELECTOR_INITIATOR = 44,
		TRAFFIC_SELECTOR_RESPONDER = 45,
		ENCRYPTED_AND_AUTHENTICATED = 46,
		CONFIGURATION = 47,
		EXTENSIBLE_AUTHENTICATION = 48,
		//added by Lin Chen, GSA type
		GROUP_SECURITY_ASSOCIATION = 49,
		GROUP_NOTIFY = 50
	};
public:	//translate enum
	static uint8_t PayloadTypeToUnit8 (IkePayloadHeader::PAYLOAD_TYPE payload_type);
	static IkePayloadHeader::PAYLOAD_TYPE Uint8ToPayloadType (uint8_t value);
public:	//Header override
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;
public:	//const
	uint16_t GetPayloadLength (void) const;
	IkePayloadHeader::PAYLOAD_TYPE GetNextPayloadType (void) const;
public:	//non-const
	void SetNextPayloadType (IkePayloadHeader::PAYLOAD_TYPE payload_type);
	void SetPayloadLength (uint16_t length);
private:
	IkePayloadHeader::PAYLOAD_TYPE m_next_payload;
	bool m_flag_critical;
	uint16_t m_payload_length;
};

class IkeHeader : public Header {

/*
 * IKE Header format, rfc 5996
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       IKE SA Initiator's SPI                  |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       IKE SA Responder's SPI                  |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Message ID                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                            Length                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

public:	//Header override
	static TypeId GetTypeId (void);
	IkeHeader ();
	virtual ~IkeHeader ();

	enum EXCHANGE_TYPE {
		NONE = 0,
		IKE_SA_INIT = 34,
		IKE_AUTH = 35,
		CREATE_CHILD_SA = 36,
		INFORMATIONAL = 37
	};

public:	//static
	static uint8_t ExchangeTypeToUint8 (IkeHeader::EXCHANGE_TYPE exchange_type);
	static IkeHeader::EXCHANGE_TYPE Uint8ToExchangeType (uint8_t value);
public:	//Header override
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;
public:
	void SetIkev2Version (void);
	void SetInitiatorSpi (uint64_t spi);
	uint64_t GetInitiatorSpi (void) const;
	void SetResponderSpi (uint64_t spi);
	uint64_t GetResponderSpi (void) const;
	void SetNextPayloadType (IkePayloadHeader::PAYLOAD_TYPE payload_type);
	IkePayloadHeader::PAYLOAD_TYPE GetNextPayloadType (void) const;
	void SetExchangeType (IkeHeader::EXCHANGE_TYPE exchange_type);
	IkeHeader::EXCHANGE_TYPE GetExchangeType (void) const;
	void SetAsInitiator (void);
	bool IsInitiator (void) const;
	void SetAsResponder (void);
	bool IsResponder (void) const;
	void SetMessageId (uint32_t id);
	uint32_t GetMessageId (void) const;
	void SetLength (uint32_t length);
private:
	uint8_t FlagsToU8 (void) const;
	void U8ToFlags (uint8_t input);
private:
	uint64_t m_initiator_spi;
	uint64_t m_responder_spi;
	IkePayloadHeader::PAYLOAD_TYPE m_next_payload;

	struct Version {
	private:
		uint8_t mjver;	//lowest 4 bits
		uint8_t mnver;	//highest 4 bits
	public:
		Version (uint8_t i) {
			this->mjver = (i & 0x0f);
			this->mnver = (i & 0xf0);
		}
		void set_Mjver (uint8_t i) {
			if (i > 0x0f)
			{
				//larger than 4 bits
				NS_ASSERT (false);
			}
			else
			{
				//smaller than 4 bits
				this->mjver = (i & 0x0f);
			}
		}
		uint8_t get_Mjver (void) const {
			return this->mjver;
		}
		void set_Mnver (uint8_t i) {
			if (i > 0x0f)
			{
				//larger than 4 bits
				NS_ASSERT (false);
			}
			else
			{
				//smaller than 4 bits
				this->mnver = ((i & 0x0f) << 4);
			}
		}
		uint8_t get_Mnver (void) const {
			return ((this->mnver) >> 4);
		}
		uint8_t toUint8_t() const {
			return this->mnver + this->mjver;
		}
		void SetIkev2 (void) {
			set_Mjver (2);
			set_Mnver (0);
		}

	} m_version;

	IkeHeader::EXCHANGE_TYPE m_exchange_type;
	bool m_flag_response;
	bool m_flag_version;
	bool m_flag_initiator;
	uint32_t m_message_id;
	uint32_t m_length;
};

class IkePayloadSubstructure : public Object {
public:
	static TypeId GetTypeId (void);
	IkePayloadSubstructure ();
	virtual ~IkePayloadSubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:
	virtual void SetLength (uint16_t length);
	virtual uint32_t Deserialize (Buffer::Iterator start, uint16_t length);
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
protected:
	uint16_t m_length;	//total substructure length (bytes), for deserialization
};

class Spi : public IkePayloadSubstructure {
public:
	static TypeId GetTypeId (void);
	Spi ();
	explicit Spi (uint32_t spi);
	virtual ~Spi ();
public:	//header override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:	//self-defined
	uint32_t ToUint32 (void) const;
	uint64_t ToUint64 (void) const;
	void SetValueFromUint32 (const uint32_t value);
	void SetValueFromUint64 (const uint64_t value);
	void Copy (Spi spi);
public:
	using IkePayloadSubstructure::Deserialize;
private:
	std::list<uint8_t> m_lst_var;
};

class IkePayload : public Header {

	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Next Payload  |C|  RESERVED   |         Payload Length        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                       SubStructure                       	   ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:
	static TypeId GetTypeId (void);
	IkePayload ();
	virtual ~IkePayload ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:	//const
	bool IsInitialized (void) const;
	IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
	IkePayloadHeader::PAYLOAD_TYPE GetNextPayloadType (void) const;
	const Ptr<IkePayloadSubstructure> GetSubstructure (void) const;
	const std::list<Ptr<IkeSaProposal> >& GetSAProposals (void) const;
	const std::list<IkeTrafficSelector>& GetTrafficSelectors (void) const;
	Ipv4Address GetIpv4AddressId (void) const;
	Ptr<IkePayloadSubstructure> GetPayloadSubstructure (void) const;
	bool HasPayloadSubstructure (void) const;
public:	//non-const
//	void SetPayload (IkePayloadSubstructure substructure);
	void SetSubstructure (Ptr<IkePayloadSubstructure> substructure);
	void SetNextPayloadType (IkePayloadHeader::PAYLOAD_TYPE payload_type);
public:	//static
	/*
	 * For Deserilization Only
	 */
	static IkePayload GetEmptyPayloadFromPayloadType (IkePayloadHeader::PAYLOAD_TYPE payload_type);
private:	//non-const
	void ClearPayloadSubstructure (void);
private:
	IkePayloadHeader m_header;
	Ptr<IkePayloadSubstructure> m_ptr_substructure;
};

class IkeTransformAttribute : public Object {
	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |A|       Attribute Type        |    AF=0  Attribute Length     |
     * |F|                             |    AF=1  Attribute Value      |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                   AF=0  Attribute Value                       |
     * |                   AF=1  Not Transmitted                       |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
public:
	static TypeId GetTypeId (void);
	IkeTransformAttribute ();
	virtual ~IkeTransformAttribute ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:	//self-defined
	uint16_t GetAttributeType (void);
	void SetAttributeType (uint16_t type);
	uint16_t GetAttributeValue (void);
	void SetAttributeValue (uint16_t value);
private:
	bool m_flag_TLV;
	uint16_t m_attribute_type;
	uint16_t m_attribute_length_or_value;
	std::list<uint8_t> m_lst_attribute_value;
};

class IkeTransformSubStructure : public IkePayloadSubstructure {
	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | 0 (last) or 3 |   RESERVED    |        Transform Length       |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |Transform Type |   RESERVED    |          Transform ID         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                      Transform Attributes                     ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
public:
	enum TRANSFORM_TYPE {
		NO_TRANSFORM = 0,
		ENCRYPTION_ALGORITHM = 1,
		PSEUDORANDOM_FUNCTION = 2,
		INTEGRITY_ALGORITHM = 3,
		DIFFIE_HELLMAN_GROUP = 4,
		TYPE_EXTENDED_SEQUENCE_NUMBERS = 5
	};

	enum GENERIC_TRANSFORM_ID {
		NO_ID = 0
	};

	enum TRANSFORM_EA_ID {
		//TYPE 1
		//encryption algorithm
		ENCR_DES_IV64 = 1,
		ENCR_DES = 2,
		ENCR_3DES = 3,
		ENCR_RC5 = 4,
		ENCR_IDEA = 5,
		ENCR_CAST = 6,
		ENCR_BLOWFISH = 7,
		ENCR_3IDEA = 8,
		ENCR_DES_IV32 = 9,
		ENCR_NULL = 11,
		ENCR_AES_CBC = 12,
		ENCR_AES_CTR = 13
	};
	enum TRANSFORM_PF_ID {
		//TYPE 2
		//pseudorandom function
		PRF_HMAC_MD5 = 1,
		PRF_HMAC_SHA1 = 2,
		PRF_HMAC_TIGER = 3
	};
	enum TRANSFORM_IA_ID {
		//TYPE 3
		//integrity algorithm
		NONE_IA_ID = 0,
		AUTH_HMAC_MD5_96 = 1,
		AUTH_HMAC_SHA1_96 = 2,
		AUTH_DES_MAC = 3,
		AUTH_KPDK_MD5 = 4,
		AUTH_AES_XCBC_96 = 5
	};
	enum TRANSFORM_DHG_ID {
		//TYPE 4
		//diffie-hellman group
		NONE_DHG_ID = 0,
		DH_768_BIT_MODP = 1,
		DH_1024_BIT_MODP = 2,
		DH_1536_BIT_MODP = 5,
		DH_2048_BIT_MODP = 14,
		DH_3072_BIT_MODP = 15,
		DH_4096_BIT_MODP = 16,
		DH_6144_BIT_MODP = 17,
		DH_8192_BIT_MODP = 18,
		//dummy test use
		DH_32_BIT_MODP = 19
	};
	enum TRANSFORM_ESN_ID {
		//TYPE 5
		//extended sequence numbers
		NO_EXTENDED_SEQUENCE_NUMBERS = 0,
		EXTENDED_SEQUENCE_NUMBERS = 1
	};

public:
	static TypeId GetTypeId (void);
	IkeTransformSubStructure ();
	virtual ~IkeTransformSubStructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
private:
	void SetTransformType (IkeTransformSubStructure::TRANSFORM_TYPE transform_type);
	void SetTransformId (IkeTransformSubStructure::GENERIC_TRANSFORM_ID transform_id);
public:
	void SetLast (void);
	void ClearLast (void);
public:	//const
	bool IsLast (void) const;
public:	//static
	static IkeTransformSubStructure GetEmptyTransform (void);
private:
	bool m_flag_last;
	uint16_t m_transform_length;
	uint8_t m_transform_type;
	uint8_t m_transform_id;
	std::list<IkeTransformAttribute> m_lst_transform_attributes;
};

class IkeSaProposal : public Object {
	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | 0 (last) or 2 |   RESERVED    |         Proposal Length       |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Proposal Num  |  Protocol ID  |    SPI Size(4)|Num  Transforms|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * ~                        SPI (variable)                         ~
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                        <Transforms>                           ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 */

public:
	static TypeId GetTypeId (void);
	IkeSaProposal ();
	virtual ~IkeSaProposal ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:	//non-const
	void SetLast (void);
	void ClearLast (void);
	void SetProposalNumber (uint8_t proposal_num);
	void SetProtocolId (IPsec::SA_Proposal_PROTOCOL_ID protocol_id);
	void SetSPI (Spi spi);
	void PushBackTransform (IkeTransformSubStructure transform);
public:	//const
	bool IsLast (void) const;
	Spi GetSpi (void) const;
protected:
	uint8_t GetSPISizeByProtocolId (IPsec::SA_Proposal_PROTOCOL_ID protocol_id);
	/*
	 * Iterate the list of transform and set the last one's "field last"
	 */
	void SetLastTransform (void);
	void ClearLastTranform (void);
public:
	static Ptr<IkeSaProposal> GenerateInitIkeProposal ();
	static Ptr<IkeSaProposal> GenerateAuthIkeProposal (Spi spi);
protected:
	bool m_flag_last;
	uint16_t m_proposal_length;	//for deserialization
	uint8_t m_proposal_num;
	uint8_t m_protocol_id;
	Spi m_spi;	//ah or esp or ike
	uint8_t m_spi_size;			//for reading
	uint8_t m_num_transforms;	//for reading
	std::list<IkeTransformSubStructure> m_lst_transforms;
};

class IkeSaPayloadSubstructure : public IkePayloadSubstructure {

	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                          <Proposals>                          ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:
	static TypeId GetTypeId (void);
	IkeSaPayloadSubstructure ();
	virtual ~IkeSaPayloadSubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:	//static
	static Ptr<IkeSaPayloadSubstructure> GenerateInitIkePayload (void);
	static Ptr<IkeSaPayloadSubstructure> GenerateAuthIkePayload (Spi spi);
	static Ptr<IkeSaPayloadSubstructure> GenerateGsaPayload (IkeTrafficSelector ts_src, IkeTrafficSelector ts_dest, Spi spi_gsa_q, Spi spi_gsa_r);
public:	//self-defined
	void PushBackProposal (Ptr<IkeSaProposal> proposal);
	void PushBackProposals (const std::list<Ptr<IkeSaProposal> >& proposals);
public:	//const
	const std::list<Ptr<IkeSaProposal> >& GetProposals (void) const;
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
protected:
	/*
	 * Iterate the list of proposals and set the last one's "field last"
	 */
	void SetLastProposal (void);
	void ClearLastProposal (void);
	/*
	 * Iterate the list of proposals and set proposal number;
	 */
	void SetProposalNum (void);
public:
	using IkePayloadSubstructure::Deserialize;
protected:
	std::list<Ptr<IkeSaProposal> > m_lst_proposal;	//proposals? Since it can be more than one.
};

class IkeGsaPayloadSubstructure : public IkeSaPayloadSubstructure {
	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * ~                          Gsa Push Id                          ~
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * ~                   <Source Traffic Selector>                   ~
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * ~                <Destination Traffic Selector>                 ~
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                          <Proposals>                          ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
public:
	static TypeId GetTypeId (void);
	IkeGsaPayloadSubstructure ();
	virtual ~IkeGsaPayloadSubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:
	using IkePayloadSubstructure::Deserialize;
public:	//static
	static Ptr<IkeGsaPayloadSubstructure> GenerateEmptyGsaPayload (uint32_t gsa_push_id, IkeTrafficSelector ts_src, IkeTrafficSelector ts_dest);
	static Ptr<IkeGsaPayloadSubstructure> GenerateEmptyGsaPayload (uint32_t gsa_push_id, Ipv4Address group_address);
private:
	void SetPushId (uint32_t gsa_push_id);
public:	//const
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
public:
	const IkeTrafficSelector& GetSourceTrafficSelector (void) const;
	const IkeTrafficSelector& GetDestTrafficSelector (void) const;
	uint32_t GetGsaPushId (void) const;
private:
	uint32_t m_gsa_push_id;
	IkeTrafficSelector m_src_ts;
	IkeTrafficSelector m_dest_ts;
};

class IkeKeyExchangeSubStructure : public IkePayloadSubstructure {

	/*
	 *                       1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   Diffie-Hellman Group Num    |           RESERVED            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                       Key Exchange Data                       ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
public:
	enum GROUP_NUM {
		NONE_DHG_ID = 0,
		DH_768_BIT_MODP = 1,
		DH_1024_BIT_MODP = 2,
		DH_1536_BIT_MODP = 5,
		DH_2048_BIT_MODP = 14,
		DH_3072_BIT_MODP = 15,
		DH_4096_BIT_MODP = 16,
		DH_6144_BIT_MODP = 17,
		DH_8192_BIT_MODP = 18,
		//dummy test use
		DH_32_BIT_MODP = 19
	};

public:
	static TypeId GetTypeId (void);
	IkeKeyExchangeSubStructure ();
	virtual ~IkeKeyExchangeSubStructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:
	static Ptr<IkeKeyExchangeSubStructure> GetDummySubstructure (void);
public:
	using IkePayloadSubstructure::Deserialize;
public:	//const
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
private:
	uint16_t m_dh_group_num;
	std::list<uint8_t> m_lst_data;
};

class IkeIdSubstructure : public IkePayloadSubstructure {

	/*
     *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   ID Type     |                 RESERVED                      |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                    Identification Data                        ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	enum ID_TYPE {
		ID_IPV4_ADDR = 1,
		ID_FQDN = 2,
		ID_RFC822_ADDR = 3,
		ID_IPV6_ADDR = 5,
		ID_DER_ASN1_DN = 9,
		ID_DER_ASN1_GN = 10,
		ID_KEY_ID = 11
	};

public:
	static TypeId GetTypeId (void);
	IkeIdSubstructure ();
	virtual ~IkeIdSubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:	//self-defined
	void SetIpv4AddressData (Ipv4Address address);
	/*
	 * Default value is initiator
	 */
	void SetResponder (void);
public:	//const
	Ipv4Address GetIpv4AddressFromData (void) const;
	bool IsResponder (void) const;
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
public:
	using IkePayloadSubstructure::Deserialize;
public:	//static
	static Ptr<IkeIdSubstructure> GenerateIpv4Substructure (Ipv4Address address, bool is_responder);
private:
	uint8_t m_id_type;
	bool m_flag_initiator_responder;	//false for initiator, true for responder
	std::list<uint8_t> m_lst_id_data;
};

class IkeAuthSubstructure : public IkePayloadSubstructure {

	/*
     *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Auth Method   |                RESERVED                       |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                      Authentication Data                      ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	enum AUTH_METHOD {
		EMPTY = 0,
		RSA_DIGITAL_SIGNATURE = 1,
		SHARED_KEY_MESSAGE_INTEGRITY_CODE = 2,
		DSS_DIGITAL_SIGNATURE = 3
	};
public:	//staitc, enum translation
	static uint8_t AuthMethodToUint8 (IkeAuthSubstructure::AUTH_METHOD auth_method);
	static IkeAuthSubstructure::AUTH_METHOD Uint8ToAuthMethod (uint8_t value);
public:
	static TypeId GetTypeId (void);
	IkeAuthSubstructure ();
	virtual ~IkeAuthSubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:
	using IkePayloadSubstructure::Deserialize;
public:	//const
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
public:	//static
	static Ptr<IkeAuthSubstructure> GenerateEmptyAuthSubstructure (void);
private:
	uint8_t m_auth_method;
	std::list<uint8_t> m_lst_id_data;
};

class IkeNonceSubstructure : public IkePayloadSubstructure {

	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                            Nonce Data                         ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:
	static TypeId GetTypeId (void);
	IkeNonceSubstructure ();
	virtual ~IkeNonceSubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:	//override IkePayloadSubstructure
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void);
public:	//static
	static Ptr<IkeNonceSubstructure> GenerateNonceSubstructure (void);
public:
	using IkePayloadSubstructure::Deserialize;
private:
	std::list<uint8_t> m_lst_nonce_data;
};

class IkeNotifySubstructure : public IkePayloadSubstructure {

	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |  Protocol ID  |   SPI Size    |      Notify Message Type      |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                Security Parameter Index (SPI)                 ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                       Notification Data                       ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	enum NOTIFY_MESSAGE_TYPE {
		//error types
		UNSUPPORTED_CRITICAL_PAYLOAD = 1,
		INVALID_IKE_SPI = 4,
		INVALID_MAJOR_VERSION = 5,
		INVALID_SYNTAX = 7,
		INVALID_MESSAGE_ID = 9,
		INVALID_SPI = 11,
		NO_PROPOSAL_CHOSEN = 14,
		INVALID_KE_PAYLOAD = 17,
		AUTHENTICATION_FAILED = 24,
		SINGLE_PAIR_REQUIRED = 34,
		NO_ADDITIONAL_SAS = 35,
		INTERNAL_ADDRESS_FAILURE = 36,
		FAILED_CP_REQUIRED = 37,
		TS_UNACCEPTABLE = 38,
		INVALID_SELECTORS = 39,
		TEMPORARY_FAILURE = 43,
		CHILD_SA_NOT_FOUND = 44,
		//status types
		INITIAL_CONTACT = 16384,
		SET_WINDOW_SIZE = 16385,
		ADDITIONAL_TS_POSSIBLE = 16386,
		IPCOMP_SUPPORTED = 16387,
		NAT_DETECTION_SOURCE_IP = 16388,
		NAT_DETECTION_DESTINATION_IP = 16389,
		COOKIE = 16390,
		USE_TRANSPORT_MODE = 16391,
		HTTP_CERT_LOOKUP_SURRPOTED = 16392,
		REKEY_SA = 16393
	};

public:
	static TypeId GetTypeId (void);
	IkeNotifySubstructure ();
	virtual ~IkeNotifySubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:	//non_const
	void SetSpi (uint32_t spi);
	void SetSpi (Spi spi);
public:	//const
	uint8_t GetNotifyMessageType (void) const;
	Spi GetSpi (void) const;
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
public:
	using IkePayloadSubstructure::Deserialize;
public:	//
	static Ptr<IkeNotifySubstructure> GenerateGsaQNotification (Spi spi);
	static Ptr<IkeNotifySubstructure> GenerateGsaRNotification (Spi spi);
	static Ptr<IkeNotifySubstructure> GenerateGsaAcknowledgedment (void);
private:
	uint8_t m_protocol_id;
	uint8_t m_spi_size;
	uint16_t m_notify_message_type;
	Spi m_spi;	//ah or esp
	std::list<uint8_t> m_lst_notification_data;
};

class IkeDeletePayloadSubstructure : public IkePayloadSubstructure {

	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Protocol ID   |   SPI Size    |          Num of SPIs          |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~               Security Parameter Index(es) (SPI)              ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:
	static TypeId GetTypeId (void);
	IkeDeletePayloadSubstructure ();
	virtual ~IkeDeletePayloadSubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:	//const
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
public:
	using IkePayloadSubstructure::Deserialize;
private:
	uint8_t m_protocol_id;
	uint8_t m_spi_size;
	uint16_t m_num_of_spis;
	std::list<Spi> m_lst_spis;
};

class IkeTrafficSelector : public Object {

	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   TS Type     |IP Protocol ID*|       Selector Length         |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |           Start Port*         |           End Port*           |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                         Starting Address*                     ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                         Ending Address*                       ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 */

	enum TS_TYPE {
		TS_IPV4_ADDR_RANGE = 7,
		TS_IPV6_ADDR_RANGE = 8
	};

public:
	static TypeId GetTypeId (void);
	IkeTrafficSelector ();
	virtual ~IkeTrafficSelector ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:	//non-const
	void SetTsType (IkeTrafficSelector::TS_TYPE ts_type);
	void SetProtocolId (uint8_t protocol_id);
	void SetStartPort (uint16_t start_port);
	void SetEndPort (uint16_t end_port);
	void SetStartingAddress (Ipv4Address starting_address);
	void SetEndingAddress (Ipv4Address ending_address);
public:	//const
	uint8_t GetTsType (void) const;
	uint8_t GetProtocolId (void) const;
	uint16_t GetStartPort (void) const;
	uint16_t GetEndPort (void) const;
	Ipv4Address GetStartingAddress (void) const;
	Ipv4Address GetEndingAddress (void) const;
public:	//static
	static IkeTrafficSelector GenerateDefaultSigmpTs(void);
	static IkeTrafficSelector GenerateSrcSecureGroupTs (void);
	static IkeTrafficSelector GenerateDestSecureGroupTs(Ipv4Address grpup_adress);
public:	//operator
	friend bool operator == (const IkeTrafficSelector& lhs, const IkeTrafficSelector& rhs);
	friend bool operator != (const IkeTrafficSelector& lhs, const IkeTrafficSelector& rhs);
private:
	uint8_t m_ts_type;
	uint8_t m_ip_protocol_id;
	uint16_t m_selector_length;
	uint16_t m_start_port;
	uint16_t m_end_port;
	Ipv4Address m_starting_address;
	Ipv4Address m_ending_address;
};

class IkeTrafficSelectorSubstructure : public IkePayloadSubstructure {

	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Number of TSs |                 RESERVED                      |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                       <Traffic Selectors>                     ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:
	static TypeId GetTypeId (void);
	IkeTrafficSelectorSubstructure ();
	virtual ~IkeTrafficSelectorSubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:
	using IkePayloadSubstructure::Deserialize;
public:	//static
	static Ptr<IkeTrafficSelectorSubstructure> GenerateEmptySubstructure (bool is_responder);
	static Ptr<IkeTrafficSelectorSubstructure> GetSecureGroupSubstructure (Ipv4Address group_address, bool is_responder);
	static Ptr<IkeTrafficSelectorSubstructure> GenerateDefaultSubstructure (bool is_responder);
public:	//non-const
	void SetResponder (void);
public:	//const
	bool IsResponder (void) const;
	const std::list<IkeTrafficSelector>& GetTrafficSelectors (void) const;
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
public:
	void PushBackTrafficSelector (const IkeTrafficSelector& ts);
	void PushBackTrafficSelectors (const std::list<IkeTrafficSelector>& tss);
private:
	uint8_t m_num_of_tss;	//for deserilization
	bool m_flag_initiator_responder;	//false for initiator, ture for responder
	std::list<IkeTrafficSelector> m_lst_traffic_selectors;
};

class IkeEncryptedPayloadSubstructure : public IkePayloadSubstructure {

	/*
	 *                     1                   2                   3
     * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                     Initialization Vector                     |
     * |         (length is block size for encryption algorithm)       |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * ~                    Encrypted IKE Payloads                     ~
     * +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |               |             Padding (0-255 octets)            |
     * +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
     * |                                               |  Pad Length   |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * ~                    Integrity Checksum Data                    ~
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 */

public:
	static TypeId GetTypeId (void);
	IkeEncryptedPayloadSubstructure ();
	virtual ~IkeEncryptedPayloadSubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:
	using IkePayloadSubstructure::Deserialize;
public:
	void SetBlockSize (uint8_t block_size);
private:	//non-const
	void DeleteEncryptedPayload (void);
public:	//const
	bool IsInitialized (void) const;
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
private:
	std::list<uint8_t> m_initialization_vector;
	//std::list<uint8_t> m_lst_encrypted_payload;	//including padding and pad length
	IkePayload* m_ptr_encrypted_payload;
	uint8_t m_block_size;
	uint8_t m_checksum_length;
	std::list<uint8_t> m_lst_integrity_checksum_data;
};

class IkeConfigAttribute : public Object {
	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |R|         Attribute Type      |            Length             |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                             Value                             ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	enum ATTRIBUTE_TYPE {
		INTERNAL_IP4_ADDRESS = 1,
		INTERNAL_IP4_NETMARK = 2,
		INTERNAL_IP4_DNS = 3,
		INTERNAL_IP4_NBNS = 4,
		INTERNAL_IP4_DHCP = 6,
		APPLICATION_VERSION = 7,
		INTERNAL_IP6_ADDRESS = 8,
		INTERNAL_IP6_DNS = 10,
		INTERNAL_IP6_DHCP = 12,
		INTERNAL_IP4_SUBNET = 13,
		SUPPORTED_ATTRIBUTES = 14,
		INTERNAL_IP6_SUBNET = 15
	};

public:
	static TypeId GetTypeId (void);
	IkeConfigAttribute ();
	virtual ~IkeConfigAttribute ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
private:
	uint16_t m_attribute_type;
	uint16_t m_length;
	std::list<uint8_t> m_lst_value;
};

class IkeConfigPayloadSubstructure : public IkePayloadSubstructure {

	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   CFG Type    |                    RESERVED                   |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                   Configuration Attributes                    ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:
	static TypeId GetTypeId (void);
	IkeConfigPayloadSubstructure ();
	virtual ~IkeConfigPayloadSubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:
	using IkePayloadSubstructure::Deserialize;
public:	//const
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
private:
	uint8_t m_cfg_type;
	std::list<IkeConfigAttribute> m_lst_config_attributes;
};

class IkeGsaProposal : public IkeSaProposal {
	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | 0 (last) or 2 |    GSA Type   |         Proposal Length       |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Proposal Num  |  Protocol ID  |    SPI Size(4)|Num  Transforms|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * ~                        SPI (variable)                         ~
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                        <Transforms>                           ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 */
public:
	enum GSA_TYPE {
		UNINITIALIZED = 0,
		GSA_Q = 1,
		GSA_R = 2
	};

public:
	static TypeId GetTypeId (void);
	IkeGsaProposal ();
	virtual ~IkeGsaProposal ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:	//non-const
	void SetAsGsaQ (void);
	void SetAsGsaR (void);
	void SetGsaType (IkeGsaProposal::GSA_TYPE gsa_type);
public:	//const
	bool IsGsaQ (void) const;
	bool IsGsaR (void) const;
public:
	static Ptr<IkeGsaProposal> GenerateGsaProposal (Spi spi, IkeGsaProposal::GSA_TYPE gsa_type);
private:
	IkeGsaProposal::GSA_TYPE m_gsa_type;
};

class IkeGroupNotifySubstructure : public IkePayloadSubstructure {
	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |  Protocol ID  |   SPI Size    |Notify Msg Type|    Num Spi    |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * ~                          Gsa Push Id                          ~
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * ~                   <Source Traffic Selector>                   ~
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * ~                <Destination Traffic Selector>                 ~
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                            SPIs                               ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
public:
	enum NOTIFY_MESSAGE_TYPE {
		NONE = 0,
		GSA_Q_SPI_REJECTION = 1,
		GSA_R_SPI_REJECTION = 2,
		GSA_Q_SPI_NOTIFICATION = 3,
		GSA_R_SPI_NOTIFICATION = 4,
		GSA_ACKNOWLEDGEDMENT = 5,
		SPI_REQUEST = 6
	};
public:
	static TypeId GetTypeId (void);
	IkeGroupNotifySubstructure ();
	virtual ~IkeGroupNotifySubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:	//non_const
	void PushBackSpi (Ptr<Spi> ptr_spi);
	void PushBackSpis (const std::list<Ptr<Spi> >& lst_ptr_spis);
	void PushBackSpis (const std::list<uint32_t>& lst_u32_spis);
public:	//const
	uint8_t GetProtocolId (void) const;
	uint8_t GetSpiSize (void) const;
	uint8_t GetNotifyMessageType (void) const;
	uint32_t GetGsaPushId (void) const;
	const IkeTrafficSelector& GetTrafficSelectorSrc (void) const;
	const IkeTrafficSelector& GetTrafficSelectorDest (void) const;
	const std::list<Ptr<Spi> >& GetSpis (void) const;
	virtual IkePayloadHeader::PAYLOAD_TYPE GetPayloadType (void) const;
public:	//static
	static Ptr<IkeGroupNotifySubstructure> GenerateEmptyGroupNotifySubstructure (	IPsec::SA_Proposal_PROTOCOL_ID protocol_id,
														uint8_t spi_size,
														IkeGroupNotifySubstructure::NOTIFY_MESSAGE_TYPE msg_type,
														uint32_t gsa_push_id,
														const IkeTrafficSelector& ts_src,
														const IkeTrafficSelector& ts_dest);
public:
	using IkePayloadSubstructure::Deserialize;
protected:	//non_const
	void SetProtocolId (uint8_t protocol_id);
	void SetNotifyMessageType (uint8_t notify_message_type);
	void SetSpiSize (uint8_t spi_size);
	void SetGsaPushId (uint32_t gsa_push_id);
private:
	uint8_t m_protocol_id;
	uint8_t m_spi_size;		//not "only" for Deserialization
	uint8_t m_notify_message_type;
	uint8_t m_num_spis;		//for Deserialization
	uint32_t m_gsa_push_id;
	IkeTrafficSelector m_ts_src;
	IkeTrafficSelector m_ts_dest;
	std::list<Ptr<Spi> > m_lst_ptr_spis;
};

}  // namespace ns3

#endif /* GSAM_H_ */
