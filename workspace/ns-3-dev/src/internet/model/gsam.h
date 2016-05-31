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
#include <list>

namespace ns3 {

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
		IKE_SA_INIT = 34,
		IKE_AUTH = 35,
		CREATE_CHILD_SA = 36,
		INFORMATIONAL = 37
	};

public:	//Header override
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;

private:
	uint64_t m_initiator_spi;
	uint64_t m_responder_spi;
	uint8_t m_next_payload;

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

	} m_version;

	uint8_t m_exchange_type;
	uint8_t m_flags;
	uint32_t m_message_id;
	uint32_t m_length;
};

class IkePayloadHeader : public Header {
	/*
	 *                       1                   2                   3
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
		EXTENSIBLE_AUTHENTICATION = 48
	};

public:	//Header override
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Print (std::ostream &os) const;
public:
	uint16_t GetPayloadLength (void) const;
private:
	uint8_t m_next_payload;
	uint8_t m_critial_reserved;
	uint16_t m_payload_length;
};

class IkeTransformAttribute : public Header {
	/*
	 *                     1                   2                   3
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
public:	//Trailer Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
private:
	bool m_TLV;
	uint16_t m_attribute_type;
	uint16_t m_attribute_length_or_value;
	std::list<uint8_t> m_lst_attribute_value;
};

class IkeTransformSubStructure : public Header {
	/*
	 *                     1                   2                   3
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
	static TypeId GetTypeId (void);
	IkeTransformSubStructure ();
	virtual ~IkeTransformSubStructure ();

	enum TRANSFORM_TYPE {
		ENCRYPTION_ALGORITHM = 1,
		PSEUDORANDOM_FUNCTION = 2,
		INTEGRITY_ALGORITHM = 3,
		DIFFIE_HELLMAN_GROUP = 4,
		TYPE_EXTENDED_SEQUENCE_NUMBERS = 5
	};

	enum TRANSFORM_ID {
		//TYPE 1
		ENCR_DES_IV64,
		ENCR_DES,
		ENCR_3DES,
		ENCR_RC5,
		ENCR_IDEA,
		ENCR_CAST,
		ENCR_BLOWFISH,
		ENCR_3IDEA,
		ENCR_DES_IV32,
		ENCR_NULL,
		ENCR_AES_CBC,
		ENCR_AES_CTR,
		//TYPE 2
		PRF_HMAC_MD5,
		PRF_HMAC_SHA1,
		PRF_HMAC_TIGER,
		//TYPE 3
		NONE,
		AUTH_HMAC_MD5_96,
		AUTH_HMAC_SHA1_96,
		AUTH_DES_MAC,
		AUTH_KPDK_MD5,
		AUTH_AES_XCBC_96,
		//TYPE 4
		DH_768_BIT_MODP,
		DH_1024_BIT_MODP,
		DH_1536_BIT_MODP,
		DH_2048_BIT_MODP,
		DH_3072_BIT_MODP,
		DH_4096_BIT_MODP,
		DH_6144_BIT_MODP,
		DH_8192_BIT_MODP,
		//TYPE 5
		ID_NO_EXTENDED_SEQUENCE_NUMBERS,
		ID_EXTENDED_SEQUENCE_NUMBERS
	};

public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
private:	//non virtual functions
	void SetLast (void);
public:
	bool IsLast (void);
private:
	bool m_last;
	uint16_t m_transform_length;
	uint8_t m_transform_type;
	uint8_t m_transform_id;
	std::list<IkeTransformAttribute> m_lst_transform_attributes;
};

class Spi : public Header {
public:
	static TypeId GetTypeId (void);
	Spi ();
	virtual ~Spi ();
public:	//header override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:
	uint8_t GetSize (void) const;	//does not return m_size;
	void SetSize (uint8_t size);
private:
	uint8_t m_size;	//for reading
	std::list<uint8_t> m_lst_var;
};

class IkeSAProposal : public Header {
	/*
	 *                       1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | 0 (last) or 2 |   RESERVED    |         Proposal Length       |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
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
	IkeSAProposal ();
	virtual ~IkeSAProposal ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual TypeId GetInstanceTypeId (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
private:
	Spi m_spi;
	bool m_last;
	uint16_t m_proposal_length;
	uint8_t m_proposal_num;
	uint8_t m_protocol_id;
	uint8_t m_spi_size;			//for reading
	uint8_t m_num_transforms;	//for reading
	std::list<IkeTransformSubStructure> m_lst_transforms;
};

class IkeSAPayload : public Header {

	/*
	 *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Next Payload  |C|  RESERVED   |         Payload Length        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                          <Proposals>                          ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:
	static TypeId GetTypeId (void);
	IkeSAPayload ();
	virtual ~IkeSAPayload ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
private:
	IkePayloadHeader m_header;
	std::list<IkeSAProposal> m_lst_proposal;	//proposals? Since it can be more than one.
};

class IkeKeyExchangeSubStructure : public Header {

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
	static TypeId GetTypeId (void);
	IkeKeyExchangeSubStructure ();
	virtual ~IkeKeyExchangeSubStructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:
	void SetLength (uint16_t length);
private:
	uint16_t m_dh_group_num;
	uint16_t m_length;	//total length for reading
	std::list<uint8_t> m_lst_data;
};

class IkeKeyExchangePayload : public Header {

	/*
	 *                       1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Next Payload  |C|  RESERVED   |         Payload Length        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   Diffie-Hellman Group Num    |           RESERVED            |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                       Key Exchange Data                       ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:
	static TypeId GetTypeId (void);
	IkeKeyExchangePayload ();
	virtual ~IkeKeyExchangePayload ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
private:
	IkePayloadHeader m_header;
	IkeKeyExchangeSubStructure m_substructure;
};

class IkeIdSubstructure : public Header {

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
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:
	void SetLength (uint16_t length);
private:
	uint8_t m_id_type;
	uint16_t m_length;	//total length, for reading
	std::list<uint8_t> m_lst_id_data;
};

class IkeIdPayload : public Header {

	/*
     *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Next Payload  |C|  RESERVED   |         Payload Length        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |   ID Type     |                 RESERVED                      |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                   Identification Data                         ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:
	static TypeId GetTypeId (void);
	IkeIdPayload ();
	virtual ~IkeIdPayload ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
private:
	IkePayloadHeader m_header;
	IkeIdSubstructure m_substructure;
};

class IkeAuthSubstructure : public Header {

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
		RSA_DIGITAL_SIGNATURE = 1,
		SHARED_KEY_MESSAGE_INTEGRITY_CODE = 2,
		DSS_DIGITAL_SIGNATURE = 3
	};

public:
	static TypeId GetTypeId (void);
	IkeAuthSubstructure ();
	virtual ~IkeAuthSubstructure ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
public:
	void SetLength (uint16_t length);
private:
	uint8_t m_auth_method;
	uint16_t m_length;	//total length, for reading
	std::list<uint8_t> m_lst_id_data;
};

class IkeAuthPayload : public Header {

	/*
     *                      1                   2                   3
     *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Next Payload  |C|  RESERVED   |         Payload Length        |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * | Auth Method   |                RESERVED                       |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |                                                               |
     * ~                      Authentication Data                      ~
     * |                                                               |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

public:
	static TypeId GetTypeId (void);
	IkeAuthPayload ();
	virtual ~IkeAuthPayload ();
public:	//Header Override
	virtual uint32_t GetSerializedSize (void) const;
	virtual void Serialize (Buffer::Iterator start) const;
	virtual uint32_t Deserialize (Buffer::Iterator start);
	virtual void Print (std::ostream &os) const;
private:
	IkePayloadHeader m_header;
	IkeAuthSubstructure m_substructure;
};

}  // namespace ns3

#endif /* GSAM_H_ */
