/*
 * Igmpv3-l4-protocol.h
 *
 *  Created on: Jan 27, 2016
 *      Author: lin
 */

#ifndef IGMPV3_L4_PROTOCOL_MULTICAST_H
#define IGMPV3_L4_PROTOCOL_MULTICAST_H

#include "ip-l4-protocol-multicast.h"
#include "igmpv3.h"

namespace ns3 {

class Node;
class Ipv4InterfaceMulticast;
class Ipv4Route;
class GsamL4Protocol;

class Igmpv3L4Protocol: public IpL4ProtocolMulticast {
public:
	enum ROLE {
		UNITIALIZED = 0,
		QUERIER = 1, NONQUERIER = 2, GROUP_MEMBER = 3
	};

public:
	//Algebraic tools
	/*
	 * list union, sort lists before use.
	 */
	template<typename T>
	static std::list<T> ListUnion (std::list<T> const &lst_a, std::list<T> const &lst_b)
	{
		{
			std::list<T> reval;

			typename std::list<T>::const_iterator it_a = lst_a.begin();
			typename std::list<T>::const_iterator it_b = lst_b.begin();

			while (it_a != lst_a.end())
			{
				while (it_b != lst_b.end())
				{
					if ((*it_a) < (*it_b))
					{
						reval.push_back(*it_a);
						it_a++;
						break;
					}
					else if ((*it_a) != (*it_b))	//(*it_a) > (*it_b)
					{
						reval.push_back(*it_b);
						it_b++;
						continue;
					}
					else
					{
						//push a or b, choose pushing a
						reval.push_back(*it_a);
						it_a++;
						it_b++;
						break;
					}
				}

				if (it_b == lst_b.end())
				{
					reval.push_back(*it_a);
					it_a++;
				}
			}

			return reval;
		}
	}

	/*
	 * list a minus list b, sort lists before use.
	 */
	template<typename T>
	static std::list<T> ListSubtraction (std::list<T> const &lst_a, std::list<T> const &lst_b)
	{
		{
			std::list<T> reval;
			std::copy (lst_a.begin(), lst_a.end(), std::back_inserter(reval));

			typename std::list<T>::const_iterator it_a = lst_a.begin();
			typename std::list<T>::const_iterator it_b = lst_b.begin();

			while (it_a != lst_a.end())
			{
				while (it_b != lst_b.end())
				{
					if ((*it_a) < (*it_b))
					{
						it_a++;
						break;
					}
					else if ((*it_a) != (*it_b))	//(*it_a) > (*it_b)
					{
						it_b++;
						continue;
					}
					else	//(*it_a) == (*it_b)
					{
						//remove the element has the same value as *it_b from lst_a
						reval.remove(*it_b);
						it_a++;
						it_b++;
						break;
					}
				}

				if (it_b == lst_b.end())
				{
					return reval;
				}
			}

			return reval;
		}
	}

	/*
	 * list a minus list b, sort lists before use.
	 */
	template<typename T>
	static std::list<T> ListIntersection (std::list<T> const &lst_a, std::list<T> const &lst_b)
	{
		{
			std::list<T> reval;

			typename std::list<T>::const_iterator it_a = lst_a.begin();
			typename std::list<T>::const_iterator it_b = lst_b.begin();

			while (it_a != lst_a.end())
			{
				while (it_b != lst_b.end())
				{
					if ((*it_a) < (*it_b))
					{
						it_a++;
						break;
					}
					else if ((*it_a) != (*it_b))	//(*it_a) > (*it_b)
					{
						it_b++;
						continue;
					}
					else	//(*it_a) == (*it_b)
					{
						//remove the element has the same value as *it_b from lst_a
						reval.push_back(*it_a);
						it_a++;
						it_b++;
						break;
					}
				}

				if (it_b == lst_b.end())
				{
					return reval;
				}
			}

			return reval;
		}
	}

public:
	/**
	 * \brief Get the type ID.
	 * \return the object TypeId
	 */
	static TypeId GetTypeId (void);
	static const uint8_t PROT_NUMBER; //!< IGMP protocol number (0x2)

	Igmpv3L4Protocol();
	virtual ~Igmpv3L4Protocol();

	/**
	 * \brief Set the node the protocol is associated with.
	 * \param node the node
	 */
	void SetNode (Ptr<Node> node);

	/**
	 * Get the protocol number
	 * \returns the protocol number
	 */
	static uint16_t GetStaticProtocolNumber (void);

	/**
	 * Get the protocol number
	 * \returns the protocol number
	 */
	virtual int GetProtocolNumber (void) const;

	/**
	 * \brief Receive method.
	 * \param p the packet
	 * \param header the IPv4 header
	 * \param incomingInterface the interface from which the packet is coming
	 * \returns the receive status
	 */
	virtual enum IpL4ProtocolMulticast::RxStatus Receive (Ptr<Packet> p,
			Ipv4Header const &header,
			Ptr<Ipv4InterfaceMulticast> incomingInterface);

	/**
	 * \brief Receive method.
	 * \param p the packet
	 * \param header the IPv6 header
	 * \param incomingInterface the interface from which the packet is coming
	 * \returns the receive status
	 */
	virtual enum IpL4ProtocolMulticast::RxStatus Receive (Ptr<Packet> p,
			Ipv6Header const &header,
			Ptr<Ipv6Interface> incomingInterface);

	// From IpL4ProtocolMulticast
	virtual void SetDownTarget (IpL4ProtocolMulticast::DownTargetCallback cb);
	virtual void SetDownTarget6 (IpL4ProtocolMulticast::DownTargetCallback6 cb);
	// From IpL4ProtocolMulticast
	virtual IpL4ProtocolMulticast::DownTargetCallback GetDownTarget (void) const;
	virtual IpL4ProtocolMulticast::DownTargetCallback6 GetDownTarget6 (void) const;

	//added by Lin Chen
	void SetRole (Igmpv3L4Protocol::ROLE role);
	Igmpv3L4Protocol::ROLE GetRole (void);
	void Initialization (void);
	void SendDefaultGeneralQuery (void);
	void SendCurrentStateReport (Ptr<Ipv4InterfaceMulticast> incomingInterface, Ptr<PerInterfaceTimer> pintimer);
	void SendStateChangesReport (Ptr<Ipv4InterfaceMulticast> incomingInterface);
	void HandleQuery (Ptr<Packet> packet, uint8_t max_resp_code, Ptr<Ipv4InterfaceMulticast> incomingInterface);
	void NonQHandleQuery (Ptr<Packet> packet, uint8_t max_resp_code, Ptr<Ipv4InterfaceMulticast> incomingInterface);
	void HandleV1MemReport (void);
	void HandleV2MemReport (void);
	void HandleV3MemReport (Ptr<Packet> packet, Ptr<Ipv4InterfaceMulticast> incomingInterface);
//	*obsolete*, moved to interface
//	void HandleGeneralQuery (Ptr<Ipv4InterfaceMulticast> incomingInterface, Time resp_time);
	void HandleGroupSpecificQuery (void);
//	void IPMulticastListen (Ptr<Socket> socket,
//							Ptr<Ipv4InterfaceMulticast> interface,
//							Ipv4Address multicast_address,
//							ns3::FILTER_MODE filter_mode,
//							std::list<Ipv4Address> &source_list);
	void IPMulticastListen (Ptr<Ipv4InterfaceMulticast> interface,
							Ipv4Address multicast_address,
							ns3::FILTER_MODE filter_mode,
							std::list<Ipv4Address> &source_list);
//	*obsolete* Move to Ipv4InterfaceMulticast
//	void SendStateChangeReport (std::list<Igmpv3GrpRecord> &records);

	/*
	 * \breif Send IGMPv3 Report
	 */
	void SendReport (Ptr<Ipv4InterfaceMulticast> incomingInterface, Ptr<Packet> packet);

	Time GetUnsolicitedReportInterval (void);
	uint8_t GetRobustnessValue (void);
	uint8_t GetMaxRespCode (void);
	Time GetRandomTime (Time max);
	Time GetMaxRespTime (uint8_t max_resp_code);
	Time GetQueryInterval (void);
	Time GetQueryReponseInterval (void);
	Time GetGroupMembershipIntervalGMI (void);
	Time GetLastMemberQueryTimeLMQT (void);
	Time GetLastMemberQueryInterval (void);
	Time GetOtherQuerierPresentInterval (void);
	Time GetStartupQueryInterval (void);
	uint8_t GetLastMemberQueryCount (void);
	uint8_t GetQQIC (void);
	uint8_t GetQRV (void);
	uint8_t GetStartupQueryCount (void);

	/*
	 * query
	 */
	void SendQuery (Ipv4Address group_address, Ptr<Ipv4InterfaceMulticast> incomingInterface, Ptr<Packet> packet);
	void DoSendQuery (Ipv4Address group_address, Ptr<Ipv4InterfaceMulticast> incomingInterface, Ptr<Packet> packet);

public:	//gsam related
	void SetGsam (Ptr<GsamL4Protocol> gsam);
	Ptr<GsamL4Protocol> GetGsam (void);
protected:
	/*
	 * This function will notify other components connected to the node that a new stack member is now connected
	 * This will be used to notify Layer 3 protocol of layer 4 protocol stack to connect them together.
	 */
	virtual void NotifyNewAggregate ();

private:
	/**
	 * \brief Send a generic IGMPv3 packet
	 *
	 * \param packet the packet
	 * \param dest the destination
	 * \param type the IGMPv3 type
	 * \param code the IGMPv3 code
	 */
	void SendMessage (Ptr<Packet> packet, Ipv4Address dest, Ptr<Ipv4Route> route);
	/**
	 * \brief Send a generic IGMPv3 packet
	 *
	 * \param packet the packet
	 * \param source the source
	 * \param dest the destination
	 * \param type the IGMPv3 type
	 * \param code the IGMPv3 code
	 * \param route the route to be used
	 */
	//	void SendMessage (Ptr<Packet> packet, Ipv4Address source, Ipv4Address dest, uint8_t type, uint8_t code, Ptr<Ipv4Route> route);

	virtual void DoDispose (void);

	Ptr<Node> m_node; //!< the node this protocol is associated with
	IpL4ProtocolMulticast::DownTargetCallback m_downTarget; //!< callback to Ipv4::Send

	//IGMPv3 Parameters Setting
	bool m_default_s_flag;				//assumed default
	uint8_t m_default_qqic;				//125sec, cisco default
	uint8_t m_default_qrv;				//cisco default
	uint8_t m_default_max_resp_code;	//10sec, cisco default
	Ipv4Address m_GenQueAddress;	//!< Address to send for general query
	Ipv4Address m_RptAddress;		//!< Address to send for group report

	ROLE m_role;

	//For accessing various States, states are stored in socket or interface
	//std::list<Ptr<Socket> > m_lst_socket_accessors;
	std::list<Ptr<Ipv4InterfaceMulticast> > m_lst_interface_accessors;

//	*Obsolete*//Timers
//	std::list<Ptr<PerInterfaceTimer> > m_lst_per_interface_timers;
//	std::list<Ptr<PerGroupInterfaceTimer> > m_lst_per_group_interface_timers;

	//robustness retransmission
	EventId m_event_robustness_retransmission;

	//gsam
	Ptr<GsamL4Protocol> m_gsam;
};

} /* namespace ns3 */

#endif /* SRC_INTERNET_MODEL_IGMPV3_L4_PROTOCOL_H_ */
