/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef IPV4_RAW_SOCKET_IMPL_MULTICAST_H
#define IPV4_RAW_SOCKET_IMPL_MULTICAST_H

#include "ns3/socket.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-route.h"
#include "ns3/ipv4-interface-multicast.h"
#include <list>

//added by Lin chen
#include "ns3/igmpv3.h"

namespace ns3 {

class NetDevice;
class Node;
class IGMPv3SocketState;

/**
 * \class Ipv4RawSocketImplMulticast
 * \brief IPv4 raw socket.
 * \ingroup socket
 *
 * A RAW Socket typically is used to access specific IP layers not usually
 * available through L4 sockets, e.g., ICMP. The implementer should take
 * particular care to define the Ipv4RawSocketImplMulticast Attributes, and in
 * particular the Protocol attribute.
 */
class Ipv4RawSocketImplMulticast : public Socket
{
public:
  /**
   * \brief Get the type ID of this class.
   * \return type ID
   */
  static TypeId GetTypeId (void);

  Ipv4RawSocketImplMulticast ();

  /**
   * \brief Set the node associated with this socket.
   * \param node node to set
   */
  void SetNode (Ptr<Node> node);

  virtual enum Socket::SocketErrno GetErrno () const;

  /**
   * \brief Get socket type (NS3_SOCK_RAW)
   * \return socket type
   */
  virtual enum Socket::SocketType GetSocketType (void) const;

  virtual Ptr<Node> GetNode (void) const;
  virtual int Bind (const Address &address);
  virtual int Bind ();
  virtual int Bind6 ();
  virtual int GetSockName (Address &address) const; 
  virtual int Close (void);
  virtual int ShutdownSend (void);
  virtual int ShutdownRecv (void);
  virtual int Connect (const Address &address);
  virtual int Listen (void);
  virtual uint32_t GetTxAvailable (void) const;
  virtual int Send (Ptr<Packet> p, uint32_t flags);
  virtual int SendTo (Ptr<Packet> p, uint32_t flags, 
                      const Address &toAddress);
  virtual uint32_t GetRxAvailable (void) const;
  virtual Ptr<Packet> Recv (uint32_t maxSize, uint32_t flags);
  virtual Ptr<Packet> RecvFrom (uint32_t maxSize, uint32_t flags,
                                Address &fromAddress);


  /**
   * \brief Set protocol field.
   * \param protocol protocol to set
   */
  void SetProtocol (uint16_t protocol);

  /**
   * \brief Forward up to receive method.
   * \param p packet
   * \param ipHeader IPv4 header
   * \param incomingInterface incoming interface
   * \return true if forwarded, false otherwise
   */
  bool ForwardUp (Ptr<const Packet> p, Ipv4Header ipHeader, Ptr<Ipv4InterfaceMulticast> incomingInterface);
  virtual bool SetAllowBroadcast (bool allowBroadcast);
  virtual bool GetAllowBroadcast () const;

  //added by Lin Chen
  /**
   *  \brief IPMulticastList at socket
   *
   */
  void IPMulticastListen (Ptr<Ipv4InterfaceMulticast> m_interface,
		  	  	  	  	  Ipv4Address multicast_address,
		  	  	  	  	  ns3::FILTER_MODE filter_mode,
		  	  	  	  	  std::list<Ipv4Address> &src_list);

private:
  virtual void DoDispose (void);

  /**
   * \struct Data
   * \brief IPv4 raw data and additional information.
   */
  struct Data {
    Ptr<Packet> packet;  /**< Packet data */
    Ipv4Address fromIp;  /**< Source address */
    uint16_t fromProtocol;   /**< Protocol used */
  };

  enum Socket::SocketErrno m_err;   //!< Last error number.
  Ptr<Node> m_node;                 //!< Node
  Ipv4Address m_src;                //!< Source address.
  Ipv4Address m_dst;                //!< Destination address.
  uint16_t m_protocol;              //!< Protocol.
  std::list<struct Data> m_recv;    //!< Packet waiting to be processed.
  bool m_shutdownSend;              //!< Flag to shutdown send capability.
  bool m_shutdownRecv;              //!< Flag to shutdown receive capability.
  uint32_t m_icmpFilter;            //!< ICMPv4 filter specification
  bool m_iphdrincl;                 //!< Include IP Header information (a.k.a setsockopt (IP_HDRINCL))

  //added by Lin Chen
  std::list<IGMPv3SocketState> m_lst_socketstates;
};

} // namespace ns3

#endif /* IPV4_RAW_SOCKET_IMPL_H */
