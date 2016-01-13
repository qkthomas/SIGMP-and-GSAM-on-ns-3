/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 University of Washington
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
 */

#ifndef INTERNET_TRACE_HELPER_MULTICAST_H
#define INTERNET_TRACE_HELPER_MULTICAST_H

#include "ns3/assert.h"
#include "ns3/ipv4-interface-container-multicast.h"
#include "ns3/ipv6-interface-container.h"
#include "ns3/ipv4-multicast.h"
#include "ns3/ipv6.h"
#include "ns3/trace-helper.h"

//added by Lin Chen
#include "internet-trace-helper.h"

namespace ns3 {

/**
 * @brief Base class providing common user-level pcap operations for helpers
 * representing IPv4 protocols .
 */
class PcapHelperForIpv4Multicast
{
public:
  /**
   * @brief Construct a PcapHelperForIpv4Multicast.
   */
  PcapHelperForIpv4Multicast () {}

  /**
   * @brief Destroy a PcapHelperForIpv4Multicast.
   */
  virtual ~PcapHelperForIpv4Multicast () {}

  /**
   * @brief Enable pcap output the indicated Ipv4Multicast and interface pair.
   *
   * @param prefix Filename prefix to use for pcap files.
   * @param ipv4 Ptr<Ipv4Multicast> on which you want to enable tracing.
   * @param interface Interface on ipv4 on which you want to enable tracing.
   * @param explicitFilename Treat the prefix as an explicit filename if true
   */
  virtual void EnablePcapIpv4Internal (std::string prefix, 
                                       Ptr<Ipv4Multicast> ipv4, 
                                       uint32_t interface,
                                       bool explicitFilename) = 0;

  /**
   * @brief Enable pcap output the indicated Ipv4Multicast and interface pair.
   *
   * @param prefix Filename prefix to use for pcap files.
   * @param ipv4 Ptr<Ipv4Multicast> on which you want to enable tracing.
   * @param interface Interface on ipv4 on which you want to enable tracing.
   * @param explicitFilename Treat the prefix as an explicit filename if true.
   */
  void EnablePcapIpv4 (std::string prefix, Ptr<Ipv4Multicast> ipv4, uint32_t interface, bool explicitFilename = false);

  /**
   * @brief Enable pcap output the indicated Ipv4Multicast and interface pair using a
   * Ptr<Ipv4Multicast> previously named using the ns-3 object name service.
   *
   * @param prefix filename prefix to use for pcap files.
   * @param ipv4Name Name of the Ptr<Ipv4Multicast> on which you want to enable tracing.
   * @param interface Interface on ipv4 on which you want to enable tracing.
   * @param explicitFilename Treat the prefix as an explicit filename if true.
   */
  void EnablePcapIpv4 (std::string prefix, std::string ipv4Name, uint32_t interface, bool explicitFilename = false);

  /**
   * @brief Enable pcap output on each Ipv4Multicast and interface pair in the container.
   *
   * @param prefix Filename prefix to use for pcap files.
   * @param c Ipv4InterfaceContainerMulticast of Ipv4Multicast and interface pairs
   */
  void EnablePcapIpv4 (std::string prefix, Ipv4InterfaceContainerMulticast c);

  /**
   * @brief Enable pcap output on all Ipv4Multicast and interface pairs existing in the
   * nodes provided in the container.
   *
   * \param prefix Filename prefix to use for pcap files.
   * \param n container of nodes.
   */
  void EnablePcapIpv4 (std::string prefix, NodeContainer n);

  /**
   * @brief Enable pcap output on the Ipv4Multicast and interface pair specified by a 
   * global node-id (of a previously created node) and interface.  Since there
   * can be only one Ipv4Multicast aggregated to a node, the node-id unambiguously 
   * determines the Ipv4Multicast.
   *
   * @param prefix Filename prefix to use for pcap files.
   * @param nodeid The node identifier/number of the node on which to enable tracing.
   * @param interface Interface on ipv4 on which you want to enable tracing.
   * @param explicitFilename Treat the prefix as an explicit filename if true
   */
  void EnablePcapIpv4 (std::string prefix, uint32_t nodeid, uint32_t interface, bool explicitFilename);

  /**
   * @brief Enable pcap output on all Ipv4Multicast and interface pairs existing in the 
   * set of all nodes created in the simulation.
   *
   * @param prefix Filename prefix to use for pcap files.
   */
  void EnablePcapIpv4All (std::string prefix);

};

/**
 * @brief Base class providing common user-level ascii trace operations for 
 * helpers representing IPv4 protocols .
 */
class AsciiTraceHelperForIpv4Multicast
{
public:
  /**
   * @brief Construct an AsciiTraceHelperForIpv4Multicast.
   */
  AsciiTraceHelperForIpv4Multicast () {}

  /**
   * @brief Destroy an AsciiTraceHelperForIpv4Multicast
   */
  virtual ~AsciiTraceHelperForIpv4Multicast () {}

  /**
   * @brief Enable ascii trace output on the indicated Ipv4Multicast and interface pair.
   *
   * The implementation is expected to use a provided Ptr<OutputStreamWrapper>
   * if it is non-null.  If the OutputStreamWrapper is null, the implementation
   * is expected to use a provided prefix to construct a new file name for
   * each net device using the rules described in the class overview.
   *
   * If the prefix is provided, there will be one file per Ipv4Multicast and interface pair
   * created.  In this case, adding a trace context to the file would be pointless,
   * so the helper implementation is expected to TraceConnectWithoutContext.
   *
   * If the output stream object is provided, there may be many different Ipv4Multicast 
   * and interface pairs writing to a single file.  In this case, the trace 
   * context could be important, so the helper implementation is expected to 
   * TraceConnect.
   *
   * @param stream An OutputStreamWrapper representing an existing file to use
   *               when writing trace data.
   * @param prefix Filename prefix to use for ascii trace files.
   * @param ipv4 Ptr<Ipv4Multicast> on which you want to enable tracing.
   * @param interface The interface on which you want to enable tracing.
   * @param explicitFilename Treat the prefix as an explicit filename if true.
   */
  virtual void EnableAsciiIpv4Internal (Ptr<OutputStreamWrapper> stream, 
                                        std::string prefix, 
                                        Ptr<Ipv4Multicast> ipv4, 
                                        uint32_t interface,
                                        bool explicitFilename) = 0;

  /**
   * @brief Enable ascii trace output on the indicated Ipv4Multicast and interface pair.
   *
   * @param prefix Filename prefix to use for ascii files.
   * @param ipv4 Ptr<Ipv4Multicast> on which you want to enable tracing.
   * @param interface The interface on which you want to enable tracing.
   * @param explicitFilename Treat the prefix as an explicit filename if true.
   */
  void EnableAsciiIpv4 (std::string prefix, Ptr<Ipv4Multicast> ipv4, uint32_t interface, bool explicitFilename = false);

  /**
   * @brief Enable ascii trace output on the indicated Ipv4Multicast and interface pair.
   *
   * @param stream An OutputStreamWrapper representing an existing file to use
   *               when writing trace data.
   * @param ipv4 Ptr<Ipv4Multicast> on which you want to enable tracing.
   * @param interface The interface on which you want to enable tracing.
   */
  void EnableAsciiIpv4 (Ptr<OutputStreamWrapper> stream, Ptr<Ipv4Multicast> ipv4, uint32_t interface);

  /**
   * @brief Enable ascii trace output the indicated Ipv4Multicast and interface pair
   * using an Ipv4Multicast previously named using the ns-3 object name service.
   *
   * @param prefix filename prefix to use for ascii files.
   * @param ipv4Name The name of the Ipv4Multicast on which you want to enable tracing.
   * @param interface The interface on which you want to enable tracing.
   * @param explicitFilename Treat the prefix as an explicit filename if true.
   */
  void EnableAsciiIpv4 (std::string prefix, std::string ipv4Name, uint32_t interface, bool explicitFilename = false);

  /**
   * @brief Enable ascii trace output the indicated net device using a device 
   * previously named using the ns-3 object name service.
   *
   * @param stream An OutputStreamWrapper representing an existing file to use
   *               when writing trace data.
   * @param ipv4Name The name of the Ipv4Multicast on which you want to enable tracing.
   * @param interface The interface on which you want to enable tracing.
   */
  void EnableAsciiIpv4 (Ptr<OutputStreamWrapper> stream, std::string ipv4Name, uint32_t interface);

  /**
   * @brief Enable ascii trace output on each Ipv4Multicast and interface pair in the 
   * container
   *
   * @param prefix Filename prefix to use for ascii files.
   * @param c Ipv4InterfaceContainerMulticast of Ipv4Multicast and interface pairs on which to 
   *          enable tracing.
   */
  void EnableAsciiIpv4 (std::string prefix, Ipv4InterfaceContainerMulticast c);

  /**
   * @brief Enable ascii trace output on each device in the container which is
   * of the appropriate type.
   *
   * @param stream An OutputStreamWrapper representing an existing file to use
   *               when writing trace data.
   * @param c Ipv4InterfaceContainerMulticast of Ipv4Multicast and interface pairs on which to 
   *          enable tracing.
   */
  void EnableAsciiIpv4 (Ptr<OutputStreamWrapper> stream, Ipv4InterfaceContainerMulticast c);

  /**
   * @brief Enable ascii trace output on all Ipv4Multicast and interface pairs existing
   * in the nodes provided in the container.
   *
   * \param prefix Filename prefix to use for ascii files.
   * \param n container of nodes.
   */
  void EnableAsciiIpv4 (std::string prefix, NodeContainer n);

  /**
   * @brief Enable ascii trace output on all Ipv4Multicast and interface pairs existing
   * in the nodes provided in the container.
   *
   * @param stream An OutputStreamWrapper representing an existing file to use
   *               when writing trace data.
   * \param n container of nodes.
   */
  void EnableAsciiIpv4 (Ptr<OutputStreamWrapper> stream, NodeContainer n);

  /**
   * @brief Enable ascii trace output on all Ipv4Multicast and interface pairs existing
   * in the set of all nodes created in the simulation.
   *
   * @param prefix Filename prefix to use for ascii files.
   */
  void EnableAsciiIpv4All (std::string prefix);

  /**
   * @brief Enable ascii trace output on each device (which is of the
   * appropriate type) in the set of all nodes created in the simulation.
   *
   * @param stream An OutputStreamWrapper representing an existing file to use
   *               when writing trace data.
   */
  void EnableAsciiIpv4All (Ptr<OutputStreamWrapper> stream);

  /**
   * @brief Enable ascii trace output on the Ipv4Multicast and interface pair specified by a
   * global node-id (of a previously created node) and interface.  Since there
   * can be only one Ipv4Multicast aggregated to a node, the node-id unambiguously 
   * determines the Ipv4Multicast.
   *
   * @param prefix Filename prefix to use when creating ascii trace files
   * @param nodeid The node identifier/number of the node on which to enable
   *               ascii tracing
   * @param deviceid The device identifier/index of the device on which to enable
   *                 ascii tracing
   * @param explicitFilename Treat the prefix as an explicit filename if true
   */
  void EnableAsciiIpv4 (std::string prefix, uint32_t nodeid, uint32_t deviceid, bool explicitFilename);

  /**
   * @brief Enable ascii trace output on the Ipv4Multicast and interface pair specified by a
   * global node-id (of a previously created node) and interface.  Since there
   * can be only one Ipv4Multicast aggregated to a node, the node-id unambiguously 
   * determines the Ipv4Multicast.
   *
   * @param stream An OutputStreamWrapper representing an existing file to use
   *               when writing trace data.
   * @param nodeid The node identifier/number of the node on which to enable
   *               ascii tracing
   * @param interface The interface on which you want to enable tracing.
   * @param explicitFilename Treat the prefix as an explicit filename if true
   */
  void EnableAsciiIpv4 (Ptr<OutputStreamWrapper> stream, uint32_t nodeid, uint32_t interface, bool explicitFilename);

private:
  /**
   * @brief Enable ascii trace output on the Ipv4Multicast and interface pair specified by a
   * global node-id (of a previously created node) and interface.  Since there
   * can be only one Ipv4Multicast aggregated to a node, the node-id unambiguously
   * determines the Ipv4Multicast.
   *
   * @param stream An OutputStreamWrapper representing an existing file to use
   *               when writing trace data.
   * @param prefix Filename prefix to use when creating ascii trace files
   * @param nodeid The node identifier/number of the node on which to enable
   *               ascii tracing
   * @param interface The device identifier/index of the device on which to enable
   *               ascii tracing
   * @param explicitFilename Treat the prefix as an explicit filename if true.
   */
  void EnableAsciiIpv4Impl (Ptr<OutputStreamWrapper> stream, 
                            std::string prefix, 
                            uint32_t nodeid, 
                            uint32_t interface,
                            bool explicitFilename);

  /**
   * @brief Enable ascii trace output on the Ipv4Multicast and interface pair specified by a
   * global node-id (of a previously created node) and interface.  Since there
   * can be only one Ipv4Multicast aggregated to a node, the node-id unambiguously
   * determines the Ipv4Multicast.
   *
   * @param stream An OutputStreamWrapper representing an existing file to use
   *               when writing trace data.
   * @param prefix Filename prefix to use when creating ascii trace files
   * @param n container of nodes.
   */
  void EnableAsciiIpv4Impl (Ptr<OutputStreamWrapper> stream, std::string prefix, NodeContainer n);

  /**
   * @brief Enable ascii trace output on the Ipv4Multicast and interface pair specified by a
   * global node-id (of a previously created node) and interface.  Since there
   * can be only one Ipv4Multicast aggregated to a node, the node-id unambiguously
   * determines the Ipv4Multicast.
   *
   * @param stream An OutputStreamWrapper representing an existing file to use
   *               when writing trace data.
   * @param prefix Filename prefix to use when creating ascii trace files
   * @param c Ipv4InterfaceContainerMulticast of Ipv4Multicast and interface pairs
   */
  void EnableAsciiIpv4Impl (Ptr<OutputStreamWrapper> stream, std::string prefix, Ipv4InterfaceContainerMulticast c);

  /**
   * @brief Enable ascii trace output on the Ipv4Multicast and interface pair specified by a
   * global node-id (of a previously created node) and interface.  Since there
   * can be only one Ipv4Multicast aggregated to a node, the node-id unambiguously
   * determines the Ipv4Multicast.
   *
   * @param stream An OutputStreamWrapper representing an existing file to use
   *               when writing trace data.
   * @param prefix Filename prefix to use when creating ascii trace files
   * @param ipv4Name Name of the Ptr<Ipv4Multicast> on which you want to enable tracing.
   * @param interface The device identifier/index of the device on which to enable
   *               ascii tracing
   * @param explicitFilename Treat the prefix as an explicit filename if true.
   */
  void EnableAsciiIpv4Impl (Ptr<OutputStreamWrapper> stream, 
                            std::string prefix, 
                            std::string ipv4Name, 
                            uint32_t interface,
                            bool explicitFilename);

  /**
   * @brief Enable ascii trace output on the Ipv4Multicast and interface pair specified by a
   * global node-id (of a previously created node) and interface.  Since there
   * can be only one Ipv4Multicast aggregated to a node, the node-id unambiguously
   * determines the Ipv4Multicast.
   *
   * @param stream An OutputStreamWrapper representing an existing file to use
   *               when writing trace data.
   * @param prefix Filename prefix to use when creating ascii trace files
   * @param ipv4 Ptr<Ipv4Multicast> on which you want to enable tracing.
   * @param interface The device identifier/index of the device on which to enable
   *               ascii tracing
   * @param explicitFilename Treat the prefix as an explicit filename if true.
   */
  void EnableAsciiIpv4Impl (Ptr<OutputStreamWrapper> stream, 
                            std::string prefix, 
                            Ptr<Ipv4Multicast> ipv4, 
                            uint32_t interface,
                            bool explicitFilename);
};


} // namespace ns3

#endif /* INTERNET_TRACE_HELPER_H */
