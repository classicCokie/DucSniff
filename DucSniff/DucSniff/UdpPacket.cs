﻿using System;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace DucSniff
{
    internal class UdpPacket
    {
        //UDP Packt Builder
        public Packet BuildUdpPacket(Packet origPacket, MacAddress newMacAdress)
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = origPacket.Ethernet.Source,
                    Destination = newMacAdress,
                    EtherType = EthernetType.None // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = origPacket.Ethernet.IpV4.Source,
                    CurrentDestination = origPacket.Ethernet.IpV4.Destination,
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = origPacket.Ethernet.IpV4.Identification,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = origPacket.Ethernet.IpV4.Ttl,
                    TypeOfService = origPacket.Ethernet.IpV4.TypeOfService
                };


            UdpLayer udpLayer =
                new UdpLayer
                {
                    SourcePort = origPacket.Ethernet.IpV4.Udp.SourcePort,
                    DestinationPort = origPacket.Ethernet.IpV4.Udp.DestinationPort,
                    Checksum = null, // Will be filled automatically.
                    CalculateChecksumValue = true
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = origPacket.Ethernet.IpV4.Udp.Payload
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, payloadLayer);

            return builder.Build(DateTime.Now);
        }
    }
}