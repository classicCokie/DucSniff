using System;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;

namespace DucSniff
{//Copy all Data From the incoming package execpt for the New Destination MacAdress on the Ethernet layer
    internal class IcmpPacket
    {
        public Packet BuildIcmpPacket(Packet origPacket, MacAddress newMacAdress)
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

            IcmpEchoLayer icmpLayer =
                new IcmpEchoLayer
                {
                    Checksum = origPacket.Ethernet.IpV4.Icmp.Checksum, // Will be filled automatically.
                    Identifier = 456,
                    SequenceNumber = 800
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer);

            return builder.Build(DateTime.Now);
        }
    }
}