using System;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace DucSniff
{
    internal class TcpPacket
    {
        public Packet BuildTcpPacket(Packet origPacket, MacAddress newMacAdress)
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


            TcpLayer tcpLayer =
                new TcpLayer
                {
                    SourcePort = origPacket.Ethernet.IpV4.Tcp.SourcePort,
                    DestinationPort = origPacket.Ethernet.IpV4.Tcp.DestinationPort,
                    Checksum = null, // Will be filled automatically.
                    SequenceNumber = origPacket.Ethernet.IpV4.Tcp.SequenceNumber,
                    AcknowledgmentNumber = origPacket.Ethernet.IpV4.Tcp.AcknowledgmentNumber,
                    ControlBits = TcpControlBits.Acknowledgment,
                    Window = origPacket.Ethernet.IpV4.Tcp.Window,
                    UrgentPointer = origPacket.Ethernet.IpV4.Tcp.UrgentPointer,
                    Options = origPacket.Ethernet.IpV4.Tcp.Options
                };


            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = origPacket.Ethernet.IpV4.Tcp.Payload
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, tcpLayer, payloadLayer);

            return builder.Build(DateTime.Now);
        }
    }
}