using System;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace DucSniff
{//Copy all Data From the incoming package execpt for the New Destination MacAdress on the Ethernet layer
    internal class DnsPacket
    {
        //DNS PACKET BUILDER 
        public Packet BuildDnsPacket(Packet origPacket, MacAddress newMacAdress)
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

            DnsLayer dnsLayer =
                new DnsLayer
                {
                    Id = origPacket.Ethernet.IpV4.Udp.Dns.Id,
                    IsResponse = origPacket.Ethernet.IpV4.Udp.Dns.IsResponse,
                    OpCode = origPacket.Ethernet.IpV4.Udp.Dns.OpCode,
                    IsAuthoritativeAnswer = origPacket.Ethernet.IpV4.Udp.Dns.IsAuthoritativeAnswer,
                    IsTruncated = origPacket.Ethernet.IpV4.Udp.Dns.IsTruncated,
                    IsRecursionDesired = origPacket.Ethernet.IpV4.Udp.Dns.IsRecursionDesired,
                    IsRecursionAvailable = origPacket.Ethernet.IpV4.Udp.Dns.IsRecursionAvailable,
                    FutureUse = origPacket.Ethernet.IpV4.Udp.Dns.FutureUse,
                    IsAuthenticData = origPacket.Ethernet.IpV4.Udp.Dns.IsAuthenticData,
                    IsCheckingDisabled = origPacket.Ethernet.IpV4.Udp.Dns.IsCheckingDisabled,
                    ResponseCode = origPacket.Ethernet.IpV4.Udp.Dns.ResponseCode,
                    Queries = origPacket.Ethernet.IpV4.Udp.Dns.Queries,
                    Answers = origPacket.Ethernet.IpV4.Udp.Dns.Answers,
                    Authorities = origPacket.Ethernet.IpV4.Udp.Dns.Authorities,
                    Additionals = origPacket.Ethernet.IpV4.Udp.Dns.Additionals,
                    DomainNameCompressionMode = DnsDomainNameCompressionMode.All
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, dnsLayer);

            return builder.Build(DateTime.Now);
        }
    }
}