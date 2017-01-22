using System;
using System.Collections.Generic;
using PcapDotNet.Base;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;

namespace DucSniff
{
    internal class ArpPacket
    {
        public static Packet BuildArpPacket(List<byte> sourceAdress, List<byte> target1Adress, List<byte> target2Adress,
            List<byte> target1Ip, List<byte> target2Ip, string srcMacAdress, string targetMacAdress)
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress(srcMacAdress),
                    Destination = new MacAddress(targetMacAdress),
                    EtherType = EthernetType.Arp // Will be filled automatically.
                };

            ArpLayer arpLayer =
                new ArpLayer
                {
                    ProtocolType = EthernetType.IpV4,
                    Operation = ArpOperation.Reply,

                    SenderHardwareAddress = new[] { sourceAdress[0], sourceAdress[1], sourceAdress[2], sourceAdress[3], sourceAdress[4], sourceAdress[5] }.AsReadOnly(),                   
                    SenderProtocolAddress = new[] {target1Ip[0], target1Ip[1], target1Ip[2], target1Ip[3]}.AsReadOnly(),
             
                    TargetHardwareAddress = new[] { target1Adress[0], target1Adress[1], target1Adress[2], target1Adress[3], target1Adress[4], target1Adress[5] }.AsReadOnly(),  
                    TargetProtocolAddress = new[] {target2Ip[0], target2Ip[1], target2Ip[2], target2Ip[3]}.AsReadOnly()            
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, arpLayer);

            return builder.Build(DateTime.Now);
        }
    }
}