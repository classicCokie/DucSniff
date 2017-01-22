using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Threading;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using DucSniff;



namespace SniffTests
{
    [TestClass]
    public class NetworkDataTest
    {
        [TestMethod]
        public void GetIpAdressTest()
        {
            NetworkData netcad = new NetworkData();

            string result = netcad.GetIpAdress();

            Assert.IsNotNull(result);
        }

        public void GetIpRangeTest()
        {
            NetworkData netcad = new NetworkData();

            string result = netcad.GetIpRange();

            Assert.IsNotNull(result);
        }

        public void GetMacAdressTest()
        {
            NetworkData netcad = new NetworkData();

            string result = netcad.GetMacAdress();

            Assert.IsNotNull(result);
        }
    }
}
