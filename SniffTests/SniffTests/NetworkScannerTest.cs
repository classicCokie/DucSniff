using System;
using System.Collections.Generic;
using DucSniff;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace SniffTests
{
    [TestClass]
    public class NetworkScannerTest
    {
        [TestMethod]
        public void testScan()
        {
            NetworkData netcad = new NetworkData();

            NetworkScanner scanner = new NetworkScanner(netcad.GetIpRange());

            scanner.start_scanning();
            List<string> result = scanner.GetHosts();
            Assert.IsNotNull(result);

        }
    }
}
