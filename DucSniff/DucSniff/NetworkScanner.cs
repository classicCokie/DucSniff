using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace DucSniff
{
    public class NetworkScanner
    {
        private static readonly List<string> HostList = new List<string>();
        private static string _ipRange;
        private int _counter = 1;


        public NetworkScanner(string ipRange)
        {
            _ipRange = ipRange;
        }

        public void start_scanning()
        {
            _counter = 1;
            List<Thread> threadList = new List<Thread>();
            for (int i = 1; i < 255; i++)
            {
                Thread request = new Thread(() => scan_Network(_counter++));
                threadList.Add(request);
                request.Start();
            }

            foreach (Thread machineThread in threadList)
                machineThread.Join();
        }

        public List<string> GetHosts()
        {
            return HostList;
        }

        public void ClearhostList()
        {
            HostList.Clear();
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(uint destIp, uint srcIp, byte[] pMacAddr, ref int phyAddrLen);

        private static void scan_Network(int counter)
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());

            IPAddress dst = IPAddress.Parse(string.Concat(_ipRange, counter));
            uint uintAddress = BitConverter.ToUInt32(dst.GetAddressBytes(), 0);
            byte[] macAddr = new byte[6];
            int macAddrLen = macAddr.Length;
            int retValue = SendARP(uintAddress, 0, macAddr, ref macAddrLen);
            if (retValue == 0)
            {
                string[] str = new string[macAddrLen];
                for (int i = 0; i < macAddrLen; i++)
                    str[i] = macAddr[i].ToString("x2");

                HostList.Add("MAC: " + string.Join(":", str) + " IP: " + string.Concat(_ipRange, counter));
            }
        }
    }
}