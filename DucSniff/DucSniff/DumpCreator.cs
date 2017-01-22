using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using PcapDotNet.Packets;
using Microsoft.VisualStudio.QualityTools.UnitTestFramework;

namespace DucSniff
{
    public class DumpCreator
    {
        private readonly List<string> _allData = new List<string>();

        public void AddData(Packet p)
        {
            _allData.Add(CreateStringFromPacket(p));
        }

        public void WriteToFile()
        {
            string path = Directory.GetCurrentDirectory();
            path = path + @"\dumpFile.txt";
            File.WriteAllLines(path, _allData);
            MessageBox.Show("All Captured Packages saved to: " + path);
           
        }

        private string CreateStringFromPacket(Packet p)
        {
            string stringPacket = "Time: " + Convert.ToString(p.Timestamp) + " Source: " +
                                  Convert.ToString(p.Ethernet.IpV4.Source) + " Destination: " +
                                  Convert.ToString(p.Ethernet.IpV4.Destination) + " Protocol Type: " +
                                  Convert.ToString(p.Ethernet.IpV4.Protocol) + " Payload: " +
                                  Convert.ToString(p.Ethernet.IpV4.Payload) + "\n";
            return stringPacket;
        }
    }
}