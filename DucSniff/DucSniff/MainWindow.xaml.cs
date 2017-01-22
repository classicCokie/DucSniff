using System.Windows;

namespace DucSniff
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        //Two Main Classes 
        private readonly NetworkData _netCard;
        private readonly NetworkScanner _scanner;

        //initliaize Components
        public MainWindow()
        {
            InitializeComponent();
            //Create netCard for Traffic Handeling and Scanner two later Scann Network for hosts
            _netCard = new NetworkData();
            _scanner = new NetworkScanner(_netCard.GetIpRange());
        }

        public void button_Click(object sender, RoutedEventArgs e)
        {
            
            listBox.Items.Clear();//Clear the list from hosts that have been added before
            _scanner.ClearhostList(); // Clear Pevious hosts
            _scanner.start_scanning(); // Start New Scan
            _scanner.GetHosts().ForEach(item => listBox.Items.Add(item)); //Write new Hosts back to list
        }

        private void button2_Click(object sender, RoutedEventArgs e) // make Selected host a target
        {
            string item = listBox.SelectedItem.ToString(); // get selected Host to string

            if (!listBox1.Items.Contains(item) && listBox1.Items.Count <= 1 || listBox1.Items.Count == 0) // Check that there are not more than two targets
                listBox1.Items.Add(item);
        }

        private void button1_Click(object sender, RoutedEventArgs e) // make arp Spoof and start listenening for packages
        {
            if (listBox1.Items.Count == 2) // Check that there are two targets
            {
                _netCard.SetTargetData(listBox1.Items[0].ToString(), listBox1.Items[1].ToString()); // Pass Data from target to netcard for arp spoof
                _netCard.SendArpSpoof(); // start arp spoof
                pbStatus.IsIndeterminate = true; // start progressbar
                label2.Content = "Listening for Packages ...";
            }
            else
            {
                MessageBox.Show("Please Choose two targets!");
            }
        }

        private void button3_Click(object sender, RoutedEventArgs e) // Stop listening for packages and stop sending arp spoof
        {
            pbStatus.IsIndeterminate = false;
            _netCard.StopListening();
            listBox1.Items.Clear();
            label2.Content = "Not Started";
        }
    }
}