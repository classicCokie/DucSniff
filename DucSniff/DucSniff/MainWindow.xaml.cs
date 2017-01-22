using System.Windows;

namespace DucSniff
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly NetworkData _netCard;
        private readonly NetworkScanner _scanner;

        public MainWindow()
        {
            InitializeComponent();
            _netCard = new NetworkData();
            _scanner = new NetworkScanner(_netCard.GetIpRange());
        }

        public void button_Click(object sender, RoutedEventArgs e)
        {
            listBox.Items.Clear();
            _scanner.ClearhostList();
            _scanner.start_scanning();
            _scanner.GetHosts().ForEach(item => listBox.Items.Add(item));
        }

        private void button2_Click(object sender, RoutedEventArgs e)
        {
            string item = listBox.SelectedItem.ToString();

            if (!listBox1.Items.Contains(item) && listBox1.Items.Count <= 1 || listBox1.Items.Count == 0)
                listBox1.Items.Add(item);
        }

        private void button1_Click(object sender, RoutedEventArgs e)
        {
            if (listBox1.Items.Count == 2)
            {
                _netCard.SetTargetData(listBox1.Items[0].ToString(), listBox1.Items[1].ToString());
                _netCard.SendArpSpoof();
                pbStatus.IsIndeterminate = true;
                label2.Content = "Listening for Packages ...";
            }
            else
            {
                MessageBox.Show("Please Choose two targets!");
            }
        }

        private void button3_Click(object sender, RoutedEventArgs e)
        {
            pbStatus.IsIndeterminate = false;
            _netCard.StopListening();
            listBox1.Items.Clear();
            label2.Content = "Not Started";
        }
    }
}