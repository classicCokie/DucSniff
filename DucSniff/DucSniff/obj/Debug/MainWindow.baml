   M S B A M L   `   `   `  ����C  ?DucSniff, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null#clr-namespace:DucSniffDucSniff  5   	       DucSniff.MainWindow   5   	   R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   (localclr-namespace:DucSniff     5   	     � Title$  
MainWindow��5   	   $��395.393��6   $��656.869��6-   .��5	      � $��0,0,2,-3q�6    � ColumnDefinitions 5
   
   �� 5      $	��35* �6   �� 5      $
��121* �6   �� 5      $
��438* �6   �� 5      $	��66* �6   .+�5   
   �� -   5         ��Name$ button��5      $��Scan Network��6!   $
��Left=�68   $��	22,36,0,0q�6S   $	��Top=�6f   $��92��6~   $��2��6�   �� 5   
   -   5         ��Name$ listBox��5      $
��Left=�6#   $	��134��6>   $��	19,36,0,0q�6K   $	��Top=�6^   $	��299��6v   $��2��6�   �� 5   
   -   5         ��Name$ label��5      $��	All Hosts��6   $
��Left=�63   $��	19,10,0,0q�6N   $	��Top=�6a   $��2��6y   �� 5   
   -   5        $ listBox1��5      $
��Left=�6$   $��60��6?   $��
19,195,0,0q�6K   $	��Top=�6_   $	��299��6w   $��2��6�   �� 5   
   -   5        $ label1��5      $��Targets��6    $
��Left=�62   $��
19,170,0,0q�6M   $	��Top=�6a   $��2��6y   �� 5   
   -   5        $ button1��5      $��Poison Targets��6"   $
��Left=�6;   $��
22,205,0,0q�6V   $	��Top=�6j   $��92��6�   $��2��6�   �� 5   
   -   5        $ button2��5      $#��Add selected
 Host as Target��6"   $��Center=�6R   $��Center=�6v   $
��Left=�6�   $��	22,72,0,0q�6�   $	��Top=�6�   $��92��6�   $��40��6�   $��2��6  �� 5   
   -   5        $ button3��5      $��Stop Attack��6"   $
��Left=�68   $��
22,269,0,0q�6S   $	��Top=�6g   $��92��6   $��2��6�   � 5   
   -	   5        $��pbStatus��5   �   $��2��6   $
��Left=�6&   $��36��6A   $��
19,269,0,0q�6M   $	��Top=�6a   $	��299��6y    � Minimum$ 0Q�6�    � Maximum$	 100Q�6�    � IsIndeterminate .  6�   �� 5   
   -
   5        $ label2��5      $��Not Started��6    $��2��66   $
��Left=�6F   $��
19,310,0,0q�6a   $	��Top=�6u   5      5      